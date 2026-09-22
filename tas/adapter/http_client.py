"""Bounded HTTPS client for the central F3 Application Service."""

from __future__ import annotations

import json
import base64
import binascii
import hashlib
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any
from urllib.parse import quote
from uuid import UUID, uuid4

import httpx
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from tas.adapter.config import AdapterConfig


class AdapterClientError(RuntimeError):
    """Base error safe to surface through an Adapter boundary."""


class AdapterTransportError(AdapterClientError):
    """The configured central service could not be reached safely."""


class AdapterTimeoutError(AdapterTransportError):
    """A bounded central service request timed out."""


class AdapterProtocolError(AdapterClientError):
    """The server returned an unsupported or malformed response."""


class AdapterResponseTooLargeError(AdapterProtocolError):
    """A response exceeded the configured byte limit."""


class AdapterVersionMismatchError(AdapterProtocolError):
    """The central API version is not the configured compatible version."""


class RemoteAPIError(AdapterClientError):
    """A controlled error returned by the central Application API."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        retryable: bool,
        correlation_id: str,
    ) -> None:
        super().__init__(f"Central API rejected the request ({code})")
        self.status_code = status_code
        self.code = code
        self.remote_message = message
        self.retryable = retryable
        self.correlation_id = correlation_id


class _SessionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    agent_id: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$"
    )
    credential_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    scopes: list[str] = Field(max_length=64)
    expires_at: datetime

    @field_validator("scopes")
    @classmethod
    def validate_scopes(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not item
            or len(item) > 255
            or not item[0].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character in "._:-"))
                for character in item
            )
            for item in value
        ):
            raise ValueError("scopes must contain unique safe bounded strings")
        return value

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("expires_at must use UTC")
        return value


class _ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1, max_length=512)
    retryable: bool
    correlation_id: str
    details: dict[str, Any] | None = None

    @field_validator("details")
    @classmethod
    def validate_details(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        if value is not None and len(value) > 16:
            raise ValueError("details exceeds 16 properties")
        return value

    @field_validator("correlation_id")
    @classmethod
    def validate_correlation_id(cls, value: str) -> str:
        try:
            normalized = str(UUID(value))
        except ValueError as error:
            raise ValueError("invalid correlation ID") from error
        if normalized != value.lower():
            raise ValueError("correlation ID is not canonical")
        return normalized


class RemoteTaskStatus(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input_required"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


class _TaskPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    project_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    assignee_agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    title: str = Field(min_length=1, max_length=1024)
    status: RemoteTaskStatus
    result: str | None = Field(default=None, max_length=65536)
    replayed: bool | None = None


class _InboxLeasePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    attempt: int = Field(strict=True, ge=1)
    lease_token: str = Field(
        min_length=16, max_length=255,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    )
    acquired_at: datetime
    expires_at: datetime

    @field_validator("acquired_at", "expires_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Inbox Lease times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_window(self) -> _InboxLeasePayload:
        if self.expires_at <= self.acquired_at:
            raise ValueError("Inbox Lease expiry is invalid")
        return self


class _InboxClaimPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item: _InboxLeasePayload | None
    replayed: StrictBool


class RemoteInboxStatus(StrEnum):
    PENDING = "pending"
    ACKNOWLEDGED = "acknowledged"
    DEAD_LETTER = "dead_letter"


class _InboxFinishPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    status: RemoteInboxStatus
    attempt: int = Field(strict=True, ge=1)
    available_at: datetime | None
    replayed: StrictBool

    @field_validator("available_at")
    @classmethod
    def validate_available_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("Inbox availability must use UTC")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> _InboxFinishPayload:
        if (self.status is RemoteInboxStatus.PENDING) != (self.available_at is not None):
            raise ValueError("Inbox availability is inconsistent with status")
        return self


class _ApprovalPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    status: str = Field(pattern=r"^(?:pending|approved|rejected|expired)$")
    requester_agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    receiving_agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    repository: str = Field(min_length=1, max_length=255)
    action: str = Field(min_length=1, max_length=64)
    scope: str = Field(min_length=1, max_length=255)
    risk: int = Field(strict=True, ge=1, le=5)
    policy_version: str = Field(min_length=1, max_length=255)
    requested_at: datetime
    expires_at: datetime
    resolved_by_owner_id: str | None = Field(default=None, max_length=255)
    resolved_at: datetime | None
    reason: str | None = Field(default=None, max_length=1024)
    replayed: bool | None = None

    @field_validator("requested_at", "expires_at", "resolved_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("Approval times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> _ApprovalPayload:
        if self.expires_at <= self.requested_at:
            raise ValueError("Approval expiry is invalid")
        if self.status == "pending":
            if self.resolved_by_owner_id is not None or self.resolved_at is not None:
                raise ValueError("pending Approval contains resolution fields")
        elif self.status in {"approved", "rejected"} and (
            self.resolved_by_owner_id is None or self.resolved_at is None
        ):
            raise ValueError("resolved Approval is missing resolution fields")
        return self


class RemoteActionGrantStatus(StrEnum):
    PREPARED = "prepared"
    RESULT_UNKNOWN = "result_unknown"
    COMPLETED = "completed"


class _ActionReceiptPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_action_id: str = Field(min_length=1, max_length=255)
    result_reference: str = Field(min_length=1, max_length=255)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def validate_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Receipt time must use UTC")
        return value


class _ActionGrantPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    operation_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    workspace_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    evidence_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    commit_sha: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    execute_before: datetime
    status: RemoteActionGrantStatus
    started_at: datetime
    receipt: _ActionReceiptPayload | None
    replayed: bool

    @field_validator("execute_before", "started_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Action Grant times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> _ActionGrantPayload:
        if self.execute_before <= self.started_at:
            raise ValueError("Action Grant execution window is invalid")
        if (self.status is RemoteActionGrantStatus.COMPLETED) != (self.receipt is not None):
            raise ValueError("Action Grant Receipt state is inconsistent")
        if self.operation_id != self.approval_id:
            raise ValueError("Action Grant operation must equal Approval")
        if self.receipt is not None and (
            self.receipt.operation_id != self.operation_id
            or self.receipt.request_fingerprint != self.request_fingerprint
        ):
            raise ValueError("Action Grant Receipt identity is inconsistent")
        return self


class _WorkspacePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    actor_agent_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    repository: str = Field(min_length=1, max_length=255)
    bound_at: datetime
    replayed: bool | None = None

    @field_validator("bound_at")
    @classmethod
    def validate_bound_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("bound_at must use UTC")
        return value


class RemoteArtifactStatus(StrEnum):
    RESERVED = "reserved"
    UPLOADED = "uploaded"
    FINALIZED = "finalized"


class RemoteArtifactPurpose(StrEnum):
    TEST_STDOUT = "test_stdout"
    TEST_STDERR = "test_stderr"
    GIT_DIFF = "git_diff"
    RESULT = "result"
    OTHER = "other"


class _ArtifactPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    media_type: str = Field(pattern=r"^(?:application/json|application/octet-stream|text/plain)$")
    purpose: RemoteArtifactPurpose
    declared_size: int = Field(strict=True, ge=0, le=10 * 1024 * 1024)
    declared_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: RemoteArtifactStatus
    actual_size: int | None = Field(default=None, strict=True, ge=0, le=10 * 1024 * 1024)
    actual_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    uploaded_at: datetime | None
    finalized_at: datetime | None
    replayed: bool

    @field_validator("created_at", "uploaded_at", "finalized_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("Artifact times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> _ArtifactPayload:
        if self.status is RemoteArtifactStatus.RESERVED:
            if any(
                value is not None
                for value in (
                    self.actual_size,
                    self.actual_sha256,
                    self.uploaded_at,
                    self.finalized_at,
                )
            ):
                raise ValueError("reserved Artifact contains completed fields")
        else:
            if (
                self.actual_size != self.declared_size
                or self.actual_sha256 != self.declared_sha256
                or self.uploaded_at is None
            ):
                raise ValueError("Artifact upload facts differ from its reservation")
            if (self.status is RemoteArtifactStatus.FINALIZED) != (
                self.finalized_at is not None
            ):
                raise ValueError("Artifact finalized state is inconsistent")
        return self


class _ArtifactMetadataPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    media_type: str = Field(pattern=r"^(?:application/json|application/octet-stream|text/plain)$")
    purpose: RemoteArtifactPurpose
    size: int = Field(strict=True, ge=0, le=10 * 1024 * 1024)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    finalized_at: datetime

    @field_validator("created_at", "finalized_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Artifact times must use UTC")
        return value


class RemoteEvidenceStatus(StrEnum):
    RESERVED = "reserved"
    FINALIZED = "finalized"


class RemoteEvidenceKind(StrEnum):
    GIT = "git"
    COMMAND_TEST = "command_test"


class _EvidencePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    workspace_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    kind: RemoteEvidenceKind
    attempt: int = Field(strict=True, ge=1, le=16)
    retry_of: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$"
    )
    observed_at: datetime
    head_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    artifact_ids: list[str] = Field(max_length=32)
    status: RemoteEvidenceStatus
    payload_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    created_at: datetime
    finalized_at: datetime | None
    replayed: bool

    @field_validator("artifact_ids")
    @classmethod
    def validate_artifact_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not item
            or len(item) > 255
            or not item[0].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character in "._:-"))
                for character in item
            )
            for item in value
        ):
            raise ValueError("artifact_ids must contain unique bounded identifiers")
        return value

    @field_validator("observed_at", "created_at", "finalized_at")
    @classmethod
    def validate_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() != timedelta(0)):
            raise ValueError("Evidence times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_state(self) -> _EvidencePayload:
        if self.kind is RemoteEvidenceKind.GIT:
            if self.attempt != 1 or self.retry_of is not None:
                raise ValueError("Git Evidence cannot be a retry")
        elif (self.attempt == 1) != (self.retry_of is None):
            raise ValueError("Command Evidence retry state is inconsistent")
        if self.status is RemoteEvidenceStatus.RESERVED:
            if self.payload_sha256 is not None or self.finalized_at is not None:
                raise ValueError("reserved Evidence contains finalized fields")
        elif self.payload_sha256 is None or self.finalized_at is None:
            raise ValueError("finalized Evidence is incomplete")
        return self


class _EvidenceAccessPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    task_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    workspace_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    kind: RemoteEvidenceKind
    attempt: int = Field(strict=True, ge=1, le=16)
    retry_of: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
    observed_at: datetime
    head_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    artifact_ids: list[str] = Field(max_length=32)
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_json: str = Field(min_length=2, max_length=256 * 1024)
    created_at: datetime
    finalized_at: datetime

    @field_validator("artifact_ids")
    @classmethod
    def validate_artifact_ids(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)) or any(
            not item
            or len(item) > 255
            or not item[0].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character in "._:-"))
                for character in item
            )
            for item in value
        ):
            raise ValueError("artifact_ids must contain unique bounded identifiers")
        return value

    @field_validator("observed_at", "created_at", "finalized_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("Evidence times must use UTC")
        return value

    @model_validator(mode="after")
    def validate_integrity(self) -> _EvidenceAccessPayload:
        if self.kind is RemoteEvidenceKind.GIT:
            if self.attempt != 1 or self.retry_of is not None:
                raise ValueError("Git Evidence cannot be a retry")
        elif (self.attempt == 1) != (self.retry_of is None):
            raise ValueError("Command Evidence retry state is inconsistent")
        if hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise ValueError("Evidence payload digest is inconsistent")
        try:
            parsed = json.loads(
                self.payload_json,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-standard JSON constant: {value}")
                ),
            )
            canonical = json.dumps(
                parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                allow_nan=False,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as error:
            raise ValueError("Evidence payload is not canonical JSON") from error
        if not isinstance(parsed, dict) or canonical != self.payload_json:
            raise ValueError("Evidence payload is not canonical JSON")
        return self


@dataclass(frozen=True, slots=True)
class AdapterSession:
    owner_id: str
    agent_id: str | None
    credential_id: str
    scopes: tuple[str, ...]
    expires_at: datetime
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteTask:
    id: str
    project_id: str
    assignee_agent_id: str
    title: str
    status: RemoteTaskStatus
    result: str | None
    replayed: bool | None
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteInboxLease:
    item_id: str
    task_id: str
    attempt: int
    lease_token: str
    acquired_at: datetime
    expires_at: datetime
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteInboxClaim:
    item: RemoteInboxLease | None
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteInboxFinish:
    item_id: str
    status: RemoteInboxStatus
    attempt: int
    available_at: datetime | None
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteApproval:
    id: str
    status: str
    requester_agent_id: str
    receiving_agent_id: str
    task_id: str
    repository: str
    action: str
    scope: str
    risk: int
    policy_version: str
    requested_at: datetime
    expires_at: datetime
    resolved_by_owner_id: str | None
    resolved_at: datetime | None
    reason: str | None
    replayed: bool | None
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteActionReceipt:
    operation_id: str
    request_fingerprint: str
    external_action_id: str
    result_reference: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class RemoteActionGrant:
    approval_id: str
    operation_id: str
    request_fingerprint: str
    workspace_id: str
    evidence_id: str
    commit_sha: str
    execute_before: datetime
    status: RemoteActionGrantStatus
    started_at: datetime
    receipt: RemoteActionReceipt | None
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteWorkspace:
    id: str
    task_id: str
    actor_agent_id: str
    repository: str
    bound_at: datetime
    replayed: bool | None
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteArtifact:
    id: str
    task_id: str
    media_type: str
    purpose: RemoteArtifactPurpose
    declared_size: int
    declared_sha256: str
    status: RemoteArtifactStatus
    actual_size: int | None
    actual_sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None
    finalized_at: datetime | None
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteArtifactMetadata:
    id: str
    task_id: str
    media_type: str
    purpose: RemoteArtifactPurpose
    size: int
    sha256: str
    created_at: datetime
    finalized_at: datetime
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteArtifactContent:
    artifact_id: str
    media_type: str
    sha256: str
    content: bytes
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteEvidence:
    id: str
    task_id: str
    workspace_id: str
    kind: RemoteEvidenceKind
    attempt: int
    retry_of: str | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[str, ...]
    status: RemoteEvidenceStatus
    payload_sha256: str | None
    created_at: datetime
    finalized_at: datetime | None
    replayed: bool
    correlation_id: str


@dataclass(frozen=True, slots=True)
class RemoteEvidenceAccess:
    id: str
    task_id: str
    workspace_id: str
    kind: RemoteEvidenceKind
    attempt: int
    retry_of: str | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[str, ...]
    payload_sha256: str
    payload_json: str
    created_at: datetime
    finalized_at: datetime
    correlation_id: str


class TASRemoteClient:
    """Calls only fixed relative paths on one configured HTTPS origin."""

    USER_AGENT = "team-agent-system-adapter/0.1"

    def __init__(
        self,
        config: AdapterConfig,
        credential: str,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not isinstance(config, AdapterConfig):
            raise TypeError("config must be AdapterConfig")
        if (
            not isinstance(credential, str)
            or not credential
            or len(credential) > 4096
            or credential != credential.strip()
            or any(character.isspace() for character in credential)
        ):
            raise ValueError("credential is invalid")
        self.config = config
        self._credential = credential
        try:
            tls_context: ssl.SSLContext | bool = (
                True
                if config.tls_ca_file is None
                else ssl.create_default_context(cafile=config.tls_ca_file)
            )
        except (OSError, ssl.SSLError) as error:
            raise AdapterTransportError("Configured TLS trust store is invalid") from error
        self._client = httpx.Client(
            base_url=config.endpoint,
            headers={"Accept": "application/json", "User-Agent": self.USER_AGENT},
            timeout=httpx.Timeout(
                connect=config.connect_timeout_seconds,
                read=config.read_timeout_seconds,
                write=config.write_timeout_seconds,
                pool=config.pool_timeout_seconds,
            ),
            verify=tls_context,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    def __enter__(self) -> TASRemoteClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def verify_compatibility(self) -> str:
        payload, _ = self._request_json("GET", "/openapi.json", authenticated=False)
        info = payload.get("info") if isinstance(payload, dict) else None
        version = info.get("version") if isinstance(info, dict) else None
        if version != self.config.expected_api_version:
            raise AdapterVersionMismatchError(
                "Central API version does not match Adapter configuration"
            )
        return str(version)

    def get_session(self) -> AdapterSession:
        payload, correlation_id = self._request_json(
            "GET", "/api/v1/session", authenticated=True
        )
        try:
            parsed = _SessionPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Session") from error
        return AdapterSession(
            parsed.owner_id,
            parsed.agent_id,
            parsed.credential_id,
            tuple(parsed.scopes),
            parsed.expires_at,
            correlation_id,
        )

    def smoke(self) -> AdapterSession:
        self.verify_compatibility()
        return self.get_session()

    def create_task(
        self,
        *,
        idempotency_key: str,
        project_id: str,
        assignee_agent_id: str,
        title: str,
    ) -> RemoteTask:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(project_id, "project_id")
        self._identifier(assignee_agent_id, "assignee_agent_id")
        if not isinstance(title, str) or not title.strip() or len(title) > 1024:
            raise ValueError("title must be 1..1024 non-whitespace characters")
        payload, correlation_id = self._request_json(
            "POST",
            "/api/v1/tasks",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={
                "project_id": project_id,
                "assignee_agent_id": assignee_agent_id,
                "title": title,
            },
        )
        return self._task(payload, correlation_id)

    def get_task(self, task_id: str) -> RemoteTask:
        self._identifier(task_id, "task_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/tasks/{quote(task_id, safe='')}",
            authenticated=True,
        )
        return self._task(payload, correlation_id)

    def claim_inbox(
        self,
        *,
        idempotency_key: str,
        lease_duration_seconds: int,
        wait_timeout_seconds: int = 0,
    ) -> RemoteInboxClaim:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        if type(lease_duration_seconds) is not int or not 5 <= lease_duration_seconds <= 300:
            raise ValueError("lease_duration_seconds must be an integer from 5 to 300")
        if type(wait_timeout_seconds) is not int or not 0 <= wait_timeout_seconds <= 25:
            raise ValueError("wait_timeout_seconds must be an integer from 0 to 25")
        if wait_timeout_seconds + 1 > self.config.read_timeout_seconds:
            raise ValueError(
                "wait_timeout_seconds must leave one second inside the read timeout"
            )
        payload, correlation_id = self._request_json(
            "POST",
            "/api/v1/inbox/claim",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={
                "lease_duration_seconds": lease_duration_seconds,
                "wait_timeout_seconds": wait_timeout_seconds,
            },
        )
        try:
            value = _InboxClaimPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Inbox Claim") from error
        item = None
        if value.item is not None:
            item = RemoteInboxLease(
                value.item.item_id, value.item.task_id, value.item.attempt,
                value.item.lease_token, value.item.acquired_at, value.item.expires_at,
                value.replayed, correlation_id,
            )
        return RemoteInboxClaim(item, value.replayed, correlation_id)

    def acknowledge_inbox(
        self, *, idempotency_key: str, item_id: str, lease_token: str
    ) -> RemoteInboxFinish:
        return self._finish_inbox(
            "acknowledge", idempotency_key=idempotency_key, item_id=item_id,
            lease_token=lease_token, retry_delay_seconds=None,
        )

    def release_inbox(
        self, *, idempotency_key: str, item_id: str, lease_token: str,
        retry_delay_seconds: int,
    ) -> RemoteInboxFinish:
        if type(retry_delay_seconds) is not int or not 0 <= retry_delay_seconds <= 604800:
            raise ValueError("retry_delay_seconds must be an integer from 0 to 604800")
        return self._finish_inbox(
            "release", idempotency_key=idempotency_key, item_id=item_id,
            lease_token=lease_token, retry_delay_seconds=retry_delay_seconds,
        )

    def _finish_inbox(
        self, operation: str, *, idempotency_key: str, item_id: str,
        lease_token: str, retry_delay_seconds: int | None,
    ) -> RemoteInboxFinish:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(item_id, "item_id")
        if (
            not isinstance(lease_token, str)
            or not 16 <= len(lease_token) <= 255
            or lease_token != lease_token.strip()
            or any(character.isspace() for character in lease_token)
        ):
            raise ValueError("lease_token is invalid")
        body: dict[str, Any] = {"lease_token": lease_token}
        if retry_delay_seconds is not None:
            body["retry_delay_seconds"] = retry_delay_seconds
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/inbox/{quote(item_id, safe='')}/{operation}",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body=body,
        )
        try:
            value = _InboxFinishPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Inbox result") from error
        if value.item_id != item_id:
            raise AdapterProtocolError("Central API Inbox result identity changed")
        return RemoteInboxFinish(
            value.item_id, value.status, value.attempt, value.available_at,
            value.replayed, correlation_id,
        )

    def get_approval(self, approval_id: str) -> RemoteApproval:
        self._identifier(approval_id, "approval_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/approvals/{quote(approval_id, safe='')}",
            authenticated=True,
        )
        return self._approval(payload, correlation_id)

    def prepare_action_grant(
        self,
        *,
        approval_id: str,
        workspace_id: str,
        evidence_id: str,
        idempotency_key: str,
    ) -> RemoteActionGrant:
        self._identifier(approval_id, "approval_id")
        self._identifier(workspace_id, "workspace_id")
        self._identifier(evidence_id, "evidence_id")
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/approvals/{quote(approval_id, safe='')}/action-grant",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={"workspace_id": workspace_id, "evidence_id": evidence_id},
        )
        return self._action_grant(payload, correlation_id)

    def get_action_grant(self, approval_id: str) -> RemoteActionGrant:
        self._identifier(approval_id, "approval_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/approvals/{quote(approval_id, safe='')}/action-grant",
            authenticated=True,
        )
        return self._action_grant(payload, correlation_id)

    def mark_action_result_unknown(
        self, *, approval_id: str, request_fingerprint: str, idempotency_key: str
    ) -> RemoteActionGrant:
        self._action_arguments(approval_id, request_fingerprint, idempotency_key)
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/approvals/{quote(approval_id, safe='')}/action-grant/result-unknown",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={"request_fingerprint": request_fingerprint},
        )
        return self._action_grant(payload, correlation_id)

    def submit_action_receipt(
        self,
        *,
        approval_id: str,
        request_fingerprint: str,
        external_action_id: str,
        result_reference: str,
        occurred_at: datetime,
        idempotency_key: str,
    ) -> RemoteActionGrant:
        self._action_arguments(approval_id, request_fingerprint, idempotency_key)
        self._bounded_text(external_action_id, "external_action_id", 255)
        self._bounded_text(result_reference, "result_reference", 255)
        if occurred_at.tzinfo is None or occurred_at.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must use UTC")
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/approvals/{quote(approval_id, safe='')}/action-receipts",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={
                "request_fingerprint": request_fingerprint,
                "external_action_id": external_action_id,
                "result_reference": result_reference,
                "occurred_at": occurred_at.isoformat(),
            },
        )
        return self._action_grant(payload, correlation_id)

    def register_workspace(
        self, *, idempotency_key: str, task_id: str, repository: str
    ) -> RemoteWorkspace:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(task_id, "task_id")
        self._bounded_text(repository, "repository", 255)
        payload, correlation_id = self._request_json(
            "POST",
            "/api/v1/workspaces",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={"task_id": task_id, "repository": repository},
        )
        return self._workspace(payload, correlation_id)

    def get_workspace(self, workspace_id: str) -> RemoteWorkspace:
        self._identifier(workspace_id, "workspace_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/workspaces/{quote(workspace_id, safe='')}",
            authenticated=True,
        )
        return self._workspace(payload, correlation_id)

    def reserve_artifact(
        self,
        *,
        idempotency_key: str,
        task_id: str,
        media_type: str,
        purpose: RemoteArtifactPurpose,
        content: bytes,
    ) -> RemoteArtifact:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(task_id, "task_id")
        if media_type not in {"application/json", "application/octet-stream", "text/plain"}:
            raise ValueError("media_type is unsupported")
        if not isinstance(purpose, RemoteArtifactPurpose):
            raise TypeError("purpose must be RemoteArtifactPurpose")
        if not isinstance(content, bytes) or len(content) > 10 * 1024 * 1024:
            raise ValueError("Artifact content exceeds the client limit")
        digest = hashlib.sha256(content).hexdigest()
        payload, correlation_id = self._request_json(
            "POST",
            "/api/v1/artifacts",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={
                "task_id": task_id,
                "media_type": media_type,
                "declared_size": len(content),
                "declared_sha256": digest,
                "purpose": purpose.value,
            },
        )
        return self._artifact(payload, correlation_id)

    def upload_artifact_content(
        self,
        *,
        idempotency_key: str,
        artifact_id: str,
        media_type: str,
        content: bytes,
    ) -> RemoteArtifact:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(artifact_id, "artifact_id")
        if media_type not in {"application/json", "application/octet-stream", "text/plain"}:
            raise ValueError("media_type is unsupported")
        if not isinstance(content, bytes) or len(content) > 10 * 1024 * 1024:
            raise ValueError("Artifact content exceeds the client limit")
        digest = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
        payload, correlation_id = self._request_json(
            "PUT",
            f"/api/v1/artifacts/{quote(artifact_id, safe='')}/content",
            authenticated=True,
            headers={
                "Idempotency-Key": idempotency_key,
                "Digest": f"sha-256=:{digest}:",
                "Content-Type": media_type,
            },
            content_body=content,
        )
        return self._artifact(payload, correlation_id)

    def finalize_artifact(
        self, *, idempotency_key: str, artifact_id: str
    ) -> RemoteArtifact:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(artifact_id, "artifact_id")
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/artifacts/{quote(artifact_id, safe='')}/finalize",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
        )
        return self._artifact(payload, correlation_id)

    def get_artifact_metadata(self, artifact_id: str) -> RemoteArtifactMetadata:
        self._identifier(artifact_id, "artifact_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/artifacts/{quote(artifact_id, safe='')}",
            authenticated=True,
        )
        try:
            value = _ArtifactMetadataPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError(
                "Central API returned invalid Artifact metadata"
            ) from error
        return RemoteArtifactMetadata(
            value.id, value.task_id, value.media_type, value.purpose,
            value.size, value.sha256, value.created_at, value.finalized_at,
            correlation_id,
        )

    def download_artifact_content(self, artifact_id: str) -> RemoteArtifactContent:
        self._identifier(artifact_id, "artifact_id")
        content, media_type, digest, correlation_id = self._request_binary(
            f"/api/v1/artifacts/{quote(artifact_id, safe='')}/content"
        )
        return RemoteArtifactContent(
            artifact_id, media_type, digest, content, correlation_id
        )

    def reserve_evidence(
        self,
        *,
        idempotency_key: str,
        task_id: str,
        workspace_id: str,
        kind: RemoteEvidenceKind,
        attempt: int,
        retry_of: str | None,
        observed_at: datetime,
        head_commit: str,
        artifact_ids: tuple[str, ...],
    ) -> RemoteEvidence:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(task_id, "task_id")
        self._identifier(workspace_id, "workspace_id")
        if not isinstance(kind, RemoteEvidenceKind):
            raise TypeError("kind must be RemoteEvidenceKind")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or not 1 <= attempt <= 16:
            raise ValueError("attempt must be 1..16")
        if kind is RemoteEvidenceKind.GIT and (attempt != 1 or retry_of is not None):
            raise ValueError("Git Evidence cannot be a retry")
        if kind is RemoteEvidenceKind.COMMAND_TEST and (attempt == 1) != (retry_of is None):
            raise ValueError("retry_of must match attempt")
        if retry_of is not None:
            self._identifier(retry_of, "retry_of")
        if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
            raise ValueError("observed_at must use UTC")
        self._commit(head_commit)
        if len(artifact_ids) > 32 or len(artifact_ids) != len(set(artifact_ids)):
            raise ValueError("artifact_ids are excessive or duplicated")
        for artifact_id in artifact_ids:
            self._identifier(artifact_id, "artifact_id")
        payload, correlation_id = self._request_json(
            "POST",
            "/api/v1/evidence",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={
                "task_id": task_id,
                "workspace_id": workspace_id,
                "kind": kind.value,
                "attempt": attempt,
                "retry_of": retry_of,
                "observed_at": observed_at.isoformat(),
                "head_commit": head_commit,
                "artifact_ids": list(artifact_ids),
            },
        )
        return self._evidence(payload, correlation_id)

    def finalize_evidence(
        self,
        *,
        idempotency_key: str,
        evidence_id: str,
        payload_json: str,
    ) -> RemoteEvidence:
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        self._identifier(evidence_id, "evidence_id")
        if not isinstance(payload_json, str) or not 2 <= len(payload_json.encode("utf-8")) <= 256 * 1024:
            raise ValueError("payload_json exceeds the client limit")
        payload, correlation_id = self._request_json(
            "POST",
            f"/api/v1/evidence/{quote(evidence_id, safe='')}/finalize",
            authenticated=True,
            headers={"Idempotency-Key": idempotency_key},
            json_body={"payload_json": payload_json},
        )
        return self._evidence(payload, correlation_id)

    def get_evidence(self, evidence_id: str) -> RemoteEvidenceAccess:
        self._identifier(evidence_id, "evidence_id")
        payload, correlation_id = self._request_json(
            "GET",
            f"/api/v1/evidence/{quote(evidence_id, safe='')}",
            authenticated=True,
        )
        try:
            value = _EvidenceAccessPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError(
                "Central API returned invalid Evidence access response"
            ) from error
        return RemoteEvidenceAccess(
            value.id, value.task_id, value.workspace_id, value.kind,
            value.attempt, value.retry_of, value.observed_at, value.head_commit,
            tuple(value.artifact_ids), value.payload_sha256, value.payload_json,
            value.created_at, value.finalized_at, correlation_id,
        )

    def _request_binary(self, path: str) -> tuple[bytes, str, str, str]:
        correlation_id = str(uuid4())
        try:
            with self._client.stream(
                "GET",
                path,
                headers={
                    "X-Correlation-ID": correlation_id,
                    "Authorization": f"Bearer {self._credential}",
                },
            ) as response:
                if response.is_redirect:
                    raise AdapterProtocolError("Central API redirects are not allowed")
                response_correlation = response.headers.get("X-Correlation-ID")
                try:
                    normalized_correlation = str(UUID(response_correlation or ""))
                except ValueError as error:
                    raise AdapterProtocolError(
                        "Central API returned an invalid X-Correlation-ID"
                    ) from error
                if normalized_correlation != correlation_id:
                    raise AdapterProtocolError(
                        "Central API response correlation does not match the request"
                    )
                if response.status_code >= 400:
                    body = self._read_bounded(response)
                    try:
                        payload = json.loads(body)
                    except (UnicodeDecodeError, json.JSONDecodeError) as error:
                        raise AdapterProtocolError(
                            "Central API returned malformed JSON"
                        ) from error
                    if not isinstance(payload, dict):
                        raise AdapterProtocolError(
                            "Central API response must be an object"
                        )
                    self._raise_remote_error(
                        response.status_code, payload, normalized_correlation
                    )
                if not 200 <= response.status_code < 300:
                    raise AdapterProtocolError(
                        "Central API returned an unexpected status"
                    )
                media_type = response.headers.get("content-type", "").lower()
                if media_type not in {
                    "application/json", "application/octet-stream", "text/plain"
                }:
                    raise AdapterProtocolError(
                        "Central API returned an unsupported Artifact media type"
                    )
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise AdapterProtocolError(
                        "Central API Artifact compression is not supported"
                    )
                if response.headers.get("content-disposition") != (
                    'attachment; filename="artifact.bin"'
                ):
                    raise AdapterProtocolError(
                        "Central API Artifact disposition is unsafe"
                    )
                if response.headers.get("x-content-type-options", "").lower() != "nosniff":
                    raise AdapterProtocolError(
                        "Central API Artifact response permits content sniffing"
                    )
                if response.headers.get("cache-control", "").lower() != "private, no-store":
                    raise AdapterProtocolError(
                        "Central API Artifact cache policy is unsafe"
                    )
                try:
                    declared_size = int(response.headers["content-length"])
                except (KeyError, ValueError) as error:
                    raise AdapterProtocolError(
                        "Central API Artifact Content-Length is invalid"
                    ) from error
                if not 0 <= declared_size <= 10 * 1024 * 1024:
                    raise AdapterResponseTooLargeError(
                        "Central API Artifact exceeds the client limit"
                    )
                digest = self._structured_digest(response.headers.get("digest", ""))
                content = bytearray()
                calculated = hashlib.sha256()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    calculated.update(chunk)
                    if len(content) > 10 * 1024 * 1024:
                        raise AdapterResponseTooLargeError(
                            "Central API Artifact exceeds the client limit"
                        )
                if len(content) != declared_size or calculated.hexdigest() != digest:
                    raise AdapterProtocolError(
                        "Central API Artifact integrity validation failed"
                    )
                return bytes(content), media_type, digest, normalized_correlation
        except AdapterClientError:
            raise
        except httpx.TimeoutException as error:
            raise AdapterTimeoutError("Central API request timed out") from error
        except httpx.RequestError as error:
            raise AdapterTransportError("Central API connection failed") from error

    @staticmethod
    def _structured_digest(value: str) -> str:
        prefix = "sha-256=:"
        if not value.startswith(prefix) or not value.endswith(":"):
            raise AdapterProtocolError("Central API Artifact Digest is invalid")
        try:
            decoded = base64.b64decode(value[len(prefix):-1], validate=True)
        except (ValueError, binascii.Error) as error:
            raise AdapterProtocolError("Central API Artifact Digest is invalid") from error
        if len(decoded) != 32:
            raise AdapterProtocolError("Central API Artifact Digest is invalid")
        return decoded.hex()

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        headers: dict[str, str] | None = None,
        json_body: dict[str, Any] | None = None,
        content_body: bytes | None = None,
    ) -> tuple[dict[str, Any], str]:
        if json_body is not None and content_body is not None:
            raise ValueError("request cannot contain JSON and binary bodies together")
        correlation_id = str(uuid4())
        request_headers = {"X-Correlation-ID": correlation_id, **(headers or {})}
        if authenticated:
            request_headers["Authorization"] = f"Bearer {self._credential}"
        try:
            with self._client.stream(
                method,
                path,
                headers=request_headers,
                json=json_body,
                content=content_body,
            ) as response:
                if response.is_redirect:
                    raise AdapterProtocolError("Central API redirects are not allowed")
                body = self._read_bounded(response)
                response_correlation = response.headers.get("X-Correlation-ID")
                if response_correlation is None:
                    raise AdapterProtocolError(
                        "Central API response is missing X-Correlation-ID"
                    )
                try:
                    response_correlation = str(UUID(response_correlation))
                except ValueError as error:
                    raise AdapterProtocolError(
                        "Central API returned an invalid X-Correlation-ID"
                    ) from error
                if response_correlation != correlation_id:
                    raise AdapterProtocolError(
                        "Central API response correlation does not match the request"
                    )
                if not response.headers.get("content-type", "").lower().startswith(
                    "application/json"
                ):
                    raise AdapterProtocolError("Central API response is not JSON")
                try:
                    payload = json.loads(body)
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise AdapterProtocolError(
                        "Central API returned malformed JSON"
                    ) from error
                if not isinstance(payload, dict):
                    raise AdapterProtocolError("Central API response must be an object")
                if response.status_code >= 400:
                    self._raise_remote_error(
                        response.status_code, payload, response_correlation
                    )
                if not 200 <= response.status_code < 300:
                    raise AdapterProtocolError(
                        "Central API returned an unexpected status"
                    )
                return payload, response_correlation
        except AdapterClientError:
            raise
        except httpx.TimeoutException as error:
            raise AdapterTimeoutError("Central API request timed out") from error
        except httpx.RequestError as error:
            raise AdapterTransportError("Central API connection failed") from error

    def _read_bounded(self, response: httpx.Response) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_length = int(declared)
                if declared_length < 0:
                    raise ValueError
                if declared_length > self.config.max_response_bytes:
                    raise AdapterResponseTooLargeError(
                        "Central API response exceeds the configured limit"
                    )
            except ValueError as error:
                raise AdapterProtocolError("Central API Content-Length is invalid") from error
        content = bytearray()
        for chunk in response.iter_bytes():
            content.extend(chunk)
            if len(content) > self.config.max_response_bytes:
                raise AdapterResponseTooLargeError(
                    "Central API response exceeds the configured limit"
                )
        return bytes(content)

    @staticmethod
    def _raise_remote_error(
        status_code: int, payload: dict[str, Any], response_correlation: str
    ) -> None:
        try:
            error = _ErrorBody.model_validate(payload.get("error"))
        except ValidationError as validation_error:
            raise AdapterProtocolError(
                "Central API returned an invalid error envelope"
            ) from validation_error
        if error.correlation_id != response_correlation:
            raise AdapterProtocolError(
                "Central API error correlation identifiers do not match"
            )
        raise RemoteAPIError(
            status_code=status_code,
            code=error.code,
            message=error.message,
            retryable=error.retryable,
            correlation_id=error.correlation_id,
        )

    @staticmethod
    def _task(payload: dict[str, Any], correlation_id: str) -> RemoteTask:
        try:
            parsed = _TaskPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Task") from error
        return RemoteTask(
            parsed.id,
            parsed.project_id,
            parsed.assignee_agent_id,
            parsed.title,
            parsed.status,
            parsed.result,
            parsed.replayed,
            correlation_id,
        )

    @staticmethod
    def _workspace(payload: dict[str, Any], correlation_id: str) -> RemoteWorkspace:
        try:
            parsed = _WorkspacePayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Workspace") from error
        return RemoteWorkspace(
            parsed.id,
            parsed.task_id,
            parsed.actor_agent_id,
            parsed.repository,
            parsed.bound_at,
            parsed.replayed,
            correlation_id,
        )

    @staticmethod
    def _artifact(payload: dict[str, Any], correlation_id: str) -> RemoteArtifact:
        try:
            parsed = _ArtifactPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Artifact") from error
        return RemoteArtifact(
            parsed.id,
            parsed.task_id,
            parsed.media_type,
            parsed.purpose,
            parsed.declared_size,
            parsed.declared_sha256,
            parsed.status,
            parsed.actual_size,
            parsed.actual_sha256,
            parsed.created_at,
            parsed.uploaded_at,
            parsed.finalized_at,
            parsed.replayed,
            correlation_id,
        )

    @staticmethod
    def _evidence(payload: dict[str, Any], correlation_id: str) -> RemoteEvidence:
        try:
            parsed = _EvidencePayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned invalid Evidence") from error
        return RemoteEvidence(
            parsed.id,
            parsed.task_id,
            parsed.workspace_id,
            parsed.kind,
            parsed.attempt,
            parsed.retry_of,
            parsed.observed_at,
            parsed.head_commit,
            tuple(parsed.artifact_ids),
            parsed.status,
            parsed.payload_sha256,
            parsed.created_at,
            parsed.finalized_at,
            parsed.replayed,
            correlation_id,
        )

    @staticmethod
    def _approval(payload: dict[str, Any], correlation_id: str) -> RemoteApproval:
        try:
            value = _ApprovalPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Approval") from error
        return RemoteApproval(
            value.id, value.status, value.requester_agent_id,
            value.receiving_agent_id, value.task_id, value.repository,
            value.action, value.scope, value.risk, value.policy_version,
            value.requested_at, value.expires_at, value.resolved_by_owner_id,
            value.resolved_at, value.reason, value.replayed, correlation_id,
        )

    @staticmethod
    def _action_grant(
        payload: dict[str, Any], correlation_id: str
    ) -> RemoteActionGrant:
        try:
            value = _ActionGrantPayload.model_validate(payload)
        except ValidationError as error:
            raise AdapterProtocolError("Central API returned an invalid Action Grant") from error
        receipt = None
        if value.receipt is not None:
            receipt = RemoteActionReceipt(
                value.receipt.operation_id,
                value.receipt.request_fingerprint,
                value.receipt.external_action_id,
                value.receipt.result_reference,
                value.receipt.occurred_at,
            )
        return RemoteActionGrant(
            value.approval_id, value.operation_id, value.request_fingerprint,
            value.workspace_id, value.evidence_id, value.commit_sha,
            value.execute_before, value.status, value.started_at, receipt,
            value.replayed, correlation_id,
        )

    def _action_arguments(
        self, approval_id: str, request_fingerprint: str, idempotency_key: str
    ) -> None:
        self._identifier(approval_id, "approval_id")
        self._identifier(idempotency_key, "idempotency_key", minimum=16, maximum=128)
        if (
            not isinstance(request_fingerprint, str)
            or len(request_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in request_fingerprint)
        ):
            raise ValueError("request_fingerprint must be lowercase SHA-256")

    @staticmethod
    def _bounded_text(value: str, field: str, maximum: int) -> None:
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ValueError(f"{field} must be 1..{maximum} non-whitespace characters")

    @staticmethod
    def _commit(value: str) -> None:
        if (
            not isinstance(value, str)
            or len(value) not in (40, 64)
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise ValueError("commit must be a full lowercase hexadecimal object ID")

    @staticmethod
    def _identifier(
        value: str, field: str, *, minimum: int = 1, maximum: int = 255
    ) -> None:
        if (
            not isinstance(value, str)
            or not minimum <= len(value) <= maximum
            or not value[0].isalnum()
            or any(
                not (
                    character.isascii()
                    and (character.isalnum() or character in "._:-")
                )
                for character in value
            )
        ):
            raise ValueError(
                f"{field} must be {minimum}..{maximum} safe identifier characters"
            )
