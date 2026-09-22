"""Application commands for bounded central Artifact ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError


MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_TASK_ARTIFACT_BYTES = 50 * 1024 * 1024


class ArtifactUploadStatus(StrEnum):
    RESERVED = "reserved"
    UPLOADED = "uploaded"
    FINALIZED = "finalized"


class ArtifactPurpose(StrEnum):
    TEST_STDOUT = "test_stdout"
    TEST_STDERR = "test_stderr"
    GIT_DIFF = "git_diff"
    RESULT = "result"
    OTHER = "other"


ALLOWED_ARTIFACT_MEDIA_TYPES = frozenset(
    {"application/json", "application/octet-stream", "text/plain"}
)


def _sha256(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DomainValidationError("sha256 must be lowercase hexadecimal")


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class ReserveArtifactCommand:
    task_id: TaskId
    media_type: str
    declared_size: int
    declared_sha256: str
    purpose: ArtifactPurpose

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if self.media_type not in ALLOWED_ARTIFACT_MEDIA_TYPES:
            raise DomainValidationError("media_type is unsupported")
        if (
            not isinstance(self.declared_size, int)
            or isinstance(self.declared_size, bool)
            or not 0 <= self.declared_size <= MAX_ARTIFACT_BYTES
        ):
            raise DomainValidationError("declared_size exceeds the Artifact limit")
        _sha256(self.declared_sha256)
        if not isinstance(self.purpose, ArtifactPurpose):
            raise TypeError("purpose must be ArtifactPurpose")


@dataclass(frozen=True, slots=True)
class ArtifactUpload:
    id: ArtifactId
    task_id: TaskId
    producer_agent_id: AgentId
    media_type: str
    purpose: ArtifactPurpose
    declared_size: int
    declared_sha256: str
    status: ArtifactUploadStatus
    actual_size: int | None
    actual_sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None
    finalized_at: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.id, ArtifactId):
            raise TypeError("id must be ArtifactId")
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.producer_agent_id, AgentId):
            raise TypeError("producer_agent_id must be AgentId")
        if self.media_type not in ALLOWED_ARTIFACT_MEDIA_TYPES:
            raise DomainValidationError("media_type is unsupported")
        if not isinstance(self.purpose, ArtifactPurpose):
            raise TypeError("purpose must be ArtifactPurpose")
        if not isinstance(self.status, ArtifactUploadStatus):
            raise TypeError("status must be ArtifactUploadStatus")
        if (
            not isinstance(self.declared_size, int)
            or isinstance(self.declared_size, bool)
            or not 0 <= self.declared_size <= MAX_ARTIFACT_BYTES
        ):
            raise DomainValidationError("declared_size exceeds the Artifact limit")
        _sha256(self.declared_sha256)
        _utc(self.created_at, "created_at")
        if self.status is ArtifactUploadStatus.RESERVED:
            if any(
                value is not None
                for value in (
                    self.actual_size,
                    self.actual_sha256,
                    self.uploaded_at,
                    self.finalized_at,
                )
            ):
                raise DomainValidationError("reserved Artifact has upload state")
        else:
            if not isinstance(self.actual_size, int) or isinstance(
                self.actual_size, bool
            ):
                raise DomainValidationError("Artifact actual_size must be an integer")
            if self.actual_size != self.declared_size:
                raise DomainValidationError("Artifact size does not match reservation")
            if self.actual_sha256 != self.declared_sha256:
                raise DomainValidationError("Artifact digest does not match reservation")
            if self.uploaded_at is None:
                raise DomainValidationError("uploaded Artifact requires uploaded_at")
            _utc(self.uploaded_at, "uploaded_at")
            if self.status is ArtifactUploadStatus.FINALIZED:
                if self.finalized_at is None:
                    raise DomainValidationError("finalized Artifact requires finalized_at")
                _utc(self.finalized_at, "finalized_at")
            elif self.finalized_at is not None:
                raise DomainValidationError("uploaded Artifact cannot be finalized")


@dataclass(frozen=True, slots=True)
class ArtifactCommandResult:
    artifact: ArtifactUpload
    replayed: bool


class ArtifactUploadUnitOfWork(Protocol):
    def reserve(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ReserveArtifactCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def upload(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        staged_path: Path,
        actual_size: int,
        actual_sha256: str,
        content_sha256: str,
        media_type: str,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def finalize(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def record_rejection(
        self,
        actor_id: AgentId,
        artifact_id: ArtifactId,
        *,
        reason: str,
        now: datetime,
        correlation_id: str,
    ) -> None: ...


class ArtifactUploadService:
    def __init__(self, unit_of_work: ArtifactUploadUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def reserve(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.reserve(*args, **kwargs)

    def upload(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.upload(*args, **kwargs)

    def finalize(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.finalize(*args, **kwargs)

    def record_rejection(self, *args, **kwargs) -> None:
        self.unit_of_work.record_rejection(*args, **kwargs)
