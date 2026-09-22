"""Application contracts for authoritative Evidence reservation and finalization."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.work_record import ObservedEvidenceKind


MAX_EVIDENCE_PAYLOAD_BYTES = 256 * 1024
MAX_EVIDENCE_ARTIFACTS = 32
MAX_EVIDENCE_JSON_DEPTH = 32
MAX_EVIDENCE_JSON_NODES = 10_000


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


def _commit(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DomainValidationError("head_commit must be a full hexadecimal object ID")


class EvidenceSubmissionStatus(StrEnum):
    RESERVED = "reserved"
    FINALIZED = "finalized"


@dataclass(frozen=True, slots=True)
class ReserveEvidenceCommand:
    task_id: TaskId
    workspace_id: WorkspaceBindingId
    kind: ObservedEvidenceKind
    attempt: int
    retry_of: EvidenceId | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[ArtifactId, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.workspace_id, WorkspaceBindingId):
            raise TypeError("workspace_id must be WorkspaceBindingId")
        if not isinstance(self.kind, ObservedEvidenceKind):
            raise TypeError("kind must be ObservedEvidenceKind")
        if (
            not isinstance(self.attempt, int)
            or isinstance(self.attempt, bool)
            or not 1 <= self.attempt <= 16
        ):
            raise DomainValidationError("attempt must be an integer from 1 to 16")
        if self.retry_of is not None and not isinstance(self.retry_of, EvidenceId):
            raise TypeError("retry_of must be EvidenceId or None")
        if self.kind is ObservedEvidenceKind.GIT:
            if self.attempt != 1 or self.retry_of is not None:
                raise DomainValidationError("Git Evidence cannot be a retry")
        elif (self.attempt == 1) != (self.retry_of is None):
            raise DomainValidationError("retry_of must match the Evidence attempt")
        _utc(self.observed_at, "observed_at")
        _commit(self.head_commit)
        if not isinstance(self.artifact_ids, tuple) or not all(
            isinstance(item, ArtifactId) for item in self.artifact_ids
        ):
            raise TypeError("artifact_ids must be a tuple of ArtifactId")
        if len(self.artifact_ids) > MAX_EVIDENCE_ARTIFACTS:
            raise DomainValidationError("Evidence links too many Artifacts")
        values = tuple(item.value for item in self.artifact_ids)
        if len(values) != len(set(values)):
            raise DomainValidationError("Evidence Artifact IDs must be unique")


@dataclass(frozen=True, slots=True)
class EvidenceSubmission:
    id: EvidenceId
    task_id: TaskId
    actor_id: AgentId
    workspace_id: WorkspaceBindingId
    kind: ObservedEvidenceKind
    attempt: int
    retry_of: EvidenceId | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[ArtifactId, ...]
    status: EvidenceSubmissionStatus
    payload_sha256: str | None
    created_at: datetime
    finalized_at: datetime | None

    def __post_init__(self) -> None:
        ReserveEvidenceCommand(
            self.task_id,
            self.workspace_id,
            self.kind,
            self.attempt,
            self.retry_of,
            self.observed_at,
            self.head_commit,
            self.artifact_ids,
        )
        if not isinstance(self.id, EvidenceId) or not isinstance(
            self.actor_id, AgentId
        ):
            raise TypeError("Evidence and actor IDs must use domain IDs")
        if not isinstance(self.status, EvidenceSubmissionStatus):
            raise TypeError("status must be EvidenceSubmissionStatus")
        _utc(self.created_at, "created_at")
        if self.status is EvidenceSubmissionStatus.RESERVED:
            if self.payload_sha256 is not None or self.finalized_at is not None:
                raise DomainValidationError("reserved Evidence has finalized state")
        else:
            if (
                not isinstance(self.payload_sha256, str)
                or len(self.payload_sha256) != 64
                or any(character not in "0123456789abcdef" for character in self.payload_sha256)
            ):
                raise DomainValidationError("finalized Evidence requires payload digest")
            if self.finalized_at is None:
                raise DomainValidationError("finalized Evidence requires finalized_at")
            _utc(self.finalized_at, "finalized_at")


@dataclass(frozen=True, slots=True)
class EvidenceSubmissionResult:
    evidence: EvidenceSubmission
    replayed: bool


def canonical_evidence_payload(value: str) -> tuple[str, dict[str, object]]:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > MAX_EVIDENCE_PAYLOAD_BYTES:
        raise DomainValidationError("Evidence payload exceeds the JSON limit")
    try:
        parsed = json.loads(
            value,
            parse_constant=lambda constant: (_ for _ in ()).throw(
                ValueError(f"non-standard JSON constant: {constant}")
            ),
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise DomainValidationError("Evidence payload must be valid JSON") from error
    if not isinstance(parsed, dict):
        raise DomainValidationError("Evidence payload must be a JSON object")
    _require_bounded_json(parsed)
    try:
        canonical = json.dumps(
            parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        )
    except (RecursionError, ValueError) as error:
        raise DomainValidationError("Evidence payload must be bounded JSON") from error
    if canonical != value:
        raise DomainValidationError("Evidence payload must use canonical JSON")
    return hashlib.sha256(value.encode("utf-8")).hexdigest(), parsed


def _require_bounded_json(value: object) -> None:
    pending = [(value, 1)]
    nodes = 0
    while pending:
        current, depth = pending.pop()
        nodes += 1
        if depth > MAX_EVIDENCE_JSON_DEPTH or nodes > MAX_EVIDENCE_JSON_NODES:
            raise DomainValidationError("Evidence payload JSON is too complex")
        if isinstance(current, dict):
            pending.extend((item, depth + 1) for item in current.values())
        elif isinstance(current, list):
            pending.extend((item, depth + 1) for item in current)


class EvidenceSubmissionUnitOfWork(Protocol):
    def reserve(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ReserveEvidenceCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EvidenceSubmissionResult: ...

    def finalize(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        evidence_id: EvidenceId,
        payload_json: str,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EvidenceSubmissionResult: ...


class EvidenceSubmissionService:
    def __init__(self, unit_of_work: EvidenceSubmissionUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def reserve(self, *args, **kwargs) -> EvidenceSubmissionResult:
        return self.unit_of_work.reserve(*args, **kwargs)

    def finalize(self, *args, **kwargs) -> EvidenceSubmissionResult:
        return self.unit_of_work.finalize(*args, **kwargs)
