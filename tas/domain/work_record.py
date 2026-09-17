"""Append-only work facts with explicit claim/observation separation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .collaboration import TaskId
from .evidence import EvidenceId
from .identity import AgentId, DomainValidationError


def _text(value: str, field: str, maximum: int) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainValidationError(f"{field} must be 1..{maximum} non-whitespace characters")


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class WorkRecordId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "WorkRecordId", 255)


class WorkRecordType(StrEnum):
    OBSERVATION = "observation"
    HYPOTHESIS = "hypothesis"
    DECISION = "decision"
    ACTION_INTENT = "action_intent"
    ACTION_RECEIPT = "action_receipt"
    RESULT = "result"
    VALIDATION = "validation"
    AUTHORIZATION = "authorization"


class ObservedEvidenceKind(StrEnum):
    GIT = "git"
    COMMAND_TEST = "command_test"


@dataclass(frozen=True, slots=True)
class ObservedEvidence:
    id: EvidenceId
    task_id: TaskId
    actor_id: AgentId
    kind: ObservedEvidenceKind
    payload_json: str
    payload_sha256: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise TypeError("id must be EvidenceId")
        if not isinstance(self.task_id, TaskId) or not isinstance(self.actor_id, AgentId):
            raise TypeError("task_id and actor_id must use domain IDs")
        if not isinstance(self.kind, ObservedEvidenceKind):
            raise TypeError("kind must be ObservedEvidenceKind")
        _text(self.payload_json, "payload_json", 1_000_000)
        try:
            parsed = json.loads(self.payload_json)
        except json.JSONDecodeError as error:
            raise DomainValidationError("payload_json must be valid JSON") from error
        canonical = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if canonical != self.payload_json:
            raise DomainValidationError("payload_json must use canonical JSON")
        expected = hashlib.sha256(self.payload_json.encode("utf-8")).hexdigest()
        if self.payload_sha256 != expected:
            raise DomainValidationError("payload_sha256 does not match payload_json")
        _utc(self.observed_at, "observed_at")


@dataclass(frozen=True, slots=True)
class WorkRecord:
    id: WorkRecordId
    task_id: TaskId
    actor_id: AgentId
    record_type: WorkRecordType
    claim_text: str | None
    observed: tuple[ObservedEvidence, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, WorkRecordId):
            raise TypeError("id must be WorkRecordId")
        if not isinstance(self.task_id, TaskId) or not isinstance(self.actor_id, AgentId):
            raise TypeError("task_id and actor_id must use domain IDs")
        if not isinstance(self.record_type, WorkRecordType):
            raise TypeError("record_type must be WorkRecordType")
        if self.claim_text is not None:
            _text(self.claim_text, "claim_text", 65_536)
        if not isinstance(self.observed, tuple) or not all(
            isinstance(item, ObservedEvidence) for item in self.observed
        ):
            raise TypeError("observed must be a tuple of ObservedEvidence")
        if self.claim_text is None and not self.observed:
            raise DomainValidationError("Work Record requires a claim or observed Evidence")
        if len(self.observed) > 100:
            raise DomainValidationError("Work Record cannot link more than 100 Evidence items")
        ids = [item.id.value for item in self.observed]
        if len(ids) != len(set(ids)):
            raise DomainValidationError("observed Evidence IDs must be unique")
        if any(
            item.task_id != self.task_id or item.actor_id != self.actor_id
            for item in self.observed
        ):
            raise DomainValidationError("observed Evidence must match Work Record scope")
        _utc(self.created_at, "created_at")
