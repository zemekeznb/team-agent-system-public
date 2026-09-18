"""Versioned team-memory candidates promoted from validated Work Records."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import re

from .collaboration import TaskId
from .epistemic import EpistemicEvent, EpistemicEventId, EpistemicStatus
from .evidence import EvidenceId
from .identity import AgentId, DomainValidationError, ProjectId, TeamId
from .work_record import WorkRecord, WorkRecordId, WorkRecordType


class MemoryValidationStatus(StrEnum):
    VALIDATED = "validated"
    INVALIDATED = "invalidated"


class ApplicabilityStatus(StrEnum):
    EXACT = "exact"
    COMPATIBLE = "compatible"
    POSSIBLY_STALE = "possibly_stale"
    SUPERSEDED = "superseded"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class MemoryId:
    value: str
    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip() or len(self.value) > 255:
            raise DomainValidationError("MemoryId must be 1..255 characters")


@dataclass(frozen=True, slots=True)
class TeamMemory:
    id: MemoryId
    source_work_record_id: WorkRecordId
    source_validation_event_id: EpistemicEventId
    task_id: TaskId
    source_actor_id: AgentId
    promoted_by_agent_id: AgentId
    record_type: WorkRecordType
    content: str
    validation_rule_id: str
    evidence_ids: tuple[EvidenceId, ...]
    validation_status: MemoryValidationStatus
    applicability_status: ApplicabilityStatus
    promotion_rule_id: str
    promoted_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, MemoryId): raise TypeError("id must be MemoryId")
        if not isinstance(self.source_work_record_id, WorkRecordId): raise TypeError("source_work_record_id must be WorkRecordId")
        if not isinstance(self.source_validation_event_id, EpistemicEventId): raise TypeError("source_validation_event_id must be EpistemicEventId")
        if not isinstance(self.task_id, TaskId): raise TypeError("task_id must be TaskId")
        if not isinstance(self.source_actor_id, AgentId) or not isinstance(self.promoted_by_agent_id, AgentId): raise TypeError("actors must use AgentId")
        if not isinstance(self.record_type, WorkRecordType): raise TypeError("record_type must be WorkRecordType")
        if not isinstance(self.content, str) or not self.content.strip() or len(self.content) > 65_536: raise DomainValidationError("content must be 1..65536 characters")
        if not isinstance(self.validation_rule_id, str) or not self.validation_rule_id.strip(): raise DomainValidationError("validation_rule_id is required")
        if not self.evidence_ids or len(set(self.evidence_ids)) != len(self.evidence_ids): raise DomainValidationError("unique validation Evidence is required")
        if self.validation_status is not MemoryValidationStatus.VALIDATED: raise DomainValidationError("new Memory must be validated")
        if self.applicability_status is not ApplicabilityStatus.UNKNOWN: raise DomainValidationError("new Memory applicability must be unknown")
        if self.promotion_rule_id != "validated_work_record_v1": raise DomainValidationError("promotion rule is unsupported")
        if not isinstance(self.promoted_at, datetime) or self.promoted_at.tzinfo is None or self.promoted_at.utcoffset() != timedelta(0): raise DomainValidationError("promoted_at must use UTC")


@dataclass(frozen=True, slots=True)
class MemorySearchQuery:
    text: str
    team_id: TeamId
    project_id: ProjectId
    validation_status: MemoryValidationStatus | None = None
    applicability_status: ApplicabilityStatus | None = None
    limit: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip() or len(self.text) > 1024:
            raise DomainValidationError("search text must be 1..1024 characters")
        terms = re.findall(r"\w+", self.text, flags=re.UNICODE)
        if not terms or len(terms) > 32 or any(ord(character) < 32 and not character.isspace() for character in self.text):
            raise DomainValidationError("search text must contain 1..32 safe terms")
        if not isinstance(self.team_id, TeamId) or not isinstance(self.project_id, ProjectId):
            raise TypeError("search scope must use TeamId and ProjectId")
        if self.validation_status is not None and not isinstance(self.validation_status, MemoryValidationStatus):
            raise TypeError("validation_status must use MemoryValidationStatus")
        if self.applicability_status is not None and not isinstance(self.applicability_status, ApplicabilityStatus):
            raise TypeError("applicability_status must use ApplicabilityStatus")
        if not isinstance(self.limit, int) or isinstance(self.limit, bool) or not 1 <= self.limit <= 100:
            raise DomainValidationError("search limit must be 1..100")


def promote_validated_work_record(record: WorkRecord, history: tuple[EpistemicEvent, ...], *, memory_id: MemoryId, promoted_by: AgentId, promoted_at: datetime) -> TeamMemory:
    if not history or history[-1].work_record_id != record.id or history[-1].to_status is not EpistemicStatus.VALIDATED:
        raise DomainValidationError("only a currently validated Work Record can be promoted")
    if any(
        event.work_record_id != record.id
        or event.sequence != index
        or (index == 1 and event.from_status is not None)
        or (index > 1 and event.from_status is not history[index - 2].to_status)
        for index, event in enumerate(history, 1)
    ):
        raise DomainValidationError("epistemic history is invalid")
    if record.claim_text is None:
        raise DomainValidationError("promotion requires explicit reusable content")
    validation = history[-1]
    available = {item.id for item in record.observed}
    if not validation.evidence_ids or any(item not in available for item in validation.evidence_ids):
        raise DomainValidationError("validation Evidence must belong to the Work Record")
    return TeamMemory(memory_id, record.id, validation.id, record.task_id, record.actor_id,
        promoted_by, record.record_type, record.claim_text, validation.rule_id,
        validation.evidence_ids, MemoryValidationStatus.VALIDATED,
        ApplicabilityStatus.UNKNOWN, "validated_work_record_v1", promoted_at)
