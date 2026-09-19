"""Versioned team-memory candidates promoted from validated Work Records."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import re
from pathlib import PurePosixPath

from .collaboration import TaskId
from .epistemic import EpistemicEvent, EpistemicEventId, EpistemicStatus
from .evidence import EvidenceId
from .identity import AgentId, DomainValidationError, ProjectId, TeamId, validate_repository_name
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


class ApplicabilityReason(StrEnum):
    EXACT_COMMIT = "exact_commit"
    SCOPED_PATHS_UNCHANGED = "scoped_paths_unchanged"
    SCOPED_PATHS_CHANGED = "scoped_paths_changed"
    REPOSITORY_MISMATCH = "repository_mismatch"
    REF_MISMATCH = "ref_mismatch"
    INVALID_WORKTREE = "invalid_worktree"
    MEMORY_COMMIT_MISSING = "memory_commit_missing"
    MEMORY_COMMIT_NOT_ANCESTOR = "memory_commit_not_ancestor"
    WORKTREE_CHANGED_DURING_CHECK = "worktree_changed_during_check"
    GIT_CHECK_FAILED = "git_check_failed"


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
        if not isinstance(self.applicability_status, ApplicabilityStatus): raise TypeError("applicability_status must use ApplicabilityStatus")
        if self.promotion_rule_id != "validated_work_record_v1": raise DomainValidationError("promotion rule is unsupported")
        if not isinstance(self.promoted_at, datetime) or self.promoted_at.tzinfo is None or self.promoted_at.utcoffset() != timedelta(0): raise DomainValidationError("promoted_at must use UTC")


@dataclass(frozen=True, slots=True)
class MemorySearchQuery:
    text: str
    team_id: TeamId
    project_id: ProjectId
    repository: str
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
        validate_repository_name(self.repository)
        if self.validation_status is not None and not isinstance(self.validation_status, MemoryValidationStatus):
            raise TypeError("validation_status must use MemoryValidationStatus")
        if self.applicability_status is not None and not isinstance(self.applicability_status, ApplicabilityStatus):
            raise TypeError("applicability_status must use ApplicabilityStatus")
        if not isinstance(self.limit, int) or isinstance(self.limit, bool) or not 1 <= self.limit <= 100:
            raise DomainValidationError("search limit must be 1..100")


@dataclass(frozen=True, slots=True)
class MemoryCodeScope:
    memory_id: MemoryId
    source_evidence_id: EvidenceId
    repository: str
    ref: str
    commit: str
    paths: tuple[str, ...]

    def __post_init__(self) -> None:
        validate_repository_name(self.repository)
        if not isinstance(self.ref, str) or not self.ref.strip() or len(self.ref) > 255:
            raise DomainValidationError("ref must be 1..255 characters")
        if len(self.commit) not in (40, 64) or any(c not in "0123456789abcdef" for c in self.commit):
            raise DomainValidationError("commit must be a full object ID")
        if not self.paths or tuple(sorted(set(self.paths))) != self.paths or any(not p or PurePosixPath(p).is_absolute() or ".." in PurePosixPath(p).parts or str(PurePosixPath(p)) != p for p in self.paths):
            raise DomainValidationError("paths must be unique sorted repository-relative paths")


@dataclass(frozen=True, slots=True)
class MemoryApplicabilityAssessment:
    id: str
    memory_id: MemoryId
    sequence: int
    previous_assessment_id: str | None
    status: ApplicabilityStatus
    reason: ApplicabilityReason
    memory_commit: str
    current_commit: str | None
    changed_paths: tuple[str, ...]
    checked_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip() or len(self.id) > 255:
            raise DomainValidationError("assessment id must be 1..255 characters")
        if not isinstance(self.memory_id, MemoryId):
            raise TypeError("memory_id must be MemoryId")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise DomainValidationError("assessment sequence must be positive")
        if self.sequence == 1 and self.previous_assessment_id is not None:
            raise DomainValidationError("first assessment cannot have a predecessor")
        if self.sequence > 1 and (not isinstance(self.previous_assessment_id, str) or not self.previous_assessment_id.strip()):
            raise DomainValidationError("later assessment must cite its predecessor")
        if self.status is ApplicabilityStatus.SUPERSEDED:
            raise DomainValidationError("superseded is owned by Memory revision")
        if not isinstance(self.status, ApplicabilityStatus) or not isinstance(self.reason, ApplicabilityReason):
            raise TypeError("assessment status and reason must use domain enums")
        expected_status = {
            ApplicabilityReason.EXACT_COMMIT: ApplicabilityStatus.EXACT,
            ApplicabilityReason.SCOPED_PATHS_UNCHANGED: ApplicabilityStatus.COMPATIBLE,
            ApplicabilityReason.SCOPED_PATHS_CHANGED: ApplicabilityStatus.POSSIBLY_STALE,
            ApplicabilityReason.REPOSITORY_MISMATCH: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.REF_MISMATCH: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.INVALID_WORKTREE: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.MEMORY_COMMIT_MISSING: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.MEMORY_COMMIT_NOT_ANCESTOR: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.WORKTREE_CHANGED_DURING_CHECK: ApplicabilityStatus.UNKNOWN,
            ApplicabilityReason.GIT_CHECK_FAILED: ApplicabilityStatus.UNKNOWN,
        }[self.reason]
        if self.status is not expected_status:
            raise DomainValidationError("assessment status does not match reason")
        if self.reason is ApplicabilityReason.SCOPED_PATHS_CHANGED and not self.changed_paths:
            raise DomainValidationError("changed scope requires changed_paths")
        if self.reason is not ApplicabilityReason.SCOPED_PATHS_CHANGED and self.changed_paths:
            raise DomainValidationError("changed_paths are only valid for changed scope")
        if len(self.memory_commit) not in (40, 64) or any(c not in "0123456789abcdef" for c in self.memory_commit):
            raise DomainValidationError("memory_commit must be a full object ID")
        if self.current_commit is not None and (
            len(self.current_commit) not in (40, 64)
            or any(c not in "0123456789abcdef" for c in self.current_commit)
        ):
            raise DomainValidationError("current_commit must be a full object ID")
        if self.status is ApplicabilityStatus.EXACT and self.current_commit != self.memory_commit:
            raise DomainValidationError("exact assessment requires the Memory commit")
        if self.status in (ApplicabilityStatus.COMPATIBLE, ApplicabilityStatus.POSSIBLY_STALE) and self.current_commit is None:
            raise DomainValidationError("determinate assessment requires current_commit")
        if self.status is ApplicabilityStatus.COMPATIBLE and self.current_commit == self.memory_commit:
            raise DomainValidationError("compatible assessment requires a later commit")
        if tuple(sorted(set(self.changed_paths))) != self.changed_paths:
            raise DomainValidationError("changed_paths must be unique and sorted")
        if any(not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts for path in self.changed_paths):
            raise DomainValidationError("changed_paths must be repository-relative")
        if not isinstance(self.checked_at, datetime) or self.checked_at.tzinfo is None or self.checked_at.utcoffset() != timedelta(0):
            raise DomainValidationError("checked_at must use UTC")


@dataclass(frozen=True, slots=True)
class MemoryRevision:
    id: str
    superseded_memory_id: MemoryId
    replacement_memory_id: MemoryId
    actor_id: AgentId
    reason: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not self.id.strip() or len(self.id) > 255:
            raise DomainValidationError("revision id must be 1..255 characters")
        if not isinstance(self.superseded_memory_id, MemoryId) or not isinstance(self.replacement_memory_id, MemoryId):
            raise TypeError("revision endpoints must use MemoryId")
        if self.superseded_memory_id == self.replacement_memory_id:
            raise DomainValidationError("Memory cannot supersede itself")
        if not isinstance(self.actor_id, AgentId):
            raise TypeError("actor_id must use AgentId")
        if not isinstance(self.reason, str) or not self.reason.strip() or len(self.reason) > 1024:
            raise DomainValidationError("revision reason must be 1..1024 characters")
        if not isinstance(self.occurred_at, datetime) or self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise DomainValidationError("occurred_at must use UTC")


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
