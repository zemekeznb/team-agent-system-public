"""Central-service contracts for Work Record writes and trusted knowledge reads."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tas.domain.collaboration import TaskId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.epistemic import EpistemicEventId, EpistemicStatus
from tas.domain.evidence import EvidenceId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError, ProjectId
from tas.domain.memory import (
    ApplicabilityStatus,
    MemoryApplicabilityAssessment,
    MemoryCodeScope,
    MemoryId,
    MemoryValidationStatus,
    TeamMemory,
)
from tas.domain.work_record import WorkRecord, WorkRecordId, WorkRecordType


MAX_WORK_RECORD_EVIDENCE = 100


@dataclass(frozen=True, slots=True)
class CreateWorkRecordCommand:
    task_id: TaskId
    record_type: WorkRecordType
    claim_text: str | None
    evidence_ids: tuple[EvidenceId, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.record_type, WorkRecordType):
            raise TypeError("record_type must be WorkRecordType")
        if self.claim_text is not None and (
            not isinstance(self.claim_text, str)
            or not self.claim_text.strip()
            or len(self.claim_text) > 65_536
        ):
            raise DomainValidationError(
                "claim_text must be 1..65536 non-whitespace characters"
            )
        if not isinstance(self.evidence_ids, tuple) or not all(
            isinstance(item, EvidenceId) for item in self.evidence_ids
        ):
            raise TypeError("evidence_ids must be a tuple of EvidenceId")
        if len(self.evidence_ids) > MAX_WORK_RECORD_EVIDENCE:
            raise DomainValidationError("Work Record links too many Evidence items")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise DomainValidationError("Work Record Evidence IDs must be unique")
        if self.claim_text is None and not self.evidence_ids:
            raise DomainValidationError("Work Record requires a claim or Evidence")


@dataclass(frozen=True, slots=True)
class WorkRecordView:
    record: WorkRecord
    current_status: EpistemicStatus
    latest_event_id: EpistemicEventId
    latest_sequence: int

    def __post_init__(self) -> None:
        if not isinstance(self.record, WorkRecord):
            raise TypeError("record must be WorkRecord")
        if not isinstance(self.current_status, EpistemicStatus):
            raise TypeError("current_status must be EpistemicStatus")
        if not isinstance(self.latest_event_id, EpistemicEventId):
            raise TypeError("latest_event_id must be EpistemicEventId")
        if not isinstance(self.latest_sequence, int) or self.latest_sequence < 1:
            raise DomainValidationError("latest_sequence must be positive")


@dataclass(frozen=True, slots=True)
class WorkRecordCommandResult:
    view: WorkRecordView
    replayed: bool


@dataclass(frozen=True, slots=True)
class PromoteMemoryCommand:
    source_work_record_id: WorkRecordId
    code_scope_evidence_id: EvidenceId

    def __post_init__(self) -> None:
        if not isinstance(self.source_work_record_id, WorkRecordId):
            raise TypeError("source_work_record_id must be WorkRecordId")
        if not isinstance(self.code_scope_evidence_id, EvidenceId):
            raise TypeError("code_scope_evidence_id must be EvidenceId")


@dataclass(frozen=True, slots=True)
class MemoryCommandResult:
    view: MemoryView
    replayed: bool


@dataclass(frozen=True, slots=True)
class MemorySearchRequest:
    text: str
    project_id: ProjectId
    repository: str
    validation_status: MemoryValidationStatus | None = None
    applicability_status: ApplicabilityStatus | None = None
    limit: int = 20

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, ProjectId):
            raise TypeError("project_id must be ProjectId")
        if not isinstance(self.text, str) or not self.text.strip():
            raise DomainValidationError("Memory search text is required")
        if not isinstance(self.repository, str) or not self.repository.strip():
            raise DomainValidationError("repository is required")
        if self.validation_status is not None and not isinstance(
            self.validation_status, MemoryValidationStatus
        ):
            raise TypeError("validation_status must use MemoryValidationStatus")
        if self.applicability_status is not None and not isinstance(
            self.applicability_status, ApplicabilityStatus
        ):
            raise TypeError("applicability_status must use ApplicabilityStatus")
        if (
            not isinstance(self.limit, int)
            or isinstance(self.limit, bool)
            or not 1 <= self.limit <= 100
        ):
            raise DomainValidationError("limit must be 1..100")


@dataclass(frozen=True, slots=True)
class MemoryView:
    memory: TeamMemory
    code_scope: MemoryCodeScope | None
    latest_applicability: MemoryApplicabilityAssessment | None
    replacement_memory_id: MemoryId | None

    def __post_init__(self) -> None:
        if not isinstance(self.memory, TeamMemory):
            raise TypeError("memory must be TeamMemory")
        if self.code_scope is not None and not isinstance(
            self.code_scope, MemoryCodeScope
        ):
            raise TypeError("code_scope must be MemoryCodeScope or None")
        if self.latest_applicability is not None and not isinstance(
            self.latest_applicability, MemoryApplicabilityAssessment
        ):
            raise TypeError(
                "latest_applicability must be MemoryApplicabilityAssessment or None"
            )
        if self.replacement_memory_id is not None and not isinstance(
            self.replacement_memory_id, MemoryId
        ):
            raise TypeError("replacement_memory_id must be MemoryId or None")


class KnowledgeAccessUnitOfWork(Protocol):
    def create_work_record(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: CreateWorkRecordCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> WorkRecordCommandResult: ...

    def promote_memory(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: PromoteMemoryCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> MemoryCommandResult: ...

    def get_work_record(
        self, principal: AuthenticatedPrincipal, record_id: WorkRecordId
    ) -> WorkRecordView | None: ...

    def get_memory(
        self, principal: AuthenticatedPrincipal, memory_id: MemoryId
    ) -> MemoryView | None: ...

    def search_memories(
        self, principal: AuthenticatedPrincipal, request: MemorySearchRequest
    ) -> tuple[MemoryView, ...]: ...


class KnowledgeAccessService:
    def __init__(self, unit_of_work: KnowledgeAccessUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def create_work_record(self, *args, **kwargs) -> WorkRecordCommandResult:
        return self.unit_of_work.create_work_record(*args, **kwargs)

    def promote_memory(self, *args, **kwargs) -> MemoryCommandResult:
        return self.unit_of_work.promote_memory(*args, **kwargs)

    def get_work_record(
        self, principal: AuthenticatedPrincipal, record_id: WorkRecordId
    ) -> WorkRecordView | None:
        return self.unit_of_work.get_work_record(principal, record_id)

    def get_memory(
        self, principal: AuthenticatedPrincipal, memory_id: MemoryId
    ) -> MemoryView | None:
        return self.unit_of_work.get_memory(principal, memory_id)

    def search_memories(
        self, principal: AuthenticatedPrincipal, request: MemorySearchRequest
    ) -> tuple[MemoryView, ...]:
        return self.unit_of_work.search_memories(principal, request)
