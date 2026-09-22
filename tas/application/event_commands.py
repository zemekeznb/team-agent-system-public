"""Authenticated central-service contracts for CodeChangeImpact routing."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tas.domain.collaboration import TaskId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.delivery import InboxItemId
from tas.domain.events import CodeImpactKind, CollaborationEventId
from tas.domain.evidence import EvidenceId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError, ProjectId


@dataclass(frozen=True, slots=True)
class CreateCodeChangeImpactCommand:
    project_id: ProjectId
    target_agent_id: AgentId
    title: str
    repository: str
    ref: str
    baseline_commit: str
    head_commit: str
    changed_paths: tuple[str, ...]
    evidence_id: EvidenceId
    impact_kind: CodeImpactKind
    affected_api: str

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, ProjectId):
            raise TypeError("project_id must be ProjectId")
        if not isinstance(self.target_agent_id, AgentId):
            raise TypeError("target_agent_id must be AgentId")
        if not isinstance(self.title, str) or not self.title.strip() or len(self.title) > 4096:
            raise DomainValidationError("title must be 1..4096 non-whitespace characters")
        if (
            not isinstance(self.changed_paths, tuple)
            or not 1 <= len(self.changed_paths) <= 1000
        ):
            raise DomainValidationError("changed_paths must contain 1..1000 paths")


@dataclass(frozen=True, slots=True)
class CodeChangeImpactView:
    id: CollaborationEventId
    project_id: ProjectId
    publisher_agent_id: AgentId
    target_agent_id: AgentId
    task_id: TaskId
    inbox_item_id: InboxItemId
    title: str
    repository: str
    ref: str
    baseline_commit: str
    head_commit: str
    changed_paths: tuple[str, ...]
    evidence_id: EvidenceId
    impact_kind: CodeImpactKind
    affected_api: str
    occurred_at: datetime


@dataclass(frozen=True, slots=True)
class EventCommandResult:
    event: CodeChangeImpactView
    replayed: bool


class EventCommandUnitOfWork(Protocol):
    def create(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: CreateCodeChangeImpactCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EventCommandResult: ...

    def get(
        self,
        principal: AuthenticatedPrincipal,
        event_id: CollaborationEventId,
    ) -> CodeChangeImpactView | None: ...


class EventCommandService:
    def __init__(self, unit_of_work: EventCommandUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def create(self, *args, **kwargs) -> EventCommandResult:
        return self.unit_of_work.create(*args, **kwargs)

    def get(self, *args, **kwargs) -> CodeChangeImpactView | None:
        return self.unit_of_work.get(*args, **kwargs)
