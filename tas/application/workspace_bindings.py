"""Authenticated central-service contracts for opaque Task workspace bindings."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tas.domain.collaboration import TaskId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.evidence import WorkspaceBindingId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError


@dataclass(frozen=True, slots=True)
class RegisterWorkspaceCommand:
    task_id: TaskId
    repository: str

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if (
            not isinstance(self.repository, str)
            or not self.repository.strip()
            or len(self.repository) > 255
        ):
            raise DomainValidationError(
                "repository must be 1..255 non-whitespace characters"
            )


@dataclass(frozen=True, slots=True)
class WorkspaceView:
    id: WorkspaceBindingId
    task_id: TaskId
    actor_agent_id: AgentId
    repository: str
    bound_at: datetime


@dataclass(frozen=True, slots=True)
class WorkspaceCommandResult:
    workspace: WorkspaceView
    replayed: bool


class WorkspaceBindingUnitOfWork(Protocol):
    def register(
        self, actor_id: AgentId, key: IdempotencyKey,
        command: RegisterWorkspaceCommand,
        *, now: datetime, correlation_id: str,
    ) -> WorkspaceCommandResult: ...

    def get(
        self, principal: AuthenticatedPrincipal, workspace_id: WorkspaceBindingId
    ) -> WorkspaceView | None: ...


class WorkspaceBindingService:
    def __init__(self, unit_of_work: WorkspaceBindingUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def register(self, *args, **kwargs) -> WorkspaceCommandResult:
        return self.unit_of_work.register(*args, **kwargs)

    def get(self, *args, **kwargs) -> WorkspaceView | None:
        return self.unit_of_work.get(*args, **kwargs)
