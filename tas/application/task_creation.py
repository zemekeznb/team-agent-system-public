"""Idempotent Task creation application use case."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tas.domain.collaboration import TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError, ProjectId


@dataclass(frozen=True, slots=True)
class CreateTaskRequest:
    project_id: ProjectId
    assignee_agent_id: AgentId
    title: str

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, ProjectId):
            raise TypeError("project_id must be ProjectId")
        if not isinstance(self.assignee_agent_id, AgentId):
            raise TypeError("assignee_agent_id must be AgentId")
        if not isinstance(self.title, str) or not self.title.strip():
            raise DomainValidationError("Task title must not be blank")


@dataclass(frozen=True, slots=True)
class CreateTaskResult:
    task_id: TaskId
    replayed: bool


class TaskCreationUnitOfWork(Protocol):
    def create_task(
        self,
        actor_id: AgentId,
        idempotency_key: IdempotencyKey,
        request: CreateTaskRequest,
    ) -> CreateTaskResult: ...


class CreateTaskService:
    def __init__(self, unit_of_work: TaskCreationUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def create(
        self,
        authenticated_actor_id: AgentId,
        idempotency_key: IdempotencyKey,
        request: CreateTaskRequest,
    ) -> CreateTaskResult:
        if not isinstance(authenticated_actor_id, AgentId):
            raise TypeError("authenticated_actor_id must be AgentId")
        if not isinstance(idempotency_key, IdempotencyKey):
            raise TypeError("idempotency_key must be IdempotencyKey")
        if not isinstance(request, CreateTaskRequest):
            raise TypeError("request must be CreateTaskRequest")
        return self.unit_of_work.create_task(
            authenticated_actor_id, idempotency_key, request
        )
