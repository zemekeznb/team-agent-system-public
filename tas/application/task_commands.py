"""F3 Task mutation commands with explicit idempotency boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from tas.domain.collaboration import Task, TaskId, TaskStatus
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


@dataclass(frozen=True, slots=True)
class TransitionTaskCommand:
    task_id: TaskId
    target: TaskStatus
    reason: str | None = None
    result: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.target, TaskStatus):
            raise TypeError("target must be TaskStatus")


@dataclass(frozen=True, slots=True)
class TransitionTaskResult:
    task: Task
    replayed: bool


class TaskTransitionUnitOfWork(Protocol):
    def transition(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: TransitionTaskCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> TransitionTaskResult: ...


class TransitionTaskService:
    def __init__(self, unit_of_work: TaskTransitionUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def transition(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: TransitionTaskCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> TransitionTaskResult:
        if not isinstance(actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if not isinstance(key, IdempotencyKey):
            raise TypeError("key must be IdempotencyKey")
        if not isinstance(command, TransitionTaskCommand):
            raise TypeError("command must be TransitionTaskCommand")
        return self.unit_of_work.transition(
            actor_id,
            key,
            command,
            occurred_at=occurred_at,
            correlation_id=correlation_id,
        )
