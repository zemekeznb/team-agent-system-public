"""Technology-independent collaboration aggregate for F2-011."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from .identity import AgentId, DomainValidationError, ProjectId


def _text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError(f"{field} must not be blank")


def _typed(value: object, expected: type[object], field: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"{field} must be {expected.__name__}")


def _aware(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DomainValidationError(f"{field} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class TaskId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "TaskId")


@dataclass(frozen=True, slots=True)
class TaskMessageId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "TaskMessageId")


@dataclass(frozen=True, slots=True)
class ArtifactId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "ArtifactId")


class TaskStatus(StrEnum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input_required"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    FAILED = "failed"
    CANCELLED = "cancelled"
    COMPLETED = "completed"


ALLOWED_TRANSITIONS: dict[TaskStatus, frozenset[TaskStatus]] = {
    TaskStatus.SUBMITTED: frozenset({TaskStatus.WORKING, TaskStatus.REJECTED, TaskStatus.EXPIRED, TaskStatus.CANCELLED}),
    TaskStatus.WORKING: frozenset({TaskStatus.INPUT_REQUIRED, TaskStatus.APPROVAL_REQUIRED, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.COMPLETED}),
    TaskStatus.INPUT_REQUIRED: frozenset({TaskStatus.WORKING, TaskStatus.CANCELLED}),
    TaskStatus.APPROVAL_REQUIRED: frozenset({TaskStatus.APPROVED, TaskStatus.REJECTED, TaskStatus.CANCELLED}),
    TaskStatus.APPROVED: frozenset({TaskStatus.WORKING, TaskStatus.CANCELLED}),
}


class InvalidTaskTransitionError(DomainValidationError):
    """Raised when a Task state change violates the transition matrix."""


@dataclass(frozen=True, slots=True)
class TaskTransition:
    from_status: TaskStatus
    to_status: TaskStatus
    actor_id: AgentId
    reason: str | None
    occurred_at: datetime

    def __post_init__(self) -> None:
        _typed(self.actor_id, AgentId, "actor_id")
        _aware(self.occurred_at, "occurred_at")
        if self.reason is not None:
            _text(self.reason, "reason")


@dataclass(frozen=True, slots=True)
class Task:
    id: TaskId
    project_id: ProjectId
    assignee_agent_id: AgentId
    title: str
    status: TaskStatus = TaskStatus.SUBMITTED
    result: str | None = None
    transitions: tuple[TaskTransition, ...] = ()

    def __post_init__(self) -> None:
        _typed(self.id, TaskId, "id")
        _typed(self.project_id, ProjectId, "project_id")
        _typed(self.assignee_agent_id, AgentId, "assignee_agent_id")
        _typed(self.status, TaskStatus, "status")
        _text(self.title, "Task title")
        if self.status is TaskStatus.COMPLETED:
            _text(self.result or "", "completed Task result")
        elif self.result is not None:
            raise DomainValidationError("result is only valid for a completed Task")
        expected = TaskStatus.SUBMITTED
        previous_time: datetime | None = None
        for transition in self.transitions:
            if transition.from_status is not expected:
                raise DomainValidationError("Task transition history is not contiguous")
            if transition.to_status not in ALLOWED_TRANSITIONS.get(
                transition.from_status, frozenset()
            ):
                raise DomainValidationError("Task transition history is invalid")
            if (
                previous_time is not None
                and transition.occurred_at < previous_time
            ):
                raise DomainValidationError(
                    "Task transition history must be chronological"
                )
            previous_time = transition.occurred_at
            expected = transition.to_status
        if self.status is not expected:
            raise DomainValidationError("Task status does not match transition history")

    def transition(
        self,
        target: TaskStatus,
        *,
        actor_id: AgentId,
        reason: str | None = None,
        result: str | None = None,
        occurred_at: datetime | None = None,
    ) -> Task:
        _typed(target, TaskStatus, "target")
        if target not in ALLOWED_TRANSITIONS.get(self.status, frozenset()):
            raise InvalidTaskTransitionError(
                f"Task cannot transition from {self.status.value} to {target.value}"
            )
        if target is TaskStatus.COMPLETED:
            if not isinstance(result, str) or not result.strip():
                raise InvalidTaskTransitionError(
                    "completed Task result must not be blank"
                )
        elif result is not None:
            raise InvalidTaskTransitionError("result is only valid when completing a Task")
        record = TaskTransition(
            self.status,
            target,
            actor_id,
            reason,
            occurred_at or datetime.now(UTC),
        )
        return replace(self, status=target, result=result, transitions=(*self.transitions, record))

@dataclass(frozen=True, slots=True)
class TaskMessage:
    id: TaskMessageId
    task_id: TaskId
    author_agent_id: AgentId
    body: str
    created_at: datetime

    def __post_init__(self) -> None:
        _typed(self.id, TaskMessageId, "id")
        _typed(self.task_id, TaskId, "task_id")
        _typed(self.author_agent_id, AgentId, "author_agent_id")
        _text(self.body, "Message body")
        _aware(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class Artifact:
    id: ArtifactId
    task_id: TaskId
    producer_agent_id: AgentId
    reference: str
    media_type: str
    created_at: datetime

    def __post_init__(self) -> None:
        _typed(self.id, ArtifactId, "id")
        _typed(self.task_id, TaskId, "task_id")
        _typed(self.producer_agent_id, AgentId, "producer_agent_id")
        _text(self.reference, "Artifact reference")
        _text(self.media_type, "Artifact media_type")
        _aware(self.created_at, "created_at")
