"""Audited Task transition application boundary."""

from datetime import datetime

from tas.domain.collaboration import (
    InvalidTaskTransitionError,
    Task,
    TaskId,
    TaskStatus,
)
from tas.domain.identity import AgentId
from tas.domain.ports import IdentityReferenceError, TaskRepository

from .audit import AuditRecorder


class TaskTransitionService:
    def __init__(self, tasks: TaskRepository, audit: AuditRecorder) -> None:
        self.tasks = tasks
        self.audit = audit

    def transition(
        self,
        task_id: TaskId,
        target: TaskStatus,
        *,
        actor_id: AgentId,
        reason: str | None = None,
        result: str | None = None,
        occurred_at: datetime | None = None,
    ) -> Task:
        task = self.tasks.get_task(task_id)
        if task is None:
            raise IdentityReferenceError("task does not exist")
        try:
            changed = task.transition(
                target,
                actor_id=actor_id,
                reason=reason,
                result=result,
                occurred_at=occurred_at,
            )
        except InvalidTaskTransitionError as error:
            self.audit.task_transition_rejected(
                task, target, actor_id.value, str(error)
            )
            raise
        self.tasks.save_task(changed)
        return changed
