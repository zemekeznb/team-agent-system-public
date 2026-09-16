"""Application orchestration for delegating a TAS Task through an A2A port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tas.application.task_creation import (
    CreateTaskRequest,
    CreateTaskResult,
    CreateTaskService,
)
from tas.domain.collaboration import Task, TaskId, TaskStatus
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId
from tas.domain.ports import TaskRepository
from tas.observability.logging import get_logger


logger = get_logger("application.a2a_bridge")

TERMINAL_REMOTE_STATUSES = frozenset(
    {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.REJECTED,
    }
)


class A2ABridgeError(RuntimeError):
    """Stable application error that does not expose adapter internals."""

    def __init__(self, code: str, *, retryable: bool) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True, slots=True)
class A2ADelegationResult:
    remote_task_id: str
    status: TaskStatus
    artifact_reference: str | None
    content_trusted: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.remote_task_id, str) or not self.remote_task_id.strip():
            raise ValueError("remote_task_id must be non-blank text")
        if not isinstance(self.status, TaskStatus):
            raise TypeError("status must be TaskStatus")
        if self.artifact_reference is not None and (
            not isinstance(self.artifact_reference, str)
            or not self.artifact_reference.strip()
        ):
            raise ValueError("artifact_reference must be null or non-blank text")
        if self.content_trusted is not False:
            raise ValueError("external A2A content must remain untrusted")


class A2AGateway(Protocol):
    async def delegate(self, task: Task, *, trace_id: str) -> A2ADelegationResult: ...


class A2ADelegationResultRepository(Protocol):
    def get(self, task_id: TaskId) -> A2ADelegationResult | None: ...
    def save(self, task_id: TaskId, result: A2ADelegationResult) -> None: ...


@dataclass(frozen=True, slots=True)
class DelegateTaskResult:
    local_task_id: str
    replayed: bool
    remote_task_id: str
    status: str
    artifact_reference: str | None
    content_trusted: bool


class DelegateTaskService:
    def __init__(
        self,
        task_creation: CreateTaskService,
        task_repository: TaskRepository,
        result_repository: A2ADelegationResultRepository,
        gateway: A2AGateway,
    ) -> None:
        self._task_creation = task_creation
        self._task_repository = task_repository
        self._result_repository = result_repository
        self._gateway = gateway

    async def delegate(
        self,
        *,
        actor_id: AgentId,
        idempotency_key: IdempotencyKey,
        request: CreateTaskRequest,
        trace_id: str,
    ) -> DelegateTaskResult:
        if not isinstance(trace_id, str) or not trace_id.strip():
            raise ValueError("trace_id must be non-blank text")
        created = self._task_creation.create(actor_id, idempotency_key, request)
        task = self._task_repository.get_task(created.task_id)
        if task is None:
            raise RuntimeError("created Task cannot be loaded")
        prior = self._result_repository.get(created.task_id)
        if prior is not None:
            return self._result(created, prior)
        if task.status is TaskStatus.SUBMITTED:
            task = task.transition(
                TaskStatus.WORKING,
                actor_id=actor_id,
                reason="A2A delegation started",
            )
            self._task_repository.save_task(task)
        logger.info(
            "a2a.bridge.started",
            extra={
                "trace_id": trace_id,
                "actor_id": actor_id.value,
                "task_id": task.id.value,
            },
        )
        try:
            remote = await self._gateway.delegate(task, trace_id=trace_id)
        except A2ABridgeError as exc:
            if not exc.retryable and task.status is TaskStatus.WORKING:
                task = task.transition(
                    TaskStatus.FAILED,
                    actor_id=actor_id,
                    reason=f"A2A delegation failed: {exc.code}",
                )
                self._task_repository.save_task(task)
            logger.warning(
                "a2a.bridge.failed",
                extra={
                    "trace_id": trace_id,
                    "actor_id": actor_id.value,
                    "task_id": task.id.value,
                    "error_code": exc.code,
                    "retryable": exc.retryable,
                },
            )
            raise

        target = remote.status
        reason = f"Remote A2A Task {remote.remote_task_id} reported {target.value}"
        resumed = False
        if (
            task.status is TaskStatus.INPUT_REQUIRED
            and target is not TaskStatus.INPUT_REQUIRED
        ):
            task = task.transition(
                TaskStatus.WORKING,
                actor_id=actor_id,
                reason="Remote A2A Task resumed after input-required",
            )
            resumed = True
        if task.status is TaskStatus.WORKING:
            if target is TaskStatus.COMPLETED:
                result = "Remote A2A Task completed"
                if remote.artifact_reference is not None:
                    result = f"{result}; artifact: {remote.artifact_reference}"
                task = task.transition(
                    TaskStatus.COMPLETED,
                    actor_id=actor_id,
                    reason=reason,
                    result=result,
                )
            elif target in {
                TaskStatus.INPUT_REQUIRED,
                TaskStatus.FAILED,
                TaskStatus.CANCELLED,
            }:
                task = task.transition(target, actor_id=actor_id, reason=reason)
            elif target is TaskStatus.REJECTED:
                task = task.transition(
                    TaskStatus.FAILED,
                    actor_id=actor_id,
                    reason=f"Remote A2A Task {remote.remote_task_id} was rejected",
                )
            if task.status is not TaskStatus.WORKING:
                self._task_repository.save_task(task)
            elif resumed:
                self._task_repository.save_task(task)
        logger.info(
            "a2a.bridge.completed",
            extra={
                "trace_id": trace_id,
                "actor_id": actor_id.value,
                "task_id": task.id.value,
                "remote_task_id": remote.remote_task_id,
                "remote_status": remote.status.value,
            },
        )
        if remote.status in TERMINAL_REMOTE_STATUSES:
            self._result_repository.save(created.task_id, remote)
        return DelegateTaskResult(
            local_task_id=created.task_id.value,
            replayed=created.replayed,
            remote_task_id=remote.remote_task_id,
            status=remote.status.value,
            artifact_reference=remote.artifact_reference,
            content_trusted=remote.content_trusted,
        )

    @staticmethod
    def _result(
        created: CreateTaskResult, remote: A2ADelegationResult
    ) -> DelegateTaskResult:
        return DelegateTaskResult(
            local_task_id=created.task_id.value,
            replayed=created.replayed,
            remote_task_id=remote.remote_task_id,
            status=remote.status.value,
            artifact_reference=remote.artifact_reference,
            content_trusted=remote.content_trusted,
        )
