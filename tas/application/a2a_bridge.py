"""Application orchestration for delegating a TAS Task through an A2A port."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from tas.application.task_creation import (
    CreateTaskRequest,
    CreateTaskResult,
    CreateTaskService,
)
from tas.domain.collaboration import Task, TaskId, TaskStatus
from tas.domain.delivery import require_utc
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

    def __init__(
        self, code: str, *, retryable: bool,
        request_may_have_been_sent: bool = True,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable
        self.request_may_have_been_sent = request_may_have_been_sent


@dataclass(frozen=True, slots=True)
class A2ADelegationResult:
    remote_task_id: str
    status: TaskStatus
    artifact_reference: str | None
    content_trusted: bool = False

    def __post_init__(self) -> None:
        if (
            not isinstance(self.remote_task_id, str)
            or not self.remote_task_id.strip()
            or len(self.remote_task_id) > 255
        ):
            raise ValueError("remote_task_id must be 1..255 non-blank characters")
        if not isinstance(self.status, TaskStatus):
            raise TypeError("status must be TaskStatus")
        if self.status not in {
            TaskStatus.SUBMITTED,
            TaskStatus.WORKING,
            TaskStatus.INPUT_REQUIRED,
            TaskStatus.REJECTED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.COMPLETED,
        }:
            raise ValueError("status is not supported by the A2A bridge")
        if self.artifact_reference is not None and (
            not isinstance(self.artifact_reference, str)
            or not self.artifact_reference.strip()
            or len(self.artifact_reference) > 2048
        ):
            raise ValueError("artifact_reference must be null or non-blank text")
        if self.content_trusted is not False:
            raise ValueError("external A2A content must remain untrusted")


class A2AGateway(Protocol):
    async def delegate(self, task: Task, *, trace_id: str) -> A2ADelegationResult: ...
    async def lookup(
        self, remote_task_id: str, *, trace_id: str
    ) -> A2ADelegationResult: ...


class A2ADelegationState(StrEnum):
    RESERVED = "reserved"
    NOT_SENT = "not_sent"
    SUBMITTING = "submitting"
    RESPONSE_UNKNOWN = "response_unknown"
    REMOTE_ACTIVE = "remote_active"
    REMOTE_TERMINAL_UNRECORDED = "remote_terminal_unrecorded"
    COMPLETED = "completed"
    FAILED_TERMINAL = "failed_terminal"


@dataclass(frozen=True, slots=True)
class A2ADelegationOperation:
    local_task_id: TaskId
    operation_id: str
    message_id: str
    target_id: str
    state: A2ADelegationState
    remote_task_id: str | None
    remote_status: TaskStatus | None
    recovery_cursor: str | None
    artifact_reference: str | None
    attempt_count: int
    last_error_code: str | None
    correlation_id: str | None
    created_at: datetime
    updated_at: datetime
    recovery_attempt_count: int
    recovery_in_progress: bool
    recovery_started_at: datetime | None
    next_recovery_at: datetime | None
    recovery_deadline_at: datetime | None
    reconciliation_required: bool

    def remote_result(self) -> A2ADelegationResult:
        if self.remote_task_id is None or self.remote_status is None:
            raise RuntimeError("A2A delegation has no remote result")
        return A2ADelegationResult(
            self.remote_task_id, self.remote_status, self.artifact_reference
        )


@dataclass(frozen=True, slots=True)
class A2ARecoveryPolicy:
    max_attempts: int = 3
    base_delay: timedelta = timedelta(seconds=1)
    max_delay: timedelta = timedelta(seconds=30)
    deadline: timedelta = timedelta(minutes=5)
    claim_timeout: timedelta = timedelta(seconds=30)

    def __post_init__(self) -> None:
        if type(self.max_attempts) is not int or not 1 <= self.max_attempts <= 100:
            raise ValueError("max_attempts must be an integer from 1 to 100")
        for value, name in (
            (self.base_delay, "base_delay"),
            (self.max_delay, "max_delay"),
            (self.deadline, "deadline"),
            (self.claim_timeout, "claim_timeout"),
        ):
            if not isinstance(value, timedelta) or value <= timedelta(0):
                raise ValueError(f"{name} must be a positive timedelta")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must not be shorter than base_delay")

    def next_recovery_at(self, now: datetime, attempt_count: int) -> datetime:
        require_utc(now, "now")
        exponent = max(0, attempt_count - 1)
        delay_seconds = min(
            self.base_delay.total_seconds() * (2 ** exponent),
            self.max_delay.total_seconds(),
        )
        return now + timedelta(seconds=delay_seconds)


class A2ARecoveryClaimStatus(StrEnum):
    ACQUIRED = "acquired"
    DEFERRED = "deferred"
    IN_PROGRESS = "in_progress"
    RECONCILIATION_REQUIRED = "reconciliation_required"


@dataclass(frozen=True, slots=True)
class A2ARecoveryClaim:
    status: A2ARecoveryClaimStatus
    operation: A2ADelegationOperation


class A2ADelegationOperationRepository(Protocol):
    def reserve(
        self, task_id: TaskId, *, target_id: str, operation_id: str,
        message_id: str, now: datetime, correlation_id: str,
        recovery_deadline_at: datetime,
    ) -> A2ADelegationOperation: ...
    def get(self, task_id: TaskId) -> A2ADelegationOperation | None: ...
    def begin_submission(self, task: Task, *, now: datetime) -> bool: ...
    def record_remote(
        self, task_id: TaskId, result: A2ADelegationResult, *, now: datetime,
        recovery_cursor: str | None = None,
        next_recovery_at: datetime | None = None,
    ) -> A2ADelegationOperation: ...
    def mark_response_unknown(
        self, task_id: TaskId, error_code: str, *, now: datetime,
    ) -> None: ...
    def mark_not_sent(
        self, task_id: TaskId, error_code: str, *, now: datetime,
        next_recovery_at: datetime,
    ) -> None: ...
    def mark_failed_terminal(
        self, task_id: TaskId, error_code: str, *, now: datetime,
    ) -> None: ...
    def mark_completed(
        self, task_id: TaskId, *, now: datetime,
    ) -> A2ADelegationOperation: ...
    def claim_recovery(
        self, task_id: TaskId, *, now: datetime, max_attempts: int,
        claim_timeout: timedelta,
    ) -> A2ARecoveryClaim: ...
    def finish_recovery_error(
        self, task_id: TaskId, *, prior_state: A2ADelegationState,
        error_code: str, now: datetime, next_recovery_at: datetime,
        response_unknown: bool = False,
        reconciliation_required: bool = False,
    ) -> A2ADelegationOperation: ...
    def mark_stale_submission_unknown(
        self, task_id: TaskId, *, now: datetime, stale_before: datetime,
    ) -> A2ADelegationOperation: ...


@dataclass(frozen=True, slots=True)
class DelegateTaskResult:
    local_task_id: str
    replayed: bool
    remote_task_id: str
    status: str
    artifact_reference: str | None
    content_trusted: bool
    operation_id: str
    message_id: str


class DelegateTaskService:
    def __init__(
        self,
        task_creation: CreateTaskService,
        task_repository: TaskRepository,
        operation_repository: A2ADelegationOperationRepository,
        gateway: A2AGateway,
        *,
        target_id: str,
        recovery_policy: A2ARecoveryPolicy | None = None,
    ) -> None:
        self._task_creation = task_creation
        self._task_repository = task_repository
        self._operation_repository = operation_repository
        self._gateway = gateway
        self._recovery_policy = recovery_policy or A2ARecoveryPolicy()
        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("target_id must be non-blank text")
        self._target_id = target_id

    async def delegate(
        self,
        *,
        actor_id: AgentId,
        idempotency_key: IdempotencyKey,
        request: CreateTaskRequest,
        trace_id: str,
        now: datetime,
    ) -> DelegateTaskResult:
        if not isinstance(trace_id, str) or not trace_id.strip():
            raise ValueError("trace_id must be non-blank text")
        require_utc(now, "now")
        created = self._task_creation.create(actor_id, idempotency_key, request)
        task = self._task_repository.get_task(created.task_id)
        if task is None:
            raise RuntimeError("created Task cannot be loaded")
        operation = self._operation_repository.reserve(
            created.task_id,
            target_id=self._target_id,
            operation_id=created.task_id.value,
            message_id=created.task_id.value,
            now=now,
            correlation_id=trace_id,
            recovery_deadline_at=now + self._recovery_policy.deadline,
        )
        prior = await self._resume_persisted(
            created, task, operation, actor_id, trace_id, now
        )
        if prior is not None:
            return prior
        if task.status is not TaskStatus.SUBMITTED:
            raise RuntimeError("reserved A2A delegation Task is not submitted")
        started_task = task.transition(
            TaskStatus.WORKING,
            actor_id=actor_id,
            reason="A2A delegation started",
            occurred_at=now,
        )
        if not self._operation_repository.begin_submission(started_task, now=now):
            operation = self._operation_repository.get(created.task_id)
            if operation is None:
                raise RuntimeError("A2A delegation reservation disappeared")
            prior = await self._resume_persisted(
                created, task, operation, actor_id, trace_id, now
            )
            if prior is not None:
                return prior
            raise A2ABridgeError("a2a_submission_in_progress", retryable=True)
        task = started_task
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
            if exc.retryable and not exc.request_may_have_been_sent:
                self._operation_repository.mark_not_sent(
                    created.task_id,
                    exc.code,
                    now=now,
                    next_recovery_at=self._recovery_policy.next_recovery_at(now, 1),
                )
            elif exc.retryable:
                self._operation_repository.mark_response_unknown(
                    created.task_id, exc.code, now=now
                )
            else:
                self._operation_repository.mark_failed_terminal(
                    created.task_id, exc.code, now=now
                )
            if not exc.retryable and task.status is TaskStatus.WORKING:
                task = task.transition(
                    TaskStatus.FAILED,
                    actor_id=actor_id,
                    reason=f"A2A delegation failed: {exc.code}",
                    occurred_at=now,
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
        except BaseException:
            self._operation_repository.mark_response_unknown(
                created.task_id, "a2a_response_unknown", now=now
            )
            raise

        operation = self._operation_repository.record_remote(
            created.task_id,
            remote,
            now=now,
            next_recovery_at=(
                self._recovery_policy.next_recovery_at(now, 1)
                if remote.status not in TERMINAL_REMOTE_STATUSES
                else None
            ),
        )

        self._apply_remote(task, remote, actor_id)
        if remote.status in TERMINAL_REMOTE_STATUSES:
            operation = self._operation_repository.mark_completed(
                created.task_id, now=now
            )
        logger.info(
            "a2a.bridge.completed",
            extra={
                "trace_id": trace_id,
                "actor_id": actor_id.value,
                "task_id": task.id.value,
                "remote_task_id": remote.remote_task_id,
                "remote_status": remote.status.value,
                "operation_id": operation.operation_id,
            },
        )
        return self._result(created, remote, operation)

    def _apply_remote(
        self, task: Task, remote: A2ADelegationResult, actor_id: AgentId
    ) -> Task:
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
        return task

    async def _resume_persisted(
        self,
        created: CreateTaskResult,
        task: Task,
        operation: A2ADelegationOperation,
        actor_id: AgentId,
        trace_id: str,
        now: datetime,
    ) -> DelegateTaskResult | None:
        if operation.state in {
            A2ADelegationState.REMOTE_TERMINAL_UNRECORDED,
            A2ADelegationState.COMPLETED,
        }:
            remote = operation.remote_result()
            self._apply_remote(task, remote, actor_id)
            if operation.state is A2ADelegationState.REMOTE_TERMINAL_UNRECORDED:
                operation = self._operation_repository.mark_completed(
                    created.task_id, now=now
                )
            return self._result(created, remote, operation)
        if operation.state in {
            A2ADelegationState.NOT_SENT,
            A2ADelegationState.REMOTE_ACTIVE,
        }:
            return await self._recover(
                created, task, operation, actor_id, trace_id, now
            )
        if operation.state is A2ADelegationState.RESPONSE_UNKNOWN:
            raise A2ABridgeError("a2a_reconciliation_required", retryable=False)
        if operation.state is A2ADelegationState.SUBMITTING:
            stale_before = now - self._recovery_policy.claim_timeout
            if operation.updated_at <= stale_before:
                self._operation_repository.mark_stale_submission_unknown(
                    created.task_id, now=now, stale_before=stale_before
                )
                raise A2ABridgeError(
                    "a2a_reconciliation_required", retryable=False
                )
            raise A2ABridgeError("a2a_submission_in_progress", retryable=True)
        if operation.state is A2ADelegationState.FAILED_TERMINAL:
            if task.status is TaskStatus.WORKING:
                task = task.transition(
                    TaskStatus.FAILED,
                    actor_id=actor_id,
                    reason=(
                        "A2A delegation failed: "
                        f"{operation.last_error_code or 'a2a_terminal_failure'}"
                    ),
                    occurred_at=now,
                )
                self._task_repository.save_task(task)
            raise A2ABridgeError(
                operation.last_error_code or "a2a_terminal_failure",
                retryable=False,
            )
        return None

    async def _recover(
        self,
        created: CreateTaskResult,
        task: Task,
        operation: A2ADelegationOperation,
        actor_id: AgentId,
        trace_id: str,
        now: datetime,
    ) -> DelegateTaskResult:
        claim = self._operation_repository.claim_recovery(
            created.task_id,
            now=now,
            max_attempts=self._recovery_policy.max_attempts,
            claim_timeout=self._recovery_policy.claim_timeout,
        )
        operation = claim.operation
        logger.info(
            "a2a.bridge.recovery_decided",
            extra={
                "trace_id": trace_id,
                "initial_trace_id": operation.correlation_id,
                "actor_id": actor_id.value,
                "task_id": task.id.value,
                "operation_id": operation.operation_id,
                "delegation_state": operation.state.value,
                "recovery_status": claim.status.value,
                "recovery_attempt_count": operation.recovery_attempt_count,
            },
        )
        if claim.status is A2ARecoveryClaimStatus.RECONCILIATION_REQUIRED:
            raise A2ABridgeError("a2a_reconciliation_required", retryable=False)
        if claim.status is A2ARecoveryClaimStatus.IN_PROGRESS:
            raise A2ABridgeError("a2a_recovery_in_progress", retryable=True)
        if claim.status is A2ARecoveryClaimStatus.DEFERRED:
            if operation.state is A2ADelegationState.REMOTE_ACTIVE:
                return self._result(created, operation.remote_result(), operation)
            raise A2ABridgeError(
                "a2a_recovery_deferred",
                retryable=True,
                request_may_have_been_sent=False,
            )

        prior_state = operation.state
        try:
            if prior_state is A2ADelegationState.NOT_SENT:
                remote = await self._gateway.delegate(
                    task,
                    trace_id=operation.correlation_id or trace_id,
                )
            else:
                if operation.remote_task_id is None:
                    raise RuntimeError("remote_active operation has no remote task")
                remote = await self._gateway.lookup(
                    operation.remote_task_id, trace_id=trace_id
                )
        except A2ABridgeError as exc:
            response_unknown = (
                prior_state is A2ADelegationState.NOT_SENT
                and exc.request_may_have_been_sent
            )
            reconciliation_required = response_unknown or not exc.retryable
            self._operation_repository.finish_recovery_error(
                created.task_id,
                prior_state=prior_state,
                error_code=exc.code,
                now=now,
                next_recovery_at=self._recovery_policy.next_recovery_at(
                    now, operation.recovery_attempt_count
                ),
                response_unknown=response_unknown,
                reconciliation_required=reconciliation_required,
            )
            if reconciliation_required:
                logger.warning(
                    "a2a.bridge.reconciliation_required",
                    extra={
                        "trace_id": trace_id,
                        "initial_trace_id": operation.correlation_id,
                        "actor_id": actor_id.value,
                        "task_id": task.id.value,
                        "operation_id": operation.operation_id,
                        "error_code": exc.code,
                    },
                )
                raise A2ABridgeError(
                    "a2a_reconciliation_required", retryable=False
                ) from exc
            raise
        except BaseException:
            self._operation_repository.finish_recovery_error(
                created.task_id,
                prior_state=prior_state,
                error_code="a2a_recovery_interrupted",
                now=now,
                next_recovery_at=self._recovery_policy.next_recovery_at(
                    now, operation.recovery_attempt_count
                ),
                response_unknown=prior_state is A2ADelegationState.NOT_SENT,
                reconciliation_required=prior_state is A2ADelegationState.NOT_SENT,
            )
            raise

        operation = self._operation_repository.record_remote(
            created.task_id,
            remote,
            now=now,
            next_recovery_at=(
                self._recovery_policy.next_recovery_at(
                    now, operation.recovery_attempt_count
                )
                if remote.status not in TERMINAL_REMOTE_STATUSES
                else None
            ),
        )
        self._apply_remote(task, remote, actor_id)
        if remote.status in TERMINAL_REMOTE_STATUSES:
            operation = self._operation_repository.mark_completed(
                created.task_id, now=now
            )
        logger.info(
            "a2a.bridge.recovery_completed",
            extra={
                "trace_id": trace_id,
                "initial_trace_id": operation.correlation_id,
                "actor_id": actor_id.value,
                "task_id": task.id.value,
                "operation_id": operation.operation_id,
                "remote_task_id": remote.remote_task_id,
                "remote_status": remote.status.value,
            },
        )
        return self._result(created, remote, operation)

    @staticmethod
    def _result(
        created: CreateTaskResult,
        remote: A2ADelegationResult,
        operation: A2ADelegationOperation,
    ) -> DelegateTaskResult:
        return DelegateTaskResult(
            local_task_id=created.task_id.value,
            replayed=created.replayed,
            remote_task_id=remote.remote_task_id,
            status=remote.status.value,
            artifact_reference=remote.artifact_reference,
            content_trusted=remote.content_trusted,
            operation_id=operation.operation_id,
            message_id=operation.message_id,
        )
