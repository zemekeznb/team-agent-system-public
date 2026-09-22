"""Persistent completed-result cache for the F2 A2A bridge."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tas.application.a2a_bridge import (
    A2ADelegationOperation,
    A2ADelegationState,
    A2ADelegationResult,
    TERMINAL_REMOTE_STATUSES,
    A2ARecoveryClaim,
    A2ARecoveryClaimStatus,
)
from tas.domain.collaboration import Task, TaskId, TaskStatus
from tas.domain.delivery import require_utc


class A2ADelegationResultConflictError(RuntimeError):
    """A local Task cannot acquire two different completed remote results."""


class A2ADelegationOperationConflictError(RuntimeError):
    """A delegation reservation or state transition conflicts."""


class SQLiteA2ADelegationOperationRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def reserve(
        self,
        task_id: TaskId,
        *,
        target_id: str,
        operation_id: str,
        message_id: str,
        now: datetime,
        correlation_id: str,
        recovery_deadline_at: datetime,
    ) -> A2ADelegationOperation:
        require_utc(now, "now")
        require_utc(recovery_deadline_at, "recovery_deadline_at")
        if recovery_deadline_at <= now:
            raise ValueError("recovery_deadline_at must be later than now")
        for value, name, maximum in (
            (target_id, "target_id", 2048),
            (operation_id, "operation_id", 255),
            (message_id, "message_id", 255),
            (correlation_id, "correlation_id", 255),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > maximum:
                raise ValueError(f"{name} must be bounded non-blank text")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute(
                    "INSERT INTO tas_a2a_delegation_operations("
                    "local_task_id,operation_id,message_id,target_id,state,"
                    "attempt_count,correlation_id,created_at,updated_at,"
                    "recovery_deadline_at) "
                    "VALUES (?,?,?,?,'reserved',0,?,?,?,?)",
                    (
                        task_id.value, operation_id, message_id, target_id,
                        correlation_id, now.isoformat(), now.isoformat(),
                        recovery_deadline_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                pass
            row = self._select(connection, task_id)
            if row is None:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation reservation failed"
                )
            operation = self._operation(row)
            legacy_completed = (
                operation.state is A2ADelegationState.COMPLETED
                and operation.target_id == "legacy-f2-a2a"
            )
            if (
                operation.operation_id != operation_id
                or operation.message_id != message_id
                or (operation.target_id != target_id and not legacy_completed)
            ):
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation identity conflicts"
                )
            connection.execute("COMMIT")
            return operation

    def get(self, task_id: TaskId) -> A2ADelegationOperation | None:
        with self._connect() as connection:
            row = self._select(connection, task_id)
        return None if row is None else self._operation(row)

    def begin_submission(self, task: Task, *, now: datetime) -> bool:
        require_utc(now, "now")
        if (
            task.status is not TaskStatus.WORKING
            or not task.transitions
            or task.transitions[-1].from_status is not TaskStatus.SUBMITTED
            or task.transitions[-1].to_status is not TaskStatus.WORKING
            or task.transitions[-1].occurred_at != now
        ):
            raise ValueError("submission Task must contain the current working transition")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            operation = connection.execute(
                "SELECT state FROM tas_a2a_delegation_operations "
                "WHERE local_task_id=?", (task.id.value,),
            ).fetchone()
            if operation is None or operation[0] != A2ADelegationState.RESERVED.value:
                connection.execute("ROLLBACK")
                return False
            persisted = connection.execute(
                "SELECT status,(SELECT count(*) FROM tas_task_transitions "
                "WHERE task_id=tas_tasks.id) FROM tas_tasks WHERE id=?",
                (task.id.value,),
            ).fetchone()
            if persisted is None or persisted[0] != TaskStatus.SUBMITTED.value:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "reserved A2A Task is not submitted"
                )
            existing = int(persisted[1])
            if len(task.transitions) != existing + 1:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A Task transition history is stale"
                )
            transition = task.transitions[-1]
            connection.execute(
                "UPDATE tas_tasks SET status='working' WHERE id=? AND status='submitted'",
                (task.id.value,),
            )
            connection.execute(
                "INSERT INTO tas_task_transitions(task_id,sequence,from_status,to_status,"
                "actor_agent_id,reason,occurred_at) VALUES (?,?,?,?,?,?,?)",
                (
                    task.id.value, existing + 1, transition.from_status.value,
                    transition.to_status.value, transition.actor_id.value,
                    transition.reason, transition.occurred_at.isoformat(),
                ),
            )
            connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state='submitting',"
                "attempt_count=attempt_count+1,last_error_code=NULL,updated_at=? "
                "WHERE local_task_id=? AND state='reserved'",
                (now.isoformat(), task.id.value),
            )
            connection.execute("COMMIT")
            return True

    def record_remote(
        self,
        task_id: TaskId,
        result: A2ADelegationResult,
        *,
        now: datetime,
        recovery_cursor: str | None = None,
        next_recovery_at: datetime | None = None,
    ) -> A2ADelegationOperation:
        require_utc(now, "now")
        if next_recovery_at is not None:
            require_utc(next_recovery_at, "next_recovery_at")
            if next_recovery_at <= now:
                raise ValueError("next_recovery_at must be later than now")
        if recovery_cursor is not None and (
            not isinstance(recovery_cursor, str)
            or not recovery_cursor
            or len(recovery_cursor) > 4096
        ):
            raise ValueError("recovery_cursor must be null or bounded text")
        next_state = (
            A2ADelegationState.REMOTE_TERMINAL_UNRECORDED
            if result.status in TERMINAL_REMOTE_STATUSES
            else A2ADelegationState.REMOTE_ACTIVE
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state=?,remote_task_id=?,"
                "remote_status=?,recovery_cursor=?,artifact_reference=?,"
                "last_error_code=NULL,updated_at=?,next_recovery_at=?,"
                "recovery_in_progress=0,recovery_started_at=NULL,"
                "reconciliation_required=0 "
                "WHERE local_task_id=? AND ("
                "(state='submitting' AND recovery_in_progress=0) OR "
                "(state IN ('not_sent','remote_active') AND recovery_in_progress=1))",
                (
                    next_state.value, result.remote_task_id, result.status.value,
                    recovery_cursor, result.artifact_reference, now.isoformat(),
                    None if next_recovery_at is None else next_recovery_at.isoformat(),
                    task_id.value,
                ),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation is not awaiting a response"
                )
            row = self._select(connection, task_id)
            connection.execute("COMMIT")
        if row is None:
            raise A2ADelegationOperationConflictError("A2A delegation disappeared")
        return self._operation(row)

    def mark_response_unknown(
        self, task_id: TaskId, error_code: str, *, now: datetime
    ) -> None:
        self._mark_failure(
            task_id, A2ADelegationState.RESPONSE_UNKNOWN, error_code, now
        )

    def mark_not_sent(
        self,
        task_id: TaskId,
        error_code: str,
        *,
        now: datetime,
        next_recovery_at: datetime,
    ) -> None:
        require_utc(next_recovery_at, "next_recovery_at")
        if next_recovery_at <= now:
            raise ValueError("next_recovery_at must be later than now")
        self._mark_failure(
            task_id,
            A2ADelegationState.NOT_SENT,
            error_code,
            now,
            next_recovery_at=next_recovery_at,
        )

    def mark_failed_terminal(
        self, task_id: TaskId, error_code: str, *, now: datetime
    ) -> None:
        self._mark_failure(
            task_id, A2ADelegationState.FAILED_TERMINAL, error_code, now
        )

    def _mark_failure(
        self,
        task_id: TaskId,
        state: A2ADelegationState,
        error_code: str,
        now: datetime,
        *,
        next_recovery_at: datetime | None = None,
    ) -> None:
        require_utc(now, "now")
        if not isinstance(error_code, str) or not error_code or len(error_code) > 128:
            raise ValueError("error_code must be bounded non-blank text")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state=?,last_error_code=?,"
                "updated_at=?,next_recovery_at=?,reconciliation_required=? "
                "WHERE local_task_id=? AND state='submitting'",
                (
                    state.value,
                    error_code,
                    now.isoformat(),
                    None if next_recovery_at is None else next_recovery_at.isoformat(),
                    1 if state is A2ADelegationState.RESPONSE_UNKNOWN else 0,
                    task_id.value,
                ),
            )
            if cursor.rowcount != 1:
                raise A2ADelegationOperationConflictError(
                    "A2A delegation is not submitting"
                )

    def mark_completed(
        self, task_id: TaskId, *, now: datetime
    ) -> A2ADelegationOperation:
        require_utc(now, "now")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._select(connection, task_id)
            if row is None:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation does not exist"
                )
            operation = self._operation(row)
            if operation.state is A2ADelegationState.COMPLETED:
                connection.execute("COMMIT")
                return operation
            if operation.state is not A2ADelegationState.REMOTE_TERMINAL_UNRECORDED:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation has no terminal result to complete"
                )
            connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state='completed',updated_at=? "
                "WHERE local_task_id=? AND state='remote_terminal_unrecorded'",
                (now.isoformat(), task_id.value),
            )
            connection.execute(
                "INSERT OR IGNORE INTO tas_a2a_delegation_results("
                "local_task_id,remote_task_id,remote_status,artifact_reference,"
                "content_trusted,completed_at) VALUES (?,?,?,?,0,?)",
                (
                    task_id.value, operation.remote_task_id,
                    operation.remote_status.value if operation.remote_status else None,
                    operation.artifact_reference, now.isoformat(),
                ),
            )
            result_row = connection.execute(
                "SELECT remote_task_id,remote_status,artifact_reference,content_trusted "
                "FROM tas_a2a_delegation_results WHERE local_task_id=?",
                (task_id.value,),
            ).fetchone()
            if result_row != (
                operation.remote_task_id,
                operation.remote_status.value if operation.remote_status else None,
                operation.artifact_reference,
                0,
            ):
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A terminal projection conflicts"
                )
            completed_row = self._select(connection, task_id)
            connection.execute("COMMIT")
        if completed_row is None:
            raise A2ADelegationOperationConflictError("A2A delegation disappeared")
        return self._operation(completed_row)

    def claim_recovery(
        self,
        task_id: TaskId,
        *,
        now: datetime,
        max_attempts: int,
        claim_timeout: timedelta,
    ) -> A2ARecoveryClaim:
        require_utc(now, "now")
        if type(max_attempts) is not int or not 1 <= max_attempts <= 100:
            raise ValueError("max_attempts must be an integer from 1 to 100")
        if not isinstance(claim_timeout, timedelta) or claim_timeout <= timedelta(0):
            raise ValueError("claim_timeout must be a positive timedelta")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._select(connection, task_id)
            if row is None:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation does not exist"
                )
            operation = self._operation(row)
            if operation.state not in {
                A2ADelegationState.NOT_SENT,
                A2ADelegationState.REMOTE_ACTIVE,
            }:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A delegation is not recoverable automatically"
                )
            if operation.recovery_in_progress:
                started = operation.recovery_started_at
                if started is not None and now - started < claim_timeout:
                    connection.execute("COMMIT")
                    return A2ARecoveryClaim(
                        A2ARecoveryClaimStatus.IN_PROGRESS, operation
                    )
                if operation.state is A2ADelegationState.NOT_SENT:
                    connection.execute(
                        "UPDATE tas_a2a_delegation_operations SET "
                        "state='response_unknown',recovery_in_progress=0,"
                        "recovery_started_at=NULL,reconciliation_required=1,"
                        "next_recovery_at=NULL,last_error_code=?,updated_at=? "
                        "WHERE local_task_id=? AND state='not_sent' "
                        "AND recovery_in_progress=1",
                        (
                            "a2a_recovery_submission_interrupted",
                            now.isoformat(),
                            task_id.value,
                        ),
                    )
                    current = self._select(connection, task_id)
                    connection.execute("COMMIT")
                    if current is None:
                        raise A2ADelegationOperationConflictError(
                            "A2A delegation disappeared"
                        )
                    return A2ARecoveryClaim(
                        A2ARecoveryClaimStatus.RECONCILIATION_REQUIRED,
                        self._operation(current),
                    )
            deadline = operation.recovery_deadline_at
            exhausted = (
                operation.reconciliation_required
                or operation.recovery_attempt_count >= max_attempts
                or (deadline is not None and now >= deadline)
            )
            if exhausted:
                connection.execute(
                    "UPDATE tas_a2a_delegation_operations SET "
                    "reconciliation_required=1,last_error_code=?,"
                    "next_recovery_at=NULL,updated_at=? WHERE local_task_id=?",
                    ("a2a_recovery_budget_exhausted", now.isoformat(), task_id.value),
                )
                current = self._select(connection, task_id)
                connection.execute("COMMIT")
                if current is None:
                    raise A2ADelegationOperationConflictError(
                        "A2A delegation disappeared"
                    )
                return A2ARecoveryClaim(
                    A2ARecoveryClaimStatus.RECONCILIATION_REQUIRED,
                    self._operation(current),
                )
            if operation.next_recovery_at is not None and now < operation.next_recovery_at:
                connection.execute("COMMIT")
                return A2ARecoveryClaim(A2ARecoveryClaimStatus.DEFERRED, operation)
            cursor = connection.execute(
                "UPDATE tas_a2a_delegation_operations SET recovery_in_progress=1,"
                "recovery_started_at=?,recovery_attempt_count=recovery_attempt_count+1,"
                "updated_at=? WHERE local_task_id=? AND state=?",
                (
                    now.isoformat(),
                    now.isoformat(),
                    task_id.value,
                    operation.state.value,
                ),
            )
            if cursor.rowcount != 1:
                connection.execute("ROLLBACK")
                raise A2ADelegationOperationConflictError(
                    "A2A recovery claim conflicted"
                )
            current = self._select(connection, task_id)
            connection.execute("COMMIT")
        if current is None:
            raise A2ADelegationOperationConflictError("A2A delegation disappeared")
        return A2ARecoveryClaim(
            A2ARecoveryClaimStatus.ACQUIRED, self._operation(current)
        )

    def finish_recovery_error(
        self,
        task_id: TaskId,
        *,
        prior_state: A2ADelegationState,
        error_code: str,
        now: datetime,
        next_recovery_at: datetime,
        response_unknown: bool = False,
        reconciliation_required: bool = False,
    ) -> A2ADelegationOperation:
        require_utc(now, "now")
        require_utc(next_recovery_at, "next_recovery_at")
        if next_recovery_at <= now:
            raise ValueError("next_recovery_at must be later than now")
        if not isinstance(prior_state, A2ADelegationState):
            raise TypeError("prior_state must be A2ADelegationState")
        if not isinstance(error_code, str) or not error_code or len(error_code) > 128:
            raise ValueError("error_code must be bounded non-blank text")
        state = (
            A2ADelegationState.RESPONSE_UNKNOWN
            if response_unknown
            else prior_state
        )
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state=?,last_error_code=?,"
                "updated_at=?,next_recovery_at=?,recovery_in_progress=0,"
                "recovery_started_at=NULL,reconciliation_required=? "
                "WHERE local_task_id=? AND state=? AND recovery_in_progress=1",
                (
                    state.value,
                    error_code,
                    now.isoformat(),
                    None if reconciliation_required else next_recovery_at.isoformat(),
                    1 if reconciliation_required else 0,
                    task_id.value,
                    prior_state.value,
                ),
            )
            if cursor.rowcount != 1:
                raise A2ADelegationOperationConflictError(
                    "A2A recovery result conflicts"
                )
            row = self._select(connection, task_id)
        if row is None:
            raise A2ADelegationOperationConflictError("A2A delegation disappeared")
        return self._operation(row)

    def mark_stale_submission_unknown(
        self,
        task_id: TaskId,
        *,
        now: datetime,
        stale_before: datetime,
    ) -> A2ADelegationOperation:
        require_utc(now, "now")
        require_utc(stale_before, "stale_before")
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tas_a2a_delegation_operations SET state='response_unknown',"
                "last_error_code='a2a_submission_interrupted',updated_at=?,"
                "next_recovery_at=NULL,reconciliation_required=1 "
                "WHERE local_task_id=? AND state='submitting' AND updated_at<=?",
                (now.isoformat(), task_id.value, stale_before.isoformat()),
            )
            if cursor.rowcount != 1:
                raise A2ADelegationOperationConflictError(
                    "A2A submission is not stale"
                )
            row = self._select(connection, task_id)
        if row is None:
            raise A2ADelegationOperationConflictError("A2A delegation disappeared")
        return self._operation(row)

    @staticmethod
    def _select(
        connection: sqlite3.Connection, task_id: TaskId
    ) -> tuple[object, ...] | None:
        return connection.execute(
            "SELECT local_task_id,operation_id,message_id,target_id,state,"
            "remote_task_id,remote_status,recovery_cursor,artifact_reference,"
            "attempt_count,last_error_code,correlation_id,created_at,updated_at,"
            "recovery_attempt_count,recovery_in_progress,recovery_started_at,"
            "next_recovery_at,recovery_deadline_at,reconciliation_required "
            "FROM tas_a2a_delegation_operations WHERE local_task_id=?",
            (task_id.value,),
        ).fetchone()

    @staticmethod
    def _operation(row: tuple[object, ...]) -> A2ADelegationOperation:
        operation = A2ADelegationOperation(
            TaskId(str(row[0])), str(row[1]), str(row[2]), str(row[3]),
            A2ADelegationState(str(row[4])),
            None if row[5] is None else str(row[5]),
            None if row[6] is None else TaskStatus(str(row[6])),
            None if row[7] is None else str(row[7]),
            None if row[8] is None else str(row[8]),
            int(row[9]), None if row[10] is None else str(row[10]),
            None if row[11] is None else str(row[11]),
            datetime.fromisoformat(str(row[12])), datetime.fromisoformat(str(row[13])),
            int(row[14]), bool(row[15]),
            None if row[16] is None else datetime.fromisoformat(str(row[16])),
            None if row[17] is None else datetime.fromisoformat(str(row[17])),
            None if row[18] is None else datetime.fromisoformat(str(row[18])),
            bool(row[19]),
        )
        require_utc(operation.created_at, "created_at")
        require_utc(operation.updated_at, "updated_at")
        for value, name in (
            (operation.recovery_started_at, "recovery_started_at"),
            (operation.next_recovery_at, "next_recovery_at"),
            (operation.recovery_deadline_at, "recovery_deadline_at"),
        ):
            if value is not None:
                require_utc(value, name)
        return operation


class SQLiteA2ADelegationResultRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def get(self, task_id: TaskId) -> A2ADelegationResult | None:
        with sqlite3.connect(self.database) as connection:
            row = connection.execute(
                "SELECT remote_task_id, remote_status, artifact_reference, "
                "content_trusted FROM tas_a2a_delegation_results "
                "WHERE local_task_id = ?",
                (task_id.value,),
            ).fetchone()
        if row is None:
            return None
        if row[3] != 0:
            raise A2ADelegationResultConflictError(
                "persisted external A2A content has an invalid trust marker"
            )
        return A2ADelegationResult(row[0], TaskStatus(row[1]), row[2])

    def save(self, task_id: TaskId, result: A2ADelegationResult) -> None:
        if result.status not in TERMINAL_REMOTE_STATUSES:
            raise ValueError("only terminal A2A results may be persisted")
        values = (
            task_id.value,
            result.remote_task_id,
            result.status.value,
            result.artifact_reference,
            datetime.now(UTC).isoformat(),
        )
        with sqlite3.connect(self.database) as connection:
            try:
                connection.execute(
                    "INSERT INTO tas_a2a_delegation_results("
                    "local_task_id, remote_task_id, remote_status, "
                    "artifact_reference, content_trusted, completed_at"
                    ") VALUES (?, ?, ?, ?, 0, ?)",
                    values,
                )
            except sqlite3.IntegrityError as exc:
                prior = self.get(task_id)
                if prior == result:
                    return
                raise A2ADelegationResultConflictError(
                    "local Task already has a different A2A result"
                ) from exc
