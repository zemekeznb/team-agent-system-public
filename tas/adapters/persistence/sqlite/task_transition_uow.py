"""Atomic F3 Task transition, rejection Audit, and idempotency replay."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError, IdempotencyInProgressError, fingerprint_payload,
)
from tas.application.task_commands import (
    TransitionTaskCommand, TransitionTaskResult,
)
from tas.domain.audit import (
    AuditActorKind, AuditEvent, AuditEventId, AuditEventKind, AuditOutcome,
)
from tas.domain.collaboration import (
    InvalidTaskTransitionError, Task, TaskId, TaskStatus, TaskTransition,
)
from tas.domain.idempotency import IdempotencyKey, IdempotencyStatus
from tas.domain.identity import AgentId, ProjectId


class TaskTransitionAccessError(PermissionError):
    """The Task is unavailable to the authenticated Agent."""


class ProtectedTaskTransitionError(InvalidTaskTransitionError):
    """A generic transition attempted to bypass the Approval aggregate."""


class TaskTransitionIntegrityError(RuntimeError):
    """Persisted transition or idempotency state is not reconstructable."""


class SQLiteTaskTransitionUnitOfWork:
    OPERATION = "task.transition"

    def __init__(
        self,
        database: str | Path,
        *,
        audit_id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.database = Path(database)
        self.audit_id_factory = audit_id_factory

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def transition(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: TransitionTaskCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> TransitionTaskResult:
        if occurred_at.tzinfo is None or occurred_at.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must use UTC")
        fingerprint = fingerprint_payload({
            "task_id": command.task_id.value,
            "target": command.target.value,
            "reason": command.reason,
            "result": command.result,
        })
        task: Task | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                task = self._authorized_task(connection, actor_id, command.task_id)
                ledger = connection.execute(
                    "SELECT request_fingerprint,status,result_json "
                    "FROM tas_idempotency_records WHERE actor_id=? AND operation=? "
                    "AND idempotency_key=?",
                    (actor_id.value, self.OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    result = self._replay(ledger, fingerprint.value, task)
                    connection.execute("COMMIT")
                    return result
                self._protect_approval_boundary(task, command.target)
                changed = task.transition(
                    command.target,
                    actor_id=actor_id,
                    reason=command.reason,
                    result=command.result,
                    occurred_at=occurred_at,
                )
                now = occurred_at.isoformat()
                connection.execute(
                    "INSERT INTO tas_idempotency_records(actor_id,operation,"
                    "idempotency_key,request_fingerprint,status,reservation_token_hash,"
                    "created_at,updated_at) VALUES (?,?,?,?, 'in_progress',?,?,?)",
                    (
                        actor_id.value, self.OPERATION, key.value, fingerprint.value,
                        hashlib.sha256(secrets.token_bytes(32)).hexdigest(), now, now,
                    ),
                )
                transition = changed.transitions[-1]
                sequence = connection.execute(
                    "SELECT count(*) FROM tas_task_transitions WHERE task_id=?",
                    (task.id.value,),
                ).fetchone()[0] + 1
                cursor = connection.execute(
                    "UPDATE tas_tasks SET status=?,result=? WHERE id=? AND status=?",
                    (
                        changed.status.value, changed.result, changed.id.value,
                        task.status.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise TaskTransitionIntegrityError("Task state changed during transition")
                connection.execute(
                    "INSERT INTO tas_task_transitions(task_id,sequence,from_status,"
                    "to_status,actor_agent_id,reason,occurred_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        task.id.value, sequence, transition.from_status.value,
                        transition.to_status.value, actor_id.value, transition.reason,
                        transition.occurred_at.isoformat(),
                    ),
                )
                result_json = json.dumps(
                    {"task_id": task.id.value}, sort_keys=True, separators=(",", ":")
                )
                cursor = connection.execute(
                    "UPDATE tas_idempotency_records SET status='completed',"
                    "reservation_token_hash=NULL,result_json=?,updated_at=? "
                    "WHERE actor_id=? AND operation=? AND idempotency_key=? "
                    "AND request_fingerprint=? AND status='in_progress'",
                    (
                        result_json, now, actor_id.value, self.OPERATION, key.value,
                        fingerprint.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise TaskTransitionIntegrityError("Transition Ledger disappeared")
                connection.execute("COMMIT")
                return TransitionTaskResult(changed, replayed=False)
        except (InvalidTaskTransitionError, ProtectedTaskTransitionError) as error:
            if task is not None:
                self._audit_rejection(
                    task, command.target, actor_id, occurred_at, correlation_id,
                    "approval_boundary" if isinstance(error, ProtectedTaskTransitionError)
                    else "invalid_transition",
                )
            raise
        except TaskTransitionAccessError:
            self._audit_access_rejection(
                command.task_id, command.target, actor_id, occurred_at, correlation_id
            )
            raise

    def _authorized_task(
        self, connection: sqlite3.Connection, actor_id: AgentId, task_id: TaskId
    ) -> Task:
        row = connection.execute(
            "SELECT task.id,task.project_id,task.assignee_agent_id,task.title,"
            "task.status,task.result FROM tas_tasks task "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id "
            "WHERE task.id=? AND task.assignee_agent_id=actor.id",
            (actor_id.value, task_id.value),
        ).fetchone()
        if row is None:
            raise TaskTransitionAccessError("Task is unavailable")
        transitions = tuple(
            TaskTransition(
                TaskStatus(source), TaskStatus(target), AgentId(actor), reason,
                datetime.fromisoformat(when),
            )
            for source, target, actor, reason, when in connection.execute(
                "SELECT from_status,to_status,actor_agent_id,reason,occurred_at "
                "FROM tas_task_transitions WHERE task_id=? ORDER BY sequence",
                (task_id.value,),
            )
        )
        return Task(
            TaskId(row[0]), ProjectId(row[1]), AgentId(row[2]), row[3],
            TaskStatus(row[4]), row[5], transitions,
        )

    @staticmethod
    def _protect_approval_boundary(task: Task, target: TaskStatus) -> None:
        if task.status is TaskStatus.APPROVAL_REQUIRED or target is TaskStatus.APPROVAL_REQUIRED:
            raise ProtectedTaskTransitionError(
                "Approval transitions require the Approval API"
            )

    def _replay(
        self,
        row: tuple[str, str, str | None],
        fingerprint: str,
        current_task: Task,
    ) -> TransitionTaskResult:
        if row[0] != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        if row[1] == IdempotencyStatus.IN_PROGRESS.value:
            raise IdempotencyInProgressError("Transition result is unknown")
        if row[1] != IdempotencyStatus.COMPLETED.value or row[2] is None:
            raise TaskTransitionIntegrityError("Transition Ledger is invalid")
        try:
            task_id = TaskId(json.loads(row[2])["task_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise TaskTransitionIntegrityError("Transition result is invalid") from error
        if task_id != current_task.id:
            raise TaskTransitionIntegrityError("Transition result references another Task")
        return TransitionTaskResult(current_task, replayed=True)

    def _audit_rejection(
        self,
        task: Task,
        target: TaskStatus,
        actor_id: AgentId,
        occurred_at: datetime,
        correlation_id: str,
        reason: str,
    ) -> None:
        event = AuditEvent(
            AuditEventId(self.audit_id_factory()),
            AuditEventKind.TASK_TRANSITION_REJECTED,
            AuditActorKind.AGENT,
            actor_id.value,
            "task",
            task.id.value,
            f"transition:{task.status.value}->{target.value}",
            AuditOutcome.REJECTED,
            reason,
            occurred_at,
            correlation_id=correlation_id,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
                "resource_id,action,outcome,reason,occurred_at,policy_version,"
                "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.id.value, event.kind.value, event.actor_kind.value,
                    event.actor_id, event.resource_type, event.resource_id, event.action,
                    event.outcome.value, event.reason, event.occurred_at.isoformat(),
                    event.policy_version, event.correlation_id,
                ),
            )

    def _audit_access_rejection(
        self,
        task_id: TaskId,
        target: TaskStatus,
        actor_id: AgentId,
        occurred_at: datetime,
        correlation_id: str,
    ) -> None:
        event = AuditEvent(
            AuditEventId(self.audit_id_factory()),
            AuditEventKind.TASK_TRANSITION_REJECTED,
            AuditActorKind.AGENT,
            actor_id.value,
            "task",
            task_id.value,
            f"transition:unavailable->{target.value}",
            AuditOutcome.REJECTED,
            "task_unavailable",
            occurred_at,
            correlation_id=correlation_id,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
                "resource_id,action,outcome,reason,occurred_at,policy_version,"
                "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.id.value, event.kind.value, event.actor_kind.value,
                    event.actor_id, event.resource_type, event.resource_id, event.action,
                    event.outcome.value, event.reason, event.occurred_at.isoformat(),
                    event.policy_version, event.correlation_id,
                ),
            )
