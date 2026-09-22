"""Atomic SQLite Unit of Work for idempotent Task creation."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    IdempotencyInProgressError,
    fingerprint_payload,
)
from tas.application.task_creation import CreateTaskRequest, CreateTaskResult
from tas.domain.collaboration import Task, TaskId
from tas.domain.delivery import InboxItemId
from tas.domain.idempotency import IdempotencyKey, IdempotencyStatus, OperationName
from tas.domain.identity import AgentId
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError


TASK_CREATE = OperationName("task.create")


class UnitOfWorkIntegrityError(RuntimeError):
    """A completed Ledger result no longer resolves to its Task."""


class SQLiteTaskCreationUnitOfWork:
    def __init__(
        self,
        database: str | Path,
        *,
        task_id_factory: Callable[[], TaskId] | None = None,
        inbox_id_factory: Callable[[], InboxItemId] | None = None,
        enforce_team_membership: bool = False,
        record_origin: bool = False,
        failure_hook: Callable[[str], None] | None = None,
    ) -> None:
        self.database = Path(database)
        self.task_id_factory = task_id_factory or (
            lambda: TaskId(str(uuid.uuid4()))
        )
        self.inbox_id_factory = inbox_id_factory
        self.enforce_team_membership = enforce_team_membership
        if record_origin and not enforce_team_membership:
            raise ValueError("Task origin requires server-side membership enforcement")
        self.record_origin = record_origin
        self.failure_hook = failure_hook

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _checkpoint(self, stage: str) -> None:
        if self.failure_hook is not None:
            self.failure_hook(stage)

    def create_task(
        self,
        actor_id: AgentId,
        idempotency_key: IdempotencyKey,
        request: CreateTaskRequest,
    ) -> CreateTaskResult:
        fingerprint = fingerprint_payload(
            {
                "project_id": request.project_id.value,
                "assignee_agent_id": request.assignee_agent_id.value,
                "title": request.title,
            }
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                requester_owner_id = None
                if self.enforce_team_membership:
                    authorized = connection.execute(
                        "SELECT actor.owner_id FROM tas_agents actor "
                        "JOIN tas_projects project ON project.id=? "
                        "JOIN tas_team_memberships actor_member "
                        "ON actor_member.team_id=project.team_id "
                        "AND actor_member.owner_id=actor.owner_id "
                        "JOIN tas_agents assignee ON assignee.id=? "
                        "JOIN tas_team_memberships assignee_member "
                        "ON assignee_member.team_id=project.team_id "
                        "AND assignee_member.owner_id=assignee.owner_id "
                        "WHERE actor.id=?",
                        (
                            request.project_id.value,
                            request.assignee_agent_id.value,
                            actor_id.value,
                        ),
                    ).fetchone()
                    if authorized is None:
                        raise IdentityReferenceError(
                            "Task creation target is unavailable to the authenticated Agent"
                        )
                    requester_owner_id = authorized[0]
                row = connection.execute(
                    "SELECT request_fingerprint, status, result_json "
                    "FROM tas_idempotency_records "
                    "WHERE actor_id = ? AND operation = ? AND idempotency_key = ?",
                    (actor_id.value, TASK_CREATE.value, idempotency_key.value),
                ).fetchone()
                if row is not None:
                    result = self._replay(
                        connection, row, fingerprint.value, actor_id
                    )
                    connection.execute("COMMIT")
                    return result

                now = datetime.now(UTC).isoformat()
                token_hash = hashlib.sha256(
                    secrets.token_bytes(32)
                ).hexdigest()
                connection.execute(
                    "INSERT INTO tas_idempotency_records("
                    "actor_id, operation, idempotency_key, request_fingerprint, "
                    "status, reservation_token_hash, created_at, updated_at"
                    ") VALUES (?, ?, ?, ?, 'in_progress', ?, ?, ?)",
                    (
                        actor_id.value,
                        TASK_CREATE.value,
                        idempotency_key.value,
                        fingerprint.value,
                        token_hash,
                        now,
                        now,
                    ),
                )
                self._checkpoint("after_reservation")

                task = Task(
                    self.task_id_factory(),
                    request.project_id,
                    request.assignee_agent_id,
                    request.title,
                )
                connection.execute(
                    "INSERT INTO tas_tasks("
                    "id, project_id, assignee_agent_id, title, status, result"
                    ") VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        task.id.value,
                        task.project_id.value,
                        task.assignee_agent_id.value,
                        task.title,
                        task.status.value,
                        task.result,
                    ),
                )
                self._checkpoint("after_task_write")

                if self.record_origin:
                    if requester_owner_id is None:
                        raise UnitOfWorkIntegrityError("Task origin has no requester Owner")
                    connection.execute(
                        "INSERT INTO tas_task_origins(task_id,requester_agent_id,"
                        "requester_owner_id,created_at) VALUES (?,?,?,?)",
                        (task.id.value, actor_id.value, requester_owner_id, now),
                    )
                    self._checkpoint("after_origin_write")

                inbox_id = None
                if self.inbox_id_factory is not None:
                    inbox_id = self.inbox_id_factory()
                    connection.execute(
                        "INSERT INTO tas_inbox_items(id,task_id,recipient_agent_id,"
                        "available_at,max_attempts,attempt_count,status) "
                        "VALUES (?,?,?,?,3,0,'pending')",
                        (
                            inbox_id.value,
                            task.id.value,
                            task.assignee_agent_id.value,
                            now,
                        ),
                    )
                    self._checkpoint("after_inbox_write")

                result_json = json.dumps(
                    {
                        "task_id": task.id.value,
                        **({} if inbox_id is None else {"inbox_item_id": inbox_id.value}),
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                cursor = connection.execute(
                    "UPDATE tas_idempotency_records SET status = 'completed', "
                    "reservation_token_hash = NULL, result_json = ?, updated_at = ? "
                    "WHERE actor_id = ? AND operation = ? AND idempotency_key = ? "
                    "AND request_fingerprint = ? AND status = 'in_progress'",
                    (
                        result_json,
                        datetime.now(UTC).isoformat(),
                        actor_id.value,
                        TASK_CREATE.value,
                        idempotency_key.value,
                        fingerprint.value,
                    ),
                )
                if cursor.rowcount != 1:
                    raise UnitOfWorkIntegrityError(
                        "idempotency reservation disappeared during transaction"
                    )
                self._checkpoint("before_commit")
                connection.execute("COMMIT")
                self._checkpoint("after_commit")
                return CreateTaskResult(task.id, replayed=False)
            except sqlite3.IntegrityError as error:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                if "foreign key" in str(error).lower():
                    raise IdentityReferenceError(
                        "Task creation references an unknown Actor, Project, or Assignee"
                    ) from error
                raise DuplicateIdentityError("Task already exists") from error
            except BaseException:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    def _replay(
        self,
        connection: sqlite3.Connection,
        ledger_row: tuple[str, str, str | None],
        fingerprint: str,
        actor_id: AgentId,
    ) -> CreateTaskResult:
        stored_fingerprint, status, result_json = ledger_row
        if stored_fingerprint != fingerprint:
            raise IdempotencyConflictError(
                "idempotency key was used with a different request"
            )
        if status == IdempotencyStatus.IN_PROGRESS.value:
            raise IdempotencyInProgressError(
                "original request is still in progress or has an unknown result"
            )
        if status != IdempotencyStatus.COMPLETED.value or result_json is None:
            raise UnitOfWorkIntegrityError("idempotency Ledger state is invalid")
        try:
            result = json.loads(result_json)
            task_id = result["task_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise UnitOfWorkIntegrityError(
                "completed idempotency result is invalid"
            ) from error
        if not isinstance(task_id, str) or not task_id.strip():
            raise UnitOfWorkIntegrityError("completed Task id is invalid")
        row = connection.execute(
            "SELECT id,assignee_agent_id FROM tas_tasks WHERE id = ?",
            (task_id,),
        ).fetchone()
        if row is None:
            raise UnitOfWorkIntegrityError(
                "completed idempotency result references a missing Task"
            )
        if self.inbox_id_factory is not None:
            inbox_item_id = result.get("inbox_item_id")
            if not isinstance(inbox_item_id, str) or not inbox_item_id.strip():
                raise UnitOfWorkIntegrityError(
                    "completed Task result has no Inbox item"
                )
            inbox = connection.execute(
                "SELECT task_id,recipient_agent_id FROM tas_inbox_items WHERE id=?",
                (inbox_item_id,),
            ).fetchone()
            if inbox != (task_id, row[1]):
                raise UnitOfWorkIntegrityError(
                    "completed Task result references an invalid Inbox item"
                )
        if self.record_origin:
            origin = connection.execute(
                "SELECT requester_agent_id FROM tas_task_origins WHERE task_id=?",
                (task_id,),
            ).fetchone()
            if origin != (actor_id.value,):
                raise UnitOfWorkIntegrityError(
                    "completed Task result references an invalid origin"
                )
        return CreateTaskResult(TaskId(row[0]), replayed=True)
