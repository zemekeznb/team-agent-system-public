"""Atomic SQLite routing for verified CodeChangeImpact events."""

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
    IdempotencyConflictError, IdempotencyInProgressError, fingerprint_payload,
)
from tas.adapters.persistence.sqlite.task_creation_uow import UnitOfWorkIntegrityError
from tas.application.code_change_impact import RouteCodeChangeImpactResult
from tas.domain.collaboration import Task, TaskId
from tas.domain.delivery import InboxItemId
from tas.domain.events import CodeChangeImpact
from tas.domain.idempotency import IdempotencyKey, IdempotencyStatus, OperationName
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError


ROUTE_CODE_CHANGE_IMPACT = OperationName("code_change_impact.route")


class CodeChangeImpactEvidenceError(DomainValidationError):
    """The referenced observed Git Evidence does not exactly support the Event."""


class SQLiteCodeChangeImpactUnitOfWork:
    def __init__(self, database: str | Path, *, task_id_factory: Callable[[], TaskId] | None = None,
                 inbox_id_factory: Callable[[], InboxItemId] | None = None,
                 failure_hook: Callable[[str], None] | None = None) -> None:
        self.database = Path(database)
        self.task_id_factory = task_id_factory or (lambda: TaskId(str(uuid.uuid4())))
        self.inbox_id_factory = inbox_id_factory or (lambda: InboxItemId(str(uuid.uuid4())))
        self.failure_hook = failure_hook

    def _checkpoint(self, stage: str) -> None:
        if self.failure_hook is not None:
            self.failure_hook(stage)

    def route(self, actor_id: AgentId, target_agent_id: AgentId, title: str,
              idempotency_key: IdempotencyKey, event: CodeChangeImpact) -> RouteCodeChangeImpactResult:
        if not isinstance(actor_id, AgentId) or not isinstance(target_agent_id, AgentId):
            raise TypeError("actor IDs must be AgentId")
        if not isinstance(idempotency_key, IdempotencyKey):
            raise TypeError("idempotency_key must be IdempotencyKey")
        if not isinstance(event, CodeChangeImpact):
            raise TypeError("event must be CodeChangeImpact")
        if actor_id != event.publisher_agent_id:
            raise PermissionError("event publisher must be the authenticated actor")
        if event.occurred_at > datetime.now(UTC):
            raise DomainValidationError("event occurred_at cannot be in the future")
        if not isinstance(title, str) or not title.strip() or len(title) > 4096:
            raise DomainValidationError("Task title must be 1..4096 non-whitespace characters")
        fingerprint = fingerprint_payload({
            "event": {
                "id": event.id.value, "project_id": event.project_id.value,
                "publisher_agent_id": event.publisher_agent_id.value,
                "repository": event.repository, "ref": event.ref,
                "baseline_commit": event.baseline_commit, "head_commit": event.head_commit,
                "changed_paths": list(event.changed_paths), "evidence_id": event.evidence_id.value,
                "impact_kind": event.impact_kind.value, "affected_api": event.affected_api,
                "occurred_at": event.occurred_at.isoformat(),
            },
            "target_agent_id": target_agent_id.value, "title": title,
        })
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_fingerprint,status,result_json FROM tas_idempotency_records "
                "WHERE actor_id=? AND operation=? AND idempotency_key=?",
                (actor_id.value, ROUTE_CODE_CHANGE_IMPACT.value, idempotency_key.value),
            ).fetchone()
            if row is not None:
                result = self._replay(connection, row, fingerprint.value)
                connection.execute("COMMIT")
                return result

            now = datetime.now(UTC).isoformat()
            connection.execute(
                "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,request_fingerprint,"
                "status,reservation_token_hash,created_at,updated_at) VALUES (?,?,?,?, 'in_progress',?,?,?)",
                (actor_id.value, ROUTE_CODE_CHANGE_IMPACT.value, idempotency_key.value,
                 fingerprint.value, hashlib.sha256(secrets.token_bytes(32)).hexdigest(), now, now),
            )
            self._checkpoint("after_reservation")
            self._validate_evidence(connection, event)
            self._validate_target(connection, event.project_id.value, target_agent_id.value)

            connection.execute(
                "INSERT INTO tas_code_change_impact_events VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (event.id.value, event.project_id.value, actor_id.value, event.repository, event.ref,
                 event.baseline_commit, event.head_commit, event.evidence_id.value,
                 event.impact_kind.value, event.affected_api, event.occurred_at.isoformat()),
            )
            connection.executemany(
                "INSERT INTO tas_code_change_impact_paths VALUES (?,?,?)",
                [(event.id.value, index, path) for index, path in enumerate(event.changed_paths, 1)],
            )
            self._checkpoint("after_event_write")

            task = Task(self.task_id_factory(), event.project_id, target_agent_id, title)
            connection.execute(
                "INSERT INTO tas_tasks(id,project_id,assignee_agent_id,title,status,result) VALUES (?,?,?,?,?,NULL)",
                (task.id.value, task.project_id.value, task.assignee_agent_id.value, task.title, task.status.value),
            )
            connection.execute("INSERT INTO tas_event_task_links VALUES (?,?)", (event.id.value, task.id.value))
            self._checkpoint("after_task_write")
            inbox_id = self.inbox_id_factory()
            connection.execute(
                "INSERT INTO tas_inbox_items(id,task_id,recipient_agent_id,available_at,max_attempts,attempt_count,status) "
                "VALUES (?,?,?,?,3,0,'pending')",
                (inbox_id.value, task.id.value, target_agent_id.value, now),
            )
            self._checkpoint("after_inbox_write")

            result_json = json.dumps({"event_id": event.id.value, "inbox_item_id": inbox_id.value,
                                      "task_id": task.id.value}, sort_keys=True, separators=(",", ":"))
            cursor = connection.execute(
                "UPDATE tas_idempotency_records SET status='completed',reservation_token_hash=NULL,result_json=?,updated_at=? "
                "WHERE actor_id=? AND operation=? AND idempotency_key=? AND request_fingerprint=? AND status='in_progress'",
                (result_json, datetime.now(UTC).isoformat(), actor_id.value, ROUTE_CODE_CHANGE_IMPACT.value,
                 idempotency_key.value, fingerprint.value),
            )
            if cursor.rowcount != 1:
                raise UnitOfWorkIntegrityError("idempotency reservation disappeared during transaction")
            self._checkpoint("before_commit")
            connection.execute("COMMIT")
            self._checkpoint("after_commit")
            return RouteCodeChangeImpactResult(event.id, task.id, inbox_id, False)
        except (CodeChangeImpactEvidenceError, IdempotencyConflictError, IdempotencyInProgressError,
                UnitOfWorkIntegrityError):
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.IntegrityError as error:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            if getattr(error, "sqlite_errorname", "") == "SQLITE_CONSTRAINT_FOREIGNKEY":
                raise IdentityReferenceError("impact route references an unknown identity, repository, Task, or Evidence") from error
            raise DuplicateIdentityError("impact route contains an existing identifier") from error
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @staticmethod
    def _validate_target(connection: sqlite3.Connection, project_id: str, target_id: str) -> None:
        row = connection.execute(
            "SELECT 1 FROM tas_agents a JOIN tas_owners o ON o.id=a.owner_id "
            "JOIN tas_team_memberships m ON m.owner_id=o.id JOIN tas_projects p ON p.team_id=m.team_id "
            "WHERE a.id=? AND p.id=?", (target_id, project_id),
        ).fetchone()
        if row is None:
            raise IdentityReferenceError("target Agent is not a member of the Event Project team")

    @staticmethod
    def _validate_evidence(connection: sqlite3.Connection, event: CodeChangeImpact) -> None:
        row = connection.execute(
            "SELECT e.actor_agent_id,e.kind,e.payload_json,t.project_id,b.project_id,e.observed_at,"
            "EXISTS(SELECT 1 FROM tas_agents a JOIN tas_team_memberships m ON m.owner_id=a.owner_id "
            "JOIN tas_projects p ON p.team_id=m.team_id WHERE a.id=e.actor_agent_id AND p.id=t.project_id),"
            "b.controlling_owner_id,a.owner_id "
            "FROM tas_observed_evidence e JOIN tas_tasks t ON t.id=e.task_id "
            "LEFT JOIN tas_repository_bindings b ON b.repository=? "
            "LEFT JOIN tas_agents a ON a.id=e.actor_agent_id WHERE e.id=?",
            (event.repository, event.evidence_id.value),
        ).fetchone()
        if row is None or row[1] != "git":
            raise CodeChangeImpactEvidenceError("Event requires existing Git Evidence")
        if (row[0] != event.publisher_agent_id.value or row[3] != event.project_id.value
                or row[4] != event.project_id.value or row[6] != 1 or row[7] != row[8]):
            raise CodeChangeImpactEvidenceError("Git Evidence actor, Task Project, or Repository binding does not match Event")
        if event.occurred_at < datetime.fromisoformat(str(row[5])):
            raise CodeChangeImpactEvidenceError("Event cannot occur before its Git Evidence was observed")
        try:
            payload = json.loads(row[2])
            paths = tuple(item["path"] for item in payload["files"])
            facts = (payload["repository"], payload["branch"], payload["baseline_commit"],
                     payload["head_commit"], paths)
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise CodeChangeImpactEvidenceError("Git Evidence payload is incomplete") from error
        expected = (event.repository, event.ref, event.baseline_commit, event.head_commit, event.changed_paths)
        if facts != expected:
            raise CodeChangeImpactEvidenceError("Event does not exactly match Git Evidence facts")

    @staticmethod
    def _replay(connection: sqlite3.Connection, row: tuple[str, str, str | None], fingerprint: str) -> RouteCodeChangeImpactResult:
        stored, status, raw = row
        if stored != fingerprint:
            raise IdempotencyConflictError("idempotency key was used with a different request")
        if status == IdempotencyStatus.IN_PROGRESS.value:
            raise IdempotencyInProgressError("original request is still in progress or has an unknown result")
        if status != IdempotencyStatus.COMPLETED.value or raw is None:
            raise UnitOfWorkIntegrityError("idempotency Ledger state is invalid")
        try:
            result = json.loads(raw)
            event_id, task_id, inbox_id = result["event_id"], result["task_id"], result["inbox_item_id"]
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise UnitOfWorkIntegrityError("completed impact route result is invalid") from error
        exists = connection.execute(
            "SELECT 1 FROM tas_event_task_links l JOIN tas_inbox_items i ON i.task_id=l.task_id "
            "WHERE l.event_id=? AND l.task_id=? AND i.id=?", (event_id, task_id, inbox_id),
        ).fetchone()
        if exists is None:
            raise UnitOfWorkIntegrityError("completed impact route references missing state")
        from tas.domain.events import CollaborationEventId
        return RouteCodeChangeImpactResult(CollaborationEventId(event_id), TaskId(task_id), InboxItemId(inbox_id), True)
