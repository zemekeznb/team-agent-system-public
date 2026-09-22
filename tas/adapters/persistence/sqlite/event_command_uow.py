"""Authoritative SQLite transaction boundary for F3 collaboration Events."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.event_commands import (
    CodeChangeImpactView,
    CreateCodeChangeImpactCommand,
    EventCommandResult,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import Task, TaskId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.delivery import InboxItemId
from tas.domain.events import CodeChangeImpact, CodeImpactKind, CollaborationEventId
from tas.domain.evidence import EvidenceId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, ProjectId


class EventCommandAccessError(PermissionError):
    """Event scope is unavailable to the authenticated principal."""


class EventCommandConflictError(RuntimeError):
    """Event request conflicts with authoritative Evidence or state."""


class EventCommandIntegrityError(RuntimeError):
    """Persisted Event state cannot be reconstructed safely."""


class SQLiteEventCommandUnitOfWork:
    OPERATION = "event.create"

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def create(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: CreateCodeChangeImpactCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EventCommandResult:
        self._utc(now)
        fingerprint = fingerprint_payload(
            {
                "project_id": command.project_id.value,
                "target_agent_id": command.target_agent_id.value,
                "title": command.title,
                "repository": command.repository,
                "ref": command.ref,
                "baseline_commit": command.baseline_commit,
                "head_commit": command.head_commit,
                "changed_paths": list(command.changed_paths),
                "evidence_id": command.evidence_id.value,
                "impact_kind": command.impact_kind.value,
                "affected_api": command.affected_api,
            }
        ).value
        reason = "event_scope_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                authority = self._authority(connection, actor_id, command)
                if authority is None:
                    raise EventCommandAccessError("Event scope is unavailable")
                publisher_owner_id = str(authority[0])
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_json FROM "
                    "tas_idempotency_records WHERE actor_id=? AND operation=? "
                    "AND idempotency_key=?",
                    (actor_id.value, self.OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    if str(ledger[0]) != fingerprint:
                        reason = "event_idempotency_conflict"
                        raise IdempotencyConflictError("Idempotency key conflicts")
                    try:
                        event_id = CollaborationEventId(
                            str(json.loads(str(ledger[1]))["event_id"])
                        )
                    except (json.JSONDecodeError, KeyError, TypeError) as error:
                        raise EventCommandIntegrityError(
                            "Event result is invalid"
                        ) from error
                    event = self._authorized_event(
                        connection, event_id.value, principal_owner_id=publisher_owner_id,
                        expected_publisher_id=actor_id.value,
                    )
                    if event is None:
                        raise EventCommandAccessError("Event scope is unavailable")
                    connection.execute("COMMIT")
                    return EventCommandResult(event, True)

                event_id = CollaborationEventId(str(uuid4()))
                task_id = TaskId(str(uuid4()))
                inbox_id = InboxItemId(str(uuid4()))
                event = CodeChangeImpact(
                    event_id,
                    command.project_id,
                    actor_id,
                    command.repository,
                    command.ref,
                    command.baseline_commit,
                    command.head_commit,
                    command.changed_paths,
                    command.evidence_id,
                    command.impact_kind,
                    command.affected_api,
                    now,
                )
                reason = "event_evidence_conflict"
                self._validate_evidence_payload(connection, event)
                task = Task(
                    task_id, command.project_id, command.target_agent_id, command.title
                )
                connection.execute(
                    "INSERT INTO tas_code_change_impact_events VALUES "
                    "(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.id.value, event.project_id.value, actor_id.value,
                        event.repository, event.ref, event.baseline_commit,
                        event.head_commit, event.evidence_id.value,
                        event.impact_kind.value, event.affected_api,
                        event.occurred_at.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO tas_code_change_impact_paths VALUES (?,?,?)",
                    tuple(
                        (event.id.value, index, path)
                        for index, path in enumerate(event.changed_paths, 1)
                    ),
                )
                connection.execute(
                    "INSERT INTO tas_tasks(id,project_id,assignee_agent_id,title,"
                    "status,result) VALUES (?,?,?,?,?,NULL)",
                    (
                        task.id.value, task.project_id.value,
                        task.assignee_agent_id.value, task.title, task.status.value,
                    ),
                )
                connection.execute(
                    "INSERT INTO tas_task_origins VALUES (?,?,?,?)",
                    (task.id.value, actor_id.value, publisher_owner_id, now.isoformat()),
                )
                connection.execute(
                    "INSERT INTO tas_event_task_links VALUES (?,?)",
                    (event.id.value, task.id.value),
                )
                connection.execute(
                    "INSERT INTO tas_inbox_items(id,task_id,recipient_agent_id,"
                    "available_at,max_attempts,attempt_count,status) "
                    "VALUES (?,?,?,?,3,0,'pending')",
                    (
                        inbox_id.value, task.id.value,
                        command.target_agent_id.value, now.isoformat(),
                    ),
                )
                connection.execute(
                    "INSERT INTO tas_event_submissions VALUES (?,?)",
                    (event.id.value, now.isoformat()),
                )
                result = json.dumps(
                    {
                        "event_id": event.id.value,
                        "task_id": task.id.value,
                        "inbox_item_id": inbox_id.value,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                connection.execute(
                    "INSERT INTO tas_idempotency_records(actor_id,operation,"
                    "idempotency_key,request_fingerprint,status,"
                    "reservation_token_hash,result_json,created_at,updated_at) "
                    "VALUES (?,?,?,?,'completed',NULL,?,?,?)",
                    (
                        actor_id.value, self.OPERATION, key.value, fingerprint,
                        result, now.isoformat(), now.isoformat(),
                    ),
                )
                view = self._authorized_event(
                    connection, event.id.value,
                    principal_owner_id=publisher_owner_id,
                    expected_publisher_id=actor_id.value,
                )
                if view is None:
                    raise EventCommandIntegrityError("Event could not be restored")
                connection.execute("COMMIT")
                return EventCommandResult(view, False)
        except (EventCommandAccessError, EventCommandConflictError, IdempotencyConflictError):
            self._audit(
                actor_id, command.project_id.value, reason, now, correlation_id
            )
            raise
        except sqlite3.IntegrityError as error:
            raise EventCommandIntegrityError("Event could not be committed") from error

    def get(
        self,
        principal: AuthenticatedPrincipal,
        event_id: CollaborationEventId,
    ) -> CodeChangeImpactView | None:
        with self._connect() as connection:
            connection.execute("BEGIN")
            event = self._authorized_event(
                connection,
                event_id.value,
                principal_owner_id=principal.owner_id.value,
            )
            connection.execute("COMMIT")
            return event

    @staticmethod
    def _authority(connection, actor_id, command):
        return connection.execute(
            "SELECT publisher.owner_id FROM tas_agents publisher "
            "JOIN tas_projects project ON project.id=? "
            "JOIN tas_team_memberships publisher_member "
            "ON publisher_member.team_id=project.team_id "
            "AND publisher_member.owner_id=publisher.owner_id "
            "JOIN tas_agents target ON target.id=? "
            "JOIN tas_team_memberships target_member "
            "ON target_member.team_id=project.team_id "
            "AND target_member.owner_id=target.owner_id "
            "JOIN tas_repository_bindings repository ON repository.project_id=project.id "
            "AND repository.repository=? "
            "AND repository.controlling_owner_id=publisher.owner_id "
            "JOIN tas_evidence_submissions submission ON submission.id=? "
            "AND submission.status='finalized' AND submission.actor_agent_id=publisher.id "
            "JOIN tas_observed_evidence evidence ON evidence.id=submission.id "
            "AND evidence.kind='git' AND evidence.task_id=submission.task_id "
            "JOIN tas_tasks source_task ON source_task.id=submission.task_id "
            "AND source_task.project_id=project.id "
            "JOIN tas_workspace_registrations workspace "
            "ON workspace.workspace_id=submission.workspace_id "
            "WHERE publisher.id=?",
            (
                command.project_id.value, command.target_agent_id.value,
                command.repository, command.evidence_id.value, actor_id.value,
            ),
        ).fetchone()

    @staticmethod
    def _validate_evidence_payload(connection, event: CodeChangeImpact) -> None:
        row = connection.execute(
            "SELECT evidence.payload_json,submission.observed_at "
            "FROM tas_observed_evidence evidence "
            "JOIN tas_evidence_submissions submission ON submission.id=evidence.id "
            "WHERE evidence.id=?",
            (event.evidence_id.value,),
        ).fetchone()
        if row is None:
            raise EventCommandAccessError("Event Evidence is unavailable")
        if event.occurred_at < datetime.fromisoformat(str(row[1])):
            raise EventCommandConflictError("Event predates its Evidence")
        try:
            payload = json.loads(str(row[0]))
            paths = tuple(item["path"] for item in payload["files"])
            facts = (
                payload["repository"], payload["branch"],
                payload["baseline_commit"], payload["head_commit"], paths,
            )
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise EventCommandConflictError("Git Evidence payload is incomplete") from error
        expected = (
            event.repository, event.ref, event.baseline_commit,
            event.head_commit, event.changed_paths,
        )
        if facts != expected:
            raise EventCommandConflictError(
                "Event facts do not match finalized Git Evidence"
            )

    @staticmethod
    def _authorized_event(
        connection,
        event_id,
        *,
        principal_owner_id,
        expected_publisher_id=None,
    ):
        row = connection.execute(
            "SELECT event.id,event.project_id,event.publisher_agent_id,"
            "task.assignee_agent_id,task.id,inbox.id,task.title,event.repository,"
            "event.ref,event.baseline_commit,event.head_commit,event.evidence_id,"
            "event.impact_kind,event.affected_api,event.occurred_at "
            "FROM tas_code_change_impact_events event "
            "JOIN tas_event_submissions submission ON submission.event_id=event.id "
            "JOIN tas_event_task_links link ON link.event_id=event.id "
            "JOIN tas_tasks task ON task.id=link.task_id "
            "JOIN tas_inbox_items inbox ON inbox.task_id=task.id "
            "JOIN tas_projects project ON project.id=event.project_id "
            "JOIN tas_team_memberships viewer ON viewer.team_id=project.team_id "
            "AND viewer.owner_id=? "
            "JOIN tas_agents publisher ON publisher.id=event.publisher_agent_id "
            "JOIN tas_team_memberships publisher_member "
            "ON publisher_member.team_id=project.team_id "
            "AND publisher_member.owner_id=publisher.owner_id "
            "JOIN tas_agents target ON target.id=task.assignee_agent_id "
            "JOIN tas_team_memberships target_member "
            "ON target_member.team_id=project.team_id "
            "AND target_member.owner_id=target.owner_id "
            "JOIN tas_repository_bindings repository "
            "ON repository.project_id=project.id AND repository.repository=event.repository "
            "AND repository.controlling_owner_id=publisher.owner_id "
            "WHERE event.id=? AND (? IS NULL OR event.publisher_agent_id=?)",
            (principal_owner_id, event_id, expected_publisher_id, expected_publisher_id),
        ).fetchone()
        if row is None:
            return None
        paths = tuple(
            str(item[0]) for item in connection.execute(
                "SELECT path FROM tas_code_change_impact_paths "
                "WHERE event_id=? ORDER BY sequence",
                (event_id,),
            ).fetchall()
        )
        return CodeChangeImpactView(
            CollaborationEventId(str(row[0])), ProjectId(str(row[1])),
            AgentId(str(row[2])), AgentId(str(row[3])), TaskId(str(row[4])),
            InboxItemId(str(row[5])), str(row[6]), str(row[7]), str(row[8]),
            str(row[9]), str(row[10]), paths, EvidenceId(str(row[11])),
            CodeImpactKind(str(row[12])),
            str(row[13]), datetime.fromisoformat(str(row[14])),
        )

    def _audit(self, actor_id, project_id, reason, now, correlation_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,"
                "resource_type,resource_id,action,outcome,reason,occurred_at,"
                "policy_version,correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                    AuditActorKind.AGENT.value, actor_id.value, "project", project_id,
                    "event.create", AuditOutcome.REJECTED.value, reason,
                    now.isoformat(), None, correlation_id,
                ),
            )

    @staticmethod
    def _utc(value: datetime) -> None:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("now must use UTC")
