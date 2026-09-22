"""SQLite resource-authorized Audit query with stable insertion-order cursors."""

from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tas.application.audit_query import (
    AuditEventPage,
    AuditQueryAccessError,
    AuditResourceType,
)
from tas.domain.audit import (
    AuditActorKind,
    AuditEvent,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
from tas.domain.identity import OwnerId


class SQLiteAuditQueryRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def list_for_owner(
        self,
        owner_id: OwnerId,
        resource_type: AuditResourceType,
        resource_id: str,
        *,
        cursor: str | None,
        limit: int,
        correlation_id: str,
    ) -> AuditEventPage:
        with self._connect() as connection:
            connection.execute("BEGIN")
            if not self._owner_can_access(
                connection, owner_id.value, resource_type, resource_id
            ):
                self._record_denial(
                    connection, owner_id, resource_type, resource_id, correlation_id
                )
                connection.execute("COMMIT")
                raise AuditQueryAccessError("Audit resource is unavailable")

            after_sequence = 0
            if cursor is not None:
                row = connection.execute(
                    "SELECT ordering.sequence FROM tas_audit_event_order ordering "
                    "JOIN tas_audit_events event ON event.id=ordering.event_id "
                    "WHERE ordering.event_id=? AND event.resource_type=? "
                    "AND event.resource_id=?",
                    (cursor, resource_type.value, resource_id),
                ).fetchone()
                if row is None:
                    connection.execute("ROLLBACK")
                    raise ValueError("cursor is invalid for this Audit resource")
                after_sequence = int(row[0])

            rows = connection.execute(
                "SELECT event.id,event.kind,event.actor_kind,event.actor_id,"
                "event.resource_type,event.resource_id,event.action,event.outcome,"
                "event.reason,event.occurred_at,event.policy_version,"
                "event.correlation_id FROM tas_audit_event_order ordering "
                "JOIN tas_audit_events event ON event.id=ordering.event_id "
                "WHERE event.resource_type=? AND event.resource_id=? "
                "AND ordering.sequence>? ORDER BY ordering.sequence LIMIT ?",
                (resource_type.value, resource_id, after_sequence, limit + 1),
            ).fetchall()
            connection.execute("COMMIT")

        has_more = len(rows) > limit
        visible = rows[:limit]
        items = tuple(self._restore(row) for row in visible)
        return AuditEventPage(
            items,
            items[-1].id.value if has_more and items else None,
        )

    @staticmethod
    def _owner_can_access(
        connection: sqlite3.Connection,
        owner_id: str,
        resource_type: AuditResourceType,
        resource_id: str,
    ) -> bool:
        if resource_type is AuditResourceType.CREDENTIAL:
            query = "SELECT 1 FROM tas_credentials WHERE id=? AND owner_id=?"
            parameters = (resource_id, owner_id)
        elif resource_type is AuditResourceType.OWNER_POLICY:
            query = "SELECT 1 FROM tas_owners WHERE id=? AND id=?"
            parameters = (resource_id, owner_id)
        elif resource_type is AuditResourceType.PROJECT:
            query = (
                "SELECT 1 FROM tas_projects project JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id WHERE project.id=? "
                "AND member.owner_id=?"
            )
            parameters = (resource_id, owner_id)
        elif resource_type is AuditResourceType.TASK:
            query = (
                "SELECT 1 FROM tas_tasks task JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "JOIN tas_agents receiver ON receiver.id=task.assignee_agent_id "
                "LEFT JOIN tas_task_origins origin ON origin.task_id=task.id "
                "WHERE task.id=? AND (receiver.owner_id=? "
                "OR origin.requester_owner_id=?)"
            )
            parameters = (owner_id, resource_id, owner_id, owner_id)
        elif resource_type is AuditResourceType.INBOX_ITEM:
            query = (
                "SELECT 1 FROM tas_inbox_items item JOIN tas_agents recipient "
                "ON recipient.id=item.recipient_agent_id JOIN tas_tasks task "
                "ON task.id=item.task_id JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "WHERE item.id=? AND recipient.owner_id=?"
            )
            parameters = (owner_id, resource_id, owner_id)
        elif resource_type is AuditResourceType.APPROVAL:
            query = (
                "SELECT 1 FROM tas_approvals approval JOIN tas_team_memberships member "
                "ON member.team_id=approval.team_id AND member.owner_id=? "
                "WHERE approval.id=? AND (?=approval.requester_owner_id "
                "OR ?=approval.receiving_owner_id)"
            )
            parameters = (owner_id, resource_id, owner_id, owner_id)
        elif resource_type is AuditResourceType.WORK_RECORD:
            query = (
                "SELECT 1 FROM tas_work_records record JOIN tas_tasks task "
                "ON task.id=record.task_id JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "JOIN tas_agents actor ON actor.id=record.actor_agent_id "
                "WHERE record.id=? AND actor.owner_id=?"
            )
            parameters = (owner_id, resource_id, owner_id)
        elif resource_type is AuditResourceType.ARTIFACT:
            query = (
                "SELECT 1 FROM tas_artifact_uploads upload JOIN tas_tasks task "
                "ON task.id=upload.task_id JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "JOIN tas_agents producer ON producer.id=upload.producer_agent_id "
                "WHERE upload.id=? AND producer.owner_id=?"
            )
            parameters = (owner_id, resource_id, owner_id)
        elif resource_type is AuditResourceType.EVIDENCE:
            query = (
                "SELECT 1 FROM tas_evidence_submissions evidence JOIN tas_tasks task "
                "ON task.id=evidence.task_id JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "JOIN tas_agents producer ON producer.id=evidence.actor_agent_id "
                "WHERE evidence.id=? AND producer.owner_id=?"
            )
            parameters = (owner_id, resource_id, owner_id)
        else:
            query = (
                "SELECT 1 FROM tas_repository_bindings binding "
                "JOIN tas_projects project ON project.id=binding.project_id "
                "JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "WHERE binding.repository=? AND binding.controlling_owner_id=? "
                "AND member.owner_id=?"
            )
            parameters = (resource_id, owner_id, owner_id)
        return connection.execute(query, parameters).fetchone() is not None

    @staticmethod
    def _record_denial(
        connection: sqlite3.Connection,
        owner_id: OwnerId,
        resource_type: AuditResourceType,
        resource_id: str,
        correlation_id: str,
    ) -> None:
        connection.execute(
            "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
            "resource_id,action,outcome,reason,occurred_at,policy_version,"
            "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                AuditActorKind.OWNER.value, owner_id.value, "audit_query",
                hashlib.sha256(
                    f"{resource_type.value}\0{resource_id}".encode("utf-8")
                ).hexdigest(), "audit.read",
                AuditOutcome.REJECTED.value, "audit_resource_unavailable",
                datetime.now(UTC).isoformat(), None, correlation_id,
            ),
        )

    @staticmethod
    def _restore(row: tuple[object, ...]) -> AuditEvent:
        return AuditEvent(
            AuditEventId(str(row[0])), AuditEventKind(str(row[1])),
            AuditActorKind(str(row[2])), str(row[3]), str(row[4]), str(row[5]),
            str(row[6]), AuditOutcome(str(row[7])), str(row[8]),
            datetime.fromisoformat(str(row[9])),
            None if row[10] is None else str(row[10]),
            None if row[11] is None else str(row[11]),
        )
