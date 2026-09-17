"""Append-only SQLite security audit persistence."""

import sqlite3
from contextlib import closing
from pathlib import Path

from tas.domain.audit import (
    AuditActorKind,
    AuditEvent,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
from tas.domain.ports import DuplicateAuditEventError


class SQLiteAuditRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add(self, event: AuditEvent) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO tas_audit_events "
                    "(id,kind,actor_kind,actor_id,resource_type,resource_id,action,"
                    "outcome,reason,occurred_at,policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        event.id.value,
                        event.kind.value,
                        event.actor_kind.value,
                        event.actor_id,
                        event.resource_type,
                        event.resource_id,
                        event.action,
                        event.outcome.value,
                        event.reason,
                        event.occurred_at.isoformat(),
                        event.policy_version,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise DuplicateAuditEventError("Audit Event cannot be appended") from error

    def get(self, event_id: AuditEventId) -> AuditEvent | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id,kind,actor_kind,actor_id,resource_type,resource_id,action,"
                "outcome,reason,occurred_at,policy_version "
                "FROM tas_audit_events WHERE id=?",
                (event_id.value,),
            ).fetchone()
        return None if row is None else self._restore(row)

    def list_for_resource(
        self, resource_type: str, resource_id: str
    ) -> tuple[AuditEvent, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id,kind,actor_kind,actor_id,resource_type,resource_id,action,"
                "outcome,reason,occurred_at,policy_version "
                "FROM tas_audit_events WHERE resource_type=? AND resource_id=? "
                "ORDER BY occurred_at,id",
                (resource_type, resource_id),
            ).fetchall()
        return tuple(self._restore(row) for row in rows)

    @staticmethod
    def _restore(row: tuple[object, ...]) -> AuditEvent:
        from datetime import datetime

        return AuditEvent(
            AuditEventId(str(row[0])),
            AuditEventKind(str(row[1])),
            AuditActorKind(str(row[2])),
            str(row[3]),
            str(row[4]),
            str(row[5]),
            str(row[6]),
            AuditOutcome(str(row[7])),
            str(row[8]),
            datetime.fromisoformat(str(row[9])),
            None if row[10] is None else str(row[10]),
        )
