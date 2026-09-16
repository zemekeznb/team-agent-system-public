"""Persistent completed-result cache for the F2 A2A bridge."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

from tas.application.a2a_bridge import (
    A2ADelegationResult,
    TERMINAL_REMOTE_STATUSES,
)
from tas.domain.collaboration import TaskId, TaskStatus


class A2ADelegationResultConflictError(RuntimeError):
    """A local Task cannot acquire two different completed remote results."""


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
