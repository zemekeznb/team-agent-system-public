"""SQLite Task/Workspace Binding persistence."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.collaboration import TaskId
from tas.domain.evidence import TaskWorkspaceBinding, WorkspaceBindingId
from tas.domain.identity import AgentId
from tas.domain.ports import WorkRecordPersistenceError


class SQLiteWorkspaceBindingRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add(self, binding: TaskWorkspaceBinding) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO tas_task_workspace_bindings "
                    "(id,task_id,actor_agent_id,repository,root_sha256,bound_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        binding.id.value,
                        binding.task_id.value,
                        binding.actor_id.value,
                        binding.repository,
                        binding.root_sha256,
                        binding.bound_at.isoformat(),
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise WorkRecordPersistenceError(
                "Task Workspace Binding conflicts or references unknown state"
            ) from error

    def get(self, binding_id: WorkspaceBindingId) -> TaskWorkspaceBinding | None:
        return self._get("id", binding_id.value)

    def get_for_task(self, task_id: TaskId) -> TaskWorkspaceBinding | None:
        return self._get("task_id", task_id.value)

    def _get(self, field: str, value: str) -> TaskWorkspaceBinding | None:
        if field not in {"id", "task_id"}:
            raise ValueError("unsupported Workspace Binding lookup")
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id,task_id,actor_agent_id,repository,root_sha256,bound_at "
                f"FROM tas_task_workspace_bindings WHERE {field}=?",
                (value,),
            ).fetchone()
        if row is None:
            return None
        return TaskWorkspaceBinding(
            WorkspaceBindingId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            str(row[3]),
            str(row[4]),
            datetime.fromisoformat(str(row[5])),
        )
