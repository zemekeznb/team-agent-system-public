"""Small SQLite-backed official A2A TaskStore for restart experiments.

This store belongs to the controlled Remote Agent fixture.  It is deliberately
separate from the central TAS schema and does not make an external Agent durable.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from a2a.server.context import ServerCallContext
from a2a.server.owner_resolver import OwnerResolver, resolve_user_scope
from a2a.server.tasks import TaskStore
from a2a.types import ListTasksRequest, ListTasksResponse, Task
from a2a.utils.constants import DEFAULT_LIST_TASKS_PAGE_SIZE
from a2a.utils.errors import InvalidParamsError
from a2a.utils.task import decode_page_token, encode_page_token


MAX_TASK_BYTES = 1024 * 1024


class SQLiteA2ATaskStore(TaskStore):
    """Persist bounded protobuf Tasks by SDK-resolved tenant/user scope."""

    def __init__(
        self,
        database: str | Path,
        *,
        owner_resolver: OwnerResolver = resolve_user_scope,
    ) -> None:
        self.database = Path(database)
        self.owner_resolver = owner_resolver
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database) as connection:
            central_schema = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='schema_migrations'"
            ).fetchone()
            if central_schema is not None:
                raise ValueError(
                    "Remote A2A TaskStore must not reuse the central TAS database"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS a2a_remote_tasks ("
                "owner TEXT NOT NULL, task_id TEXT NOT NULL, task_blob BLOB NOT NULL,"
                "PRIMARY KEY(owner, task_id),"
                "CHECK(length(owner) BETWEEN 0 AND 512),"
                "CHECK(length(task_id) BETWEEN 1 AND 255),"
                f"CHECK(length(task_blob) BETWEEN 1 AND {MAX_TASK_BYTES}))"
            )

    async def save(self, task: Task, context: ServerCallContext) -> None:
        owner = self._owner(context)
        if not isinstance(task.id, str) or not 1 <= len(task.id) <= 255:
            raise InvalidParamsError("Task ID must contain 1..255 characters")
        payload = task.SerializeToString(deterministic=True)
        if not payload or len(payload) > MAX_TASK_BYTES:
            raise InvalidParamsError("Serialized Task exceeds the store limit")
        with sqlite3.connect(self.database, timeout=5) as connection:
            connection.execute(
                "INSERT INTO a2a_remote_tasks(owner,task_id,task_blob) VALUES (?,?,?) "
                "ON CONFLICT(owner,task_id) DO UPDATE SET task_blob=excluded.task_blob",
                (owner, task.id, payload),
            )

    async def get(
        self, task_id: str, context: ServerCallContext
    ) -> Task | None:
        owner = self._owner(context)
        with sqlite3.connect(self.database, timeout=5) as connection:
            row = connection.execute(
                "SELECT task_blob FROM a2a_remote_tasks WHERE owner=? AND task_id=?",
                (owner, task_id),
            ).fetchone()
        return None if row is None else Task.FromString(row[0])

    async def list(
        self, params: ListTasksRequest, context: ServerCallContext
    ) -> ListTasksResponse:
        owner = self._owner(context)
        with sqlite3.connect(self.database, timeout=5) as connection:
            rows = connection.execute(
                "SELECT task_blob FROM a2a_remote_tasks WHERE owner=?", (owner,)
            ).fetchall()
        tasks = [Task.FromString(row[0]) for row in rows]
        if params.context_id:
            tasks = [task for task in tasks if task.context_id == params.context_id]
        if params.status:
            tasks = [task for task in tasks if task.status.state == params.status]
        if params.HasField("status_timestamp_after"):
            after = params.status_timestamp_after.ToJsonString()
            tasks = [
                task
                for task in tasks
                if task.HasField("status")
                and task.status.HasField("timestamp")
                and task.status.timestamp.ToJsonString() >= after
            ]
        tasks.sort(
            key=lambda task: (
                task.status.HasField("timestamp")
                if task.HasField("status")
                else False,
                task.status.timestamp.ToJsonString()
                if task.HasField("status") and task.status.HasField("timestamp")
                else "",
                task.id,
            ),
            reverse=True,
        )
        total_size = len(tasks)
        start = 0
        if params.page_token:
            start_id = decode_page_token(params.page_token)
            for index, task in enumerate(tasks):
                if task.id == start_id:
                    start = index
                    break
            else:
                raise InvalidParamsError(f"Invalid page token: {params.page_token}")
        page_size = params.page_size or DEFAULT_LIST_TASKS_PAGE_SIZE
        end = start + page_size
        next_token = encode_page_token(tasks[end].id) if end < total_size else None
        return ListTasksResponse(
            tasks=tasks[start:end],
            total_size=total_size,
            page_size=page_size,
            next_page_token=next_token,
        )

    async def delete(self, task_id: str, context: ServerCallContext) -> None:
        owner = self._owner(context)
        with sqlite3.connect(self.database, timeout=5) as connection:
            connection.execute(
                "DELETE FROM a2a_remote_tasks WHERE owner=? AND task_id=?",
                (owner, task_id),
            )

    def _owner(self, context: ServerCallContext) -> str:
        owner = self.owner_resolver(context)
        if not isinstance(owner, str) or len(owner) > 512:
            raise InvalidParamsError("Resolved task owner is invalid")
        return owner
