"""SQLite Task aggregate persistence for F2-011."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.collaboration import (
    Artifact,
    ArtifactId,
    Task,
    TaskId,
    TaskMessage,
    TaskMessageId,
    TaskStatus,
    TaskTransition,
)
from tas.domain.identity import AgentId, ProjectId
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError


class TaskPersistenceConflictError(RuntimeError):
    """A stale or fabricated Task snapshot cannot overwrite persisted state."""


class SQLiteTaskRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def _translate(error: sqlite3.IntegrityError, resource: str) -> None:
        if "foreign key" in str(error).lower():
            raise IdentityReferenceError(
                f"{resource} references an unknown Task, Project, or Agent"
            ) from error
        raise DuplicateIdentityError(f"{resource} already exists") from error

    def add_task(self, task: Task) -> None:
        if task.status is not TaskStatus.SUBMITTED or task.transitions:
            raise TaskPersistenceConflictError(
                "add_task requires a new submitted Task without transition history"
            )
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO tas_tasks(id, project_id, assignee_agent_id, title, status, result) VALUES (?, ?, ?, ?, ?, ?)",
                    (task.id.value, task.project_id.value, task.assignee_agent_id.value, task.title, task.status.value, task.result),
                )
        except sqlite3.IntegrityError as error:
            self._translate(error, "task")

    def save_task(self, task: Task) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            persisted = connection.execute(
                "SELECT status, result, (SELECT count(*) FROM tas_task_transitions WHERE task_id = tas_tasks.id) FROM tas_tasks WHERE id = ?",
                (task.id.value,),
            ).fetchone()
            if persisted is None:
                raise IdentityReferenceError("task does not exist")
            status, result, existing = persisted
            if len(task.transitions) < existing:
                raise TaskPersistenceConflictError("Task snapshot is stale")
            pending = task.transitions[existing:]
            if not pending:
                if task.status.value == status and task.result == result:
                    connection.execute("COMMIT")
                    return
                raise TaskPersistenceConflictError(
                    "Task state changed without a new transition"
                )
            expected = TaskStatus(status)
            for transition in pending:
                if transition.from_status is not expected:
                    raise TaskPersistenceConflictError(
                        "Task transition history does not extend persisted state"
                    )
                expected = transition.to_status
            if task.status is not expected:
                raise TaskPersistenceConflictError(
                    "Task state does not match its transition history"
                )
            cursor = connection.execute(
                "UPDATE tas_tasks SET status = ?, result = ? WHERE id = ?",
                (task.status.value, task.result, task.id.value),
            )
            for sequence, transition in enumerate(task.transitions[existing:], existing + 1):
                connection.execute(
                    "INSERT INTO tas_task_transitions(task_id, sequence, from_status, to_status, actor_agent_id, reason, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (task.id.value, sequence, transition.from_status.value, transition.to_status.value, transition.actor_id.value, transition.reason, transition.occurred_at.isoformat()),
                )
            connection.execute("COMMIT")

    def get_task(self, task_id: TaskId) -> Task | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(
                "SELECT id, project_id, assignee_agent_id, title, status, result FROM tas_tasks WHERE id = ?",
                (task_id.value,),
            ).fetchone()
            if row is None:
                return None
            transitions = tuple(
                TaskTransition(TaskStatus(source), TaskStatus(target), AgentId(actor), reason, datetime.fromisoformat(occurred_at))
                for source, target, actor, reason, occurred_at in connection.execute(
                    "SELECT from_status, to_status, actor_agent_id, reason, occurred_at FROM tas_task_transitions WHERE task_id = ? ORDER BY sequence",
                    (task_id.value,),
                )
            )
        return Task(TaskId(row[0]), ProjectId(row[1]), AgentId(row[2]), row[3], TaskStatus(row[4]), row[5], transitions)

    def add_message(self, message: TaskMessage) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO tas_task_messages(id, task_id, author_agent_id, body, created_at) VALUES (?, ?, ?, ?, ?)",
                    (message.id.value, message.task_id.value, message.author_agent_id.value, message.body, message.created_at.isoformat()),
                )
        except sqlite3.IntegrityError as error:
            self._translate(error, "message")

    def get_message(self, message_id: TaskMessageId) -> TaskMessage | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT id, task_id, author_agent_id, body, created_at FROM tas_task_messages WHERE id = ?", (message_id.value,)).fetchone()
        return None if row is None else TaskMessage(TaskMessageId(row[0]), TaskId(row[1]), AgentId(row[2]), row[3], datetime.fromisoformat(row[4]))

    def add_artifact(self, artifact: Artifact) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(
                    "INSERT INTO tas_artifacts(id, task_id, producer_agent_id, reference, media_type, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (artifact.id.value, artifact.task_id.value, artifact.producer_agent_id.value, artifact.reference, artifact.media_type, artifact.created_at.isoformat()),
                )
        except sqlite3.IntegrityError as error:
            self._translate(error, "artifact")

    def get_artifact(self, artifact_id: ArtifactId) -> Artifact | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute("SELECT id, task_id, producer_agent_id, reference, media_type, created_at FROM tas_artifacts WHERE id = ?", (artifact_id.value,)).fetchone()
        return None if row is None else Artifact(ArtifactId(row[0]), TaskId(row[1]), AgentId(row[2]), row[3], row[4], datetime.fromisoformat(row[5]))
