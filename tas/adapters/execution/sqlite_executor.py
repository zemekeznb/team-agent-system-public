"""Independent durable F2 external-action simulator with idempotent receipts."""

import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tas.domain.action_execution import (
    ActionExecutionRequest,
    ActionReceipt,
    ExternalOperationConflictError,
    ExternalPreconditionChangedError,
)


class SQLiteExternalActionExecutor:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)
        with closing(self._connect()) as connection, connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS external_resource_state (
                    repository TEXT PRIMARY KEY,
                    workspace_revision TEXT NOT NULL,
                    commit_sha TEXT NOT NULL,
                    execution_count INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS external_action_receipts (
                    operation_id TEXT PRIMARY KEY,
                    request_fingerprint TEXT NOT NULL,
                    external_action_id TEXT NOT NULL UNIQUE,
                    result_reference TEXT NOT NULL,
                    occurred_at TEXT NOT NULL
                );
                CREATE TRIGGER IF NOT EXISTS external_action_receipts_no_update
                BEFORE UPDATE ON external_action_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'external receipt is immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS external_action_receipts_no_delete
                BEFORE DELETE ON external_action_receipts
                BEGIN
                    SELECT RAISE(ABORT, 'external receipt is immutable');
                END;
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def configure_resource(
        self, repository: str, workspace_revision: str, commit_sha: str
    ) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                "INSERT INTO external_resource_state "
                "(repository,workspace_revision,commit_sha) VALUES (?,?,?) "
                "ON CONFLICT(repository) DO UPDATE SET "
                "workspace_revision=excluded.workspace_revision,commit_sha=excluded.commit_sha",
                (repository, workspace_revision, commit_sha),
            )

    def find_receipt(self, operation_id: str) -> ActionReceipt | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT operation_id,request_fingerprint,external_action_id,"
                "result_reference,occurred_at FROM external_action_receipts "
                "WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        return None if row is None else self._restore(row)

    def check_preconditions(self, request: ActionExecutionRequest) -> None:
        with closing(self._connect()) as connection:
            current = connection.execute(
                "SELECT workspace_revision,commit_sha FROM external_resource_state "
                "WHERE repository=?",
                (request.intent.repository,),
            ).fetchone()
        expected = (
            request.preconditions.workspace_revision,
            request.preconditions.commit_sha,
        )
        if current != expected:
            raise ExternalPreconditionChangedError(
                "external resource preconditions no longer match"
            )

    def execute_once(
        self, request: ActionExecutionRequest, request_fingerprint: str
    ) -> ActionReceipt:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT operation_id,request_fingerprint,external_action_id,"
                "result_reference,occurred_at FROM external_action_receipts "
                "WHERE operation_id=?",
                (request.approval_id.value,),
            ).fetchone()
            if existing is not None:
                receipt = self._restore(existing)
                if receipt.request_fingerprint != request_fingerprint:
                    raise ExternalOperationConflictError(
                        "operation ID was used for another exact request"
                    )
                return receipt
            current = connection.execute(
                "SELECT workspace_revision,commit_sha FROM external_resource_state "
                "WHERE repository=?",
                (request.intent.repository,),
            ).fetchone()
            expected = (
                request.preconditions.workspace_revision,
                request.preconditions.commit_sha,
            )
            if current != expected:
                raise ExternalPreconditionChangedError(
                    "external resource preconditions no longer match"
                )
            occurred_at = datetime.now(UTC)
            external_action_id = str(uuid4())
            result_reference = f"sqlite-external-action:{external_action_id}"
            connection.execute(
                "UPDATE external_resource_state SET execution_count=execution_count+1 "
                "WHERE repository=?",
                (request.intent.repository,),
            )
            connection.execute(
                "INSERT INTO external_action_receipts VALUES (?,?,?,?,?)",
                (
                    request.approval_id.value,
                    request_fingerprint,
                    external_action_id,
                    result_reference,
                    occurred_at.isoformat(),
                ),
            )
            return ActionReceipt(
                request.approval_id.value,
                request_fingerprint,
                external_action_id,
                result_reference,
                occurred_at,
            )

    def execution_count(self, repository: str) -> int:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT execution_count FROM external_resource_state WHERE repository=?",
                (repository,),
            ).fetchone()
        return 0 if row is None else int(row[0])

    @staticmethod
    def _restore(row: tuple[object, ...]) -> ActionReceipt:
        return ActionReceipt(
            str(row[0]),
            str(row[1]),
            str(row[2]),
            str(row[3]),
            datetime.fromisoformat(str(row[4])),
        )
