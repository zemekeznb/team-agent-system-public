"""SQLite single-consumption ledger for approved external actions."""

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.action_execution import ActionReceipt, GrantReservation
from tas.domain.approval import ApprovalId


class GrantConsumptionConflictError(RuntimeError):
    """A Grant was already reserved with another request or Receipt."""


class SQLiteActionGrantRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def reserve(
        self, approval_id: ApprovalId, request_fingerprint: str, started_at: datetime
    ) -> GrantReservation:
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_fingerprint,status,completed_at,external_action_id,"
                "result_reference,receipt_occurred_at FROM tas_action_grant_consumptions "
                "WHERE approval_id=?",
                (approval_id.value,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO tas_action_grant_consumptions "
                    "(approval_id,request_fingerprint,status,started_at) "
                    "VALUES (?,?,'in_progress',?)",
                    (approval_id.value, request_fingerprint, started_at.isoformat()),
                )
                return GrantReservation(True, None)
            if row[0] != request_fingerprint:
                raise GrantConsumptionConflictError(
                    "Approval Grant was reserved for another exact request"
                )
            receipt = None
            if row[1] == "completed":
                receipt = ActionReceipt(
                    approval_id.value,
                    request_fingerprint,
                    row[3],
                    row[4],
                    datetime.fromisoformat(row[5]),
                )
            return GrantReservation(False, receipt)

    def get(
        self, approval_id: ApprovalId, request_fingerprint: str
    ) -> GrantReservation | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT request_fingerprint,status,external_action_id,result_reference,"
                "receipt_occurred_at FROM tas_action_grant_consumptions WHERE approval_id=?",
                (approval_id.value,),
            ).fetchone()
        if row is None:
            return None
        if row[0] != request_fingerprint:
            raise GrantConsumptionConflictError(
                "Approval Grant was reserved for another exact request"
            )
        receipt = None
        if row[1] == "completed":
            receipt = ActionReceipt(
                approval_id.value,
                request_fingerprint,
                row[2],
                row[3],
                datetime.fromisoformat(row[4]),
            )
        return GrantReservation(False, receipt)

    def complete(
        self, approval_id: ApprovalId, request_fingerprint: str, receipt: ActionReceipt
    ) -> ActionReceipt:
        if receipt.operation_id != approval_id.value or receipt.request_fingerprint != request_fingerprint:
            raise GrantConsumptionConflictError("Receipt does not match Approval Grant")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_fingerprint,status,external_action_id,result_reference,"
                "receipt_occurred_at FROM tas_action_grant_consumptions WHERE approval_id=?",
                (approval_id.value,),
            ).fetchone()
            if row is None or row[0] != request_fingerprint:
                raise GrantConsumptionConflictError("Approval Grant is not reserved")
            if row[1] == "completed":
                persisted = ActionReceipt(
                    approval_id.value,
                    request_fingerprint,
                    row[2],
                    row[3],
                    datetime.fromisoformat(row[4]),
                )
                if persisted != receipt:
                    raise GrantConsumptionConflictError("Receipt conflicts with persisted result")
                return persisted
            connection.execute(
                "UPDATE tas_action_grant_consumptions SET status='completed',"
                "completed_at=?,external_action_id=?,result_reference=?,receipt_occurred_at=? "
                "WHERE approval_id=? AND status='in_progress'",
                (
                    datetime.now(receipt.occurred_at.tzinfo).isoformat(),
                    receipt.external_action_id,
                    receipt.result_reference,
                    receipt.occurred_at.isoformat(),
                    approval_id.value,
                ),
            )
            return receipt
