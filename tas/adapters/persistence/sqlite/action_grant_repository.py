"""SQLite single-consumption ledger for approved external actions."""

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.action_execution import (
    ActionReceipt,
    GrantConsumptionConflictError,
    GrantReservation,
    ReceiptSource,
)
from tas.domain.approval import ApprovalId
from tas.domain.audit import AuditEventId


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
                "result_reference,receipt_occurred_at,receipt_source,audit_status "
                "FROM tas_action_grant_consumptions "
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
            return GrantReservation(
                False,
                receipt,
                None if row[6] is None else ReceiptSource(row[6]),
                row[7] == "pending",
            )

    def get(
        self, approval_id: ApprovalId, request_fingerprint: str
    ) -> GrantReservation | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT request_fingerprint,status,external_action_id,result_reference,"
                "receipt_occurred_at,receipt_source,audit_status "
                "FROM tas_action_grant_consumptions WHERE approval_id=?",
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
        return GrantReservation(
            False,
            receipt,
            None if row[5] is None else ReceiptSource(row[5]),
            row[6] == "pending",
        )

    def complete(
        self,
        approval_id: ApprovalId,
        request_fingerprint: str,
        receipt: ActionReceipt,
        receipt_source: ReceiptSource,
    ) -> GrantReservation:
        if receipt.operation_id != approval_id.value or receipt.request_fingerprint != request_fingerprint:
            raise GrantConsumptionConflictError("Receipt does not match Approval Grant")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_fingerprint,status,external_action_id,result_reference,"
                "receipt_occurred_at,receipt_source,audit_status "
                "FROM tas_action_grant_consumptions WHERE approval_id=?",
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
                return GrantReservation(
                    False,
                    persisted,
                    ReceiptSource(row[5]),
                    row[6] == "pending",
                )
            connection.execute(
                "UPDATE tas_action_grant_consumptions SET status='completed',"
                "completed_at=?,external_action_id=?,result_reference=?,receipt_occurred_at=?,"
                "receipt_source=?,audit_status='pending',audit_event_id=NULL "
                "WHERE approval_id=? AND status='in_progress'",
                (
                    datetime.now(receipt.occurred_at.tzinfo).isoformat(),
                    receipt.external_action_id,
                    receipt.result_reference,
                    receipt.occurred_at.isoformat(),
                    receipt_source.value,
                    approval_id.value,
                ),
            )
            return GrantReservation(False, receipt, receipt_source, True)

    def mark_audited(
        self, approval_id: ApprovalId, request_fingerprint: str, event_id: AuditEventId
    ) -> None:
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "UPDATE tas_action_grant_consumptions "
                "SET audit_status='recorded',audit_event_id=? "
                "WHERE approval_id=? AND request_fingerprint=? "
                "AND status='completed' AND audit_status='pending'",
                (event_id.value, approval_id.value, request_fingerprint),
            )
            if cursor.rowcount == 0:
                row = connection.execute(
                    "SELECT audit_event_id FROM tas_action_grant_consumptions "
                    "WHERE approval_id=? AND request_fingerprint=? AND audit_status='recorded'",
                    (approval_id.value, request_fingerprint),
                ).fetchone()
                if row != (event_id.value,):
                    raise GrantConsumptionConflictError(
                        "Action Grant audit state conflicts with event"
                    )
