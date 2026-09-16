"""SQLite idempotency reservation and replay ledger."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from tas.domain.idempotency import (
    IdempotencyKey,
    IdempotencyRecord,
    IdempotencyStatus,
    OperationName,
    RequestFingerprint,
    ReservationToken,
)
from tas.domain.identity import AgentId


class IdempotencyConflictError(RuntimeError):
    """The scoped key was already used for a different request."""


class IdempotencyInProgressError(RuntimeError):
    """The original request has no safely replayable result yet."""


class IdempotencyTokenError(RuntimeError):
    """The caller does not hold the active reservation token."""


class IdempotencySensitiveDataError(ValueError):
    """An idempotency payload contains a field that must not be persisted."""


SENSITIVE_RESULT_KEYS = {
    "authorization",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
}


def _reject_sensitive_fields(value: object, context: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SENSITIVE_RESULT_KEYS:
                raise IdempotencySensitiveDataError(
                    f"idempotency {context} must not contain sensitive field: {key}"
                )
            _reject_sensitive_fields(child, context)
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive_fields(child, context)


def fingerprint_payload(payload: object) -> RequestFingerprint:
    _reject_sensitive_fields(payload, "request")
    canonical = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return RequestFingerprint(hashlib.sha256(canonical).hexdigest())


class SQLiteIdempotencyRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def reserve(
        self,
        actor: AgentId,
        operation: OperationName,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
    ) -> IdempotencyRecord:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT request_fingerprint, status, reservation_token_hash, result_json "
                "FROM tas_idempotency_records "
                "WHERE actor_id = ? AND operation = ? AND idempotency_key = ?",
                (actor.value, operation.value, key.value),
            ).fetchone()
            if row is not None:
                connection.execute("COMMIT")
                if row[0] != fingerprint.value:
                    raise IdempotencyConflictError(
                        "idempotency key was used with a different request"
                    )
                if row[1] == IdempotencyStatus.IN_PROGRESS.value:
                    raise IdempotencyInProgressError(
                        "original request is still in progress or has an unknown result"
                    )
                return IdempotencyRecord(
                    actor,
                    operation,
                    key,
                    fingerprint,
                    IdempotencyStatus.COMPLETED,
                    None,
                    json.loads(row[3]),
                )

            token = ReservationToken(secrets.token_urlsafe(32))
            now = datetime.now(UTC).isoformat()
            connection.execute(
                "INSERT INTO tas_idempotency_records(actor_id, operation, idempotency_key, request_fingerprint, status, reservation_token_hash, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, 'in_progress', ?, ?, ?)",
                (
                    actor.value,
                    operation.value,
                    key.value,
                    fingerprint.value,
                    hashlib.sha256(token.value.encode("utf-8")).hexdigest(),
                    now,
                    now,
                ),
            )
            connection.execute("COMMIT")
        return IdempotencyRecord(
            actor,
            operation,
            key,
            fingerprint,
            IdempotencyStatus.IN_PROGRESS,
            token,
        )

    def complete(
        self, reservation: IdempotencyRecord, result: dict[str, Any]
    ) -> IdempotencyRecord:
        if reservation.status is not IdempotencyStatus.IN_PROGRESS:
            raise IdempotencyTokenError("record is not an active reservation")
        _reject_sensitive_fields(result, "result")
        serialized = json.dumps(
            result, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE tas_idempotency_records SET status = 'completed', "
                "reservation_token_hash = NULL, result_json = ?, updated_at = ? "
                "WHERE actor_id = ? AND operation = ? AND idempotency_key = ? "
                "AND request_fingerprint = ? AND status = 'in_progress' "
                "AND reservation_token_hash = ?",
                (
                    serialized,
                    datetime.now(UTC).isoformat(),
                    reservation.actor_id.value,
                    reservation.operation.value,
                    reservation.key.value,
                    reservation.fingerprint.value,
                    hashlib.sha256(
                        reservation.reservation_token.value.encode("utf-8")
                    ).hexdigest(),
                ),
            )
            if cursor.rowcount != 1:
                raise IdempotencyTokenError("reservation token is not current")
        return IdempotencyRecord(
            reservation.actor_id,
            reservation.operation,
            reservation.key,
            reservation.fingerprint,
            IdempotencyStatus.COMPLETED,
            None,
            result,
        )
