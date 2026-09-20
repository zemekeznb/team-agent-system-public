"""SQLite durable Inbox, Claim, Lease, and Retry adapter."""

from __future__ import annotations

import sqlite3
import secrets
import hashlib
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from tas.domain.collaboration import TaskId
from tas.domain.delivery import (
    InboxItem,
    InboxItemId,
    InboxStatus,
    LeaseToken,
    TaskLease,
    require_utc,
)
from tas.domain.identity import AgentId
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError


class InboxConflictError(RuntimeError):
    """Raised when an item already has an active lease."""


class LeaseAuthorizationError(RuntimeError):
    """Raised when a lease token is missing, stale, wrong, or expired."""


class InboxStateError(RuntimeError):
    """Raised when a fabricated Inbox state is passed to a creation method."""


class SQLiteInboxRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add(self, item: InboxItem) -> None:
        if (
            item.status is not InboxStatus.PENDING
            or item.attempt_count != 0
            or item.lease is not None
        ):
            raise InboxStateError(
                "add requires a new pending InboxItem with no attempts or lease"
            )
        try:
            with closing(self._connect()) as connection:
                connection.execute(
                    "INSERT INTO tas_inbox_items(id, task_id, recipient_agent_id, available_at, max_attempts, attempt_count, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (item.id.value, item.task_id.value, item.recipient_agent_id.value, item.available_at.isoformat(), item.max_attempts, item.attempt_count, item.status.value),
                )
        except sqlite3.IntegrityError as error:
            if "foreign key" in str(error).lower():
                raise IdentityReferenceError("InboxItem references an unknown Task or Agent") from error
            raise DuplicateIdentityError("InboxItem already exists") from error

    def get(self, item_id: InboxItemId) -> InboxItem | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT id, task_id, recipient_agent_id, available_at, max_attempts, attempt_count, status, lease_token_hash, claimant_agent_id, lease_acquired_at, lease_expires_at FROM tas_inbox_items WHERE id = ?", (item_id.value,)).fetchone()
        return None if row is None else self._build(row)

    def claim_next(self, recipient: AgentId, claimant: AgentId, now: datetime, duration: timedelta) -> InboxItem | None:
        require_utc(now, "now")
        if claimant != recipient:
            raise LeaseAuthorizationError("only the recipient Agent may claim this Inbox")
        if duration <= timedelta(0):
            raise ValueError("lease duration must be positive")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._reap_expired(connection, now)
            active = connection.execute(
                "SELECT 1 FROM tas_inbox_items WHERE recipient_agent_id = ? AND status = 'leased' AND lease_expires_at > ? LIMIT 1",
                (recipient.value, now.isoformat()),
            ).fetchone()
            if active is not None:
                connection.execute("COMMIT")
                raise InboxConflictError("recipient has an actively leased InboxItem")
            row = connection.execute(
                "SELECT id FROM tas_inbox_items WHERE recipient_agent_id = ? AND attempt_count < max_attempts AND ((status = 'pending' AND available_at <= ?) OR (status = 'leased' AND lease_expires_at <= ?)) ORDER BY available_at, id LIMIT 1",
                (recipient.value, now.isoformat(), now.isoformat()),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            expires = now + duration
            token = LeaseToken(secrets.token_urlsafe(32))
            connection.execute(
                "UPDATE tas_inbox_items SET status = 'leased', attempt_count = attempt_count + 1, lease_token_hash = ?, claimant_agent_id = ?, lease_acquired_at = ?, lease_expires_at = ? WHERE id = ?",
                (self._token_digest(token), claimant.value, now.isoformat(), expires.isoformat(), row[0]),
            )
            connection.execute("COMMIT")
        claimed = self.get(InboxItemId(row[0]))
        return replace(claimed, lease=replace(claimed.lease, token=token))

    def acknowledge(self, item_id: InboxItemId, token: LeaseToken, now: datetime) -> None:
        require_utc(now, "now")
        self._finish_lease(item_id, token, now, acknowledge=True)

    def release(self, item_id: InboxItemId, token: LeaseToken, now: datetime, retry_at: datetime) -> None:
        require_utc(now, "now")
        require_utc(retry_at, "retry_at")
        self._finish_lease(item_id, token, now, acknowledge=False, retry_at=retry_at)

    def reap_expired(self, now: datetime) -> int:
        """Normalize exhausted expired leases; suitable for poll or maintenance loops."""
        require_utc(now, "now")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = self._reap_expired(connection, now)
            connection.execute("COMMIT")
        return changed

    @staticmethod
    def _reap_expired(connection: sqlite3.Connection, now: datetime) -> int:
        cursor = connection.execute(
            "UPDATE tas_inbox_items SET status = 'dead_letter', lease_token_hash = NULL, claimant_agent_id = NULL, lease_acquired_at = NULL, lease_expires_at = NULL WHERE status = 'leased' AND lease_expires_at <= ? AND attempt_count >= max_attempts",
            (now.isoformat(),),
        )
        return cursor.rowcount

    def _finish_lease(self, item_id: InboxItemId, token: LeaseToken, now: datetime, *, acknowledge: bool, retry_at: datetime | None = None) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT attempt_count, max_attempts, status, lease_token_hash, lease_expires_at FROM tas_inbox_items WHERE id = ?", (item_id.value,)).fetchone()
            if row is None or row[2] != "leased" or row[3] != self._token_digest(token) or row[4] <= now.isoformat():
                connection.execute("ROLLBACK")
                raise LeaseAuthorizationError("lease token is not current and active")
            if acknowledge:
                status, available = "acknowledged", None
            elif row[0] >= row[1]:
                status, available = "dead_letter", None
            else:
                if retry_at is None or retry_at < now:
                    connection.execute("ROLLBACK")
                    raise ValueError("retry_at must not be before now")
                status, available = "pending", retry_at.isoformat()
            connection.execute(
                "UPDATE tas_inbox_items SET status = ?, available_at = COALESCE(?, available_at), lease_token_hash = NULL, claimant_agent_id = NULL, lease_acquired_at = NULL, lease_expires_at = NULL WHERE id = ?",
                (status, available, item_id.value),
            )
            connection.execute("COMMIT")

    @staticmethod
    def _build(row: tuple[object, ...]) -> InboxItem:
        lease = None
        if row[7] is not None:
            lease = TaskLease(None, AgentId(str(row[8])), datetime.fromisoformat(str(row[9])), datetime.fromisoformat(str(row[10])))
        return InboxItem(InboxItemId(str(row[0])), TaskId(str(row[1])), AgentId(str(row[2])), datetime.fromisoformat(str(row[3])), int(row[4]), int(row[5]), InboxStatus(str(row[6])), lease)

    @staticmethod
    def _token_digest(token: LeaseToken) -> str:
        return hashlib.sha256(token.value.encode("utf-8")).hexdigest()
