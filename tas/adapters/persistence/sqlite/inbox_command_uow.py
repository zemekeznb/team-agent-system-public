"""Atomic idempotent Inbox Claim for the F3 remote API."""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError, fingerprint_payload,
)
from tas.application.inbox_commands import (
    ClaimInboxResult, FinishInboxResult, LeaseTokenProvider,
)
from tas.domain.audit import (
    AuditActorKind, AuditEvent, AuditEventId, AuditEventKind, AuditOutcome,
)
from tas.domain.collaboration import TaskId
from tas.domain.delivery import (
    InboxItem, InboxItemId, InboxStatus, LeaseToken, TaskLease, require_utc,
)
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class InboxCommandConflictError(RuntimeError):
    """The Agent already holds an active Lease."""


class InboxCommandIntegrityError(RuntimeError):
    """A replay result cannot be reconstructed safely."""


class SQLiteInboxCommandUnitOfWork:
    OPERATION = "inbox.claim"

    def __init__(self, database: str | Path, tokens: LeaseTokenProvider) -> None:
        self.database = Path(database)
        self.tokens = tokens

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def claim(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        *,
        now: datetime,
        lease_duration: timedelta,
        correlation_id: str,
        wait_timeout: timedelta = timedelta(0),
    ) -> ClaimInboxResult:
        require_utc(now, "now")
        if (
            not isinstance(lease_duration, timedelta)
            or not lease_duration.total_seconds().is_integer()
            or not timedelta(seconds=5) <= lease_duration <= timedelta(minutes=5)
        ):
            raise ValueError("lease duration must be 5..300 seconds")
        if (
            not isinstance(wait_timeout, timedelta)
            or not wait_timeout.total_seconds().is_integer()
            or not timedelta(0) <= wait_timeout <= timedelta(seconds=25)
        ):
            raise ValueError("wait timeout must be 0..25 seconds")
        fingerprint_payload_value = {
            "lease_duration_seconds": int(lease_duration.total_seconds())
        }
        if wait_timeout:
            fingerprint_payload_value["wait_timeout_seconds"] = int(
                wait_timeout.total_seconds()
            )
        fingerprint = fingerprint_payload(fingerprint_payload_value)
        deadline = time.monotonic() + wait_timeout.total_seconds()
        current_now = now
        while True:
            finalize_empty = time.monotonic() >= deadline
            if finalize_empty or self._claim_may_progress(
                actor_id, key, current_now
            ):
                result = self._claim_once(
                    actor_id,
                    key,
                    now=current_now,
                    lease_duration=lease_duration,
                    correlation_id=correlation_id,
                    fingerprint=fingerprint.value,
                    finalize_empty=finalize_empty,
                )
                if result is not None:
                    return result
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                current_now = datetime.now(now.tzinfo)
                continue
            time.sleep(min(0.25, remaining))
            current_now = datetime.now(now.tzinfo)

    def _claim_may_progress(
        self, actor_id: AgentId, key: IdempotencyKey, now: datetime
    ) -> bool:
        """Read-only probe; the authoritative decision remains in _claim_once."""
        with self._connect() as connection:
            if connection.execute(
                "SELECT 1 FROM tas_agents WHERE id=?", (actor_id.value,)
            ).fetchone() is None:
                return True
            if connection.execute(
                "SELECT 1 FROM tas_idempotency_records WHERE actor_id=? "
                "AND operation=? AND idempotency_key=?",
                (actor_id.value, self.OPERATION, key.value),
            ).fetchone() is not None:
                return True
            return connection.execute(
                "SELECT 1 FROM tas_inbox_items item "
                "LEFT JOIN tas_tasks task ON task.id=item.task_id "
                "LEFT JOIN tas_projects project ON project.id=task.project_id "
                "LEFT JOIN tas_agents actor ON actor.id=item.recipient_agent_id "
                "LEFT JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "AND member.owner_id=actor.owner_id "
                "WHERE item.recipient_agent_id=? AND ("
                "(item.status='leased' AND item.lease_expires_at>?) OR "
                "(item.status='leased' AND item.lease_expires_at<=? AND "
                "(item.attempt_count>=item.max_attempts OR member.owner_id IS NOT NULL)) OR "
                "(item.status='pending' AND item.attempt_count<item.max_attempts "
                "AND item.available_at<=? AND member.owner_id IS NOT NULL)) LIMIT 1",
                (
                    actor_id.value, now.isoformat(), now.isoformat(),
                    now.isoformat(),
                ),
            ).fetchone() is not None

    def _claim_once(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        *,
        now: datetime,
        lease_duration: timedelta,
        correlation_id: str,
        fingerprint: str,
        finalize_empty: bool,
    ) -> ClaimInboxResult | None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_current_recipient(connection, actor_id)
            ledger = connection.execute(
                "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
                "WHERE actor_id=? AND operation=? AND idempotency_key=?",
                (actor_id.value, self.OPERATION, key.value),
            ).fetchone()
            if ledger is not None:
                result = self._replay(
                    connection, actor_id, key, ledger, fingerprint,
                    now, correlation_id,
                )
                connection.execute("COMMIT")
                return result
            connection.execute(
                "UPDATE tas_inbox_items SET status='dead_letter',lease_token_hash=NULL,"
                "claimant_agent_id=NULL,lease_acquired_at=NULL,lease_expires_at=NULL "
                "WHERE recipient_agent_id=? AND status='leased' AND lease_expires_at<=? "
                "AND attempt_count>=max_attempts",
                (actor_id.value, now.isoformat()),
            )
            active = connection.execute(
                "SELECT 1 FROM tas_inbox_items WHERE recipient_agent_id=? "
                "AND status='leased' AND lease_expires_at>? LIMIT 1",
                (actor_id.value, now.isoformat()),
            ).fetchone()
            if active is not None:
                connection.execute("ROLLBACK")
                raise InboxCommandConflictError("Agent already has an active Lease")
            row = connection.execute(
                "SELECT item.id,item.task_id,item.available_at,item.max_attempts,"
                "item.attempt_count "
                "FROM tas_inbox_items item "
                "JOIN tas_tasks task ON task.id=item.task_id "
                "JOIN tas_projects project ON project.id=task.project_id "
                "JOIN tas_agents actor ON actor.id=item.recipient_agent_id "
                "JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "AND member.owner_id=actor.owner_id "
                "WHERE item.recipient_agent_id=? "
                "AND item.attempt_count<item.max_attempts "
                "AND ((item.status='pending' AND item.available_at<=?) "
                "OR (item.status='leased' AND item.lease_expires_at<=?)) "
                "ORDER BY item.available_at,item.id LIMIT 1",
                (actor_id.value, now.isoformat(), now.isoformat()),
            ).fetchone()
            if row is None:
                if not finalize_empty:
                    connection.execute("ROLLBACK")
                    return None
                result_payload = {"item": None}
                self._complete_ledger(
                    connection, actor_id, key, fingerprint, result_payload, now
                )
                connection.execute("COMMIT")
                return ClaimInboxResult(None, replayed=False)
            item_id = InboxItemId(str(row[0]))
            attempt = int(row[4]) + 1
            token, token_key_id = self.tokens.issue(actor_id, key, item_id, attempt)
            expires_at = now + lease_duration
            connection.execute(
                "UPDATE tas_inbox_items SET status='leased',attempt_count=?,"
                "lease_token_hash=?,claimant_agent_id=?,lease_acquired_at=?,"
                "lease_expires_at=? WHERE id=?",
                (
                    attempt, hashlib.sha256(token.value.encode()).hexdigest(),
                    actor_id.value, now.isoformat(), expires_at.isoformat(), item_id.value,
                ),
            )
            payload = {
                "item_id": item_id.value,
                "task_id": str(row[1]),
                "available_at": str(row[2]),
                "max_attempts": int(row[3]),
                "attempt": attempt,
                "acquired_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "token_version": 1,
                "token_key_id": token_key_id,
            }
            self._complete_ledger(
                connection, actor_id, key, fingerprint, payload, now
            )
            connection.execute("COMMIT")
            return ClaimInboxResult(
                self._item(actor_id, payload, token), replayed=False
            )

    def acknowledge(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        item_id: InboxItemId,
        token: LeaseToken,
        *,
        now: datetime,
        correlation_id: str,
    ) -> FinishInboxResult:
        return self._finish(
            actor_id, key, item_id, token, now=now, retry_delay=None,
            correlation_id=correlation_id,
        )

    def release(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        item_id: InboxItemId,
        token: LeaseToken,
        *,
        now: datetime,
        retry_delay: timedelta,
        correlation_id: str,
    ) -> FinishInboxResult:
        if (
            not isinstance(retry_delay, timedelta)
            or not retry_delay.total_seconds().is_integer()
            or not timedelta(0) <= retry_delay <= timedelta(days=7)
        ):
            raise ValueError("retry delay must be 0..604800 seconds")
        return self._finish(
            actor_id, key, item_id, token, now=now, retry_delay=retry_delay,
            correlation_id=correlation_id,
        )

    def _finish(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        item_id: InboxItemId,
        token: LeaseToken,
        *,
        now: datetime,
        retry_delay: timedelta | None,
        correlation_id: str,
    ) -> FinishInboxResult:
        require_utc(now, "now")
        operation = "inbox.acknowledge" if retry_delay is None else "inbox.release"
        token_hash = hashlib.sha256(token.value.encode("utf-8")).hexdigest()
        fingerprint = fingerprint_payload({
            "item_id": item_id.value,
            "lease_token_sha256": token_hash,
            "retry_delay_seconds": (
                None if retry_delay is None else int(retry_delay.total_seconds())
            ),
        })
        rejection_reason: str | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                item = self._authorized_item(connection, actor_id, item_id)
                if item is None:
                    rejection_reason = "inbox_unavailable"
                    raise InboxCommandConflictError("Inbox item is unavailable")
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
                    "WHERE actor_id=? AND operation=? AND idempotency_key=?",
                    (actor_id.value, operation, key.value),
                ).fetchone()
                if ledger is not None:
                    result = self._replay_finish(
                        ledger, fingerprint.value, item_id,
                        allowed_statuses=(
                            {InboxStatus.ACKNOWLEDGED}
                            if retry_delay is None
                            else {InboxStatus.PENDING, InboxStatus.DEAD_LETTER}
                        ),
                    )
                    connection.execute("COMMIT")
                    return result
                if (
                    item[3] != InboxStatus.LEASED.value
                    or not isinstance(item[4], str)
                    or not hmac.compare_digest(item[4], token_hash)
                    or item[5] != actor_id.value
                    or item[6] <= now.isoformat()
                ):
                    rejection_reason = "lease_not_current"
                    raise InboxCommandConflictError("Lease is not current")
                attempt = int(item[1])
                max_attempts = int(item[2])
                if retry_delay is None:
                    next_status = InboxStatus.ACKNOWLEDGED
                    available_at = None
                elif attempt >= max_attempts:
                    next_status = InboxStatus.DEAD_LETTER
                    available_at = None
                else:
                    next_status = InboxStatus.PENDING
                    available_at = now + retry_delay
                cursor = connection.execute(
                    "UPDATE tas_inbox_items SET status=?,"
                    "available_at=COALESCE(?,available_at),lease_token_hash=NULL,"
                    "claimant_agent_id=NULL,lease_acquired_at=NULL,lease_expires_at=NULL "
                    "WHERE id=? AND status='leased' AND lease_token_hash=? "
                    "AND claimant_agent_id=? AND lease_expires_at>?",
                    (
                        next_status.value,
                        None if available_at is None else available_at.isoformat(),
                        item_id.value, token_hash, actor_id.value, now.isoformat(),
                    ),
                )
                if cursor.rowcount != 1:
                    raise InboxCommandIntegrityError("Lease changed during command")
                payload = {
                    "item_id": item_id.value,
                    "status": next_status.value,
                    "attempt": attempt,
                    "available_at": (
                        None if available_at is None else available_at.isoformat()
                    ),
                }
                self._complete_ledger(
                    connection, actor_id, key, fingerprint.value, payload, now,
                    operation=operation,
                )
                connection.execute("COMMIT")
                return self._finish_result(payload, replayed=False)
        except InboxCommandConflictError:
            if rejection_reason is not None:
                self._audit_rejection(
                    actor_id, item_id, operation, rejection_reason, now,
                    correlation_id,
                )
            raise

    @staticmethod
    def _require_current_recipient(
        connection: sqlite3.Connection, actor_id: AgentId
    ) -> None:
        if connection.execute(
            "SELECT 1 FROM tas_agents WHERE id=?", (actor_id.value,)
        ).fetchone() is None:
            raise InboxCommandConflictError("Agent binding is unavailable")

    def _replay(
        self,
        connection: sqlite3.Connection,
        actor_id: AgentId,
        key: IdempotencyKey,
        row: tuple[str, str],
        fingerprint: str,
        now: datetime,
        correlation_id: str,
    ) -> ClaimInboxResult:
        if row[0] != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            payload = json.loads(row[1])
        except (json.JSONDecodeError, TypeError) as error:
            raise InboxCommandIntegrityError("Claim result is invalid") from error
        if payload.get("item") is None and set(payload) == {"item"}:
            return ClaimInboxResult(None, replayed=True)
        try:
            item_id = InboxItemId(payload["item_id"])
            attempt = payload["attempt"]
            token_version = payload["token_version"]
            token_key_id = payload["token_key_id"]
            if type(attempt) is not int or attempt < 1:
                raise ValueError
            if type(token_version) is not int or token_version != 1:
                raise ValueError
            if not isinstance(token_key_id, str) or not token_key_id:
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise InboxCommandIntegrityError("Claim result is invalid") from error
        if connection.execute(
            "SELECT 1 FROM tas_inbox_items item "
            "JOIN tas_tasks task ON task.id=item.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=item.recipient_agent_id "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id "
            "WHERE item.id=? AND item.recipient_agent_id=?",
            (item_id.value, actor_id.value),
        ).fetchone() is None:
            connection.execute("ROLLBACK")
            self._audit_rejection(
                actor_id, item_id, self.OPERATION, "inbox_unavailable",
                now, correlation_id,
            )
            raise InboxCommandConflictError("Inbox item is unavailable")
        token = self.tokens.restore(
            actor_id, key, item_id, attempt, token_key_id
        )
        return ClaimInboxResult(self._item(actor_id, payload, token), replayed=True)

    @staticmethod
    def _authorized_item(
        connection: sqlite3.Connection, actor_id: AgentId, item_id: InboxItemId
    ) -> tuple[object, ...] | None:
        return connection.execute(
            "SELECT item.id,item.attempt_count,item.max_attempts,item.status,"
            "item.lease_token_hash,item.claimant_agent_id,item.lease_expires_at "
            "FROM tas_inbox_items item "
            "JOIN tas_tasks task ON task.id=item.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=item.recipient_agent_id "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id "
            "WHERE item.id=? AND item.recipient_agent_id=?",
            (item_id.value, actor_id.value),
        ).fetchone()

    @staticmethod
    def _replay_finish(
        row: tuple[str, str], fingerprint: str, item_id: InboxItemId, *,
        allowed_statuses: set[InboxStatus],
    ) -> FinishInboxResult:
        if row[0] != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            payload = json.loads(row[1])
            if payload["item_id"] != item_id.value:
                raise ValueError
            result = SQLiteInboxCommandUnitOfWork._finish_result(
                payload, replayed=True
            )
            if result.status not in allowed_statuses:
                raise ValueError
            return result
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as error:
            raise InboxCommandIntegrityError("Inbox result is invalid") from error

    @staticmethod
    def _finish_result(payload: dict, *, replayed: bool) -> FinishInboxResult:
        available_at = payload.get("available_at")
        attempt = payload["attempt"]
        if type(attempt) is not int:
            raise ValueError("Inbox result attempt is invalid")
        return FinishInboxResult(
            InboxItemId(payload["item_id"]),
            InboxStatus(payload["status"]),
            attempt,
            None if available_at is None else datetime.fromisoformat(available_at),
            replayed,
        )

    @staticmethod
    def _item(actor_id: AgentId, payload: dict, token) -> InboxItem:
        return InboxItem(
            InboxItemId(payload["item_id"]),
            TaskId(payload["task_id"]),
            actor_id,
            datetime.fromisoformat(payload["available_at"]),
            int(payload["max_attempts"]),
            int(payload["attempt"]),
            InboxStatus.LEASED,
            TaskLease(
                token, actor_id, datetime.fromisoformat(payload["acquired_at"]),
                datetime.fromisoformat(payload["expires_at"]),
            ),
        )

    def _complete_ledger(
        self, connection, actor_id, key, fingerprint, payload, now, *,
        operation: str | None = None,
    ) -> None:
        connection.execute(
            "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,"
            "request_fingerprint,status,reservation_token_hash,result_json,created_at,"
            "updated_at) VALUES (?,?,?,?, 'completed',NULL,?,?,?)",
            (
                actor_id.value, operation or self.OPERATION, key.value, fingerprint,
                json.dumps(payload, sort_keys=True, separators=(",", ":")),
                now.isoformat(), now.isoformat(),
            ),
        )

    def _audit_rejection(
        self,
        actor_id: AgentId,
        item_id: InboxItemId,
        operation: str,
        reason: str,
        now: datetime,
        correlation_id: str,
    ) -> None:
        event = AuditEvent(
            AuditEventId(str(uuid4())), AuditEventKind.AUTHORIZATION_DECISION,
            AuditActorKind.AGENT, actor_id.value, "inbox_item", item_id.value,
            operation, AuditOutcome.REJECTED, reason, now,
            correlation_id=correlation_id,
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,"
                "resource_type,resource_id,action,outcome,reason,occurred_at,"
                "policy_version,correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    event.id.value, event.kind.value, event.actor_kind.value,
                    event.actor_id, event.resource_type, event.resource_id,
                    event.action, event.outcome.value, event.reason,
                    event.occurred_at.isoformat(), event.policy_version,
                    event.correlation_id,
                ),
            )
