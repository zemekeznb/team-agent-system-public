"""F3 Inbox commands with replay-safe Lease results."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from tas.domain.delivery import (
    InboxItem, InboxItemId, InboxStatus, LeaseToken, require_utc,
)
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.idempotency import IdempotencyKey


class LeaseTokenProvider(Protocol):
    active_key_id: str

    def issue(
        self, actor_id: AgentId, request_key: IdempotencyKey,
        item_id: InboxItemId, attempt: int,
    ) -> tuple[LeaseToken, str]: ...
    def restore(
        self, actor_id: AgentId, request_key: IdempotencyKey,
        item_id: InboxItemId, attempt: int, key_id: str,
    ) -> LeaseToken: ...


@dataclass(frozen=True, slots=True)
class ClaimInboxResult:
    item: InboxItem | None
    replayed: bool


@dataclass(frozen=True, slots=True)
class FinishInboxResult:
    item_id: InboxItemId
    status: InboxStatus
    attempt: int
    available_at: datetime | None
    replayed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.item_id, InboxItemId):
            raise TypeError("item_id must be InboxItemId")
        if not isinstance(self.status, InboxStatus):
            raise TypeError("status must be InboxStatus")
        if type(self.attempt) is not int:
            raise TypeError("attempt must be an integer")
        if type(self.replayed) is not bool:
            raise TypeError("replayed must be a boolean")
        if self.status not in {
            InboxStatus.PENDING, InboxStatus.ACKNOWLEDGED, InboxStatus.DEAD_LETTER,
        }:
            raise DomainValidationError("finish status is invalid")
        if self.attempt < 1:
            raise DomainValidationError("attempt must be positive")
        if (self.status is InboxStatus.PENDING) != (self.available_at is not None):
            raise DomainValidationError(
                "available_at must exist exactly for a pending result"
            )
        if self.available_at is not None:
            require_utc(self.available_at, "available_at")


class InboxCommandUnitOfWork(Protocol):
    def claim(
        self, actor_id: AgentId, key: IdempotencyKey, *, now: datetime,
        lease_duration: timedelta, correlation_id: str,
        wait_timeout: timedelta = timedelta(0),
    ) -> ClaimInboxResult: ...
    def acknowledge(
        self, actor_id: AgentId, key: IdempotencyKey, item_id: InboxItemId,
        token: LeaseToken, *, now: datetime, correlation_id: str,
    ) -> FinishInboxResult: ...
    def release(
        self, actor_id: AgentId, key: IdempotencyKey, item_id: InboxItemId,
        token: LeaseToken, *, now: datetime, retry_delay: timedelta,
        correlation_id: str,
    ) -> FinishInboxResult: ...


class InboxCommandService:
    def __init__(self, unit_of_work: InboxCommandUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def claim(
        self, actor_id: AgentId, key: IdempotencyKey, *, now: datetime,
        lease_duration: timedelta, correlation_id: str,
        wait_timeout: timedelta = timedelta(0),
    ) -> ClaimInboxResult:
        return self.unit_of_work.claim(
            actor_id, key, now=now, lease_duration=lease_duration,
            correlation_id=correlation_id, wait_timeout=wait_timeout,
        )

    def acknowledge(
        self, actor_id: AgentId, key: IdempotencyKey, item_id: InboxItemId,
        token: LeaseToken, *, now: datetime, correlation_id: str,
    ) -> FinishInboxResult:
        return self.unit_of_work.acknowledge(
            actor_id, key, item_id, token, now=now,
            correlation_id=correlation_id,
        )

    def release(
        self, actor_id: AgentId, key: IdempotencyKey, item_id: InboxItemId,
        token: LeaseToken, *, now: datetime, retry_delay: timedelta,
        correlation_id: str,
    ) -> FinishInboxResult:
        return self.unit_of_work.release(
            actor_id, key, item_id, token, now=now, retry_delay=retry_delay,
            correlation_id=correlation_id,
        )
