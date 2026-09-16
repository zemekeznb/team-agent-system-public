"""Durable inbox values independent of storage and notification technology."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .collaboration import TaskId
from .identity import AgentId, DomainValidationError


def _text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError(f"{field} must not be blank")


def require_utc(value: datetime, field: str) -> None:
    """Validate a timezone-aware UTC timestamp at a domain boundary."""
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DomainValidationError(f"{field} must be timezone-aware")
    if value.utcoffset() != timedelta(0):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class InboxItemId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "InboxItemId")


@dataclass(frozen=True, slots=True)
class LeaseToken:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "LeaseToken")


class InboxStatus(StrEnum):
    PENDING = "pending"
    LEASED = "leased"
    ACKNOWLEDGED = "acknowledged"
    DEAD_LETTER = "dead_letter"


@dataclass(frozen=True, slots=True)
class TaskLease:
    token: LeaseToken | None
    claimant_agent_id: AgentId
    acquired_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.token is not None and not isinstance(self.token, LeaseToken):
            raise TypeError("token must be LeaseToken or None")
        if not isinstance(self.claimant_agent_id, AgentId):
            raise TypeError("claimant_agent_id must be AgentId")
        require_utc(self.acquired_at, "acquired_at")
        require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.acquired_at:
            raise DomainValidationError("expires_at must be after acquired_at")


@dataclass(frozen=True, slots=True)
class InboxItem:
    id: InboxItemId
    task_id: TaskId
    recipient_agent_id: AgentId
    available_at: datetime
    max_attempts: int = 3
    attempt_count: int = 0
    status: InboxStatus = InboxStatus.PENDING
    lease: TaskLease | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, InboxItemId):
            raise TypeError("id must be InboxItemId")
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.recipient_agent_id, AgentId):
            raise TypeError("recipient_agent_id must be AgentId")
        require_utc(self.available_at, "available_at")
        if self.max_attempts < 1:
            raise DomainValidationError("max_attempts must be positive")
        if self.attempt_count < 0 or self.attempt_count > self.max_attempts:
            raise DomainValidationError("attempt_count is outside its valid range")
        if (self.status is InboxStatus.LEASED) != (self.lease is not None):
            raise DomainValidationError("lease must exist exactly while status is leased")
