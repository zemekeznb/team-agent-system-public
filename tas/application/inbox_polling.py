"""Technology-independent bounded polling over the durable Inbox port."""

from __future__ import annotations

import asyncio
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Awaitable, Callable, Protocol

from tas.domain.delivery import InboxItem, InboxItemId, LeaseToken
from tas.domain.identity import AgentId
from tas.domain.ports import InboxRepository


class PollClock(Protocol):
    def utc_now(self) -> datetime: ...
    def monotonic(self) -> float: ...


class SystemPollClock:
    def utc_now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class PollResult:
    item: InboxItem | None
    timed_out: bool

    def __post_init__(self) -> None:
        if self.timed_out == (self.item is not None):
            raise ValueError("poll result must be either an item or a timeout")


class InboxAccessError(RuntimeError):
    """The bound actor cannot operate the requested Inbox item."""


class InboxPollingService:
    def __init__(
        self,
        repository: InboxRepository,
        *,
        clock: PollClock | None = None,
        sleeper: Callable[[float], Awaitable[None]] = asyncio.sleep,
        poll_interval_seconds: float = 0.1,
    ) -> None:
        if not isinstance(poll_interval_seconds, (int, float)) or isinstance(
            poll_interval_seconds, bool
        ) or not math.isfinite(poll_interval_seconds) or poll_interval_seconds <= 0:
            raise ValueError("poll_interval_seconds must be positive")
        self._repository = repository
        self._clock = clock or SystemPollClock()
        self._sleeper = sleeper
        self._poll_interval_seconds = float(poll_interval_seconds)

    async def poll_and_claim(
        self,
        *,
        actor_id: AgentId,
        wait_timeout: timedelta,
        lease_duration: timedelta,
    ) -> PollResult:
        if not isinstance(actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if not isinstance(wait_timeout, timedelta) or wait_timeout < timedelta(0):
            raise ValueError("wait_timeout must be a non-negative timedelta")
        if not isinstance(lease_duration, timedelta) or lease_duration <= timedelta(0):
            raise ValueError("lease_duration must be a positive timedelta")

        deadline = self._clock.monotonic() + wait_timeout.total_seconds()
        while True:
            item = self._repository.claim_next(
                actor_id,
                actor_id,
                self._clock.utc_now(),
                lease_duration,
            )
            if item is not None:
                return PollResult(item=item, timed_out=False)
            remaining = deadline - self._clock.monotonic()
            if remaining <= 0:
                return PollResult(item=None, timed_out=True)
            await self._sleeper(min(self._poll_interval_seconds, remaining))

    def acknowledge(
        self,
        *,
        actor_id: AgentId,
        item_id: InboxItemId,
        lease_token: LeaseToken,
    ) -> None:
        self._require_recipient(actor_id, item_id)
        self._repository.acknowledge(
            item_id, lease_token, self._clock.utc_now()
        )

    def release(
        self,
        *,
        actor_id: AgentId,
        item_id: InboxItemId,
        lease_token: LeaseToken,
        retry_delay: timedelta,
    ) -> None:
        if not isinstance(retry_delay, timedelta) or retry_delay < timedelta(0):
            raise ValueError("retry_delay must be a non-negative timedelta")
        self._require_recipient(actor_id, item_id)
        now = self._clock.utc_now()
        self._repository.release(item_id, lease_token, now, now + retry_delay)

    def _require_recipient(self, actor_id: AgentId, item_id: InboxItemId) -> None:
        if not isinstance(actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if not isinstance(item_id, InboxItemId):
            raise TypeError("item_id must be InboxItemId")
        item = self._repository.get(item_id)
        if item is None or item.recipient_agent_id != actor_id:
            raise InboxAccessError("Inbox item is unavailable to the bound Agent")
