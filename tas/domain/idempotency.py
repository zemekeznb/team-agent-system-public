"""Technology-independent idempotency values for F2-013."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Any

from .identity import AgentId, DomainValidationError


FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")


def _text(value: str, field: str, maximum: int = 255) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError(f"{field} must not be blank")
    if len(value) > maximum:
        raise DomainValidationError(f"{field} is too long")


@dataclass(frozen=True, slots=True)
class IdempotencyKey:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "IdempotencyKey")


@dataclass(frozen=True, slots=True)
class OperationName:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "OperationName", 100)


@dataclass(frozen=True, slots=True)
class RequestFingerprint:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or FINGERPRINT.fullmatch(self.value) is None:
            raise DomainValidationError("RequestFingerprint must be lowercase SHA-256 hex")


@dataclass(frozen=True, slots=True)
class ReservationToken:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "ReservationToken")


class IdempotencyStatus(StrEnum):
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class IdempotencyRecord:
    actor_id: AgentId
    operation: OperationName
    key: IdempotencyKey
    fingerprint: RequestFingerprint
    status: IdempotencyStatus
    reservation_token: ReservationToken | None
    result: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if (self.status is IdempotencyStatus.IN_PROGRESS) != (
            self.reservation_token is not None
        ):
            raise DomainValidationError(
                "reservation token must exist exactly while in progress"
            )
        if (self.status is IdempotencyStatus.COMPLETED) != (self.result is not None):
            raise DomainValidationError("result must exist exactly when completed")

    def with_token(self, value: str) -> IdempotencyRecord:
        return replace(self, reservation_token=ReservationToken(value))
