"""Infrastructure-independent security audit events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .identity import DomainValidationError


def _text(value: str, field: str, maximum: int = 255) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainValidationError(
            f"{field} must be 1..{maximum} non-whitespace characters"
        )


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class AuditEventId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "AuditEventId")


class AuditEventKind(StrEnum):
    AUTHORIZATION_DECISION = "authorization_decision"
    TASK_TRANSITION_REJECTED = "task_transition_rejected"


class AuditActorKind(StrEnum):
    AGENT = "agent"
    OWNER = "owner"
    SYSTEM = "system"


class AuditOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED = "rejected"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    id: AuditEventId
    kind: AuditEventKind
    actor_kind: AuditActorKind
    actor_id: str
    resource_type: str
    resource_id: str
    action: str
    outcome: AuditOutcome
    reason: str
    occurred_at: datetime
    policy_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, AuditEventId):
            raise TypeError("id must be AuditEventId")
        if not isinstance(self.kind, AuditEventKind):
            raise TypeError("kind must be AuditEventKind")
        if not isinstance(self.actor_kind, AuditActorKind):
            raise TypeError("actor_kind must be AuditActorKind")
        if not isinstance(self.outcome, AuditOutcome):
            raise TypeError("outcome must be AuditOutcome")
        for value, field in (
            (self.actor_id, "actor_id"),
            (self.resource_type, "resource_type"),
            (self.resource_id, "resource_id"),
            (self.action, "action"),
            (self.reason, "reason"),
        ):
            _text(value, field)
        _utc(self.occurred_at, "occurred_at")
        if self.policy_version is not None:
            _text(self.policy_version, "policy_version")
