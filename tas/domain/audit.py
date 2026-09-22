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
    ACTION_GRANT_CONSUMED = "action_grant_consumed"
    ACTION_GRANT_REJECTED = "action_grant_rejected"
    ACTION_RESULT_UNKNOWN = "action_result_unknown"
    ACTION_RECEIPT_RECONCILED = "action_receipt_reconciled"
    CREDENTIAL_ISSUED = "credential_issued"
    CREDENTIAL_REVOKED = "credential_revoked"
    CREDENTIAL_ROTATED = "credential_rotated"
    AUTHENTICATION_REJECTED = "authentication_rejected"
    POLICY_VERSION_CREATED = "policy_version_created"
    POLICY_CURRENT_CHANGED = "policy_current_changed"


class AuditActorKind(StrEnum):
    AGENT = "agent"
    OWNER = "owner"
    SYSTEM = "system"


class AuditOutcome(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"
    REJECTED = "rejected"
    CONSUMED = "consumed"
    RESULT_UNKNOWN = "result_unknown"
    RECONCILED = "reconciled"
    ISSUED = "issued"
    REVOKED = "revoked"
    ROTATED = "rotated"
    CREATED = "created"
    SELECTED = "selected"


class ActionGrantAuditReason(StrEnum):
    CONSUMED = "grant_consumed"
    RECEIPT_RECONCILED = "receipt_reconciled"
    CALLER_NOT_RECEIVER = "caller_not_receiver"
    APPROVAL_NOT_APPROVED = "approval_not_approved"
    INTENT_MISMATCH = "intent_mismatch"
    APPROVAL_EXPIRED = "approval_expired"
    POLICY_VERSION_CHANGED = "policy_version_changed"
    AUTHORIZATION_CHANGED = "authorization_changed"
    PRECONDITION_CHANGED = "precondition_changed"
    OPERATION_CONFLICT = "operation_conflict"
    EXTERNAL_RESULT_UNKNOWN = "external_result_unknown"


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
    correlation_id: str | None = None

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
        if self.correlation_id is not None:
            _text(self.correlation_id, "correlation_id")
