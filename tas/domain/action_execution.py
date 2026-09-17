"""Approval Grant consumption and external Action Receipt values."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .approval import ApprovalId
from .identity import DomainValidationError
from .policy import ActionIntent


class ExternalActionRejectedError(RuntimeError):
    """The external system authoritatively rejected this exact action."""


class ExternalPreconditionChangedError(ExternalActionRejectedError):
    """The external resource no longer matches approved preconditions."""


class ExternalOperationConflictError(ExternalActionRejectedError):
    """The external operation ID belongs to another exact request."""


class GrantConsumptionConflictError(RuntimeError):
    """A Grant was reserved or completed with another exact request."""


def _text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > 255:
        raise DomainValidationError(f"{field} must be 1..255 non-whitespace characters")


def _utc(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class ExecutionPreconditions:
    workspace_revision: str
    commit_sha: str

    def __post_init__(self) -> None:
        _text(self.workspace_revision, "workspace_revision")
        _text(self.commit_sha, "commit_sha")


@dataclass(frozen=True, slots=True)
class ActionExecutionRequest:
    approval_id: ApprovalId
    intent: ActionIntent
    policy_version: str
    preconditions: ExecutionPreconditions
    requested_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, ApprovalId):
            raise TypeError("approval_id must be ApprovalId")
        if not isinstance(self.intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        _text(self.policy_version, "policy_version")
        if not isinstance(self.preconditions, ExecutionPreconditions):
            raise TypeError("preconditions must be ExecutionPreconditions")
        _utc(self.requested_at, "requested_at")


@dataclass(frozen=True, slots=True)
class ActionReceipt:
    operation_id: str
    request_fingerprint: str
    external_action_id: str
    result_reference: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        for value, field in (
            (self.operation_id, "operation_id"),
            (self.external_action_id, "external_action_id"),
            (self.result_reference, "result_reference"),
        ):
            _text(value, field)
        if (
            not isinstance(self.request_fingerprint, str)
            or len(self.request_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.request_fingerprint)
        ):
            raise DomainValidationError(
                "request_fingerprint must be 64 lowercase hexadecimal characters"
            )
        _utc(self.occurred_at, "occurred_at")


@dataclass(frozen=True, slots=True)
class GrantReservation:
    is_new: bool
    receipt: ActionReceipt | None
    receipt_source: ReceiptSource | None = None
    audit_pending: bool = False


class ReceiptSource(StrEnum):
    EXECUTED = "executed"
    RECONCILED = "reconciled"
