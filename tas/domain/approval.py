"""Infrastructure-independent approval aggregate."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum

from .identity import DomainValidationError, OwnerId
from .policy import AuthorizationDecision, PolicyOutcome
from .collaboration import Task, TaskStatus


def _utc(value: datetime, field: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class ApprovalId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip():
            raise DomainValidationError("ApprovalId must not be blank")


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class InvalidApprovalTransitionError(DomainValidationError):
    """Raised when an approval decision violates its state or time boundary."""


@dataclass(frozen=True, slots=True)
class Approval:
    id: ApprovalId
    decision: AuthorizationDecision
    requested_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    resolved_by: OwnerId | None = None
    resolved_at: datetime | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, ApprovalId):
            raise TypeError("id must be ApprovalId")
        if not isinstance(self.decision, AuthorizationDecision):
            raise TypeError("decision must be AuthorizationDecision")
        if self.decision.outcome is not PolicyOutcome.APPROVAL_REQUIRED:
            raise DomainValidationError("Approval requires an approval_required decision")
        if self.decision.policy_owner_id != self.decision.intent.receiving_owner_id:
            raise DomainValidationError("Approval policy Owner must be the receiving Owner")
        _utc(self.requested_at, "requested_at")
        _utc(self.expires_at, "expires_at")
        if self.expires_at <= self.requested_at:
            raise DomainValidationError("expires_at must be after requested_at")
        if self.status is ApprovalStatus.PENDING:
            if any(value is not None for value in (self.resolved_by, self.resolved_at, self.reason)):
                raise DomainValidationError("pending Approval cannot have resolution fields")
        else:
            if self.resolved_at is None:
                raise DomainValidationError("resolved Approval requires resolved_at")
            _utc(self.resolved_at, "resolved_at")
            if self.resolved_at < self.requested_at:
                raise DomainValidationError("resolved_at cannot precede requested_at")
            if self.status is ApprovalStatus.EXPIRED:
                if self.resolved_by is not None or self.reason is not None or self.resolved_at < self.expires_at:
                    raise DomainValidationError("expired Approval must resolve at or after expiry without actor")
            elif not isinstance(self.resolved_by, OwnerId):
                raise DomainValidationError("human decision requires resolving Owner")
            elif self.resolved_by != self.decision.policy_owner_id:
                raise DomainValidationError("resolving Owner must be the receiving policy Owner")
            elif self.resolved_at >= self.expires_at:
                raise DomainValidationError("human decision must precede expiry")
            if self.reason is not None and (not isinstance(self.reason, str) or not self.reason.strip()):
                raise DomainValidationError("resolution reason must not be blank")
            if self.status is ApprovalStatus.REJECTED and (not isinstance(self.reason, str) or not self.reason.strip()):
                raise DomainValidationError("rejected Approval requires a reason")

    def approve(self, approver: OwnerId, now: datetime, reason: str | None = None) -> Approval:
        return self._human_resolution(ApprovalStatus.APPROVED, approver, now, reason)

    def reject(self, approver: OwnerId, now: datetime, reason: str) -> Approval:
        return self._human_resolution(ApprovalStatus.REJECTED, approver, now, reason)

    def expire(self, now: datetime) -> Approval:
        self._require_pending()
        _utc(now, "now")
        if now < self.expires_at:
            raise InvalidApprovalTransitionError("Approval cannot expire before expires_at")
        return replace(self, status=ApprovalStatus.EXPIRED, resolved_at=now)

    def apply_to_task(self, task: Task) -> Task:
        if self.status is ApprovalStatus.PENDING:
            raise InvalidApprovalTransitionError("pending Approval cannot update Task")
        if self.decision.intent.task_id is None or task.id != self.decision.intent.task_id:
            raise InvalidApprovalTransitionError("Approval does not belong to Task")
        if task.status is not TaskStatus.APPROVAL_REQUIRED:
            raise InvalidApprovalTransitionError("Task is not awaiting approval")
        target = {
            ApprovalStatus.APPROVED: TaskStatus.WORKING,
            ApprovalStatus.REJECTED: TaskStatus.REJECTED,
            ApprovalStatus.EXPIRED: TaskStatus.EXPIRED,
        }[self.status]
        return task.transition(
            target,
            actor_id=self.decision.intent.receiving_agent_id,
            reason=f"approval:{self.id.value}:{self.status.value}",
            occurred_at=self.resolved_at,
        )

    def _human_resolution(self, status: ApprovalStatus, approver: OwnerId, now: datetime, reason: str | None) -> Approval:
        self._require_pending()
        if not isinstance(approver, OwnerId):
            raise TypeError("approver must be OwnerId")
        _utc(now, "now")
        if approver != self.decision.policy_owner_id:
            raise InvalidApprovalTransitionError("only the receiving policy Owner may decide")
        if now >= self.expires_at:
            raise InvalidApprovalTransitionError("expired Approval cannot be decided")
        return replace(self, status=status, resolved_by=approver, resolved_at=now, reason=reason)

    def _require_pending(self) -> None:
        if self.status is not ApprovalStatus.PENDING:
            raise InvalidApprovalTransitionError("Approval is already resolved")
