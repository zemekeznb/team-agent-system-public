"""Safe consumption and reconciliation of approved external actions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4

from tas.domain.action_execution import (
    ActionExecutionRequest,
    ActionReceipt,
    ExecutionPreconditions,
    ExternalOperationConflictError,
    ExternalPreconditionChangedError,
    GrantConsumptionConflictError,
    GrantReservation,
    ReceiptSource,
)
from tas.domain.approval import ApprovalId, ApprovalStatus
from tas.domain.audit import (
    ActionGrantAuditReason,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
from tas.domain.identity import AgentId
from tas.domain.policy import ActionIntent, OwnerPolicy
from tas.domain.ports import (
    ActionGrantRepository,
    ApprovalRepository,
    ExternalActionExecutor,
)

from .resource_authorization import ResourceAuthorizationService
from .audit import AuditRecorder


class GrantConsumptionRejectedError(RuntimeError):
    """The current request no longer matches an executable Approval Grant."""


class ExternalActionResultUnknownError(RuntimeError):
    """The external result cannot yet be classified safely."""

    def __init__(self, message: str, *, audit_pending: bool) -> None:
        super().__init__(message)
        self.audit_pending = audit_pending


@dataclass(frozen=True, slots=True)
class ConsumeGrantResult:
    receipt: ActionReceipt
    replayed: bool
    reconciled: bool
    audit_pending: bool = False


class ConsumeApprovalGrantService:
    def __init__(
        self,
        approvals: ApprovalRepository,
        authorization: ResourceAuthorizationService,
        grants: ActionGrantRepository,
        executor: ExternalActionExecutor,
        audit: AuditRecorder,
    ) -> None:
        self.approvals = approvals
        self.authorization = authorization
        self.grants = grants
        self.executor = executor
        self.audit = audit

    def consume(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy: OwnerPolicy,
        preconditions: ExecutionPreconditions,
        now: datetime,
    ) -> ConsumeGrantResult:
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timedelta(0):
            raise GrantConsumptionRejectedError("execution time must use UTC")
        if not isinstance(actor_id, AgentId) or actor_id != intent.receiving_agent_id:
            if isinstance(actor_id, AgentId):
                self._reject(
                    approval_id,
                    actor_id,
                    intent,
                    policy.version,
                    now,
                    ActionGrantAuditReason.CALLER_NOT_RECEIVER,
                )
            raise GrantConsumptionRejectedError(
                "request rejected at Action Grant security boundary"
            )
        approval = self.approvals.get(approval_id)
        if approval is None or approval.status is not ApprovalStatus.APPROVED:
            self._reject(
                approval_id,
                actor_id,
                intent,
                policy.version,
                now,
                ActionGrantAuditReason.APPROVAL_NOT_APPROVED,
            )
        if approval.decision.intent != intent:
            self._reject(
                approval_id,
                actor_id,
                intent,
                approval.decision.policy_version,
                now,
                ActionGrantAuditReason.INTENT_MISMATCH,
            )
        request = ActionExecutionRequest(
            approval_id,
            intent,
            approval.decision.policy_version,
            preconditions,
            now,
        )
        fingerprint = fingerprint_action_request(request)
        try:
            existing = self.grants.get(approval_id, fingerprint)
        except GrantConsumptionConflictError:
            self._reject(
                approval_id,
                actor_id,
                intent,
                approval.decision.policy_version,
                now,
                ActionGrantAuditReason.OPERATION_CONFLICT,
            )
        if existing is not None and existing.receipt is not None:
            audit_pending = self._record_completion(
                approval_id, actor_id, intent, approval.decision.policy_version,
                fingerprint, existing
            )
            return ConsumeGrantResult(existing.receipt, True, False, audit_pending)
        if existing is not None:
            receipt = self._find_receipt_or_unknown(
                approval_id, actor_id, intent, approval.decision.policy_version, now
            )
            if receipt is not None:
                completed = self._complete_or_reject(
                    approval_id, actor_id, intent, approval.decision.policy_version,
                    now, fingerprint, receipt, ReceiptSource.RECONCILED
                )
                audit_pending = self._record_completion(
                    approval_id, actor_id, intent, approval.decision.policy_version,
                    fingerprint, completed
                )
                return ConsumeGrantResult(
                    completed.receipt, True, True, audit_pending
                )
        if now >= approval.expires_at:
            self._reject(
                approval_id, actor_id, intent, approval.decision.policy_version,
                now, ActionGrantAuditReason.APPROVAL_EXPIRED
            )
        if policy.version != approval.decision.policy_version:
            self._reject(
                approval_id, actor_id, intent, approval.decision.policy_version,
                now, ActionGrantAuditReason.POLICY_VERSION_CHANGED
            )
        authorization = self.authorization.authorize(intent, policy)
        if authorization.policy_decision != approval.decision:
            self._reject(
                approval_id, actor_id, intent, approval.decision.policy_version,
                now, ActionGrantAuditReason.AUTHORIZATION_CHANGED
            )
        try:
            self.executor.check_preconditions(request)
        except ExternalPreconditionChangedError:
            self._reject(
                approval_id, actor_id, intent, approval.decision.policy_version,
                now, ActionGrantAuditReason.PRECONDITION_CHANGED
            )
        try:
            reservation = self.grants.reserve(approval_id, fingerprint, now)
        except GrantConsumptionConflictError:
            self._reject(
                approval_id, actor_id, intent, approval.decision.policy_version,
                now, ActionGrantAuditReason.OPERATION_CONFLICT
            )
        if reservation.receipt is not None:
            audit_pending = self._record_completion(
                approval_id, actor_id, intent, approval.decision.policy_version,
                fingerprint, reservation
            )
            return ConsumeGrantResult(
                reservation.receipt, True, False, audit_pending
            )
        receipt = self._find_receipt_or_unknown(
            approval_id, actor_id, intent, approval.decision.policy_version, now
        )
        reconciled = receipt is not None
        if receipt is None:
            try:
                receipt = self.executor.execute_once(request, fingerprint)
            except ExternalPreconditionChangedError:
                self._reject(
                    approval_id, actor_id, intent, approval.decision.policy_version,
                    now, ActionGrantAuditReason.PRECONDITION_CHANGED
                )
            except ExternalOperationConflictError:
                self._reject(
                    approval_id, actor_id, intent, approval.decision.policy_version,
                    now, ActionGrantAuditReason.OPERATION_CONFLICT
                )
            except Exception as error:
                audit_pending = not self._record_unknown(
                    approval_id,
                    actor_id,
                    intent,
                    approval.decision.policy_version,
                    now,
                )
                raise ExternalActionResultUnknownError(
                    "external action result is unknown; reconcile by operation ID",
                    audit_pending=audit_pending,
                ) from error
        source = ReceiptSource.RECONCILED if reconciled else ReceiptSource.EXECUTED
        completed = self._complete_or_reject(
            approval_id, actor_id, intent, approval.decision.policy_version,
            now, fingerprint, receipt, source
        )
        audit_pending = self._record_completion(
            approval_id, actor_id, intent, approval.decision.policy_version,
            fingerprint, completed
        )
        return ConsumeGrantResult(
            completed.receipt,
            not reservation.is_new,
            reconciled,
            audit_pending,
        )

    def _reject(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy_version: str | None,
        now: datetime,
        reason: ActionGrantAuditReason,
    ) -> None:
        try:
            self.audit.action_grant_event(
                event_id=AuditEventId(str(uuid4())),
                kind=AuditEventKind.ACTION_GRANT_REJECTED,
                actor_id=actor_id,
                approval_id=approval_id,
                intent=intent,
                outcome=AuditOutcome.REJECTED,
                reason=reason,
                occurred_at=now,
                policy_version=policy_version,
            )
        except Exception as error:
            raise GrantConsumptionRejectedError(
                "request rejected; security audit is unavailable"
            ) from error
        raise GrantConsumptionRejectedError(
            "request rejected at Action Grant security boundary"
        )

    def _complete_or_reject(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy_version: str,
        now: datetime,
        fingerprint: str,
        receipt: ActionReceipt,
        source: ReceiptSource,
    ) -> GrantReservation:
        if receipt.request_fingerprint != fingerprint:
            self._reject(
                approval_id, actor_id, intent, policy_version, now,
                ActionGrantAuditReason.OPERATION_CONFLICT
            )
        try:
            return self.grants.complete(
                approval_id, fingerprint, receipt, source
            )
        except GrantConsumptionConflictError:
            self._reject(
                approval_id, actor_id, intent, policy_version, now,
                ActionGrantAuditReason.OPERATION_CONFLICT
            )

    def _record_unknown(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy_version: str,
        now: datetime,
    ) -> bool:
        try:
            self.audit.action_grant_event(
                event_id=AuditEventId(str(uuid4())),
                kind=AuditEventKind.ACTION_RESULT_UNKNOWN,
                actor_id=actor_id,
                approval_id=approval_id,
                intent=intent,
                outcome=AuditOutcome.RESULT_UNKNOWN,
                reason=ActionGrantAuditReason.EXTERNAL_RESULT_UNKNOWN,
                occurred_at=now,
                policy_version=policy_version,
            )
            return True
        except Exception:
            return False

    def _find_receipt_or_unknown(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy_version: str,
        now: datetime,
    ) -> ActionReceipt | None:
        try:
            return self.executor.find_receipt(approval_id.value)
        except Exception as error:
            audit_pending = not self._record_unknown(
                approval_id, actor_id, intent, policy_version, now
            )
            raise ExternalActionResultUnknownError(
                "external action result is unknown; reconcile by operation ID",
                audit_pending=audit_pending,
            ) from error

    def _record_completion(
        self,
        approval_id: ApprovalId,
        actor_id: AgentId,
        intent: ActionIntent,
        policy_version: str,
        fingerprint: str,
        reservation: GrantReservation,
    ) -> bool:
        if not reservation.audit_pending:
            return False
        source = reservation.receipt_source
        receipt = reservation.receipt
        if source is None or receipt is None:
            return True
        reconciled = source is ReceiptSource.RECONCILED
        event_id = AuditEventId(f"action-grant:{approval_id.value}:completion")
        try:
            event = self.audit.action_grant_event(
                event_id=event_id,
                kind=(
                    AuditEventKind.ACTION_RECEIPT_RECONCILED
                    if reconciled
                    else AuditEventKind.ACTION_GRANT_CONSUMED
                ),
                actor_id=actor_id,
                approval_id=approval_id,
                intent=intent,
                outcome=(
                    AuditOutcome.RECONCILED if reconciled else AuditOutcome.CONSUMED
                ),
                reason=(
                    ActionGrantAuditReason.RECEIPT_RECONCILED
                    if reconciled
                    else ActionGrantAuditReason.CONSUMED
                ),
                occurred_at=receipt.occurred_at,
                policy_version=policy_version,
            )
            self.grants.mark_audited(approval_id, fingerprint, event.id)
            return False
        except Exception:
            return True


def fingerprint_action_request(request: ActionExecutionRequest) -> str:
    intent = request.intent
    payload = {
        "approval_id": request.approval_id.value,
        "requester_agent_id": intent.requester_agent_id.value,
        "requester_owner_id": intent.requester_owner_id.value,
        "receiving_agent_id": intent.receiving_agent_id.value,
        "receiving_owner_id": intent.receiving_owner_id.value,
        "team_id": intent.team_id.value,
        "project_id": intent.project_id.value,
        "task_id": None if intent.task_id is None else intent.task_id.value,
        "repository": intent.repository,
        "action": intent.action.value,
        "scope": intent.scope,
        "risk": int(intent.risk),
        "policy_version": request.policy_version,
        "workspace_revision": request.preconditions.workspace_revision,
        "commit_sha": request.preconditions.commit_sha,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
