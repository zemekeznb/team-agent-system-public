"""Safe consumption and reconciliation of approved external actions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta

from tas.domain.action_execution import (
    ActionExecutionRequest,
    ActionReceipt,
    ExecutionPreconditions,
    ExternalActionRejectedError,
)
from tas.domain.approval import ApprovalId, ApprovalStatus
from tas.domain.identity import AgentId
from tas.domain.policy import ActionIntent, OwnerPolicy
from tas.domain.ports import (
    ActionGrantRepository,
    ApprovalRepository,
    ExternalActionExecutor,
)

from .resource_authorization import ResourceAuthorizationService


class GrantConsumptionRejectedError(RuntimeError):
    """The current request no longer matches an executable Approval Grant."""


class ExternalActionResultUnknownError(RuntimeError):
    """The external result cannot yet be classified safely."""


@dataclass(frozen=True, slots=True)
class ConsumeGrantResult:
    receipt: ActionReceipt
    replayed: bool
    reconciled: bool


class ConsumeApprovalGrantService:
    def __init__(
        self,
        approvals: ApprovalRepository,
        authorization: ResourceAuthorizationService,
        grants: ActionGrantRepository,
        executor: ExternalActionExecutor,
    ) -> None:
        self.approvals = approvals
        self.authorization = authorization
        self.grants = grants
        self.executor = executor

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
            raise GrantConsumptionRejectedError(
                "only the receiving Agent may consume or replay this Grant"
            )
        approval = self.approvals.get(approval_id)
        if approval is None or approval.status is not ApprovalStatus.APPROVED:
            raise GrantConsumptionRejectedError("Approval Grant is not approved")
        if approval.decision.intent != intent:
            raise GrantConsumptionRejectedError("request does not match approved ActionIntent")
        request = ActionExecutionRequest(
            approval_id,
            intent,
            approval.decision.policy_version,
            preconditions,
            now,
        )
        fingerprint = _fingerprint(request)
        existing = self.grants.get(approval_id, fingerprint)
        if existing is not None and existing.receipt is not None:
            return ConsumeGrantResult(existing.receipt, True, False)
        if existing is not None:
            receipt = self.executor.find_receipt(approval_id.value)
            if receipt is not None:
                persisted = self.grants.complete(approval_id, fingerprint, receipt)
                return ConsumeGrantResult(persisted, True, True)
        if now >= approval.expires_at:
            raise GrantConsumptionRejectedError("Approval Grant has expired")
        if policy.version != approval.decision.policy_version:
            raise GrantConsumptionRejectedError("Policy Version no longer matches Approval")
        authorization = self.authorization.authorize(intent, policy)
        if authorization.policy_decision != approval.decision:
            raise GrantConsumptionRejectedError(
                "current resource or Policy decision no longer matches Approval"
            )
        try:
            self.executor.check_preconditions(request)
        except ExternalActionRejectedError as error:
            raise GrantConsumptionRejectedError(str(error)) from error
        reservation = self.grants.reserve(approval_id, fingerprint, now)
        if reservation.receipt is not None:
            return ConsumeGrantResult(reservation.receipt, True, False)
        receipt = self.executor.find_receipt(approval_id.value)
        reconciled = receipt is not None
        if receipt is None:
            try:
                receipt = self.executor.execute_once(request, fingerprint)
            except ExternalActionRejectedError as error:
                raise GrantConsumptionRejectedError(str(error)) from error
            except Exception as error:
                raise ExternalActionResultUnknownError(
                    "external action result is unknown; reconcile by operation ID"
                ) from error
        persisted = self.grants.complete(approval_id, fingerprint, receipt)
        return ConsumeGrantResult(persisted, not reservation.is_new, reconciled)


def _fingerprint(request: ActionExecutionRequest) -> str:
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
