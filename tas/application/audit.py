"""Application-level creation of security Audit Events."""

from datetime import UTC, datetime
from uuid import uuid4

from tas.domain.audit import (
    ActionGrantAuditReason,
    AuditActorKind,
    AuditEvent,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
from tas.domain.approval import ApprovalId
from tas.domain.identity import AgentId
from tas.domain.policy import ActionIntent
from tas.domain.collaboration import Task, TaskStatus
from tas.domain.ports import AuditRepository

from .resource_authorization import ResourceAuthorizationResult


class AuditRecorder:
    def __init__(self, repository: AuditRepository) -> None:
        self.repository = repository

    def authorization_decision(
        self, result: ResourceAuthorizationResult
    ) -> AuditEvent:
        if result.policy_decision is None:
            policy_version = None
            reason = result.reason.value
        else:
            policy_version = result.policy_decision.policy_version
            reason = result.policy_decision.reason.value
        event = AuditEvent(
            AuditEventId(str(uuid4())),
            AuditEventKind.AUTHORIZATION_DECISION,
            AuditActorKind.AGENT,
            result.intent.requester_agent_id.value,
            "repository",
            result.intent.repository,
            result.intent.action.value,
            AuditOutcome(result.outcome.value),
            reason,
            datetime.now(UTC),
            policy_version,
        )
        self.repository.add(event)
        return event

    def task_transition_rejected(
        self,
        task: Task,
        target: TaskStatus,
        actor_id: str,
        reason: str,
    ) -> AuditEvent:
        event = AuditEvent(
            AuditEventId(str(uuid4())),
            AuditEventKind.TASK_TRANSITION_REJECTED,
            AuditActorKind.AGENT,
            actor_id,
            "task",
            task.id.value,
            f"transition:{task.status.value}->{target.value}",
            AuditOutcome.REJECTED,
            reason,
            datetime.now(UTC),
        )
        self.repository.add(event)
        return event

    def action_grant_event(
        self,
        *,
        event_id: AuditEventId,
        kind: AuditEventKind,
        actor_id: AgentId,
        approval_id: ApprovalId,
        intent: ActionIntent,
        outcome: AuditOutcome,
        reason: ActionGrantAuditReason,
        occurred_at: datetime,
        policy_version: str | None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id,
            kind,
            AuditActorKind.AGENT,
            actor_id.value,
            "repository",
            intent.repository,
            intent.action.value,
            outcome,
            reason.value,
            occurred_at,
            policy_version,
            approval_id.value,
        )
        existing = self.repository.get(event_id)
        if existing is None:
            self.repository.add(event)
        elif existing != event:
            raise RuntimeError("stable Action Grant audit event conflicts")
        return event
