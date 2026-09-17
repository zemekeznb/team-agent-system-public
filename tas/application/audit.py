"""Application-level creation of security Audit Events."""

from datetime import UTC, datetime
from uuid import uuid4

from tas.domain.audit import (
    AuditActorKind,
    AuditEvent,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
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
