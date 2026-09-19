"""Route a verified code-change impact to a durable adaptation Task."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from tas.domain.collaboration import TaskId
from tas.domain.delivery import InboxItemId
from tas.domain.events import CodeChangeImpact, CollaborationEventId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


@dataclass(frozen=True, slots=True)
class RouteCodeChangeImpactResult:
    event_id: CollaborationEventId
    task_id: TaskId
    inbox_item_id: InboxItemId
    replayed: bool


class CodeChangeImpactUnitOfWork(Protocol):
    def route(self, actor_id: AgentId, target_agent_id: AgentId, title: str,
              idempotency_key: IdempotencyKey, event: CodeChangeImpact) -> RouteCodeChangeImpactResult: ...


class RouteCodeChangeImpactService:
    def __init__(self, unit_of_work: CodeChangeImpactUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def route(self, authenticated_actor_id: AgentId, target_agent_id: AgentId, title: str,
              idempotency_key: IdempotencyKey, event: CodeChangeImpact) -> RouteCodeChangeImpactResult:
        if not isinstance(authenticated_actor_id, AgentId) or not isinstance(target_agent_id, AgentId):
            raise TypeError("actor IDs must be AgentId")
        if not isinstance(idempotency_key, IdempotencyKey):
            raise TypeError("idempotency_key must be IdempotencyKey")
        if not isinstance(event, CodeChangeImpact):
            raise TypeError("event must be CodeChangeImpact")
        if event.publisher_agent_id != authenticated_actor_id:
            raise PermissionError("event publisher must be the authenticated actor")
        return self.unit_of_work.route(authenticated_actor_id, target_agent_id, title, idempotency_key, event)
