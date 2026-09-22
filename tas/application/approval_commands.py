"""F3 Approval request and decision commands."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from tas.domain.approval import Approval, ApprovalId
from tas.domain.collaboration import TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, OwnerId
from tas.domain.policy import Action, Risk


@dataclass(frozen=True, slots=True)
class RequestApprovalCommand:
    task_id: TaskId
    repository: str
    action: Action
    scope: str
    risk: Risk
    lifetime: timedelta


@dataclass(frozen=True, slots=True)
class DecideApprovalCommand:
    approval_id: ApprovalId
    approve: bool
    reason: str | None


@dataclass(frozen=True, slots=True)
class ApprovalCommandResult:
    approval: Approval
    replayed: bool


class ApprovalCommandUnitOfWork(Protocol):
    def request(
        self, actor_id: AgentId, key: IdempotencyKey,
        command: RequestApprovalCommand, *, now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult: ...

    def decide(
        self, actor_id: OwnerId, key: IdempotencyKey,
        command: DecideApprovalCommand, *, now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult: ...

    def get_for_agent(
        self, actor_id: AgentId, approval_id: ApprovalId
    ) -> Approval | None: ...

    def get_for_owner(
        self, actor_id: OwnerId, approval_id: ApprovalId
    ) -> Approval | None: ...


class ApprovalCommandService:
    def __init__(self, unit_of_work: ApprovalCommandUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def request(
        self, actor_id: AgentId, key: IdempotencyKey,
        command: RequestApprovalCommand, *, now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult:
        return self.unit_of_work.request(
            actor_id, key, command, now=now, correlation_id=correlation_id
        )

    def decide(
        self, actor_id: OwnerId, key: IdempotencyKey,
        command: DecideApprovalCommand, *, now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult:
        return self.unit_of_work.decide(
            actor_id, key, command, now=now, correlation_id=correlation_id
        )

    def get_for_agent(
        self, actor_id: AgentId, approval_id: ApprovalId
    ) -> Approval | None:
        return self.unit_of_work.get_for_agent(actor_id, approval_id)

    def get_for_owner(
        self, actor_id: OwnerId, approval_id: ApprovalId
    ) -> Approval | None:
        return self.unit_of_work.get_for_owner(actor_id, approval_id)
