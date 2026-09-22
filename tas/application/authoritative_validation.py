"""Authoritative Work Record validation commands for the central service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from tas.domain.epistemic import EpistemicEvent
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId
from tas.domain.work_record import WorkRecordId


class ValidationRule(StrEnum):
    TEST_SUCCESS = "test_success"
    CODE_ADAPTATION = "code_adaptation"


@dataclass(frozen=True, slots=True)
class ValidateWorkRecordCommand:
    work_record_id: WorkRecordId
    rule: ValidationRule

    def __post_init__(self) -> None:
        if not isinstance(self.work_record_id, WorkRecordId):
            raise TypeError("work_record_id must be WorkRecordId")
        if not isinstance(self.rule, ValidationRule):
            raise TypeError("rule must be ValidationRule")


@dataclass(frozen=True, slots=True)
class ValidateWorkRecordResult:
    event: EpistemicEvent
    replayed: bool


class AuthoritativeValidationUnitOfWork(Protocol):
    def validate(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ValidateWorkRecordCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ValidateWorkRecordResult: ...


class AuthoritativeValidationService:
    def __init__(self, unit_of_work: AuthoritativeValidationUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def validate(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ValidateWorkRecordCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ValidateWorkRecordResult:
        return self.unit_of_work.validate(
            actor_id, key, command,
            occurred_at=occurred_at,
            correlation_id=correlation_id,
        )
