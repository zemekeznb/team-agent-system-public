"""Work Record epistemic status and append-only transition rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .evidence import EvidenceId
from .identity import DomainValidationError
from .work_record import WorkRecord, WorkRecordId


class EpistemicStatus(StrEnum):
    CLAIMED = "claimed"
    OBSERVED = "observed"
    VALIDATED = "validated"
    CONFLICTED = "conflicted"


class ValidationVerdict(StrEnum):
    VALIDATE = "validate"
    CONFLICT = "conflict"


@dataclass(frozen=True, slots=True)
class EpistemicEventId:
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not self.value.strip() or len(self.value) > 512:
            raise DomainValidationError("EpistemicEventId must be 1..512 characters")


@dataclass(frozen=True, slots=True)
class EpistemicEvent:
    id: EpistemicEventId
    work_record_id: WorkRecordId
    sequence: int
    from_status: EpistemicStatus | None
    to_status: EpistemicStatus
    rule_id: str
    evidence_ids: tuple[EvidenceId, ...]
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, EpistemicEventId):
            raise TypeError("id must be EpistemicEventId")
        if not isinstance(self.work_record_id, WorkRecordId):
            raise TypeError("work_record_id must be WorkRecordId")
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise DomainValidationError("sequence must be a positive integer")
        if self.from_status is not None and not isinstance(self.from_status, EpistemicStatus):
            raise TypeError("from_status must be EpistemicStatus or None")
        if not isinstance(self.to_status, EpistemicStatus):
            raise TypeError("to_status must be EpistemicStatus")
        if not isinstance(self.rule_id, str) or not self.rule_id.strip() or len(self.rule_id) > 255:
            raise DomainValidationError("rule_id must be 1..255 characters")
        if not isinstance(self.evidence_ids, tuple) or not all(
            isinstance(item, EvidenceId) for item in self.evidence_ids
        ):
            raise TypeError("evidence_ids must be a tuple of EvidenceId")
        values = [item.value for item in self.evidence_ids]
        if len(values) != len(set(values)):
            raise DomainValidationError("evidence_ids must be unique")
        if (
            not isinstance(self.occurred_at, datetime)
            or self.occurred_at.tzinfo is None
            or self.occurred_at.utcoffset() != timedelta(0)
        ):
            raise DomainValidationError("occurred_at must use UTC")
        if self.sequence == 1:
            if self.from_status is not None or self.to_status not in {
                EpistemicStatus.CLAIMED,
                EpistemicStatus.OBSERVED,
            } or self.rule_id != "record_created":
                raise DomainValidationError("initial epistemic event is invalid")
            if self.to_status is EpistemicStatus.CLAIMED and self.evidence_ids:
                raise DomainValidationError("claimed initial status cannot cite Evidence")
            if self.to_status is EpistemicStatus.OBSERVED and not self.evidence_ids:
                raise DomainValidationError("observed initial status requires Evidence")
        else:
            allowed = {
                EpistemicStatus.OBSERVED: {
                    EpistemicStatus.VALIDATED,
                    EpistemicStatus.CONFLICTED,
                },
                EpistemicStatus.VALIDATED: {EpistemicStatus.CONFLICTED},
            }
            if (
                self.from_status not in allowed
                or self.to_status not in allowed[self.from_status]
                or self.rule_id == "record_created"
            ):
                raise DomainValidationError("epistemic transition event is invalid")
            if not self.evidence_ids:
                raise DomainValidationError("epistemic transition requires Evidence")


def initial_epistemic_event(
    record: WorkRecord, *, event_id: EpistemicEventId, occurred_at: datetime
) -> EpistemicEvent:
    status = EpistemicStatus.OBSERVED if record.observed else EpistemicStatus.CLAIMED
    return EpistemicEvent(
        event_id,
        record.id,
        1,
        None,
        status,
        "record_created",
        tuple(item.id for item in record.observed),
        occurred_at,
    )


def decide_epistemic_event(
    record: WorkRecord,
    history: tuple[EpistemicEvent, ...],
    *,
    event_id: EpistemicEventId,
    verdict: ValidationVerdict,
    rule_id: str,
    evidence_ids: tuple[EvidenceId, ...],
    occurred_at: datetime,
) -> EpistemicEvent:
    _validate_history(record, history)
    if not isinstance(verdict, ValidationVerdict):
        raise TypeError("verdict must be ValidationVerdict")
    if not evidence_ids:
        raise DomainValidationError("validation requires observed Evidence")
    available = {item.id for item in record.observed}
    if any(item not in available for item in evidence_ids):
        raise DomainValidationError("validation Evidence must belong to the Work Record")
    current = history[-1].to_status
    target = (
        EpistemicStatus.VALIDATED
        if verdict is ValidationVerdict.VALIDATE
        else EpistemicStatus.CONFLICTED
    )
    allowed = {
        EpistemicStatus.OBSERVED: {
            EpistemicStatus.VALIDATED,
            EpistemicStatus.CONFLICTED,
        },
        EpistemicStatus.VALIDATED: {EpistemicStatus.CONFLICTED},
        EpistemicStatus.CLAIMED: set(),
        EpistemicStatus.CONFLICTED: set(),
    }
    if target not in allowed[current]:
        raise DomainValidationError(
            f"illegal epistemic transition: {current.value} -> {target.value}"
        )
    return EpistemicEvent(
        event_id,
        record.id,
        len(history) + 1,
        current,
        target,
        rule_id,
        evidence_ids,
        occurred_at,
    )


def _validate_history(
    record: WorkRecord, history: tuple[EpistemicEvent, ...]
) -> None:
    if not history:
        raise DomainValidationError("epistemic history cannot be empty")
    expected_initial = EpistemicStatus.OBSERVED if record.observed else EpistemicStatus.CLAIMED
    for index, event in enumerate(history, start=1):
        if event.work_record_id != record.id or event.sequence != index:
            raise DomainValidationError("epistemic history scope or sequence is invalid")
        if index == 1:
            if event.from_status is not None or event.to_status is not expected_initial:
                raise DomainValidationError("epistemic initial event is invalid")
        elif event.from_status is not history[index - 2].to_status:
            raise DomainValidationError("epistemic history is discontinuous")
