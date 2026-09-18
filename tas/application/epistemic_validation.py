"""Deterministic validators that compare versioned claims with observed Evidence."""

from __future__ import annotations

import json
from datetime import datetime

from tas.domain.epistemic import (
    EpistemicEvent,
    EpistemicEventId,
    ValidationVerdict,
    decide_epistemic_event,
)
from tas.domain.evidence import EvidenceId
from tas.domain.identity import DomainValidationError
from tas.domain.work_record import ObservedEvidenceKind, WorkRecord, WorkRecordType


TEST_SUCCESS_RULE_ID = "command_test_success_v1"
_CLAIM_KEYS = {"evidenceIds", "expectedOutcome", "kind", "schemaVersion"}


def build_test_success_claim(evidence_ids: tuple[EvidenceId, ...]) -> str:
    """Build the only machine-readable test-success claim supported in F2."""
    if (
        not isinstance(evidence_ids, tuple)
        or not evidence_ids
        or len(evidence_ids) > 100
        or not all(isinstance(item, EvidenceId) for item in evidence_ids)
        or len({item.value for item in evidence_ids}) != len(evidence_ids)
    ):
        raise DomainValidationError("test success claim requires unique Evidence IDs")
    payload = {
        "evidenceIds": [item.value for item in evidence_ids],
        "expectedOutcome": "passed",
        "kind": "test_result",
        "schemaVersion": 1,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assess_test_success_claim(
    record: WorkRecord,
    history: tuple[EpistemicEvent, ...],
    *,
    event_id: EpistemicEventId,
    occurred_at: datetime,
) -> EpistemicEvent:
    """Compare a strict test-success claim with its cited command observations."""
    evidence_ids = _parse_claim(record)
    observed = {item.id: item for item in record.observed}
    if any(item not in observed for item in evidence_ids):
        raise DomainValidationError("claim references Evidence outside the Work Record")

    passed = True
    for evidence_id in evidence_ids:
        evidence = observed[evidence_id]
        if evidence.kind is not ObservedEvidenceKind.COMMAND_TEST:
            raise DomainValidationError("test success claim requires command-test Evidence")
        try:
            payload = json.loads(evidence.payload_json)
        except json.JSONDecodeError as error:  # defensive for non-domain persistence adapters
            raise DomainValidationError("command-test Evidence payload is invalid") from error
        if not isinstance(payload, dict):
            raise DomainValidationError("command-test Evidence payload must be an object")
        exit_code = payload.get("exit_code")
        outcome = payload.get("outcome")
        outcome_basis = payload.get("outcome_basis")
        if exit_code is not None and (
            not isinstance(exit_code, int) or isinstance(exit_code, bool)
        ):
            raise DomainValidationError("command-test exit_code is invalid")
        if not isinstance(outcome, str) or not isinstance(outcome_basis, str):
            raise DomainValidationError("command-test outcome fields are invalid")
        summary = payload.get("summary")
        summary_passed = True
        if summary is not None:
            if not isinstance(summary, dict):
                raise DomainValidationError("command-test summary is invalid")
            failed = summary.get("failed")
            errors = summary.get("errors")
            if any(
                not isinstance(value, int) or isinstance(value, bool) or value < 0
                for value in (failed, errors)
            ):
                raise DomainValidationError("command-test summary counts are invalid")
            summary_passed = failed == 0 and errors == 0
        passed = passed and (
            exit_code == 0
            and outcome == "passed"
            and outcome_basis == "exit_code"
            and summary_passed
        )

    return decide_epistemic_event(
        record,
        history,
        event_id=event_id,
        verdict=ValidationVerdict.VALIDATE if passed else ValidationVerdict.CONFLICT,
        rule_id=TEST_SUCCESS_RULE_ID,
        evidence_ids=evidence_ids,
        occurred_at=occurred_at,
    )


def _parse_claim(record: WorkRecord) -> tuple[EvidenceId, ...]:
    if record.record_type is not WorkRecordType.RESULT or record.claim_text is None:
        raise DomainValidationError("test success validation requires a result claim")
    try:
        payload = json.loads(record.claim_text)
    except json.JSONDecodeError as error:
        raise DomainValidationError("test success claim must be valid JSON") from error
    if not isinstance(payload, dict) or set(payload) != _CLAIM_KEYS:
        raise DomainValidationError("test success claim schema is invalid")
    if type(payload["schemaVersion"]) is not int or payload["schemaVersion"] != 1:
        raise DomainValidationError("test success claim schema version is invalid")
    if payload["kind"] != "test_result" or payload["expectedOutcome"] != "passed":
        raise DomainValidationError("test success claim semantics are unsupported")
    raw_ids = payload["evidenceIds"]
    if (
        not isinstance(raw_ids, list)
        or not raw_ids
        or len(raw_ids) > 100
        or any(not isinstance(item, str) for item in raw_ids)
    ):
        raise DomainValidationError("test success claim Evidence IDs are invalid")
    evidence_ids = tuple(EvidenceId(item) for item in raw_ids)
    if len({item.value for item in evidence_ids}) != len(evidence_ids):
        raise DomainValidationError("test success claim Evidence IDs must be unique")
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != record.claim_text:
        raise DomainValidationError("test success claim must use canonical JSON")
    return evidence_ids
