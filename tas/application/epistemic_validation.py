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
CODE_ADAPTATION_RULE_ID = "api_client_adaptation_v1"
_CLAIM_KEYS = {"evidenceIds", "expectedOutcome", "kind", "schemaVersion"}
_ADAPTATION_CLAIM_KEYS = {
    "gitEvidenceId", "kind", "repository", "schemaVersion", "testEvidenceId"
}


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


def build_code_adaptation_claim(
    *, git_evidence_id: EvidenceId, test_evidence_id: EvidenceId, repository: str
) -> str:
    if not isinstance(git_evidence_id, EvidenceId) or not isinstance(test_evidence_id, EvidenceId):
        raise TypeError("Evidence IDs must use EvidenceId")
    if git_evidence_id == test_evidence_id:
        raise DomainValidationError("Git and test Evidence must be distinct")
    if not isinstance(repository, str) or not repository.strip() or len(repository) > 255:
        raise DomainValidationError("repository must be 1..255 characters")
    return json.dumps({
        "gitEvidenceId": git_evidence_id.value,
        "kind": "code_adaptation_result",
        "repository": repository,
        "schemaVersion": 1,
        "testEvidenceId": test_evidence_id.value,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assess_code_adaptation_claim(
    record: WorkRecord,
    history: tuple[EpistemicEvent, ...],
    *,
    event_id: EpistemicEventId,
    occurred_at: datetime,
) -> EpistemicEvent:
    """Validate that a committed Git adaptation is exactly the code tested."""
    if record.record_type is not WorkRecordType.RESULT or record.claim_text is None:
        raise DomainValidationError("code adaptation validation requires a result claim")
    try:
        claim = json.loads(record.claim_text)
    except json.JSONDecodeError as error:
        raise DomainValidationError("code adaptation claim must be valid JSON") from error
    canonical = json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if canonical != record.claim_text or not isinstance(claim, dict) or set(claim) != _ADAPTATION_CLAIM_KEYS:
        raise DomainValidationError("code adaptation claim schema is invalid")
    if type(claim["schemaVersion"]) is not int or claim["schemaVersion"] != 1 or claim["kind"] != "code_adaptation_result":
        raise DomainValidationError("code adaptation claim semantics are unsupported")
    if (not isinstance(claim["repository"], str) or not claim["repository"].strip()
            or len(claim["repository"]) > 255):
        raise DomainValidationError("code adaptation repository is invalid")
    git_id = EvidenceId(claim["gitEvidenceId"])
    test_id = EvidenceId(claim["testEvidenceId"])
    observed = {item.id: item for item in record.observed}
    if set(observed) != {git_id, test_id}:
        raise DomainValidationError("code adaptation claim must cite exactly its Git and test Evidence")
    git = observed[git_id]
    test = observed[test_id]
    if git.kind is not ObservedEvidenceKind.GIT or test.kind is not ObservedEvidenceKind.COMMAND_TEST:
        raise DomainValidationError("code adaptation Evidence kinds are invalid")
    try:
        git_payload = json.loads(git.payload_json)
        test_payload = json.loads(test.payload_json)
        files = git_payload["files"]
        command = test_payload["command"]
        raw_worktree = test_payload["worktree_root"]
        worktree = raw_worktree.replace("\\", "/").rstrip("/") if isinstance(raw_worktree, str) else ""
        command_script = command[1].replace("\\", "/") if isinstance(command, list) and len(command) > 1 and isinstance(command[1], str) else ""
        passed = (
            git_payload["repository"] == claim["repository"]
            and test_payload["repository"] == claim["repository"]
            and test_payload["commit"] == git_payload["head_commit"]
            and isinstance(files, list)
            and any(
                isinstance(item, dict)
                and item.get("path") == "client_typescript/src/user-client.ts"
                for item in files
            )
            and any(
                isinstance(item, dict)
                and item.get("path") == "client_typescript/dist/src/read-user-cli.js"
                for item in files
            )
            and isinstance(command, list)
            and len(command) == 4
            and isinstance(command[0], str)
            and command[0].lower().endswith(("node", "node.exe"))
            and isinstance(command[1], str)
            and command_script == worktree + "/client_typescript/dist/src/read-user-cli.js"
            and isinstance(command[2], str)
            and command[2].startswith("http://127.0.0.1:")
            and command[3] == "user-001"
            and type(test_payload["exit_code"]) is int
            and test_payload["exit_code"] == 0
            and test_payload["outcome"] == "passed"
            and test_payload["outcome_basis"] == "exit_code"
        )
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise DomainValidationError("code adaptation Evidence payload is incomplete") from error
    return decide_epistemic_event(
        record, history, event_id=event_id,
        verdict=ValidationVerdict.VALIDATE if passed else ValidationVerdict.CONFLICT,
        rule_id=CODE_ADAPTATION_RULE_ID, evidence_ids=(git_id, test_id),
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
