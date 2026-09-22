"""Deterministic validators that compare versioned claims with observed Evidence."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import PurePosixPath

from tas.application.evidence_registry import (
    require_registry_snapshot,
    require_trusted_workspace,
)
from tas.domain.epistemic import (
    EpistemicEvent,
    EpistemicEventId,
    ValidationVerdict,
    decide_epistemic_event,
)
from tas.domain.evidence import EvidenceId, TaskWorkspaceBinding
from tas.domain.identity import DomainValidationError
from tas.domain.work_record import (
    ObservedEvidence,
    ObservedEvidenceKind,
    WorkRecord,
    WorkRecordType,
)


TEST_SUCCESS_RULE_ID = "command_test_success_v1"
CODE_ADAPTATION_RULE_ID = "api_client_adaptation_v1"
_CLAIM_KEYS = {"evidenceIds", "expectedOutcome", "kind", "schemaVersion"}
_ADAPTATION_CLAIM_KEYS = {
    "changedPaths", "gitEvidenceId", "kind", "repository", "schemaVersion",
    "testEvidenceIds",
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
    registered_evidence: tuple[ObservedEvidence, ...],
    event_id: EpistemicEventId,
    occurred_at: datetime,
) -> EpistemicEvent:
    """Compare a strict test-success claim with its cited command observations."""
    evidence_ids = _parse_claim(record)
    observed = {item.id: item for item in record.observed}
    registry = require_registry_snapshot(record, registered_evidence)
    if any(item not in observed for item in evidence_ids):
        raise DomainValidationError("claim references Evidence outside the Work Record")
    _require_complete_command_series(evidence_ids, observed, registry)

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
    *,
    git_evidence_id: EvidenceId,
    test_evidence_ids: tuple[EvidenceId, ...],
    repository: str,
    changed_paths: tuple[str, ...],
) -> str:
    if not isinstance(git_evidence_id, EvidenceId):
        raise TypeError("Evidence IDs must use EvidenceId")
    if (not isinstance(test_evidence_ids, tuple) or not 1 <= len(test_evidence_ids) <= 2
            or not all(isinstance(item, EvidenceId) for item in test_evidence_ids)):
        raise DomainValidationError("one or two test Evidence attempts are required")
    all_ids = (git_evidence_id, *test_evidence_ids)
    if len(set(all_ids)) != len(all_ids):
        raise DomainValidationError("Git and test Evidence IDs must be distinct")
    if not isinstance(repository, str) or not repository.strip() or len(repository) > 255:
        raise DomainValidationError("repository must be 1..255 characters")
    _validate_changed_paths(changed_paths, require_tuple=True)
    return json.dumps({
        "changedPaths": list(changed_paths),
        "gitEvidenceId": git_evidence_id.value,
        "kind": "code_adaptation_result",
        "repository": repository,
        "schemaVersion": 1,
        "testEvidenceIds": [item.value for item in test_evidence_ids],
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def assess_code_adaptation_claim(
    record: WorkRecord,
    history: tuple[EpistemicEvent, ...],
    *,
    workspace_binding: TaskWorkspaceBinding,
    registered_evidence: tuple[ObservedEvidence, ...],
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
    raw_test_ids = claim["testEvidenceIds"]
    if (not isinstance(raw_test_ids, list) or not 1 <= len(raw_test_ids) <= 2
            or any(not isinstance(item, str) for item in raw_test_ids)):
        raise DomainValidationError("code adaptation test Evidence IDs are invalid")
    test_ids = tuple(EvidenceId(item) for item in raw_test_ids)
    if len(set(test_ids)) != len(test_ids) or git_id in test_ids:
        raise DomainValidationError("code adaptation Evidence IDs must be distinct")
    observed = {item.id: item for item in record.observed}
    registry = require_registry_snapshot(record, registered_evidence)
    if set(observed) != {git_id, *test_ids}:
        raise DomainValidationError("code adaptation claim must cite exactly its Git and test Evidence attempts")
    git = observed[git_id]
    tests = tuple(observed[item] for item in test_ids)
    if (git.kind is not ObservedEvidenceKind.GIT
            or any(item.kind is not ObservedEvidenceKind.COMMAND_TEST for item in tests)):
        raise DomainValidationError("code adaptation Evidence kinds are invalid")
    try:
        git_payload = json.loads(git.payload_json)
        test_payloads = tuple(json.loads(item.payload_json) for item in tests)
        test_payload = test_payloads[-1]
        files = git_payload["files"]
        raw_changed_paths = claim["changedPaths"]
        _validate_changed_paths(raw_changed_paths, require_tuple=False)
        actual_paths = [
            item.get("path") if isinstance(item, dict) else None for item in files
        ] if isinstance(files, list) else []
        command = test_payload["command"]
        raw_worktree = test_payload.get("worktree_root")
        worktree = raw_worktree.replace("\\", "/").rstrip("/") if isinstance(raw_worktree, str) else ""
        command_script = command[1].replace("\\", "/") if isinstance(command, list) and len(command) > 1 and isinstance(command[1], str) else ""
        workspace_ids = (
            git_payload.get("workspace_id"),
            *(payload.get("workspace_id") for payload in test_payloads),
        )
        uses_workspace_ids = all(isinstance(item, str) for item in workspace_ids)
        chain_valid = all(
            payload.get("attempt") == index
            and (payload.get("retry_of") is None if index == 1 else payload.get("retry_of") == {"value": test_ids[index - 2].value})
            and payload.get("repository") == claim["repository"]
            and payload.get("commit") == git_payload["head_commit"]
            and payload.get("command") == command
            for index, payload in enumerate(test_payloads, 1)
        )
        prior_failures_valid = all(
            type(payload.get("exit_code")) is int
            and payload.get("exit_code") != 0
            and payload.get("outcome") == "external_dependency_error"
            and payload.get("outcome_basis") == "caller_asserted"
            for payload in test_payloads[:-1]
        )
        if uses_workspace_ids:
            require_trusted_workspace(
                record,
                workspace_binding,
                repository=claim["repository"],
                evidence_workspace_ids=workspace_ids,
            )
        else:
            require_trusted_workspace(
                record,
                workspace_binding,
                repository=claim["repository"],
                evidence_roots=(
                    git_payload["worktree_root"],
                    *(payload["worktree_root"] for payload in test_payloads),
                ),
            )
        _require_complete_command_series(test_ids, observed, registry)
        passed = (
            git_payload["repository"] == claim["repository"]
            and test_payload["repository"] == claim["repository"]
            and test_payload["commit"] == git_payload["head_commit"]
            and isinstance(files, list)
            and actual_paths == raw_changed_paths
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
            and command_script == (
                "client_typescript/dist/src/read-user-cli.js"
                if uses_workspace_ids
                else worktree + "/client_typescript/dist/src/read-user-cli.js"
            )
            and isinstance(command[2], str)
            and command[2].startswith("http://127.0.0.1:")
            and command[3] == "user-001"
            and chain_valid
            and prior_failures_valid
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
        rule_id=CODE_ADAPTATION_RULE_ID, evidence_ids=(git_id, *test_ids),
        occurred_at=occurred_at,
    )


def _require_complete_command_series(
    cited_ids: tuple[EvidenceId, ...],
    observed: dict[EvidenceId, ObservedEvidence],
    registry: dict[EvidenceId, ObservedEvidence],
) -> None:
    cited = set(cited_ids)
    scopes = {
        scope
        for evidence_id in cited_ids
        if (scope := _command_scope(observed[evidence_id])) is not None
    }
    related = set(cited)
    changed = True
    while changed:
        changed = False
        for candidate in registry.values():
            if candidate.kind is not ObservedEvidenceKind.COMMAND_TEST:
                continue
            scope = _command_scope(candidate)
            retry_of = _retry_of(candidate)
            if scope in scopes or retry_of in related:
                if candidate.id not in related:
                    related.add(candidate.id)
                    changed = True
    omitted = related - cited
    if omitted:
        raise DomainValidationError("updated command Evidence cannot be omitted")


def _validate_changed_paths(
    values: tuple[str, ...] | list[str], *, require_tuple: bool
) -> None:
    expected_type = tuple if require_tuple else list
    if (
        not isinstance(values, expected_type)
        or not values
        or len(values) > 10_000
        or any(not isinstance(value, str) for value in values)
        or list(values) != sorted(set(values))
    ):
        raise DomainValidationError("changed paths must be sorted and unique")
    for value in values:
        path = PurePosixPath(value)
        if (
            not value.strip()
            or len(value) > 4096
            or "\\" in value
            or path.is_absolute()
            or ".." in path.parts
            or str(path) != value
        ):
            raise DomainValidationError("changed paths must be repository-relative")


def _command_payload(evidence: ObservedEvidence) -> dict[str, object] | None:
    if evidence.kind is not ObservedEvidenceKind.COMMAND_TEST:
        return None
    try:
        payload = json.loads(evidence.payload_json)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _command_scope(evidence: ObservedEvidence) -> str | None:
    payload = _command_payload(evidence)
    if payload is None:
        return None
    fields = (
        payload.get("repository"),
        payload.get("commit"),
        payload.get("workspace_id", payload.get("worktree_root")),
        payload.get("command"),
    )
    if (
        not all(value is not None for value in fields)
        or not isinstance(fields[3], list)
        or any(not isinstance(item, str) for item in fields[3])
    ):
        return None
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _retry_of(evidence: ObservedEvidence) -> EvidenceId | None:
    payload = _command_payload(evidence)
    if payload is None:
        return None
    raw = payload.get("retry_of")
    if isinstance(raw, dict):
        raw = raw.get("value")
    try:
        return None if raw is None else EvidenceId(raw)
    except (TypeError, DomainValidationError):
        return None


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
