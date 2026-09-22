"""Trusted Workspace Binding and Evidence Registry helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from tas.domain.evidence import EvidenceId, TaskWorkspaceBinding
from tas.domain.identity import DomainValidationError
from tas.domain.work_record import ObservedEvidence, WorkRecord


def workspace_root_sha256(root: str | Path) -> str:
    """Fingerprint a canonical local root without placing the path in central state."""

    try:
        canonical = Path(root).resolve(strict=True)
    except (OSError, TypeError) as error:
        raise DomainValidationError("Workspace root cannot be resolved") from error
    if not canonical.is_dir():
        raise DomainValidationError("Workspace root must be a directory")
    normalized = canonical.as_posix()
    if len(normalized) > 4096:
        raise DomainValidationError("Workspace root is too long")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def require_trusted_workspace(
    record: WorkRecord,
    binding: TaskWorkspaceBinding,
    *,
    repository: str,
    evidence_roots: tuple[str, ...] = (),
    evidence_workspace_ids: tuple[str, ...] = (),
) -> None:
    if (
        record.task_id != binding.task_id
        or record.actor_id != binding.actor_id
        or repository != binding.repository
    ):
        raise DomainValidationError("Evidence does not match the Task Workspace Binding")
    if bool(evidence_roots) == bool(evidence_workspace_ids):
        raise DomainValidationError(
            "Evidence must identify exactly one Workspace representation"
        )
    if evidence_workspace_ids:
        if any(value != binding.id.value for value in evidence_workspace_ids):
            raise DomainValidationError("Evidence uses a different Task Workspace")
        return
    for root in evidence_roots:
        try:
            digest = hashlib.sha256(
                Path(root).resolve(strict=False).as_posix().encode("utf-8")
            ).hexdigest()
        except (OSError, TypeError) as error:
            raise DomainValidationError("Evidence Workspace root is invalid") from error
        if digest != binding.root_sha256:
            raise DomainValidationError("Evidence uses a different Task Workspace")


def require_registry_snapshot(
    record: WorkRecord, registered: tuple[ObservedEvidence, ...]
) -> dict[EvidenceId, ObservedEvidence]:
    if not isinstance(registered, tuple) or not all(
        isinstance(item, ObservedEvidence) for item in registered
    ):
        raise TypeError("registered Evidence must be a tuple of ObservedEvidence")
    registry = {item.id: item for item in registered}
    if len(registry) != len(registered):
        raise DomainValidationError("Evidence Registry contains duplicate IDs")
    if any(
        item.task_id != record.task_id or item.actor_id != record.actor_id
        for item in registered
    ):
        raise DomainValidationError("Evidence Registry scope does not match Work Record")
    for observed in record.observed:
        if registry.get(observed.id) != observed:
            raise DomainValidationError("Work Record Evidence is not canonical Registry data")
    return registry
