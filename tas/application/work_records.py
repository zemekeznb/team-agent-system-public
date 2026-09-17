"""Normalize Collector outputs into observed Work Record snapshots."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from enum import Enum
from pathlib import Path

from tas.domain.evidence import CommandEvidence, GitEvidence, OutputArtifact
from tas.domain.identity import DomainValidationError
from tas.domain.work_record import ObservedEvidence, ObservedEvidenceKind


MAX_SNAPSHOT_ARTIFACT_BYTES = 64 * 1024 * 1024


def _json_value(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    return value


def observed_evidence(
    source: GitEvidence | CommandEvidence, *, artifact_root: str | Path | None = None
) -> ObservedEvidence:
    """Create a canonical snapshot; this does not validate the underlying conclusion."""
    if isinstance(source, GitEvidence):
        kind = ObservedEvidenceKind.GIT
        observed_at = source.captured_at
    elif isinstance(source, CommandEvidence):
        if artifact_root is None:
            raise DomainValidationError(
                "artifact_root is required for Command Evidence"
            )
        root = Path(artifact_root).resolve(strict=True)
        _verify_artifact(root, source.stdout)
        _verify_artifact(root, source.stderr)
        kind = ObservedEvidenceKind.COMMAND_TEST
        observed_at = source.finished_at
    else:
        raise TypeError("source must be GitEvidence or CommandEvidence")
    payload = asdict(source)
    payload_json = json.dumps(
        _json_value(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return ObservedEvidence(
        source.id,
        source.task_id,
        source.actor_id,
        kind,
        payload_json,
        hashlib.sha256(payload_json.encode("utf-8")).hexdigest(),
        observed_at,
    )


def _verify_artifact(root: Path, artifact: OutputArtifact) -> None:
    path = root / Path(artifact.reference)
    if path.is_symlink():
        raise DomainValidationError("Evidence Artifact cannot be a symlink")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise DomainValidationError("Evidence Artifact does not exist") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise DomainValidationError("Evidence Artifact escapes its controlled root")
    size = resolved.stat().st_size
    if size > MAX_SNAPSHOT_ARTIFACT_BYTES or size != artifact.captured_size:
        raise DomainValidationError("Evidence Artifact integrity check failed")
    digest = hashlib.sha256()
    with resolved.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    if digest.hexdigest() != artifact.sha256:
        raise DomainValidationError("Evidence Artifact integrity check failed")
