"""Business collaboration events independent of transport and persistence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath

from .evidence import EvidenceId
from .identity import AgentId, DomainValidationError, ProjectId


def _text(value: str, field: str, maximum: int = 255) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainValidationError(f"{field} must be 1..{maximum} non-whitespace characters")


def _commit(value: str, field: str) -> None:
    if not isinstance(value, str) or len(value) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise DomainValidationError(f"{field} must be a full hexadecimal object ID")


@dataclass(frozen=True, slots=True)
class CollaborationEventId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "CollaborationEventId")


class CodeImpactKind(StrEnum):
    API_CONTRACT_BREAKING = "api_contract_breaking"


@dataclass(frozen=True, slots=True)
class CodeChangeImpact:
    id: CollaborationEventId
    project_id: ProjectId
    publisher_agent_id: AgentId
    repository: str
    ref: str
    baseline_commit: str
    head_commit: str
    changed_paths: tuple[str, ...]
    evidence_id: EvidenceId
    impact_kind: CodeImpactKind
    affected_api: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.id, CollaborationEventId):
            raise TypeError("id must be CollaborationEventId")
        if not isinstance(self.project_id, ProjectId):
            raise TypeError("project_id must be ProjectId")
        if not isinstance(self.publisher_agent_id, AgentId):
            raise TypeError("publisher_agent_id must be AgentId")
        if not isinstance(self.evidence_id, EvidenceId):
            raise TypeError("evidence_id must be EvidenceId")
        if not isinstance(self.impact_kind, CodeImpactKind):
            raise TypeError("impact_kind must be CodeImpactKind")
        _text(self.repository, "repository")
        _text(self.ref, "ref")
        _commit(self.baseline_commit, "baseline_commit")
        _commit(self.head_commit, "head_commit")
        if self.baseline_commit == self.head_commit:
            raise DomainValidationError("baseline_commit and head_commit must differ")
        if not isinstance(self.changed_paths, tuple) or not self.changed_paths:
            raise DomainValidationError("changed_paths must be a non-empty tuple")
        for value in self.changed_paths:
            _text(value, "changed path", 4096)
            path = PurePosixPath(value)
            if path.is_absolute() or ".." in path.parts or str(path) != value:
                raise DomainValidationError("changed paths must be normalized repository-relative paths")
        if list(self.changed_paths) != sorted(self.changed_paths) or len(self.changed_paths) != len(set(self.changed_paths)):
            raise DomainValidationError("changed_paths must be unique and sorted")
        _text(self.affected_api, "affected_api", 1024)
        if not self.affected_api.startswith("/"):
            raise DomainValidationError("affected_api must be an absolute API path")
        if not isinstance(self.occurred_at, datetime) or self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() != timedelta(0):
            raise DomainValidationError("occurred_at must use UTC")
