"""Infrastructure-independent engineering Evidence values."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import PurePosixPath

from .collaboration import TaskId
from .identity import AgentId, DomainValidationError


def _text(value: str, field: str, maximum: int = 4096) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainValidationError(
            f"{field} must be 1..{maximum} non-whitespace characters"
        )


def _sha256(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DomainValidationError(
            f"{field} must be 64 lowercase hexadecimal characters"
        )


def _commit(value: str, field: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) not in (40, 64)
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DomainValidationError(f"{field} must be a full hexadecimal object ID")


@dataclass(frozen=True, slots=True)
class EvidenceId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "EvidenceId", 255)


class FileEvidenceKind(StrEnum):
    FILE = "file"
    SYMLINK = "symlink"
    DELETED = "deleted"
    GITLINK = "gitlink"


@dataclass(frozen=True, slots=True)
class GitFileEvidence:
    path: str
    kind: FileEvidenceKind
    sha256: str | None
    size: int | None

    def __post_init__(self) -> None:
        _text(self.path, "path")
        path = PurePosixPath(self.path)
        if path.is_absolute() or ".." in path.parts or str(path) != self.path:
            raise DomainValidationError("path must be a normalized repository-relative path")
        if not isinstance(self.kind, FileEvidenceKind):
            raise TypeError("kind must be FileEvidenceKind")
        if self.kind is FileEvidenceKind.DELETED:
            if self.sha256 is not None or self.size is not None:
                raise DomainValidationError("deleted file cannot have hash or size")
        else:
            _sha256(self.sha256 or "", "sha256")
            if not isinstance(self.size, int) or self.size < 0:
                raise DomainValidationError("size must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class GitEvidence:
    id: EvidenceId
    actor_id: AgentId
    task_id: TaskId
    repository: str
    worktree_root: str
    baseline_commit: str
    head_commit: str
    branch: str | None
    diff_sha256: str
    diff_size: int
    files: tuple[GitFileEvidence, ...]
    captured_at: datetime
    git_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise TypeError("id must be EvidenceId")
        if not isinstance(self.actor_id, AgentId):
            raise TypeError("actor_id must be AgentId")
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        _text(self.repository, "repository", 255)
        _text(self.worktree_root, "worktree_root")
        _commit(self.baseline_commit, "baseline_commit")
        _commit(self.head_commit, "head_commit")
        if self.branch is not None:
            _text(self.branch, "branch", 255)
        _sha256(self.diff_sha256, "diff_sha256")
        if not isinstance(self.diff_size, int) or self.diff_size < 0:
            raise DomainValidationError("diff_size must be a non-negative integer")
        if not isinstance(self.files, tuple) or not all(
            isinstance(item, GitFileEvidence) for item in self.files
        ):
            raise TypeError("files must be a tuple of GitFileEvidence")
        paths = [item.path for item in self.files]
        if paths != sorted(paths) or len(paths) != len(set(paths)):
            raise DomainValidationError("files must have unique paths in sorted order")
        if (
            not isinstance(self.captured_at, datetime)
            or self.captured_at.tzinfo is None
            or self.captured_at.utcoffset() != timedelta(0)
        ):
            raise DomainValidationError("captured_at must use UTC")
        _text(self.git_version, "git_version", 255)


@dataclass(frozen=True, slots=True)
class GitEvidenceVerification:
    matches: bool
    mismatches: tuple[str, ...]
