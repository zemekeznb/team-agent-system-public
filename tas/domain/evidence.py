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


class CommandOutcome(StrEnum):
    PASSED = "passed"
    FUNCTIONAL_FAILURE = "functional_failure"
    PERFORMANCE_FAILURE = "performance_failure"
    ENVIRONMENT_JITTER = "environment_jitter"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True, slots=True)
class OutputArtifact:
    reference: str
    sha256: str
    captured_size: int
    observed_size: int
    truncated: bool

    def __post_init__(self) -> None:
        _text(self.reference, "reference")
        path = PurePosixPath(self.reference)
        if path.is_absolute() or ".." in path.parts or str(path) != self.reference:
            raise DomainValidationError("reference must be a normalized relative path")
        _sha256(self.sha256, "sha256")
        if (
            not isinstance(self.captured_size, int)
            or isinstance(self.captured_size, bool)
            or self.captured_size < 0
            or not isinstance(self.observed_size, int)
            or isinstance(self.observed_size, bool)
            or self.observed_size < self.captured_size
        ):
            raise DomainValidationError("artifact sizes are invalid")
        if not isinstance(self.truncated, bool):
            raise TypeError("truncated must be bool")
        if self.truncated != (self.observed_size > self.captured_size):
            raise DomainValidationError("truncated must match artifact sizes")


@dataclass(frozen=True, slots=True)
class TestSummary:
    framework: str
    passed: int
    failed: int
    skipped: int
    errors: int

    def __post_init__(self) -> None:
        _text(self.framework, "framework", 64)
        for value, field in (
            (self.passed, "passed"),
            (self.failed, "failed"),
            (self.skipped, "skipped"),
            (self.errors, "errors"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise DomainValidationError(f"{field} must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class CommandEvidence:
    id: EvidenceId
    actor_id: AgentId
    task_id: TaskId
    repository: str
    worktree_root: str
    commit: str
    command: tuple[str, ...]
    attempt: int
    retry_of: EvidenceId | None
    started_at: datetime
    finished_at: datetime
    duration_ms: int
    exit_code: int | None
    outcome: CommandOutcome
    outcome_basis: str
    stdout: OutputArtifact
    stderr: OutputArtifact
    summary: TestSummary | None

    def __post_init__(self) -> None:
        if not isinstance(self.id, EvidenceId):
            raise TypeError("id must be EvidenceId")
        if not isinstance(self.actor_id, AgentId) or not isinstance(self.task_id, TaskId):
            raise TypeError("actor_id and task_id must use domain IDs")
        _text(self.repository, "repository", 255)
        _text(self.worktree_root, "worktree_root")
        _commit(self.commit, "commit")
        if not isinstance(self.command, tuple) or not self.command:
            raise DomainValidationError("command must be a non-empty argv tuple")
        for argument in self.command:
            _text(argument, "command argument")
            if "\0" in argument:
                raise DomainValidationError("command argument cannot contain NUL")
        if not isinstance(self.attempt, int) or isinstance(self.attempt, bool) or self.attempt < 1:
            raise DomainValidationError("attempt must be a positive integer")
        if self.retry_of is not None and not isinstance(self.retry_of, EvidenceId):
            raise TypeError("retry_of must be EvidenceId or None")
        if self.attempt == 1 and self.retry_of is not None:
            raise DomainValidationError("first attempt cannot retry another Evidence")
        if self.attempt > 1 and self.retry_of is None:
            raise DomainValidationError("retry attempt must link previous Evidence")
        for value, field in ((self.started_at, "started_at"), (self.finished_at, "finished_at")):
            if (
                not isinstance(value, datetime)
                or value.tzinfo is None
                or value.utcoffset() != timedelta(0)
            ):
                raise DomainValidationError(f"{field} must use UTC")
        if self.finished_at < self.started_at:
            raise DomainValidationError("finished_at cannot precede started_at")
        if not isinstance(self.duration_ms, int) or isinstance(self.duration_ms, bool) or self.duration_ms < 0:
            raise DomainValidationError("duration_ms must be a non-negative integer")
        if self.exit_code is not None and (
            not isinstance(self.exit_code, int) or isinstance(self.exit_code, bool)
        ):
            raise DomainValidationError("exit_code must be an integer or None")
        if not isinstance(self.outcome, CommandOutcome):
            raise TypeError("outcome must be CommandOutcome")
        if self.outcome_basis not in {
            "exit_code",
            "caller_asserted",
            "collector_timeout",
            "collector_error",
        }:
            raise DomainValidationError("outcome_basis is invalid")
        if self.outcome is CommandOutcome.PASSED and self.exit_code != 0:
            raise DomainValidationError("passed Evidence must have exit code zero")
        if self.outcome is CommandOutcome.TIMED_OUT and self.exit_code is not None:
            raise DomainValidationError("timed out Evidence cannot claim an exit code")
        if not isinstance(self.stdout, OutputArtifact) or not isinstance(self.stderr, OutputArtifact):
            raise TypeError("stdout and stderr must be OutputArtifact")
        if self.summary is not None and not isinstance(self.summary, TestSummary):
            raise TypeError("summary must be TestSummary or None")


def command_attempt_series(evidence: tuple[CommandEvidence, ...]) -> str:
    """Classify an explicit retry chain without modifying any attempt."""
    if not evidence:
        raise DomainValidationError("attempt series cannot be empty")
    for index, item in enumerate(evidence):
        if item.attempt != index + 1:
            raise DomainValidationError("attempt series must be ordered and contiguous")
        if index == 0:
            if item.retry_of is not None:
                raise DomainValidationError("attempt series must start at its original Evidence")
        elif item.retry_of != evidence[index - 1].id:
            raise DomainValidationError("retry chain is broken")
        if index and (
            item.actor_id != evidence[0].actor_id
            or item.task_id != evidence[0].task_id
            or item.repository != evidence[0].repository
            or item.worktree_root != evidence[0].worktree_root
            or item.commit != evidence[0].commit
            or item.command != evidence[0].command
        ):
            raise DomainValidationError("retry series scope changed between attempts")
    passed = [item.outcome is CommandOutcome.PASSED for item in evidence]
    if all(passed):
        return "stable_pass"
    if any(passed):
        return "flaky"
    return "stable_failure"
