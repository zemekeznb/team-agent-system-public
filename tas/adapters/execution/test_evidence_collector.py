"""Run bounded commands and preserve integrity-addressed test observations."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tas.domain.collaboration import TaskId
from tas.domain.evidence import (
    CommandEvidence,
    CommandOutcome,
    EvidenceId,
    OutputArtifact,
    TestSummary,
)
from tas.domain.identity import AgentId


class TestEvidenceCollectionError(RuntimeError):
    """The command could not be observed within the configured boundary."""


_PYTEST_COUNT = re.compile(
    rb"(?P<count>\d+) (?P<kind>passed|failed|skipped|error|errors)(?:[, ]|$)"
)


@dataclass(slots=True)
class _Capture:
    limit: int
    retained: bytearray = field(default_factory=bytearray)
    observed_size: int = 0
    digest: object = field(default_factory=hashlib.sha256)
    exceeded: threading.Event = field(default_factory=threading.Event)

    def consume(self, stream: object) -> None:
        while True:
            chunk = stream.read(64 * 1024)  # type: ignore[attr-defined]
            if not chunk:
                return
            self.observed_size += len(chunk)
            self.digest.update(chunk)  # type: ignore[attr-defined]
            remaining = self.limit - len(self.retained)
            if remaining > 0:
                self.retained.extend(chunk[:remaining])
            if self.observed_size > self.limit:
                self.exceeded.set()


class TestEvidenceCollector:
    def __init__(
        self,
        artifact_root: str | Path,
        *,
        timeout_seconds: float = 300,
        max_output_bytes: int = 4 * 1024 * 1024,
    ) -> None:
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be positive")
        if (
            not isinstance(max_output_bytes, int)
            or isinstance(max_output_bytes, bool)
            or max_output_bytes <= 0
        ):
            raise ValueError("max_output_bytes must be a positive integer")
        self.artifact_root = Path(artifact_root).resolve()
        self.artifact_root.mkdir(parents=True, exist_ok=True)
        if self.artifact_root.is_symlink():
            raise ValueError("artifact_root cannot be a symlink")
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = max_output_bytes

    def collect(
        self,
        workspace: str | Path,
        *,
        repository: str,
        command: tuple[str, ...],
        actor_id: AgentId,
        task_id: TaskId,
        attempt: int = 1,
        retry_of: EvidenceId | None = None,
        failure_outcome: CommandOutcome = CommandOutcome.FUNCTIONAL_FAILURE,
        environment: dict[str, str] | None = None,
    ) -> CommandEvidence:
        if failure_outcome not in {
            CommandOutcome.FUNCTIONAL_FAILURE,
            CommandOutcome.PERFORMANCE_FAILURE,
            CommandOutcome.ENVIRONMENT_JITTER,
            CommandOutcome.EXTERNAL_DEPENDENCY_ERROR,
        }:
            raise TestEvidenceCollectionError("failure_outcome is not caller-selectable")
        if not isinstance(command, tuple) or not command:
            raise TestEvidenceCollectionError("command must be a non-empty argv tuple")
        if any(
            not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value
            for value in command
        ):
            raise TestEvidenceCollectionError("command contains an unsafe argument")
        if not isinstance(repository, str) or not repository.strip() or len(repository) > 255:
            raise TestEvidenceCollectionError("repository must be 1..255 characters")
        if not isinstance(actor_id, AgentId) or not isinstance(task_id, TaskId):
            raise TestEvidenceCollectionError("actor_id and task_id must use domain IDs")
        if (
            not isinstance(attempt, int)
            or isinstance(attempt, bool)
            or attempt < 1
            or (attempt == 1 and retry_of is not None)
            or (attempt > 1 and not isinstance(retry_of, EvidenceId))
        ):
            raise TestEvidenceCollectionError("attempt and retry_of are inconsistent")
        try:
            root = Path(workspace).resolve(strict=True)
        except (OSError, TypeError) as error:
            raise TestEvidenceCollectionError("workspace cannot be resolved") from error
        actual_root = Path(self._git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
        if root != actual_root:
            raise TestEvidenceCollectionError("workspace must be the exact Git worktree root")
        commit = self._git(root, "rev-parse", "--verify", "HEAD^{commit}")

        evidence_id = EvidenceId(str(uuid4()))
        started_at = datetime.now(UTC)
        started_monotonic = time.monotonic()
        stdout = _Capture(self.max_output_bytes)
        stderr = _Capture(self.max_output_bytes)
        exit_code: int | None = None
        timed_out = False
        output_exceeded = False
        try:
            process = subprocess.Popen(
                list(command),
                cwd=root,
                env=self._environment(environment),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError:
            finished_at = datetime.now(UTC)
            return self._evidence(
                evidence_id, actor_id, task_id, repository, root, commit, command,
                attempt, retry_of, started_at, finished_at,
                max(0, round((time.monotonic() - started_monotonic) * 1000)), None,
                CommandOutcome.INFRASTRUCTURE_ERROR, "collector_error", stdout, stderr,
            )
        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(target=stdout.consume, args=(process.stdout,), daemon=True),
            threading.Thread(target=stderr.consume, args=(process.stderr,), daemon=True),
        ]
        for reader in readers:
            reader.start()
        deadline = started_monotonic + self.timeout_seconds
        while process.poll() is None:
            if stdout.exceeded.is_set() or stderr.exceeded.is_set():
                output_exceeded = True
                process.kill()
                break
            if time.monotonic() >= deadline:
                timed_out = True
                process.kill()
                break
            time.sleep(0.01)
        process.wait()
        for reader in readers:
            reader.join(timeout=5)
        if any(reader.is_alive() for reader in readers):
            raise TestEvidenceCollectionError("output reader did not terminate")
        output_exceeded = (
            output_exceeded
            or stdout.exceeded.is_set()
            or stderr.exceeded.is_set()
        )
        if not timed_out and not output_exceeded:
            exit_code = process.returncode
        finished_at = datetime.now(UTC)
        duration_ms = max(0, round((time.monotonic() - started_monotonic) * 1000))
        commit_after = self._git(root, "rev-parse", "--verify", "HEAD^{commit}")
        if commit_after != commit:
            raise TestEvidenceCollectionError("Git commit changed during command execution")
        if timed_out:
            outcome = CommandOutcome.TIMED_OUT
            outcome_basis = "collector_timeout"
        elif output_exceeded:
            outcome = CommandOutcome.INFRASTRUCTURE_ERROR
            outcome_basis = "collector_error"
        elif exit_code == 0:
            outcome = CommandOutcome.PASSED
            outcome_basis = "exit_code"
        else:
            outcome = failure_outcome
            outcome_basis = "caller_asserted"
        return self._evidence(
            evidence_id, actor_id, task_id, repository, root, commit, command,
            attempt, retry_of, started_at, finished_at, duration_ms, exit_code,
            outcome, outcome_basis, stdout, stderr,
        )

    def _evidence(
        self, evidence_id: EvidenceId, actor_id: AgentId, task_id: TaskId,
        repository: str, root: Path, commit: str, command: tuple[str, ...],
        attempt: int, retry_of: EvidenceId | None, started_at: datetime,
        finished_at: datetime, duration_ms: int, exit_code: int | None,
        outcome: CommandOutcome, outcome_basis: str, stdout: _Capture, stderr: _Capture,
    ) -> CommandEvidence:
        stdout_artifact = self._save(evidence_id, "stdout", stdout)
        stderr_artifact = self._save(evidence_id, "stderr", stderr)
        summary = None
        if not stdout.exceeded.is_set() and not stderr.exceeded.is_set():
            summary = self._pytest_summary(
                bytes(stdout.retained) + b"\n" + bytes(stderr.retained)
            )
        return CommandEvidence(
            evidence_id, actor_id, task_id, repository, str(root), commit, command,
            attempt, retry_of, started_at, finished_at, duration_ms,
            exit_code, outcome, outcome_basis, stdout_artifact, stderr_artifact, summary,
        )

    def _save(self, evidence_id: EvidenceId, name: str, capture: _Capture) -> OutputArtifact:
        directory = self.artifact_root / evidence_id.value
        directory.mkdir(parents=False, exist_ok=True)
        path = directory / f"{name}.bin"
        path.write_bytes(capture.retained)
        reference = path.relative_to(self.artifact_root).as_posix()
        return OutputArtifact(
            reference, hashlib.sha256(capture.retained).hexdigest(), len(capture.retained),
            capture.observed_size, capture.observed_size > len(capture.retained),
        )

    @staticmethod
    def _pytest_summary(output: bytes) -> TestSummary | None:
        counts = {"passed": 0, "failed": 0, "skipped": 0, "errors": 0}
        matches = list(_PYTEST_COUNT.finditer(output))
        if not matches:
            return None
        for match in matches:
            kind = match.group("kind").decode("ascii")
            if kind == "error":
                kind = "errors"
            counts[kind] = int(match.group("count"))
        return TestSummary("pytest", **counts)

    @staticmethod
    def _environment(overrides: dict[str, str] | None) -> dict[str, str]:
        environment = os.environ.copy()
        if overrides is None:
            return environment
        if any(
            not isinstance(key, str) or not key or "=" in key or "\0" in key
            or not isinstance(value, str) or "\0" in value
            for key, value in overrides.items()
        ):
            raise TestEvidenceCollectionError("environment override is invalid")
        environment.update(overrides)
        return environment

    @staticmethod
    def _git(root: Path, *arguments: str) -> str:
        try:
            result = subprocess.run(
                ["git", "-c", "core.quotepath=false", *arguments], cwd=root,
                stdin=subprocess.DEVNULL, capture_output=True, check=False,
                timeout=10, shell=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise TestEvidenceCollectionError("Git inspection failed") from error
        if result.returncode != 0 or len(result.stdout) > 1024 * 1024:
            raise TestEvidenceCollectionError("Git inspection failed")
        try:
            value = result.stdout.decode("utf-8").strip()
        except UnicodeDecodeError as error:
            raise TestEvidenceCollectionError("Git output must use UTF-8") from error
        if not value:
            raise TestEvidenceCollectionError("Git returned an empty required value")
        return value
