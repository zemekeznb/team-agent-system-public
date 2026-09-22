"""Run bounded commands and preserve integrity-addressed test observations."""

from __future__ import annotations

import hashlib
import json
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
from tas.domain.idempotency import IdempotencyKey


class TestEvidenceCollectionError(RuntimeError):
    """The command could not be observed within the configured boundary."""


class EvidenceIdempotencyConflictError(TestEvidenceCollectionError):
    """A key was reused for a different collection request."""


class EvidenceRequestInProgressError(TestEvidenceCollectionError):
    """A reserved request has no durable completed result yet."""


class EvidenceReplayIntegrityError(TestEvidenceCollectionError):
    """A completed result cannot be replayed with intact output artifacts."""


_PYTEST_COUNT = re.compile(
    rb"(?P<count>\d+) (?P<kind>passed|failed|skipped|error|errors)(?:[, ]|$)"
)
_SECRET_ENVIRONMENT_NAME = re.compile(
    r"(?:^|_)(?:TOKEN|PASSWORD|PASSWD|SECRET|CREDENTIAL|API_KEY|PRIVATE_KEY)(?:$|_)",
    re.IGNORECASE,
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
        known_secrets: tuple[str, ...] = (),
        inherit_environment: bool = True,
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
        requested_artifact_root = Path(artifact_root)
        requested_artifact_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._is_link(requested_artifact_root):
            raise ValueError("artifact_root cannot be a symlink")
        self.artifact_root = requested_artifact_root.resolve(strict=True)
        os.chmod(self.artifact_root, 0o700)
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = max_output_bytes
        if not isinstance(inherit_environment, bool):
            raise TypeError("inherit_environment must be bool")
        self.inherit_environment = inherit_environment
        if (
            not isinstance(known_secrets, tuple)
            or len(known_secrets) > 100
            or any(
                not isinstance(value, str)
                or not 8 <= len(value.encode("utf-8")) <= 4096
                for value in known_secrets
            )
            or len(set(known_secrets)) != len(known_secrets)
        ):
            raise ValueError("known_secrets must be unique 8..4096 byte strings")
        self._known_secrets = tuple(value.encode("utf-8") for value in known_secrets)

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
        idempotency_key: IdempotencyKey | None = None,
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
        process_environment = self._environment(environment)
        request_secrets = self._request_secrets(process_environment)
        if any(
            secret.decode("utf-8") in argument
            for secret in request_secrets
            for argument in command
        ):
            raise TestEvidenceCollectionError("command cannot contain a known Secret")
        try:
            root = Path(workspace).resolve(strict=True)
        except (OSError, TypeError) as error:
            raise TestEvidenceCollectionError("workspace cannot be resolved") from error
        actual_root = Path(self._git(root, "rev-parse", "--show-toplevel")).resolve(strict=True)
        if root != actual_root:
            raise TestEvidenceCollectionError("workspace must be the exact Git worktree root")
        commit = self._git(root, "rev-parse", "--verify", "HEAD^{commit}")

        request_path: Path | None = None
        fingerprint: str | None = None
        if idempotency_key is not None:
            if not isinstance(idempotency_key, IdempotencyKey):
                raise TestEvidenceCollectionError("idempotency_key must use the domain type")
            fingerprint = self._request_fingerprint(
                root, repository, command, actor_id, task_id, commit, attempt,
                retry_of, failure_outcome, environment, request_secrets,
            )
            request_path, replay = self._reserve_request(
                actor_id, idempotency_key, fingerprint
            )
            if replay is not None:
                return replay

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
                env=process_environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
        except OSError:
            finished_at = datetime.now(UTC)
            evidence = self._evidence(
                evidence_id, actor_id, task_id, repository, root, commit, command,
                attempt, retry_of, started_at, finished_at,
                max(0, round((time.monotonic() - started_monotonic) * 1000)), None,
                CommandOutcome.INFRASTRUCTURE_ERROR, "collector_error", stdout, stderr,
                request_secrets,
            )
            self._complete_request(request_path, fingerprint, evidence)
            return evidence
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
        evidence = self._evidence(
            evidence_id, actor_id, task_id, repository, root, commit, command,
            attempt, retry_of, started_at, finished_at, duration_ms, exit_code,
            outcome, outcome_basis, stdout, stderr,
            request_secrets,
        )
        self._complete_request(request_path, fingerprint, evidence)
        return evidence

    def _reserve_request(
        self, actor_id: AgentId, key: IdempotencyKey, fingerprint: str
    ) -> tuple[Path, CommandEvidence | None]:
        directory = self.artifact_root / ".requests"
        directory.mkdir(parents=False, exist_ok=True, mode=0o700)
        if self._is_link(directory):
            raise EvidenceReplayIntegrityError("evidence request ledger directory is unsafe")
        os.chmod(directory, 0o700)
        identity = hashlib.sha256(
            f"{actor_id.value}\0{key.value}".encode("utf-8")
        ).hexdigest()
        path = directory / f"{identity}.json"
        reservation = json.dumps(
            {"schemaVersion": 1, "status": "in_progress", "fingerprint": fingerprint},
            sort_keys=True,
        ).encode("utf-8")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            record = self._read_request(path)
            if record.get("fingerprint") != fingerprint:
                raise EvidenceIdempotencyConflictError(
                    "idempotency key was already used for a different request"
                )
            if record.get("status") == "in_progress":
                raise EvidenceRequestInProgressError(
                    "evidence request is in progress or its result is unknown"
                )
            if record.get("status") != "completed" or not isinstance(record.get("evidence"), dict):
                raise EvidenceReplayIntegrityError("evidence request ledger is invalid")
            evidence = self._deserialize_evidence(record["evidence"])
            self._verify_artifact(evidence.stdout)
            self._verify_artifact(evidence.stderr)
            return path, evidence
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(reservation)
            stream.flush()
            os.fsync(stream.fileno())
        return path, None

    def _complete_request(
        self, path: Path | None, fingerprint: str | None, evidence: CommandEvidence
    ) -> None:
        if path is None or fingerprint is None:
            return
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        payload = {
            "schemaVersion": 1,
            "status": "completed",
            "fingerprint": fingerprint,
            "evidence": self._serialize_evidence(evidence),
        }
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    def _read_request(self, path: Path) -> dict[str, object]:
        try:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise EvidenceReplayIntegrityError("evidence request ledger is unsafe")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise EvidenceReplayIntegrityError("evidence request ledger cannot be read") from error
        if (
            not isinstance(value, dict)
            or type(value.get("schemaVersion")) is not int
            or value.get("schemaVersion") != 1
        ):
            raise EvidenceReplayIntegrityError("evidence request ledger is invalid")
        return value

    def _verify_artifact(self, artifact: OutputArtifact) -> None:
        path = self.artifact_root / Path(artifact.reference)
        try:
            if path.is_symlink() or not path.is_file():
                raise EvidenceReplayIntegrityError("replayed output artifact is missing or unsafe")
            content = path.read_bytes()
        except OSError as error:
            raise EvidenceReplayIntegrityError("replayed output artifact cannot be read") from error
        if len(content) != artifact.captured_size or hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise EvidenceReplayIntegrityError("replayed output artifact failed integrity verification")

    @staticmethod
    def _request_fingerprint(
        root: Path, repository: str, command: tuple[str, ...], actor_id: AgentId,
        task_id: TaskId, commit: str, attempt: int, retry_of: EvidenceId | None,
        failure_outcome: CommandOutcome, environment: dict[str, str] | None,
        secrets: tuple[bytes, ...],
    ) -> str:
        payload = {
            "workspace": str(root), "repository": repository, "command": command,
            "actorId": actor_id.value, "taskId": task_id.value, "commit": commit,
            "attempt": attempt, "retryOf": None if retry_of is None else retry_of.value,
            "failureOutcome": failure_outcome.value,
            "environmentSha256": hashlib.sha256(json.dumps(
                sorted((environment or {}).items()), ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")).hexdigest(),
            "redactionPolicySha256": hashlib.sha256(json.dumps(
                sorted(hashlib.sha256(value).hexdigest() for value in secrets),
                separators=(",", ":"),
            ).encode("ascii")).hexdigest(),
        }
        return hashlib.sha256(json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()

    @staticmethod
    def _serialize_evidence(evidence: CommandEvidence) -> dict[str, object]:
        def artifact(value: OutputArtifact) -> dict[str, object]:
            return {"reference": value.reference, "sha256": value.sha256,
                    "capturedSize": value.captured_size, "observedSize": value.observed_size,
                    "truncated": value.truncated,
                    "preRedactionSha256": value.pre_redaction_sha256,
                    "redactionCount": value.redaction_count}
        summary = None if evidence.summary is None else {
            "framework": evidence.summary.framework, "passed": evidence.summary.passed,
            "failed": evidence.summary.failed, "skipped": evidence.summary.skipped,
            "errors": evidence.summary.errors,
        }
        return {
            "id": evidence.id.value, "actorId": evidence.actor_id.value,
            "taskId": evidence.task_id.value, "repository": evidence.repository,
            "worktreeRoot": evidence.worktree_root, "commit": evidence.commit,
            "command": list(evidence.command), "attempt": evidence.attempt,
            "retryOf": None if evidence.retry_of is None else evidence.retry_of.value,
            "startedAt": evidence.started_at.isoformat(),
            "finishedAt": evidence.finished_at.isoformat(), "durationMs": evidence.duration_ms,
            "exitCode": evidence.exit_code, "outcome": evidence.outcome.value,
            "outcomeBasis": evidence.outcome_basis, "stdout": artifact(evidence.stdout),
            "stderr": artifact(evidence.stderr), "summary": summary,
        }

    @staticmethod
    def _deserialize_evidence(value: dict[str, object]) -> CommandEvidence:
        try:
            def artifact(name: str) -> OutputArtifact:
                item = value[name]
                if not isinstance(item, dict):
                    raise TypeError
                return OutputArtifact(str(item["reference"]), str(item["sha256"]),
                                      item["capturedSize"], item["observedSize"], item["truncated"],
                                      None if item.get("preRedactionSha256") is None else str(item["preRedactionSha256"]),
                                      item.get("redactionCount", 0))
            summary_value = value["summary"]
            summary = None
            if isinstance(summary_value, dict):
                summary = TestSummary(str(summary_value["framework"]), summary_value["passed"],
                                      summary_value["failed"], summary_value["skipped"],
                                      summary_value["errors"])
            retry = value["retryOf"]
            return CommandEvidence(
                EvidenceId(str(value["id"])), AgentId(str(value["actorId"])),
                TaskId(str(value["taskId"])), str(value["repository"]),
                str(value["worktreeRoot"]), str(value["commit"]),
                tuple(value["command"]), value["attempt"],
                None if retry is None else EvidenceId(str(retry)),
                datetime.fromisoformat(str(value["startedAt"])),
                datetime.fromisoformat(str(value["finishedAt"])), value["durationMs"],
                value["exitCode"], CommandOutcome(str(value["outcome"])),
                str(value["outcomeBasis"]), artifact("stdout"), artifact("stderr"), summary,
            )
        except (KeyError, TypeError, ValueError) as error:
            raise EvidenceReplayIntegrityError("completed evidence result is invalid") from error

    def _evidence(
        self, evidence_id: EvidenceId, actor_id: AgentId, task_id: TaskId,
        repository: str, root: Path, commit: str, command: tuple[str, ...],
        attempt: int, retry_of: EvidenceId | None, started_at: datetime,
        finished_at: datetime, duration_ms: int, exit_code: int | None,
        outcome: CommandOutcome, outcome_basis: str, stdout: _Capture, stderr: _Capture,
        secrets: tuple[bytes, ...],
    ) -> CommandEvidence:
        stdout_artifact = self._save(evidence_id, "stdout", stdout, secrets)
        stderr_artifact = self._save(evidence_id, "stderr", stderr, secrets)
        summary = None
        if not stdout.exceeded.is_set() and not stderr.exceeded.is_set():
            redacted_stdout, _ = self._redact(bytes(stdout.retained), secrets)
            redacted_stderr, _ = self._redact(bytes(stderr.retained), secrets)
            summary = self._pytest_summary(redacted_stdout + b"\n" + redacted_stderr)
        return CommandEvidence(
            evidence_id, actor_id, task_id, repository, str(root), commit, command,
            attempt, retry_of, started_at, finished_at, duration_ms,
            exit_code, outcome, outcome_basis, stdout_artifact, stderr_artifact, summary,
        )

    def _save(
        self,
        evidence_id: EvidenceId,
        name: str,
        capture: _Capture,
        secrets: tuple[bytes, ...],
    ) -> OutputArtifact:
        directory = self.artifact_root / evidence_id.value
        directory.mkdir(parents=False, exist_ok=True, mode=0o700)
        if self._is_link(directory):
            raise TestEvidenceCollectionError("evidence Artifact directory is unsafe")
        os.chmod(directory, 0o700)
        path = directory / f"{name}.bin"
        persisted, redaction_count = self._redact(bytes(capture.retained), secrets)
        with path.open("xb") as stream:
            os.chmod(path, 0o600)
            stream.write(persisted)
            stream.flush()
            os.fsync(stream.fileno())
        reference = path.relative_to(self.artifact_root).as_posix()
        return OutputArtifact(
            reference,
            hashlib.sha256(persisted).hexdigest(),
            len(persisted),
            capture.observed_size,
            capture.observed_size > len(persisted),
            capture.digest.hexdigest(),
            redaction_count,
        )

    def _request_secrets(
        self, environment: dict[str, str] | None
    ) -> tuple[bytes, ...]:
        values = list(self._known_secrets)
        for key, value in (environment or {}).items():
            if _SECRET_ENVIRONMENT_NAME.search(key) and value:
                encoded = value.encode("utf-8")
                if not 8 <= len(encoded) <= 4096:
                    raise TestEvidenceCollectionError(
                        "sensitive environment values must be 8..4096 bytes"
                    )
                values.append(encoded)
        return tuple(sorted(set(values), key=lambda item: (-len(item), item)))

    @staticmethod
    def _redact(content: bytes, secrets: tuple[bytes, ...]) -> tuple[bytes, int]:
        redacted = content
        count = 0
        for secret in secrets:
            occurrences = redacted.count(secret)
            if occurrences:
                redacted = redacted.replace(secret, b"*" * len(secret))
                count += occurrences
            # If capture stopped in the middle of a known Secret, redact its retained prefix.
            if len(redacted) < len(secret):
                maximum = len(redacted)
            else:
                maximum = len(secret) - 1
            for length in range(maximum, 3, -1):
                if redacted.endswith(secret[:length]):
                    redacted = redacted[:-length] + b"*" * length
                    count += 1
                    break
        return redacted, count

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

    def _environment(self, overrides: dict[str, str] | None) -> dict[str, str]:
        environment = os.environ.copy() if self.inherit_environment else {}
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
    def _is_link(path: Path) -> bool:
        return path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        )

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
