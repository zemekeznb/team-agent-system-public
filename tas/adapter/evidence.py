"""Local collection and resumable publication of authoritative remote Evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol
from uuid import uuid4

from tas.adapter.config import TestCommandProfile
from tas.adapter.http_client import (
    RemoteArtifact,
    RemoteArtifactPurpose,
    RemoteArtifactStatus,
    RemoteEvidence,
    RemoteEvidenceKind,
    RemoteEvidenceStatus,
    RemoteWorkspace,
)
from tas.adapter.workspaces import LocalWorkspace, LocalWorkspaceError, LocalWorkspaceStore
from tas.adapters.execution.test_evidence_collector import (
    TestEvidenceCollectionError,
    TestEvidenceCollector,
)
from tas.adapters.git.evidence_collector import (
    GitEvidenceCollectionError,
    GitEvidenceCollector,
)
from tas.domain.collaboration import TaskId
from tas.domain.evidence import CommandEvidence, EvidenceId, GitEvidence, OutputArtifact
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class AdapterEvidenceError(RuntimeError):
    """Evidence cannot be collected or published without weakening its boundary."""


_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")


class EvidenceRemoteClient(Protocol):
    def get_workspace(self, workspace_id: str) -> RemoteWorkspace: ...

    def reserve_artifact(self, **kwargs): ...

    def upload_artifact_content(self, **kwargs): ...

    def finalize_artifact(self, **kwargs): ...

    def reserve_evidence(self, **kwargs) -> RemoteEvidence: ...

    def finalize_evidence(self, **kwargs) -> RemoteEvidence: ...


@dataclass(frozen=True, slots=True)
class PublishedEvidence:
    evidence_id: str
    kind: str
    task_id: str
    workspace_id: str
    head_commit: str
    artifact_ids: tuple[str, ...]
    replayed: bool
    correlation_id: str


class _GitRequestLedger:
    """Durable sanitized snapshot so retry never invents a new observed_at."""

    def __init__(self, state_root: Path) -> None:
        self.root = state_root / "git-evidence-requests"
        try:
            self.root.mkdir(mode=0o700, exist_ok=True)
            if self.root.is_symlink() or (
                hasattr(self.root, "is_junction") and self.root.is_junction()
            ):
                raise AdapterEvidenceError("Git Evidence ledger directory is unsafe")
            os.chmod(self.root, 0o700)
        except AdapterEvidenceError:
            raise
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence ledger is unavailable") from error

    def reserve(
        self, actor_id: str, key: str, fingerprint: str
    ) -> tuple[Path, dict[str, object] | None]:
        identity = hashlib.sha256(f"{actor_id}\0{key}".encode()).hexdigest()
        path = self.root / f"{identity}.json"
        value = {
            "schemaVersion": 1,
            "status": "in_progress",
            "fingerprint": fingerprint,
        }
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            record = self._read(path)
            if record.get("fingerprint") != fingerprint:
                raise AdapterEvidenceError(
                    "Git Evidence idempotency key was reused for another request"
                )
            if record.get("status") == "in_progress":
                raise AdapterEvidenceError(
                    "Git Evidence collection is in progress or its result is unknown"
                )
            snapshot = record.get("snapshot")
            if record.get("status") != "completed" or not isinstance(snapshot, dict):
                raise AdapterEvidenceError("Git Evidence ledger is invalid")
            return path, snapshot
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence request cannot be reserved") from error
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        return path, None

    def complete(
        self, path: Path, fingerprint: str, snapshot: dict[str, object]
    ) -> None:
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        value = {
            "schemaVersion": 1,
            "status": "completed",
            "fingerprint": fingerprint,
            "snapshot": snapshot,
        }
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                os.chmod(temporary, 0o600)
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence result cannot be persisted") from error
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _read(path: Path) -> dict[str, object]:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024:
                raise AdapterEvidenceError("Git Evidence ledger entry is unsafe")
            value = json.loads(path.read_text(encoding="utf-8"))
        except AdapterEvidenceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AdapterEvidenceError("Git Evidence ledger cannot be read") from error
        if (
            not isinstance(value, dict)
            or type(value.get("schemaVersion")) is not int
            or value.get("schemaVersion") != 1
        ):
            raise AdapterEvidenceError("Git Evidence ledger is invalid")
        return value


class LocalGitEvidenceIndex:
    """Owner-local binding from central Evidence ID to its immutable snapshot."""

    def __init__(self, state_root: Path, secret: str) -> None:
        if not isinstance(secret, str) or len(secret.encode("utf-8")) < 8:
            raise ValueError("Git Evidence index secret is invalid")
        self._key = hashlib.sha256(
            b"tas-adapter-git-evidence-index\0" + secret.encode("utf-8")
        ).digest()
        self.root = state_root / "git-evidence-index"
        try:
            self.root.mkdir(mode=0o700, exist_ok=True)
            if self.root.is_symlink() or (
                hasattr(self.root, "is_junction") and self.root.is_junction()
            ):
                raise AdapterEvidenceError("Git Evidence index directory is unsafe")
            os.chmod(self.root, 0o700)
        except AdapterEvidenceError:
            raise
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence index is unavailable") from error

    def bind(
        self,
        evidence_id: str,
        snapshot: dict[str, object],
        *,
        replace_unverifiable: bool = False,
    ) -> None:
        identity = hashlib.sha256(evidence_id.encode("utf-8")).hexdigest()
        path = self.root / f"{identity}.json"
        value = {
            "schemaVersion": 1,
            "evidence_id": evidence_id,
            "snapshot": snapshot,
        }
        value["mac"] = self._mac(value)
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        if len(encoded.encode("utf-8")) > 512 * 1024:
            raise AdapterEvidenceError("Git Evidence index entry is too large")
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            try:
                existing = self._read(path)
            except AdapterEvidenceError:
                if not replace_unverifiable:
                    raise
                self._replace(path, encoded)
                return
            if existing != value:
                raise AdapterEvidenceError("Git Evidence ID conflicts with local state")
            return
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence index cannot be written") from error
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())

    def _replace(self, path: Path, encoded: str) -> None:
        temporary = path.with_name(f"{path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                os.chmod(temporary, 0o600)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        except OSError as error:
            raise AdapterEvidenceError("Git Evidence index cannot be replaced") from error
        finally:
            temporary.unlink(missing_ok=True)

    def get(self, evidence_id: str) -> dict[str, object]:
        identity = hashlib.sha256(evidence_id.encode("utf-8")).hexdigest()
        value = self._read(self.root / f"{identity}.json")
        if (
            value.get("evidence_id") != evidence_id
            or not isinstance(value.get("snapshot"), dict)
            or not self._valid_mac(value)
        ):
            raise AdapterEvidenceError("Git Evidence index entry is invalid")
        return value["snapshot"]

    def _read(self, path: Path) -> dict[str, object]:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size > 512 * 1024:
                raise AdapterEvidenceError("Git Evidence index entry is unsafe")
            value = json.loads(path.read_text(encoding="utf-8"))
        except AdapterEvidenceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise AdapterEvidenceError("Git Evidence index cannot be read") from error
        if (
            not isinstance(value, dict)
            or set(value) != {"schemaVersion", "evidence_id", "snapshot", "mac"}
            or type(value.get("schemaVersion")) is not int
            or value.get("schemaVersion") != 1
        ):
            raise AdapterEvidenceError("Git Evidence index entry is invalid")
        if not self._valid_mac(value):
            raise AdapterEvidenceError("Git Evidence index integrity check failed")
        return value

    def _mac(self, value: dict[str, object]) -> str:
        unsigned = {key: item for key, item in value.items() if key != "mac"}
        encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key, encoded, hashlib.sha256).hexdigest()

    def _valid_mac(self, value: dict[str, object]) -> bool:
        mac = value.get("mac")
        return isinstance(mac, str) and hmac.compare_digest(mac, self._mac(value))


class AdapterEvidenceService:
    """Collect locally, then publish through central reservation/finalization APIs."""

    def __init__(
        self,
        *,
        client: EvidenceRemoteClient,
        workspaces: LocalWorkspaceStore,
        actor_id: str,
        credential: str,
        profiles: dict[str, TestCommandProfile],
        test_collector_factory: Callable[..., TestEvidenceCollector] = TestEvidenceCollector,
    ) -> None:
        if not actor_id or not credential:
            raise ValueError("actor_id and credential are required")
        self.client = client
        self.workspaces = workspaces
        self.actor_id = actor_id
        self.credential = credential
        self.profiles = dict(profiles)
        self.test_collector_factory = test_collector_factory
        self.git_collector = GitEvidenceCollector()
        self.git_ledger = _GitRequestLedger(workspaces.root)
        self.git_index = LocalGitEvidenceIndex(workspaces.root, credential)
        self.artifact_root = workspaces.root / "evidence-artifacts"

    def collect_git(
        self, *, workspace_id: str, baseline: str, idempotency_key: str
    ) -> PublishedEvidence:
        self._validate_idempotency_key(idempotency_key)
        mapping = self._mapping(workspace_id)
        fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "actor": self.actor_id,
                    "workspace": workspace_id,
                    "root": mapping.root,
                    "baseline": baseline,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        ledger_path, snapshot = self.git_ledger.reserve(
            self.actor_id, idempotency_key, fingerprint
        )
        if snapshot is None:
            try:
                evidence = self.git_collector.collect(
                    mapping.root,
                    repository=mapping.repository,
                    baseline=baseline,
                    actor_id=AgentId(self.actor_id),
                    task_id=TaskId(mapping.task_id),
                )
            except (GitEvidenceCollectionError, OSError, ValueError) as error:
                raise AdapterEvidenceError("Git Evidence collection failed") from error
            snapshot = self._git_snapshot(mapping, evidence)
            self.git_ledger.complete(ledger_path, fingerprint, snapshot)
        published = self._publish_snapshot(idempotency_key, snapshot)
        self.git_index.bind(
            published.evidence_id, snapshot, replace_unverifiable=True
        )
        return published

    def run_test(
        self,
        *,
        workspace_id: str,
        profile_name: str,
        attempt: int,
        retry_of: str | None,
        idempotency_key: str,
    ) -> PublishedEvidence:
        self._validate_idempotency_key(idempotency_key)
        mapping = self._mapping(workspace_id)
        profile = self.profiles.get(profile_name)
        if profile is None:
            raise AdapterEvidenceError("Unknown test command profile")
        try:
            executable = (Path(mapping.root) / profile.argv[0]).resolve(strict=True)
        except OSError as error:
            raise AdapterEvidenceError("Test profile executable is unavailable") from error
        if not executable.is_relative_to(Path(mapping.root)) or not executable.is_file():
            raise AdapterEvidenceError("Test profile executable is outside the Workspace")
        try:
            collector = self.test_collector_factory(
                self.artifact_root,
                timeout_seconds=profile.timeout_seconds,
                max_output_bytes=profile.max_output_bytes,
                known_secrets=(self.credential,),
                inherit_environment=False,
            )
        except (OSError, TypeError, ValueError) as error:
            raise AdapterEvidenceError("Test Evidence collector is unavailable") from error
        retry = None if retry_of is None else EvidenceId(retry_of)
        try:
            evidence = collector.collect(
                mapping.root,
                repository=mapping.repository,
                command=profile.argv,
                actor_id=AgentId(self.actor_id),
                task_id=TaskId(mapping.task_id),
                attempt=attempt,
                retry_of=retry,
                environment=self._sanitized_environment(),
                idempotency_key=IdempotencyKey(idempotency_key),
            )
        except (TestEvidenceCollectionError, OSError, ValueError) as error:
            raise AdapterEvidenceError("Test Evidence collection failed") from error
        artifact_ids = (
            self._publish_output_artifact(
                mapping, evidence.stdout, RemoteArtifactPurpose.TEST_STDOUT,
                idempotency_key, "stdout",
            ),
            self._publish_output_artifact(
                mapping, evidence.stderr, RemoteArtifactPurpose.TEST_STDERR,
                idempotency_key, "stderr",
            ),
        )
        snapshot = self._command_snapshot(mapping, evidence, artifact_ids)
        return self._publish_snapshot(idempotency_key, snapshot)

    def _mapping(self, workspace_id: str) -> LocalWorkspace:
        try:
            mapping = self.workspaces.get(workspace_id)
        except LocalWorkspaceError as error:
            raise AdapterEvidenceError(str(error)) from error
        remote = self.client.get_workspace(workspace_id)
        if (
            remote.id != mapping.workspace_id
            or remote.task_id != mapping.task_id
            or remote.actor_agent_id != mapping.agent_id
            or remote.repository != mapping.repository
            or mapping.agent_id != self.actor_id
        ):
            raise AdapterEvidenceError("Local and central Workspace bindings differ")
        return mapping

    def _publish_output_artifact(
        self,
        mapping: LocalWorkspace,
        artifact: OutputArtifact,
        purpose: RemoteArtifactPurpose,
        root_key: str,
        label: str,
    ) -> str:
        try:
            path = (self.artifact_root / artifact.reference).resolve(strict=True)
        except OSError as error:
            raise AdapterEvidenceError("Collected Artifact cannot be resolved") from error
        if not path.is_relative_to(self.artifact_root.resolve()) or path.is_symlink():
            raise AdapterEvidenceError("Collected Artifact path is unsafe")
        try:
            content = path.read_bytes()
        except OSError as error:
            raise AdapterEvidenceError("Collected Artifact cannot be read") from error
        if len(content) != artifact.captured_size or hashlib.sha256(content).hexdigest() != artifact.sha256:
            raise AdapterEvidenceError("Collected Artifact failed integrity verification")
        reserved = self.client.reserve_artifact(
            idempotency_key=self._key(root_key, f"artifact:{label}:reserve"),
            task_id=mapping.task_id,
            media_type="text/plain",
            purpose=purpose,
            content=content,
        )
        if (
            reserved.task_id != mapping.task_id
            or reserved.purpose is not purpose
            or reserved.media_type != "text/plain"
            or reserved.declared_size != len(content)
            or reserved.declared_sha256 != artifact.sha256
        ):
            raise AdapterEvidenceError("Central Artifact reservation differs")
        uploaded = self.client.upload_artifact_content(
            idempotency_key=self._key(root_key, f"artifact:{label}:upload"),
            artifact_id=reserved.id,
            media_type="text/plain",
            content=content,
        )
        self._verify_artifact_response(
            uploaded,
            reserved=reserved,
            allowed_statuses={
                RemoteArtifactStatus.UPLOADED,
                RemoteArtifactStatus.FINALIZED,
            },
        )
        finalized = self.client.finalize_artifact(
            idempotency_key=self._key(root_key, f"artifact:{label}:finalize"),
            artifact_id=reserved.id,
        )
        self._verify_artifact_response(
            finalized,
            reserved=reserved,
            allowed_statuses={RemoteArtifactStatus.FINALIZED},
        )
        return finalized.id

    def _publish_snapshot(
        self, root_key: str, snapshot: dict[str, object]
    ) -> PublishedEvidence:
        try:
            kind = RemoteEvidenceKind(str(snapshot["kind"]))
            task_id = str(snapshot["task_id"])
            workspace_id = str(snapshot["workspace_id"])
            attempt = snapshot["attempt"]
            retry_of = snapshot["retry_of"]
            observed_at = datetime.fromisoformat(str(snapshot["observed_at"]))
            head_commit = str(snapshot["head_commit"])
            artifact_ids = tuple(str(item) for item in snapshot["artifact_ids"])
            payload_json = str(snapshot["payload_json"])
        except (KeyError, TypeError, ValueError) as error:
            raise AdapterEvidenceError("Local Evidence snapshot is invalid") from error
        self._validate_snapshot_payload(
            kind=kind,
            workspace_id=workspace_id,
            head_commit=head_commit,
            artifact_ids=artifact_ids,
            payload_json=payload_json,
        )
        reserved = self.client.reserve_evidence(
            idempotency_key=self._key(root_key, "evidence:reserve"),
            task_id=task_id,
            workspace_id=workspace_id,
            kind=kind,
            attempt=attempt,
            retry_of=retry_of,
            observed_at=observed_at,
            head_commit=head_commit,
            artifact_ids=artifact_ids,
        )
        expected = (
            task_id,
            workspace_id,
            kind,
            attempt,
            retry_of,
            observed_at,
            head_commit,
            artifact_ids,
        )
        if self._evidence_identity(reserved) != expected:
            raise AdapterEvidenceError("Central Evidence reservation differs")
        finalized = self.client.finalize_evidence(
            idempotency_key=self._key(root_key, "evidence:finalize"),
            evidence_id=reserved.id,
            payload_json=payload_json,
        )
        expected_digest = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
        if (
            finalized.id != reserved.id
            or self._evidence_identity(finalized) != expected
            or finalized.status is not RemoteEvidenceStatus.FINALIZED
            or finalized.payload_sha256 != expected_digest
        ):
            raise AdapterEvidenceError("Central Evidence finalization differs")
        return PublishedEvidence(
            finalized.id,
            finalized.kind.value,
            finalized.task_id,
            finalized.workspace_id,
            finalized.head_commit,
            finalized.artifact_ids,
            reserved.replayed or finalized.replayed,
            finalized.correlation_id,
        )

    @staticmethod
    def _git_snapshot(
        mapping: LocalWorkspace, evidence: GitEvidence
    ) -> dict[str, object]:
        payload = {
            "artifact_ids": [],
            "baseline_commit": evidence.baseline_commit,
            "branch": evidence.branch,
            "diff_sha256": evidence.diff_sha256,
            "diff_size": evidence.diff_size,
            "files": [
                {
                    "kind": item.kind.value,
                    "path": item.path,
                    "sha256": item.sha256,
                    "size": item.size,
                }
                for item in evidence.files
            ],
            "git_version": evidence.git_version,
            "head_commit": evidence.head_commit,
            "kind": "git",
            "repository": mapping.repository,
            "workspace_id": mapping.workspace_id,
        }
        return {
            "task_id": mapping.task_id,
            "workspace_id": mapping.workspace_id,
            "kind": "git",
            "attempt": 1,
            "retry_of": None,
            "observed_at": evidence.captured_at.isoformat(),
            "head_commit": evidence.head_commit,
            "artifact_ids": [],
            "payload_json": AdapterEvidenceService._canonical(payload),
        }

    @staticmethod
    def _command_snapshot(
        mapping: LocalWorkspace,
        evidence: CommandEvidence,
        artifact_ids: tuple[str, str],
    ) -> dict[str, object]:
        def output(value: OutputArtifact, remote_id: str) -> dict[str, object]:
            return {
                "artifact_id": remote_id,
                "captured_size": value.captured_size,
                "observed_size": value.observed_size,
                "sha256": value.sha256,
                "truncated": value.truncated,
                "pre_redaction_sha256": value.pre_redaction_sha256,
                "redaction_count": value.redaction_count,
            }

        summary = None
        if evidence.summary is not None:
            summary = {
                "errors": evidence.summary.errors,
                "failed": evidence.summary.failed,
                "framework": evidence.summary.framework,
                "passed": evidence.summary.passed,
                "skipped": evidence.summary.skipped,
            }
        retry = None if evidence.retry_of is None else {"value": evidence.retry_of.value}
        payload = {
            "artifact_ids": list(artifact_ids),
            "attempt": evidence.attempt,
            "command": list(evidence.command),
            "commit": evidence.commit,
            "duration_ms": evidence.duration_ms,
            "exit_code": evidence.exit_code,
            "finished_at": evidence.finished_at.isoformat(),
            "kind": "command_test",
            "outcome": evidence.outcome.value,
            "outcome_basis": evidence.outcome_basis,
            "repository": mapping.repository,
            "retry_of": retry,
            "started_at": evidence.started_at.isoformat(),
            "stderr": output(evidence.stderr, artifact_ids[1]),
            "stdout": output(evidence.stdout, artifact_ids[0]),
            "summary": summary,
            "workspace_id": mapping.workspace_id,
        }
        return {
            "task_id": mapping.task_id,
            "workspace_id": mapping.workspace_id,
            "kind": "command_test",
            "attempt": evidence.attempt,
            "retry_of": None if evidence.retry_of is None else evidence.retry_of.value,
            "observed_at": evidence.started_at.isoformat(),
            "head_commit": evidence.commit,
            "artifact_ids": list(artifact_ids),
            "payload_json": AdapterEvidenceService._canonical(payload),
        }

    @staticmethod
    def _canonical(value: dict[str, object]) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def _validate_snapshot_payload(
        self,
        *,
        kind: RemoteEvidenceKind,
        workspace_id: str,
        head_commit: str,
        artifact_ids: tuple[str, ...],
        payload_json: str,
    ) -> None:
        try:
            payload = json.loads(payload_json)
        except (json.JSONDecodeError, RecursionError) as error:
            raise AdapterEvidenceError("Local Evidence payload is invalid") from error
        git_fields = {
            "artifact_ids", "baseline_commit", "branch", "diff_sha256", "diff_size",
            "files", "git_version", "head_commit", "kind", "repository", "workspace_id",
        }
        command_fields = {
            "artifact_ids", "attempt", "command", "commit", "duration_ms", "exit_code",
            "finished_at", "kind", "outcome", "outcome_basis", "repository", "retry_of",
            "started_at", "stderr", "stdout", "summary", "workspace_id",
        }
        expected = git_fields if kind is RemoteEvidenceKind.GIT else command_fields
        if (
            not isinstance(payload, dict)
            or set(payload) != expected
            or self._canonical(payload) != payload_json
            or payload.get("kind") != kind.value
            or payload.get("workspace_id") != workspace_id
            or payload.get("artifact_ids") != list(artifact_ids)
            or payload.get("head_commit", payload.get("commit")) != head_commit
        ):
            raise AdapterEvidenceError("Local Evidence payload is inconsistent")
        mapping = self.workspaces.get(workspace_id)
        if (
            payload.get("repository") != mapping.repository
            or mapping.root in payload_json
            or self.credential in payload_json
        ):
            raise AdapterEvidenceError("Local Evidence payload crosses a private boundary")

    @staticmethod
    def _key(root: str, phase: str) -> str:
        return "tas:" + hashlib.sha256(f"{root}\0{phase}".encode()).hexdigest()

    @staticmethod
    def _verify_artifact_response(
        value: RemoteArtifact,
        *,
        reserved: RemoteArtifact,
        allowed_statuses: set[RemoteArtifactStatus],
    ) -> None:
        if (
            value.id != reserved.id
            or value.task_id != reserved.task_id
            or value.media_type != reserved.media_type
            or value.purpose is not reserved.purpose
            or value.declared_size != reserved.declared_size
            or value.declared_sha256 != reserved.declared_sha256
            or value.status not in allowed_statuses
        ):
            raise AdapterEvidenceError("Central Artifact lifecycle response differs")

    @staticmethod
    def _evidence_identity(value: RemoteEvidence) -> tuple[object, ...]:
        return (
            value.task_id,
            value.workspace_id,
            value.kind,
            value.attempt,
            value.retry_of,
            value.observed_at,
            value.head_commit,
            value.artifact_ids,
        )

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        allowed = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")
        environment = {
            key: os.environ[key]
            for key in allowed
            if key in os.environ and os.environ[key]
        }
        environment["PYTHONIOENCODING"] = "utf-8"
        environment["PYTHONUTF8"] = "1"
        return environment

    @staticmethod
    def _validate_idempotency_key(value: str) -> None:
        if not isinstance(value, str) or _IDEMPOTENCY_KEY.fullmatch(value) is None:
            raise AdapterEvidenceError("Evidence idempotency key is invalid")
