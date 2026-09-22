"""Credential-bound local Git commit Provider and remote Grant orchestration."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator, Protocol

from tas.adapter.evidence import AdapterEvidenceError, AdapterEvidenceService
from tas.adapter.http_client import (
    AdapterClientError,
    RemoteActionGrant,
    RemoteActionGrantStatus,
    RemoteActionReceipt,
    RemoteAPIError,
    RemoteApproval,
)
from tas.adapter.workspaces import LocalWorkspace, LocalWorkspaceError, LocalWorkspaceStore
from tas.adapters.git.evidence_collector import GitEvidenceCollectionError, GitEvidenceCollector
from tas.domain.collaboration import TaskId
from tas.domain.identity import AgentId


class AdapterActionError(RuntimeError):
    """An approved action cannot proceed without weakening its safety boundary."""


class AdapterActionResultUnknownError(AdapterActionError):
    """The Provider may have completed; only reconciliation may continue."""


class ActionRemoteClient(Protocol):
    def get_approval(self, approval_id: str) -> RemoteApproval: ...
    def prepare_action_grant(self, **kwargs) -> RemoteActionGrant: ...
    def get_action_grant(self, approval_id: str) -> RemoteActionGrant: ...
    def mark_action_result_unknown(self, **kwargs) -> RemoteActionGrant: ...
    def submit_action_receipt(self, **kwargs) -> RemoteActionGrant: ...


@dataclass(frozen=True, slots=True)
class ExecutedAction:
    approval_id: str
    operation_id: str
    status: str
    external_action_id: str | None
    result_reference: str | None
    replayed: bool
    correlation_id: str


class GitCommitProvider:
    """Commit an already-staged exact Evidence snapshot without hooks or filters."""

    _OPERATION = "TAS-Operation-ID"
    _FINGERPRINT = "TAS-Request-Fingerprint"

    def __init__(self, *, timeout_seconds: float = 15, max_output_bytes: int = 1024 * 1024) -> None:
        if timeout_seconds <= 0 or max_output_bytes <= 0:
            raise ValueError("Git Provider limits must be positive")
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = int(max_output_bytes)

    def find_receipt(
        self, root: Path, operation_id: str, request_fingerprint: str
    ) -> RemoteActionReceipt | None:
        self._validate_operation(operation_id, request_fingerprint)
        operation_ref = self._operation_ref(operation_id)
        resolved = self._completed(
            root, "rev-parse", "--verify", f"{operation_ref}^{{commit}}"
        )
        if resolved.returncode != 0:
            return None
        commit = resolved.stdout.decode("ascii").strip()
        record = self._run(root, "show", "-s", "--format=%H%x00%cI%x00%B", commit)
        fields = record.strip(b"\r\n\x00").split(b"\x00", 2)
        if len(fields) != 3:
            raise AdapterActionError("Git Provider Receipt history is malformed")
        try:
            shown_commit = fields[0].decode("ascii")
            occurred_at = datetime.fromisoformat(fields[1].decode("ascii"))
            message = fields[2].decode("utf-8")
        except (UnicodeError, ValueError) as error:
            raise AdapterActionError("Git Provider Receipt history is malformed") from error
        trailers = self._trailers(message)
        if shown_commit != commit or trailers.get(self._OPERATION) != operation_id:
            raise AdapterActionError("Git Provider Receipt operation is inconsistent")
        if trailers.get(self._FINGERPRINT) != request_fingerprint:
            raise AdapterActionError("Git operation ID belongs to another request")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise AdapterActionError("Git Provider Receipt time is invalid")
        return RemoteActionReceipt(
            operation_id, request_fingerprint, commit,
            f"git:commit:{commit}", occurred_at.astimezone(UTC),
        )

    def execute_once(
        self,
        root: Path,
        *,
        branch_ref: str,
        expected_head: str,
        operation_id: str,
        request_fingerprint: str,
        execute_before: datetime,
    ) -> RemoteActionReceipt:
        with self._lock(root):
            return self._execute_once_locked(
                root,
                branch_ref=branch_ref,
                expected_head=expected_head,
                operation_id=operation_id,
                request_fingerprint=request_fingerprint,
                execute_before=execute_before,
            )

    def _execute_once_locked(
        self,
        root: Path,
        *,
        branch_ref: str,
        expected_head: str,
        operation_id: str,
        request_fingerprint: str,
        execute_before: datetime,
    ) -> RemoteActionReceipt:
        self._validate_operation(operation_id, request_fingerprint)
        existing = self.find_receipt(root, operation_id, request_fingerprint)
        if existing is not None:
            return existing
        try:
            self._check_preconditions(root, branch_ref, expected_head, execute_before)
            self._check_staged(root)
        except AdapterActionError:
            recovered = self.find_receipt(root, operation_id, request_fingerprint)
            if recovered is not None:
                return recovered
            raise

        attempt_object, is_new_attempt = self._reserve_attempt(
            root, operation_id, request_fingerprint
        )
        if not is_new_attempt:
            raise AdapterActionResultUnknownError(
                "Git Provider attempt exists without a Receipt"
            )

        tree = self._text(root, "write-tree")
        occurred_at = datetime.now(UTC).replace(microsecond=0)
        if occurred_at >= execute_before:
            raise AdapterActionError("Action Grant execution window expired")
        message = (
            "TAS approved commit\n\n"
            f"{self._OPERATION}: {operation_id}\n"
            f"{self._FINGERPRINT}: {request_fingerprint}\n"
        )
        environment = {
            "GIT_AUTHOR_NAME": "TAS Adapter",
            "GIT_AUTHOR_EMAIL": "tas-adapter@invalid",
            "GIT_COMMITTER_NAME": "TAS Adapter",
            "GIT_COMMITTER_EMAIL": "tas-adapter@invalid",
            "GIT_AUTHOR_DATE": occurred_at.isoformat(),
            "GIT_COMMITTER_DATE": occurred_at.isoformat(),
        }
        commit = self._text(
            root, "-c", "commit.gpgsign=false", "commit-tree", tree,
            "-p", expected_head, "-m", message, environment=environment,
        )
        if datetime.now(UTC) >= execute_before:
            raise AdapterActionError("Action Grant expired before Git ref update")
        transaction = (
            "start\n"
            f"verify {self._attempt_ref(operation_id)} {attempt_object}\n"
            f"update {branch_ref} {commit} {expected_head}\n"
            f"create {self._operation_ref(operation_id)} {commit}\n"
            "prepare\n"
            "commit\n"
        ).encode("ascii")
        result = self._completed(root, "update-ref", "--stdin", input_bytes=transaction)
        if result.returncode != 0:
            recovered = self.find_receipt(root, operation_id, request_fingerprint)
            if recovered is not None:
                return recovered
            raise AdapterActionError("Git branch changed before approved update")
        return RemoteActionReceipt(
            operation_id, request_fingerprint, commit,
            f"git:commit:{commit}", occurred_at,
        )

    def _reserve_attempt(
        self, root: Path, operation_id: str, request_fingerprint: str
    ) -> tuple[str, bool]:
        attempt_ref = self._attempt_ref(operation_id)
        payload = json.dumps(
            {
                "operation_id": operation_id,
                "request_fingerprint": request_fingerprint,
                "schemaVersion": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        existing = self._completed(root, "rev-parse", "--verify", attempt_ref)
        if existing.returncode == 0:
            object_id = existing.stdout.decode("ascii").strip()
            stored = self._run(root, "cat-file", "blob", object_id)
            if stored != payload:
                raise AdapterActionError("Git Provider attempt belongs to another request")
            return object_id, False
        object_id = self._run(
            root, "hash-object", "-w", "--stdin", input_bytes=payload
        ).decode("ascii").strip()
        created = self._completed(root, "update-ref", attempt_ref, object_id, "0" * 40)
        if created.returncode != 0:
            stored_id = self._text(root, "rev-parse", "--verify", attempt_ref)
            stored = self._run(root, "cat-file", "blob", stored_id)
            if stored != payload:
                raise AdapterActionError("Git Provider attempt belongs to another request")
            return stored_id, False
        return object_id, True

    @contextmanager
    def _lock(self, root: Path) -> Iterator[None]:
        raw_path = self._text(root, "rev-parse", "--git-path", "tas-adapter-action.lock")
        path = Path(raw_path)
        if not path.is_absolute():
            path = root / path
        if path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        ):
            raise AdapterActionError("Git Provider lock path is unsafe")
        path = path.resolve(strict=False)
        try:
            handle = path.open("a+b")
            os.chmod(path, 0o600)
        except OSError as error:
            raise AdapterActionError("Git Provider lock is unavailable") from error
        locked = False
        try:
            if handle.seek(0, os.SEEK_END) == 0:
                handle.write(b"0")
                handle.flush()
            deadline = time.monotonic() + self.timeout_seconds
            while True:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                    break
                except OSError as error:
                    if time.monotonic() >= deadline:
                        raise AdapterActionError("Git Provider lock timed out") from error
                    time.sleep(0.05)
            yield
        finally:
            if locked:
                try:
                    handle.seek(0)
                    if os.name == "nt":
                        import msvcrt

                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                    else:
                        import fcntl

                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
                except OSError:
                    pass
            handle.close()

    def check_ready(
        self,
        root: Path,
        *,
        branch_ref: str,
        expected_head: str,
        execute_before: datetime,
    ) -> None:
        self._check_preconditions(root, branch_ref, expected_head, execute_before)
        self._check_staged(root)

    def _check_staged(self, root: Path) -> None:
        staged = self._returncode(root, "diff", "--cached", "--quiet", "--")
        if staged not in (0, 1):
            raise AdapterActionError("Git Provider could not inspect staged changes")
        if staged == 0:
            raise AdapterActionError("Git Provider requires staged changes")
        staged_raw = self._run(root, "diff", "--cached", "--raw", "--no-renames", "-z", "--")
        if b":160000 " in staged_raw or b" 160000 " in staged_raw:
            raise AdapterActionError("Git Provider does not support Gitlink changes")
        unstaged = self._returncode(root, "diff", "--quiet", "--")
        if unstaged not in (0, 1):
            raise AdapterActionError("Git Provider could not inspect unstaged changes")
        if unstaged == 1:
            raise AdapterActionError("Git Provider rejects unstaged changes")
        if self._run(root, "ls-files", "--others", "--exclude-standard", "-z"):
            raise AdapterActionError("Git Provider rejects untracked files")

    def _check_preconditions(
        self, root: Path, branch_ref: str, expected_head: str, execute_before: datetime
    ) -> None:
        if (
            not isinstance(branch_ref, str)
            or len(branch_ref) > 255
            or any(character in branch_ref for character in "\0\r\n")
            or self._returncode(root, "check-ref-format", branch_ref) != 0
        ):
            raise AdapterActionError("Approval scope is not a valid Git branch ref")
        if (
            not isinstance(expected_head, str)
            or len(expected_head) not in (40, 64)
            or any(character not in "0123456789abcdef" for character in expected_head)
        ):
            raise AdapterActionError("Action Grant commit is invalid")
        if datetime.now(UTC) >= execute_before:
            raise AdapterActionError("Action Grant execution window expired")
        if self._text(root, "symbolic-ref", "-q", "HEAD") != branch_ref:
            raise AdapterActionError("Git branch no longer matches Approval scope")
        if self._text(root, "rev-parse", "--verify", "HEAD^{commit}") != expected_head:
            raise AdapterActionError("Git HEAD no longer matches Action Grant")

    def _text(self, root: Path, *arguments: str, environment: dict[str, str] | None = None) -> str:
        value = self._run(root, *arguments, environment=environment).decode("utf-8").strip()
        if not value:
            raise AdapterActionError("Git Provider returned an empty result")
        return value

    def _returncode(self, root: Path, *arguments: str) -> int:
        completed = self._completed(root, *arguments)
        return completed.returncode

    def _run(
        self,
        root: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> bytes:
        completed = self._completed(
            root, *arguments, environment=environment, input_bytes=input_bytes
        )
        if completed.returncode != 0:
            raise AdapterActionError("Git Provider command failed")
        return completed.stdout

    def _completed(
        self,
        root: Path,
        *arguments: str,
        environment: dict[str, str] | None = None,
        input_bytes: bytes | None = None,
    ) -> subprocess.CompletedProcess[bytes]:
        process_environment = os.environ.copy()
        for key in tuple(process_environment):
            if key.upper().startswith("GIT_"):
                process_environment.pop(key, None)
        process_environment.pop("TAS_ADAPTER_CONFIG", None)
        process_environment.update(environment or {})
        try:
            completed = subprocess.run(
                ["git", "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null", *arguments],
                cwd=root, input=b"" if input_bytes is None else input_bytes,
                capture_output=True,
                timeout=self.timeout_seconds, check=False, shell=False,
                env=process_environment,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AdapterActionError("Git Provider command unavailable") from error
        if len(completed.stdout) > self.max_output_bytes or len(completed.stderr) > self.max_output_bytes:
            raise AdapterActionError("Git Provider output exceeds limit")
        return completed

    @staticmethod
    def _operation_ref(operation_id: str) -> str:
        digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return f"refs/tas/operations/{digest}"

    @staticmethod
    def _attempt_ref(operation_id: str) -> str:
        digest = hashlib.sha256(operation_id.encode("utf-8")).hexdigest()
        return f"refs/tas/attempts/{digest}"

    @staticmethod
    def _validate_operation(operation_id: str, request_fingerprint: str) -> None:
        if (
            not isinstance(operation_id, str)
            or not 1 <= len(operation_id) <= 255
            or not operation_id[0].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character in "._:-"))
                for character in operation_id
            )
            or not isinstance(request_fingerprint, str)
            or len(request_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in request_fingerprint)
        ):
            raise AdapterActionError("Git Provider operation identity is invalid")

    @staticmethod
    def _trailers(message: str) -> dict[str, str]:
        trailers: dict[str, str] = {}
        for line in message.splitlines():
            match = re.fullmatch(r"(TAS-(?:Operation-ID|Request-Fingerprint)): (.+)", line)
            if match:
                if match.group(1) in trailers:
                    raise AdapterActionError("Git Provider Receipt trailers are ambiguous")
                trailers[match.group(1)] = match.group(2)
        return trailers


class AdapterActionService:
    def __init__(
        self,
        *,
        client: ActionRemoteClient,
        workspaces: LocalWorkspaceStore,
        evidence: AdapterEvidenceService,
        actor_id: str,
        provider: GitCommitProvider | None = None,
    ) -> None:
        self.client = client
        self.workspaces = workspaces
        self.evidence = evidence
        self.actor_id = actor_id
        self.provider = provider or GitCommitProvider()
        self.collector = GitEvidenceCollector()

    def execute_git_commit(
        self,
        *,
        approval_id: str,
        workspace_id: str,
        evidence_id: str,
        idempotency_key: str,
    ) -> ExecutedAction:
        mapping = self._mapping(workspace_id)
        approval = self.client.get_approval(approval_id)
        self._verify_approval(approval, mapping)
        grant = self._get_grant(approval_id)
        if grant is None:
            expected_head = self._snapshot_head(evidence_id)
            self._verify_snapshot(mapping, evidence_id)
            self.provider.check_ready(
                Path(mapping.root), branch_ref=approval.scope,
                expected_head=expected_head,
                execute_before=approval.expires_at,
            )
            grant = self.client.prepare_action_grant(
                approval_id=approval_id,
                workspace_id=workspace_id,
                evidence_id=evidence_id,
                idempotency_key=self._key(idempotency_key, "prepare"),
            )
            self._verify_grant(
                grant, approval_id, workspace_id, evidence_id,
                expected_head, approval.expires_at,
            )
        else:
            self._verify_grant(
                grant, approval_id, workspace_id, evidence_id,
                None, approval.expires_at,
            )
        if grant.status is RemoteActionGrantStatus.COMPLETED:
            return self._result(grant)

        receipt = self.provider.find_receipt(
            Path(mapping.root), grant.operation_id, grant.request_fingerprint
        )
        if receipt is not None:
            return self._submit_receipt(grant, receipt, idempotency_key)
        if grant.status is RemoteActionGrantStatus.RESULT_UNKNOWN:
            return self._result(grant)

        expected_head = self._snapshot_head(evidence_id)
        if grant.commit_sha != expected_head:
            raise AdapterActionError("Central Action Grant differs from local Evidence")
        self._verify_snapshot(mapping, evidence_id)
        try:
            receipt = self.provider.execute_once(
                Path(mapping.root), branch_ref=approval.scope,
                expected_head=grant.commit_sha, operation_id=grant.operation_id,
                request_fingerprint=grant.request_fingerprint,
                execute_before=grant.execute_before,
            )
        except AdapterActionError as error:
            try:
                recovered = self.provider.find_receipt(
                    Path(mapping.root), grant.operation_id, grant.request_fingerprint
                )
            except AdapterActionError:
                recovered = None
            if recovered is not None:
                return self._submit_receipt(grant, recovered, idempotency_key)
            try:
                unknown = self.client.mark_action_result_unknown(
                    approval_id=approval_id,
                    request_fingerprint=grant.request_fingerprint,
                    idempotency_key=self._key(idempotency_key, "unknown"),
                )
            except AdapterClientError as marker_error:
                raise AdapterActionResultUnknownError(
                    "Provider result is unknown and central marker must be retried"
                ) from marker_error
            self._verify_grant(
                unknown, approval_id, workspace_id, evidence_id,
                grant.commit_sha, approval.expires_at,
            )
            raise AdapterActionResultUnknownError(
                "Provider result is unknown; reconcile without re-executing"
            ) from error
        return self._submit_receipt(grant, receipt, idempotency_key)

    def _get_grant(self, approval_id: str) -> RemoteActionGrant | None:
        try:
            return self.client.get_action_grant(approval_id)
        except RemoteAPIError as error:
            if error.status_code == 404:
                return None
            raise

    def _submit_receipt(
        self, grant: RemoteActionGrant, receipt: RemoteActionReceipt, root_key: str
    ) -> ExecutedAction:
        try:
            completed = self.client.submit_action_receipt(
                approval_id=grant.approval_id,
                request_fingerprint=receipt.request_fingerprint,
                external_action_id=receipt.external_action_id,
                result_reference=receipt.result_reference,
                occurred_at=receipt.occurred_at,
                idempotency_key=self._key(root_key, "receipt"),
            )
        except AdapterClientError as error:
            raise AdapterActionResultUnknownError(
                "Provider Receipt is known; retry only Receipt submission"
            ) from error
        if (
            completed.request_fingerprint != grant.request_fingerprint
            or completed.commit_sha != grant.commit_sha
            or completed.execute_before != grant.execute_before
            or completed.receipt != receipt
        ):
            raise AdapterActionError("Central Receipt response differs from Provider Receipt")
        self._verify_grant(
            completed, grant.approval_id, grant.workspace_id, grant.evidence_id,
            grant.commit_sha, grant.execute_before,
        )
        if completed.status is not RemoteActionGrantStatus.COMPLETED:
            raise AdapterActionError("Central service did not complete the known Receipt")
        return self._result(completed)

    def _mapping(self, workspace_id: str) -> LocalWorkspace:
        try:
            mapping = self.workspaces.get(workspace_id)
        except LocalWorkspaceError as error:
            raise AdapterActionError(str(error)) from error
        if mapping.agent_id != self.actor_id:
            raise AdapterActionError("Workspace belongs to another Agent")
        return mapping

    def _verify_approval(self, approval: RemoteApproval, mapping: LocalWorkspace) -> None:
        if (
            approval.status != "approved"
            or approval.receiving_agent_id != self.actor_id
            or approval.task_id != mapping.task_id
            or approval.repository != mapping.repository
            or approval.action != "commit"
            or not approval.scope.startswith("refs/heads/")
        ):
            raise AdapterActionError("Approval does not authorize this Git commit")

    def _verify_snapshot(self, mapping: LocalWorkspace, evidence_id: str) -> None:
        try:
            snapshot = self.evidence.git_index.get(evidence_id)
            payload = json.loads(str(snapshot["payload_json"]))
            baseline = str(payload["baseline_commit"])
            observed = self.collector.collect(
                mapping.root, repository=mapping.repository, baseline=baseline,
                actor_id=AgentId(self.actor_id), task_id=TaskId(mapping.task_id),
            )
            current = AdapterEvidenceService._git_snapshot(mapping, observed)
        except (AdapterEvidenceError, GitEvidenceCollectionError, KeyError, TypeError, ValueError) as error:
            raise AdapterActionError("Git Evidence cannot be revalidated locally") from error
        if (
            snapshot.get("kind") != "git"
            or snapshot.get("workspace_id") != mapping.workspace_id
            or snapshot.get("task_id") != mapping.task_id
            or current["payload_json"] != snapshot["payload_json"]
            or current["head_commit"] != snapshot["head_commit"]
        ):
            raise AdapterActionError("Workspace changed after Git Evidence")

    @staticmethod
    def _verify_grant(
        grant: RemoteActionGrant,
        approval_id: str,
        workspace_id: str,
        evidence_id: str,
        expected_head: str | None,
        approval_expires_at: datetime,
    ) -> None:
        if (
            grant.approval_id != approval_id
            or grant.operation_id != approval_id
            or grant.workspace_id != workspace_id
            or grant.evidence_id != evidence_id
            or (expected_head is not None and grant.commit_sha != expected_head)
            or grant.execute_before > approval_expires_at
        ):
            raise AdapterActionError("Central Action Grant differs from the request")

    def _snapshot_head(self, evidence_id: str) -> str:
        try:
            value = self.evidence.git_index.get(evidence_id).get("head_commit")
        except AdapterEvidenceError as error:
            raise AdapterActionError("Git Evidence is unavailable locally") from error
        if (
            not isinstance(value, str)
            or len(value) not in (40, 64)
            or any(character not in "0123456789abcdef" for character in value)
        ):
            raise AdapterActionError("Git Evidence head is invalid")
        return value

    @staticmethod
    def _result(grant: RemoteActionGrant) -> ExecutedAction:
        receipt = grant.receipt
        return ExecutedAction(
            grant.approval_id, grant.operation_id, grant.status.value,
            None if receipt is None else receipt.external_action_id,
            None if receipt is None else receipt.result_reference,
            grant.replayed, grant.correlation_id,
        )

    @staticmethod
    def _key(root: str, phase: str) -> str:
        return "tas:" + hashlib.sha256(f"{root}\0{phase}".encode()).hexdigest()
