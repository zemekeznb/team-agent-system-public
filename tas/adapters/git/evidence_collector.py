"""Collect hash-only Git facts without trusting Agent statements."""

from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tas.domain.collaboration import TaskId
from tas.domain.evidence import (
    EvidenceId,
    FileEvidenceKind,
    GitEvidence,
    GitEvidenceVerification,
    GitFileEvidence,
)
from tas.domain.identity import AgentId


class GitEvidenceCollectionError(RuntimeError):
    """Git facts could not be collected within the configured trust boundary."""


class GitEvidenceCollector:
    def __init__(
        self,
        *,
        timeout_seconds: float = 10.0,
        max_command_output_bytes: int = 1024 * 1024,
        max_diff_bytes: int = 64 * 1024 * 1024,
        max_changed_paths: int = 10_000,
        max_file_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        for value, field in (
            (timeout_seconds, "timeout_seconds"),
            (max_command_output_bytes, "max_command_output_bytes"),
            (max_diff_bytes, "max_diff_bytes"),
            (max_changed_paths, "max_changed_paths"),
            (max_file_bytes, "max_file_bytes"),
        ):
            if not isinstance(value, (int, float)) or value <= 0:
                raise ValueError(f"{field} must be positive")
        self.timeout_seconds = float(timeout_seconds)
        self.max_command_output_bytes = int(max_command_output_bytes)
        self.max_diff_bytes = int(max_diff_bytes)
        self.max_changed_paths = int(max_changed_paths)
        self.max_file_bytes = int(max_file_bytes)

    def collect(
        self,
        workspace: str | Path,
        *,
        repository: str,
        baseline: str,
        actor_id: AgentId,
        task_id: TaskId,
    ) -> GitEvidence:
        if (
            not isinstance(repository, str)
            or not repository.strip()
            or len(repository) > 255
        ):
            raise GitEvidenceCollectionError("repository must be 1..255 characters")
        if (
            not isinstance(baseline, str)
            or not baseline.strip()
            or len(baseline) > 255
            or "\0" in baseline
        ):
            raise GitEvidenceCollectionError("baseline must be a safe non-empty revision")
        if not isinstance(actor_id, AgentId) or not isinstance(task_id, TaskId):
            raise GitEvidenceCollectionError("actor_id and task_id must use domain IDs")
        requested_root = Path(workspace).resolve(strict=True)
        actual_root = Path(
            self._text(requested_root, "rev-parse", "--show-toplevel")
        ).resolve(strict=True)
        if actual_root != requested_root:
            raise GitEvidenceCollectionError(
                "workspace must be the exact Git worktree root"
            )
        head = self._text(actual_root, "rev-parse", "--verify", "HEAD^{commit}")
        baseline_commit = self._text(
            actual_root,
            "rev-parse",
            "--verify",
            "--end-of-options",
            f"{baseline}^{{commit}}",
        )
        ancestor = self._run(
            actual_root,
            "merge-base",
            "--is-ancestor",
            baseline_commit,
            head,
            allowed_returncodes=(0, 1),
        )
        if ancestor[0] != 0:
            raise GitEvidenceCollectionError("baseline must be an ancestor of HEAD")
        branch_result = self._run(
            actual_root,
            "symbolic-ref",
            "--short",
            "-q",
            "HEAD",
            allowed_returncodes=(0, 1),
        )
        branch = branch_result[1].decode("utf-8").strip() or None
        first_snapshot = self._snapshot(actual_root, baseline_commit)
        second_snapshot = self._snapshot(actual_root, baseline_commit)
        head_after = self._text(actual_root, "rev-parse", "--verify", "HEAD^{commit}")
        branch_after_result = self._run(
            actual_root,
            "symbolic-ref",
            "--short",
            "-q",
            "HEAD",
            allowed_returncodes=(0, 1),
        )
        branch_after = branch_after_result[1].decode("utf-8").strip() or None
        if first_snapshot != second_snapshot or head_after != head or branch_after != branch:
            raise GitEvidenceCollectionError("worktree changed during Evidence collection")
        files, diff_sha256, diff_size = second_snapshot
        git_version = self._text(actual_root, "--version")
        return GitEvidence(
            EvidenceId(str(uuid4())),
            actor_id,
            task_id,
            repository,
            str(actual_root),
            baseline_commit,
            head,
            branch,
            diff_sha256,
            diff_size,
            files,
            datetime.now(UTC),
            git_version,
        )

    def verify(self, evidence: GitEvidence) -> GitEvidenceVerification:
        current = self.collect(
            evidence.worktree_root,
            repository=evidence.repository,
            baseline=evidence.baseline_commit,
            actor_id=evidence.actor_id,
            task_id=evidence.task_id,
        )
        fields = (
            "repository",
            "worktree_root",
            "baseline_commit",
            "head_commit",
            "branch",
            "diff_sha256",
            "diff_size",
            "files",
            "git_version",
        )
        mismatches = tuple(
            field for field in fields if getattr(evidence, field) != getattr(current, field)
        )
        return GitEvidenceVerification(not mismatches, mismatches)

    def _changed_paths(self, root: Path, baseline: str) -> list[str]:
        tracked = self._run(
            root, "diff", "--no-renames", "--name-only", "-z", baseline, "--"
        )[1]
        untracked = self._run(
            root, "ls-files", "--others", "--exclude-standard", "-z"
        )[1]
        raw_paths = set(filter(None, (tracked + untracked).split(b"\0")))
        if len(raw_paths) > self.max_changed_paths:
            raise GitEvidenceCollectionError("changed path count exceeds configured limit")
        try:
            paths = sorted(path.decode("utf-8") for path in raw_paths)
        except UnicodeDecodeError as error:
            raise GitEvidenceCollectionError(
                "changed paths must use UTF-8 for F2 Evidence"
            ) from error
        for path in paths:
            candidate = Path(path)
            if candidate.is_absolute() or ".." in candidate.parts:
                raise GitEvidenceCollectionError("Git returned an unsafe changed path")
            resolved_parent = (root / candidate).parent.resolve(strict=False)
            if not resolved_parent.is_relative_to(root):
                raise GitEvidenceCollectionError("changed path escapes worktree root")
        return [Path(path).as_posix() for path in paths]

    def _snapshot(
        self, root: Path, baseline: str
    ) -> tuple[tuple[GitFileEvidence, ...], str, int]:
        changed = self._changed_paths(root, baseline)
        files = tuple(self._file_evidence(root, path) for path in changed)
        diff_sha256, diff_size = self._diff_hash(root, baseline)
        return files, diff_sha256, diff_size

    def _file_evidence(self, root: Path, relative: str) -> GitFileEvidence:
        path = root / Path(relative)
        if path.is_symlink():
            target = os.readlink(path).encode("utf-8")
            return GitFileEvidence(
                relative,
                FileEvidenceKind.SYMLINK,
                hashlib.sha256(target).hexdigest(),
                len(target),
            )
        if not path.exists():
            return GitFileEvidence(relative, FileEvidenceKind.DELETED, None, None)
        if path.is_dir():
            index_entry = self._run(
                root, "ls-files", "--stage", "-z", "--", relative
            )[1]
            if not index_entry.startswith(b"160000 "):
                raise GitEvidenceCollectionError(
                    "changed path is a directory but not a Gitlink"
                )
            object_id = self._text(root, "rev-parse", f"HEAD:{relative}")
            payload = object_id.encode("ascii")
            return GitFileEvidence(
                relative,
                FileEvidenceKind.GITLINK,
                hashlib.sha256(payload).hexdigest(),
                len(payload),
            )
        size = path.stat().st_size
        if size > self.max_file_bytes:
            raise GitEvidenceCollectionError("changed file exceeds configured hash limit")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return GitFileEvidence(relative, FileEvidenceKind.FILE, digest.hexdigest(), size)

    def _diff_hash(self, root: Path, baseline: str) -> tuple[str, int]:
        _, output = self._run(
            root,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--full-index",
            baseline,
            "--",
            max_bytes=self.max_diff_bytes,
        )
        return hashlib.sha256(output).hexdigest(), len(output)

    def _text(self, root: Path, *arguments: str) -> str:
        value = self._run(root, *arguments)[1].decode("utf-8").strip()
        if not value:
            raise GitEvidenceCollectionError("Git returned an empty required value")
        return value

    def _run(
        self,
        root: Path,
        *arguments: str,
        allowed_returncodes: tuple[int, ...] = (0,),
        max_bytes: int | None = None,
    ) -> tuple[int, bytes]:
        limit = self.max_command_output_bytes if max_bytes is None else max_bytes
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.upper().startswith("GIT_"):
                environment.pop(key, None)
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            try:
                completed = subprocess.run(
                    ["git", "-c", "core.quotepath=false", *arguments],
                    cwd=root,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=error,
                    timeout=self.timeout_seconds,
                    check=False,
                    shell=False,
                    env=environment,
                )
            except subprocess.TimeoutExpired as exception:
                raise GitEvidenceCollectionError("Git command timed out") from exception
            except OSError as exception:
                raise GitEvidenceCollectionError("Git command could not be started") from exception
            output_size = output.tell()
            error_size = error.tell()
            if output_size > limit or error_size > self.max_command_output_bytes:
                raise GitEvidenceCollectionError("Git command output exceeds configured limit")
            output.seek(0)
            error.seek(0)
            stdout, stderr = output.read(), error.read()
        if completed.returncode not in allowed_returncodes:
            summary = stderr.decode("utf-8", errors="replace")[:200].strip()
            raise GitEvidenceCollectionError(
                f"Git command failed with exit code {completed.returncode}: {summary}"
            )
        return completed.returncode, stdout
