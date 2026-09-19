"""Evaluate version-scoped Memory against a controlled Git worktree."""

from __future__ import annotations

import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from tas.domain.memory import (
    ApplicabilityReason,
    ApplicabilityStatus,
    MemoryApplicabilityAssessment,
    MemoryCodeScope,
)


class GitMemoryApplicabilityEvaluator:
    def __init__(self, *, timeout_seconds: float = 10.0, max_output_bytes: int = 1024 * 1024) -> None:
        if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool) or max_output_bytes <= 0:
            raise ValueError("max_output_bytes must be positive")
        self.timeout_seconds = float(timeout_seconds)
        self.max_output_bytes = max_output_bytes

    def evaluate(
        self,
        scope: MemoryCodeScope,
        workspace: str | Path,
        *,
        repository: str,
        sequence: int = 1,
        previous_assessment_id: str | None = None,
        checked_at: datetime | None = None,
    ) -> MemoryApplicabilityAssessment:
        now = datetime.now(UTC) if checked_at is None else checked_at
        if repository != scope.repository:
            return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.REPOSITORY_MISMATCH, None, (), now)
        try:
            requested = Path(workspace).resolve(strict=True)
            root = Path(self._text(requested, "rev-parse", "--show-toplevel")).resolve(strict=True)
            if requested != root:
                return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.INVALID_WORKTREE, None, (), now)
            branch_result = self._run(root, "symbolic-ref", "--short", "-q", "HEAD", allowed_returncodes=(0, 1))
            branch = branch_result[1].decode("utf-8").strip() or None
            head = self._text(root, "rev-parse", "--verify", "HEAD^{commit}")
            if branch != scope.ref:
                return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.REF_MISMATCH, head, (), now)
            exists = self._run(root, "cat-file", "-e", f"{scope.commit}^{{commit}}", allowed_returncodes=(0, 1, 128))[0]
            if exists != 0:
                return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.MEMORY_COMMIT_MISSING, head, (), now)
            committed: tuple[str, ...] = ()
            if head != scope.commit:
                ancestor = self._run(root, "merge-base", "--is-ancestor", scope.commit, head, allowed_returncodes=(0, 1))[0]
                if ancestor != 0:
                    return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.MEMORY_COMMIT_NOT_ANCESTOR, head, (), now)
                output = self._run(root, "diff", "--no-renames", "--name-only", "-z", scope.commit, head, "--", *scope.paths)[1]
                committed = tuple(path.decode("utf-8") for path in filter(None, output.split(b"\0")))
            working = self._working_changes(root, scope.paths)
            changed = tuple(sorted(set(committed + working)))
            head_after = self._text(root, "rev-parse", "--verify", "HEAD^{commit}")
            branch_after_result = self._run(root, "symbolic-ref", "--short", "-q", "HEAD", allowed_returncodes=(0, 1))
            branch_after = branch_after_result[1].decode("utf-8").strip() or None
            working_after = self._working_changes(root, scope.paths)
            if head_after != head or branch_after != branch or working_after != working:
                return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.WORKTREE_CHANGED_DURING_CHECK, head_after, (), now)
            if changed:
                status, reason = ApplicabilityStatus.POSSIBLY_STALE, ApplicabilityReason.SCOPED_PATHS_CHANGED
            elif head == scope.commit:
                status, reason = ApplicabilityStatus.EXACT, ApplicabilityReason.EXACT_COMMIT
            else:
                status, reason = ApplicabilityStatus.COMPATIBLE, ApplicabilityReason.SCOPED_PATHS_UNCHANGED
            return self._result(scope, sequence, previous_assessment_id, status, reason, head, changed, now)
        except (OSError, RuntimeError, UnicodeDecodeError):
            return self._result(scope, sequence, previous_assessment_id, ApplicabilityStatus.UNKNOWN, ApplicabilityReason.GIT_CHECK_FAILED, None, (), now)

    @staticmethod
    def _result(scope, sequence, previous, status, reason, current, changed, checked_at):
        return MemoryApplicabilityAssessment(str(uuid4()), scope.memory_id, sequence, previous, status, reason, scope.commit, current, changed, checked_at)

    def _text(self, root: Path, *arguments: str) -> str:
        value = self._run(root, *arguments)[1].decode("utf-8").strip()
        if not value:
            raise RuntimeError("Git returned an empty required value")
        return value

    def _working_changes(self, root: Path, paths: tuple[str, ...]) -> tuple[str, ...]:
        tracked = self._run(root, "diff", "--no-renames", "--name-only", "-z", "HEAD", "--", *paths)[1]
        untracked = self._run(root, "ls-files", "--others", "--exclude-standard", "-z", "--", *paths)[1]
        return tuple(sorted(path.decode("utf-8") for path in set(filter(None, (tracked + untracked).split(b"\0")))))

    def _run(self, root: Path, *arguments: str, allowed_returncodes: tuple[int, ...] = (0,)) -> tuple[int, bytes]:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
            try:
                completed = subprocess.run(
                    ["git", "-c", "core.quotepath=false", *arguments], cwd=root,
                    stdin=subprocess.DEVNULL, stdout=output, stderr=error,
                    timeout=self.timeout_seconds, check=False, shell=False,
                )
            except (subprocess.TimeoutExpired, OSError) as exception:
                raise RuntimeError("Git command failed") from exception
            if output.tell() > self.max_output_bytes or error.tell() > self.max_output_bytes:
                raise RuntimeError("Git command output exceeds configured limit")
            output.seek(0); error.seek(0)
            stdout, stderr = output.read(), error.read()
        if completed.returncode not in allowed_returncodes:
            raise RuntimeError(f"Git command failed with exit code {completed.returncode}: {stderr[:200]!r}")
        return completed.returncode, stdout
