"""Owner-local immutable mapping from opaque Workspace IDs to Git roots."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterator
from uuid import uuid4


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_MAX_STORE_BYTES = 1024 * 1024
_MAX_MAPPINGS = 1000


class LocalWorkspaceError(RuntimeError):
    """A local Workspace mapping cannot be trusted or persisted safely."""


@dataclass(frozen=True, slots=True)
class LocalWorkspace:
    workspace_id: str
    task_id: str
    agent_id: str
    repository: str
    root: str


class LocalWorkspaceStore:
    """Small locked JSON store; absolute roots never leave this boundary."""

    def __init__(self, state_directory: str | Path, *, lock_timeout: float = 5) -> None:
        requested = Path(state_directory)
        if not requested.is_absolute():
            raise LocalWorkspaceError("Adapter state directory must be absolute")
        try:
            requested.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self._is_link(requested):
                raise LocalWorkspaceError("Adapter state directory cannot use links")
            resolved = requested.resolve(strict=True)
            if requested.absolute() != resolved:
                raise LocalWorkspaceError("Adapter state directory cannot use links")
            os.chmod(resolved, 0o700)
        except LocalWorkspaceError:
            raise
        except OSError as error:
            raise LocalWorkspaceError("Adapter state directory is unavailable") from error
        if not resolved.is_dir():
            raise LocalWorkspaceError("Adapter state path must be a directory")
        if not isinstance(lock_timeout, (int, float)) or isinstance(lock_timeout, bool) or lock_timeout <= 0:
            raise ValueError("lock_timeout must be positive")
        self.root = resolved
        self.path = resolved / "workspace-mappings.json"
        self.lock_path = resolved / ".workspace-mappings.lock"
        self.lock_timeout = float(lock_timeout)

    def bind(
        self,
        *,
        workspace_id: str,
        task_id: str,
        agent_id: str,
        repository: str,
        workspace_root: str | Path,
    ) -> LocalWorkspace:
        self._identifier(workspace_id, "workspace_id")
        self._identifier(task_id, "task_id")
        self._identifier(agent_id, "agent_id")
        if not isinstance(repository, str) or not repository.strip() or len(repository) > 255:
            raise LocalWorkspaceError("repository must be 1..255 non-whitespace characters")
        root = self._canonical_git_root(workspace_root)
        candidate = LocalWorkspace(
            workspace_id, task_id, agent_id, repository, str(root)
        )
        with self._lock():
            mappings = self._read()
            existing = mappings.get(workspace_id)
            if existing is not None:
                if existing != candidate:
                    raise LocalWorkspaceError(
                        "Workspace ID is already bound to different local state"
                    )
                return existing
            if any(item.task_id == task_id for item in mappings.values()):
                raise LocalWorkspaceError(
                    "Task already has a different local Workspace mapping"
                )
            if len(mappings) >= _MAX_MAPPINGS:
                raise LocalWorkspaceError("Workspace mapping limit is reached")
            mappings[workspace_id] = candidate
            self._write(mappings)
        return candidate

    def validate_root(self, workspace_root: str | Path) -> Path:
        return self._canonical_git_root(workspace_root)

    def get(self, workspace_id: str) -> LocalWorkspace:
        self._identifier(workspace_id, "workspace_id")
        with self._lock():
            mapping = self._read().get(workspace_id)
        if mapping is None:
            raise LocalWorkspaceError("Workspace is not mapped on this Adapter")
        current = self._canonical_git_root(mapping.root)
        if str(current) != mapping.root:
            raise LocalWorkspaceError(
                "Workspace root moved; register a new Workspace and Task"
            )
        return mapping

    @contextmanager
    def _lock(self) -> Iterator[None]:
        if self.lock_path.exists() and self._is_link(self.lock_path):
            raise LocalWorkspaceError("Workspace mapping lock is unsafe")
        try:
            handle = self.lock_path.open("a+b")
            os.chmod(self.lock_path, 0o600)
        except OSError as error:
            raise LocalWorkspaceError("Workspace mapping lock is unavailable") from error
        try:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"0")
                handle.flush()
            deadline = time.monotonic() + self.lock_timeout
            while True:
                try:
                    self._lock_handle(handle)
                    break
                except OSError as error:
                    if time.monotonic() >= deadline:
                        raise LocalWorkspaceError(
                            "Workspace mapping lock timed out"
                        ) from error
                    time.sleep(0.05)
            try:
                yield
            finally:
                self._unlock_handle(handle)
        finally:
            handle.close()

    @staticmethod
    def _lock_handle(handle) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    @staticmethod
    def _unlock_handle(handle) -> None:
        handle.seek(0)
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read(self) -> dict[str, LocalWorkspace]:
        if not self.path.exists():
            return {}
        try:
            if self._is_link(self.path) or not self.path.is_file():
                raise LocalWorkspaceError("Workspace mapping file is unsafe")
            if self.path.stat().st_size > _MAX_STORE_BYTES:
                raise LocalWorkspaceError("Workspace mapping file is too large")
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except LocalWorkspaceError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            raise LocalWorkspaceError("Workspace mapping file cannot be read") from error
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schemaVersion", "mappings"}
            or type(raw.get("schemaVersion")) is not int
            or raw.get("schemaVersion") != 1
            or not isinstance(raw.get("mappings"), list)
            or len(raw["mappings"]) > _MAX_MAPPINGS
        ):
            raise LocalWorkspaceError("Workspace mapping file is invalid")
        mappings: dict[str, LocalWorkspace] = {}
        try:
            for value in raw["mappings"]:
                if not isinstance(value, dict) or set(value) != {
                    "workspace_id", "task_id", "agent_id", "repository", "root"
                }:
                    raise ValueError
                mapping = LocalWorkspace(**value)
                self._identifier(mapping.workspace_id, "workspace_id")
                self._identifier(mapping.task_id, "task_id")
                self._identifier(mapping.agent_id, "agent_id")
                if (
                    not mapping.repository.strip()
                    or len(mapping.repository) > 255
                    or not Path(mapping.root).is_absolute()
                    or mapping.workspace_id in mappings
                ):
                    raise ValueError
                mappings[mapping.workspace_id] = mapping
        except (TypeError, ValueError, LocalWorkspaceError) as error:
            raise LocalWorkspaceError("Workspace mapping file is invalid") from error
        if len({item.task_id for item in mappings.values()}) != len(mappings):
            raise LocalWorkspaceError("Workspace mapping file contains duplicate Tasks")
        return mappings

    def _write(self, mappings: dict[str, LocalWorkspace]) -> None:
        payload = json.dumps(
            {
                "schemaVersion": 1,
                "mappings": [
                    asdict(mappings[key]) for key in sorted(mappings)
                ],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ) + "\n"
        temporary = self.path.with_name(f"{self.path.name}.{uuid4().hex}.tmp")
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as stream:
                os.chmod(temporary, 0o600)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            os.chmod(self.path, 0o600)
        except OSError as error:
            raise LocalWorkspaceError("Workspace mapping file cannot be persisted") from error
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _canonical_git_root(workspace_root: str | Path) -> Path:
        try:
            requested = Path(workspace_root).resolve(strict=True)
            environment = os.environ.copy()
            for key in tuple(environment):
                if key.upper().startswith("GIT_"):
                    environment.pop(key, None)
            result = subprocess.run(
                ["git", "-c", "core.quotepath=false", "rev-parse", "--show-toplevel"],
                cwd=requested,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=10,
                shell=False,
                env=environment,
            )
            if result.returncode != 0 or len(result.stdout) > 4096:
                raise LocalWorkspaceError("Workspace must be an accessible Git root")
            actual = Path(result.stdout.decode("utf-8").strip()).resolve(strict=True)
        except LocalWorkspaceError:
            raise
        except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            raise LocalWorkspaceError("Workspace must be an accessible Git root") from error
        if requested != actual or not requested.is_dir():
            raise LocalWorkspaceError("Workspace must be the exact Git worktree root")
        return actual

    @staticmethod
    def _identifier(value: str, field: str) -> None:
        if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
            raise LocalWorkspaceError(f"{field} is invalid")

    @staticmethod
    def _is_link(path: Path) -> bool:
        return path.is_symlink() or (
            hasattr(path, "is_junction") and path.is_junction()
        )
