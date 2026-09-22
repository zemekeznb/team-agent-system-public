"""SQLite metadata transaction and controlled local-volume Artifact ingestion."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.artifact_uploads import (
    MAX_TASK_ARTIFACT_BYTES,
    ArtifactCommandResult,
    ArtifactPurpose,
    ArtifactUpload,
    ArtifactUploadStatus,
    ReserveArtifactCommand,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class ArtifactUploadAccessError(PermissionError):
    """The Artifact or target Task is unavailable to this Agent."""


class ArtifactUploadConflictError(RuntimeError):
    """The request conflicts with current Artifact state or declared integrity."""


class ArtifactUploadIntegrityError(RuntimeError):
    """Committed Artifact metadata and controlled body cannot be reconstructed."""


class SQLiteArtifactUploadUnitOfWork:
    def __init__(self, database: str | Path, artifact_root: str | Path) -> None:
        self.database = Path(database)
        requested_root = Path(artifact_root)
        if requested_root.is_symlink():
            raise ArtifactUploadIntegrityError("Artifact storage root is unsafe")
        self.artifact_root = requested_root.resolve(strict=False)
        self.staging_root = self.artifact_root / ".staging"
        self.quarantine_root = self.artifact_root / "quarantine"
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        if self.artifact_root.is_symlink() or any(
            path.is_symlink() for path in (self.staging_root, self.quarantine_root)
        ):
            raise ArtifactUploadIntegrityError("Artifact storage root is unsafe")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def reserve(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ReserveArtifactCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload(
            {
                "task_id": command.task_id.value,
                "media_type": command.media_type,
                "declared_size": command.declared_size,
                "declared_sha256": command.declared_sha256,
                "purpose": command.purpose.value,
            }
        ).value
        rejection: tuple[str, str, str] | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if not self._actor_can_write_task(
                    connection, actor_id.value, command.task_id.value
                ):
                    rejection = ("task", command.task_id.value, "artifact_task_unavailable")
                    raise ArtifactUploadAccessError("Artifact Task is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, "artifact.reserve", key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = (
                        "task", command.task_id.value,
                        "artifact_idempotency_conflict",
                    )
                    raise
                if replay is not None:
                    artifact = self._authorized_artifact(
                        connection, actor_id.value, replay
                    )
                    if artifact is None:
                        raise ArtifactUploadIntegrityError(
                            "Artifact reservation result is unavailable"
                        )
                    connection.execute("COMMIT")
                    return ArtifactCommandResult(artifact, replayed=True)
                totals = connection.execute(
                    "SELECT count(*),COALESCE(sum(declared_size),0) "
                    "FROM tas_artifact_uploads WHERE task_id=?",
                    (command.task_id.value,),
                ).fetchone()
                if int(totals[0]) >= 1000 or int(totals[1]) + command.declared_size > MAX_TASK_ARTIFACT_BYTES:
                    rejection = ("task", command.task_id.value, "artifact_quota_exceeded")
                    raise ArtifactUploadConflictError("Artifact Task quota is exceeded")
                artifact_id = ArtifactId(str(uuid4()))
                connection.execute(
                    "INSERT INTO tas_artifact_uploads(id,task_id,producer_agent_id,"
                    "media_type,purpose,declared_size,declared_sha256,status,created_at) "
                    "VALUES (?,?,?,?,?,?,?,'reserved',?)",
                    (
                        artifact_id.value,
                        command.task_id.value,
                        actor_id.value,
                        command.media_type,
                        command.purpose.value,
                        command.declared_size,
                        command.declared_sha256,
                        now.isoformat(),
                    ),
                )
                self._complete_ledger(
                    connection,
                    actor_id,
                    "artifact.reserve",
                    key,
                    fingerprint,
                    artifact_id,
                    now,
                )
                artifact = self._authorized_artifact(
                    connection, actor_id.value, artifact_id.value
                )
                if artifact is None:
                    raise ArtifactUploadIntegrityError(
                        "Artifact reservation could not be restored"
                    )
                connection.execute("COMMIT")
                return ArtifactCommandResult(artifact, replayed=False)
        except (
            ArtifactUploadAccessError,
            ArtifactUploadConflictError,
            IdempotencyConflictError,
        ):
            if rejection is not None:
                self._audit_rejection(actor_id, *rejection, now, correlation_id)
            raise

    def upload(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        staged_path: Path,
        actual_size: int,
        actual_sha256: str,
        content_sha256: str,
        media_type: str,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult:
        self._require_utc(now)
        staged = staged_path.resolve(strict=True)
        if staged.parent != self.staging_root or staged.is_symlink() or not staged.is_file():
            raise ArtifactUploadIntegrityError("Staged Artifact is unsafe")
        fingerprint = fingerprint_payload(
            {
                "artifact_id": artifact_id.value,
                "actual_size": actual_size,
                "actual_sha256": actual_sha256,
                "content_sha256": content_sha256,
                "media_type": media_type,
            }
        ).value
        rejection: str | None = None
        created_body = False
        final_path = self._body_path(artifact_id)
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                artifact = self._authorized_artifact(
                    connection, actor_id.value, artifact_id.value
                )
                if artifact is None:
                    rejection = "artifact_unavailable"
                    raise ArtifactUploadAccessError("Artifact is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, "artifact.upload", key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = "artifact_idempotency_conflict"
                    raise
                if replay is not None:
                    replayed = self._authorized_artifact(
                        connection, actor_id.value, replay
                    )
                    if replayed is None or replayed.id != artifact.id:
                        raise ArtifactUploadIntegrityError("Upload result is unavailable")
                    self._verify_body(replayed)
                    connection.execute("COMMIT")
                    return ArtifactCommandResult(replayed, replayed=True)
                if artifact.status is not ArtifactUploadStatus.RESERVED:
                    rejection = "artifact_state_conflict"
                    raise ArtifactUploadConflictError("Artifact is not reserved")
                if (
                    actual_size != artifact.declared_size
                    or actual_sha256 != artifact.declared_sha256
                    or content_sha256 != actual_sha256
                    or media_type != artifact.media_type
                ):
                    rejection = "artifact_integrity_mismatch"
                    raise ArtifactUploadConflictError(
                        "Artifact content does not match its reservation"
                    )
                if final_path.exists():
                    self._verify_file(final_path, actual_size, actual_sha256)
                else:
                    os.replace(staged, final_path)
                    created_body = True
                connection.execute(
                    "UPDATE tas_artifact_uploads SET status='uploaded',actual_size=?,"
                    "actual_sha256=?,uploaded_at=? WHERE id=? AND status='reserved'",
                    (actual_size, actual_sha256, now.isoformat(), artifact.id.value),
                )
                self._complete_ledger(
                    connection,
                    actor_id,
                    "artifact.upload",
                    key,
                    fingerprint,
                    artifact.id,
                    now,
                )
                restored = self._authorized_artifact(
                    connection, actor_id.value, artifact.id.value
                )
                if restored is None:
                    raise ArtifactUploadIntegrityError("Uploaded Artifact is unavailable")
                connection.execute("COMMIT")
                return ArtifactCommandResult(restored, replayed=False)
        except (
            ArtifactUploadAccessError,
            ArtifactUploadConflictError,
            IdempotencyConflictError,
        ):
            if rejection is not None:
                self._audit_rejection(
                    actor_id,
                    "artifact",
                    artifact_id.value,
                    rejection,
                    now,
                    correlation_id,
                )
            raise
        except BaseException:
            if created_body:
                final_path.unlink(missing_ok=True)
            raise
        finally:
            staged_path.unlink(missing_ok=True)

    def finalize(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload({"artifact_id": artifact_id.value}).value
        rejection: str | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                artifact = self._authorized_artifact(
                    connection, actor_id.value, artifact_id.value
                )
                if artifact is None:
                    rejection = "artifact_unavailable"
                    raise ArtifactUploadAccessError("Artifact is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, "artifact.finalize", key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = "artifact_idempotency_conflict"
                    raise
                if replay is not None:
                    replayed = self._authorized_artifact(
                        connection, actor_id.value, replay
                    )
                    if replayed is None or replayed.id != artifact.id:
                        raise ArtifactUploadIntegrityError("Finalize result is unavailable")
                    self._verify_body(replayed)
                    connection.execute("COMMIT")
                    return ArtifactCommandResult(replayed, replayed=True)
                if artifact.status is not ArtifactUploadStatus.UPLOADED:
                    rejection = "artifact_state_conflict"
                    raise ArtifactUploadConflictError("Artifact is not ready to finalize")
                self._verify_body(artifact)
                connection.execute(
                    "UPDATE tas_artifact_uploads SET status='finalized',finalized_at=? "
                    "WHERE id=? AND status='uploaded'",
                    (now.isoformat(), artifact.id.value),
                )
                connection.execute(
                    "INSERT INTO tas_artifacts(id,task_id,producer_agent_id,reference,"
                    "media_type,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        artifact.id.value,
                        artifact.task_id.value,
                        artifact.producer_agent_id.value,
                        f"artifact:{artifact.id.value}",
                        artifact.media_type,
                        now.isoformat(),
                    ),
                )
                self._complete_ledger(
                    connection,
                    actor_id,
                    "artifact.finalize",
                    key,
                    fingerprint,
                    artifact.id,
                    now,
                )
                restored = self._authorized_artifact(
                    connection, actor_id.value, artifact.id.value
                )
                if restored is None:
                    raise ArtifactUploadIntegrityError("Finalized Artifact is unavailable")
                connection.execute("COMMIT")
                return ArtifactCommandResult(restored, replayed=False)
        except (
            ArtifactUploadAccessError,
            ArtifactUploadConflictError,
            IdempotencyConflictError,
        ):
            if rejection is not None:
                self._audit_rejection(
                    actor_id,
                    "artifact",
                    artifact_id.value,
                    rejection,
                    now,
                    correlation_id,
                )
            raise

    def record_rejection(
        self,
        actor_id: AgentId,
        artifact_id: ArtifactId,
        *,
        reason: str,
        now: datetime,
        correlation_id: str,
    ) -> None:
        self._require_utc(now)
        if reason not in {"artifact_payload_too_large"}:
            raise ValueError("Artifact rejection reason is unsupported")
        self._audit_rejection(
            actor_id,
            "artifact",
            artifact_id.value,
            reason,
            now,
            correlation_id,
        )

    def _body_path(self, artifact_id: ArtifactId) -> Path:
        candidate = self.quarantine_root / f"{artifact_id.value}.bin"
        resolved = candidate.resolve(strict=False)
        if resolved.parent != self.quarantine_root:
            raise ArtifactUploadIntegrityError("Artifact body reference is unsafe")
        return candidate

    def _verify_body(self, artifact: ArtifactUpload) -> None:
        if artifact.actual_size is None or artifact.actual_sha256 is None:
            raise ArtifactUploadIntegrityError("Artifact body metadata is incomplete")
        self._verify_file(
            self._body_path(artifact.id), artifact.actual_size, artifact.actual_sha256
        )

    @staticmethod
    def _verify_file(path: Path, size: int, digest: str) -> None:
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_size != size:
                raise ArtifactUploadIntegrityError("Artifact body integrity failed")
            calculated = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    calculated.update(chunk)
        except OSError as error:
            raise ArtifactUploadIntegrityError("Artifact body cannot be read") from error
        if calculated.hexdigest() != digest:
            raise ArtifactUploadIntegrityError("Artifact body integrity failed")

    @staticmethod
    def _actor_can_write_task(connection, actor_id: str, task_id: str) -> bool:
        return connection.execute(
            "SELECT 1 FROM tas_tasks task JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id WHERE task.id=? "
            "AND task.assignee_agent_id=actor.id",
            (actor_id, task_id),
        ).fetchone() is not None

    @staticmethod
    def _authorized_artifact(connection, actor_id: str, artifact_id: str):
        row = connection.execute(
            "SELECT upload.id,upload.task_id,upload.producer_agent_id,upload.media_type,"
            "upload.purpose,upload.declared_size,upload.declared_sha256,upload.status,"
            "upload.actual_size,upload.actual_sha256,upload.created_at,upload.uploaded_at,"
            "upload.finalized_at FROM tas_artifact_uploads upload "
            "JOIN tas_tasks task ON task.id=upload.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=? JOIN tas_team_memberships member "
            "ON member.team_id=project.team_id AND member.owner_id=actor.owner_id "
            "WHERE upload.id=? AND upload.producer_agent_id=actor.id "
            "AND task.assignee_agent_id=actor.id",
            (actor_id, artifact_id),
        ).fetchone()
        return None if row is None else SQLiteArtifactUploadUnitOfWork._restore(row)

    @staticmethod
    def _restore(row) -> ArtifactUpload:
        return ArtifactUpload(
            ArtifactId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            str(row[3]),
            ArtifactPurpose(str(row[4])),
            int(row[5]),
            str(row[6]),
            ArtifactUploadStatus(str(row[7])),
            None if row[8] is None else int(row[8]),
            None if row[9] is None else str(row[9]),
            datetime.fromisoformat(str(row[10])),
            None if row[11] is None else datetime.fromisoformat(str(row[11])),
            None if row[12] is None else datetime.fromisoformat(str(row[12])),
        )

    @staticmethod
    def _ledger(connection, actor_id, operation, key, fingerprint):
        row = connection.execute(
            "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
            "WHERE actor_id=? AND operation=? AND idempotency_key=?",
            (actor_id.value, operation, key.value),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            return str(json.loads(str(row[1]))["artifact_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ArtifactUploadIntegrityError("Artifact result is invalid") from error

    @staticmethod
    def _complete_ledger(
        connection, actor_id, operation, key, fingerprint, artifact_id, now
    ) -> None:
        result = json.dumps(
            {"artifact_id": artifact_id.value}, sort_keys=True, separators=(",", ":")
        )
        connection.execute(
            "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,"
            "request_fingerprint,status,reservation_token_hash,result_json,created_at,"
            "updated_at) VALUES (?,?,?,?,'completed',NULL,?,?,?)",
            (
                actor_id.value,
                operation,
                key.value,
                fingerprint,
                result,
                now.isoformat(),
                now.isoformat(),
            ),
        )

    def _audit_rejection(
        self, actor_id, resource_type, resource_id, reason, now, correlation_id
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
                "resource_id,action,outcome,reason,occurred_at,policy_version,"
                "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()),
                    AuditEventKind.AUTHORIZATION_DECISION.value,
                    AuditActorKind.AGENT.value,
                    actor_id.value,
                    resource_type,
                    resource_id,
                    "artifact.write",
                    AuditOutcome.REJECTED.value,
                    reason,
                    now.isoformat(),
                    None,
                    correlation_id,
                ),
            )

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("now must use UTC")
