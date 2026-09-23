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
from tas.adapters.persistence.sqlite.artifact_rows import (
    ARTIFACT_COLUMNS, ARTIFACT_JOINS, restore_artifact,
)
from tas.application.artifact_uploads import (
    MAX_TASK_ARTIFACT_BYTES,
    MAX_OWNER_ARTIFACT_BYTES,
    MAX_OWNER_ARTIFACT_COUNT,
    ArtifactAvailabilityStatus,
    ArtifactCommandResult,
    ArtifactScanner,
    ArtifactSecurityStatus,
    ArtifactUpload,
    ArtifactUploadStatus,
    RegisteredSecretScanner,
    ReserveArtifactCommand,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import ArtifactId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class ArtifactUploadAccessError(PermissionError):
    """The Artifact or target Task is unavailable to this Agent."""


class ArtifactUploadConflictError(RuntimeError):
    """The request conflicts with current Artifact state or declared integrity."""


class ArtifactUploadIntegrityError(RuntimeError):
    """Committed Artifact metadata and controlled body cannot be reconstructed."""


class SQLiteArtifactUploadUnitOfWork:
    def __init__(
        self,
        database: str | Path,
        artifact_root: str | Path,
        scanner: ArtifactScanner | None = None,
    ) -> None:
        self.database = Path(database)
        requested_root = Path(artifact_root)
        if requested_root.is_symlink():
            raise ArtifactUploadIntegrityError("Artifact storage root is unsafe")
        self.artifact_root = requested_root.resolve(strict=False)
        self.staging_root = self.artifact_root / ".staging"
        self.quarantine_root = self.artifact_root / "quarantine"
        self.available_root = self.artifact_root / "available"
        self.staging_root.mkdir(parents=True, exist_ok=True)
        self.quarantine_root.mkdir(parents=True, exist_ok=True)
        self.available_root.mkdir(parents=True, exist_ok=True)
        if self.artifact_root.is_symlink() or any(
            path.is_symlink()
            for path in (
                self.staging_root,
                self.quarantine_root,
                self.available_root,
            )
        ):
            raise ArtifactUploadIntegrityError("Artifact storage root is unsafe")
        self.scanner = scanner or RegisteredSecretScanner()
        if not isinstance(self.scanner.version, str) or not self.scanner.version:
            raise ArtifactUploadIntegrityError("Artifact scanner version is invalid")

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
                        lifecycle = connection.execute(
                            "SELECT cleanup_status FROM tas_artifact_lifecycle "
                            "WHERE artifact_id=?", (replay,),
                        ).fetchone()
                        if lifecycle is not None and lifecycle[0] != "active":
                            rejection = ("artifact", replay, "artifact_retention_unavailable")
                            raise ArtifactUploadAccessError("Artifact is unavailable")
                        raise ArtifactUploadIntegrityError(
                            "Artifact reservation result is unavailable"
                        )
                    connection.execute("COMMIT")
                    return ArtifactCommandResult(artifact, replayed=True)
                charge = command.declared_size * (
                    2 if command.media_type in {"text/plain", "application/json"} else 1
                )
                totals = connection.execute(
                    "SELECT count(*),COALESCE(sum(life.charged_bytes),0) "
                    "FROM tas_artifact_uploads upload JOIN tas_artifact_lifecycle life "
                    "ON life.artifact_id=upload.id WHERE upload.task_id=? "
                    "AND life.cleanup_status<>'purged'",
                    (command.task_id.value,),
                ).fetchone()
                if int(totals[0]) >= 1000 or int(totals[1]) + charge > MAX_TASK_ARTIFACT_BYTES:
                    rejection = ("task", command.task_id.value, "artifact_quota_exceeded")
                    raise ArtifactUploadConflictError("Artifact Task quota is exceeded")
                owner_totals = connection.execute(
                    "SELECT count(*),COALESCE(sum(charged_bytes),0) "
                    "FROM tas_artifact_lifecycle WHERE owner_id=("
                    "SELECT owner_id FROM tas_agents WHERE id=?) "
                    "AND cleanup_status<>'purged'", (actor_id.value,),
                ).fetchone()
                if (int(owner_totals[0]) >= MAX_OWNER_ARTIFACT_COUNT
                    or int(owner_totals[1]) + charge > MAX_OWNER_ARTIFACT_BYTES):
                    rejection = ("task", command.task_id.value, "artifact_owner_quota_exceeded")
                    raise ArtifactUploadConflictError("Artifact Owner quota is exceeded")
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
        final_path = self._quarantine_path(artifact_id)
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
        moved_source = False
        created_derived_path: Path | None = None
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
                content = self._read_verified_body(artifact)
                try:
                    scan = self.scanner.scan(content, artifact.media_type)
                except Exception:
                    scan_status = ArtifactSecurityStatus.SCAN_FAILED
                    redacted_content = None
                    redaction_count = 0
                else:
                    scan_status = scan.status
                    redacted_content = scan.redacted_content
                    redaction_count = scan.redaction_count
                    if (
                        scan_status is ArtifactSecurityStatus.SECRET_DETECTED
                        and redacted_content == content
                    ):
                        scan_status = ArtifactSecurityStatus.SCAN_FAILED
                        redacted_content = None
                        redaction_count = 0
                derived_id: ArtifactId | None = None
                if scan_status is ArtifactSecurityStatus.CLEAN:
                    os.replace(
                        self._quarantine_path(artifact.id),
                        self._available_path(artifact.id),
                    )
                    moved_source = True
                elif scan_status is ArtifactSecurityStatus.SECRET_DETECTED:
                    if redacted_content is None or redaction_count < 1:
                        raise ArtifactUploadIntegrityError(
                            "Artifact scanner returned an invalid redaction"
                        )
                    derived_id = ArtifactId(str(uuid4()))
                    created_derived_path = self._available_path(derived_id)
                    self._write_derived_body(created_derived_path, redacted_content)
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
                connection.execute(
                    "UPDATE tas_artifact_security SET scan_status=?,availability_status=?,"
                    "scanner_version=?,scanned_at=?,redaction_count=? WHERE artifact_id=?",
                    (
                        scan_status.value,
                        (
                            ArtifactAvailabilityStatus.AVAILABLE.value
                            if scan_status is ArtifactSecurityStatus.CLEAN
                            else ArtifactAvailabilityStatus.QUARANTINED.value
                        ),
                        self.scanner.version,
                        now.isoformat(),
                        redaction_count,
                        artifact.id.value,
                    ),
                )
                connection.execute(
                    "UPDATE tas_artifact_lifecycle SET retention_class=?,expires_at=?,"
                    "charged_bytes=? WHERE artifact_id=?",
                    (
                        "available" if scan_status is ArtifactSecurityStatus.CLEAN else "quarantine",
                        (now + timedelta(days=(90 if scan_status is ArtifactSecurityStatus.CLEAN else 7))).isoformat(),
                        artifact.declared_size,
                        artifact.id.value,
                    ),
                )
                if derived_id is not None and redacted_content is not None:
                    derived_digest = hashlib.sha256(redacted_content).hexdigest()
                    connection.execute(
                        "INSERT INTO tas_artifact_uploads(id,task_id,producer_agent_id,"
                        "media_type,purpose,declared_size,declared_sha256,status,actual_size,"
                        "actual_sha256,created_at,uploaded_at,finalized_at) VALUES "
                        "(?,?,?,?,?,?,?,'finalized',?,?,?,?,?)",
                        (
                            derived_id.value,
                            artifact.task_id.value,
                            artifact.producer_agent_id.value,
                            artifact.media_type,
                            artifact.purpose.value,
                            len(redacted_content),
                            derived_digest,
                            len(redacted_content),
                            derived_digest,
                            now.isoformat(),
                            now.isoformat(),
                            now.isoformat(),
                        ),
                    )
                    connection.execute(
                        "UPDATE tas_artifact_security SET scan_status='redacted',"
                        "availability_status='available',scanner_version=?,scanned_at=?,"
                        "redaction_count=? WHERE artifact_id=?",
                        (
                            self.scanner.version,
                            now.isoformat(),
                            redaction_count,
                            derived_id.value,
                        ),
                    )
                    connection.execute(
                        "INSERT INTO tas_artifacts(id,task_id,producer_agent_id,reference,"
                        "media_type,created_at) VALUES (?,?,?,?,?,?)",
                        (
                            derived_id.value,
                            artifact.task_id.value,
                            artifact.producer_agent_id.value,
                            f"artifact:{derived_id.value}",
                            artifact.media_type,
                            now.isoformat(),
                        ),
                    )
                    connection.execute(
                        "INSERT INTO tas_artifact_derivations(source_artifact_id,"
                        "derived_artifact_id,derivation_kind,redaction_count,created_at) "
                        "VALUES (?,?,'redacted',?,?)",
                        (
                            artifact.id.value,
                            derived_id.value,
                            redaction_count,
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
        except BaseException:
            if moved_source:
                available = self._available_path(artifact_id)
                quarantine = self._quarantine_path(artifact_id)
                if available.exists() and not quarantine.exists():
                    os.replace(available, quarantine)
            if created_derived_path is not None:
                created_derived_path.unlink(missing_ok=True)
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
        """Compatibility alias for the pre-scan upload location."""
        return self._quarantine_path(artifact_id)

    def _quarantine_path(self, artifact_id: ArtifactId) -> Path:
        candidate = self.quarantine_root / f"{artifact_id.value}.bin"
        resolved = candidate.resolve(strict=False)
        if resolved.parent != self.quarantine_root:
            raise ArtifactUploadIntegrityError("Artifact body reference is unsafe")
        return candidate

    def _available_path(self, artifact_id: ArtifactId) -> Path:
        candidate = self.available_root / f"{artifact_id.value}.bin"
        resolved = candidate.resolve(strict=False)
        if resolved.parent != self.available_root:
            raise ArtifactUploadIntegrityError("Artifact body reference is unsafe")
        return candidate

    def _verify_body(self, artifact: ArtifactUpload) -> None:
        if artifact.actual_size is None or artifact.actual_sha256 is None:
            raise ArtifactUploadIntegrityError("Artifact body metadata is incomplete")
        path = (
            self._available_path(artifact.id)
            if artifact.availability_status is ArtifactAvailabilityStatus.AVAILABLE
            else self._quarantine_path(artifact.id)
        )
        self._verify_file(
            path, artifact.actual_size, artifact.actual_sha256
        )

    def _read_verified_body(self, artifact: ArtifactUpload) -> bytes:
        if artifact.actual_size is None or artifact.actual_sha256 is None:
            raise ArtifactUploadIntegrityError("Artifact body metadata is incomplete")
        path = self._quarantine_path(artifact.id)
        self._verify_file(path, artifact.actual_size, artifact.actual_sha256)
        try:
            content = path.read_bytes()
        except OSError as error:
            raise ArtifactUploadIntegrityError("Artifact body cannot be read") from error
        if len(content) != artifact.actual_size:
            raise ArtifactUploadIntegrityError("Artifact body integrity failed")
        return content

    @staticmethod
    def _write_derived_body(path: Path, content: bytes) -> None:
        try:
            with path.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as error:
            raise ArtifactUploadIntegrityError(
                "Redacted Artifact body cannot be written"
            ) from error

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
            f"SELECT {ARTIFACT_COLUMNS} FROM tas_artifact_uploads upload "
            + ARTIFACT_JOINS +
            "JOIN tas_tasks task ON task.id=upload.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=? JOIN tas_team_memberships member "
            "ON member.team_id=project.team_id AND member.owner_id=actor.owner_id "
            "WHERE upload.id=? AND life.cleanup_status='active' "
            "AND life.owner_id=actor.owner_id "
            "AND upload.producer_agent_id=actor.id "
            "AND task.assignee_agent_id=actor.id",
            (actor_id, artifact_id),
        ).fetchone()
        return None if row is None else restore_artifact(row)

    @staticmethod
    def _restore(row) -> ArtifactUpload:
        return restore_artifact(row)

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
