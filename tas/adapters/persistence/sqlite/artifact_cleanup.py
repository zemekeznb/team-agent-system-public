"""Bounded, system-only Artifact Body retention cleanup.

Metadata, security assessments, derivation links and audit history are retained.
An interrupted purge remains pending and can be retried without deleting another body.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.domain.collaboration import ArtifactId


class ArtifactCleanupError(RuntimeError):
    """The controlled Body cannot safely be removed."""


class SQLiteArtifactCleanupService:
    def __init__(self, database: str | Path, artifact_root: str | Path) -> None:
        self.database = Path(database)
        requested = Path(artifact_root)
        if requested.is_symlink():
            raise ArtifactCleanupError("Artifact root is unsafe")
        self.root = requested.resolve(strict=False)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @staticmethod
    def _validate(now: datetime, correlation_id: str, limit: int) -> None:
        if (not isinstance(now, datetime) or now.tzinfo is None
                or now.utcoffset() != timedelta(0)):
            raise ValueError("now must use UTC")
        if not isinstance(correlation_id, str) or not 1 <= len(correlation_id) <= 255:
            raise ValueError("correlation_id is invalid")
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")

    @staticmethod
    def _audit(connection, artifact_id: str, action: str, reason: str,
               now: datetime, correlation_id: str, outcome: str = "allow") -> None:
        connection.execute(
            "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
            "resource_id,action,outcome,reason,occurred_at,policy_version,correlation_id) "
            "VALUES (?,'authorization_decision','system','system','artifact',?,?,?,?,?,NULL,?)",
            (str(uuid4()), artifact_id, action, outcome, reason, now.isoformat(), correlation_id),
        )

    def request_expired(self, *, now: datetime, correlation_id: str,
                        limit: int = 100) -> tuple[ArtifactId, ...]:
        """Atomically seal expired, unreferenced bodies against new readers/links."""
        self._validate(now, correlation_id, limit)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT life.artifact_id FROM tas_artifact_lifecycle life "
                "WHERE life.cleanup_status='active' "
                "AND julianday(life.expires_at)<=julianday(?) "
                "AND NOT EXISTS (SELECT 1 FROM tas_evidence_submission_artifacts link "
                "WHERE link.artifact_id=life.artifact_id) "
                "ORDER BY life.expires_at,life.artifact_id LIMIT ?",
                (now.isoformat(), limit),
            ).fetchall()
            for (artifact_id,) in rows:
                connection.execute(
                    "UPDATE tas_artifact_lifecycle SET cleanup_status='pending',"
                    "cleanup_requested_at=? WHERE artifact_id=? AND cleanup_status='active'",
                    (now.isoformat(), artifact_id),
                )
                self._audit(connection, artifact_id, "artifact.cleanup.request",
                            "expired_unreferenced", now, correlation_id)
            connection.execute("COMMIT")
            return tuple(ArtifactId(str(row[0])) for row in rows)

    def purge_pending(self, *, now: datetime, correlation_id: str,
                      limit: int = 100) -> tuple[ArtifactId, ...]:
        """Remove only known pending Body files, then release quota atomically."""
        self._validate(now, correlation_id, limit)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT life.artifact_id,upload.status,security.availability_status "
                "FROM tas_artifact_lifecycle life "
                "JOIN tas_artifact_uploads upload ON upload.id=life.artifact_id "
                "JOIN tas_artifact_security security ON security.artifact_id=life.artifact_id "
                "WHERE life.cleanup_status='pending' "
                "ORDER BY life.cleanup_requested_at,life.artifact_id LIMIT ?",
                (limit,),
            ).fetchall()
        completed: list[ArtifactId] = []
        for artifact_id, upload_status, availability in rows:
            try:
                subdir = "available" if availability == "available" else "quarantine"
                body_root = self.root / subdir
                if body_root.is_symlink() or body_root.resolve(strict=False) != self.root / subdir:
                    raise ArtifactCleanupError("Artifact Body root is unsafe")
                path = body_root / f"{ArtifactId(str(artifact_id)).value}.bin"
                if path.is_symlink() or path.resolve(strict=False).parent != body_root:
                    raise ArtifactCleanupError("Artifact Body path is unsafe")
                if path.exists():
                    if not path.is_file():
                        raise ArtifactCleanupError("Artifact Body is not a regular file")
                    path.unlink()
                    reason = "body_removed"
                else:
                    # A reserved row has no Body; for other rows this is also
                    # the recovery state after interruption post-unlink.
                    reason = "body_already_absent" if upload_status != "reserved" else "no_body"
            except (ArtifactCleanupError, OSError) as error:
                with self._connect() as connection:
                    self._audit(connection, str(artifact_id), "artifact.cleanup.purge",
                                "body_unsafe_or_unavailable", now, correlation_id,
                                outcome="rejected")
                raise ArtifactCleanupError("Artifact Body cannot be safely purged") from error
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    "UPDATE tas_artifact_lifecycle SET cleanup_status='purged',"
                    "charged_bytes=0,purged_at=? WHERE artifact_id=? "
                    "AND cleanup_status='pending'",
                    (now.isoformat(), artifact_id),
                ).rowcount
                if updated:
                    self._audit(connection, str(artifact_id), "artifact.cleanup.purge",
                                reason, now, correlation_id)
                    completed.append(ArtifactId(str(artifact_id)))
                connection.execute("COMMIT")
        return tuple(completed)
