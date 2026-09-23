"""SQLite authorization and controlled-volume reads for finalized raw resources."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.application.artifact_access import ArtifactDownload, EvidenceAccessView
from tas.adapters.persistence.sqlite.artifact_rows import (
    ARTIFACT_COLUMNS, ARTIFACT_JOINS, restore_artifact,
)
from tas.application.artifact_uploads import (
    ArtifactAvailabilityStatus,
    ArtifactUpload,
)
from tas.application.evidence_submissions import (
    EvidenceSubmission,
    EvidenceSubmissionStatus,
)
from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.credential import AuthenticatedPrincipal, CredentialSubjectType
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.work_record import ObservedEvidenceKind


class ArtifactAccessIntegrityError(RuntimeError):
    """Persisted metadata or controlled Body failed reconstruction."""


class SQLiteArtifactEvidenceAccessRepository:
    def __init__(self, database: str | Path, artifact_root: str | Path) -> None:
        self.database = Path(database)
        requested_root = Path(artifact_root)
        if requested_root.is_symlink():
            raise ArtifactAccessIntegrityError("Artifact storage root is unsafe")
        self.artifact_root = requested_root.resolve(strict=False)
        requested_body_root = self.artifact_root / "available"
        if requested_body_root.is_symlink():
            raise ArtifactAccessIntegrityError("Artifact Body root is unsafe")
        self.body_root = requested_body_root.resolve(strict=False)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def get_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        *, now: datetime, correlation_id: str,
    ) -> ArtifactUpload | None:
        self._require_utc(now)
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = self._artifact_row(connection, principal, artifact_id.value)
            if row is None:
                connection.execute("COMMIT")
                self._audit_rejection(
                    principal, "artifact", artifact_id.value,
                    "artifact_read_unavailable", "artifact.read", now,
                    correlation_id,
                )
                return None
            try:
                artifact = self._restore_artifact(row)
            except (DomainValidationError, TypeError, ValueError) as error:
                raise ArtifactAccessIntegrityError(
                    "Persisted Artifact metadata is invalid"
                ) from error
            connection.execute("COMMIT")
            return artifact

    def open_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        *, now: datetime, correlation_id: str,
    ) -> ArtifactDownload | None:
        artifact = self.get_artifact(
            principal, artifact_id, now=now, correlation_id=correlation_id
        )
        if artifact is None:
            return None
        if artifact.availability_status is not ArtifactAvailabilityStatus.AVAILABLE:
            self._audit_rejection(
                principal, "artifact", artifact_id.value,
                "artifact_read_unavailable", "artifact.read", now,
                correlation_id,
            )
            return None
        if artifact.actual_size is None or artifact.actual_sha256 is None:
            raise ArtifactAccessIntegrityError("Artifact Body metadata is incomplete")
        path = self._body_path(artifact.id)
        try:
            if path.is_symlink() or not path.is_file():
                raise ArtifactAccessIntegrityError("Artifact Body is unavailable")
            stream = path.open("rb")
            try:
                stat = os.fstat(stream.fileno())
                if stat.st_size != artifact.actual_size:
                    raise ArtifactAccessIntegrityError("Artifact Body integrity failed")
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
                if digest.hexdigest() != artifact.actual_sha256:
                    raise ArtifactAccessIntegrityError("Artifact Body integrity failed")
                stream.seek(0)
            except BaseException:
                stream.close()
                raise
        except OSError as error:
            raise ArtifactAccessIntegrityError("Artifact Body cannot be read") from error
        return ArtifactDownload(artifact, stream)

    def get_evidence(
        self, principal: AuthenticatedPrincipal, evidence_id: EvidenceId,
        *, now: datetime, correlation_id: str,
    ) -> EvidenceAccessView | None:
        self._require_utc(now)
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT evidence.id,evidence.task_id,evidence.actor_agent_id,"
                "evidence.workspace_id,evidence.kind,evidence.attempt,evidence.retry_of,"
                "evidence.observed_at,evidence.head_commit,evidence.status,"
                "evidence.payload_sha256,evidence.created_at,evidence.finalized_at,"
                "observed.payload_json,observed.payload_sha256 "
                "FROM tas_evidence_submissions evidence JOIN tas_observed_evidence observed "
                "ON observed.id=evidence.id AND observed.task_id=evidence.task_id "
                "AND observed.actor_agent_id=evidence.actor_agent_id "
                "AND observed.kind=evidence.kind AND observed.observed_at=evidence.observed_at "
                "AND observed.payload_sha256=evidence.payload_sha256 "
                "JOIN tas_tasks task ON task.id=evidence.task_id "
                "JOIN tas_projects project ON project.id=task.project_id "
                "JOIN tas_agents author ON author.id=evidence.actor_agent_id "
                "JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "AND member.owner_id=author.owner_id WHERE evidence.id=? "
                "AND evidence.status='finalized' "
                "AND NOT EXISTS (SELECT 1 FROM tas_evidence_submission_artifacts link "
                "JOIN tas_artifact_security security "
                "ON security.artifact_id=link.artifact_id "
                "WHERE link.evidence_id=evidence.id "
                "AND security.availability_status<>'available') "
                "AND task.assignee_agent_id=evidence.actor_agent_id "
                "AND author.owner_id=? AND (? IS NULL OR evidence.actor_agent_id=?)",
                (
                    evidence_id.value,
                    principal.owner_id.value,
                    self._agent_id(principal),
                    self._agent_id(principal),
                ),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                self._audit_rejection(
                    principal, "evidence", evidence_id.value,
                    "evidence_read_unavailable", "evidence.read", now,
                    correlation_id,
                )
                return None
            artifacts = tuple(
                ArtifactId(str(item[0]))
                for item in connection.execute(
                    "SELECT artifact_id FROM tas_evidence_submission_artifacts "
                    "WHERE evidence_id=? ORDER BY sequence",
                    (evidence_id.value,),
                ).fetchall()
            )
            try:
                evidence = EvidenceSubmission(
                    EvidenceId(str(row[0])),
                    TaskId(str(row[1])),
                    AgentId(str(row[2])),
                    WorkspaceBindingId(str(row[3])),
                    ObservedEvidenceKind(str(row[4])),
                    int(row[5]),
                    None if row[6] is None else EvidenceId(str(row[6])),
                    datetime.fromisoformat(str(row[7])),
                    str(row[8]),
                    artifacts,
                    EvidenceSubmissionStatus(str(row[9])),
                    None if row[10] is None else str(row[10]),
                    datetime.fromisoformat(str(row[11])),
                    None if row[12] is None else datetime.fromisoformat(str(row[12])),
                )
                payload_json = str(row[13])
                if row[10] != row[14] or hashlib.sha256(
                    payload_json.encode("utf-8")
                ).hexdigest() != str(row[10]):
                    raise ArtifactAccessIntegrityError(
                        "Evidence payload integrity failed"
                    )
                view = EvidenceAccessView(evidence, payload_json)
            except (DomainValidationError, TypeError, ValueError) as error:
                raise ArtifactAccessIntegrityError(
                    "Persisted Evidence is invalid"
                ) from error
            connection.execute("COMMIT")
            return view

    def _artifact_row(self, connection, principal, artifact_id):
        return connection.execute(
            f"SELECT {ARTIFACT_COLUMNS} FROM tas_artifact_uploads upload "
            + ARTIFACT_JOINS +
            "JOIN tas_tasks task ON task.id=upload.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents producer ON producer.id=upload.producer_agent_id "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=producer.owner_id WHERE upload.id=? "
            "AND upload.status='finalized' AND life.cleanup_status='active' "
            "AND life.owner_id=producer.owner_id "
            "AND task.assignee_agent_id=upload.producer_agent_id "
            "AND producer.owner_id=? AND (? IS NULL OR upload.producer_agent_id=?)",
            (
                artifact_id,
                principal.owner_id.value,
                self._agent_id(principal),
                self._agent_id(principal),
            ),
        ).fetchone()

    def _body_path(self, artifact_id: ArtifactId) -> Path:
        candidate = self.body_root / f"{artifact_id.value}.bin"
        resolved = candidate.resolve(strict=False)
        if resolved.parent != self.body_root:
            raise ArtifactAccessIntegrityError("Artifact Body reference is unsafe")
        return candidate

    def _audit_rejection(
        self, principal, resource_type, resource_id, reason, action, now,
        correlation_id,
    ) -> None:
        actor_kind = (
            AuditActorKind.OWNER
            if principal.subject_type is CredentialSubjectType.OWNER
            else AuditActorKind.AGENT
        )
        actor_id = (
            principal.owner_id.value
            if principal.subject_type is CredentialSubjectType.OWNER
            else principal.agent_id.value
        )
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
                "resource_id,action,outcome,reason,occurred_at,policy_version,"
                "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                    actor_kind.value, actor_id, resource_type, resource_id, action,
                    AuditOutcome.REJECTED.value, reason, now.isoformat(), None,
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

    @staticmethod
    def _agent_id(principal: AuthenticatedPrincipal) -> str | None:
        if principal.subject_type is CredentialSubjectType.OWNER:
            return None
        return None if principal.agent_id is None else principal.agent_id.value

    @staticmethod
    def _restore_artifact(row) -> ArtifactUpload:
        return restore_artifact(row)
