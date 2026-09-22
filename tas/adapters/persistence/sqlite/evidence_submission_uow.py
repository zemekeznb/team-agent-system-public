"""SQLite transaction boundary for F3 Evidence reservation and finalization."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.evidence_submissions import (
    EvidenceSubmission,
    EvidenceSubmissionResult,
    EvidenceSubmissionStatus,
    ReserveEvidenceCommand,
    canonical_evidence_payload,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.work_record import ObservedEvidence, ObservedEvidenceKind


class EvidenceSubmissionAccessError(PermissionError):
    """The Task, Workspace, Evidence, retry, or Artifact is unavailable."""


class EvidenceSubmissionConflictError(RuntimeError):
    """The request conflicts with Evidence state or reserved metadata."""


class EvidenceSubmissionIntegrityError(RuntimeError):
    """Committed Evidence state cannot be safely reconstructed."""


class SQLiteEvidenceSubmissionUnitOfWork:
    RESERVE_OPERATION = "evidence.reserve"
    FINALIZE_OPERATION = "evidence.finalize"

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def reserve(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ReserveEvidenceCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EvidenceSubmissionResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload(
            {
                "task_id": command.task_id.value,
                "workspace_id": command.workspace_id.value,
                "kind": command.kind.value,
                "attempt": command.attempt,
                "retry_of": None if command.retry_of is None else command.retry_of.value,
                "observed_at": command.observed_at.isoformat(),
                "head_commit": command.head_commit,
                "artifact_ids": [item.value for item in command.artifact_ids],
            }
        ).value
        rejection = "evidence_scope_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if not self._authorized_scope(connection, actor_id, command):
                    raise EvidenceSubmissionAccessError("Evidence scope is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, self.RESERVE_OPERATION, key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = "evidence_idempotency_conflict"
                    raise
                if replay is not None:
                    evidence = self._authorized_evidence(connection, actor_id, replay)
                    if evidence is None:
                        raise EvidenceSubmissionIntegrityError(
                            "Evidence reservation result is unavailable"
                        )
                    connection.execute("COMMIT")
                    return EvidenceSubmissionResult(evidence, replayed=True)
                if command.observed_at > now + timedelta(minutes=5):
                    rejection = "evidence_time_invalid"
                    raise EvidenceSubmissionConflictError(
                        "Evidence observation time is invalid"
                    )
                if not self._retry_is_valid(connection, actor_id, command):
                    rejection = "evidence_dependency_unavailable"
                    raise EvidenceSubmissionAccessError(
                        "Evidence retry dependency is unavailable"
                    )
                if not self._artifacts_are_eligible(connection, actor_id, command):
                    rejection = "evidence_artifact_unavailable"
                    raise EvidenceSubmissionAccessError(
                        "Evidence Artifact is unavailable"
                    )
                evidence_id = EvidenceId(str(uuid4()))
                connection.execute(
                    "INSERT INTO tas_evidence_submissions(id,task_id,actor_agent_id,"
                    "workspace_id,kind,attempt,retry_of,observed_at,head_commit,status,"
                    "payload_sha256,created_at,finalized_at) VALUES "
                    "(?,?,?,?,?,?,?,?,?,'reserved',NULL,?,NULL)",
                    (
                        evidence_id.value,
                        command.task_id.value,
                        actor_id.value,
                        command.workspace_id.value,
                        command.kind.value,
                        command.attempt,
                        None if command.retry_of is None else command.retry_of.value,
                        command.observed_at.isoformat(),
                        command.head_commit,
                        now.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO tas_evidence_submission_artifacts"
                    "(evidence_id,sequence,artifact_id) VALUES (?,?,?)",
                    [
                        (evidence_id.value, index, artifact_id.value)
                        for index, artifact_id in enumerate(
                            command.artifact_ids, start=1
                        )
                    ],
                )
                self._complete_ledger(
                    connection,
                    actor_id,
                    self.RESERVE_OPERATION,
                    key,
                    fingerprint,
                    evidence_id,
                    now,
                )
                evidence = self._authorized_evidence(
                    connection, actor_id, evidence_id.value
                )
                if evidence is None:
                    raise EvidenceSubmissionIntegrityError(
                        "Evidence reservation could not be restored"
                    )
                connection.execute("COMMIT")
                return EvidenceSubmissionResult(evidence, replayed=False)
        except (
            EvidenceSubmissionAccessError,
            EvidenceSubmissionConflictError,
            IdempotencyConflictError,
        ):
            self._audit_rejection(
                actor_id,
                "task",
                command.task_id.value,
                rejection,
                now,
                correlation_id,
            )
            raise

    def finalize(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        evidence_id: EvidenceId,
        payload_json: str,
        *,
        now: datetime,
        correlation_id: str,
    ) -> EvidenceSubmissionResult:
        self._require_utc(now)
        payload_sha256, payload = canonical_evidence_payload(payload_json)
        fingerprint = fingerprint_payload(
            {
                "evidence_id": evidence_id.value,
                "payload_sha256": payload_sha256,
            }
        ).value
        rejection = "evidence_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                evidence = self._authorized_evidence(
                    connection, actor_id, evidence_id.value
                )
                if evidence is None:
                    raise EvidenceSubmissionAccessError("Evidence is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, self.FINALIZE_OPERATION, key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = "evidence_idempotency_conflict"
                    raise
                if replay is not None:
                    restored = self._authorized_evidence(connection, actor_id, replay)
                    if (
                        restored is None
                        or restored.id != evidence.id
                        or restored.status is not EvidenceSubmissionStatus.FINALIZED
                        or restored.payload_sha256 != payload_sha256
                    ):
                        raise EvidenceSubmissionIntegrityError(
                            "Finalized Evidence result is unavailable"
                        )
                    self._verify_observed_snapshot(connection, restored)
                    connection.execute("COMMIT")
                    return EvidenceSubmissionResult(restored, replayed=True)
                if evidence.status is not EvidenceSubmissionStatus.RESERVED:
                    rejection = "evidence_state_conflict"
                    raise EvidenceSubmissionConflictError(
                        "Evidence is not reserved"
                    )
                if not self._current_dependencies_are_valid(connection, evidence):
                    rejection = "evidence_dependency_unavailable"
                    raise EvidenceSubmissionAccessError(
                        "Evidence dependency is unavailable"
                    )
                try:
                    self._validate_payload(connection, evidence, payload)
                    snapshot = ObservedEvidence(
                        evidence.id,
                        evidence.task_id,
                        evidence.actor_id,
                        evidence.kind,
                        payload_json,
                        payload_sha256,
                        evidence.observed_at,
                    )
                except (DomainValidationError, TypeError, ValueError) as error:
                    rejection = "evidence_payload_conflict"
                    raise EvidenceSubmissionConflictError(
                        "Evidence payload conflicts with reservation"
                    ) from error
                connection.execute(
                    "INSERT INTO tas_observed_evidence(id,task_id,actor_agent_id,kind,"
                    "payload_json,payload_sha256,observed_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        snapshot.id.value,
                        snapshot.task_id.value,
                        snapshot.actor_id.value,
                        snapshot.kind.value,
                        snapshot.payload_json,
                        snapshot.payload_sha256,
                        snapshot.observed_at.isoformat(),
                    ),
                )
                connection.execute(
                    "UPDATE tas_evidence_submissions SET status='finalized',"
                    "payload_sha256=?,finalized_at=? WHERE id=? AND status='reserved'",
                    (payload_sha256, now.isoformat(), evidence.id.value),
                )
                self._complete_ledger(
                    connection,
                    actor_id,
                    self.FINALIZE_OPERATION,
                    key,
                    fingerprint,
                    evidence.id,
                    now,
                )
                restored = self._authorized_evidence(
                    connection, actor_id, evidence.id.value
                )
                if restored is None:
                    raise EvidenceSubmissionIntegrityError(
                        "Finalized Evidence could not be restored"
                    )
                connection.execute("COMMIT")
                return EvidenceSubmissionResult(restored, replayed=False)
        except (
            EvidenceSubmissionAccessError,
            EvidenceSubmissionConflictError,
            IdempotencyConflictError,
        ):
            self._audit_rejection(
                actor_id,
                "evidence",
                evidence_id.value,
                rejection,
                now,
                correlation_id,
            )
            raise

    @staticmethod
    def _authorized_scope(connection, actor_id, command) -> bool:
        return connection.execute(
            "SELECT 1 FROM tas_tasks task JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id "
            "JOIN tas_task_workspace_bindings workspace ON workspace.id=? "
            "AND workspace.task_id=task.id AND workspace.actor_agent_id=actor.id "
            "WHERE task.id=? AND task.assignee_agent_id=actor.id",
            (actor_id.value, command.workspace_id.value, command.task_id.value),
        ).fetchone() is not None

    @staticmethod
    def _retry_is_valid(connection, actor_id, command) -> bool:
        if command.retry_of is None:
            return True
        return connection.execute(
            "SELECT 1 FROM tas_evidence_submissions WHERE id=? AND task_id=? "
            "AND actor_agent_id=? AND kind='command_test' AND status='finalized' "
            "AND attempt=?",
            (
                command.retry_of.value,
                command.task_id.value,
                actor_id.value,
                command.attempt - 1,
            ),
        ).fetchone() is not None

    @staticmethod
    def _artifacts_are_eligible(connection, actor_id, command) -> bool:
        rows = connection.execute(
            "SELECT upload.id,upload.purpose FROM tas_artifact_uploads upload "
            "WHERE upload.id IN ({}) AND upload.status='finalized' "
            "AND upload.task_id=? AND upload.producer_agent_id=?".format(
                ",".join("?" for _ in command.artifact_ids) or "NULL"
            ),
            tuple(item.value for item in command.artifact_ids)
            + (command.task_id.value, actor_id.value),
        ).fetchall()
        purposes = {str(row[0]): str(row[1]) for row in rows}
        if set(purposes) != {item.value for item in command.artifact_ids}:
            return False
        if command.kind is ObservedEvidenceKind.COMMAND_TEST:
            return sorted(purposes.values()) == ["test_stderr", "test_stdout"]
        return len(purposes) <= 1 and all(
            purpose == "git_diff" for purpose in purposes.values()
        )

    @staticmethod
    def _validate_payload(connection, evidence, payload) -> None:
        if any(
            field in payload
            for field in ("actor_id", "task_id", "owner_id", "worktree_root")
        ):
            raise DomainValidationError("Evidence payload contains forbidden scope")
        if payload.get("kind") != evidence.kind.value:
            raise DomainValidationError("Evidence kind does not match reservation")
        if payload.get("workspace_id") != evidence.workspace_id.value:
            raise DomainValidationError("Evidence Workspace does not match reservation")
        repository = connection.execute(
            "SELECT repository FROM tas_task_workspace_bindings WHERE id=?",
            (evidence.workspace_id.value,),
        ).fetchone()
        if repository is None or payload.get("repository") != str(repository[0]):
            raise DomainValidationError("Evidence Repository does not match Workspace")
        if payload.get("artifact_ids") != [
            item.value for item in evidence.artifact_ids
        ]:
            raise DomainValidationError("Evidence Artifacts do not match reservation")
        if evidence.kind is ObservedEvidenceKind.GIT:
            if payload.get("head_commit") != evidence.head_commit:
                raise DomainValidationError("Git Evidence commit does not match")
        else:
            retry = None if evidence.retry_of is None else {"value": evidence.retry_of.value}
            if (
                payload.get("commit") != evidence.head_commit
                or payload.get("attempt") != evidence.attempt
                or payload.get("retry_of") != retry
            ):
                raise DomainValidationError("Command Evidence attempt does not match")

    @staticmethod
    def _current_dependencies_are_valid(connection, evidence) -> bool:
        command = ReserveEvidenceCommand(
            evidence.task_id,
            evidence.workspace_id,
            evidence.kind,
            evidence.attempt,
            evidence.retry_of,
            evidence.observed_at,
            evidence.head_commit,
            evidence.artifact_ids,
        )
        return (
            SQLiteEvidenceSubmissionUnitOfWork._authorized_scope(
                connection, evidence.actor_id, command
            )
            and SQLiteEvidenceSubmissionUnitOfWork._retry_is_valid(
                connection, evidence.actor_id, command
            )
            and SQLiteEvidenceSubmissionUnitOfWork._artifacts_are_eligible(
                connection, evidence.actor_id, command
            )
        )

    @staticmethod
    def _authorized_evidence(connection, actor_id, evidence_id):
        row = connection.execute(
            "SELECT evidence.id,evidence.task_id,evidence.actor_agent_id,"
            "evidence.workspace_id,evidence.kind,evidence.attempt,evidence.retry_of,"
            "evidence.observed_at,evidence.head_commit,evidence.status,"
            "evidence.payload_sha256,evidence.created_at,evidence.finalized_at "
            "FROM tas_evidence_submissions evidence JOIN tas_tasks task "
            "ON task.id=evidence.task_id JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id WHERE evidence.id=? "
            "AND evidence.actor_agent_id=actor.id AND task.assignee_agent_id=actor.id",
            (actor_id.value, evidence_id),
        ).fetchone()
        if row is None:
            return None
        artifacts = tuple(
            ArtifactId(str(item[0]))
            for item in connection.execute(
                "SELECT artifact_id FROM tas_evidence_submission_artifacts "
                "WHERE evidence_id=? ORDER BY sequence",
                (evidence_id,),
            ).fetchall()
        )
        try:
            return EvidenceSubmission(
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
        except (DomainValidationError, TypeError, ValueError) as error:
            raise EvidenceSubmissionIntegrityError(
                "Persisted Evidence submission is invalid"
            ) from error

    @staticmethod
    def _verify_observed_snapshot(connection, evidence) -> None:
        row = connection.execute(
            "SELECT payload_sha256 FROM tas_observed_evidence WHERE id=? AND task_id=? "
            "AND actor_agent_id=? AND kind=? AND observed_at=?",
            (
                evidence.id.value,
                evidence.task_id.value,
                evidence.actor_id.value,
                evidence.kind.value,
                evidence.observed_at.isoformat(),
            ),
        ).fetchone()
        if row != (evidence.payload_sha256,):
            raise EvidenceSubmissionIntegrityError(
                "Finalized Evidence snapshot is invalid"
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
            return str(json.loads(str(row[1]))["evidence_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise EvidenceSubmissionIntegrityError("Evidence result is invalid") from error

    @staticmethod
    def _complete_ledger(
        connection, actor_id, operation, key, fingerprint, evidence_id, now
    ) -> None:
        result = json.dumps(
            {"evidence_id": evidence_id.value}, sort_keys=True, separators=(",", ":")
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
                    "evidence.write",
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
