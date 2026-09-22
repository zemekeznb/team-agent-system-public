"""SQLite transaction that reloads the authoritative Evidence Registry to validate."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.authoritative_validation import (
    ValidateWorkRecordCommand,
    ValidateWorkRecordResult,
    ValidationRule,
)
from tas.application.epistemic_validation import (
    assess_code_adaptation_claim,
    assess_test_success_claim,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import TaskId
from tas.domain.epistemic import (
    EpistemicEvent,
    EpistemicEventId,
    EpistemicStatus,
)
from tas.domain.evidence import EvidenceId, TaskWorkspaceBinding, WorkspaceBindingId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError
from tas.domain.work_record import (
    ObservedEvidence,
    ObservedEvidenceKind,
    WorkRecord,
    WorkRecordId,
    WorkRecordType,
)


class AuthoritativeValidationAccessError(PermissionError):
    """The Work Record is not visible to the authenticated Agent."""


class AuthoritativeValidationConflictError(RuntimeError):
    """Current authoritative Evidence or epistemic state rejects validation."""


class AuthoritativeValidationIntegrityError(RuntimeError):
    """Persisted validation state cannot be safely reconstructed."""


class SQLiteAuthoritativeValidationUnitOfWork:
    OPERATION = "work_record.validate"

    def __init__(
        self,
        database: str | Path,
        *,
        before_authoritative_transaction: Callable[[], None] | None = None,
        before_commit: Callable[[], None] | None = None,
    ) -> None:
        self.database = Path(database)
        self.before_authoritative_transaction = before_authoritative_transaction
        self.before_commit = before_commit

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def validate(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ValidateWorkRecordCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> ValidateWorkRecordResult:
        self._require_utc(occurred_at)
        fingerprint = fingerprint_payload({
            "work_record_id": command.work_record_id.value,
            "rule": command.rule.value,
        })

        # A test hook may interleave a concurrent Registry append after a stale
        # preflight read. The authoritative decision below always reloads inside
        # the write transaction and never commits this preflight snapshot.
        if self.before_authoritative_transaction is not None:
            with self._connect() as preflight:
                self._load_record(preflight, command.work_record_id)
                self._load_registry(preflight, command.work_record_id)
            self.before_authoritative_transaction()

        rejection_reason: str | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                try:
                    record = self._authorized_record(
                        connection, actor_id, command.work_record_id
                    )
                except (DomainValidationError, TypeError, ValueError) as error:
                    raise AuthoritativeValidationIntegrityError(
                        "Persisted Work Record state is invalid"
                    ) from error
                if record is None:
                    rejection_reason = "work_record_unavailable"
                    raise AuthoritativeValidationAccessError(
                        "Work Record is unavailable"
                    )
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
                    "WHERE actor_id=? AND operation=? AND idempotency_key=?",
                    (actor_id.value, self.OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    result = self._replay(
                        connection, ledger, fingerprint.value, record.id
                    )
                    connection.execute("COMMIT")
                    return result

                try:
                    history = self._load_history(connection, record.id)
                    registry = self._load_registry_for_scope(
                        connection, record.task_id, record.actor_id
                    )
                except (DomainValidationError, TypeError, ValueError) as error:
                    raise AuthoritativeValidationIntegrityError(
                        "Persisted Validation state is invalid"
                    ) from error
                try:
                    if command.rule is ValidationRule.TEST_SUCCESS:
                        event = assess_test_success_claim(
                            record,
                            history,
                            registered_evidence=registry,
                            event_id=EpistemicEventId(str(uuid4())),
                            occurred_at=occurred_at,
                        )
                    elif command.rule is ValidationRule.CODE_ADAPTATION:
                        try:
                            binding = self._load_workspace_binding(
                                connection, record.task_id
                            )
                        except (DomainValidationError, TypeError, ValueError) as error:
                            raise AuthoritativeValidationIntegrityError(
                                "Persisted Workspace Binding is invalid"
                            ) from error
                        if binding is None:
                            raise DomainValidationError(
                                "Task Workspace Binding is unavailable"
                            )
                        event = assess_code_adaptation_claim(
                            record, history, workspace_binding=binding,
                            registered_evidence=registry,
                            event_id=EpistemicEventId(str(uuid4())),
                            occurred_at=occurred_at,
                        )
                    else:  # Defensive boundary for non-domain callers.
                        raise TypeError("rule must be ValidationRule")
                except DomainValidationError as error:
                    rejection_reason = "validation_conflict"
                    raise AuthoritativeValidationConflictError(
                        "Authoritative Validation conflicts with current Evidence"
                    ) from error
                self._append_event(connection, event)
                result_json = json.dumps(
                    {"event_id": event.id.value},
                    sort_keys=True, separators=(",", ":"),
                )
                connection.execute(
                    "INSERT INTO tas_idempotency_records(actor_id,operation,"
                    "idempotency_key,request_fingerprint,status,reservation_token_hash,"
                    "result_json,created_at,updated_at) VALUES "
                    "(?,?,?,?, 'completed',NULL,?,?,?)",
                    (
                        actor_id.value, self.OPERATION, key.value,
                        fingerprint.value, result_json,
                        occurred_at.isoformat(), occurred_at.isoformat(),
                    ),
                )
                if self.before_commit is not None:
                    self.before_commit()
                connection.execute("COMMIT")
                return ValidateWorkRecordResult(event, replayed=False)
        except (AuthoritativeValidationAccessError, AuthoritativeValidationConflictError):
            if rejection_reason is not None:
                self._audit_rejection(
                    actor_id, command.work_record_id, rejection_reason,
                    occurred_at, correlation_id,
                )
            raise

    @staticmethod
    def _authorized_record(connection, actor_id, record_id):
        row = connection.execute(
            "SELECT record.id,record.task_id,record.actor_agent_id,record.record_type,"
            "record.claim_text,record.created_at FROM tas_work_records record "
            "JOIN tas_tasks task ON task.id=record.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id "
            "WHERE record.id=? AND record.actor_agent_id=? "
            "AND task.assignee_agent_id=?",
            (actor_id.value, record_id.value, actor_id.value, actor_id.value),
        ).fetchone()
        if row is None:
            return None
        return SQLiteAuthoritativeValidationUnitOfWork._restore_record(
            row,
            SQLiteAuthoritativeValidationUnitOfWork._load_record_evidence(
                connection, record_id
            ),
        )

    @staticmethod
    def _load_record(connection, record_id):
        row = connection.execute(
            "SELECT id,task_id,actor_agent_id,record_type,claim_text,created_at "
            "FROM tas_work_records WHERE id=?", (record_id.value,),
        ).fetchone()
        if row is None:
            return None
        return SQLiteAuthoritativeValidationUnitOfWork._restore_record(
            row,
            SQLiteAuthoritativeValidationUnitOfWork._load_record_evidence(
                connection, record_id
            ),
        )

    @staticmethod
    def _load_registry(connection, record_id):
        row = connection.execute(
            "SELECT task_id,actor_agent_id FROM tas_work_records WHERE id=?",
            (record_id.value,),
        ).fetchone()
        if row is None:
            return ()
        return SQLiteAuthoritativeValidationUnitOfWork._load_registry_for_scope(
            connection, TaskId(str(row[0])), AgentId(str(row[1]))
        )

    @staticmethod
    def _load_registry_for_scope(connection, task_id, actor_id):
        rows = connection.execute(
            "SELECT id,task_id,actor_agent_id,kind,payload_json,payload_sha256,"
            "observed_at FROM tas_observed_evidence WHERE task_id=? "
            "AND actor_agent_id=? ORDER BY observed_at,id",
            (task_id.value, actor_id.value),
        ).fetchall()
        return tuple(
            SQLiteAuthoritativeValidationUnitOfWork._restore_evidence(row)
            for row in rows
        )

    @staticmethod
    def _load_record_evidence(connection, record_id):
        rows = connection.execute(
            "SELECT evidence.id,evidence.task_id,evidence.actor_agent_id,evidence.kind,"
            "evidence.payload_json,evidence.payload_sha256,evidence.observed_at "
            "FROM tas_work_record_evidence link JOIN tas_observed_evidence evidence "
            "ON evidence.id=link.evidence_id WHERE link.work_record_id=? "
            "ORDER BY link.sequence",
            (record_id.value,),
        ).fetchall()
        return tuple(
            SQLiteAuthoritativeValidationUnitOfWork._restore_evidence(row)
            for row in rows
        )

    @staticmethod
    def _load_history(connection, record_id):
        rows = connection.execute(
            "SELECT id,work_record_id,sequence,from_status,to_status,rule_id,occurred_at "
            "FROM tas_epistemic_events WHERE work_record_id=? ORDER BY sequence",
            (record_id.value,),
        ).fetchall()
        return tuple(
            EpistemicEvent(
                EpistemicEventId(str(row[0])), WorkRecordId(str(row[1])),
                int(row[2]),
                None if row[3] is None else EpistemicStatus(str(row[3])),
                EpistemicStatus(str(row[4])), str(row[5]),
                tuple(
                    EvidenceId(str(item[0]))
                    for item in connection.execute(
                        "SELECT evidence_id FROM tas_epistemic_event_evidence "
                        "WHERE epistemic_event_id=? ORDER BY sequence", (str(row[0]),)
                    )
                ),
                datetime.fromisoformat(str(row[6])),
            )
            for row in rows
        )

    @staticmethod
    def _load_workspace_binding(connection, task_id):
        row = connection.execute(
            "SELECT id,task_id,actor_agent_id,repository,root_sha256,bound_at "
            "FROM tas_task_workspace_bindings WHERE task_id=?", (task_id.value,),
        ).fetchone()
        return None if row is None else TaskWorkspaceBinding(
            WorkspaceBindingId(str(row[0])), TaskId(str(row[1])), AgentId(str(row[2])),
            str(row[3]), str(row[4]), datetime.fromisoformat(str(row[5])),
        )

    @staticmethod
    def _append_event(connection, event):
        connection.execute(
            "INSERT INTO tas_epistemic_events(id,work_record_id,sequence,from_status,"
            "to_status,rule_id,occurred_at) VALUES (?,?,?,?,?,?,?)",
            (
                event.id.value, event.work_record_id.value, event.sequence,
                None if event.from_status is None else event.from_status.value,
                event.to_status.value, event.rule_id, event.occurred_at.isoformat(),
            ),
        )
        connection.executemany(
            "INSERT INTO tas_epistemic_event_evidence(epistemic_event_id,sequence,"
            "evidence_id) VALUES (?,?,?)",
            [
                (event.id.value, index, evidence_id.value)
                for index, evidence_id in enumerate(event.evidence_ids, start=1)
            ],
        )

    @staticmethod
    def _replay(connection, row, fingerprint, record_id):
        if row[0] != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            event_id = EpistemicEventId(json.loads(row[1])["event_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise AuthoritativeValidationIntegrityError(
                "Validation result is invalid"
            ) from error
        events = SQLiteAuthoritativeValidationUnitOfWork._load_history(
            connection, record_id
        )
        event = next((item for item in events if item.id == event_id), None)
        if event is None:
            raise AuthoritativeValidationIntegrityError(
                "Validation result references a missing Event"
            )
        return ValidateWorkRecordResult(event, replayed=True)

    def _audit_rejection(
        self, actor_id, record_id, reason, occurred_at, correlation_id
    ):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
                "resource_id,action,outcome,reason,occurred_at,policy_version,"
                "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                    AuditActorKind.AGENT.value, actor_id.value, "work_record",
                    record_id.value, self.OPERATION, AuditOutcome.REJECTED.value,
                    reason, occurred_at.isoformat(), None, correlation_id,
                ),
            )

    @staticmethod
    def _restore_record(row, evidence):
        return WorkRecord(
            WorkRecordId(str(row[0])), TaskId(str(row[1])), AgentId(str(row[2])),
            WorkRecordType(str(row[3])), None if row[4] is None else str(row[4]),
            evidence, datetime.fromisoformat(str(row[5])),
        )

    @staticmethod
    def _restore_evidence(row):
        return ObservedEvidence(
            EvidenceId(str(row[0])), TaskId(str(row[1])), AgentId(str(row[2])),
            ObservedEvidenceKind(str(row[3])), str(row[4]), str(row[5]),
            datetime.fromisoformat(str(row[6])),
        )

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("occurred_at must use UTC")
