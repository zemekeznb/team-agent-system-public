"""SQLite boundary for F3 Work Record writes and authorized knowledge reads."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.knowledge_access import (
    CreateWorkRecordCommand,
    MemoryCommandResult,
    MemoryView,
    MemorySearchRequest,
    PromoteMemoryCommand,
    WorkRecordCommandResult,
    WorkRecordView,
)
from tas.application.memory_applicability import code_scope_from_git_evidence
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import TaskId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.epistemic import (
    EpistemicEvent,
    EpistemicEventId,
    EpistemicStatus,
    initial_epistemic_event,
)
from tas.domain.evidence import EvidenceId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError, TeamId
from tas.domain.memory import (
    ApplicabilityReason,
    ApplicabilityStatus,
    MemoryApplicabilityAssessment,
    MemoryCodeScope,
    MemoryId,
    MemorySearchQuery,
    MemoryValidationStatus,
    TeamMemory,
    promote_validated_work_record,
)
from tas.domain.work_record import (
    ObservedEvidence,
    ObservedEvidenceKind,
    WorkRecord,
    WorkRecordId,
    WorkRecordType,
)


class KnowledgeAccessError(PermissionError):
    """The requested Task, Work Record, Evidence, or Memory is unavailable."""


class KnowledgeIntegrityError(RuntimeError):
    """Persisted knowledge state cannot be safely reconstructed."""


class KnowledgeConflictError(RuntimeError):
    """Knowledge operation conflicts with current immutable state."""


class SQLiteKnowledgeAccessUnitOfWork:
    CREATE_OPERATION = "work_record.create"
    PROMOTE_OPERATION = "memory.promote"

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def create_work_record(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: CreateWorkRecordCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> WorkRecordCommandResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload(
            {
                "task_id": command.task_id.value,
                "record_type": command.record_type.value,
                "claim_text": command.claim_text,
                "evidence_ids": [item.value for item in command.evidence_ids],
            }
        ).value
        rejection = "work_record_scope_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if not self._authorized_task(connection, actor_id, command.task_id):
                    raise KnowledgeAccessError("Work Record scope is unavailable")
                try:
                    replay = self._ledger(
                        connection, actor_id, key, fingerprint
                    )
                except IdempotencyConflictError:
                    rejection = "work_record_idempotency_conflict"
                    raise
                if replay is not None:
                    view = self._authorized_agent_record(
                        connection, actor_id, WorkRecordId(replay)
                    )
                    if view is None:
                        raise KnowledgeIntegrityError(
                            "Work Record replay result is unavailable"
                        )
                    connection.execute("COMMIT")
                    return WorkRecordCommandResult(view, replayed=True)

                try:
                    observed = self._load_finalized_evidence(
                        connection, actor_id, command.task_id, command.evidence_ids
                    )
                except KnowledgeAccessError:
                    rejection = "work_record_evidence_unavailable"
                    raise
                record = WorkRecord(
                    WorkRecordId(str(uuid4())),
                    command.task_id,
                    actor_id,
                    command.record_type,
                    command.claim_text,
                    observed,
                    now,
                )
                connection.execute(
                    "INSERT INTO tas_work_records(id,task_id,actor_agent_id,"
                    "record_type,claim_text,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        record.id.value,
                        record.task_id.value,
                        record.actor_id.value,
                        record.record_type.value,
                        record.claim_text,
                        record.created_at.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO tas_work_record_evidence"
                    "(work_record_id,sequence,evidence_id) VALUES (?,?,?)",
                    [
                        (record.id.value, index, evidence.id.value)
                        for index, evidence in enumerate(record.observed, start=1)
                    ],
                )
                initial = initial_epistemic_event(
                    record,
                    event_id=EpistemicEventId(f"initial:{record.id.value}"),
                    occurred_at=now,
                )
                connection.execute(
                    "INSERT INTO tas_epistemic_events(id,work_record_id,sequence,"
                    "from_status,to_status,rule_id,occurred_at) VALUES (?,?,?,?,?,?,?)",
                    (
                        initial.id.value,
                        initial.work_record_id.value,
                        initial.sequence,
                        None,
                        initial.to_status.value,
                        initial.rule_id,
                        initial.occurred_at.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO tas_epistemic_event_evidence"
                    "(epistemic_event_id,sequence,evidence_id) VALUES (?,?,?)",
                    [
                        (initial.id.value, index, evidence_id.value)
                        for index, evidence_id in enumerate(
                            initial.evidence_ids, start=1
                        )
                    ],
                )
                connection.execute(
                    "INSERT INTO tas_work_record_submissions VALUES (?,?)",
                    (record.id.value, now.isoformat()),
                )
                self._complete_ledger(
                    connection, actor_id, key, fingerprint, record.id, now
                )
                view = self._authorized_agent_record(connection, actor_id, record.id)
                if view is None:
                    raise KnowledgeIntegrityError(
                        "Created Work Record could not be restored"
                    )
                connection.execute("COMMIT")
                return WorkRecordCommandResult(view, replayed=False)
        except (KnowledgeAccessError, IdempotencyConflictError):
            self._audit_rejection(
                actor_id,
                "task",
                command.task_id.value,
                rejection,
                now,
                correlation_id,
            )
            raise
        except sqlite3.IntegrityError as error:
            raise KnowledgeIntegrityError(
                "Work Record could not be committed"
            ) from error

    def get_work_record(
        self, principal: AuthenticatedPrincipal, record_id: WorkRecordId
    ) -> WorkRecordView | None:
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                "SELECT record.id,record.task_id,record.actor_agent_id,"
                "record.record_type,record.claim_text,record.created_at "
                "FROM tas_work_records record JOIN tas_tasks task "
                "ON task.id=record.task_id JOIN tas_projects project "
                "ON project.id=task.project_id JOIN tas_agents author "
                "ON author.id=record.actor_agent_id JOIN tas_team_memberships member "
                "ON member.team_id=project.team_id AND member.owner_id=? "
                "WHERE record.id=? AND author.owner_id=? AND "
                "task.assignee_agent_id=record.actor_agent_id AND "
                "(? IS NULL OR record.actor_agent_id=?)",
                (
                    principal.owner_id.value,
                    record_id.value,
                    principal.owner_id.value,
                    None if principal.agent_id is None else principal.agent_id.value,
                    None if principal.agent_id is None else principal.agent_id.value,
                ),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            try:
                view = self._restore_work_record_view(connection, row)
            except (DomainValidationError, TypeError, ValueError) as error:
                raise KnowledgeIntegrityError(
                    "Persisted Work Record is invalid"
                ) from error
            connection.execute("COMMIT")
            return view

    def promote_memory(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: PromoteMemoryCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> MemoryCommandResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload(
            {
                "source_work_record_id": command.source_work_record_id.value,
                "code_scope_evidence_id": command.code_scope_evidence_id.value,
            }
        ).value
        rejection = "memory_source_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                view = self._authorized_agent_record(
                    connection, actor_id, command.source_work_record_id
                )
                if view is None:
                    raise KnowledgeAccessError("Memory source is unavailable")
                replay = self._memory_ledger(
                    connection, actor_id, key, fingerprint
                )
                if replay is not None:
                    restored = self._authorized_agent_memory(
                        connection, actor_id, MemoryId(replay)
                    )
                    if restored is None:
                        exists = connection.execute(
                            "SELECT 1 FROM tas_team_memories memory "
                            "JOIN tas_team_memory_code_scopes scope "
                            "ON scope.memory_id=memory.id WHERE memory.id=?",
                            (replay,),
                        ).fetchone()
                        if exists is not None:
                            rejection = "memory_scope_unavailable"
                            raise KnowledgeAccessError(
                                "Memory scope is unavailable"
                            )
                        raise KnowledgeIntegrityError(
                            "Memory replay result is unavailable"
                        )
                    connection.execute("COMMIT")
                    return MemoryCommandResult(restored, replayed=True)

                if connection.execute(
                    "SELECT 1 FROM tas_team_memories "
                    "WHERE source_work_record_id=?",
                    (command.source_work_record_id.value,),
                ).fetchone() is not None:
                    rejection = "memory_already_promoted"
                    raise KnowledgeConflictError(
                        "Work Record was already promoted"
                    )

                history = self._restore_epistemic_history(
                    connection, command.source_work_record_id
                )
                try:
                    memory = promote_validated_work_record(
                        view.record,
                        history,
                        memory_id=MemoryId(str(uuid4())),
                        promoted_by=actor_id,
                        promoted_at=now,
                    )
                    scope = code_scope_from_git_evidence(
                        memory,
                        view.record,
                        evidence_id=command.code_scope_evidence_id,
                    )
                except DomainValidationError as error:
                    rejection = "memory_source_not_promotable"
                    raise KnowledgeConflictError(
                        "Work Record cannot be promoted"
                    ) from error
                if not self._scope_matches_current_project(
                    connection, memory.task_id, scope
                ):
                    rejection = "memory_scope_unavailable"
                    raise KnowledgeAccessError("Memory scope is unavailable")

                self._insert_memory(connection, memory, scope)
                self._complete_memory_ledger(
                    connection, actor_id, key, fingerprint, memory.id, now
                )
                restored = self._authorized_agent_memory(
                    connection, actor_id, memory.id
                )
                if restored is None:
                    raise KnowledgeIntegrityError(
                        "Promoted Memory could not be restored"
                    )
                connection.execute("COMMIT")
                return MemoryCommandResult(restored, replayed=False)
        except IdempotencyConflictError:
            rejection = "memory_idempotency_conflict"
            self._audit_rejection(
                actor_id, "work_record", command.source_work_record_id.value,
                rejection, now, correlation_id, action="memory.promote",
            )
            raise
        except (KnowledgeAccessError, KnowledgeConflictError):
            self._audit_rejection(
                actor_id, "work_record", command.source_work_record_id.value,
                rejection, now, correlation_id, action="memory.promote",
            )
            raise
        except sqlite3.IntegrityError as error:
            raise KnowledgeIntegrityError("Memory could not be promoted") from error

    def get_memory(
        self, principal: AuthenticatedPrincipal, memory_id: MemoryId
    ) -> MemoryView | None:
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute(
                self._memory_select()
                + " JOIN tas_tasks task ON task.id=m.task_id "
                "JOIN tas_projects project ON project.id=task.project_id "
                "JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "AND member.owner_id=? WHERE m.id=?",
                (principal.owner_id.value, memory_id.value),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            try:
                memory = self._restore_memory_view(connection, row)
            except (DomainValidationError, TypeError, ValueError) as error:
                raise KnowledgeIntegrityError("Persisted Memory is invalid") from error
            connection.execute("COMMIT")
            return memory

    def search_memories(
        self, principal: AuthenticatedPrincipal, request: MemorySearchRequest
    ) -> tuple[MemoryView, ...]:
        with self._connect() as connection:
            connection.execute("BEGIN")
            scope = connection.execute(
                "SELECT project.team_id FROM tas_projects project "
                "JOIN tas_team_memberships member ON member.team_id=project.team_id "
                "AND member.owner_id=? JOIN tas_repository_bindings binding "
                "ON binding.project_id=project.id AND binding.repository=? "
                "WHERE project.id=?",
                (
                    principal.owner_id.value,
                    request.repository,
                    request.project_id.value,
                ),
            ).fetchone()
            if scope is None:
                connection.execute("COMMIT")
                raise KnowledgeAccessError("Memory search scope is unavailable")
            query = MemorySearchQuery(
                request.text,
                TeamId(str(scope[0])),
                request.project_id,
                request.repository,
                request.validation_status,
                request.applicability_status,
                request.limit,
            )
            match = " AND ".join(
                f'"{token}"'
                for token in re.findall(r"\w+", query.text, flags=re.UNICODE)
            )
            clauses = [
                "project.team_id=?",
                "task.project_id=?",
                "code.repository=?",
            ]
            values: list[object] = [
                match,
                query.team_id.value,
                query.project_id.value,
                query.repository,
            ]
            effective_validation = self._effective_validation_sql("m")
            effective_applicability = self._effective_applicability_sql("m")
            if query.validation_status is not None:
                clauses.append(effective_validation + "=?")
                values.append(query.validation_status.value)
            if query.applicability_status is not None:
                clauses.append(effective_applicability + "=?")
                values.append(query.applicability_status.value)
            values.append(query.limit)
            rows = connection.execute(
                "SELECT m.id," + effective_applicability + "," +
                effective_validation + " FROM tas_team_memories_fts f "
                "JOIN tas_team_memories m ON m.rowid=f.rowid "
                "JOIN tas_tasks task ON task.id=m.task_id "
                "JOIN tas_projects project ON project.id=task.project_id "
                "JOIN tas_team_memory_code_scopes code ON code.memory_id=m.id "
                "WHERE tas_team_memories_fts MATCH ? AND "
                + " AND ".join(clauses)
                + " ORDER BY bm25(tas_team_memories_fts),m.promoted_at,m.id LIMIT ?",
                values,
            ).fetchall()
            memories: list[MemoryView] = []
            try:
                for identifier, applicability, validation in rows:
                    base = connection.execute(
                        "SELECT m.*,? AS effective_applicability,"
                        "? AS effective_validation FROM tas_team_memories m "
                        "WHERE m.id=?",
                        (applicability, validation, str(identifier)),
                    ).fetchone()
                    if base is None:
                        raise KnowledgeIntegrityError(
                            "Memory search result disappeared"
                        )
                    memories.append(self._restore_memory_view(connection, base))
            except (DomainValidationError, TypeError, ValueError) as error:
                raise KnowledgeIntegrityError("Persisted Memory is invalid") from error
            connection.execute("COMMIT")
            return tuple(memories)

    @staticmethod
    def _authorized_task(connection, actor_id, task_id) -> bool:
        return connection.execute(
            "SELECT 1 FROM tas_tasks task JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id WHERE task.id=? "
            "AND task.assignee_agent_id=actor.id",
            (actor_id.value, task_id.value),
        ).fetchone() is not None

    @staticmethod
    def _load_finalized_evidence(
        connection, actor_id, task_id, evidence_ids
    ) -> tuple[ObservedEvidence, ...]:
        if not evidence_ids:
            return ()
        rows = connection.execute(
            "SELECT observed.id,observed.task_id,observed.actor_agent_id,"
            "observed.kind,observed.payload_json,observed.payload_sha256,"
            "observed.observed_at FROM tas_observed_evidence observed "
            "JOIN tas_evidence_submissions submission ON submission.id=observed.id "
            "AND submission.status='finalized' WHERE observed.id IN ({}) "
            "AND observed.task_id=? AND observed.actor_agent_id=?".format(
                ",".join("?" for _ in evidence_ids)
            ),
            tuple(item.value for item in evidence_ids)
            + (task_id.value, actor_id.value),
        ).fetchall()
        indexed = {str(row[0]): row for row in rows}
        if set(indexed) != {item.value for item in evidence_ids}:
            raise KnowledgeAccessError("Work Record Evidence is unavailable")
        return tuple(
            SQLiteKnowledgeAccessUnitOfWork._restore_evidence(
                indexed[identifier.value]
            )
            for identifier in evidence_ids
        )

    @staticmethod
    def _restore_evidence(row) -> ObservedEvidence:
        return ObservedEvidence(
            EvidenceId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            ObservedEvidenceKind(str(row[3])),
            str(row[4]),
            str(row[5]),
            datetime.fromisoformat(str(row[6])),
        )

    @staticmethod
    def _restore_work_record_view(connection, row) -> WorkRecordView:
        evidence_rows = connection.execute(
            "SELECT observed.id,observed.task_id,observed.actor_agent_id,"
            "observed.kind,observed.payload_json,observed.payload_sha256,"
            "observed.observed_at FROM tas_work_record_evidence link "
            "JOIN tas_observed_evidence observed ON observed.id=link.evidence_id "
            "WHERE link.work_record_id=? ORDER BY link.sequence",
            (str(row[0]),),
        ).fetchall()
        record = WorkRecord(
            WorkRecordId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            WorkRecordType(str(row[3])),
            None if row[4] is None else str(row[4]),
            tuple(
                SQLiteKnowledgeAccessUnitOfWork._restore_evidence(item)
                for item in evidence_rows
            ),
            datetime.fromisoformat(str(row[5])),
        )
        latest = connection.execute(
            "SELECT id,sequence,to_status FROM tas_epistemic_events "
            "WHERE work_record_id=? ORDER BY sequence DESC LIMIT 1",
            (record.id.value,),
        ).fetchone()
        if latest is None:
            raise KnowledgeIntegrityError("Work Record epistemic state is missing")
        return WorkRecordView(
            record,
            EpistemicStatus(str(latest[2])),
            EpistemicEventId(str(latest[0])),
            int(latest[1]),
        )

    @staticmethod
    def _restore_epistemic_history(connection, record_id):
        events = []
        for row in connection.execute(
            "SELECT id,sequence,from_status,to_status,rule_id,occurred_at "
            "FROM tas_epistemic_events WHERE work_record_id=? ORDER BY sequence",
            (record_id.value,),
        ).fetchall():
            evidence = tuple(
                EvidenceId(str(item[0]))
                for item in connection.execute(
                    "SELECT evidence_id FROM tas_epistemic_event_evidence "
                    "WHERE epistemic_event_id=? ORDER BY sequence",
                    (str(row[0]),),
                ).fetchall()
            )
            events.append(
                EpistemicEvent(
                    EpistemicEventId(str(row[0])),
                    record_id,
                    int(row[1]),
                    None if row[2] is None else EpistemicStatus(str(row[2])),
                    EpistemicStatus(str(row[3])),
                    str(row[4]),
                    evidence,
                    datetime.fromisoformat(str(row[5])),
                )
            )
        return tuple(events)

    @staticmethod
    def _authorized_agent_record(connection, actor_id, record_id):
        row = connection.execute(
            "SELECT record.id,record.task_id,record.actor_agent_id,"
            "record.record_type,record.claim_text,record.created_at "
            "FROM tas_work_records record JOIN tas_work_record_submissions submission "
            "ON submission.work_record_id=record.id JOIN tas_tasks task "
            "ON task.id=record.task_id JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id WHERE record.id=? "
            "AND record.actor_agent_id=actor.id AND task.assignee_agent_id=actor.id",
            (actor_id.value, record_id.value),
        ).fetchone()
        if row is None:
            return None
        return SQLiteKnowledgeAccessUnitOfWork._restore_work_record_view(
            connection, row
        )

    @classmethod
    def _authorized_agent_memory(cls, connection, actor_id, memory_id):
        row = connection.execute(
            cls._memory_select()
            + " JOIN tas_tasks task ON task.id=m.task_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_team_memory_code_scopes scope ON scope.memory_id=m.id "
            "JOIN tas_repository_bindings binding "
            "ON binding.repository=scope.repository "
            "AND binding.project_id=task.project_id "
            "JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id WHERE m.id=? "
            "AND m.source_actor_agent_id=actor.id "
            "AND m.promoted_by_agent_id=actor.id "
            "AND task.assignee_agent_id=actor.id",
            (actor_id.value, memory_id.value),
        ).fetchone()
        if row is None:
            return None
        return cls._restore_memory_view(connection, row)

    @staticmethod
    def _scope_matches_current_project(connection, task_id, scope):
        row = connection.execute(
            "SELECT task.project_id,binding.project_id "
            "FROM tas_tasks task LEFT JOIN tas_repository_bindings binding "
            "ON binding.repository=? WHERE task.id=?",
            (scope.repository, task_id.value),
        ).fetchone()
        return row is not None and row[1] is not None and row[0] == row[1]

    @staticmethod
    def _insert_memory(connection, memory, scope):
        connection.execute(
            "INSERT INTO tas_team_memories VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                memory.id.value,
                memory.source_work_record_id.value,
                memory.source_validation_event_id.value,
                memory.task_id.value,
                memory.source_actor_id.value,
                memory.promoted_by_agent_id.value,
                memory.record_type.value,
                memory.content,
                memory.validation_rule_id,
                memory.validation_status.value,
                memory.applicability_status.value,
                memory.promotion_rule_id,
                memory.promoted_at.isoformat(),
            ),
        )
        connection.executemany(
            "INSERT INTO tas_team_memory_evidence VALUES (?,?,?)",
            [
                (memory.id.value, index, evidence_id.value)
                for index, evidence_id in enumerate(memory.evidence_ids, start=1)
            ],
        )
        connection.execute(
            "INSERT INTO tas_team_memory_code_scopes VALUES (?,?,?,?,?)",
            (
                memory.id.value,
                scope.source_evidence_id.value,
                scope.repository,
                scope.ref,
                scope.commit,
            ),
        )
        connection.executemany(
            "INSERT INTO tas_team_memory_code_paths VALUES (?,?,?)",
            [
                (memory.id.value, index, path)
                for index, path in enumerate(scope.paths, start=1)
            ],
        )
        connection.execute(
            "INSERT INTO tas_memory_promotions(memory_id,recorded_at) VALUES (?,?)",
            (memory.id.value, memory.promoted_at.isoformat()),
        )

    @staticmethod
    def _effective_validation_sql(alias: str) -> str:
        return (
            "CASE WHEN COALESCE((SELECT event.to_status FROM tas_epistemic_events "
            f"event WHERE event.work_record_id={alias}.source_work_record_id "
            "ORDER BY event.sequence DESC LIMIT 1),'missing')='validated' "
            f"THEN {alias}.validation_status ELSE 'invalidated' END"
        )

    @staticmethod
    def _effective_applicability_sql(alias: str) -> str:
        return (
            "CASE WHEN EXISTS(SELECT 1 FROM tas_memory_revisions revision "
            f"WHERE revision.superseded_memory_id={alias}.id) THEN 'superseded' "
            "ELSE COALESCE((SELECT assessment.status FROM "
            "tas_memory_applicability_assessments assessment "
            f"WHERE assessment.memory_id={alias}.id ORDER BY assessment.sequence "
            f"DESC LIMIT 1),{alias}.applicability_status) END"
        )

    @classmethod
    def _memory_select(cls) -> str:
        return (
            "SELECT m.*," + cls._effective_applicability_sql("m") + "," +
            cls._effective_validation_sql("m") + " FROM tas_team_memories m"
        )

    @staticmethod
    def _restore_memory(connection, row) -> TeamMemory:
        evidence = tuple(
            EvidenceId(str(item[0]))
            for item in connection.execute(
                "SELECT evidence_id FROM tas_team_memory_evidence "
                "WHERE memory_id=? ORDER BY sequence",
                (str(row[0]),),
            ).fetchall()
        )
        return TeamMemory(
            MemoryId(str(row[0])),
            WorkRecordId(str(row[1])),
            EpistemicEventId(str(row[2])),
            TaskId(str(row[3])),
            AgentId(str(row[4])),
            AgentId(str(row[5])),
            WorkRecordType(str(row[6])),
            str(row[7]),
            str(row[8]),
            evidence,
            MemoryValidationStatus(str(row[14])),
            ApplicabilityStatus(str(row[13])),
            str(row[11]),
            datetime.fromisoformat(str(row[12])),
        )

    @staticmethod
    def _restore_memory_view(connection, row) -> MemoryView:
        memory = SQLiteKnowledgeAccessUnitOfWork._restore_memory(connection, row)
        scope_row = connection.execute(
            "SELECT source_evidence_id,repository,ref,commit_id FROM "
            "tas_team_memory_code_scopes WHERE memory_id=?",
            (memory.id.value,),
        ).fetchone()
        code_scope = None
        if scope_row is not None:
            paths = tuple(
                str(item[0])
                for item in connection.execute(
                    "SELECT path FROM tas_team_memory_code_paths "
                    "WHERE memory_id=? ORDER BY sequence",
                    (memory.id.value,),
                ).fetchall()
            )
            code_scope = MemoryCodeScope(
                memory.id,
                EvidenceId(str(scope_row[0])),
                str(scope_row[1]),
                str(scope_row[2]),
                str(scope_row[3]),
                paths,
            )
        applicability_row = connection.execute(
            "SELECT id,sequence,previous_assessment_id,status,reason,memory_commit,"
            "current_commit,checked_at FROM tas_memory_applicability_assessments "
            "WHERE memory_id=? ORDER BY sequence DESC LIMIT 1",
            (memory.id.value,),
        ).fetchone()
        applicability = None
        if applicability_row is not None:
            changed_paths = tuple(
                str(item[0])
                for item in connection.execute(
                    "SELECT path FROM tas_memory_applicability_changed_paths "
                    "WHERE assessment_id=? ORDER BY sequence",
                    (str(applicability_row[0]),),
                ).fetchall()
            )
            applicability = MemoryApplicabilityAssessment(
                str(applicability_row[0]),
                memory.id,
                int(applicability_row[1]),
                None if applicability_row[2] is None else str(applicability_row[2]),
                ApplicabilityStatus(str(applicability_row[3])),
                ApplicabilityReason(str(applicability_row[4])),
                str(applicability_row[5]),
                None if applicability_row[6] is None else str(applicability_row[6]),
                changed_paths,
                datetime.fromisoformat(str(applicability_row[7])),
            )
        replacement = connection.execute(
            "SELECT replacement_memory_id FROM tas_memory_revisions "
            "WHERE superseded_memory_id=?",
            (memory.id.value,),
        ).fetchone()
        return MemoryView(
            memory,
            code_scope,
            applicability,
            None if replacement is None else MemoryId(str(replacement[0])),
        )

    @classmethod
    def _ledger(cls, connection, actor_id, key, fingerprint):
        row = connection.execute(
            "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
            "WHERE actor_id=? AND operation=? AND idempotency_key=?",
            (actor_id.value, cls.CREATE_OPERATION, key.value),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            return str(json.loads(str(row[1]))["work_record_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise KnowledgeIntegrityError("Work Record result is invalid") from error

    @classmethod
    def _complete_ledger(
        cls, connection, actor_id, key, fingerprint, record_id, now
    ) -> None:
        result = json.dumps(
            {"work_record_id": record_id.value},
            sort_keys=True,
            separators=(",", ":"),
        )
        connection.execute(
            "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,"
            "request_fingerprint,status,reservation_token_hash,result_json,created_at,"
            "updated_at) VALUES (?,?,?,?,'completed',NULL,?,?,?)",
            (
                actor_id.value,
                cls.CREATE_OPERATION,
                key.value,
                fingerprint,
                result,
                now.isoformat(),
                now.isoformat(),
            ),
        )

    @classmethod
    def _memory_ledger(cls, connection, actor_id, key, fingerprint):
        row = connection.execute(
            "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
            "WHERE actor_id=? AND operation=? AND idempotency_key=?",
            (actor_id.value, cls.PROMOTE_OPERATION, key.value),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            return str(json.loads(str(row[1]))["memory_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise KnowledgeIntegrityError("Memory result is invalid") from error

    @classmethod
    def _complete_memory_ledger(
        cls, connection, actor_id, key, fingerprint, memory_id, now
    ):
        result = json.dumps(
            {"memory_id": memory_id.value}, sort_keys=True, separators=(",", ":")
        )
        connection.execute(
            "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,"
            "request_fingerprint,status,reservation_token_hash,result_json,created_at,"
            "updated_at) VALUES (?,?,?,?,'completed',NULL,?,?,?)",
            (
                actor_id.value,
                cls.PROMOTE_OPERATION,
                key.value,
                fingerprint,
                result,
                now.isoformat(),
                now.isoformat(),
            ),
        )

    def _audit_rejection(
        self, actor_id, resource_type, resource_id, reason, now, correlation_id,
        *, action="work_record.create",
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,"
                "resource_type,resource_id,action,outcome,reason,occurred_at,"
                "policy_version,correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()),
                    AuditEventKind.AUTHORIZATION_DECISION.value,
                    AuditActorKind.AGENT.value,
                    actor_id.value,
                    resource_type,
                    resource_id,
                    action,
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
