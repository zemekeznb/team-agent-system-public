"""SQLite persistence for atomic Work Record promotion."""

import sqlite3
import re
import json
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.collaboration import TaskId
from tas.domain.epistemic import EpistemicEventId
from tas.domain.evidence import EvidenceId
from tas.domain.identity import AgentId
from tas.domain.memory import ApplicabilityReason, ApplicabilityStatus, MemoryApplicabilityAssessment, MemoryCodeScope, MemoryId, MemorySearchQuery, MemoryValidationStatus, TeamMemory
from tas.domain.ports import MemoryPersistenceError
from tas.domain.work_record import WorkRecordId, WorkRecordType


class SQLiteMemoryRepository:
    def __init__(self, database: str | Path) -> None: self.database = Path(database)
    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def add(self, memory: TeamMemory) -> None:
        if memory.applicability_status is not ApplicabilityStatus.UNKNOWN:
            raise MemoryPersistenceError("new Memory applicability must be unknown")
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                source = connection.execute(
                    "SELECT task_id,actor_agent_id,record_type,claim_text "
                    "FROM tas_work_records WHERE id=?",
                    (memory.source_work_record_id.value,),
                ).fetchone()
                expected_source = (
                    memory.task_id.value,
                    memory.source_actor_id.value,
                    memory.record_type.value,
                    memory.content,
                )
                if source != expected_source:
                    raise MemoryPersistenceError("Memory does not match its source Work Record")
                latest = connection.execute("SELECT id,to_status,rule_id FROM tas_epistemic_events WHERE work_record_id=? ORDER BY sequence DESC LIMIT 1", (memory.source_work_record_id.value,)).fetchone()
                if latest != (memory.source_validation_event_id.value, "validated", memory.validation_rule_id):
                    raise MemoryPersistenceError("source Work Record is no longer validated by the cited event")
                actual = tuple(EvidenceId(str(row[0])) for row in connection.execute("SELECT evidence_id FROM tas_epistemic_event_evidence WHERE epistemic_event_id=? ORDER BY sequence", (memory.source_validation_event_id.value,)))
                if actual != memory.evidence_ids: raise MemoryPersistenceError("validation Evidence snapshot changed")
                connection.execute("INSERT INTO tas_team_memories VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", (memory.id.value,memory.source_work_record_id.value,memory.source_validation_event_id.value,memory.task_id.value,memory.source_actor_id.value,memory.promoted_by_agent_id.value,memory.record_type.value,memory.content,memory.validation_rule_id,memory.validation_status.value,memory.applicability_status.value,memory.promotion_rule_id,memory.promoted_at.isoformat()))
                connection.executemany("INSERT INTO tas_team_memory_evidence VALUES (?,?,?)", [(memory.id.value,i,item.value) for i,item in enumerate(memory.evidence_ids,1)])
                connection.execute("COMMIT")
            except MemoryPersistenceError:
                connection.execute("ROLLBACK"); raise
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK"); raise MemoryPersistenceError("Memory could not be promoted") from error

    def get(self, memory_id: MemoryId) -> TeamMemory | None:
        with closing(self._connect()) as connection:
            row=connection.execute(
                "SELECT m.*,COALESCE((SELECT a.status FROM tas_memory_applicability_assessments a "
                "WHERE a.memory_id=m.id ORDER BY a.sequence DESC LIMIT 1),m.applicability_status) "
                "FROM tas_team_memories m WHERE m.id=?",(memory_id.value,)
            ).fetchone()
            if row is None: return None
            evidence=tuple(EvidenceId(str(item[0])) for item in connection.execute("SELECT evidence_id FROM tas_team_memory_evidence WHERE memory_id=? ORDER BY sequence",(memory_id.value,)))
        return TeamMemory(MemoryId(str(row[0])),WorkRecordId(str(row[1])),EpistemicEventId(str(row[2])),TaskId(str(row[3])),AgentId(str(row[4])),AgentId(str(row[5])),WorkRecordType(str(row[6])),str(row[7]),str(row[8]),evidence,MemoryValidationStatus(str(row[9])),ApplicabilityStatus(str(row[13])),str(row[11]),datetime.fromisoformat(str(row[12])))

    def search(self, query: MemorySearchQuery) -> tuple[TeamMemory, ...]:
        match = " AND ".join(f'"{token}"' for token in re.findall(r"\w+", query.text, flags=re.UNICODE))
        clauses = ["p.team_id=?", "m.task_id=t.id", "t.project_id=?", "s.repository=?"]
        values: list[object] = [match, query.team_id.value, query.project_id.value, query.repository]
        if query.validation_status is not None:
            clauses.append("m.validation_status=?")
            values.append(query.validation_status.value)
        if query.applicability_status is not None:
            clauses.append("COALESCE(a.status,m.applicability_status)=?")
            values.append(query.applicability_status.value)
        values.append(query.limit)
        sql = (
            "SELECT m.id FROM tas_team_memories_fts f "
            "JOIN tas_team_memories m ON m.rowid=f.rowid "
            "JOIN tas_tasks t ON t.id=m.task_id "
            "JOIN tas_projects p ON p.id=t.project_id "
            "JOIN tas_team_memory_code_scopes s ON s.memory_id=m.id "
            "LEFT JOIN tas_memory_applicability_assessments a ON a.memory_id=m.id AND a.sequence=(SELECT MAX(a2.sequence) FROM tas_memory_applicability_assessments a2 WHERE a2.memory_id=m.id) "
            "WHERE tas_team_memories_fts MATCH ? AND " + " AND ".join(clauses) +
            " ORDER BY bm25(tas_team_memories_fts),m.promoted_at,m.id LIMIT ?"
        )
        with closing(self._connect()) as connection:
            ids = [MemoryId(str(row[0])) for row in connection.execute(sql, values)]
        return tuple(item for identifier in ids if (item := self.get(identifier)) is not None)

    def add_code_scope(self, scope: MemoryCodeScope) -> None:
        with closing(self._connect()) as connection, connection:
            row=connection.execute("SELECT m.task_id,e.kind,e.payload_json FROM tas_team_memories m JOIN tas_observed_evidence e ON e.id=? WHERE m.id=? AND EXISTS(SELECT 1 FROM tas_team_memory_evidence l WHERE l.memory_id=m.id AND l.evidence_id=e.id)",(scope.source_evidence_id.value,scope.memory_id.value)).fetchone()
            if row is None: raise MemoryPersistenceError("scope Evidence is not cited by Memory")
            if str(row[1]) != "git": raise MemoryPersistenceError("code scope requires cited Git Evidence")
            project=connection.execute("SELECT project_id FROM tas_tasks WHERE id=?",(str(row[0]),)).fetchone()
            binding=connection.execute("SELECT project_id FROM tas_repository_bindings WHERE repository=?",(scope.repository,)).fetchone()
            payload=json.loads(str(row[2]))
            expected=(payload.get("repository"),payload.get("branch"),payload.get("head_commit"),tuple(sorted(item.get("path") for item in payload.get("files",[]))))
            if binding is None or project is None or binding[0] != project[0] or expected != (scope.repository,scope.ref,scope.commit,scope.paths): raise MemoryPersistenceError("code scope does not match Git Evidence and Project binding")
            try:
                connection.execute("INSERT INTO tas_team_memory_code_scopes VALUES (?,?,?,?,?)",(scope.memory_id.value,scope.source_evidence_id.value,scope.repository,scope.ref,scope.commit))
                connection.executemany("INSERT INTO tas_team_memory_code_paths VALUES (?,?,?)",[(scope.memory_id.value,i,p) for i,p in enumerate(scope.paths,1)])
            except sqlite3.IntegrityError as error: raise MemoryPersistenceError("code scope could not be appended") from error

    def get_code_scope(self, memory_id: MemoryId) -> MemoryCodeScope | None:
        with closing(self._connect()) as connection:
            row=connection.execute("SELECT source_evidence_id,repository,ref,commit_id FROM tas_team_memory_code_scopes WHERE memory_id=?",(memory_id.value,)).fetchone()
            if row is None:return None
            paths=tuple(str(p[0]) for p in connection.execute("SELECT path FROM tas_team_memory_code_paths WHERE memory_id=? ORDER BY sequence",(memory_id.value,)))
        return MemoryCodeScope(memory_id,EvidenceId(str(row[0])),str(row[1]),str(row[2]),str(row[3]),paths)

    def append_applicability(self, assessment: MemoryApplicabilityAssessment) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                scope = connection.execute(
                    "SELECT commit_id FROM tas_team_memory_code_scopes WHERE memory_id=?",
                    (assessment.memory_id.value,),
                ).fetchone()
                if scope is None or str(scope[0]) != assessment.memory_commit:
                    raise MemoryPersistenceError("assessment does not match Memory code scope")
                latest = connection.execute(
                    "SELECT id,sequence,checked_at FROM tas_memory_applicability_assessments "
                    "WHERE memory_id=? ORDER BY sequence DESC LIMIT 1",
                    (assessment.memory_id.value,),
                ).fetchone()
                expected = None if latest is None else str(latest[0])
                expected_sequence = 1 if latest is None else int(latest[1]) + 1
                if assessment.previous_assessment_id != expected or assessment.sequence != expected_sequence:
                    raise MemoryPersistenceError("applicability history changed; evaluate again")
                if latest is not None and datetime.fromisoformat(str(latest[2])) > assessment.checked_at:
                    raise MemoryPersistenceError("assessment time cannot move backwards")
                connection.execute(
                    "INSERT INTO tas_memory_applicability_assessments VALUES (?,?,?,?,?,?,?,?,?)",
                    (assessment.id,assessment.memory_id.value,assessment.sequence,
                     assessment.previous_assessment_id,assessment.status.value,assessment.reason.value,
                     assessment.memory_commit,assessment.current_commit,assessment.checked_at.isoformat()),
                )
                connection.executemany(
                    "INSERT INTO tas_memory_applicability_changed_paths VALUES (?,?,?)",
                    [(assessment.id,index,path) for index,path in enumerate(assessment.changed_paths,1)],
                )
                connection.execute("COMMIT")
            except MemoryPersistenceError:
                connection.execute("ROLLBACK"); raise
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK"); raise MemoryPersistenceError("applicability assessment could not be appended") from error

    def latest_applicability(self, memory_id: MemoryId) -> MemoryApplicabilityAssessment | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id,sequence,previous_assessment_id,status,reason,memory_commit,current_commit,checked_at "
                "FROM tas_memory_applicability_assessments WHERE memory_id=? ORDER BY sequence DESC LIMIT 1",
                (memory_id.value,),
            ).fetchone()
            if row is None:
                return None
            paths = tuple(str(item[0]) for item in connection.execute(
                "SELECT path FROM tas_memory_applicability_changed_paths WHERE assessment_id=? ORDER BY sequence",
                (str(row[0]),),
            ))
        return MemoryApplicabilityAssessment(str(row[0]),memory_id,int(row[1]),None if row[2] is None else str(row[2]),ApplicabilityStatus(str(row[3])),ApplicabilityReason(str(row[4])),str(row[5]),None if row[6] is None else str(row[6]),paths,datetime.fromisoformat(str(row[7])))
