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
from tas.domain.memory import ApplicabilityReason, ApplicabilityStatus, MemoryApplicabilityAssessment, MemoryCodeScope, MemoryId, MemoryRevision, MemorySearchQuery, MemoryValidationStatus, TeamMemory
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
        if memory.validation_status is not MemoryValidationStatus.VALIDATED:
            raise MemoryPersistenceError("new Memory validation must be validated")
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
            connection.execute("BEGIN")
            row=connection.execute(
                "SELECT m.*,CASE WHEN EXISTS(SELECT 1 FROM tas_memory_revisions r WHERE r.superseded_memory_id=m.id) "
                "THEN 'superseded' ELSE COALESCE((SELECT a.status FROM tas_memory_applicability_assessments a "
                "WHERE a.memory_id=m.id ORDER BY a.sequence DESC LIMIT 1),m.applicability_status) END,"
                "CASE WHEN COALESCE((SELECT e.to_status FROM tas_epistemic_events e "
                "WHERE e.work_record_id=m.source_work_record_id ORDER BY e.sequence DESC LIMIT 1),'missing')='validated' "
                "THEN m.validation_status ELSE 'invalidated' END "
                "FROM tas_team_memories m WHERE m.id=?",(memory_id.value,)
            ).fetchone()
            if row is None: return None
            evidence=tuple(EvidenceId(str(item[0])) for item in connection.execute("SELECT evidence_id FROM tas_team_memory_evidence WHERE memory_id=? ORDER BY sequence",(memory_id.value,)))
            connection.execute("COMMIT")
        return TeamMemory(MemoryId(str(row[0])),WorkRecordId(str(row[1])),EpistemicEventId(str(row[2])),TaskId(str(row[3])),AgentId(str(row[4])),AgentId(str(row[5])),WorkRecordType(str(row[6])),str(row[7]),str(row[8]),evidence,MemoryValidationStatus(str(row[14])),ApplicabilityStatus(str(row[13])),str(row[11]),datetime.fromisoformat(str(row[12])))

    def search(self, query: MemorySearchQuery) -> tuple[TeamMemory, ...]:
        match = " AND ".join(f'"{token}"' for token in re.findall(r"\w+", query.text, flags=re.UNICODE))
        clauses = ["p.team_id=?", "m.task_id=t.id", "t.project_id=?", "s.repository=?"]
        values: list[object] = [match, query.team_id.value, query.project_id.value, query.repository]
        if query.validation_status is not None:
            clauses.append("CASE WHEN COALESCE((SELECT e.to_status FROM tas_epistemic_events e WHERE e.work_record_id=m.source_work_record_id ORDER BY e.sequence DESC LIMIT 1),'missing')='validated' THEN m.validation_status ELSE 'invalidated' END=?")
            values.append(query.validation_status.value)
        if query.applicability_status is not None:
            clauses.append("CASE WHEN r.id IS NOT NULL THEN 'superseded' ELSE COALESCE(a.status,m.applicability_status) END=?")
            values.append(query.applicability_status.value)
        values.append(query.limit)
        sql = (
            "SELECT m.id FROM tas_team_memories_fts f "
            "JOIN tas_team_memories m ON m.rowid=f.rowid "
            "JOIN tas_tasks t ON t.id=m.task_id "
            "JOIN tas_projects p ON p.id=t.project_id "
            "JOIN tas_team_memory_code_scopes s ON s.memory_id=m.id "
            "LEFT JOIN tas_memory_applicability_assessments a ON a.memory_id=m.id AND a.sequence=(SELECT MAX(a2.sequence) FROM tas_memory_applicability_assessments a2 WHERE a2.memory_id=m.id) "
            "LEFT JOIN tas_memory_revisions r ON r.superseded_memory_id=m.id "
            "WHERE tas_team_memories_fts MATCH ? AND " + " AND ".join(clauses) +
            " ORDER BY bm25(tas_team_memories_fts),m.promoted_at,m.id LIMIT ?"
        )
        with closing(self._connect()) as connection:
            ids = [MemoryId(str(row[0])) for row in connection.execute(sql, values)]
        restored = tuple(
            item for identifier in ids if (item := self.get(identifier)) is not None
        )
        return tuple(
            item for item in restored
            if (query.validation_status is None or item.validation_status is query.validation_status)
            and (query.applicability_status is None or item.applicability_status is query.applicability_status)
        )

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
                if connection.execute("SELECT 1 FROM tas_memory_revisions WHERE superseded_memory_id=?",(assessment.memory_id.value,)).fetchone() is not None:
                    raise MemoryPersistenceError("superseded Memory cannot receive new applicability assessments")
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

    def add_revision(self, revision: MemoryRevision) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                rows = connection.execute(
                    "SELECT m.id,t.project_id,p.team_id,m.promoted_by_agent_id,m.promoted_at,s.repository,s.ref,s.commit_id,"
                    "m.source_validation_event_id,(SELECT e.id FROM tas_epistemic_events e WHERE e.work_record_id=m.source_work_record_id ORDER BY e.sequence DESC LIMIT 1),"
                    "(SELECT e.to_status FROM tas_epistemic_events e WHERE e.work_record_id=m.source_work_record_id ORDER BY e.sequence DESC LIMIT 1) "
                    "FROM tas_team_memories m JOIN tas_tasks t ON t.id=m.task_id JOIN tas_projects p ON p.id=t.project_id "
                    "JOIN tas_team_memory_code_scopes s ON s.memory_id=m.id WHERE m.id IN (?,?)",
                    (revision.superseded_memory_id.value,revision.replacement_memory_id.value),
                ).fetchall()
                values = {str(row[0]): row for row in rows}
                old = values.get(revision.superseded_memory_id.value); new = values.get(revision.replacement_memory_id.value)
                if old is None or new is None:
                    raise MemoryPersistenceError("revision endpoints require code-scoped Memories")
                if old[1:3] != new[1:3] or old[5:7] != new[5:7]:
                    raise MemoryPersistenceError("revision endpoints must share Team, Project, Repository, and Ref")
                if any(str(item[8]) != str(item[9]) or str(item[10]) != "validated" for item in (old,new)):
                    raise MemoryPersistenceError("revision endpoints must remain validated at decision time")
                if str(new[3]) != revision.actor_id.value:
                    raise MemoryPersistenceError("revision actor must be the replacement promoter")
                if str(old[7]) == str(new[7]):
                    raise MemoryPersistenceError("replacement must use a different code commit")
                old_paths = {str(row[0]) for row in connection.execute("SELECT path FROM tas_team_memory_code_paths WHERE memory_id=?",(revision.superseded_memory_id.value,))}
                new_paths = {str(row[0]) for row in connection.execute("SELECT path FROM tas_team_memory_code_paths WHERE memory_id=?",(revision.replacement_memory_id.value,))}
                if not old_paths.intersection(new_paths):
                    raise MemoryPersistenceError("revision code scopes must overlap")
                old_status = self._latest_status(connection, revision.superseded_memory_id.value)
                new_status = self._latest_status(connection, revision.replacement_memory_id.value)
                if old_status != ApplicabilityStatus.POSSIBLY_STALE.value:
                    raise MemoryPersistenceError("only a possibly stale Memory can be superseded in F2")
                if new_status not in (ApplicabilityStatus.EXACT.value,ApplicabilityStatus.COMPATIBLE.value):
                    raise MemoryPersistenceError("replacement Memory must have current applicability")
                old_current = self._latest_current_commit(connection, revision.superseded_memory_id.value)
                new_current = self._latest_current_commit(connection, revision.replacement_memory_id.value)
                if old_current is None or old_current != new_current:
                    raise MemoryPersistenceError("revision endpoints must be assessed against the same current commit")
                if connection.execute("SELECT 1 FROM tas_memory_revisions WHERE superseded_memory_id=?",(revision.replacement_memory_id.value,)).fetchone() is not None:
                    raise MemoryPersistenceError("replacement Memory is already superseded")
                if revision.occurred_at < max(datetime.fromisoformat(str(old[4])),datetime.fromisoformat(str(new[4]))):
                    raise MemoryPersistenceError("revision cannot predate its Memories")
                if connection.execute(
                    "WITH RECURSIVE chain(id) AS (SELECT ? UNION ALL SELECT r.replacement_memory_id FROM tas_memory_revisions r JOIN chain c ON r.superseded_memory_id=c.id) SELECT 1 FROM chain WHERE id=? LIMIT 1",
                    (revision.replacement_memory_id.value,revision.superseded_memory_id.value),
                ).fetchone() is not None:
                    raise MemoryPersistenceError("Memory revision would create a cycle")
                connection.execute("INSERT INTO tas_memory_revisions VALUES (?,?,?,?,?,?)",(
                    revision.id,revision.superseded_memory_id.value,revision.replacement_memory_id.value,
                    revision.actor_id.value,revision.reason,revision.occurred_at.isoformat(),
                ))
                connection.execute("COMMIT")
            except MemoryPersistenceError:
                connection.execute("ROLLBACK"); raise
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK"); raise MemoryPersistenceError("Memory revision could not be appended") from error

    @staticmethod
    def _latest_status(connection: sqlite3.Connection, memory_id: str) -> str:
        row = connection.execute(
            "SELECT status FROM tas_memory_applicability_assessments WHERE memory_id=? ORDER BY sequence DESC LIMIT 1",
            (memory_id,),
        ).fetchone()
        return ApplicabilityStatus.UNKNOWN.value if row is None else str(row[0])

    @staticmethod
    def _latest_current_commit(connection: sqlite3.Connection, memory_id: str) -> str | None:
        row = connection.execute(
            "SELECT current_commit FROM tas_memory_applicability_assessments WHERE memory_id=? ORDER BY sequence DESC LIMIT 1",
            (memory_id,),
        ).fetchone()
        return None if row is None or row[0] is None else str(row[0])

    def get_revision(self, superseded_memory_id: MemoryId) -> MemoryRevision | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id,replacement_memory_id,actor_agent_id,reason,occurred_at FROM tas_memory_revisions WHERE superseded_memory_id=?",
                (superseded_memory_id.value,),
            ).fetchone()
        if row is None: return None
        return MemoryRevision(str(row[0]),superseded_memory_id,MemoryId(str(row[1])),AgentId(str(row[2])),str(row[3]),datetime.fromisoformat(str(row[4])))
