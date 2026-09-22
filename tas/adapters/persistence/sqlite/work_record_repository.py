"""Append-only SQLite Work Record and observed Evidence persistence."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.collaboration import TaskId
from tas.domain.evidence import EvidenceId
from tas.domain.epistemic import EpistemicEventId, initial_epistemic_event
from tas.domain.identity import AgentId
from tas.domain.ports import DuplicateWorkRecordError, WorkRecordReferenceError
from tas.domain.work_record import (
    ObservedEvidence,
    ObservedEvidenceKind,
    WorkRecord,
    WorkRecordId,
    WorkRecordType,
)


class SQLiteWorkRecordRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add(self, record: WorkRecord) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                for evidence in record.observed:
                    existing = connection.execute(
                        "SELECT task_id,actor_agent_id,kind,payload_json,payload_sha256,"
                        "observed_at FROM tas_observed_evidence WHERE id=?",
                        (evidence.id.value,),
                    ).fetchone()
                    values = self._evidence_values(evidence)
                    if existing is None:
                        connection.execute(
                            "INSERT INTO tas_observed_evidence "
                            "(id,task_id,actor_agent_id,kind,payload_json,payload_sha256,observed_at) "
                            "VALUES (?,?,?,?,?,?,?)",
                            (evidence.id.value, *values),
                        )
                    elif existing != values:
                        raise DuplicateWorkRecordError(
                            "Evidence ID already exists with different content"
                        )
                connection.execute(
                    "INSERT INTO tas_work_records "
                    "(id,task_id,actor_agent_id,record_type,claim_text,created_at) "
                    "VALUES (?,?,?,?,?,?)",
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
                    "INSERT INTO tas_work_record_evidence "
                    "(work_record_id,sequence,evidence_id) VALUES (?,?,?)",
                    [
                        (record.id.value, index, evidence.id.value)
                        for index, evidence in enumerate(record.observed, start=1)
                    ],
                )
                initial = initial_epistemic_event(
                    record,
                    event_id=EpistemicEventId(f"initial:{record.id.value}"),
                    occurred_at=record.created_at,
                )
                connection.execute(
                    "INSERT INTO tas_epistemic_events "
                    "(id,work_record_id,sequence,from_status,to_status,rule_id,occurred_at) "
                    "VALUES (?,?,?,?,?,?,?)",
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
                    "INSERT INTO tas_epistemic_event_evidence "
                    "(epistemic_event_id,sequence,evidence_id) VALUES (?,?,?)",
                    [
                        (initial.id.value, index, evidence_id.value)
                        for index, evidence_id in enumerate(
                            initial.evidence_ids, start=1
                        )
                    ],
                )
        except DuplicateWorkRecordError:
            raise
        except sqlite3.IntegrityError as error:
            if getattr(error, "sqlite_errorname", "") == "SQLITE_CONSTRAINT_FOREIGNKEY":
                raise WorkRecordReferenceError(
                    "Work Record references an unknown Task or Agent"
                ) from error
            raise DuplicateWorkRecordError(
                "Work Record could not be appended"
            ) from error

    def get(self, record_id: WorkRecordId) -> WorkRecord | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT id,task_id,actor_agent_id,record_type,claim_text,created_at "
                "FROM tas_work_records WHERE id=?",
                (record_id.value,),
            ).fetchone()
            if row is None:
                return None
            evidence = self._load_evidence(connection, record_id.value)
        return self._restore(row, evidence)

    def list_for_task(self, task_id: TaskId) -> tuple[WorkRecord, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id,task_id,actor_agent_id,record_type,claim_text,created_at "
                "FROM tas_work_records WHERE task_id=? ORDER BY created_at,id",
                (task_id.value,),
            ).fetchall()
            restored = tuple(
                self._restore(row, self._load_evidence(connection, str(row[0])))
                for row in rows
            )
        return restored

    def list_evidence_for_task(
        self, task_id: TaskId
    ) -> tuple[ObservedEvidence, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id,task_id,actor_agent_id,kind,payload_json,payload_sha256,"
                "observed_at FROM tas_observed_evidence WHERE task_id=? "
                "ORDER BY observed_at,id",
                (task_id.value,),
            ).fetchall()
        return tuple(
            ObservedEvidence(
                EvidenceId(str(row[0])),
                TaskId(str(row[1])),
                AgentId(str(row[2])),
                ObservedEvidenceKind(str(row[3])),
                str(row[4]),
                str(row[5]),
                datetime.fromisoformat(str(row[6])),
            )
            for row in rows
        )

    @staticmethod
    def _evidence_values(evidence: ObservedEvidence) -> tuple[object, ...]:
        return (
            evidence.task_id.value,
            evidence.actor_id.value,
            evidence.kind.value,
            evidence.payload_json,
            evidence.payload_sha256,
            evidence.observed_at.isoformat(),
        )

    @staticmethod
    def _load_evidence(
        connection: sqlite3.Connection, record_id: str
    ) -> tuple[ObservedEvidence, ...]:
        rows = connection.execute(
            "SELECT e.id,e.task_id,e.actor_agent_id,e.kind,e.payload_json,"
            "e.payload_sha256,e.observed_at FROM tas_work_record_evidence l "
            "JOIN tas_observed_evidence e ON e.id=l.evidence_id "
            "WHERE l.work_record_id=? ORDER BY l.sequence",
            (record_id,),
        ).fetchall()
        return tuple(
            ObservedEvidence(
                EvidenceId(str(row[0])),
                TaskId(str(row[1])),
                AgentId(str(row[2])),
                ObservedEvidenceKind(str(row[3])),
                str(row[4]),
                str(row[5]),
                datetime.fromisoformat(str(row[6])),
            )
            for row in rows
        )

    @staticmethod
    def _restore(
        row: tuple[object, ...], evidence: tuple[ObservedEvidence, ...]
    ) -> WorkRecord:
        return WorkRecord(
            WorkRecordId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            WorkRecordType(str(row[3])),
            None if row[4] is None else str(row[4]),
            evidence,
            datetime.fromisoformat(str(row[5])),
        )
