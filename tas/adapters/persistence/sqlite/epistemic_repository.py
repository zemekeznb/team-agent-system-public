"""Append-only SQLite epistemic status history."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.epistemic import EpistemicEvent, EpistemicEventId, EpistemicStatus
from tas.domain.evidence import EvidenceId
from tas.domain.ports import EpistemicPersistenceError
from tas.domain.work_record import WorkRecordId


class SQLiteEpistemicRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def history(self, record_id: WorkRecordId) -> tuple[EpistemicEvent, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT id,work_record_id,sequence,from_status,to_status,rule_id,occurred_at "
                "FROM tas_epistemic_events WHERE work_record_id=? ORDER BY sequence",
                (record_id.value,),
            ).fetchall()
            return tuple(self._restore(connection, row) for row in rows)

    def append(self, event: EpistemicEvent) -> None:
        with closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                current = connection.execute(
                    "SELECT sequence,to_status FROM tas_epistemic_events "
                    "WHERE work_record_id=? ORDER BY sequence DESC LIMIT 1",
                    (event.work_record_id.value,),
                ).fetchone()
                expected = None if current is None else (int(current[0]) + 1, str(current[1]))
                actual = (
                    event.sequence,
                    None if event.from_status is None else event.from_status.value,
                )
                if expected != actual:
                    raise EpistemicPersistenceError(
                        "epistemic event is stale or history is missing"
                    )
                available = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT evidence_id FROM tas_work_record_evidence WHERE work_record_id=?",
                        (event.work_record_id.value,),
                    )
                }
                if any(item.value not in available for item in event.evidence_ids):
                    raise EpistemicPersistenceError(
                        "epistemic event references Evidence outside the Work Record"
                    )
                connection.execute(
                    "INSERT INTO tas_epistemic_events "
                    "(id,work_record_id,sequence,from_status,to_status,rule_id,occurred_at) "
                    "VALUES (?,?,?,?,?,?,?)",
                    (
                        event.id.value,
                        event.work_record_id.value,
                        event.sequence,
                        None if event.from_status is None else event.from_status.value,
                        event.to_status.value,
                        event.rule_id,
                        event.occurred_at.isoformat(),
                    ),
                )
                connection.executemany(
                    "INSERT INTO tas_epistemic_event_evidence "
                    "(epistemic_event_id,sequence,evidence_id) VALUES (?,?,?)",
                    [
                        (event.id.value, index, item.value)
                        for index, item in enumerate(event.evidence_ids, start=1)
                    ],
                )
                connection.execute("COMMIT")
            except EpistemicPersistenceError:
                connection.execute("ROLLBACK")
                raise
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                raise EpistemicPersistenceError(
                    "epistemic event could not be appended"
                ) from error
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _restore(
        connection: sqlite3.Connection, row: tuple[object, ...]
    ) -> EpistemicEvent:
        evidence = tuple(
            EvidenceId(str(item[0]))
            for item in connection.execute(
                "SELECT evidence_id FROM tas_epistemic_event_evidence "
                "WHERE epistemic_event_id=? ORDER BY sequence",
                (str(row[0]),),
            )
        )
        return EpistemicEvent(
            EpistemicEventId(str(row[0])),
            WorkRecordId(str(row[1])),
            int(row[2]),
            None if row[3] is None else EpistemicStatus(str(row[3])),
            EpistemicStatus(str(row[4])),
            str(row[5]),
            evidence,
            datetime.fromisoformat(str(row[6])),
        )
