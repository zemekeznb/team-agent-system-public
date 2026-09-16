"""Small versioned SQL migration runner for the F2 SQLite adapter."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Iterator


MIGRATION_NAME = re.compile(r"^(?P<version>\d{4})_(?P<name>[a-z][a-z0-9_]*)\.sql$")
DEFAULT_MIGRATIONS_DIRECTORY = Path(__file__).with_name("sql")


class MigrationDriftError(RuntimeError):
    """Raised when an applied migration no longer matches its source file."""


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    version_text: str
    name: str
    sql: str
    checksum: str

    @property
    def identifier(self) -> str:
        return f"{self.version_text}_{self.name}"


class SQLiteMigrator:
    def __init__(self, database: str | Path, migrations_directory: str | Path) -> None:
        self.database = Path(database)
        self.migrations_directory = Path(migrations_directory)

    def migrate(self) -> list[str]:
        migrations = self._load_migrations()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.database, isolation_level=None)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            self._ensure_history_table(connection)
            connection.execute("BEGIN IMMEDIATE")
            try:
                applied = self._applied_migrations(connection)
                self._validate_history(migrations, applied)

                identifiers: list[str] = []
                for migration in migrations:
                    if migration.version in applied:
                        continue
                    self._preserve_pre_migration_anomalies(connection, migration)
                    self._apply(connection, migration)
                    identifiers.append(migration.identifier)
                connection.execute("COMMIT")
                return identifiers
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def _load_migrations(self) -> list[Migration]:
        if not self.migrations_directory.is_dir():
            raise FileNotFoundError(
                f"Migration directory does not exist: {self.migrations_directory}"
            )

        migrations: list[Migration] = []
        versions: set[int] = set()
        for path in sorted(self.migrations_directory.glob("*.sql")):
            match = MIGRATION_NAME.fullmatch(path.name)
            if match is None:
                raise ValueError(f"Invalid migration filename: {path.name}")
            version = int(match.group("version"))
            if version in versions:
                raise ValueError(f"Duplicate migration version: {version:04d}")
            versions.add(version)
            raw = path.read_bytes()
            migrations.append(
                Migration(
                    version=version,
                    version_text=match.group("version"),
                    name=match.group("name"),
                    sql=raw.decode("utf-8"),
                    checksum=hashlib.sha256(raw).hexdigest(),
                )
            )
        return migrations

    @staticmethod
    def _ensure_history_table(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TEXT NOT NULL
            )
            """
        )

    @staticmethod
    def _applied_migrations(connection: sqlite3.Connection) -> dict[int, tuple[str, str]]:
        return {
            version: (name, checksum)
            for version, name, checksum in connection.execute(
                "SELECT version, name, checksum FROM schema_migrations"
            )
        }

    @staticmethod
    def _validate_history(
        migrations: list[Migration], applied: dict[int, tuple[str, str]]
    ) -> None:
        available = {migration.version: migration for migration in migrations}
        for version, (name, checksum) in applied.items():
            migration = available.get(version)
            identifier = f"{version:04d}_{name}"
            if migration is None:
                raise MigrationDriftError(f"Applied migration is missing: {identifier}")
            if migration.name != name or migration.checksum != checksum:
                raise MigrationDriftError(f"Applied migration has changed: {identifier}")

    @staticmethod
    def _preserve_pre_migration_anomalies(
        connection: sqlite3.Connection, migration: Migration
    ) -> None:
        if migration.version != 10:
            return
        connection.execute(
            "CREATE TABLE IF NOT EXISTS schema_migration_quarantine ("
            "migration_version INTEGER NOT NULL, resource_type TEXT NOT NULL, "
            "resource_key TEXT NOT NULL, payload TEXT NOT NULL, captured_at TEXT NOT NULL, "
            "PRIMARY KEY (migration_version, resource_type, resource_key))"
        )
        captured_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        rows = connection.execute(
            "SELECT task_id,sequence,from_status,to_status,actor_agent_id,reason,occurred_at "
            "FROM tas_task_transitions WHERE from_status='working' AND to_status='working'"
        ).fetchall()
        for row in rows:
            payload = json.dumps(
                {
                    "task_id": row[0],
                    "sequence": row[1],
                    "from_status": row[2],
                    "to_status": row[3],
                    "actor_agent_id": row[4],
                    "reason": row[5],
                    "occurred_at": row[6],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migration_quarantine("
                "migration_version,resource_type,resource_key,payload,captured_at) "
                "VALUES (10,'task_transition',?,?,?)",
                (f"{row[0]}:{row[1]}", payload, captured_at),
            )

    @staticmethod
    def _apply(connection: sqlite3.Connection, migration: Migration) -> None:
        for statement in _sql_statements(migration.sql):
            connection.execute(statement)
        connection.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at) "
            "VALUES (?, ?, ?, ?)",
            (
                migration.version,
                migration.name,
                migration.checksum,
                datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            ),
        )


def _sql_statements(sql: str) -> Iterator[str]:
    buffer = ""
    for line in sql.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            if buffer.strip():
                yield buffer
            buffer = ""
    if buffer.strip():
        raise ValueError("Migration contains an incomplete SQL statement")


def main() -> None:
    parser = argparse.ArgumentParser(description="Apply TAS F2 SQLite migrations")
    parser.add_argument(
        "--database", type=Path, default=Path(".tas-local") / "data" / "tas.db"
    )
    parser.add_argument(
        "--migrations", type=Path, default=DEFAULT_MIGRATIONS_DIRECTORY
    )
    args = parser.parse_args()

    applied = SQLiteMigrator(args.database, args.migrations).migrate()
    if applied:
        print("Applied migrations:")
        for identifier in applied:
            print(f"- {identifier}")
    else:
        print("Database is up to date.")


if __name__ == "__main__":
    main()
