"""SQLite Repository resource bindings."""

import sqlite3
from contextlib import closing
from pathlib import Path

from tas.domain.identity import (
    OwnerId,
    ProjectId,
    RepositoryBinding,
    validate_repository_name,
)
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError


class SQLiteResourceRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def add_repository(self, binding: RepositoryBinding) -> None:
        with closing(self._connect()) as connection, connection:
            project = connection.execute(
                "SELECT team_id FROM tas_projects WHERE id=?",
                (binding.project_id.value,),
            ).fetchone()
            membership = None
            if project is not None:
                membership = connection.execute(
                    "SELECT 1 FROM tas_team_memberships "
                    "WHERE team_id=? AND owner_id=?",
                    (project[0], binding.controlling_owner_id.value),
                ).fetchone()
            if project is None or membership is None:
                raise IdentityReferenceError(
                    "repository controller must belong to the Project Team"
                )
            try:
                connection.execute(
                    "INSERT INTO tas_repository_bindings VALUES (?,?,?)",
                    (
                        binding.repository,
                        binding.project_id.value,
                        binding.controlling_owner_id.value,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise DuplicateIdentityError(
                    "repository already exists or references are invalid"
                ) from exc

    def get_repository(self, repository: str) -> RepositoryBinding | None:
        validate_repository_name(repository)
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT repository,project_id,controlling_owner_id "
                "FROM tas_repository_bindings WHERE repository=?",
                (repository,),
            ).fetchone()
        return (
            None
            if row is None
            else RepositoryBinding(row[0], ProjectId(row[1]), OwnerId(row[2]))
        )
