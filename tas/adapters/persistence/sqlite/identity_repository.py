"""SQLite implementation of the identity repository port."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Callable, TypeVar

from tas.domain.identity import (
    Agent,
    AgentId,
    Owner,
    OwnerId,
    Project,
    ProjectId,
    Team,
    TeamId,
    TeamMembership,
)
from tas.domain.ports import DuplicateIdentityError, IdentityReferenceError

T = TypeVar("T")


class SQLiteIdentityRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _insert(self, sql: str, values: tuple[str, ...], resource: str) -> None:
        try:
            with closing(self._connect()) as connection, connection:
                connection.execute(sql, values)
        except sqlite3.IntegrityError as error:
            message = str(error).lower()
            if "foreign key" in message:
                reference = "owner" if "agent" in resource else "team or owner"
                if resource == "project":
                    reference = "team"
                raise IdentityReferenceError(
                    f"{resource} references an unknown {reference}"
                ) from error
            raise DuplicateIdentityError(f"{resource} already exists") from error

    def _one(self, sql: str, values: tuple[str, ...], build: Callable[..., T]) -> T | None:
        with closing(self._connect()) as connection, connection:
            row = connection.execute(sql, values).fetchone()
        return None if row is None else build(*row)

    def add_owner(self, owner: Owner) -> None:
        self._insert("INSERT INTO tas_owners(id, name) VALUES (?, ?)", (owner.id.value, owner.name), "owner")

    def get_owner(self, owner_id: OwnerId) -> Owner | None:
        return self._one("SELECT id, name FROM tas_owners WHERE id = ?", (owner_id.value,), lambda value, name: Owner(OwnerId(value), name))

    def add_agent(self, agent: Agent) -> None:
        self._insert("INSERT INTO tas_agents(id, owner_id, name) VALUES (?, ?, ?)", (agent.id.value, agent.owner_id.value, agent.name), "agent")

    def get_agent(self, agent_id: AgentId) -> Agent | None:
        return self._one("SELECT id, owner_id, name FROM tas_agents WHERE id = ?", (agent_id.value,), lambda value, owner, name: Agent(AgentId(value), OwnerId(owner), name))

    def add_team(self, team: Team) -> None:
        self._insert("INSERT INTO tas_teams(id, name) VALUES (?, ?)", (team.id.value, team.name), "team")

    def get_team(self, team_id: TeamId) -> Team | None:
        return self._one("SELECT id, name FROM tas_teams WHERE id = ?", (team_id.value,), lambda value, name: Team(TeamId(value), name))

    def add_membership(self, membership: TeamMembership) -> None:
        self._insert("INSERT INTO tas_team_memberships(team_id, owner_id) VALUES (?, ?)", (membership.team_id.value, membership.owner_id.value), "membership")

    def get_membership(self, team_id: TeamId, owner_id: OwnerId) -> TeamMembership | None:
        return self._one("SELECT team_id, owner_id FROM tas_team_memberships WHERE team_id = ? AND owner_id = ?", (team_id.value, owner_id.value), lambda team, owner: TeamMembership(TeamId(team), OwnerId(owner)))

    def add_project(self, project: Project) -> None:
        self._insert("INSERT INTO tas_projects(id, team_id, name) VALUES (?, ?, ?)", (project.id.value, project.team_id.value, project.name), "project")

    def get_project(self, project_id: ProjectId) -> Project | None:
        return self._one("SELECT id, team_id, name FROM tas_projects WHERE id = ?", (project_id.value,), lambda value, team, name: Project(ProjectId(value), TeamId(team), name))
