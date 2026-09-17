"""Identity and ownership domain values for F2-010."""

from __future__ import annotations

from dataclasses import dataclass


class DomainValidationError(ValueError):
    """Raised when a domain value violates a local invariant."""


def _require_text(value: str, field: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainValidationError(f"{field} must not be blank")


@dataclass(frozen=True, slots=True)
class OwnerId:
    value: str

    def __post_init__(self) -> None:
        _require_text(self.value, "OwnerId")


@dataclass(frozen=True, slots=True)
class AgentId:
    value: str

    def __post_init__(self) -> None:
        _require_text(self.value, "AgentId")


@dataclass(frozen=True, slots=True)
class TeamId:
    value: str

    def __post_init__(self) -> None:
        _require_text(self.value, "TeamId")


@dataclass(frozen=True, slots=True)
class ProjectId:
    value: str

    def __post_init__(self) -> None:
        _require_text(self.value, "ProjectId")


@dataclass(frozen=True, slots=True)
class Owner:
    id: OwnerId
    name: str

    def __post_init__(self) -> None:
        _require_type(self.id, OwnerId, "id")
        _require_text(self.name, "Owner name")


@dataclass(frozen=True, slots=True)
class Agent:
    id: AgentId
    owner_id: OwnerId
    name: str

    def __post_init__(self) -> None:
        _require_type(self.id, AgentId, "id")
        _require_type(self.owner_id, OwnerId, "owner_id")
        _require_text(self.name, "Agent name")


@dataclass(frozen=True, slots=True)
class Team:
    id: TeamId
    name: str

    def __post_init__(self) -> None:
        _require_type(self.id, TeamId, "id")
        _require_text(self.name, "Team name")


@dataclass(frozen=True, slots=True)
class TeamMembership:
    team_id: TeamId
    owner_id: OwnerId

    def __post_init__(self) -> None:
        _require_type(self.team_id, TeamId, "team_id")
        _require_type(self.owner_id, OwnerId, "owner_id")


@dataclass(frozen=True, slots=True)
class Project:
    id: ProjectId
    team_id: TeamId
    name: str

    def __post_init__(self) -> None:
        _require_type(self.id, ProjectId, "id")
        _require_type(self.team_id, TeamId, "team_id")
        _require_text(self.name, "Project name")


@dataclass(frozen=True, slots=True)
class RepositoryBinding:
    repository: str
    project_id: ProjectId
    controlling_owner_id: OwnerId

    def __post_init__(self) -> None:
        validate_repository_name(self.repository)
        _require_type(self.project_id, ProjectId, "project_id")
        _require_type(self.controlling_owner_id, OwnerId, "controlling_owner_id")


def validate_repository_name(repository: str) -> None:
    _require_text(repository, "Repository")
    if len(repository) > 255:
        raise DomainValidationError("Repository must not exceed 255 characters")


def _require_type(value: object, expected: type[object], field: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"{field} must be {expected.__name__}")
