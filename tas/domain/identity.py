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


def _require_type(value: object, expected: type[object], field: str) -> None:
    if not isinstance(value, expected):
        raise TypeError(f"{field} must be {expected.__name__}")
