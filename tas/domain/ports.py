"""Persistence contracts owned by the domain layer."""

from datetime import datetime, timedelta
from typing import Protocol

from .identity import (
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
from .collaboration import Artifact, ArtifactId, Task, TaskId, TaskMessage, TaskMessageId
from .delivery import InboxItem, InboxItemId, LeaseToken
from .idempotency import (
    IdempotencyKey,
    IdempotencyRecord,
    OperationName,
    RequestFingerprint,
)


class IdentityPersistenceError(RuntimeError):
    """Base error exposed by identity persistence ports."""


class DuplicateIdentityError(IdentityPersistenceError):
    """Raised when an identity or relationship already exists."""


class IdentityReferenceError(IdentityPersistenceError):
    """Raised when an aggregate references an unknown identity."""


class IdentityRepository(Protocol):
    def add_owner(self, owner: Owner) -> None: ...
    def get_owner(self, owner_id: OwnerId) -> Owner | None: ...
    def add_agent(self, agent: Agent) -> None: ...
    def get_agent(self, agent_id: AgentId) -> Agent | None: ...
    def add_team(self, team: Team) -> None: ...
    def get_team(self, team_id: TeamId) -> Team | None: ...
    def add_membership(self, membership: TeamMembership) -> None: ...
    def get_membership(
        self, team_id: TeamId, owner_id: OwnerId
    ) -> TeamMembership | None: ...
    def add_project(self, project: Project) -> None: ...
    def get_project(self, project_id: ProjectId) -> Project | None: ...


class TaskRepository(Protocol):
    def add_task(self, task: Task) -> None: ...
    def save_task(self, task: Task) -> None: ...
    def get_task(self, task_id: TaskId) -> Task | None: ...
    def add_message(self, message: TaskMessage) -> None: ...
    def get_message(self, message_id: TaskMessageId) -> TaskMessage | None: ...
    def add_artifact(self, artifact: Artifact) -> None: ...
    def get_artifact(self, artifact_id: ArtifactId) -> Artifact | None: ...


class InboxRepository(Protocol):
    def add(self, item: InboxItem) -> None: ...
    def get(self, item_id: InboxItemId) -> InboxItem | None: ...
    def claim_next(
        self,
        recipient: AgentId,
        claimant: AgentId,
        now: datetime,
        duration: timedelta,
    ) -> InboxItem | None: ...
    def acknowledge(
        self, item_id: InboxItemId, token: LeaseToken, now: datetime
    ) -> None: ...
    def release(
        self,
        item_id: InboxItemId,
        token: LeaseToken,
        now: datetime,
        retry_at: datetime,
    ) -> None: ...
    def reap_expired(self, now: datetime) -> int: ...


class IdempotencyRepository(Protocol):
    def reserve(
        self,
        actor: AgentId,
        operation: OperationName,
        key: IdempotencyKey,
        fingerprint: RequestFingerprint,
    ) -> IdempotencyRecord: ...
    def complete(
        self, reservation: IdempotencyRecord, result: dict[str, object]
    ) -> IdempotencyRecord: ...
