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
    RepositoryBinding,
)
from .collaboration import Artifact, ArtifactId, Task, TaskId, TaskMessage, TaskMessageId
from .delivery import InboxItem, InboxItemId, LeaseToken
from .approval import Approval, ApprovalId
from .audit import AuditEvent, AuditEventId
from .action_execution import (
    ActionExecutionRequest,
    ActionReceipt,
    GrantReservation,
    ReceiptSource,
)
from .idempotency import (
    IdempotencyKey,
    IdempotencyRecord,
    OperationName,
    RequestFingerprint,
)
from .work_record import WorkRecord, WorkRecordId


class IdentityPersistenceError(RuntimeError):
    """Base error exposed by identity persistence ports."""


class DuplicateIdentityError(IdentityPersistenceError):
    """Raised when an identity or relationship already exists."""


class IdentityReferenceError(IdentityPersistenceError):
    """Raised when an aggregate references an unknown identity."""


class DuplicateAuditEventError(RuntimeError):
    """Raised when an immutable Audit Event cannot be appended."""


class WorkRecordPersistenceError(RuntimeError):
    """Base error exposed by Work Record persistence ports."""


class DuplicateWorkRecordError(WorkRecordPersistenceError):
    """Raised when an immutable Work Record or Evidence ID conflicts."""


class WorkRecordReferenceError(WorkRecordPersistenceError):
    """Raised when a Work Record references an unknown aggregate."""


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


class ResourceRepository(Protocol):
    def add_repository(self, binding: RepositoryBinding) -> None: ...
    def get_repository(self, repository: str) -> RepositoryBinding | None: ...


class AuditRepository(Protocol):
    def add(self, event: AuditEvent) -> None: ...
    def get(self, event_id: AuditEventId) -> AuditEvent | None: ...
    def list_for_resource(
        self, resource_type: str, resource_id: str
    ) -> tuple[AuditEvent, ...]: ...


class WorkRecordRepository(Protocol):
    def add(self, record: WorkRecord) -> None: ...
    def get(self, record_id: WorkRecordId) -> WorkRecord | None: ...
    def list_for_task(self, task_id: TaskId) -> tuple[WorkRecord, ...]: ...


class ActionGrantRepository(Protocol):
    def get(
        self, approval_id: ApprovalId, request_fingerprint: str
    ) -> GrantReservation | None: ...
    def reserve(
        self, approval_id: ApprovalId, request_fingerprint: str, started_at: datetime
    ) -> GrantReservation: ...
    def complete(
        self,
        approval_id: ApprovalId,
        request_fingerprint: str,
        receipt: ActionReceipt,
        receipt_source: ReceiptSource,
    ) -> GrantReservation: ...
    def mark_audited(
        self, approval_id: ApprovalId, request_fingerprint: str, event_id: AuditEventId
    ) -> None: ...


class ExternalActionExecutor(Protocol):
    def check_preconditions(self, request: ActionExecutionRequest) -> None: ...
    def find_receipt(self, operation_id: str) -> ActionReceipt | None: ...
    def execute_once(
        self, request: ActionExecutionRequest, request_fingerprint: str
    ) -> ActionReceipt: ...


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


class ApprovalRepository(Protocol):
    def add(self, approval: Approval) -> None: ...
    def get(self, approval_id: ApprovalId) -> Approval | None: ...
    def save_resolution(self, approval: Approval) -> None: ...
    def resolve_with_task(self, approval: Approval) -> None: ...
    def complete(
        self, reservation: IdempotencyRecord, result: dict[str, object]
    ) -> IdempotencyRecord: ...
