"""F3 central Application Service composition boundary."""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Security, status
from fastapi import Path as ApiPath
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

from tas.application.credentials import (
    CredentialService,
    InsufficientCredentialScopeError,
    InvalidCredentialError,
)
from tas.application.inbox_commands import (
    FinishInboxResult, InboxCommandService, LeaseTokenProvider,
)
from tas.application.approval_commands import (
    ApprovalCommandResult, ApprovalCommandService, DecideApprovalCommand,
    RequestApprovalCommand,
)
from tas.application.remote_action_grants import (
    PrepareRemoteActionCommand,
    RemoteActionGrantAccessError,
    RemoteActionGrantConflictError,
    RemoteActionGrantRejectedError,
    RemoteActionReceiptCommitError,
    RemoteActionGrantService,
    RemoteActionGrantView,
    SubmitActionReceiptCommand,
)
from tas.application.audit_query import (
    AuditEventPage, AuditQueryAccessError, AuditQueryService, AuditResourceType,
)
from tas.application.authoritative_validation import (
    AuthoritativeValidationService,
    ValidateWorkRecordCommand,
    ValidationRule,
)
from tas.application.artifact_uploads import (
    MAX_ARTIFACT_BYTES,
    ArtifactCommandResult,
    ArtifactPurpose,
    ArtifactUploadService,
    RegisteredSecretScanner,
    ReserveArtifactCommand,
)
from tas.application.artifact_access import (
    ArtifactEvidenceAccessService,
    EvidenceAccessView,
)
from tas.application.evidence_submissions import (
    MAX_EVIDENCE_ARTIFACTS,
    MAX_EVIDENCE_PAYLOAD_BYTES,
    EvidenceSubmissionResult,
    EvidenceSubmissionService,
    ReserveEvidenceCommand,
)
from tas.application.event_commands import (
    CodeChangeImpactView,
    CreateCodeChangeImpactCommand,
    EventCommandResult,
    EventCommandService,
)
from tas.application.knowledge_access import (
    MAX_WORK_RECORD_EVIDENCE,
    CreateWorkRecordCommand,
    KnowledgeAccessService,
    MemorySearchRequest,
    MemoryView,
    PromoteMemoryCommand,
    WorkRecordCommandResult,
    WorkRecordView,
)
from tas.application.workspace_bindings import (
    RegisterWorkspaceCommand,
    WorkspaceBindingService,
    WorkspaceCommandResult,
    WorkspaceView,
)
from tas.application.task_commands import TransitionTaskCommand, TransitionTaskService
from tas.application.task_creation import CreateTaskRequest, CreateTaskService
from tas.application.policy_lifecycle import OwnerPolicyService, PolicyAccessDeniedError
from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError, IdempotencyInProgressError,
)
from tas.adapters.persistence.sqlite.inbox_command_uow import (
    InboxCommandConflictError, SQLiteInboxCommandUnitOfWork,
)
from tas.adapters.persistence.sqlite.approval_command_uow import (
    ApprovalCommandAccessError, ApprovalCommandConflictError,
    SQLiteApprovalCommandUnitOfWork,
)
from tas.adapters.persistence.sqlite.remote_action_grant_uow import (
    SQLiteRemoteActionGrantUnitOfWork,
)
from tas.adapters.persistence.sqlite.audit_query_repository import (
    SQLiteAuditQueryRepository,
)
from tas.adapters.persistence.sqlite.authoritative_validation_uow import (
    AuthoritativeValidationAccessError,
    AuthoritativeValidationConflictError,
    SQLiteAuthoritativeValidationUnitOfWork,
)
from tas.adapters.persistence.sqlite.artifact_upload_uow import (
    ArtifactUploadAccessError,
    ArtifactUploadConflictError,
    SQLiteArtifactUploadUnitOfWork,
)
from tas.adapters.persistence.sqlite.artifact_access_repository import (
    SQLiteArtifactEvidenceAccessRepository,
)
from tas.adapters.persistence.sqlite.evidence_submission_uow import (
    EvidenceSubmissionAccessError,
    EvidenceSubmissionConflictError,
    SQLiteEvidenceSubmissionUnitOfWork,
)
from tas.adapters.persistence.sqlite.event_command_uow import (
    EventCommandAccessError,
    EventCommandConflictError,
    SQLiteEventCommandUnitOfWork,
)
from tas.adapters.persistence.sqlite.knowledge_access_uow import (
    KnowledgeAccessError,
    KnowledgeConflictError,
    SQLiteKnowledgeAccessUnitOfWork,
)
from tas.adapters.persistence.sqlite.workspace_binding_uow import (
    SQLiteWorkspaceBindingUnitOfWork,
    WorkspaceBindingAccessError,
    WorkspaceBindingConflictError,
)
from tas.adapters.persistence.sqlite.task_creation_uow import SQLiteTaskCreationUnitOfWork
from tas.adapters.persistence.sqlite.task_repository import SQLiteTaskRepository
from tas.adapters.persistence.sqlite.task_transition_uow import (
    SQLiteTaskTransitionUnitOfWork, TaskTransitionAccessError,
)
from tas.domain.credential import (
    AuthenticatedPrincipal, CredentialScope, CredentialSubjectType,
)
from tas.domain.identity import DomainValidationError
from tas.domain.identity import AgentId, ProjectId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.collaboration import (
    ArtifactId,
    InvalidTaskTransitionError,
    Task,
    TaskId,
    TaskStatus,
)
from tas.domain.delivery import InboxItemId, LeaseToken
from tas.domain.approval import Approval, ApprovalId
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.events import CodeImpactKind, CollaborationEventId
from tas.domain.memory import (
    ApplicabilityStatus,
    MemoryId,
    MemoryValidationStatus,
)
from tas.domain.work_record import (
    ObservedEvidenceKind,
    WorkRecordId,
    WorkRecordType,
)
from tas.domain.policy import Action, OwnerPolicy, PolicyOutcome, PolicyRule, Risk
from tas.domain.ports import (
    IdentityReferenceError, PolicyConflictError, PolicyIdempotencyConflictError,
)


class SessionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_id: str
    agent_id: str | None
    credential_id: str
    scopes: list[str]
    expires_at: datetime


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    retryable: bool
    correlation_id: str


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    error: ErrorBody


class PolicyRuleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Action
    outcome: PolicyOutcome
    max_auto_risk: Risk = Risk.LOW


class PolicyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str = Field(min_length=1, max_length=255)
    rules: list[PolicyRuleInput] = Field(max_length=len(Action))


class PolicySelectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_current_version: str | None = Field(max_length=255)


class PolicyRuleResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: Action
    outcome: PolicyOutcome
    max_auto_risk: Risk


class PolicyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    version: str
    rules: list[PolicyRuleResponse]


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(min_length=1, max_length=255)
    assignee_agent_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=1024)


class TaskResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    assignee_agent_id: str
    title: str
    status: str
    result: str | None
    replayed: bool | None = None


class TaskTransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: TaskStatus
    reason: str | None = Field(default=None, max_length=1024)
    result: str | None = Field(default=None, max_length=65536)


class InboxClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_duration_seconds: int = Field(strict=True, ge=5, le=300)
    wait_timeout_seconds: int = Field(default=0, strict=True, ge=0, le=25)


class InboxLeaseResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str
    task_id: str
    attempt: int
    lease_token: str
    acquired_at: datetime
    expires_at: datetime


class InboxClaimResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item: InboxLeaseResponse | None
    replayed: bool


class InboxAcknowledgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_token: str = Field(min_length=16, max_length=255)


class InboxReleaseRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_token: str = Field(min_length=16, max_length=255)
    retry_delay_seconds: int = Field(strict=True, ge=0, le=604800)


class InboxFinishResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    item_id: str
    status: str
    attempt: int
    available_at: datetime | None
    replayed: bool


class ApprovalRequestInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=1, max_length=255)
    action: Action
    scope: str = Field(min_length=1, max_length=255)
    risk: Risk
    lifetime_seconds: int = Field(ge=60, le=86400)


class ApprovalDecisionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    decision: Literal["approved", "rejected"]
    reason: str | None = Field(default=None, max_length=1024)


class ApprovalResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    status: str
    requester_agent_id: str
    receiving_agent_id: str
    task_id: str
    repository: str
    action: str
    scope: str
    risk: int
    policy_version: str
    requested_at: datetime
    expires_at: datetime
    resolved_by_owner_id: str | None
    resolved_at: datetime | None
    reason: str | None
    replayed: bool | None = None


class ActionGrantPrepareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=255)
    evidence_id: str = Field(min_length=1, max_length=255)


class ActionResultUnknownRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


class ActionReceiptSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    external_action_id: str = Field(min_length=1, max_length=255)
    result_reference: str = Field(min_length=1, max_length=255)
    occurred_at: datetime


class ActionReceiptResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    operation_id: str
    request_fingerprint: str
    external_action_id: str
    result_reference: str
    occurred_at: datetime


class ActionGrantResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approval_id: str
    operation_id: str
    request_fingerprint: str
    workspace_id: str
    evidence_id: str
    commit_sha: str
    execute_before: datetime
    status: str
    started_at: datetime
    receipt: ActionReceiptResponse | None
    replayed: bool


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    actor_kind: str
    actor_id: str
    resource_type: str
    resource_id: str
    action: str
    outcome: str
    reason_category: str
    occurred_at: datetime
    policy_version: str | None
    correlation_id: str | None


class AuditEventPageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: tuple[AuditEventResponse, ...]
    next_cursor: str | None


class WorkRecordValidationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule: ValidationRule


class WorkRecordCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=255)
    record_type: WorkRecordType
    claim_text: str | None = Field(default=None, min_length=1, max_length=65_536)
    evidence_ids: list[
        Annotated[str, Field(min_length=1, max_length=255)]
    ] = Field(max_length=MAX_WORK_RECORD_EVIDENCE)


class WorkRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    actor_agent_id: str
    record_type: str
    claim_text: str | None
    evidence_ids: tuple[str, ...]
    created_at: datetime
    current_status: str
    latest_event_id: str
    latest_sequence: int
    replayed: bool | None


class MemoryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    source_work_record_id: str
    source_validation_event_id: str
    task_id: str
    source_actor_id: str
    promoted_by_agent_id: str
    record_type: str
    content: str
    validation_rule_id: str
    evidence_ids: tuple[str, ...]
    validation_status: str
    applicability_status: str
    promotion_rule_id: str
    promoted_at: datetime
    code_scope: MemoryCodeScopeResponse | None
    latest_applicability: MemoryApplicabilityResponse | None
    replacement_memory_id: str | None
    replayed: bool | None = None


class MemoryPromotionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_work_record_id: str = Field(min_length=1, max_length=255)
    code_scope_evidence_id: str = Field(min_length=1, max_length=255)


class MemoryCodeScopeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_evidence_id: str
    repository: str
    ref: str
    commit: str
    paths: tuple[str, ...]


class MemoryApplicabilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    sequence: int
    previous_assessment_id: str | None
    status: str
    reason: str
    memory_commit: str
    current_commit: str | None
    changed_paths: tuple[str, ...]
    checked_at: datetime


class MemorySearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: tuple[MemoryResponse, ...]


class WorkRecordValidationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    work_record_id: str
    sequence: int
    from_status: str
    to_status: str
    rule_id: str
    evidence_ids: tuple[str, ...]
    occurred_at: datetime
    replayed: bool


class ArtifactReservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=255)
    media_type: Literal[
        "application/json", "application/octet-stream", "text/plain"
    ]
    declared_size: int = Field(strict=True, ge=0, le=MAX_ARTIFACT_BYTES)
    declared_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    purpose: ArtifactPurpose


class ArtifactUploadResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    media_type: str
    purpose: str
    declared_size: int
    declared_sha256: str
    status: str
    actual_size: int | None
    actual_sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None
    finalized_at: datetime | None
    security_status: str
    availability_status: str
    scanner_version: str | None
    scanned_at: datetime | None
    redaction_count: int
    source_artifact_id: str | None
    derived_artifact_id: str | None
    replayed: bool


class ArtifactMetadataResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    media_type: str
    purpose: str
    size: int
    sha256: str
    created_at: datetime
    finalized_at: datetime
    security_status: str
    availability_status: str
    scanner_version: str | None
    scanned_at: datetime | None
    redaction_count: int
    source_artifact_id: str | None
    derived_artifact_id: str | None


class EvidenceReservationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=255)
    workspace_id: str = Field(min_length=1, max_length=255)
    kind: ObservedEvidenceKind
    attempt: int = Field(strict=True, ge=1, le=16)
    retry_of: str | None = Field(default=None, min_length=1, max_length=255)
    observed_at: datetime
    head_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    artifact_ids: list[str] = Field(max_length=MAX_EVIDENCE_ARTIFACTS)


class EvidenceFinalizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    payload_json: str = Field(min_length=2, max_length=MAX_EVIDENCE_PAYLOAD_BYTES)


class EvidenceSubmissionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    workspace_id: str
    kind: str
    attempt: int
    retry_of: str | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[str, ...]
    status: str
    payload_sha256: str | None
    created_at: datetime
    finalized_at: datetime | None
    replayed: bool


class EvidenceAccessResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    workspace_id: str
    kind: str
    attempt: int
    retry_of: str | None
    observed_at: datetime
    head_commit: str
    artifact_ids: tuple[str, ...]
    payload_sha256: str
    payload_json: str
    created_at: datetime
    finalized_at: datetime


class WorkspaceRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_id: str = Field(min_length=1, max_length=255)
    repository: str = Field(min_length=1, max_length=255)


class WorkspaceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    task_id: str
    actor_agent_id: str
    repository: str
    bound_at: datetime
    replayed: bool | None = None


class CodeChangeImpactCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(min_length=1, max_length=255)
    target_agent_id: str = Field(min_length=1, max_length=255)
    title: str = Field(min_length=1, max_length=4096)
    repository: str = Field(min_length=1, max_length=255)
    ref: str = Field(min_length=1, max_length=255)
    baseline_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    head_commit: str = Field(pattern=r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
    changed_paths: list[Annotated[str, Field(min_length=1, max_length=4096)]] = Field(
        min_length=1, max_length=1000
    )
    evidence_id: str = Field(min_length=1, max_length=255)
    impact_kind: CodeImpactKind
    affected_api: str = Field(min_length=1, max_length=1024)


class CodeChangeImpactResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    publisher_agent_id: str
    target_agent_id: str
    task_id: str
    inbox_item_id: str
    title: str
    repository: str
    ref: str
    baseline_commit: str
    head_commit: str
    changed_paths: tuple[str, ...]
    evidence_id: str
    impact_kind: str
    affected_api: str
    occurred_at: datetime
    replayed: bool | None = None


def create_f3_app(
    credentials: CredentialService,
    database: str | Path,
    policies: OwnerPolicyService,
    lease_tokens: LeaseTokenProvider,
    artifact_root: str | Path | None = None,
    artifact_secrets: tuple[bytes, ...] = (),
) -> FastAPI:
    database_path = Path(database)
    artifact_root_path = (
        database_path.parent / "artifacts"
        if artifact_root is None
        else Path(artifact_root)
    )
    task_repository = SQLiteTaskRepository(database_path)
    task_creation = CreateTaskService(
        SQLiteTaskCreationUnitOfWork(
            database_path,
            inbox_id_factory=lambda: InboxItemId(str(uuid4())),
            enforce_team_membership=True,
            record_origin=True,
        )
    )
    task_transitions = TransitionTaskService(
        SQLiteTaskTransitionUnitOfWork(database_path)
    )
    inbox_commands = InboxCommandService(
        SQLiteInboxCommandUnitOfWork(database_path, lease_tokens)
    )
    approval_commands = ApprovalCommandService(
        SQLiteApprovalCommandUnitOfWork(database_path)
    )
    remote_action_grants = RemoteActionGrantService(
        SQLiteRemoteActionGrantUnitOfWork(database_path)
    )
    audit_queries = AuditQueryService(SQLiteAuditQueryRepository(database_path))
    authoritative_validation = AuthoritativeValidationService(
        SQLiteAuthoritativeValidationUnitOfWork(database_path)
    )
    artifact_uploads = ArtifactUploadService(
        SQLiteArtifactUploadUnitOfWork(
            database_path,
            artifact_root_path,
            RegisteredSecretScanner(artifact_secrets),
        )
    )
    artifact_access = ArtifactEvidenceAccessService(
        SQLiteArtifactEvidenceAccessRepository(database_path, artifact_root_path)
    )
    evidence_submissions = EvidenceSubmissionService(
        SQLiteEvidenceSubmissionUnitOfWork(database_path)
    )
    knowledge = KnowledgeAccessService(
        SQLiteKnowledgeAccessUnitOfWork(database_path)
    )
    workspace_bindings = WorkspaceBindingService(
        SQLiteWorkspaceBindingUnitOfWork(database_path)
    )
    event_commands = EventCommandService(
        SQLiteEventCommandUnitOfWork(database_path)
    )
    application = FastAPI(
        title="Team Agent System F3 Application API",
        version="1.0.0-draft.17",
        description="F3-PREP central service; not production ready.",
    )
    long_poll_guard = Lock()
    active_long_polls: set[str] = set()

    @application.middleware("http")
    async def correlation(request: Request, call_next):
        raw = request.headers.get("x-correlation-id")
        try:
            correlation_id = str(uuid4()) if raw is None else str(UUID(raw))
            if raw is not None and correlation_id != raw.lower():
                raise ValueError
        except ValueError:
            correlation_id = str(uuid4())
            return _error(
                status.HTTP_422_UNPROCESSABLE_CONTENT,
                "validation_error",
                "Invalid X-Correlation-ID",
                correlation_id,
            )
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response

    bearer = HTTPBearer(auto_error=False, scheme_name="bearerAuth")

    def require_scope(required_scope: CredentialScope):
        def authenticate(
            request: Request,
            _: HTTPAuthorizationCredentials | None = Security(bearer),
        ) -> AuthenticatedPrincipal:
            authorization = request.headers.get("authorization")
            scheme, separator, token = (authorization or "").partition(" ")
            if (
                separator != " "
                or scheme.lower() != "bearer"
                or not token
                or token.strip() != token
                or " " in token
            ):
                try:
                    credentials.authenticate("", required_scope, datetime.now(UTC))
                except InvalidCredentialError:
                    pass
                raise _unauthenticated(request)
            try:
                return credentials.authenticate(token, required_scope, datetime.now(UTC))
            except InsufficientCredentialScopeError:
                raise _permission_denied(request) from None
            except InvalidCredentialError:
                raise _unauthenticated(request) from None

        return authenticate

    @application.exception_handler(HTTPException)
    async def controlled_http_error(request: Request, error: HTTPException):
        detail = error.detail if isinstance(error.detail, dict) else {}
        response = _error(
            error.status_code,
            str(detail.get("code", "internal_error")),
            str(detail.get("message", "Request failed")),
            request.state.correlation_id,
        )
        response.headers.update(error.headers or {})
        return response

    @application.exception_handler(RequestValidationError)
    async def request_validation_error(request: Request, error: RequestValidationError):
        return _error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "Request validation failed",
            request.state.correlation_id,
        )

    @application.exception_handler(PolicyAccessDeniedError)
    async def policy_access_denied(request: Request, error: PolicyAccessDeniedError):
        return _error(
            status.HTTP_403_FORBIDDEN,
            "permission_denied",
            "Policy access is not permitted",
            request.state.correlation_id,
        )

    @application.exception_handler(PolicyConflictError)
    async def policy_conflict(request: Request, error: PolicyConflictError):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Policy state conflicts with the request",
            request.state.correlation_id,
        )

    @application.exception_handler(PolicyIdempotencyConflictError)
    async def policy_idempotency_conflict(
        request: Request, error: PolicyIdempotencyConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "idempotency_conflict",
            "Idempotency key conflicts with an earlier request",
            request.state.correlation_id,
        )

    @application.exception_handler(IdempotencyConflictError)
    async def idempotency_conflict(
        request: Request, error: IdempotencyConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "idempotency_conflict",
            "Idempotency key conflicts with an earlier request",
            request.state.correlation_id,
        )

    @application.exception_handler(IdempotencyInProgressError)
    async def idempotency_in_progress(
        request: Request, error: IdempotencyInProgressError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "The original request has no replayable result yet",
            request.state.correlation_id,
            retryable=True,
        )

    @application.exception_handler(IdentityReferenceError)
    async def identity_reference_error(
        request: Request, error: IdentityReferenceError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Resource not found",
            request.state.correlation_id,
        )

    @application.exception_handler(TaskTransitionAccessError)
    async def task_transition_access_error(
        request: Request, error: TaskTransitionAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Task not found",
            request.state.correlation_id,
        )

    @application.exception_handler(InboxCommandConflictError)
    async def inbox_command_conflict(
        request: Request, error: InboxCommandConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Inbox operation conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(ApprovalCommandConflictError)
    async def approval_command_conflict(
        request: Request, error: ApprovalCommandConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Approval operation conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(ApprovalCommandAccessError)
    async def approval_command_access(
        request: Request, error: ApprovalCommandAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Approval target not found",
            request.state.correlation_id,
        )

    @application.exception_handler(RemoteActionGrantAccessError)
    async def remote_action_grant_access_error(
        request: Request, error: RemoteActionGrantAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Action Grant not found",
            request.state.correlation_id,
        )

    @application.exception_handler(RemoteActionGrantRejectedError)
    async def remote_action_grant_rejected(
        request: Request, error: RemoteActionGrantRejectedError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "grant_rejected",
            "Action Grant is not executable",
            request.state.correlation_id,
        )

    @application.exception_handler(RemoteActionGrantConflictError)
    async def remote_action_grant_conflict(
        request: Request, error: RemoteActionGrantConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "action_conflict",
            "Action operation conflicts with authoritative state",
            request.state.correlation_id,
        )

    @application.exception_handler(RemoteActionReceiptCommitError)
    async def remote_action_receipt_commit_error(
        request: Request, error: RemoteActionReceiptCommitError
    ):
        return _error(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "receipt_commit_unavailable",
            "Retry Receipt submission; do not re-execute the action",
            request.state.correlation_id,
            retryable=True,
        )

    @application.exception_handler(AuditQueryAccessError)
    async def audit_query_access(
        request: Request, error: AuditQueryAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Audit resource not found",
            request.state.correlation_id,
        )

    @application.exception_handler(AuthoritativeValidationAccessError)
    async def authoritative_validation_access(
        request: Request, error: AuthoritativeValidationAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Work Record not found",
            request.state.correlation_id,
        )

    @application.exception_handler(AuthoritativeValidationConflictError)
    async def authoritative_validation_conflict(
        request: Request, error: AuthoritativeValidationConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Validation conflicts with current Evidence or state",
            request.state.correlation_id,
        )

    @application.exception_handler(ArtifactUploadAccessError)
    async def artifact_upload_access(
        request: Request, error: ArtifactUploadAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Artifact target not found",
            request.state.correlation_id,
        )

    @application.exception_handler(ArtifactUploadConflictError)
    async def artifact_upload_conflict(
        request: Request, error: ArtifactUploadConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Artifact operation conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(EvidenceSubmissionAccessError)
    async def evidence_submission_access(
        request: Request, error: EvidenceSubmissionAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Evidence target not found",
            request.state.correlation_id,
        )

    @application.exception_handler(EvidenceSubmissionConflictError)
    async def evidence_submission_conflict(
        request: Request, error: EvidenceSubmissionConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Evidence operation conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(KnowledgeAccessError)
    async def knowledge_access_error(
        request: Request, error: KnowledgeAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Knowledge resource not found",
            request.state.correlation_id,
        )

    @application.exception_handler(KnowledgeConflictError)
    async def knowledge_conflict(
        request: Request, error: KnowledgeConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Knowledge operation conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(WorkspaceBindingAccessError)
    async def workspace_binding_access(
        request: Request, error: WorkspaceBindingAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Workspace not found",
            request.state.correlation_id,
        )

    @application.exception_handler(WorkspaceBindingConflictError)
    async def workspace_binding_conflict(
        request: Request, error: WorkspaceBindingConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Workspace registration conflicts with current state",
            request.state.correlation_id,
        )

    @application.exception_handler(EventCommandAccessError)
    async def event_command_access(
        request: Request, error: EventCommandAccessError
    ):
        return _error(
            status.HTTP_404_NOT_FOUND,
            "not_found",
            "Event target not found",
            request.state.correlation_id,
        )

    @application.exception_handler(EventCommandConflictError)
    async def event_command_conflict(
        request: Request, error: EventCommandConflictError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Event conflicts with authoritative Evidence or state",
            request.state.correlation_id,
        )

    @application.exception_handler(InvalidTaskTransitionError)
    async def invalid_task_transition(
        request: Request, error: InvalidTaskTransitionError
    ):
        return _error(
            status.HTTP_409_CONFLICT,
            "conflict",
            "Task transition is not permitted",
            request.state.correlation_id,
        )

    @application.exception_handler(DomainValidationError)
    @application.exception_handler(ValueError)
    @application.exception_handler(TypeError)
    async def domain_validation_error(request: Request, error: Exception):
        return _error(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation_error",
            "Request validation failed",
            request.state.correlation_id,
        )

    @application.exception_handler(Exception)
    async def controlled_internal_error(request: Request, error: Exception):
        return _error(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal_error",
            "Request failed",
            request.state.correlation_id,
        )

    @application.get(
        "/healthz", tags=["system"], openapi_extra={"security": []}
    )
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/readyz", include_in_schema=False)
    def readyz(request: Request) -> dict[str, str]:
        try:
            with sqlite3.connect(database_path) as connection:
                applied_versions = tuple(
                    int(row[0])
                    for row in connection.execute(
                        "SELECT version FROM schema_migrations ORDER BY version"
                    ).fetchall()
                )
                connection.execute("SELECT 1").fetchone()
            if applied_versions != tuple(range(1, 40)):
                raise RuntimeError
            _verify_artifact_storage_ready(artifact_root_path)
        except (OSError, sqlite3.Error, RuntimeError):
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "not_ready"},
                headers={"X-Correlation-ID": request.state.correlation_id},
            )
        return {"status": "ready"}

    @application.get(
        "/api/v1/session",
        response_model=SessionResponse,
        responses={401: {"model": ErrorEnvelope}},
        tags=["session"],
    )
    def session(
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.SESSION_READ)
        ),
    ) -> SessionResponse:
        return SessionResponse(
            owner_id=principal.owner_id.value,
            agent_id=None if principal.agent_id is None else principal.agent_id.value,
            credential_id=principal.credential_id.value,
            scopes=[scope.value for scope in principal.scopes],
            expires_at=principal.expires_at,
        )

    @application.post(
        "/api/v1/workspaces",
        response_model=WorkspaceResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["workspaces"],
    )
    def register_workspace(
        body: WorkspaceRegistrationRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVIDENCE_WRITE)
        ),
    ) -> WorkspaceResponse:
        _require_agent_principal(principal, request)
        return _workspace_response(
            workspace_bindings.register(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                RegisterWorkspaceCommand(TaskId(body.task_id), body.repository),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/workspaces/{workspace_id}",
        response_model=WorkspaceResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["workspaces"],
    )
    def get_workspace(
        request: Request,
        workspace_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVIDENCE_READ)
        ),
    ) -> WorkspaceResponse:
        workspace = workspace_bindings.get(
            principal, WorkspaceBindingId(workspace_id)
        )
        if workspace is None:
            raise _not_found(request, "Workspace not found")
        return _workspace_view_response(workspace)

    @application.post(
        "/api/v1/events",
        response_model=CodeChangeImpactResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["events"],
    )
    def create_event(
        body: CodeChangeImpactCreateRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVENTS_WRITE)
        ),
    ) -> CodeChangeImpactResponse:
        _require_agent_principal(principal, request)
        return _event_result_response(
            event_commands.create(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                CreateCodeChangeImpactCommand(
                    ProjectId(body.project_id),
                    AgentId(body.target_agent_id),
                    body.title,
                    body.repository,
                    body.ref,
                    body.baseline_commit,
                    body.head_commit,
                    tuple(body.changed_paths),
                    EvidenceId(body.evidence_id),
                    body.impact_kind,
                    body.affected_api,
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/events/{event_id}",
        response_model=CodeChangeImpactResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["events"],
    )
    def get_event(
        request: Request,
        event_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVENTS_READ)
        ),
    ) -> CodeChangeImpactResponse:
        event = event_commands.get(
            principal, CollaborationEventId(event_id)
        )
        if event is None:
            raise _not_found(request, "Event not found")
        return _event_view_response(event)

    @application.post(
        "/api/v1/policies",
        response_model=PolicyResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["policies"],
    )
    def create_policy(
        body: PolicyCreateRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.POLICIES_WRITE)
        ),
    ) -> PolicyResponse:
        _require_owner_principal(principal, request)
        policy = OwnerPolicy(
            principal.owner_id,
            body.version,
            tuple(
                PolicyRule(rule.action, rule.outcome, rule.max_auto_risk)
                for rule in body.rules
            ),
        )
        return _policy_response(
            policies.create(
                principal,
                policy,
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
                idempotency_key=IdempotencyKey(idempotency_key),
            )
        )

    @application.get(
        "/api/v1/policies/current",
        response_model=PolicyResponse,
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope},
        },
        tags=["policies"],
    )
    def get_current_policy(
        request: Request,
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.POLICIES_READ)
        ),
    ) -> PolicyResponse:
        _require_owner_principal(principal, request)
        policy = policies.get_current(principal, principal.owner_id)
        if policy is None:
            raise _not_found(request)
        return _policy_response(policy)

    @application.get(
        "/api/v1/policies/{version}",
        response_model=PolicyResponse,
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["policies"],
    )
    def get_policy(
        request: Request,
        version: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.POLICIES_READ)
        ),
    ) -> PolicyResponse:
        _require_owner_principal(principal, request)
        policy = policies.get(principal, principal.owner_id, version)
        if policy is None:
            raise _not_found(request)
        return _policy_response(policy)

    @application.post(
        "/api/v1/policies/{version}/select",
        response_model=PolicyResponse,
        responses={
            401: {"model": ErrorEnvelope},
            403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope},
            409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["policies"],
    )
    def select_policy(
        body: PolicySelectRequest,
        request: Request,
        version: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.POLICIES_WRITE)
        ),
    ) -> PolicyResponse:
        _require_owner_principal(principal, request)
        return _policy_response(
            policies.select_current(
                principal,
                principal.owner_id,
                version,
                expected_current_version=body.expected_current_version,
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
                idempotency_key=IdempotencyKey(idempotency_key),
            )
        )

    @application.post(
        "/api/v1/tasks",
        response_model=TaskResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["tasks"],
    )
    def create_task(
        body: TaskCreateRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.TASKS_WRITE)
        ),
    ) -> TaskResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        try:
            result = task_creation.create(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                CreateTaskRequest(
                    ProjectId(body.project_id),
                    AgentId(body.assignee_agent_id),
                    body.title,
                ),
            )
        except IdentityReferenceError:
            _record_task_creation_rejection(
                database_path, principal.agent_id, body.project_id,
                datetime.now(UTC), request.state.correlation_id,
            )
            raise
        task = task_repository.get_task(result.task_id)
        if task is None:
            raise RuntimeError("committed Task could not be restored")
        return _task_response(task, replayed=result.replayed)

    @application.get(
        "/api/v1/tasks/{task_id}",
        response_model=TaskResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["tasks"],
    )
    def get_task(
        request: Request,
        task_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.TASKS_READ)
        ),
    ) -> TaskResponse:
        task = task_repository.get_task(TaskId(task_id))
        if task is None or not _owner_can_access_project(
            database_path, principal.owner_id.value, task.project_id.value
        ):
            raise _not_found(request, "Task not found")
        return _task_response(task)

    @application.post(
        "/api/v1/tasks/{task_id}/transitions",
        response_model=TaskResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["tasks"],
    )
    def transition_task(
        body: TaskTransitionRequest,
        request: Request,
        task_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.TASKS_WRITE)
        ),
    ) -> TaskResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        result = task_transitions.transition(
            principal.agent_id,
            IdempotencyKey(idempotency_key),
            TransitionTaskCommand(
                TaskId(task_id), body.target, body.reason, body.result
            ),
            occurred_at=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        return _task_response(result.task, replayed=result.replayed)

    @application.post(
        "/api/v1/inbox/claim",
        response_model=InboxClaimResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            409: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["inbox"],
    )
    def claim_inbox(
        body: InboxClaimRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.INBOX_CLAIM)
        ),
    ) -> InboxClaimResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        long_poll_actor = (
            principal.agent_id.value if body.wait_timeout_seconds > 0 else None
        )
        if long_poll_actor is not None:
            with long_poll_guard:
                if long_poll_actor in active_long_polls:
                    raise InboxCommandConflictError(
                        "Agent already has an active long-poll"
                    )
                active_long_polls.add(long_poll_actor)
        try:
            result = inbox_commands.claim(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                now=datetime.now(UTC),
                lease_duration=timedelta(seconds=body.lease_duration_seconds),
                correlation_id=request.state.correlation_id,
                wait_timeout=timedelta(seconds=body.wait_timeout_seconds),
            )
        finally:
            if long_poll_actor is not None:
                with long_poll_guard:
                    active_long_polls.discard(long_poll_actor)
        if result.item is None:
            return InboxClaimResponse(item=None, replayed=result.replayed)
        lease = result.item.lease
        if lease is None or lease.token is None:
            raise RuntimeError("Claim result has no Lease token")
        return InboxClaimResponse(
            item=InboxLeaseResponse(
                item_id=result.item.id.value,
                task_id=result.item.task_id.value,
                attempt=result.item.attempt_count,
                lease_token=lease.token.value,
                acquired_at=lease.acquired_at,
                expires_at=lease.expires_at,
            ),
            replayed=result.replayed,
        )

    @application.post(
        "/api/v1/inbox/{item_id}/acknowledge",
        response_model=InboxFinishResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            409: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["inbox"],
    )
    def acknowledge_inbox(
        body: InboxAcknowledgeRequest,
        request: Request,
        item_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.INBOX_CLAIM)
        ),
    ) -> InboxFinishResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        result = inbox_commands.acknowledge(
            principal.agent_id, IdempotencyKey(idempotency_key),
            InboxItemId(item_id), LeaseToken(body.lease_token),
            now=datetime.now(UTC), correlation_id=request.state.correlation_id,
        )
        return _inbox_finish_response(result)

    @application.post(
        "/api/v1/inbox/{item_id}/release",
        response_model=InboxFinishResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            409: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["inbox"],
    )
    def release_inbox(
        body: InboxReleaseRequest,
        request: Request,
        item_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.INBOX_CLAIM)
        ),
    ) -> InboxFinishResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        result = inbox_commands.release(
            principal.agent_id, IdempotencyKey(idempotency_key),
            InboxItemId(item_id), LeaseToken(body.lease_token),
            now=datetime.now(UTC),
            retry_delay=timedelta(seconds=body.retry_delay_seconds),
            correlation_id=request.state.correlation_id,
        )
        return _inbox_finish_response(result)

    @application.post(
        "/api/v1/tasks/{task_id}/approval-requests",
        response_model=ApprovalResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["approvals"],
    )
    def request_approval(
        body: ApprovalRequestInput,
        request: Request,
        task_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.APPROVALS_REQUEST)
        ),
    ) -> ApprovalResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        result = approval_commands.request(
            principal.agent_id, IdempotencyKey(idempotency_key),
            RequestApprovalCommand(
                TaskId(task_id), body.repository, body.action, body.scope,
                body.risk, timedelta(seconds=body.lifetime_seconds),
            ),
            now=datetime.now(UTC), correlation_id=request.state.correlation_id,
        )
        return _approval_response(result)

    @application.get(
        "/api/v1/approvals/{approval_id}",
        response_model=ApprovalResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["approvals"],
    )
    def get_approval(
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.APPROVALS_READ)
        ),
    ) -> ApprovalResponse:
        identifier = ApprovalId(approval_id)
        if principal.subject_type is CredentialSubjectType.AGENT:
            if principal.agent_id is None:
                raise _permission_denied(request)
            approval = approval_commands.get_for_agent(principal.agent_id, identifier)
        else:
            approval = approval_commands.get_for_owner(principal.owner_id, identifier)
        if approval is None:
            raise _not_found(request, "Approval not found")
        return _approval_response(ApprovalCommandResult(approval, replayed=False))

    @application.post(
        "/api/v1/approvals/{approval_id}/decide",
        response_model=ApprovalResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["approvals"],
    )
    def decide_approval(
        body: ApprovalDecisionInput,
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.APPROVALS_DECIDE)
        ),
    ) -> ApprovalResponse:
        _require_owner_principal(principal, request)
        if body.decision == "rejected" and (
            body.reason is None or not body.reason.strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail={"code": "validation_error", "message": "Reason is required"},
            )
        result = approval_commands.decide(
            principal.owner_id, IdempotencyKey(idempotency_key),
            DecideApprovalCommand(
                ApprovalId(approval_id), body.decision == "approved", body.reason,
            ),
            now=datetime.now(UTC), correlation_id=request.state.correlation_id,
        )
        return _approval_response(result)

    @application.post(
        "/api/v1/approvals/{approval_id}/action-grant",
        response_model=ActionGrantResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["actions"],
    )
    def prepare_action_grant(
        body: ActionGrantPrepareRequest,
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ACTIONS_EXECUTE)
        ),
    ) -> ActionGrantResponse:
        _require_agent_principal(principal, request)
        return _action_grant_response(
            remote_action_grants.prepare(
                principal.agent_id,
                ApprovalId(approval_id),
                PrepareRemoteActionCommand(
                    WorkspaceBindingId(body.workspace_id),
                    EvidenceId(body.evidence_id),
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/approvals/{approval_id}/action-grant",
        response_model=ActionGrantResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["actions"],
    )
    def get_action_grant(
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ACTIONS_EXECUTE)
        ),
    ) -> ActionGrantResponse:
        _require_agent_principal(principal, request)
        view = remote_action_grants.get(principal.agent_id, ApprovalId(approval_id))
        if view is None:
            raise _not_found(request, "Action Grant not found")
        return _action_grant_response(view)

    @application.post(
        "/api/v1/approvals/{approval_id}/action-grant/result-unknown",
        response_model=ActionGrantResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["actions"],
    )
    def mark_action_result_unknown(
        body: ActionResultUnknownRequest,
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ACTIONS_EXECUTE)
        ),
    ) -> ActionGrantResponse:
        _require_agent_principal(principal, request)
        return _action_grant_response(
            remote_action_grants.mark_result_unknown(
                principal.agent_id,
                ApprovalId(approval_id),
                body.request_fingerprint,
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.post(
        "/api/v1/approvals/{approval_id}/action-receipts",
        response_model=ActionGrantResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope}, 503: {"model": ErrorEnvelope},
        },
        tags=["actions"],
    )
    def submit_action_receipt(
        body: ActionReceiptSubmitRequest,
        request: Request,
        approval_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ACTIONS_EXECUTE)
        ),
    ) -> ActionGrantResponse:
        _require_agent_principal(principal, request)
        return _action_grant_response(
            remote_action_grants.submit_receipt(
                principal.agent_id,
                ApprovalId(approval_id),
                SubmitActionReceiptCommand(
                    body.request_fingerprint,
                    body.external_action_id,
                    body.result_reference,
                    body.occurred_at,
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/audit-events",
        response_model=AuditEventPageResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["audit"],
    )
    def list_audit_events(
        request: Request,
        resource_type: AuditResourceType = Query(),
        resource_id: str = Query(min_length=1, max_length=255),
        cursor: str | None = Query(default=None, min_length=1, max_length=255),
        limit: int = Query(default=50, ge=1, le=100),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.AUDITS_READ)
        ),
    ) -> AuditEventPageResponse:
        _require_owner_principal(principal, request)
        page = audit_queries.list_resource(
            principal, resource_type, resource_id, cursor=cursor, limit=limit,
            correlation_id=request.state.correlation_id,
        )
        return _audit_page_response(page)

    @application.post(
        "/api/v1/evidence",
        response_model=EvidenceSubmissionResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["evidence"],
    )
    def reserve_evidence(
        body: EvidenceReservationRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVIDENCE_WRITE)
        ),
    ) -> EvidenceSubmissionResponse:
        _require_agent_principal(principal, request)
        return _evidence_submission_response(
            evidence_submissions.reserve(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                ReserveEvidenceCommand(
                    TaskId(body.task_id),
                    WorkspaceBindingId(body.workspace_id),
                    body.kind,
                    body.attempt,
                    None if body.retry_of is None else EvidenceId(body.retry_of),
                    body.observed_at,
                    body.head_commit,
                    tuple(ArtifactId(item) for item in body.artifact_ids),
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.post(
        "/api/v1/evidence/{evidence_id}/finalize",
        response_model=EvidenceSubmissionResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["evidence"],
    )
    def finalize_evidence(
        body: EvidenceFinalizeRequest,
        request: Request,
        evidence_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVIDENCE_WRITE)
        ),
    ) -> EvidenceSubmissionResponse:
        _require_agent_principal(principal, request)
        return _evidence_submission_response(
            evidence_submissions.finalize(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                EvidenceId(evidence_id),
                body.payload_json,
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/evidence/{evidence_id}",
        response_model=EvidenceAccessResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["evidence"],
    )
    def get_evidence(
        request: Request,
        evidence_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.EVIDENCE_READ)
        ),
    ) -> EvidenceAccessResponse:
        view = artifact_access.get_evidence(
            principal, EvidenceId(evidence_id), now=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        if view is None:
            raise _not_found(request, "Evidence not found")
        return _evidence_access_response(view)

    @application.post(
        "/api/v1/artifacts",
        response_model=ArtifactUploadResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["artifacts"],
    )
    def reserve_artifact(
        body: ArtifactReservationRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ARTIFACTS_WRITE)
        ),
    ) -> ArtifactUploadResponse:
        _require_agent_principal(principal, request)
        return _artifact_upload_response(
            artifact_uploads.reserve(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                ReserveArtifactCommand(
                    TaskId(body.task_id), body.media_type, body.declared_size,
                    body.declared_sha256, body.purpose,
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/artifacts/{artifact_id}",
        response_model=ArtifactMetadataResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["artifacts"],
    )
    def get_artifact_metadata(
        request: Request,
        artifact_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ARTIFACTS_READ)
        ),
    ) -> ArtifactMetadataResponse:
        artifact = artifact_access.get_artifact(
            principal, ArtifactId(artifact_id), now=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        if artifact is None:
            raise _not_found(request, "Artifact not found")
        return _artifact_metadata_response(artifact)

    @application.get(
        "/api/v1/artifacts/{artifact_id}/content",
        response_class=StreamingResponse,
        responses={
            200: {
                "description": "Integrity-checked finalized Artifact Body",
                "headers": {
                    "Content-Length": {"schema": {"type": "integer"}},
                    "Digest": {"schema": {"type": "string"}},
                    "Content-Disposition": {"schema": {"type": "string"}},
                    "X-Content-Type-Options": {"schema": {"type": "string"}},
                    "Cache-Control": {"schema": {"type": "string"}},
                },
                "content": {
                    "application/json": {},
                    "application/octet-stream": {},
                    "text/plain": {},
                }
            },
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["artifacts"],
    )
    def download_artifact_content(
        request: Request,
        artifact_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ARTIFACTS_READ)
        ),
    ) -> StreamingResponse:
        download = artifact_access.open_artifact(
            principal, ArtifactId(artifact_id), now=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        if download is None:
            raise _not_found(request, "Artifact not found")
        artifact = download.artifact
        if artifact.actual_size is None or artifact.actual_sha256 is None:
            download.stream.close()
            raise RuntimeError("Finalized Artifact metadata is incomplete")
        return StreamingResponse(
            download.iter_bytes(),
            headers={
                "Content-Type": artifact.media_type,
                "Content-Length": str(artifact.actual_size),
                "Digest": _digest_header(artifact.actual_sha256),
                "Content-Disposition": 'attachment; filename="artifact.bin"',
                "X-Content-Type-Options": "nosniff",
                "Cache-Control": "private, no-store",
            },
        )

    @application.put(
        "/api/v1/artifacts/{artifact_id}/content",
        response_model=ArtifactUploadResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            413: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["artifacts"],
    )
    async def upload_artifact_content(
        request: Request,
        artifact_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        digest: str = Header(alias="Digest", min_length=1, max_length=128),
        content_type: str = Header(alias="Content-Type", min_length=1, max_length=128),
        content_length: int | None = Header(
            default=None, alias="Content-Length", ge=0
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ARTIFACTS_WRITE)
        ),
    ) -> ArtifactUploadResponse:
        _require_agent_principal(principal, request)
        declared_digest = _content_digest_sha256(digest)
        media_type = content_type.split(";", 1)[0].strip().lower()
        try:
            staged_path, actual_size, actual_sha256 = await _stage_artifact_body(
                request, artifact_root_path, content_length
            )
        except HTTPException as error:
            if error.status_code == status.HTTP_413_CONTENT_TOO_LARGE:
                artifact_uploads.record_rejection(
                    principal.agent_id,
                    ArtifactId(artifact_id),
                    reason="artifact_payload_too_large",
                    now=datetime.now(UTC),
                    correlation_id=request.state.correlation_id,
                )
            raise
        return _artifact_upload_response(
            artifact_uploads.upload(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                ArtifactId(artifact_id),
                staged_path=staged_path,
                actual_size=actual_size,
                actual_sha256=actual_sha256,
                content_sha256=declared_digest,
                media_type=media_type,
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.post(
        "/api/v1/artifacts/{artifact_id}/finalize",
        response_model=ArtifactUploadResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["artifacts"],
    )
    def finalize_artifact(
        request: Request,
        artifact_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.ARTIFACTS_WRITE)
        ),
    ) -> ArtifactUploadResponse:
        _require_agent_principal(principal, request)
        return _artifact_upload_response(
            artifact_uploads.finalize(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                ArtifactId(artifact_id),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.post(
        "/api/v1/work-records",
        response_model=WorkRecordResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["work-records"],
    )
    def create_work_record(
        body: WorkRecordCreateRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.WORK_RECORDS_WRITE)
        ),
    ) -> WorkRecordResponse:
        _require_agent_principal(principal, request)
        return _work_record_response(
            knowledge.create_work_record(
                principal.agent_id,
                IdempotencyKey(idempotency_key),
                CreateWorkRecordCommand(
                    TaskId(body.task_id),
                    body.record_type,
                    body.claim_text,
                    tuple(EvidenceId(item) for item in body.evidence_ids),
                ),
                now=datetime.now(UTC),
                correlation_id=request.state.correlation_id,
            )
        )

    @application.get(
        "/api/v1/work-records/{work_record_id}",
        response_model=WorkRecordResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["work-records"],
    )
    def get_work_record(
        request: Request,
        work_record_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.WORK_RECORDS_READ)
        ),
    ) -> WorkRecordResponse:
        view = knowledge.get_work_record(
            principal, WorkRecordId(work_record_id)
        )
        if view is None:
            raise _not_found(request, "Work Record not found")
        return _work_record_view_response(view)

    @application.post(
        "/api/v1/memories",
        response_model=MemoryResponse,
        status_code=status.HTTP_201_CREATED,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["memories"],
    )
    def promote_memory(
        body: MemoryPromotionRequest,
        request: Request,
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.MEMORIES_WRITE)
        ),
    ) -> MemoryResponse:
        _require_agent_principal(principal, request)
        result = knowledge.promote_memory(
            principal.agent_id,
            IdempotencyKey(idempotency_key),
            PromoteMemoryCommand(
                WorkRecordId(body.source_work_record_id),
                EvidenceId(body.code_scope_evidence_id),
            ),
            now=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        return _memory_response(result.view, replayed=result.replayed)

    @application.get(
        "/api/v1/memories",
        response_model=MemorySearchResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["memories"],
    )
    def search_memories(
        request: Request,
        query: str = Query(min_length=1, max_length=1024),
        project_id: str = Query(min_length=1, max_length=255),
        repository: str = Query(min_length=1, max_length=255),
        validation_status: MemoryValidationStatus | None = Query(default=None),
        applicability_status: ApplicabilityStatus | None = Query(default=None),
        limit: int = Query(default=20, ge=1, le=100),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.MEMORIES_READ)
        ),
    ) -> MemorySearchResponse:
        memories = knowledge.search_memories(
            principal,
            MemorySearchRequest(
                query,
                ProjectId(project_id),
                repository,
                validation_status,
                applicability_status,
                limit,
            ),
        )
        return MemorySearchResponse(
            items=tuple(_memory_response(item) for item in memories)
        )

    @application.get(
        "/api/v1/memories/{memory_id}",
        response_model=MemoryResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 422: {"model": ErrorEnvelope},
        },
        tags=["memories"],
    )
    def get_memory(
        request: Request,
        memory_id: str = ApiPath(min_length=1, max_length=255),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.MEMORIES_READ)
        ),
    ) -> MemoryResponse:
        memory = knowledge.get_memory(principal, MemoryId(memory_id))
        if memory is None:
            raise _not_found(request, "Memory not found")
        return _memory_response(memory)

    @application.post(
        "/api/v1/work-records/{work_record_id}/validations",
        response_model=WorkRecordValidationResponse,
        responses={
            401: {"model": ErrorEnvelope}, 403: {"model": ErrorEnvelope},
            404: {"model": ErrorEnvelope}, 409: {"model": ErrorEnvelope},
            422: {"model": ErrorEnvelope},
        },
        tags=["work-records"],
    )
    def validate_work_record(
        body: WorkRecordValidationRequest,
        request: Request,
        work_record_id: str = ApiPath(min_length=1, max_length=255),
        idempotency_key: str = Header(
            alias="Idempotency-Key", min_length=16, max_length=128,
            pattern=r"^[!-~]+$",
        ),
        principal: AuthenticatedPrincipal = Depends(
            require_scope(CredentialScope.WORK_RECORDS_WRITE)
        ),
    ) -> WorkRecordValidationResponse:
        if (
            principal.subject_type is not CredentialSubjectType.AGENT
            or principal.agent_id is None
        ):
            raise _permission_denied(request)
        result = authoritative_validation.validate(
            principal.agent_id,
            IdempotencyKey(idempotency_key),
            ValidateWorkRecordCommand(WorkRecordId(work_record_id), body.rule),
            occurred_at=datetime.now(UTC),
            correlation_id=request.state.correlation_id,
        )
        event = result.event
        if event.from_status is None:
            raise RuntimeError("Validation Event has no source status")
        return WorkRecordValidationResponse(
            event_id=event.id.value,
            work_record_id=event.work_record_id.value,
            sequence=event.sequence,
            from_status=event.from_status.value,
            to_status=event.to_status.value,
            rule_id=event.rule_id,
            evidence_ids=tuple(item.value for item in event.evidence_ids),
            occurred_at=event.occurred_at,
            replayed=result.replayed,
        )

    return application


def _unauthenticated(request: Request) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "code": "unauthenticated",
            "message": "Invalid credential",
            "retryable": False,
            "correlation_id": request.state.correlation_id,
        },
        headers={"WWW-Authenticate": "Bearer"},
    )


def _permission_denied(request: Request) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail={"code": "permission_denied", "message": "Permission denied"},
    )


def _not_found(request: Request, message: str = "Policy not found") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={"code": "not_found", "message": message},
    )


def _require_owner_principal(
    principal: AuthenticatedPrincipal, request: Request
) -> None:
    if principal.subject_type is not CredentialSubjectType.OWNER:
        raise _permission_denied(request)


def _require_agent_principal(
    principal: AuthenticatedPrincipal, request: Request
) -> None:
    if (
        principal.subject_type is not CredentialSubjectType.AGENT
        or principal.agent_id is None
    ):
        raise _permission_denied(request)


def _work_record_response(result: WorkRecordCommandResult) -> WorkRecordResponse:
    return _work_record_view_response(result.view, replayed=result.replayed)


def _work_record_view_response(
    view: WorkRecordView, *, replayed: bool | None = None
) -> WorkRecordResponse:
    record = view.record
    return WorkRecordResponse(
        id=record.id.value,
        task_id=record.task_id.value,
        actor_agent_id=record.actor_id.value,
        record_type=record.record_type.value,
        claim_text=record.claim_text,
        evidence_ids=tuple(item.id.value for item in record.observed),
        created_at=record.created_at,
        current_status=view.current_status.value,
        latest_event_id=view.latest_event_id.value,
        latest_sequence=view.latest_sequence,
        replayed=replayed,
    )


def _memory_response(
    view: MemoryView, *, replayed: bool | None = None
) -> MemoryResponse:
    memory = view.memory
    scope = view.code_scope
    applicability = view.latest_applicability
    return MemoryResponse(
        id=memory.id.value,
        source_work_record_id=memory.source_work_record_id.value,
        source_validation_event_id=memory.source_validation_event_id.value,
        task_id=memory.task_id.value,
        source_actor_id=memory.source_actor_id.value,
        promoted_by_agent_id=memory.promoted_by_agent_id.value,
        record_type=memory.record_type.value,
        content=memory.content,
        validation_rule_id=memory.validation_rule_id,
        evidence_ids=tuple(item.value for item in memory.evidence_ids),
        validation_status=memory.validation_status.value,
        applicability_status=memory.applicability_status.value,
        promotion_rule_id=memory.promotion_rule_id,
        promoted_at=memory.promoted_at,
        code_scope=None if scope is None else MemoryCodeScopeResponse(
            source_evidence_id=scope.source_evidence_id.value,
            repository=scope.repository,
            ref=scope.ref,
            commit=scope.commit,
            paths=scope.paths,
        ),
        latest_applicability=(
            None if applicability is None else MemoryApplicabilityResponse(
                id=applicability.id,
                sequence=applicability.sequence,
                previous_assessment_id=applicability.previous_assessment_id,
                status=applicability.status.value,
                reason=applicability.reason.value,
                memory_commit=applicability.memory_commit,
                current_commit=applicability.current_commit,
                changed_paths=applicability.changed_paths,
                checked_at=applicability.checked_at,
            )
        ),
        replacement_memory_id=(
            None
            if view.replacement_memory_id is None
            else view.replacement_memory_id.value
        ),
        replayed=replayed,
    )


def _artifact_upload_response(result: ArtifactCommandResult) -> ArtifactUploadResponse:
    artifact = result.artifact
    return ArtifactUploadResponse(
        id=artifact.id.value,
        task_id=artifact.task_id.value,
        media_type=artifact.media_type,
        purpose=artifact.purpose.value,
        declared_size=artifact.declared_size,
        declared_sha256=artifact.declared_sha256,
        status=artifact.status.value,
        actual_size=artifact.actual_size,
        actual_sha256=artifact.actual_sha256,
        created_at=artifact.created_at,
        uploaded_at=artifact.uploaded_at,
        finalized_at=artifact.finalized_at,
        security_status=artifact.security_status.value,
        availability_status=artifact.availability_status.value,
        scanner_version=artifact.scanner_version,
        scanned_at=artifact.scanned_at,
        redaction_count=artifact.redaction_count,
        source_artifact_id=(
            None if artifact.source_artifact_id is None
            else artifact.source_artifact_id.value
        ),
        derived_artifact_id=(
            None if artifact.derived_artifact_id is None
            else artifact.derived_artifact_id.value
        ),
        replayed=result.replayed,
    )


def _artifact_metadata_response(artifact) -> ArtifactMetadataResponse:
    if (
        artifact.actual_size is None
        or artifact.actual_sha256 is None
        or artifact.finalized_at is None
    ):
        raise RuntimeError("Finalized Artifact metadata is incomplete")
    return ArtifactMetadataResponse(
        id=artifact.id.value,
        task_id=artifact.task_id.value,
        media_type=artifact.media_type,
        purpose=artifact.purpose.value,
        size=artifact.actual_size,
        sha256=artifact.actual_sha256,
        created_at=artifact.created_at,
        finalized_at=artifact.finalized_at,
        security_status=artifact.security_status.value,
        availability_status=artifact.availability_status.value,
        scanner_version=artifact.scanner_version,
        scanned_at=artifact.scanned_at,
        redaction_count=artifact.redaction_count,
        source_artifact_id=(
            None if artifact.source_artifact_id is None
            else artifact.source_artifact_id.value
        ),
        derived_artifact_id=(
            None if artifact.derived_artifact_id is None
            else artifact.derived_artifact_id.value
        ),
    )


def _evidence_submission_response(
    result: EvidenceSubmissionResult,
) -> EvidenceSubmissionResponse:
    evidence = result.evidence
    return EvidenceSubmissionResponse(
        id=evidence.id.value,
        task_id=evidence.task_id.value,
        workspace_id=evidence.workspace_id.value,
        kind=evidence.kind.value,
        attempt=evidence.attempt,
        retry_of=None if evidence.retry_of is None else evidence.retry_of.value,
        observed_at=evidence.observed_at,
        head_commit=evidence.head_commit,
        artifact_ids=tuple(item.value for item in evidence.artifact_ids),
        status=evidence.status.value,
        payload_sha256=evidence.payload_sha256,
        created_at=evidence.created_at,
        finalized_at=evidence.finalized_at,
        replayed=result.replayed,
    )


def _evidence_access_response(view: EvidenceAccessView) -> EvidenceAccessResponse:
    evidence = view.evidence
    if evidence.payload_sha256 is None or evidence.finalized_at is None:
        raise RuntimeError("Finalized Evidence metadata is incomplete")
    return EvidenceAccessResponse(
        id=evidence.id.value,
        task_id=evidence.task_id.value,
        workspace_id=evidence.workspace_id.value,
        kind=evidence.kind.value,
        attempt=evidence.attempt,
        retry_of=None if evidence.retry_of is None else evidence.retry_of.value,
        observed_at=evidence.observed_at,
        head_commit=evidence.head_commit,
        artifact_ids=tuple(item.value for item in evidence.artifact_ids),
        payload_sha256=evidence.payload_sha256,
        payload_json=view.payload_json,
        created_at=evidence.created_at,
        finalized_at=evidence.finalized_at,
    )


def _content_digest_sha256(value: str) -> str:
    prefix = "sha-256=:"
    if not value.startswith(prefix) or not value.endswith(":"):
        raise ValueError("Digest must use sha-256 structured field syntax")
    try:
        decoded = base64.b64decode(value[len(prefix):-1], validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("Digest is invalid") from error
    if len(decoded) != 32:
        raise ValueError("Digest is invalid")
    return decoded.hex()


def _digest_header(value: str) -> str:
    return f"sha-256=:{base64.b64encode(bytes.fromhex(value)).decode('ascii')}:"


async def _stage_artifact_body(
    request: Request, artifact_root: Path, content_length: int | None
) -> tuple[Path, int, str]:
    if content_length is not None and content_length > MAX_ARTIFACT_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail={"code": "payload_too_large", "message": "Artifact is too large"},
        )
    staging = artifact_root.resolve(strict=False) / ".staging"
    staging.mkdir(parents=True, exist_ok=True)
    path = staging / f"{uuid4()}.tmp"
    size = 0
    digest = hashlib.sha256()
    try:
        with path.open("xb") as stream:
            async for chunk in request.stream():
                size += len(chunk)
                if size > MAX_ARTIFACT_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                        detail={
                            "code": "payload_too_large",
                            "message": "Artifact is too large",
                        },
                    )
                digest.update(chunk)
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if content_length is not None and size != content_length:
            raise ValueError("Content-Length does not match Artifact body")
        return path, size, digest.hexdigest()
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _verify_artifact_storage_ready(artifact_root: Path) -> None:
    if artifact_root.is_symlink():
        raise RuntimeError("Artifact storage is unsafe")
    root = artifact_root.resolve(strict=True)
    staging = root / ".staging"
    quarantine = root / "quarantine"
    available = root / "available"
    if any(
        path.is_symlink() or not path.is_dir()
        for path in (root, staging, quarantine, available)
    ):
        raise RuntimeError("Artifact storage is unavailable")
    probe = staging / f"{uuid4()}.ready"
    try:
        with probe.open("xb") as stream:
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        probe.unlink(missing_ok=True)


def _policy_response(policy: OwnerPolicy) -> PolicyResponse:
    return PolicyResponse(
        version=policy.version,
        rules=[
            PolicyRuleResponse(
                action=rule.action,
                outcome=rule.outcome,
                max_auto_risk=rule.max_auto_risk,
            )
            for rule in policy.rules
        ],
    )


def _task_response(task: Task, replayed: bool | None = None) -> TaskResponse:
    return TaskResponse(
        id=task.id.value,
        project_id=task.project_id.value,
        assignee_agent_id=task.assignee_agent_id.value,
        title=task.title,
        status=task.status.value,
        result=task.result,
        replayed=replayed,
    )


def _workspace_view_response(
    workspace: WorkspaceView, replayed: bool | None = None
) -> WorkspaceResponse:
    return WorkspaceResponse(
        id=workspace.id.value,
        task_id=workspace.task_id.value,
        actor_agent_id=workspace.actor_agent_id.value,
        repository=workspace.repository,
        bound_at=workspace.bound_at,
        replayed=replayed,
    )


def _workspace_response(result: WorkspaceCommandResult) -> WorkspaceResponse:
    return _workspace_view_response(result.workspace, result.replayed)


def _event_view_response(
    event: CodeChangeImpactView, replayed: bool | None = None
) -> CodeChangeImpactResponse:
    return CodeChangeImpactResponse(
        id=event.id.value,
        project_id=event.project_id.value,
        publisher_agent_id=event.publisher_agent_id.value,
        target_agent_id=event.target_agent_id.value,
        task_id=event.task_id.value,
        inbox_item_id=event.inbox_item_id.value,
        title=event.title,
        repository=event.repository,
        ref=event.ref,
        baseline_commit=event.baseline_commit,
        head_commit=event.head_commit,
        changed_paths=event.changed_paths,
        evidence_id=event.evidence_id.value,
        impact_kind=event.impact_kind.value,
        affected_api=event.affected_api,
        occurred_at=event.occurred_at,
        replayed=replayed,
    )


def _event_result_response(result: EventCommandResult) -> CodeChangeImpactResponse:
    return _event_view_response(result.event, result.replayed)


def _inbox_finish_response(result: FinishInboxResult) -> InboxFinishResponse:
    return InboxFinishResponse(
        item_id=result.item_id.value,
        status=result.status.value,
        attempt=result.attempt,
        available_at=result.available_at,
        replayed=result.replayed,
    )


def _approval_response(result: ApprovalCommandResult) -> ApprovalResponse:
    approval = result.approval
    intent = approval.decision.intent
    if intent.task_id is None:
        raise RuntimeError("Task Approval has no Task")
    return ApprovalResponse(
        id=approval.id.value, status=approval.status.value,
        requester_agent_id=intent.requester_agent_id.value,
        receiving_agent_id=intent.receiving_agent_id.value,
        task_id=intent.task_id.value, repository=intent.repository,
        action=intent.action.value, scope=intent.scope, risk=int(intent.risk),
        policy_version=approval.decision.policy_version,
        requested_at=approval.requested_at, expires_at=approval.expires_at,
        resolved_by_owner_id=(
            None if approval.resolved_by is None else approval.resolved_by.value
        ),
        resolved_at=approval.resolved_at, reason=approval.reason,
        replayed=result.replayed,
    )


def _action_grant_response(view: RemoteActionGrantView) -> ActionGrantResponse:
    receipt = view.receipt
    return ActionGrantResponse(
        approval_id=view.approval_id.value,
        operation_id=view.operation_id,
        request_fingerprint=view.request_fingerprint,
        workspace_id=view.workspace_id.value,
        evidence_id=view.evidence_id.value,
        commit_sha=view.commit_sha,
        execute_before=view.execute_before,
        status=view.status.value,
        started_at=view.started_at,
        receipt=(
            None
            if receipt is None
            else ActionReceiptResponse(
                operation_id=receipt.operation_id,
                request_fingerprint=receipt.request_fingerprint,
                external_action_id=receipt.external_action_id,
                result_reference=receipt.result_reference,
                occurred_at=receipt.occurred_at,
            )
        ),
        replayed=view.replayed,
    )


def _audit_page_response(page: AuditEventPage) -> AuditEventPageResponse:
    def reason_category(outcome: str) -> str:
        return {
            "allow": "allowed",
            "approval_required": "approval_required",
            "deny": "denied",
            "rejected": "denied",
        }.get(outcome, "recorded")

    return AuditEventPageResponse(
        items=tuple(
            AuditEventResponse(
                id=event.id.value, kind=event.kind.value,
                actor_kind=event.actor_kind.value, actor_id=event.actor_id,
                resource_type=event.resource_type, resource_id=event.resource_id,
                action=event.action, outcome=event.outcome.value,
                reason_category=reason_category(event.outcome.value),
                occurred_at=event.occurred_at,
                policy_version=event.policy_version,
                correlation_id=event.correlation_id,
            )
            for event in page.items
        ),
        next_cursor=page.next_cursor,
    )


def _owner_can_access_project(
    database: Path, owner_id: str, project_id: str
) -> bool:
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT 1 FROM tas_projects project "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "WHERE project.id=? AND member.owner_id=?",
            (project_id, owner_id),
        ).fetchone()
    return row is not None


def _record_task_creation_rejection(
    database: Path, actor_id: AgentId, project_id: str, occurred_at: datetime,
    correlation_id: str,
) -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
            "resource_id,action,outcome,reason,occurred_at,policy_version,"
            "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()), "authorization_decision", "agent", actor_id.value,
                "project", project_id, "task.create", "rejected",
                "task_target_unavailable", occurred_at.isoformat(), None,
                correlation_id,
            ),
        )


def _error(
    status_code: int,
    code: str,
    message: str,
    correlation_id: str,
    retryable: bool = False,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error": {
                "code": code,
                "message": message,
                "retryable": retryable,
                "correlation_id": correlation_id,
            }
        },
        headers={"X-Correlation-ID": correlation_id},
    )
