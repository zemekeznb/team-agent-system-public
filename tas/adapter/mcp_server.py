"""MCP tools backed only by the remote F3 Application API."""

from __future__ import annotations

from typing import Annotated, Protocol, TypedDict

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field, StrictInt, StrictStr

from tas.adapter.actions import AdapterActionService, ExecutedAction
from tas.adapter.evidence import AdapterEvidenceService, PublishedEvidence
from tas.adapter.http_client import (
    AdapterSession,
    RemoteInboxClaim,
    RemoteInboxFinish,
    RemoteTask,
    TASRemoteClient,
)
from tas.observability.logging import get_logger


Identifier = Annotated[
    StrictStr,
    Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
LeaseTokenArgument = Annotated[
    StrictStr,
    Field(min_length=16, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"),
]
IdempotencyKey = Annotated[
    StrictStr,
    Field(
        min_length=16,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
TaskTitle = Annotated[StrictStr, Field(min_length=1, max_length=1024)]
GitRevision = Annotated[StrictStr, Field(min_length=1, max_length=255)]
EvidenceAttempt = Annotated[StrictInt, Field(ge=1, le=16)]
LeaseDuration = Annotated[StrictInt, Field(ge=5, le=300)]
WaitTimeout = Annotated[StrictInt, Field(ge=0, le=25)]
RetryDelay = Annotated[StrictInt, Field(ge=0, le=604800)]
logger = get_logger("adapter.mcp")


class RemoteClient(Protocol):
    def get_session(self) -> AdapterSession: ...

    def create_task(
        self,
        *,
        idempotency_key: str,
        project_id: str,
        assignee_agent_id: str,
        title: str,
    ) -> RemoteTask: ...

    def get_task(self, task_id: str) -> RemoteTask: ...

    def claim_inbox(
        self, *, idempotency_key: str, lease_duration_seconds: int,
        wait_timeout_seconds: int = 0,
    ) -> RemoteInboxClaim: ...

    def acknowledge_inbox(
        self, *, idempotency_key: str, item_id: str, lease_token: str,
    ) -> RemoteInboxFinish: ...

    def release_inbox(
        self, *, idempotency_key: str, item_id: str, lease_token: str,
        retry_delay_seconds: int,
    ) -> RemoteInboxFinish: ...


class SessionToolResult(TypedDict):
    owner_id: str
    agent_id: str
    credential_id: str
    scopes: list[str]
    expires_at: str
    correlation_id: str


class TaskToolResult(TypedDict):
    task_id: str
    project_id: str
    assignee_agent_id: str
    title: str
    status: str
    result: str | None
    replayed: bool | None
    correlation_id: str


class InboxLeaseToolResult(TypedDict):
    item_id: str
    task_id: str
    attempt: int
    lease_token: str
    acquired_at: str
    expires_at: str


class InboxClaimToolResult(TypedDict):
    item: InboxLeaseToolResult | None
    replayed: bool
    correlation_id: str


class InboxFinishToolResult(TypedDict):
    item_id: str
    status: str
    attempt: int
    available_at: str | None
    replayed: bool
    correlation_id: str


class EvidenceToolResult(TypedDict):
    evidence_id: str
    kind: str
    task_id: str
    workspace_id: str
    head_commit: str
    artifact_ids: list[str]
    replayed: bool
    correlation_id: str


class ActionToolResult(TypedDict):
    approval_id: str
    operation_id: str
    status: str
    external_action_id: str | None
    result_reference: str | None
    replayed: bool
    correlation_id: str


def _forbid_extra_tool_arguments(server: FastMCP) -> None:
    for registered in server._tool_manager.list_tools():
        registered.fn_metadata.arg_model.model_config["extra"] = "forbid"
        registered.fn_metadata.arg_model.model_rebuild(force=True)
        registered.parameters = registered.fn_metadata.arg_model.model_json_schema(
            by_alias=True
        )


def create_remote_mcp_server(
    *,
    client: RemoteClient,
    startup_session: AdapterSession,
    evidence_service: AdapterEvidenceService,
    action_service: AdapterActionService,
) -> FastMCP:
    """Create an Agent-facing server with no caller-controlled actor fields."""
    if startup_session.agent_id is None:
        raise ValueError("Remote MCP requires an Agent Credential")
    required = {
        "session:read",
        "tasks:read",
        "tasks:write",
        "evidence:write",
        "artifacts:write",
        "actions:execute",
        "approvals:read",
        "inbox:claim",
    }
    if not required.issubset(startup_session.scopes):
        raise ValueError("Remote MCP Credential lacks required scopes")

    server = FastMCP("Team Agent System Remote Adapter")

    @server.tool(name="tas_session", structured_output=True)
    def session(ctx: Context) -> SessionToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_session",
            },
        )
        current = client.get_session()
        if (
            current.owner_id != startup_session.owner_id
            or current.agent_id != startup_session.agent_id
            or current.credential_id != startup_session.credential_id
        ):
            raise RuntimeError("Authenticated Session binding changed")
        return {
            "owner_id": current.owner_id,
            "agent_id": current.agent_id,
            "credential_id": current.credential_id,
            "scopes": list(current.scopes),
            "expires_at": current.expires_at.isoformat(),
            "correlation_id": current.correlation_id,
        }

    @server.tool(name="tas_create_task", structured_output=True)
    def create_task(
        idempotency_key: IdempotencyKey,
        project_id: Identifier,
        assignee_agent_id: Identifier,
        title: TaskTitle,
        ctx: Context,
    ) -> TaskToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_create_task",
            },
        )
        return _task_result(
            client.create_task(
                idempotency_key=idempotency_key,
                project_id=project_id,
                assignee_agent_id=assignee_agent_id,
                title=title,
            )
        )

    @server.tool(name="tas_task_get", structured_output=True)
    def get_task(task_id: Identifier, ctx: Context) -> TaskToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_task_get",
            },
        )
        return _task_result(client.get_task(task_id))

    @server.tool(name="tas_inbox_claim", structured_output=True)
    def claim_inbox(
        idempotency_key: IdempotencyKey,
        lease_duration_seconds: LeaseDuration,
        wait_timeout_seconds: WaitTimeout,
        ctx: Context,
    ) -> InboxClaimToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_inbox_claim",
            },
        )
        return _inbox_claim_result(client.claim_inbox(
            idempotency_key=idempotency_key,
            lease_duration_seconds=lease_duration_seconds,
            wait_timeout_seconds=wait_timeout_seconds,
        ))

    @server.tool(name="tas_inbox_acknowledge", structured_output=True)
    def acknowledge_inbox(
        item_id: Identifier,
        lease_token: LeaseTokenArgument,
        idempotency_key: IdempotencyKey,
        ctx: Context,
    ) -> InboxFinishToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_inbox_acknowledge",
            },
        )
        return _inbox_finish_result(client.acknowledge_inbox(
            idempotency_key=idempotency_key,
            item_id=item_id,
            lease_token=lease_token,
        ))

    @server.tool(name="tas_inbox_release", structured_output=True)
    def release_inbox(
        item_id: Identifier,
        lease_token: LeaseTokenArgument,
        retry_delay_seconds: RetryDelay,
        idempotency_key: IdempotencyKey,
        ctx: Context,
    ) -> InboxFinishToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_inbox_release",
            },
        )
        return _inbox_finish_result(client.release_inbox(
            idempotency_key=idempotency_key,
            item_id=item_id,
            lease_token=lease_token,
            retry_delay_seconds=retry_delay_seconds,
        ))

    @server.tool(name="tas_collect_git_evidence", structured_output=True)
    def collect_git_evidence(
        workspace_id: Identifier,
        baseline: GitRevision,
        idempotency_key: IdempotencyKey,
        ctx: Context,
    ) -> EvidenceToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_collect_git_evidence",
            },
        )
        return _evidence_result(
            evidence_service.collect_git(
                workspace_id=workspace_id,
                baseline=baseline,
                idempotency_key=idempotency_key,
            )
        )

    @server.tool(name="tas_run_test_evidence", structured_output=True)
    def run_test_evidence(
        workspace_id: Identifier,
        profile_name: Identifier,
        attempt: EvidenceAttempt,
        retry_of: Identifier | None,
        idempotency_key: IdempotencyKey,
        ctx: Context,
    ) -> EvidenceToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_run_test_evidence",
            },
        )
        return _evidence_result(
            evidence_service.run_test(
                workspace_id=workspace_id,
                profile_name=profile_name,
                attempt=attempt,
                retry_of=retry_of,
                idempotency_key=idempotency_key,
            )
        )

    @server.tool(name="tas_execute_approved_git_commit", structured_output=True)
    def execute_approved_git_commit(
        approval_id: Identifier,
        workspace_id: Identifier,
        evidence_id: Identifier,
        idempotency_key: IdempotencyKey,
        ctx: Context,
    ) -> ActionToolResult:
        logger.info(
            "adapter.mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": startup_session.agent_id,
                "tool": "tas_execute_approved_git_commit",
            },
        )
        return _action_result(action_service.execute_git_commit(
            approval_id=approval_id,
            workspace_id=workspace_id,
            evidence_id=evidence_id,
            idempotency_key=idempotency_key,
        ))

    _forbid_extra_tool_arguments(server)
    return server


def _task_result(task: RemoteTask) -> TaskToolResult:
    return {
        "task_id": task.id,
        "project_id": task.project_id,
        "assignee_agent_id": task.assignee_agent_id,
        "title": task.title,
        "status": task.status.value,
        "result": task.result,
        "replayed": task.replayed,
        "correlation_id": task.correlation_id,
    }


def _inbox_claim_result(claim: RemoteInboxClaim) -> InboxClaimToolResult:
    item = None
    if claim.item is not None:
        item = {
            "item_id": claim.item.item_id,
            "task_id": claim.item.task_id,
            "attempt": claim.item.attempt,
            "lease_token": claim.item.lease_token,
            "acquired_at": claim.item.acquired_at.isoformat(),
            "expires_at": claim.item.expires_at.isoformat(),
        }
    return {
        "item": item,
        "replayed": claim.replayed,
        "correlation_id": claim.correlation_id,
    }


def _inbox_finish_result(result: RemoteInboxFinish) -> InboxFinishToolResult:
    return {
        "item_id": result.item_id,
        "status": result.status.value,
        "attempt": result.attempt,
        "available_at": (
            None if result.available_at is None else result.available_at.isoformat()
        ),
        "replayed": result.replayed,
        "correlation_id": result.correlation_id,
    }


def _evidence_result(evidence: PublishedEvidence) -> EvidenceToolResult:
    return {
        "evidence_id": evidence.evidence_id,
        "kind": evidence.kind,
        "task_id": evidence.task_id,
        "workspace_id": evidence.workspace_id,
        "head_commit": evidence.head_commit,
        "artifact_ids": list(evidence.artifact_ids),
        "replayed": evidence.replayed,
        "correlation_id": evidence.correlation_id,
    }


def _action_result(action: ExecutedAction) -> ActionToolResult:
    return {
        "approval_id": action.approval_id,
        "operation_id": action.operation_id,
        "status": action.status,
        "external_action_id": action.external_action_id,
        "result_reference": action.result_reference,
        "replayed": action.replayed,
        "correlation_id": action.correlation_id,
    }
