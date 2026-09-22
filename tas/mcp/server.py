"""Official-SDK MCP server exposing the currently implemented F2 tools."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, TypedDict

from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field, StrictInt, StrictStr

from tas.adapters.persistence.sqlite.task_creation_uow import (
    SQLiteTaskCreationUnitOfWork,
)
from tas.adapters.persistence.sqlite.task_repository import SQLiteTaskRepository
from tas.adapters.persistence.sqlite.a2a_delegation_repository import (
    SQLiteA2ADelegationOperationRepository,
)
from tas.application.task_creation import CreateTaskRequest, CreateTaskService
from tas.application.a2a_bridge import (
    A2AGateway,
    A2ARecoveryPolicy,
    DelegateTaskService,
)
from tas.application.inbox_polling import InboxPollingService
from tas.domain.collaboration import TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, ProjectId
from tas.domain.delivery import InboxItemId, LeaseToken
from tas.adapters.persistence.sqlite.inbox_repository import SQLiteInboxRepository
from tas.observability.logging import get_logger


Identifier = Annotated[StrictStr, Field(min_length=1, max_length=255)]
TaskTitle = Annotated[StrictStr, Field(min_length=1, max_length=500)]
PollWaitSeconds = Annotated[StrictInt, Field(ge=0, le=30)]
LeaseSeconds = Annotated[StrictInt, Field(ge=1, le=300)]
RetryDelaySeconds = Annotated[StrictInt, Field(ge=0, le=3600)]
logger = get_logger("mcp.server")


class HealthResult(TypedDict):
    status: str
    scope: str


class CreateTaskToolResult(TypedDict):
    task_id: str
    replayed: bool


class DelegateTaskToolResult(TypedDict):
    local_task_id: str
    replayed: bool
    remote_task_id: str
    status: str
    artifact_reference: str | None
    content_trusted: bool
    operation_id: str
    message_id: str


class PollInboxToolResult(TypedDict):
    status: str
    item_id: str | None
    task_id: str | None
    attempt_count: int | None
    lease_token: str | None
    lease_expires_at: str | None


class InboxDispositionResult(TypedDict):
    status: str
    item_id: str


def _forbid_extra_tool_arguments(server: FastMCP) -> None:
    """Make SDK 1.x argument validation fail closed for registered tools."""
    for registered in server._tool_manager.list_tools():
        registered.fn_metadata.arg_model.model_config["extra"] = "forbid"
        registered.fn_metadata.arg_model.model_rebuild(force=True)
        registered.parameters = registered.fn_metadata.arg_model.model_json_schema(
            by_alias=True
        )


def create_mcp_server(
    *,
    database: str | Path,
    actor_id: AgentId,
    task_id_factory: Callable[[], TaskId] | None = None,
    a2a_gateway: A2AGateway | None = None,
    a2a_recovery_policy: A2ARecoveryPolicy | None = None,
    clock: Callable[[], datetime] | None = None,
) -> FastMCP:
    """Build an MCP server whose authenticated actor is process-bound."""
    if not isinstance(actor_id, AgentId):
        raise TypeError("actor_id must be AgentId")
    current_time = clock or (lambda: datetime.now(UTC))

    service = CreateTaskService(
        SQLiteTaskCreationUnitOfWork(database, task_id_factory=task_id_factory)
    )
    server = FastMCP("Team Agent System")
    polling = InboxPollingService(SQLiteInboxRepository(database))

    @server.tool(name="tas_health", structured_output=True)
    def health(ctx: Context) -> HealthResult:
        """Return process liveness without probing downstream dependencies."""
        logger.info(
            "mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": actor_id.value,
                "tool": "tas_health",
            },
        )
        return {"status": "ok", "scope": "liveness"}

    @server.tool(name="tas_create_task", structured_output=True)
    def create_task(
        idempotency_key: Identifier,
        project_id: Identifier,
        assignee_agent_id: Identifier,
        title: TaskTitle,
        ctx: Context,
    ) -> CreateTaskToolResult:
        """Create a Task atomically, replaying an identical prior request."""
        logger.info(
            "mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": actor_id.value,
                "tool": "tas_create_task",
            },
        )
        result = service.create(
            actor_id,
            IdempotencyKey(idempotency_key),
            CreateTaskRequest(
                project_id=ProjectId(project_id),
                assignee_agent_id=AgentId(assignee_agent_id),
                title=title,
            ),
        )
        return {"task_id": result.task_id.value, "replayed": result.replayed}

    if a2a_gateway is not None:
        delegation = DelegateTaskService(
            service,
            SQLiteTaskRepository(database),
            SQLiteA2ADelegationOperationRepository(database),
            a2a_gateway,
            target_id=getattr(a2a_gateway, "target_id", "configured-a2a"),
            recovery_policy=a2a_recovery_policy,
        )

        @server.tool(name="tas_delegate_task", structured_output=True)
        async def delegate_task(
            idempotency_key: Identifier,
            project_id: Identifier,
            assignee_agent_id: Identifier,
            title: TaskTitle,
            ctx: Context,
        ) -> DelegateTaskToolResult:
            """Create a local Task and delegate it through the configured A2A port."""
            result = await delegation.delegate(
                actor_id=actor_id,
                idempotency_key=IdempotencyKey(idempotency_key),
                request=CreateTaskRequest(
                    project_id=ProjectId(project_id),
                    assignee_agent_id=AgentId(assignee_agent_id),
                    title=title,
                ),
                trace_id=str(ctx.request_id),
                now=current_time(),
            )
            return {
                "local_task_id": result.local_task_id,
                "replayed": result.replayed,
                "remote_task_id": result.remote_task_id,
                "status": result.status,
                "artifact_reference": result.artifact_reference,
                "content_trusted": result.content_trusted,
                "operation_id": result.operation_id,
                "message_id": result.message_id,
            }

    @server.tool(name="tas_poll_inbox", structured_output=True)
    async def poll_inbox(
        wait_seconds: PollWaitSeconds,
        lease_seconds: LeaseSeconds,
        ctx: Context,
    ) -> PollInboxToolResult:
        """Wait for and atomically claim the next durable Inbox item."""
        logger.info(
            "mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": actor_id.value,
                "tool": "tas_poll_inbox",
            },
        )
        result = await polling.poll_and_claim(
            actor_id=actor_id,
            wait_timeout=timedelta(seconds=wait_seconds),
            lease_duration=timedelta(seconds=lease_seconds),
        )
        if result.item is None:
            return {
                "status": "timeout",
                "item_id": None,
                "task_id": None,
                "attempt_count": None,
                "lease_token": None,
                "lease_expires_at": None,
            }
        lease = result.item.lease
        if lease is None or lease.token is None:
            raise RuntimeError("claimed Inbox item is missing its Lease token")
        return {
            "status": "claimed",
            "item_id": result.item.id.value,
            "task_id": result.item.task_id.value,
            "attempt_count": result.item.attempt_count,
            "lease_token": lease.token.value,
            "lease_expires_at": lease.expires_at.isoformat(),
        }

    @server.tool(name="tas_ack_inbox", structured_output=True)
    def acknowledge_inbox(
        item_id: Identifier,
        lease_token: Identifier,
        ctx: Context,
    ) -> InboxDispositionResult:
        """Acknowledge successful handling of a currently owned Inbox Lease."""
        logger.info(
            "mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": actor_id.value,
                "tool": "tas_ack_inbox",
            },
        )
        polling.acknowledge(
            actor_id=actor_id,
            item_id=InboxItemId(item_id),
            lease_token=LeaseToken(lease_token),
        )
        return {"status": "acknowledged", "item_id": item_id}

    @server.tool(name="tas_release_inbox", structured_output=True)
    def release_inbox(
        item_id: Identifier,
        lease_token: Identifier,
        retry_delay_seconds: RetryDelaySeconds,
        ctx: Context,
    ) -> InboxDispositionResult:
        """Release a currently owned Inbox Lease for bounded retry."""
        logger.info(
            "mcp.tool.called",
            extra={
                "trace_id": ctx.request_id,
                "actor_id": actor_id.value,
                "tool": "tas_release_inbox",
            },
        )
        polling.release(
            actor_id=actor_id,
            item_id=InboxItemId(item_id),
            lease_token=LeaseToken(lease_token),
            retry_delay=timedelta(seconds=retry_delay_seconds),
        )
        return {"status": "released", "item_id": item_id}

    # MCP SDK 1.x defaults every generated argument model to ``extra=ignore``.
    # Apply one fail-closed policy to every published tool so runtime
    # validation and advertised JSON Schema cannot drift tool by tool.
    _forbid_extra_tool_arguments(server)

    return server
