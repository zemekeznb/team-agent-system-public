"""Official A2A SDK implementation of the application gateway port."""

from __future__ import annotations

from urllib.parse import quote

import httpx
from a2a.client import Client
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, SendMessageRequest, TaskState
from a2a.utils.errors import A2AError

from tas.application.a2a_bridge import (
    A2ABridgeError,
    A2ADelegationResult,
)
from tas.domain.collaboration import Task, TaskStatus


_FROM_A2A_STATE = {
    TaskState.TASK_STATE_SUBMITTED: TaskStatus.SUBMITTED,
    TaskState.TASK_STATE_WORKING: TaskStatus.WORKING,
    TaskState.TASK_STATE_INPUT_REQUIRED: TaskStatus.INPUT_REQUIRED,
    TaskState.TASK_STATE_COMPLETED: TaskStatus.COMPLETED,
    TaskState.TASK_STATE_FAILED: TaskStatus.FAILED,
    TaskState.TASK_STATE_CANCELED: TaskStatus.CANCELLED,
    TaskState.TASK_STATE_REJECTED: TaskStatus.REJECTED,
}


class OfficialA2AGateway:
    def __init__(self, client: Client) -> None:
        self._client = client

    async def delegate(self, task: Task, *, trace_id: str) -> A2ADelegationResult:
        request = SendMessageRequest(
            message=Message(
                message_id=task.id.value,
                context_id=task.project_id.value,
                role=Role.ROLE_USER,
                parts=[Part(text=f"complete: {task.title}")],
                metadata={
                    "tasTraceId": trace_id,
                    "tasSourceTrust": "external-untrusted",
                },
            )
        )
        try:
            responses = [item async for item in self._client.send_message(request)]
        except httpx.HTTPError as exc:
            raise A2ABridgeError("a2a_unavailable", retryable=True) from exc
        except A2AError as exc:
            raise A2ABridgeError("a2a_protocol_error", retryable=False) from exc

        remote = next(
            (item.task for item in reversed(responses) if item.HasField("task")),
            None,
        )
        if remote is None or remote.status.state not in _FROM_A2A_STATE:
            raise A2ABridgeError("a2a_invalid_response", retryable=False)
        artifact_reference = None
        if remote.artifacts:
            artifact_reference = (
                f"a2a://tasks/{quote(remote.id, safe='')}/artifacts/"
                f"{quote(remote.artifacts[0].artifact_id, safe='')}"
            )
        return A2ADelegationResult(
            remote_task_id=remote.id,
            status=_FROM_A2A_STATE[remote.status.state],
            artifact_reference=artifact_reference,
        )


class DiscoveringOfficialA2AGateway:
    """Resolve the current Agent Card for each stdio bridge invocation."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url

    async def delegate(self, task: Task, *, trace_id: str) -> A2ADelegationResult:
        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                card = await A2ACardResolver(http, self._base_url).get_agent_card()
                client = ClientFactory(
                    ClientConfig(
                        httpx_client=http,
                        streaming=False,
                        polling=False,
                    )
                ).create(card)
                return await OfficialA2AGateway(client).delegate(
                    task, trace_id=trace_id
                )
        except A2ABridgeError:
            raise
        except (httpx.HTTPError, ValueError) as exc:
            raise A2ABridgeError("a2a_unavailable", retryable=True) from exc
