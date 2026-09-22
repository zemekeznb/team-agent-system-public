"""Official A2A SDK implementation of the application gateway port."""

from __future__ import annotations

from urllib.parse import quote

import httpx
from a2a.client import Client
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.client.errors import A2AClientError
from a2a.types import (
    GetTaskRequest,
    Message,
    Part,
    Role,
    SendMessageRequest,
    TaskState,
)
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


def _transport_error(error: BaseException) -> httpx.RequestError | None:
    """Recover the SDK-wrapped httpx cause without relying on error text."""
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, httpx.RequestError):
            return current
        current = current.__cause__ or current.__context__
    return None


class OfficialA2AGateway:
    def __init__(self, client: Client, *, target_id: str = "official-a2a") -> None:
        self._client = client
        if not isinstance(target_id, str) or not target_id.strip():
            raise ValueError("target_id must be non-blank text")
        self.target_id = target_id

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
            definitely_not_sent = isinstance(
                exc, (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout)
            )
            raise A2ABridgeError(
                "a2a_unavailable",
                retryable=True,
                request_may_have_been_sent=not definitely_not_sent,
            ) from exc
        except A2AClientError as exc:
            transport = _transport_error(exc)
            if transport is not None:
                definitely_not_sent = isinstance(
                    transport,
                    (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout),
                )
                raise A2ABridgeError(
                    "a2a_unavailable",
                    retryable=True,
                    request_may_have_been_sent=not definitely_not_sent,
                ) from exc
            raise A2ABridgeError("a2a_protocol_error", retryable=False) from exc
        except A2AError as exc:
            raise A2ABridgeError("a2a_protocol_error", retryable=False) from exc

        remote = next(
            (item.task for item in reversed(responses) if item.HasField("task")),
            None,
        )
        if remote is None:
            raise A2ABridgeError("a2a_invalid_response", retryable=False)
        return self._result(remote)

    async def lookup(
        self, remote_task_id: str, *, trace_id: str
    ) -> A2ADelegationResult:
        if (
            not isinstance(remote_task_id, str)
            or not remote_task_id.strip()
            or len(remote_task_id) > 255
        ):
            raise ValueError("remote_task_id must be bounded non-blank text")
        if not isinstance(trace_id, str) or not trace_id.strip():
            raise ValueError("trace_id must be non-blank text")
        try:
            remote = await self._client.get_task(GetTaskRequest(id=remote_task_id))
        except httpx.HTTPError as exc:
            raise A2ABridgeError(
                "a2a_query_unavailable",
                retryable=True,
                request_may_have_been_sent=False,
            ) from exc
        except A2AError as exc:
            raise A2ABridgeError(
                "a2a_query_failed",
                retryable=True,
                request_may_have_been_sent=False,
            ) from exc
        return self._result(remote)

    @staticmethod
    def _result(remote) -> A2ADelegationResult:
        if remote.status.state not in _FROM_A2A_STATE:
            raise A2ABridgeError("a2a_invalid_response", retryable=False)
        artifact_reference = None
        if remote.artifacts:
            artifact_reference = (
                f"a2a://tasks/{quote(remote.id, safe='')}/artifacts/"
                f"{quote(remote.artifacts[0].artifact_id, safe='')}"
            )
        try:
            return A2ADelegationResult(
                remote_task_id=remote.id,
                status=_FROM_A2A_STATE[remote.status.state],
                artifact_reference=artifact_reference,
            )
        except (TypeError, ValueError) as exc:
            raise A2ABridgeError(
                "a2a_invalid_response", retryable=False
            ) from exc


class DiscoveringOfficialA2AGateway:
    """Resolve the current Agent Card for each stdio bridge invocation."""

    def __init__(self, base_url: str) -> None:
        self._base_url = base_url
        self.target_id = base_url

    async def delegate(self, task: Task, *, trace_id: str) -> A2ADelegationResult:
        return await self._with_client(
            lambda gateway: gateway.delegate(task, trace_id=trace_id)
        )

    async def lookup(
        self, remote_task_id: str, *, trace_id: str
    ) -> A2ADelegationResult:
        return await self._with_client(
            lambda gateway: gateway.lookup(remote_task_id, trace_id=trace_id)
        )

    async def _with_client(self, operation) -> A2ADelegationResult:
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
                return await operation(
                    OfficialA2AGateway(client, target_id=self.target_id)
                )
        except A2ABridgeError:
            raise
        except (httpx.HTTPError, A2AError, ValueError) as exc:
            raise A2ABridgeError(
                "a2a_unavailable",
                retryable=True,
                request_may_have_been_sent=False,
            ) from exc
