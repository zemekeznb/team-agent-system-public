"""Minimal official-SDK A2A remote agent used by the F2 interop experiment."""

from __future__ import annotations

import asyncio
import json
from collections import OrderedDict
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes.agent_card_routes import create_agent_card_routes
from a2a.server.routes.jsonrpc_routes import create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore, TaskStore, TaskUpdater
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Part,
    Role,
    Task,
    TaskState,
    TaskStatus,
)
from fastapi import FastAPI
from google.protobuf.message import Message as ProtobufMessage
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


class RequestLimitExceeded(ValueError):
    def __init__(self, limit: str) -> None:
        super().__init__(limit)
        self.limit = limit


class RequestLimitsMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: FastAPI,
        max_bytes: int,
        max_text_chars: int,
        max_collection_items: int,
        max_depth: int,
    ) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes
        self.max_text_chars = max_text_chars
        self.max_collection_items = max_collection_items
        self.max_depth = max_depth

    def _validate_json(self, value: Any, depth: int = 1) -> None:
        if depth > self.max_depth:
            raise RequestLimitExceeded("depth")
        if isinstance(value, str):
            if len(value) > self.max_text_chars:
                raise RequestLimitExceeded("text")
        elif isinstance(value, dict):
            if len(value) > self.max_collection_items:
                raise RequestLimitExceeded("collection")
            for key, item in value.items():
                self._validate_json(key, depth + 1)
                self._validate_json(item, depth + 1)
        elif isinstance(value, list):
            if len(value) > self.max_collection_items:
                raise RequestLimitExceeded("collection")
            for item in value:
                self._validate_json(item, depth + 1)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        if request.method != "POST":
            return await call_next(request)
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_bytes:
                    return Response(status_code=413)
            except ValueError:
                return Response(status_code=400)
        body = await request.body()
        if len(body) > self.max_bytes:
            return Response(status_code=413)
        try:
            value = json.loads(body)
            self._validate_json(value)
        except json.JSONDecodeError:
            return JSONResponse(
                {"error": {"code": "invalid_json"}}, status_code=400
            )
        except RequestLimitExceeded as exc:
            return JSONResponse(
                {
                    "error": {
                        "code": "request_limit_exceeded",
                        "limit": exc.limit,
                    }
                },
                status_code=422,
            )
        return await call_next(request)


class IdempotentRequestHandler(DefaultRequestHandler):
    """Replay completed SendMessage results by stable message ID within a process."""

    def __init__(
        self, *args: Any, max_idempotency_entries: int = 1_000, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self._max_idempotency_entries = max_idempotency_entries
        self._message_results: OrderedDict[
            tuple[str, str, str], tuple[bytes, ProtobufMessage]
        ] = OrderedDict()
        self._message_lock = asyncio.Lock()

    async def on_message_send(self, params: Any, context: Any) -> Any:
        if params.message.role != Role.ROLE_USER:
            from a2a.utils.errors import InvalidParamsError

            raise InvalidParamsError(message="incoming message role must be user")
        message_id = params.message.message_id
        scope = (params.tenant, params.message.context_id, message_id)
        fingerprint = params.SerializeToString(deterministic=True)
        async with self._message_lock:
            prior = self._message_results.get(scope)
            if prior is not None:
                prior_fingerprint, prior_result = prior
                if prior_fingerprint != fingerprint:
                    from a2a.utils.errors import InvalidParamsError

                    raise InvalidParamsError(
                        message="message_id was already used with different content"
                    )
                replay = type(prior_result)()
                replay.CopyFrom(prior_result)
                self._message_results.move_to_end(scope)
                return replay
            result = await super().on_message_send(params, context)
            saved = type(result)()
            saved.CopyFrom(result)
            self._message_results[scope] = (fingerprint, saved)
            if len(self._message_results) > self._max_idempotency_entries:
                self._message_results.popitem(last=False)
            return result


class F2RemoteAgentExecutor(AgentExecutor):
    """Small deterministic executor; production agent behavior is out of scope."""

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        task_id = context.task_id or str(uuid4())
        context_id = context.context_id or str(uuid4())
        updater = TaskUpdater(event_queue, task_id, context_id)
        trace_metadata: dict[str, str] = {}
        if (
            context.message is not None
            and "tasTraceId" in context.message.metadata
        ):
            trace_id = context.message.metadata["tasTraceId"]
            if isinstance(trace_id, str) and trace_id.strip():
                trace_metadata["tasTraceId"] = trace_id
        await event_queue.enqueue_event(
            Task(
                id=task_id,
                context_id=context_id,
                status=TaskStatus(state=TaskState.TASK_STATE_SUBMITTED),
                metadata=trace_metadata,
            )
        )
        await updater.start_work()

        user_input = context.get_user_input()
        if user_input.startswith("fail: "):
            await updater.failed()
            return
        if not user_input.startswith("complete: "):
            await updater.requires_input(
                Message(
                    message_id=str(uuid4()),
                    role=Role.ROLE_AGENT,
                    parts=[Part(text="Send 'complete: <text>' to finish the task.")],
                )
            )
            return

        result = user_input.removeprefix("complete: ")
        await updater.add_artifact(
            [Part(text=result)], artifact_id=str(uuid4()), name="result"
        )
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        if not context.task_id or not context.context_id:
            raise ValueError("cancellation requires task_id and context_id")
        await TaskUpdater(event_queue, context.task_id, context.context_id).cancel()


def create_remote_agent_app(
    *,
    public_url: str,
    max_request_bytes: int = 64 * 1024,
    max_text_chars: int = 4_096,
    max_collection_items: int = 100,
    max_depth: int = 12,
    max_idempotency_entries: int = 1_000,
    task_store: TaskStore | None = None,
) -> FastAPI:
    """Create an ASGI app publishing the official Agent Card and JSON-RPC route."""
    limits = {
        "max_request_bytes": max_request_bytes,
        "max_text_chars": max_text_chars,
        "max_collection_items": max_collection_items,
        "max_depth": max_depth,
        "max_idempotency_entries": max_idempotency_entries,
    }
    for name, value in limits.items():
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    parsed_url = urlparse(public_url)
    if (
        parsed_url.scheme not in {"http", "https"}
        or not parsed_url.netloc
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ValueError("public_url must be an HTTP(S) URL without credentials")
    card = AgentCard(
        name="Team Agent System F2 Remote Agent",
        description="Minimal A2A interoperability endpoint for F2 validation.",
        version="0.1.0",
        supported_interfaces=[
            AgentInterface(
                url=public_url,
                protocol_binding="JSONRPC",
                protocol_version="1.0",
            )
        ],
        capabilities=AgentCapabilities(streaming=True),
        default_input_modes=["text/plain"],
        default_output_modes=["text/plain"],
        skills=[
            AgentSkill(
                id="f2-echo",
                name="F2 echo",
                description="Returns supplied text as an Artifact.",
                tags=["f2", "interop"],
                input_modes=["text/plain"],
                output_modes=["text/plain"],
            )
        ],
    )
    handler = IdempotentRequestHandler(
        F2RemoteAgentExecutor(),
        task_store if task_store is not None else InMemoryTaskStore(),
        card,
        max_idempotency_entries=max_idempotency_entries,
    )
    app = FastAPI()
    app.add_middleware(
        RequestLimitsMiddleware,
        max_bytes=max_request_bytes,
        max_text_chars=max_text_chars,
        max_collection_items=max_collection_items,
        max_depth=max_depth,
    )
    app.router.routes.extend(create_agent_card_routes(card))
    app.router.routes.extend(create_jsonrpc_routes(handler, "/a2a"))
    return app
