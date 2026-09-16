"""ASGI middleware for request trace identifiers and request logs."""

from __future__ import annotations

from time import perf_counter
from typing import Any
from uuid import UUID, uuid4

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from tas.observability.logging import get_logger, reset_trace_id, set_trace_id


TRACE_HEADER = b"x-trace-id"
logger = get_logger("http")


class TraceMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        trace_id = _request_trace_id(scope) or str(uuid4())
        context_token = set_trace_id(trace_id)
        started_at = perf_counter()
        status_code = 500
        failed = False

        async def send_with_trace(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = [
                    (key, value)
                    for key, value in message.get("headers", [])
                    if key.lower() != TRACE_HEADER
                ]
                headers.append((TRACE_HEADER, trace_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        log_fields: dict[str, Any] = {
            "method": scope["method"],
            "path": scope["path"],
        }
        logger.info("http.request.started", extra=log_fields)
        try:
            await self.app(scope, receive, send_with_trace)
        except BaseException:
            failed = True
            logger.exception(
                "http.request.failed",
                extra={
                    **log_fields,
                    "status_code": status_code,
                    "duration_ms": _duration_ms(started_at),
                    "error_code": "internal_error",
                },
            )
            raise
        finally:
            if not failed:
                logger.info(
                    "http.request.completed",
                    extra={
                        **log_fields,
                        "status_code": status_code,
                        "duration_ms": _duration_ms(started_at),
                    },
                )
            reset_trace_id(context_token)


def _request_trace_id(scope: Scope) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() != TRACE_HEADER:
            continue
        try:
            candidate = value.decode("ascii")
            return str(UUID(candidate)) if str(UUID(candidate)) == candidate.lower() else None
        except (UnicodeDecodeError, ValueError):
            return None
    return None


def _duration_ms(started_at: float) -> float:
    return round((perf_counter() - started_at) * 1000, 3)
