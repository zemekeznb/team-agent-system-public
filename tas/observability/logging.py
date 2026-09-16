"""JSON logging with trace context and conservative field redaction."""

from __future__ import annotations

import json
import logging
import sys
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import IO, Any


TRACE_ID: ContextVar[str | None] = ContextVar("tas_trace_id", default=None)
SENSITIVE_KEY_PARTS = ("authorization", "credential", "password", "secret", "token")
STANDARD_LOG_RECORD_KEYS = frozenset(logging.makeLogRecord({}).__dict__)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "logger": record.name,
            "event": (
                record.msg
                if isinstance(record.msg, str)
                else "unstructured_log_event"
            ),
        }
        trace_id = getattr(record, "trace_id", None) or TRACE_ID.get()
        if trace_id is not None:
            payload["trace_id"] = trace_id

        for key, value in record.__dict__.items():
            if key in STANDARD_LOG_RECORD_KEYS or key in {"message", "asctime", "trace_id"}:
                continue
            payload[key] = _redact(key, value)
        if record.exc_info:
            exception_type = record.exc_info[0]
            payload["exception_type"] = (
                exception_type.__name__ if exception_type is not None else "Exception"
            )
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_json_logging(stream: IO[str] | None = None) -> None:
    """Replace TAS handlers with one deterministic JSON stream handler."""

    handler = logging.StreamHandler(stream if stream is not None else sys.stderr)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("tas")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"tas.{name}")


def set_trace_id(trace_id: str) -> Token[str | None]:
    return TRACE_ID.set(trace_id)


def reset_trace_id(token: Token[str | None]) -> None:
    TRACE_ID.reset(token)


def _redact(key: str, value: Any) -> Any:
    normalized = key.casefold()
    if any(part in normalized for part in SENSITIVE_KEY_PARTS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(child_key): _redact(str(child_key), child) for child_key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(key, child) for child in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)
