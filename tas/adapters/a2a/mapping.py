"""Minimal A2A-shaped DTO mapping for the F2 contract experiment.

The dictionaries in this module are protocol-boundary values, not domain objects.
No transport or SDK dependency is intentionally introduced by F2-014.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from tas.domain.collaboration import (
    Artifact,
    ArtifactId,
    Task,
    TaskId,
    TaskMessage,
    TaskMessageId,
    TaskStatus,
    TaskTransition,
)
from tas.domain.identity import AgentId, ProjectId


TAS_EXTENSION = "io.team-agent-system/v1"

_TO_A2A_STATE = {
    TaskStatus.SUBMITTED: "submitted",
    TaskStatus.WORKING: "working",
    TaskStatus.INPUT_REQUIRED: "input-required",
    TaskStatus.APPROVAL_REQUIRED: "input-required",
    TaskStatus.APPROVED: "working",
    TaskStatus.REJECTED: "rejected",
    TaskStatus.EXPIRED: "failed",
    TaskStatus.FAILED: "failed",
    TaskStatus.CANCELLED: "canceled",
    TaskStatus.COMPLETED: "completed",
}


class A2AContractError(ValueError):
    """Raised when an external A2A-shaped value violates the mapping contract."""


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise A2AContractError(f"{field} must be an object")
    return value


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise A2AContractError(f"{field} must be non-blank text")
    return value


def _instant(value: Any, field: str) -> datetime:
    text = _text(value, field)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise A2AContractError(f"{field} must be an ISO-8601 instant") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != UTC.utcoffset(parsed):
        raise A2AContractError(f"{field} must use UTC")
    return parsed


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _tas_metadata(wire: dict[str, Any]) -> dict[str, Any]:
    metadata = _object(wire.get("metadata"), "metadata")
    extension = metadata.get(TAS_EXTENSION)
    if not isinstance(extension, dict):
        raise A2AContractError(f"metadata must contain {TAS_EXTENSION} tas extension")
    schema_version = extension.get("schemaVersion")
    if type(schema_version) is not int or schema_version != 1:
        raise A2AContractError("unsupported tas schemaVersion")
    return extension


def task_to_a2a(task: Task) -> dict[str, Any]:
    transitions = [
        {
            "from": item.from_status.value,
            "to": item.to_status.value,
            "actorId": item.actor_id.value,
            "reason": item.reason,
            "occurredAt": _timestamp(item.occurred_at),
        }
        for item in task.transitions
    ]
    status: dict[str, Any] = {"state": _TO_A2A_STATE[task.status]}
    if task.transitions:
        status["timestamp"] = _timestamp(task.transitions[-1].occurred_at)
    return {
        "id": task.id.value,
        "contextId": task.project_id.value,
        "status": status,
        "artifacts": [],
        "history": [],
        "metadata": {
            TAS_EXTENSION: {
                "schemaVersion": 1,
                "title": task.title,
                "state": task.status.value,
                "result": task.result,
                "transitions": transitions,
            }
        },
    }


def task_from_a2a(
    wire: dict[str, Any],
    *,
    project_id: ProjectId,
    assignee_agent_id: AgentId,
    trust_tas_history: bool = False,
) -> Task:
    value = _object(wire, "task")
    context_id = value.get("contextId")
    if context_id is not None:
        if _text(context_id, "task.contextId") != project_id.value:
            raise A2AContractError("task.contextId does not match authenticated project")
    extension = _tas_metadata(value)
    try:
        state = TaskStatus(_text(extension.get("state"), "tas state"))
    except ValueError as exc:
        raise A2AContractError("unknown tas task state") from exc
    a2a_state = _text(_object(value.get("status"), "status").get("state"), "status.state")
    if a2a_state != _TO_A2A_STATE[state]:
        raise A2AContractError("A2A state is inconsistent with tas state")
    raw_transitions = extension.get("transitions")
    if not isinstance(raw_transitions, list):
        raise A2AContractError("tas transitions must be an array")
    if raw_transitions and not trust_tas_history:
        raise A2AContractError("tas transition history requires an explicitly trusted source")
    transitions: list[TaskTransition] = []
    for raw in raw_transitions:
        item = _object(raw, "transition")
        try:
            from_status = TaskStatus(_text(item.get("from"), "transition.from"))
            to_status = TaskStatus(_text(item.get("to"), "transition.to"))
        except ValueError as exc:
            raise A2AContractError("unknown tas transition state") from exc
        reason = item.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            raise A2AContractError("transition.reason must be null or non-blank text")
        transitions.append(
            TaskTransition(
                from_status,
                to_status,
                AgentId(_text(item.get("actorId"), "transition.actorId")),
                reason,
                _instant(item.get("occurredAt"), "transition.occurredAt"),
            )
        )
    result = extension.get("result")
    if result is not None and not isinstance(result, str):
        raise A2AContractError("tas result must be text or null")
    return Task(
        TaskId(_text(value.get("id"), "task.id")),
        project_id,
        assignee_agent_id,
        _text(extension.get("title"), "tas title"),
        status=state,
        result=result,
        transitions=tuple(transitions),
    )


def message_to_a2a(message: TaskMessage) -> dict[str, Any]:
    return {
        "role": "agent",
        "parts": [{"kind": "text", "text": message.body}],
        "messageId": message.id.value,
        "taskId": message.task_id.value,
        "metadata": {TAS_EXTENSION: {"schemaVersion": 1, "createdAt": _timestamp(message.created_at)}},
    }


def message_from_a2a(wire: dict[str, Any], *, author_agent_id: AgentId) -> TaskMessage:
    value = _object(wire, "message")
    if value.get("role") != "agent":
        raise A2AContractError("message.role must be agent")
    parts = value.get("parts")
    if not isinstance(parts, list) or len(parts) != 1:
        raise A2AContractError("message must contain exactly one text part")
    part = _object(parts[0], "message part")
    if part.get("kind") != "text":
        raise A2AContractError("message part must be text")
    extension = _tas_metadata(value)
    return TaskMessage(
        TaskMessageId(_text(value.get("messageId"), "message.messageId")),
        TaskId(_text(value.get("taskId"), "message.taskId")),
        author_agent_id,
        _text(part.get("text"), "message text"),
        _instant(extension.get("createdAt"), "tas createdAt"),
    )


def artifact_to_a2a(artifact: Artifact) -> dict[str, Any]:
    return {
        "artifactId": artifact.id.value,
        "parts": [{"kind": "data", "data": {"reference": artifact.reference, "mediaType": artifact.media_type}}],
        "metadata": {
            TAS_EXTENSION: {
                "schemaVersion": 1,
                "taskId": artifact.task_id.value,
                "createdAt": _timestamp(artifact.created_at),
            }
        },
    }


def artifact_from_a2a(wire: dict[str, Any], *, producer_agent_id: AgentId) -> Artifact:
    value = _object(wire, "artifact")
    parts = value.get("parts")
    if not isinstance(parts, list) or len(parts) != 1:
        raise A2AContractError("artifact must contain exactly one data part")
    part = _object(parts[0], "artifact part")
    if part.get("kind") != "data":
        raise A2AContractError("artifact part must be data")
    data = _object(part.get("data"), "artifact data")
    extension = _tas_metadata(value)
    return Artifact(
        ArtifactId(_text(value.get("artifactId"), "artifact.artifactId")),
        TaskId(_text(extension.get("taskId"), "tas taskId")),
        producer_agent_id,
        _text(data.get("reference"), "artifact reference"),
        _text(data.get("mediaType"), "artifact mediaType"),
        _instant(extension.get("createdAt"), "tas createdAt"),
    )
