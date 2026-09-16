"""A2A protocol-boundary adapters."""

from .mapping import (
    A2AContractError,
    artifact_from_a2a,
    artifact_to_a2a,
    message_from_a2a,
    message_to_a2a,
    task_from_a2a,
    task_to_a2a,
)

__all__ = [
    "A2AContractError",
    "artifact_from_a2a",
    "artifact_to_a2a",
    "message_from_a2a",
    "message_to_a2a",
    "task_from_a2a",
    "task_to_a2a",
]
