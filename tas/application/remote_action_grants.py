"""Remote Action Grant preparation and Receipt reconciliation contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from tas.domain.action_execution import ActionReceipt
from tas.domain.approval import ApprovalId
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.identity import AgentId, DomainValidationError


class RemoteActionGrantAccessError(PermissionError):
    """The authenticated Agent cannot access this Grant."""


class RemoteActionGrantRejectedError(RuntimeError):
    """The Approval or its current execution preconditions are no longer valid."""


class RemoteActionGrantConflictError(RuntimeError):
    """The Grant or Receipt conflicts with an earlier exact operation."""


class RemoteActionReceiptCommitError(RuntimeError):
    """A known external Receipt could not yet be committed centrally."""


class RemoteActionGrantStatus(StrEnum):
    PREPARED = "prepared"
    RESULT_UNKNOWN = "result_unknown"
    COMPLETED = "completed"


@dataclass(frozen=True, slots=True)
class PrepareRemoteActionCommand:
    workspace_id: WorkspaceBindingId
    evidence_id: EvidenceId

    def __post_init__(self) -> None:
        if not isinstance(self.workspace_id, WorkspaceBindingId):
            raise TypeError("workspace_id must be WorkspaceBindingId")
        if not isinstance(self.evidence_id, EvidenceId):
            raise TypeError("evidence_id must be EvidenceId")


@dataclass(frozen=True, slots=True)
class SubmitActionReceiptCommand:
    request_fingerprint: str
    external_action_id: str
    result_reference: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        if (
            not isinstance(self.request_fingerprint, str)
            or len(self.request_fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in self.request_fingerprint)
        ):
            raise DomainValidationError(
                "request_fingerprint must be 64 lowercase hexadecimal characters"
            )
        for value, field in (
            (self.external_action_id, "external_action_id"),
            (self.result_reference, "result_reference"),
        ):
            if not isinstance(value, str) or not value.strip() or len(value) > 255:
                raise DomainValidationError(
                    f"{field} must be 1..255 non-whitespace characters"
                )


@dataclass(frozen=True, slots=True)
class RemoteActionGrantView:
    approval_id: ApprovalId
    operation_id: str
    request_fingerprint: str
    workspace_id: WorkspaceBindingId
    evidence_id: EvidenceId
    commit_sha: str
    execute_before: datetime
    status: RemoteActionGrantStatus
    started_at: datetime
    receipt: ActionReceipt | None
    replayed: bool


class RemoteActionGrantUnitOfWork(Protocol):
    def prepare(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        command: PrepareRemoteActionCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView: ...

    def get(
        self, actor_id: AgentId, approval_id: ApprovalId
    ) -> RemoteActionGrantView | None: ...

    def mark_result_unknown(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        request_fingerprint: str,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView: ...

    def submit_receipt(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        command: SubmitActionReceiptCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView: ...


class RemoteActionGrantService:
    def __init__(self, unit_of_work: RemoteActionGrantUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def prepare(self, *args, **kwargs) -> RemoteActionGrantView:
        return self.unit_of_work.prepare(*args, **kwargs)

    def get(self, *args, **kwargs) -> RemoteActionGrantView | None:
        return self.unit_of_work.get(*args, **kwargs)

    def mark_result_unknown(self, *args, **kwargs) -> RemoteActionGrantView:
        return self.unit_of_work.mark_result_unknown(*args, **kwargs)

    def submit_receipt(self, *args, **kwargs) -> RemoteActionGrantView:
        return self.unit_of_work.submit_receipt(*args, **kwargs)
