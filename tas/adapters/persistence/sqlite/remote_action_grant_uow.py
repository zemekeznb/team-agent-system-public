"""Authoritative SQLite boundary for remote Grant preparation and Receipts."""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path

from tas.application.action_execution import fingerprint_action_request
from tas.application.remote_action_grants import (
    PrepareRemoteActionCommand,
    RemoteActionGrantAccessError,
    RemoteActionGrantConflictError,
    RemoteActionGrantRejectedError,
    RemoteActionReceiptCommitError,
    RemoteActionGrantStatus,
    RemoteActionGrantView,
    SubmitActionReceiptCommand,
)
from tas.domain.action_execution import (
    ActionExecutionRequest,
    ActionReceipt,
    ExecutionPreconditions,
)
from tas.domain.approval import ApprovalId, ApprovalStatus
from tas.domain.audit import ActionGrantAuditReason
from tas.domain.evidence import EvidenceId, WorkspaceBindingId
from tas.domain.identity import AgentId
from tas.domain.policy import PolicyEngine
from tas.adapters.persistence.sqlite.approval_repository import SQLiteApprovalRepository
from tas.adapters.persistence.sqlite.policy_repository import SQLitePolicyRepository


class SQLiteRemoteActionGrantUnitOfWork:
    """Keeps authorization checks, reservation, Receipt and Audit atomic locally."""

    EXECUTION_WINDOW = timedelta(seconds=60)

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def prepare(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        command: PrepareRemoteActionCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView:
        self._utc(now)
        reason = ActionGrantAuditReason.APPROVAL_NOT_APPROVED
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                approval = SQLiteApprovalRepository._get_with_connection(
                    connection, approval_id
                )
                if approval is None or approval.decision.intent.receiving_agent_id != actor_id:
                    reason = ActionGrantAuditReason.CALLER_NOT_RECEIVER
                    raise RemoteActionGrantAccessError("Action Grant is unavailable")
                intent = approval.decision.intent
                if approval.status is not ApprovalStatus.APPROVED:
                    raise RemoteActionGrantRejectedError("Approval is not executable")

                existing = self._get_with_connection(connection, actor_id, approval_id)
                evidence = connection.execute(
                    "SELECT head_commit FROM tas_evidence_submissions "
                    "WHERE id=? AND task_id=? AND actor_agent_id=? AND workspace_id=? "
                    "AND kind='git' AND status='finalized'",
                    (
                        command.evidence_id.value,
                        None if intent.task_id is None else intent.task_id.value,
                        actor_id.value,
                        command.workspace_id.value,
                    ),
                ).fetchone()
                if evidence is None or not self._workspace_is_current(
                    connection, approval_id, command.workspace_id
                ):
                    reason = ActionGrantAuditReason.PRECONDITION_CHANGED
                    raise RemoteActionGrantRejectedError(
                        "Execution preconditions are unavailable"
                    )
                commit_sha = str(evidence[0])
                request = ActionExecutionRequest(
                    approval_id,
                    intent,
                    approval.decision.policy_version,
                    ExecutionPreconditions(command.workspace_id.value, commit_sha),
                    now,
                )
                fingerprint = fingerprint_action_request(request)
                if existing is not None:
                    if existing.request_fingerprint != fingerprint:
                        reason = ActionGrantAuditReason.OPERATION_CONFLICT
                        raise RemoteActionGrantConflictError(
                            "Approval Grant belongs to another exact request"
                        )
                    if (
                        existing.receipt is not None
                        or existing.status is RemoteActionGrantStatus.RESULT_UNKNOWN
                    ):
                        connection.execute("COMMIT")
                        return self._with_replay(existing)

                if now >= approval.expires_at:
                    reason = ActionGrantAuditReason.APPROVAL_EXPIRED
                    raise RemoteActionGrantRejectedError("Approval expired")
                policy = SQLitePolicyRepository._restore_current_with_connection(
                    connection, intent.receiving_owner_id
                )
                if policy is None or policy.version != approval.decision.policy_version:
                    reason = ActionGrantAuditReason.POLICY_VERSION_CHANGED
                    raise RemoteActionGrantRejectedError("Policy changed")
                decision = PolicyEngine().authorize(intent, policy)
                if decision != approval.decision:
                    reason = ActionGrantAuditReason.AUTHORIZATION_CHANGED
                    raise RemoteActionGrantRejectedError("Authorization changed")
                if not self._resource_relationships_current(connection, approval_id):
                    reason = ActionGrantAuditReason.AUTHORIZATION_CHANGED
                    raise RemoteActionGrantRejectedError("Authorization changed")

                if existing is not None:
                    if now >= existing.execute_before:
                        reason = ActionGrantAuditReason.PRECONDITION_CHANGED
                        raise RemoteActionGrantRejectedError(
                            "Execution authorization window closed; reconcile the operation"
                        )
                    connection.execute("COMMIT")
                    return self._with_replay(existing)

                execute_before = min(approval.expires_at, now + self.EXECUTION_WINDOW)
                connection.execute(
                    "INSERT INTO tas_action_grant_consumptions "
                    "(approval_id,request_fingerprint,status,started_at) "
                    "VALUES (?,?,'in_progress',?)",
                    (approval_id.value, fingerprint, now.isoformat()),
                )
                connection.execute(
                    "INSERT INTO tas_remote_action_grants "
                    "(approval_id,workspace_id,evidence_id,commit_sha,execute_before) "
                    "VALUES (?,?,?,?,?)",
                    (
                        approval_id.value,
                        command.workspace_id.value,
                        command.evidence_id.value,
                        commit_sha,
                        execute_before.isoformat(),
                    ),
                )
                self._insert_audit(
                    connection,
                    self._event_id("authorization", approval_id.value, fingerprint),
                    "authorization_decision",
                    actor_id,
                    intent.repository,
                    intent.action.value,
                    "approval_required",
                    "policy_evaluated",
                    now,
                    approval.decision.policy_version,
                    correlation_id,
                )
                view = self._get_with_connection(connection, actor_id, approval_id)
                if view is None:
                    raise RuntimeError("Action Grant reservation could not be restored")
                connection.execute("COMMIT")
                return view
        except (
            RemoteActionGrantAccessError,
            RemoteActionGrantRejectedError,
            RemoteActionGrantConflictError,
        ):
            self._audit_rejection(
                actor_id, approval_id, reason, now, correlation_id
            )
            raise
        except sqlite3.IntegrityError as error:
            self._audit_rejection(
                actor_id,
                approval_id,
                ActionGrantAuditReason.OPERATION_CONFLICT,
                now,
                correlation_id,
            )
            raise RemoteActionGrantConflictError(
                "Action Grant reservation conflicts"
            ) from error

    def get(
        self, actor_id: AgentId, approval_id: ApprovalId
    ) -> RemoteActionGrantView | None:
        with closing(self._connect()) as connection:
            return self._get_with_connection(connection, actor_id, approval_id)

    def mark_result_unknown(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        request_fingerprint: str,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView:
        self._utc(now)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                view = self._require_exact(
                    connection, actor_id, approval_id, request_fingerprint
                )
                if view.receipt is not None:
                    connection.execute("COMMIT")
                    return self._with_replay(view)
                replayed = self._has_unknown(
                    connection, approval_id, request_fingerprint
                )
                self._insert_audit(
                    connection,
                    self._event_id("unknown", approval_id.value, request_fingerprint),
                    "action_result_unknown",
                    actor_id,
                    self._repository(connection, approval_id),
                    self._action(connection, approval_id),
                    "result_unknown",
                    ActionGrantAuditReason.EXTERNAL_RESULT_UNKNOWN.value,
                    now,
                    self._policy_version(connection, approval_id),
                    correlation_id,
                    ignore_existing=True,
                )
                result = self._get_with_connection(connection, actor_id, approval_id)
                if result is None:
                    raise RuntimeError("Action Grant disappeared")
                connection.execute("COMMIT")
                return RemoteActionGrantView(
                    result.approval_id,
                    result.operation_id,
                    result.request_fingerprint,
                    result.workspace_id,
                    result.evidence_id,
                    result.commit_sha,
                    result.execute_before,
                    RemoteActionGrantStatus.RESULT_UNKNOWN,
                    result.started_at,
                    result.receipt,
                    replayed,
                )
        except (RemoteActionGrantAccessError, RemoteActionGrantConflictError) as error:
            self._audit_rejection(
                actor_id,
                approval_id,
                (
                    ActionGrantAuditReason.CALLER_NOT_RECEIVER
                    if isinstance(error, RemoteActionGrantAccessError)
                    else ActionGrantAuditReason.OPERATION_CONFLICT
                ),
                now,
                correlation_id,
            )
            raise

    def submit_receipt(
        self,
        actor_id: AgentId,
        approval_id: ApprovalId,
        command: SubmitActionReceiptCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> RemoteActionGrantView:
        self._utc(now)
        self._utc(command.occurred_at)
        try:
            with closing(self._connect()) as connection:
                connection.execute("BEGIN IMMEDIATE")
                view = self._require_exact(
                    connection, actor_id, approval_id, command.request_fingerprint
                )
                receipt = ActionReceipt(
                    approval_id.value,
                    command.request_fingerprint,
                    command.external_action_id,
                    command.result_reference,
                    command.occurred_at,
                )
                if view.receipt is not None:
                    if view.receipt != receipt:
                        raise RemoteActionGrantConflictError(
                            "Receipt conflicts with the authoritative result"
                        )
                    connection.execute("COMMIT")
                    return self._with_replay(view)
                if (
                    command.occurred_at < view.started_at
                    or command.occurred_at > view.execute_before
                    or command.occurred_at > now + timedelta(minutes=5)
                ):
                    raise RemoteActionGrantRejectedError(
                        "Receipt occurred outside the execution authorization window"
                    )
                reconciled = self._has_unknown(
                    connection, approval_id, command.request_fingerprint
                )
                source = "reconciled" if reconciled else "executed"
                connection.execute(
                    "UPDATE tas_action_grant_consumptions SET status='completed',"
                    "completed_at=?,external_action_id=?,result_reference=?,"
                    "receipt_occurred_at=?,receipt_source=?,audit_status='recorded',"
                    "audit_event_id=? WHERE approval_id=? AND status='in_progress' "
                    "AND request_fingerprint=?",
                    (
                        now.isoformat(),
                        receipt.external_action_id,
                        receipt.result_reference,
                        receipt.occurred_at.isoformat(),
                        source,
                        self._event_id("completion", approval_id.value, command.request_fingerprint),
                        approval_id.value,
                        command.request_fingerprint,
                    ),
                )
                self._insert_audit(
                    connection,
                    self._event_id("completion", approval_id.value, command.request_fingerprint),
                    "action_receipt_reconciled" if reconciled else "action_grant_consumed",
                    actor_id,
                    self._repository(connection, approval_id),
                    self._action(connection, approval_id),
                    "reconciled" if reconciled else "consumed",
                    (
                        ActionGrantAuditReason.RECEIPT_RECONCILED.value
                        if reconciled
                        else ActionGrantAuditReason.CONSUMED.value
                    ),
                    command.occurred_at,
                    self._policy_version(connection, approval_id),
                    correlation_id,
                )
                result = self._get_with_connection(connection, actor_id, approval_id)
                if result is None or result.receipt is None:
                    raise RuntimeError("Receipt could not be restored")
                connection.execute("COMMIT")
                return result
        except (
            RemoteActionGrantAccessError,
            RemoteActionGrantRejectedError,
            RemoteActionGrantConflictError,
        ) as error:
            self._audit_rejection(
                actor_id,
                approval_id,
                (
                    ActionGrantAuditReason.OPERATION_CONFLICT
                    if isinstance(error, RemoteActionGrantConflictError)
                    else ActionGrantAuditReason.PRECONDITION_CHANGED
                ),
                now,
                correlation_id,
            )
            raise
        except sqlite3.Error as error:
            raise RemoteActionReceiptCommitError(
                "Receipt commit is unavailable; retry this Receipt, not the action"
            ) from error

    def _get_with_connection(self, connection, actor_id, approval_id):
        row = connection.execute(
            "SELECT consumption.request_fingerprint,consumption.status,"
            "consumption.started_at,consumption.external_action_id,"
            "consumption.result_reference,consumption.receipt_occurred_at,"
            "remote.workspace_id,remote.evidence_id,remote.commit_sha,"
            "remote.execute_before FROM tas_action_grant_consumptions consumption "
            "JOIN tas_remote_action_grants remote "
            "ON remote.approval_id=consumption.approval_id "
            "JOIN tas_approvals approval ON approval.id=consumption.approval_id "
            "WHERE consumption.approval_id=? AND approval.receiving_agent_id=?",
            (approval_id.value, actor_id.value),
        ).fetchone()
        if row is None:
            return None
        receipt = None
        if str(row[1]) == "completed":
            receipt = ActionReceipt(
                approval_id.value,
                str(row[0]),
                str(row[3]),
                str(row[4]),
                datetime.fromisoformat(str(row[5])),
            )
        status = (
            RemoteActionGrantStatus.COMPLETED
            if receipt is not None
            else (
                RemoteActionGrantStatus.RESULT_UNKNOWN
                if self._has_unknown(connection, approval_id, str(row[0]))
                else RemoteActionGrantStatus.PREPARED
            )
        )
        return RemoteActionGrantView(
            approval_id,
            approval_id.value,
            str(row[0]),
            WorkspaceBindingId(str(row[6])),
            EvidenceId(str(row[7])),
            str(row[8]),
            datetime.fromisoformat(str(row[9])),
            status,
            datetime.fromisoformat(str(row[2])),
            receipt,
            False,
        )

    def _require_exact(self, connection, actor_id, approval_id, fingerprint):
        view = self._get_with_connection(connection, actor_id, approval_id)
        if view is None:
            raise RemoteActionGrantAccessError("Action Grant is unavailable")
        if view.request_fingerprint != fingerprint:
            raise RemoteActionGrantConflictError(
                "Request fingerprint conflicts with the reserved Grant"
            )
        return view

    @staticmethod
    def _with_replay(view):
        return RemoteActionGrantView(
            view.approval_id,
            view.operation_id,
            view.request_fingerprint,
            view.workspace_id,
            view.evidence_id,
            view.commit_sha,
            view.execute_before,
            view.status,
            view.started_at,
            view.receipt,
            True,
        )

    @staticmethod
    def _workspace_is_current(connection, approval_id, workspace_id):
        return connection.execute(
            "SELECT 1 FROM tas_approvals approval "
            "JOIN tas_task_workspace_bindings workspace "
            "ON workspace.id=? AND workspace.task_id=approval.task_id "
            "AND workspace.actor_agent_id=approval.receiving_agent_id "
            "AND workspace.repository=approval.repository "
            "JOIN tas_workspace_registrations registration "
            "ON registration.workspace_id=workspace.id "
            "WHERE approval.id=?",
            (workspace_id.value, approval_id.value),
        ).fetchone() is not None

    @staticmethod
    def _resource_relationships_current(connection, approval_id):
        return connection.execute(
            "SELECT 1 FROM tas_approvals approval "
            "JOIN tas_agents requester ON requester.id=approval.requester_agent_id "
            "AND requester.owner_id=approval.requester_owner_id "
            "JOIN tas_agents receiver ON receiver.id=approval.receiving_agent_id "
            "AND receiver.owner_id=approval.receiving_owner_id "
            "JOIN tas_projects project ON project.id=approval.project_id "
            "AND project.team_id=approval.team_id "
            "JOIN tas_team_memberships requester_member "
            "ON requester_member.team_id=approval.team_id "
            "AND requester_member.owner_id=approval.requester_owner_id "
            "JOIN tas_team_memberships receiver_member "
            "ON receiver_member.team_id=approval.team_id "
            "AND receiver_member.owner_id=approval.receiving_owner_id "
            "JOIN tas_repository_bindings repository "
            "ON repository.repository=approval.repository "
            "AND repository.project_id=approval.project_id "
            "AND repository.controlling_owner_id=approval.receiving_owner_id "
            "JOIN tas_tasks task ON task.id=approval.task_id "
            "AND task.project_id=approval.project_id "
            "AND task.assignee_agent_id=approval.receiving_agent_id "
            "AND task.status='working' WHERE approval.id=?",
            (approval_id.value,),
        ).fetchone() is not None

    @staticmethod
    def _has_unknown(connection, approval_id, request_fingerprint):
        event_id = SQLiteRemoteActionGrantUnitOfWork._event_id(
            "unknown", approval_id.value, request_fingerprint
        )
        return connection.execute(
            "SELECT 1 FROM tas_audit_events WHERE id=? "
            "AND kind='action_result_unknown'",
            (event_id,),
        ).fetchone() is not None

    @staticmethod
    def _repository(connection, approval_id):
        return str(connection.execute(
            "SELECT repository FROM tas_approvals WHERE id=?", (approval_id.value,)
        ).fetchone()[0])

    @staticmethod
    def _action(connection, approval_id):
        return str(connection.execute(
            "SELECT action FROM tas_approvals WHERE id=?", (approval_id.value,)
        ).fetchone()[0])

    @staticmethod
    def _policy_version(connection, approval_id):
        return str(connection.execute(
            "SELECT policy_version FROM tas_approvals WHERE id=?", (approval_id.value,)
        ).fetchone()[0])

    def _audit_rejection(self, actor_id, approval_id, reason, now, correlation_id):
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT repository,action,policy_version FROM tas_approvals WHERE id=?",
                (approval_id.value,),
            ).fetchone()
            repository, action, policy_version = (
                ("approval", "execute", None)
                if row is None
                else (str(row[0]), str(row[1]), str(row[2]))
            )
            self._insert_audit(
                connection,
                self._event_id("rejected", approval_id.value, correlation_id),
                "action_grant_rejected",
                actor_id,
                repository,
                action,
                "rejected",
                reason.value,
                now,
                policy_version,
                correlation_id,
            )

    @staticmethod
    def _insert_audit(
        connection,
        event_id,
        kind,
        actor_id,
        repository,
        action,
        outcome,
        reason,
        occurred_at,
        policy_version,
        correlation_id,
        *,
        ignore_existing=False,
    ):
        verb = "INSERT OR IGNORE" if ignore_existing else "INSERT"
        connection.execute(
            f"{verb} INTO tas_audit_events(id,kind,actor_kind,actor_id,"
            "resource_type,resource_id,action,outcome,reason,occurred_at,"
            "policy_version,correlation_id) VALUES (?,?, 'agent',?, 'repository',"
            "?,?,?,?,?,?,?)",
            (
                event_id,
                kind,
                actor_id.value,
                repository,
                action,
                outcome,
                reason,
                occurred_at.isoformat(),
                policy_version,
                correlation_id,
            ),
        )

    @staticmethod
    def _event_id(kind, approval_id, discriminator):
        digest = hashlib.sha256(
            f"{kind}\0{approval_id}\0{discriminator}".encode()
        ).hexdigest()
        return f"remote-action:{kind}:{digest}"

    @staticmethod
    def _utc(value):
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("time must use UTC")
