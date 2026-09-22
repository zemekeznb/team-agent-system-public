"""Atomic F3 Approval request/decision commands and authorization checks."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.approval_repository import (
    SQLiteApprovalRepository,
)
from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError, fingerprint_payload,
)
from tas.application.approval_commands import (
    ApprovalCommandResult, DecideApprovalCommand, RequestApprovalCommand,
)
from tas.domain.approval import (
    Approval, ApprovalId, ApprovalStatus, InvalidApprovalTransitionError,
)
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.collaboration import TaskId, TaskStatus
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, OwnerId, ProjectId, TeamId
from tas.domain.policy import (
    Action, ActionIntent, OwnerPolicy, PolicyEngine, PolicyOutcome, PolicyRule,
    Risk,
)


class ApprovalCommandConflictError(RuntimeError):
    """Approval command conflicts with current state or authorization."""


class ApprovalCommandAccessError(RuntimeError):
    """Approval target is not visible to the authenticated principal."""


class ApprovalCommandIntegrityError(RuntimeError):
    """Persisted Approval command state cannot be reconstructed safely."""


class SQLiteApprovalCommandUnitOfWork:
    REQUEST_OPERATION = "approval.request"
    DECIDE_OPERATION = "approval.decide"

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def request(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: RequestApprovalCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult:
        self._require_utc(now)
        if (
            not isinstance(command.lifetime, timedelta)
            or not command.lifetime.total_seconds().is_integer()
            or not timedelta(minutes=1) <= command.lifetime <= timedelta(days=1)
        ):
            raise ValueError("Approval lifetime must be 60..86400 seconds")
        fingerprint = fingerprint_payload({
            "task_id": command.task_id.value,
            "repository": command.repository,
            "action": command.action.value,
            "scope": command.scope,
            "risk": int(command.risk),
            "lifetime_seconds": int(command.lifetime.total_seconds()),
        })
        rejected_reason: str | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                context = self._request_context(
                    connection, actor_id, command.task_id, command.repository
                )
                if context is None:
                    rejected_reason = "task_or_resource_unavailable"
                    raise ApprovalCommandAccessError("Approval target is unavailable")
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_json FROM tas_idempotency_records "
                    "WHERE actor_id=? AND operation=? AND idempotency_key=?",
                    (actor_id.value, self.REQUEST_OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    result = self._replay_request(
                        connection, ledger, fingerprint.value, actor_id,
                        command.task_id,
                    )
                    connection.execute("COMMIT")
                    return result
                (
                    requester_agent, requester_owner, receiving_owner,
                    project_id, team_id, task_status,
                ) = context
                if task_status != TaskStatus.WORKING.value:
                    rejected_reason = "task_not_working"
                    raise ApprovalCommandConflictError(
                        "Task is not ready for an Approval request"
                    )
                policy = self._current_policy(connection, OwnerId(receiving_owner))
                if policy is None:
                    self._insert_authorization_audit(
                        connection, AuditActorKind.AGENT, actor_id.value,
                        "task", command.task_id.value, command.action.value,
                        AuditOutcome.DENY, "policy_not_configured", now,
                        correlation_id,
                    )
                    connection.execute("COMMIT")
                    raise ApprovalCommandConflictError("Approval is not permitted")
                intent = ActionIntent(
                    AgentId(requester_agent), OwnerId(requester_owner), actor_id,
                    OwnerId(receiving_owner), TeamId(team_id), ProjectId(project_id),
                    command.repository, command.action, command.scope, command.risk,
                    command.task_id,
                )
                decision = PolicyEngine().authorize(intent, policy)
                self._insert_authorization_audit(
                    connection, AuditActorKind.AGENT, requester_agent,
                    "repository", command.repository, command.action.value,
                    AuditOutcome(decision.outcome.value), decision.reason.value, now,
                    correlation_id, policy.version,
                )
                if decision.outcome is not PolicyOutcome.APPROVAL_REQUIRED:
                    connection.execute("COMMIT")
                    raise ApprovalCommandConflictError("Approval is not required")
                approval = Approval(
                    ApprovalId(str(uuid4())), decision, now, now + command.lifetime
                )
                self._insert_approval(connection, approval)
                sequence = connection.execute(
                    "SELECT count(*) FROM tas_task_transitions WHERE task_id=?",
                    (command.task_id.value,),
                ).fetchone()[0] + 1
                cursor = connection.execute(
                    "UPDATE tas_tasks SET status='approval_required' "
                    "WHERE id=? AND status='working'",
                    (command.task_id.value,),
                )
                if cursor.rowcount != 1:
                    raise ApprovalCommandIntegrityError("Task changed during request")
                connection.execute(
                    "INSERT INTO tas_task_transitions(task_id,sequence,from_status,"
                    "to_status,actor_agent_id,reason,occurred_at) "
                    "VALUES (?,?, 'working','approval_required',?,?,?)",
                    (
                        command.task_id.value, sequence, actor_id.value,
                        f"approval:{approval.id.value}:requested", now.isoformat(),
                    ),
                )
                self._complete_agent_ledger(
                    connection, actor_id, key, fingerprint.value,
                    {"approval_id": approval.id.value}, now,
                )
                connection.execute("COMMIT")
                return ApprovalCommandResult(approval, replayed=False)
        except (ApprovalCommandAccessError, ApprovalCommandConflictError):
            if rejected_reason is not None:
                self._audit_rejection(
                    AuditActorKind.AGENT, actor_id.value, "task",
                    command.task_id.value, self.REQUEST_OPERATION, rejected_reason,
                    now, correlation_id,
                )
            raise

    def decide(
        self,
        actor_id: OwnerId,
        key: IdempotencyKey,
        command: DecideApprovalCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ApprovalCommandResult:
        self._require_utc(now)
        fingerprint = fingerprint_payload({
            "approval_id": command.approval_id.value,
            "decision": "approved" if command.approve else "rejected",
            "reason": command.reason,
        })
        rejection_reason: str | None = None
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                approval = self._authorized_for_owner(
                    connection, actor_id, command.approval_id
                )
                if approval is None:
                    rejection_reason = "approval_unavailable"
                    raise ApprovalCommandAccessError("Approval is unavailable")
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_version "
                    "FROM tas_api_idempotency_records WHERE owner_id=? "
                    "AND operation=? AND idempotency_key=?",
                    (actor_id.value, self.DECIDE_OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    if ledger[0] != fingerprint.value:
                        raise IdempotencyConflictError("Idempotency key conflicts")
                    if ledger[1] != approval.id.value:
                        raise ApprovalCommandIntegrityError(
                            "Decision result references another Approval"
                        )
                    connection.execute("COMMIT")
                    return ApprovalCommandResult(approval, replayed=True)
                if approval.status is not ApprovalStatus.PENDING:
                    rejection_reason = "approval_already_resolved"
                    raise ApprovalCommandConflictError("Approval is already resolved")
                try:
                    if now >= approval.expires_at:
                        resolved = approval.expire(now)
                    elif command.approve:
                        resolved = approval.approve(actor_id, now, command.reason)
                    else:
                        resolved = approval.reject(actor_id, now, command.reason or "")
                except InvalidApprovalTransitionError:
                    rejection_reason = "invalid_approval_decision"
                    raise ApprovalCommandConflictError(
                        "Approval decision is invalid"
                    ) from None
                self._persist_resolution(connection, resolved)
                connection.execute(
                    "INSERT INTO tas_api_idempotency_records(owner_id,operation,"
                    "idempotency_key,request_fingerprint,result_version,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        actor_id.value, self.DECIDE_OPERATION, key.value,
                        fingerprint.value, approval.id.value, now.isoformat(),
                    ),
                )
                connection.execute("COMMIT")
                return ApprovalCommandResult(resolved, replayed=False)
        except (ApprovalCommandAccessError, ApprovalCommandConflictError):
            if rejection_reason is not None:
                self._audit_rejection(
                    AuditActorKind.OWNER, actor_id.value, "approval",
                    command.approval_id.value, self.DECIDE_OPERATION,
                    rejection_reason, now, correlation_id,
                )
            raise

    def get_for_agent(
        self, actor_id: AgentId, approval_id: ApprovalId
    ) -> Approval | None:
        with self._connect() as connection:
            approval = SQLiteApprovalRepository._get_with_connection(
                connection, approval_id
            )
            if approval is None:
                return None
            intent = approval.decision.intent
            if actor_id not in {
                intent.requester_agent_id, intent.receiving_agent_id,
            }:
                return None
            if connection.execute(
                "SELECT 1 FROM tas_agents actor "
                "JOIN tas_team_memberships member ON member.owner_id=actor.owner_id "
                "WHERE actor.id=? AND member.team_id=?",
                (actor_id.value, intent.team_id.value),
            ).fetchone() is None:
                return None
            return approval

    def get_for_owner(
        self, actor_id: OwnerId, approval_id: ApprovalId
    ) -> Approval | None:
        with self._connect() as connection:
            approval = SQLiteApprovalRepository._get_with_connection(
                connection, approval_id
            )
            if approval is None or actor_id not in {
                approval.decision.intent.requester_owner_id,
                approval.decision.intent.receiving_owner_id,
            }:
                return None
            if connection.execute(
                "SELECT 1 FROM tas_team_memberships WHERE team_id=? AND owner_id=?",
                (approval.decision.intent.team_id.value, actor_id.value),
            ).fetchone() is None:
                return None
            return approval

    @staticmethod
    def _request_context(connection, actor_id, task_id, repository):
        return connection.execute(
            "SELECT origin.requester_agent_id,origin.requester_owner_id,"
            "receiver.owner_id,task.project_id,project.team_id,task.status "
            "FROM tas_tasks task "
            "JOIN tas_task_origins origin ON origin.task_id=task.id "
            "JOIN tas_agents requester ON requester.id=origin.requester_agent_id "
            "AND requester.owner_id=origin.requester_owner_id "
            "JOIN tas_agents receiver ON receiver.id=task.assignee_agent_id "
            "JOIN tas_projects project ON project.id=task.project_id "
            "JOIN tas_team_memberships requester_member "
            "ON requester_member.team_id=project.team_id "
            "AND requester_member.owner_id=origin.requester_owner_id "
            "JOIN tas_team_memberships receiver_member "
            "ON receiver_member.team_id=project.team_id "
            "AND receiver_member.owner_id=receiver.owner_id "
            "JOIN tas_repository_bindings binding ON binding.repository=? "
            "AND binding.project_id=task.project_id "
            "AND binding.controlling_owner_id=receiver.owner_id "
            "WHERE task.id=? AND task.assignee_agent_id=?",
            (repository, task_id.value, actor_id.value),
        ).fetchone()

    @staticmethod
    def _current_policy(connection, owner_id: OwnerId) -> OwnerPolicy | None:
        row = connection.execute(
            "SELECT policy.policy_version FROM tas_owner_policy_current policy "
            "WHERE policy.owner_id=?",
            (owner_id.value,),
        ).fetchone()
        if row is None:
            return None
        rules = tuple(
            PolicyRule(Action(action), PolicyOutcome(outcome), Risk(risk))
            for action, outcome, risk in connection.execute(
                "SELECT action,outcome,max_auto_risk FROM tas_owner_policy_rules "
                "WHERE owner_id=? AND policy_version=? ORDER BY sequence",
                (owner_id.value, row[0]),
            )
        )
        return OwnerPolicy(owner_id, row[0], rules)

    @staticmethod
    def _insert_approval(connection, approval: Approval) -> None:
        intent = approval.decision.intent
        connection.execute(
            "INSERT INTO tas_approvals(id,status,requester_agent_id,"
            "requester_owner_id,receiving_agent_id,receiving_owner_id,team_id,"
            "project_id,task_id,repository,action,scope,risk,policy_reason,"
            "policy_version,requested_at,expires_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                approval.id.value, approval.status.value,
                intent.requester_agent_id.value, intent.requester_owner_id.value,
                intent.receiving_agent_id.value, intent.receiving_owner_id.value,
                intent.team_id.value, intent.project_id.value, intent.task_id.value,
                intent.repository, intent.action.value, intent.scope, int(intent.risk),
                approval.decision.reason.value, approval.decision.policy_version,
                approval.requested_at.isoformat(), approval.expires_at.isoformat(),
            ),
        )

    def _replay_request(
        self, connection, row, fingerprint, actor_id, task_id
    ) -> ApprovalCommandResult:
        if row[0] != fingerprint:
            raise IdempotencyConflictError("Idempotency key conflicts")
        try:
            approval_id = ApprovalId(json.loads(row[1])["approval_id"])
        except (json.JSONDecodeError, KeyError, TypeError) as error:
            raise ApprovalCommandIntegrityError("Approval result is invalid") from error
        approval = SQLiteApprovalRepository._get_with_connection(
            connection, approval_id
        )
        if (
            approval is None
            or approval.decision.intent.receiving_agent_id != actor_id
            or approval.decision.intent.task_id != task_id
        ):
            raise ApprovalCommandIntegrityError("Approval result is inconsistent")
        return ApprovalCommandResult(approval, replayed=True)

    def _persist_resolution(self, connection, approval: Approval) -> None:
        task_id = approval.decision.intent.task_id
        if task_id is None:
            raise ApprovalCommandIntegrityError("Task Approval has no Task")
        target = {
            ApprovalStatus.APPROVED: TaskStatus.WORKING,
            ApprovalStatus.REJECTED: TaskStatus.REJECTED,
            ApprovalStatus.EXPIRED: TaskStatus.EXPIRED,
        }[approval.status]
        cursor = connection.execute(
            "UPDATE tas_approvals SET status=?,resolved_by_owner_id=?,resolved_at=?,"
            "resolution_reason=? WHERE id=? AND status='pending'",
            (
                approval.status.value,
                None if approval.resolved_by is None else approval.resolved_by.value,
                approval.resolved_at.isoformat(), approval.reason, approval.id.value,
            ),
        )
        if cursor.rowcount != 1:
            raise ApprovalCommandIntegrityError("Approval changed during decision")
        sequence = connection.execute(
            "SELECT count(*) FROM tas_task_transitions WHERE task_id=?",
            (task_id.value,),
        ).fetchone()[0] + 1
        cursor = connection.execute(
            "UPDATE tas_tasks SET status=? WHERE id=? AND status='approval_required'",
            (target.value, task_id.value),
        )
        if cursor.rowcount != 1:
            raise ApprovalCommandIntegrityError("Task is not awaiting Approval")
        connection.execute(
            "INSERT INTO tas_task_transitions(task_id,sequence,from_status,to_status,"
            "actor_agent_id,reason,occurred_at) VALUES (?,?, 'approval_required',?,?,?,?)",
            (
                task_id.value, sequence, target.value,
                approval.decision.intent.receiving_agent_id.value,
                f"approval:{approval.id.value}:{approval.status.value}",
                approval.resolved_at.isoformat(),
            ),
        )

    @staticmethod
    def _authorized_for_owner(connection, actor_id, approval_id):
        approval = SQLiteApprovalRepository._get_with_connection(
            connection, approval_id
        )
        if approval is None or approval.decision.intent.receiving_owner_id != actor_id:
            return None
        if connection.execute(
            "SELECT 1 FROM tas_team_memberships WHERE team_id=? AND owner_id=?",
            (approval.decision.intent.team_id.value, actor_id.value),
        ).fetchone() is None:
            return None
        return approval

    def _complete_agent_ledger(
        self, connection, actor_id, key, fingerprint, result, now
    ) -> None:
        connection.execute(
            "INSERT INTO tas_idempotency_records(actor_id,operation,idempotency_key,"
            "request_fingerprint,status,reservation_token_hash,result_json,created_at,"
            "updated_at) VALUES (?,?,?,?, 'completed',NULL,?,?,?)",
            (
                actor_id.value, self.REQUEST_OPERATION, key.value, fingerprint,
                json.dumps(result, sort_keys=True, separators=(",", ":")),
                now.isoformat(), now.isoformat(),
            ),
        )

    @staticmethod
    def _insert_authorization_audit(
        connection, actor_kind, actor_id, resource_type, resource_id, action,
        outcome, reason, now, correlation_id, policy_version=None,
    ) -> None:
        connection.execute(
            "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
            "resource_id,action,outcome,reason,occurred_at,policy_version,"
            "correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                actor_kind.value, actor_id, resource_type, resource_id, action,
                outcome.value, reason, now.isoformat(), policy_version,
                correlation_id,
            ),
        )

    def _audit_rejection(
        self, actor_kind, actor_id, resource_type, resource_id, action, reason,
        now, correlation_id,
    ) -> None:
        with self._connect() as connection:
            self._insert_authorization_audit(
                connection, actor_kind, actor_id, resource_type, resource_id,
                action, AuditOutcome.REJECTED, reason, now, correlation_id,
            )

    @staticmethod
    def _require_utc(value: datetime) -> None:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("now must use UTC")
