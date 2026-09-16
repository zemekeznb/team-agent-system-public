"""SQLite persistence for the Approval aggregate."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.approval import Approval, ApprovalId, ApprovalStatus
from tas.domain.collaboration import TaskId
from tas.domain.identity import AgentId, OwnerId, ProjectId, TeamId
from tas.domain.policy import Action, ActionIntent, AuthorizationDecision, PolicyOutcome, PolicyReason, Risk


class ApprovalPersistenceConflictError(RuntimeError):
    """A stale Approval snapshot cannot overwrite a persisted decision."""


class SQLiteApprovalRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add(self, approval: Approval) -> None:
        if approval.status is not ApprovalStatus.PENDING:
            raise ApprovalPersistenceConflictError("only pending Approval may be added")
        intent = approval.decision.intent
        with closing(self._connect()) as connection, connection:
            try:
                connection.execute(
                    "INSERT INTO tas_approvals(id,status,requester_agent_id,requester_owner_id,receiving_agent_id,receiving_owner_id,team_id,project_id,task_id,repository,action,scope,risk,policy_reason,policy_version,requested_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (approval.id.value, approval.status.value, intent.requester_agent_id.value, intent.requester_owner_id.value, intent.receiving_agent_id.value, intent.receiving_owner_id.value, intent.team_id.value, intent.project_id.value, None if intent.task_id is None else intent.task_id.value, intent.repository, intent.action.value, intent.scope, int(intent.risk), approval.decision.reason.value, approval.decision.policy_version, approval.requested_at.isoformat(), approval.expires_at.isoformat()),
                )
            except sqlite3.IntegrityError as exc:
                raise ApprovalPersistenceConflictError("Approval cannot be inserted") from exc

    def save_resolution(self, approval: Approval) -> None:
        if approval.status is ApprovalStatus.PENDING:
            raise ApprovalPersistenceConflictError("pending Approval has no resolution")
        if approval.decision.intent.task_id is not None:
            raise ApprovalPersistenceConflictError("task Approval must use atomic task resolution")
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                "UPDATE tas_approvals SET status=?,resolved_by_owner_id=?,resolved_at=?,resolution_reason=? WHERE id=? AND status='pending'",
                (approval.status.value, None if approval.resolved_by is None else approval.resolved_by.value, approval.resolved_at.isoformat(), approval.reason, approval.id.value),
            )
            if cursor.rowcount != 1:
                raise ApprovalPersistenceConflictError("Approval is missing or already resolved")

    def resolve_with_task(self, approval: Approval) -> None:
        """Atomically persist a resolution and its exact Task disposition."""
        if approval.status is ApprovalStatus.PENDING or approval.decision.intent.task_id is None:
            raise ApprovalPersistenceConflictError("resolved task Approval is required")
        target = {
            ApprovalStatus.APPROVED: "working",
            ApprovalStatus.REJECTED: "rejected",
            ApprovalStatus.EXPIRED: "expired",
        }[approval.status]
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            persisted = self._get_with_connection(connection, approval.id)
            if persisted is None or persisted.status is not ApprovalStatus.PENDING:
                raise ApprovalPersistenceConflictError("Approval is missing or already resolved")
            expected = Approval(persisted.id, persisted.decision, persisted.requested_at, persisted.expires_at)
            candidate = Approval(approval.id, approval.decision, approval.requested_at, approval.expires_at)
            if candidate != expected:
                raise ApprovalPersistenceConflictError("Approval resolution does not match persisted request")
            task_id = approval.decision.intent.task_id
            task = connection.execute("SELECT status FROM tas_tasks WHERE id=?", (task_id.value,)).fetchone()
            if task is None or task[0] != "approval_required":
                raise ApprovalPersistenceConflictError("Task is not awaiting this Approval")
            sequence = connection.execute("SELECT count(*) FROM tas_task_transitions WHERE task_id=?", (task_id.value,)).fetchone()[0] + 1
            connection.execute("UPDATE tas_approvals SET status=?,resolved_by_owner_id=?,resolved_at=?,resolution_reason=? WHERE id=? AND status='pending'", (approval.status.value, None if approval.resolved_by is None else approval.resolved_by.value, approval.resolved_at.isoformat(), approval.reason, approval.id.value))
            connection.execute("UPDATE tas_tasks SET status=? WHERE id=? AND status='approval_required'", (target, task_id.value))
            connection.execute("INSERT INTO tas_task_transitions(task_id,sequence,from_status,to_status,actor_agent_id,reason,occurred_at) VALUES (?,?,?,?,?,?,?)", (task_id.value, sequence, "approval_required", target, approval.decision.intent.receiving_agent_id.value, f"approval:{approval.id.value}:{approval.status.value}", approval.resolved_at.isoformat()))

    def get(self, approval_id: ApprovalId) -> Approval | None:
        with closing(self._connect()) as connection:
            return self._get_with_connection(connection, approval_id)

    @staticmethod
    def _get_with_connection(connection: sqlite3.Connection, approval_id: ApprovalId) -> Approval | None:
        row = connection.execute("SELECT id,status,requester_agent_id,requester_owner_id,receiving_agent_id,receiving_owner_id,team_id,project_id,task_id,repository,action,scope,risk,policy_reason,policy_version,requested_at,expires_at,resolved_by_owner_id,resolved_at,resolution_reason FROM tas_approvals WHERE id=?", (approval_id.value,)).fetchone()
        if row is None:
            return None
        intent = ActionIntent(AgentId(row[2]), OwnerId(row[3]), AgentId(row[4]), OwnerId(row[5]), TeamId(row[6]), ProjectId(row[7]), row[9], Action(row[10]), row[11], Risk(row[12]), None if row[8] is None else TaskId(row[8]))
        decision = AuthorizationDecision(PolicyOutcome.APPROVAL_REQUIRED, PolicyReason(row[13]), OwnerId(row[5]), row[14], intent)
        return Approval(ApprovalId(row[0]), decision, datetime.fromisoformat(row[15]), datetime.fromisoformat(row[16]), ApprovalStatus(row[1]), None if row[17] is None else OwnerId(row[17]), None if row[18] is None else datetime.fromisoformat(row[18]), row[19])
