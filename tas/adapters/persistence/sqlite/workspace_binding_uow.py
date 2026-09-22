"""SQLite Unit of Work for server-issued opaque Workspace IDs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

from tas.adapters.persistence.sqlite.idempotency_repository import (
    IdempotencyConflictError,
    fingerprint_payload,
)
from tas.application.workspace_bindings import (
    RegisterWorkspaceCommand,
    WorkspaceCommandResult,
    WorkspaceView,
)
from tas.domain.collaboration import TaskId
from tas.domain.audit import AuditActorKind, AuditEventKind, AuditOutcome
from tas.domain.credential import AuthenticatedPrincipal, CredentialSubjectType
from tas.domain.evidence import WorkspaceBindingId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId


class WorkspaceBindingAccessError(PermissionError):
    """Workspace target is unavailable to the authenticated principal."""


class WorkspaceBindingConflictError(RuntimeError):
    """Task already has a binding or the request key conflicts."""


class WorkspaceBindingIntegrityError(RuntimeError):
    """Persisted Workspace state cannot be reconstructed safely."""


class SQLiteWorkspaceBindingUnitOfWork:
    OPERATION = "workspace.register"

    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self):
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def register(
        self, actor_id: AgentId, key: IdempotencyKey,
        command: RegisterWorkspaceCommand, *, now: datetime,
        correlation_id: str,
    ) -> WorkspaceCommandResult:
        self._utc(now)
        fingerprint = fingerprint_payload({
            "task_id": command.task_id.value,
            "repository": command.repository,
        }).value
        reason = "workspace_scope_unavailable"
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                if not self._authorized_task(
                    connection, actor_id.value, command.task_id.value,
                    command.repository,
                ):
                    raise WorkspaceBindingAccessError("Workspace scope unavailable")
                ledger = connection.execute(
                    "SELECT request_fingerprint,result_json FROM "
                    "tas_idempotency_records WHERE actor_id=? AND operation=? "
                    "AND idempotency_key=?",
                    (actor_id.value, self.OPERATION, key.value),
                ).fetchone()
                if ledger is not None:
                    if str(ledger[0]) != fingerprint:
                        reason = "workspace_idempotency_conflict"
                        raise IdempotencyConflictError("Idempotency key conflicts")
                    try:
                        workspace_id = WorkspaceBindingId(
                            str(json.loads(str(ledger[1]))["workspace_id"])
                        )
                    except (json.JSONDecodeError, KeyError, TypeError) as error:
                        raise WorkspaceBindingIntegrityError(
                            "Workspace result is invalid"
                        ) from error
                    workspace = self._authorized_workspace(
                        connection, actor_id.value, workspace_id.value
                    )
                    if workspace is None:
                        raise WorkspaceBindingAccessError(
                            "Workspace scope unavailable"
                        )
                    connection.execute("COMMIT")
                    return WorkspaceCommandResult(workspace, True)
                if connection.execute(
                    "SELECT 1 FROM tas_task_workspace_bindings WHERE task_id=?",
                    (command.task_id.value,),
                ).fetchone() is not None:
                    reason = "workspace_already_bound"
                    raise WorkspaceBindingConflictError("Task is already bound")

                workspace_id = WorkspaceBindingId(str(uuid4()))
                compatibility_digest = hashlib.sha256(
                    ("opaque-workspace-v1\0" + workspace_id.value).encode("utf-8")
                ).hexdigest()
                connection.execute(
                    "INSERT INTO tas_task_workspace_bindings "
                    "(id,task_id,actor_agent_id,repository,root_sha256,bound_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        workspace_id.value, command.task_id.value, actor_id.value,
                        command.repository, compatibility_digest, now.isoformat(),
                    ),
                )
                connection.execute(
                    "INSERT INTO tas_workspace_registrations VALUES (?,?)",
                    (workspace_id.value, now.isoformat()),
                )
                result = json.dumps(
                    {"workspace_id": workspace_id.value},
                    sort_keys=True, separators=(",", ":"),
                )
                connection.execute(
                    "INSERT INTO tas_idempotency_records(actor_id,operation,"
                    "idempotency_key,request_fingerprint,status,"
                    "reservation_token_hash,result_json,created_at,updated_at) "
                    "VALUES (?,?,?,?,'completed',NULL,?,?,?)",
                    (
                        actor_id.value, self.OPERATION, key.value, fingerprint,
                        result, now.isoformat(), now.isoformat(),
                    ),
                )
                workspace = self._authorized_workspace(
                    connection, actor_id.value, workspace_id.value
                )
                if workspace is None:
                    raise WorkspaceBindingIntegrityError(
                        "Workspace could not be restored"
                    )
                connection.execute("COMMIT")
                return WorkspaceCommandResult(workspace, False)
        except IdempotencyConflictError:
            self._audit(actor_id, command.task_id.value, reason, now, correlation_id)
            raise
        except (WorkspaceBindingAccessError, WorkspaceBindingConflictError):
            self._audit(actor_id, command.task_id.value, reason, now, correlation_id)
            raise
        except sqlite3.IntegrityError as error:
            raise WorkspaceBindingIntegrityError(
                "Workspace could not be committed"
            ) from error

    def get(
        self,
        principal: AuthenticatedPrincipal,
        workspace_id: WorkspaceBindingId,
    ) -> WorkspaceView | None:
        with self._connect() as connection:
            connection.execute("BEGIN")
            row = self._authorized_workspace(
                connection,
                None if principal.agent_id is None else principal.agent_id.value,
                workspace_id.value,
                owner_id=(
                    principal.owner_id.value
                    if principal.subject_type is CredentialSubjectType.OWNER
                    else None
                ),
            )
            connection.execute("COMMIT")
            return row

    @staticmethod
    def _authorized_task(connection, actor_id, task_id, repository):
        return connection.execute(
            "SELECT 1 FROM tas_tasks task JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor ON actor.id=? "
            "JOIN tas_team_memberships member ON member.team_id=project.team_id "
            "AND member.owner_id=actor.owner_id JOIN tas_repository_bindings binding "
            "ON binding.project_id=project.id AND binding.repository=? "
            "WHERE task.id=? AND task.assignee_agent_id=actor.id",
            (actor_id, repository, task_id),
        ).fetchone() is not None

    @staticmethod
    def _authorized_workspace(
        connection, actor_id, workspace_id, *, owner_id=None,
    ):
        row = connection.execute(
            "SELECT binding.id,binding.task_id,binding.actor_agent_id,"
            "binding.repository,binding.bound_at FROM tas_task_workspace_bindings binding "
            "JOIN tas_workspace_registrations registration "
            "ON registration.workspace_id=binding.id JOIN tas_tasks task "
            "ON task.id=binding.task_id JOIN tas_projects project "
            "ON project.id=task.project_id JOIN tas_agents actor "
            "ON actor.id=binding.actor_agent_id JOIN tas_team_memberships member "
            "ON member.team_id=project.team_id AND member.owner_id=actor.owner_id "
            "JOIN tas_repository_bindings repository "
            "ON repository.project_id=project.id "
            "AND repository.repository=binding.repository WHERE binding.id=? "
            "AND task.assignee_agent_id=binding.actor_agent_id "
            "AND ((? IS NOT NULL AND binding.actor_agent_id=?) "
            "OR (? IS NOT NULL AND actor.owner_id=?))",
            (workspace_id, actor_id, actor_id, owner_id, owner_id),
        ).fetchone()
        if row is None:
            return None
        return WorkspaceView(
            WorkspaceBindingId(str(row[0])),
            TaskId(str(row[1])),
            AgentId(str(row[2])),
            str(row[3]),
            datetime.fromisoformat(str(row[4])),
        )

    def _audit(self, actor_id, task_id, reason, now, correlation_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,"
                "resource_type,resource_id,action,outcome,reason,occurred_at,"
                "policy_version,correlation_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    str(uuid4()), AuditEventKind.AUTHORIZATION_DECISION.value,
                    AuditActorKind.AGENT.value, actor_id.value, "task", task_id,
                    "workspace.register", AuditOutcome.REJECTED.value, reason,
                    now.isoformat(), None, correlation_id,
                ),
            )

    @staticmethod
    def _utc(value):
        if (
            not isinstance(value, datetime) or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("now must use UTC")
