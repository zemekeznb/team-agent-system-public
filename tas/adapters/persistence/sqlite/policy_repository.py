"""SQLite immutable Owner Policy versions and atomic current selection."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.audit import AuditEvent
from tas.domain.identity import OwnerId
from tas.domain.policy import (
    Action, OwnerPolicy, PolicyMutationContext, PolicyOutcome, PolicyRule, Risk,
)
from tas.domain.ports import (
    PolicyConflictError, PolicyIdempotencyConflictError, PolicyPersistenceError,
)


class SQLitePolicyRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def add_with_audit(
        self,
        policy: OwnerPolicy,
        created_at: datetime,
        created_by: str,
        event: AuditEvent,
        idempotency: PolicyMutationContext | None = None,
    ) -> None:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                if self._replay(connection, idempotency) is not None:
                    connection.execute("COMMIT")
                    return
                connection.execute(
                    "INSERT INTO tas_owner_policies(owner_id,version,created_at,created_by) "
                    "VALUES (?,?,?,?)",
                    (policy.owner_id.value, policy.version, created_at.isoformat(), created_by),
                )
                connection.executemany(
                    "INSERT INTO tas_owner_policy_rules(owner_id,policy_version,sequence,"
                    "action,outcome,max_auto_risk) VALUES (?,?,?,?,?,?)",
                    (
                        (
                            policy.owner_id.value, policy.version, sequence,
                            rule.action.value, rule.outcome.value, int(rule.max_auto_risk),
                        )
                        for sequence, rule in enumerate(policy.rules, 1)
                    ),
                )
                self._insert_audit(connection, event)
                self._complete_idempotency(
                    connection, idempotency, policy.version, event.occurred_at
                )
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                raise PolicyConflictError("Policy version conflicts or Owner is unknown") from error
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def get(self, owner_id: OwnerId, version: str) -> OwnerPolicy | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT owner_id,version FROM tas_owner_policies "
                "WHERE owner_id=? AND version=?",
                (owner_id.value, version),
            ).fetchone()
            return None if row is None else self._restore(connection, row)

    def get_current(self, owner_id: OwnerId) -> OwnerPolicy | None:
        with closing(self._connect()) as connection:
            return self._restore_current_with_connection(connection, owner_id)

    @staticmethod
    def _restore_current_with_connection(
        connection: sqlite3.Connection, owner_id: OwnerId
    ) -> OwnerPolicy | None:
        row = connection.execute(
            "SELECT p.owner_id,p.version FROM tas_owner_policy_current c "
            "JOIN tas_owner_policies p ON p.owner_id=c.owner_id "
            "AND p.version=c.policy_version WHERE c.owner_id=?",
            (owner_id.value,),
        ).fetchone()
        return None if row is None else SQLitePolicyRepository._restore(connection, row)

    def select_current_with_audit(
        self,
        owner_id: OwnerId,
        version: str,
        expected_current_version: str | None,
        event: AuditEvent,
        idempotency: PolicyMutationContext | None = None,
    ) -> OwnerPolicy:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                replayed_version = self._replay(connection, idempotency)
                if replayed_version is not None:
                    replayed = connection.execute(
                        "SELECT owner_id,version FROM tas_owner_policies "
                        "WHERE owner_id=? AND version=?",
                        (owner_id.value, replayed_version),
                    ).fetchone()
                    if replayed is None:
                        raise PolicyPersistenceError("Idempotency result is invalid")
                    policy = self._restore(connection, replayed)
                    connection.execute("COMMIT")
                    return policy
                selected = connection.execute(
                    "SELECT owner_id,version FROM tas_owner_policies "
                    "WHERE owner_id=? AND version=?",
                    (owner_id.value, version),
                ).fetchone()
                if selected is None:
                    raise PolicyConflictError("Policy version does not exist")
                current = connection.execute(
                    "SELECT policy_version FROM tas_owner_policy_current WHERE owner_id=?",
                    (owner_id.value,),
                ).fetchone()
                actual = None if current is None else str(current[0])
                if actual != expected_current_version:
                    raise PolicyConflictError("Current Policy version changed")
                connection.execute(
                    "INSERT INTO tas_owner_policy_current(owner_id,policy_version,selected_at,"
                    "selected_by) VALUES (?,?,?,?) ON CONFLICT(owner_id) DO UPDATE SET "
                    "policy_version=excluded.policy_version,selected_at=excluded.selected_at,"
                    "selected_by=excluded.selected_by",
                    (
                        owner_id.value, version, event.occurred_at.isoformat(),
                        event.actor_id,
                    ),
                )
                self._insert_audit(connection, event)
                self._complete_idempotency(
                    connection, idempotency, version, event.occurred_at
                )
                policy = self._restore(connection, selected)
                connection.execute("COMMIT")
                return policy
            except PolicyConflictError:
                connection.execute("ROLLBACK")
                raise
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                raise PolicyConflictError("Policy current selection conflicts") from error
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _restore(connection: sqlite3.Connection, row: tuple[object, ...]) -> OwnerPolicy:
        rules = tuple(
            PolicyRule(Action(action), PolicyOutcome(outcome), Risk(int(risk)))
            for action, outcome, risk in connection.execute(
                "SELECT action,outcome,max_auto_risk FROM tas_owner_policy_rules "
                "WHERE owner_id=? AND policy_version=? ORDER BY sequence",
                (str(row[0]), str(row[1])),
            )
        )
        return OwnerPolicy(OwnerId(str(row[0])), str(row[1]), rules)

    @staticmethod
    def _insert_audit(connection: sqlite3.Connection, event: AuditEvent) -> None:
        connection.execute(
            "INSERT INTO tas_audit_events(id,kind,actor_kind,actor_id,resource_type,"
            "resource_id,action,outcome,reason,occurred_at,policy_version,correlation_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                event.id.value, event.kind.value, event.actor_kind.value, event.actor_id,
                event.resource_type, event.resource_id, event.action, event.outcome.value,
                event.reason, event.occurred_at.isoformat(), event.policy_version,
                event.correlation_id,
            ),
        )

    @staticmethod
    def _replay(
        connection: sqlite3.Connection,
        context: PolicyMutationContext | None,
    ) -> str | None:
        if context is None:
            return None
        row = connection.execute(
            "SELECT request_fingerprint,result_version FROM tas_api_idempotency_records "
            "WHERE owner_id=? AND operation=? AND idempotency_key=?",
            (context.owner_id.value, context.operation, context.key.value),
        ).fetchone()
        if row is None:
            return None
        if str(row[0]) != context.fingerprint.value:
            raise PolicyIdempotencyConflictError(
                "Idempotency key was used with a different request"
            )
        return str(row[1])

    @staticmethod
    def _complete_idempotency(
        connection: sqlite3.Connection,
        context: PolicyMutationContext | None,
        result_version: str,
        created_at: datetime,
    ) -> None:
        if context is None:
            return
        connection.execute(
            "INSERT INTO tas_api_idempotency_records(owner_id,operation,"
            "idempotency_key,request_fingerprint,result_version,created_at) "
            "VALUES (?,?,?,?,?,?)",
            (
                context.owner_id.value,
                context.operation,
                context.key.value,
                context.fingerprint.value,
                result_version,
                created_at.isoformat(),
            ),
        )
