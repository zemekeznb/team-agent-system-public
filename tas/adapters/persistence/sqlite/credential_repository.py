"""SQLite Credential lifecycle persistence with atomic security audit."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path

from tas.domain.audit import AuditEvent
from tas.domain.credential import (
    Credential,
    CredentialAssuranceLevel,
    CredentialAuthenticationRecord,
    CredentialId,
    CredentialIdentitySource,
    CredentialRevocationReason,
    CredentialScope,
    CredentialStatus,
    CredentialSubjectType,
)
from tas.domain.identity import AgentId, OwnerId
from tas.domain.ports import (
    CredentialConflictError,
    CredentialPersistenceError,
    CredentialReferenceError,
)


class SQLiteCredentialRepository:
    def __init__(self, database: str | Path) -> None:
        self.database = Path(database)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def add_with_audit(
        self,
        credential: Credential,
        secret_digest: str,
        secret_key_id: str,
        event: AuditEvent,
    ) -> None:
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                self._insert(connection, credential, secret_digest, secret_key_id)
                self._insert_audit(connection, event)
                connection.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                self._raise_integrity(error)
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def get(self, credential_id: CredentialId) -> Credential | None:
        with closing(self._connect()) as connection:
            row = self._select_one(connection, credential_id)
        return None if row is None else self._restore(row)

    def get_for_authentication(
        self, credential_id: CredentialId
    ) -> CredentialAuthenticationRecord | None:
        with closing(self._connect()) as connection:
            row = self._select_one(connection, credential_id)
            if row is None:
                return None
            binding_valid = bool(
                connection.execute(
                    "SELECT CASE WHEN ?='owner' THEN EXISTS("
                    "SELECT 1 FROM tas_owners WHERE id=?"
                    ") ELSE EXISTS(SELECT 1 FROM tas_agents WHERE id=? AND owner_id=?) END",
                    (row[1], row[2], row[3], row[2]),
                ).fetchone()[0]
            )
            binding_valid = binding_valid and bool(
                connection.execute(
                    "SELECT scopes_sealed FROM tas_credentials WHERE id=?",
                    (credential_id.value,),
                ).fetchone()[0]
            )
        return CredentialAuthenticationRecord(
            self._restore(row), str(row[4]), str(row[5]), binding_valid
        )

    def revoke_with_audit(
        self,
        credential_id: CredentialId,
        revoked_at: datetime,
        reason: CredentialRevocationReason,
        event: AuditEvent,
    ) -> Credential:
        if reason is CredentialRevocationReason.ROTATED:
            raise CredentialPersistenceError("Rotation requires a replacement Credential")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE tas_credentials SET status='revoked',revoked_at=?,"
                    "revocation_reason=? WHERE id=? AND status='active'",
                    (revoked_at.isoformat(), reason.value, credential_id.value),
                )
                if cursor.rowcount != 1:
                    raise CredentialConflictError("Credential is absent or no longer active")
                self._insert_audit(connection, event)
                row = self._select_one(connection, credential_id)
                connection.execute("COMMIT")
                assert row is not None
                return self._restore(row)
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                self._raise_integrity(error)
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def rotate_with_audit(
        self,
        old_id: CredentialId,
        replacement: Credential,
        secret_digest: str,
        secret_key_id: str,
        event: AuditEvent,
    ) -> tuple[Credential, Credential]:
        if replacement.rotated_from_id != old_id:
            raise CredentialPersistenceError("Replacement must identify rotated Credential")
        with closing(self._connect()) as connection:
            try:
                connection.execute("BEGIN IMMEDIATE")
                old_row = self._select_one(connection, old_id)
                if old_row is None or old_row[8] != CredentialStatus.ACTIVE.value:
                    raise CredentialConflictError("Credential is absent or no longer active")
                old = self._restore(old_row)
                if (
                    replacement.subject_type != old.subject_type
                    or replacement.owner_id != old.owner_id
                    or replacement.agent_id != old.agent_id
                    or replacement.scopes != old.scopes
                    or replacement.identity_source != old.identity_source
                    or replacement.assurance_level != old.assurance_level
                    or replacement.is_test_fixture != old.is_test_fixture
                ):
                    raise CredentialPersistenceError(
                        "Replacement cannot change subject, assurance, or scopes"
                    )
                self._insert(connection, replacement, secret_digest, secret_key_id)
                cursor = connection.execute(
                    "UPDATE tas_credentials SET status='revoked',revoked_at=?,"
                    "revocation_reason='rotated',replaced_by_id=? "
                    "WHERE id=? AND status='active'",
                    (replacement.issued_at.isoformat(), replacement.id.value, old_id.value),
                )
                if cursor.rowcount != 1:
                    raise CredentialConflictError("Credential is no longer active")
                self._insert_audit(connection, event)
                updated = self._select_one(connection, old_id)
                connection.execute("COMMIT")
                assert updated is not None
                return self._restore(updated), replacement
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                self._raise_integrity(error)
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _insert(
        connection: sqlite3.Connection,
        credential: Credential,
        secret_digest: str,
        secret_key_id: str,
    ) -> None:
        connection.execute(
            "INSERT INTO tas_credentials(id,subject_type,owner_id,agent_id,secret_digest,"
            "secret_key_id,issued_at,expires_at,status,identity_source,assurance_level,"
            "is_test_fixture,issued_by,revoked_at,revocation_reason,rotated_from_id,"
            "replaced_by_id,scopes_sealed) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
            (
                credential.id.value,
                credential.subject_type.value,
                credential.owner_id.value,
                None if credential.agent_id is None else credential.agent_id.value,
                secret_digest,
                secret_key_id,
                credential.issued_at.isoformat(),
                credential.expires_at.isoformat(),
                credential.status.value,
                credential.identity_source.value,
                credential.assurance_level.value,
                int(credential.is_test_fixture),
                credential.issued_by,
                None if credential.revoked_at is None else credential.revoked_at.isoformat(),
                None if credential.revocation_reason is None else credential.revocation_reason.value,
                None if credential.rotated_from_id is None else credential.rotated_from_id.value,
                None if credential.replaced_by_id is None else credential.replaced_by_id.value,
            ),
        )
        connection.executemany(
            "INSERT INTO tas_credential_scopes(credential_id,scope) VALUES (?,?)",
            ((credential.id.value, scope.value) for scope in credential.scopes),
        )
        connection.execute(
            "UPDATE tas_credentials SET scopes_sealed=1 WHERE id=? AND scopes_sealed=0",
            (credential.id.value,),
        )

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
    def _select_one(connection: sqlite3.Connection, credential_id: CredentialId):
        return connection.execute(
            "SELECT id,subject_type,owner_id,agent_id,secret_digest,secret_key_id,issued_at,"
            "expires_at,status,identity_source,assurance_level,is_test_fixture,issued_by,"
            "revoked_at,revocation_reason,rotated_from_id,replaced_by_id "
            "FROM tas_credentials WHERE id=?",
            (credential_id.value,),
        ).fetchone()

    def _restore(self, row: tuple[object, ...]) -> Credential:
        with closing(self._connect()) as connection:
            scopes = tuple(
                CredentialScope(value)
                for (value,) in connection.execute(
                    "SELECT scope FROM tas_credential_scopes WHERE credential_id=? ORDER BY scope",
                    (str(row[0]),),
                )
            )
        return Credential(
            CredentialId(str(row[0])), CredentialSubjectType(str(row[1])), OwnerId(str(row[2])),
            None if row[3] is None else AgentId(str(row[3])), scopes,
            datetime.fromisoformat(str(row[6])), datetime.fromisoformat(str(row[7])),
            CredentialStatus(str(row[8])), CredentialIdentitySource(str(row[9])),
            CredentialAssuranceLevel(str(row[10])), bool(row[11]), str(row[12]),
            None if row[13] is None else datetime.fromisoformat(str(row[13])),
            None if row[14] is None else CredentialRevocationReason(str(row[14])),
            None if row[15] is None else CredentialId(str(row[15])),
            None if row[16] is None else CredentialId(str(row[16])),
        )

    @staticmethod
    def _raise_integrity(error: sqlite3.IntegrityError) -> None:
        message = str(error).lower()
        if "foreign key" in message or "binding invalid" in message:
            raise CredentialReferenceError(
                "Credential references an unknown or inconsistent subject"
            ) from error
        raise CredentialConflictError("Credential lifecycle operation conflicts") from error
