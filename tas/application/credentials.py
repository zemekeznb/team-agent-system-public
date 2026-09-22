"""Credential issuance, authentication, revocation, and rotation policy."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timedelta
from uuid import uuid4

from tas.domain.audit import (
    AuditActorKind,
    AuditEvent,
    AuditEventId,
    AuditEventKind,
    AuditOutcome,
)
from tas.domain.credential import (
    AuthenticatedPrincipal,
    Credential,
    CredentialAssuranceLevel,
    CredentialAuditReason,
    CredentialId,
    CredentialIdentitySource,
    CredentialKeyUnavailableError,
    CredentialRevocationReason,
    CredentialScope,
    CredentialStatus,
    CredentialSubjectType,
    CredentialTokenError,
    IssuedCredential,
    OWNER_ONLY_CREDENTIAL_SCOPES,
)
from tas.domain.identity import AgentId, DomainValidationError, OwnerId
from tas.domain.ports import AuditRepository, CredentialRepository, CredentialTokenProvider


MIN_LIFETIME = timedelta(minutes=5)
MAX_LIFETIME = timedelta(days=90)
class InvalidCredentialError(PermissionError):
    """Stable external authentication failure without reason disclosure."""


class InsufficientCredentialScopeError(InvalidCredentialError):
    """The Credential is valid but does not grant the required operation scope."""


class CredentialPolicyError(ValueError):
    """Raised before persistence when issuance policy is invalid."""


class CredentialService:
    """Lifecycle service for a trusted management context.

    F3-PREP-004 must derive Owner actors from an authenticated Principal and enforce
    ``credentials:manage`` before calling lifecycle methods. Request data is not a
    valid source for ``actor_kind`` or ``actor_id``.
    """

    def __init__(
        self,
        credentials: CredentialRepository,
        audit: AuditRepository,
        codec: CredentialTokenProvider,
        *,
        id_factory: Callable[[], str] = lambda: str(uuid4()),
        audit_id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.credentials = credentials
        self.audit = audit
        self.codec = codec
        self.id_factory = id_factory
        self.audit_id_factory = audit_id_factory

    def issue(
        self,
        *,
        subject_type: CredentialSubjectType,
        owner_id: OwnerId,
        agent_id: AgentId | None,
        scopes: tuple[CredentialScope, ...],
        now: datetime,
        lifetime: timedelta,
        actor_kind: AuditActorKind,
        actor_id: str,
        identity_source: CredentialIdentitySource = CredentialIdentitySource.OUT_OF_BAND_REGISTRATION,
        assurance_level: CredentialAssuranceLevel = CredentialAssuranceLevel.REGISTERED,
        is_test_fixture: bool = False,
    ) -> IssuedCredential:
        self._require_management_actor(actor_kind)
        self._require_owner_scope(actor_kind, actor_id, owner_id)
        self._validate_policy(subject_type, scopes, lifetime)
        credential = Credential(
            CredentialId(self.id_factory()), subject_type, owner_id, agent_id, scopes,
            now, now + lifetime, CredentialStatus.ACTIVE, identity_source,
            assurance_level, is_test_fixture, actor_id,
        )
        token, digest, key_id = self.codec.issue(credential.id)
        self.credentials.add_with_audit(
            credential, digest, key_id,
            self._event(
                AuditEventKind.CREDENTIAL_ISSUED, actor_kind, actor_id, credential.id,
                "issue", AuditOutcome.ISSUED, CredentialAuditReason.ISSUED, now,
            ),
        )
        return IssuedCredential(credential, token)

    def authenticate(
        self, token: str, required_scope: CredentialScope, now: datetime
    ) -> AuthenticatedPrincipal:
        credential_id: CredentialId | None = None
        reason = CredentialAuditReason.MALFORMED
        try:
            credential_id = self.codec.identify(token)
            record = self.credentials.get_for_authentication(credential_id)
            if record is None:
                reason = CredentialAuditReason.UNKNOWN
                raise InvalidCredentialError("Invalid credential")
            credential = record.credential
            if credential.status is CredentialStatus.REVOKED:
                reason = CredentialAuditReason.REVOKED_CREDENTIAL
                raise InvalidCredentialError("Invalid credential")
            if credential.effective_status(now) is CredentialStatus.EXPIRED:
                reason = CredentialAuditReason.EXPIRED
                raise InvalidCredentialError("Invalid credential")
            if not record.binding_valid:
                reason = CredentialAuditReason.BINDING_INVALID
                raise InvalidCredentialError("Invalid credential")
            try:
                valid = self.codec.verify(
                    token, credential.id, record.secret_key_id, record.secret_digest
                )
            except CredentialKeyUnavailableError:
                reason = CredentialAuditReason.KEY_UNAVAILABLE
                raise InvalidCredentialError("Invalid credential") from None
            if not valid:
                reason = CredentialAuditReason.INVALID_SECRET
                raise InvalidCredentialError("Invalid credential")
            if not isinstance(required_scope, CredentialScope) or required_scope not in credential.scopes:
                reason = CredentialAuditReason.SCOPE_INSUFFICIENT
                raise InsufficientCredentialScopeError("Invalid credential")
            return AuthenticatedPrincipal(
                credential.id, credential.subject_type, credential.owner_id,
                credential.agent_id, credential.scopes, credential.identity_source,
                credential.assurance_level, credential.is_test_fixture,
                credential.expires_at,
            )
        except CredentialTokenError:
            self.audit.add(
                self._event(
                    AuditEventKind.AUTHENTICATION_REJECTED, AuditActorKind.SYSTEM,
                    "credential-authenticator", credential_id, "authenticate",
                    AuditOutcome.REJECTED, reason, now,
                )
            )
            raise InvalidCredentialError("Invalid credential") from None
        except InvalidCredentialError as error:
            self.audit.add(
                self._event(
                    AuditEventKind.AUTHENTICATION_REJECTED, AuditActorKind.SYSTEM,
                    "credential-authenticator", credential_id, "authenticate",
                    AuditOutcome.REJECTED, reason, now,
                )
            )
            raise error from None

    def revoke(
        self,
        credential_id: CredentialId,
        *,
        now: datetime,
        reason: CredentialRevocationReason,
        actor_kind: AuditActorKind,
        actor_id: str,
    ) -> Credential:
        self._require_management_actor(actor_kind)
        existing = self.credentials.get(credential_id)
        if existing is None:
            raise InvalidCredentialError("Invalid credential")
        self._require_owner_scope(actor_kind, actor_id, existing.owner_id)
        return self.credentials.revoke_with_audit(
            credential_id, now, reason,
            self._event(
                AuditEventKind.CREDENTIAL_REVOKED, actor_kind, actor_id,
                credential_id, "revoke", AuditOutcome.REVOKED,
                self._revocation_audit_reason(reason), now,
            ),
        )

    def rotate(
        self,
        credential_id: CredentialId,
        *,
        now: datetime,
        lifetime: timedelta,
        actor_kind: AuditActorKind,
        actor_id: str,
    ) -> IssuedCredential:
        self._require_management_actor(actor_kind)
        old = self.credentials.get(credential_id)
        if old is None or old.status is not CredentialStatus.ACTIVE:
            raise InvalidCredentialError("Invalid credential")
        self._require_owner_scope(actor_kind, actor_id, old.owner_id)
        self._validate_policy(old.subject_type, old.scopes, lifetime)
        replacement = Credential(
            CredentialId(self.id_factory()), old.subject_type, old.owner_id, old.agent_id,
            old.scopes, now, now + lifetime, CredentialStatus.ACTIVE,
            old.identity_source, old.assurance_level, old.is_test_fixture, actor_id,
            rotated_from_id=old.id,
        )
        token, digest, key_id = self.codec.issue(replacement.id)
        self.credentials.rotate_with_audit(
            old.id, replacement, digest, key_id,
            self._event(
                AuditEventKind.CREDENTIAL_ROTATED, actor_kind, actor_id,
                old.id, "rotate", AuditOutcome.ROTATED,
                CredentialAuditReason.ROTATED, now,
            ),
        )
        return IssuedCredential(replacement, token)

    @staticmethod
    def _validate_policy(
        subject_type: CredentialSubjectType,
        scopes: tuple[CredentialScope, ...],
        lifetime: timedelta,
    ) -> None:
        if not isinstance(lifetime, timedelta) or not MIN_LIFETIME <= lifetime <= MAX_LIFETIME:
            raise CredentialPolicyError("Credential lifetime must be 5 minutes..90 days")
        if subject_type is CredentialSubjectType.AGENT and OWNER_ONLY_CREDENTIAL_SCOPES.intersection(scopes):
            raise CredentialPolicyError("Agent Credential cannot receive Owner-only scopes")

    @staticmethod
    def _require_management_actor(actor_kind: AuditActorKind) -> None:
        if actor_kind not in (AuditActorKind.OWNER, AuditActorKind.SYSTEM):
            raise CredentialPolicyError("Agent actor cannot manage Credentials")

    @staticmethod
    def _require_owner_scope(
        actor_kind: AuditActorKind, actor_id: str, target_owner_id: OwnerId
    ) -> None:
        if actor_kind is AuditActorKind.OWNER and actor_id != target_owner_id.value:
            raise CredentialPolicyError("Owner cannot manage another Owner's Credential")

    @staticmethod
    def _revocation_audit_reason(
        reason: CredentialRevocationReason,
    ) -> CredentialAuditReason:
        mapping = {
            CredentialRevocationReason.MANUAL: CredentialAuditReason.REVOKED_MANUAL,
            CredentialRevocationReason.COMPROMISED: CredentialAuditReason.REVOKED_COMPROMISED,
            CredentialRevocationReason.OWNER_REMOVED: CredentialAuditReason.REVOKED_OWNER_REMOVED,
            CredentialRevocationReason.BINDING_INVALID: CredentialAuditReason.REVOKED_BINDING_INVALID,
        }
        try:
            return mapping[reason]
        except (KeyError, TypeError):
            raise CredentialPolicyError("Rotation revocation requires rotate()") from None

    def _event(
        self,
        kind: AuditEventKind,
        actor_kind: AuditActorKind,
        actor_id: str,
        credential_id: CredentialId | None,
        action: str,
        outcome: AuditOutcome,
        reason: CredentialAuditReason,
        now: datetime,
    ) -> AuditEvent:
        try:
            event_id = AuditEventId(self.audit_id_factory())
            return AuditEvent(
                event_id, kind, actor_kind, actor_id, "credential",
                "unknown" if credential_id is None else credential_id.value,
                action, outcome, reason.value, now,
            )
        except DomainValidationError:
            raise CredentialPolicyError("Credential audit context is invalid") from None


class PrincipalCredentialManagementService:
    """Credential management whose actor is an authenticated Owner Principal."""

    def __init__(self, lifecycle: CredentialService) -> None:
        self.lifecycle = lifecycle

    def issue(
        self,
        principal: AuthenticatedPrincipal,
        *,
        subject_type: CredentialSubjectType,
        owner_id: OwnerId,
        agent_id: AgentId | None,
        scopes: tuple[CredentialScope, ...],
        now: datetime,
        lifetime: timedelta,
    ) -> IssuedCredential:
        self._authorize(principal, owner_id)
        return self.lifecycle.issue(
            subject_type=subject_type,
            owner_id=owner_id,
            agent_id=agent_id,
            scopes=scopes,
            now=now,
            lifetime=lifetime,
            actor_kind=AuditActorKind.OWNER,
            actor_id=principal.owner_id.value,
        )

    def revoke(
        self,
        principal: AuthenticatedPrincipal,
        credential_id: CredentialId,
        *,
        now: datetime,
        reason: CredentialRevocationReason,
    ) -> Credential:
        target = self.lifecycle.credentials.get(credential_id)
        if target is None:
            raise InvalidCredentialError("Invalid credential")
        self._authorize(principal, target.owner_id)
        return self.lifecycle.revoke(
            credential_id,
            now=now,
            reason=reason,
            actor_kind=AuditActorKind.OWNER,
            actor_id=principal.owner_id.value,
        )

    def rotate(
        self,
        principal: AuthenticatedPrincipal,
        credential_id: CredentialId,
        *,
        now: datetime,
        lifetime: timedelta,
    ) -> IssuedCredential:
        target = self.lifecycle.credentials.get(credential_id)
        if target is None:
            raise InvalidCredentialError("Invalid credential")
        self._authorize(principal, target.owner_id)
        return self.lifecycle.rotate(
            credential_id,
            now=now,
            lifetime=lifetime,
            actor_kind=AuditActorKind.OWNER,
            actor_id=principal.owner_id.value,
        )

    @staticmethod
    def _authorize(
        principal: AuthenticatedPrincipal, target_owner_id: OwnerId
    ) -> None:
        if not isinstance(principal, AuthenticatedPrincipal):
            raise TypeError("principal must be AuthenticatedPrincipal")
        if (
            principal.subject_type is not CredentialSubjectType.OWNER
            or CredentialScope.CREDENTIALS_MANAGE not in principal.scopes
            or principal.owner_id != target_owner_id
        ):
            raise CredentialPolicyError("Credential management is not permitted")
