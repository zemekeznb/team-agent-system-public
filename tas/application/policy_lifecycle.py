"""Owner-scoped immutable Policy lifecycle driven by authenticated Principals."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from tas.domain.audit import (
    AuditActorKind, AuditEvent, AuditEventId, AuditEventKind, AuditOutcome,
)
from tas.domain.credential import (
    AuthenticatedPrincipal, CredentialScope, CredentialSubjectType,
)
from tas.domain.identity import OwnerId
from tas.domain.idempotency import IdempotencyKey, RequestFingerprint
from tas.domain.policy import OwnerPolicy, PolicyMutationContext
from tas.domain.ports import PolicyRepository


class PolicyAccessDeniedError(PermissionError):
    """Stable denial for Policy lifecycle access."""


class OwnerPolicyService:
    def __init__(
        self,
        repository: PolicyRepository,
        *,
        audit_id_factory: Callable[[], str] = lambda: str(uuid4()),
    ) -> None:
        self.repository = repository
        self.audit_id_factory = audit_id_factory

    def create(
        self,
        principal: AuthenticatedPrincipal,
        policy: OwnerPolicy,
        *,
        now: datetime,
        correlation_id: str | None = None,
        idempotency_key: IdempotencyKey | None = None,
    ) -> OwnerPolicy:
        self._authorize(principal, policy.owner_id, CredentialScope.POLICIES_WRITE)
        self.repository.add_with_audit(
            policy, now, principal.owner_id.value,
            self._event(
                principal, policy, AuditEventKind.POLICY_VERSION_CREATED,
                AuditOutcome.CREATED, "policy_version_created", now, correlation_id,
            ),
            self._idempotency(principal, "policy.create", idempotency_key, {
                "version": policy.version,
                "rules": [
                    [rule.action.value, rule.outcome.value, int(rule.max_auto_risk)]
                    for rule in policy.rules
                ],
            }),
        )
        return policy

    def get(
        self,
        principal: AuthenticatedPrincipal,
        owner_id: OwnerId,
        version: str,
    ) -> OwnerPolicy | None:
        self._authorize(principal, owner_id, CredentialScope.POLICIES_READ)
        return self.repository.get(owner_id, version)

    def get_current(
        self, principal: AuthenticatedPrincipal, owner_id: OwnerId
    ) -> OwnerPolicy | None:
        self._authorize(principal, owner_id, CredentialScope.POLICIES_READ)
        return self.repository.get_current(owner_id)

    def select_current(
        self,
        principal: AuthenticatedPrincipal,
        owner_id: OwnerId,
        version: str,
        *,
        expected_current_version: str | None,
        now: datetime,
        correlation_id: str | None = None,
        idempotency_key: IdempotencyKey | None = None,
    ) -> OwnerPolicy:
        self._authorize(principal, owner_id, CredentialScope.POLICIES_WRITE)
        return self.repository.select_current_with_audit(
            owner_id, version, expected_current_version,
            self._event_for_version(
                principal, owner_id, version, now, correlation_id
            ),
            self._idempotency(principal, "policy.select", idempotency_key, {
                "version": version,
                "expected_current_version": expected_current_version,
            }),
        )

    @staticmethod
    def _idempotency(
        principal: AuthenticatedPrincipal,
        operation: str,
        key: IdempotencyKey | None,
        payload: object,
    ) -> PolicyMutationContext | None:
        if key is None:
            return None
        canonical = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return PolicyMutationContext(
            principal.owner_id,
            operation,
            key,
            RequestFingerprint(hashlib.sha256(canonical).hexdigest()),
        )

    @staticmethod
    def _authorize(
        principal: AuthenticatedPrincipal,
        owner_id: OwnerId,
        scope: CredentialScope,
    ) -> None:
        if (
            not isinstance(principal, AuthenticatedPrincipal)
            or principal.subject_type is not CredentialSubjectType.OWNER
            or principal.owner_id != owner_id
            or scope not in principal.scopes
        ):
            raise PolicyAccessDeniedError("Policy access is not permitted")

    def _event(
        self,
        principal: AuthenticatedPrincipal,
        policy: OwnerPolicy,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        reason: str,
        now: datetime,
        correlation_id: str | None,
    ) -> AuditEvent:
        return AuditEvent(
            AuditEventId(self.audit_id_factory()), kind, AuditActorKind.OWNER,
            principal.owner_id.value, "owner_policy", principal.owner_id.value,
            kind.value, outcome, reason, now, policy.version, correlation_id,
        )

    def _event_for_version(
        self,
        principal: AuthenticatedPrincipal,
        owner_id: OwnerId,
        version: str,
        now: datetime,
        correlation_id: str | None,
    ) -> AuditEvent:
        policy = OwnerPolicy(owner_id, version, ())
        return self._event(
            principal, policy, AuditEventKind.POLICY_CURRENT_CHANGED,
            AuditOutcome.SELECTED, "policy_current_selected", now, correlation_id,
        )
