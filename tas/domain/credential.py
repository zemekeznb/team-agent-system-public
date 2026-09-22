"""Credential lifecycle values independent of HTTP and persistence adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

from .identity import AgentId, DomainValidationError, OwnerId


class CredentialTokenError(ValueError):
    """Raised for malformed Credential material without echoing it."""


class CredentialKeyUnavailableError(RuntimeError):
    """Raised when a stored digest refers to an unavailable server key."""


def _text(value: str, field: str, maximum: int = 255) -> None:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise DomainValidationError(
            f"{field} must be 1..{maximum} non-whitespace characters"
        )


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class CredentialId:
    value: str

    def __post_init__(self) -> None:
        _text(self.value, "CredentialId", 128)


class CredentialSubjectType(StrEnum):
    OWNER = "owner"
    AGENT = "agent"


class CredentialStatus(StrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CredentialScope(StrEnum):
    SESSION_READ = "session:read"
    CREDENTIALS_MANAGE = "credentials:manage"
    EVENTS_READ = "events:read"
    EVENTS_WRITE = "events:write"
    TASKS_READ = "tasks:read"
    TASKS_WRITE = "tasks:write"
    INBOX_READ = "inbox:read"
    INBOX_CLAIM = "inbox:claim"
    APPROVALS_READ = "approvals:read"
    APPROVALS_REQUEST = "approvals:request"
    APPROVALS_DECIDE = "approvals:decide"
    ACTIONS_EXECUTE = "actions:execute"
    EVIDENCE_READ = "evidence:read"
    EVIDENCE_WRITE = "evidence:write"
    ARTIFACTS_READ = "artifacts:read"
    ARTIFACTS_WRITE = "artifacts:write"
    WORK_RECORDS_READ = "work_records:read"
    WORK_RECORDS_WRITE = "work_records:write"
    MEMORIES_READ = "memories:read"
    MEMORIES_WRITE = "memories:write"
    POLICIES_READ = "policies:read"
    POLICIES_WRITE = "policies:write"
    AUDITS_READ = "audits:read"


OWNER_ONLY_CREDENTIAL_SCOPES = frozenset(
    {
        CredentialScope.CREDENTIALS_MANAGE,
        CredentialScope.APPROVALS_DECIDE,
        CredentialScope.POLICIES_WRITE,
        CredentialScope.AUDITS_READ,
    }
)


class CredentialIdentitySource(StrEnum):
    LOCAL_FIXTURE = "local_fixture"
    OUT_OF_BAND_REGISTRATION = "out_of_band_registration"


class CredentialAssuranceLevel(StrEnum):
    TEST_ONLY = "test_only"
    REGISTERED = "registered"


class CredentialRevocationReason(StrEnum):
    MANUAL = "manual"
    ROTATED = "rotated"
    COMPROMISED = "compromised"
    OWNER_REMOVED = "owner_removed"
    BINDING_INVALID = "binding_invalid"


class CredentialAuditReason(StrEnum):
    ISSUED = "credential_issued"
    REVOKED_MANUAL = "credential_revoked_manual"
    REVOKED_COMPROMISED = "credential_revoked_compromised"
    REVOKED_OWNER_REMOVED = "credential_revoked_owner_removed"
    REVOKED_BINDING_INVALID = "credential_revoked_binding_invalid"
    ROTATED = "credential_rotated"
    MALFORMED = "malformed"
    UNKNOWN = "unknown"
    INVALID_SECRET = "invalid_secret"
    EXPIRED = "expired"
    REVOKED_CREDENTIAL = "revoked"
    SCOPE_INSUFFICIENT = "scope_insufficient"
    BINDING_INVALID = "binding_invalid"
    KEY_UNAVAILABLE = "key_unavailable"


@dataclass(frozen=True, slots=True)
class Credential:
    id: CredentialId
    subject_type: CredentialSubjectType
    owner_id: OwnerId
    agent_id: AgentId | None
    scopes: tuple[CredentialScope, ...]
    issued_at: datetime
    expires_at: datetime
    status: CredentialStatus
    identity_source: CredentialIdentitySource
    assurance_level: CredentialAssuranceLevel
    is_test_fixture: bool
    issued_by: str
    revoked_at: datetime | None = None
    revocation_reason: CredentialRevocationReason | None = None
    rotated_from_id: CredentialId | None = None
    replaced_by_id: CredentialId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, CredentialId):
            raise TypeError("id must be CredentialId")
        if not isinstance(self.subject_type, CredentialSubjectType):
            raise TypeError("subject_type must be CredentialSubjectType")
        if not isinstance(self.owner_id, OwnerId):
            raise TypeError("owner_id must be OwnerId")
        if self.agent_id is not None and not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId or None")
        if self.subject_type is CredentialSubjectType.AGENT and self.agent_id is None:
            raise DomainValidationError("Agent Credential requires agent_id")
        if self.subject_type is CredentialSubjectType.OWNER and self.agent_id is not None:
            raise DomainValidationError("Owner Credential cannot bind agent_id")
        if (
            not isinstance(self.scopes, tuple)
            or not self.scopes
            or len(self.scopes) > 64
            or not all(isinstance(item, CredentialScope) for item in self.scopes)
            or tuple(sorted(set(self.scopes), key=lambda item: item.value)) != self.scopes
        ):
            raise DomainValidationError("scopes must be a sorted unique non-empty tuple")
        if (
            self.subject_type is CredentialSubjectType.AGENT
            and OWNER_ONLY_CREDENTIAL_SCOPES.intersection(self.scopes)
        ):
            raise DomainValidationError("Agent Credential cannot contain Owner-only scopes")
        _utc(self.issued_at, "issued_at")
        _utc(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise DomainValidationError("expires_at must follow issued_at")
        if not isinstance(self.status, CredentialStatus):
            raise TypeError("status must be CredentialStatus")
        if self.revocation_reason is not None and not isinstance(
            self.revocation_reason, CredentialRevocationReason
        ):
            raise TypeError("revocation_reason must be CredentialRevocationReason or None")
        if self.status is CredentialStatus.EXPIRED:
            raise DomainValidationError("expired is derived from expires_at, not stored")
        if not isinstance(self.identity_source, CredentialIdentitySource):
            raise TypeError("identity_source must be CredentialIdentitySource")
        if not isinstance(self.assurance_level, CredentialAssuranceLevel):
            raise TypeError("assurance_level must be CredentialAssuranceLevel")
        if not isinstance(self.is_test_fixture, bool):
            raise TypeError("is_test_fixture must be bool")
        fixture = (
            self.identity_source is CredentialIdentitySource.LOCAL_FIXTURE
            and self.assurance_level is CredentialAssuranceLevel.TEST_ONLY
            and self.is_test_fixture
        )
        registered = (
            self.identity_source is CredentialIdentitySource.OUT_OF_BAND_REGISTRATION
            and self.assurance_level is CredentialAssuranceLevel.REGISTERED
            and not self.is_test_fixture
        )
        if not (fixture or registered):
            raise DomainValidationError("identity source, assurance, and fixture flag conflict")
        _text(self.issued_by, "issued_by")
        for value, field in (
            (self.revoked_at, "revoked_at"),
        ):
            if value is not None:
                _utc(value, field)
        if self.status is CredentialStatus.ACTIVE:
            if any(
                value is not None
                for value in (self.revoked_at, self.revocation_reason, self.replaced_by_id)
            ):
                raise DomainValidationError("active Credential cannot contain revocation state")
        else:
            if self.revoked_at is None or self.revocation_reason is None:
                raise DomainValidationError("revoked Credential requires reason and time")
            if self.revoked_at < self.issued_at:
                raise DomainValidationError("revoked_at cannot precede issued_at")
            if (
                self.revocation_reason is CredentialRevocationReason.ROTATED
                and self.replaced_by_id is None
            ):
                raise DomainValidationError("rotated Credential requires replacement")
            if (
                self.revocation_reason is not CredentialRevocationReason.ROTATED
                and self.replaced_by_id is not None
            ):
                raise DomainValidationError("only rotation can identify a replacement")
        for value, field in (
            (self.rotated_from_id, "rotated_from_id"),
            (self.replaced_by_id, "replaced_by_id"),
        ):
            if value is not None and not isinstance(value, CredentialId):
                raise TypeError(f"{field} must be CredentialId or None")
            if value == self.id:
                raise DomainValidationError("Credential rotation cannot reference itself")

    def effective_status(self, now: datetime) -> CredentialStatus:
        _utc(now, "now")
        if self.status is CredentialStatus.REVOKED:
            return CredentialStatus.REVOKED
        if now >= self.expires_at:
            return CredentialStatus.EXPIRED
        return CredentialStatus.ACTIVE


@dataclass(frozen=True, slots=True)
class CredentialAuthenticationRecord:
    credential: Credential
    secret_digest: str
    secret_key_id: str
    binding_valid: bool

    def __post_init__(self) -> None:
        if not isinstance(self.credential, Credential):
            raise TypeError("credential must be Credential")
        if (
            not isinstance(self.secret_digest, str)
            or len(self.secret_digest) != 64
            or any(character not in "0123456789abcdef" for character in self.secret_digest)
        ):
            raise DomainValidationError("secret_digest must be lowercase SHA-256")
        _text(self.secret_key_id, "secret_key_id", 64)
        if not isinstance(self.binding_valid, bool):
            raise TypeError("binding_valid must be bool")


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    credential_id: CredentialId
    subject_type: CredentialSubjectType
    owner_id: OwnerId
    agent_id: AgentId | None
    scopes: tuple[CredentialScope, ...]
    identity_source: CredentialIdentitySource
    assurance_level: CredentialAssuranceLevel
    is_test_fixture: bool
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, CredentialId):
            raise TypeError("credential_id must be CredentialId")
        if not isinstance(self.subject_type, CredentialSubjectType):
            raise TypeError("subject_type must be CredentialSubjectType")
        if not isinstance(self.owner_id, OwnerId):
            raise TypeError("owner_id must be OwnerId")
        if self.agent_id is not None and not isinstance(self.agent_id, AgentId):
            raise TypeError("agent_id must be AgentId or None")
        if self.subject_type is CredentialSubjectType.AGENT and self.agent_id is None:
            raise DomainValidationError("Agent Principal requires agent_id")
        if self.subject_type is CredentialSubjectType.OWNER and self.agent_id is not None:
            raise DomainValidationError("Owner Principal cannot bind agent_id")
        if not self.scopes or not all(isinstance(item, CredentialScope) for item in self.scopes):
            raise DomainValidationError("Principal scopes must be non-empty")
        if (
            self.subject_type is CredentialSubjectType.AGENT
            and OWNER_ONLY_CREDENTIAL_SCOPES.intersection(self.scopes)
        ):
            raise DomainValidationError("Agent Principal cannot contain Owner-only scopes")
        if not isinstance(self.identity_source, CredentialIdentitySource):
            raise TypeError("identity_source must be CredentialIdentitySource")
        if not isinstance(self.assurance_level, CredentialAssuranceLevel):
            raise TypeError("assurance_level must be CredentialAssuranceLevel")
        if not isinstance(self.is_test_fixture, bool):
            raise TypeError("is_test_fixture must be bool")
        _utc(self.expires_at, "expires_at")


@dataclass(frozen=True, slots=True)
class IssuedCredential:
    credential: Credential
    token: str

    def __post_init__(self) -> None:
        if not isinstance(self.credential, Credential):
            raise TypeError("credential must be Credential")
        _text(self.token, "token", 512)
