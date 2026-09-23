"""Application commands for bounded central Artifact ingestion."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.idempotency import IdempotencyKey
from tas.domain.identity import AgentId, DomainValidationError


MAX_ARTIFACT_BYTES = 10 * 1024 * 1024
MAX_TASK_ARTIFACT_BYTES = 50 * 1024 * 1024
MAX_OWNER_ARTIFACT_BYTES = 4 * 1024 * 1024 * 1024
MAX_OWNER_ARTIFACT_COUNT = 50_000


class ArtifactUploadStatus(StrEnum):
    RESERVED = "reserved"
    UPLOADED = "uploaded"
    FINALIZED = "finalized"


class ArtifactSecurityStatus(StrEnum):
    PENDING = "pending"
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SECRET_DETECTED = "secret_detected"
    UNSUPPORTED = "unsupported"
    SCAN_FAILED = "scan_failed"
    REDACTED = "redacted"


class ArtifactAvailabilityStatus(StrEnum):
    QUARANTINED = "quarantined"
    AVAILABLE = "available"


class ArtifactCleanupStatus(StrEnum):
    ACTIVE = "active"
    PENDING = "pending"
    PURGED = "purged"


class ArtifactRetentionClass(StrEnum):
    PENDING = "pending"
    AVAILABLE = "available"
    QUARANTINE = "quarantine"


class ArtifactPurpose(StrEnum):
    TEST_STDOUT = "test_stdout"
    TEST_STDERR = "test_stderr"
    GIT_DIFF = "git_diff"
    RESULT = "result"
    OTHER = "other"


ALLOWED_ARTIFACT_MEDIA_TYPES = frozenset(
    {"application/json", "application/octet-stream", "text/plain"}
)
SCANNABLE_ARTIFACT_MEDIA_TYPES = frozenset({"application/json", "text/plain"})
ARTIFACT_SCANNER_VERSION = "registered-secret-v1"


@dataclass(frozen=True, slots=True)
class ArtifactScanResult:
    status: ArtifactSecurityStatus
    redacted_content: bytes | None = None
    redaction_count: int = 0

    def __post_init__(self) -> None:
        if self.status not in {
            ArtifactSecurityStatus.CLEAN,
            ArtifactSecurityStatus.SECRET_DETECTED,
            ArtifactSecurityStatus.UNSUPPORTED,
        }:
            raise DomainValidationError("scanner returned an invalid terminal status")
        if self.status is ArtifactSecurityStatus.SECRET_DETECTED:
            if self.redacted_content is None or self.redaction_count < 1:
                raise DomainValidationError("Secret detection requires redacted content")
        elif self.redacted_content is not None or self.redaction_count != 0:
            raise DomainValidationError("non-secret scan cannot return redacted content")


class ArtifactScanner(Protocol):
    version: str

    def scan(self, content: bytes, media_type: str) -> ArtifactScanResult: ...


class RegisteredSecretScanner:
    """Exact-value scanner for bounded Secrets registered at process assembly."""

    version = ARTIFACT_SCANNER_VERSION

    def __init__(self, secrets: tuple[bytes, ...] = ()) -> None:
        if not isinstance(secrets, tuple) or any(
            not isinstance(secret, bytes) or not 8 <= len(secret) <= 4096
            for secret in secrets
        ):
            raise DomainValidationError("registered Secrets must be 8..4096 bytes")
        self._secrets = tuple(sorted(set(secrets), key=lambda item: (-len(item), item)))

    def scan(self, content: bytes, media_type: str) -> ArtifactScanResult:
        if not isinstance(content, bytes) or len(content) > MAX_ARTIFACT_BYTES:
            raise DomainValidationError("scanner content is invalid")
        if media_type not in SCANNABLE_ARTIFACT_MEDIA_TYPES:
            return ArtifactScanResult(ArtifactSecurityStatus.UNSUPPORTED)
        redacted = content
        count = 0
        for secret in self._secrets:
            occurrences = redacted.count(secret)
            if occurrences:
                redacted = redacted.replace(secret, b"*" * len(secret))
                count += occurrences
        if count:
            return ArtifactScanResult(
                ArtifactSecurityStatus.SECRET_DETECTED, redacted, count
            )
        return ArtifactScanResult(ArtifactSecurityStatus.CLEAN)


def _sha256(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DomainValidationError("sha256 must be lowercase hexadecimal")


def _utc(value: datetime, field: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != timedelta(0)
    ):
        raise DomainValidationError(f"{field} must use UTC")


@dataclass(frozen=True, slots=True)
class ReserveArtifactCommand:
    task_id: TaskId
    media_type: str
    declared_size: int
    declared_sha256: str
    purpose: ArtifactPurpose

    def __post_init__(self) -> None:
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if self.media_type not in ALLOWED_ARTIFACT_MEDIA_TYPES:
            raise DomainValidationError("media_type is unsupported")
        if (
            not isinstance(self.declared_size, int)
            or isinstance(self.declared_size, bool)
            or not 0 <= self.declared_size <= MAX_ARTIFACT_BYTES
        ):
            raise DomainValidationError("declared_size exceeds the Artifact limit")
        _sha256(self.declared_sha256)
        if not isinstance(self.purpose, ArtifactPurpose):
            raise TypeError("purpose must be ArtifactPurpose")


@dataclass(frozen=True, slots=True)
class ArtifactUpload:
    id: ArtifactId
    task_id: TaskId
    producer_agent_id: AgentId
    media_type: str
    purpose: ArtifactPurpose
    declared_size: int
    declared_sha256: str
    status: ArtifactUploadStatus
    actual_size: int | None
    actual_sha256: str | None
    created_at: datetime
    uploaded_at: datetime | None
    finalized_at: datetime | None
    security_status: ArtifactSecurityStatus = ArtifactSecurityStatus.PENDING
    availability_status: ArtifactAvailabilityStatus = (
        ArtifactAvailabilityStatus.QUARANTINED
    )
    scanner_version: str | None = None
    scanned_at: datetime | None = None
    redaction_count: int = 0
    retention_class: ArtifactRetentionClass = ArtifactRetentionClass.PENDING
    expires_at: datetime | None = None
    cleanup_status: ArtifactCleanupStatus = ArtifactCleanupStatus.ACTIVE
    source_artifact_id: ArtifactId | None = None
    derived_artifact_id: ArtifactId | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, ArtifactId):
            raise TypeError("id must be ArtifactId")
        if not isinstance(self.task_id, TaskId):
            raise TypeError("task_id must be TaskId")
        if not isinstance(self.producer_agent_id, AgentId):
            raise TypeError("producer_agent_id must be AgentId")
        if self.media_type not in ALLOWED_ARTIFACT_MEDIA_TYPES:
            raise DomainValidationError("media_type is unsupported")
        if not isinstance(self.purpose, ArtifactPurpose):
            raise TypeError("purpose must be ArtifactPurpose")
        if not isinstance(self.status, ArtifactUploadStatus):
            raise TypeError("status must be ArtifactUploadStatus")
        if not isinstance(self.security_status, ArtifactSecurityStatus):
            raise TypeError("security_status must be ArtifactSecurityStatus")
        if not isinstance(self.availability_status, ArtifactAvailabilityStatus):
            raise TypeError("availability_status must be ArtifactAvailabilityStatus")
        if not isinstance(self.retention_class, ArtifactRetentionClass):
            raise TypeError("retention_class must be ArtifactRetentionClass")
        if not isinstance(self.cleanup_status, ArtifactCleanupStatus):
            raise TypeError("cleanup_status must be ArtifactCleanupStatus")
        _utc(self.created_at, "created_at")
        _utc(self.expires_at, "expires_at")
        if self.expires_at <= self.created_at:
            raise DomainValidationError("Artifact expiry must follow creation")
        if self.status is ArtifactUploadStatus.FINALIZED:
            expected_retention = (
                ArtifactRetentionClass.AVAILABLE
                if self.availability_status is ArtifactAvailabilityStatus.AVAILABLE
                else ArtifactRetentionClass.QUARANTINE
            )
            if self.retention_class is not expected_retention:
                raise DomainValidationError("Artifact retention contradicts availability")
        elif self.retention_class is not ArtifactRetentionClass.PENDING:
            raise DomainValidationError("Unfinalized Artifact requires pending retention")
        if (
            not isinstance(self.declared_size, int)
            or isinstance(self.declared_size, bool)
            or not 0 <= self.declared_size <= MAX_ARTIFACT_BYTES
        ):
            raise DomainValidationError("declared_size exceeds the Artifact limit")
        _sha256(self.declared_sha256)
        if self.status is ArtifactUploadStatus.RESERVED:
            if any(
                value is not None
                for value in (
                    self.actual_size,
                    self.actual_sha256,
                    self.uploaded_at,
                    self.finalized_at,
                )
            ):
                raise DomainValidationError("reserved Artifact has upload state")
        else:
            if not isinstance(self.actual_size, int) or isinstance(
                self.actual_size, bool
            ):
                raise DomainValidationError("Artifact actual_size must be an integer")
            if self.actual_size != self.declared_size:
                raise DomainValidationError("Artifact size does not match reservation")
            if self.actual_sha256 != self.declared_sha256:
                raise DomainValidationError("Artifact digest does not match reservation")
            if self.uploaded_at is None:
                raise DomainValidationError("uploaded Artifact requires uploaded_at")
            _utc(self.uploaded_at, "uploaded_at")
            if self.status is ArtifactUploadStatus.FINALIZED:
                if self.finalized_at is None:
                    raise DomainValidationError("finalized Artifact requires finalized_at")
                _utc(self.finalized_at, "finalized_at")
            elif self.finalized_at is not None:
                raise DomainValidationError("uploaded Artifact cannot be finalized")
        if (
            not isinstance(self.redaction_count, int)
            or isinstance(self.redaction_count, bool)
            or self.redaction_count < 0
        ):
            raise DomainValidationError("redaction_count must be a non-negative integer")
        unresolved = self.security_status in {
            ArtifactSecurityStatus.PENDING,
            ArtifactSecurityStatus.UNKNOWN,
        }
        available = self.security_status in {
            ArtifactSecurityStatus.CLEAN,
            ArtifactSecurityStatus.REDACTED,
        }
        if unresolved:
            if (
                self.availability_status is not ArtifactAvailabilityStatus.QUARANTINED
                or self.scanner_version is not None
                or self.scanned_at is not None
                or self.redaction_count != 0
            ):
                raise DomainValidationError("unscanned Artifact must remain quarantined")
        else:
            if not self.scanner_version or self.scanned_at is None:
                raise DomainValidationError("scanned Artifact requires scanner metadata")
            _utc(self.scanned_at, "scanned_at")
            expected = (
                ArtifactAvailabilityStatus.AVAILABLE
                if available
                else ArtifactAvailabilityStatus.QUARANTINED
            )
            if self.availability_status is not expected:
                raise DomainValidationError("Artifact availability contradicts scan status")
        if self.security_status is ArtifactSecurityStatus.REDACTED:
            if self.redaction_count < 1 or self.source_artifact_id is None:
                raise DomainValidationError("redacted Artifact requires its source")
        elif self.source_artifact_id is not None:
            raise DomainValidationError("only redacted Artifacts have a source")
        if self.security_status is ArtifactSecurityStatus.SECRET_DETECTED:
            if self.redaction_count < 1 or self.derived_artifact_id is None:
                raise DomainValidationError("Secret-bearing Artifact requires redacted output")
        elif self.derived_artifact_id is not None:
            raise DomainValidationError("only Secret-bearing Artifacts have a derivative")


@dataclass(frozen=True, slots=True)
class ArtifactCommandResult:
    artifact: ArtifactUpload
    replayed: bool


class ArtifactUploadUnitOfWork(Protocol):
    def reserve(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        command: ReserveArtifactCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def upload(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        staged_path: Path,
        actual_size: int,
        actual_sha256: str,
        content_sha256: str,
        media_type: str,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def finalize(
        self,
        actor_id: AgentId,
        key: IdempotencyKey,
        artifact_id: ArtifactId,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ArtifactCommandResult: ...

    def record_rejection(
        self,
        actor_id: AgentId,
        artifact_id: ArtifactId,
        *,
        reason: str,
        now: datetime,
        correlation_id: str,
    ) -> None: ...


class ArtifactUploadService:
    def __init__(self, unit_of_work: ArtifactUploadUnitOfWork) -> None:
        self.unit_of_work = unit_of_work

    def reserve(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.reserve(*args, **kwargs)

    def upload(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.upload(*args, **kwargs)

    def finalize(self, *args, **kwargs) -> ArtifactCommandResult:
        return self.unit_of_work.finalize(*args, **kwargs)

    def record_rejection(self, *args, **kwargs) -> None:
        self.unit_of_work.record_rejection(*args, **kwargs)
