"""Authorized, paginated views over security Audit Events."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from tas.application.credentials import AuthenticatedPrincipal
from tas.domain.audit import AuditEvent
from tas.domain.credential import CredentialScope, CredentialSubjectType
from tas.domain.identity import OwnerId


class AuditResourceType(StrEnum):
    CREDENTIAL = "credential"
    OWNER_POLICY = "owner_policy"
    PROJECT = "project"
    TASK = "task"
    INBOX_ITEM = "inbox_item"
    APPROVAL = "approval"
    REPOSITORY = "repository"
    WORK_RECORD = "work_record"
    ARTIFACT = "artifact"
    EVIDENCE = "evidence"


class AuditQueryAccessError(PermissionError):
    """The requested Audit resource is not visible to the principal."""


@dataclass(frozen=True, slots=True)
class AuditEventPage:
    items: tuple[AuditEvent, ...]
    next_cursor: str | None


class AuditQueryRepository(Protocol):
    def list_for_owner(
        self,
        owner_id: OwnerId,
        resource_type: AuditResourceType,
        resource_id: str,
        *,
        cursor: str | None,
        limit: int,
        correlation_id: str,
    ) -> AuditEventPage: ...


class AuditQueryService:
    def __init__(self, repository: AuditQueryRepository) -> None:
        self.repository = repository

    def list_resource(
        self,
        principal: AuthenticatedPrincipal,
        resource_type: AuditResourceType,
        resource_id: str,
        *,
        cursor: str | None,
        limit: int,
        correlation_id: str,
    ) -> AuditEventPage:
        if (
            not isinstance(principal, AuthenticatedPrincipal)
            or principal.subject_type is not CredentialSubjectType.OWNER
            or CredentialScope.AUDITS_READ not in principal.scopes
        ):
            raise AuditQueryAccessError("Audit access is not permitted")
        if not isinstance(resource_type, AuditResourceType):
            raise TypeError("resource_type must be AuditResourceType")
        if not isinstance(resource_id, str) or not resource_id.strip() or len(resource_id) > 255:
            raise ValueError("resource_id must be 1..255 non-whitespace characters")
        if cursor is not None and (
            not isinstance(cursor, str) or not cursor.strip() or len(cursor) > 255
        ):
            raise ValueError("cursor must be 1..255 non-whitespace characters")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        return self.repository.list_for_owner(
            principal.owner_id,
            resource_type,
            resource_id,
            cursor=cursor,
            limit=limit,
            correlation_id=correlation_id,
        )
