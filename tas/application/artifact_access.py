"""Authorized read contracts for finalized Evidence and Artifact resources."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import BinaryIO, Iterator, Protocol

from tas.application.artifact_uploads import ArtifactUpload
from tas.application.evidence_submissions import EvidenceSubmission
from tas.domain.collaboration import ArtifactId
from tas.domain.credential import AuthenticatedPrincipal
from tas.domain.evidence import EvidenceId


ARTIFACT_STREAM_CHUNK_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class EvidenceAccessView:
    evidence: EvidenceSubmission
    payload_json: str

    def __post_init__(self) -> None:
        if not isinstance(self.evidence, EvidenceSubmission):
            raise TypeError("evidence must be EvidenceSubmission")
        if not isinstance(self.payload_json, str) or not self.payload_json:
            raise ValueError("finalized Evidence requires a canonical payload")


@dataclass(slots=True)
class ArtifactDownload:
    artifact: ArtifactUpload
    stream: BinaryIO

    def iter_bytes(self) -> Iterator[bytes]:
        try:
            while chunk := self.stream.read(ARTIFACT_STREAM_CHUNK_BYTES):
                yield chunk
        finally:
            self.stream.close()


class ArtifactEvidenceAccessRepository(Protocol):
    def get_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        *, now: datetime, correlation_id: str,
    ) -> ArtifactUpload | None: ...

    def open_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        *, now: datetime, correlation_id: str,
    ) -> ArtifactDownload | None: ...

    def get_evidence(
        self, principal: AuthenticatedPrincipal, evidence_id: EvidenceId,
        *, now: datetime, correlation_id: str,
    ) -> EvidenceAccessView | None: ...


class ArtifactEvidenceAccessService:
    def __init__(self, repository: ArtifactEvidenceAccessRepository) -> None:
        self.repository = repository

    def get_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        **kwargs,
    ) -> ArtifactUpload | None:
        return self.repository.get_artifact(principal, artifact_id, **kwargs)

    def open_artifact(
        self, principal: AuthenticatedPrincipal, artifact_id: ArtifactId,
        **kwargs,
    ) -> ArtifactDownload | None:
        return self.repository.open_artifact(principal, artifact_id, **kwargs)

    def get_evidence(
        self, principal: AuthenticatedPrincipal, evidence_id: EvidenceId,
        **kwargs,
    ) -> EvidenceAccessView | None:
        return self.repository.get_evidence(principal, evidence_id, **kwargs)
