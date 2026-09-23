"""Shared, positional SQLite projection for Artifact metadata."""

from datetime import datetime

from tas.application.artifact_uploads import (
    ArtifactAvailabilityStatus, ArtifactCleanupStatus, ArtifactPurpose,
    ArtifactRetentionClass, ArtifactSecurityStatus, ArtifactUpload,
    ArtifactUploadStatus,
)
from tas.domain.collaboration import ArtifactId, TaskId
from tas.domain.identity import AgentId


ARTIFACT_COLUMNS = (
    "upload.id,upload.task_id,upload.producer_agent_id,upload.media_type,"
    "upload.purpose,upload.declared_size,upload.declared_sha256,upload.status,"
    "upload.actual_size,upload.actual_sha256,upload.created_at,upload.uploaded_at,"
    "upload.finalized_at,security.scan_status,security.availability_status,"
    "security.scanner_version,security.scanned_at,security.redaction_count,"
    "source.source_artifact_id,derived.derived_artifact_id,"
    "life.retention_class,life.expires_at,life.cleanup_status"
)

ARTIFACT_JOINS = (
    "JOIN tas_artifact_security security ON security.artifact_id=upload.id "
    "JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id "
    "LEFT JOIN tas_artifact_derivations source ON source.derived_artifact_id=upload.id "
    "LEFT JOIN tas_artifact_derivations derived ON derived.source_artifact_id=upload.id "
)


def restore_artifact(row) -> ArtifactUpload:
    return ArtifactUpload(
        ArtifactId(str(row[0])), TaskId(str(row[1])), AgentId(str(row[2])),
        str(row[3]), ArtifactPurpose(str(row[4])), int(row[5]), str(row[6]),
        ArtifactUploadStatus(str(row[7])),
        None if row[8] is None else int(row[8]),
        None if row[9] is None else str(row[9]),
        datetime.fromisoformat(str(row[10])),
        None if row[11] is None else datetime.fromisoformat(str(row[11])),
        None if row[12] is None else datetime.fromisoformat(str(row[12])),
        ArtifactSecurityStatus(str(row[13])),
        ArtifactAvailabilityStatus(str(row[14])),
        None if row[15] is None else str(row[15]),
        None if row[16] is None else datetime.fromisoformat(str(row[16])),
        int(row[17]),
        ArtifactRetentionClass(str(row[20])),
        datetime.fromisoformat(str(row[21])),
        ArtifactCleanupStatus(str(row[22])),
        None if row[18] is None else ArtifactId(str(row[18])),
        None if row[19] is None else ArtifactId(str(row[19])),
    )
