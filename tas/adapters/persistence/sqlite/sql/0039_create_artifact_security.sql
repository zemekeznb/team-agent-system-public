CREATE TABLE tas_artifact_security (
    artifact_id TEXT PRIMARY KEY REFERENCES tas_artifact_uploads(id)
        ON DELETE RESTRICT,
    scan_status TEXT NOT NULL CHECK (scan_status IN (
        'pending','unknown','clean','secret_detected','unsupported','scan_failed','redacted'
    )),
    availability_status TEXT NOT NULL CHECK (
        availability_status IN ('quarantined','available')
    ),
    scanner_version TEXT,
    scanned_at TEXT CHECK (
        scanned_at IS NULL OR substr(scanned_at,-6)='+00:00'
    ),
    redaction_count INTEGER NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
    CHECK (
        (scan_status IN ('pending','unknown')
            AND availability_status='quarantined'
            AND scanner_version IS NULL AND scanned_at IS NULL
            AND redaction_count=0)
        OR
        (scan_status='clean' AND availability_status='available'
            AND scanner_version IS NOT NULL AND scanned_at IS NOT NULL
            AND redaction_count=0)
        OR
        (scan_status IN ('secret_detected','unsupported','scan_failed')
            AND availability_status='quarantined'
            AND scanner_version IS NOT NULL AND scanned_at IS NOT NULL)
        OR
        (scan_status='redacted' AND availability_status='available'
            AND scanner_version IS NOT NULL AND scanned_at IS NOT NULL
            AND redaction_count > 0)
    )
);

INSERT INTO tas_artifact_security(
    artifact_id,scan_status,availability_status,scanner_version,scanned_at,
    redaction_count
)
SELECT id,
       CASE WHEN status='finalized' THEN 'unknown' ELSE 'pending' END,
       'quarantined',NULL,NULL,0
FROM tas_artifact_uploads;

CREATE TRIGGER tas_artifact_security_after_artifact_insert
AFTER INSERT ON tas_artifact_uploads
BEGIN
    INSERT INTO tas_artifact_security(
        artifact_id,scan_status,availability_status,scanner_version,scanned_at,
        redaction_count
    ) VALUES (NEW.id,'pending','quarantined',NULL,NULL,0);
END;

CREATE TRIGGER tas_artifact_security_update_guard
BEFORE UPDATE ON tas_artifact_security
BEGIN
    SELECT CASE WHEN NEW.artifact_id<>OLD.artifact_id
    THEN RAISE(ABORT, 'Artifact security identity is immutable') END;
    SELECT CASE WHEN OLD.scan_status NOT IN ('pending','unknown')
    THEN RAISE(ABORT, 'Artifact security assessment is immutable') END;
    SELECT CASE WHEN NEW.scan_status IN ('pending','unknown')
    THEN RAISE(ABORT, 'Artifact security assessment cannot remain unresolved') END;
END;

CREATE TRIGGER tas_artifact_security_no_delete
BEFORE DELETE ON tas_artifact_security
BEGIN SELECT RAISE(ABORT, 'Artifact security assessment is append-only'); END;

CREATE TABLE tas_artifact_derivations (
    source_artifact_id TEXT NOT NULL REFERENCES tas_artifact_uploads(id)
        ON DELETE RESTRICT,
    derived_artifact_id TEXT PRIMARY KEY REFERENCES tas_artifact_uploads(id)
        ON DELETE RESTRICT,
    derivation_kind TEXT NOT NULL CHECK (derivation_kind='redacted'),
    redaction_count INTEGER NOT NULL CHECK (redaction_count > 0),
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00'),
    CHECK (source_artifact_id<>derived_artifact_id),
    UNIQUE (source_artifact_id,derivation_kind)
);

CREATE TRIGGER tas_artifact_derivations_insert_guard
BEFORE INSERT ON tas_artifact_derivations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM tas_artifact_uploads source
        JOIN tas_artifact_security source_security
          ON source_security.artifact_id=source.id
        JOIN tas_artifact_uploads derived
          ON derived.id=NEW.derived_artifact_id
        JOIN tas_artifact_security derived_security
          ON derived_security.artifact_id=derived.id
        WHERE source.id=NEW.source_artifact_id
          AND source.status='finalized'
          AND source_security.scan_status='secret_detected'
          AND source_security.availability_status='quarantined'
          AND derived.status='finalized'
          AND derived_security.scan_status='redacted'
          AND derived_security.availability_status='available'
          AND source.task_id=derived.task_id
          AND source.producer_agent_id=derived.producer_agent_id
          AND source.media_type=derived.media_type
          AND source.purpose=derived.purpose
          AND source.declared_sha256<>derived.declared_sha256
          AND NEW.redaction_count=source_security.redaction_count
          AND NEW.redaction_count=derived_security.redaction_count
    ) THEN RAISE(ABORT, 'Artifact redaction derivation is invalid') END;
END;

CREATE TRIGGER tas_artifact_derivations_no_update
BEFORE UPDATE ON tas_artifact_derivations
BEGIN SELECT RAISE(ABORT, 'Artifact derivation is immutable'); END;

CREATE TRIGGER tas_artifact_derivations_no_delete
BEFORE DELETE ON tas_artifact_derivations
BEGIN SELECT RAISE(ABORT, 'Artifact derivation is append-only'); END;

CREATE TRIGGER tas_evidence_artifact_security_guard
BEFORE INSERT ON tas_evidence_submission_artifacts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_artifact_security security
        WHERE security.artifact_id=NEW.artifact_id
          AND security.availability_status='available'
          AND security.scan_status IN ('clean','redacted')
    ) THEN RAISE(ABORT, 'Evidence Artifact is quarantined') END;
END;
