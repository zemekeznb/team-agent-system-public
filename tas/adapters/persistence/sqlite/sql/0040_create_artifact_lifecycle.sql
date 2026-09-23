CREATE TABLE tas_artifact_lifecycle (
    artifact_id TEXT PRIMARY KEY REFERENCES tas_artifact_uploads(id) ON DELETE RESTRICT,
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    retention_class TEXT NOT NULL CHECK (retention_class IN ('pending','available','quarantine')),
    expires_at TEXT NOT NULL CHECK (substr(expires_at,-6)='+00:00'),
    cleanup_status TEXT NOT NULL CHECK (cleanup_status IN ('active','pending','purged')),
    charged_bytes INTEGER NOT NULL CHECK (charged_bytes >= 0),
    cleanup_requested_at TEXT CHECK (cleanup_requested_at IS NULL OR substr(cleanup_requested_at,-6)='+00:00'),
    purged_at TEXT CHECK (purged_at IS NULL OR substr(purged_at,-6)='+00:00'),
    CHECK (
        (cleanup_status='active' AND cleanup_requested_at IS NULL AND purged_at IS NULL)
        OR (cleanup_status='pending' AND cleanup_requested_at IS NOT NULL AND purged_at IS NULL)
        OR (cleanup_status='purged' AND cleanup_requested_at IS NOT NULL AND purged_at IS NOT NULL AND charged_bytes=0)
    )
);

INSERT INTO tas_artifact_lifecycle
    (artifact_id,owner_id,retention_class,expires_at,cleanup_status,charged_bytes)
SELECT upload.id,agent.owner_id,
    CASE WHEN upload.status<>'finalized' THEN 'pending'
         WHEN security.availability_status='available' THEN 'available'
         ELSE 'quarantine' END,
    CASE WHEN upload.status='finalized' AND security.scan_status='unknown'
         THEN strftime('%Y-%m-%dT%H:%M:%S+00:00','now','+7 days')
         ELSE strftime('%Y-%m-%dT%H:%M:%S+00:00',upload.created_at,
             CASE WHEN upload.status<>'finalized' THEN '+1 day'
                  WHEN security.availability_status='available' THEN '+90 days'
                  ELSE '+7 days' END) END,
    'active',
    CASE WHEN upload.status<>'finalized' AND upload.media_type IN ('text/plain','application/json')
         THEN upload.declared_size*2 ELSE upload.declared_size END
FROM tas_artifact_uploads upload
JOIN tas_agents agent ON agent.id=upload.producer_agent_id
JOIN tas_artifact_security security ON security.artifact_id=upload.id;

CREATE INDEX idx_tas_artifact_lifecycle_owner
ON tas_artifact_lifecycle(owner_id,cleanup_status,artifact_id);
CREATE INDEX idx_tas_artifact_lifecycle_expiry
ON tas_artifact_lifecycle(cleanup_status,expires_at,artifact_id);

CREATE TRIGGER tas_artifact_lifecycle_after_insert
AFTER INSERT ON tas_artifact_uploads
BEGIN
    INSERT INTO tas_artifact_lifecycle
        (artifact_id,owner_id,retention_class,expires_at,cleanup_status,charged_bytes)
    SELECT NEW.id,agent.owner_id,
        CASE WHEN NEW.status='finalized' THEN 'available' ELSE 'pending' END,
        strftime('%Y-%m-%dT%H:%M:%S+00:00',NEW.created_at,
            CASE WHEN NEW.status='finalized' THEN '+90 days' ELSE '+1 day' END),
        'active',
        CASE WHEN NEW.status<>'finalized' AND NEW.media_type IN ('text/plain','application/json')
             THEN NEW.declared_size*2 ELSE NEW.declared_size END
    FROM tas_agents agent WHERE agent.id=NEW.producer_agent_id;
END;

CREATE TRIGGER tas_artifact_lifecycle_update_guard
BEFORE UPDATE ON tas_artifact_lifecycle
BEGIN
    SELECT CASE WHEN NEW.artifact_id<>OLD.artifact_id OR NEW.owner_id<>OLD.owner_id
    THEN RAISE(ABORT,'Artifact lifecycle identity is immutable') END;
    SELECT CASE WHEN NOT (
        (OLD.cleanup_status='active' AND NEW.cleanup_status='active'
         AND OLD.retention_class='pending'
         AND NEW.retention_class IN ('available','quarantine')
         AND NEW.charged_bytes=(SELECT declared_size FROM tas_artifact_uploads WHERE id=OLD.artifact_id)
         AND (SELECT status FROM tas_artifact_uploads WHERE id=OLD.artifact_id)='finalized'
         AND NEW.retention_class=(
             SELECT CASE WHEN availability_status='available' THEN 'available'
                         ELSE 'quarantine' END
             FROM tas_artifact_security WHERE artifact_id=OLD.artifact_id)
         AND abs(julianday(NEW.expires_at)-(
             SELECT julianday(scanned_at) +
                    CASE WHEN availability_status='available' THEN 90 ELSE 7 END
             FROM tas_artifact_security WHERE artifact_id=OLD.artifact_id
         )) < 0.0000001
         AND NEW.cleanup_requested_at IS NULL AND NEW.purged_at IS NULL)
        OR (OLD.cleanup_status='active' AND NEW.cleanup_status='pending'
         AND NEW.retention_class=OLD.retention_class AND NEW.expires_at=OLD.expires_at
         AND NEW.charged_bytes=OLD.charged_bytes AND NEW.purged_at IS NULL
         AND julianday(NEW.cleanup_requested_at)>=julianday(OLD.expires_at)
         AND NOT EXISTS (SELECT 1 FROM tas_evidence_submission_artifacts
                         WHERE artifact_id=OLD.artifact_id))
        OR (OLD.cleanup_status='pending' AND NEW.cleanup_status='purged'
         AND NEW.retention_class=OLD.retention_class AND NEW.expires_at=OLD.expires_at
         AND NEW.cleanup_requested_at=OLD.cleanup_requested_at
         AND NEW.charged_bytes=0 AND NEW.purged_at IS NOT NULL)
    ) THEN RAISE(ABORT,'Artifact lifecycle transition is invalid') END;
END;

CREATE TRIGGER tas_artifact_lifecycle_no_delete
BEFORE DELETE ON tas_artifact_lifecycle
BEGIN SELECT RAISE(ABORT,'Artifact lifecycle is retained'); END;

DROP TRIGGER tas_artifact_uploads_insert_guard;
CREATE TRIGGER tas_artifact_uploads_insert_guard
BEFORE INSERT ON tas_artifact_uploads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_tasks task
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents producer ON producer.id=NEW.producer_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=producer.owner_id
        WHERE task.id=NEW.task_id AND task.assignee_agent_id=NEW.producer_agent_id
    ) THEN RAISE(ABORT,'Artifact producer is not authorized for Task') END;
    SELECT CASE WHEN (
        SELECT count(*) FROM tas_artifact_uploads upload
        JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id
        WHERE upload.task_id=NEW.task_id AND life.cleanup_status<>'purged'
    )>=1000 THEN RAISE(ABORT,'Artifact Task count quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(life.charged_bytes),0) FROM tas_artifact_uploads upload
        JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id
        WHERE upload.task_id=NEW.task_id AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized' AND NEW.media_type IN ('text/plain','application/json')
             THEN NEW.declared_size*2 ELSE NEW.declared_size END > 52428800
    THEN RAISE(ABORT,'Artifact Task byte quota exceeded') END;
    SELECT CASE WHEN (
        SELECT count(*) FROM tas_artifact_lifecycle life
        WHERE life.owner_id=(SELECT owner_id FROM tas_agents WHERE id=NEW.producer_agent_id)
          AND life.cleanup_status<>'purged'
    )>=50000 THEN RAISE(ABORT,'Artifact Owner count quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(charged_bytes),0) FROM tas_artifact_lifecycle life
        WHERE life.owner_id=(SELECT owner_id FROM tas_agents WHERE id=NEW.producer_agent_id)
          AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized' AND NEW.media_type IN ('text/plain','application/json')
    THEN NEW.declared_size*2 ELSE NEW.declared_size END > 4294967296
    THEN RAISE(ABORT,'Artifact Owner byte quota exceeded') END;
END;

DROP TRIGGER tas_evidence_artifact_security_guard;
CREATE TRIGGER tas_evidence_artifact_security_guard
BEFORE INSERT ON tas_evidence_submission_artifacts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_artifact_security security
        JOIN tas_artifact_lifecycle life ON life.artifact_id=security.artifact_id
        JOIN tas_artifact_uploads upload ON upload.id=security.artifact_id
        JOIN tas_agents producer ON producer.id=upload.producer_agent_id
        WHERE security.artifact_id=NEW.artifact_id
          AND security.availability_status='available'
          AND security.scan_status IN ('clean','redacted')
          AND life.cleanup_status='active'
          AND life.owner_id=producer.owner_id
    ) THEN RAISE(ABORT,'Evidence Artifact is unavailable') END;
END;
