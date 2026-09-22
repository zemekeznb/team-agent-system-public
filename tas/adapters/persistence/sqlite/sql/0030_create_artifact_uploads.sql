CREATE TABLE tas_artifact_uploads (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    producer_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    media_type TEXT NOT NULL CHECK (media_type IN (
        'application/json','application/octet-stream','text/plain'
    )),
    purpose TEXT NOT NULL CHECK (purpose IN (
        'test_stdout','test_stderr','git_diff','result','other'
    )),
    declared_size INTEGER NOT NULL CHECK (declared_size BETWEEN 0 AND 10485760),
    declared_sha256 TEXT NOT NULL CHECK (
        length(declared_sha256)=64 AND declared_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('reserved','uploaded','finalized')),
    actual_size INTEGER,
    actual_sha256 TEXT,
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00'),
    uploaded_at TEXT CHECK (
        uploaded_at IS NULL OR substr(uploaded_at,-6)='+00:00'
    ),
    finalized_at TEXT CHECK (
        finalized_at IS NULL OR substr(finalized_at,-6)='+00:00'
    ),
    CHECK (
        (status='reserved' AND actual_size IS NULL AND actual_sha256 IS NULL
            AND uploaded_at IS NULL AND finalized_at IS NULL)
        OR
        (status='uploaded' AND actual_size=declared_size
            AND actual_sha256=declared_sha256 AND uploaded_at IS NOT NULL
            AND finalized_at IS NULL)
        OR
        (status='finalized' AND actual_size=declared_size
            AND actual_sha256=declared_sha256 AND uploaded_at IS NOT NULL
            AND finalized_at IS NOT NULL)
    )
);

CREATE INDEX idx_tas_artifact_uploads_task
ON tas_artifact_uploads(task_id, status, created_at, id);

CREATE TRIGGER tas_artifact_uploads_insert_guard
BEFORE INSERT ON tas_artifact_uploads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_tasks task
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents producer ON producer.id=NEW.producer_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=producer.owner_id
        WHERE task.id=NEW.task_id
          AND task.assignee_agent_id=NEW.producer_agent_id
    ) THEN RAISE(ABORT, 'Artifact producer is not authorized for Task') END;
    SELECT CASE WHEN (
        SELECT count(*) FROM tas_artifact_uploads WHERE task_id=NEW.task_id
    ) >= 1000 THEN RAISE(ABORT, 'Artifact Task count quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(declared_size),0) FROM tas_artifact_uploads
        WHERE task_id=NEW.task_id
    ) + NEW.declared_size > 52428800
    THEN RAISE(ABORT, 'Artifact Task byte quota exceeded') END;
END;

CREATE TRIGGER tas_artifact_uploads_update_guard
BEFORE UPDATE ON tas_artifact_uploads
BEGIN
    SELECT CASE WHEN
        NEW.id<>OLD.id OR NEW.task_id<>OLD.task_id
        OR NEW.producer_agent_id<>OLD.producer_agent_id
        OR NEW.media_type<>OLD.media_type OR NEW.purpose<>OLD.purpose
        OR NEW.declared_size<>OLD.declared_size
        OR NEW.declared_sha256<>OLD.declared_sha256
        OR NEW.created_at<>OLD.created_at
    THEN RAISE(ABORT, 'Artifact reservation metadata is immutable') END;
    SELECT CASE WHEN NOT (
        (OLD.status='reserved' AND NEW.status='uploaded')
        OR (OLD.status='uploaded' AND NEW.status='finalized')
    ) THEN RAISE(ABORT, 'Artifact upload transition is invalid') END;
END;

CREATE TRIGGER tas_artifact_uploads_no_delete
BEFORE DELETE ON tas_artifact_uploads
BEGIN SELECT RAISE(ABORT, 'Artifact upload metadata is append-only'); END;
