CREATE TABLE tas_evidence_submissions (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL REFERENCES tas_task_workspace_bindings(id)
        ON DELETE RESTRICT,
    kind TEXT NOT NULL CHECK (kind IN ('git','command_test')),
    attempt INTEGER NOT NULL CHECK (attempt BETWEEN 1 AND 16),
    retry_of TEXT REFERENCES tas_evidence_submissions(id) ON DELETE RESTRICT,
    observed_at TEXT NOT NULL CHECK (substr(observed_at,-6)='+00:00'),
    head_commit TEXT NOT NULL CHECK (
        length(head_commit) IN (40,64)
        AND head_commit NOT GLOB '*[^0-9a-f]*'
    ),
    status TEXT NOT NULL CHECK (status IN ('reserved','finalized')),
    payload_sha256 TEXT CHECK (
        payload_sha256 IS NULL OR (
            length(payload_sha256)=64
            AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
        )
    ),
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00'),
    finalized_at TEXT CHECK (
        finalized_at IS NULL OR substr(finalized_at,-6)='+00:00'
    ),
    CHECK (
        (kind='git' AND attempt=1 AND retry_of IS NULL)
        OR
        (kind='command_test' AND (
            (attempt=1 AND retry_of IS NULL)
            OR (attempt>1 AND retry_of IS NOT NULL)
        ))
    ),
    CHECK (
        (status='reserved' AND payload_sha256 IS NULL AND finalized_at IS NULL)
        OR
        (status='finalized' AND payload_sha256 IS NOT NULL AND finalized_at IS NOT NULL)
    )
);

CREATE TABLE tas_evidence_submission_artifacts (
    evidence_id TEXT NOT NULL REFERENCES tas_evidence_submissions(id)
        ON DELETE RESTRICT,
    sequence INTEGER NOT NULL CHECK (sequence BETWEEN 1 AND 32),
    artifact_id TEXT NOT NULL REFERENCES tas_artifact_uploads(id)
        ON DELETE RESTRICT,
    PRIMARY KEY (evidence_id,sequence),
    UNIQUE (evidence_id,artifact_id)
);

CREATE INDEX idx_tas_evidence_submissions_scope
ON tas_evidence_submissions(task_id,actor_agent_id,observed_at,id);

CREATE TRIGGER tas_evidence_submissions_insert_guard
BEFORE INSERT ON tas_evidence_submissions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_tasks task
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents actor ON actor.id=NEW.actor_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=actor.owner_id
        JOIN tas_task_workspace_bindings workspace
          ON workspace.id=NEW.workspace_id
         AND workspace.task_id=task.id
         AND workspace.actor_agent_id=actor.id
        WHERE task.id=NEW.task_id AND task.assignee_agent_id=actor.id
    ) THEN RAISE(ABORT, 'Evidence scope is not authorized') END;
    SELECT CASE WHEN NEW.retry_of IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM tas_evidence_submissions prior
        WHERE prior.id=NEW.retry_of AND prior.status='finalized'
          AND prior.task_id=NEW.task_id
          AND prior.actor_agent_id=NEW.actor_agent_id
          AND prior.kind='command_test'
          AND prior.attempt=NEW.attempt-1
    ) THEN RAISE(ABORT, 'Evidence retry chain is invalid') END;
END;

CREATE TRIGGER tas_evidence_submission_artifacts_insert_guard
BEFORE INSERT ON tas_evidence_submission_artifacts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_evidence_submissions evidence
        JOIN tas_artifact_uploads artifact ON artifact.id=NEW.artifact_id
        WHERE evidence.id=NEW.evidence_id
          AND evidence.status='reserved'
          AND artifact.status='finalized'
          AND artifact.task_id=evidence.task_id
          AND artifact.producer_agent_id=evidence.actor_agent_id
          AND (
              (evidence.kind='command_test'
                AND artifact.purpose IN ('test_stdout','test_stderr'))
              OR (evidence.kind='git' AND artifact.purpose='git_diff')
          )
    ) THEN RAISE(ABORT, 'Evidence Artifact is not eligible') END;
END;

CREATE TRIGGER tas_evidence_submissions_update_guard
BEFORE UPDATE ON tas_evidence_submissions
BEGIN
    SELECT CASE WHEN
        NEW.id<>OLD.id OR NEW.task_id<>OLD.task_id
        OR NEW.actor_agent_id<>OLD.actor_agent_id
        OR NEW.workspace_id<>OLD.workspace_id OR NEW.kind<>OLD.kind
        OR NEW.attempt<>OLD.attempt OR NEW.retry_of IS NOT OLD.retry_of
        OR NEW.observed_at<>OLD.observed_at OR NEW.head_commit<>OLD.head_commit
        OR NEW.created_at<>OLD.created_at
    THEN RAISE(ABORT, 'Evidence reservation metadata is immutable') END;
    SELECT CASE WHEN NOT (OLD.status='reserved' AND NEW.status='finalized')
    THEN RAISE(ABORT, 'Evidence transition is invalid') END;
    SELECT CASE WHEN OLD.kind='command_test' AND NOT (
        (SELECT count(*) FROM tas_evidence_submission_artifacts link
         WHERE link.evidence_id=OLD.id)=2
        AND
        (SELECT count(*) FROM tas_evidence_submission_artifacts link
         JOIN tas_artifact_uploads artifact ON artifact.id=link.artifact_id
         WHERE link.evidence_id=OLD.id AND artifact.purpose='test_stdout')=1
        AND
        (SELECT count(*) FROM tas_evidence_submission_artifacts link
         JOIN tas_artifact_uploads artifact ON artifact.id=link.artifact_id
         WHERE link.evidence_id=OLD.id AND artifact.purpose='test_stderr')=1
    ) THEN RAISE(ABORT, 'Command Evidence requires stdout and stderr') END;
    SELECT CASE WHEN OLD.kind='git' AND (
        SELECT count(*) FROM tas_evidence_submission_artifacts link
        WHERE link.evidence_id=OLD.id
    ) > 1 THEN RAISE(ABORT, 'Git Evidence accepts at most one diff Artifact') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_observed_evidence observed
        WHERE observed.id=OLD.id AND observed.task_id=OLD.task_id
          AND observed.actor_agent_id=OLD.actor_agent_id
          AND observed.kind=OLD.kind
          AND observed.payload_sha256=NEW.payload_sha256
          AND observed.observed_at=OLD.observed_at
    ) THEN RAISE(ABORT, 'Finalized Evidence snapshot is missing') END;
END;

CREATE TRIGGER tas_evidence_submissions_no_delete
BEFORE DELETE ON tas_evidence_submissions
BEGIN SELECT RAISE(ABORT, 'Evidence submission is append-only'); END;

CREATE TRIGGER tas_evidence_submission_artifacts_no_update
BEFORE UPDATE ON tas_evidence_submission_artifacts
BEGIN SELECT RAISE(ABORT, 'Evidence Artifact links are immutable'); END;

CREATE TRIGGER tas_evidence_submission_artifacts_no_delete
BEFORE DELETE ON tas_evidence_submission_artifacts
BEGIN SELECT RAISE(ABORT, 'Evidence Artifact links are immutable'); END;
