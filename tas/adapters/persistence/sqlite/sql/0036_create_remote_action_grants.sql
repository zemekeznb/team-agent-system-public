DROP TRIGGER tas_credential_scopes_insert_only_during_issuance;
DROP TRIGGER tas_credential_scopes_no_update;
DROP TRIGGER tas_credential_scopes_no_delete;

ALTER TABLE tas_credential_scopes RENAME TO tas_credential_scopes_before_actions;

CREATE TABLE tas_credential_scopes (
    credential_id TEXT NOT NULL REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN (
        'session:read','credentials:manage','events:read','events:write',
        'tasks:read','tasks:write','inbox:read','inbox:claim',
        'approvals:read','approvals:request','approvals:decide','actions:execute',
        'evidence:read','evidence:write','artifacts:read','artifacts:write',
        'work_records:read','work_records:write','memories:read','memories:write',
        'policies:read','policies:write','audits:read'
    )),
    PRIMARY KEY (credential_id, scope)
);

INSERT INTO tas_credential_scopes
SELECT * FROM tas_credential_scopes_before_actions;
DROP TABLE tas_credential_scopes_before_actions;

CREATE TRIGGER tas_credential_scopes_insert_only_during_issuance
BEFORE INSERT ON tas_credential_scopes
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND scopes_sealed=0 AND status='active'
    ) THEN RAISE(ABORT, 'credential scopes are sealed') END;
    SELECT CASE WHEN NEW.scope IN (
        'credentials:manage','approvals:decide','policies:write','audits:read'
    ) AND EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND subject_type='agent'
    ) THEN RAISE(ABORT, 'agent credential cannot contain owner-only scope') END;
END;

CREATE TRIGGER tas_credential_scopes_no_update
BEFORE UPDATE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TRIGGER tas_credential_scopes_no_delete
BEFORE DELETE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TABLE tas_remote_action_grants (
    approval_id TEXT PRIMARY KEY
        REFERENCES tas_action_grant_consumptions(approval_id) ON DELETE RESTRICT,
    workspace_id TEXT NOT NULL
        REFERENCES tas_workspace_registrations(workspace_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL
        REFERENCES tas_evidence_submissions(id) ON DELETE RESTRICT,
    commit_sha TEXT NOT NULL CHECK (
        length(commit_sha) IN (40,64)
        AND commit_sha NOT GLOB '*[^0-9a-f]*'
    ),
    execute_before TEXT NOT NULL CHECK (substr(execute_before,-6)='+00:00'),
    CHECK (length(trim(approval_id)) BETWEEN 1 AND 255)
);

CREATE TRIGGER tas_remote_action_grants_insert_guard
BEFORE INSERT ON tas_remote_action_grants
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_approvals approval
        JOIN tas_action_grant_consumptions consumption
          ON consumption.approval_id=approval.id
         AND consumption.status='in_progress'
         AND consumption.started_at < NEW.execute_before
        JOIN tas_task_workspace_bindings workspace
          ON workspace.id=NEW.workspace_id
         AND workspace.task_id=approval.task_id
         AND workspace.actor_agent_id=approval.receiving_agent_id
         AND workspace.repository=approval.repository
        JOIN tas_evidence_submissions evidence
          ON evidence.id=NEW.evidence_id
         AND evidence.task_id=approval.task_id
         AND evidence.actor_agent_id=approval.receiving_agent_id
         AND evidence.workspace_id=workspace.id
         AND evidence.kind='git'
         AND evidence.status='finalized'
         AND evidence.head_commit=NEW.commit_sha
        WHERE approval.id=NEW.approval_id
          AND NEW.execute_before <= approval.expires_at
    ) THEN RAISE(ABORT, 'remote Action Grant preconditions are not authoritative') END;
END;

CREATE TRIGGER tas_remote_action_grants_no_update
BEFORE UPDATE ON tas_remote_action_grants
BEGIN SELECT RAISE(ABORT, 'remote Action Grant metadata is immutable'); END;

CREATE TRIGGER tas_remote_action_grants_no_delete
BEFORE DELETE ON tas_remote_action_grants
BEGIN SELECT RAISE(ABORT, 'remote Action Grant metadata is immutable'); END;
