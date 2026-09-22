DROP TRIGGER tas_credential_scopes_insert_only_during_issuance;
DROP TRIGGER tas_credential_scopes_no_update;
DROP TRIGGER tas_credential_scopes_no_delete;

ALTER TABLE tas_credential_scopes RENAME TO tas_credential_scopes_before_policy;

CREATE TABLE tas_credential_scopes (
    credential_id TEXT NOT NULL REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN (
        'session:read','credentials:manage','events:read','events:write',
        'tasks:read','tasks:write','inbox:read','inbox:claim',
        'approvals:read','approvals:request','approvals:decide',
        'evidence:read','evidence:write','artifacts:read','artifacts:write',
        'work_records:read','work_records:write','memories:read',
        'policies:read','policies:write'
    )),
    PRIMARY KEY (credential_id, scope)
);

INSERT INTO tas_credential_scopes SELECT * FROM tas_credential_scopes_before_policy;
DROP TABLE tas_credential_scopes_before_policy;

CREATE TRIGGER tas_credential_scopes_insert_only_during_issuance
BEFORE INSERT ON tas_credential_scopes
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND scopes_sealed=0 AND status='active'
    ) THEN RAISE(ABORT, 'credential scopes are sealed') END;
    SELECT CASE WHEN NEW.scope IN (
        'credentials:manage','approvals:decide','policies:write'
    )
        AND EXISTS (
            SELECT 1 FROM tas_credentials
            WHERE id=NEW.credential_id AND subject_type='agent'
        )
        THEN RAISE(ABORT, 'agent credential cannot contain owner-only scope') END;
END;

CREATE TRIGGER tas_credential_scopes_no_update BEFORE UPDATE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;
CREATE TRIGGER tas_credential_scopes_no_delete BEFORE DELETE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

DROP TRIGGER tas_audit_events_no_update;
DROP TRIGGER tas_audit_events_no_delete;
DROP INDEX idx_tas_audit_events_resource_time;
ALTER TABLE tas_audit_events RENAME TO tas_audit_events_before_policy;

CREATE TABLE tas_audit_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK (kind IN (
        'authorization_decision','task_transition_rejected',
        'action_grant_consumed','action_grant_rejected','action_result_unknown',
        'action_receipt_reconciled','credential_issued','credential_revoked',
        'credential_rotated','authentication_rejected','policy_version_created',
        'policy_current_changed'
    )),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent','owner','system')),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 255),
    resource_type TEXT NOT NULL CHECK (length(trim(resource_type)) BETWEEN 1 AND 255),
    resource_id TEXT NOT NULL CHECK (length(trim(resource_id)) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 255),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'allow','deny','approval_required','rejected','consumed','result_unknown',
        'reconciled','issued','revoked','rotated','created','selected'
    )),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 255),
    occurred_at TEXT NOT NULL CHECK (
        length(occurred_at) BETWEEN 7 AND 64 AND substr(occurred_at, -6) = '+00:00'
    ),
    policy_version TEXT CHECK (
        policy_version IS NULL OR length(trim(policy_version)) BETWEEN 1 AND 255
    ),
    correlation_id TEXT CHECK (
        correlation_id IS NULL OR length(trim(correlation_id)) BETWEEN 1 AND 255
    )
);
INSERT INTO tas_audit_events SELECT * FROM tas_audit_events_before_policy;
DROP TABLE tas_audit_events_before_policy;
CREATE INDEX idx_tas_audit_events_resource_time
ON tas_audit_events(resource_type, resource_id, occurred_at, id);
CREATE TRIGGER tas_audit_events_no_update BEFORE UPDATE ON tas_audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;
CREATE TRIGGER tas_audit_events_no_delete BEFORE DELETE ON tas_audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TABLE tas_owner_policies (
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (length(trim(version)) BETWEEN 1 AND 255),
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00'),
    created_by TEXT NOT NULL CHECK (length(trim(created_by)) BETWEEN 1 AND 255),
    PRIMARY KEY (owner_id,version)
);

CREATE TABLE tas_owner_policy_rules (
    owner_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    action TEXT NOT NULL CHECK (action IN (
        'communicate','read_metadata','read_content','analyze','modify_workspace',
        'commit','push','merge','deploy'
    )),
    outcome TEXT NOT NULL CHECK (outcome IN ('allow','deny','approval_required')),
    max_auto_risk INTEGER NOT NULL CHECK (max_auto_risk BETWEEN 1 AND 4),
    PRIMARY KEY (owner_id,policy_version,sequence),
    UNIQUE (owner_id,policy_version,action),
    FOREIGN KEY (owner_id,policy_version)
        REFERENCES tas_owner_policies(owner_id,version) ON DELETE RESTRICT
);

CREATE TABLE tas_owner_policy_current (
    owner_id TEXT PRIMARY KEY REFERENCES tas_owners(id) ON DELETE RESTRICT,
    policy_version TEXT NOT NULL,
    selected_at TEXT NOT NULL CHECK (substr(selected_at,-6)='+00:00'),
    selected_by TEXT NOT NULL CHECK (length(trim(selected_by)) BETWEEN 1 AND 255),
    FOREIGN KEY (owner_id,policy_version)
        REFERENCES tas_owner_policies(owner_id,version) ON DELETE RESTRICT
);

CREATE TRIGGER tas_owner_policies_no_update BEFORE UPDATE ON tas_owner_policies
BEGIN SELECT RAISE(ABORT, 'policy versions are immutable'); END;
CREATE TRIGGER tas_owner_policies_no_delete BEFORE DELETE ON tas_owner_policies
BEGIN SELECT RAISE(ABORT, 'policy versions are immutable'); END;
CREATE TRIGGER tas_owner_policy_rules_no_update BEFORE UPDATE ON tas_owner_policy_rules
BEGIN SELECT RAISE(ABORT, 'policy rules are immutable'); END;
CREATE TRIGGER tas_owner_policy_rules_no_delete BEFORE DELETE ON tas_owner_policy_rules
BEGIN SELECT RAISE(ABORT, 'policy rules are immutable'); END;
