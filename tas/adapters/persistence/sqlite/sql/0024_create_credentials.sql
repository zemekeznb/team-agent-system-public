DROP TRIGGER tas_audit_events_no_update;
DROP TRIGGER tas_audit_events_no_delete;
DROP INDEX idx_tas_audit_events_resource_time;

ALTER TABLE tas_audit_events RENAME TO tas_audit_events_before_credentials;

CREATE TABLE tas_audit_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK (kind IN (
        'authorization_decision','task_transition_rejected',
        'action_grant_consumed','action_grant_rejected','action_result_unknown',
        'action_receipt_reconciled','credential_issued','credential_revoked',
        'credential_rotated','authentication_rejected'
    )),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent','owner','system')),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 255),
    resource_type TEXT NOT NULL CHECK (length(trim(resource_type)) BETWEEN 1 AND 255),
    resource_id TEXT NOT NULL CHECK (length(trim(resource_id)) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 255),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'allow','deny','approval_required','rejected','consumed','result_unknown',
        'reconciled','issued','revoked','rotated'
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

INSERT INTO tas_audit_events SELECT * FROM tas_audit_events_before_credentials;
DROP TABLE tas_audit_events_before_credentials;

CREATE INDEX idx_tas_audit_events_resource_time
ON tas_audit_events(resource_type, resource_id, occurred_at, id);

CREATE TRIGGER tas_audit_events_no_update BEFORE UPDATE ON tas_audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TRIGGER tas_audit_events_no_delete BEFORE DELETE ON tas_audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TABLE tas_credentials (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 128),
    subject_type TEXT NOT NULL CHECK (subject_type IN ('owner','agent')),
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    agent_id TEXT REFERENCES tas_agents(id) ON DELETE RESTRICT,
    secret_digest TEXT NOT NULL CHECK (
        length(secret_digest) = 64 AND secret_digest NOT GLOB '*[^0-9a-f]*'
    ),
    secret_key_id TEXT NOT NULL CHECK (length(trim(secret_key_id)) BETWEEN 1 AND 64),
    issued_at TEXT NOT NULL CHECK (substr(issued_at, -6) = '+00:00'),
    expires_at TEXT NOT NULL CHECK (substr(expires_at, -6) = '+00:00'),
    status TEXT NOT NULL CHECK (status IN ('active','revoked')),
    identity_source TEXT NOT NULL CHECK (
        identity_source IN ('local_fixture','out_of_band_registration')
    ),
    assurance_level TEXT NOT NULL CHECK (assurance_level IN ('test_only','registered')),
    is_test_fixture INTEGER NOT NULL CHECK (is_test_fixture IN (0,1)),
    issued_by TEXT NOT NULL CHECK (length(trim(issued_by)) BETWEEN 1 AND 255),
    revoked_at TEXT CHECK (revoked_at IS NULL OR substr(revoked_at, -6) = '+00:00'),
    revocation_reason TEXT CHECK (
        revocation_reason IS NULL OR revocation_reason IN (
            'manual','rotated','compromised','owner_removed','binding_invalid'
        )
    ),
    rotated_from_id TEXT UNIQUE REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    replaced_by_id TEXT UNIQUE REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    CHECK (
        (subject_type='owner' AND agent_id IS NULL)
        OR (subject_type='agent' AND agent_id IS NOT NULL)
    ),
    CHECK (
        (identity_source='local_fixture' AND assurance_level='test_only' AND is_test_fixture=1)
        OR (identity_source='out_of_band_registration' AND assurance_level='registered' AND is_test_fixture=0)
    ),
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at),
    CHECK (
        (status='active' AND revoked_at IS NULL AND revocation_reason IS NULL AND replaced_by_id IS NULL)
        OR (status='revoked' AND revoked_at IS NOT NULL AND revocation_reason IS NOT NULL)
    ),
    CHECK (
        (revocation_reason='rotated' AND replaced_by_id IS NOT NULL)
        OR (revocation_reason IS NOT 'rotated' AND replaced_by_id IS NULL)
    ),
    CHECK (rotated_from_id IS NULL OR rotated_from_id <> id),
    CHECK (replaced_by_id IS NULL OR replaced_by_id <> id)
);

CREATE TABLE tas_credential_scopes (
    credential_id TEXT NOT NULL REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN (
        'session:read','credentials:manage','events:read','events:write',
        'tasks:read','tasks:write','inbox:read','inbox:claim',
        'approvals:read','approvals:request','approvals:decide',
        'evidence:read','evidence:write','artifacts:read','artifacts:write',
        'work_records:read','work_records:write','memories:read'
    )),
    PRIMARY KEY (credential_id, scope)
);

CREATE TRIGGER tas_credentials_validate_agent_owner_insert
BEFORE INSERT ON tas_credentials WHEN NEW.subject_type='agent'
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_agents WHERE id=NEW.agent_id AND owner_id=NEW.owner_id
    ) THEN RAISE(ABORT, 'credential agent owner binding invalid') END;
END;

CREATE TRIGGER tas_credentials_lifecycle_only
BEFORE UPDATE ON tas_credentials
WHEN NOT (
    OLD.status='active' AND NEW.status='revoked'
    AND NEW.id IS OLD.id AND NEW.subject_type IS OLD.subject_type
    AND NEW.owner_id IS OLD.owner_id AND NEW.agent_id IS OLD.agent_id
    AND NEW.secret_digest IS OLD.secret_digest AND NEW.secret_key_id IS OLD.secret_key_id
    AND NEW.issued_at IS OLD.issued_at AND NEW.expires_at IS OLD.expires_at
    AND NEW.identity_source IS OLD.identity_source
    AND NEW.assurance_level IS OLD.assurance_level
    AND NEW.is_test_fixture IS OLD.is_test_fixture AND NEW.issued_by IS OLD.issued_by
    AND NEW.rotated_from_id IS OLD.rotated_from_id
)
BEGIN SELECT RAISE(ABORT, 'credential fields are immutable'); END;

CREATE TRIGGER tas_credentials_no_delete BEFORE DELETE ON tas_credentials
BEGIN SELECT RAISE(ABORT, 'credentials are immutable'); END;

CREATE TRIGGER tas_credential_scopes_no_update BEFORE UPDATE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TRIGGER tas_credential_scopes_no_delete BEFORE DELETE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;
