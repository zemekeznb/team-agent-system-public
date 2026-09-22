DROP TRIGGER tas_credential_scopes_no_update;
DROP TRIGGER tas_credential_scopes_no_delete;

CREATE TABLE tas_credential_scope_quarantine (
    credential_id TEXT NOT NULL,
    scope TEXT NOT NULL,
    reason TEXT NOT NULL CHECK (reason='agent_owner_only_scope'),
    captured_at TEXT NOT NULL,
    PRIMARY KEY (credential_id, scope)
);

INSERT INTO tas_credential_scope_quarantine(credential_id,scope,reason,captured_at)
SELECT s.credential_id,s.scope,'agent_owner_only_scope',
       strftime('%Y-%m-%dT%H:%M:%f+00:00','now')
FROM tas_credential_scopes s
JOIN tas_credentials c ON c.id=s.credential_id
WHERE c.subject_type='agent'
AND s.scope IN ('credentials:manage','approvals:decide');

UPDATE tas_credentials
SET status='revoked',
    revoked_at=strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),
    revocation_reason='binding_invalid'
WHERE status='active' AND id IN (
    SELECT credential_id FROM tas_credential_scope_quarantine
);

INSERT INTO tas_audit_events(
    id,kind,actor_kind,actor_id,resource_type,resource_id,action,
    outcome,reason,occurred_at,policy_version,correlation_id
)
SELECT
    'migration-0025-' || c.id,'credential_revoked','system','migration-0025',
    'credential',c.id,'revoke','revoked','owner_only_scope_quarantined',
    strftime('%Y-%m-%dT%H:%M:%f+00:00','now'),NULL,NULL
FROM tas_credentials c
WHERE c.id IN (SELECT credential_id FROM tas_credential_scope_quarantine);

DELETE FROM tas_credential_scopes
WHERE (credential_id,scope) IN (
    SELECT credential_id,scope FROM tas_credential_scope_quarantine
);

INSERT INTO tas_credential_scopes(credential_id,scope)
SELECT q.credential_id,'session:read'
FROM (SELECT DISTINCT credential_id FROM tas_credential_scope_quarantine) q
WHERE NOT EXISTS (
    SELECT 1 FROM tas_credential_scopes s WHERE s.credential_id=q.credential_id
);

ALTER TABLE tas_credentials
ADD COLUMN scopes_sealed INTEGER NOT NULL DEFAULT 1 CHECK (scopes_sealed IN (0,1));

DROP TRIGGER tas_credentials_lifecycle_only;

CREATE TRIGGER tas_credentials_lifecycle_only
BEFORE UPDATE ON tas_credentials
WHEN NOT (
    (
        OLD.status='active' AND NEW.status='revoked'
        AND NEW.scopes_sealed IS OLD.scopes_sealed
    )
    OR (
        OLD.status='active' AND NEW.status='active'
        AND OLD.scopes_sealed=0 AND NEW.scopes_sealed=1
        AND NEW.revoked_at IS OLD.revoked_at
        AND NEW.revocation_reason IS OLD.revocation_reason
        AND NEW.replaced_by_id IS OLD.replaced_by_id
    )
)
OR NOT (
    NEW.id IS OLD.id AND NEW.subject_type IS OLD.subject_type
    AND NEW.owner_id IS OLD.owner_id AND NEW.agent_id IS OLD.agent_id
    AND NEW.secret_digest IS OLD.secret_digest AND NEW.secret_key_id IS OLD.secret_key_id
    AND NEW.issued_at IS OLD.issued_at AND NEW.expires_at IS OLD.expires_at
    AND NEW.identity_source IS OLD.identity_source
    AND NEW.assurance_level IS OLD.assurance_level
    AND NEW.is_test_fixture IS OLD.is_test_fixture AND NEW.issued_by IS OLD.issued_by
    AND NEW.rotated_from_id IS OLD.rotated_from_id
)
BEGIN SELECT RAISE(ABORT, 'credential fields are immutable'); END;

CREATE TRIGGER tas_credential_scopes_insert_only_during_issuance
BEFORE INSERT ON tas_credential_scopes
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND scopes_sealed=0 AND status='active'
    ) THEN RAISE(ABORT, 'credential scopes are sealed') END;
    SELECT CASE WHEN NEW.scope IN ('credentials:manage','approvals:decide')
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

CREATE TRIGGER tas_credential_scope_quarantine_no_update
BEFORE UPDATE ON tas_credential_scope_quarantine
BEGIN SELECT RAISE(ABORT, 'credential scope quarantine is immutable'); END;

CREATE TRIGGER tas_credential_scope_quarantine_no_delete
BEFORE DELETE ON tas_credential_scope_quarantine
BEGIN SELECT RAISE(ABORT, 'credential scope quarantine is immutable'); END;
