DROP TRIGGER tas_credential_scopes_insert_only_during_issuance;
DROP TRIGGER tas_credential_scopes_no_update;
DROP TRIGGER tas_credential_scopes_no_delete;

ALTER TABLE tas_credential_scopes RENAME TO tas_credential_scopes_before_audit_read;

CREATE TABLE tas_credential_scopes (
    credential_id TEXT NOT NULL REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN (
        'session:read','credentials:manage','events:read','events:write',
        'tasks:read','tasks:write','inbox:read','inbox:claim',
        'approvals:read','approvals:request','approvals:decide',
        'evidence:read','evidence:write','artifacts:read','artifacts:write',
        'work_records:read','work_records:write','memories:read',
        'policies:read','policies:write','audits:read'
    )),
    PRIMARY KEY (credential_id, scope)
);

INSERT INTO tas_credential_scopes
SELECT * FROM tas_credential_scopes_before_audit_read;
DROP TABLE tas_credential_scopes_before_audit_read;

CREATE TRIGGER tas_credential_scopes_insert_only_during_issuance
BEFORE INSERT ON tas_credential_scopes
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND scopes_sealed=0 AND status='active'
    ) THEN RAISE(ABORT, 'credential scopes are sealed') END;
    SELECT CASE WHEN NEW.scope IN (
        'credentials:manage','approvals:decide','policies:write','audits:read'
    )
        AND EXISTS (
            SELECT 1 FROM tas_credentials
            WHERE id=NEW.credential_id AND subject_type='agent'
        )
        THEN RAISE(ABORT, 'agent credential cannot contain owner-only scope') END;
END;

CREATE TRIGGER tas_credential_scopes_no_update
BEFORE UPDATE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TRIGGER tas_credential_scopes_no_delete
BEFORE DELETE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TABLE tas_audit_event_order (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE REFERENCES tas_audit_events(id) ON DELETE RESTRICT
);

INSERT INTO tas_audit_event_order(event_id)
SELECT id FROM tas_audit_events ORDER BY rowid;

CREATE TRIGGER tas_audit_event_order_after_insert
AFTER INSERT ON tas_audit_events
BEGIN
    INSERT INTO tas_audit_event_order(event_id) VALUES (NEW.id);
END;

CREATE TRIGGER tas_audit_event_order_no_update
BEFORE UPDATE ON tas_audit_event_order
BEGIN SELECT RAISE(ABORT, 'audit query order is immutable'); END;

CREATE TRIGGER tas_audit_event_order_no_delete
BEFORE DELETE ON tas_audit_event_order
BEGIN SELECT RAISE(ABORT, 'audit query order is immutable'); END;
