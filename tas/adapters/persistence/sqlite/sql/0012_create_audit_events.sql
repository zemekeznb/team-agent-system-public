CREATE TABLE tas_audit_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK (kind IN ('authorization_decision', 'task_transition_rejected')),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent', 'owner', 'system')),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 255),
    resource_type TEXT NOT NULL CHECK (length(trim(resource_type)) BETWEEN 1 AND 255),
    resource_id TEXT NOT NULL CHECK (length(trim(resource_id)) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 255),
    outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'deny', 'approval_required', 'rejected')),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 255),
    occurred_at TEXT NOT NULL CHECK (
        length(occurred_at) BETWEEN 7 AND 64
        AND substr(occurred_at, -6) = '+00:00'
    ),
    policy_version TEXT CHECK (policy_version IS NULL OR length(trim(policy_version)) BETWEEN 1 AND 255)
);

CREATE INDEX idx_tas_audit_events_resource_time
ON tas_audit_events(resource_type, resource_id, occurred_at, id);

CREATE TRIGGER tas_audit_events_no_update
BEFORE UPDATE ON tas_audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER tas_audit_events_no_delete
BEFORE DELETE ON tas_audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
