DROP TRIGGER tas_audit_events_no_update;
DROP TRIGGER tas_audit_events_no_delete;
DROP INDEX idx_tas_audit_events_resource_time;

ALTER TABLE tas_audit_events RENAME TO tas_audit_events_before_action_audit;

CREATE TABLE tas_audit_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    kind TEXT NOT NULL CHECK (kind IN (
        'authorization_decision',
        'task_transition_rejected',
        'action_grant_consumed',
        'action_grant_rejected',
        'action_result_unknown',
        'action_receipt_reconciled'
    )),
    actor_kind TEXT NOT NULL CHECK (actor_kind IN ('agent', 'owner', 'system')),
    actor_id TEXT NOT NULL CHECK (length(trim(actor_id)) BETWEEN 1 AND 255),
    resource_type TEXT NOT NULL CHECK (length(trim(resource_type)) BETWEEN 1 AND 255),
    resource_id TEXT NOT NULL CHECK (length(trim(resource_id)) BETWEEN 1 AND 255),
    action TEXT NOT NULL CHECK (length(trim(action)) BETWEEN 1 AND 255),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'allow','deny','approval_required','rejected',
        'consumed','result_unknown','reconciled'
    )),
    reason TEXT NOT NULL CHECK (length(trim(reason)) BETWEEN 1 AND 255),
    occurred_at TEXT NOT NULL CHECK (
        length(occurred_at) BETWEEN 7 AND 64
        AND substr(occurred_at, -6) = '+00:00'
    ),
    policy_version TEXT CHECK (
        policy_version IS NULL OR length(trim(policy_version)) BETWEEN 1 AND 255
    ),
    correlation_id TEXT CHECK (
        correlation_id IS NULL OR length(trim(correlation_id)) BETWEEN 1 AND 255
    )
);

INSERT INTO tas_audit_events (
    id,kind,actor_kind,actor_id,resource_type,resource_id,action,
    outcome,reason,occurred_at,policy_version,correlation_id
)
SELECT
    id,kind,actor_kind,actor_id,resource_type,resource_id,action,
    outcome,reason,occurred_at,policy_version,NULL
FROM tas_audit_events_before_action_audit;

DROP TABLE tas_audit_events_before_action_audit;

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

ALTER TABLE tas_action_grant_consumptions
ADD COLUMN receipt_source TEXT CHECK (
    receipt_source IS NULL OR receipt_source IN ('executed','reconciled')
);

ALTER TABLE tas_action_grant_consumptions
ADD COLUMN audit_status TEXT NOT NULL DEFAULT 'pending'
CHECK (audit_status IN ('pending','recorded'));

ALTER TABLE tas_action_grant_consumptions
ADD COLUMN audit_event_id TEXT CHECK (
    audit_event_id IS NULL OR length(trim(audit_event_id)) BETWEEN 1 AND 255
);

DROP TRIGGER tas_completed_action_grant_no_update;

CREATE TRIGGER tas_completed_action_grant_no_update
BEFORE UPDATE ON tas_action_grant_consumptions
WHEN OLD.status = 'completed' AND (
    NEW.approval_id IS NOT OLD.approval_id
    OR NEW.request_fingerprint IS NOT OLD.request_fingerprint
    OR NEW.status IS NOT OLD.status
    OR NEW.started_at IS NOT OLD.started_at
    OR NEW.completed_at IS NOT OLD.completed_at
    OR NEW.external_action_id IS NOT OLD.external_action_id
    OR NEW.result_reference IS NOT OLD.result_reference
    OR NEW.receipt_occurred_at IS NOT OLD.receipt_occurred_at
    OR NEW.receipt_source IS NOT OLD.receipt_source
)
BEGIN
    SELECT RAISE(ABORT, 'completed action grant is immutable');
END;
