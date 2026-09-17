CREATE TABLE tas_action_grant_consumptions (
    approval_id TEXT PRIMARY KEY REFERENCES tas_approvals(id) ON DELETE RESTRICT,
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64),
    status TEXT NOT NULL CHECK (status IN ('in_progress','completed')),
    started_at TEXT NOT NULL CHECK (substr(started_at, -6) = '+00:00'),
    completed_at TEXT CHECK (completed_at IS NULL OR substr(completed_at, -6) = '+00:00'),
    external_action_id TEXT,
    result_reference TEXT,
    receipt_occurred_at TEXT CHECK (receipt_occurred_at IS NULL OR substr(receipt_occurred_at, -6) = '+00:00'),
    CHECK (
        (status = 'in_progress' AND completed_at IS NULL AND external_action_id IS NULL AND result_reference IS NULL AND receipt_occurred_at IS NULL)
        OR
        (status = 'completed' AND completed_at IS NOT NULL AND external_action_id IS NOT NULL AND result_reference IS NOT NULL AND receipt_occurred_at IS NOT NULL)
    )
);

CREATE TRIGGER tas_action_grant_requires_approved
BEFORE INSERT ON tas_action_grant_consumptions
WHEN (SELECT status FROM tas_approvals WHERE id = NEW.approval_id) <> 'approved'
BEGIN
    SELECT RAISE(ABORT, 'action grant requires approved Approval');
END;

CREATE TRIGGER tas_completed_action_grant_no_update
BEFORE UPDATE ON tas_action_grant_consumptions
WHEN OLD.status = 'completed'
BEGIN
    SELECT RAISE(ABORT, 'completed action grant is immutable');
END;

CREATE TRIGGER tas_action_grant_no_delete
BEFORE DELETE ON tas_action_grant_consumptions
BEGIN
    SELECT RAISE(ABORT, 'action grant consumption cannot be deleted');
END;
