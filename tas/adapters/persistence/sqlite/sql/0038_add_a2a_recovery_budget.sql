ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN recovery_attempt_count INTEGER NOT NULL DEFAULT 0
CHECK (recovery_attempt_count BETWEEN 0 AND 100);

ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN recovery_in_progress INTEGER NOT NULL DEFAULT 0
CHECK (recovery_in_progress IN (0, 1));

ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN recovery_started_at TEXT;

ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN next_recovery_at TEXT;

ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN recovery_deadline_at TEXT;

ALTER TABLE tas_a2a_delegation_operations
ADD COLUMN reconciliation_required INTEGER NOT NULL DEFAULT 0
CHECK (reconciliation_required IN (0, 1));

UPDATE tas_a2a_delegation_operations
SET recovery_deadline_at = strftime(
    '%Y-%m-%dT%H:%M:%fZ', updated_at, '+5 minutes'
)
WHERE state NOT IN ('completed', 'failed_terminal');

DROP TRIGGER tas_a2a_delegation_remote_identity_immutable;

CREATE TRIGGER tas_a2a_delegation_remote_identity_immutable
BEFORE UPDATE OF remote_task_id, remote_status, recovery_cursor, artifact_reference
ON tas_a2a_delegation_operations
WHEN
    OLD.state NOT IN ('submitting', 'not_sent', 'response_unknown', 'remote_active')
    OR (
        OLD.remote_task_id IS NOT NULL
        AND NEW.remote_task_id IS NOT OLD.remote_task_id
    )
BEGIN
    SELECT RAISE(ABORT, 'A2A remote binding is immutable');
END;

DROP TRIGGER tas_a2a_delegation_operations_state_transition;

CREATE TRIGGER tas_a2a_delegation_operations_state_transition
BEFORE UPDATE OF state ON tas_a2a_delegation_operations
WHEN NOT (
    (OLD.state = 'reserved' AND NEW.state IN ('submitting', 'failed_terminal'))
    OR (OLD.state = 'submitting' AND NEW.state IN (
        'not_sent', 'response_unknown', 'remote_active',
        'remote_terminal_unrecorded', 'failed_terminal'
    ))
    OR (OLD.state = 'response_unknown' AND NEW.state IN (
        'submitting', 'remote_active',
        'remote_terminal_unrecorded', 'failed_terminal'
    ))
    OR (OLD.state = 'not_sent' AND NEW.state IN (
        'not_sent', 'submitting', 'response_unknown', 'remote_active',
        'remote_terminal_unrecorded', 'failed_terminal'
    ))
    OR (OLD.state = 'remote_active' AND NEW.state IN (
        'remote_active', 'response_unknown',
        'remote_terminal_unrecorded', 'failed_terminal'
    ))
    OR (OLD.state = 'remote_terminal_unrecorded' AND NEW.state = 'completed')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid A2A delegation state transition');
END;

CREATE TRIGGER tas_a2a_recovery_attempts_monotonic
BEFORE UPDATE OF recovery_attempt_count
ON tas_a2a_delegation_operations
WHEN NEW.recovery_attempt_count < OLD.recovery_attempt_count
BEGIN
    SELECT RAISE(ABORT, 'A2A recovery attempts cannot decrease');
END;

CREATE TRIGGER tas_a2a_recovery_deadline_immutable
BEFORE UPDATE OF recovery_deadline_at
ON tas_a2a_delegation_operations
WHEN OLD.recovery_deadline_at IS NOT NEW.recovery_deadline_at
BEGIN
    SELECT RAISE(ABORT, 'A2A recovery deadline is immutable');
END;

CREATE TRIGGER tas_a2a_reconciliation_cannot_reopen
BEFORE UPDATE OF reconciliation_required
ON tas_a2a_delegation_operations
WHEN OLD.reconciliation_required = 1 AND NEW.reconciliation_required = 0
BEGIN
    SELECT RAISE(ABORT, 'A2A reconciliation requirement is irreversible');
END;

CREATE TRIGGER tas_a2a_recovery_fields_consistent
BEFORE UPDATE ON tas_a2a_delegation_operations
WHEN
    (NEW.recovery_in_progress = 1 AND NEW.recovery_started_at IS NULL)
    OR (NEW.recovery_in_progress = 0 AND NEW.recovery_started_at IS NOT NULL)
    OR (NEW.reconciliation_required = 1 AND NEW.next_recovery_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'A2A recovery fields are inconsistent');
END;

CREATE TRIGGER tas_a2a_recovery_fields_consistent_insert
BEFORE INSERT ON tas_a2a_delegation_operations
WHEN
    (NEW.recovery_in_progress = 1 AND NEW.recovery_started_at IS NULL)
    OR (NEW.recovery_in_progress = 0 AND NEW.recovery_started_at IS NOT NULL)
    OR (NEW.reconciliation_required = 1 AND NEW.next_recovery_at IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'A2A recovery fields are inconsistent');
END;
