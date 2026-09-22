CREATE TABLE tas_a2a_delegation_operations (
    local_task_id TEXT PRIMARY KEY REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    operation_id TEXT NOT NULL UNIQUE CHECK (length(trim(operation_id)) BETWEEN 1 AND 255),
    message_id TEXT NOT NULL CHECK (length(trim(message_id)) BETWEEN 1 AND 255),
    target_id TEXT NOT NULL CHECK (length(trim(target_id)) BETWEEN 1 AND 2048),
    state TEXT NOT NULL CHECK (
        state IN (
            'reserved', 'not_sent', 'submitting', 'response_unknown', 'remote_active',
            'remote_terminal_unrecorded', 'completed', 'failed_terminal'
        )
    ),
    remote_task_id TEXT CHECK (
        remote_task_id IS NULL OR length(trim(remote_task_id)) BETWEEN 1 AND 255
    ),
    remote_status TEXT CHECK (
        remote_status IS NULL OR remote_status IN (
            'submitted', 'working', 'input_required', 'rejected',
            'failed', 'cancelled', 'completed'
        )
    ),
    recovery_cursor TEXT CHECK (
        recovery_cursor IS NULL OR length(recovery_cursor) BETWEEN 1 AND 4096
    ),
    artifact_reference TEXT CHECK (
        artifact_reference IS NULL OR length(trim(artifact_reference)) BETWEEN 1 AND 2048
    ),
    content_trusted INTEGER NOT NULL DEFAULT 0 CHECK (content_trusted = 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 100),
    last_error_code TEXT CHECK (
        last_error_code IS NULL OR length(last_error_code) BETWEEN 1 AND 128
    ),
    correlation_id TEXT CHECK (
        correlation_id IS NULL OR length(correlation_id) BETWEEN 1 AND 255
    ),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    CHECK (
        (state IN ('reserved', 'not_sent', 'submitting', 'response_unknown')
         AND remote_task_id IS NULL AND remote_status IS NULL)
        OR
        (state IN ('remote_active', 'remote_terminal_unrecorded', 'completed')
         AND remote_task_id IS NOT NULL AND remote_status IS NOT NULL)
        OR
        (state = 'failed_terminal' AND (
            (remote_task_id IS NULL AND remote_status IS NULL)
            OR (remote_task_id IS NOT NULL AND remote_status IS NOT NULL)
        ))
    ),
    CHECK (
        state NOT IN ('remote_terminal_unrecorded', 'completed')
        OR remote_status IN ('rejected', 'failed', 'cancelled', 'completed')
    ),
    CHECK (
        state != 'remote_active'
        OR remote_status IN ('submitted', 'working', 'input_required')
    )
);

CREATE UNIQUE INDEX idx_tas_a2a_delegation_message
ON tas_a2a_delegation_operations(target_id, message_id);

CREATE UNIQUE INDEX idx_tas_a2a_delegation_remote_task
ON tas_a2a_delegation_operations(target_id, remote_task_id)
WHERE remote_task_id IS NOT NULL;

INSERT INTO tas_a2a_delegation_operations(
    local_task_id, operation_id, message_id, target_id, state,
    remote_task_id, remote_status, artifact_reference, content_trusted,
    attempt_count, created_at, updated_at
)
SELECT
    local_task_id, local_task_id, local_task_id, 'legacy-f2-a2a', 'completed',
    remote_task_id, remote_status, artifact_reference, content_trusted,
    1, completed_at, completed_at
FROM tas_a2a_delegation_results;

CREATE TRIGGER tas_a2a_delegation_operations_identity_immutable
BEFORE UPDATE OF local_task_id, operation_id, message_id, target_id, correlation_id, created_at
ON tas_a2a_delegation_operations
BEGIN
    SELECT RAISE(ABORT, 'A2A delegation identity is immutable');
END;

CREATE TRIGGER tas_a2a_delegation_operations_no_delete
BEFORE DELETE ON tas_a2a_delegation_operations
BEGIN
    SELECT RAISE(ABORT, 'A2A delegation history is immutable');
END;

CREATE TRIGGER tas_a2a_delegation_remote_identity_immutable
BEFORE UPDATE OF remote_task_id, remote_status, recovery_cursor, artifact_reference
ON tas_a2a_delegation_operations
WHEN
    OLD.state NOT IN ('submitting', 'response_unknown', 'remote_active')
    OR (
        OLD.remote_task_id IS NOT NULL
        AND NEW.remote_task_id IS NOT OLD.remote_task_id
    )
BEGIN
    SELECT RAISE(ABORT, 'A2A remote binding is immutable');
END;

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
    OR (OLD.state = 'not_sent' AND NEW.state IN ('submitting', 'failed_terminal'))
    OR (OLD.state = 'remote_active' AND NEW.state IN (
        'remote_active', 'response_unknown',
        'remote_terminal_unrecorded', 'failed_terminal'
    ))
    OR (OLD.state = 'remote_terminal_unrecorded' AND NEW.state = 'completed')
)
BEGIN
    SELECT RAISE(ABORT, 'invalid A2A delegation state transition');
END;
