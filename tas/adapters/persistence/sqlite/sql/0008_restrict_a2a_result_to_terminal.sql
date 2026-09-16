CREATE TABLE tas_a2a_delegation_terminal_results (
    local_task_id TEXT PRIMARY KEY REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    remote_task_id TEXT NOT NULL CHECK (length(trim(remote_task_id)) > 0),
    remote_status TEXT NOT NULL CHECK (
        remote_status IN ('rejected', 'failed', 'cancelled', 'completed')
    ),
    artifact_reference TEXT,
    content_trusted INTEGER NOT NULL DEFAULT 0 CHECK (content_trusted = 0),
    completed_at TEXT NOT NULL,
    CHECK (
        artifact_reference IS NULL OR length(trim(artifact_reference)) > 0
    )
);

INSERT INTO tas_a2a_delegation_terminal_results(
    local_task_id,
    remote_task_id,
    remote_status,
    artifact_reference,
    content_trusted,
    completed_at
)
SELECT
    local_task_id,
    remote_task_id,
    remote_status,
    artifact_reference,
    content_trusted,
    completed_at
FROM tas_a2a_delegation_results
WHERE remote_status IN ('rejected', 'failed', 'cancelled', 'completed');

DROP TABLE tas_a2a_delegation_results;

ALTER TABLE tas_a2a_delegation_terminal_results
RENAME TO tas_a2a_delegation_results;
