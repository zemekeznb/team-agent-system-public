CREATE TABLE tas_inbox_items (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE CASCADE,
    recipient_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    available_at TEXT NOT NULL,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0 AND attempt_count <= max_attempts),
    status TEXT NOT NULL CHECK (status IN ('pending','leased','acknowledged','dead_letter')),
    lease_token TEXT,
    claimant_agent_id TEXT REFERENCES tas_agents(id) ON DELETE RESTRICT,
    lease_acquired_at TEXT,
    lease_expires_at TEXT,
    CHECK (
        (status = 'leased' AND lease_token IS NOT NULL AND claimant_agent_id IS NOT NULL AND lease_acquired_at IS NOT NULL AND lease_expires_at IS NOT NULL)
        OR
        (status <> 'leased' AND lease_token IS NULL AND claimant_agent_id IS NULL AND lease_acquired_at IS NULL AND lease_expires_at IS NULL)
    )
);

CREATE INDEX tas_inbox_poll_idx
ON tas_inbox_items(recipient_agent_id, status, available_at, lease_expires_at);
