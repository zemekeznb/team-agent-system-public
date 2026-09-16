UPDATE tas_tasks SET status = 'working' WHERE status = 'approved';
UPDATE tas_task_transitions SET to_status = 'working' WHERE to_status = 'approved';
UPDATE tas_task_transitions SET from_status = 'working' WHERE from_status = 'approved';

CREATE TABLE tas_approvals (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired')),
    requester_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    requester_owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    receiving_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    receiving_owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    team_id TEXT NOT NULL REFERENCES tas_teams(id) ON DELETE RESTRICT,
    project_id TEXT NOT NULL REFERENCES tas_projects(id) ON DELETE RESTRICT,
    task_id TEXT REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL,
    action TEXT NOT NULL,
    scope TEXT NOT NULL,
    risk INTEGER NOT NULL CHECK (risk BETWEEN 1 AND 4),
    policy_reason TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_by_owner_id TEXT REFERENCES tas_owners(id) ON DELETE RESTRICT,
    resolved_at TEXT,
    resolution_reason TEXT,
    CHECK (
        (status = 'pending' AND resolved_by_owner_id IS NULL AND resolved_at IS NULL AND resolution_reason IS NULL)
        OR (status = 'expired' AND resolved_by_owner_id IS NULL AND resolved_at IS NOT NULL AND resolution_reason IS NULL)
        OR (status = 'approved' AND resolved_by_owner_id IS NOT NULL AND resolved_at IS NOT NULL)
        OR (status = 'rejected' AND resolved_by_owner_id IS NOT NULL AND resolved_at IS NOT NULL AND length(trim(resolution_reason)) > 0)
    )
);
