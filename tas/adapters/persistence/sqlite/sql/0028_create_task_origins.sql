CREATE TABLE tas_task_origins (
    task_id TEXT PRIMARY KEY REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    requester_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    requester_owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00')
);

CREATE TRIGGER tas_task_origins_validate_owner
BEFORE INSERT ON tas_task_origins
WHEN NOT EXISTS (
    SELECT 1 FROM tas_agents
    WHERE id=NEW.requester_agent_id AND owner_id=NEW.requester_owner_id
)
BEGIN SELECT RAISE(ABORT, 'Task origin Agent/Owner mismatch'); END;

CREATE TRIGGER tas_task_origins_no_update
BEFORE UPDATE ON tas_task_origins
BEGIN SELECT RAISE(ABORT, 'Task origin is immutable'); END;

CREATE TRIGGER tas_task_origins_no_delete
BEFORE DELETE ON tas_task_origins
BEGIN SELECT RAISE(ABORT, 'Task origin is immutable'); END;
