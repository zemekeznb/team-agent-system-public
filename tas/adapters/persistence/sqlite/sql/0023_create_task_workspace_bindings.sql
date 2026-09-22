CREATE TABLE tas_task_workspace_bindings (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    task_id TEXT NOT NULL UNIQUE REFERENCES tas_tasks(id) ON DELETE RESTRICT,
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    repository TEXT NOT NULL CHECK (length(trim(repository)) BETWEEN 1 AND 255),
    root_sha256 TEXT NOT NULL CHECK (
        length(root_sha256) = 64 AND root_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bound_at TEXT NOT NULL CHECK (
        length(bound_at) BETWEEN 7 AND 64 AND substr(bound_at, -6) = '+00:00'
    )
);

CREATE TRIGGER tas_task_workspace_bindings_assignee_guard
BEFORE INSERT ON tas_task_workspace_bindings
WHEN NOT EXISTS (
    SELECT 1 FROM tas_tasks
    WHERE id = NEW.task_id AND assignee_agent_id = NEW.actor_agent_id
)
BEGIN
    SELECT RAISE(ABORT, 'workspace binding actor must be the task assignee');
END;

CREATE TRIGGER tas_task_workspace_bindings_no_update
BEFORE UPDATE ON tas_task_workspace_bindings BEGIN
    SELECT RAISE(ABORT, 'task workspace bindings are immutable');
END;

CREATE TRIGGER tas_task_workspace_bindings_no_delete
BEFORE DELETE ON tas_task_workspace_bindings BEGIN
    SELECT RAISE(ABORT, 'task workspace bindings are immutable');
END;
