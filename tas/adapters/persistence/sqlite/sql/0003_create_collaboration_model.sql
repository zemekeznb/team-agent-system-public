CREATE TABLE tas_tasks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES tas_projects(id) ON DELETE RESTRICT,
    assignee_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    title TEXT NOT NULL CHECK (length(trim(title)) > 0),
    status TEXT NOT NULL CHECK (status IN ('submitted','working','input_required','approval_required','approved','rejected','expired','failed','cancelled','completed')),
    result TEXT,
    CHECK ((status = 'completed' AND length(trim(result)) > 0) OR (status <> 'completed' AND result IS NULL))
);

CREATE TABLE tas_task_transitions (
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    from_status TEXT NOT NULL,
    to_status TEXT NOT NULL,
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    reason TEXT,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (task_id, sequence)
);

CREATE TABLE tas_task_messages (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE CASCADE,
    author_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    body TEXT NOT NULL CHECK (length(trim(body)) > 0),
    created_at TEXT NOT NULL
);

CREATE TABLE tas_artifacts (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE CASCADE,
    producer_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    reference TEXT NOT NULL CHECK (length(trim(reference)) > 0),
    media_type TEXT NOT NULL CHECK (length(trim(media_type)) > 0),
    created_at TEXT NOT NULL
);
