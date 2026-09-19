CREATE TABLE tas_code_change_impact_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    project_id TEXT NOT NULL REFERENCES tas_projects(id),
    publisher_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    repository TEXT NOT NULL REFERENCES tas_repository_bindings(repository),
    ref TEXT NOT NULL CHECK (length(trim(ref)) BETWEEN 1 AND 255),
    baseline_commit TEXT NOT NULL CHECK (
        length(baseline_commit) IN (40,64) AND baseline_commit NOT GLOB '*[^0-9a-f]*'
    ),
    head_commit TEXT NOT NULL CHECK (
        length(head_commit) IN (40,64) AND head_commit NOT GLOB '*[^0-9a-f]*'
        AND head_commit <> baseline_commit
    ),
    evidence_id TEXT NOT NULL REFERENCES tas_observed_evidence(id),
    impact_kind TEXT NOT NULL CHECK (impact_kind = 'api_contract_breaking'),
    affected_api TEXT NOT NULL CHECK (length(trim(affected_api)) BETWEEN 1 AND 1024),
    occurred_at TEXT NOT NULL CHECK (substr(occurred_at, -6) = '+00:00')
);

CREATE TABLE tas_code_change_impact_paths (
    event_id TEXT NOT NULL REFERENCES tas_code_change_impact_events(id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    path TEXT NOT NULL CHECK (length(trim(path)) BETWEEN 1 AND 4096),
    PRIMARY KEY (event_id, sequence), UNIQUE (event_id, path)
);

CREATE TABLE tas_event_task_links (
    event_id TEXT PRIMARY KEY REFERENCES tas_code_change_impact_events(id),
    task_id TEXT NOT NULL UNIQUE REFERENCES tas_tasks(id)
);

CREATE TRIGGER tas_code_change_impact_events_no_update BEFORE UPDATE ON tas_code_change_impact_events
BEGIN SELECT RAISE(ABORT, 'code change impact events are immutable'); END;
CREATE TRIGGER tas_code_change_impact_events_no_delete BEFORE DELETE ON tas_code_change_impact_events
BEGIN SELECT RAISE(ABORT, 'code change impact events are immutable'); END;
CREATE TRIGGER tas_code_change_impact_paths_no_update BEFORE UPDATE ON tas_code_change_impact_paths
BEGIN SELECT RAISE(ABORT, 'code change impact paths are immutable'); END;
CREATE TRIGGER tas_code_change_impact_paths_no_delete BEFORE DELETE ON tas_code_change_impact_paths
BEGIN SELECT RAISE(ABORT, 'code change impact paths are immutable'); END;
CREATE TRIGGER tas_event_task_links_no_update BEFORE UPDATE ON tas_event_task_links
BEGIN SELECT RAISE(ABORT, 'event task links are immutable'); END;
CREATE TRIGGER tas_event_task_links_no_delete BEFORE DELETE ON tas_event_task_links
BEGIN SELECT RAISE(ABORT, 'event task links are immutable'); END;
