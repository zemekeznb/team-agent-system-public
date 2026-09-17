CREATE TABLE tas_repository_bindings (
    repository TEXT PRIMARY KEY CHECK (length(trim(repository)) BETWEEN 1 AND 255),
    project_id TEXT NOT NULL REFERENCES tas_projects(id) ON DELETE RESTRICT,
    controlling_owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT
);
