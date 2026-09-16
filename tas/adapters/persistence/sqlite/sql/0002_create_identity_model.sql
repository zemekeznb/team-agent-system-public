CREATE TABLE tas_owners (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);

CREATE TABLE tas_agents (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);

CREATE TABLE tas_teams (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);

CREATE TABLE tas_team_memberships (
    team_id TEXT NOT NULL REFERENCES tas_teams(id) ON DELETE CASCADE,
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, owner_id)
);

CREATE TABLE tas_projects (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES tas_teams(id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0)
);
