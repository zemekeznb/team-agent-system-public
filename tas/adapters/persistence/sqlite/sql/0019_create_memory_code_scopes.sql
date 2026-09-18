CREATE TABLE tas_team_memory_code_scopes (
    memory_id TEXT PRIMARY KEY REFERENCES tas_team_memories(id),
    source_evidence_id TEXT NOT NULL REFERENCES tas_observed_evidence(id),
    repository TEXT NOT NULL REFERENCES tas_repository_bindings(repository),
    ref TEXT NOT NULL CHECK(length(trim(ref)) BETWEEN 1 AND 255),
    commit_id TEXT NOT NULL CHECK(length(commit_id) IN (40,64)),
    UNIQUE(memory_id,repository)
);
CREATE TABLE tas_team_memory_code_paths (
    memory_id TEXT NOT NULL REFERENCES tas_team_memory_code_scopes(memory_id),
    sequence INTEGER NOT NULL CHECK(sequence>0), path TEXT NOT NULL,
    PRIMARY KEY(memory_id,sequence), UNIQUE(memory_id,path)
);
CREATE TRIGGER tas_memory_code_scopes_no_update BEFORE UPDATE ON tas_team_memory_code_scopes BEGIN SELECT RAISE(ABORT,'memory code scope is immutable'); END;
CREATE TRIGGER tas_memory_code_scopes_no_delete BEFORE DELETE ON tas_team_memory_code_scopes BEGIN SELECT RAISE(ABORT,'memory code scope is immutable'); END;
CREATE TRIGGER tas_memory_code_paths_no_update BEFORE UPDATE ON tas_team_memory_code_paths BEGIN SELECT RAISE(ABORT,'memory code path is immutable'); END;
CREATE TRIGGER tas_memory_code_paths_no_delete BEFORE DELETE ON tas_team_memory_code_paths BEGIN SELECT RAISE(ABORT,'memory code path is immutable'); END;
