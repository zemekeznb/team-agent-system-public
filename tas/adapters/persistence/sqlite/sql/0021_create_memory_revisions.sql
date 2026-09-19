CREATE TABLE tas_memory_revisions (
    id TEXT PRIMARY KEY,
    superseded_memory_id TEXT NOT NULL UNIQUE REFERENCES tas_team_memories(id),
    replacement_memory_id TEXT NOT NULL UNIQUE REFERENCES tas_team_memories(id),
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    reason TEXT NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 1024),
    occurred_at TEXT NOT NULL,
    CHECK(superseded_memory_id <> replacement_memory_id)
);
CREATE TRIGGER tas_memory_revisions_no_update BEFORE UPDATE ON tas_memory_revisions BEGIN SELECT RAISE(ABORT,'memory revision is immutable'); END;
CREATE TRIGGER tas_memory_revisions_no_delete BEFORE DELETE ON tas_memory_revisions BEGIN SELECT RAISE(ABORT,'memory revision is immutable'); END;
