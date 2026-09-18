CREATE TABLE tas_team_memories (
    id TEXT PRIMARY KEY,
    source_work_record_id TEXT NOT NULL UNIQUE REFERENCES tas_work_records(id),
    source_validation_event_id TEXT NOT NULL UNIQUE REFERENCES tas_epistemic_events(id),
    task_id TEXT NOT NULL REFERENCES tas_tasks(id),
    source_actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    promoted_by_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    record_type TEXT NOT NULL,
    content TEXT NOT NULL CHECK(length(content) BETWEEN 1 AND 65536),
    validation_rule_id TEXT NOT NULL,
    validation_status TEXT NOT NULL CHECK(validation_status IN ('validated','invalidated')),
    applicability_status TEXT NOT NULL CHECK(applicability_status IN ('exact','compatible','possibly_stale','superseded','unknown')),
    promotion_rule_id TEXT NOT NULL CHECK(promotion_rule_id='validated_work_record_v1'),
    promoted_at TEXT NOT NULL
);
CREATE TABLE tas_team_memory_evidence (
    memory_id TEXT NOT NULL REFERENCES tas_team_memories(id),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    evidence_id TEXT NOT NULL REFERENCES tas_observed_evidence(id),
    PRIMARY KEY(memory_id,sequence), UNIQUE(memory_id,evidence_id)
);
CREATE TRIGGER tas_team_memories_no_update BEFORE UPDATE ON tas_team_memories BEGIN SELECT RAISE(ABORT,'team memory is immutable'); END;
CREATE TRIGGER tas_team_memories_no_delete BEFORE DELETE ON tas_team_memories BEGIN SELECT RAISE(ABORT,'team memory is immutable'); END;
CREATE TRIGGER tas_team_memory_evidence_no_update BEFORE UPDATE ON tas_team_memory_evidence BEGIN SELECT RAISE(ABORT,'team memory evidence is immutable'); END;
CREATE TRIGGER tas_team_memory_evidence_no_delete BEFORE DELETE ON tas_team_memory_evidence BEGIN SELECT RAISE(ABORT,'team memory evidence is immutable'); END;
