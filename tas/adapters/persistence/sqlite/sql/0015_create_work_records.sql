CREATE TABLE tas_observed_evidence (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    task_id TEXT NOT NULL REFERENCES tas_tasks(id),
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    kind TEXT NOT NULL CHECK (kind IN ('git','command_test')),
    payload_json TEXT NOT NULL CHECK (length(payload_json) BETWEEN 2 AND 1000000),
    payload_sha256 TEXT NOT NULL CHECK (
        length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    observed_at TEXT NOT NULL CHECK (
        length(observed_at) BETWEEN 7 AND 64 AND substr(observed_at, -6) = '+00:00'
    )
);

CREATE TABLE tas_work_records (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 255),
    task_id TEXT NOT NULL REFERENCES tas_tasks(id),
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id),
    record_type TEXT NOT NULL CHECK (record_type IN (
        'observation','hypothesis','decision','action_intent',
        'action_receipt','result','validation','authorization'
    )),
    claim_text TEXT CHECK (
        claim_text IS NULL OR length(trim(claim_text)) BETWEEN 1 AND 65536
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) BETWEEN 7 AND 64 AND substr(created_at, -6) = '+00:00'
    )
);

CREATE TABLE tas_work_record_evidence (
    work_record_id TEXT NOT NULL REFERENCES tas_work_records(id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    evidence_id TEXT NOT NULL REFERENCES tas_observed_evidence(id),
    PRIMARY KEY (work_record_id, sequence),
    UNIQUE (work_record_id, evidence_id)
);

CREATE INDEX idx_tas_work_records_task_time
ON tas_work_records(task_id, created_at, id);

CREATE TRIGGER tas_observed_evidence_no_update
BEFORE UPDATE ON tas_observed_evidence BEGIN
    SELECT RAISE(ABORT, 'observed evidence is immutable');
END;
CREATE TRIGGER tas_observed_evidence_no_delete
BEFORE DELETE ON tas_observed_evidence BEGIN
    SELECT RAISE(ABORT, 'observed evidence is immutable');
END;
CREATE TRIGGER tas_work_records_no_update
BEFORE UPDATE ON tas_work_records BEGIN
    SELECT RAISE(ABORT, 'work records are immutable');
END;
CREATE TRIGGER tas_work_records_no_delete
BEFORE DELETE ON tas_work_records BEGIN
    SELECT RAISE(ABORT, 'work records are immutable');
END;
CREATE TRIGGER tas_work_record_evidence_no_update
BEFORE UPDATE ON tas_work_record_evidence BEGIN
    SELECT RAISE(ABORT, 'work record evidence links are immutable');
END;
CREATE TRIGGER tas_work_record_evidence_no_delete
BEFORE DELETE ON tas_work_record_evidence BEGIN
    SELECT RAISE(ABORT, 'work record evidence links are immutable');
END;
