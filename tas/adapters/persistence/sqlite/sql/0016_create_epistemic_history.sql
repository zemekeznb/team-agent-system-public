CREATE TABLE tas_epistemic_events (
    id TEXT PRIMARY KEY CHECK (length(trim(id)) BETWEEN 1 AND 512),
    work_record_id TEXT NOT NULL REFERENCES tas_work_records(id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    from_status TEXT CHECK (
        from_status IS NULL OR from_status IN ('claimed','observed','validated','conflicted')
    ),
    to_status TEXT NOT NULL CHECK (
        to_status IN ('claimed','observed','validated','conflicted')
    ),
    rule_id TEXT NOT NULL CHECK (length(trim(rule_id)) BETWEEN 1 AND 255),
    occurred_at TEXT NOT NULL CHECK (
        length(occurred_at) BETWEEN 7 AND 64 AND substr(occurred_at, -6) = '+00:00'
    ),
    CHECK (
        (sequence = 1 AND from_status IS NULL
            AND to_status IN ('claimed','observed') AND rule_id = 'record_created')
        OR
        (sequence > 1 AND rule_id <> 'record_created' AND (
            (from_status = 'observed' AND to_status IN ('validated','conflicted'))
            OR (from_status = 'validated' AND to_status = 'conflicted')
        ))
    ),
    UNIQUE (work_record_id, sequence)
);

CREATE TABLE tas_epistemic_event_evidence (
    epistemic_event_id TEXT NOT NULL REFERENCES tas_epistemic_events(id),
    sequence INTEGER NOT NULL CHECK (sequence >= 1),
    evidence_id TEXT NOT NULL REFERENCES tas_observed_evidence(id),
    PRIMARY KEY (epistemic_event_id, sequence),
    UNIQUE (epistemic_event_id, evidence_id)
);

INSERT INTO tas_epistemic_events (
    id,work_record_id,sequence,from_status,to_status,rule_id,occurred_at
)
SELECT
    'initial:' || wr.id,
    wr.id,
    1,
    NULL,
    CASE WHEN EXISTS (
        SELECT 1 FROM tas_work_record_evidence link WHERE link.work_record_id=wr.id
    ) THEN 'observed' ELSE 'claimed' END,
    'record_created',
    wr.created_at
FROM tas_work_records wr;

INSERT INTO tas_epistemic_event_evidence (
    epistemic_event_id,sequence,evidence_id
)
SELECT 'initial:' || link.work_record_id,link.sequence,link.evidence_id
FROM tas_work_record_evidence link;

CREATE TRIGGER tas_epistemic_events_no_update
BEFORE UPDATE ON tas_epistemic_events BEGIN
    SELECT RAISE(ABORT, 'epistemic events are immutable');
END;
CREATE TRIGGER tas_epistemic_events_no_delete
BEFORE DELETE ON tas_epistemic_events BEGIN
    SELECT RAISE(ABORT, 'epistemic events are immutable');
END;
CREATE TRIGGER tas_epistemic_event_evidence_no_update
BEFORE UPDATE ON tas_epistemic_event_evidence BEGIN
    SELECT RAISE(ABORT, 'epistemic event evidence links are immutable');
END;
CREATE TRIGGER tas_epistemic_event_evidence_no_delete
BEFORE DELETE ON tas_epistemic_event_evidence BEGIN
    SELECT RAISE(ABORT, 'epistemic event evidence links are immutable');
END;
