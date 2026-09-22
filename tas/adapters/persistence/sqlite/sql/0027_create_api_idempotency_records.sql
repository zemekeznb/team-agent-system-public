CREATE TABLE tas_api_idempotency_records (
    owner_id TEXT NOT NULL REFERENCES tas_owners(id) ON DELETE RESTRICT,
    operation TEXT NOT NULL CHECK (length(trim(operation)) BETWEEN 1 AND 255),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
    request_fingerprint TEXT NOT NULL CHECK (
        length(request_fingerprint)=64
        AND request_fingerprint NOT GLOB '*[^0-9a-f]*'
    ),
    result_version TEXT NOT NULL CHECK (length(trim(result_version)) BETWEEN 1 AND 255),
    created_at TEXT NOT NULL CHECK (substr(created_at,-6)='+00:00'),
    PRIMARY KEY (owner_id,operation,idempotency_key)
);

CREATE TRIGGER tas_api_idempotency_records_no_update
BEFORE UPDATE ON tas_api_idempotency_records
BEGIN SELECT RAISE(ABORT, 'API idempotency records are immutable'); END;

CREATE TRIGGER tas_api_idempotency_records_no_delete
BEFORE DELETE ON tas_api_idempotency_records
BEGIN SELECT RAISE(ABORT, 'API idempotency records are immutable'); END;
