CREATE TABLE tas_idempotency_records (
    actor_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    operation TEXT NOT NULL CHECK (length(trim(operation)) > 0),
    idempotency_key TEXT NOT NULL CHECK (length(trim(idempotency_key)) > 0),
    request_fingerprint TEXT NOT NULL CHECK (length(request_fingerprint) = 64),
    status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed')),
    reservation_token_hash TEXT,
    result_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (actor_id, operation, idempotency_key),
    CHECK (
        (status = 'in_progress' AND reservation_token_hash IS NOT NULL AND result_json IS NULL)
        OR
        (status = 'completed' AND reservation_token_hash IS NULL AND result_json IS NOT NULL)
    )
);
