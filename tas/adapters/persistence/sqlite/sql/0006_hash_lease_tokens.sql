UPDATE tas_inbox_items
SET status = CASE
        WHEN attempt_count >= max_attempts THEN 'dead_letter'
        ELSE 'pending'
    END,
    lease_token = NULL,
    claimant_agent_id = NULL,
    lease_acquired_at = NULL,
    lease_expires_at = NULL
WHERE status = 'leased';

ALTER TABLE tas_inbox_items RENAME COLUMN lease_token TO lease_token_hash;
