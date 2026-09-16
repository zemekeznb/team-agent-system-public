UPDATE tas_tasks SET status = 'working' WHERE status = 'approved';

CREATE TABLE tas_task_transitions_v2 (
    task_id TEXT NOT NULL REFERENCES tas_tasks(id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    from_status TEXT NOT NULL CHECK (from_status IN ('submitted','working','input_required','approval_required','rejected','expired','failed','cancelled','completed')),
    to_status TEXT NOT NULL CHECK (to_status IN ('submitted','working','input_required','approval_required','rejected','expired','failed','cancelled','completed')),
    actor_agent_id TEXT NOT NULL REFERENCES tas_agents(id) ON DELETE RESTRICT,
    reason TEXT,
    occurred_at TEXT NOT NULL,
    PRIMARY KEY (task_id, sequence)
);

INSERT INTO tas_task_transitions_v2(
    task_id, sequence, from_status, to_status, actor_agent_id, reason, occurred_at
)
SELECT
    task_id,
    ROW_NUMBER() OVER (PARTITION BY task_id ORDER BY sequence),
    from_status,
    to_status,
    actor_agent_id,
    CASE
        WHEN from_status = 'approval_required' AND to_status = 'working'
             AND EXISTS (
                 SELECT 1 FROM tas_task_transitions AS next_transition
                 WHERE next_transition.task_id = tas_task_transitions.task_id
                   AND next_transition.sequence = tas_task_transitions.sequence + 1
                   AND next_transition.from_status = 'working'
                   AND next_transition.to_status = 'working'
             )
        THEN COALESCE(reason || '; ', '') || 'migration-0010: legacy approved normalized to working'
        ELSE reason
    END,
    occurred_at
FROM tas_task_transitions
WHERE NOT (from_status = 'working' AND to_status = 'working');

DROP TABLE tas_task_transitions;
ALTER TABLE tas_task_transitions_v2 RENAME TO tas_task_transitions;

CREATE TRIGGER tas_tasks_current_status_insert
BEFORE INSERT ON tas_tasks
WHEN NEW.status NOT IN ('submitted','working','input_required','approval_required','rejected','expired','failed','cancelled','completed')
BEGIN
    SELECT RAISE(ABORT, 'invalid current Task status');
END;

CREATE TRIGGER tas_tasks_current_status_update
BEFORE UPDATE OF status ON tas_tasks
WHEN NEW.status NOT IN ('submitted','working','input_required','approval_required','rejected','expired','failed','cancelled','completed')
BEGIN
    SELECT RAISE(ABORT, 'invalid current Task status');
END;
