CREATE TABLE tas_work_record_submissions (
    work_record_id TEXT PRIMARY KEY REFERENCES tas_work_records(id)
        ON DELETE RESTRICT,
    submitted_at TEXT NOT NULL CHECK (substr(submitted_at,-6)='+00:00')
);

CREATE TRIGGER tas_work_record_submissions_insert_guard
BEFORE INSERT ON tas_work_record_submissions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_work_records record
        JOIN tas_tasks task ON task.id=record.task_id
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents actor ON actor.id=record.actor_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=actor.owner_id
        WHERE record.id=NEW.work_record_id
          AND task.assignee_agent_id=record.actor_agent_id
    ) THEN RAISE(ABORT, 'Work Record scope is not authorized') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM tas_work_record_evidence link
        LEFT JOIN tas_evidence_submissions evidence
          ON evidence.id=link.evidence_id
         AND evidence.status='finalized'
        JOIN tas_work_records record ON record.id=link.work_record_id
        WHERE link.work_record_id=NEW.work_record_id
          AND (
              evidence.id IS NULL
              OR evidence.task_id<>record.task_id
              OR evidence.actor_agent_id<>record.actor_agent_id
          )
    ) THEN RAISE(ABORT, 'Work Record Evidence is not authoritative') END;
    SELECT CASE WHEN (
        SELECT count(*) FROM tas_work_record_evidence link
        WHERE link.work_record_id=NEW.work_record_id
    ) > 100 OR COALESCE((
        SELECT max(link.sequence) FROM tas_work_record_evidence link
        WHERE link.work_record_id=NEW.work_record_id
    ),0) <> (
        SELECT count(*) FROM tas_work_record_evidence link
        WHERE link.work_record_id=NEW.work_record_id
    ) THEN RAISE(ABORT, 'Work Record Evidence sequence is invalid') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_work_records record
        WHERE record.id=NEW.work_record_id
          AND (
              record.claim_text IS NOT NULL
              OR EXISTS (
                  SELECT 1 FROM tas_work_record_evidence link
                  WHERE link.work_record_id=record.id
              )
          )
    ) THEN RAISE(ABORT, 'Work Record content is empty') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_epistemic_events event
        WHERE event.work_record_id=NEW.work_record_id
          AND event.sequence=1
          AND event.id='initial:' || NEW.work_record_id
          AND event.from_status IS NULL
          AND event.rule_id='record_created'
          AND event.to_status=CASE WHEN EXISTS (
              SELECT 1 FROM tas_work_record_evidence link
              WHERE link.work_record_id=NEW.work_record_id
          ) THEN 'observed' ELSE 'claimed' END
    ) THEN RAISE(ABORT, 'Work Record initial epistemic state is missing') END;
    SELECT CASE WHEN EXISTS (
        SELECT sequence,evidence_id FROM tas_work_record_evidence
        WHERE work_record_id=NEW.work_record_id
        EXCEPT
        SELECT link.sequence,link.evidence_id
        FROM tas_epistemic_event_evidence link
        WHERE link.epistemic_event_id='initial:' || NEW.work_record_id
    ) OR EXISTS (
        SELECT sequence,evidence_id FROM tas_epistemic_event_evidence
        WHERE epistemic_event_id='initial:' || NEW.work_record_id
        EXCEPT
        SELECT link.sequence,link.evidence_id
        FROM tas_work_record_evidence link
        WHERE link.work_record_id=NEW.work_record_id
    ) THEN RAISE(ABORT, 'Work Record initial Evidence snapshot differs') END;
END;

CREATE TRIGGER tas_work_record_submissions_no_update
BEFORE UPDATE ON tas_work_record_submissions
BEGIN SELECT RAISE(ABORT, 'Work Record submission is immutable'); END;

CREATE TRIGGER tas_work_record_submissions_no_delete
BEFORE DELETE ON tas_work_record_submissions
BEGIN SELECT RAISE(ABORT, 'Work Record submission is append-only'); END;

CREATE TRIGGER tas_work_record_submission_links_finalized
BEFORE INSERT ON tas_work_record_evidence
WHEN EXISTS (
    SELECT 1 FROM tas_work_record_submissions submission
    WHERE submission.work_record_id=NEW.work_record_id
)
BEGIN SELECT RAISE(ABORT, 'Work Record Evidence links are finalized'); END;
