-- A scannable, unfinalized Artifact may create one redacted derivative.
-- Count that prospective derivative at reservation time, just as 0040
-- already reserves its Body bytes. Finalization releases the spare slot
-- before inserting the derivative in the same write transaction.
DROP TRIGGER tas_artifact_uploads_insert_guard;
CREATE TRIGGER tas_artifact_uploads_insert_guard
BEFORE INSERT ON tas_artifact_uploads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_tasks task
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents producer ON producer.id=NEW.producer_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=producer.owner_id
        WHERE task.id=NEW.task_id AND task.assignee_agent_id=NEW.producer_agent_id
    ) THEN RAISE(ABORT,'Artifact producer is not authorized for Task') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(CASE WHEN upload.status<>'finalized'
                 AND upload.media_type IN ('text/plain','application/json')
                 THEN 2 ELSE 1 END),0)
        FROM tas_artifact_uploads upload
        JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id
        WHERE upload.task_id=NEW.task_id AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized'
                  AND NEW.media_type IN ('text/plain','application/json')
             THEN 2 ELSE 1 END > 1000
    THEN RAISE(ABORT,'Artifact Task count quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(life.charged_bytes),0)
        FROM tas_artifact_uploads upload
        JOIN tas_artifact_lifecycle life ON life.artifact_id=upload.id
        WHERE upload.task_id=NEW.task_id AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized'
                  AND NEW.media_type IN ('text/plain','application/json')
             THEN NEW.declared_size*2 ELSE NEW.declared_size END > 52428800
    THEN RAISE(ABORT,'Artifact Task byte quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(CASE WHEN upload.status<>'finalized'
                 AND upload.media_type IN ('text/plain','application/json')
                 THEN 2 ELSE 1 END),0)
        FROM tas_artifact_lifecycle life
        JOIN tas_artifact_uploads upload ON upload.id=life.artifact_id
        WHERE life.owner_id=(SELECT owner_id FROM tas_agents WHERE id=NEW.producer_agent_id)
          AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized'
                  AND NEW.media_type IN ('text/plain','application/json')
             THEN 2 ELSE 1 END > 50000
    THEN RAISE(ABORT,'Artifact Owner count quota exceeded') END;
    SELECT CASE WHEN (
        SELECT COALESCE(sum(charged_bytes),0) FROM tas_artifact_lifecycle life
        WHERE life.owner_id=(SELECT owner_id FROM tas_agents WHERE id=NEW.producer_agent_id)
          AND life.cleanup_status<>'purged'
    ) + CASE WHEN NEW.status<>'finalized'
                  AND NEW.media_type IN ('text/plain','application/json')
             THEN NEW.declared_size*2 ELSE NEW.declared_size END > 4294967296
    THEN RAISE(ABORT,'Artifact Owner byte quota exceeded') END;
END;
