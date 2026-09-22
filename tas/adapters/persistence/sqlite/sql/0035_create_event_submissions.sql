CREATE TABLE tas_event_submissions (
    event_id TEXT PRIMARY KEY REFERENCES tas_code_change_impact_events(id)
        ON DELETE RESTRICT,
    recorded_at TEXT NOT NULL CHECK (substr(recorded_at,-6)='+00:00')
);

CREATE TRIGGER tas_event_submissions_validate_insert
BEFORE INSERT ON tas_event_submissions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM tas_code_change_impact_events event
        JOIN tas_evidence_submissions submission
          ON submission.id=event.evidence_id AND submission.status='finalized'
        JOIN tas_observed_evidence evidence ON evidence.id=event.evidence_id
        JOIN tas_workspace_registrations workspace_registration
          ON workspace_registration.workspace_id=submission.workspace_id
        JOIN tas_event_task_links link ON link.event_id=event.id
        JOIN tas_tasks task ON task.id=link.task_id
        JOIN tas_inbox_items inbox
          ON inbox.task_id=task.id AND inbox.recipient_agent_id=task.assignee_agent_id
        JOIN tas_task_origins origin ON origin.task_id=task.id
        JOIN tas_projects project ON project.id=event.project_id
        JOIN tas_agents publisher ON publisher.id=event.publisher_agent_id
        JOIN tas_agents target ON target.id=task.assignee_agent_id
        JOIN tas_team_memberships publisher_member
          ON publisher_member.team_id=project.team_id
         AND publisher_member.owner_id=publisher.owner_id
        JOIN tas_team_memberships target_member
          ON target_member.team_id=project.team_id
         AND target_member.owner_id=target.owner_id
        JOIN tas_repository_bindings repository
          ON repository.repository=event.repository
         AND repository.project_id=event.project_id
         AND repository.controlling_owner_id=publisher.owner_id
        WHERE event.id=NEW.event_id
          AND event.occurred_at=NEW.recorded_at
          AND evidence.kind='git'
          AND evidence.task_id=submission.task_id
          AND evidence.actor_agent_id=event.publisher_agent_id
          AND submission.actor_agent_id=event.publisher_agent_id
          AND submission.head_commit=event.head_commit
          AND submission.task_id IN (
              SELECT source_task.id FROM tas_tasks source_task
              WHERE source_task.project_id=event.project_id
          )
          AND origin.requester_agent_id=event.publisher_agent_id
          AND origin.requester_owner_id=publisher.owner_id
          AND task.project_id=event.project_id
          AND json_valid(evidence.payload_json)
          AND json_extract(evidence.payload_json,'$.repository')=event.repository
          AND json_extract(evidence.payload_json,'$.workspace_id')=submission.workspace_id
          AND json_extract(evidence.payload_json,'$.branch')=event.ref
          AND json_extract(evidence.payload_json,'$.baseline_commit')=event.baseline_commit
          AND json_extract(evidence.payload_json,'$.head_commit')=event.head_commit
          AND json_type(evidence.payload_json,'$.files')='array'
          AND (
              SELECT count(*) FROM tas_code_change_impact_paths path
              WHERE path.event_id=event.id
          )=json_array_length(evidence.payload_json,'$.files')
          AND NOT EXISTS (
              SELECT 1 FROM json_each(evidence.payload_json,'$.files') item
              WHERE json_type(item.value,'$.path')<>'text'
                 OR NOT EXISTS (
                     SELECT 1 FROM tas_code_change_impact_paths path
                     WHERE path.event_id=event.id
                       AND path.path=json_extract(item.value,'$.path')
                 )
          )
          AND (
              SELECT count(*) FROM tas_inbox_items event_inbox
              WHERE event_inbox.task_id=task.id
                AND event_inbox.recipient_agent_id=task.assignee_agent_id
          )=1
    ) THEN RAISE(ABORT, 'Event submission is not authoritative') END;
END;

CREATE TRIGGER tas_event_submissions_no_update
BEFORE UPDATE ON tas_event_submissions
BEGIN SELECT RAISE(ABORT, 'Event submission is immutable'); END;

CREATE TRIGGER tas_event_submissions_no_delete
BEFORE DELETE ON tas_event_submissions
BEGIN SELECT RAISE(ABORT, 'Event submission is immutable'); END;

CREATE TRIGGER tas_code_change_impact_paths_no_insert_after_submission
BEFORE INSERT ON tas_code_change_impact_paths
WHEN EXISTS (
    SELECT 1 FROM tas_event_submissions WHERE event_id=NEW.event_id
)
BEGIN SELECT RAISE(ABORT, 'Event paths are finalized'); END;
