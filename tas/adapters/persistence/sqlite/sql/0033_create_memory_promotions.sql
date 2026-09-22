DROP TRIGGER tas_credential_scopes_insert_only_during_issuance;
DROP TRIGGER tas_credential_scopes_no_update;
DROP TRIGGER tas_credential_scopes_no_delete;

ALTER TABLE tas_credential_scopes RENAME TO tas_credential_scopes_before_memory_write;

CREATE TABLE tas_credential_scopes (
    credential_id TEXT NOT NULL REFERENCES tas_credentials(id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN (
        'session:read','credentials:manage','events:read','events:write',
        'tasks:read','tasks:write','inbox:read','inbox:claim',
        'approvals:read','approvals:request','approvals:decide',
        'evidence:read','evidence:write','artifacts:read','artifacts:write',
        'work_records:read','work_records:write','memories:read','memories:write',
        'policies:read','policies:write','audits:read'
    )),
    PRIMARY KEY (credential_id, scope)
);

INSERT INTO tas_credential_scopes
SELECT * FROM tas_credential_scopes_before_memory_write;
DROP TABLE tas_credential_scopes_before_memory_write;

CREATE TRIGGER tas_credential_scopes_insert_only_during_issuance
BEFORE INSERT ON tas_credential_scopes
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND scopes_sealed=0 AND status='active'
    ) THEN RAISE(ABORT, 'credential scopes are sealed') END;
    SELECT CASE WHEN NEW.scope IN (
        'credentials:manage','approvals:decide','policies:write','audits:read'
    ) AND EXISTS (
        SELECT 1 FROM tas_credentials
        WHERE id=NEW.credential_id AND subject_type='agent'
    ) THEN RAISE(ABORT, 'agent credential cannot contain owner-only scope') END;
END;

CREATE TRIGGER tas_credential_scopes_no_update
BEFORE UPDATE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TRIGGER tas_credential_scopes_no_delete
BEFORE DELETE ON tas_credential_scopes
BEGIN SELECT RAISE(ABORT, 'credential scopes are immutable'); END;

CREATE TABLE tas_memory_promotions (
    memory_id TEXT PRIMARY KEY REFERENCES tas_team_memories(id) ON DELETE RESTRICT,
    recorded_at TEXT NOT NULL CHECK (substr(recorded_at,-6)='+00:00')
);

CREATE TRIGGER tas_memory_promotions_validate_insert
BEFORE INSERT ON tas_memory_promotions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
        FROM tas_team_memories memory
        JOIN tas_work_record_submissions submission
          ON submission.work_record_id=memory.source_work_record_id
        JOIN tas_work_records record ON record.id=memory.source_work_record_id
        JOIN tas_tasks task ON task.id=memory.task_id
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents actor ON actor.id=memory.source_actor_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=actor.owner_id
        JOIN tas_team_memory_code_scopes scope ON scope.memory_id=memory.id
        JOIN tas_repository_bindings binding
          ON binding.repository=scope.repository AND binding.project_id=task.project_id
        JOIN tas_observed_evidence evidence
          ON evidence.id=scope.source_evidence_id AND evidence.kind='git'
        JOIN tas_evidence_submissions evidence_submission
          ON evidence_submission.id=evidence.id
         AND evidence_submission.status='finalized'
        WHERE memory.id=NEW.memory_id
          AND memory.source_actor_agent_id=record.actor_agent_id
          AND memory.promoted_by_agent_id=record.actor_agent_id
          AND memory.task_id=record.task_id
          AND task.assignee_agent_id=record.actor_agent_id
          AND memory.record_type=record.record_type
          AND memory.content=record.claim_text
          AND memory.validation_status='validated'
          AND memory.applicability_status='unknown'
          AND memory.promotion_rule_id='validated_work_record_v1'
          AND memory.promoted_at=NEW.recorded_at
          AND evidence.task_id=memory.task_id
          AND evidence.actor_agent_id=memory.source_actor_agent_id
          AND json_valid(evidence.payload_json)
          AND json_extract(evidence.payload_json,'$.repository')=scope.repository
          AND json_extract(evidence.payload_json,'$.branch')=scope.ref
          AND json_extract(evidence.payload_json,'$.head_commit')=scope.commit_id
          AND json_type(evidence.payload_json,'$.files')='array'
          AND (
              SELECT count(*) FROM tas_team_memory_code_paths path
              WHERE path.memory_id=memory.id
          )=json_array_length(evidence.payload_json,'$.files')
          AND NOT EXISTS (
              SELECT 1 FROM json_each(evidence.payload_json,'$.files') item
              WHERE json_type(item.value,'$.path')<>'text'
                 OR NOT EXISTS (
                     SELECT 1 FROM tas_team_memory_code_paths path
                     WHERE path.memory_id=memory.id
                       AND path.path=json_extract(item.value,'$.path')
                 )
          )
          AND EXISTS (
              SELECT 1 FROM tas_team_memory_evidence link
              WHERE link.memory_id=memory.id AND link.evidence_id=evidence.id
          )
          AND EXISTS (
              SELECT 1 FROM tas_epistemic_events event
              WHERE event.id=memory.source_validation_event_id
                AND event.work_record_id=memory.source_work_record_id
                AND event.to_status='validated'
                AND event.rule_id=memory.validation_rule_id
                AND event.id=(
                    SELECT latest.id FROM tas_epistemic_events latest
                    WHERE latest.work_record_id=memory.source_work_record_id
                    ORDER BY latest.sequence DESC LIMIT 1
                )
          )
          AND NOT EXISTS (
              SELECT 1 FROM tas_epistemic_event_evidence event_link
              WHERE event_link.epistemic_event_id=memory.source_validation_event_id
                AND NOT EXISTS (
                    SELECT 1 FROM tas_team_memory_evidence memory_link
                    WHERE memory_link.memory_id=memory.id
                      AND memory_link.sequence=event_link.sequence
                      AND memory_link.evidence_id=event_link.evidence_id
                )
          )
          AND NOT EXISTS (
              SELECT 1 FROM tas_team_memory_evidence memory_link
              WHERE memory_link.memory_id=memory.id
                AND NOT EXISTS (
                    SELECT 1 FROM tas_epistemic_event_evidence event_link
                    WHERE event_link.epistemic_event_id=memory.source_validation_event_id
                      AND event_link.sequence=memory_link.sequence
                      AND event_link.evidence_id=memory_link.evidence_id
                )
          )
    ) THEN RAISE(ABORT, 'memory promotion is not authoritative') END;
END;

CREATE TRIGGER tas_memory_promotions_no_update
BEFORE UPDATE ON tas_memory_promotions
BEGIN SELECT RAISE(ABORT, 'memory promotion is immutable'); END;

CREATE TRIGGER tas_memory_promotions_no_delete
BEFORE DELETE ON tas_memory_promotions
BEGIN SELECT RAISE(ABORT, 'memory promotion is immutable'); END;

CREATE TRIGGER tas_team_memory_evidence_no_insert_after_promotion
BEFORE INSERT ON tas_team_memory_evidence
WHEN EXISTS (SELECT 1 FROM tas_memory_promotions WHERE memory_id=NEW.memory_id)
BEGIN SELECT RAISE(ABORT, 'memory evidence is finalized'); END;

CREATE TRIGGER tas_memory_code_scope_no_insert_after_promotion
BEFORE INSERT ON tas_team_memory_code_scopes
WHEN EXISTS (SELECT 1 FROM tas_memory_promotions WHERE memory_id=NEW.memory_id)
BEGIN SELECT RAISE(ABORT, 'memory code scope is finalized'); END;

CREATE TRIGGER tas_memory_code_path_no_insert_after_promotion
BEFORE INSERT ON tas_team_memory_code_paths
WHEN EXISTS (SELECT 1 FROM tas_memory_promotions WHERE memory_id=NEW.memory_id)
BEGIN SELECT RAISE(ABORT, 'memory code scope is finalized'); END;
