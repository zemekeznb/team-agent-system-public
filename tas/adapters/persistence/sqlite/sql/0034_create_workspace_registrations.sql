CREATE TABLE tas_workspace_registrations (
    workspace_id TEXT PRIMARY KEY REFERENCES tas_task_workspace_bindings(id)
        ON DELETE RESTRICT,
    registered_at TEXT NOT NULL CHECK (substr(registered_at,-6)='+00:00')
);

CREATE TRIGGER tas_workspace_registrations_insert_guard
BEFORE INSERT ON tas_workspace_registrations
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM tas_task_workspace_bindings workspace
        JOIN tas_tasks task ON task.id=workspace.task_id
        JOIN tas_projects project ON project.id=task.project_id
        JOIN tas_agents actor ON actor.id=workspace.actor_agent_id
        JOIN tas_team_memberships member
          ON member.team_id=project.team_id AND member.owner_id=actor.owner_id
        JOIN tas_repository_bindings repository
          ON repository.repository=workspace.repository
         AND repository.project_id=project.id
        WHERE workspace.id=NEW.workspace_id
          AND task.assignee_agent_id=workspace.actor_agent_id
          AND workspace.bound_at=NEW.registered_at
    ) THEN RAISE(ABORT, 'Workspace registration is not authorized') END;
END;

CREATE TRIGGER tas_workspace_registrations_no_update
BEFORE UPDATE ON tas_workspace_registrations
BEGIN SELECT RAISE(ABORT, 'Workspace registration is immutable'); END;

CREATE TRIGGER tas_workspace_registrations_no_delete
BEFORE DELETE ON tas_workspace_registrations
BEGIN SELECT RAISE(ABORT, 'Workspace registration is immutable'); END;

CREATE TRIGGER tas_evidence_submissions_workspace_registration_guard
BEFORE INSERT ON tas_evidence_submissions
WHEN NOT EXISTS (
    SELECT 1 FROM tas_workspace_registrations
    WHERE workspace_id=NEW.workspace_id
)
BEGIN
    SELECT RAISE(ABORT, 'Evidence requires a registered Workspace');
END;
