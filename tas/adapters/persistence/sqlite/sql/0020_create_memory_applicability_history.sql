CREATE TABLE tas_memory_applicability_assessments (
    id TEXT PRIMARY KEY,
    memory_id TEXT NOT NULL REFERENCES tas_team_memory_code_scopes(memory_id),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    previous_assessment_id TEXT REFERENCES tas_memory_applicability_assessments(id),
    status TEXT NOT NULL CHECK(status IN ('exact','compatible','possibly_stale','unknown')),
    reason TEXT NOT NULL CHECK(reason IN ('exact_commit','scoped_paths_unchanged','scoped_paths_changed','repository_mismatch','ref_mismatch','invalid_worktree','memory_commit_missing','memory_commit_not_ancestor','worktree_changed_during_check','git_check_failed')),
    memory_commit TEXT NOT NULL CHECK(length(memory_commit) IN (40,64)),
    current_commit TEXT CHECK(current_commit IS NULL OR length(current_commit) IN (40,64)),
    checked_at TEXT NOT NULL,
    CHECK((status='exact' AND reason='exact_commit' AND current_commit=memory_commit)
       OR (status='compatible' AND reason='scoped_paths_unchanged' AND current_commit IS NOT NULL AND current_commit<>memory_commit)
       OR (status='possibly_stale' AND reason='scoped_paths_changed' AND current_commit IS NOT NULL)
       OR (status='unknown' AND reason IN ('repository_mismatch','ref_mismatch','invalid_worktree','memory_commit_missing','memory_commit_not_ancestor','worktree_changed_during_check','git_check_failed'))),
    UNIQUE(memory_id,sequence),
    UNIQUE(memory_id,previous_assessment_id)
);
CREATE TABLE tas_memory_applicability_changed_paths (
    assessment_id TEXT NOT NULL REFERENCES tas_memory_applicability_assessments(id),
    sequence INTEGER NOT NULL CHECK(sequence > 0),
    path TEXT NOT NULL,
    PRIMARY KEY(assessment_id,sequence), UNIQUE(assessment_id,path)
);
CREATE TRIGGER tas_memory_applicability_no_update BEFORE UPDATE ON tas_memory_applicability_assessments BEGIN SELECT RAISE(ABORT,'memory applicability is immutable'); END;
CREATE TRIGGER tas_memory_applicability_no_delete BEFORE DELETE ON tas_memory_applicability_assessments BEGIN SELECT RAISE(ABORT,'memory applicability is immutable'); END;
CREATE TRIGGER tas_memory_applicability_paths_no_update BEFORE UPDATE ON tas_memory_applicability_changed_paths BEGIN SELECT RAISE(ABORT,'memory applicability path is immutable'); END;
CREATE TRIGGER tas_memory_applicability_paths_no_delete BEFORE DELETE ON tas_memory_applicability_changed_paths BEGIN SELECT RAISE(ABORT,'memory applicability path is immutable'); END;
