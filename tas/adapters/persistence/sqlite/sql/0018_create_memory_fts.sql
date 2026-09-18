CREATE VIRTUAL TABLE tas_team_memories_fts USING fts5(
    content,
    content='tas_team_memories',
    content_rowid='rowid',
    tokenize='unicode61'
);
INSERT INTO tas_team_memories_fts(rowid,content)
SELECT rowid,content FROM tas_team_memories;
CREATE TRIGGER tas_team_memories_fts_insert AFTER INSERT ON tas_team_memories BEGIN
    INSERT INTO tas_team_memories_fts(rowid,content) VALUES(new.rowid,new.content);
END;
