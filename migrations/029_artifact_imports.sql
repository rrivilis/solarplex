-- Cross-session artifact import — a publish/import operation, not a live
-- reference: the imported artifact is a genuine independent copy in the
-- target session from the moment it's created (ceases to be shared mutable
-- state immediately — editing either copy afterward never touches the
-- other). This is the audit trail / receipt for that operation; it carries
-- no live authorization meaning of its own — deleting or unlinking the
-- source session afterward does not retract or invalidate the copy already
-- made (revocation semantics apply going forward, not retroactively to a
-- completed, independent copy).
--
-- Authority does not travel with the import: importing requires standing
-- read access to the source (Observer, via the normal linked-access check)
-- and Collaborator+ in the target (the same bar any artifact creation
-- needs) — nothing about this table itself grants anything.
CREATE TABLE artifact_imports (
    id                  TEXT PRIMARY KEY,          -- the receipt id
    source_session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    source_artifact_id  TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    source_event_seq    BIGINT,                     -- source session's cursor at export time (best-effort)
    target_session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_artifact_id  TEXT NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    content_hash        TEXT NOT NULL,              -- sha256 of the copied content
    published_by        TEXT NOT NULL REFERENCES actors(id),  -- original artifact's own author
    published_at        TIMESTAMPTZ NOT NULL,        -- original artifact's own created_at
    imported_by         TEXT NOT NULL REFERENCES actors(id),  -- who performed this import
    imported_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    session_link_id     TEXT REFERENCES session_links(id)      -- which link this flowed through, for the audit note
);

CREATE INDEX artifact_imports_target ON artifact_imports(target_artifact_id);
CREATE INDEX artifact_imports_source ON artifact_imports(source_artifact_id);
