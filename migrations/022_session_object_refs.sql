-- Cross-session object refs — a thin edge relation, not a new store. Points
-- a target session at a source-session-owned fact by reference
-- (EntityHandle::uri()) rather than duplicating its content, so there is no
-- second source of truth to drift out of sync with the source session's own
-- events. Row is written exactly once, atomically, at approval-resolution
-- time (see crates/server/src/ws.rs::handle_vote) — never at propose time —
-- so there is no "proposed but not yet real" row to race against or clean
-- up on denial.
CREATE TABLE session_object_refs (
    id                 TEXT PRIMARY KEY,
    source_uri         TEXT NOT NULL,   -- EntityHandle::uri(), e.g. "artifact/01J..."
    source_session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    target_session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    proposed_by        TEXT NOT NULL REFERENCES actors(id),
    -- The approval_requests row (synthetic tool_name "cross_session.accept_ref")
    -- whose resolution created this row. Nullable only for schema symmetry with
    -- other FK-to-approval columns elsewhere; every row in practice has one.
    approval_id        TEXT REFERENCES approval_requests(id),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_uri, target_session_id)
);

CREATE INDEX session_object_refs_target ON session_object_refs(target_session_id, created_at DESC);
CREATE INDEX session_object_refs_source ON session_object_refs(source_session_id, created_at DESC);
