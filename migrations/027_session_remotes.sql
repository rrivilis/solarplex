-- Git-remote-style fetch between sessions: a durable, directional pointer
-- with a watermark cursor, distinct from session_links (which is symmetric/
-- unordered and has no cursor concept). Deliberately NOT built on the
-- reflector (crates/server/src/reflector.rs) — that's in-memory only,
-- single-process, and dies on restart; this needs to survive a restart.
--
-- Adding a remote grants nothing by itself (same principle as `git remote
-- add` against a URL you may not yet have access to) — authorization is
-- checked at fetch time against the remote session, not at add time. Fetch
-- never writes into the local session's own event log: fetched content is
-- displayed, never copied, same non-copying principle as session digests.
CREATE TABLE session_remotes (
    id                TEXT PRIMARY KEY,
    local_session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    remote_session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    added_by          TEXT NOT NULL REFERENCES actors(id),
    last_fetched_seq  BIGINT NOT NULL DEFAULT 0,
    last_fetched_at   TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (local_session_id, remote_session_id)
);

CREATE INDEX session_remotes_local ON session_remotes(local_session_id);
