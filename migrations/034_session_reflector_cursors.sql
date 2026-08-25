-- Durable per-session watermark into the in-memory reflector log
-- (crates/server/src/reflector.rs), so a respawned session_task doesn't
-- redeliver a cross-session bundle it already drained in a previous
-- lifetime. A session_task exists only while at least one client is
-- attached to that session -- it can be dropped and respawned many times
-- across a single server's uptime without the server itself restarting,
-- and each respawn would otherwise re-drain the *entire* reflector log
-- from scratch, re-injecting bundles the session already fully processed
-- (there is no bundle_id dedup in the session state machine to catch this
-- downstream -- see crates/server/src/session_task.rs's
-- drain_reflector_backlog for the full reasoning).
--
-- Meaningless across an actual server restart -- the reflector's own log
-- doesn't survive one either -- but harmless then too: a fresh reflector's
-- log is empty, so replaying any persisted cursor against it just returns
-- nothing, same as starting from zero would.
CREATE TABLE session_reflector_cursors (
    session_id TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    seq        BIGINT NOT NULL DEFAULT 0,
    epoch      INT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
