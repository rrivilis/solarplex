-- Connection audit trail — deliberately separate from the `events` table.
-- Precedent: tmux has no concept of "who attached when" as part of a
-- session's own content (`tmux list-clients` is a live query, not a log);
-- Slack/Discord presence is a live pub/sub signal, never written into
-- channel history. This table is the durable half of that split — every
-- WS connect/disconnect is recorded here (append-only, one row per
-- transition) but never touches `events`/`seq`/session_snapshots, so it
-- can't flood the Activity Log or Messages feed the way it used to when
-- ordinary reconnects were persisted as `actor.joined`/`actor.detached`
-- events. A genuinely new membership grant (invite redemption, add_member)
-- still gets a real event — this table is for connection lifecycle only.
CREATE TABLE session_connections (
    id         TEXT        PRIMARY KEY,
    session_id TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_id   TEXT        NOT NULL REFERENCES actors(id),
    event      TEXT        NOT NULL CHECK (event IN ('connected', 'disconnected')),
    at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX session_connections_session ON session_connections(session_id, at);
CREATE INDEX session_connections_actor   ON session_connections(actor_id, at);
