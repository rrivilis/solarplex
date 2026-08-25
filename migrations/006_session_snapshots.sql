-- Durable session projection.
-- Updated atomically inside the same transaction as every event INSERT.
-- Cold WS attach reads this single row instead of 5 concurrent queries.
CREATE TABLE IF NOT EXISTS session_snapshots (
    session_id  TEXT        PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    seq         BIGINT      NOT NULL DEFAULT 0,
    state       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed one row per existing session so cold attaches never get NotFound.
INSERT INTO session_snapshots (session_id, seq, state)
SELECT id, 0, '{}'::jsonb
FROM sessions
ON CONFLICT (session_id) DO NOTHING;
