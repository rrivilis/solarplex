-- Session-scoped attach tokens for agent onboarding.
-- Issued by the UI "Attach Agent" button; exchanged once by the sidecar at startup.
CREATE TABLE IF NOT EXISTS session_tokens (
    id          TEXT        PRIMARY KEY,                -- ULID, the opaque token value
    session_id  TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_id    TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ,                            -- NULL = not yet exchanged
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS session_tokens_session_id ON session_tokens(session_id);
