-- Human OIDC sessions.
--
-- Maps an OIDC (sub, provider) identity pair to a Solarplex actor_id and
-- stores opaque Solarplex session tokens for WebSocket authentication.
--
-- These are distinct from session_tokens (agent caps):
--   - human_sessions are longer-lived (7-day default) and multi-use
--   - session_tokens are single-use attach tokens for agents
--
-- Trust boundary: OIDC answers "who are you?".
-- Authorization (what you can do) is handled by the cap DAG.
-- These two layers must remain separate.

CREATE TABLE human_sessions (
    id          TEXT        PRIMARY KEY,            -- opaque Solarplex token (ULID)
    actor_id    TEXT        NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    sub         TEXT        NOT NULL,               -- OIDC subject claim
    provider    TEXT        NOT NULL,               -- "google", "github", "microsoft", etc.
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    last_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One actor can have multiple concurrent sessions (e.g. two browsers, two devices).
CREATE INDEX human_sessions_actor   ON human_sessions(actor_id);
-- Look up existing actor_id by OIDC identity (used during callback to avoid duplicate actors).
CREATE INDEX human_sessions_sub     ON human_sessions(sub, provider);
-- Sweep expired sessions (background job or lazy cleanup).
CREATE INDEX human_sessions_expires ON human_sessions(expires_at);
