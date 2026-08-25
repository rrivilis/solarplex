-- actors: humans and agents as first-class participants
CREATE TABLE actors (
    id           TEXT        PRIMARY KEY,
    type         TEXT        NOT NULL CHECK (type IN ('human', 'agent')),
    name         TEXT        NOT NULL,
    -- human fields
    email        TEXT,
    -- agent fields
    provider     TEXT        CHECK (provider IN ('anthropic', 'openai', 'gemini', 'custom')),
    model        TEXT,
    config       JSONB,      -- { tool_policy, approval_policy, max_turns }
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- sessions: root object, persists beyond any individual actor
CREATE TABLE sessions (
    id           TEXT        PRIMARY KEY,
    name         TEXT        NOT NULL,
    description  TEXT,
    status       TEXT        NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'archived')),
    created_by   TEXT        NOT NULL REFERENCES actors(id),
    approval_policy TEXT     NOT NULL DEFAULT 'single_vote' CHECK (approval_policy IN ('single_vote', 'majority', 'unanimous')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- session_memberships: role + escalation config per actor per session
CREATE TABLE session_memberships (
    id                  TEXT        PRIMARY KEY,
    session_id          TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_id            TEXT        NOT NULL REFERENCES actors(id),
    role                TEXT        NOT NULL CHECK (role IN ('owner', 'collaborator', 'observer', 'agent')),
    escalation_order    INT,
    escalation_timeout  INT,        -- seconds
    joined_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    detached_at         TIMESTAMPTZ,
    UNIQUE (session_id, actor_id)
);

-- events: append-only causal log, never updated
CREATE TABLE events (
    id              TEXT        PRIMARY KEY,
    session_id      TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_id        TEXT        NOT NULL REFERENCES actors(id),
    type            TEXT        NOT NULL,
    payload         JSONB       NOT NULL DEFAULT '{}',
    parent_event_id TEXT        REFERENCES events(id),
    seq             BIGINT      NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX events_session_seq ON events (session_id, seq);
CREATE INDEX events_session_type ON events (session_id, type);
CREATE INDEX events_session_timestamp ON events (session_id, timestamp);

-- sequences: per-session event sequence counter
CREATE TABLE session_sequences (
    session_id  TEXT    PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    next_seq    BIGINT  NOT NULL DEFAULT 1
);

-- approval_requests: typed, queryable fact table for pending approvals
CREATE TABLE approval_requests (
    id           TEXT        PRIMARY KEY,
    session_id   TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_id     TEXT        NOT NULL REFERENCES actors(id),  -- the agent
    tool_name    TEXT        NOT NULL,
    arguments    JSONB       NOT NULL DEFAULT '{}',
    state        TEXT        NOT NULL DEFAULT 'Pending'
                             CHECK (state IN ('Pending', 'Claimed', 'Approved', 'Denied', 'Contested', 'Expired')),
    votes        JSONB       NOT NULL DEFAULT '{}',  -- { actor_id: "approve" | "deny" }
    resolved_by  TEXT        REFERENCES actors(id),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    timeout_at   TIMESTAMPTZ,
    resolved_at  TIMESTAMPTZ
);

CREATE INDEX approval_requests_session_state ON approval_requests (session_id, state);
CREATE INDEX approval_requests_actor_state   ON approval_requests (actor_id, state);
CREATE INDEX approval_requests_session_tool  ON approval_requests (session_id, tool_name);
CREATE INDEX approval_requests_timeout       ON approval_requests (timeout_at) WHERE state = 'Pending' OR state = 'Claimed' OR state = 'Contested';

-- artifacts: documents, plans, diffs, reports, etc.
CREATE TABLE artifacts (
    id           TEXT        PRIMARY KEY,
    session_id   TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    created_by   TEXT        NOT NULL REFERENCES actors(id),
    name         TEXT        NOT NULL,
    type         TEXT        NOT NULL CHECK (type IN ('document', 'plan', 'code_diff', 'report', 'prompt', 'spreadsheet', 'other')),
    storage_ref  TEXT        NOT NULL,  -- inline content or blob URL
    version      INT         NOT NULL DEFAULT 1,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX artifacts_session ON artifacts (session_id);
