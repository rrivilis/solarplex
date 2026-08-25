-- 012_orb.sql  —  Object Request Broker: method registry + execution receipts
--
-- Restructures the agent tool-call trust boundary so that authorization
-- decisions live in the server rather than the sidecar.  Three additions:
--
-- 1. mcp_methods     — typed method registry per session/actor.  The sidecar
--                      registers its tool manifest at attach time; the server
--                      validates method addresses in cap permissions against it.
--
-- 2. execution_receipts — single-use, server-issued authorization tokens that
--                      bind a specific (method, args) pair to an approved cap.
--                      The sidecar fetches the receipt by ID and MUST execute
--                      the server's stored args verbatim — closing the post-
--                      approval args-swap gap.
--
-- Relationship to authority-arena (migration 011):
--   cap.permissions  now contains method addresses ("mcp.{slug}.{method}")
--   rather than free tool name strings.  The ORB validates every invocation
--   against the cap's typed method set before issuing a receipt.
--   The cap DAG's attenuation invariant now applies to typed addresses:
--   a delegate cannot hold an address its parent does not hold.

-- ── Method registry ───────────────────────────────────────────────────────────

CREATE TABLE mcp_methods (
    id              TEXT        PRIMARY KEY,
    session_id      TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- Normalized actor_id of the registering sidecar.  Becomes the first
    -- component of the method address: "mcp.{server_slug}.{method_name}".
    server_slug     TEXT        NOT NULL,
    method_name     TEXT        NOT NULL,
    -- Full typed address used in cap permissions arrays.
    address         TEXT        NOT NULL,
    -- JSON Schema for the method's input arguments.  Used for structural
    -- validation in the invoke endpoint before authorization.
    arg_schema      JSONB       NOT NULL DEFAULT '{}',
    description     TEXT,
    -- If FALSE, the server auto-approves the invocation (equivalent to the
    -- sidecar's legacy auto_approve list, but now server-side and auditable).
    requires_approval BOOLEAN   NOT NULL DEFAULT TRUE,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- One address per session per sidecar — re-registration is an upsert.
    UNIQUE (session_id, address)
);

CREATE INDEX mcp_methods_session_address ON mcp_methods (session_id, address);
CREATE INDEX mcp_methods_server_slug     ON mcp_methods (session_id, server_slug);

-- ── Execution receipts ────────────────────────────────────────────────────────

CREATE TABLE execution_receipts (
    id          TEXT        PRIMARY KEY,
    cap_id      TEXT        NOT NULL REFERENCES session_tokens(id) ON DELETE CASCADE,
    session_id  TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- Full method address (matches mcp_methods.address).
    method      TEXT        NOT NULL,
    -- Server-canonical args JSON — authoritative.  The sidecar MUST execute
    -- with these args, not its own copy, to close the post-approval args-swap gap.
    args        JSONB       NOT NULL,
    issued_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMPTZ NOT NULL,
    -- Set atomically when the sidecar consumes the receipt (verify + mark used).
    -- NULL = available; non-NULL = already consumed (single-use).
    used_at     TIMESTAMPTZ,
    -- Non-null when the invocation went through the human approval gate.
    approval_id TEXT
);

CREATE INDEX execution_receipts_cap     ON execution_receipts (cap_id, issued_at DESC);
-- Partial index on live (unconsumed) receipts — used by expiry GC.
CREATE INDEX execution_receipts_live    ON execution_receipts (expires_at)
    WHERE used_at IS NULL;
