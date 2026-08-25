-- 011_epoch_revocation.sql
--
-- Epoch-based capability revocation system.
--
-- CONCEPTS
-- ════════
-- epoch    — per-session generation counter.  Increments when a revocation
--            closes the current generation.  All caps carry the epoch they were
--            issued in; fencing compares the cap's epoch against the current one.
--
-- stratum  — delegation depth.  0 = root (human-issued cap).  Each delegation
--            hop adds 1.  Auto-computed on cap INSERT from parent's stratum + 1.
--            Stratum-based revocation closes all caps at depth ≥ threshold.
--
-- REVOCATION STRATEGIES
-- ═════════════════════
-- cap      — prune the subtree rooted at a specific cap (recursive CTE).
-- stratum  — revoke all caps with stratum ≥ threshold in the current epoch.
-- epoch    — close the entire current generation (revoke every active cap in
--            the session's current epoch).
--
-- DRAIN-BOUNDED LIVENESS
-- ══════════════════════
-- Agents that have already observed seq ≤ drain_seq at revocation time are
-- given a wall-clock grace window (drain_deadline) to complete in-flight work.
-- After drain_deadline, fencing rejects their writes with WS close 4401.
--
-- REROOTING
-- ══════════
-- When a subtree is pruned, surviving children (non-revoked descendants of the
-- revoked node) can optionally be rerooted: their parent_cap pointer is updated
-- to point to the revoked node's parent, preserving attenuation invariant.

-- ── session_tokens extensions ─────────────────────────────────────────────────

ALTER TABLE session_tokens
    -- The epoch in which this cap was issued.  0 = pre-epoch-system baseline.
    ADD COLUMN epoch      BIGINT      NOT NULL DEFAULT 0,
    -- Delegation depth: 0 = root, N = Nth-generation delegate.
    -- Computed from the parent cap's stratum + 1 at INSERT time.
    ADD COLUMN stratum    BIGINT      NOT NULL DEFAULT 0,
    -- Set when this specific cap (or its entire epoch/stratum) was revoked.
    ADD COLUMN revoked_at TIMESTAMPTZ;

-- Fast index for stratum-based revocation and active-cap queries.
CREATE INDEX session_tokens_epoch_stratum
    ON session_tokens (session_id, epoch, stratum)
    WHERE revoked_at IS NULL;

-- ── session_epochs ────────────────────────────────────────────────────────────

CREATE TABLE session_epochs (
    session_id TEXT        PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    epoch      BIGINT      NOT NULL    DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL    DEFAULT NOW()
);

-- Seed initial epoch rows for all existing sessions so they participate in the
-- epoch system without needing a data migration.
INSERT INTO session_epochs (session_id)
SELECT id FROM sessions
ON CONFLICT DO NOTHING;

-- ── cap_revocations ───────────────────────────────────────────────────────────

CREATE TABLE cap_revocations (
    id              TEXT        PRIMARY KEY,
    session_id      TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- Which strategy was used.
    strategy        TEXT        NOT NULL CHECK (strategy IN ('cap', 'stratum', 'epoch')),
    -- strategy = 'cap': the subtree root that was revoked.
    target_cap_id   TEXT,
    -- strategy = 'stratum': the depth threshold (all caps with stratum >= this
    -- value in the closed epoch were revoked).
    target_stratum  BIGINT,
    -- The committed event seq at the moment revocation fired.  Agents that had
    -- observed seq <= drain_seq are eligible for the drain grace window.
    drain_seq       BIGINT      NOT NULL,
    -- Wall-clock deadline for the drain window.  After this instant, fenced
    -- connections are closed with WS code 4401.
    drain_deadline  TIMESTAMPTZ NOT NULL,
    -- The epoch that was closed by this revocation event.
    closed_epoch    BIGINT      NOT NULL,
    -- The new epoch that became active after revocation.
    new_epoch       BIGINT      NOT NULL,
    revoked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The actor who triggered the revocation.
    revoked_by      TEXT        NOT NULL REFERENCES actors(id)
);

CREATE INDEX cap_revocations_session
    ON cap_revocations (session_id, revoked_at DESC);
