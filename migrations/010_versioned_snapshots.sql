-- 010_versioned_snapshots.sql
--
-- Replace the single-row-per-session UPSERT snapshot with INSERT-only versioned
-- rows.  Each committed event now produces a new snapshot row instead of
-- clobbering the previous one.
--
-- Benefits:
--   * Full audit trail: every snapshot version is inspectable
--   * Enables write-behind/lazy shadow page on epoch revocation (dirty flag)
--   * Snapshot rows become first-class inspectable objects (clickable in sp plumb)
--   * Simplifies concurrent write paths (no UPDATE contention on a hot row)

DROP TABLE IF EXISTS session_snapshots;

CREATE TABLE session_snapshots (
    -- ULID primary key; generated server-side so it sorts chronologically.
    id              TEXT        PRIMARY KEY,
    session_id      TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- The event seq this snapshot was produced at.
    seq             BIGINT      NOT NULL,
    -- Materialized projection of all events up to seq.
    state           JSONB       NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- dirty = TRUE when an epoch revocation invalidated this snapshot row.
    -- The stored state is still present (it is the pre-revocation projection),
    -- but a cold-attach MUST rebuild from fact tables rather than trusting this
    -- state for authorization decisions.
    dirty           BOOLEAN     NOT NULL DEFAULT FALSE,
    -- Set when dirty = TRUE.  The event seq at which the epoch revocation fired.
    -- Used to find the last clean baseline during lazy recompute.
    stale_since_seq BIGINT
);

-- Primary read: latest snapshot for a session (most recent seq first).
CREATE INDEX session_snapshots_session_latest
    ON session_snapshots (session_id, seq DESC);

-- Secondary read: latest CLEAN snapshot — used during dirty recompute to find
-- the last good baseline rather than replaying from seq 0 every time.
CREATE INDEX session_snapshots_session_clean
    ON session_snapshots (session_id, seq DESC)
    WHERE dirty = FALSE;
