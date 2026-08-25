-- Cross-session approval delegation: session A asks session B to decide on
-- A's approval. Reuses the saga/reflector machinery for the cross-session
-- hop (crates/session's SessionSaga::Custom + Effect::Bundle), but the
-- decision itself is a completely normal ApprovalRequest created in B,
-- decided via B's own approval_policy unchanged — same dual-row pattern the
-- ORB path already uses (orb_approval_id + a linked second row), just
-- crossing a session boundary instead of staying in-process.
--
-- Not a SessionMemory field: this must survive independent of any one
-- process's in-memory state, same reasoning as session_remotes' watermark.
CREATE TABLE cross_session_delegations (
    saga_id             TEXT PRIMARY KEY,
    source_session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    source_approval_id  TEXT NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    target_session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    -- NULL until the Step bundle lands and session_task.rs creates the real
    -- local approval in B (the pure session-crate machine can't itself do
    -- that async DB insert — see CrossSessionDelegationReceived's doc comment).
    target_approval_id  TEXT REFERENCES approval_requests(id),
    status               TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved', 'expired')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX cross_session_delegations_target_approval ON cross_session_delegations(target_approval_id);
CREATE INDEX cross_session_delegations_source ON cross_session_delegations(source_session_id);
