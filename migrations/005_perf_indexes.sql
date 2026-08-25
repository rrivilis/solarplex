-- Performance indexes added after profiling.
--
-- session_memberships has no index on session_id.  Every list_memberships call
-- (snapshot build, vote eligibility check) does a sequential scan.  At small
-- membership counts this is fine, but we add the index proactively.
CREATE INDEX IF NOT EXISTS idx_memberships_session
    ON session_memberships (session_id);

-- Partial index for pending approvals — list_pending only reads non-terminal
-- states.  The existing approval_requests_session_state index covers
-- (session_id, state) but listing all pending/claimed/contested for a session
-- hits three equality conditions; this partial index is cheaper.
CREATE INDEX IF NOT EXISTS idx_approvals_session_pending
    ON approval_requests (session_id)
    WHERE state IN ('Pending', 'Claimed', 'Contested');
