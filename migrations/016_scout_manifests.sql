-- 016_scout_manifests.sql
--
-- Adds runahead scout columns to approval_requests.
--
-- The scout speculatively executes a Ring-2 shell command during the human
-- approval window, capturing file/network/subprocess effects under strace(1).
-- The execution_manifest records what actually happened post-execution.
-- manifest_diverged is true when the two differ — a persistent security signal.
--
-- Ring-2 invariant: the human approval decision is always authoritative.
-- Divergence is a detection signal, not a prevention gate.

ALTER TABLE approval_requests
    ADD COLUMN scout_manifest     JSONB,
    ADD COLUMN execution_manifest JSONB,
    ADD COLUMN manifest_diverged  BOOLEAN;

-- Fast lookup for security event queries (diverged approvals per session).
CREATE INDEX idx_approval_requests_diverged
    ON approval_requests (session_id)
    WHERE manifest_diverged = true;
