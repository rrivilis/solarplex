-- 018_ring2_sandbox.sql
--
-- Adds declared_effects to approval_requests.
--
-- The Ring-2 runahead scout promotes its predicted effects to a
-- declared set after the human-visible scout manifest is stored.
-- The sidecar executor derives its sandbox policy (bwrap mounts,
-- seccomp denylist, landlock rules) exclusively from this field —
-- no out-of-band configuration, no drift between approval and enforcement.
--
-- Populated by PATCH /api/approvals/:id/declared-effects immediately
-- after the scout manifest is stored (before the human votes).

ALTER TABLE approval_requests
    ADD COLUMN declared_effects JSONB;
