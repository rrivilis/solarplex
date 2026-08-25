-- session_link_invites.redeemed_by_session was missing ON DELETE CASCADE,
-- inconsistent with source_session_id on the same table (both reference
-- sessions, the aggregate root that cascades everywhere else —
-- session_memberships, approval_requests, etc.). redeemed_by_actor is left
-- alone: session_invites.redeemed_by sets no cascade on its actor FK either
-- (actors are never hard-deleted in this app), so this keeps the same
-- convention rather than introducing a new one.
ALTER TABLE session_link_invites
    DROP CONSTRAINT session_link_invites_redeemed_by_session_fkey,
    ADD CONSTRAINT session_link_invites_redeemed_by_session_fkey
        FOREIGN KEY (redeemed_by_session) REFERENCES sessions(id) ON DELETE CASCADE;
