-- Session-to-session linking. Two mechanisms, one destination table:
--   1. Mint-a-link-invite + redeem (mirrors session_invites exactly — the
--      invite's own ULID id IS the bearer token, no separate hash column,
--      same as session_invites' /invite/{id} pattern).
--   2. Direct link when the same actor already holds Owner|Collaborator in
--      both sessions (the "admin fast path" — no invite round trip).
--
-- A link is an authorization relationship, not a data copy: once linked
-- (visibility='full'), a member of either session gets lazily auto-granted
-- real Observer membership in the other the first time they actually try to
-- access it (see db::sessions::require_membership_or_linked_access) — after
-- that everything (WS live connection, REST reads, historical events,
-- artifacts, approval visibility) works through the exact same membership
-- checks every other session-scoped endpoint already uses. No new replay or
-- mirroring machinery, no separate durability story: Postgres already is
-- the durable log via session_memberships/events, for free.
CREATE TABLE session_link_invites (
    id                  TEXT PRIMARY KEY,          -- also the bearer token
    source_session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    invited_by          TEXT NOT NULL REFERENCES actors(id),
    expires_at          TIMESTAMPTZ NOT NULL,
    redeemed_by_session TEXT REFERENCES sessions(id),
    redeemed_by_actor   TEXT REFERENCES actors(id),
    redeemed_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX session_link_invites_source ON session_link_invites(source_session_id);

CREATE TABLE session_links (
    id           TEXT PRIMARY KEY,
    -- Canonical ordering (session_a < session_b, enforced by the app layer
    -- before insert, checked here) so an A-B link and a B-A link can never
    -- both exist as distinct rows.
    session_a    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    session_b    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    linked_by    TEXT NOT NULL REFERENCES actors(id),
    -- 'full' = default-visible per the product decision; 'muted' is the
    -- admin's one-lever opt-out. v1 note: muting stops *new* auto-grants via
    -- this link — it does not retroactively revoke Observer memberships
    -- already auto-provisioned before the mute.
    visibility   TEXT NOT NULL DEFAULT 'full' CHECK (visibility IN ('full', 'muted')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (session_a < session_b),
    UNIQUE (session_a, session_b)
);

CREATE INDEX session_links_a ON session_links(session_a);
CREATE INDEX session_links_b ON session_links(session_b);
