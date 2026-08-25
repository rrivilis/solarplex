-- Session invites: redemption-gated membership grants.
--
-- Redeeming an invite always performs exactly one thing uniformly: a
-- session_memberships row (attribute grant — role, escalation config).
-- Minting a session_tokens cap is a strictly optional, second-order grant,
-- staged here only as a request the redemption handler may separately act
-- on. These stay two different tables and two different writes at
-- redemption time; see db::invites::{MembershipGrant, CapGrant} and
-- routes::invites::redeem.
--
-- Trust boundary: invitee_email answers "is this the person the inviter
-- meant to invite?" — checked against the OIDC-verified email on the
-- redeeming actor (crates/server/src/auth.rs::oidc_callback), never a
-- self-asserted value. A NULL invitee_email is an anonymous link invite:
-- any authenticated identity may redeem it. See migration 009's note — OIDC
-- answers "who are you", membership/authority stay separate layers.
CREATE TABLE session_invites (
    id                  TEXT        PRIMARY KEY,               -- opaque ULID, the invite token
    session_id          TEXT        NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    invited_by          TEXT        NOT NULL REFERENCES actors(id),
    role                TEXT        NOT NULL CHECK (role IN ('owner', 'collaborator', 'observer')),
    escalation_order    INT,
    escalation_timeout  INT,

    invitee_email       TEXT,                                  -- NULL = anonymous link invite

    -- Optional, second-order cap request. Both NULL = redemption grants
    -- membership only, no cap minted (the common case today — see the
    -- module doc comment in crates/db/src/invites.rs for why).
    cap_permissions     JSONB,
    cap_ttl_secs        BIGINT,

    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    redeemed_at         TIMESTAMPTZ,                           -- NULL = not yet redeemed
    redeemed_by         TEXT        REFERENCES actors(id),
    revoked_at          TIMESTAMPTZ                            -- pre-redemption cancellation
);

CREATE INDEX session_invites_session_id ON session_invites(session_id);
-- Sweep/lookup of invites still awaiting redemption.
CREATE INDEX session_invites_pending ON session_invites(expires_at)
    WHERE redeemed_at IS NULL AND revoked_at IS NULL;
