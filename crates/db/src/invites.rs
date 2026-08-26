//! Session invites — redemption-gated membership grants.
//!
//! Redemption always performs a `MembershipGrant` (a `session_memberships`
//! row via `sessions::add_member`) — that's the uniform, required outcome.
//! A `CapGrant` (a `session_tokens` row via `tokens::insert`) is minted only
//! if the invite staged one. These are deliberately separate types with no
//! shared fields beyond what's unavoidable: attributes (who you are in this
//! session) and delegated authority (what you're permitted to do) are
//! different axes, and a caller should never be able to construct a value
//! that conflates them. See migration 019 for the schema this backs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct InviteRow {
    pub id: String,
    pub session_id: String,
    pub invited_by: String,
    pub role: String,
    pub escalation_order: Option<i32>,
    pub escalation_timeout: Option<i32>,
    pub invitee_email: Option<String>,
    pub cap_permissions: Option<serde_json::Value>,
    pub cap_ttl_secs: Option<i64>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub redeemed_by: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// The attribute-only half of what redemption grants — exactly what
/// `sessions::add_member` needs. No cap-shaped field exists on this type;
/// it is not possible to construct one that also carries authority.
pub struct MembershipGrant {
    pub role: String,
    pub escalation_order: Option<i32>,
    pub escalation_timeout: Option<i32>,
}

/// The second-order authority half — exactly what `tokens::insert` needs
/// beyond `session_id`/`actor_id`/`observed_seq` (which the redemption
/// handler supplies at call time, not from the invite row). Only ever
/// constructed when an invite actually staged a cap request; caps minted
/// this way are always root (human-issued), never delegated from a parent.
pub struct CapGrant {
    pub permissions: Vec<String>,
    pub ttl_secs: i64,
}

pub struct CreateInvite {
    pub session_id: String,
    pub invited_by: String,
    pub membership: MembershipGrant,
    /// `None` = anonymous link invite, redeemable by any authenticated identity.
    pub invitee_email: Option<String>,
    /// `None` = redemption grants membership only, no cap minted.
    pub cap: Option<CapGrant>,
    /// The invite's own lifetime — independent of `cap.ttl_secs`, which (if
    /// present) times out the cap, not the invite.
    pub ttl_secs: i64,
}

pub async fn create(pool: &PgPool, input: CreateInvite) -> DbResult<InviteRow> {
    let id = Ulid::new().to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(input.ttl_secs);
    let (cap_permissions, cap_ttl_secs) = match &input.cap {
        Some(c) => (
            Some(serde_json::to_value(&c.permissions).map_err(DbError::Json)?),
            Some(c.ttl_secs),
        ),
        None => (None, None),
    };

    sqlx::query_as::<_, InviteRow>(
        "INSERT INTO session_invites
             (id, session_id, invited_by, role, escalation_order, escalation_timeout,
              invitee_email, cap_permissions, cap_ttl_secs, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         RETURNING id, session_id, invited_by, role, escalation_order, escalation_timeout,
                   invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                   redeemed_at, redeemed_by, revoked_at",
    )
    .bind(&id)
    .bind(&input.session_id)
    .bind(&input.invited_by)
    .bind(&input.membership.role)
    .bind(input.membership.escalation_order)
    .bind(input.membership.escalation_timeout)
    .bind(&input.invitee_email)
    .bind(cap_permissions)
    .bind(cap_ttl_secs)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<InviteRow> {
    sqlx::query_as::<_, InviteRow>(
        "SELECT id, session_id, invited_by, role, escalation_order, escalation_timeout,
                invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                redeemed_at, redeemed_by, revoked_at
         FROM session_invites WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Atomically validate and consume an invite in a single query — mirrors
/// `tokens::exchange`'s validate-and-consume pattern so there is no window
/// between "check eligibility" and "mark redeemed" for two concurrent
/// redemption attempts (e.g. a double-click, or a replayed request) to race
/// through and both succeed.
///
/// `actor_email` is the OIDC-verified email of the redeeming identity (may
/// be `None`). A named invite (`invitee_email` set) only matches an equal,
/// non-null `actor_email` — never a self-asserted one, by construction: the
/// caller can only get an email here via `auth::validate_sp_token`.
///
/// Returns `DbError::NotFound` on any disqualifying condition (expired,
/// already redeemed, revoked, wrong email) without distinguishing which —
/// callers that want a specific reason for the caller-facing error should
/// follow up with `get()` and inspect the row.
pub async fn redeem(
    pool: &PgPool,
    id: &str,
    actor_id: &str,
    actor_email: Option<&str>,
) -> DbResult<InviteRow> {
    sqlx::query_as::<_, InviteRow>(
        "UPDATE session_invites
         SET redeemed_at = NOW(), redeemed_by = $2
         WHERE id = $1
           AND redeemed_at IS NULL
           AND revoked_at IS NULL
           AND expires_at > NOW()
           AND (invitee_email IS NULL OR invitee_email = $3)
         RETURNING id, session_id, invited_by, role, escalation_order, escalation_timeout,
                   invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                   redeemed_at, redeemed_by, revoked_at",
    )
    .bind(id)
    .bind(actor_id)
    .bind(actor_email)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn revoke(pool: &PgPool, id: &str) -> DbResult<InviteRow> {
    sqlx::query_as::<_, InviteRow>(
        "UPDATE session_invites
         SET revoked_at = NOW()
         WHERE id = $1 AND redeemed_at IS NULL AND revoked_at IS NULL
         RETURNING id, session_id, invited_by, role, escalation_order, escalation_timeout,
                   invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                   redeemed_at, redeemed_by, revoked_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn list_by_session(pool: &PgPool, session_id: &str) -> DbResult<Vec<InviteRow>> {
    sqlx::query_as::<_, InviteRow>(
        "SELECT id, session_id, invited_by, role, escalation_order, escalation_timeout,
                invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                redeemed_at, redeemed_by, revoked_at
         FROM session_invites WHERE session_id = $1 ORDER BY created_at DESC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Named invites still awaiting redemption for `email` — the backfill sweep
/// run once, on first login, for an actor whose invites arrived before they
/// had an account. Expired/revoked/redeemed invites are excluded; a mailbox
/// entry for a dead invite would be a route to nothing.
pub async fn list_pending_by_email(pool: &PgPool, email: &str) -> DbResult<Vec<InviteRow>> {
    sqlx::query_as::<_, InviteRow>(
        "SELECT id, session_id, invited_by, role, escalation_order, escalation_timeout,
                invitee_email, cap_permissions, cap_ttl_secs, expires_at, created_at,
                redeemed_at, redeemed_by, revoked_at
         FROM session_invites
         WHERE invitee_email = $1 AND redeemed_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(email)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Decode the staged cap request off a redeemed invite row, if any.
/// `None` means "membership only" — the common case — not an error.
pub fn parse_cap_grant(row: &InviteRow) -> Option<CapGrant> {
    let permissions: Vec<String> = row
        .cap_permissions
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())?;
    let ttl_secs = row.cap_ttl_secs?;
    Some(CapGrant {
        permissions,
        ttl_secs,
    })
}
