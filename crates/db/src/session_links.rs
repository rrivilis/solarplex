//! Session-to-session linking — an authorization relationship, not a data
//! copy. Two ways to create a `session_links` row: mint-a-link-invite +
//! redeem (mirrors `invites.rs` exactly, including "the row's own id is the
//! bearer token"), or a direct fast path when the caller already holds
//! Owner|Collaborator in both sessions.
//!
//! Once linked with `visibility = 'full'`, `sessions::require_membership_or_
//! linked_access` lazily auto-grants real Observer membership in the peer
//! session the first time a member actually tries to access it — see that
//! function's doc comment for why nothing else (no replay log, no mirroring)
//! is needed on top of that.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionLinkInviteRow {
    pub id: String,
    pub source_session_id: String,
    pub invited_by: String,
    pub expires_at: DateTime<Utc>,
    pub redeemed_by_session: Option<String>,
    pub redeemed_by_actor: Option<String>,
    pub redeemed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionLinkRow {
    pub id: String,
    pub session_a: String,
    pub session_b: String,
    pub linked_by: String,
    pub visibility: String,
    pub created_at: DateTime<Utc>,
}

impl SessionLinkRow {
    /// The session on the other side of this link from `session_id`.
    pub fn peer_of(&self, session_id: &str) -> &str {
        if self.session_a == session_id { &self.session_b } else { &self.session_a }
    }
}

/// Canonicalize an unordered pair so an A-B link and a B-A link are always
/// the same row.
fn canonical_pair<'a>(x: &'a str, y: &'a str) -> (&'a str, &'a str) {
    if x < y { (x, y) } else { (y, x) }
}

pub async fn mint_invite(
    pool: &PgPool,
    source_session_id: &str,
    invited_by: &str,
    ttl_secs: i64,
) -> DbResult<SessionLinkInviteRow> {
    let id = Ulid::new().to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);
    sqlx::query_as::<_, SessionLinkInviteRow>(
        "INSERT INTO session_link_invites (id, source_session_id, invited_by, expires_at)
         VALUES ($1, $2, $3, $4)
         RETURNING id, source_session_id, invited_by, expires_at, redeemed_by_session,
                   redeemed_by_actor, redeemed_at, created_at",
    )
    .bind(&id)
    .bind(source_session_id)
    .bind(invited_by)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Atomically validate-and-consume a link invite, then create (or revive) the
/// `session_links` row — both in one transaction, so a race between two
/// concurrent redemption attempts can't produce two links or a consumed
/// invite with no resulting link.
pub async fn redeem_invite(
    pool: &PgPool,
    invite_id: &str,
    redeeming_session_id: &str,
    redeeming_actor_id: &str,
) -> DbResult<SessionLinkRow> {
    let mut tx: Transaction<'_, Postgres> = pool.begin().await?;

    let invite = sqlx::query_as::<_, SessionLinkInviteRow>(
        "UPDATE session_link_invites
         SET redeemed_at = NOW(), redeemed_by_session = $2, redeemed_by_actor = $3
         WHERE id = $1 AND redeemed_at IS NULL AND expires_at > NOW()
         RETURNING id, source_session_id, invited_by, expires_at, redeemed_by_session,
                   redeemed_by_actor, redeemed_at, created_at",
    )
    .bind(invite_id)
    .bind(redeeming_session_id)
    .bind(redeeming_actor_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(DbError::NotFound)?;

    if invite.source_session_id == redeeming_session_id {
        return Err(DbError::Conflict("cannot link a session to itself".to_string()));
    }

    let link = insert_link_in_tx(&mut tx, &invite.source_session_id, redeeming_session_id, redeeming_actor_id).await?;
    tx.commit().await?;
    Ok(link)
}

/// Direct link when the caller already holds sufficient authority in both
/// sessions — no invite round trip. Caller (route layer) has already
/// verified Owner|Collaborator membership in both `session_x` and `session_y`.
pub async fn direct_link(
    pool: &PgPool,
    session_x: &str,
    session_y: &str,
    actor_id: &str,
) -> DbResult<SessionLinkRow> {
    let mut tx = pool.begin().await?;
    let link = insert_link_in_tx(&mut tx, session_x, session_y, actor_id).await?;
    tx.commit().await?;
    Ok(link)
}

async fn insert_link_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_x: &str,
    session_y: &str,
    actor_id: &str,
) -> DbResult<SessionLinkRow> {
    let (a, b) = canonical_pair(session_x, session_y);
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, SessionLinkRow>(
        "INSERT INTO session_links (id, session_a, session_b, linked_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (session_a, session_b) DO UPDATE
             -- Re-linking an existing (possibly muted) pair revives it to
             -- full visibility rather than erroring — same idempotent-write
             -- posture as mailbox::insert_route.
             SET visibility = 'full'
         RETURNING id, session_a, session_b, linked_by, visibility, created_at",
    )
    .bind(&id)
    .bind(a)
    .bind(b)
    .bind(actor_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(DbError::from)
}

/// Does any `session_links` row exist between these two sessions, regardless
/// of visibility (including muted)? Used as a lightweight "these sessions
/// have agreed to interact" precondition for cross-session delegation —
/// deliberately not viewer-scoped like `list_visible_for_session`, since this
/// is a yes/no existence check, not a rendering decision.
pub async fn exists_between(pool: &PgPool, session_x: &str, session_y: &str) -> DbResult<bool> {
    let (a, b) = canonical_pair(session_x, session_y);
    let row: Option<(i32,)> = sqlx::query_as(
        "SELECT 1 FROM session_links WHERE session_a = $1 AND session_b = $2",
    )
    .bind(a)
    .bind(b)
    .fetch_optional(pool)
    .await?;
    Ok(row.is_some())
}

/// The full `session_links` row between these two sessions, if any —
/// `exists_between`'s sibling for callers (like artifact import) that need
/// the link's own id, not just a yes/no.
pub async fn get_between(pool: &PgPool, session_x: &str, session_y: &str) -> DbResult<Option<SessionLinkRow>> {
    let (a, b) = canonical_pair(session_x, session_y);
    sqlx::query_as::<_, SessionLinkRow>(
        "SELECT id, session_a, session_b, linked_by, visibility, created_at
         FROM session_links WHERE session_a = $1 AND session_b = $2",
    )
    .bind(a)
    .bind(b)
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, link_id: &str) -> DbResult<SessionLinkRow> {
    sqlx::query_as::<_, SessionLinkRow>(
        "SELECT id, session_a, session_b, linked_by, visibility, created_at
         FROM session_links WHERE id = $1",
    )
    .bind(link_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Links visible to `viewer_actor_id` from `session_id`'s side — never the
/// full set of `session_id`'s links.
///
/// Linking confers no authority of its own; it renders the union of
/// sessions the *viewer* already belongs to. So a link is visible only when
/// the viewer is a member of *both* endpoints — being a member of
/// `session_id` alone is not enough. Otherwise Bob, a member of A but not
/// B, could see "A is linked to «name of a session Bob can't otherwise
/// know exists»" just by asking about a session he's actually in — a real
/// (if narrower) leak of B's existence and name to a non-member. Same rule
/// applied to the edge as to everything the edge exposes: render against
/// the viewer, or the link is invisible and A simply looks unlinked from
/// their vantage.
pub async fn list_visible_for_session(
    pool: &PgPool,
    session_id: &str,
    viewer_actor_id: &str,
) -> DbResult<Vec<SessionLinkRow>> {
    sqlx::query_as::<_, SessionLinkRow>(
        "SELECT sl.id, sl.session_a, sl.session_b, sl.linked_by, sl.visibility, sl.created_at
         FROM session_links sl
         WHERE (sl.session_a = $1 OR sl.session_b = $1)
           AND EXISTS (
               SELECT 1 FROM session_memberships sm
               WHERE sm.actor_id = $2
                 AND sm.detached_at IS NULL
                 AND sm.session_id = CASE WHEN sl.session_a = $1 THEN sl.session_b ELSE sl.session_a END
           )
         ORDER BY sl.created_at DESC",
    )
    .bind(session_id)
    .bind(viewer_actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn set_visibility(pool: &PgPool, link_id: &str, visibility: &str) -> DbResult<SessionLinkRow> {
    sqlx::query_as::<_, SessionLinkRow>(
        "UPDATE session_links SET visibility = $2 WHERE id = $1
         RETURNING id, session_a, session_b, linked_by, visibility, created_at",
    )
    .bind(link_id)
    .bind(visibility)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn unlink(pool: &PgPool, link_id: &str) -> DbResult<()> {
    let result = sqlx::query("DELETE FROM session_links WHERE id = $1")
        .bind(link_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 { return Err(DbError::NotFound); }
    Ok(())
}

/// Does `actor_id` have standing to access `target_session_id` via a
/// full-visibility link, by virtue of being a member of some other session
/// linked to it? Returns the peer session_id (the one they're actually a
/// member of) if so — `None` means no linked access, not "checked and denied"
/// (the caller falls back to a plain 403).
pub async fn actor_has_linked_access(
    pool: &PgPool,
    actor_id: &str,
    target_session_id: &str,
) -> DbResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT sm.session_id
         FROM session_links sl
         JOIN session_memberships sm
           ON sm.session_id = CASE WHEN sl.session_a = $2 THEN sl.session_b ELSE sl.session_a END
         WHERE (sl.session_a = $2 OR sl.session_b = $2)
           AND sl.visibility = 'full'
           AND sm.actor_id = $1
           AND sm.detached_at IS NULL
         LIMIT 1",
    )
    .bind(actor_id)
    .bind(target_session_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(peer,)| peer))
}
