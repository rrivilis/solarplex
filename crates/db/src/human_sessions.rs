use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool};

use crate::{DbError, DbResult};

/// SHA-256 hex of a raw token — the value stored in the database.
/// The raw token is never persisted; only the hash lives in the DB.
fn token_hash(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

#[derive(Debug, Clone, FromRow)]
pub struct HumanSessionRow {
    pub id:         String,
    pub actor_id:   String,
    /// OIDC subject claim (opaque, provider-assigned user identifier).
    pub sub:        String,
    /// Normalized provider slug ("google", "github", "microsoft", …).
    pub provider:   String,
    pub issued_at:  DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_seen:  DateTime<Utc>,
}

/// Issue a new human session token.
///
/// `id` is the raw (plaintext) sp_token — the caller retains it and sends it
/// to the client. Only the SHA-256 hash is written to the database so that
/// a DB dump does not expose bearer tokens.
pub async fn create(
    pool:       &PgPool,
    id:         &str,
    actor_id:   &str,
    sub:        &str,
    provider:   &str,
    expires_at: DateTime<Utc>,
) -> DbResult<HumanSessionRow> {
    let id_hash = token_hash(id);
    sqlx::query_as::<_, HumanSessionRow>(
        "INSERT INTO human_sessions (id, actor_id, sub, provider, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, actor_id, sub, provider, issued_at, expires_at, last_seen",
    )
    .bind(&id_hash)
    .bind(actor_id)
    .bind(sub)
    .bind(provider)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Look up a human session by raw token.
/// Hashes the raw token before querying. Returns `NotFound` if the token
/// does not exist or has expired.
pub async fn lookup(pool: &PgPool, id: &str) -> DbResult<HumanSessionRow> {
    let id_hash = token_hash(id);
    sqlx::query_as::<_, HumanSessionRow>(
        "SELECT id, actor_id, sub, provider, issued_at, expires_at, last_seen
         FROM human_sessions
         WHERE id = $1 AND expires_at > NOW()",
    )
    .bind(&id_hash)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Update `last_seen` for an active session.
/// Call on every WS connect; best-effort (non-fatal on failure).
pub async fn touch(pool: &PgPool, id: &str) -> DbResult<()> {
    let id_hash = token_hash(id);
    sqlx::query("UPDATE human_sessions SET last_seen = NOW() WHERE id = $1")
        .bind(&id_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// Revoke a single session (logout from one device).
pub async fn revoke(pool: &PgPool, id: &str) -> DbResult<()> {
    let id_hash = token_hash(id);
    sqlx::query("DELETE FROM human_sessions WHERE id = $1")
        .bind(&id_hash)
        .execute(pool)
        .await?;
    Ok(())
}

/// List every active session for an actor — the sign-in history view (a
/// Google/GitHub-style "devices" page). Never returns the raw token (it was
/// never stored); `id` here is the same hash `lookup`/`revoke` key on, safe
/// to show since it's one-way and only ever matched back against a bearer
/// token the caller already possesses.
pub async fn list_for_actor(pool: &PgPool, actor_id: &str) -> DbResult<Vec<HumanSessionRow>> {
    sqlx::query_as::<_, HumanSessionRow>(
        "SELECT id, actor_id, sub, provider, issued_at, expires_at, last_seen
         FROM human_sessions
         WHERE actor_id = $1 AND expires_at > NOW()
         ORDER BY last_seen DESC",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Revoke one session by its hash id, scoped to the owning actor — the
/// sign-in history "sign out this device" action. The route handler already
/// derives `actor_id` from a verified bearer token before calling this, so
/// cross-actor revocation shouldn't be reachable regardless; the `actor_id`
/// clause here is defense in depth, not the only gate. Returns the number of
/// rows deleted (0 means "not found, or not yours" — the caller should treat
/// both the same way, same anti-enumeration posture as session_links' 404s).
pub async fn revoke_by_id_for_actor(pool: &PgPool, id: &str, actor_id: &str) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM human_sessions WHERE id = $1 AND actor_id = $2")
        .bind(id)
        .bind(actor_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Hash a raw sp_token the same way `create`/`lookup`/`revoke` do — lets a
/// route handler that already has the caller's raw bearer token compute
/// which `list_for_actor` row (if any) it corresponds to, so the sign-in
/// history view can mark "this device" instead of just listing rows with no
/// way to tell which one is the request that's asking.
pub fn hash_token(raw: &str) -> String {
    token_hash(raw)
}

/// Revoke all sessions for an actor (logout everywhere / account deletion).
/// Returns the number of rows deleted.
pub async fn revoke_all(pool: &PgPool, actor_id: &str) -> DbResult<u64> {
    let result = sqlx::query("DELETE FROM human_sessions WHERE actor_id = $1")
        .bind(actor_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

/// Find the actor_id for a given OIDC (sub, provider) pair, if one exists.
///
/// Used during OIDC callback to re-use an existing actor rather than creating
/// a duplicate when the same user logs in again from a different browser.
///
/// Provider is part of the key: `google/alice` ≠ `github/alice`.
pub async fn find_actor_by_sub(
    pool:     &PgPool,
    sub:      &str,
    provider: &str,
) -> DbResult<Option<String>> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT actor_id FROM human_sessions
         WHERE sub = $1 AND provider = $2
         LIMIT 1",
    )
    .bind(sub)
    .bind(provider)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|(actor_id,)| actor_id))
}
