//! Git-remote-style fetch between sessions — a durable, directional pointer
//! with a watermark cursor. Distinct from `session_links` (symmetric,
//! unordered, no cursor): a remote always has a `local_session_id` that owns
//! the pointer and a `remote_session_id` it fetches from.
//!
//! Deliberately not built on `crates/server/src/reflector.rs` (in-memory,
//! single-process, dies on restart) — fetching pulls directly from the
//! remote session's real `events` table (`db::events::list`, the same
//! mechanism `sp watch`'s `SavedCursor` already uses), so the watermark
//! survives a server restart. Fetching never writes into the local
//! session's own event log — fetched events are returned for display only,
//! same non-copying principle as `sessions::compute_digest`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionRemoteRow {
    pub id: String,
    pub local_session_id: String,
    pub remote_session_id: String,
    pub added_by: String,
    pub last_fetched_seq: i64,
    pub last_fetched_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Adding a pointer grants nothing by itself — same principle as `git remote
/// add` against a URL you may not yet have access to. Authorization against
/// `remote_session_id` is checked at fetch time, not here.
pub async fn add_remote(
    pool: &PgPool,
    local_session_id: &str,
    remote_session_id: &str,
    added_by: &str,
) -> DbResult<SessionRemoteRow> {
    if local_session_id == remote_session_id {
        return Err(DbError::Conflict(
            "cannot add a session as its own remote".to_string(),
        ));
    }
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, SessionRemoteRow>(
        "INSERT INTO session_remotes (id, local_session_id, remote_session_id, added_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (local_session_id, remote_session_id) DO UPDATE
             -- Idempotent re-add — same posture as session_links' revive-on-conflict.
             SET added_by = EXCLUDED.added_by
         RETURNING id, local_session_id, remote_session_id, added_by,
                   last_fetched_seq, last_fetched_at, created_at",
    )
    .bind(&id)
    .bind(local_session_id)
    .bind(remote_session_id)
    .bind(added_by)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, remote_id: &str) -> DbResult<SessionRemoteRow> {
    sqlx::query_as::<_, SessionRemoteRow>(
        "SELECT id, local_session_id, remote_session_id, added_by,
                last_fetched_seq, last_fetched_at, created_at
         FROM session_remotes WHERE id = $1",
    )
    .bind(remote_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn list_for_session(
    pool: &PgPool,
    local_session_id: &str,
) -> DbResult<Vec<SessionRemoteRow>> {
    sqlx::query_as::<_, SessionRemoteRow>(
        "SELECT id, local_session_id, remote_session_id, added_by,
                last_fetched_seq, last_fetched_at, created_at
         FROM session_remotes WHERE local_session_id = $1
         ORDER BY created_at DESC",
    )
    .bind(local_session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Advances the watermark to `last_fetched_seq`'s new value — the caller
/// (route layer) has already pulled the events up to this seq via
/// `db::events::list`. Never called with a seq lower than the current one
/// (`GREATEST` guards against a stale/racing caller regressing it).
pub async fn advance_watermark(
    pool: &PgPool,
    remote_id: &str,
    up_to_seq: i64,
) -> DbResult<SessionRemoteRow> {
    sqlx::query_as::<_, SessionRemoteRow>(
        "UPDATE session_remotes
         SET last_fetched_seq = GREATEST(last_fetched_seq, $2), last_fetched_at = NOW()
         WHERE id = $1
         RETURNING id, local_session_id, remote_session_id, added_by,
                   last_fetched_seq, last_fetched_at, created_at",
    )
    .bind(remote_id)
    .bind(up_to_seq)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn remove(pool: &PgPool, remote_id: &str) -> DbResult<()> {
    let result = sqlx::query("DELETE FROM session_remotes WHERE id = $1")
        .bind(remote_id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}
