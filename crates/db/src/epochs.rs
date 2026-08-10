//! Epoch management — per-session generation counter + revocation audit log.
//!
//! An epoch is a monotonically-increasing integer on a session.  It advances
//! whenever a revocation fires.  All capability tokens carry the epoch in which
//! they were issued; after epoch N is closed, caps from epoch N can be fenced.
//!
//! The audit log in `cap_revocations` is append-only and retains the full
//! revocation history for a session: strategy, target, drain window, and the
//! actor who triggered each event.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::{DbError, DbResult};

// ── Row types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct RevocationRow {
    pub id:             String,
    pub session_id:     String,
    pub strategy:       String,
    pub target_cap_id:  Option<String>,
    pub target_stratum: Option<i64>,
    pub drain_seq:      i64,
    pub drain_deadline: DateTime<Utc>,
    pub closed_epoch:   i64,
    pub new_epoch:      i64,
    pub revoked_at:     DateTime<Utc>,
    pub revoked_by:     String,
}

// ── Session epoch reads / writes ──────────────────────────────────────────────

/// Seed an epoch row for a newly-created session.
///
/// Idempotent via ON CONFLICT DO NOTHING — safe to call multiple times.
pub async fn seed(pool: &PgPool, session_id: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO session_epochs (session_id) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Return the current epoch for a session.  Returns 0 for sessions that were
/// created before the epoch system was added (migration 011 back-fills all rows).
pub async fn current(pool: &PgPool, session_id: &str) -> DbResult<i64> {
    let epoch = sqlx::query_scalar::<_, i64>(
        "SELECT epoch FROM session_epochs WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .unwrap_or(0);
    Ok(epoch)
}

/// Atomically increment the epoch counter and return the new value.
///
/// Called inside the revocation endpoint's DB transaction so the epoch advance
/// and cap revocation are atomic.
pub async fn advance(pool: &PgPool, session_id: &str) -> DbResult<i64> {
    let new_epoch = sqlx::query_scalar::<_, i64>(
        "UPDATE session_epochs
         SET epoch = epoch + 1, updated_at = NOW()
         WHERE session_id = $1
         RETURNING epoch",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| DbError::Conflict(format!("no epoch row for session {session_id}")))?;
    Ok(new_epoch)
}

// ── Revocation audit log ──────────────────────────────────────────────────────

/// Append a revocation event to the audit log.
///
/// `closed_epoch` is the epoch that was closed; `new_epoch` is the one now
/// active.  At least one of `target_cap_id` or `target_stratum` must be set
/// for the `cap` and `stratum` strategies respectively.
#[allow(clippy::too_many_arguments)]
pub async fn record_revocation(
    pool:          &PgPool,
    id:            &str,
    session_id:    &str,
    strategy:      &str,
    target_cap_id: Option<&str>,
    target_stratum: Option<i64>,
    drain_seq:     i64,
    drain_deadline: DateTime<Utc>,
    closed_epoch:  i64,
    new_epoch:     i64,
    revoked_by:    &str,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO cap_revocations
             (id, session_id, strategy, target_cap_id, target_stratum,
              drain_seq, drain_deadline, closed_epoch, new_epoch, revoked_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(session_id)
    .bind(strategy)
    .bind(target_cap_id)
    .bind(target_stratum)
    .bind(drain_seq)
    .bind(drain_deadline)
    .bind(closed_epoch)
    .bind(new_epoch)
    .bind(revoked_by)
    .execute(pool)
    .await?;
    Ok(())
}

/// Return the 20 most recent revocation events for a session, newest first.
pub async fn list_recent(
    pool:       &PgPool,
    session_id: &str,
) -> DbResult<Vec<RevocationRow>> {
    sqlx::query_as::<_, RevocationRow>(
        "SELECT id, session_id, strategy, target_cap_id, target_stratum,
                drain_seq, drain_deadline, closed_epoch, new_epoch, revoked_at, revoked_by
         FROM cap_revocations
         WHERE session_id = $1
         ORDER BY revoked_at DESC
         LIMIT 20",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
