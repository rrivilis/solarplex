//! Durable cross-replica session-ownership directory — see migration 035's
//! comment for the full design. `claim` is the one entry point: it both
//! claims a previously-unowned/stale session and renews an already-held
//! claim (a renewal is just a claim where `replica_id` happens to match).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::DbResult;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionPlacementRow {
    pub session_id: String,
    pub replica_id: String,
    pub fencing_token: i64,
    pub heartbeat_at: DateTime<Utc>,
    pub ttl_secs: i32,
}

/// Attempt to claim (or renew) `session_id` for `replica_id`.
///
/// Atomic — the `INSERT ... ON CONFLICT DO UPDATE ... WHERE` is one
/// statement, evaluated under Postgres's own row locking, so two replicas
/// racing to claim the same session can never both succeed. Returns
/// `Some(row)` when this replica now holds the claim (fresh, re-claimed
/// after staleness, or renewed), `None` when another replica legitimately
/// holds it and its heartbeat hasn't gone stale — same "expired() means
/// free" shape as `crate::lease::LeaseRecord`, just durable instead of
/// in-process.
pub async fn claim(
    pool: &PgPool,
    session_id: &str,
    replica_id: &str,
    ttl_secs: i32,
) -> DbResult<Option<SessionPlacementRow>> {
    sqlx::query_as::<_, SessionPlacementRow>(
        "INSERT INTO session_placements (session_id, replica_id, fencing_token, heartbeat_at, ttl_secs)
         VALUES ($1, $2, 1, NOW(), $3)
         ON CONFLICT (session_id) DO UPDATE
             SET replica_id    = EXCLUDED.replica_id,
                 fencing_token = session_placements.fencing_token + 1,
                 heartbeat_at  = NOW(),
                 ttl_secs      = EXCLUDED.ttl_secs
             WHERE session_placements.replica_id = EXCLUDED.replica_id
                OR session_placements.heartbeat_at + (session_placements.ttl_secs * interval '1 second') < NOW()
         RETURNING session_id, replica_id, fencing_token, heartbeat_at, ttl_secs",
    )
    .bind(session_id)
    .bind(replica_id)
    .bind(ttl_secs)
    .fetch_optional(pool)
    .await
    .map_err(Into::into)
}

/// Current, non-stale owner of `session_id`, if any — read-only
/// counterpart to `claim` for callers that only need to know who owns a
/// session without claiming or renewing it themselves.
pub async fn current_owner(pool: &PgPool, session_id: &str) -> DbResult<Option<String>> {
    let row = sqlx::query_as::<_, SessionPlacementRow>(
        "SELECT session_id, replica_id, fencing_token, heartbeat_at, ttl_secs
         FROM session_placements
         WHERE session_id = $1
           AND heartbeat_at + (ttl_secs * interval '1 second') >= NOW()",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| r.replica_id))
}

/// Whether any *other* replica currently has a non-stale claim on anything
/// in the directory. The only observable signal of "another replica
/// exists" in this design is through sessions it owns — a second replica
/// that's up but hasn't claimed any session yet is invisible to this check.
/// That's a real limitation, not a bug: this backs `ReplicationManager`'s
/// membership *awareness*, not a full cluster heartbeat/membership
/// protocol, which is deliberately out of scope until something actually
/// needs one (see reflector.rs's module doc).
pub async fn other_active_replicas(pool: &PgPool, my_replica_id: &str) -> DbResult<bool> {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
             SELECT 1 FROM session_placements
             WHERE replica_id != $1
               AND heartbeat_at + (ttl_secs * interval '1 second') >= NOW()
         )",
    )
    .bind(my_replica_id)
    .fetch_one(pool)
    .await
    .map_err(Into::into)
}
