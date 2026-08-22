//! Durable per-session watermark into the in-memory reflector log
//! (`crates/server/src/reflector.rs`) -- see migration 034's comment for
//! why this needs to exist even though the reflector itself doesn't
//! persist across a session_task respawn (only across a full server
//! restart, where it's moot -- see the migration).

use sqlx::{FromRow, PgPool};

use crate::DbResult;

#[derive(Debug, Clone, FromRow)]
struct ReflectorCursorRow {
    seq:   i64,
    epoch: i32,
}

/// The persisted `(seq, epoch)` watermark for `session_id`, or `(0, 0)`
/// (equivalent to `ReflectorCursor::zero()`) if none has been recorded yet.
pub async fn get(pool: &PgPool, session_id: &str) -> DbResult<(i64, i32)> {
    let row = sqlx::query_as::<_, ReflectorCursorRow>(
        "SELECT seq, epoch FROM session_reflector_cursors WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(|r| (r.seq, r.epoch)).unwrap_or((0, 0)))
}

/// Record the watermark after a successful drain. `seq` never regresses
/// (`GREATEST` guards against a stale/racing caller) -- `epoch` is taken
/// as given, since a lower epoch after a `compact()` would mean something
/// has already gone wrong upstream, not a race worth silently masking here.
pub async fn upsert(pool: &PgPool, session_id: &str, seq: i64, epoch: i32) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO session_reflector_cursors (session_id, seq, epoch, updated_at)
         VALUES ($1, $2, $3, NOW())
         ON CONFLICT (session_id) DO UPDATE
             SET seq = GREATEST(session_reflector_cursors.seq, EXCLUDED.seq),
                 epoch = EXCLUDED.epoch,
                 updated_at = NOW()",
    )
    .bind(session_id)
    .bind(seq)
    .bind(epoch)
    .execute(pool)
    .await?;
    Ok(())
}
