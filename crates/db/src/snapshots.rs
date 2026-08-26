use serde_json::Value;
use sqlx::{PgPool, Postgres, Row, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

// ── Row type ──────────────────────────────────────────────────────────────────

/// A single versioned snapshot row.  There may be many rows per session;
/// callers should use `get_latest` for the hot path and `get_latest_clean` for
/// the recompute path after an epoch revocation.
#[derive(Debug, Clone)]
pub struct SnapshotRow {
    pub id: String,
    pub session_id: String,
    pub seq: i64,
    pub state: Value,
    pub dirty: bool,
    pub stale_since_seq: Option<i64>,
}

// ── Reads ─────────────────────────────────────────────────────────────────────

/// Return the latest snapshot for a session — dirty or clean.
///
/// Returns `(id, seq, state, dirty)`.  When `dirty` is true the state still
/// reflects the pre-revocation projection; callers should rebuild from fact
/// tables and INSERT a new clean row via `insert_clean`.
pub async fn get_latest(pool: &PgPool, session_id: &str) -> DbResult<SnapshotRow> {
    let row = sqlx::query(
        "SELECT id, session_id, seq, state, dirty, stale_since_seq
         FROM session_snapshots
         WHERE session_id = $1
         ORDER BY seq DESC
         LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)?;

    Ok(SnapshotRow {
        id: row.get("id"),
        session_id: row.get("session_id"),
        seq: row.get("seq"),
        state: row.get("state"),
        dirty: row.get("dirty"),
        stale_since_seq: row.get("stale_since_seq"),
    })
}

/// Return the latest CLEAN snapshot for a session.
///
/// Used during lazy recompute: find the last known-good baseline, then replay
/// events from `returned_seq + 1` to rebuild the current state.
pub async fn get_latest_clean(pool: &PgPool, session_id: &str) -> DbResult<Option<SnapshotRow>> {
    let row = sqlx::query(
        "SELECT id, session_id, seq, state, dirty, stale_since_seq
         FROM session_snapshots
         WHERE session_id = $1 AND dirty = FALSE
         ORDER BY seq DESC
         LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| SnapshotRow {
        id: r.get("id"),
        session_id: r.get("session_id"),
        seq: r.get("seq"),
        state: r.get("state"),
        dirty: false,
        stale_since_seq: None,
    }))
}

/// Legacy shim: returns `(seq, state)` from the latest snapshot row.
/// Replaces the old single-row `get()`.  Call sites that only need the data
/// and don't care about the dirty flag can use this for a clean migration.
pub async fn get(pool: &PgPool, session_id: &str) -> DbResult<(i64, Value)> {
    let row = get_latest(pool, session_id).await?;
    Ok((row.seq, row.state))
}

// ── Writes ────────────────────────────────────────────────────────────────────

/// INSERT a new snapshot version inside an existing transaction.
///
/// Replaces the old `upsert_in_tx`.  The caller receives the new row's `id`
/// in case it needs to reference it (e.g. to mark it dirty later).
pub async fn insert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    seq: i64,
    state: &Value,
) -> DbResult<String> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots (id, session_id, seq, state)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(session_id)
    .bind(seq)
    .bind(state)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

/// Like [`insert_in_tx`] but accepts a pre-serialized JSON string for `state`.
///
/// Avoids the `serde_json::Value` intermediate: the caller serializes the
/// snapshot to a `&str` (e.g. via `serde_json::to_string` or `BumpWriter`)
/// and postgres parses it via the `::jsonb` cast.
pub async fn insert_raw_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    seq: i64,
    state_json: &str,
) -> DbResult<String> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots (id, session_id, seq, state)
         VALUES ($1, $2, $3, $4::jsonb)",
    )
    .bind(&id)
    .bind(session_id)
    .bind(seq)
    .bind(state_json)
    .execute(&mut **tx)
    .await?;
    Ok(id)
}

/// Seed an empty snapshot row when a new session is created.
///
/// Pool-level (no ongoing transaction needed).  Idempotent via ON CONFLICT.
pub async fn seed(pool: &PgPool, session_id: &str) -> DbResult<()> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots (id, session_id, seq, state)
         VALUES ($1, $2, 0, '{}'::jsonb)
         ON CONFLICT DO NOTHING",
    )
    .bind(&id)
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Mark the current snapshot dirty by inserting a sentinel row.
///
/// Called immediately after an epoch revocation fires.  The sentinel carries
/// the pre-revocation state (from `current_state`) and flags it with
/// `dirty = TRUE, stale_since_seq = drain_seq` so cold-attach can detect it.
///
/// This is INSERT-only: we do NOT mutate the previous row.  The dirty sentinel
/// appears in the snapshot history as a first-class record of the revocation
/// boundary — "the snapshot at seq N was the last clean one before epoch N+1".
pub async fn mark_dirty(
    pool: &PgPool,
    session_id: &str,
    current_state: &Value,
    drain_seq: i64,
) -> DbResult<String> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots
             (id, session_id, seq, state, dirty, stale_since_seq)
         VALUES ($1, $2, $3, $4, TRUE, $3)",
    )
    .bind(&id)
    .bind(session_id)
    .bind(drain_seq)
    .bind(current_state)
    .execute(pool)
    .await?;
    Ok(id)
}

/// INSERT a clean snapshot after a lazy recompute.
///
/// Called from `load_snapshot_from_db` after rebuilding state from fact tables
/// when the latest row was dirty.  The new row supersedes the dirty sentinel
/// in the `ORDER BY seq DESC` read path once a new event is committed.
///
/// We insert at the highest known seq so this row sorts above the dirty sentinel.
pub async fn insert_clean(
    pool: &PgPool,
    session_id: &str,
    seq: i64,
    state: &Value,
) -> DbResult<String> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots (id, session_id, seq, state, dirty)
         VALUES ($1, $2, $3, $4, FALSE)",
    )
    .bind(&id)
    .bind(session_id)
    .bind(seq)
    .bind(state)
    .execute(pool)
    .await?;
    Ok(id)
}

// ── GC ────────────────────────────────────────────────────────────────────────

/// Compact historical clean snapshot rows across all sessions.
///
/// Keeps the `keep_n` most recent clean rows per session (ring-buffer
/// semantics).  Dirty rows are excluded from the count and are never deleted
/// by this function — they are revocation audit boundary markers and are
/// managed separately by `compact_dirty_sentinels`.
///
/// The window function runs a single pass over the whole table rather than
/// looping per-session, so cost is O(total rows) regardless of session count.
/// The index on `(session_id, seq DESC)` makes the per-partition sort fast.
///
/// Returns the number of rows deleted.
pub async fn compact_all(pool: &PgPool, keep_n: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "WITH ranked AS (
             SELECT id,
                    ROW_NUMBER() OVER (
                        PARTITION BY session_id
                        ORDER BY seq DESC
                    ) AS rn
             FROM session_snapshots
             WHERE dirty = FALSE
         )
         DELETE FROM session_snapshots
         WHERE id IN (SELECT id FROM ranked WHERE rn > $1)",
    )
    .bind(keep_n)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Compact dirty sentinel rows older than `retention_days`.
///
/// Dirty sentinels are the epoch-revocation boundary markers: they record
/// where in the snapshot timeline authority changed.  After `retention_days`
/// the detailed snapshot blob is no longer needed — the `cap_revocations`
/// table retains the structured audit summary (strategy, drain_seq, etc.)
/// indefinitely.
///
/// Returns the number of rows deleted.
pub async fn compact_dirty_sentinels(pool: &PgPool, retention_days: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM session_snapshots
         WHERE dirty = TRUE
           AND created_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(retention_days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Write a snapshot asynchronously (Tier-2 / projection path).
///
/// Uses `synchronous_commit = off` — snapshots are always recoverable by
/// replaying events from the last durable snapshot, so losing a write on
/// crash costs a slightly longer cold-attach replay, not data loss.
pub async fn write_async(
    pool: &PgPool,
    session_id: &str,
    seq: i64,
    state_json: &str,
) -> DbResult<()> {
    let mut tx = pool.begin().await?;
    sqlx::query("SET LOCAL synchronous_commit = off")
        .execute(&mut *tx)
        .await?;
    insert_raw_in_tx(&mut tx, session_id, seq, state_json).await?;
    tx.commit().await?;
    Ok(())
}

/// Compatibility shim for call sites that haven't migrated to `insert_in_tx`.
/// Delegates to `insert_in_tx`; callers can drop this once fully migrated.
#[allow(dead_code)]
pub async fn upsert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    seq: i64,
    state: &Value,
) -> DbResult<()> {
    insert_in_tx(tx, session_id, seq, state).await?;
    Ok(())
}
