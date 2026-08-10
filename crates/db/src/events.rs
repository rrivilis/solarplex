use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Row, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct EventRow {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub payload: serde_json::Value,
    pub parent_event_id: Option<String>,
    pub seq: i64,
    pub timestamp: DateTime<Utc>,
}

pub struct AppendEvent {
    pub session_id: String,
    pub actor_id: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub parent_event_id: Option<String>,
    pub seq: i64,
}

pub async fn append(pool: &PgPool, input: AppendEvent) -> DbResult<EventRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, EventRow>(
        "INSERT INTO events (id, session_id, actor_id, type, payload, parent_event_id, seq)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, session_id, actor_id, type, payload, parent_event_id, seq, timestamp",
    )
    .bind(&id)
    .bind(&input.session_id)
    .bind(&input.actor_id)
    .bind(&input.event_type)
    .bind(&input.payload)
    .bind(&input.parent_event_id)
    .bind(input.seq)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Atomically increment the session seq counter and return the new value,
/// running inside an existing transaction so the seq and event INSERT are atomic.
pub async fn alloc_seq_block_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    count: i64,
) -> DbResult<i64> {
    let row = sqlx::query(
        "UPDATE session_sequences SET next_seq = next_seq + $2
         WHERE session_id = $1
         RETURNING next_seq - $2",
    )
    .bind(session_id)
    .bind(count)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)?;
    Ok(row.get::<i64, _>(0))
}

/// Allocate a single seq number directly against the pool, with no event row
/// to insert alongside it — for callers that need a real, monotonic position
/// in the *same* counter every durable event row is numbered from, but aren't
/// writing a row themselves (e.g. `session_task::shadow_persist`, which
/// advances the session-crate machine's own bookkeeping for an event some
/// other code path is the durable writer for).
///
/// The underlying `UPDATE ... RETURNING` is a single statement — already
/// atomic without an explicit transaction, so this skips the BEGIN/COMMIT
/// round-trips `alloc_seq_block_in_tx` needs when paired with an INSERT.
///
/// Callers must not treat the returned seq as backed by a row in `events` —
/// it deliberately is not one. See `alloc_seq_block_in_tx` for the paired
/// allocate+insert path real event writers use.
pub async fn alloc_seq(pool: &PgPool, session_id: &str) -> DbResult<i64> {
    let row = sqlx::query(
        "UPDATE session_sequences SET next_seq = next_seq + 1
         WHERE session_id = $1
         RETURNING next_seq - 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)?;
    Ok(row.get::<i64, _>(0))
}

/// Append an event inside an existing transaction.
/// The caller is responsible for also calling `snapshots::upsert_in_tx` in the
/// same transaction so the persisted snapshot stays in sync.
pub async fn append_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    actor_id: &str,
    event_type: &str,
    payload: &serde_json::Value,
    seq: i64,
) -> DbResult<EventRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, EventRow>(
        "INSERT INTO events (id, session_id, actor_id, type, payload, parent_event_id, seq)
         VALUES ($1, $2, $3, $4, $5, NULL, $6)
         RETURNING id, session_id, actor_id, type, payload, parent_event_id, seq, timestamp",
    )
    .bind(&id)
    .bind(session_id)
    .bind(actor_id)
    .bind(event_type)
    .bind(payload)
    .bind(seq)
    .fetch_one(&mut **tx)
    .await
    .map_err(DbError::from)
}

/// Like [`append_in_tx`] but accepts a pre-serialized JSON string for `payload`.
///
/// Avoids the `serde_json::Value` intermediate representation: the caller
/// serializes the event directly to a `&str` (e.g. via `serde_json::to_string`
/// or `BumpWriter`) and postgres parses it via the `::jsonb` cast.
///
/// Use this variant from paths where `serde_json::to_value` would otherwise
/// build an intermediate `Value` tree only to have sqlx serialize it again.
pub async fn append_raw_in_tx(
    tx:           &mut Transaction<'_, Postgres>,
    session_id:   &str,
    actor_id:     &str,
    event_type:   &str,
    payload_json: &str,
    seq:          i64,
) -> DbResult<()> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO events (id, session_id, actor_id, type, payload, parent_event_id, seq)
         VALUES ($1, $2, $3, $4, $5::jsonb, NULL, $6)",
    )
    .bind(&id)
    .bind(session_id)
    .bind(actor_id)
    .bind(event_type)
    .bind(payload_json)
    .bind(seq)
    .execute(&mut **tx)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

/// A single row to insert via [`append_batch_raw_in_tx`].
pub struct RawEventRow<'a> {
    pub session_id:   &'a str,
    pub actor_id:     &'a str,
    pub event_type:   &'a str,
    pub payload_json: &'a str,
    pub seq:          i64,
}

/// Append multiple events in one transaction, amortising the fsync across all rows.
///
/// All rows commit together in one WAL flush.  Uses a single UNNEST INSERT so
/// seq allocation (1 round-trip) + INSERT (1 round-trip) + COMMIT (1 fsync)
/// is constant regardless of batch size.
///
/// Returns the ULID IDs assigned to each row in the same order as `rows`.
pub async fn append_batch_raw_in_tx<'a>(
    tx:   &mut Transaction<'_, Postgres>,
    rows: &[RawEventRow<'a>],
) -> DbResult<Vec<String>> {
    if rows.is_empty() {
        return Ok(vec![]);
    }

    let mut ids:     Vec<String> = Vec::with_capacity(rows.len());
    let mut sids:    Vec<&str>   = Vec::with_capacity(rows.len());
    let mut aids:    Vec<&str>   = Vec::with_capacity(rows.len());
    let mut etypes:  Vec<&str>   = Vec::with_capacity(rows.len());
    let mut payloads: Vec<&str>  = Vec::with_capacity(rows.len());
    let mut seqs:    Vec<i64>    = Vec::with_capacity(rows.len());

    for row in rows {
        ids.push(Ulid::new().to_string());
        sids.push(row.session_id);
        aids.push(row.actor_id);
        etypes.push(row.event_type);
        payloads.push(row.payload_json);
        seqs.push(row.seq);
    }

    sqlx::query(
        "INSERT INTO events (id, session_id, actor_id, type, payload, parent_event_id, seq)
         SELECT id, session_id, actor_id, type, payload::jsonb, NULL, seq
         FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bigint[])
              AS t(id, session_id, actor_id, type, payload, seq)",
    )
    .bind(&ids)
    .bind(&sids)
    .bind(&aids)
    .bind(&etypes)
    .bind(&payloads)
    .bind(&seqs)
    .execute(&mut **tx)
    .await
    .map_err(DbError::from)?;

    Ok(ids)
}

/// Fire a pg_notify wakeup for observers after a Tier-1 commit.
///
/// Uses a single `session_events` channel for all sessions; payload is
/// `{session_id}:{seq}`.  The server-side notifier parses this and wakes
/// any connected WebSocket clients via the hub broadcast channel.
///
/// Called outside the transaction (non-transactional notify) so a slow
/// notify cannot block the commit path.
pub async fn notify_session(pool: &PgPool, session_id: &str, seq: i64) -> DbResult<()> {
    sqlx::query("SELECT pg_notify('session_events', $1)")
        .bind(format!("{session_id}:{seq}"))
        .execute(pool)
        .await
        .map_err(DbError::from)?;
    Ok(())
}

pub async fn list(
    pool: &PgPool,
    session_id: &str,
    after_seq: Option<i64>,
    limit: i64,
) -> DbResult<Vec<EventRow>> {
    sqlx::query_as::<_, EventRow>(
        "SELECT id, session_id, actor_id, type, payload, parent_event_id, seq, timestamp
         FROM events
         WHERE session_id = $1 AND seq > $2
         ORDER BY seq ASC
         LIMIT $3",
    )
    .bind(session_id)
    .bind(after_seq.unwrap_or(0))
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// The highest committed seq for a session. Returns 0 if no events yet.
/// Used to stamp observed_seq on newly-issued caps.
/// Recent events across every session in `session_ids`, ordered by wall-
/// clock `timestamp` (not `seq` — `seq` is a per-session counter allocated
/// from `session_sequences`, so values collide across sessions and carry no
/// meaningful cross-session order). Callers get the session_id set from
/// `sessions::list_by_actor`, so there's no separate per-session membership
/// check needed here — the caller already only knows about sessions they
/// belong to.
pub async fn list_recent_across_sessions(
    pool:        &PgPool,
    session_ids: &[String],
    limit:       i64,
) -> DbResult<Vec<EventRow>> {
    if session_ids.is_empty() { return Ok(Vec::new()); }
    sqlx::query_as::<_, EventRow>(
        "SELECT id, session_id, actor_id, type, payload, parent_event_id, seq, timestamp
         FROM events
         WHERE session_id = ANY($1)
         ORDER BY timestamp DESC
         LIMIT $2",
    )
    .bind(session_ids)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn current_seq(pool: &PgPool, session_id: &str) -> DbResult<i64> {
    let row = sqlx::query_scalar::<_, Option<i64>>(
        "SELECT MAX(seq) FROM events WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)?;
    Ok(row.unwrap_or(0))
}

pub async fn get(pool: &PgPool, event_id: &str) -> DbResult<EventRow> {
    sqlx::query_as::<_, EventRow>(
        "SELECT id, session_id, actor_id, type, payload, parent_event_id, seq, timestamp
         FROM events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}
