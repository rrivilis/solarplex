//! PersistPlan — mini compiler that lowers tuple assertions into optimal SQL.
//!
//! The plan accumulates event tuples for one coordination step, then executes
//! them in a single transaction:
//!
//!   1. `alloc_seq_block_in_tx(N)` — one round-trip, reserves N seq numbers.
//!   2. UNNEST INSERT              — one round-trip, inserts all N event rows.
//!   3. `COMMIT`                   — one WAL fsync.
//!   4. `pg_notify`                — post-commit observer wakeup (best-effort).
//!
//! Round-trips per plan execution: 3, regardless of N.
//!
//! # Interpreter / compiler duality
//!
//! The session machine's `transition` fold is the interpreter — it evaluates
//! the event log against the current environment (state + memory).  The
//! PersistPlan is the compiler — it takes the high-level tuple assertions
//! produced by one transition step and lowers them to the optimal target code
//! (SQL).  The snapshot is the compiled residual: the Futamura first projection
//! of the interpreter specialised over the event log up to seq N.
//!
//! # Tier model
//!
//! - [`PersistPlan::execute`]       — Tier-1: synchronous commit, full durability.
//! - [`PersistPlan::execute_async`] — Tier-2: `SET LOCAL synchronous_commit = off`;
//!   safe for projection / snapshot writes where the event log is the source of truth.

use sqlx::PgPool;
use ulid::Ulid;

use crate::{DbError, DbResult};

// ── Event spec ────────────────────────────────────────────────────────────────

/// One event tuple to append within the plan.
pub struct EventSpec<'a> {
    pub type_name:    &'a str,
    pub actor_id:     &'a str,
    pub payload_json: &'a str,
}

// ── Plan ──────────────────────────────────────────────────────────────────────

/// Accumulated write plan for one coordination step.
///
/// Built with a fluent builder; executed with [`execute`](Self::execute) or
/// [`execute_async`](Self::execute_async).
pub struct PersistPlan<'a> {
    session_id: &'a str,
    events:     Vec<EventSpec<'a>>,
    notify:     bool,
}

impl<'a> PersistPlan<'a> {
    pub fn new(session_id: &'a str) -> Self {
        Self { session_id, events: Vec::new(), notify: false }
    }

    /// Append an event tuple to the plan.
    pub fn append(mut self, spec: EventSpec<'a>) -> Self {
        self.events.push(spec);
        self
    }

    /// Fire a post-commit observer wakeup (best-effort). See `run`'s notify
    /// block for the actual channel/payload — it must match
    /// `db::events::notify_session`'s convention exactly, since
    /// `notifier.rs` is the one and only subscriber and LISTEN/NOTIFY has no
    /// wildcard: a channel name or payload shape that doesn't match byte for
    /// byte is a silent no-op, not an error.
    pub fn notify(mut self) -> Self {
        self.notify = true;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Execute with synchronous commit (Tier-1 / durable path).
    ///
    /// Returns the first allocated seq; the full block is `[first, first+N)`.
    pub async fn execute(self, db: &PgPool) -> DbResult<i64> {
        self.run(db, false).await
    }

    /// Execute with `synchronous_commit = off` (Tier-2 / async path).
    ///
    /// Returns the first allocated seq.
    pub async fn execute_async(self, db: &PgPool) -> DbResult<i64> {
        self.run(db, true).await
    }

    async fn run(self, db: &PgPool, async_commit: bool) -> DbResult<i64> {
        if self.events.is_empty() {
            return Ok(0);
        }

        let n = self.events.len();
        let mut tx = db.begin().await?;

        if async_commit {
            sqlx::query("SET LOCAL synchronous_commit = off")
                .execute(&mut *tx)
                .await?;
        }

        let first_seq =
            crate::events::alloc_seq_block_in_tx(&mut tx, self.session_id, n as i64).await?;

        // Build parallel column arrays for the single UNNEST INSERT.
        let mut ids:      Vec<String> = Vec::with_capacity(n);
        let mut aids:     Vec<&str>   = Vec::with_capacity(n);
        let mut etypes:   Vec<&str>   = Vec::with_capacity(n);
        let mut payloads: Vec<&str>   = Vec::with_capacity(n);
        let mut seqs:     Vec<i64>    = Vec::with_capacity(n);
        let     sids:     Vec<&str>   = vec![self.session_id; n];

        for (i, ev) in self.events.iter().enumerate() {
            ids.push(Ulid::new().to_string());
            aids.push(ev.actor_id);
            etypes.push(ev.type_name);
            payloads.push(ev.payload_json);
            seqs.push(first_seq + i as i64);
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
        .execute(&mut *tx)
        .await
        .map_err(DbError::from)?;

        tx.commit().await?;

        if self.notify {
            // Must match db::events::notify_session exactly: fixed channel
            // name (LISTEN/NOTIFY has no wildcard, so notifier.rs can only
            // ever subscribe to one literal string) and "{session_id}:{seq}"
            // payload (notifier.rs splits on the first colon to recover
            // both). This previously used a per-session channel name
            // ("session:{id}") with a bare seq payload — nothing was ever
            // listening on that channel, so every notify from this path was
            // a silent no-op; connected clients only ever updated via the
            // separate in-process hub.broadcast() path.
            let last_seq = first_seq + n as i64 - 1;
            let _ = sqlx::query("SELECT pg_notify('session_events', $1)")
                .bind(format!("{}:{last_seq}", self.session_id))
                .execute(db)
                .await;
        }

        Ok(first_seq)
    }
}
