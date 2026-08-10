//! Postgres batch-commit roundtrip benchmark.
//!
//! Measures the per-event wall time for three write strategies:
//!
//! - **single**:  one transaction per event (current production path).
//!                Cost: N × (network + WAL fsync).
//!
//! - **batch-N**: N events per transaction (batch commit).
//!                Cost: (N/batch) × (network + WAL fsync) + N × INSERT overhead.
//!                Batch sizes tested: 2, 4, 8 (typical saga step counts).
//!
//! Requires a live Postgres instance.  Set DATABASE_URL before running:
//!
//! ```text
//! DATABASE_URL=postgres://localhost/solarplex \
//!   cargo run -p db --example batch_commit_bench --release -- 200
//! ```
//!
//! The argument is the total number of events to write per strategy (default 100).
//! Each run creates a throwaway session and cleans up after itself.
//!
//! # What to look for
//!
//! - **fsync dominance**: if single >> batch-2 ≈ batch-4, fsync is the
//!   bottleneck and batching pays off immediately.
//! - **network dominance**: if single ≈ batch-N, the round-trip is dominated
//!   by TCP latency (cloud Postgres); larger batches needed.
//! - **INSERT overhead**: batch-8 / batch-4 ratio reveals per-row INSERT cost
//!   after the fsync is amortised.

use std::time::Instant;

use ulid::Ulid;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Write `n` events one transaction each. Returns total elapsed ms.
/// `sync_commit`: if false, sets `synchronous_commit = off` (Tier-2 async path).
async fn bench_single(
    pool:        &sqlx::PgPool,
    session_id:  &str,
    actor_id:    &str,
    n:           usize,
    sync_commit: bool,
) -> f64 {
    let t = Instant::now();
    for i in 0..n {
        let payload = serde_json::json!({ "seq": i, "data": "single" }).to_string();
        let mut tx = pool.begin().await.unwrap();
        if !sync_commit {
            sqlx::query("SET LOCAL synchronous_commit = off")
                .execute(&mut *tx).await.unwrap();
        }
        let seq = db::events::alloc_seq_block_in_tx(&mut tx, session_id, 1).await.unwrap();
        db::events::append_raw_in_tx(
            &mut tx, session_id, actor_id, "saga_step_sent", &payload, seq,
        ).await.unwrap();
        tx.commit().await.unwrap();
    }
    t.elapsed().as_secs_f64() * 1000.0
}

/// Write `n` events in transactions of size `batch`. Returns total elapsed ms.
/// `sync_commit`: if false, sets `synchronous_commit = off` (Tier-2 async path).
async fn bench_batch(
    pool:        &sqlx::PgPool,
    session_id:  &str,
    actor_id:    &str,
    n:           usize,
    batch:       usize,
    sync_commit: bool,
) -> f64 {
    let t = Instant::now();
    let mut i = 0usize;
    while i < n {
        let count = batch.min(n - i);
        let mut tx = pool.begin().await.unwrap();
        if !sync_commit {
            sqlx::query("SET LOCAL synchronous_commit = off")
                .execute(&mut *tx).await.unwrap();
        }

        let mut rows_data: Vec<(i64, String)> = Vec::with_capacity(count);
        let first_seq = db::events::alloc_seq_block_in_tx(&mut tx, session_id, count as i64).await.unwrap();
        for j in 0..count {
            let seq = first_seq + j as i64;
            let payload = serde_json::json!({ "seq": i + j, "data": "batch" }).to_string();
            rows_data.push((seq, payload));
        }

        let rows: Vec<db::events::RawEventRow<'_>> = rows_data.iter().map(|(seq, payload)| {
            db::events::RawEventRow {
                session_id,
                actor_id,
                event_type:   "saga_step_sent",
                payload_json: payload,
                seq:          *seq,
            }
        }).collect();

        db::events::append_batch_raw_in_tx(&mut tx, &rows).await.unwrap();
        tx.commit().await.unwrap();
        i += count;
    }
    t.elapsed().as_secs_f64() * 1000.0
}

// ── Setup / teardown ──────────────────────────────────────────────────────────

async fn setup_session(pool: &sqlx::PgPool, session_id: &str) -> String {
    // sessions.created_by is a NOT NULL FK → actors.id, so we need a throwaway actor.
    let actor_id = format!("bench-{session_id}");
    sqlx::query(
        "INSERT INTO actors (id, type, name) VALUES ($1, 'agent', 'bench')
         ON CONFLICT DO NOTHING",
    )
    .bind(&actor_id)
    .execute(pool)
    .await
    .unwrap();

    // Parent sessions row required by the session_sequences + events FKs.
    sqlx::query(
        "INSERT INTO sessions (id, name, created_by) VALUES ($1, 'bench', $2)
         ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .bind(&actor_id)
    .execute(pool)
    .await
    .unwrap();

    // Sequence counter — session_sequences also references sessions(id).
    sqlx::query(
        "INSERT INTO session_sequences (session_id, next_seq)
         VALUES ($1, 1)
         ON CONFLICT DO NOTHING",
    )
    .bind(session_id)
    .execute(pool)
    .await
    .unwrap();

    actor_id
}

async fn teardown_session(pool: &sqlx::PgPool, session_id: &str, actor_id: &str) {
    // events and session_sequences both CASCADE on sessions delete.
    sqlx::query("DELETE FROM sessions WHERE id = $1")
        .bind(session_id).execute(pool).await.unwrap();
    sqlx::query("DELETE FROM actors WHERE id = $1")
        .bind(actor_id).execute(pool).await.unwrap();
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://localhost/solarplex".into());

    let pool = db::connect(&database_url).await.expect("connect");

    println!("batch_commit_bench: n={n} events per strategy, url={database_url}");
    println!("{:<18} {:>12} {:>16} {:>16}", "strategy", "total ms", "per-event µs", "events/s");
    println!("{}", "-".repeat(66));

    // (label, batch_size, sync_commit)
    // sync=true  → Tier-1 durable path (fsync per commit)
    // sync=false → Tier-2 async path   (no fsync, wal_writer_delay flush)
    for (label, batch_size, sync_commit) in [
        ("single",          1usize, true),
        ("batch-2",         2,      true),
        ("batch-4",         4,      true),
        ("batch-8",         8,      true),
        ("batch-16",        16,     true),
        ("batch-32",        32,     true),
        ("batch-64",        64,     true),
        ("batch-128",       128,    true),
        ("async-single",    1,      false),
        ("async-batch-4",   4,      false),
        ("async-batch-8",   8,      false),
        ("async-batch-32",  32,     false),
        ("async-batch-64",  64,     false),
        ("async-batch-128", 128,    false),
    ] {
        let session_id = Ulid::new().to_string();
        let actor_id = setup_session(&pool, &session_id).await;

        let ms = if batch_size == 1 {
            bench_single(&pool, &session_id, &actor_id, n, sync_commit).await
        } else {
            bench_batch(&pool, &session_id, &actor_id, n, batch_size, sync_commit).await
        };

        teardown_session(&pool, &session_id, &actor_id).await;

        let per_event_us = ms * 1000.0 / n as f64;
        let events_per_s = n as f64 / (ms / 1000.0);
        println!("{label:<18} {ms:>11.1}ms {per_event_us:>15.1}µs {events_per_s:>15.0}/s");
    }
}
