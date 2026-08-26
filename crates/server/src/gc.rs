//! Background GC tasks for the Solarplex server.
//!
//! Two jobs run on independent hourly intervals:
//!
//! - **`cap_gc`** — delete revoked cap token rows after their retention window.
//!   The `cap_revocations` audit table retains summary records indefinitely;
//!   the fine-grained token rows are only needed during and just after the
//!   drain window.  Retention default: 7 days past `revoked_at`.
//!
//! - **`snapshot_gc`** — compact historical snapshot rows per session:
//!     - clean rows: keep the 50 most recent per session (ring-buffer)
//!     - dirty sentinels: keep for 30 days then drop (the `cap_revocations`
//!       table retains the structured audit record)
//!
//! Both jobs are fire-and-forget: failure is logged at WARN level but never
//! propagates.  The server is fully functional while GC is running or if a
//! pass fails.
//!
//! # Design note
//!
//! The GC concerns are intentionally separated:
//!
//! - **Cap row GC** is authority-semantic: a row is safe to reclaim when its
//!   epoch is closed and its retention window has passed.  Epoch advance is
//!   the GC barrier; expiry bounds the cohort.
//!
//! - **Snapshot row GC** is purely retention-semantic: old snapshot rows
//!   accumulate because the table is INSERT-only (no natural dead-tuple path
//!   for VACUUM).  The ring-buffer policy keeps the read baseline (`get_latest`)
//!   cheap; the dirty sentinel policy bounds the audit trail size.
//!
//! See THREAT_MODEL.md §4.1 for the authority-arena model that motivates this
//! separation.

use sqlx::PgPool;
use tokio::time::{interval, Duration};

/// Spawn all GC background tasks against the given pool.
///
/// Call once at server startup, after migrations have run.  Each task owns
/// a cloned pool handle so they run fully independently.
pub fn spawn_gc_tasks(pool: PgPool) {
    tracing::info!("GC: spawning cap_gc, snapshot_gc, receipt_gc, and proposal_gc tasks (hourly)");
    tokio::spawn(cap_gc(pool.clone()));
    tokio::spawn(snapshot_gc(pool.clone()));
    tokio::spawn(receipt_gc(pool.clone()));
    tokio::spawn(proposal_gc(pool));
}

// ── Receipt GC ────────────────────────────────────────────────────────────────

/// Compact execution receipt rows.
///
/// Two passes per tick:
/// 1. Expired unused receipts — approval timed out or sidecar crashed.  No
///    audit value; delete after a short grace period (1 hour).
/// 2. Consumed receipts — retain for 30-day audit window then drop.
async fn receipt_gc(pool: PgPool) {
    const EXPIRED_GRACE_SECS: i64 = 3600; // 1 h after expiry
    const CONSUMED_RETAIN_DAYS: i64 = 30;

    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        ticker.tick().await;

        match db::receipts::compact_expired(&pool, EXPIRED_GRACE_SECS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "receipt_gc: compacted expired unused receipts"),
            Err(e) => tracing::warn!(error = %e, "receipt_gc: compact_expired failed"),
        }
        match db::receipts::compact_consumed(&pool, CONSUMED_RETAIN_DAYS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "receipt_gc: expired consumed receipts"),
            Err(e) => tracing::warn!(error = %e, "receipt_gc: compact_consumed failed"),
        }
    }
}

// ── Proposal & attestation GC ─────────────────────────────────────────────────

/// Compact write proposal and file-write attestation rows.
///
/// Three passes per tick:
/// 1. Expire pending proposals whose TTL elapsed — marks them rejected so the
///    audit log explains why they didn't land.
/// 2. Delete resolved (committed or rejected) proposals after 30-day retention.
/// 3. Delete non-mismatch attestation rows after 30-day retention.
///    **Mismatch rows are never deleted** — they are permanent security events.
async fn proposal_gc(pool: PgPool) {
    const RETAIN_DAYS: i64 = 30;

    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        ticker.tick().await;

        match db::proposals::compact_expired(&pool).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(expired = n, "proposal_gc: expired pending proposals"),
            Err(e) => tracing::warn!(error = %e, "proposal_gc: compact_expired failed"),
        }
        match db::proposals::compact_resolved(&pool, RETAIN_DAYS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "proposal_gc: deleted resolved proposals"),
            Err(e) => tracing::warn!(error = %e, "proposal_gc: compact_resolved failed"),
        }
        match db::proposals::compact_attestations(&pool, RETAIN_DAYS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(
                deleted = n,
                "proposal_gc: deleted non-mismatch attestations"
            ),
            Err(e) => tracing::warn!(error = %e, "proposal_gc: compact_attestations failed"),
        }
    }
}

// ── Cap GC ────────────────────────────────────────────────────────────────────

/// Compact revoked cap token rows.
///
/// Epoch advance is the GC barrier; this job is the reclamation pass that
/// fires lazily (every hour) after the drain window and a 7-day audit buffer.
async fn cap_gc(pool: PgPool) {
    const RETENTION_DAYS: i64 = 7;
    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        ticker.tick().await;
        match db::tokens::compact_revoked(&pool, RETENTION_DAYS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "cap_gc: compacted revoked token rows"),
            Err(e) => tracing::warn!(error = %e, "cap_gc: pass failed"),
        }
    }
}

// ── Snapshot GC ───────────────────────────────────────────────────────────────

/// Compact historical snapshot rows.
///
/// Two independent passes per tick:
/// 1. Ring-buffer compaction: keep the 50 most recent clean rows per session.
/// 2. Dirty sentinel compaction: drop dirty markers older than 30 days.
async fn snapshot_gc(pool: PgPool) {
    const KEEP_N_CLEAN: i64 = 50;
    const DIRTY_RETENTION_DAYS: i64 = 30;

    let mut ticker = interval(Duration::from_secs(3600));
    loop {
        ticker.tick().await;

        // Pass 1: ring-buffer compaction of clean rows.
        match db::snapshots::compact_all(&pool, KEEP_N_CLEAN).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "snapshot_gc: compacted clean rows"),
            Err(e) => tracing::warn!(error = %e, "snapshot_gc: compact_all failed"),
        }

        // Pass 2: expire old dirty sentinels.
        match db::snapshots::compact_dirty_sentinels(&pool, DIRTY_RETENTION_DAYS).await {
            Ok(0) => {}
            Ok(n) => tracing::info!(deleted = n, "snapshot_gc: expired dirty sentinels"),
            Err(e) => tracing::warn!(error = %e, "snapshot_gc: compact_dirty_sentinels failed"),
        }
    }
}
