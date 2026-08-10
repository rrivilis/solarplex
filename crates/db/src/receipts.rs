//! Execution receipts — single-use arg-bound authorization tokens (ORB layer 2).
//!
//! When the invoke endpoint approves a tool call it issues a receipt binding
//! `(cap_id, method, args)`.  The sidecar fetches and atomically consumes the
//! receipt before executing.  The server's stored `args` are authoritative —
//! the sidecar executes those verbatim, closing the post-approval args-swap gap.
//!
//! Single-use is enforced by the `consume` function's UPDATE … WHERE used_at IS
//! NULL: only the first caller wins; concurrent consume attempts return NotFound.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use ulid::Ulid;

use crate::{DbError, DbResult};

// ── Row type ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ReceiptRow {
    pub id:          String,
    pub cap_id:      String,
    pub session_id:  String,
    /// Full method address: `"mcp.{slug}.{method}"`.
    pub method:      String,
    /// Server-canonical args — what the sidecar MUST execute.
    pub args:        serde_json::Value,
    pub issued_at:   DateTime<Utc>,
    pub expires_at:  DateTime<Utc>,
    pub used_at:     Option<DateTime<Utc>>,
    pub approval_id: Option<String>,
}

// ── Writes ────────────────────────────────────────────────────────────────────

/// Issue a new execution receipt.
///
/// `ttl_secs` controls how long the receipt is valid before the sidecar must
/// present it; default in the invoke handler is 120 s (enough for approval wait
/// plus execution).  Receipts that expire unused are cleaned up by `gc.rs`.
pub async fn issue(
    pool:        &PgPool,
    cap_id:      &str,
    session_id:  &str,
    method:      &str,
    args:        &serde_json::Value,
    ttl_secs:    i64,
    approval_id: Option<&str>,
) -> DbResult<ReceiptRow> {
    let id         = Ulid::new().to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(ttl_secs);
    sqlx::query_as::<_, ReceiptRow>(
        "INSERT INTO execution_receipts
             (id, cap_id, session_id, method, args, expires_at, approval_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, cap_id, session_id, method, args, issued_at, expires_at,
                   used_at, approval_id",
    )
    .bind(&id)
    .bind(cap_id)
    .bind(session_id)
    .bind(method)
    .bind(args)
    .bind(expires_at)
    .bind(approval_id)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Atomically consume a receipt: mark `used_at = NOW()` and return the row.
///
/// Returns `DbError::NotFound` if:
/// - the receipt doesn't exist
/// - it's already been consumed (`used_at IS NOT NULL`)
/// - it has expired (`expires_at <= NOW()`)
///
/// This single UPDATE enforces single-use atomically — no concurrent consume
/// can slip through.
pub async fn consume(pool: &PgPool, receipt_id: &str) -> DbResult<ReceiptRow> {
    sqlx::query_as::<_, ReceiptRow>(
        "UPDATE execution_receipts
         SET used_at = NOW()
         WHERE id          = $1
           AND used_at     IS NULL
           AND expires_at  > NOW()
         RETURNING id, cap_id, session_id, method, args, issued_at, expires_at,
                   used_at, approval_id",
    )
    .bind(receipt_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Fetch a receipt without consuming it (for inspection / debugging).
pub async fn get(pool: &PgPool, receipt_id: &str) -> DbResult<ReceiptRow> {
    sqlx::query_as::<_, ReceiptRow>(
        "SELECT id, cap_id, session_id, method, args, issued_at, expires_at,
                used_at, approval_id
         FROM execution_receipts WHERE id = $1",
    )
    .bind(receipt_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

// ── GC helper (used by gc.rs) ─────────────────────────────────────────────────

/// Delete expired unused receipts older than `retention_secs`.
///
/// Receipts that were consumed are kept for the audit window; unconsumed expired
/// receipts (approval took too long, sidecar crashed, etc.) are purely waste.
pub async fn compact_expired(pool: &PgPool, retention_secs: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM execution_receipts
         WHERE used_at  IS NULL
           AND expires_at < NOW() - make_interval(secs => $1::int)",
    )
    .bind(retention_secs)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Delete consumed receipts older than `retention_days` (audit window).
pub async fn compact_consumed(pool: &PgPool, retention_days: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM execution_receipts
         WHERE used_at  IS NOT NULL
           AND used_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(retention_days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
