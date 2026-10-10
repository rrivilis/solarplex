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
    pub id: String,
    pub cap_id: String,
    pub session_id: String,
    /// Full method address: `"mcp.{slug}.{method}"`.
    pub method: String,
    /// Server-canonical args — what the sidecar MUST execute.
    pub args: serde_json::Value,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub approval_id: Option<String>,
}

// ── Writes ────────────────────────────────────────────────────────────────────

/// Issue a new execution receipt.
///
/// `ttl_secs` controls how long the receipt is valid before the sidecar must
/// present it; default in the invoke handler is 120 s (enough for approval wait
/// plus execution).  Receipts that expire unused are cleaned up by `gc.rs`.
pub async fn issue(
    pool: &PgPool,
    cap_id: &str,
    session_id: &str,
    method: &str,
    args: &serde_json::Value,
    ttl_secs: i64,
    approval_id: Option<&str>,
) -> DbResult<ReceiptRow> {
    let id = Ulid::new().to_string();
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
/// Returns `DbError::NotFound` unless *every* one of these holds, evaluated in
/// the same statement that marks the receipt used:
/// - the receipt exists and belongs to `session_id`
/// - it hasn't been consumed (`used_at IS NULL`) or expired
/// - the cap it was issued under is still live: not revoked, not expired, and
///   its epoch still matches the session's current epoch
/// - if the receipt is bound to an approval, that approval is `Approved`
///
/// The cap and approval conditions are re-checked here, not just when the
/// receipt was issued, because a receipt outlives the request that created it
/// (30 s auto-approved, longer while a human decides). Without the re-check a
/// cap revoked in that window, or a receipt whose approval was denied,
/// expired, or never granted, would still hand out its canonical args.
///
/// A single UPDATE enforces all of it atomically with single-use: no
/// concurrent consume can slip through, and nothing can change between the
/// checks and the mark.
pub async fn consume(pool: &PgPool, session_id: &str, receipt_id: &str) -> DbResult<ReceiptRow> {
    sqlx::query_as::<_, ReceiptRow>(
        "UPDATE execution_receipts r
         SET used_at = NOW()
         FROM session_tokens t
         WHERE r.id          = $1
           AND r.session_id  = $2
           AND r.used_at     IS NULL
           AND r.expires_at  > NOW()
           AND t.id          = r.cap_id
           AND t.session_id  = r.session_id
           AND t.revoked_at  IS NULL
           AND t.expires_at  > NOW()
           AND t.epoch = COALESCE(
                 (SELECT e.epoch FROM session_epochs e WHERE e.session_id = r.session_id), 0)
           AND (r.approval_id IS NULL
                OR EXISTS (SELECT 1 FROM approval_requests a
                           WHERE a.id = r.approval_id
                             AND a.session_id = r.session_id
                             AND a.state = 'Approved'))
         RETURNING r.id, r.cap_id, r.session_id, r.method, r.args, r.issued_at,
                   r.expires_at, r.used_at, r.approval_id",
    )
    .bind(receipt_id)
    .bind(session_id)
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

// ── Tests ─────────────────────────────────────────────────────────────────────
//
// Live-DB tests: `consume`'s whole job is a set of conditions evaluated inside
// one SQL statement, so there is nothing meaningful to test without a real
// Postgres. `#[ignore]`d so `cargo test --workspace` stays DB-free; run with a
// scratch database that has every migration applied:
//   DATABASE_URL=postgres://... cargo test -p db --lib receipts -- --ignored --test-threads=1

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{actors, approvals, epochs, sessions, tokens};

    struct Fx {
        pool: PgPool,
        session_id: String,
        actor_id: String,
        cap_id: String,
    }

    impl Fx {
        async fn new() -> Self {
            let url = std::env::var("DATABASE_URL")
                .expect("DATABASE_URL must be set to run this live-DB test");
            let pool = PgPool::connect(&url).await.expect("connect");
            let human = actors::create_human(
                &pool,
                actors::CreateHuman {
                    name: "receipt-test".into(),
                    email: format!("receipt-test-{}@example.invalid", Ulid::new()),
                },
            )
            .await
            .expect("create human");
            let created = sessions::create(
                &pool,
                sessions::CreateSession {
                    name: "receipt-test".into(),
                    description: None,
                    created_by: human.id.clone(),
                    approval_policy: None,
                },
            )
            .await
            .expect("create session");
            let session_id = created.session.id.clone();
            epochs::seed(&pool, &session_id).await.expect("seed epoch");
            let cap_id = Ulid::new().to_string();
            tokens::insert(
                &pool,
                &cap_id,
                &session_id,
                &human.id,
                Utc::now() + chrono::Duration::hours(1),
                None,
                0,
                &["mcp.test.tool".to_string()],
            )
            .await
            .expect("insert cap");
            Self {
                pool,
                session_id,
                actor_id: human.id,
                cap_id,
            }
        }

        async fn receipt(&self, approval_id: Option<&str>) -> ReceiptRow {
            issue(
                &self.pool,
                &self.cap_id,
                &self.session_id,
                "mcp.test.tool",
                &serde_json::json!({"path": "/tmp/x"}),
                60,
                approval_id,
            )
            .await
            .expect("issue receipt")
        }

        async fn approval(&self, state: &str) -> String {
            let row = approvals::create(
                &self.pool,
                approvals::CreateApproval {
                    session_id: self.session_id.clone(),
                    actor_id: self.actor_id.clone(),
                    tool_name: "mcp.test.tool".into(),
                    arguments: serde_json::json!({}),
                    timeout_at: None,
                },
            )
            .await
            .expect("create approval");
            sqlx::query("UPDATE approval_requests SET state = $1 WHERE id = $2")
                .bind(state)
                .bind(&row.id)
                .execute(&self.pool)
                .await
                .expect("set approval state");
            row.id
        }
    }

    #[tokio::test]
    #[ignore]
    async fn consume_returns_canonical_args_once() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        let got = consume(&f.pool, &f.session_id, &r.id)
            .await
            .expect("first consume succeeds");
        assert_eq!(got.args, serde_json::json!({"path": "/tmp/x"}));
        assert!(got.used_at.is_some());
        assert!(
            matches!(
                consume(&f.pool, &f.session_id, &r.id).await,
                Err(DbError::NotFound)
            ),
            "a receipt is single-use"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn concurrent_consumes_have_exactly_one_winner() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        let results = futures_join_all(
            (0..8)
                .map(|_| {
                    let (pool, sid, rid) = (f.pool.clone(), f.session_id.clone(), r.id.clone());
                    tokio::spawn(async move { consume(&pool, &sid, &rid).await.is_ok() })
                })
                .collect(),
        )
        .await;
        assert_eq!(results.iter().filter(|ok| **ok).count(), 1);
    }

    async fn futures_join_all(handles: Vec<tokio::task::JoinHandle<bool>>) -> Vec<bool> {
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await.expect("task"));
        }
        out
    }

    /// A caller naming another session must neither read the args nor burn the
    /// receipt (the old handler consumed first and checked the session after).
    #[tokio::test]
    #[ignore]
    async fn consume_is_scoped_to_the_receipts_session_and_does_not_burn_it() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        assert!(matches!(
            consume(&f.pool, "some-other-session", &r.id).await,
            Err(DbError::NotFound)
        ));
        assert!(
            consume(&f.pool, &f.session_id, &r.id).await.is_ok(),
            "a wrong-session attempt must not consume the receipt"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn consume_refused_after_cap_revoked() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        sqlx::query("UPDATE session_tokens SET revoked_at = NOW() WHERE id = $1")
            .bind(&f.cap_id)
            .execute(&f.pool)
            .await
            .expect("revoke cap");
        assert!(matches!(
            consume(&f.pool, &f.session_id, &r.id).await,
            Err(DbError::NotFound)
        ));
    }

    #[tokio::test]
    #[ignore]
    async fn consume_refused_after_epoch_advanced() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        epochs::advance(&f.pool, &f.session_id)
            .await
            .expect("advance epoch");
        assert!(matches!(
            consume(&f.pool, &f.session_id, &r.id).await,
            Err(DbError::NotFound)
        ));
    }

    #[tokio::test]
    #[ignore]
    async fn consume_refused_after_cap_expired() {
        let f = Fx::new().await;
        let r = f.receipt(None).await;
        sqlx::query(
            "UPDATE session_tokens SET expires_at = NOW() - interval '1 second' WHERE id = $1",
        )
        .bind(&f.cap_id)
        .execute(&f.pool)
        .await
        .expect("expire cap");
        assert!(matches!(
            consume(&f.pool, &f.session_id, &r.id).await,
            Err(DbError::NotFound)
        ));
    }

    /// A receipt bound to an approval is only usable once that approval is
    /// `Approved`: anything else (still open, denied, expired) must refuse.
    #[tokio::test]
    #[ignore]
    async fn consume_requires_the_bound_approval_to_be_approved() {
        for (state, usable) in [
            ("Pending", false),
            ("Claimed", false),
            ("Contested", false),
            ("Denied", false),
            ("Expired", false),
            ("Approved", true),
        ] {
            let f = Fx::new().await;
            let approval_id = f.approval(state).await;
            let r = f.receipt(Some(&approval_id)).await;
            let got = consume(&f.pool, &f.session_id, &r.id).await;
            assert_eq!(
                got.is_ok(),
                usable,
                "receipt bound to a {state} approval: expected usable={usable}"
            );
        }
    }

    /// The approval can resolve *after* the receipt was issued (the normal
    /// flow): refused while pending, usable the moment it is approved.
    #[tokio::test]
    #[ignore]
    async fn consume_unlocks_when_the_approval_is_later_approved() {
        let f = Fx::new().await;
        let approval_id = f.approval("Pending").await;
        let r = f.receipt(Some(&approval_id)).await;
        assert!(consume(&f.pool, &f.session_id, &r.id).await.is_err());
        sqlx::query("UPDATE approval_requests SET state = 'Approved' WHERE id = $1")
            .bind(&approval_id)
            .execute(&f.pool)
            .await
            .expect("approve");
        assert!(
            consume(&f.pool, &f.session_id, &r.id).await.is_ok(),
            "a refused consume must not have burned the receipt"
        );
    }

    #[tokio::test]
    #[ignore]
    async fn consume_refused_after_receipt_expiry() {
        let f = Fx::new().await;
        let r = issue(
            &f.pool,
            &f.cap_id,
            &f.session_id,
            "mcp.test.tool",
            &serde_json::json!({}),
            -5,
            None,
        )
        .await
        .expect("issue already-expired receipt");
        assert!(matches!(
            consume(&f.pool, &f.session_id, &r.id).await,
            Err(DbError::NotFound)
        ));
    }
}
