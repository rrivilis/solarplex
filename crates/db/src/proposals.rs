//! Write-proposal and file-write-attestation persistence layer.
//!
//! ## Tier 1 — Solarplex-managed state (write_proposals)
//!
//! Every structured mutation of server-managed state goes through a proposal:
//! create → commit (or reject).  The commit path in the server route enforces
//! the CAS precondition `expected_hash_before` inside a single Postgres
//! transaction, so proposals cannot land against stale state.
//!
//! ## Tier 2 — Filesystem writes (file_write_attestations)
//!
//! Filesystem writes are executed by the sidecar (the server cannot atomically
//! CAS a file).  The sidecar reads before/after hashes and posts an attestation
//! immediately after the write completes.  A `hash_mismatch` flag (generated
//! column in Postgres) marks divergence between approved and observed hashes —
//! a queryable security event in the audit log.
//!
//! See THREAT_MODEL.md §4.2 (three-tier commitment model) for full analysis.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

// ── Proposal ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProposalRow {
    pub id: String,
    pub receipt_id: String,
    pub cap_id: String,
    pub session_id: String,
    pub method: String,
    pub canonical_args_hash: String,
    pub effect_type: String,
    pub effect_payload: serde_json::Value,
    pub expected_hash_before: String,
    pub claimed_hash_after: String,
    pub proposed_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub committed_at: Option<DateTime<Utc>>,
    pub rejected_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
    pub commit_event_id: Option<String>,
}

pub struct CreateProposal {
    pub receipt_id: String,
    pub cap_id: String,
    pub session_id: String,
    pub method: String,
    pub canonical_args_hash: String,
    pub effect_type: String,
    pub effect_payload: serde_json::Value,
    pub expected_hash_before: String,
    pub claimed_hash_after: String,
    /// Seconds until this proposal expires if not acted on.
    pub ttl_secs: i64,
}

pub async fn create(pool: &PgPool, input: CreateProposal) -> DbResult<ProposalRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, ProposalRow>(
        "INSERT INTO write_proposals (
             id, receipt_id, cap_id, session_id, method,
             canonical_args_hash, effect_type, effect_payload,
             expected_hash_before, claimed_hash_after, expires_at
         )
         VALUES (
             $1,  $2,  $3,  $4,  $5,
             $6,  $7,  $8::jsonb,
             $9,  $10,
             NOW() + ($11 || ' seconds')::interval
         )
         RETURNING
             id, receipt_id, cap_id, session_id, method,
             canonical_args_hash, effect_type, effect_payload,
             expected_hash_before, claimed_hash_after,
             proposed_at, expires_at,
             committed_at, rejected_at, rejection_reason, commit_event_id",
    )
    .bind(&id)
    .bind(&input.receipt_id)
    .bind(&input.cap_id)
    .bind(&input.session_id)
    .bind(&input.method)
    .bind(&input.canonical_args_hash)
    .bind(&input.effect_type)
    .bind(&input.effect_payload)
    .bind(&input.expected_hash_before)
    .bind(&input.claimed_hash_after)
    .bind(input.ttl_secs)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        // Surface unique-constraint violations (duplicate receipt_id) as Conflict.
        if let sqlx::Error::Database(ref de) = e {
            if de.code().as_deref() == Some("23505") {
                return DbError::Conflict("a proposal already exists for this receipt".into());
            }
        }
        DbError::Sqlx(e)
    })
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<ProposalRow> {
    sqlx::query_as::<_, ProposalRow>(
        "SELECT id, receipt_id, cap_id, session_id, method,
                canonical_args_hash, effect_type, effect_payload,
                expected_hash_before, claimed_hash_after,
                proposed_at, expires_at,
                committed_at, rejected_at, rejection_reason, commit_event_id
         FROM write_proposals WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn list_pending(pool: &PgPool, session_id: &str) -> DbResult<Vec<ProposalRow>> {
    sqlx::query_as::<_, ProposalRow>(
        "SELECT id, receipt_id, cap_id, session_id, method,
                canonical_args_hash, effect_type, effect_payload,
                expected_hash_before, claimed_hash_after,
                proposed_at, expires_at,
                committed_at, rejected_at, rejection_reason, commit_event_id
         FROM write_proposals
         WHERE session_id = $1
           AND committed_at IS NULL
           AND rejected_at  IS NULL
           AND expires_at   > NOW()
         ORDER BY proposed_at DESC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Lock a proposal row for the commit path.
///
/// `SELECT … FOR UPDATE` serializes concurrent commit attempts on the same
/// proposal; combined with the pending-state check the caller performs, this
/// ensures exactly-once commit semantics.
///
/// Call this inside an open transaction; the lock is released at COMMIT.
pub async fn get_for_commit(
    tx: &mut Transaction<'_, Postgres>,
    proposal_id: &str,
) -> DbResult<ProposalRow> {
    sqlx::query_as::<_, ProposalRow>(
        "SELECT id, receipt_id, cap_id, session_id, method,
                canonical_args_hash, effect_type, effect_payload,
                expected_hash_before, claimed_hash_after,
                proposed_at, expires_at,
                committed_at, rejected_at, rejection_reason, commit_event_id
         FROM write_proposals
         WHERE id = $1
         FOR UPDATE",
    )
    .bind(proposal_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)
}

/// Mark a proposal as successfully committed.
///
/// Must be called inside the same transaction that applied the effect, so the
/// state mutation and the audit record land atomically.
pub async fn mark_committed(
    tx: &mut Transaction<'_, Postgres>,
    proposal_id: &str,
    event_id: &str,
) -> DbResult<()> {
    let n = sqlx::query(
        "UPDATE write_proposals
         SET committed_at   = NOW(),
             commit_event_id = $1
         WHERE id = $2
           AND committed_at IS NULL
           AND rejected_at  IS NULL",
    )
    .bind(event_id)
    .bind(proposal_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(DbError::Conflict("proposal already resolved".into()));
    }
    Ok(())
}

/// Mark a proposal as rejected (CAS mismatch, validation failure, or expiry).
///
/// May be called inside a transaction (e.g. when the mismatch is discovered
/// after locking the row) or on the pool directly (expiry GC path).
pub async fn mark_rejected_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    proposal_id: &str,
    reason: &str,
) -> DbResult<()> {
    let n = sqlx::query(
        "UPDATE write_proposals
         SET rejected_at      = NOW(),
             rejection_reason = $1
         WHERE id = $2
           AND committed_at IS NULL
           AND rejected_at  IS NULL",
    )
    .bind(reason)
    .bind(proposal_id)
    .execute(&mut **tx)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(DbError::Conflict("proposal already resolved".into()));
    }
    Ok(())
}

// ── GC ───────────────────────────────────────────────────────────────────────

/// Expire proposals whose TTL has elapsed without resolution.
///
/// Sets `rejected_at = NOW()` with reason `"expired"` so the audit trail
/// records why the proposal did not land.  Returns the count of rows updated.
pub async fn compact_expired(pool: &PgPool) -> DbResult<u64> {
    let row = sqlx::query(
        "UPDATE write_proposals
         SET rejected_at      = NOW(),
             rejection_reason = 'expired'
         WHERE committed_at IS NULL
           AND rejected_at  IS NULL
           AND expires_at   < NOW()
         RETURNING id",
    )
    .fetch_all(pool)
    .await?;
    Ok(row.len() as u64)
}

/// Delete committed and rejected proposals older than `retain_days`.
///
/// Resolved proposals are an audit trail — keep them for `retain_days` before
/// reclaiming disk space.  Mismatched attestations (Tier 2) have their own GC.
pub async fn compact_resolved(pool: &PgPool, retain_days: i64) -> DbResult<u64> {
    let n = sqlx::query(
        "DELETE FROM write_proposals
         WHERE (committed_at IS NOT NULL OR rejected_at IS NOT NULL)
           AND COALESCE(committed_at, rejected_at) < NOW() - ($1 || ' days')::interval",
    )
    .bind(retain_days)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}

// ── File-write attestations ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AttestationRow {
    pub id: String,
    pub receipt_id: String,
    pub session_id: String,
    pub cap_id: String,
    pub actor_id: String,
    pub tool: String,
    pub path: String,
    pub approved_hash_before: String,
    pub approved_hash_after: String,
    pub observed_hash_before: String,
    pub actual_hash_after: String,
    pub hash_mismatch: bool,
    pub attested_at: DateTime<Utc>,
}

pub struct CreateAttestation {
    pub receipt_id: String,
    pub session_id: String,
    pub cap_id: String,
    pub actor_id: String,
    pub tool: String,
    pub path: String,
    pub approved_hash_before: String,
    pub approved_hash_after: String,
    pub observed_hash_before: String,
    pub actual_hash_after: String,
}

pub async fn attest(pool: &PgPool, input: CreateAttestation) -> DbResult<AttestationRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, AttestationRow>(
        "INSERT INTO file_write_attestations (
             id, receipt_id, session_id, cap_id, actor_id,
             tool, path,
             approved_hash_before, approved_hash_after,
             observed_hash_before, actual_hash_after
         )
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING
             id, receipt_id, session_id, cap_id, actor_id,
             tool, path,
             approved_hash_before, approved_hash_after,
             observed_hash_before, actual_hash_after,
             hash_mismatch, attested_at",
    )
    .bind(&id)
    .bind(&input.receipt_id)
    .bind(&input.session_id)
    .bind(&input.cap_id)
    .bind(&input.actor_id)
    .bind(&input.tool)
    .bind(&input.path)
    .bind(&input.approved_hash_before)
    .bind(&input.approved_hash_after)
    .bind(&input.observed_hash_before)
    .bind(&input.actual_hash_after)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_attestations(
    pool: &PgPool,
    session_id: &str,
    limit: i64,
) -> DbResult<Vec<AttestationRow>> {
    sqlx::query_as::<_, AttestationRow>(
        "SELECT id, receipt_id, session_id, cap_id, actor_id,
                tool, path,
                approved_hash_before, approved_hash_after,
                observed_hash_before, actual_hash_after,
                hash_mismatch, attested_at
         FROM file_write_attestations
         WHERE session_id = $1
         ORDER BY attested_at DESC
         LIMIT $2",
    )
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// All attestations with `hash_mismatch = true` for the session.
///
/// These are security events: the filesystem was in a different state than the
/// human approved, or the write produced a different result.  Use for alerting
/// and audit dashboards.
pub async fn list_mismatches(pool: &PgPool, session_id: &str) -> DbResult<Vec<AttestationRow>> {
    sqlx::query_as::<_, AttestationRow>(
        "SELECT id, receipt_id, session_id, cap_id, actor_id,
                tool, path,
                approved_hash_before, approved_hash_after,
                observed_hash_before, actual_hash_after,
                hash_mismatch, attested_at
         FROM file_write_attestations
         WHERE session_id = $1
           AND hash_mismatch = true
         ORDER BY attested_at DESC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// GC: delete attestation rows older than `retain_days`.
///
/// Mismatch rows are excluded — they are permanent security events and must be
/// retained indefinitely (or until explicitly purged by an operator).
pub async fn compact_attestations(pool: &PgPool, retain_days: i64) -> DbResult<u64> {
    let n = sqlx::query(
        "DELETE FROM file_write_attestations
         WHERE hash_mismatch = false
           AND attested_at < NOW() - ($1 || ' days')::interval",
    )
    .bind(retain_days)
    .execute(pool)
    .await?
    .rows_affected();
    Ok(n)
}
