//! Three-tier commitment model — write-proposal and attestation routes.
//!
//! ## Endpoints
//!
//! - `POST /sessions/{id}/propose`            — create a Tier-1 write proposal
//! - `GET  /sessions/{id}/proposals`          — list pending proposals
//! - `POST /sessions/{id}/proposals/{pid}/commit` — atomic CAS commit
//! - `POST /sessions/{id}/attest`             — Tier-2 file-write attestation
//! - `GET  /sessions/{id}/attestations`       — list attestations (optionally mismatch-only)
//!
//! ## Tier 1 commit path
//!
//! For `artifact_patch`:
//!   1. BEGIN
//!   2. SELECT artifact FOR UPDATE  (lock prevents concurrent landing)
//!   3. sha256(storage_ref) == expected_hash_before?  → reject if not
//!   4. sha256(new_content) == claimed_hash_after?    → reject if not
//!   5. UPDATE artifact + mark proposal committed + append event
//!   6. COMMIT
//!
//! For `context_entry` (append-only, no hash fence):
//!   1. BEGIN
//!   2. Append context entry event
//!   3. Mark proposal committed
//!   4. COMMIT
//!
//! See THREAT_MODEL.md §4.4 (protection ring model — Ring 0 / Ring 1).

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use ulid::Ulid;

use protocol::effects::Tier1Type;
use protocol::types::MemberRole;

use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/propose",                    post(propose_handler))
        .route("/proposals",                  get(list_proposals_handler))
        .route("/proposals/{pid}/commit",      post(commit_handler))
        .route("/attest",                     post(attest_handler))
        .route("/attestations",               get(list_attestations_handler))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Compute `"sha256:<hex>"` of a UTF-8 string.
pub fn sha256_hex(data: &str) -> String {
    let hash = Sha256::digest(data.as_bytes());
    format!("sha256:{:x}", hash)
}

// ── POST /sessions/{id}/propose ────────────────────────────────────────────────

#[derive(Deserialize)]
struct ProposeBody {
    receipt_id:           String,
    cap_id:               String,
    effect_type:          String,
    effect_payload:       serde_json::Value,
    expected_hash_before: String,
    claimed_hash_after:   String,
    /// TTL for this proposal; defaults to 300 s (5 min) if omitted.
    ttl_secs: Option<i64>,
}

#[autometrics]
async fn propose_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<ProposeBody>,
) -> impl IntoResponse {
    // Validate effect_type is in the Ring-0 allowed set.
    if Tier1Type::from_db_str(&body.effect_type).is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unsupported effect_type '{}'; must be artifact_patch or context_entry", body.effect_type),
        ).into_response();
    }

    // Validate the receipt exists and belongs to this session + actor.
    let receipt = match db::receipts::get(&state.db, &body.receipt_id).await {
        Ok(r) => r,
        Err(db::DbError::NotFound) =>
            return (StatusCode::NOT_FOUND, "receipt not found").into_response(),
        Err(e) =>
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if receipt.session_id != session_id {
        return (StatusCode::FORBIDDEN, "receipt session mismatch").into_response();
    }
    if receipt.cap_id != body.cap_id {
        return (StatusCode::FORBIDDEN, "receipt cap mismatch").into_response();
    }

    // Compute canonical_args_hash from the receipt's bound args.
    let canonical_args_str = receipt.args.to_string();
    let canonical_args_hash = sha256_hex(&canonical_args_str);

    let ttl = body.ttl_secs.unwrap_or(300);

    match db::proposals::create(&state.db, db::proposals::CreateProposal {
        receipt_id:           body.receipt_id,
        cap_id:               body.cap_id,
        session_id,
        method:               receipt.method,
        canonical_args_hash,
        effect_type:          body.effect_type,
        effect_payload:       body.effect_payload,
        expected_hash_before: body.expected_hash_before,
        claimed_hash_after:   body.claimed_hash_after,
        ttl_secs:             ttl,
    }).await {
        Ok(row) => Json(serde_json::json!({
            "proposal_id": row.id,
            "status":      "pending",
            "expires_at":  row.expires_at,
        })).into_response(),
        Err(db::DbError::Conflict(msg)) =>
            (StatusCode::CONFLICT, msg).into_response(),
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── GET /sessions/{id}/proposals ───────────────────────────────────────────────

#[autometrics]
async fn list_proposals_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Human-facing audit view (proposal status) — gated same as other
    // session reads. propose/commit/attest stay cap-driven (receipt_id/
    // cap_id chain), a different trust boundary this doesn't touch.
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &session_id, MemberRole::Observer).await {
        return res;
    }
    match db::proposals::list_pending(&state.db, &session_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── POST /sessions/{id}/proposals/{pid}/commit ──────────────────────────────────

#[derive(Deserialize)]
struct CommitBody {
    actor_id: String,
}

#[autometrics]
async fn commit_handler(
    State(state): State<Arc<AppState>>,
    Path((session_id, proposal_id)): Path<(String, String)>,
    Json(body): Json<CommitBody>,
) -> impl IntoResponse {
    // Open a serializable transaction — the whole CAS lives in here.
    let mut tx = match state.db.begin().await {
        Ok(t)  => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Lock the proposal row.
    let proposal = match db::proposals::get_for_commit(&mut tx, &proposal_id).await {
        Ok(p) => p,
        Err(db::DbError::NotFound) => {
            let _ = tx.rollback().await;
            return (StatusCode::NOT_FOUND, "proposal not found").into_response();
        }
        Err(e) => {
            let _ = tx.rollback().await;
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    // Verify the proposal belongs to this session.
    if proposal.session_id != session_id {
        let _ = tx.rollback().await;
        return (StatusCode::FORBIDDEN, "proposal session mismatch").into_response();
    }

    // Reject already-resolved or expired proposals.
    if proposal.committed_at.is_some() {
        let _ = tx.rollback().await;
        return (StatusCode::CONFLICT, "proposal already committed").into_response();
    }
    if proposal.rejected_at.is_some() {
        let _ = tx.rollback().await;
        return (StatusCode::CONFLICT, "proposal already rejected").into_response();
    }
    if proposal.expires_at <= chrono::Utc::now() {
        // Expire it in-transaction so the audit log is accurate.
        let _ = db::proposals::mark_rejected_in_tx(&mut tx, &proposal_id, "expired").await;
        let _ = tx.commit().await;
        return (StatusCode::GONE, "proposal expired").into_response();
    }

    // Dispatch on effect_type — enum-typed so unknown variants are caught at parse, not here.
    let tier1_type = match Tier1Type::from_db_str(&proposal.effect_type) {
        Some(t) => t,
        None => {
            let _ = tx.rollback().await;
            return (StatusCode::UNPROCESSABLE_ENTITY,
                    format!("unknown effect_type in proposal: {}", proposal.effect_type)).into_response();
        }
    };

    let commit_result = match tier1_type {
        Tier1Type::ArtifactPatch =>
            commit_artifact_patch(&state.db, &mut tx, &proposal, &body.actor_id).await,
        Tier1Type::ContextEntry =>
            commit_context_entry(&mut tx, &proposal, &body.actor_id).await,
    };

    match commit_result {
        Ok(event_id) => {
            if let Err(e) = db::proposals::mark_committed(&mut tx, &proposal_id, &event_id).await {
                let _ = tx.rollback().await;
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
            match tx.commit().await {
                Ok(_) => Json(serde_json::json!({
                    "proposal_id": proposal_id,
                    "status":      "committed",
                    "event_id":    event_id,
                })).into_response(),
                Err(e) =>
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        Err(CommitError::CasMismatch(reason)) => {
            // Record the rejection in the same transaction before rolling back
            // is impossible (the CAS mismatch may have dirtied the tx state).
            // Roll back and re-reject on the pool.
            let _ = tx.rollback().await;
            let _ = sqlx::query(
                "UPDATE write_proposals
                 SET rejected_at = NOW(), rejection_reason = $1
                 WHERE id = $2 AND committed_at IS NULL AND rejected_at IS NULL",
            )
            .bind(&reason)
            .bind(&proposal_id)
            .execute(&state.db)
            .await;
            (StatusCode::PRECONDITION_FAILED, reason).into_response()
        }
        Err(CommitError::Db(e)) => {
            let _ = tx.rollback().await;
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

enum CommitError {
    CasMismatch(String),
    Db(db::DbError),
}

impl From<db::DbError> for CommitError {
    fn from(e: db::DbError) -> Self { CommitError::Db(e) }
}

/// Artifact-patch commit: full CAS inside the transaction.
///
/// Effect payload shape: `{ "artifact_id": "...", "content": "..." }`
async fn commit_artifact_patch(
    _pool:    &sqlx::PgPool,
    tx:       &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proposal: &db::proposals::ProposalRow,
    actor_id: &str,
) -> Result<String, CommitError> {
    let artifact_id = proposal.effect_payload["artifact_id"]
        .as_str()
        .ok_or_else(|| CommitError::CasMismatch("effect_payload.artifact_id missing".into()))?;
    let new_content = proposal.effect_payload["content"]
        .as_str()
        .ok_or_else(|| CommitError::CasMismatch("effect_payload.content missing".into()))?;

    // Lock the artifact row — prevents concurrent proposals from racing.
    let artifact_row = sqlx::query_as::<_, db::artifacts::ArtifactRow>(
        "SELECT id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at
         FROM artifacts
         WHERE id = $1 AND session_id = $2
         FOR UPDATE",
    )
    .bind(artifact_id)
    .bind(&proposal.session_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(db::DbError::from)?
    .ok_or_else(|| CommitError::CasMismatch("artifact not found or session mismatch".into()))?;

    // ── H_before check ───────────────────────────────────────────────────────
    let actual_before = sha256_hex(&artifact_row.storage_ref);
    if actual_before != proposal.expected_hash_before {
        return Err(CommitError::CasMismatch(format!(
            "H_before mismatch: artifact has been modified since proposal was created \
             (expected {}, found {})",
            proposal.expected_hash_before, actual_before,
        )));
    }

    // ── H_after check ────────────────────────────────────────────────────────
    let actual_after = sha256_hex(new_content);
    if actual_after != proposal.claimed_hash_after {
        return Err(CommitError::CasMismatch(format!(
            "H_after mismatch: claimed_hash_after does not match sha256(new_content) \
             (claimed {}, computed {})",
            proposal.claimed_hash_after, actual_after,
        )));
    }

    // ── Apply effect ─────────────────────────────────────────────────────────
    sqlx::query(
        "UPDATE artifacts
         SET storage_ref = $1, version = version + 1, updated_at = NOW()
         WHERE id = $2",
    )
    .bind(new_content)
    .bind(artifact_id)
    .execute(&mut **tx)
    .await
    .map_err(db::DbError::from)?;

    // ── Append event ─────────────────────────────────────────────────────────
    let seq = db::events::alloc_seq_block_in_tx(tx, &proposal.session_id, 1).await?;
    let event = db::events::append_in_tx(
        tx,
        &proposal.session_id,
        actor_id,
        "proposal.committed",
        &serde_json::json!({
            "proposal_id": proposal.id,
            "effect_type": "artifact_patch",
            "artifact_id": artifact_id,
            "h_before":    proposal.expected_hash_before,
            "h_after":     actual_after,
        }),
        seq,
    ).await?;

    Ok(event.id)
}

/// Context-entry commit: append-only, no hash fence.
///
/// Effect payload shape: `{ "kind": "hypothesis|decision|...", "content": "..." }`
async fn commit_context_entry(
    tx:       &mut sqlx::Transaction<'_, sqlx::Postgres>,
    proposal: &db::proposals::ProposalRow,
    actor_id: &str,
) -> Result<String, CommitError> {
    let kind = proposal.effect_payload["kind"]
        .as_str()
        .ok_or_else(|| CommitError::CasMismatch("effect_payload.kind missing".into()))?;
    let content = proposal.effect_payload["content"]
        .as_str()
        .ok_or_else(|| CommitError::CasMismatch("effect_payload.content missing".into()))?;

    // Generate the context entry ID.
    let entry_id = Ulid::new().to_string();

    // Append as an event — the context entries projection is built from events.
    let seq = db::events::alloc_seq_block_in_tx(tx, &proposal.session_id, 1).await?;
    let event = db::events::append_in_tx(
        tx,
        &proposal.session_id,
        actor_id,
        "proposal.context_entry.committed",
        &serde_json::json!({
            "proposal_id": proposal.id,
            "entry_id":    entry_id,
            "kind":        kind,
            "content":     content,
        }),
        seq,
    ).await?;

    Ok(event.id)
}

// ── POST /sessions/{id}/attest ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct AttestBody {
    receipt_id:           String,
    cap_id:               String,
    actor_id:             String,
    tool:                 String,
    path:                 String,
    approved_hash_before: String,
    approved_hash_after:  String,
    observed_hash_before: String,
    actual_hash_after:    String,
}

#[autometrics]
async fn attest_handler(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<AttestBody>,
) -> impl IntoResponse {
    // Verify the receipt exists and belongs to this session.
    let receipt = match db::receipts::get(&state.db, &body.receipt_id).await {
        Ok(r) => r,
        Err(db::DbError::NotFound) =>
            return (StatusCode::NOT_FOUND, "receipt not found").into_response(),
        Err(e) =>
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if receipt.session_id != session_id {
        return (StatusCode::FORBIDDEN, "receipt session mismatch").into_response();
    }

    match db::proposals::attest(&state.db, db::proposals::CreateAttestation {
        receipt_id:           body.receipt_id,
        session_id:           session_id.clone(),
        cap_id:               body.cap_id,
        actor_id:             body.actor_id,
        tool:                 body.tool,
        path:                 body.path,
        approved_hash_before: body.approved_hash_before,
        approved_hash_after:  body.approved_hash_after,
        observed_hash_before: body.observed_hash_before,
        actual_hash_after:    body.actual_hash_after,
    }).await {
        Ok(row) => {
            let status = if row.hash_mismatch {
                tracing::warn!(
                    session_id = %session_id,
                    receipt_id = %row.receipt_id,
                    path       = %row.path,
                    "file-write hash mismatch: security event recorded",
                );
                StatusCode::ACCEPTED
            } else {
                StatusCode::CREATED
            };
            (status, Json(serde_json::json!({
                "attestation_id": row.id,
                "hash_mismatch":  row.hash_mismatch,
            }))).into_response()
        }
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── GET /sessions/{id}/attestations ───────────────────────────────────────────

#[derive(Deserialize)]
struct AttestationsQuery {
    mismatch_only: Option<bool>,
    limit:         Option<i64>,
}

#[autometrics]
async fn list_attestations_handler(
    State(state):    State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Query(params):   Query<AttestationsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &session_id, MemberRole::Observer).await {
        return res;
    }
    if params.mismatch_only.unwrap_or(false) {
        match db::proposals::list_mismatches(&state.db, &session_id).await {
            Ok(rows) => Json(rows).into_response(),
            Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        let limit = params.limit.unwrap_or(100).min(500);
        match db::proposals::list_attestations(&state.db, &session_id, limit).await {
            Ok(rows) => Json(rows).into_response(),
            Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}
