use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use serde::Deserialize;

use protocol::types::{MemberRole, Vote};
use session::rate_limit::RateLimitKey;
use crate::rate_limit::gate_session;
use crate::state::AppState;
use crate::ws::vote_on_approval;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/pending", get(list_pending_for_actor))
        .route("/:id",                  get(get_for_guardian))
        .route("/:id/resolution",       get(poll_resolution))
        .route("/:id/vote",             post(cast_vote))
        .route("/:id/delegate",         post(delegate_cross_session))
        .route("/:id/scout",            patch(patch_scout_manifest))
        .route("/:id/execution",        patch(patch_execution_manifest))
        .route("/:id/declared-effects", patch(patch_declared_effects_handler))
}

// ── Auth helpers ──────────────────────────────────────────────────────────────
//
// extract_bearer/require_sp_auth now live in crate::auth — shared with every
// other REST handler that needs a verified human identity.
use crate::auth::require_sp_auth;

/// Validate X-Session-Id + X-Actor-Id headers for shim-originated requests
/// (scout/execution manifest patches, resolution poll).
///
/// Verifies:
///   1. Both headers are present.
///   2. The stated actor is a member of the stated session.
///   3. The approval belongs to the stated session.
///
/// Returns the fetched `ApprovalRow` on success so callers avoid a second lookup.
/// Returns `(actor_id, approval)` on success — callers that need the actor
/// id too (e.g. to rate-limit gate) no longer have to re-parse the header.
async fn require_shim_auth(
    state:       &Arc<AppState>,
    headers:     &HeaderMap,
    approval_id: &str,
) -> Result<(String, db::approvals::ApprovalRow), axum::response::Response> {
    let session_id = headers.get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "X-Session-Id header required").into_response())?
        .to_string();
    let actor_id = headers.get("x-actor-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "X-Actor-Id header required").into_response())?
        .to_string();

    // Verify session membership first (cheap; prevents cross-session IDOR
    // even if the approval_id lookup were to return a row from another session).
    db::sessions::get_membership(&state.db, &session_id, &actor_id).await.map_err(|_| {
        (StatusCode::FORBIDDEN, "actor is not a member of the stated session").into_response()
    })?;

    // Fetch the approval and confirm it belongs to this session.
    let row = match db::approvals::get(&state.db, approval_id).await {
        Ok(r)                      => r,
        Err(db::DbError::NotFound) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
    };
    if row.session_id != session_id {
        tracing::error!(
            approval_id, session_id, approval_session = %row.session_id,
            "require_shim_auth: approval belongs to a different session"
        );
        return Err((StatusCode::FORBIDDEN, "approval does not belong to the stated session")
            .into_response());
    }
    Ok((actor_id, row))
}

// ── GET /api/approvals/pending ─────────────────────────────────────────────────

/// Returns pending approvals for the authenticated actor.
/// Requires `Authorization: Bearer <sp_token>` — the query-param fallback
/// that used to accept a self-asserted actor_id has been removed.
async fn list_pending_for_actor(
    headers:       HeaderMap,
    State(state):  State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::approvals::list_pending_for_actor(&state.db, &actor_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── GET /api/approvals/:id (guardian fetch) ────────────────────────────────────

/// Guardian calls this to fetch the server-canonical command and declared effects
/// for an approval.  The caller must supply:
///   X-Session-Id: <session_id>
///   X-Actor-Id:   <actor_id>
/// The server verifies that the actor is a member of the session that owns
/// this approval, preventing cross-session IDOR.
async fn get_for_guardian(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
) -> impl IntoResponse {
    let session_id = match headers.get("x-session-id").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_string(),
        None    => return (StatusCode::BAD_REQUEST, "X-Session-Id header required").into_response(),
    };
    let actor_id = match headers.get("x-actor-id").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_string(),
        None    => return (StatusCode::BAD_REQUEST, "X-Actor-Id header required").into_response(),
    };

    // Verify the actor is a member of the stated session.
    match db::sessions::get_membership(&state.db, &session_id, &actor_id).await {
        Ok(_)                      => {}
        Err(db::DbError::NotFound) => {
            tracing::warn!(
                approval_id, session_id, actor_id,
                "get_for_guardian: actor is not a session member"
            );
            return (StatusCode::FORBIDDEN, "actor is not a member of the stated session")
                .into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    // Fetch the approval and verify it belongs to the stated session.
    let row = match db::approvals::get_with_effects(&state.db, &approval_id).await {
        Ok(r)                      => r,
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if row.session_id != session_id {
        tracing::error!(
            approval_id, session_id, approval_session = %row.session_id,
            "get_for_guardian: approval belongs to a different session"
        );
        return (StatusCode::FORBIDDEN, "approval does not belong to the stated session")
            .into_response();
    }

    let decision = match row.state.as_str() {
        "Approved" => "granted",
        "Denied"   => "denied",
        other      => other,
    };

    let approved_command = row.arguments.get("command")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Json(serde_json::json!({
        "decision":          decision,
        "approved_command":  approved_command,
        "declared_effects":  row.declared_effects,
    }))
    .into_response()
}

// ── POST /api/approvals/:id/vote ──────────────────────────────────────────────

/// POST /api/approvals/:id/vote
///
/// Requires `Authorization: Bearer <sp_token>`. The actor_id is derived from
/// the token server-side; `actor_id` in the request body is ignored.
#[derive(Deserialize)]
struct CastVoteBody {
    #[allow(dead_code)]
    actor_id: Option<String>, // kept for backward compat JSON parsing; ignored
    decision: String,         // "grant" | "deny"
}

async fn cast_vote(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
    Json(body):        Json<CastVoteBody>,
) -> impl IntoResponse {
    // Actor identity must come from a validated sp_token, never from the body.
    let actor_id = match require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let row = match db::approvals::get(&state.db, &approval_id).await {
        Ok(r)                      => r,
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Verify the voter is a member of the session with enough authority to
    // approve — matches MemberRole::can_approve() (Owner|Collaborator),
    // enforced here for the first time; previously any member, including
    // Observer, could vote.
    match db::sessions::require_membership(
        &state.db, &row.session_id, &actor_id, MemberRole::Collaborator,
    ).await {
        Ok(_) => {}
        Err(db::DbError::NotFound) => {
            tracing::warn!(
                approval_id, actor_id, session_id = %row.session_id,
                "cast_vote: actor is not a member of the approval's session"
            );
            return (StatusCode::FORBIDDEN, "not a member of this session").into_response();
        }
        Err(db::DbError::Unauthorized) => {
            tracing::warn!(
                approval_id, actor_id, session_id = %row.session_id,
                "cast_vote: actor role insufficient to approve"
            );
            return (StatusCode::FORBIDDEN, "observers cannot vote on approvals").into_response();
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    if let Some(res) = gate_session(
        &state, &row.session_id, &actor_id, RateLimitKey::ApprovalVote { actor_id: actor_id.clone() },
    ).await {
        return res;
    }

    let vote = match body.decision.as_str() {
        "grant" | "approve" => Vote::Approve,
        "deny"  | "reject"  => Vote::Deny,
        other => return (StatusCode::BAD_REQUEST, format!("unknown decision: {other}")).into_response(),
    };

    vote_on_approval(&state, &row.session_id, &actor_id, &approval_id, vote).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── POST /api/approvals/:id/delegate ─────────────────────────────────────────
//
// Cross-session approval delegation: session A asks session B to decide this
// approval on its behalf. B's decision is a completely normal ApprovalRequest,
// created and resolved via B's own approval_policy unchanged — see
// crates/session/src/transition.rs::live_cross_session_delegate and
// migration 028's own doc comment for the full design.
//
// Authorization: Collaborator+ in A (the same bar as creating any approval —
// delegating doesn't escalate anyone's authority, B decides using B's own
// members' pre-existing authority) plus an existing session_links row
// between A and B, any visibility — reuses linking as a lightweight "these
// sessions have agreed to interact" precondition, not as a source of
// decision authority.

#[derive(Deserialize)]
struct DelegateBody {
    target_session_id: String,
}

async fn delegate_cross_session(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
    Json(body):        Json<DelegateBody>,
) -> impl IntoResponse {
    let actor_id = match require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let row = match db::approvals::get(&state.db, &approval_id).await {
        Ok(r)                      => r,
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let source_session_id = row.session_id.clone();

    if source_session_id == body.target_session_id {
        return (StatusCode::BAD_REQUEST, "cannot delegate a session to itself").into_response();
    }

    match db::sessions::require_membership(&state.db, &source_session_id, &actor_id, MemberRole::Collaborator).await {
        Ok(_) => {}
        Err(db::DbError::NotFound) =>
            return (StatusCode::FORBIDDEN, "not a member of this session").into_response(),
        Err(db::DbError::Unauthorized) =>
            return (StatusCode::FORBIDDEN, "insufficient role to delegate an approval").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    if let Some(res) = gate_session(
        &state, &source_session_id, &actor_id,
        RateLimitKey::CrossSessionDelegate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }

    match db::session_links::exists_between(&state.db, &source_session_id, &body.target_session_id).await {
        Ok(true)  => {}
        Ok(false) => return (StatusCode::BAD_REQUEST,
            "source and target sessions must be linked before delegating (see POST /sessions/:a/link/:b)").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }

    let saga_id = ulid::Ulid::new().to_string();
    if let Err(e) = db::cross_session_delegations::insert(
        &state.db, &saga_id, &source_session_id, &approval_id, &body.target_session_id,
    ).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    let hub  = state.get_or_create_hub(&source_session_id);
    let task = state.get_or_create_session_task(&source_session_id, &row.actor_id, hub);
    let arguments = serde_json::json!({ "tool": row.tool_name, "arguments": row.arguments });
    crate::session_task::task_cross_session_delegate(
        &task, saga_id.clone(), approval_id, body.target_session_id, actor_id, arguments,
    ).await;

    (StatusCode::CREATED, Json(serde_json::json!({ "saga_id": saga_id }))).into_response()
}

// ── Ring-2 scout manifest endpoints ──────────────────────────────────────────

/// PATCH /api/approvals/:id/scout
#[derive(Deserialize)]
struct PatchScoutBody {
    scout_manifest: serde_json::Value,
}

async fn patch_scout_manifest(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
    Json(body):        Json<PatchScoutBody>,
) -> impl IntoResponse {
    let (actor_id, row) = match require_shim_auth(&state, &headers, &approval_id).await {
        Ok(v)    => v,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &row.session_id, &actor_id, RateLimitKey::ManifestPatch { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::approvals::set_scout_manifest(&state.db, &approval_id, &body.scout_manifest).await {
        Ok(())                     => StatusCode::NO_CONTENT.into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// PATCH /api/approvals/:id/execution
#[derive(Deserialize)]
struct PatchExecutionBody {
    execution_manifest: serde_json::Value,
    diverged:           bool,
}

async fn patch_execution_manifest(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
    Json(body):        Json<PatchExecutionBody>,
) -> impl IntoResponse {
    let (actor_id, row) = match require_shim_auth(&state, &headers, &approval_id).await {
        Ok(v)    => v,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &row.session_id, &actor_id, RateLimitKey::ManifestPatch { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    if body.diverged {
        tracing::warn!(
            approval_id,
            "Ring-2 security event: execution manifest diverged from scout prediction"
        );
    }
    match db::approvals::set_execution_manifest(
        &state.db, &approval_id, &body.execution_manifest, body.diverged,
    ).await {
        Ok(())                     => StatusCode::NO_CONTENT.into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── PATCH /api/approvals/:id/declared-effects ────────────────────────────────

#[derive(Deserialize)]
struct PatchDeclaredEffectsBody {
    declared_effects: serde_json::Value,
}

async fn patch_declared_effects_handler(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    State(state):      State<Arc<AppState>>,
    Json(body):        Json<PatchDeclaredEffectsBody>,
) -> impl IntoResponse {
    let (actor_id, row) = match require_shim_auth(&state, &headers, &approval_id).await {
        Ok(v)    => v,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &row.session_id, &actor_id, RateLimitKey::ManifestPatch { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::approvals::set_declared_effects(&state.db, &approval_id, &body.declared_effects).await {
        Ok(())                     => StatusCode::NO_CONTENT.into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Long-poll resolution endpoint ─────────────────────────────────────────────

#[derive(Deserialize)]
struct ResolutionQuery {
    timeout: Option<u64>,
}

/// GET /api/approvals/:id/resolution?timeout=N
async fn poll_resolution(
    Path(approval_id): Path<String>,
    headers:           HeaderMap,
    Query(q):          Query<ResolutionQuery>,
    State(state):      State<Arc<AppState>>,
) -> impl IntoResponse {
    // Authenticate once before the polling loop.
    if let Err(res) = require_shim_auth(&state, &headers, &approval_id).await {
        return res;
    }

    let timeout_secs = q.timeout.unwrap_or(25).min(60);
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);

    tracing::info!(approval_id, timeout_secs, "poll_resolution: waiting for decision");

    loop {
        match db::approvals::get(&state.db, &approval_id).await {
            Ok(row) => {
                let decision = match row.state.as_str() {
                    "Approved" => Some("granted"),
                    "Denied"   => Some("denied"),
                    "Expired"  => Some("timed_out"),
                    other => {
                        tracing::debug!(approval_id, state = other, "poll_resolution: still pending");
                        None
                    }
                };
                if let Some(d) = decision {
                    tracing::info!(approval_id, decision = d, "poll_resolution: resolved");
                    return Json(serde_json::json!({ "decision": d })).into_response();
                }
            }
            Err(db::DbError::NotFound) => {
                tracing::warn!(approval_id, "poll_resolution: approval not found in DB");
                return (StatusCode::NOT_FOUND, "approval not found").into_response();
            }
            Err(e) => {
                tracing::error!(approval_id, "poll_resolution DB error: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        }

        if std::time::Instant::now() >= deadline {
            tracing::info!(approval_id, "poll_resolution: timed out after {timeout_secs}s");
            return Json(serde_json::json!({ "decision": "timed_out" })).into_response();
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}
