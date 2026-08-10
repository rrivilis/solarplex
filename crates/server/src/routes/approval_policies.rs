//! Standing approval policies — per-session auto-approve / always-deny rules.
//!
//! Policies are in-memory only: they survive the process lifetime but not a
//! restart.  First matching policy wins (insertion order).  A policy can target
//! a specific actor or apply to all agents in the session.
//!
//! ## Endpoints
//!
//! - `GET  /sessions/:id/approval-policies`        — list active policies
//! - `POST /sessions/:id/approval-policies`        — create a policy
//! - `DELETE /sessions/:id/approval-policies/:pid` — remove a policy

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get},
    Json, Router,
};
use serde::Deserialize;
use ulid::Ulid;

use protocol::types::MemberRole;
use crate::state::{AppState, PolicyDecision, StandingPolicy};

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/approval-policies",      get(list).post(create))
        .route("/approval-policies/:pid", delete(remove))
}

// ── GET /sessions/:id/approval-policies ──────────────────────────────────────

/// Two credential shapes accepted: a human's `sp_token` (dashboard reads),
/// or an agent's `X-Session-Id`/`X-Actor-Id` headers (the shim needs its own
/// session's standing policy to actually enforce it — see crates/shim's
/// policy module — but agents never hold an sp_token; OIDC is human-only).
/// Same header-based pattern already established for shim-originated reads
/// in routes/approvals.rs's `require_shim_auth`, minus the approval-specific
/// checks (there's no approval_id here, just the session's own policy list).
async fn require_member_or_shim(
    state: &Arc<AppState>, headers: &HeaderMap, session_id: &str,
) -> Result<(), axum::response::Response> {
    if crate::auth::require_session_member(&state.db, headers, session_id, MemberRole::Observer).await.is_ok() {
        return Ok(());
    }
    let actor_id = headers.get("x-actor-id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authorization: Bearer <sp_token>, or X-Session-Id/X-Actor-Id required").into_response())?;
    db::sessions::get_membership(&state.db, session_id, actor_id).await
        .map_err(|_| (StatusCode::FORBIDDEN, "actor is not a member of the stated session").into_response())?;
    Ok(())
}

async fn list(
    Path(session_id): Path<String>,
    headers:          HeaderMap,
    State(state):     State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = require_member_or_shim(&state, &headers, &session_id).await {
        return res;
    }
    let policies = state.approval_policies
        .get(&session_id)
        .map(|p| {
            p.iter().map(|sp| serde_json::json!({
                "id":             sp.id,
                "actor_id":       sp.actor_id,
                "method_pattern": sp.method_pattern,
                "decision":       match sp.decision {
                    PolicyDecision::AutoApprove => "auto_approve",
                    PolicyDecision::AlwaysDeny  => "always_deny",
                },
            })).collect::<Vec<_>>()
        })
        .unwrap_or_default();
    Json(policies).into_response()
}

// ── POST /sessions/:id/approval-policies ──────────────────────────────────────

#[derive(Deserialize)]
struct CreateBody {
    /// Target actor.  Omit to apply to all agents in the session.
    actor_id:       Option<String>,
    /// Exact method address ("mcp.slug.tool_name") or prefix with trailing "*"
    /// ("mcp.slug.*" = all tools for that slug, "*" = everything).
    method_pattern: String,
    /// "auto_approve" or "always_deny"
    decision:       String,
}

async fn create(
    Path(session_id): Path<String>,
    State(state):     State<Arc<AppState>>,
    Json(body):       Json<CreateBody>,
) -> impl IntoResponse {
    let decision = match body.decision.as_str() {
        "auto_approve" => PolicyDecision::AutoApprove,
        "always_deny"  => PolicyDecision::AlwaysDeny,
        other => return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("unknown decision '{}'; expected auto_approve or always_deny", other),
        ).into_response(),
    };

    let policy = StandingPolicy {
        id:             Ulid::new().to_string(),
        actor_id:       body.actor_id.clone(),
        method_pattern: body.method_pattern.clone(),
        decision,
    };
    let policy_id = policy.id.clone();

    state.approval_policies
        .entry(session_id)
        .or_insert_with(Vec::new)
        .push(policy);

    (StatusCode::CREATED, Json(serde_json::json!({
        "policy_id":      policy_id,
        "actor_id":       body.actor_id,
        "method_pattern": body.method_pattern,
        "decision":       body.decision,
    }))).into_response()
}

// ── DELETE /sessions/:id/approval-policies/:pid ───────────────────────────────

async fn remove(
    Path((session_id, policy_id)): Path<(String, String)>,
    State(state):                   State<Arc<AppState>>,
) -> impl IntoResponse {
    let mut found = false;
    if let Some(mut policies) = state.approval_policies.get_mut(&session_id) {
        let before = policies.len();
        policies.retain(|p| p.id != policy_id);
        found = policies.len() < before;
    }
    if found {
        StatusCode::NO_CONTENT.into_response()
    } else {
        (StatusCode::NOT_FOUND, "policy not found").into_response()
    }
}
