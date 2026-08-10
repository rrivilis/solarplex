//! POST /api/sessions/:id/invoke — ORB layer 2 execution dispatch.
//!
//! This is the trust boundary for all agent tool calls.  The sidecar calls this
//! endpoint instead of executing tools itself; the server decides whether to
//! auto-approve (no human gate) or route through the approval queue.
//!
//! ## Request flow
//!
//! 1. Validate cap: non-expired, non-revoked, epoch matches current session epoch.
//! 2. Look up method in registry: must be registered for this session.
//! 3. Check cap permissions: method address must appear in cap's permissions list.
//! 4. If `requires_approval = false` → auto-approve, issue receipt immediately.
//! 5. If `requires_approval = true`  → create approval request, issue receipt
//!    after approval resolves (long-poll handled on the sidecar side via
//!    `GET /api/approvals/:id/resolution`).
//! 6. Return `{ status, receipt_id?, approval_id? }`.
//!
//! ## Execution receipt
//!
//! The receipt binds `(cap_id, method, args)` server-side.  The sidecar MUST
//! call `POST /api/sessions/:id/consume-receipt` with the receipt_id, then
//! execute the **server's** stored args verbatim — not the args it sent in the
//! invoke request.  This closes the post-approval args-swap trust gap.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::state::AppState;
use crate::ws::create_approval_for_session;

// ── Request body ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct InvokeBody {
    /// The cap token used by the calling agent.
    pub cap_id: String,
    /// Full method address: `"mcp.{slug}.{method}"`.
    pub method:  String,
    /// Arguments the agent wants to invoke the method with.
    pub args:    serde_json::Value,
    /// Approval timeout in seconds (only used when `requires_approval = true`).
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout_secs: u64,
}

fn default_approval_timeout() -> u64 { 120 }

/// Receipt TTL for auto-approved invocations (sidecar must consume within 30 s).
const AUTO_APPROVE_RECEIPT_TTL_SECS: i64 = 30;
/// Receipt TTL when approval is pending (human has up to N s to respond, then
/// sidecar consumes; total window = approval_timeout + execution grace).
const PENDING_RECEIPT_TTL_SECS:      i64 = 240;

// ── Handler ───────────────────────────────────────────────────────────────────

pub async fn handler(
    Path(session_id): Path<String>,
    State(state):     State<Arc<AppState>>,
    Json(body):       Json<InvokeBody>,
) -> impl IntoResponse {
    // ── 0. Rate limit ─────────────────────────────────────────────────────────
    // 60 invoke requests per cap per minute.  Checked before cap validation to
    // avoid DB load from flooded caps.
    {
        let mut bucket = state.invoke_rate_limits
            .entry(body.cap_id.clone())
            .or_insert_with(crate::state::RateBucket::new);
        if !bucket.check_and_increment(60) {
            return (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "invoke rate limit exceeded (60 req/min per cap)",
            ).into_response();
        }
    }

    // ── 1. Validate cap ───────────────────────────────────────────────────────

    let cap = match db::tokens::get_cap(&state.db, &body.cap_id).await {
        Ok(c)                           => c,
        Err(db::DbError::NotFound)      => {
            return (StatusCode::UNAUTHORIZED, "cap not found").into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    // Must belong to this session.
    if cap.session_id != session_id {
        return (StatusCode::FORBIDDEN, "cap does not belong to this session").into_response();
    }

    // Must not be expired.
    if cap.expires_at < chrono::Utc::now() {
        return (StatusCode::GONE, "cap expired").into_response();
    }

    // Must not be revoked.
    if cap.revoked_at.is_some() {
        return (StatusCode::GONE, "cap revoked").into_response();
    }

    // Must match current session epoch.
    let current_epoch = match db::epochs::current(&state.db, &session_id).await {
        Ok(e)  => e,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };
    if cap.epoch != current_epoch {
        return (StatusCode::GONE, "cap epoch superseded — re-attach required").into_response();
    }

    // ── 2. Resolve method in registry ─────────────────────────────────────────

    let method_row = match db::methods::get_by_address(&state.db, &session_id, &body.method).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, "method not registered for this session").into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    // ── 3. Check cap permissions ───────────────────────────────────────────────

    let cap_permissions = db::tokens::parse_permissions(&cap);
    if !cap_permissions.is_empty() && !cap_permissions.contains(&body.method) {
        return (StatusCode::FORBIDDEN, "method not in cap permissions").into_response();
    }

    // ── 3.5. Standing policy check ────────────────────────────────────────────
    // First matching policy for this session wins; human gate is bypassed for
    // auto_approve policies (receipt issued immediately) or hard-denied for
    // always_deny policies.  Pattern "*" matches any method; a pattern ending
    // in "*" is treated as a prefix match ("mcp.slug.*" → all tools for slug).
    if let Some(policies) = state.approval_policies.get(&session_id) {
        for policy in policies.iter() {
            let actor_match = policy.actor_id.as_deref()
                .map_or(true, |a| a == cap.actor_id);
            let method_match = policy.method_pattern == "*"
                || policy.method_pattern == body.method
                || (policy.method_pattern.ends_with('*')
                    && body.method.starts_with(
                        &policy.method_pattern[..policy.method_pattern.len() - 1]
                    ));
            if actor_match && method_match {
                match policy.decision {
                    crate::state::PolicyDecision::AutoApprove => {
                        let receipt = match db::receipts::issue(
                            &state.db, &body.cap_id, &session_id, &body.method,
                            &body.args, AUTO_APPROVE_RECEIPT_TTL_SECS, None,
                        ).await {
                            Ok(r)  => r,
                            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
                        };
                        return Json(serde_json::json!({
                            "status":     "approved",
                            "receipt_id": receipt.id,
                            "source":     "standing_policy",
                        })).into_response();
                    }
                    crate::state::PolicyDecision::AlwaysDeny => {
                        return (StatusCode::FORBIDDEN, "denied by standing policy").into_response();
                    }
                }
            }
        }
    }

    // ── 4/5. Approval gate ────────────────────────────────────────────────────

    if !method_row.requires_approval {
        // Auto-approve: issue receipt immediately.
        let receipt = match db::receipts::issue(
            &state.db,
            &body.cap_id,
            &session_id,
            &body.method,
            &body.args,
            AUTO_APPROVE_RECEIPT_TTL_SECS,
            None,
        ).await {
            Ok(r)  => r,
            Err(e) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
            }
        };
        return Json(serde_json::json!({
            "status":     "approved",
            "receipt_id": receipt.id,
        })).into_response();
    }

    // Requires human approval: create an approval request then issue the receipt
    // bound to that approval_id.  The sidecar long-polls
    // GET /api/approvals/:approval_id/resolution to learn when approved.
    // The receipt is issued immediately so the sidecar can proceed without a
    // second round-trip after approval resolves.
    let method_name = method_row.method_name.clone();
    let approval = match create_approval_for_session(
        &state,
        &session_id,
        &cap.actor_id,
        &method_name,
        &body.args,
        body.approval_timeout_secs,
    ).await {
        Some((approval_id, _expires_at)) => approval_id,
        None => {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let receipt = match db::receipts::issue(
        &state.db,
        &body.cap_id,
        &session_id,
        &body.method,
        &body.args,
        PENDING_RECEIPT_TTL_SECS,
        Some(&approval),
    ).await {
        Ok(r)  => r,
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    Json(serde_json::json!({
        "status":      "pending",
        "approval_id": approval,
        "receipt_id":  receipt.id,
    })).into_response()
}

// ── Consume receipt handler ───────────────────────────────────────────────────

/// POST /api/sessions/:id/consume-receipt
///
/// Called by the sidecar immediately before executing a tool call.
/// Returns the receipt row (including the server-canonical `args`) and marks
/// the receipt consumed in a single atomic UPDATE — a second call with the same
/// receipt_id will get a 410 Gone.
#[derive(Deserialize)]
pub struct ConsumeBody {
    pub receipt_id: String,
}

pub async fn consume_handler(
    Path(session_id): Path<String>,
    State(state):     State<Arc<AppState>>,
    Json(body):       Json<ConsumeBody>,
) -> impl IntoResponse {
    let receipt = match db::receipts::consume(&state.db, &body.receipt_id).await {
        Ok(r)                      => r,
        Err(db::DbError::NotFound) => {
            return (StatusCode::GONE, "receipt not found, already consumed, or expired")
                .into_response();
        }
        Err(e) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    };

    // Guard: receipt must belong to this session (prevents cross-session replay).
    if receipt.session_id != session_id {
        return (StatusCode::FORBIDDEN, "receipt session mismatch").into_response();
    }

    Json(serde_json::json!({
        "receipt_id":  receipt.id,
        "cap_id":      receipt.cap_id,
        "method":      receipt.method,
        // The sidecar MUST use these args, not its own copy.
        "args":        receipt.args,
        "approval_id": receipt.approval_id,
    })).into_response()
}
