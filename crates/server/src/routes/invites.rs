//! Invite redemption — the one place a `MembershipGrant` and an optional
//! `CapGrant` are both in scope together, and they stay two sequential,
//! independent writes here rather than one merged call. See
//! `db::invites` for why that separation exists.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use serde::Deserialize;
use ulid::Ulid;

use db::{actors, events, invites, sessions, tokens};
use protocol::messages::{WsMessage, WsPayload};
use protocol::types::MemberRole;

use crate::state::AppState;
use crate::ws::emit_to_session;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/:id", get(preview))
        .route("/:id/redeem", post(redeem))
        .route("/:id/revoke", post(revoke))
}

// ── Preview ──────────────────────────────────────────────────────────────────
//
// Lets the frontend show "you've been invited to <session> as <role>" before
// the invitee authenticates — no sp_token required, read-only, no side effects.

async fn preview(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let row = match invites::get(&state.db, &id).await {
        Ok(row) => row,
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // A direct DB read, not a call through the gated GET /sessions/:id
    // endpoint — the invitee isn't a member yet, which is exactly the case
    // that handler now correctly rejects. The preview is deliberately
    // unauthenticated, so it has to fetch what it needs to show itself.
    let session_name = sessions::get(&state.db, &row.session_id).await
        .map(|s| s.name)
        .unwrap_or_else(|_| "(unknown session)".to_string());
    // Same reason session_name needs resolving here: row.invited_by is a raw
    // actor_id, and there's no other enrichment funnel this unauthenticated
    // page could reach (it isn't a session member yet, so it can't hit any
    // of the normal membership-gated name-resolution paths).
    let inviter_name = actors::get(&state.db, &row.invited_by).await
        .map(|a| a.name)
        .unwrap_or_else(|_| row.invited_by.clone());

    let mut json = serde_json::json!(row);
    json["session_name"] = serde_json::Value::String(session_name);
    json["inviter_name"] = serde_json::Value::String(inviter_name);
    Json(json).into_response()
}

// ── Redeem ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RedeemBody {
    /// OIDC-issued sp_token. Redemption grants real membership, so it
    /// authenticates identity the same way the human WS path already does
    /// (crates/server/src/ws.rs's sp_token branch) — not a self-asserted
    /// actor_id, unlike the rest of this REST surface today.
    pub sp_token: String,
}

async fn redeem(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RedeemBody>,
) -> impl IntoResponse {
    let human_session = match crate::auth::validate_sp_token(&state.db, &body.sp_token).await {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(invite_id = %id, error = %e, "invite redeem rejected: invalid sp_token");
            return (StatusCode::UNAUTHORIZED, "invalid or expired session token").into_response();
        }
    };
    let actor_id = human_session.actor_id;
    if let Some(res) = crate::rate_limit::gate_global(
        crate::rate_limit::GlobalRateLimitKey::InviteRedeemAttempt { actor_id: actor_id.clone() },
        &state.rate_limits,
    ) {
        return res;
    }

    // Best-effort: a named invite can only be checked against an email if
    // one is on record. Missing email just means a named invite can never
    // match this actor — redeem() below will correctly reject it.
    let actor_email = actors::get(&state.db, &actor_id).await.ok().and_then(|a| a.email);

    let invite = match invites::redeem(&state.db, &id, &actor_id, actor_email.as_deref()).await {
        Ok(row) => row,
        Err(db::DbError::NotFound) => return diagnose_redeem_failure(&state, &id).await,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // ── MembershipGrant — the uniform, required half ─────────────────────────
    if let Err(e) = actors::ensure_human(&state.db, &actor_id, &actor_id).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    // Snapshot whoever currently holds ownership *before* add_member's own
    // demotion runs (see its doc comment) — needed below to emit a real
    // OwnershipTransferred event for an owner-role invite, the same event
    // the live transfer_ownership REST/WS handlers emit. Without this, an
    // owner handoff done via invite only ever shows up in the event log as
    // an ordinary ActorJoined, indistinguishable from any other member
    // joining — the Activity Log has no way to render it as a transfer.
    let previous_owner = if invite.role == "owner" {
        sessions::list_memberships(&state.db, &invite.session_id).await
            .ok()
            .and_then(|ms| ms.into_iter().find(|m| m.role == "owner"))
            .map(|m| m.actor_id)
            .filter(|owner| *owner != actor_id)
    } else {
        None
    };

    let membership = match sessions::add_member(
        &state.db, &invite.session_id, &actor_id, &invite.role,
        invite.escalation_order, invite.escalation_timeout,
    ).await {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // First and only point membership becomes visible to the live session —
    // same redemption-gated principle as the agent-attach path.
    let joiner_name = actors::get(&state.db, &actor_id).await.ok().map(|a| a.name);
    emit_to_session(
        &state, &invite.session_id, &actor_id,
        WsMessage::new(
            Ulid::new().to_string(),
            WsPayload::ActorJoined {
                session_id: invite.session_id.clone(),
                actor: actor_id.clone(),
                timestamp: Utc::now(),
                seq: 0,
                role: invite.role.parse().ok(),
                name: joiner_name,
            },
        ),
    ).await;

    // A distinct OwnershipTransferred event, right after the join it rode
    // in on — not bridged into a live session task the way the direct
    // transfer_ownership handler is: this whole redeem() flow never touches
    // the session task (there's no live WS connection at redemption time to
    // hang it off of), consistent with how ActorJoined above already skips
    // it. Cold-start replay reconciles `SessionMemory` from this durable
    // event the same way it already does for the join itself.
    if let Some(from_actor) = previous_owner {
        emit_to_session(
            &state, &invite.session_id, &from_actor,
            WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::OwnershipTransferred {
                    session_id: invite.session_id.clone(),
                    actor: from_actor.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: protocol::messages::OwnershipTransferredPayload {
                        from: from_actor.clone(),
                        to: actor_id.clone(),
                    },
                },
            ),
        ).await;
    }

    // ── CapGrant — strictly optional, strictly separate write ────────────────
    let mut cap_token: Option<serde_json::Value> = None;
    if let Some(grant) = invites::parse_cap_grant(&invite) {
        let observed_seq = events::current_seq(&state.db, &invite.session_id).await.unwrap_or(0);
        let token_id = Ulid::new().to_string();
        let expires_at = Utc::now() + chrono::Duration::seconds(grant.ttl_secs);
        match tokens::insert(
            &state.db, &token_id, &invite.session_id, &actor_id, expires_at,
            None, observed_seq, &grant.permissions,
        ).await {
            Ok(row) => {
                if let Err(e) = db::descriptors::grant(&state.db, &actor_id, &format!("cap/{}", row.id)).await {
                    tracing::warn!(cap_id = %row.id, actor_id, "descriptor grant failed: {e}");
                }
                cap_token = Some(serde_json::json!({
                    "token":       row.id,
                    "expires_at":  row.expires_at,
                    "permissions": tokens::parse_permissions(&row),
                }));
            }
            // Membership already succeeded and was already broadcast — the cap
            // is a second-order grant, so its failure doesn't unwind the
            // membership half. Surfaced in logs, not to the caller as a whole
            // request failure.
            Err(e) => tracing::error!(invite_id = %id, actor_id, error = %e,
                "cap grant failed after membership succeeded"),
        }
    }

    Json(serde_json::json!({
        "session_id": invite.session_id,
        "membership": membership,
        "cap":        cap_token,
    })).into_response()
}

/// `invites::redeem` collapses every disqualifying condition into one
/// `NotFound` (deliberately, to keep the atomic UPDATE simple). This does
/// one follow-up read purely to give the caller a specific, actionable
/// reason instead of an opaque 404 — same principle as the WS handler using
/// distinct close codes instead of silently dropping the connection.
async fn diagnose_redeem_failure(state: &Arc<AppState>, id: &str) -> axum::response::Response {
    match invites::get(&state.db, id).await {
        Ok(row) if row.revoked_at.is_some() =>
            (StatusCode::GONE, "invite has been revoked").into_response(),
        Ok(row) if row.redeemed_at.is_some() =>
            (StatusCode::CONFLICT, "invite has already been redeemed").into_response(),
        Ok(row) if row.expires_at <= Utc::now() =>
            (StatusCode::GONE, "invite has expired").into_response(),
        Ok(row) if row.invitee_email.is_some() =>
            (StatusCode::FORBIDDEN, format!(
                "this invite is addressed to {}, not the signed-in identity",
                row.invitee_email.unwrap_or_default(),
            )).into_response(),
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── Revoke ─────────────────────────────────────────────────────────────────

async fn revoke(
    Path(id):     Path<String>,
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Previously had no auth check at all — anyone who knew or guessed an
    // invite id (a ULID, not a secret; the preview endpoint above is
    // deliberately public) could revoke it, unauthenticated. The bar here:
    // the original inviter can always revoke their own invite; otherwise
    // the caller needs at least Collaborator in the invite's session — same
    // "either admin, not just the creator" posture
    // session_links::require_link_admin already uses for the analogous
    // link-invite system.
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let invite = match invites::get(&state.db, &id).await {
        Ok(row) => row,
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let is_inviter = actor_id == invite.invited_by;
    let is_admin = sessions::require_membership(
        &state.db, &invite.session_id, &actor_id, MemberRole::Collaborator,
    ).await.is_ok();
    if !is_inviter && !is_admin {
        return (StatusCode::FORBIDDEN, "not the inviter or a session admin").into_response();
    }

    match invites::revoke(&state.db, &id).await {
        Ok(row) => Json(row).into_response(),
        Err(db::DbError::NotFound) =>
            (StatusCode::NOT_FOUND, "invite not found, already redeemed, or already revoked").into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
