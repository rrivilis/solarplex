use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use ulid::Ulid;

use db::{actors, invites, sessions, tokens};
use protocol::messages::{
    AgentStatusPayload, ArtifactPayload, ContextEntryAddedPayload,
    MessagePostedPayload, OwnershipTransferredPayload, SessionRenamedPayload,
    SessionStatusPayload, ShellCommandCompletedPayload, ShellCommandStartedPayload, WsMessage,
    WsPayload,
};
use protocol::types::{AgentStatus, ContextEntryKind, MemberRole};
use session::rate_limit::RateLimitKey;
use session::{BundleKind, SagaBundle};
use crate::session_task::{
    task_admin_archive, task_admin_pause, task_admin_resume, task_artifact_create,
    task_artifact_delete, task_artifact_update, task_context_add, task_message_post,
    task_ownership_transfer,
};
use crate::state::AppState;
use crate::ws::{create_approval_for_session, emit_to_session};
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_sessions).post(create_session))
        .route("/{id}", get(get_session).patch(update_session))
        .route("/{id}/digest", get(get_digest))
        .route("/{id}/members", post(add_member))
        .route("/{id}/invites", get(list_invites).post(create_invite))
        .route("/{id}/attach-token", post(issue_attach_token))
        .route("/{id}/regenerate-join-token", post(regenerate_join_token))
        .route("/{id}/transfer", post(transfer_ownership))
        .route("/{id}/events", get(list_events))
        .route("/{id}/connections", get(list_connections))
        .route("/{id}/messages", post(post_message))
        .route("/{id}/context", post(add_context))
        .route("/{id}/context/send", post(send_context_entry))
        .route("/{id}/annotate", post(annotate_object))
        .route("/{id}/artifacts", get(list_artifacts).post(create_artifact))
        .route("/{id}/artifacts/import", post(import_artifact))
        .route("/{id}/artifacts/{artifact_id}", get(get_artifact).patch(update_artifact).delete(delete_artifact))
        .route("/{id}/approvals", get(list_approvals).post(create_approval_rest))
        .route("/{id}/agent-attach", post(agent_attach))
        .route("/{id}/agent-detach", post(agent_detach))
        .route("/{id}/agent-status", post(agent_status))
        .route("/{id}/agent-heartbeat", post(agent_heartbeat))
        .route("/{id}/shell/start",    post(shell_start))
        .route("/{id}/shell/complete", post(shell_complete))
        .route("/{id}/methods", get(list_methods).post(register_methods))
}

#[derive(Deserialize)]
pub struct CreateSessionBody {
    pub name: String,
    pub description: Option<String>,
    pub approval_policy: Option<String>,
}

#[autometrics]
async fn create_session(
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body):   Json<CreateSessionBody>,
) -> impl IntoResponse {
    // Owner identity comes from a verified sp_token, not a self-asserted
    // created_by — same fix as create_invite. Session creation itself was
    // never gated on membership (there's nothing to be a member of yet, for
    // the very first session an actor creates), so this is purely closing
    // the identity gap, not adding a new authorization check.
    let created_by = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    if let Some(res) = crate::rate_limit::gate_global(
        crate::rate_limit::GlobalRateLimitKey::SessionCreate { actor_id: created_by.clone() },
        &state.rate_limits,
    ) {
        return res;
    }

    // Register the actor on first use — actor_id is only ever a name
    // *fallback* for a genuinely new row; ensure_human leaves an existing
    // actor's real name (OIDC-derived or chosen via rename) untouched.
    if let Err(e) = actors::ensure_human(&state.db, &created_by, &created_by).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    match sessions::create(&state.db, sessions::CreateSession {
        name: body.name,
        description: body.description,
        created_by,
        approval_policy: body.approval_policy,
    })
    .await
    {
        Ok(result) => {
            // Merge session fields with the raw join token (shown once; not in DB).
            let mut resp = serde_json::json!(result.session);
            resp["join_token"] = serde_json::Value::String(result.raw_join_token);
            (StatusCode::CREATED, Json(resp)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn list_sessions(
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Always scoped to the authenticated caller — the former unauthenticated
    // "list every session in the deployment" branch (when actor_id was
    // omitted) is gone. Like Slack — you only see sessions you've joined.
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match sessions::list_by_actor(&state.db, &actor_id).await {
        Ok(rows) => {
            // Same enrichment principle as make_snapshot_msg: SessionRow
            // stores created_by as a raw id (correctly — that's DB-layer
            // shape, not API-response shape), resolved to a display name
            // here rather than baked into the row itself.
            let creator_ids: Vec<String> = rows.iter().map(|r| r.created_by.clone()).collect();
            let names = actors::get_many(&state.db, &creator_ids).await.unwrap_or_default();
            let enriched: Vec<serde_json::Value> = rows.iter().map(|r| {
                let mut v = serde_json::json!(r);
                v["created_by_name"] = serde_json::Value::String(
                    names.get(&r.created_by).map(|a| a.name.clone()).unwrap_or_else(|| r.created_by.clone())
                );
                v
            }).collect();
            Json(enriched).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn get_session(
    Path(id):     Path<String>,
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(
        &state.db, &headers, &id, MemberRole::Observer,
    ).await {
        return res;
    }
    match sessions::get(&state.db, &id).await {
        Ok(session) => {
            // Embed members so the CLI and other consumers don't need a second request.
            let members = sessions::list_memberships(&state.db, &id)
                .await
                .unwrap_or_default();
            // MembershipRow is a raw DB row — actor_id only, no name. Same
            // enrichment principle as list_sessions' created_by_name: resolve
            // display names here, at the response boundary, rather than
            // baking them into the row type. Without this, every consumer of
            // this endpoint (the CLI's feed included) has nothing but raw
            // ULIDs to show for each member.
            let actor_ids: Vec<String> = members.iter().map(|m| m.actor_id.clone()).collect();
            let names = actors::get_many(&state.db, &actor_ids).await.unwrap_or_default();
            let enriched_members: Vec<serde_json::Value> = members.iter().map(|m| {
                let mut v = serde_json::json!(m);
                v["name"] = serde_json::Value::String(
                    names.get(&m.actor_id).map(|a| a.name.clone()).unwrap_or_else(|| m.actor_id.clone())
                );
                v
            }).collect();
            let mut json = serde_json::json!(session);
            json["members"] = serde_json::json!(enriched_members);
            Json(json).into_response()
        }
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// Computed-on-read session summary — the "SQL VIEW" analog for cross-session
/// communication, deliberately not a stored/copied value. Same authorization
/// as every other session-scoped read (`require_session_member`, Observer
/// minimum), which already transparently satisfies linked-session access via
/// `require_membership_or_linked_access` — no new authorization code needed.
#[autometrics]
async fn get_digest(
    Path(id):     Path<String>,
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(
        &state.db, &headers, &id, MemberRole::Observer,
    ).await {
        return res;
    }
    match sessions::compute_digest(&state.db, &id).await {
        Ok(digest) => Json(digest).into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Regenerate join token ─────────────────────────────────────────────────────
//
// The raw join token is only ever visible once, in create_session's response
// (SessionRow.join_token is #[serde(skip)] everywhere else, and only its hash
// is persisted). This mints a fresh one for callers — human members without an
// OIDC-issued sp_token — who need a usable invite link for an existing session.
// Rotating invalidates any previously-issued raw token for this session.
#[autometrics]
async fn regenerate_join_token(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Rotating the join token affects every future attach for this session —
    // administrative write, same bar as update_session's rename/status change.
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Collaborator).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &actor_id, RateLimitKey::MembershipGrant { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match sessions::regenerate_join_token(&state.db, &id).await {
        Ok(raw_token) => Json(serde_json::json!({ "join_token": raw_token })).into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateSessionBody {
    pub status:   Option<String>,
    pub name:     Option<String>,
    /// No longer trusted for identity — accepted-but-ignored so existing
    /// callers that still send it don't break deserialization. A caller-
    /// asserted actor_id here let anyone rename/change the status of any
    /// session while claiming to be any of its members, with no proof at
    /// all. The real actor is the verified bearer identity below.
    #[allow(dead_code)]
    pub actor_id: Option<String>,
}

#[autometrics]
async fn update_session(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateSessionBody>,
) -> impl IntoResponse {
    // Rename and status changes are both administrative writes — require at
    // least Collaborator, matching the existing "any member with write
    // access can rename" comment this enforces for the first time.
    let actor = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Collaborator).await {
        Ok(actor_id) => actor_id,
        Err(res) => return res,
    };

    // ── Rename ────────────────────────────────────────────────────────────────
    // Name is editable state; ULID identity stays stable.  Any member with write
    // access can rename — the rename fires a `session.renamed` WS event so every
    // connected participant sees the change immediately.
    if let Some(ref new_name) = body.name {
        // Grab old name before overwriting so the event carries both sides.
        let old_name = sessions::get(&state.db, &id).await
            .ok()
            .and_then(|s| Some(s.name))
            .unwrap_or_default();

        match sessions::rename(&state.db, &id, new_name).await {
            Ok(session) => {
                let event = WsMessage::new(
                    Ulid::new().to_string(),
                    WsPayload::SessionRenamed {
                        session_id: id.clone(),
                        actor: actor.clone(),
                        timestamp: Utc::now(),
                        seq: 0,
                        payload: SessionRenamedPayload {
                            old_name,
                            new_name: new_name.clone(),
                        },
                    },
                );
                emit_to_session(&state, &id, &actor, event).await;
                return Json(session).into_response();
            }
            Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    // ── Status change ─────────────────────────────────────────────────────────
    if let Some(ref status) = body.status {
        match sessions::update_status(&state.db, &id, status).await {
            Ok(session) => {
                let event = WsMessage::new(
                    Ulid::new().to_string(),
                    WsPayload::SessionStatusChanged {
                        session_id: id.clone(),
                        actor: actor.clone(),
                        timestamp: Utc::now(),
                        seq: 0,
                        payload: SessionStatusPayload { status: status.clone() },
                    },
                );
                emit_to_session(&state, &id, &actor, event).await;

                // ── Session task: feed AdminPause/Resume/Archive (after durable
                // commit) ────────────────────────────────────────────────────
                // Shadow-persisted (see is_machine_autonomous) — this route
                // remains the authoritative writer; keeps the machine's own
                // lifecycle state correct without waiting for cold replay.
                let hub  = state.get_or_create_hub(&id);
                let task = state.get_or_create_session_task(&id, &actor, hub);
                match status.as_str() {
                    "suspended" => task_admin_pause(&task, actor.clone(), None).await,
                    "active"    => task_admin_resume(&task, actor.clone()).await,
                    "archived"  => task_admin_archive(&task, actor.clone()).await,
                    _ => {}
                }

                return Json(session).into_response();
            }
            Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }

    StatusCode::NO_CONTENT.into_response()
}

#[derive(Deserialize)]
pub struct AddMemberBody {
    pub actor_id: String,
    pub role: String,
    pub escalation_order: Option<i32>,
    pub escalation_timeout: Option<i32>,
}

#[autometrics]
async fn add_member(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddMemberBody>,
) -> impl IntoResponse {
    // Directly granting membership (any role, including Owner rank) is more
    // consequential than create_invite's role-ceiling-checked flow — require
    // the caller already be Owner themselves. Nothing in this codebase calls
    // this route today (create_invite + redeem is the sanctioned path); this
    // is a conservative default for an otherwise-unused primitive, not a tuned
    // policy.
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Owner).await {
        return res;
    }
    // Auto-register the actor if they don't exist yet — same pattern as create_session.
    // Use ensure_agent for agent role so the actor type is recorded correctly;
    // ensure_* (not upsert_*) so re-adding an already-named actor never
    // clobbers their real name back to the raw id.
    let upsert_result = if body.role == "agent" {
        actors::ensure_agent(&state.db, &body.actor_id, &body.actor_id).await
    } else {
        actors::ensure_human(&state.db, &body.actor_id, &body.actor_id).await
    };
    if let Err(e) = upsert_result {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    match sessions::add_member(
        &state.db, &id, &body.actor_id, &body.role,
        body.escalation_order, body.escalation_timeout,
    )
    .await
    {
        Ok(m) => {
            // Emit ActorJoined with the correct role so the live in-memory snapshot
            // is updated immediately — without this, the frontend only sees the new
            // role after the actor reconnects via WebSocket.
            let member_role: Option<protocol::types::MemberRole> = body.role.parse().ok();
            let joiner_name = actors::get(&state.db, &body.actor_id).await.ok().map(|a| a.name);
            emit_to_session(
                &state, &id, &body.actor_id,
                WsMessage::new(
                    body.actor_id.clone(),
                    WsPayload::ActorJoined {
                        session_id: id.clone(),
                        actor: body.actor_id.clone(),
                        timestamp: Utc::now(),
                        seq: 0,
                        role: member_role,
                        name: joiner_name,
                    },
                ),
            ).await;
            (StatusCode::CREATED, Json(m)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Invites ──────────────────────────────────────────────────────────────────
//
// Creating an invite grants nothing by itself — it's a proposal that only
// takes effect at redemption (routes::invites::redeem), which is the one
// step in this whole flow gated on real identity. See db::invites for the
// MembershipGrant/CapGrant split this stages.

fn default_invite_ttl_secs() -> i64 { 3 * 24 * 3600 } // 3 days

#[derive(Deserialize)]
pub struct CreateInviteBody {
    /// OIDC-issued sp_token identifying the inviter. `invited_by` is derived
    /// from this, not taken from the body — a caller-asserted inviter would
    /// let anyone claim to invite as anyone, which is exactly the gap
    /// `authz::can_create_invite`'s role-ceiling check exists to close.
    pub sp_token: String,
    /// owner | collaborator | observer — agents keep their own attach flow.
    pub role: String,
    pub escalation_order: Option<i32>,
    pub escalation_timeout: Option<i32>,
    /// Omit for an anonymous link invite redeemable by any authenticated identity.
    pub invitee_email: Option<String>,
    /// Both or neither — a partially-specified cap request is a caller error.
    pub cap_permissions: Option<Vec<String>>,
    pub cap_ttl_secs: Option<i64>,
    #[serde(default = "default_invite_ttl_secs")]
    pub ttl_secs: i64,
}

#[autometrics]
async fn create_invite(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateInviteBody>,
) -> impl IntoResponse {
    let target_role: protocol::types::MemberRole = match body.role.parse() {
        Ok(r) if !matches!(r, protocol::types::MemberRole::Agent) => r,
        _ => return (StatusCode::BAD_REQUEST, "role must be owner, collaborator, or observer").into_response(),
    };
    let cap = match (body.cap_permissions, body.cap_ttl_secs) {
        (Some(permissions), Some(ttl_secs)) => Some(invites::CapGrant { permissions, ttl_secs }),
        (None, None) => None,
        _ => return (
            StatusCode::BAD_REQUEST,
            "cap_permissions and cap_ttl_secs must both be set or both omitted",
        ).into_response(),
    };

    // authenticated(actor) — resolve the caller's real identity from a
    // verified sp_token, same as invite redemption already does.
    let human_session = match crate::auth::validate_sp_token(&state.db, &body.sp_token).await {
        Ok(row) => row,
        Err(e) => {
            tracing::warn!(session_id = %id, error = %e, "create_invite rejected: invalid sp_token");
            return (StatusCode::UNAUTHORIZED, "invalid or expired session token").into_response();
        }
    };
    let invited_by = human_session.actor_id;

    // member(actor, session) — the generic "are you allowed to be here"
    // gate. Observer is the lowest human role: this only asserts membership,
    // not sufficient authority to invite — that's the role-ceiling check below.
    let caller = match sessions::require_membership(
        &state.db, &id, &invited_by, protocol::types::MemberRole::Observer,
    ).await {
        Ok(m) => m,
        Err(db::DbError::NotFound) =>
            return (StatusCode::FORBIDDEN, "not a member of this session").into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let caller_role: protocol::types::MemberRole = match caller.role.parse() {
        Ok(r) => r,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "unrecognized membership role").into_response(),
    };

    // permit(actor, CreateInvite(request)) — role ceiling + owner-only cap staging.
    if let Err(reason) = crate::authz::can_create_invite(&caller_role, &target_role, cap.is_some()) {
        return (StatusCode::FORBIDDEN, reason).into_response();
    }
    if let Some(res) = gate_session(
        &state, &id, &invited_by, RateLimitKey::MembershipGrant { actor_id: invited_by.clone() },
    ).await {
        return res;
    }

    match invites::create(&state.db, invites::CreateInvite {
        session_id: id,
        invited_by,
        membership: invites::MembershipGrant {
            role: body.role,
            escalation_order: body.escalation_order,
            escalation_timeout: body.escalation_timeout,
        },
        invitee_email: body.invitee_email,
        cap,
        ttl_secs: body.ttl_secs,
    }).await {
        Ok(row) => {
            // Write-time mailbox population: only when the invitee's email
            // already resolves to a known actor. A brand-new invitee (never
            // logged in, no actor row to key on) gets nothing here — they're
            // caught by the one-time backfill sweep in sub_to_actor_id on
            // their first login instead. Non-fatal: a missed mailbox entry
            // is a display gap, not a broken invite (the invite itself is
            // unaffected and still redeemable by link).
            //
            // mailbox_status tells the caller which of the three actually
            // happened — the modal used to give zero feedback either way,
            // so filling in an email and getting silence looked identical
            // to it not doing anything at all.
            let mailbox_status = match &row.invitee_email {
                None => "not_addressed",
                Some(email) => match actors::find_by_email(&state.db, email).await {
                    Ok(Some(mailbox_actor_id)) => {
                        let uri = format!("invite/{}", row.id);
                        if let Err(e) = db::mailbox::insert_route(&state.db, &mailbox_actor_id, &uri).await {
                            tracing::warn!(invite_id = %row.id, mailbox_actor_id, "mailbox route insert failed: {e}");
                            "delivery_failed"
                        } else {
                            "delivered"
                        }
                    }
                    Ok(None) => "pending_first_login",
                    Err(e) => {
                        tracing::warn!(invite_id = %row.id, "mailbox lookup failed: {e}");
                        "delivery_failed"
                    }
                },
            };
            let mut json = serde_json::json!(row);
            json["mailbox_status"] = serde_json::Value::String(mailbox_status.to_string());
            (StatusCode::CREATED, Json(json)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn list_invites(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        return res;
    }
    match invites::list_by_session(&state.db, &id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct TransferBody {
    /// No longer trusted for identity — kept accepted-but-ignored so existing
    /// callers that still send it don't break deserialization. The real
    /// "from" is the verified bearer identity below: a caller-asserted owner
    /// id let anyone who knew (or guessed) the real owner's actor_id steal
    /// ownership of any session with zero authentication.
    #[allow(dead_code)]
    pub from: Option<String>,
    pub to: String,
}

// ── Tier-1 rate-limit gating ───────────────────────────────────────────────
//
// Checked synchronously, before any durable write — the REST handler is the
// true "did this action happen" boundary (see `session::rate_limit`'s
// module doc). `crate::rate_limit::gate_session` does the check, the audit
// event on denial, and the 429 response; every handler below just calls it
// and returns early on `Some`.
use crate::rate_limit::gate_session;

#[autometrics]
async fn transfer_ownership(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<TransferBody>,
) -> impl IntoResponse {
    // Matches MemberRole::can_transfer_ownership() — Owner only. The verified
    // caller *is* the "from" — you can only transfer away ownership you
    // actually, verifiably hold.
    let from = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Owner).await {
        Ok(actor_id) => actor_id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(&state, &id, &from, RateLimitKey::OwnershipTransfer).await {
        return res;
    }
    match sessions::transfer_ownership(&state.db, &id, &from, &body.to).await {
        Ok(_) => {
            let event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::OwnershipTransferred {
                    session_id: id.clone(),
                    actor: from.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: OwnershipTransferredPayload { from: from.clone(), to: body.to.clone() },
                },
            );
            emit_to_session(&state, &id, &from, event).await;

            // ── Session task: feed OwnershipTransfer (after durable commit,
            // shadow-persisted — see task_ownership_transfer's doc comment) ──
            let hub  = state.get_or_create_hub(&id);
            let task = state.get_or_create_session_task(&id, &from, hub);
            task_ownership_transfer(&task, from.clone(), body.to.clone()).await;

            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Attach token ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct IssueAttachTokenBody {
    actor_id: String,
    #[serde(default = "default_agent_role")]
    role: String,
    /// Token lifetime in seconds. Defaults to 15 minutes.
    #[serde(default = "default_ttl")]
    ttl_secs: u64,
    /// Filesystem path to expose via the MCP server (included in the generated launch command).
    mcp_path: Option<String>,
    /// Cap this token is delegated from. None = root (human-issued).
    parent_cap: Option<String>,
    /// Allowed tool names. Empty = all tools permitted.
    #[serde(default)]
    permissions: Vec<String>,
}

fn default_agent_role() -> String { "agent".into() }
fn default_ttl() -> u64 { 900 }

#[autometrics]
async fn issue_attach_token(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<IssueAttachTokenBody>,
) -> impl IntoResponse {
    // Minting a capability token is granting authority — require the caller
    // already be a Collaborator+ member of this session. Before this, anyone
    // on the internet could mint an all-tools cap for a self-chosen actor_id
    // in any session with zero authentication.
    let issuer_id = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Collaborator).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &issuer_id, RateLimitKey::MembershipGrant { actor_id: issuer_id.clone() },
    ).await {
        return res;
    }
    // Auto-register actor and add as session member. ensure_* (not upsert_*)
    // so re-adding an already-named actor never clobbers their real name.
    let upsert = if body.role == "agent" {
        actors::ensure_agent(&state.db, &body.actor_id, &body.actor_id).await
    } else {
        actors::ensure_human(&state.db, &body.actor_id, &body.actor_id).await
    };
    if let Err(e) = upsert {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }
    if let Err(e) = sessions::add_member(&state.db, &id, &body.actor_id, &body.role, None, None).await {
        // Ignore conflict — actor may already be a member.
        if !matches!(e, db::DbError::Conflict(_)) {
            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
        }
    }

    // Capture the current session seq as the causal anchor for this cap.
    let observed_seq = db::events::current_seq(&state.db, &id).await.unwrap_or(0);

    // Mint and store the token.
    let token_id = Ulid::new().to_string();
    let expires_at = Utc::now() + chrono::Duration::seconds(body.ttl_secs as i64);
    match tokens::insert(
        &state.db, &token_id, &id, &body.actor_id, expires_at,
        body.parent_cap.as_deref(), observed_seq, &body.permissions,
    ).await {
        Ok(row) => {
            if let Err(e) = db::descriptors::grant(&state.db, &row.actor_id, &format!("cap/{}", row.id)).await {
                tracing::warn!(cap_id = %row.id, actor_id = %row.actor_id, "descriptor grant failed: {e}");
            }
            let perms = tokens::parse_permissions(&row);
            Json(serde_json::json!({
                "token":        row.id,
                "session_id":   row.session_id,
                "actor_id":     row.actor_id,
                "expires_at":   row.expires_at,
                "observed_seq": row.observed_seq,
                "permissions":  perms,
                "parent_cap":   row.parent_cap,
                // `shim` is the entry point — it does the SOLARPLEX_TOKEN exchange and
                // spawns the guardian + sidecar as children over an inherited IPC fd.
                // Running `sidecar` (solarplex-adapter) directly cannot work: it has no
                // token exchange of its own and expects that fd to already exist.
                // Fish syntax (`set -gx`) matches the shell integration everywhere else
                // in the CLI — see config::save's fish companion file.
                "launch_cmd": format!(
                    "set -gx SOLARPLEX_TOKEN \"{}\"\nset -gx UPSTREAM_MCP_CMD \"npx -y @modelcontextprotocol/server-filesystem {}\"\nset -gx SIDECAR_PORT \"7777\"\ncargo run -p shim",
                    row.id,
                    body.mcp_path.as_deref().unwrap_or("/path/to/allowed/dir"),
                ),
            })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── REST message post ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct PostMessageBody {
    /// No longer trusted for identity — accepted-but-ignored so existing
    /// callers that still send it don't break deserialization. Previously
    /// this endpoint had no auth at all: anyone with any valid credential
    /// (or none — the handler took no headers) could post a message as any
    /// member of the session just by naming them here. The real actor is
    /// now the verified sp_token/cap_id identity below.
    #[allow(dead_code)]
    actor_id: Option<String>,
    content: String,
    /// Agent callers (sidecar) have no sp_token — this is their credential.
    /// Absent for human callers, who authenticate via the Authorization header.
    #[serde(default)]
    cap_id: Option<String>,
}

#[autometrics]
async fn post_message(
    Path(id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<PostMessageBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_or_cap_auth(
        &state.db, &headers, &id, body.cap_id.as_deref(), MemberRole::Collaborator,
    ).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &actor_id, RateLimitKey::MessagePost { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    let event = WsMessage::new(
        ulid::Ulid::new().to_string(),
        WsPayload::MessagePosted {
            session_id: id.clone(),
            actor: actor_id.clone(),
            timestamp: Utc::now(),
            seq: 0,
            payload: MessagePostedPayload { content: body.content.clone() },
        },
    );
    emit_to_session(&state, &id, &actor_id, event).await;

    // ── Session task: feed MessagePost (after durable commit, shadow-
    // persisted — see task_message_post's doc comment) ───────────────────────
    let hub  = state.get_or_create_hub(&id);
    let task = state.get_or_create_session_task(&id, &actor_id, hub);
    task_message_post(&task, actor_id, body.content.clone()).await;

    StatusCode::NO_CONTENT.into_response()
}

// ── REST context add ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct AddContextBody {
    /// No longer trusted for identity — see PostMessageBody's identical note.
    #[allow(dead_code)]
    actor_id: Option<String>,
    kind: String,
    content: String,
    /// "agent" or "human" — supplied by the sidecar based on whether it holds a cap.
    #[serde(default)]
    authored_by: Option<String>,
    /// Agent callers (sidecar) have no sp_token — this is their credential.
    #[serde(default)]
    cap_id: Option<String>,
}

#[autometrics]
async fn add_context(
    Path(id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddContextBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_or_cap_auth(
        &state.db, &headers, &id, body.cap_id.as_deref(), MemberRole::Collaborator,
    ).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &actor_id, RateLimitKey::ContextAdd { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    let kind = match body.kind.as_str() {
        "hypothesis"  => ContextEntryKind::Hypothesis,
        "decision"    => ContextEntryKind::Decision,
        "question"    => ContextEntryKind::Question,
        "constraint"  => ContextEntryKind::Constraint,
        _             => ContextEntryKind::Fact,
    };
    let entry_id = ulid::Ulid::new().to_string();
    let event = WsMessage::new(
        ulid::Ulid::new().to_string(),
        WsPayload::ContextEntryAdded {
            session_id: id.clone(),
            actor: actor_id.clone(),
            timestamp: Utc::now(),
            seq: 0,
            payload: ContextEntryAddedPayload {
                entry_id: entry_id.clone(),
                kind: kind.clone(),
                content: body.content.clone(),
                authored_by: body.authored_by.clone(),
            },
        },
    );
    emit_to_session(&state, &id, &actor_id, event).await;

    // ── Session task: feed ContextAdd (after durable commit, shadow-
    // persisted) ──────────────────────────────────────────────────────────
    let hub  = state.get_or_create_hub(&id);
    let task = state.get_or_create_session_task(&id, &actor_id, hub);
    task_context_add(&task, entry_id, actor_id, kind, body.content.clone()).await;

    StatusCode::NO_CONTENT.into_response()
}

// ── Events list ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EventsQuery {
    pub after_seq: Option<i64>,
    pub limit: Option<i64>,
}

#[autometrics]
async fn list_events(
    Path(id): Path<String>,
    headers:  HeaderMap,
    Query(q): Query<EventsQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        Ok(actor_id) => actor_id,
        Err(res) => return res,
    };
    // Linked-session (session_links) access has no real `session_memberships`
    // row for this session -- treat that the same as the lowest human tier
    // rather than erroring, matching require_membership_or_linked_access's
    // own Observer-level grant for that path.
    let role = sessions::get_membership(&state.db, &id, &actor_id).await
        .map(|m| m.role.parse().unwrap_or(MemberRole::Observer))
        .unwrap_or(MemberRole::Observer);

    match db::events::list(&state.db, &id, q.after_seq, q.limit.unwrap_or(100)).await {
        Ok(mut events) => {
            events.retain_mut(|e| match crate::event_visibility::min_role_for_type(&e.r#type) {
                None => true,
                Some(min) if role.satisfies(&min) => true,
                Some(_) => crate::event_visibility::redact_value(&e.r#type, &mut e.payload),
            });
            Json(events).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ConnectionsQuery {
    limit: Option<i64>,
}

/// The queryable half of the connect/disconnect audit trail — see migration
/// 033's doc comment. Deliberately separate from `/events`: this is
/// connection lifecycle (including routine reconnects), not session content.
#[autometrics]
async fn list_connections(
    Path(id):     Path<String>,
    headers:      HeaderMap,
    Query(q):     Query<ConnectionsQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        return res;
    }
    match db::session_connections::list_for_session(&state.db, &id, q.limit.unwrap_or(200)).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn list_approvals(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        return res;
    }
    match db::approvals::list_pending(&state.db, &id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Artifact routes (nested under session) ────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateArtifactBody {
    /// No longer trusted for identity — see PostMessageBody's identical note.
    #[allow(dead_code)]
    pub created_by: Option<String>,
    pub name: String,
    pub artifact_type: String,
    pub content: String,
    /// Agent callers (sidecar) have no sp_token — this is their credential.
    #[serde(default)]
    pub cap_id: Option<String>,
}

#[autometrics]
async fn list_artifacts(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        return res;
    }
    match db::artifacts::list(&state.db, &id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn create_artifact(
    Path(id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateArtifactBody>,
) -> impl IntoResponse {
    let created_by = match crate::auth::require_sp_or_cap_auth(
        &state.db, &headers, &id, body.cap_id.as_deref(), MemberRole::Collaborator,
    ).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &created_by, RateLimitKey::ArtifactCreate { actor_id: created_by.clone() },
    ).await {
        return res;
    }
    // Compute SHA-256 and feed CMS before `body.content` is moved.
    let sha256 = {
        let mut h = Sha256::new();
        h.update(body.content.as_bytes());
        format!("{:x}", h.finalize())
    };
    state.cms.insert(&body.content);
    let db2   = state.db.clone();
    let sha2c = sha256.clone();
    tokio::spawn(async move {
        if let Err(e) = db::artifact_reputation::upsert_hash(&db2, &sha2c).await {
            tracing::warn!("artifact_hashes upsert: {e}");
        }
    });

    match db::artifacts::create(&state.db, db::artifacts::CreateArtifact {
        session_id: id.clone(),
        created_by: created_by.clone(),
        name: body.name.clone(),
        artifact_type: body.artifact_type.clone(),
        storage_ref: body.content,
    })
    .await
    {
        Ok(a) => {
            let event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ArtifactCreated {
                    session_id: id.clone(),
                    actor: created_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ArtifactPayload {
                        artifact_id: a.id.clone(),
                        name: a.name.clone(),
                        artifact_type: Some(a.r#type.clone()),
                    },
                },
            );
            emit_to_session(&state, &id, &created_by, event).await;

            // ── Session task: feed ArtifactCreate (after durable commit,
            // shadow-persisted) ─────────────────────────────────────────────
            let hub  = state.get_or_create_hub(&id);
            let task = state.get_or_create_session_task(&id, &created_by, hub);
            task_artifact_create(&task, a.id.clone(), created_by, a.name.clone(), Some(a.r#type.clone())).await;

            (StatusCode::CREATED, Json(a)).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Cross-session artifact import ─────────────────────────────────────────────
//
// A publish/import operation, not a live reference — see migration 029's
// doc comment. The copy is independent from the moment it's created;
// authority and approval never travel with it. Auto-fires a ContextEntry in
// the target with a fixed audit note, per product decision.

#[derive(Deserialize)]
struct ImportArtifactBody {
    source_session_id: String,
    source_artifact_id: String,
}

#[autometrics]
async fn import_artifact(
    Path(target_id): Path<String>,
    headers:         HeaderMap,
    State(state):    State<Arc<AppState>>,
    Json(body):      Json<ImportArtifactBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &target_id, MemberRole::Collaborator,
    ).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    // Read access to the source — the normal linked-access check, same one
    // every other cross-session read uses. This is the entire authority
    // bar for the source side: importing doesn't need Collaborator+ in A,
    // only standing visibility into it.
    if let Err(e) = db::sessions::require_membership_or_linked_access(
        &state.db, &body.source_session_id, &actor_id, MemberRole::Observer,
    ).await {
        return match e {
            db::DbError::NotFound | db::DbError::Unauthorized => StatusCode::NOT_FOUND.into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    let source_artifact = match db::artifacts::get(&state.db, &body.source_artifact_id).await {
        Ok(a) if a.session_id == body.source_session_id => a,
        Ok(_) | Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let (source_seq, source_session, target_session, link) = tokio::join!(
        db::events::current_seq(&state.db, &body.source_session_id),
        db::sessions::get(&state.db, &body.source_session_id),
        db::sessions::get(&state.db, &target_id),
        db::session_links::get_between(&state.db, &body.source_session_id, &target_id),
    );
    let source_seq = source_seq.unwrap_or(0);
    let source_name = source_session.map(|s| s.name).unwrap_or_else(|_| body.source_session_id.clone());
    let target_name = target_session.map(|s| s.name).unwrap_or_else(|_| target_id.clone());
    let link_id = link.ok().flatten().map(|l| l.id);

    let content_hash = {
        let mut h = Sha256::new();
        h.update(source_artifact.storage_ref.as_bytes());
        format!("{:x}", h.finalize())
    };

    // Idempotency: does the target session already contain this exact
    // content — as either a prior import *or* a native artifact an import
    // chain started from? Content hash alone is the right key (see
    // db::artifact_imports::find_existing's doc comment for why keying on
    // source_artifact_id let a round-trip re-import — A -> B, then drag
    // the copy back B -> A — slip through as a fresh duplicate). Scanning
    // the target's own artifacts catches both cases in one check, since a
    // prior import's copy is itself one of the target's artifacts, and the
    // *original* artifact an import chain started from was never itself
    // recorded as an import — there's no artifact_imports row for it to
    // match against otherwise.
    let target_artifacts = db::artifacts::list(&state.db, &target_id).await.unwrap_or_default();
    if let Some(dup) = target_artifacts.iter().find(|a| {
        let mut h = Sha256::new();
        h.update(a.storage_ref.as_bytes());
        format!("{:x}", h.finalize()) == content_hash
    }) {
        return (StatusCode::OK, Json(serde_json::json!({
            "artifact": dup, "already_imported": true,
        }))).into_response();
    }

    // Beyond this point the write moves to the target session's own mailbox
    // via the reflector, instead of a direct create + emit_to_session here.
    // That direct write was exactly the uncoordinated side-channel the
    // actor-model rewrite was meant to eliminate: the target session's own
    // live effect processing had no idea this write happened except after
    // the fact. Dispatching a bundle serializes it through the target's own
    // session task like every other mutation, and makes delivery correct
    // when that task lives on a different replica than the one handling
    // this request (Reflector::dispatch forwards durably; the notifier.rs
    // cross-replica fix makes the resulting broadcast reach clients on any
    // replica, not just whichever one processed it). See Part 3 of the plan.
    let bundle = SagaBundle {
        bundle_id:    Ulid::new().to_string(),
        saga_id:      Ulid::new().to_string(),
        step_idx:     0,
        from_session: body.source_session_id.clone(),
        to_session:   target_id.clone(),
        kind: BundleKind::Step {
            message: serde_json::json!({
                "kind":               "artifact_import",
                "source_artifact_id": source_artifact.id,
                "source_seq":         source_seq,
                "name":               source_artifact.name,
                "artifact_type":      source_artifact.r#type,
                "storage_ref":        source_artifact.storage_ref,
                "content_hash":       content_hash,
                "source_created_by":  source_artifact.created_by,
                "source_created_at":  source_artifact.created_at.to_rfc3339(),
                "imported_by":        actor_id,
                "link_id":            link_id,
                "source_name":        source_name,
                "target_name":        target_name,
            }),
            compensation: serde_json::json!({}),
        },
        // A human decision window isn't relevant here (there's no ack leg),
        // but the target session's task may not be live at dispatch time —
        // a generous TTL keeps the bundle in the reflector log for delivery
        // on reconnect rather than losing it to a tight expiry.
        ttl_ms: Utc::now().timestamp_millis() as u64 + 24 * 60 * 60 * 1000,
    };
    let local_node = crate::numa::session_numa_node(&body.source_session_id, state.numa_nodes);
    crate::session_task::route_bundle(
        &body.source_session_id, bundle, &state.reflector, &state.sessions, local_node,
    ).await;

    // No artifact/receipt to return synchronously — creation now happens
    // asynchronously in the target's own mailbox. The frontend doesn't need
    // it either: it relies on the live ArtifactCreated broadcast, not this
    // response body (see SyncWorkspace.tsx's handleArtifactDrop).
    (StatusCode::ACCEPTED, Json(serde_json::json!({
        "already_imported": false,
        "dispatched": true,
    }))).into_response()
}

#[derive(Deserialize)]
pub struct SendContextEntryBody {
    pub source_session_id:   String,
    pub source_entry_id:     String,
    /// "fact" | "hypothesis" | "question" | "constraint" | "decision" — same
    /// string set add_context's body already accepts; unrecognized falls
    /// back to "fact", matching that handler's own fallback.
    pub kind:                String,
    pub content:              String,
    pub source_authored_by:   String,
    pub source_authored_at:   DateTime<Utc>,
}

/// Part 4B: send one of *your* session's existing context entries into a
/// linked session's context log, with provenance. The caller already has
/// the entry's own fields from its own live `state.contextEntries` (there's
/// no `context_entries` table to re-read server-side — see Part 4's plan
/// context) so this trusts the client for content/kind/authorship and only
/// verifies genuine access to the claimed source session, same bar
/// `import_artifact` uses for its own source-side check.
#[autometrics]
async fn send_context_entry(
    Path(target_id): Path<String>,
    headers:         HeaderMap,
    State(state):    State<Arc<AppState>>,
    Json(body):      Json<SendContextEntryBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &target_id, MemberRole::Collaborator,
    ).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    if let Err(e) = db::sessions::require_membership_or_linked_access(
        &state.db, &body.source_session_id, &actor_id, MemberRole::Observer,
    ).await {
        return match e {
            db::DbError::NotFound | db::DbError::Unauthorized => StatusCode::NOT_FOUND.into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    let (source_session, target_session, link) = tokio::join!(
        db::sessions::get(&state.db, &body.source_session_id),
        db::sessions::get(&state.db, &target_id),
        db::session_links::get_between(&state.db, &body.source_session_id, &target_id),
    );
    let source_name = source_session.map(|s| s.name).unwrap_or_else(|_| body.source_session_id.clone());
    let target_name = target_session.map(|s| s.name).unwrap_or_else(|_| target_id.clone());
    let link_id = link.ok().flatten().map(|l| l.id);

    let bundle = SagaBundle {
        bundle_id:    Ulid::new().to_string(),
        saga_id:      Ulid::new().to_string(),
        step_idx:     0,
        from_session: body.source_session_id.clone(),
        to_session:   target_id.clone(),
        kind: BundleKind::Step {
            message: serde_json::json!({
                "kind":                "context_summary_send",
                "source_entry_id":     body.source_entry_id,
                "entry_kind":          body.kind,
                "content":             body.content,
                "source_authored_by":  body.source_authored_by,
                "source_authored_at":  body.source_authored_at.to_rfc3339(),
                "imported_by":         actor_id,
                "link_id":             link_id,
                "source_name":         source_name,
                "target_name":         target_name,
            }),
            compensation: serde_json::json!({}),
        },
        ttl_ms: Utc::now().timestamp_millis() as u64 + 24 * 60 * 60 * 1000,
    };
    let local_node = crate::numa::session_numa_node(&body.source_session_id, state.numa_nodes);
    crate::session_task::route_bundle(
        &body.source_session_id, bundle, &state.reflector, &state.sessions, local_node,
    ).await;

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "dispatched": true }))).into_response()
}

#[derive(Deserialize)]
pub struct AnnotateObjectBody {
    pub source_session_id: String,
    /// v1: "artifact" only (see Part 4's plan context).
    pub object_type:        String,
    pub object_id:           String,
    pub object_name:         String,
    pub note:                 String,
}

/// Part 4C: leave a note on an artifact that lives in `target_id` (the
/// session owning the object), authored by a member of `source_session_id`
/// (typically the caller's own home session, viewing `target_id` as a
/// linked SyncWorkspace pane). Same authorization bar as artifact import
/// and context-summary-send — Collaborator+ in the target, deliberately not
/// loosened to Observer for v1 (see the plan's note on this call).
#[autometrics]
async fn annotate_object(
    Path(target_id): Path<String>,
    headers:         HeaderMap,
    State(state):    State<Arc<AppState>>,
    Json(body):      Json<AnnotateObjectBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &target_id, MemberRole::Collaborator,
    ).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    if let Err(e) = db::sessions::require_membership_or_linked_access(
        &state.db, &body.source_session_id, &actor_id, MemberRole::Observer,
    ).await {
        return match e {
            db::DbError::NotFound | db::DbError::Unauthorized => StatusCode::NOT_FOUND.into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    let (source_session, link) = tokio::join!(
        db::sessions::get(&state.db, &body.source_session_id),
        db::session_links::get_between(&state.db, &body.source_session_id, &target_id),
    );
    let source_name = source_session.map(|s| s.name).unwrap_or_else(|_| body.source_session_id.clone());
    let link_id = link.ok().flatten().map(|l| l.id);

    let bundle = SagaBundle {
        bundle_id:    Ulid::new().to_string(),
        saga_id:      Ulid::new().to_string(),
        step_idx:     0,
        from_session: body.source_session_id.clone(),
        to_session:   target_id.clone(),
        kind: BundleKind::Step {
            message: serde_json::json!({
                "kind":        "annotation",
                "object_type": body.object_type,
                "object_id":   body.object_id,
                "object_name": body.object_name,
                "note":        body.note,
                "authored_by": actor_id,
                "link_id":     link_id,
                "source_name": source_name,
            }),
            compensation: serde_json::json!({}),
        },
        ttl_ms: Utc::now().timestamp_millis() as u64 + 24 * 60 * 60 * 1000,
    };
    let local_node = crate::numa::session_numa_node(&body.source_session_id, state.numa_nodes);
    crate::session_task::route_bundle(
        &body.source_session_id, bundle, &state.reflector, &state.sessions, local_node,
    ).await;

    (StatusCode::ACCEPTED, Json(serde_json::json!({ "dispatched": true }))).into_response()
}

#[autometrics]
async fn get_artifact(
    Path((session_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &session_id, MemberRole::Observer).await {
        return res;
    }
    match db::artifacts::get(&state.db, &artifact_id).await {
        Ok(a) if a.session_id == session_id => Json(a).into_response(),
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct UpdateArtifactBody {
    pub content:  String,
    /// No longer trusted for identity — see PostMessageBody's identical note.
    #[allow(dead_code)]
    #[serde(default)]
    pub actor_id: Option<String>,
    /// Agent callers (sidecar) have no sp_token — this is their credential.
    #[serde(default)]
    pub cap_id: Option<String>,
}

#[autometrics]
async fn update_artifact(
    Path((session_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<UpdateArtifactBody>,
) -> impl IntoResponse {
    // Same bar as create_artifact — active (non-Observer) member of this
    // session. Previously had no gate at all: anyone could edit any
    // artifact in any session.
    let actor_id = match crate::auth::require_sp_or_cap_auth(
        &state.db, &headers, &session_id, body.cap_id.as_deref(), MemberRole::Collaborator,
    ).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &session_id, &actor_id, RateLimitKey::ArtifactMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    // Cross-session guard — `db::artifacts::update` addresses purely by
    // artifact_id, so without this a member of *any* session could edit an
    // artifact belonging to a session they're not part of, just by knowing
    // its id. Matches the check `get_artifact` already does after fetch.
    match db::artifacts::get(&state.db, &artifact_id).await {
        Ok(a) if a.session_id == session_id => {}
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    match db::artifacts::update(&state.db, &artifact_id, &body.content).await {
        Ok(a) => {
            let event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ArtifactUpdated {
                    session_id: session_id.clone(),
                    actor: a.created_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ArtifactPayload {
                        artifact_id: a.id.clone(),
                        name: a.name.clone(),
                        artifact_type: Some(a.r#type.clone()),
                    },
                },
            );
            emit_to_session(&state, &session_id, &a.created_by.clone(), event).await;

            // ── Session task: feed ArtifactUpdate (after durable commit,
            // shadow-persisted). actor_id here is the verified update caller,
            // not a.created_by — matches who actually performed this action,
            // same distinction the WsPayload event above blurs by
            // attributing to the artifact's original creator.
            let hub  = state.get_or_create_hub(&session_id);
            let task = state.get_or_create_session_task(&session_id, &actor_id, hub);
            task_artifact_update(&task, a.id.clone(), actor_id, a.name.clone(), Some(a.r#type.clone())).await;

            Json(a).into_response()
        }
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct DeleteArtifactQuery {
    /// No longer trusted for identity — see PostMessageBody's identical note.
    #[allow(dead_code)]
    pub actor_id: Option<String>,
    /// Agent callers (sidecar) have no sp_token — this is their credential.
    pub cap_id: Option<String>,
}

#[autometrics]
async fn delete_artifact(
    Path((session_id, artifact_id)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<DeleteArtifactQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Same bar as update_artifact/create_artifact — active (non-Observer)
    // member of this session. Previously had no gate at all: anyone could
    // delete any artifact in any session.
    let actor_id = match crate::auth::require_sp_or_cap_auth(
        &state.db, &headers, &session_id, q.cap_id.as_deref(), MemberRole::Collaborator,
    ).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &session_id, &actor_id, RateLimitKey::ArtifactMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    // Fetch artifact first so we have name/type for the event payload —
    // also doubles as the cross-session guard (matches get_artifact/
    // update_artifact): db::artifacts::delete addresses purely by
    // artifact_id, so without this a member of *any* session could delete
    // an artifact belonging to a session they're not part of.
    let artifact = match db::artifacts::get(&state.db, &artifact_id).await {
        Ok(a) if a.session_id == session_id => a,
        Ok(_) => return StatusCode::NOT_FOUND.into_response(),
        Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    match db::artifacts::delete(&state.db, &artifact_id).await {
        Ok(_) => {
            let actor = artifact.created_by.clone();
            let event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ArtifactDeleted {
                    session_id: session_id.clone(),
                    actor: actor.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ArtifactPayload {
                        artifact_id: artifact.id.clone(),
                        name: artifact.name.clone(),
                        artifact_type: Some(artifact.r#type.clone()),
                    },
                },
            );
            emit_to_session(&state, &session_id, &actor, event).await;

            // ── Session task: feed ArtifactDelete (after durable commit,
            // shadow-persisted). Uses the verified delete caller as the
            // bridge actor, same distinction as update_artifact above.
            let hub  = state.get_or_create_hub(&session_id);
            let task = state.get_or_create_session_task(&session_id, &actor_id, hub);
            task_artifact_delete(
                &task, artifact.id.clone(), actor_id, artifact.name.clone(),
                Some(artifact.r#type.clone()),
            ).await;

            StatusCode::NO_CONTENT.into_response()
        }
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Sidecar REST endpoints (no WS) ───────────────────────────────────────────

/// POST /api/sessions/{id}/agent-attach
///
/// Called by the sidecar on startup instead of opening a WS connection.
/// Emits `actor.joined` (role = Agent) + `agent.status.changed` (Running)
/// so the UI shows the agent as online immediately.
#[derive(Deserialize)]
struct AgentAttachBody {
    /// No longer trusted for identity — see `cap_id`. Kept accepted-but-
    /// ignored so a client that still sends it doesn't break deserialization.
    #[allow(dead_code)]
    actor_id: Option<String>,
    /// The cap minted for this agent at attach-token-issue time — the only
    /// credential an agent has (it never holds an sp_token; OIDC is human-
    /// only). Previously this endpoint had no auth at all: anyone could
    /// forge agent presence for any session by POSTing any actor_id.
    cap_id: String,
}

#[autometrics]
async fn agent_attach(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentAttachBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)      => a,
        Err(res)   => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &actor_id, RateLimitKey::AgentAttach { actor_id: actor_id.clone() },
    ).await {
        return res;
    }

    // actor.joined — sets attached=true + role=Agent in the snapshot projection
    let joiner_name = actors::get(&state.db, &actor_id).await.ok().map(|a| a.name);
    emit_to_session(
        &state, &id, &actor_id,
        WsMessage::new(
            Ulid::new().to_string(),
            WsPayload::ActorJoined {
                session_id: id.clone(),
                actor: actor_id.clone(),
                timestamp: Utc::now(),
                seq: 0,
                role: Some(MemberRole::Agent),
                name: joiner_name,
            },
        ),
    ).await;

    // agent.status.changed { Running }
    emit_to_session(
        &state, &id, &actor_id,
        WsMessage::new(
            Ulid::new().to_string(),
            WsPayload::AgentStatusChanged {
                session_id: id.clone(),
                actor: actor_id.clone(),
                timestamp: Utc::now(),
                seq: 0,
                payload: AgentStatusPayload { status: AgentStatus::Running },
            },
        ),
    ).await;

    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/sessions/{id}/agent-detach
///
/// Called by shim when the adapter reports its MCP client's SSE stream
/// closed (AdapterMessage::ClientDisconnected). Mirrors agent_attach: emits
/// ActorDetached so the snapshot projection clears `attached` immediately,
/// rather than waiting on the heartbeat sweeper's ~45s backstop.
#[derive(Deserialize)]
struct AgentDetachBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id: String,
}

#[autometrics]
async fn agent_detach(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentDetachBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };

    emit_to_session(
        &state, &id, &actor_id,
        WsMessage::new(
            Ulid::new().to_string(),
            WsPayload::ActorDetached {
                session_id: id.clone(),
                actor: actor_id.clone(),
                timestamp: Utc::now(),
                seq: 0,
            },
        ),
    ).await;

    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/sessions/{id}/agent-status
///
/// Called by the sidecar to update its live status (Running / Waiting / etc.)
/// without a WS connection.
#[derive(Deserialize)]
struct AgentStatusBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id: String,
    status: String,
}

#[autometrics]
async fn agent_status(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentStatusBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    let parsed = match body.status.as_str() {
        "running" => AgentStatus::Running,
        "waiting" => AgentStatus::Waiting,
        "blocked" => AgentStatus::Blocked,
        "error"   => AgentStatus::Error,
        _         => AgentStatus::Idle,
    };
    emit_to_session(
        &state, &id, &actor_id,
        WsMessage::new(
            Ulid::new().to_string(),
            WsPayload::AgentStatusChanged {
                session_id: id.clone(),
                actor: actor_id.clone(),
                timestamp: Utc::now(),
                seq: 0,
                payload: AgentStatusPayload { status: parsed },
            },
        ),
    ).await;
    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/sessions/{id}/agent-heartbeat
///
/// Called periodically by shim for the life of the process. Agents never
/// hold a WS connection to `/stream` (that's browser-only), so this is the
/// only liveness signal the server has for them — `sweep_stale_agents`
/// (ws.rs) checks these timestamps and emits `ActorDetached` for any actor
/// whose heartbeat has lapsed, so a crashed shim stops showing as "active".
#[derive(Deserialize)]
struct AgentHeartbeatBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id: String,
}

#[autometrics]
async fn agent_heartbeat(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentHeartbeatBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    let hub = state.get_or_create_hub(&id);
    hub.agent_heartbeats.insert(actor_id, Instant::now());
    StatusCode::NO_CONTENT.into_response()
}

/// POST /api/sessions/{id}/approvals
///
/// Called by the sidecar to create an approval request.  The sidecar then
/// GETs `/api/approvals/{approval_id}/resolution` to long-poll for the result.
///
/// Body: `{ actor_id, tool_name, arguments, timeout_secs? }`
/// Response: `{ approval_id, expires_at }`
#[derive(Deserialize)]
struct CreateApprovalBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id: String,
    tool_name: String,
    arguments: serde_json::Value,
    #[serde(default = "default_approval_timeout")]
    timeout_secs: u64,
}

fn default_approval_timeout() -> u64 { 25 }

// ── Shell adapter routes ──────────────────────────────────────────────────────

/// POST /api/sessions/{id}/shell/start
///
/// Emits `shell.command.started` and returns `{ command_id }` so the fish
/// adapter can link the matching `complete` call.
#[derive(Deserialize)]
struct ShellStartBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id: String,
    /// Basename of argv[0] — always present; never contains arguments.
    argv0: String,
    /// Full command string — present only when tracked=true and the
    /// credential seatbelt did not fire on the client side.
    #[serde(default)]
    command: Option<String>,
    /// Whether the user opted in to full-command logging for this invocation.
    #[serde(default)]
    tracked: bool,
    /// Whether the client-side seatbelt suppressed the full argv.
    #[serde(default)]
    redacted: bool,
    #[serde(default)]
    cwd: Option<String>,
}

#[autometrics]
async fn shell_start(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ShellStartBody>,
) -> impl IntoResponse {
    // This is an audit-trail endpoint — without a real credential, anyone
    // could forge shell-command log entries into any session's history,
    // which is worse than most of the other gaps here given the whole
    // point of this product is auditing what agents actually did.
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    let command_id = Ulid::new().to_string();
    let event = WsMessage::new(
        Ulid::new().to_string(),
        WsPayload::ShellCommandStarted {
            session_id: id.clone(),
            actor: actor_id.clone(),
            timestamp: Utc::now(),
            seq: 0,
            payload: ShellCommandStartedPayload {
                command_id: command_id.clone(),
                argv0:      body.argv0.clone(),
                command:    body.command.clone(),
                tracked:    body.tracked,
                redacted:   body.redacted,
                cwd:        body.cwd,
            },
        },
    );
    emit_to_session(&state, &id, &actor_id, event).await;
    (StatusCode::CREATED, Json(serde_json::json!({ "command_id": command_id }))).into_response()
}

/// POST /api/sessions/{id}/shell/complete
///
/// Emits `shell.command.completed`.  Called after the command exits.
#[derive(Deserialize)]
struct ShellCompleteBody {
    #[allow(dead_code)]
    actor_id:   Option<String>,
    cap_id:     String,
    command_id: String,
    exit_code:  i32,
    duration_ms: u64,
}

#[autometrics]
async fn shell_complete(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ShellCompleteBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    let event = WsMessage::new(
        Ulid::new().to_string(),
        WsPayload::ShellCommandCompleted {
            session_id: id.clone(),
            actor: actor_id.clone(),
            timestamp: Utc::now(),
            seq: 0,
            payload: ShellCommandCompletedPayload {
                command_id: body.command_id.clone(),
                exit_code:  body.exit_code,
                duration_ms: body.duration_ms,
            },
        },
    );
    emit_to_session(&state, &id, &actor_id, event).await;
    StatusCode::NO_CONTENT.into_response()
}

// ── ORB method registry ───────────────────────────────────────────────────────

/// GET /api/sessions/{id}/methods
///
/// List all registered MCP methods for a session.  Returns every method
/// across all attached sidecars, ordered by server_slug + method_name.
#[autometrics]
async fn list_methods(
    Path(id): Path<String>,
    headers:  HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        return res;
    }
    match db::methods::list_for_session(&state.db, &id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

/// POST /api/sessions/{id}/methods
///
/// Register (or re-register) a batch of MCP methods for a sidecar/actor.
///
/// Called by the sidecar at attach time with its full `tools/list` manifest.
/// Idempotent: re-registration updates the schema and approval policy so
/// sidecar upgrades take effect without a session restart.
///
/// Body: `{ actor_id, methods: [{ name, description?, input_schema?, requires_approval? }] }`
/// Response: `{ registered: N }`
#[derive(Deserialize)]
struct RegisterMethodsBody {
    #[allow(dead_code)]
    actor_id: Option<String>,
    cap_id:   String,
    methods:  Vec<db::methods::MethodDef>,
}

#[autometrics]
async fn register_methods(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RegisterMethodsBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    let slug = db::methods::actor_id_to_slug(&actor_id);
    match db::methods::register_bulk(&state.db, &id, &slug, &body.methods).await {
        Ok(n) => (
            StatusCode::OK,
            Json(serde_json::json!({ "registered": n })),
        ).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn create_approval_rest(
    Path(id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateApprovalBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_cap_auth(&state.db, &id, &body.cap_id).await {
        Ok(a)    => a,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &id, &actor_id, RateLimitKey::ApprovalRequest { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match create_approval_for_session(
        &state, &id, &actor_id, &body.tool_name, &body.arguments, body.timeout_secs,
    ).await {
        Some((approval_id, expires_at)) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "approval_id": approval_id,
                "expires_at":  expires_at,
            })),
        ).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
