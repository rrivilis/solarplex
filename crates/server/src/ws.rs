use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use tokio::sync::mpsc;
use ulid::Ulid;

use db::approvals;
use db::artifacts;
use db::sessions;
use protocol::messages::{
    ApprovalDecision, ApprovalEventPayload, ContextEntryAddedPayload, ContextEntryResolvedPayload,
    EffectRateLimitedPayload, WsMessage, WsPayload,
};
use protocol::types::{
    ApprovalPolicy, ApprovalState, ArtifactSummary, ContextEntry, ContextEntryKind,
    MemberRole, PendingApproval, SessionSnapshot, SessionStatus, Vote,
};
use session::rate_limit::{Admission, RateLimitKey};

use crate::session_task::{
    task_actor_connected, task_actor_disconnected,
    task_approval_cancel, task_approval_claim, task_approval_create, task_approval_delegate,
    task_approval_dispute, task_context_add, task_context_resolve, task_message_post,
    task_saga_ack, task_vote_cast,
};
use crate::state::{AppState, LiveSnapshot, SessionHub};

// ── Public WS upgrade handler ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WsQuery {
    // ── Human OIDC path ──────────────────────────────────────────────────────
    /// Opaque Solarplex session token issued after OIDC callback.
    /// When present, actor_id is derived from the token; raw actor_id is ignored.
    sp_token: Option<String>,
    // ── Agent / legacy path ──────────────────────────────────────────────────
    /// Actor identifier.  Required when sp_token is absent.
    actor_id: Option<String>,
    /// Join token for agent onboarding (single-use, issued by "Attach Agent" UI).
    /// When absent and sp_token is also absent, the actor must already be a member.
    token: Option<String>,
}

pub async fn handler(
    ws: WebSocketUpgrade,
    Path(session_id): Path<String>,
    Query(query): Query<WsQuery>,
    State(state): State<Arc<AppState>>,
) -> Response {
    // Human sp_token path: validate token BEFORE the WebSocket upgrade.
    // On failure the client receives a plain HTTP 401 (not a WS close frame),
    // which is cheaper and more informative for human-facing clients.
    if let Some(ref sp_token) = query.sp_token {
        match crate::auth::validate_sp_token(&state.db, sp_token).await {
            Ok(row) => {
                let actor_id = row.actor_id;
                return ws.on_upgrade(move |socket| {
                    // join_token is None for the human path — membership is
                    // already established; OIDC only verifies identity.
                    handle_ws(socket, state, session_id, actor_id, None)
                });
            }
            Err(e) => {
                tracing::warn!(session_id, error = %e, "WS rejected: invalid sp_token");
                return (axum::http::StatusCode::UNAUTHORIZED, "invalid or expired session token")
                    .into_response();
            }
        }
    }

    // Agent path: actor_id + join_token, both required.
    // The tokenless legacy path (actor_id only, no sp_token, no join_token) is
    // closed — it admitted caller-supplied identity with no verification.
    let actor_id = match query.actor_id {
        Some(id) => id,
        None => {
            tracing::warn!(session_id, "WS rejected: no auth credentials");
            return (axum::http::StatusCode::BAD_REQUEST, "actor_id or sp_token required")
                .into_response();
        }
    };
    if query.token.is_none() {
        tracing::warn!(session_id, actor_id, "WS rejected: join_token required");
        return (axum::http::StatusCode::UNAUTHORIZED, "join_token required for agent connections")
            .into_response();
    }
    ws.on_upgrade(move |socket| {
        handle_ws(socket, state, session_id, actor_id, query.token)
    })
}

// ── Connection lifecycle ──────────────────────────────────────────────────────

async fn handle_ws(
    socket: WebSocket,
    state: Arc<AppState>,
    session_id: String,
    actor_id: String,
    token: Option<String>,
) {
    // Set true only when this connect genuinely creates membership for the
    // first time (the join_token path's fallback add_member below) — that
    // still warrants a real, durable ActorJoined event. Every other case
    // (including every subsequent reconnect of that same actor) is just a
    // connection flickering, not a membership change — see broadcast_presence.
    let mut is_new_membership = false;

    let membership = match token {
        Some(ref provided) => {
            let session = match sessions::get(&state.db, &session_id).await {
                Ok(s) => s,
                Err(_) => {
                    tracing::warn!(session_id, "WS rejected: session not found");
                    let (mut sink, _) = socket.split();
                    let _ = sink.send(Message::Close(Some(CloseFrame {
                        code: 4404,
                        reason: "session_not_found".into(),
                    }))).await;
                    return;
                }
            };
            if !db::sessions::verify_join_token(provided, &session.join_token) {
                // No close frame previously sent here: the client would see the
                // socket just die with no code, indistinguishable from a network
                // drop, and (with no reconnect logic) hang indefinitely. A stale
                // cached token — e.g. after a rotation elsewhere invalidated it —
                // needs to be diagnosable so the client can clear its cache and
                // re-mint instead of retrying the same dead token forever.
                tracing::warn!(session_id, actor_id, "WS rejected: invalid token");
                let (mut sink, _) = socket.split();
                let _ = sink.send(Message::Close(Some(CloseFrame {
                    code: 4405,
                    reason: "invalid_token".into(),
                }))).await;
                return;
            }
            match sessions::get_membership(&state.db, &session_id, &actor_id).await {
                Ok(m) => m,
                Err(_) => {
                    // Reject an actor_id that already belongs to a real
                    // OIDC-registered human before minting anything under
                    // it — actor_id is never secret (it appears in every
                    // broadcast event this actor's ever been part of), so
                    // "pick the same string a real person uses" is a real
                    // impersonation path via this anonymous, unauthenticated
                    // path otherwise. Checked before the rate limit below so
                    // a targeted collision attempt doesn't also spend down
                    // the session's legitimate-join budget.
                    match db::human_sessions::exists_for_actor(&state.db, &actor_id).await {
                        Ok(true) => {
                            tracing::warn!(session_id, actor_id, "WS rejected: actor_id reserved by an OIDC identity");
                            let (mut sink, _) = socket.split();
                            let _ = sink.send(Message::Close(Some(CloseFrame {
                                code: 4406,
                                reason: "actor_id_reserved".into(),
                            }))).await;
                            return;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::error!(session_id, actor_id, "exists_for_actor: {e}"); return;
                        }
                    }

                    // Bound how many distinct new identities one session's
                    // shared join_token can mint — not a per-actor limit
                    // (there's no actor yet), a per-session one. Checked
                    // directly against the limiter rather than through
                    // `check_rate_limit`: that helper commits a durable
                    // `EffectRateLimited` event attributed to `actor_id`,
                    // which doesn't fit here — this actor was never a member
                    // and, on denial, still won't be.
                    let (admission, policy) = state.session_rate_limits.check(&session_id, RateLimitKey::AnonymousJoin);
                    if !matches!(admission, Admission::Allowed) {
                        tracing::warn!(
                            session_id, actor_id,
                            policy = policy.map(|p| p.describe()).unwrap_or_default(),
                            "WS rejected: too many new anonymous identities for this session",
                        );
                        let (mut sink, _) = socket.split();
                        let _ = sink.send(Message::Close(Some(CloseFrame {
                            code: 4429,
                            reason: "too_many_new_joins".into(),
                        }))).await;
                        return;
                    }

                    is_new_membership = true;
                    if let Err(e) = db::actors::ensure_human(&state.db, &actor_id, &actor_id).await {
                        tracing::error!(session_id, actor_id, "upsert actor: {e}"); return;
                    }
                    match sessions::add_member(&state.db, &session_id, &actor_id, "collaborator", None, None).await {
                        Ok(m) => m,
                        Err(e) => { tracing::error!(session_id, actor_id, "add_member: {e}"); return; }
                    }
                }
            }
        }
        // sp_token-authenticated human path (ws_handler guarantees `token`
        // is only None here for a verified sp_token, never "no credentials
        // at all"). Falls back to a linked-session auto-grant before
        // rejecting — see require_membership_or_linked_access. This branch
        // never creates membership itself (it requires membership already
        // exist, or grants only transient linked-session access), so
        // is_new_membership is never set true here.
        None => match sessions::require_membership_or_linked_access(
            &state.db, &session_id, &actor_id, MemberRole::Observer,
        ).await {
            Ok(m) => m,
            Err(_) => {
                tracing::warn!(session_id, actor_id, "WS rejected: not a member");
                // Send a custom close frame so the client can distinguish
                // "not a member" from a network drop and show a proper error.
                let (mut sink, _) = socket.split();
                let _ = sink.send(Message::Close(Some(CloseFrame {
                    code: 4403,
                    reason: "not_member".into(),
                }))).await;
                return;
            }
        },
    };

    let hub = state.get_or_create_hub(&session_id);
    let (write_tx, mut write_rx) = mpsc::unbounded_channel::<Utf8Bytes>();
    hub.actor_senders.insert(actor_id.clone(), write_tx.clone());
    let mut broadcast_rx = hub.broadcast_tx.subscribe();
    let write_tx_bcast = write_tx.clone();
    let (mut ws_sink, mut ws_stream) = socket.split();

    // ── Snapshot on attach ─────────────────────────────────────────────────────
    // Hot path: ArcSwap has a warm snapshot (O(1)).
    // Cold path: read session_snapshots — one DB row, not five queries.
    {
        let arc = hub.snapshot.load_full();
        let snap_msg = if let Some(live) = arc.as_ref() {
            tracing::debug!(session_id = %session_id, seq = live.seq, "attach: hot ArcSwap");
            make_snapshot_msg(&state.db, &session_id, live.seq, &live.state).await
        } else {
            let t0 = std::time::Instant::now();
            match load_snapshot_from_db(&state, &session_id).await {
                Ok((seq, snap)) => {
                    tracing::info!(
                        session_id = %session_id,
                        elapsed_ms = %t0.elapsed().as_millis(),
                        "attach: cold DB load",
                    );
                    hub.snapshot.store(Arc::new(Some(LiveSnapshot { seq, state: snap.clone() })));
                    make_snapshot_msg(&state.db, &session_id, seq, &snap).await
                }
                Err(e) => {
                    tracing::error!(session_id = %session_id, "load_snapshot_from_db: {e}");
                    return;
                }
            }
        };
        if let Ok(json) = serde_json::to_string(&snap_msg) {
            let _ = ws_sink.send(Message::Text(Utf8Bytes::from(json))).await;
        }
    }

    let writer_task = tokio::spawn(async move {
        while let Some(msg) = write_rx.recv().await {
            // `msg` is already owned (recv() yields by value, not by
            // reference) and `Utf8Bytes` clones are O(1) refcount bumps —
            // no `.clone()` needed here at all, unlike the old `Arc<String>`
            // dereference-then-clone this replaced.
            if ws_sink.send(Message::Text(msg)).await.is_err() { break; }
        }
    });
    let bcast_task = tokio::spawn(async move {
        while let Ok(msg) = broadcast_rx.recv().await {
            if write_tx_bcast.send(msg).is_err() { break; }
        }
    });

    // Include the membership role so the snapshot is updated with the correct role
    // even when the in-memory snapshot already has a stale value from a prior session.
    let actor_role = match membership.role.as_str() {
        "owner"        => Some(MemberRole::Owner),
        "collaborator" => Some(MemberRole::Collaborator),
        "observer"     => Some(MemberRole::Observer),
        "agent"        => Some(MemberRole::Agent),
        _              => None,
    };
    if is_new_membership {
        let joiner_name = db::actors::get(&state.db, &actor_id).await.ok().map(|a| a.name);
        commit_event(&state, &hub, &session_id, &actor_id,
            make_event(WsPayload::ActorJoined {
                session_id: session_id.clone(), actor: actor_id.clone(),
                timestamp: Utc::now(), seq: 0, role: actor_role, name: joiner_name,
            }),
        ).await;
    } else {
        broadcast_presence(&hub, &session_id, &actor_id, true, actor_role);
    }
    let _ = db::session_connections::record(&state.db, &session_id, &actor_id, "connected").await;

    // ── Session task: feed ActorConnected ────────────────────────────────────
    {
        let owner_id = hub.snapshot.load_full()
            .as_ref()
            .as_ref()
            .map(|s| s.state.owner.clone())
            .unwrap_or_else(|| actor_id.clone());
        let task    = state.get_or_create_session_task(&session_id, &owner_id, Arc::clone(&hub));
        let conn_id = format!("ws-{actor_id}");
        task_actor_connected(&task, actor_id.clone(), conn_id).await;
    }

    // Agents get an immediate Idle status so the minimap shows them as online.
    if membership.role == "agent" {
        commit_event(&state, &hub, &session_id, &actor_id,
            make_event(WsPayload::AgentStatusChanged {
                session_id: session_id.clone(), actor: actor_id.clone(),
                timestamp: Utc::now(), seq: 0,
                payload: protocol::messages::AgentStatusPayload {
                    status: protocol::types::AgentStatus::Idle,
                },
            }),
        ).await;
    }

    while let Some(Ok(msg)) = ws_stream.next().await {
        match msg {
            Message::Text(text) => {
                // Staleness fencing: if this actor's cap was revoked and the
                // drain window has closed, reject all writes with close 4401.
                if hub.is_fenced_and_expired(&actor_id) {
                    tracing::info!(
                        session_id,
                        actor_id,
                        "WS write rejected: epoch revocation drain window expired",
                    );
                    // The write_tx channel drives ws_sink, so close via that path.
                    let close_msg = serde_json::json!({
                        "type": "session.fenced",
                        "reason": "epoch_revocation",
                        "code": 4401,
                    });
                    if let Ok(json) = serde_json::to_string(&close_msg) {
                        let _ = write_tx.send(Utf8Bytes::from(json));
                    }
                    break;
                }
                if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                    dispatch(&state, &hub, &session_id, &actor_id, &membership.role, ws_msg).await;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    hub.actor_senders.remove(&actor_id);
    writer_task.abort();
    bcast_task.abort();

    broadcast_presence(&hub, &session_id, &actor_id, false, None);
    let _ = db::session_connections::record(&state.db, &session_id, &actor_id, "disconnected").await;

    // ── Session task: feed ActorDisconnected ─────────────────────────────────
    if let Some(task) = state.sessions.get(&session_id).map(|e| e.value().clone()) {
        task_actor_disconnected(&task, actor_id.clone(), format!("ws-{actor_id}")).await;
    }

    if hub.actor_senders.is_empty() {
        state.hubs.remove(&session_id);
        // Removing the SessionTaskHandle drops the sender; the task exits after
        // draining any remaining messages in its mailbox.
        state.sessions.remove(&session_id);
    }
}

// ── Dispatch ──────────────────────────────────────────────────────────────────

async fn dispatch(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    role: &str,
    msg: WsMessage,
) {
    // ── Session lifecycle gating ─────────────────────────────────────────────
    // Archived sessions are fully read-only — no commands accepted.
    // Suspended sessions only allow approval resolution (in-flight work can finish).
    let session_status = current_snap(hub).map(|s| s.status).unwrap_or(SessionStatus::Active);

    match session_status {
        SessionStatus::Archived => return, // all commands blocked
        SessionStatus::Suspended => {
            let is_approval_resolution = matches!(
                &msg.payload,
                WsPayload::ApprovalGrant { .. }
                    | WsPayload::ApprovalDeny { .. }
                    | WsPayload::ApprovalClaim { .. }
                    | WsPayload::ApprovalCancel { .. }
            );
            if !is_approval_resolution {
                return;
            }
        }
        SessionStatus::Active => {}
    }

    match msg.payload {
        WsPayload::ApprovalRequest { approval_id, tool_call, expires_at, .. } =>
            handle_approval_request(state, hub, session_id, actor_id, approval_id, tool_call, expires_at).await,
        WsPayload::ApprovalClaim { approval_id, .. } =>
            handle_approval_claim(state, hub, session_id, actor_id, &approval_id).await,
        WsPayload::ApprovalGrant { approval_id, .. } if can_vote(role) =>
            handle_vote(state, hub, session_id, actor_id, &approval_id, Vote::Approve).await,
        WsPayload::ApprovalDeny { approval_id, .. } if can_vote(role) =>
            handle_vote(state, hub, session_id, actor_id, &approval_id, Vote::Deny).await,
        WsPayload::ApprovalCancel { approval_id, .. } =>
            handle_approval_cancel(state, hub, session_id, actor_id, &approval_id).await,
        WsPayload::ApprovalDelegate { approval_id, to, .. } =>
            handle_approval_delegate(state, hub, session_id, actor_id, &approval_id, &to).await,
        WsPayload::ApprovalDispute { approval_id, reason, .. } =>
            handle_approval_dispute(state, hub, session_id, actor_id, &approval_id, &reason).await,
        WsPayload::OwnershipTransfer { from, to, .. } if role == "owner" =>
            handle_ownership_transfer(state, hub, session_id, &from, &to).await,
        WsPayload::MessagePost { content, .. } =>
            handle_message_post(state, hub, session_id, actor_id, &content).await,
        WsPayload::AgentStatusUpdate { status, .. } =>
            handle_agent_status(state, hub, session_id, actor_id, status.clone()).await,
        WsPayload::ContextEntryAdd { kind, content, .. } =>
            handle_context_add(state, hub, session_id, actor_id, kind.clone(), content.clone()).await,
        WsPayload::ContextEntryResolve { entry_id, note, .. } =>
            handle_context_resolve(state, hub, session_id, actor_id, entry_id.clone(), note.clone()).await,
        WsPayload::PresenceFocusSet { tab, .. } =>
            broadcast_presence_focus(hub, session_id, actor_id, tab.clone()),
        _ => {}
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async fn handle_approval_request(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    approval_id: String,
    tool_call: protocol::types::ToolCall,
    expires_at: Option<chrono::DateTime<Utc>>,
) {
    if !check_rate_limit(
        state, hub, session_id, actor_id,
        RateLimitKey::ApprovalRequest { actor_id: actor_id.to_string() },
    ).await {
        return;
    }
    let event = make_event(WsPayload::ApprovalRequested {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::ApprovalRequestedPayload {
            approval_id: approval_id.clone(), tool: tool_call.tool.clone(),
            summary: format!("{actor_id} wants to call {}", tool_call.tool),
            requested_by: actor_id.to_string(), expires_at,
            arguments: tool_call.args.clone(),
        },
    });

    let snap_ref = warm_snap(state, hub, session_id).await;
    let mut tx = match state.db.begin().await {
        Ok(t) => t, Err(e) => { tracing::error!(session_id, "begin tx: {e}"); return; }
    };
    if let Err(e) = approvals::insert_in_tx(
        &mut tx, &approval_id, session_id, actor_id,
        &tool_call.tool, &tool_call.args, expires_at,
    ).await {
        tracing::error!(session_id, "insert_in_tx: {e}"); return;
    }
    let (seq, new_snap, stamped) = match stamp_append_snapshot(&mut tx, snap_ref.as_ref(), session_id, actor_id, event).await {
        Ok(r) => r, Err(e) => { tracing::error!(session_id, "stamp_append_snapshot: {e}"); return; }
    };
    if let Err(e) = tx.commit().await { tracing::error!(session_id, "commit: {e}"); return; }
    store_and_broadcast(hub, seq, new_snap, &stamped).await;

    // ── Session task: feed ApprovalCreate (after durable commit) ─────────────
    // Consolidates onto the same bridge create_approval_for_session (the REST
    // sidecar path) already uses, closing the gap where this WS-originated
    // path never fed the machine at all.
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        let expires_ms = expires_at.map(|e| (e - Utc::now()).num_milliseconds().max(0) as u64);
        task_approval_create(
            &task, approval_id.clone(), actor_id.to_string(), tool_call.tool.clone(),
            tool_call.args.clone(), expires_ms,
        ).await;
    }
}

async fn handle_approval_claim(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    approval_id: &str,
) {
    let event = make_event(WsPayload::ApprovalClaimed {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: ApprovalEventPayload { approval_id: approval_id.to_string() },
    });
    let snap_ref = warm_snap(state, hub, session_id).await;
    let mut tx = match state.db.begin().await {
        Ok(t) => t, Err(e) => { tracing::error!(session_id, "begin tx: {e}"); return; }
    };
    // CAS: only succeeds if state is currently 'Pending'
    if let Err(e) = approvals::claim_if_pending_in_tx(&mut tx, approval_id, actor_id).await {
        tracing::warn!(session_id, approval_id, "claim_if_pending: {e}"); return;
    }
    let (seq, new_snap, stamped) = match stamp_append_snapshot(&mut tx, snap_ref.as_ref(), session_id, actor_id, event).await {
        Ok(r) => r, Err(e) => { tracing::error!(session_id, "stamp_append_snapshot: {e}"); return; }
    };
    if let Err(e) = tx.commit().await { tracing::error!(session_id, "commit: {e}"); return; }
    store_and_broadcast(hub, seq, new_snap, &stamped).await;

    // ── Session task: feed ApprovalClaim (after durable commit, shadow-
    // persisted — see task_approval_claim's doc comment) ─────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_approval_claim(&task, approval_id.to_string(), actor_id.to_string()).await;
    }
}

async fn handle_vote(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    approval_id: &str,
    vote: Vote,
) {
    let t0 = std::time::Instant::now();
    let vote_str = match vote { Vote::Approve => "approve", Vote::Deny => "deny" };

    // Read policy from warm snapshot (zero DB queries on hot path)
    let (policy, eligible) = {
        let arc = hub.snapshot.load_full();
        match arc.as_ref() {
            Some(live) => {
                let p = match live.state.approval_policy.as_str() {
                    "majority"  => ApprovalPolicy::Majority,
                    "unanimous" => ApprovalPolicy::Unanimous,
                    _           => ApprovalPolicy::SingleVote,
                };
                let e = live.state.members.iter()
                    .filter(|m| matches!(m.role, MemberRole::Owner | MemberRole::Collaborator))
                    .count();
                (p, e)
            }
            None => (ApprovalPolicy::SingleVote, 1),
        }
    };

    // Capture snapshot before opening transaction (no borrow conflict with tx)
    let snap_ref = warm_snap(state, hub, session_id).await;

    let mut tx = match state.db.begin().await {
        Ok(t) => t, Err(e) => { tracing::error!(session_id, "vote begin tx: {e}"); return; }
    };

    let updated = match approvals::record_vote_in_tx(&mut tx, approval_id, actor_id, vote_str).await {
        Ok(r) => r, Err(e) => { tracing::error!(session_id, "record_vote_in_tx: {e}"); return; }
    };

    let votes: HashMap<String, Vote> =
        serde_json::from_value(updated.votes.clone()).unwrap_or_default();
    let new_state = policy.evaluate(&votes, eligible);

    tracing::debug!(
        session_id, approval_id, vote = vote_str, outcome = ?new_state,
        record_vote_ms = %t0.elapsed().as_millis(), "handle_vote",
    );

    // Determine outcome event; update approval row in same tx
    let outcome_event: Option<WsMessage> = match &new_state {
        ApprovalState::Approved => {
            let _ = approvals::resolve_in_tx(&mut tx, approval_id, "Approved", actor_id).await;
            Some(make_event(WsPayload::ApprovalGranted {
                session_id: session_id.to_string(), actor: actor_id.to_string(),
                timestamp: Utc::now(), seq: 0,
                payload: ApprovalEventPayload { approval_id: approval_id.to_string() },
            }))
        }
        ApprovalState::Denied => {
            let _ = approvals::resolve_in_tx(&mut tx, approval_id, "Denied", actor_id).await;
            Some(make_event(WsPayload::ApprovalDenied {
                session_id: session_id.to_string(), actor: actor_id.to_string(),
                timestamp: Utc::now(), seq: 0,
                payload: protocol::messages::ApprovalDeniedPayload {
                    approval_id: approval_id.to_string(), reason: None,
                },
            }))
        }
        ApprovalState::Contested => {
            let _ = approvals::set_state_in_tx(&mut tx, approval_id, "Contested").await;
            Some(make_event(WsPayload::ApprovalContested {
                session_id: session_id.to_string(), actor: "system".to_string(),
                timestamp: Utc::now(), seq: 0,
                payload: protocol::messages::ApprovalContestedPayload {
                    approval_id: approval_id.to_string(),
                    votes: votes.clone(),
                    pending_resolution: "owner".to_string(),
                },
            }))
        }
        _ => None,
    };

    // Append event + snapshot in the same tx, then commit
    let broadcast_event: Option<(i64, SessionSnapshot, WsMessage)> = if let Some(ev) = outcome_event {
        match stamp_append_snapshot(&mut tx, snap_ref.as_ref(), session_id, actor_id, ev).await {
            Ok((seq, new_snap, stamped)) => Some((seq, new_snap, stamped)),
            Err(e) => {
                tracing::error!(session_id, "vote stamp_append_snapshot: {e}"); return;
            }
        }
    } else {
        None
    };

    if let Err(e) = tx.commit().await {
        tracing::error!(session_id, "vote commit: {e}"); return;
    }

    // Post-commit: update ArcSwap + broadcast + send_resolved (after durable commit)
    if let Some((seq, new_snap, ev)) = broadcast_event {
        store_and_broadcast(hub, seq, new_snap, &ev).await;
    }

    // ── Session task: feed VoteCast (after durable commit) ───────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        let approve = vote == Vote::Approve;
        task_vote_cast(&task, approval_id.to_string(), actor_id.to_string(), approve).await;
    }

    let resolution = match &new_state {
        ApprovalState::Approved => Some((updated.actor_id.clone(), ApprovalDecision::Granted)),
        ApprovalState::Denied   => Some((updated.actor_id.clone(), ApprovalDecision::Denied)),
        _                       => None,
    };

    // ── Cross-session delegation: if this approval was created on B's side
    // of a delegation from session A, tell A's session task so it can send
    // the saga Ack back — closing the loop by resolving A's original
    // approval to match. Best-effort: a lookup miss just means this wasn't
    // a delegated approval, not an error.
    if matches!(new_state, ApprovalState::Approved | ApprovalState::Denied) {
        match db::cross_session_delegations::get_by_target_approval(&state.db, approval_id).await {
            Ok(Some(delegation)) => {
                let outcome = if matches!(new_state, ApprovalState::Approved) {
                    session::SagaOutcome::Committed
                } else {
                    session::SagaOutcome::Rejected { reason: "denied by delegated session".to_string() }
                };
                if let Some(source_task) = state.sessions.get(&delegation.source_session_id).map(|e| e.value().clone()) {
                    task_saga_ack(&source_task, delegation.saga_id, 0, outcome).await;
                } else {
                    tracing::warn!(
                        session_id, approval_id, source_session_id = %delegation.source_session_id,
                        "cross-session delegation: source session task not running, ack not delivered \
                         (queued in reflector for replay once a reconnect-drain path exists)",
                    );
                }
            }
            Ok(None) => {}
            Err(e) => tracing::warn!(session_id, approval_id, "cross-session delegation lookup: {e}"),
        }
    }

    // pg_notify: wake any HTTP long-poll sidecar waiting on this approval.
    // Fires after commit — sidecar only proceeds on durable state.
    if let Some((_, ref decision)) = resolution {
        let decision_str = match decision {
            ApprovalDecision::Granted  => "granted",
            ApprovalDecision::Denied   => "denied",
            ApprovalDecision::TimedOut => "timed_out",
        };
        let notify_json = serde_json::json!({
            "approval_id": approval_id,
            "decision": decision_str,
        }).to_string();
        if let Err(e) = sqlx::query("SELECT pg_notify('approval_resolved', $1)")
            .bind(&notify_json)
            .execute(&state.db)
            .await
        {
            tracing::warn!(approval_id, "pg_notify approval_resolved: {e}");
        }
    }

    if let Some((sidecar_actor, decision)) = resolution {
        // WS path: backward compat — no-op if sidecar is no longer WS-connected.
        send_resolved(hub, &sidecar_actor, approval_id, decision, Some(actor_id)).await;
    }
}

async fn handle_approval_cancel(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    approval_id: &str,
) {
    let event = make_event(WsPayload::ApprovalCancelled {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: ApprovalEventPayload { approval_id: approval_id.to_string() },
    });
    let snap_ref = warm_snap(state, hub, session_id).await;
    let mut tx = match state.db.begin().await {
        Ok(t) => t, Err(e) => { tracing::error!(session_id, "begin tx: {e}"); return; }
    };
    let _ = approvals::set_state_in_tx(&mut tx, approval_id, "Expired").await;
    let (seq, new_snap, stamped) = match stamp_append_snapshot(&mut tx, snap_ref.as_ref(), session_id, actor_id, event).await {
        Ok(r) => r, Err(e) => { tracing::error!(session_id, "stamp_append_snapshot: {e}"); return; }
    };
    if let Err(e) = tx.commit().await { tracing::error!(session_id, "commit: {e}"); return; }
    store_and_broadcast(hub, seq, new_snap, &stamped).await;

    // ── Session task: feed ApprovalCancel (after durable commit, shadow-
    // persisted — see task_approval_cancel's doc comment) ────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_approval_cancel(&task, approval_id.to_string(), actor_id.to_string()).await;
    }
}

async fn handle_approval_delegate(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, approval_id: &str, to: &str,
) {
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::ApprovalDelegated {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::ApprovalDelegatedPayload {
            approval_id: approval_id.to_string(),
            from: actor_id.to_string(), to: to.to_string(),
        },
    })).await;

    // ── Session task: feed ApprovalDelegate (after durable commit, shadow-
    // persisted) ──────────────────────────────────────────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_approval_delegate(&task, approval_id.to_string(), actor_id.to_string(), to.to_string()).await;
    }
}

async fn handle_approval_dispute(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, approval_id: &str, reason: &str,
) {
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::ApprovalDisputed {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::ApprovalDisputedPayload {
            approval_id: approval_id.to_string(), reason: reason.to_string(),
        },
    })).await;

    // ── Session task: feed ApprovalDispute (after durable commit, shadow-
    // persisted) ──────────────────────────────────────────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_approval_dispute(&task, approval_id.to_string(), actor_id.to_string(), reason.to_string()).await;
    }
}

async fn handle_agent_status(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, status: protocol::types::AgentStatus,
) {
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::AgentStatusChanged {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::AgentStatusPayload { status },
    })).await;
}

async fn handle_message_post(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, content: &str,
) {
    if !check_rate_limit(
        state, hub, session_id, actor_id,
        RateLimitKey::MessagePost { actor_id: actor_id.to_string() },
    ).await {
        return;
    }
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::MessagePosted {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::MessagePostedPayload { content: content.to_string() },
    })).await;

    // ── Session task: feed MessagePost (after durable commit, shadow-
    // persisted — see task_message_post's doc comment) ───────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_message_post(&task, actor_id.to_string(), content.to_string()).await;
    }
}

async fn handle_context_add(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, kind: ContextEntryKind, content: String,
) {
    if !check_rate_limit(
        state, hub, session_id, actor_id,
        RateLimitKey::ContextAdd { actor_id: actor_id.to_string() },
    ).await {
        return;
    }
    let entry_id = ulid::Ulid::new().to_string();
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::ContextEntryAdded {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: ContextEntryAddedPayload { entry_id: entry_id.clone(), kind: kind.clone(), content: content.clone(), authored_by: None },
    })).await;

    // ── Session task: feed ContextAdd (after durable commit, shadow-
    // persisted) ──────────────────────────────────────────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_context_add(&task, entry_id, actor_id.to_string(), kind, content).await;
    }
}

async fn handle_context_resolve(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, actor_id: &str, entry_id: String, note: Option<String>,
) {
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::ContextEntryResolved {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: ContextEntryResolvedPayload { entry_id: entry_id.clone(), resolved_by: actor_id.to_string(), note: note.clone() },
    })).await;

    // ── Session task: feed ContextResolve (after durable commit, shadow-
    // persisted) ──────────────────────────────────────────────────────────
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        task_context_resolve(&task, entry_id, actor_id.to_string(), note).await;
    }
}

async fn handle_ownership_transfer(
    state: &Arc<AppState>, hub: &Arc<SessionHub>,
    session_id: &str, from: &str, to: &str,
) {
    if !check_rate_limit(state, hub, session_id, from, RateLimitKey::OwnershipTransfer).await {
        return;
    }
    let event = make_event(WsPayload::OwnershipTransferred {
        session_id: session_id.to_string(), actor: from.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: protocol::messages::OwnershipTransferredPayload {
            from: from.to_string(), to: to.to_string(),
        },
    });
    let snap_ref = warm_snap(state, hub, session_id).await;
    let mut tx = match state.db.begin().await {
        Ok(t) => t, Err(e) => { tracing::error!(session_id, "begin tx: {e}"); return; }
    };
    let _ = sessions::transfer_ownership_in_tx(&mut tx, session_id, from, to).await;
    let (seq, new_snap, stamped) = match stamp_append_snapshot(&mut tx, snap_ref.as_ref(), session_id, from, event).await {
        Ok(r) => r, Err(e) => { tracing::error!(session_id, "stamp_append_snapshot: {e}"); return; }
    };
    if let Err(e) = tx.commit().await { tracing::error!(session_id, "commit: {e}"); return; }
    store_and_broadcast(hub, seq, new_snap, &stamped).await;
}

// ── Tier-1 rate-limit gating (WS-originated commands) ──────────────────────
//
// `routes/sessions.rs` has an equivalent for REST-originated calls to the
// same actions. Both exist because both are live, independent durable-write
// paths for the same semantic actions: a browser's chat/context/ownership-
// transfer traffic goes through `dispatch` below over the open WS
// connection, never through the REST handlers of the same name — gating
// only the REST side (as an earlier pass did) would have left the actual
// UI-driven traffic completely unthrottled.
//
// Returns `true` to proceed, `false` if denied. WS commands are
// fire-and-forget frames, not request/response, so there's no status code
// to return here — the `EffectRateLimited` audit event, committed and
// broadcast to the hub, is the only signal a denial happened.
async fn check_rate_limit(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    key: RateLimitKey,
) -> bool {
    let key_label = key.label();
    let (admission, policy) = state.session_rate_limits.check(session_id, key);
    let Admission::Denied { retry_after } = admission else {
        return true;
    };
    let policy_desc = policy.map(|p| p.describe()).unwrap_or_default();
    let retry_after_secs = retry_after.as_secs();
    tracing::warn!(session_id, actor_id, key = key_label, policy = policy_desc, "rate limited");
    commit_event(state, hub, session_id, actor_id, make_event(WsPayload::EffectRateLimited {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), seq: 0,
        payload: EffectRateLimitedPayload {
            key_label: key_label.to_string(), policy: policy_desc, retry_after_secs,
        },
    })).await;
    false
}

// ── Core transactional primitives ─────────────────────────────────────────────

/// Commit a pure event (no additional state mutation).
async fn commit_event(
    state: &Arc<AppState>,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    event: WsMessage,
) {
    let snap_ref = warm_snap(state, hub, session_id).await;
    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => { tracing::error!(session_id, event = event.payload.type_name(), "begin: {e}"); return; }
    };
    let (seq, new_snap, stamped) = match stamp_append_snapshot(
        &mut tx, snap_ref.as_ref(), session_id, actor_id, event,
    ).await {
        Ok(r) => r,
        Err(e) => { tracing::error!(session_id, "stamp_append_snapshot: {e}"); return; }
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(session_id, "commit_event commit: {e}"); return;
    }
    store_and_broadcast(hub, seq, new_snap, &stamped).await;
}

/// Create an approval request record + emit `ApprovalRequested` event atomically.
///
/// Called from `POST /api/sessions/:id/approvals` (sidecar REST path).  The
/// combined atomic tx means the DB row and the broadcast event are always in
/// sync — if the commit fails, neither the record nor the event exist.
///
/// Returns `(approval_id, expires_at)` on success, `None` on any DB error.
pub(crate) async fn create_approval_for_session(
    state: &Arc<AppState>,
    session_id: &str,
    actor_id: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
    timeout_secs: u64,
) -> Option<(String, chrono::DateTime<Utc>)> {
    let approval_id = Ulid::new().to_string();
    let expires_at  = Utc::now() + chrono::Duration::seconds(timeout_secs as i64);

    let event = make_event(WsPayload::ApprovalRequested {
        session_id: session_id.to_string(),
        actor: actor_id.to_string(),
        timestamp: Utc::now(),
        seq: 0,
        payload: protocol::messages::ApprovalRequestedPayload {
            approval_id: approval_id.clone(),
            tool: tool_name.to_string(),
            summary: format!("{actor_id} wants to call {tool_name}"),
            requested_by: actor_id.to_string(),
            expires_at: Some(expires_at),
            arguments: arguments.clone(),
        },
    });

    // Hub may not exist if no human is currently attached — fall back to DB load.
    let hub_opt: Option<Arc<SessionHub>> = state.hubs.get(session_id).map(|e| e.value().clone());
    let snap_ref: Option<SessionSnapshot> = if let Some(ref hub) = hub_opt {
        current_snap(hub)
    } else {
        match load_snapshot_from_db(state, session_id).await {
            Ok((_, snap)) => Some(snap),
            Err(e) => {
                tracing::warn!(session_id, "create_approval_for_session: snapshot load: {e}");
                None
            }
        }
    };

    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(session_id, "create_approval_for_session: begin tx: {e}");
            return None;
        }
    };
    if let Err(e) = approvals::insert_in_tx(
        &mut tx, &approval_id, session_id, actor_id,
        tool_name, arguments, Some(expires_at),
    ).await {
        tracing::error!(session_id, "create_approval_for_session: insert_in_tx: {e}");
        return None;
    }
    let (seq, new_snap, stamped) = match stamp_append_snapshot(
        &mut tx, snap_ref.as_ref(), session_id, actor_id, event,
    ).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(session_id, "create_approval_for_session: stamp: {e}");
            return None;
        }
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(session_id, "create_approval_for_session: commit: {e}");
        return None;
    }

    if let Some(hub) = hub_opt {
        store_and_broadcast(&hub, seq, new_snap, &stamped).await;
    }

    // ── Session task: arm per-approval expiry timer ───────────────────────────
    // Done after hub commit so the task and hub are always in the same DB state.
    if let Some(task) = state.sessions.get(session_id).map(|e| e.value().clone()) {
        let expires_ms = Some(
            (expires_at - Utc::now()).num_milliseconds().max(0) as u64
        );
        task_approval_create(
            &task,
            approval_id.clone(),
            actor_id.to_string(),
            tool_name.to_string(),
            arguments.clone(),
            expires_ms,
        ).await;
    }

    Some((approval_id, expires_at))
}

/// REST-accessible vote wrapper.
///
/// Looks up (or creates) the session hub so the vote runs through the same
/// policy evaluation logic as the WebSocket path, with the same ArcSwap +
/// broadcast + pg_notify side-effects.
///
/// Called from `POST /api/approvals/:id/vote`.
pub(crate) async fn vote_on_approval(
    state: &Arc<AppState>,
    session_id: &str,
    actor_id: &str,
    approval_id: &str,
    vote: protocol::types::Vote,
) {
    // Use an existing hub if present; otherwise create a cold one so the
    // snapshot can still be loaded and updated.
    let hub = state.get_or_create_hub(session_id);

    // If the hub has no warm snapshot, prime it from the DB so policy reads work.
    if hub.snapshot.load_full().as_ref().is_none() {
        if let Ok((seq, snap)) = load_snapshot_from_db(state, session_id).await {
            hub.snapshot.store(Arc::new(Some(LiveSnapshot { seq, state: snap })));
        }
    }

    handle_vote(state, &hub, session_id, actor_id, approval_id, vote).await;
}

/// Emit a WS event from outside the WS connection loop (e.g. REST handlers).
///
/// Always persists the event + snapshot atomically to DB.  If an active hub
/// exists for the session, the ArcSwap is updated and the event is broadcast
/// to connected clients so the WS-first frontend sees it immediately.
pub(crate) async fn emit_to_session(
    state: &Arc<AppState>,
    session_id: &str,
    actor_id: &str,
    event: WsMessage,
) {
    // Clone hub Arc before any await so we don't hold a DashMap ref across awaits.
    let hub_opt: Option<Arc<SessionHub>> = state.hubs.get(session_id).map(|e| e.value().clone());

    // Snapshot: hot from ArcSwap if connected, cold from DB otherwise.
    let snap_ref: Option<SessionSnapshot> = if let Some(ref hub) = hub_opt {
        current_snap(hub)
    } else {
        match load_snapshot_from_db(state, session_id).await {
            Ok((_, snap)) => Some(snap),
            Err(e) => {
                tracing::warn!(session_id, "emit_to_session: load_snapshot fallback: {e}");
                None
            }
        }
    };

    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => { tracing::error!(session_id, "emit_to_session: begin tx: {e}"); return; }
    };
    let (seq, new_snap, stamped) = match stamp_append_snapshot(
        &mut tx, snap_ref.as_ref(), session_id, actor_id, event,
    ).await {
        Ok(r) => r,
        Err(e) => { tracing::error!(session_id, "emit_to_session: stamp: {e}"); return; }
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(session_id, "emit_to_session: commit: {e}"); return;
    }

    // Tier-1 wakeup: notify observers (best-effort).
    let _ = db::events::notify_session(&state.db, session_id, seq, state.reflector.replica_id()).await;

    if let Some(hub) = hub_opt {
        store_and_broadcast(&hub, seq, new_snap, &stamped).await;
    }
}

/// Within an open transaction:
///   1. Allocate seq (atomic counter increment — no holes)
///   2. Stamp the real seq into the event
///   3. INSERT event row
///   4. Apply event to current snapshot projection → UPSERT session_snapshots
///
/// Returns `(seq, new_snapshot)` for the caller to store into ArcSwap after commit.
/// The caller must still call `tx.commit()`.
///
/// `pub(crate)`: also called directly from `session_task.rs`'s cross-session
/// side-effect hooks, which already hold `db`/`hub` and don't have `state`
/// (see `emit_via_task`) — same durable pipeline `emit_to_session` uses, so
/// these events get real EventRows and cross-replica delivery picks them up.
pub(crate) async fn stamp_append_snapshot(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    current: Option<&SessionSnapshot>,
    session_id: &str,
    actor_id: &str,
    event: WsMessage,
) -> anyhow::Result<(i64, SessionSnapshot, WsMessage)> {
    let seq     = db::events::alloc_seq_block_in_tx(tx, session_id, 1).await?;
    let stamped = stamp_seq(&event, seq);
    let payload = serde_json::to_value(&stamped)?;

    db::events::append_in_tx(
        tx, session_id, actor_id, stamped.payload.type_name(), &payload, seq,
    ).await?;

    let new_snap = match current {
        Some(s) => apply_event(s, &stamped),
        None => {
            // Last-resort fallback — callers now warm the snapshot via
            // `warm_snap` before reaching here, so this only fires if that
            // DB load itself failed. Still worth a real `name`/`owner`
            // lookup rather than fabricating blanks: a blank snapshot
            // persisted here becomes the new canonical row and silently
            // blanks the session's displayed title until something else
            // happens to reload it from scratch.
            let row: Option<(String, String)> = sqlx::query_as(
                "SELECT name, approval_policy FROM sessions WHERE id = $1",
            )
            .bind(session_id)
            .fetch_optional(&mut **tx)
            .await
            .ok()
            .flatten();
            let (name, approval_policy) = row
                .unwrap_or_else(|| (String::new(), "single_vote".to_string()));
            SessionSnapshot {
                owner: actor_id.to_string(),
                owner_name: String::new(), // enriched in make_snapshot_msg
                name,
                approval_policy,
                status: SessionStatus::Active,
                members: vec![],
                pending_approvals: vec![],
                artifacts: vec![],
                context: vec![],
            }
        }
    };
    let snap_json = serde_json::to_value(&new_snap)?;
    db::snapshots::insert_in_tx(tx, session_id, seq, &snap_json).await?;

    // Return the stamped event so callers broadcast the version with the real seq,
    // not the original with seq=0 (which caused live messages to sort before history).
    Ok((seq, new_snap, stamped))
}

/// Read the current in-memory snapshot (if warm) before opening a transaction.
/// Calling this before `db.begin()` avoids any borrow conflict with the tx.
pub(crate) fn current_snap(hub: &Arc<SessionHub>) -> Option<SessionSnapshot> {
    hub.snapshot.load_full().as_ref().as_ref().map(|l| l.state.clone())
}

/// Snapshot for a write: warm from the hub's ArcSwap if present, else a cold
/// load from DB (and warm the hub with it) — never `None` for a session that
/// already has history.
///
/// Handlers inside the WS message loop used to call bare `current_snap(hub)`
/// on the assumption the hub is always warm by the time a message arrives.
/// It isn't guaranteed: `get_or_create_hub` registers a hub with an empty
/// ArcSwap immediately, and nothing blocks a write from reaching
/// `stamp_append_snapshot` before anything has populated it. When that raced,
/// `stamp_append_snapshot`'s `current: None` branch fabricated a blank
/// snapshot (name/owner_name/context all empty) and persisted it as the new
/// canonical row — silently wiping the session's displayed title and context
/// entries with no corresponding "removed" event, since nothing was actually
/// removed from the event log. This closes the gap the same way
/// `create_approval_for_session`/`emit_to_session` already did for their
/// REST-reachable callers.
pub(crate) async fn warm_snap(state: &Arc<AppState>, hub: &Arc<SessionHub>, session_id: &str) -> Option<SessionSnapshot> {
    if let Some(s) = current_snap(hub) {
        return Some(s);
    }
    match load_snapshot_from_db(state, session_id).await {
        Ok((seq, snap)) => {
            hub.snapshot.store(Arc::new(Some(LiveSnapshot { seq, state: snap.clone() })));
            Some(snap)
        }
        Err(e) => {
            tracing::warn!(session_id, "warm_snap: load fallback failed: {e}");
            None
        }
    }
}

/// Update ArcSwap and broadcast — called ONLY after a successful tx.commit()
/// (or, from `notifier.rs`, after replaying an already-committed event onto
/// a different replica's hub — same invariant, the durable write already
/// happened, this just needs to be reflected locally).
pub(crate) async fn store_and_broadcast(hub: &Arc<SessionHub>, seq: i64, new_snap: SessionSnapshot, event: &WsMessage) {
    hub.snapshot.store(Arc::new(Some(LiveSnapshot { seq, state: new_snap })));
    let Ok(json) = serde_json::to_string(event) else { return };
    match crate::event_visibility::min_role(&event.payload) {
        // Unrestricted — exactly today's behavior, zero added cost.
        None => hub.broadcast(Utf8Bytes::from(json)),
        // See `event_visibility` + `SessionHub::broadcast_gated` — a below-
        // bar connection gets `redacted` if there's a safe residual, else
        // nothing at all.
        Some(min_role) => {
            let redacted = crate::event_visibility::redact(event)
                .and_then(|m| serde_json::to_string(&m).ok())
                .map(Utf8Bytes::from);
            hub.broadcast_gated(min_role, Utf8Bytes::from(json), redacted).await;
        }
    }
}

/// Live-only presence update for an *already-known* member — patches the
/// hub's cached `attached`/`role` in place (same seq, no DB write) and
/// broadcasts a `PresenceChanged` message. Used for ordinary WS connect/
/// disconnect instead of `commit_event`, so a route change or a brief
/// network blip never allocates a seq or lands in the event log — see
/// `PresenceChanged`'s doc comment. Durable `session_connections` audit
/// rows are recorded separately by the caller regardless of this.
fn broadcast_presence(hub: &Arc<SessionHub>, session_id: &str, actor_id: &str, attached: bool, role: Option<MemberRole>) {
    let current = hub.snapshot.load_full();
    if let Some(live) = current.as_ref().as_ref() {
        let mut snap = live.state.clone();
        if let Some(m) = snap.members.iter_mut().find(|m| m.actor_id == actor_id) {
            m.attached = attached;
            if let Some(ref r) = role { m.role = r.clone(); }
        }
        hub.snapshot.store(Arc::new(Some(LiveSnapshot { seq: live.seq, state: snap })));
    }
    let msg = WsMessage::new(Ulid::new().to_string(), WsPayload::PresenceChanged {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), attached, role,
    });
    if let Ok(json) = serde_json::to_string(&msg) {
        hub.broadcast(Utf8Bytes::from(json));
    }
}

/// Live-only "which pane-tab is this actor looking at" signal (Part 4A).
/// Same posture as `broadcast_presence`: no snapshot mutation (there's no
/// per-actor-focus field in `SessionSnapshot`, and it doesn't need one --
/// this is transient UI state, not replayable), no durable write, just a
/// direct hub broadcast so every other connected client (including a
/// linked-session viewer via `session_links`'s auto-granted access to the
/// same hub) sees it live.
fn broadcast_presence_focus(hub: &Arc<SessionHub>, session_id: &str, actor_id: &str, tab: Option<String>) {
    let msg = WsMessage::new(Ulid::new().to_string(), WsPayload::PresenceFocus {
        session_id: session_id.to_string(), actor: actor_id.to_string(),
        timestamp: Utc::now(), tab,
    });
    if let Ok(json) = serde_json::to_string(&msg) {
        hub.broadcast(Utf8Bytes::from(json));
    }
}

// ── Cold-attach snapshot loader ───────────────────────────────────────────────

/// Load persisted snapshot from session_snapshots (one DB row).
/// Falls back to a 5-query table scan for brand-new sessions whose snapshot
/// row is the empty seed value, or if the row doesn't exist yet (defensive).
async fn load_snapshot_from_db(
    state: &Arc<AppState>,
    session_id: &str,
) -> anyhow::Result<(i64, SessionSnapshot)> {
    let row = db::snapshots::get_latest(&state.db, session_id).await;

    let snap_row = match row {
        Ok(r) => r,
        Err(db::DbError::NotFound) => {
            // Row missing — session was created before migration 010 or seeding
            // failed. Fall back to table scan; result will be seeded next event.
            tracing::warn!(session_id, "session_snapshots row missing — falling back to table scan");
            return build_snapshot_from_tables(state, session_id).await;
        }
        Err(e) => return Err(e.into()),
    };

    // Dirty flag: an epoch revocation invalidated this snapshot.
    // Rebuild from fact tables (lazy shadow page recompute) and persist a
    // new clean snapshot so the next cold-attach is free.
    if snap_row.dirty {
        tracing::info!(
            session_id,
            stale_since_seq = snap_row.stale_since_seq,
            "load_snapshot_from_db: dirty snapshot — lazy recompute from fact tables",
        );
        let (seq, snap) = build_snapshot_from_tables(state, session_id).await?;
        let snap_json = serde_json::to_value(&snap)?;
        // Persist the clean version so subsequent cold-attaches skip recompute.
        if let Err(e) = db::snapshots::insert_clean(&state.db, session_id, seq, &snap_json).await {
            // Non-fatal: the snapshot is already computed; just log and continue.
            tracing::warn!(session_id, "could not persist clean snapshot after recompute: {e}");
        }
        return Ok((seq, snap));
    }

    let is_empty = snap_row.state.as_object().map_or(false, |m| m.is_empty());
    if is_empty {
        return build_snapshot_from_tables(state, session_id).await;
    }

    let mut snap: SessionSnapshot = serde_json::from_value(snap_row.state)?;
    // Patch live attachment status from in-process hub state
    if let Some(h) = state.hubs.get(session_id) {
        for m in &mut snap.members {
            m.attached = h.actor_senders.contains_key(&m.actor_id);
        }
    }
    Ok((snap_row.seq, snap))
}

/// Full 5-query rebuild for sessions that have never committed an event.
///
/// Context entries have no fact table of their own (unlike approvals/
/// artifacts) — they only exist by folding `ContextEntryAdded`/
/// `ContextEntryResolved` out of the event log. A 6th query pulls the log
/// and `fold_context_from_events` replays just those two event kinds; this
/// used to be hardcoded to `vec![]` here, which silently dropped every
/// context entry (and persisted the empty result as the new canonical
/// snapshot) any time this fallback ran — e.g. after an epoch-dirty
/// recompute — even though the entries were never actually removed.
async fn build_snapshot_from_tables(
    state: &Arc<AppState>,
    session_id: &str,
) -> anyhow::Result<(i64, SessionSnapshot)> {
    let (session_res, memberships_res, pending_res, artifacts_res, events_res, seq_res) = tokio::join!(
        sessions::get(&state.db, session_id),
        sessions::list_memberships(&state.db, session_id),
        db::approvals::list_pending(&state.db, session_id),
        db::artifacts::list(&state.db, session_id),
        db::events::list(&state.db, session_id, None, i64::MAX),
        sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(next_seq - 1, 0) FROM session_sequences WHERE session_id = $1",
        )
        .bind(session_id)
        .fetch_optional(&state.db),
    );
    let session     = session_res?;
    let memberships = memberships_res?;
    let pending     = pending_res?;
    let context     = fold_context_from_events(&events_res?);
    let artifacts   = artifacts_res?;
    let seq: i64    = seq_res.ok().flatten().unwrap_or(0);

    let hub = state.hubs.get(session_id);
    let members: Vec<_> = memberships.iter().map(|m| {
        let role = match m.role.as_str() {
            "owner"        => MemberRole::Owner,
            "collaborator" => MemberRole::Collaborator,
            "agent"        => MemberRole::Agent,
            _              => MemberRole::Observer,
        };
        // Agents never hold a WS connection to `/stream` (only human
        // browsers do -- see `sweep_stale_agents`'s doc comment a bit
        // further down this file), so `actor_senders` can never reflect
        // their liveness. Checking it unconditionally for every role meant
        // a cold-rebuilt snapshot (session_snapshots row missing/dirty)
        // showed every agent as permanently unattached regardless of real
        // status -- the live incremental path (`apply_event` on a real
        // `ActorJoined`/heartbeat) was correct, only this from-scratch
        // rebuild path had the wrong signal. Mirrors the same
        // heartbeat-plus-staleness-threshold check `sweep_stale_agents`
        // itself uses to decide when an agent is actually gone.
        let attached = match role {
            MemberRole::Agent => hub.as_ref().map_or(false, |h| {
                h.agent_heartbeats.get(&m.actor_id)
                    .map_or(false, |t| t.elapsed() < Duration::from_secs(AGENT_STALE_THRESHOLD_SECS))
            }),
            _ => hub.as_ref().map_or(false, |h| h.actor_senders.contains_key(&m.actor_id)),
        };
        protocol::types::SessionMember {
            actor_id: m.actor_id.clone(),
            name: String::new(), // enriched in make_snapshot_msg
            role,
            attached, status: None,
        }
    }).collect();

    let pending_approvals: Vec<_> = pending.iter().map(|a| {
        let votes: HashMap<String, Vote> = serde_json::from_value(a.votes.clone()).unwrap_or_default();
        PendingApproval {
            approval_id: a.id.clone(), tool: a.tool_name.clone(),
            requested_by: a.actor_id.clone(),
            state: match a.state.as_str() {
                "Claimed"   => ApprovalState::Claimed,
                "Contested" => ApprovalState::Contested,
                _           => ApprovalState::Pending,
            },
            votes, claimed_by: None, expires_at: a.timeout_at,
            arguments: a.arguments.clone(),
        }
    }).collect();

    let artifact_summaries: Vec<_> = artifacts.iter().map(|a| ArtifactSummary {
        id: a.id.clone(), name: a.name.clone(), artifact_type: a.r#type.clone(),
    }).collect();

    let owner = memberships.iter()
        .find(|m| m.role == "owner")
        .map(|m| m.actor_id.clone())
        .unwrap_or_default();

    Ok((seq, SessionSnapshot {
        owner, owner_name: String::new(), // enriched in make_snapshot_msg
        name: session.name, approval_policy: session.approval_policy,
        status: match session.status.as_str() {
            "suspended" => SessionStatus::Suspended,
            "archived"  => SessionStatus::Archived,
            _           => SessionStatus::Active,
        },
        members, pending_approvals, artifacts: artifact_summaries, context,
    }))
}

/// Replay `ContextEntryAdded`/`ContextEntryResolved` out of raw event rows.
/// Mirrors `apply_event`'s own arms for those two payloads exactly, since
/// context entries have no fact table to query directly — this is the only
/// way to reconstruct them outside of a warm `hub.snapshot`.
fn fold_context_from_events(rows: &[db::events::EventRow]) -> Vec<ContextEntry> {
    let mut context: Vec<ContextEntry> = Vec::new();
    for row in rows {
        let msg: WsMessage = match serde_json::from_value(row.payload.clone()) {
            Ok(m) => m,
            Err(_) => continue, // not a WsMessage-shaped row (e.g. a session-crate SessionEvent) — skip
        };
        match msg.payload {
            WsPayload::ContextEntryAdded { actor, timestamp, seq, payload, .. } => {
                context.push(ContextEntry {
                    id: payload.entry_id.clone(),
                    kind: payload.kind.clone(),
                    content: payload.content.clone(),
                    actor_id: actor.clone(),
                    timestamp,
                    resolved: false,
                    resolved_by: None,
                    resolution_note: None,
                    seq,
                });
            }
            WsPayload::ContextEntryResolved { payload, .. } => {
                if let Some(e) = context.iter_mut().find(|e| e.id == payload.entry_id) {
                    e.resolved = true;
                    e.resolved_by = Some(payload.resolved_by.clone());
                    e.resolution_note = payload.note.clone();
                }
            }
            _ => {}
        }
    }
    context
}

// ── Snapshot projection (pure) ────────────────────────────────────────────────

pub(crate) fn apply_event(snap: &SessionSnapshot, msg: &WsMessage) -> SessionSnapshot {
    let mut s = snap.clone();
    match &msg.payload {
        WsPayload::ApprovalRequested { payload, .. } => {
            if !s.pending_approvals.iter().any(|a| a.approval_id == payload.approval_id) {
                s.pending_approvals.push(PendingApproval {
                    approval_id: payload.approval_id.clone(), tool: payload.tool.clone(),
                    requested_by: payload.requested_by.clone(), state: ApprovalState::Pending,
                    votes: HashMap::new(), claimed_by: None, expires_at: payload.expires_at,
                    arguments: payload.arguments.clone(),
                });
            }
        }
        WsPayload::ApprovalClaimed { actor, payload, .. } => {
            for a in &mut s.pending_approvals {
                if a.approval_id == payload.approval_id {
                    a.state = ApprovalState::Claimed;
                    a.claimed_by = Some(actor.clone());
                }
            }
        }
        WsPayload::ApprovalContested { payload, .. } => {
            for a in &mut s.pending_approvals {
                if a.approval_id == payload.approval_id {
                    a.state = ApprovalState::Contested;
                    a.votes = payload.votes.clone();
                }
            }
        }
        WsPayload::ApprovalGranted { payload, .. } => {
            s.pending_approvals.retain(|a| a.approval_id != payload.approval_id);
        }
        WsPayload::ApprovalDenied { payload, .. } => {
            s.pending_approvals.retain(|a| a.approval_id != payload.approval_id);
        }
        WsPayload::ApprovalTimedOut { payload, .. } => {
            s.pending_approvals.retain(|a| a.approval_id != payload.approval_id);
        }
        WsPayload::ApprovalCancelled { payload, .. } => {
            s.pending_approvals.retain(|a| a.approval_id != payload.approval_id);
        }
        WsPayload::OwnershipTransferred { payload, .. } => {
            s.owner = payload.to.clone();
            for m in &mut s.members {
                if m.actor_id == payload.from      { m.role = MemberRole::Collaborator; }
                else if m.actor_id == payload.to   { m.role = MemberRole::Owner; }
            }
        }
        WsPayload::ActorJoined { actor, role, name, .. } => {
            let effective_role = role.clone().unwrap_or(MemberRole::Collaborator);
            // db::sessions::add_member demotes whoever currently holds owner
            // at the DB level the moment this role is granted (see its own
            // doc comment) — but that's a fact about session_memberships,
            // not this cached snapshot. make_snapshot_msg re-resolves
            // owner_name on every connect, but never re-derives *which*
            // actor_id is `owner` — so without mirroring the demotion here,
            // an already-connected session would just never find out who
            // the real owner is until something forces a cold rebuild.
            if effective_role == MemberRole::Owner {
                for m in s.members.iter_mut() {
                    if m.role == MemberRole::Owner && m.actor_id != *actor {
                        m.role = MemberRole::Collaborator;
                    }
                }
                s.owner = actor.clone();
                if let Some(n) = name { if !n.is_empty() { s.owner_name = n.clone(); } }
            }
            if let Some(m) = s.members.iter_mut().find(|m| m.actor_id == *actor) {
                m.attached = true;
                m.role = effective_role;
                // A resolved name arriving on a re-join is real data, worth
                // taking; never downgrade an already-known name back to blank.
                if let Some(n) = name { if !n.is_empty() { m.name = n.clone(); } }
            } else {
                s.members.push(protocol::types::SessionMember {
                    actor_id: actor.clone(),
                    name: name.clone().unwrap_or_else(|| actor.clone()),
                    role: effective_role,
                    attached: true, status: None,
                });
            }
        }
        WsPayload::ActorDetached { actor, .. } => {
            if let Some(m) = s.members.iter_mut().find(|m| m.actor_id == *actor) {
                m.attached = false;
            }
        }
        WsPayload::ArtifactCreated { payload, .. } => {
            if !s.artifacts.iter().any(|a| a.id == payload.artifact_id) {
                s.artifacts.push(ArtifactSummary {
                    id: payload.artifact_id.clone(), name: payload.name.clone(),
                    artifact_type: payload.artifact_type.clone().unwrap_or_else(|| "other".to_string()),
                });
            }
        }
        WsPayload::ArtifactUpdated { payload, .. } => {
            if let Some(a) = s.artifacts.iter_mut().find(|a| a.id == payload.artifact_id) {
                a.name = payload.name.clone();
            }
        }
        WsPayload::ArtifactDeleted { payload, .. } => {
            s.artifacts.retain(|a| a.id != payload.artifact_id);
        }
        WsPayload::AgentStatusChanged { actor, payload, .. } => {
            if let Some(m) = s.members.iter_mut().find(|m| m.actor_id == *actor) {
                m.status = Some(payload.status.clone());
            }
        }
        WsPayload::SessionStatusChanged { payload, .. } => {
            s.status = match payload.status.as_str() {
                "suspended" => SessionStatus::Suspended,
                "archived"  => SessionStatus::Archived,
                _           => SessionStatus::Active,
            };
        }
        WsPayload::ContextEntryAdded { actor, timestamp, seq, payload, .. } => {
            s.context.push(ContextEntry {
                id: payload.entry_id.clone(),
                kind: payload.kind.clone(),
                content: payload.content.clone(),
                actor_id: actor.clone(),
                timestamp: *timestamp,
                resolved: false,
                resolved_by: None,
                resolution_note: None,
                seq: *seq,
            });
        }
        WsPayload::ContextEntryResolved { payload, .. } => {
            if let Some(e) = s.context.iter_mut().find(|e| e.id == payload.entry_id) {
                e.resolved = true;
                e.resolved_by = Some(payload.resolved_by.clone());
                e.resolution_note = payload.note.clone();
            }
        }
        _ => {} // MessagePosted, tool calls, delegation, dispute — EventLog only
    }
    s
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_event(payload: WsPayload) -> WsMessage {
    WsMessage::new(Ulid::new().to_string(), payload)
}

fn stamp_seq(msg: &WsMessage, seq: i64) -> WsMessage {
    let mut m = msg.clone();
    match &mut m.payload {
        WsPayload::ToolCallRequested    { seq: s, .. } |
        WsPayload::ToolCallExecuted     { seq: s, .. } |
        WsPayload::ToolCallBlocked      { seq: s, .. } |
        WsPayload::ApprovalRequested    { seq: s, .. } |
        WsPayload::ApprovalGranted      { seq: s, .. } |
        WsPayload::ApprovalContested    { seq: s, .. } |
        WsPayload::ApprovalClaimed      { seq: s, .. } |
        WsPayload::ApprovalCancelled    { seq: s, .. } |
        WsPayload::ApprovalDelegated    { seq: s, .. } |
        WsPayload::ApprovalDisputed     { seq: s, .. } |
        WsPayload::ApprovalTimedOut     { seq: s, .. } |
        WsPayload::ActorJoined          { seq: s, .. } |
        WsPayload::ActorDetached        { seq: s, .. } |
        WsPayload::OwnershipTransferred { seq: s, .. } |
        WsPayload::ArtifactCreated      { seq: s, .. } |
        WsPayload::ArtifactUpdated      { seq: s, .. } |
        WsPayload::ArtifactDeleted      { seq: s, .. } |
        WsPayload::AgentStatusChanged   { seq: s, .. } |
        WsPayload::SessionStatusChanged { seq: s, .. } |
        WsPayload::MessagePosted        { seq: s, .. } |
        WsPayload::ContextEntryAdded      { seq: s, .. } |
        WsPayload::ContextEntryResolved   { seq: s, .. } |
        WsPayload::ShellCommandStarted    { seq: s, .. } |
        WsPayload::ShellCommandCompleted  { seq: s, .. } |
        WsPayload::EffectRateLimited      { seq: s, .. } => *s = seq,
        // ApprovalDenied has a different payload type than the others; handle separately
        _ => {}
    }
    // ApprovalDenied doesn't participate in the `|` chain above due to payload type
    if let WsPayload::ApprovalDenied { seq: s, .. } = &mut m.payload { *s = seq; }
    m
}

/// The single point where a `SessionSnapshot` gets real display names before
/// hitting the wire — both the pure `session` crate's live rebuild and this
/// module's cold DB rebuild produce snapshots with empty `name`/`owner_name`
/// (neither has actor-lookup access), so every snapshot funnels through
/// here on its way to a client regardless of which path produced it.
async fn make_snapshot_msg(db: &sqlx::PgPool, session_id: &str, seq: i64, snap: &SessionSnapshot) -> WsMessage {
    let mut enriched = snap.clone();

    let mut ids: Vec<String> = enriched.members.iter().map(|m| m.actor_id.clone()).collect();
    ids.push(enriched.owner.clone());
    ids.sort();
    ids.dedup();

    let names = db::actors::get_many(db, &ids).await.unwrap_or_default();

    enriched.owner_name = names.get(&enriched.owner)
        .map(|a| a.name.clone())
        .unwrap_or_else(|| enriched.owner.clone());
    for m in &mut enriched.members {
        m.name = names.get(&m.actor_id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| m.actor_id.clone());
    }

    WsMessage::new(
        Ulid::new().to_string(),
        WsPayload::SessionSnapshot { session_id: session_id.to_string(), seq, state: enriched },
    )
}

fn can_vote(role: &str) -> bool { role == "owner" || role == "collaborator" }

async fn send_resolved(
    hub: &Arc<SessionHub>,
    sidecar_actor_id: &str,
    approval_id: &str,
    decision: ApprovalDecision,
    resolved_by: Option<&str>,
) {
    let msg = make_event(WsPayload::ApprovalResolved {
        approval_id: approval_id.to_string(),
        decision,
        resolved_by: resolved_by.map(str::to_string),
        resolved_at: Utc::now(),
        escalated_to: None,
    });
    if let Ok(json) = serde_json::to_string(&msg) {
        hub.send_to(sidecar_actor_id, Utf8Bytes::from(json));
    }
}

// ── Approval timeout sweeper ──────────────────────────────────────────────────

pub async fn sweep_expired_approvals(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        match db::approvals::expire_timed_out(&state.db).await {
            Ok(expired_ids) => {
                for approval_id in expired_ids {
                    // pg_notify fires regardless of whether a hub is active — the
                    // sidecar long-polls directly against the DB channel and doesn't
                    // need a connected human browser.
                    let notify_json = serde_json::json!({
                        "approval_id": &approval_id,
                        "decision": "timed_out",
                    }).to_string();
                    if let Err(e) = sqlx::query("SELECT pg_notify('approval_resolved', $1)")
                        .bind(&notify_json)
                        .execute(&state.db)
                        .await
                    {
                        tracing::warn!(approval_id, "sweeper pg_notify approval_resolved: {e}");
                    }

                    if let Ok(approval) = db::approvals::get(&state.db, &approval_id).await {
                        if let Some(hub) = state.hubs.get(&approval.session_id) {
                            send_resolved(
                                &hub, &approval.actor_id, &approval_id,
                                ApprovalDecision::TimedOut, None,
                            ).await;
                            // Use the requesting actor, not "system" — events.actor_id has a
                            // FK → actors(id) and "system" is not seeded in that table.
                            let event_actor = approval.actor_id.clone();
                            let event = make_event(WsPayload::ApprovalTimedOut {
                                session_id: approval.session_id.clone(),
                                actor: event_actor.clone(),
                                timestamp: Utc::now(), seq: 0,
                                payload: ApprovalEventPayload { approval_id: approval_id.clone() },
                            });
                            commit_event(&state, &hub, &approval.session_id, &event_actor, event).await;
                        }
                    }
                }
            }
            Err(e) => tracing::error!("approval sweeper: {e}"),
        }
    }
}

// ── Scheduled ownership-transfer sweeper ─────────────────────────────────────

/// JSON shape stored in `artifacts.storage_ref` for `type = 'scheduled_transfer'`.
#[derive(serde::Deserialize)]
struct ScheduledTransferData {
    to: String,
    // `scheduled_at` and `note` are stored but only needed for logging / filtering.
    #[allow(dead_code)]
    scheduled_at: Option<String>,
    #[allow(dead_code)]
    note: Option<String>,
}

/// Background loop: every 30 s find any `scheduled_transfer` artifacts whose
/// `scheduled_at` has elapsed, execute the ownership handoff, delete the
/// artifact, and emit the corresponding WS events.
pub async fn sweep_scheduled_transfers(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    loop {
        interval.tick().await;
        match artifacts::list_overdue_scheduled_transfers(&state.db).await {
            Ok(overdue) => {
                for artifact in overdue {
                    fire_scheduled_transfer(&state, artifact).await;
                }
            }
            Err(e) => tracing::error!("scheduled_transfer sweeper: list: {e}"),
        }
    }
}

async fn fire_scheduled_transfer(state: &Arc<AppState>, artifact: db::artifacts::ArtifactRow) {
    let data: ScheduledTransferData = match serde_json::from_str(&artifact.storage_ref) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(artifact_id = %artifact.id, "fire_scheduled_transfer: parse JSON: {e}");
            return;
        }
    };

    // Find the current owner (the `from` side of the transfer).
    let memberships = match sessions::list_memberships(&state.db, &artifact.session_id).await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(session_id = %artifact.session_id, "fire_scheduled_transfer: list_memberships: {e}");
            return;
        }
    };
    let from = match memberships.iter().find(|m| m.role == "owner") {
        Some(m) => m.actor_id.clone(),
        None => {
            tracing::warn!(session_id = %artifact.session_id, "fire_scheduled_transfer: no owner — deleting stale artifact");
            let _ = db::artifacts::delete(&state.db, &artifact.id).await;
            return;
        }
    };

    // Already transferred (manual transfer raced the sweeper).
    if from == data.to {
        tracing::info!(session_id = %artifact.session_id, "fire_scheduled_transfer: already owner, cleaning up");
        let _ = db::artifacts::delete(&state.db, &artifact.id).await;
        return;
    }

    // Capture snapshot BEFORE opening the tx (same pattern as handle_ownership_transfer).
    let hub_opt: Option<Arc<SessionHub>> = state.hubs.get(&artifact.session_id).map(|e| e.value().clone());
    let snap_ref: Option<SessionSnapshot> = if let Some(ref hub) = hub_opt {
        current_snap(hub)
    } else {
        match load_snapshot_from_db(state, &artifact.session_id).await {
            Ok((_, snap)) => Some(snap),
            Err(e) => { tracing::warn!(session_id = %artifact.session_id, "fire_scheduled_transfer: snapshot load: {e}"); None }
        }
    };

    let event = make_event(WsPayload::OwnershipTransferred {
        session_id: artifact.session_id.clone(),
        actor: from.clone(),
        timestamp: Utc::now(),
        seq: 0,
        payload: protocol::messages::OwnershipTransferredPayload {
            from: from.clone(),
            to: data.to.clone(),
        },
    });

    // One atomic tx: membership update + event + snapshot + artifact delete.
    // Mirrors handle_ownership_transfer exactly so the same code path is exercised.
    let mut tx = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => { tracing::error!("fire_scheduled_transfer: begin tx: {e}"); return; }
    };

    if let Err(e) = sessions::transfer_ownership_in_tx(&mut tx, &artifact.session_id, &from, &data.to).await {
        tracing::error!(session_id = %artifact.session_id, "fire_scheduled_transfer: transfer_ownership_in_tx: {e}");
        return;
    }

    let (seq, new_snap, stamped) = match stamp_append_snapshot(
        &mut tx, snap_ref.as_ref(), &artifact.session_id, &from, event,
    ).await {
        Ok(r) => r,
        Err(e) => { tracing::error!(session_id = %artifact.session_id, "fire_scheduled_transfer: stamp_append_snapshot: {e}"); return; }
    };

    if let Err(e) = sqlx::query("DELETE FROM artifacts WHERE id = $1")
        .bind(&artifact.id)
        .execute(&mut *tx)
        .await
    {
        tracing::error!(artifact_id = %artifact.id, "fire_scheduled_transfer: delete artifact: {e}");
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("fire_scheduled_transfer: commit: {e}");
        return;
    }

    // Post-commit: update ArcSwap and broadcast to all connected clients.
    if let Some(hub) = hub_opt {
        store_and_broadcast(&hub, seq, new_snap, &stamped).await;
    }

    tracing::info!(
        session_id = %artifact.session_id,
        from = %from,
        to = %data.to,
        "fire_scheduled_transfer: ownership transferred",
    );
}

// ── Stale agent sweeper ───────────────────────────────────────────────────────

/// Expected interval between shim heartbeats — see `agent_heartbeat` in
/// routes/sessions.rs. Kept here so the stale threshold is a clear multiple.
const AGENT_HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// Missed-heartbeat threshold before an agent is declared detached.
/// 3x the expected interval tolerates a couple of transient misses without
/// flapping an agent's status on every brief network hiccup.
///
/// `pub(crate)`: also the liveness threshold `routes/agents.rs::list_agents`
/// reads directly off `hub.agent_heartbeats` for the cross-session Agents
/// directory — same signal this module's own sweep uses, not a second one.
pub(crate) const AGENT_STALE_THRESHOLD_SECS: u64 = AGENT_HEARTBEAT_INTERVAL_SECS * 3;

/// Background loop: agents attached via shim never hold a WS connection to
/// `/stream` (only human browsers do), so `actor_senders` never sees them —
/// there was previously no liveness signal for them at all beyond the
/// one-shot `agent-attach` announcement fired once at shim startup. A shim
/// that crashes (missing guardian binary, killed process, etc.) after that
/// announcement left the actor permanently "active" in the session with no
/// way to ever become detached.
///
/// This periodically checks every hub's `agent_heartbeats` and emits
/// `ActorDetached` for any actor whose heartbeat has lapsed past the
/// threshold, mirroring `sweep_expired_approvals` above.
pub async fn sweep_stale_agents(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(AGENT_HEARTBEAT_INTERVAL_SECS));
    let threshold = Duration::from_secs(AGENT_STALE_THRESHOLD_SECS);
    loop {
        interval.tick().await;

        // Snapshot (session_id, hub) pairs first — avoid holding a DashMap
        // iterator guard across the `.await` calls in the loop below.
        let hubs: Vec<(String, Arc<SessionHub>)> = state.hubs
            .iter()
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        for (session_id, hub) in hubs {
            let stale: Vec<String> = hub.agent_heartbeats
                .iter()
                .filter(|e| e.value().elapsed() > threshold)
                .map(|e| e.key().clone())
                .collect();

            for actor_id in stale {
                hub.agent_heartbeats.remove(&actor_id);
                tracing::info!(
                    session_id, actor_id,
                    "sweep_stale_agents: no heartbeat within threshold — marking detached",
                );
                broadcast_presence(&hub, &session_id, &actor_id, false, None);
                let _ = db::session_connections::record(&state.db, &session_id, &actor_id, "disconnected").await;
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn base_snap() -> SessionSnapshot {
        SessionSnapshot {
            owner: "alice".to_string(), owner_name: "Alice".to_string(), name: "Test".to_string(),
            approval_policy: "single_vote".to_string(), status: SessionStatus::Active,
            members: vec![
                protocol::types::SessionMember {
                    actor_id: "alice".to_string(), name: "Alice".to_string(), role: MemberRole::Owner,
                    attached: true, status: None,
                },
                protocol::types::SessionMember {
                    actor_id: "bob".to_string(), name: "Bob".to_string(), role: MemberRole::Collaborator,
                    attached: false, status: None,
                },
            ],
            pending_approvals: vec![], artifacts: vec![], context: vec![],
        }
    }

    fn ev(payload: WsPayload) -> WsMessage { WsMessage::new("t".to_string(), payload) }

    fn extract_seq(m: &WsMessage) -> Option<i64> {
        match &m.payload {
            WsPayload::ActorJoined          { seq, .. } |
            WsPayload::ActorDetached        { seq, .. } |
            WsPayload::OwnershipTransferred { seq, .. } |
            WsPayload::MessagePosted        { seq, .. } => Some(*seq),
            _ => None,
        }
    }

    fn pending(id: &str) -> PendingApproval {
        PendingApproval {
            approval_id: id.to_string(), tool: "bash".to_string(),
            requested_by: "agent".to_string(), state: ApprovalState::Pending,
            votes: HashMap::new(), claimed_by: None, expires_at: None,
            arguments: serde_json::Value::Null,
        }
    }

    #[test]
    fn approval_requested_adds_and_is_idempotent() {
        let snap = base_snap();
        let event = ev(WsPayload::ApprovalRequested {
            session_id: "s".into(), actor: "a".into(), timestamp: Utc::now(), seq: 1,
            payload: protocol::messages::ApprovalRequestedPayload {
                approval_id: "x".into(), tool: "bash".into(),
                summary: "".into(), requested_by: "a".into(), expires_at: None,
                arguments: serde_json::Value::Null,
            },
        });
        let once  = apply_event(&snap, &event);
        let twice = apply_event(&once, &event);
        assert_eq!(once.pending_approvals.len(), 1);
        assert_eq!(twice.pending_approvals.len(), 1, "idempotent");
    }

    #[test]
    fn approval_claimed_is_cas() {
        let mut snap = base_snap();
        snap.pending_approvals.push(pending("x"));
        let event = ev(WsPayload::ApprovalClaimed {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 2,
            payload: ApprovalEventPayload { approval_id: "x".into() },
        });
        let next = apply_event(&snap, &event);
        assert_eq!(next.pending_approvals[0].state, ApprovalState::Claimed);
        assert_eq!(next.pending_approvals[0].claimed_by.as_deref(), Some("alice"));
    }

    #[test]
    fn approval_granted_removes() {
        let mut snap = base_snap();
        snap.pending_approvals.push(pending("x"));
        let next = apply_event(&snap, &ev(WsPayload::ApprovalGranted {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 3,
            payload: ApprovalEventPayload { approval_id: "x".into() },
        }));
        assert!(next.pending_approvals.is_empty());
    }

    #[test]
    fn approval_denied_removes() {
        let mut snap = base_snap();
        snap.pending_approvals.push(pending("x"));
        let next = apply_event(&snap, &ev(WsPayload::ApprovalDenied {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 3,
            payload: protocol::messages::ApprovalDeniedPayload {
                approval_id: "x".into(), reason: None,
            },
        }));
        assert!(next.pending_approvals.is_empty());
    }

    #[test]
    fn ownership_transfer() {
        let snap = base_snap();
        let next = apply_event(&snap, &ev(WsPayload::OwnershipTransferred {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 4,
            payload: protocol::messages::OwnershipTransferredPayload {
                from: "alice".into(), to: "bob".into(),
            },
        }));
        assert_eq!(next.owner, "bob");
        assert_eq!(next.members.iter().find(|m| m.actor_id == "alice").unwrap().role, MemberRole::Collaborator);
        assert_eq!(next.members.iter().find(|m| m.actor_id == "bob").unwrap().role,   MemberRole::Owner);
    }

    #[test]
    fn actor_joined_sets_attached_and_adds_new() {
        let snap = base_snap();
        let bob_joined = apply_event(&snap, &ev(WsPayload::ActorJoined {
            session_id: "s".into(), actor: "bob".into(), timestamp: Utc::now(), seq: 5, role: None, name: None,
        }));
        assert!(bob_joined.members.iter().find(|m| m.actor_id == "bob").unwrap().attached);

        let carol_joined = apply_event(&snap, &ev(WsPayload::ActorJoined {
            session_id: "s".into(), actor: "carol".into(), timestamp: Utc::now(), seq: 5, role: None, name: None,
        }));
        let carol = carol_joined.members.iter().find(|m| m.actor_id == "carol").unwrap();
        assert_eq!(carol.role, MemberRole::Collaborator);
        assert!(carol.attached);
    }

    #[test]
    fn actor_detached_clears_attached() {
        let snap = base_snap();
        let next = apply_event(&snap, &ev(WsPayload::ActorDetached {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 6,
        }));
        assert!(!next.members.iter().find(|m| m.actor_id == "alice").unwrap().attached);
    }

    #[test]
    fn artifact_lifecycle() {
        let snap = base_snap();
        let created = apply_event(&snap, &ev(WsPayload::ArtifactCreated {
            session_id: "s".into(), actor: "a".into(), timestamp: Utc::now(), seq: 7,
            payload: protocol::messages::ArtifactPayload {
                artifact_id: "z".into(), name: "report.md".into(),
                artifact_type: Some("document".into()),
            },
        }));
        assert_eq!(created.artifacts.len(), 1);
        // idempotent
        let again = apply_event(&created, &ev(WsPayload::ArtifactCreated {
            session_id: "s".into(), actor: "a".into(), timestamp: Utc::now(), seq: 7,
            payload: protocol::messages::ArtifactPayload {
                artifact_id: "z".into(), name: "report.md".into(),
                artifact_type: Some("document".into()),
            },
        }));
        assert_eq!(again.artifacts.len(), 1);
        // delete
        let deleted = apply_event(&again, &ev(WsPayload::ArtifactDeleted {
            session_id: "s".into(), actor: "a".into(), timestamp: Utc::now(), seq: 8,
            payload: protocol::messages::ArtifactPayload {
                artifact_id: "z".into(), name: "report.md".into(), artifact_type: None,
            },
        }));
        assert!(deleted.artifacts.is_empty());
    }

    #[test]
    fn message_posted_is_noop() {
        let snap = base_snap();
        let next = apply_event(&snap, &ev(WsPayload::MessagePosted {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 9,
            payload: protocol::messages::MessagePostedPayload { content: "hi".into() },
        }));
        assert_eq!(next.owner, snap.owner);
        assert_eq!(next.members.len(), snap.members.len());
    }

    #[test]
    fn stamp_seq_roundtrip() {
        let m = ev(WsPayload::ActorJoined {
            session_id: "s".into(), actor: "alice".into(), timestamp: Utc::now(), seq: 0, role: None, name: None,
        });
        let stamped = stamp_seq(&m, 99);
        assert_eq!(extract_seq(&stamped), Some(99));
    }
}
