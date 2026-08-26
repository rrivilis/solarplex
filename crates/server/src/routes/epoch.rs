//! Epoch-based capability revocation endpoint.
//!
//! `POST /api/sessions/:id/epoch/revoke` — revoke caps by strategy, advance
//! the session epoch, mark the snapshot dirty, broadcast `EpochAdvanced`, and
//! schedule drain-bounded fencing for the affected actors.
//!
//! ## Revocation strategies
//!
//! | strategy  | target field      | effect                                         |
//! |-----------|-------------------|------------------------------------------------|
//! | `cap`     | `target_cap_id`   | revoke that cap and its entire subtree          |
//! | `stratum` | `target_stratum`  | revoke all caps at depth >= threshold in epoch  |
//! | `epoch`   | (none)            | close the entire current generation             |
//!
//! ## Drain-bounded liveness
//!
//! `drain_window_secs` (default 30) gives in-flight agents a grace period.
//! After the window closes, fenced actors that send a write receive WS close
//! 4401.  The session hub's `fenced_actors` DashMap drives this lazily.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{ws::Utf8Bytes, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::state::AppState;
use crate::ws::emit_to_session;
use autometrics::autometrics;
use protocol::messages::{EpochAdvancedPayload, WsMessage, WsPayload};
use protocol::types::MemberRole;

// ── GET /api/sessions/:id/epoch ───────────────────────────────────────────────

/// Return the current epoch and recent revocation history for a session.
#[autometrics]
pub async fn get_epoch(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(res) =
        crate::auth::require_session_member(&state.db, &headers, &session_id, MemberRole::Observer)
            .await
    {
        return res;
    }
    let epoch = match db::epochs::current(&state.db, &session_id).await {
        Ok(e) => e,
        Err(db::DbError::NotFound) => 0,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let revocations = match db::epochs::list_recent(&state.db, &session_id).await {
        Ok(r) => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    Json(serde_json::json!({
        "session_id":  session_id,
        "epoch":       epoch,
        "revocations": revocations,
    }))
    .into_response()
}

// ── Request / response types ──────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RevokeBody {
    /// Actor triggering the revocation (must be a session owner/collaborator).
    pub revoked_by: String,
    /// Revocation strategy: `"cap"` | `"stratum"` | `"epoch"`.
    pub strategy: String,
    /// For `strategy = "cap"`: ULID of the cap to revoke (subtree is pruned).
    pub target_cap_id: Option<String>,
    /// For `strategy = "stratum"`: depth threshold; caps with stratum >= this
    /// value in the current epoch are revoked.
    pub target_stratum: Option<i64>,
    /// Seconds of grace window for in-flight agents (default 30).
    #[serde(default = "default_drain_window")]
    pub drain_window_secs: u64,
    /// When `true` and `strategy = "cap"`, surviving children of the revoked
    /// cap are rerooted to point at the revoked cap's parent.
    #[serde(default)]
    pub reroot: bool,
}

fn default_drain_window() -> u64 {
    30
}

#[derive(Serialize)]
pub struct RevokeResponse {
    pub new_epoch: i64,
    pub closed_epoch: i64,
    pub revoked_count: u64,
    pub drain_seq: i64,
    pub drain_deadline: String, // ISO-8601
}

// ── Handler ───────────────────────────────────────────────────────────────────

#[autometrics]
pub async fn revoke(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    Json(body): Json<RevokeBody>,
) -> impl IntoResponse {
    // Epoch revocation fences every connected agent in the session — the
    // RevokeBody doc comment already said this "must be a session
    // owner/collaborator"; this is the first place that's actually enforced.
    if let Err(e) = db::sessions::require_membership(
        &state.db,
        &session_id,
        &body.revoked_by,
        protocol::types::MemberRole::Collaborator,
    )
    .await
    {
        return match e {
            db::DbError::NotFound => {
                (StatusCode::FORBIDDEN, "not a member of this session").into_response()
            }
            db::DbError::Unauthorized => (
                StatusCode::FORBIDDEN,
                "epoch revocation requires collaborator or owner role",
            )
                .into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    // ── Validate strategy ──────────────────────────────────────────────────────
    match body.strategy.as_str() {
        "cap" => {
            if body.target_cap_id.is_none() {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "strategy 'cap' requires target_cap_id",
                )
                    .into_response();
            }
        }
        "stratum" => {
            if body.target_stratum.is_none() {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "strategy 'stratum' requires target_stratum",
                )
                    .into_response();
            }
        }
        "epoch" => {}
        s => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                format!("unknown strategy '{s}'; expected cap | stratum | epoch"),
            )
                .into_response();
        }
    }

    // ── Current epoch + drain_seq ─────────────────────────────────────────────
    let closed_epoch = match db::epochs::current(&state.db, &session_id).await {
        Ok(e) => e,
        Err(db::DbError::NotFound) => {
            // Session exists but has no epoch row (pre-011 session) — seed and use 0.
            let _ = db::epochs::seed(&state.db, &session_id).await;
            0
        }
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let drain_seq = match db::events::current_seq(&state.db, &session_id).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let drain_deadline_utc = Utc::now() + chrono::Duration::seconds(body.drain_window_secs as i64);
    let drain_deadline_instant = Instant::now() + Duration::from_secs(body.drain_window_secs);

    // ── Revoke caps ───────────────────────────────────────────────────────────
    let revoked_ids: Vec<String> = match body.strategy.as_str() {
        "cap" => {
            let cap_id = body.target_cap_id.as_deref().unwrap();
            if body.reroot {
                // Find the revoked cap's parent BEFORE revoking so surviving
                // children can be rerooted to the grandparent.  Direct children
                // are rerooted first; deeper descendants follow their own parent
                // pointers and naturally land on the new root.
                let grandparent_id = db::tokens::get_parent_id(&state.db, cap_id)
                    .await
                    .unwrap_or(None);
                if let Err(e) = db::tokens::reroot_caps(
                    &state.db,
                    &session_id,
                    cap_id,
                    grandparent_id.as_deref(),
                )
                .await
                {
                    tracing::warn!(session_id, "reroot_caps failed: {e}");
                }
            }
            match db::tokens::revoke_cap_subtree(&state.db, cap_id).await {
                Ok(ids) => ids,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            }
        }
        "stratum" => {
            let threshold = body.target_stratum.unwrap();
            match db::tokens::revoke_by_stratum(&state.db, &session_id, closed_epoch, threshold)
                .await
            {
                Ok(ids) => ids,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
                }
            }
        }
        "epoch" => match db::tokens::revoke_epoch(&state.db, &session_id, closed_epoch).await {
            Ok(ids) => ids,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        _ => unreachable!(),
    };
    // Primary descriptor cleanup — resolve()'s live-cap join is defense in
    // depth, this is what actually keeps the table from accumulating dead
    // rows under normal revocation traffic.
    if let Err(e) = db::descriptors::delete_for_caps(&state.db, &revoked_ids).await {
        tracing::warn!(
            session_id,
            "descriptor cleanup after revocation failed: {e}"
        );
    }
    let revoked_count = revoked_ids.len() as u64;

    // ── Advance epoch ─────────────────────────────────────────────────────────
    let new_epoch = match db::epochs::advance(&state.db, &session_id).await {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // ── Audit log ─────────────────────────────────────────────────────────────
    let revocation_id = Ulid::new().to_string();
    if let Err(e) = db::epochs::record_revocation(
        &state.db,
        &revocation_id,
        &session_id,
        &body.strategy,
        body.target_cap_id.as_deref(),
        body.target_stratum,
        drain_seq,
        drain_deadline_utc,
        closed_epoch,
        new_epoch,
        &body.revoked_by,
    )
    .await
    {
        tracing::warn!(session_id, "record_revocation audit log failed: {e}");
        // Non-fatal: revocation has already happened; continue.
    }

    // ── Mark snapshot dirty (write-behind / lazy shadow page) ─────────────────
    // Insert a dirty sentinel row so cold-attach detects the revocation boundary
    // and rebuilds the snapshot from fact tables rather than trusting stale state.
    let current_snap_state = if let Some(hub) = state.hubs.get(&session_id) {
        hub.snapshot
            .load_full()
            .as_ref()
            .as_ref()
            .map(|ls| serde_json::to_value(&ls.state).unwrap_or_default())
            .unwrap_or_default()
    } else {
        serde_json::json!({})
    };
    if let Err(e) =
        db::snapshots::mark_dirty(&state.db, &session_id, &current_snap_state, drain_seq).await
    {
        tracing::warn!(session_id, "mark_dirty snapshot failed: {e}");
    }
    // Invalidate the ArcSwap so the next hot-path read rebuilds from DB.
    if let Some(hub) = state.hubs.get(&session_id) {
        hub.snapshot.store(Arc::new(None));
    }

    // ── Fence affected actors in the hub ──────────────────────────────────────
    // Collect actor_ids whose caps were in the closed epoch (all strategies).
    // These actors enter the drain window; after deadline their writes are
    // rejected with WS close 4401 by the fencing check in handle_ws.
    if let Some(hub) = state.hubs.get(&session_id) {
        match db::tokens::actors_in_revoked_epoch(&state.db, &session_id, closed_epoch).await {
            Ok(actor_ids) => {
                hub.fence_actors(actor_ids, drain_deadline_instant);
            }
            Err(e) => {
                tracing::warn!(session_id, "actors_in_revoked_epoch query failed: {e}");
            }
        }

        // Schedule background close for fenced actors after drain window expires.
        // This closes connections that haven't self-terminated by then.
        let hub_arc = hub.clone();
        let session_id_owned = session_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(body.drain_window_secs)).await;
            // After deadline: close all fenced actors that are still connected.
            let to_close: Vec<String> = hub_arc
                .fenced_actors
                .iter()
                .filter(|entry| Instant::now() > *entry.value())
                .map(|entry| entry.key().clone())
                .collect();
            for actor_id in to_close {
                if let Some(tx) = hub_arc.actor_senders.get(&actor_id) {
                    let close_msg = serde_json::json!({
                        "type": "session.fenced",
                        "reason": "epoch_revocation",
                        "code": 4401,
                    });
                    if let Ok(json) = serde_json::to_string(&close_msg) {
                        let _ = tx.send(Utf8Bytes::from(json));
                    }
                }
                tracing::info!(
                    session_id = session_id_owned,
                    actor_id,
                    "epoch revocation: drain expired, fencing connection",
                );
            }
        });
    }

    // ── Broadcast EpochAdvanced ───────────────────────────────────────────────
    let epoch_event = WsMessage::new(
        Ulid::new().to_string(),
        WsPayload::EpochAdvanced {
            session_id: session_id.clone(),
            actor: body.revoked_by.clone(),
            timestamp: Utc::now(),
            seq: 0, // stamped by emit_to_session
            payload: EpochAdvancedPayload {
                new_epoch,
                strategy: body.strategy.clone(),
                target_cap_id: body.target_cap_id.clone(),
                target_stratum: body.target_stratum,
                drain_seq,
                drain_deadline_ms: body.drain_window_secs * 1000,
                closed_epoch,
                revoked_count,
            },
        },
    );
    emit_to_session(&state, &session_id, &body.revoked_by, epoch_event).await;

    // ── Response ──────────────────────────────────────────────────────────────
    Json(RevokeResponse {
        new_epoch,
        closed_epoch,
        revoked_count,
        drain_seq,
        drain_deadline: drain_deadline_utc.to_rfc3339(),
    })
    .into_response()
}
