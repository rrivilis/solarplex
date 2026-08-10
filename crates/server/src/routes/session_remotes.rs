//! Git-remote-style fetch between sessions — durable, directional, with a
//! per-pair watermark cursor. See `db::session_remotes` and migration 027.
//!
//! - `POST /sessions/:id/remotes` — add a remote pointer (Collaborator+ in
//!   the *local* session only; adding grants nothing by itself).
//! - `GET /sessions/:id/remotes` — list this session's remotes.
//! - `POST /sessions/:id/remotes/:remote_id/fetch` — pull events since the
//!   last watermark. Authorization against the *remote* session is checked
//!   here, at fetch time, via the same `require_membership_or_linked_access`
//!   every other cross-session read uses. Never writes into the local
//!   session's event log.
//! - `DELETE /sessions/:id/remotes/:remote_id` — remove.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use protocol::types::MemberRole;
use session::rate_limit::RateLimitKey;

use crate::rate_limit::gate_session;
use crate::state::AppState;

/// Mounted at `/sessions/:id` alongside session_links.
pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/remotes", get(list_remotes).post(add_remote))
        .route("/remotes/:remote_id", axum::routing::delete(remove_remote))
        .route("/remotes/:remote_id/fetch", post(fetch_remote))
}

#[derive(Deserialize)]
struct AddRemoteBody {
    remote_session_id: String,
}

async fn add_remote(
    Path(local_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddRemoteBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &local_id, MemberRole::Collaborator,
    ).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &local_id, &actor_id, RateLimitKey::SessionRemoteMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_remotes::add_remote(&state.db, &local_id, &body.remote_session_id, &actor_id).await {
        Ok(row) => (StatusCode::CREATED, Json(row)).into_response(),
        Err(db::DbError::Conflict(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn list_remotes(
    Path(local_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(
        &state.db, &headers, &local_id, MemberRole::Observer,
    ).await {
        return res;
    }
    match db::session_remotes::list_for_session(&state.db, &local_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn fetch_remote(
    Path((local_id, remote_id)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    // Caller must at least be a real member of the local session — this is
    // the "you may use this configured remote" bar, distinct from the
    // separate check against the remote session's own data below.
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &local_id, MemberRole::Observer,
    ).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &local_id, &actor_id, RateLimitKey::SessionRemoteMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }

    let remote = match db::session_remotes::get(&state.db, &remote_id).await {
        Ok(r) if r.local_session_id == local_id => r,
        Ok(_) | Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // The actual authorization gate: does this actor have real (or
    // linked-Observer) standing in the *remote* session? Checked here, at
    // fetch time, not at add-remote time — same as `git remote add` working
    // against a URL you don't yet have access to. 404, not 403 — same
    // anti-enumeration posture as session_links' require_link_admin.
    if let Err(e) = db::sessions::require_membership_or_linked_access(
        &state.db, &remote.remote_session_id, &actor_id, MemberRole::Observer,
    ).await {
        return match e {
            db::DbError::NotFound | db::DbError::Unauthorized => StatusCode::NOT_FOUND.into_response(),
            e => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }

    let events = match db::events::list(&state.db, &remote.remote_session_id, Some(remote.last_fetched_seq), 500).await {
        Ok(e)  => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let updated = if let Some(max_seq) = events.iter().map(|e| e.seq).max() {
        match db::session_remotes::advance_watermark(&state.db, &remote_id, max_seq).await {
            Ok(r)  => r,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    } else {
        remote
    };

    Json(serde_json::json!({ "remote": updated, "events": events })).into_response()
}

async fn remove_remote(
    Path((local_id, remote_id)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(
        &state.db, &headers, &local_id, MemberRole::Collaborator,
    ).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &local_id, &actor_id, RateLimitKey::SessionRemoteMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_remotes::get(&state.db, &remote_id).await {
        Ok(r) if r.local_session_id == local_id => {}
        Ok(_) | Err(db::DbError::NotFound) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
    match db::session_remotes::remove(&state.db, &remote_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
