//! `GET /api/agent-caps` / `DELETE /api/agent-caps/:id` — the Settings
//! "active agent sessions" view: every live agent attach-credential across
//! every session the signed-in actor owns, with a revoke action.
//!
//! Mirrors activity.rs's shape (cross-session, sp_token-scoped to the
//! caller's own identity, no per-row membership check needed because the
//! underlying query is already scoped to sessions the caller owns).

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde_json::json;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_mine))
        .route("/:id", axum::routing::delete(revoke))
}

async fn list_mine(
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::tokens::list_root_caps_for_owner(&state.db, &actor_id).await {
        Ok(rows) => {
            let out: Vec<serde_json::Value> = rows.iter().map(|r| json!({
                "cap_id":       r.cap_id,
                "session_id":   r.session_id,
                "session_name": r.session_name,
                "actor_id":     r.actor_id,
                "created_at":   r.created_at,
                "expires_at":   r.expires_at,
                "used_at":      r.used_at,
            })).collect();
            Json(out).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn revoke(
    headers:      HeaderMap,
    Path(id):     Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::tokens::revoke_owned_root_cap(&state.db, &id, &actor_id).await {
        Ok(Some(_revoked_ids)) => StatusCode::NO_CONTENT.into_response(),
        Ok(None)               => StatusCode::NOT_FOUND.into_response(),
        Err(e)                 => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
