//! `GET /api/team` — member directory scoped to the caller's own network
//! (themselves + anyone they currently share a session with). Read-only
//! v1: no role management, escalation chains, or approval-authority
//! scoping — those need a workspace-level default-role concept that
//! doesn't exist in the schema yet (roles today are purely
//! per-session-membership). See `db::actors::list_teammates`.

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::get, Json, Router};

use db::actors;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(list_teammates))
}

async fn list_teammates(headers: HeaderMap, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match actors::list_teammates(&state.db, &actor_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
