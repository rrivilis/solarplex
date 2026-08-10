//! `GET /api/agents` — agent directory scoped to the caller's own network
//! (any agent actor currently sharing an active session membership with
//! them). Read-only, same shape and same co-membership boundary as
//! `routes/team.rs` — this is that page's counterpart for agent-type
//! actors instead of human ones. See `db::actors::list_agent_directory`.

use std::sync::Arc;

use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::get, Json, Router};

use db::actors;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(list_agents))
}

async fn list_agents(headers: HeaderMap, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match actors::list_agent_directory(&state.db, &actor_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
