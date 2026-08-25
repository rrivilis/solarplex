//! `GET /api/agents` — agent directory scoped to the caller's own network
//! (any agent actor currently sharing an active session membership with
//! them). Read-only, same shape and same co-membership boundary as
//! `routes/team.rs` — this is that page's counterpart for agent-type
//! actors instead of human ones. See `db::actors::list_agent_directory`.
//!
//! Unlike Teammates, each row also carries a `live` flag. Revoking a live
//! attach-cap stays a Settings action (owner-only, credential-scoped — see
//! `routes/agent_caps.rs`); this directory only adds "is this agent here
//! right now," which every viewer with co-membership can already see once
//! they open the session itself.

use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, http::HeaderMap, response::IntoResponse, routing::get, Json, Router};
use serde::Serialize;

use db::actors;

use crate::state::AppState;
use crate::ws::AGENT_STALE_THRESHOLD_SECS;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(list_agents))
}

#[derive(Serialize)]
struct AgentDirectoryRow {
    #[serde(flatten)]
    row: actors::TeammateRow,
    live: bool,
}

#[autometrics]
async fn list_agents(headers: HeaderMap, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    let rows = match actors::list_agent_directory(&state.db, &actor_id).await {
        Ok(rows) => rows,
        Err(e)   => return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Agents never hold a WS connection (see shim/session.rs), so
    // `actor_senders` never sees them — `agent_heartbeats` is the only
    // real liveness signal, same one `sweep_stale_agents` and the
    // per-session snapshot's `attached` field already use. This directory
    // spans every session the agent might be in, not just one, so it
    // checks every currently-loaded hub rather than a single session's —
    // an agent attached to more than one session at once is live here if
    // it's heartbeating in any of them.
    let threshold = Duration::from_secs(AGENT_STALE_THRESHOLD_SECS);
    let out: Vec<AgentDirectoryRow> = rows.into_iter().map(|row| {
        let live = state.hubs.iter().any(|hub| {
            hub.agent_heartbeats.get(&row.id)
                .map_or(false, |t| t.elapsed() < threshold)
        });
        AgentDirectoryRow { row, live }
    }).collect();

    Json(out).into_response()
}
