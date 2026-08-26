//! `GET /api/activity` — a cross-session event feed: recent events merged
//! across every session the signed-in actor is a member of, ordered by
//! wall-clock time.
//!
//! Deliberately polling/refetch, not live-pushed. Each session's live event
//! stream is backed by its own isolated in-memory broadcast channel
//! (`SessionHub`, one per session_id, created/destroyed with connection
//! lifecycle) — there is no existing cross-session event bus to tap into.
//! Wiring a live-pushed version would mean new server-side fan-out
//! infrastructure (a genuinely global broadcast/pg_notify-based channel
//! every event-commit path also publishes to), which is a separate,
//! larger piece of work than this read endpoint. This proves the
//! cross-session read model first, same reasoning as deferring SSE on the
//! mailbox.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use db::{actors, sessions};

use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(list_mine))
}

#[derive(Deserialize)]
struct ActivityQuery {
    limit: Option<i64>,
}

#[autometrics]
async fn list_mine(
    headers: HeaderMap,
    Query(q): Query<ActivityQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id) => id,
        Err(res) => return res,
    };

    // Excludes archived sessions (list_by_actor's own filter) — a stale
    // archive isn't worth an activity row anyway. No separate per-session
    // membership check needed below: this list is already scoped to
    // sessions the actor belongs to.
    let member_sessions = match sessions::list_by_actor(&state.db, &actor_id).await {
        Ok(s) => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    if member_sessions.is_empty() {
        return Json(Vec::<serde_json::Value>::new()).into_response();
    }

    let session_ids: Vec<String> = member_sessions.iter().map(|s| s.id.clone()).collect();
    let session_names: HashMap<String, String> = member_sessions
        .into_iter()
        .map(|s| (s.id, s.name))
        .collect();

    let events = match db::events::list_recent_across_sessions(
        &state.db,
        &session_ids,
        q.limit.unwrap_or(100),
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let actor_ids: Vec<String> = events.iter().map(|e| e.actor_id.clone()).collect();
    let names = actors::get_many(&state.db, &actor_ids)
        .await
        .unwrap_or_default();

    let out: Vec<serde_json::Value> = events.iter().map(|e| {
        let actor_name = names.get(&e.actor_id).map(|a| a.name.clone()).unwrap_or_else(|| e.actor_id.clone());
        json!({
            "id":           e.id,
            "session_id":   e.session_id,
            "session_name": session_names.get(&e.session_id).cloned().unwrap_or_else(|| "(unknown session)".to_string()),
            "actor_id":     e.actor_id,
            "actor_name":   actor_name,
            "type":         e.r#type,
            "payload":      e.payload,
            "timestamp":    e.timestamp,
        })
    }).collect();

    Json(out).into_response()
}
