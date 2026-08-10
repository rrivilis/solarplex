//! `GET /api/search?q=...` — cross-session search, v1. Sessions/artifacts/
//! events are scoped to the caller's own membership, same visibility
//! boundary as `GET /api/activity`; actors are scoped to the caller's
//! co-membership network, same boundary as the Teammates directory — see
//! `db::search`'s module doc comment for the full reasoning.

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

use db::{actors, search, sessions};

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", get(search_all))
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
    limit: Option<i64>,
}

async fn search_all(
    headers:      HeaderMap,
    Query(q):     Query<SearchQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let query = q.q.trim();
    // A 1-2 char query against `payload::text ILIKE` across every event a
    // member has would be an expensive, useless scan — same floor a
    // mention-picker/autocomplete would use.
    if query.len() < 2 {
        return Json(json!({
            "sessions": [], "artifacts": [], "actors": [], "events": [],
        })).into_response();
    }
    let limit = q.limit.unwrap_or(10).clamp(1, 50);

    let member_sessions = match sessions::list_by_actor(&state.db, &actor_id).await {
        Ok(s)  => s,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let session_ids: Vec<String> = member_sessions.iter().map(|s| s.id.clone()).collect();
    let session_names: std::collections::HashMap<String, String> =
        member_sessions.into_iter().map(|s| (s.id, s.name)).collect();

    let (sessions_hit, artifacts_hit, actors_hit, events_hit) = tokio::join!(
        search::search_sessions(&state.db, &session_ids, query, limit),
        search::search_artifacts(&state.db, &session_ids, query, limit),
        search::search_actors(&state.db, &actor_id, query, limit),
        search::search_events(&state.db, &session_ids, query, limit),
    );

    let sessions_hit  = sessions_hit.unwrap_or_default();
    let artifacts_hit = artifacts_hit.unwrap_or_default();
    let actors_hit    = actors_hit.unwrap_or_default();
    let events_hit    = events_hit.unwrap_or_default();

    // Enrich artifact/event rows with the session name for display — the
    // same "resolve at render time, from an already-fetched map" pattern
    // activity.rs uses, not a per-row extra query.
    let actor_name_map: std::collections::HashMap<String, String> = {
        let ids: Vec<String> = events_hit.iter().map(|e| e.actor_id.clone())
            .chain(artifacts_hit.iter().map(|a| a.created_by.clone()))
            .collect();
        actors::get_many(&state.db, &ids).await.unwrap_or_default()
            .into_iter().map(|(id, a)| (id, a.name)).collect()
    };

    Json(json!({
        "sessions": sessions_hit,
        "artifacts": artifacts_hit.iter().map(|a| json!({
            "id": a.id, "session_id": a.session_id,
            "session_name": session_names.get(&a.session_id).cloned().unwrap_or_else(|| "(unknown session)".to_string()),
            "name": a.name, "type": a.r#type,
            "created_by": a.created_by,
            "created_by_name": actor_name_map.get(&a.created_by).cloned().unwrap_or_else(|| a.created_by.clone()),
        })).collect::<Vec<_>>(),
        "actors": actors_hit,
        "events": events_hit.iter().map(|e| json!({
            "id": e.id, "session_id": e.session_id,
            "session_name": session_names.get(&e.session_id).cloned().unwrap_or_else(|| "(unknown session)".to_string()),
            "actor_id": e.actor_id,
            "actor_name": actor_name_map.get(&e.actor_id).cloned().unwrap_or_else(|| e.actor_id.clone()),
            "type": e.r#type, "payload": e.payload, "timestamp": e.timestamp,
        })).collect::<Vec<_>>(),
    })).into_response()
}
