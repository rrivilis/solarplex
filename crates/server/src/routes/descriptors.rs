//! Doors-styled resolution for per-actor capability descriptors.
//!
//! Mirrors guardian's own invocation shape at the HTTP layer instead of a
//! persistent socket: caller presents credentials, the server independently
//! verifies against its own authoritative record rather than trusting the
//! caller's claim, and returns a definitive result. Here the "receipt" is
//! the sp_token (verified identity) and the thing never trusted as a bearer
//! value on its own is `local_index` — it only ever means anything when
//! resolved against the specific actor it was verified to belong to.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use db::descriptors;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_mine))
        .route("/resolve", post(resolve))
}

/// GET /api/descriptors — every local descriptor the caller currently holds.
async fn list_mine(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match descriptors::list_for_actor(&state.db, &actor_id).await {
        Ok(rows) => Json(rows).into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct ResolveBody {
    local_index: i32,
}

/// POST /api/descriptors/resolve
///
/// The one and only resolution path. `local_index` is never trusted as a
/// bearer value by itself — it's only ever checked against the caller's own
/// row set, established by a verified sp_token, never a self-asserted actor
/// id. A local_index that's real for a different actor resolves to the same
/// 404 as one that doesn't exist at all — never distinguish the two, or the
/// error itself becomes an oracle for enumerating other actors' grants.
async fn resolve(
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<ResolveBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match descriptors::resolve(&state.db, &actor_id, body.local_index).await {
        Ok(row)                    => Json(row).into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e)                     => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
