//! Unauthenticated liveness/readiness probe for load balancers and uptime
//! monitors. Deliberately outside `/api` and outside rate limiting — the
//! whole point is to tolerate high-frequency polling from infrastructure
//! that has no cap/session context to authenticate with.

use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;

use crate::state::AppState;

/// `GET /health` — 200 with a small JSON body if the DB is reachable,
/// 503 otherwise. Not a deep check: one cheap round trip, not a proxy for
/// "is every subsystem fully healthy."
pub async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "health check: database ping failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
                .into_response()
        }
    }
}
