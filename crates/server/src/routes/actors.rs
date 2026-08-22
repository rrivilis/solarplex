use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use db::actors;
use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/humans", post(create_human))
        .route("/agents", post(create_agent))
        .route("/{id}", get(get_actor))
}

/// Minimal, deliberately non-`ActorRow` response shape — an actor lookup is
/// meant for resolving id → display name (the CLI's `sp actor show` is the
/// first caller; nothing previously exposed this at all), not for exposing
/// `email`/`provider`/`model`/`config`, which `ActorRow` also carries.
#[derive(Serialize)]
struct ActorSummary {
    id:   String,
    name: String,
    #[serde(rename = "type")]
    actor_type: String,
}

#[autometrics]
async fn get_actor(
    Path(id):     Path<String>,
    headers:      HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_sp_auth(&state.db, &headers).await {
        return res;
    }
    match actors::get(&state.db, &id).await {
        Ok(a) => Json(ActorSummary { id: a.id, name: a.name, actor_type: a.r#type }).into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateHumanBody {
    pub name: String,
    pub email: String,
}

#[autometrics]
async fn create_human(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateHumanBody>,
) -> impl IntoResponse {
    match actors::create_human(&state.db, actors::CreateHuman {
        name: body.name,
        email: body.email,
    })
    .await
    {
        Ok(actor) => (StatusCode::CREATED, Json(actor)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
pub struct CreateAgentBody {
    pub name: String,
    pub provider: String,
    pub model: String,
    pub config: Option<serde_json::Value>,
}

#[autometrics]
async fn create_agent(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateAgentBody>,
) -> impl IntoResponse {
    match actors::create_agent(&state.db, actors::CreateAgent {
        name: body.name,
        provider: body.provider,
        model: body.model,
        config: body.config,
    })
    .await
    {
        Ok(actor) => (StatusCode::CREATED, Json(actor)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
