mod sessions;
mod activity;
mod agent_caps;
mod agents;
mod approvals;
mod actors;
mod approval_policies;
mod artifact_hashes;
mod auth_query;
mod descriptors;
mod authority_import;
mod epoch;
mod intent;
mod invites;
mod invoke;
mod mailbox;
mod proposals;
mod session_links;
mod session_remotes;
mod search;
mod team;

use std::sync::Arc;
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::{get, post}, Json, Router};
use serde::Deserialize;
use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .nest("/sessions", sessions::router())
        .nest("/approvals", approvals::router())
        .nest("/actors", actors::router())
        .nest("/invites", invites::router())
        .nest("/descriptors", descriptors::router())
        .nest("/mailbox", mailbox::router())
        .nest("/activity", activity::router())
        .nest("/agent-caps", agent_caps::router())
        .nest("/search", search::router())
        .nest("/team", team::router())
        .nest("/agents", agents::router())
        .nest("/intent", intent::router())
        .route("/attach", post(exchange_token))
        // Tuple-space auth query layer — read-only, explanatory, not enforcement
        .route("/auth/why",      get(auth_query::why))
        .route("/auth/who-can",  get(auth_query::who_can))
        .route("/auth/lineage",  get(auth_query::lineage))
        // Epoch-based cap revocation + status
        .route("/sessions/{id}/epoch",        get(epoch::get_epoch))
        .route("/sessions/{id}/epoch/revoke", post(epoch::revoke))
        // ORB execution dispatch
        .route("/sessions/{id}/invoke",          post(invoke::handler))
        .route("/sessions/{id}/consume-receipt", post(invoke::consume_handler))
        // Three-tier commitment model: write proposals (Tier 1) + attestations (Tier 2)
        .nest("/sessions/{id}", proposals::router())
        // Standing approval policies (in-memory; survive process lifetime)
        .nest("/sessions/{id}", approval_policies::router())
        // Cross-session sync: session-to-session linking (live multiplex)
        .nest("/sessions/{id}", session_links::session_scoped_router())
        .merge(session_links::top_level_router())
        // Cross-session sync: git-remote-style durable fetch
        .nest("/sessions/{id}", session_remotes::router())
        // Artifact reputation: hash prevalence + family graph
        .merge(artifact_hashes::router())
        // authority-dsl (Lisp) → AuthorityArena import
        .nest("/sessions/{id}/authority", authority_import::router())
}

// ── Token exchange ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct ExchangeBody {
    token: String,
}

#[autometrics]
async fn exchange_token(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ExchangeBody>,
) -> impl IntoResponse {
    match db::tokens::exchange(&state.db, &body.token).await {
        Ok(row) => {
            let perms = db::tokens::parse_permissions(&row);
            Json(serde_json::json!({
                "session_id":   row.session_id,
                "actor_id":     row.actor_id,
                "permissions":  perms,
                "observed_seq": row.observed_seq,
                "parent_cap":   row.parent_cap,
            })).into_response()
        }
        Err(db::DbError::NotFound) =>
            (StatusCode::GONE, "token expired, already used, or not found").into_response(),
        Err(e) =>
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
