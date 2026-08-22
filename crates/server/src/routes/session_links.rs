//! Session-to-session linking — the single mechanism for cross-session sync
//! (supersedes the v1 single-artifact propose/approve flow).
//!
//! - `POST /sessions/{id}/link-invites` — mint a link invite (Collaborator+).
//!   The invite row's own id is the bearer token, same convention as
//!   `session_invites`/`/invite/{id}`.
//! - `POST /link-invites/{id}/redeem` — redeem into a target session
//!   (Collaborator+ in the target).
//! - `POST /sessions/{a}/link/{b}` — direct fast path when the caller already
//!   holds Collaborator+ in both sessions; no invite round trip.
//! - `GET /sessions/{id}/links` — list this session's links, peer names
//!   resolved for display.
//! - `PATCH /links/{id}` — toggle visibility (full|muted).
//! - `DELETE /links/{id}` — unlink.
//!
//! Once a `session_links` row exists with `visibility = 'full'`, nothing
//! else here does the actual "live multiplex" work — that's entirely
//! `db::sessions::require_membership_or_linked_access`, called from the
//! normal WS-attach and REST membership gates every other endpoint already
//! uses.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, patch, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use protocol::types::MemberRole;
use session::rate_limit::RateLimitKey;

use crate::rate_limit::gate_session;
use crate::state::AppState;
use autometrics::autometrics;

/// Mounted at `/sessions/{id}` (nested alongside proposals/approval_policies).
pub fn session_scoped_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/link-invites", post(mint_link_invite))
        .route("/links", get(list_links))
}

/// Mounted at the API root.
pub fn top_level_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/link-invites/{id}/redeem", post(redeem_link_invite))
        .route("/links/{id}", patch(mute_link).delete(delete_link))
        .route("/sessions/{a}/link/{b}", post(direct_link))
}

fn default_ttl_secs() -> i64 { 259_200 } // 3 days — matches create_invite's default

#[derive(Deserialize)]
struct MintLinkInviteBody {
    #[serde(default = "default_ttl_secs")]
    ttl_secs: i64,
}

#[autometrics]
async fn mint_link_invite(
    Path(source_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<MintLinkInviteBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &source_id, MemberRole::Collaborator).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &source_id, &actor_id, RateLimitKey::SessionLinkMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_links::mint_invite(&state.db, &source_id, &actor_id, body.ttl_secs).await {
        Ok(row) => (StatusCode::CREATED, Json(row)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[derive(Deserialize)]
struct RedeemLinkInviteBody {
    target_session_id: String,
}

#[autometrics]
async fn redeem_link_invite(
    Path(invite_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<RedeemLinkInviteBody>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &body.target_session_id, MemberRole::Collaborator).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &body.target_session_id, &actor_id, RateLimitKey::SessionLinkMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_links::redeem_invite(&state.db, &invite_id, &body.target_session_id, &actor_id).await {
        Ok(row) => Json(row).into_response(),
        Err(db::DbError::NotFound) =>
            (StatusCode::GONE, "link invite expired, already redeemed, or not found").into_response(),
        Err(db::DbError::Conflict(msg)) => (StatusCode::BAD_REQUEST, msg).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn direct_link(
    Path((a, b)): Path<(String, String)>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    if a == b {
        return (StatusCode::BAD_REQUEST, "cannot link a session to itself").into_response();
    }
    // Same actor must independently clear the Collaborator+ bar in *both*
    // sessions — this is what makes it a fast path rather than a privilege
    // escalation: it's exactly the authority they could already exercise on
    // each session alone, just without a round trip through the other side.
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &a, MemberRole::Collaborator).await {
        Ok(id) => id,
        Err(res) => return res,
    };
    if let Err(res) = crate::auth::require_session_member(&state.db, &headers, &b, MemberRole::Collaborator).await {
        return res;
    }
    if let Some(res) = gate_session(
        &state, &a, &actor_id, RateLimitKey::SessionLinkMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_links::direct_link(&state.db, &a, &b, &actor_id).await {
        Ok(row) => (StatusCode::CREATED, Json(row)).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn list_links(
    Path(id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_session_member(&state.db, &headers, &id, MemberRole::Observer).await {
        Ok(a) => a,
        Err(res) => return res,
    };
    // Rendered against this specific viewer, not the full set of `id`'s
    // links — see list_visible_for_session's doc comment.
    let links = match db::session_links::list_visible_for_session(&state.db, &id, &actor_id).await {
        Ok(l) => l, Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let mut out = Vec::with_capacity(links.len());
    for link in links {
        let peer_id = link.peer_of(&id).to_string();
        let peer_name = db::sessions::get(&state.db, &peer_id).await.map(|s| s.name).unwrap_or_else(|_| peer_id.clone());
        out.push(json!({
            "id": link.id,
            "peer_session_id": peer_id,
            "peer_session_name": peer_name,
            "visibility": link.visibility,
            "linked_by": link.linked_by,
            "created_at": link.created_at,
        }));
    }
    Json(out).into_response()
}

/// Fetch the link and verify the caller holds Collaborator+ in *either*
/// side — either admin can mute or dissolve a link, not just the one who
/// created it.
///
/// "Not found" and "found but you're not an admin of either side" return
/// the same 404 rather than a distinguishing 403 — same anti-enumeration
/// posture as `mailbox::mark_seen`/`descriptors::resolve`. Without this, a
/// caller who merely guessed or previously saw a link_id (e.g. before being
/// removed from one side) could use the 403-vs-404 split to confirm a link
/// still exists between two sessions they can no longer see via the list
/// endpoint's own viewer-scoped filter.
/// Returns `(actor_id, link)` on success — same reasoning as
/// `approvals.rs`'s `require_shim_auth`: callers that need to rate-limit
/// gate afterward shouldn't have to re-resolve the actor's identity.
async fn require_link_admin(
    state: &Arc<AppState>, headers: &HeaderMap, link_id: &str,
) -> Result<(String, db::session_links::SessionLinkRow), axum::response::Response> {
    let link = match db::session_links::get(&state.db, link_id).await {
        Ok(l) => l,
        Err(db::DbError::NotFound) => return Err(StatusCode::NOT_FOUND.into_response()),
        Err(e) => return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
    };
    let actor_id = crate::auth::require_sp_auth(&state.db, headers).await?;
    let in_a = db::sessions::require_membership(&state.db, &link.session_a, &actor_id, MemberRole::Collaborator).await.is_ok();
    let in_b = db::sessions::require_membership(&state.db, &link.session_b, &actor_id, MemberRole::Collaborator).await.is_ok();
    if !in_a && !in_b {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    Ok((actor_id, link))
}

#[derive(Deserialize)]
struct MuteLinkBody {
    visibility: String,
}

#[autometrics]
async fn mute_link(
    Path(link_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
    Json(body): Json<MuteLinkBody>,
) -> impl IntoResponse {
    let (actor_id, link) = match require_link_admin(&state, &headers, &link_id).await {
        Ok(v)    => v,
        Err(res) => return res,
    };
    if body.visibility != "full" && body.visibility != "muted" {
        return (StatusCode::BAD_REQUEST, "visibility must be 'full' or 'muted'").into_response();
    }
    if let Some(res) = gate_session(
        &state, &link.session_a, &actor_id, RateLimitKey::SessionLinkMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_links::set_visibility(&state.db, &link_id, &body.visibility).await {
        Ok(row) => Json(row).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[autometrics]
async fn delete_link(
    Path(link_id): Path<String>,
    headers: HeaderMap,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let (actor_id, link) = match require_link_admin(&state, &headers, &link_id).await {
        Ok(v)    => v,
        Err(res) => return res,
    };
    if let Some(res) = gate_session(
        &state, &link.session_a, &actor_id, RateLimitKey::SessionLinkMutate { actor_id: actor_id.clone() },
    ).await {
        return res;
    }
    match db::session_links::unlink(&state.db, &link_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
