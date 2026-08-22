//! `GET /api/mailbox`, `POST /api/mailbox/{id}/seen` — the receiver-specific
//! read side of the `mailbox_routes` edge table. See `db::mailbox` for the
//! write side (populated at invite-create time and backfilled on first
//! login, both non-fatal best-effort); this route is purely resolve-and-
//! render — no state changes here beyond marking an entry seen.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde_json::json;

use db::{actors, invites, sessions};
use protocol::types::EntityHandle;

use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/", get(list_mine))
        .route("/{id}/seen", post(mark_seen))
}

#[autometrics]
async fn list_mine(headers: HeaderMap, State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let routes = match db::mailbox::list_for_actor(&state.db, &actor_id).await {
        Ok(r)  => r,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Resolve each route's entity_uri back to the real object. "invite" is
    // the only kind ever routed today; any other/future kind falls back to
    // a generic entry rather than vanishing from the list or erroring.
    let mut resolved: Vec<(db::mailbox::MailboxRouteRow, Option<db::invites::InviteRow>)> = Vec::new();
    let mut inviter_ids: Vec<String> = Vec::new();
    for route in routes {
        let invite = match EntityHandle::from_uri(&route.entity_uri) {
            Some(EntityHandle::Invite(id)) => invites::get(&state.db, &id).await.ok(),
            _ => None,
        };
        if let Some(ref inv) = invite {
            inviter_ids.push(inv.invited_by.clone());
        }
        resolved.push((route, invite));
    }

    let names = actors::get_many(&state.db, &inviter_ids).await.unwrap_or_default();

    let mut out = Vec::with_capacity(resolved.len());
    for (route, invite) in resolved {
        let entry = match invite {
            Some(inv) => {
                let session_name = sessions::get(&state.db, &inv.session_id).await
                    .map(|s| s.name)
                    .unwrap_or_else(|_| "(unknown session)".to_string());
                let invited_by_name = names.get(&inv.invited_by)
                    .map(|a| a.name.clone())
                    .unwrap_or_else(|| inv.invited_by.clone());
                json!({
                    "id":         route.id,
                    "kind":       "invite",
                    "entity_uri": route.entity_uri,
                    "created_at": route.created_at,
                    "seen_at":    route.seen_at,
                    "invite": {
                        "id":              inv.id,
                        "session_id":      inv.session_id,
                        "session_name":    session_name,
                        "role":            inv.role,
                        "invited_by":      inv.invited_by,
                        "invited_by_name": invited_by_name,
                        "expires_at":      inv.expires_at,
                        "redeemed_at":     inv.redeemed_at,
                        "revoked_at":      inv.revoked_at,
                    },
                })
            }
            // Route pointed at something that no longer resolves (e.g. the
            // invite was hard-deleted) — surface it as an inert entry rather
            // than silently dropping it; the frontend can still offer "mark seen".
            None => json!({
                "id":         route.id,
                "kind":       "unknown",
                "entity_uri": route.entity_uri,
                "created_at": route.created_at,
                "seen_at":    route.seen_at,
            }),
        };
        out.push(entry);
    }

    Json(out).into_response()
}

#[autometrics]
async fn mark_seen(
    headers:      HeaderMap,
    Path(id):     Path<String>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::mailbox::mark_seen(&state.db, &id, &actor_id).await {
        Ok(())                     => StatusCode::NO_CONTENT.into_response(),
        Err(db::DbError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(e)                     => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}
