//! `POST /api/sessions/:id/authority/import` — mint a real Solarplex
//! capability from a Lisp-authored `authority-dsl` s-expression: a
//! `(capability ...)` wire form mints a new root cap, a `(delegation ...)`
//! wire form delegates from an existing one. See docs/dsl-guide.md's
//! "Rust Consumers" section for the DSL side of this.
//!
//! This is the concrete backend consumer for the `authority-dsl` toolchain:
//! `crates/splx-ir` reads the wire form, `db::authority_import` translates
//! its `AuthorityEntry` list into Solarplex's flat permission-string
//! vocabulary, and the result goes through exactly the same
//! `AuthorityArena::alloc` / `Authority::delegate` calls — same
//! attenuation check, same epoch scoping, same revocation/audit machinery
//! — as any capability created from inside the app. Deliberately *not* a
//! new enforcement path and not wired into `crates/guardian`'s live
//! Landlock path, which stays on its own native
//! `protocol::effects::DeclaredEffects` — see db::authority_import's doc
//! comment for why that boundary is intentional.
//!
//! Gated Collaborator+, same bar as epoch revocation (`routes/epoch.rs`) —
//! minting authority isn't something any session member should be able to
//! do freely. `actor_id` (who the resulting cap is for) is caller-supplied
//! rather than resolved from the DSL's own principal names — this endpoint
//! doesn't attempt Lisp-principal-name → Solarplex-actor resolution; the
//! caller (CLI, or a future UI) already knows which real actor it means.

use std::sync::Arc;

use axum::{extract::{Path, State}, http::{HeaderMap, StatusCode}, response::IntoResponse, routing::post, Json, Router};
use chrono::Duration;
use serde::{Deserialize, Serialize};

use db::authority_arena::AuthorityArena;
use protocol::types::MemberRole;
use session::rate_limit::RateLimitKey;
use splx_ir::SplxValue;

use crate::rate_limit::gate_session;
use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/", post(import))
}

#[derive(Deserialize)]
struct ImportBody {
    /// A `(capability ...)` or `(delegation ...)` authority-dsl wire
    /// s-expression (see docs/dsl-guide.md).
    sexpr: String,
    /// The real Solarplex actor the resulting cap is minted for
    /// (`capability`) or delegated to (`delegation`).
    actor_id: String,
    /// Required only when `sexpr` is a `(delegation ...)` — the existing
    /// parent cap (ULID) in this session to delegate from.
    #[serde(default)]
    parent_cap_id: Option<String>,
    #[serde(default = "default_ttl_secs")]
    ttl_secs: i64,
}

fn default_ttl_secs() -> i64 { 3600 }

#[derive(Serialize)]
struct ImportResponse {
    cap_id: String,
    permissions: Vec<String>,
    expires_at: String,
    stratum: i64,
}

#[autometrics]
async fn import(
    headers:      HeaderMap,
    Path(session_id): Path<String>,
    State(state): State<Arc<AppState>>,
    Json(body):   Json<ImportBody>,
) -> impl IntoResponse {
    let caller = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    if let Err(e) = db::sessions::require_membership(&state.db, &session_id, &caller, MemberRole::Collaborator).await {
        return match e {
            db::DbError::NotFound     => (StatusCode::FORBIDDEN, "not a member of this session").into_response(),
            db::DbError::Unauthorized => (StatusCode::FORBIDDEN, "authority import requires collaborator or owner role").into_response(),
            e                         => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        };
    }
    if let Some(res) = gate_session(
        &state, &session_id, &caller, RateLimitKey::AuthorityImport { actor_id: caller.clone() },
    ).await {
        return res;
    }

    let parsed = match body.sexpr.parse::<SplxValue>() {
        Ok(v)  => v,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, format!("invalid authority-dsl s-expression: {e}")).into_response(),
    };

    let arena = match AuthorityArena::for_session(&state.db, &session_id).await {
        Ok(a)  => a,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    let ttl = Duration::seconds(body.ttl_secs);

    let authority = match parsed {
        SplxValue::Capability(cap) => {
            match db::authority_import::import_capability(&arena, &body.actor_id, &cap, ttl).await {
                Ok(a)  => a,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        SplxValue::Delegation(delegation) => {
            let Some(parent_cap_id) = body.parent_cap_id.as_deref() else {
                return (StatusCode::UNPROCESSABLE_ENTITY, "delegation import requires parent_cap_id").into_response();
            };
            let parent = match arena.authority_for_cap(parent_cap_id).await {
                Ok(a)  => a,
                Err(db::DbError::NotFound) => return (StatusCode::NOT_FOUND, "parent_cap_id not found in this session").into_response(),
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            };
            match db::authority_import::import_delegation(&parent, &body.actor_id, &delegation, ttl).await {
                Ok(a)  => a,
                Err(db::DbError::Conflict(msg)) => return (StatusCode::CONFLICT, msg).into_response(),
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            }
        }
        other => return (
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("expected a (capability ...) or (delegation ...) wire form, got {other:?}"),
        ).into_response(),
    };

    // Best-effort audit event — the cap itself is already durably created
    // regardless of whether this succeeds (same non-fatal pattern
    // routes/epoch.rs's record_revocation uses).
    if let Ok(seq) = db::events::alloc_seq(&state.db, &session_id).await {
        let _ = db::events::append(&state.db, db::events::AppendEvent {
            session_id: session_id.clone(),
            actor_id: caller,
            event_type: "authority.imported_from_dsl".to_string(),
            payload: serde_json::json!({
                "cap_id": authority.id,
                "permissions": authority.permissions,
            }),
            parent_event_id: None,
            seq,
        }).await;
    }

    Json(ImportResponse {
        cap_id:      authority.id.clone(),
        permissions: authority.permissions.clone(),
        expires_at:  authority.expires_at.to_rfc3339(),
        stratum:     authority.stratum,
    }).into_response()
}
