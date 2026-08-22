//! `GET /api/intent/parse` — deterministic governance-command parsing, the
//! server-side outlet for the `intent` crate (NFST/rustfst grammar match,
//! not an LLM). Read-only and side-effect-free: it never mutates anything
//! and has no opinion on authorization — a parsed intent is a *proposal* a
//! caller (CommandPalette, the message composer) surfaces to the user, who
//! still drives the actual action through its normal, already-authorized
//! REST path. See `crates/intent/src/lib.rs`'s doc comment for the full
//! determinism/auditability rationale.
//!
//! `intent::parse_intent` is deliberately DB-agnostic — it extracts raw
//! *names* (a target session, an invitee/transfer-recipient actor) without
//! resolving them to real IDs. That resolution happens here, where DB
//! access already lives, using the exact same membership boundaries as the
//! rest of this app: target-session name matching is scoped to sessions the
//! caller belongs to (mirrors the CLI's own `resolve_session_id`), actor
//! name matching is scoped to co-members (mirrors the Teammates directory /
//! search's actor scoping — see `db::actors::list_teammates`). Resolution
//! only enriches the proposal (a name that doesn't resolve just stays an
//! unresolved string the frontend shows as-is); it never blocks a parse or
//! substitutes a guess.
//!
//! Auth-gated the same as every other `/api/*` route (`require_sp_auth`).

use std::sync::Arc;

use axum::{extract::{Query, State}, response::IntoResponse, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

use intent::Intent;

use crate::state::AppState;
use autometrics::autometrics;

pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/parse", get(parse))
}

#[derive(Deserialize)]
struct ParseQuery {
    text: String,
}

#[autometrics]
async fn parse(
    headers:      axum::http::HeaderMap,
    Query(q):     Query<ParseQuery>,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let actor_id = match crate::auth::require_sp_auth(&state.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    let Some(parsed) = intent::parse_intent(&q.text) else {
        return Json(serde_json::json!({ "intent": null, "target_session": null, "resolution": {} })).into_response();
    };

    let mut resolution = serde_json::Map::new();
    if let Some(name) = &parsed.target_session {
        let outcome = resolve_target_session(&state.db, &actor_id, name).await;
        resolution.insert("target_session".into(), serde_json::to_value(outcome).unwrap());
    }
    let actor_name = match &parsed.intent {
        Intent::Invite { invitee: Some(name), .. } => Some(name.as_str()),
        Intent::TransferOwnership { to }            => Some(to.as_str()),
        _                                            => None,
    };
    if let Some(name) = actor_name {
        let outcome = resolve_actor(&state.db, &actor_id, name).await;
        resolution.insert("actor".into(), serde_json::to_value(outcome).unwrap());
    }

    Json(serde_json::json!({
        "intent":         parsed.intent,
        "target_session": parsed.target_session,
        "resolution":     resolution,
    })).into_response()
}

// ── Name resolution ──────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum NameResolution {
    Matched {
        id: String,
        name: String,
        /// Only ever populated by `resolve_actor` — sessions have no email.
        /// Lets a resolved co-member's *real* email prefill the Invite
        /// modal's email field instead of just their display name.
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,
    },
    Ambiguous { candidates: Vec<NameHit> },
    NotFound,
}

#[derive(Serialize)]
struct NameHit {
    id:    String,
    name:  String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

async fn resolve_target_session(pool: &PgPool, viewer_actor_id: &str, raw_name: &str) -> NameResolution {
    match db::sessions::list_by_actor(pool, viewer_actor_id).await {
        Ok(sessions) => resolve_by_name(raw_name, sessions.into_iter().map(|s| (s.id, s.name, None))),
        Err(_)       => NameResolution::NotFound,
    }
}

async fn resolve_actor(pool: &PgPool, viewer_actor_id: &str, raw_name: &str) -> NameResolution {
    match db::actors::list_teammates(pool, viewer_actor_id).await {
        Ok(teammates) => resolve_by_name(raw_name, teammates.into_iter().map(|t| (t.id, t.name, t.email))),
        Err(_)        => NameResolution::NotFound,
    }
}

/// Exact case-insensitive name match wins outright; otherwise fall back to
/// a substring match. Zero hits is `NotFound`, more than one at whichever
/// tier resolved is `Ambiguous` — never silently pick one.
fn resolve_by_name(raw: &str, items: impl Iterator<Item = (String, String, Option<String>)>) -> NameResolution {
    let items: Vec<(String, String, Option<String>)> = items.collect();
    let needle = raw.to_lowercase();

    let exact: Vec<&(String, String, Option<String>)> = items.iter().filter(|(_, n, _)| n.to_lowercase() == needle).collect();
    let tier = if !exact.is_empty() {
        exact
    } else {
        items.iter().filter(|(_, n, _)| n.to_lowercase().contains(&needle)).collect()
    };

    match tier.as_slice() {
        []       => NameResolution::NotFound,
        [(id, name, email)] => NameResolution::Matched { id: id.clone(), name: name.clone(), email: email.clone() },
        many     => NameResolution::Ambiguous {
            candidates: many.iter().map(|(id, name, email)| NameHit { id: id.clone(), name: name.clone(), email: email.clone() }).collect(),
        },
    }
}
