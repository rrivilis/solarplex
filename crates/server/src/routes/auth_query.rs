//! Tuple-space query layer for the Solarplex cap DAG.
//!
//! These are read-only, explanatory endpoints — they describe the current
//! authorization state but are not themselves enforcement points.
//! Enforcement lives in the cap DAG; these endpoints are the "show your work"
//! interface for debugging, auditing, and building intuition about attenuation.
//!
//! # Endpoints
//!
//! - `GET /api/auth/why?session_id=…&actor_id=…&entity=…`
//!   What authorizes `actor` to interact with `entity`?
//!   Returns: membership role + active caps with delegation lineage.
//!
//! - `GET /api/auth/who-can?session_id=…&entity=…`
//!   Who has authority over `entity` in this session?
//!   Returns: members by role + cap holders with tool permissions.
//!
//! - `GET /api/auth/lineage?cap_id=…`
//!   Delegation chain for a capability, root-to-leaf.
//!   Returns: ordered list of cap hops with actor names and attenuation.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::state::AppState;
use autometrics::autometrics;
use protocol::types::MemberRole;

// ── GET /api/auth/why ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WhyQuery {
    session_id: String,
    actor_id: String,
    /// EntityHandle URI form: "approval/01J...", "artifact/01J...", etc.
    /// Used to annotate which caps cover this entity type's operations.
    /// Optional — if absent, all caps are returned without entity filtering.
    entity: Option<String>,
}

#[autometrics]
pub async fn why(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WhyQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(
        &state.db,
        &headers,
        &q.session_id,
        MemberRole::Observer,
    )
    .await
    {
        return res;
    }

    // ── Membership ────────────────────────────────────────────────────────────
    let membership = match db::sessions::get_membership(&state.db, &q.session_id, &q.actor_id).await
    {
        Ok(m) => Some(membership_json(&m)),
        Err(_) => None, // actor not a formal member — may still hold caps
    };

    // ── Active caps for this actor in this session ────────────────────────────
    let caps = match db::tokens::actor_caps_in_session(&state.db, &q.session_id, &q.actor_id).await
    {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // ── For each cap: fetch its delegation lineage ────────────────────────────
    let mut caps_with_lineage: Vec<Value> = Vec::new();
    for cap in &caps {
        let lineage = match db::tokens::lineage(&state.db, &cap.id).await {
            Ok(l) => l,
            Err(_) => vec![],
        };

        // Collect unique actor_ids across the lineage for name enrichment
        let actor_ids: Vec<String> = lineage.iter().map(|r| r.actor_id.clone()).collect();
        let names = db::actors::get_many(&state.db, &actor_ids)
            .await
            .unwrap_or_default();

        let lineage_json: Vec<Value> = lineage
            .iter()
            .enumerate()
            .map(|(i, row)| {
                let actor_name = names
                    .get(&row.actor_id)
                    .map(|a| a.name.as_str())
                    .unwrap_or("?");
                json!({
                    "id":           row.id,
                    "actor_id":     row.actor_id,
                    "actor_name":   actor_name,
                    "permissions":  db::tokens::parse_permissions(row),
                    "observed_seq": row.observed_seq,
                    "is_root":      row.parent_cap.is_none(),
                    "is_leaf":      i + 1 == lineage.len(),
                    "used_at":      row.used_at,
                    "expires_at":   row.expires_at,
                })
            })
            .collect();

        let perms = db::tokens::parse_permissions(cap);
        let entity_covered = q
            .entity
            .as_deref()
            .map(|e| entity_permissions_match(&perms, e))
            .unwrap_or(true);

        caps_with_lineage.push(json!({
            "id":             cap.id,
            "permissions":    perms,
            "permissions_label": if cap.permissions.as_array().map(|a| a.is_empty()).unwrap_or(true) {
                "all tools"
            } else { "restricted" },
            "observed_seq":   cap.observed_seq,
            "is_root":        cap.parent_cap.is_none(),
            "used_at":        cap.used_at,
            "expires_at":     cap.expires_at,
            "entity_covered": entity_covered,
            "lineage":        lineage_json,
        }));
    }

    Json(json!({
        "actor_id":   q.actor_id,
        "entity":     q.entity,
        "session_id": q.session_id,
        "membership": membership,
        "caps":       caps_with_lineage,
    }))
    .into_response()
}

// ── GET /api/auth/who-can ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct WhoCanQuery {
    session_id: String,
    entity: Option<String>,
}

#[autometrics]
pub async fn who_can(
    State(state): State<Arc<AppState>>,
    Query(q): Query<WhoCanQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Err(res) = crate::auth::require_session_member(
        &state.db,
        &headers,
        &q.session_id,
        MemberRole::Observer,
    )
    .await
    {
        return res;
    }

    // ── Members by role ───────────────────────────────────────────────────────
    let memberships = match db::sessions::list_memberships(&state.db, &q.session_id).await {
        Ok(m) => m,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // Collect member actor_ids for name enrichment
    let member_ids: Vec<String> = memberships.iter().map(|m| m.actor_id.clone()).collect();
    let member_names = db::actors::get_many(&state.db, &member_ids)
        .await
        .unwrap_or_default();

    let by_role: Vec<Value> = memberships
        .iter()
        .map(|m| {
            let name = member_names
                .get(&m.actor_id)
                .map(|a| a.name.as_str())
                .unwrap_or("?");
            json!({
                "actor_id":      m.actor_id,
                "actor_name":    name,
                "role":          m.role,
                "can_approve":   matches!(m.role.as_str(), "owner" | "collaborator"),
                "detached":      m.detached_at.is_some(),
            })
        })
        .collect();

    // ── Cap holders in session ────────────────────────────────────────────────
    let cap_holders = match db::tokens::session_cap_holders(&state.db, &q.session_id).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    let holder_ids: Vec<String> = cap_holders.iter().map(|c| c.actor_id.clone()).collect();
    let holder_names = db::actors::get_many(&state.db, &holder_ids)
        .await
        .unwrap_or_default();

    let by_cap: Vec<Value> = cap_holders
        .iter()
        .filter(|c| {
            // If an entity filter was provided, only show caps that could cover it
            q.entity
                .as_deref()
                .map(|e| {
                    entity_permissions_match(
                        &db::tokens::parse_permissions_from_json(&c.permissions),
                        e,
                    )
                })
                .unwrap_or(true)
        })
        .map(|c| {
            let name = holder_names
                .get(&c.actor_id)
                .map(|a| a.name.as_str())
                .unwrap_or("?");
            let perms = db::tokens::parse_permissions_from_json(&c.permissions);
            json!({
                "actor_id":     c.actor_id,
                "actor_name":   name,
                "cap_id":       c.cap_id,
                "permissions":  perms,
                "permissions_label": if perms.is_empty() { "all tools" } else { "restricted" },
                "expires_at":   c.expires_at,
                "observed_seq": c.observed_seq,
                "delegated":    c.parent_cap.is_some(),
            })
        })
        .collect();

    Json(json!({
        "entity":     q.entity,
        "session_id": q.session_id,
        "by_role":    by_role,
        "by_cap":     by_cap,
    }))
    .into_response()
}

// ── GET /api/auth/lineage ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LineageQuery {
    cap_id: String,
}

#[autometrics]
pub async fn lineage(
    State(state): State<Arc<AppState>>,
    Query(q): Query<LineageQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let chain = match db::tokens::lineage(&state.db, &q.cap_id).await {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    if chain.is_empty() {
        return (StatusCode::NOT_FOUND, "cap not found").into_response();
    }

    // Every hop in one delegation chain belongs to the same session — gate on
    // membership before any of it (including actor names) leaves the server.
    let session_id = &chain[0].session_id;
    if let Err(res) =
        crate::auth::require_session_member(&state.db, &headers, session_id, MemberRole::Observer)
            .await
    {
        return res;
    }

    let actor_ids: Vec<String> = chain.iter().map(|r| r.actor_id.clone()).collect();
    let names = db::actors::get_many(&state.db, &actor_ids)
        .await
        .unwrap_or_default();

    let now = chrono::Utc::now();
    let chain_json: Vec<Value> = chain
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let actor_name = names
                .get(&row.actor_id)
                .map(|a| a.name.as_str())
                .unwrap_or("?");
            let perms = db::tokens::parse_permissions(row);
            let status = if row.expires_at < now {
                "expired"
            } else if row.used_at.is_some() && row.parent_cap.is_none() {
                "exchanged" // root token: consumed at WS attach
            } else {
                "active"
            };

            json!({
                "hop":          i,
                "id":           row.id,
                "actor_id":     row.actor_id,
                "actor_name":   actor_name,
                "session_id":   row.session_id,
                "permissions":  perms,
                "permissions_label": if perms.is_empty() { "all tools" } else { "restricted" },
                "observed_seq": row.observed_seq,
                "is_root":      row.parent_cap.is_none(),
                "is_leaf":      i + 1 == chain.len(),
                "status":       status,
                "issued_at":    row.created_at,
                "used_at":      row.used_at,
                "expires_at":   row.expires_at,
            })
        })
        .collect();

    Json(json!({
        "cap_id":   q.cap_id,
        "depth":    chain.len(),
        "chain":    chain_json,
    }))
    .into_response()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn membership_json(m: &db::sessions::MembershipRow) -> Value {
    json!({
        "role":        m.role,
        "can_approve": matches!(m.role.as_str(), "owner" | "collaborator"),
        "can_write":   matches!(m.role.as_str(), "owner" | "collaborator"),
        "joined_at":   m.joined_at,
        "detached":    m.detached_at.is_some(),
    })
}

/// Whether a set of cap tool permissions covers operations on a given entity type.
///
/// An empty permissions list means "all tools" — covers everything.
/// A non-empty list is checked against the tool prefixes associated with the entity.
/// This is a heuristic for the explanatory layer; it is NOT an enforcement check.
fn entity_permissions_match(perms: &[String], entity_uri: &str) -> bool {
    if perms.is_empty() {
        return true; // all-tools cap covers everything
    }
    // Infer relevant tool prefix from entity type
    let relevant_prefix = entity_uri.split('/').next().unwrap_or("");
    let relevant_keywords: &[&str] = match relevant_prefix {
        "artifact" => &[
            "artifact",
            "write_artifact",
            "read_artifact",
            "create_artifact",
        ],
        "approval" => &["approval", "vote", "create_approval", "claim_approval"],
        "context" => &["context", "add_context", "resolve_context"],
        "session" => &["session"],
        "cap" => &["cap", "delegate"],
        "actor" => &["actor"],
        _ => &[],
    };
    // Check if any of the cap's permissions contain a relevant keyword
    perms
        .iter()
        .any(|p| relevant_keywords.iter().any(|k| p.contains(k)))
}
