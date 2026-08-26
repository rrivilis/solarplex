//! MCP method registry — the typed object namespace for the ORB layer.
//!
//! Each sidecar registers its tool manifest at attach time via
//! `POST /api/sessions/:id/methods`.  The server records the manifest here and
//! validates method addresses in cap permissions against it.
//!
//! Method address format: `"mcp.{server_slug}.{method_name}"`
//! - `server_slug`: normalized (lowercase, non-alphanumeric → `_`) actor_id
//! - `method_name`: the MCP tool name as returned by `tools/list`
//!
//! This makes cap permissions typed references into the ORB's object namespace
//! rather than free strings.  Attenuation in the cap DAG applies to addresses:
//! a delegate cannot hold an address its parent does not hold.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use ulid::Ulid;

use crate::{DbError, DbResult};

// ── Row type ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct MethodRow {
    pub id: String,
    pub session_id: String,
    pub server_slug: String,
    pub method_name: String,
    /// Full typed address: `"mcp.{server_slug}.{method_name}"`.
    pub address: String,
    pub arg_schema: serde_json::Value,
    pub description: Option<String>,
    /// When `false` the server auto-approves invocations without a human gate.
    pub requires_approval: bool,
    pub registered_at: DateTime<Utc>,
}

// ── Input type (from sidecar registration payload) ────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodDef {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: serde_json::Value,
    /// Mirrors the sidecar's legacy `auto_approve` list: `false` = no gate.
    #[serde(default = "default_requires_approval")]
    pub requires_approval: bool,
}

fn default_requires_approval() -> bool {
    true
}

// ── Address helpers ───────────────────────────────────────────────────────────

/// Normalize an actor_id into a stable method-address segment.
///
/// Lowercase, non-alphanumeric characters replaced with `_`.  This keeps
/// method addresses URL-safe and predictable regardless of actor naming
/// conventions.
pub fn actor_id_to_slug(actor_id: &str) -> String {
    actor_id
        .to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Build the canonical method address for a (slug, method_name) pair.
pub fn method_address(server_slug: &str, method_name: &str) -> String {
    format!("mcp.{server_slug}.{method_name}")
}

// ── Writes ────────────────────────────────────────────────────────────────────

/// Register (or re-register) a batch of methods for a session/actor.
///
/// Idempotent via `ON CONFLICT (session_id, address) DO UPDATE`.  Re-
/// registration updates the schema and approval flag so that sidecar upgrades
/// take effect without a session restart.
pub async fn register_bulk(
    pool: &PgPool,
    session_id: &str,
    server_slug: &str,
    methods: &[MethodDef],
) -> DbResult<usize> {
    let mut registered = 0usize;
    for m in methods {
        let id = Ulid::new().to_string();
        let address = method_address(server_slug, &m.name);
        sqlx::query(
            "INSERT INTO mcp_methods
                 (id, session_id, server_slug, method_name, address,
                  arg_schema, description, requires_approval)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (session_id, address) DO UPDATE
                 SET arg_schema        = EXCLUDED.arg_schema,
                     description       = EXCLUDED.description,
                     requires_approval = EXCLUDED.requires_approval,
                     registered_at     = NOW()",
        )
        .bind(&id)
        .bind(session_id)
        .bind(server_slug)
        .bind(&m.name)
        .bind(&address)
        .bind(&m.input_schema)
        .bind(&m.description)
        .bind(m.requires_approval)
        .execute(pool)
        .await?;
        registered += 1;
    }
    Ok(registered)
}

// ── Reads ─────────────────────────────────────────────────────────────────────

/// Look up a single method by its typed address within a session.
pub async fn get_by_address(
    pool: &PgPool,
    session_id: &str,
    address: &str,
) -> DbResult<Option<MethodRow>> {
    sqlx::query_as::<_, MethodRow>(
        "SELECT id, session_id, server_slug, method_name, address,
                arg_schema, description, requires_approval, registered_at
         FROM mcp_methods
         WHERE session_id = $1 AND address = $2",
    )
    .bind(session_id)
    .bind(address)
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

/// All registered methods for a session, ordered by server_slug + method_name.
pub async fn list_for_session(pool: &PgPool, session_id: &str) -> DbResult<Vec<MethodRow>> {
    sqlx::query_as::<_, MethodRow>(
        "SELECT id, session_id, server_slug, method_name, address,
                arg_schema, description, requires_approval, registered_at
         FROM mcp_methods
         WHERE session_id = $1
         ORDER BY server_slug ASC, method_name ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Check which addresses in `permissions` are NOT registered in this session.
///
/// Used by `AuthorityArena::delegate()` to enforce typed attenuation: you
/// cannot delegate an address that isn't registered, because it would be a
/// reference into an empty region of the method namespace.
///
/// Returns the slice of unrecognised addresses (empty = all valid).
pub async fn unknown_addresses(
    pool: &PgPool,
    session_id: &str,
    permissions: &[String],
) -> DbResult<Vec<String>> {
    if permissions.is_empty() {
        return Ok(vec![]);
    }
    // Only validate addresses that look like method addresses (mcp.* prefix).
    // Free strings without the prefix are legacy and pass through unchanged.
    let method_perms: Vec<&str> = permissions
        .iter()
        .filter(|p| p.starts_with("mcp."))
        .map(|s| s.as_str())
        .collect();

    if method_perms.is_empty() {
        return Ok(vec![]);
    }

    let rows = sqlx::query_scalar::<_, String>(
        "SELECT address FROM mcp_methods
         WHERE session_id = $1 AND address = ANY($2)",
    )
    .bind(session_id)
    .bind(&method_perms)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;

    let known: std::collections::HashSet<&str> = rows.iter().map(|s| s.as_str()).collect();
    Ok(method_perms
        .into_iter()
        .filter(|a| !known.contains(a))
        .map(String::from)
        .collect())
}
