use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Row, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApprovalRow {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub state: String,
    pub votes: serde_json::Value,
    pub resolved_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub timeout_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
    // Ring-2 scout fields — added by migration 016.
    // #[sqlx(default)] makes them Optional[None] when the SELECT column list
    // doesn't include them (backward-compat with all existing queries).
    #[sqlx(default)]
    pub scout_manifest: Option<serde_json::Value>,
    #[sqlx(default)]
    pub execution_manifest: Option<serde_json::Value>,
    #[sqlx(default)]
    pub manifest_diverged: Option<bool>,
    /// Declared effects derived from scout manifest; stored before human votes.
    /// The Ring-2 executor derives its sandbox policy exclusively from this field.
    #[sqlx(default)]
    pub declared_effects: Option<serde_json::Value>,
}

pub struct CreateApproval {
    pub session_id: String,
    pub actor_id: String,
    pub tool_name: String,
    pub arguments: serde_json::Value,
    pub timeout_at: Option<DateTime<Utc>>,
}

pub async fn create(pool: &PgPool, input: CreateApproval) -> DbResult<ApprovalRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, ApprovalRow>(
        "INSERT INTO approval_requests (id, session_id, actor_id, tool_name, arguments, timeout_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(&id)
    .bind(&input.session_id)
    .bind(&input.actor_id)
    .bind(&input.tool_name)
    .bind(&input.arguments)
    .bind(input.timeout_at)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at
         FROM approval_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Like `get` but also SELECTs the Ring-2 declared_effects column.
/// Used by the guardian fetch endpoint to return sandbox policy alongside the decision.
pub async fn get_with_effects(pool: &PgPool, id: &str) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by,
                created_at, timeout_at, resolved_at, declared_effects
         FROM approval_requests WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn list_pending(pool: &PgPool, session_id: &str) -> DbResult<Vec<ApprovalRow>> {
    sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at
         FROM approval_requests
         WHERE session_id = $1 AND state IN ('Pending', 'Claimed', 'Contested')
         ORDER BY created_at ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn list_pending_for_actor(pool: &PgPool, actor_id: &str) -> DbResult<Vec<ApprovalRow>> {
    sqlx::query_as::<_, ApprovalRow>(
        "SELECT id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at
         FROM approval_requests
         WHERE actor_id = $1 AND state IN ('Pending', 'Claimed', 'Contested')
         ORDER BY created_at ASC",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn set_state(pool: &PgPool, id: &str, state: &str) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests SET state = $1
         WHERE id = $2
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(state)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn record_vote(pool: &PgPool, id: &str, voter_id: &str, vote: &str) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET votes = jsonb_set(votes, ARRAY[$1], to_jsonb($2::text))
         WHERE id = $3
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(voter_id)
    .bind(vote)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn resolve(pool: &PgPool, id: &str, state: &str, resolved_by: &str) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET state = $1, resolved_by = $2, resolved_at = now()
         WHERE id = $3
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(state)
    .bind(resolved_by)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

// ── Transaction-aware variants ────────────────────────────────────────────────

/// Claim an approval, but only if its current state is 'Pending' (CAS).
/// Returns `DbError::NotFound` if already claimed/resolved — caller should
/// surface this as a conflict rather than an error.
pub async fn claim_if_pending_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    claimer_id: &str,
) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET state = 'Claimed'
         WHERE id = $1 AND state = 'Pending'
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(id)
    .bind(claimer_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn set_state_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    state: &str,
) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests SET state = $1
         WHERE id = $2
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(state)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn resolve_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    state: &str,
    resolved_by: &str,
) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET state = $1, resolved_by = $2, resolved_at = now()
         WHERE id = $3
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(state)
    .bind(resolved_by)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)
}

/// Atomic CAS resolve, used by the cross-session delegation path: a saga Ack
/// arriving from B must not blindly overwrite A's approval if it's no longer
/// `Pending` (already resolved by a direct vote, cancelled, or expired while
/// the delegation was in flight) — same commit-barrier discipline as Ring-0's
/// `expected_hash_before` CAS, just keyed on `state` instead of a content
/// hash. Returns `Ok(None)` (not an error) when the row wasn't `Pending` —
/// the caller treats a stale/late Ack as a no-op, not a failure.
pub async fn resolve_if_pending_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    state: &str,
    resolved_by: &str,
) -> DbResult<Option<ApprovalRow>> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET state = $1, resolved_by = $2, resolved_at = now()
         WHERE id = $3 AND state = 'Pending'
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(state)
    .bind(resolved_by)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(DbError::from)
}

pub async fn record_vote_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    voter_id: &str,
    vote: &str,
) -> DbResult<ApprovalRow> {
    sqlx::query_as::<_, ApprovalRow>(
        "UPDATE approval_requests
         SET votes = jsonb_set(votes, ARRAY[$1], to_jsonb($2::text))
         WHERE id = $3
         RETURNING id, session_id, actor_id, tool_name, arguments, state, votes, resolved_by, created_at, timeout_at, resolved_at",
    )
    .bind(voter_id)
    .bind(vote)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn insert_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    id: &str,
    session_id: &str,
    actor_id: &str,
    tool_name: &str,
    arguments: &serde_json::Value,
    timeout_at: Option<DateTime<Utc>>,
) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO approval_requests
             (id, session_id, actor_id, tool_name, arguments, timeout_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(session_id)
    .bind(actor_id)
    .bind(tool_name)
    .bind(arguments)
    .bind(timeout_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Expire approvals whose timeout_at has passed. Returns expired IDs.
pub async fn expire_timed_out(pool: &PgPool) -> DbResult<Vec<String>> {
    let rows = sqlx::query(
        "UPDATE approval_requests
         SET state = 'Expired', resolved_at = now()
         WHERE state IN ('Pending', 'Claimed', 'Contested')
           AND timeout_at IS NOT NULL
           AND timeout_at < now()
         RETURNING id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("id")).collect())
}

// ── Ring-2 scout manifest storage ─────────────────────────────────────────────

/// Store the runahead scout's pre-execution effect manifest for an approval.
/// Called by the sidecar when the scout finishes (typically during approval wait).
pub async fn set_scout_manifest(
    pool:        &PgPool,
    id:          &str,
    manifest:    &serde_json::Value,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE approval_requests SET scout_manifest = $1 WHERE id = $2",
    )
    .bind(manifest)
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

/// Store declared effects derived from the scout manifest.
/// Called immediately after `set_scout_manifest` so the human sees the sandbox
/// policy alongside the scout prediction before voting.
pub async fn set_declared_effects(
    pool:    &PgPool,
    id:      &str,
    effects: &serde_json::Value,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE approval_requests SET declared_effects = $1 WHERE id = $2",
    )
    .bind(effects)
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}

/// Store the post-execution manifest and divergence flag for an approval.
/// Called by the sidecar after the upstream tool returns.
/// `diverged = true` is a Ring-2 security event (execution ≠ scout prediction).
pub async fn set_execution_manifest(
    pool:        &PgPool,
    id:          &str,
    manifest:    &serde_json::Value,
    diverged:    bool,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE approval_requests
         SET execution_manifest = $1, manifest_diverged = $2
         WHERE id = $3",
    )
    .bind(manifest)
    .bind(diverged)
    .bind(id)
    .execute(pool)
    .await
    .map(|_| ())
    .map_err(DbError::from)
}
