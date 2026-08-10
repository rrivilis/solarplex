//! Cross-session approval delegation — the durable, mutable counterpart to
//! `crates/session`'s pure saga bookkeeping. See migration 028 and
//! `SessionEvent::CrossSessionDelegation{Requested,Received,Resolved}`'s doc
//! comments for the full design: B's decision is a completely normal
//! `ApprovalRequest`, decided via B's own `approval_policy` unchanged; this
//! table just tracks the source↔target mapping and the saga id that
//! threads the two together.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CrossSessionDelegationRow {
    pub saga_id: String,
    pub source_session_id: String,
    pub source_approval_id: String,
    pub target_session_id: String,
    pub target_approval_id: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
}

pub async fn insert(
    pool: &PgPool,
    saga_id: &str,
    source_session_id: &str,
    source_approval_id: &str,
    target_session_id: &str,
) -> DbResult<CrossSessionDelegationRow> {
    sqlx::query_as::<_, CrossSessionDelegationRow>(
        "INSERT INTO cross_session_delegations
            (saga_id, source_session_id, source_approval_id, target_session_id)
         VALUES ($1, $2, $3, $4)
         RETURNING saga_id, source_session_id, source_approval_id, target_session_id,
                   target_approval_id, status, created_at",
    )
    .bind(saga_id)
    .bind(source_session_id)
    .bind(source_approval_id)
    .bind(target_session_id)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Filled in once the Step bundle lands and the real local approval exists
/// in the target session — see the module doc comment for why this can't
/// happen inside the pure session-crate transition.
pub async fn set_target_approval_id(
    pool: &PgPool,
    saga_id: &str,
    target_approval_id: &str,
) -> DbResult<CrossSessionDelegationRow> {
    sqlx::query_as::<_, CrossSessionDelegationRow>(
        "UPDATE cross_session_delegations SET target_approval_id = $2
         WHERE saga_id = $1
         RETURNING saga_id, source_session_id, source_approval_id, target_session_id,
                   target_approval_id, status, created_at",
    )
    .bind(saga_id)
    .bind(target_approval_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Looked up from B's approval-resolution hook (`ws.rs::handle_vote`) —
/// `target_approval_id` is the only thing B's own code knows at that point.
pub async fn get_by_target_approval(
    pool: &PgPool,
    target_approval_id: &str,
) -> DbResult<Option<CrossSessionDelegationRow>> {
    sqlx::query_as::<_, CrossSessionDelegationRow>(
        "SELECT saga_id, source_session_id, source_approval_id, target_session_id,
                target_approval_id, status, created_at
         FROM cross_session_delegations
         WHERE target_approval_id = $1 AND status = 'pending'",
    )
    .bind(target_approval_id)
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

pub async fn mark_resolved(pool: &PgPool, saga_id: &str) -> DbResult<()> {
    sqlx::query("UPDATE cross_session_delegations SET status = 'resolved' WHERE saga_id = $1")
        .bind(saga_id)
        .execute(pool)
        .await?;
    Ok(())
}
