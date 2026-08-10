//! Connection audit trail — see migration 033's doc comment for why this is
//! a separate table from `events`: connection lifecycle (routine reconnects
//! included) needs to stay queryable without ever competing with real
//! session content for a seq number or a spot in the Activity Log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ConnectionEventRow {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    pub event: String, // "connected" | "disconnected"
    pub at: DateTime<Utc>,
}

pub async fn record(pool: &PgPool, session_id: &str, actor_id: &str, event: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO session_connections (id, session_id, actor_id, event)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(Ulid::new().to_string())
    .bind(session_id)
    .bind(actor_id)
    .bind(event)
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub async fn list_for_session(
    pool: &PgPool, session_id: &str, limit: i64,
) -> DbResult<Vec<ConnectionEventRow>> {
    sqlx::query_as::<_, ConnectionEventRow>(
        "SELECT id, session_id, actor_id, event, at
         FROM session_connections
         WHERE session_id = $1
         ORDER BY at DESC
         LIMIT $2",
    )
    .bind(session_id)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
