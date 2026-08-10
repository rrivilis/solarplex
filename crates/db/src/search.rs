//! Cross-session search — v1, minimal-friction: plain `ILIKE`, no tsvector/
//! ranking. Sessions/artifacts/events/actors are all scoped to the
//! caller's own membership — sessions/artifacts/events to the same
//! visibility boundary `GET /api/activity` already uses (see
//! routes/activity.rs), actors to the same co-membership boundary as the
//! Teammates directory (see `actors::list_teammates`). Actor search used
//! to be a deliberately global lookup ("a quick-jump find-someone-by-name
//! search is a different use case than a standing directory"), but that's
//! the same reasoning Teammates itself used to have before it was scoped
//! down — identity isn't confidential in the abstract, but a consistent
//! security boundary matters more than the theoretical convenience of a
//! global directory, so search now draws the same line Teammates does.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct SessionHit {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub created_by: String,
}

pub async fn search_sessions(
    pool: &PgPool, session_ids: &[String], q: &str, limit: i64,
) -> DbResult<Vec<SessionHit>> {
    if session_ids.is_empty() { return Ok(vec![]); }
    let pat = format!("%{q}%");
    sqlx::query_as::<_, SessionHit>(
        "SELECT id, name, description, status, created_by
         FROM sessions
         WHERE id = ANY($1) AND (name ILIKE $2 OR description ILIKE $2)
         ORDER BY updated_at DESC
         LIMIT $3",
    )
    .bind(session_ids)
    .bind(&pat)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ArtifactHit {
    pub id: String,
    pub session_id: String,
    pub name: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub created_by: String,
}

pub async fn search_artifacts(
    pool: &PgPool, session_ids: &[String], q: &str, limit: i64,
) -> DbResult<Vec<ArtifactHit>> {
    if session_ids.is_empty() { return Ok(vec![]); }
    let pat = format!("%{q}%");
    sqlx::query_as::<_, ArtifactHit>(
        "SELECT id, session_id, name, type, created_by
         FROM artifacts
         WHERE session_id = ANY($1) AND (name ILIKE $2 OR storage_ref ILIKE $2)
         ORDER BY updated_at DESC
         LIMIT $3",
    )
    .bind(session_ids)
    .bind(&pat)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct ActorHit {
    pub id: String,
    pub name: String,
    pub email: Option<String>,
    #[sqlx(rename = "type")]
    pub r#type: String,
}

/// Scoped to the viewer's own co-membership network — same boundary and
/// same self-join shape as `actors::list_teammates`, except this also
/// includes agents (Teammates is human-only by design; an agent attached
/// to one of your own sessions is exactly the kind of thing a "find
/// someone/something by name" search should surface, unlike Teammates'
/// narrower "human collaborators" concept).
pub async fn search_actors(
    pool: &PgPool, viewer_actor_id: &str, q: &str, limit: i64,
) -> DbResult<Vec<ActorHit>> {
    let pat = format!("%{q}%");
    sqlx::query_as::<_, ActorHit>(
        "SELECT a.id, a.name, a.email, a.type
         FROM actors a
         WHERE (a.name ILIKE $2 OR a.email ILIKE $2)
           AND (
               a.id = $1
               OR EXISTS (
                   SELECT 1 FROM session_memberships my_sm
                   JOIN session_memberships their_sm
                     ON their_sm.session_id = my_sm.session_id
                   WHERE my_sm.actor_id = $1
                     AND my_sm.detached_at IS NULL
                     AND their_sm.actor_id = a.id
                     AND their_sm.detached_at IS NULL
               )
           )
         ORDER BY a.name
         LIMIT $3",
    )
    .bind(viewer_actor_id)
    .bind(&pat)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct EventHit {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub payload: serde_json::Value,
    pub timestamp: DateTime<Utc>,
}

/// Matches on the raw JSON payload text — covers message content, context
/// entries, tool-call arguments, approval tool names, all in one query
/// rather than a dedicated query per event kind. Good enough for v1 at this
/// scale; a real tsvector index is the natural upgrade if payloads get big
/// or session counts get large enough for `::text ILIKE` to show up in
/// query latency.
pub async fn search_events(
    pool: &PgPool, session_ids: &[String], q: &str, limit: i64,
) -> DbResult<Vec<EventHit>> {
    if session_ids.is_empty() { return Ok(vec![]); }
    let pat = format!("%{q}%");
    sqlx::query_as::<_, EventHit>(
        "SELECT id, session_id, actor_id, type, payload, timestamp
         FROM events
         WHERE session_id = ANY($1) AND payload::text ILIKE $2
         ORDER BY timestamp DESC
         LIMIT $3",
    )
    .bind(session_ids)
    .bind(&pat)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
