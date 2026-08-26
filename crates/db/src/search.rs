//! Cross-session search. Sessions/artifacts/events/actors are all scoped to
//! the caller's own membership — sessions/artifacts/events to the same
//! visibility boundary `GET /api/activity` already uses (see
//! routes/activity.rs), actors to the same co-membership boundary as the
//! Teammates directory (see `actors::list_teammates`). Actor search used
//! to be a deliberately global lookup ("a quick-jump find-someone-by-name
//! search is a different use case than a standing directory"), but that's
//! the same reasoning Teammates itself used to have before it was scoped
//! down — identity isn't confidential in the abstract, but a consistent
//! security boundary matters more than the theoretical convenience of a
//! global directory, so search now draws the same line Teammates does.
//!
//! `search_events`/`search_artifacts` use the `search_vector` generated
//! tsvector columns (migration 037) instead of `::text ILIKE '%q%'` /
//! `name ILIKE ... OR storage_ref ILIKE ...` — same fields, indexed and
//! word-aware instead of an unindexed substring scan. `search_sessions`/
//! `search_actors` stay on plain `ILIKE`: both tables are inherently small
//! (one row per session/actor, not per event), so there's no query-latency
//! case for a tsvector index there yet.
//!
//! `free_text: Option<&str>` (not a possibly-empty `&str`) throughout: the
//! caller (`routes/search.rs`'s structured-filter parser) only passes
//! `Some` when there's an actual free-text remainder after `type:`/
//! `session:`/`actor:` filters are stripped out. A bare `type:artifact`
//! query has no free text at all, and `websearch_to_tsquery('english', "")`
//! produces an empty tsquery that matches nothing via `@@` — passing `NULL`
//! and short-circuiting in SQL avoids that trap entirely rather than
//! special-casing an empty string.

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

/// `session_ids` is already narrowed to whatever a `session:` filter
/// matched (see routes/search.rs) — `free_text` here only ever further
/// filters *within* that set by name/description, same as before.
pub async fn search_sessions(
    pool: &PgPool,
    session_ids: &[String],
    free_text: Option<&str>,
    limit: i64,
) -> DbResult<Vec<SessionHit>> {
    if session_ids.is_empty() {
        return Ok(vec![]);
    }
    let pat = free_text.map(|q| format!("%{q}%"));
    sqlx::query_as::<_, SessionHit>(
        "SELECT id, name, description, status, created_by
         FROM sessions
         WHERE id = ANY($1)
           AND ($2::text IS NULL OR name ILIKE $2 OR description ILIKE $2)
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

/// `type_filter` matches artifacts.type exactly (a structured `type:`
/// filter, not a text search term). `actor_ids` — already resolved from an
/// `actor:` filter's name match, see routes/search.rs — narrows to
/// artifacts created by one of those actors; `None` means no actor filter
/// was given, not "matches nobody".
pub async fn search_artifacts(
    pool: &PgPool,
    session_ids: &[String],
    free_text: Option<&str>,
    type_filter: Option<&str>,
    actor_ids: Option<&[String]>,
    limit: i64,
) -> DbResult<Vec<ArtifactHit>> {
    if session_ids.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as::<_, ArtifactHit>(
        "SELECT id, session_id, name, type, created_by
         FROM artifacts
         WHERE session_id = ANY($1)
           AND ($2::text IS NULL OR search_vector @@ websearch_to_tsquery('english', $2))
           AND ($3::text IS NULL OR type = $3)
           AND ($4::text[] IS NULL OR created_by = ANY($4))
         ORDER BY
           CASE WHEN $2::text IS NOT NULL
                THEN ts_rank(search_vector, websearch_to_tsquery('english', $2))
           END DESC NULLS LAST,
           updated_at DESC
         LIMIT $5",
    )
    .bind(session_ids)
    .bind(free_text)
    .bind(type_filter)
    .bind(actor_ids)
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
    pool: &PgPool,
    viewer_actor_id: &str,
    q: &str,
    limit: i64,
) -> DbResult<Vec<ActorHit>> {
    let pat = format!("%{q}%");
    sqlx::query_as::<_, ActorHit>(
        // Same gate as `list_actors_of_type` in `db::actors` -- a
        // `session_memberships` row exists from the moment an attach cap is
        // minted, before an agent has ever actually run. Without this, a
        // never-attached (or crashed-before-attaching) agent is fully
        // searchable as if it were a real session participant. Humans
        // aren't gated the same way -- an invited-but-not-yet-logged-in
        // human legitimately belongs in search.
        "WITH agent_real_joins AS (
            SELECT DISTINCT session_id, actor_id FROM events WHERE type = 'actor.joined'
         )
         SELECT a.id, a.name, a.email, a.type
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
                     AND (a.type != 'agent' OR EXISTS (
                         SELECT 1 FROM agent_real_joins j WHERE j.session_id = their_sm.session_id AND j.actor_id = a.id
                     ))
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

/// Matches on the `search_vector` generated tsvector (migration 037), built
/// from the raw JSON payload text — covers message content, context
/// entries, tool-call arguments, approval tool names, all in one query
/// rather than a dedicated query per event kind, same scope the old
/// `payload::text ILIKE '%q%'` had. `type_filter`/`actor_ids` are
/// structured `type:`/`actor:` filters (see routes/search.rs) — exact
/// match, not text search.
///
/// One known residual gap, not fixed here: a filter-only query (`type:`
/// with no free text, so `free_text` is `None`) skips the `search_vector
/// @@ ...` clause entirely and falls back to `WHERE session_id = ANY($1)
/// AND type = $3 ORDER BY timestamp DESC LIMIT $5` — the same
/// scan-then-sort shape `list_recent_across_sessions` had before its
/// LATERAL rewrite, just usually narrower thanks to the type filter. Worth
/// the same LATERAL treatment if a pure-filter search ever shows up in
/// query latency; not applied speculatively here.
pub async fn search_events(
    pool: &PgPool,
    session_ids: &[String],
    free_text: Option<&str>,
    type_filter: Option<&str>,
    actor_ids: Option<&[String]>,
    limit: i64,
) -> DbResult<Vec<EventHit>> {
    if session_ids.is_empty() {
        return Ok(vec![]);
    }
    sqlx::query_as::<_, EventHit>(
        "SELECT id, session_id, actor_id, type, payload, timestamp
         FROM events
         WHERE session_id = ANY($1)
           AND ($2::text IS NULL OR search_vector @@ websearch_to_tsquery('english', $2))
           AND ($3::text IS NULL OR type = $3)
           AND ($4::text[] IS NULL OR actor_id = ANY($4))
         ORDER BY
           CASE WHEN $2::text IS NOT NULL
                THEN ts_rank(search_vector, websearch_to_tsquery('english', $2))
           END DESC NULLS LAST,
           timestamp DESC
         LIMIT $5",
    )
    .bind(session_ids)
    .bind(free_text)
    .bind(type_filter)
    .bind(actor_ids)
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
