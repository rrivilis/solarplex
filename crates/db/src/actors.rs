use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ActorRow {
    pub id: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub name: String,
    pub email: Option<String>,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub config: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

pub struct CreateHuman {
    pub name: String,
    pub email: String,
}

pub struct CreateAgent {
    pub name: String,
    pub provider: String,
    pub model: String,
    pub config: Option<serde_json::Value>,
}

pub async fn create_human(pool: &PgPool, input: CreateHuman) -> DbResult<ActorRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name, email)
         VALUES ($1, 'human', $2, $3)
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(&id)
    .bind(&input.name)
    .bind(&input.email)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn create_agent(pool: &PgPool, input: CreateAgent) -> DbResult<ActorRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name, provider, model, config)
         VALUES ($1, 'agent', $2, $3, $4, $5)
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(&id)
    .bind(&input.name)
    .bind(&input.provider)
    .bind(&input.model)
    .bind(&input.config)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Upsert a human actor by id, **overwriting** any existing name. Only
/// correct for a call site where the caller actually intends a rename —
/// today that's exactly one place, `PATCH /auth/me`. Every other call used
/// to reach for this for ordinary "register on first use" and quietly
/// clobbered a real chosen name back to the actor's own raw id on every
/// subsequent invite redemption, session creation, or reattach (they all
/// pass `actor_id` as both id and name) — see `ensure_human` for that case.
pub async fn upsert_human(pool: &PgPool, id: &str, name: &str) -> DbResult<ActorRow> {
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name)
         VALUES ($1, 'human', $2)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Register a human actor if this id has never been seen before; a true
/// no-op otherwise. An already-registered actor's name (real OIDC name,
/// or a rename via `PATCH /auth/me`) is never touched. Use this, not
/// `upsert_human`, for every "make sure this actor exists" call site that
/// isn't itself the rename endpoint. `name` here is only ever a fallback
/// for a genuinely new row.
pub async fn ensure_human(pool: &PgPool, id: &str, name: &str) -> DbResult<ActorRow> {
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name)
         VALUES ($1, 'human', $2)
         ON CONFLICT (id) DO UPDATE SET name = actors.name
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Upsert an agent actor by id, overwriting any existing name/type. See
/// `upsert_human`'s doc comment; same caveat, no current caller actually
/// wants this for "register on first use".
pub async fn upsert_agent(pool: &PgPool, id: &str, name: &str) -> DbResult<ActorRow> {
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name)
         VALUES ($1, 'agent', $2)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, type = EXCLUDED.type
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// `ensure_human`'s agent counterpart — register if new, no-op if not.
pub async fn ensure_agent(pool: &PgPool, id: &str, name: &str) -> DbResult<ActorRow> {
    sqlx::query_as::<_, ActorRow>(
        "INSERT INTO actors (id, type, name)
         VALUES ($1, 'agent', $2)
         ON CONFLICT (id) DO UPDATE SET name = actors.name
         RETURNING id, type, name, email, provider, model, config, created_at",
    )
    .bind(id)
    .bind(name)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Fetch multiple actors by id in a single query.
/// Returns a map of `id → ActorRow` for O(1) lookup when stitching query results.
/// Missing ids are silently omitted (actor may have been deleted).
pub async fn get_many(pool: &PgPool, ids: &[String]) -> DbResult<std::collections::HashMap<String, ActorRow>> {
    if ids.is_empty() { return Ok(Default::default()); }
    let rows = sqlx::query_as::<_, ActorRow>(
        "SELECT id, type, name, email, provider, model, config, created_at
         FROM actors WHERE id = ANY($1)",
    )
    .bind(ids)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows.into_iter().map(|r| (r.id.clone(), r)).collect())
}

/// Resolve a human actor by their OIDC-verified email, if one is on record.
/// Used to decide whether an invite's `invitee_email` already has an actor
/// to route a mailbox entry to at invite-creation time.
pub async fn find_by_email(pool: &PgPool, email: &str) -> DbResult<Option<String>> {
    sqlx::query_scalar::<_, String>(
        "SELECT id FROM actors WHERE email = $1 AND type = 'human' LIMIT 1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}

#[derive(Debug, Clone, Serialize, FromRow)]
pub struct TeammateRow {
    pub id: String,
    pub name: String,
    // `skip_serializing`, not removed outright: `routes/intent.rs`'s
    // @mention name-resolution still reads this field server-side, to
    // prefill the Invite modal's email input once you've specifically
    // typed a co-member's name — a targeted, opt-in-by-typing-their-name
    // action, not a passive listing. The two `/team` and `/agents`
    // directory *endpoints* (routes/team.rs, routes/agents.rs) both
    // serialize `TeammateRow` straight to JSON, so this is also the only
    // place that needs to change to keep email out of a co-membership
    // directory nobody consented to appearing in. Reinstate serialization
    // only alongside an actual opt-in (e.g. a per-actor visibility flag).
    #[serde(skip_serializing)]
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Sessions with a live (non-detached) membership row.
    pub session_count: i64,
    /// Distinct roles held across any of those sessions — a directory-level
    /// summary, not a claim about which role applies to which session. Real
    /// per-session role management is v2 (needs a workspace-level default-
    /// role concept that doesn't exist yet — roles today are purely
    /// per-session-membership).
    pub roles: Vec<String>,
    /// Most recent event timestamp attributed to this actor, across every
    /// session — the closest proxy to "last seen" the event log can give
    /// without a dedicated presence/heartbeat table.
    pub last_active_at: Option<DateTime<Utc>>,
}

/// Member directory scoped to the viewer's own network: themselves, plus
/// every human who currently shares an active session membership with
/// them. Originally this was workspace-wide (every human actor, no
/// scoping at all) — reasonable-sounding in the abstract ("identity isn't
/// session-confidential"), but in practice it dumped every throwaway
/// test-fixture actor (proptest/e2e human rows with `@example.invalid`
/// emails) into a real user's directory alongside people they'd actually
/// worked with, with no way to tell them apart. Scoping to "people I share
/// a session with" is both more useful and a much smaller, more sensible
/// blast radius for what "identity isn't confidential" actually needs to
/// mean here.
pub async fn list_teammates(pool: &PgPool, viewer_actor_id: &str) -> DbResult<Vec<TeammateRow>> {
    list_actors_of_type(pool, viewer_actor_id, "human").await
}

/// Same directory, same co-membership boundary, `a.type = 'agent'` instead
/// of `'human'` — the Agents page's read-only counterpart to Teammates
/// (see `routes/agents.rs`). Shares `TeammateRow`'s shape rather than a
/// parallel struct: session_count/roles/last_active_at mean exactly the
/// same thing for an agent actor as a human one.
pub async fn list_agent_directory(pool: &PgPool, viewer_actor_id: &str) -> DbResult<Vec<TeammateRow>> {
    list_actors_of_type(pool, viewer_actor_id, "agent").await
}

async fn list_actors_of_type(pool: &PgPool, viewer_actor_id: &str, actor_type: &str) -> DbResult<Vec<TeammateRow>> {
    sqlx::query_as::<_, TeammateRow>(
        // `session_memberships` gets a row the instant a Collaborator mints
        // an attach cap (`issue_attach_token`), before the agent process
        // has ever run, let alone connected. Left ungated, a minted-but-
        // never-attached (or crashed-before-attaching) agent shows up here
        // as a full "1 session" participant next to "never active", which
        // is exactly backwards. The membership row means "authorized",
        // not "showed up". `agent_real_joins` is the actual attach signal:
        // a real `actor.joined` event only exists once `agent_attach`
        // genuinely ran. Humans are deliberately not gated the same way.
        // An invited-but-not-yet-logged-in human legitimately belongs in a
        // membership directory; a never-attached agent doesn't.
        //
        // `human_real_auth` is a separate gate, for a separate problem: a
        // human actor row can exist — and hold a real session membership —
        // without ever having proven who they are. The anonymous
        // join_token path (`ws.rs::handle_ws`) upserts a bare actor row
        // for whatever name the caller picks the moment they connect, no
        // OIDC round trip involved. That's a deliberate, permissive
        // guest-link design (see threat-model.md), but it means co-
        // membership alone — the scoping this query already does, see the
        // doc comment above — isn't enough to keep an unverified guest
        // name out of a real user's contact directory. `human_sessions`
        // only ever gets a row from a completed OIDC callback, so "has one"
        // is exactly "has provenance." Agents authenticate a different way
        // entirely (caps, not OIDC) so this gate doesn't apply to them.
        "WITH agent_real_joins AS (
            SELECT DISTINCT session_id, actor_id FROM events WHERE type = 'actor.joined'
         ),
         human_real_auth AS (
            SELECT DISTINCT actor_id FROM human_sessions
         )
         SELECT
            a.id, a.name, a.email, a.created_at,
            COUNT(DISTINCT sm.session_id) FILTER (
                WHERE sm.detached_at IS NULL
                  AND (a.type != 'agent' OR EXISTS (
                      SELECT 1 FROM agent_real_joins j WHERE j.session_id = sm.session_id AND j.actor_id = a.id
                  ))
            ) AS session_count,
            COALESCE(
                ARRAY_AGG(DISTINCT sm.role) FILTER (
                    WHERE sm.detached_at IS NULL AND sm.role IS NOT NULL
                      AND (a.type != 'agent' OR EXISTS (
                          SELECT 1 FROM agent_real_joins j WHERE j.session_id = sm.session_id AND j.actor_id = a.id
                      ))
                ),
                ARRAY[]::TEXT[]
            ) AS roles,
            MAX(e.timestamp) AS last_active_at
         FROM actors a
         LEFT JOIN session_memberships sm ON sm.actor_id = a.id
         LEFT JOIN events e ON e.actor_id = a.id
         WHERE a.type = $2
           AND (a.type != 'human' OR EXISTS (
               SELECT 1 FROM human_real_auth h WHERE h.actor_id = a.id
           ))
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
         GROUP BY a.id
         ORDER BY last_active_at DESC NULLS LAST, a.name",
    )
    .bind(viewer_actor_id)
    .bind(actor_type)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<ActorRow> {
    sqlx::query_as::<_, ActorRow>(
        "SELECT id, type, name, email, provider, model, config, created_at
         FROM actors WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}
