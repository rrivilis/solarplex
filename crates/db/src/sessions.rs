use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{FromRow, PgPool, Postgres, Row, Transaction};
use ulid::Ulid;
use uuid::Uuid;

use protocol::types::MemberRole;

use crate::{tokens, DbError, DbResult};

/// SHA-256 hex of a raw join token.
/// Only the hash is stored in the database; the raw token is shown once at
/// session creation and never persisted, following the API-key pattern.
pub fn token_hash(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Constant-time comparison of a raw join token against a stored hash.
/// Returns `true` only when `sha256(raw) == stored_hash`.
pub fn verify_join_token(raw_provided: &str, stored_hash: &str) -> bool {
    let h = token_hash(raw_provided);
    // Constant-time comparison to prevent timing oracle on hash prefix.
    if h.len() != stored_hash.len() { return false; }
    h.bytes().zip(stored_hash.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// TTL granted to the new owner's root cap on cooperative transfer.
/// Long enough that normal session work isn't interrupted; the operator
/// can always re-issue longer-lived caps if needed.
const DEFAULT_OWNER_TTL_HOURS: i64 = 24;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SessionRow {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub created_by: String,
    pub approval_policy: String,
    // Stored as a SHA-256 hash; never serialized to API callers.
    // The raw token is returned once at session creation via CreateSessionResult.
    #[serde(skip)]
    pub join_token: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Returned only by `create()` — carries the raw join token alongside the session
/// row so the API layer can present it to the caller once. After this call the
/// raw token is gone; only the hash lives in the database.
pub struct CreateSessionResult {
    pub session:        SessionRow,
    pub raw_join_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MembershipRow {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    pub role: String,
    pub escalation_order: Option<i32>,
    pub escalation_timeout: Option<i32>,
    pub joined_at: DateTime<Utc>,
    pub detached_at: Option<DateTime<Utc>>,
}

pub struct CreateSession {
    pub name: String,
    pub description: Option<String>,
    pub created_by: String,
    pub approval_policy: Option<String>,
}

pub async fn create(pool: &PgPool, input: CreateSession) -> DbResult<CreateSessionResult> {
    let session_id    = Ulid::new().to_string();
    let membership_id = Ulid::new().to_string();
    let policy        = input.approval_policy.unwrap_or_else(|| "single_vote".into());
    let raw_join_token = Uuid::new_v4().to_string();
    let join_token_hash = token_hash(&raw_join_token);

    let mut tx = pool.begin().await?;

    let session = sqlx::query_as::<_, SessionRow>(
        "INSERT INTO sessions (id, name, description, created_by, approval_policy, join_token)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, name, description, status, created_by, approval_policy, join_token, created_at, updated_at",
    )
    .bind(&session_id)
    .bind(&input.name)
    .bind(&input.description)
    .bind(&input.created_by)
    .bind(&policy)
    .bind(&join_token_hash)
    .fetch_one(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO session_memberships (id, session_id, actor_id, role) VALUES ($1, $2, $3, 'owner')",
    )
    .bind(&membership_id)
    .bind(&session_id)
    .bind(&input.created_by)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        "INSERT INTO session_sequences (session_id, next_seq) VALUES ($1, 1)",
    )
    .bind(&session_id)
    .execute(&mut *tx)
    .await?;

    // Seed an empty snapshot row (versioned INSERT-only schema from migration 010).
    let snapshot_id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO session_snapshots (id, session_id, seq, state) VALUES ($1, $2, 0, '{}'::jsonb)",
    )
    .bind(&snapshot_id)
    .bind(&session_id)
    .execute(&mut *tx)
    .await?;

    // Seed epoch row (migration 011) — new sessions start at epoch 0.
    sqlx::query(
        "INSERT INTO session_epochs (session_id) VALUES ($1) ON CONFLICT DO NOTHING",
    )
    .bind(&session_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(CreateSessionResult { session, raw_join_token })
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<SessionRow> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT id, name, description, status, created_by, approval_policy, join_token, created_at, updated_at
         FROM sessions WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Computed fresh on every call — see `protocol::types::SessionDigest`'s doc
/// comment for why this is deliberately not a stored/materialized value.
pub async fn compute_digest(pool: &PgPool, session_id: &str) -> DbResult<protocol::types::SessionDigest> {
    let session = get(pool, session_id).await?;

    let recent_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM events WHERE session_id = $1 AND timestamp > now() - interval '24 hours'",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    let open_approvals: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM approval_requests WHERE session_id = $1 AND state IN ('Pending', 'Claimed', 'Contested')",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    let artifacts_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM artifacts WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    let last_activity_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT max(timestamp) FROM events WHERE session_id = $1",
    )
    .bind(session_id)
    .fetch_one(pool)
    .await?;

    Ok(protocol::types::SessionDigest {
        session_id: session_id.to_string(),
        session_name: session.name,
        recent_event_count,
        open_approvals,
        artifacts_count,
        last_activity_at,
    })
}

pub async fn list(pool: &PgPool) -> DbResult<Vec<SessionRow>> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT id, name, description, status, created_by, approval_policy, join_token, created_at, updated_at
         FROM sessions WHERE status != 'archived' ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Mint a fresh raw join token for a session, replacing the stored hash.
///
/// Same one-time-reveal pattern as session creation: only the hash is
/// persisted, the raw value is returned here and never recoverable again.
/// This is the only way to re-establish a usable invite link for a session
/// whose original raw token was never captured by the caller (or has since
/// been rotated) — `SessionRow.join_token` is `#[serde(skip)]`'d specifically
/// so it can't be re-read via a GET, only re-minted via this path.
///
/// Rotating invalidates any previously-issued raw token for this session —
/// an outstanding invite link that hasn't been used yet stops working.
pub async fn regenerate_join_token(pool: &PgPool, session_id: &str) -> DbResult<String> {
    let raw_token = Uuid::new_v4().to_string();
    let hash = token_hash(&raw_token);
    let updated = sqlx::query("UPDATE sessions SET join_token = $1, updated_at = now() WHERE id = $2")
        .bind(&hash)
        .bind(session_id)
        .execute(pool)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(raw_token)
}

/// Returns only sessions where `actor_id` has a membership row.
/// This is the default view for the session list — you see only sessions you're in.
pub async fn list_by_actor(pool: &PgPool, actor_id: &str) -> DbResult<Vec<SessionRow>> {
    sqlx::query_as::<_, SessionRow>(
        "SELECT s.id, s.name, s.description, s.status, s.created_by, s.approval_policy,
                s.join_token, s.created_at, s.updated_at
         FROM sessions s
         INNER JOIN session_memberships sm ON sm.session_id = s.id
         WHERE sm.actor_id = $1 AND s.status != 'archived'
         ORDER BY s.created_at DESC",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn update_status(pool: &PgPool, id: &str, status: &str) -> DbResult<SessionRow> {
    sqlx::query_as::<_, SessionRow>(
        "UPDATE sessions SET status = $1, updated_at = now()
         WHERE id = $2
         RETURNING id, name, description, status, created_by, approval_policy, join_token, created_at, updated_at",
    )
    .bind(status)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Rename a session — name is editable state; ULID stays stable.
/// Returns the updated row so callers can reflect the new name immediately.
pub async fn rename(pool: &PgPool, id: &str, new_name: &str) -> DbResult<SessionRow> {
    sqlx::query_as::<_, SessionRow>(
        "UPDATE sessions SET name = $1, updated_at = now()
         WHERE id = $2
         RETURNING id, name, description, status, created_by, approval_policy, join_token, created_at, updated_at",
    )
    .bind(new_name)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn get_membership(pool: &PgPool, session_id: &str, actor_id: &str) -> DbResult<MembershipRow> {
    sqlx::query_as::<_, MembershipRow>(
        "SELECT id, session_id, actor_id, role, escalation_order, escalation_timeout, joined_at, detached_at
         FROM session_memberships WHERE session_id = $1 AND actor_id = $2",
    )
    .bind(session_id)
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Verify `actor_id` is a member of `session_id` with at least `min_role`'s
/// authority, returning their membership row. Intended to be called at the
/// top of session-scoped mutating handlers — the generic "are you allowed
/// to be here at all" gate; endpoint-specific policy (e.g. can this role
/// invite that role) layers on top in the caller, not here.
///
/// `DbError::NotFound` — not a member at all.
/// `DbError::Unauthorized` — a member, but below `min_role`.
pub async fn require_membership(
    pool: &PgPool,
    session_id: &str,
    actor_id: &str,
    min_role: MemberRole,
) -> DbResult<MembershipRow> {
    let membership = get_membership(pool, session_id, actor_id).await?;
    let role: MemberRole = membership.role.parse().map_err(|_| DbError::Unauthorized)?;
    if !role.satisfies(&min_role) {
        return Err(DbError::Unauthorized);
    }
    Ok(membership)
}

/// Same as `require_membership`, but if `actor_id` has no membership row at
/// all, falls back to checking whether they qualify via a session_links
/// grant — a member of some other session `session_id` is linked to
/// (`visibility = 'full'`) — and if so, lazily provisions a real Observer
/// membership row on the spot.
///
/// Only ever satisfies an Observer-ceiling request: a real member who's
/// simply below `min_role` still gets `Unauthorized`, not a link check —
/// linking never grants more than read access, so it can't be used to shop
/// around a role-ceiling gate on a Collaborator+ endpoint.
///
/// This is the *only* piece of new machinery cross-session sync needed:
/// once this auto-grants a real `session_memberships` row, every other
/// membership-gated endpoint (WS attach, REST reads, historical events,
/// artifacts, approval visibility) already works for free — no separate
/// replay log, no event mirroring, nothing else to keep in sync. Postgres
/// (session_memberships/events, both already durable) is the entire
/// "deterministic replay" story.
pub async fn require_membership_or_linked_access(
    pool: &PgPool,
    session_id: &str,
    actor_id: &str,
    min_role: MemberRole,
) -> DbResult<MembershipRow> {
    match require_membership(pool, session_id, actor_id, min_role.clone()).await {
        Ok(m) => return Ok(m),
        Err(DbError::Unauthorized) => return Err(DbError::Unauthorized),
        Err(DbError::NotFound) => {}
        Err(e) => return Err(e),
    }
    if !MemberRole::Observer.satisfies(&min_role) {
        return Err(DbError::NotFound);
    }
    match crate::session_links::actor_has_linked_access(pool, actor_id, session_id).await? {
        Some(_peer_session_id) => add_member(pool, session_id, actor_id, "observer", None, None).await,
        None => Err(DbError::NotFound),
    }
}

/// Verify `actor_id` is a session member who isn't read-only (Observer).
///
/// This is a different axis than `require_membership`'s rank ceiling: Agent
/// legitimately ranks *below* Observer on the human-authority ladder (it
/// isn't part of that ladder at all), but agents are the primary caller of
/// several content-creation endpoints (add_context, create_artifact) and
/// must not be locked out by a Collaborator-or-above check. This checks
/// "is a member and isn't Observer" directly, rather than a rank threshold.
pub async fn require_active_membership(
    pool: &PgPool,
    session_id: &str,
    actor_id: &str,
) -> DbResult<MembershipRow> {
    let membership = get_membership(pool, session_id, actor_id).await?;
    let role: MemberRole = membership.role.parse().map_err(|_| DbError::Unauthorized)?;
    if role == MemberRole::Observer {
        return Err(DbError::Unauthorized);
    }
    Ok(membership)
}

pub async fn list_memberships(pool: &PgPool, session_id: &str) -> DbResult<Vec<MembershipRow>> {
    sqlx::query_as::<_, MembershipRow>(
        "SELECT id, session_id, actor_id, role, escalation_order, escalation_timeout, joined_at, detached_at
         FROM session_memberships WHERE session_id = $1 ORDER BY joined_at",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Grant (or update) membership. When `role` is `"owner"`, this atomically
/// demotes whoever currently holds owner in the session first — mirroring
/// `transfer_ownership_in_tx`'s own display-label step — so granting
/// ownership through an invite or the direct add-member route can never
/// leave two simultaneous owner-role rows the way a plain insert would.
/// `transfer_ownership` remains the richer path (it also moves the root cap
/// DAG); this only keeps the role-label invariant intact for every entry
/// point that can hand out the owner role.
pub async fn add_member(
    pool: &PgPool,
    session_id: &str,
    actor_id: &str,
    role: &str,
    escalation_order: Option<i32>,
    escalation_timeout: Option<i32>,
) -> DbResult<MembershipRow> {
    let mut tx = pool.begin().await?;

    if role == "owner" {
        sqlx::query(
            "UPDATE session_memberships SET role = 'collaborator'
             WHERE session_id = $1 AND role = 'owner' AND actor_id != $2",
        )
        .bind(session_id)
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    }

    let id = Ulid::new().to_string();
    let row = sqlx::query_as::<_, MembershipRow>(
        "INSERT INTO session_memberships (id, session_id, actor_id, role, escalation_order, escalation_timeout)
         VALUES ($1, $2, $3, $4, $5, $6)
         ON CONFLICT (session_id, actor_id) DO UPDATE
           SET role = EXCLUDED.role,
               escalation_order = EXCLUDED.escalation_order,
               escalation_timeout = EXCLUDED.escalation_timeout,
               detached_at = NULL
         RETURNING id, session_id, actor_id, role, escalation_order, escalation_timeout, joined_at, detached_at",
    )
    .bind(&id)
    .bind(session_id)
    .bind(actor_id)
    .bind(role)
    .bind(escalation_order)
    .bind(escalation_timeout)
    .fetch_one(&mut *tx)
    .await
    .map_err(DbError::from)?;

    tx.commit().await?;
    Ok(row)
}

pub async fn transfer_ownership(pool: &PgPool, session_id: &str, from: &str, to: &str) -> DbResult<()> {
    let mut tx = pool.begin().await?;
    transfer_ownership_in_tx(&mut tx, session_id, from, to).await?;
    tx.commit().await?;
    Ok(())
}

/// Atomically transfer session ownership within an existing transaction.
///
/// Two actions per the unified graph rewrite algebra (THREAT_MODEL.md §4.3):
///
/// 1. **Display label update** — `session_memberships.role` is demoted/promoted
///    for `from`/`to` respectively.  This field is now a display label only;
///    the cap DAG is the authoritative authorization source.
///
/// 2. **Cap DAG transfer** — if `from` holds an active root cap (stratum=0),
///    it is retired with `transferred_to` pointing at a new root cap issued
///    to `to`.  Children of the old root are reparented atomically.
///    The epoch is NOT advanced — existing agent/collaborator caps remain valid.
///
/// Best-effort on the cap DAG side: sessions created before the epoch system
/// (migration 011) may have no root cap for `from`, in which case only the
/// display label update fires.
pub async fn transfer_ownership_in_tx(
    tx:         &mut Transaction<'_, Postgres>,
    session_id: &str,
    from:       &str,
    to:         &str,
) -> DbResult<()> {
    // ── 1. Display label update ───────────────────────────────────────────────
    sqlx::query(
        "UPDATE session_memberships SET role = 'collaborator'
         WHERE session_id = $1 AND actor_id = $2",
    )
    .bind(session_id)
    .bind(from)
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "UPDATE session_memberships SET role = 'owner'
         WHERE session_id = $1 AND actor_id = $2",
    )
    .bind(session_id)
    .bind(to)
    .execute(&mut **tx)
    .await?;

    // ── 2. Cap DAG transfer ───────────────────────────────────────────────────
    if let Some(old_root_id) = tokens::find_root_cap_in_tx(tx, session_id, from).await? {
        tokens::transfer_root_in_tx(tx, session_id, &old_root_id, to, DEFAULT_OWNER_TTL_HOURS)
            .await?;
    }

    Ok(())
}

/// Atomically increment and return the current sequence number for the session.
pub async fn next_seq(pool: &PgPool, session_id: &str) -> DbResult<i64> {
    let row = sqlx::query(
        "UPDATE session_sequences SET next_seq = next_seq + 1
         WHERE session_id = $1
         RETURNING next_seq - 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)?;
    Ok(row.get::<i64, _>(0))
}
