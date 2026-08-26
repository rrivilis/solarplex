use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TokenRow {
    pub id: String,
    pub session_id: String,
    pub actor_id: String,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    /// The cap this was delegated from. NULL = root (human-issued).
    pub parent_cap: Option<String>,
    /// Session seq the issuer observed at delegation time — the causal anchor.
    pub observed_seq: i64,
    /// Allowed tool names. Empty array = all tools permitted.
    pub permissions: serde_json::Value,
    /// The session epoch in which this cap was issued.  0 for pre-epoch caps.
    #[sqlx(default)]
    pub epoch: i64,
    /// Delegation depth: 0 = root (human-issued), N = Nth-generation delegate.
    #[sqlx(default)]
    pub stratum: i64,
    /// Set when this cap has been explicitly revoked.
    #[sqlx(default)]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Set on cooperative transfer: the ID of the new root cap that replaced this one.
    /// Distinguishes transfer() (cooperative, epoch preserved) from revoke()
    /// (adversarial, epoch advanced) in the audit trail.
    /// NULL on adversarial revocations; non-NULL when transferred_to IS NOT NULL.
    #[sqlx(default)]
    pub transferred_to: Option<String>,
}

/// Insert a new single-use attach token.
///
/// Epoch is read from `session_epochs` and stratum is computed from the
/// parent cap's stratum + 1 (root caps have stratum = 0).
pub async fn insert(
    pool: &PgPool,
    id: &str,
    session_id: &str,
    actor_id: &str,
    expires_at: DateTime<Utc>,
    parent_cap: Option<&str>,
    observed_seq: i64,
    permissions: &[String],
) -> DbResult<TokenRow> {
    let permissions_json = serde_json::to_value(permissions).map_err(DbError::Json)?;
    sqlx::query_as::<_, TokenRow>(
        "INSERT INTO session_tokens
             (id, session_id, actor_id, expires_at, parent_cap, observed_seq,
              permissions, epoch, stratum)
         VALUES (
             $1, $2, $3, $4, $5, $6, $7,
             -- epoch: current epoch for this session (0 if no row yet)
             COALESCE((SELECT epoch FROM session_epochs WHERE session_id = $2), 0),
             -- stratum: parent's stratum + 1, or 0 if root cap
             COALESCE((SELECT stratum + 1 FROM session_tokens WHERE id = $5), 0)
         )
         RETURNING id, session_id, actor_id, expires_at, used_at, created_at,
                   parent_cap, observed_seq, permissions, epoch, stratum, revoked_at",
    )
    .bind(id)
    .bind(session_id)
    .bind(actor_id)
    .bind(expires_at)
    .bind(parent_cap)
    .bind(observed_seq)
    .bind(permissions_json)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// Fetch a cap by ID without consuming it.
///
/// Used by the invoke endpoint to validate cap state (epoch, revoked_at,
/// permissions) without marking the cap as used.  Unlike `exchange`, the
/// cap is not a single-use attach token. It's a long-lived delegation
/// credential that persists across multiple tool calls.
pub async fn get_cap(pool: &PgPool, id: &str) -> DbResult<TokenRow> {
    sqlx::query_as::<_, TokenRow>(
        "SELECT id, session_id, actor_id, expires_at, used_at, created_at,
                parent_cap, observed_seq, permissions, epoch, stratum, revoked_at
         FROM session_tokens WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

/// Atomically validate and consume a token (mark used_at = now).
/// Returns the token row on success.
/// Errors: NotFound if token doesn't exist, expired, already used, or revoked.
pub async fn exchange(pool: &PgPool, id: &str) -> DbResult<TokenRow> {
    let row = sqlx::query_as::<_, TokenRow>(
        "UPDATE session_tokens
         SET used_at = NOW()
         WHERE id = $1
           AND used_at IS NULL
           AND expires_at > NOW()
           AND revoked_at IS NULL
         RETURNING id, session_id, actor_id, expires_at, used_at, created_at,
                   parent_cap, observed_seq, permissions, epoch, stratum, revoked_at",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)?;
    Ok(row)
}

/// Walk the cap DAG from a given token up to the root (human-issued cap).
/// Returns the full lineage ordered by observed_seq ascending (oldest auth first).
pub async fn lineage(pool: &PgPool, id: &str) -> DbResult<Vec<TokenRow>> {
    let rows = sqlx::query_as::<_, TokenRow>(
        "WITH RECURSIVE lineage AS (
             SELECT id, session_id, actor_id, expires_at, used_at, created_at,
                    parent_cap, observed_seq, permissions, epoch, stratum, revoked_at
             FROM session_tokens WHERE id = $1
             UNION ALL
             SELECT t.id, t.session_id, t.actor_id, t.expires_at, t.used_at, t.created_at,
                    t.parent_cap, t.observed_seq, t.permissions, t.epoch, t.stratum, t.revoked_at
             FROM session_tokens t
             JOIN lineage l ON t.id = l.parent_cap
         )
         SELECT * FROM lineage ORDER BY observed_seq ASC",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;
    Ok(rows)
}

/// All direct children of a cap (one-hop delegates).
pub async fn children(pool: &PgPool, parent_id: &str) -> DbResult<Vec<TokenRow>> {
    sqlx::query_as::<_, TokenRow>(
        "SELECT id, session_id, actor_id, expires_at, used_at, created_at,
                parent_cap, observed_seq, permissions, epoch, stratum, revoked_at
         FROM session_tokens WHERE parent_cap = $1",
    )
    .bind(parent_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Parse permissions from a token row into a Vec<String>.
/// Empty vec means all tools permitted.
pub fn parse_permissions(row: &TokenRow) -> Vec<String> {
    parse_permissions_from_json(&row.permissions)
}

/// Parse a raw permissions JSON value into a Vec<String>.
/// Useful when working with `CapHolderRow` which carries `permissions` directly.
pub fn parse_permissions_from_json(permissions: &serde_json::Value) -> Vec<String> {
    permissions
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// All non-expired, non-revoked caps held by a specific actor in a session.
///
/// Used by `sp auth why` to enumerate what authorities the actor currently holds.
/// `used_at` is shown in the response so callers can distinguish an already-exchanged
/// root token (agent has attached) from a pending one.
pub async fn actor_caps_in_session(
    pool: &PgPool,
    session_id: &str,
    actor_id: &str,
) -> DbResult<Vec<TokenRow>> {
    sqlx::query_as::<_, TokenRow>(
        "SELECT id, session_id, actor_id, expires_at, used_at, created_at,
                parent_cap, observed_seq, permissions, epoch, stratum, revoked_at
         FROM session_tokens
         WHERE session_id = $1
           AND actor_id   = $2
           AND expires_at > NOW()
           AND revoked_at IS NULL
         ORDER BY observed_seq ASC",
    )
    .bind(session_id)
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Row type for `sp auth who-can`: one cap held by one actor.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CapHolderRow {
    pub cap_id: String,
    pub actor_id: String,
    pub permissions: serde_json::Value,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub observed_seq: i64,
    pub parent_cap: Option<String>,
}

/// All non-expired, non-revoked cap holders in a session, ordered by actor then seq.
///
/// Used by `sp auth who-can` to list every actor that holds an active capability
/// in the session regardless of their formal membership role.
pub async fn session_cap_holders(pool: &PgPool, session_id: &str) -> DbResult<Vec<CapHolderRow>> {
    sqlx::query_as::<_, CapHolderRow>(
        "SELECT id AS cap_id, actor_id, permissions, expires_at, observed_seq, parent_cap
         FROM session_tokens
         WHERE session_id = $1
           AND expires_at > NOW()
           AND revoked_at IS NULL
         ORDER BY actor_id ASC, observed_seq ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

// ── Cross-session view for session owners ─────────────────────────────────────

/// One active agent attach-credential, with enough context (session name) to
/// render in a cross-session list without a second round trip per row.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct OwnedAgentCapRow {
    pub cap_id: String,
    pub session_id: String,
    pub session_name: String,
    pub actor_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// NULL means the agent was issued this token but never actually
    /// attached (exchanged it) — distinguishes "waiting to be used" from
    /// "an agent has been live with this credential since <used_at>".
    pub used_at: Option<DateTime<Utc>>,
}

/// Every active (non-revoked, non-expired) root cap — i.e. an agent
/// attach-credential, `stratum = 0` — across every session where
/// `owner_actor_id` holds the Owner role. The Settings "active agent
/// sessions" view: root caps are exactly the caps an owner minted (directly
/// or via a delegate chain rooted at their own authority), one per
/// attached-or-attachable agent, regardless of how many tool-scoped caps
/// that agent has since delegated further down.
pub async fn list_root_caps_for_owner(
    pool: &PgPool,
    owner_actor_id: &str,
) -> DbResult<Vec<OwnedAgentCapRow>> {
    sqlx::query_as::<_, OwnedAgentCapRow>(
        "SELECT t.id AS cap_id, t.session_id, s.name AS session_name, t.actor_id,
                t.created_at, t.expires_at, t.used_at
         FROM session_tokens t
         JOIN sessions s ON s.id = t.session_id
         JOIN session_memberships m ON m.session_id = t.session_id AND m.role = 'owner'
         WHERE m.actor_id  = $1
           AND t.stratum   = 0
           AND t.revoked_at IS NULL
           AND t.expires_at > NOW()
         ORDER BY t.created_at DESC",
    )
    .bind(owner_actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Revoke a root cap (and its delegate subtree) on behalf of an owner,
/// scoped to sessions they actually own — the route handler passes the
/// caller's verified actor_id here rather than trusting a session_id in the
/// request body, so this can never be used to revoke a cap in a session the
/// caller doesn't own no matter what cap_id is passed.
///
/// Returns `Ok(None)` if the cap doesn't exist, isn't a root cap, or the
/// caller doesn't own its session — the route handler maps all three to the
/// same 404, same anti-enumeration posture as session_links.
pub async fn revoke_owned_root_cap(
    pool: &PgPool,
    cap_id: &str,
    owner_actor_id: &str,
) -> DbResult<Option<Vec<String>>> {
    let owns: bool = sqlx::query_scalar(
        "SELECT EXISTS (
             SELECT 1 FROM session_tokens t
             JOIN session_memberships m ON m.session_id = t.session_id AND m.role = 'owner'
             WHERE t.id = $1 AND t.stratum = 0 AND m.actor_id = $2
         )",
    )
    .bind(cap_id)
    .bind(owner_actor_id)
    .fetch_one(pool)
    .await?;
    if !owns {
        return Ok(None);
    }
    Ok(Some(revoke_cap_subtree(pool, cap_id).await?))
}

// ── Revocation functions ──────────────────────────────────────────────────────

/// Revoke a cap and its entire subtree (all descendants via recursive CTE).
///
/// Returns the ids of every cap actually revoked (including the root, not
/// counting already-revoked caps) — callers use this to also clean up any
/// `actor_descriptors` rows pointing at them (see `descriptors::delete_for_caps`).
pub async fn revoke_cap_subtree(pool: &PgPool, cap_id: &str) -> DbResult<Vec<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE subtree AS (
             SELECT id FROM session_tokens WHERE id = $1
             UNION ALL
             SELECT t.id FROM session_tokens t
             JOIN subtree s ON t.parent_cap = s.id
             WHERE t.revoked_at IS NULL
         )
         UPDATE session_tokens
         SET revoked_at = NOW()
         WHERE id IN (SELECT id FROM subtree)
           AND revoked_at IS NULL
         RETURNING id",
    )
    .bind(cap_id)
    .fetch_all(pool)
    .await?;
    Ok(ids)
}

/// Revoke all caps in a session at a given epoch with stratum >= threshold.
///
/// Used for stratum-based revocation: closes all caps at depth >= N in the
/// specified epoch, preserving shallower roots. Returns the ids revoked.
pub async fn revoke_by_stratum(
    pool: &PgPool,
    session_id: &str,
    epoch: i64,
    stratum_threshold: i64,
) -> DbResult<Vec<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "UPDATE session_tokens
         SET revoked_at = NOW()
         WHERE session_id  = $1
           AND epoch        = $2
           AND stratum      >= $3
           AND revoked_at   IS NULL
         RETURNING id",
    )
    .bind(session_id)
    .bind(epoch)
    .bind(stratum_threshold)
    .fetch_all(pool)
    .await?;
    Ok(ids)
}

/// Revoke all caps in a session's entire epoch.
///
/// Closes every active cap in the session that belongs to the given epoch.
/// Returns the ids revoked.
pub async fn revoke_epoch(pool: &PgPool, session_id: &str, epoch: i64) -> DbResult<Vec<String>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "UPDATE session_tokens
         SET revoked_at = NOW()
         WHERE session_id = $1
           AND epoch       = $2
           AND revoked_at  IS NULL
         RETURNING id",
    )
    .bind(session_id)
    .bind(epoch)
    .fetch_all(pool)
    .await?;
    Ok(ids)
}

/// Reroot non-revoked children of a revoked cap to a new parent.
///
/// When a cap is revoked but its children should survive under a different
/// parent (the revoked cap's own parent), update their `parent_cap` pointer.
/// This preserves the attenuation invariant: children cannot gain permissions
/// through rerooting because permissions are capped by the new parent's set.
///
/// The `session_id` parameter scopes the update to one session, preventing a
/// hostile or misconfigured caller from cross-session reparenting.  The DB-level
/// epoch-coherence trigger (`015_security_hardening.sql`) provides a second line
/// of defense, but scoping at the application layer is the primary guard.
///
/// Returns the count of caps rerooted.
pub async fn reroot_caps(
    pool: &PgPool,
    session_id: &str,
    old_parent_id: &str,
    new_parent_id: Option<&str>,
) -> DbResult<u64> {
    let result = sqlx::query(
        "UPDATE session_tokens
         SET parent_cap = $2
         WHERE parent_cap = $1
           AND session_id  = $3
           AND revoked_at  IS NULL",
    )
    .bind(old_parent_id)
    .bind(new_parent_id)
    .bind(session_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Return the parent cap ID (grandparent link) for a given cap.
///
/// Used during rerooting to find where to redirect children when the
/// intermediate parent is being revoked.  Returns `None` for root caps.
pub async fn get_parent_id(pool: &PgPool, cap_id: &str) -> DbResult<Option<String>> {
    let parent = sqlx::query_scalar::<_, Option<String>>(
        "SELECT parent_cap FROM session_tokens WHERE id = $1",
    )
    .bind(cap_id)
    .fetch_optional(pool)
    .await?
    .flatten();
    Ok(parent)
}

/// Delete revoked cap rows whose `revoked_at` timestamp is older than
/// `retention_days`.
///
/// Safe to run at any time — only touches rows where `revoked_at IS NOT NULL`,
/// meaning the cap has already been explicitly revoked.  The `cap_revocations`
/// table retains the audit summary indefinitely; the fine-grained token rows
/// are only needed during the drain window and short audit window after it.
///
/// Returns the number of rows deleted.
pub async fn compact_revoked(pool: &PgPool, retention_days: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM session_tokens
         WHERE revoked_at IS NOT NULL
           AND revoked_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(retention_days)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}

/// Returns whether a specific cap has been revoked.
///
/// Used for per-write staleness fencing in the WS handler.
pub async fn is_revoked(pool: &PgPool, cap_id: &str) -> DbResult<bool> {
    let revoked = sqlx::query_scalar::<_, Option<bool>>(
        "SELECT (revoked_at IS NOT NULL) FROM session_tokens WHERE id = $1",
    )
    .bind(cap_id)
    .fetch_optional(pool)
    .await?
    .flatten()
    .unwrap_or(false);
    Ok(revoked)
}

// ── Cooperative transfer primitives ──────────────────────────────────────────

/// Result returned by `transfer_root_in_tx`.
pub struct TransferResult {
    /// The newly-created root cap (now authoritative).
    pub new_root_id: String,
    /// How many child caps were reparented to the new root.
    pub rerooted_count: u64,
}

/// Find the most-recent active root cap (stratum=0, live) for an actor within
/// an existing transaction.
///
/// Returns `None` for sessions that predate the cap system — callers should
/// treat this as a clean no-op and proceed with display-label-only transfer.
pub async fn find_root_cap_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    actor_id: &str,
) -> DbResult<Option<String>> {
    let id = sqlx::query_scalar::<_, String>(
        "SELECT id FROM session_tokens
         WHERE session_id  = $1
           AND actor_id    = $2
           AND stratum     = 0
           AND revoked_at  IS NULL
           AND expires_at  > NOW()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(session_id)
    .bind(actor_id)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(id)
}

/// Atomically execute a cooperative ownership transfer within an existing
/// transaction.
///
/// Three steps — all in the caller's transaction so they commit together with
/// the session membership role update:
///
/// 1. INSERT new root cap for `new_actor_id` inheriting `old_root`'s permissions.
/// 2. UPDATE children of `old_root_id` → reparent to new root.
/// 3. RETIRE `old_root_id`: set `revoked_at = NOW()`, `transferred_to = new_root_id`.
///
/// Does NOT advance the epoch — existing agent/collaborator caps remain valid
/// in the new root's authority namespace.  The old root's `transferred_to`
/// field distinguishes this retirement from adversarial revocation.
pub async fn transfer_root_in_tx(
    tx: &mut Transaction<'_, Postgres>,
    session_id: &str,
    old_root_id: &str,
    new_actor_id: &str,
    ttl_hours: i64,
) -> DbResult<TransferResult> {
    // Read old root's permissions — new root inherits them verbatim.
    let old_permissions = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT permissions FROM session_tokens WHERE id = $1",
    )
    .bind(old_root_id)
    .fetch_optional(&mut **tx)
    .await?
    .unwrap_or_else(|| serde_json::Value::Array(vec![]));

    // Step 1: insert new root cap.
    // Epoch is inherited from session_epochs (same epoch — no advance).
    // observed_seq is the current committed seq at transfer time.
    let new_id = Ulid::new().to_string();
    let expires_at = Utc::now() + Duration::hours(ttl_hours);

    let new_root_id: String = sqlx::query_scalar(
        "INSERT INTO session_tokens
             (id, session_id, actor_id, expires_at, permissions, epoch, stratum, observed_seq)
         VALUES ($1, $2, $3, $4, $5,
             COALESCE((SELECT epoch    FROM session_epochs    WHERE session_id = $2), 0),
             0,
             COALESCE((SELECT next_seq - 1 FROM session_sequences WHERE session_id = $2), 0))
         RETURNING id",
    )
    .bind(&new_id)
    .bind(session_id)
    .bind(new_actor_id)
    .bind(expires_at)
    .bind(&old_permissions)
    .fetch_one(&mut **tx)
    .await?;

    // Step 2: reroot non-revoked children to the new root.
    let rerooted = sqlx::query(
        "UPDATE session_tokens SET parent_cap = $1
         WHERE parent_cap = $2 AND revoked_at IS NULL",
    )
    .bind(&new_root_id)
    .bind(old_root_id)
    .execute(&mut **tx)
    .await?;

    // Step 3: retire the old root.
    // `revoked_at` marks it inactive; `transferred_to` records it was a
    // cooperative transfer (not an adversarial revocation).
    sqlx::query(
        "UPDATE session_tokens
         SET revoked_at = NOW(), transferred_to = $1
         WHERE id = $2",
    )
    .bind(&new_root_id)
    .bind(old_root_id)
    .execute(&mut **tx)
    .await?;

    Ok(TransferResult {
        new_root_id,
        rerooted_count: rerooted.rows_affected(),
    })
}

/// Return the actor_ids of all caps that were revoked by a specific revocation
/// event (identified by the drain_seq and epoch).  Used to populate the
/// `fenced_actors` set in the session hub immediately after revocation.
pub async fn actors_in_revoked_epoch(
    pool: &PgPool,
    session_id: &str,
    epoch: i64,
) -> DbResult<Vec<String>> {
    let ids = sqlx::query_scalar::<_, String>(
        "SELECT DISTINCT actor_id FROM session_tokens
         WHERE session_id  = $1
           AND epoch        = $2
           AND revoked_at   IS NOT NULL",
    )
    .bind(session_id)
    .bind(epoch)
    .fetch_all(pool)
    .await?;
    Ok(ids)
}
