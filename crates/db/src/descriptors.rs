//! Per-actor capability descriptors — doors-style local references.
//!
//! `session_tokens` (caps) are addressed globally: the raw ULID is a bearer
//! credential, whoever holds the string has the authority it encodes. This
//! module adds a *local* layer on top, scoped per actor — `local_index` is
//! meaningless outside the actor's own row set, mirroring how a Solaris
//! door descriptor or a Unix fd carries no authority outside the process
//! that holds it. `resolve()` is the one and only path to turn a
//! `local_index` into an `entity_uri`, and it always resolves through the
//! caller's own `actor_id` — there is no global lookup by `local_index`
//! alone anywhere in this module, on purpose.
//!
//! Scoped to caps only for now. Approvals were deliberately left out: caps
//! have a clean 1:1 grant (one delegation, one recipient, one row), while an
//! approval's natural descriptor shape is unresolved — does every eligible
//! voter get an entry, just the requester? That's a real design question,
//! not a wiring job, so it's left for a follow-up rather than guessed at
//! here.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct DescriptorRow {
    pub id: String,
    pub actor_id: String,
    pub local_index: i32,
    pub entity_uri: String,
    pub granted_at: DateTime<Utc>,
}

/// Grant `actor_id` a new local descriptor pointing at `entity_uri`.
/// `local_index` is computed as this actor's current max + 1 — small,
/// per-actor, sequential, in the spirit of job-control's `%1` rather than a
/// globally-unique id (it doesn't need to be one; nothing outside this
/// actor's own row set ever looks it up).
///
/// Best-effort by design at call sites: a descriptor is a second-order
/// convenience/security layer on top of the cap that already works via its
/// global id, so callers should log-and-continue on failure here rather
/// than fail the cap grant itself.
pub async fn grant(pool: &PgPool, actor_id: &str, entity_uri: &str) -> DbResult<DescriptorRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, DescriptorRow>(
        "INSERT INTO actor_descriptors (id, actor_id, local_index, entity_uri)
         VALUES (
             $1, $2,
             COALESCE((SELECT MAX(local_index) FROM actor_descriptors WHERE actor_id = $2), 0) + 1,
             $3
         )
         RETURNING id, actor_id, local_index, entity_uri, granted_at",
    )
    .bind(&id)
    .bind(actor_id)
    .bind(entity_uri)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

/// The one authoritative resolution path. `local_index` is never trusted as
/// a bearer value — this only ever resolves against `actor_id`'s own row
/// set, so an index that's real for one actor is simply not found for any
/// other. For a `cap/` entity_uri, this additionally joins live against
/// `session_tokens` and rejects a revoked or expired cap even if its
/// descriptor row hasn't been separately deleted — defense in depth, not
/// the sole mechanism (see revoke_and_delete below for the primary one).
pub async fn resolve(pool: &PgPool, actor_id: &str, local_index: i32) -> DbResult<DescriptorRow> {
    let row = sqlx::query_as::<_, DescriptorRow>(
        "SELECT id, actor_id, local_index, entity_uri, granted_at
         FROM actor_descriptors WHERE actor_id = $1 AND local_index = $2",
    )
    .bind(actor_id)
    .bind(local_index)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)?;

    if let Some(cap_id) = row.entity_uri.strip_prefix("cap/") {
        let live: Option<bool> = sqlx::query_scalar(
            "SELECT (revoked_at IS NULL AND expires_at > NOW()) FROM session_tokens WHERE id = $1",
        )
        .bind(cap_id)
        .fetch_optional(pool)
        .await?;
        if live != Some(true) {
            return Err(DbError::NotFound);
        }
    }

    Ok(row)
}

/// Delete every descriptor row pointing at the given cap ids, across all
/// actors — the primary revocation path, called alongside (not instead of)
/// marking the caps themselves revoked. `resolve()`'s live-cap join would
/// catch a stale row anyway, but deleting it is what keeps this table from
/// silently accumulating dead entries under normal revocation traffic.
pub async fn delete_for_caps(pool: &PgPool, cap_ids: &[String]) -> DbResult<u64> {
    if cap_ids.is_empty() { return Ok(0); }
    let uris: Vec<String> = cap_ids.iter().map(|id| format!("cap/{id}")).collect();
    let result = sqlx::query("DELETE FROM actor_descriptors WHERE entity_uri = ANY($1)")
        .bind(&uris)
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}

pub async fn list_for_actor(pool: &PgPool, actor_id: &str) -> DbResult<Vec<DescriptorRow>> {
    sqlx::query_as::<_, DescriptorRow>(
        "SELECT id, actor_id, local_index, entity_uri, granted_at
         FROM actor_descriptors WHERE actor_id = $1 ORDER BY local_index",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}
