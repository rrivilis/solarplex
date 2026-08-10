//! Mailbox routes — a thin edge relation connecting a receiver-specific
//! address (an actor's mailbox) to a sender-owned fact by reference.
//!
//! `mailbox_routes(mailbox_actor_id, entity_uri)` is `(who, what)`, nothing
//! more — no invite/cap/session data is copied here. Reading a mailbox is an
//! index scan on this table plus resolving each `entity_uri` back to the
//! real object (via `protocol::types::EntityHandle::from_uri`) on read, in
//! the route handler, not in this module.
//!
//! Write-time population (invite creation, first-login backfill) lives at
//! the call sites in `crates/server` that already know about the fact being
//! routed — this module only knows how to store and retrieve edges.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct MailboxRouteRow {
    pub id: String,
    pub mailbox_actor_id: String,
    pub entity_uri: String,
    pub created_at: DateTime<Utc>,
    pub seen_at: Option<DateTime<Utc>>,
}

/// Insert a route. Idempotent on `(mailbox_actor_id, entity_uri)` — a
/// duplicate insert (e.g. a retried backfill) is silently a no-op rather
/// than an error; callers never need to distinguish "created" from
/// "already existed" here.
pub async fn insert_route(pool: &PgPool, mailbox_actor_id: &str, entity_uri: &str) -> DbResult<()> {
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO mailbox_routes (id, mailbox_actor_id, entity_uri)
         VALUES ($1, $2, $3)
         ON CONFLICT (mailbox_actor_id, entity_uri) DO NOTHING",
    )
    .bind(id)
    .bind(mailbox_actor_id)
    .bind(entity_uri)
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    Ok(())
}

pub async fn list_for_actor(pool: &PgPool, actor_id: &str) -> DbResult<Vec<MailboxRouteRow>> {
    sqlx::query_as::<_, MailboxRouteRow>(
        "SELECT id, mailbox_actor_id, entity_uri, created_at, seen_at
         FROM mailbox_routes WHERE mailbox_actor_id = $1 ORDER BY created_at DESC",
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

/// Mark a route seen — scoped to `actor_id` so one actor can't dismiss
/// another's mailbox entry by guessing a route id. `NotFound` covers both
/// "no such route" and "not yours", deliberately indistinguishable to the
/// caller (same anti-enumeration reasoning as `descriptors::resolve`).
pub async fn mark_seen(pool: &PgPool, route_id: &str, actor_id: &str) -> DbResult<()> {
    let result = sqlx::query(
        "UPDATE mailbox_routes SET seen_at = NOW() WHERE id = $1 AND mailbox_actor_id = $2",
    )
    .bind(route_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .map_err(DbError::from)?;
    if result.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

/// Sweep pending named invites for `email` and create mailbox routes for
/// each — the one-time catch-up for an actor whose invites arrived before
/// they had an account. Called once, right after actor creation, on first
/// OIDC login.
pub async fn backfill_for_email(pool: &PgPool, actor_id: &str, email: &str) -> DbResult<()> {
    if email.is_empty() { return Ok(()); }
    let invites = crate::invites::list_pending_by_email(pool, email).await?;
    for invite in invites {
        let uri = format!("invite/{}", invite.id);
        insert_route(pool, actor_id, &uri).await?;
    }
    Ok(())
}
