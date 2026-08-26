//! Durable relay table for cross-replica saga-bundle forwarding — see
//! migration 036's comment for the full design. Deliberately separate from
//! `session_placements` (which tracks *ownership*, not payloads): this
//! table only ever holds bundles in transit, briefly, between a
//! `Plan::Forward` decision on one replica and that bundle being picked up
//! by the replica the decision named.
//!
//! Generic over the bundle type rather than depending on `session::SagaBundle`
//! directly — this crate stores opaque JSON payloads throughout (see
//! `db::events`), it doesn't know about domain types from higher-level
//! crates; the caller in `crates/server` supplies `SagaBundle` as `T`.

use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::DbResult;

/// Durably hand a bundle off to `owner_replica`.
pub async fn insert<T: Serialize>(
    pool: &PgPool,
    id: &str,
    owner_replica: &str,
    bundle: &T,
) -> DbResult<()> {
    let payload = serde_json::to_value(bundle)?;
    sqlx::query(
        "INSERT INTO reflector_forwarded_bundles (id, owner_replica, bundle) VALUES ($1, $2, $3)",
    )
    .bind(id)
    .bind(owner_replica)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, FromRow)]
struct ClaimedRow {
    id: String,
    bundle: serde_json::Value,
}

/// Atomically claim (mark consumed) every still-pending row addressed to
/// `owner_replica`, and return the bundles it can now deserialize and
/// process. Atomic per row via a single `UPDATE ... WHERE consumed_at IS
/// NULL ... RETURNING` — a duplicate notify firing twice, or this listener
/// racing a hypothetical second instance of itself, can each only ever
/// claim a given row once. A row whose payload fails to deserialize is
/// still marked consumed (skipping it forever rather than retrying a
/// value that will never parse) and logged, not returned.
pub async fn claim_pending<T: for<'de> Deserialize<'de>>(
    pool: &PgPool,
    owner_replica: &str,
) -> DbResult<Vec<(String, T)>> {
    let rows = sqlx::query_as::<_, ClaimedRow>(
        "UPDATE reflector_forwarded_bundles
         SET consumed_at = NOW()
         WHERE owner_replica = $1 AND consumed_at IS NULL
         RETURNING id, bundle",
    )
    .bind(owner_replica)
    .fetch_all(pool)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        match serde_json::from_value::<T>(row.bundle) {
            Ok(bundle) => out.push((row.id, bundle)),
            Err(e) => {
                tracing::warn!(id = %row.id, "reflector_forwarded_bundles: undeserializable row, skipping: {e}")
            }
        }
    }
    Ok(out)
}

/// Delete consumed rows older than `older_than_hours` — keeps the table
/// bounded. Never deletes unconsumed rows, however old: an unconsumed row
/// means the owning replica hasn't picked it up yet (or no longer
/// exists), and dropping it would silently lose the bundle rather than
/// just delaying it.
pub async fn prune_consumed(pool: &PgPool, older_than_hours: i64) -> DbResult<u64> {
    let result = sqlx::query(
        "DELETE FROM reflector_forwarded_bundles
         WHERE consumed_at IS NOT NULL
           AND consumed_at < NOW() - (($1 || ' hours')::interval)",
    )
    .bind(older_than_hours)
    .execute(pool)
    .await?;
    Ok(result.rows_affected())
}
