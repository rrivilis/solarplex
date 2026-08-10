use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ArtifactRow {
    pub id: String,
    pub session_id: String,
    pub created_by: String,
    pub name: String,
    #[sqlx(rename = "type")]
    pub r#type: String,
    pub storage_ref: String,
    pub version: i32,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct CreateArtifact {
    pub session_id: String,
    pub created_by: String,
    pub name: String,
    pub artifact_type: String,
    pub storage_ref: String,
}

pub async fn create(pool: &PgPool, input: CreateArtifact) -> DbResult<ArtifactRow> {
    let id = Ulid::new().to_string();
    sqlx::query_as::<_, ArtifactRow>(
        "INSERT INTO artifacts (id, session_id, created_by, name, type, storage_ref)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at",
    )
    .bind(&id)
    .bind(&input.session_id)
    .bind(&input.created_by)
    .bind(&input.name)
    .bind(&input.artifact_type)
    .bind(&input.storage_ref)
    .fetch_one(pool)
    .await
    .map_err(DbError::from)
}

pub async fn get(pool: &PgPool, id: &str) -> DbResult<ArtifactRow> {
    sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at
         FROM artifacts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn list(pool: &PgPool, session_id: &str) -> DbResult<Vec<ArtifactRow>> {
    sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at
         FROM artifacts WHERE session_id = $1 ORDER BY created_at",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await
    .map_err(DbError::from)
}

pub async fn update(pool: &PgPool, id: &str, storage_ref: &str) -> DbResult<ArtifactRow> {
    sqlx::query_as::<_, ArtifactRow>(
        "UPDATE artifacts
         SET storage_ref = $1, version = version + 1, updated_at = now()
         WHERE id = $2
         RETURNING id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at",
    )
    .bind(storage_ref)
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(DbError::NotFound)
}

pub async fn delete(pool: &PgPool, id: &str) -> DbResult<()> {
    let result = sqlx::query("DELETE FROM artifacts WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    if result.rows_affected() == 0 {
        return Err(DbError::NotFound);
    }
    Ok(())
}

/// Returns all `scheduled_transfer` artifacts whose `scheduled_at` has elapsed.
///
/// The type filter runs in SQL; the time comparison is done in Rust because other
/// artifact types (e.g. `rotation_policy`) store plain text in `storage_ref`, and
/// casting those to `jsonb` would error if Postgres evaluates the expression before
/// the type predicate is applied.
pub async fn list_overdue_scheduled_transfers(pool: &PgPool) -> DbResult<Vec<ArtifactRow>> {
    let rows = sqlx::query_as::<_, ArtifactRow>(
        "SELECT id, session_id, created_by, name, type, storage_ref, version, created_at, updated_at
         FROM artifacts
         WHERE type = 'scheduled_transfer'",
    )
    .fetch_all(pool)
    .await
    .map_err(DbError::from)?;

    let now = chrono::Utc::now();
    Ok(rows
        .into_iter()
        .filter(|a| {
            // Parse the JSON and check scheduled_at; skip malformed artifacts.
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&a.storage_ref) else {
                return false;
            };
            let Some(sat_str) = v.get("scheduled_at").and_then(|s| s.as_str()) else {
                return false;
            };
            sat_str
                .parse::<chrono::DateTime<chrono::Utc>>()
                .map_or(false, |dt| dt <= now)
        })
        .collect())
}
