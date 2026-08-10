//! Cross-session artifact import — a publish/import operation with a real,
//! independent copy, not a live reference. See migration 029's own doc
//! comment for the full design: content ceases to be shared mutable state
//! the moment the copy is created, authority and approval never travel with
//! it, and this receipt table has no live authorization meaning of its own.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};

use crate::{DbError, DbResult};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ArtifactImportRow {
    pub id: String,
    pub source_session_id: String,
    pub source_artifact_id: String,
    pub source_event_seq: Option<i64>,
    pub target_session_id: String,
    pub target_artifact_id: String,
    pub content_hash: String,
    pub published_by: String,
    pub published_at: DateTime<Utc>,
    pub imported_by: String,
    pub imported_at: DateTime<Utc>,
    pub session_link_id: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn insert(
    pool: &PgPool,
    id: &str,
    source_session_id: &str,
    source_artifact_id: &str,
    source_event_seq: i64,
    target_session_id: &str,
    target_artifact_id: &str,
    content_hash: &str,
    published_by: &str,
    published_at: DateTime<Utc>,
    imported_by: &str,
    session_link_id: Option<&str>,
) -> DbResult<ArtifactImportRow> {
    sqlx::query_as::<_, ArtifactImportRow>(
        "INSERT INTO artifact_imports
            (id, source_session_id, source_artifact_id, source_event_seq,
             target_session_id, target_artifact_id, content_hash,
             published_by, published_at, imported_by, session_link_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
         RETURNING id, source_session_id, source_artifact_id, source_event_seq,
                   target_session_id, target_artifact_id, content_hash,
                   published_by, published_at, imported_by, imported_at, session_link_id",
    )
    .bind(id)
    .bind(source_session_id)
    .bind(source_artifact_id)
    .bind(source_event_seq)
    .bind(target_session_id)
    .bind(target_artifact_id)
    .bind(content_hash)
    .bind(published_by)
    .bind(published_at)
    .bind(imported_by)
    .bind(session_link_id)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        // artifact_imports_dedup (target_session_id, source_artifact_id,
        // content_hash) — the caller's own find_existing check should catch
        // this ahead of time, so this only fires on a genuine concurrent
        // double-import race. Surfaced as Conflict so the route can fall
        // back to returning the winning row instead of a hard 500.
        if let sqlx::Error::Database(ref de) = e {
            if de.code().as_deref() == Some("23505") {
                return DbError::Conflict("artifact already imported into this session".into());
            }
        }
        DbError::Sqlx(e)
    })
}

/// Has this exact content already been imported into this target session,
/// via *any* prior import? Keyed on `(target_session_id, content_hash)`
/// alone, matching the `artifact_imports_dedup` constraint — deliberately
/// *not* also keyed on `source_artifact_id`: a prior import's resulting
/// copy gets its own fresh artifact id, so re-importing it back through a
/// different hop (A -> B, then B -> A) would carry a different
/// source_artifact_id for byte-identical content, letting a round-trip
/// slip past a narrower key. Only catches content that arrived via a prior
/// *import* — the route layer separately checks the target's own native
/// artifacts, since the original an import chain started from was never
/// itself recorded as an import.
pub async fn find_existing(
    pool: &PgPool,
    target_session_id: &str,
    content_hash: &str,
) -> DbResult<Option<ArtifactImportRow>> {
    sqlx::query_as::<_, ArtifactImportRow>(
        "SELECT id, source_session_id, source_artifact_id, source_event_seq,
                target_session_id, target_artifact_id, content_hash,
                published_by, published_at, imported_by, imported_at, session_link_id
         FROM artifact_imports
         WHERE target_session_id = $1 AND content_hash = $2",
    )
    .bind(target_session_id)
    .bind(content_hash)
    .fetch_optional(pool)
    .await
    .map_err(DbError::from)
}
