use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use ulid::Ulid;

use crate::DbResult;

/// Hashes seen fewer than this many times return `Verdict::Unknown` regardless
/// of family assignment.  Prevents single-occurrence noise from scoring.
pub const MIN_PREVALENCE: i32 = 5;

/// TLSH distance threshold for cluster membership.  TLSH distances range
/// roughly 0–300; 50 is a reasonable "same family" cutoff.
pub const TLSH_CLUSTER_THRESHOLD: i32 = 50;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct HashRow {
    pub sha256:           String,
    pub tlsh:             Option<String>,
    pub family_id:        Option<String>,
    pub first_seen:       DateTime<Utc>,
    pub last_seen:        DateTime<Utc>,
    pub seen_count:       i32,
    pub yara_matches:     Vec<String>,
    pub verdict_override: Option<String>,
    pub verdict_source:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FamilyRow {
    pub id:            String,
    pub name:          String,
    pub verdict:       String,
    pub tlsh_centroid: Option<String>,
    pub yara_rules:    Vec<String>,
    pub member_count:  i32,
    pub created_at:    DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Unknown,
    Benign,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn from_str(s: &str) -> Self {
        match s {
            "benign"     => Verdict::Benign,
            "suspicious" => Verdict::Suspicious,
            "malicious"  => Verdict::Malicious,
            _            => Verdict::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Unknown    => "unknown",
            Verdict::Benign     => "benign",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious  => "malicious",
        }
    }
}

/// Look up a hash and resolve its best-available verdict.
/// Returns `None` if the hash has never been seen.
pub async fn lookup(
    pool: &PgPool,
    sha256: &str,
) -> DbResult<Option<(HashRow, Verdict, Option<String>)>> {
    let Some(row) = sqlx::query_as::<_, HashRow>(
        "SELECT sha256, tlsh, family_id, first_seen, last_seen, seen_count,
                yara_matches, verdict_override, verdict_source
         FROM artifact_hashes WHERE sha256 = $1",
    )
    .bind(sha256)
    .fetch_optional(pool)
    .await?
    else {
        return Ok(None);
    };

    if row.seen_count < MIN_PREVALENCE {
        return Ok(Some((row, Verdict::Unknown, None)));
    }

    // Manual override wins (extract before borrowing row further)
    if let Some(v) = row.verdict_override.as_deref().map(Verdict::from_str) {
        return Ok(Some((row, v, None)));
    }

    // Family verdict
    if let Some(ref fid) = row.family_id {
        if let Some(f) = sqlx::query_as::<_, FamilyRow>(
            "SELECT id, name, verdict, tlsh_centroid, yara_rules, member_count, created_at
             FROM artifact_families WHERE id = $1",
        )
        .bind(fid)
        .fetch_optional(pool)
        .await?
        {
            return Ok(Some((row, Verdict::from_str(&f.verdict), Some(f.name))));
        }
    }

    Ok(Some((row, Verdict::Unknown, None)))
}

/// Insert a new hash record or increment `seen_count` + update `last_seen`.
pub async fn upsert_hash(pool: &PgPool, sha256: &str) -> DbResult<()> {
    sqlx::query(
        "INSERT INTO artifact_hashes (sha256) VALUES ($1)
         ON CONFLICT (sha256) DO UPDATE
         SET seen_count = artifact_hashes.seen_count + 1,
             last_seen  = NOW()",
    )
    .bind(sha256)
    .execute(pool)
    .await?;
    Ok(())
}

/// Update a hash's YARA matches and TLSH from an async scan result.
/// Returns all family rows (for caller-side TLSH clustering).
pub async fn update_scan_results(
    pool:         &PgPool,
    sha256:       &str,
    tlsh:         Option<&str>,
    yara_matches: &[String],
) -> DbResult<Vec<FamilyRow>> {
    sqlx::query(
        "UPDATE artifact_hashes
         SET tlsh         = COALESCE($2, tlsh),
             yara_matches = $3
         WHERE sha256 = $1",
    )
    .bind(sha256)
    .bind(tlsh)
    .bind(yara_matches)
    .execute(pool)
    .await?;

    // Return all families so the caller can do TLSH distance clustering.
    let families = sqlx::query_as::<_, FamilyRow>(
        "SELECT id, name, verdict, tlsh_centroid, yara_rules, member_count, created_at
         FROM artifact_families
         WHERE tlsh_centroid IS NOT NULL OR array_length(yara_rules, 1) > 0",
    )
    .fetch_all(pool)
    .await?;

    Ok(families)
}

/// Assign a family to a hash and increment the family's member_count.
pub async fn assign_family(
    pool:           &PgPool,
    sha256:         &str,
    family_id:      &str,
    verdict_source: &str,
) -> DbResult<()> {
    sqlx::query(
        "UPDATE artifact_hashes
         SET family_id = $2, verdict_source = $3
         WHERE sha256 = $1",
    )
    .bind(sha256)
    .bind(family_id)
    .bind(verdict_source)
    .execute(pool)
    .await?;

    sqlx::query("UPDATE artifact_families SET member_count = member_count + 1 WHERE id = $1")
        .bind(family_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Find the family whose `yara_rules` array contains `rule_name`, or create one.
/// Returns `(family_id, verdict)`.
pub async fn find_or_create_yara_family(
    pool:      &PgPool,
    rule_name: &str,
) -> DbResult<(String, String)> {
    if let Some(f) = sqlx::query_as::<_, FamilyRow>(
        "SELECT id, name, verdict, tlsh_centroid, yara_rules, member_count, created_at
         FROM artifact_families
         WHERE $1 = ANY(yara_rules)
         LIMIT 1",
    )
    .bind(rule_name)
    .fetch_optional(pool)
    .await?
    {
        return Ok((f.id, f.verdict));
    }

    let verdict = infer_verdict_from_rule(rule_name);
    let id = Ulid::new().to_string();
    sqlx::query(
        "INSERT INTO artifact_families (id, name, verdict, yara_rules)
         VALUES ($1, $2, $3, ARRAY[$2])",
    )
    .bind(&id)
    .bind(rule_name)
    .bind(verdict)
    .execute(pool)
    .await?;

    Ok((id, verdict.to_string()))
}

/// Create a new TLSH-cluster family with this hash as the centroid.
pub async fn create_tlsh_family(pool: &PgPool, centroid_sha256: &str, tlsh: &str) -> DbResult<String> {
    let id   = Ulid::new().to_string();
    let name = format!("tlsh-cluster-{}", &centroid_sha256[..8.min(centroid_sha256.len())]);
    sqlx::query(
        "INSERT INTO artifact_families (id, name, verdict, tlsh_centroid)
         VALUES ($1, $2, 'unknown', $3)",
    )
    .bind(&id)
    .bind(&name)
    .bind(tlsh)
    .execute(pool)
    .await?;
    Ok(id)
}

fn infer_verdict_from_rule(rule_name: &str) -> &'static str {
    let lower = rule_name.to_lowercase();
    if lower.contains("malware") || lower.contains("malicious") || lower.contains("ransomware") || lower.contains("trojan") {
        "malicious"
    } else {
        "suspicious"
    }
}
