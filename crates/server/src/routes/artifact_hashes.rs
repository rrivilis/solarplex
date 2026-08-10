use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::state::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/artifact-hashes/:sha256",   get(lookup))
        .route("/artifact-hashes/scan-result", post(scan_result))
}

// ── GET /api/artifact-hashes/:sha256 ─────────────────────────────────────────

async fn lookup(
    Path(sha256):  Path<String>,
    State(state):  State<Arc<AppState>>,
) -> impl IntoResponse {
    match db::artifact_reputation::lookup(&state.db, &sha256).await {
        Ok(None) => (StatusCode::NOT_FOUND, "hash not seen").into_response(),
        Ok(Some((row, verdict, family_name))) => {
            let cms_score = state.cms.lock().ok()
                .and_then(|cms| cms.score(""));  // placeholder — scoring happens at write time
            Json(serde_json::json!({
                "sha256":      row.sha256,
                "verdict":     verdict.as_str(),
                "family_id":   row.family_id,
                "family_name": family_name,
                "seen_count":  row.seen_count,
                "yara_matches":row.yara_matches,
                "tlsh":        row.tlsh,
                "cms_score":   cms_score,
            })).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── POST /api/artifact-hashes/scan-result ────────────────────────────────────

#[derive(Deserialize)]
struct ScanResultBody {
    sha256:       String,
    tlsh:         Option<String>,
    #[serde(default)]
    yara_matches: Vec<String>,
}

async fn scan_result(
    State(state): State<Arc<AppState>>,
    Json(body):   Json<ScanResultBody>,
) -> impl IntoResponse {
    // Update hash record with YARA matches + TLSH; get all families for clustering.
    let families = match db::artifact_reputation::update_scan_results(
        &state.db,
        &body.sha256,
        body.tlsh.as_deref(),
        &body.yara_matches,
    )
    .await
    {
        Ok(f)  => f,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };

    // YARA-based family assignment takes precedence (first match wins).
    if let Some(rule_name) = body.yara_matches.first() {
        match db::artifact_reputation::find_or_create_yara_family(&state.db, rule_name).await {
            Ok((family_id, _)) => {
                let _ = db::artifact_reputation::assign_family(
                    &state.db, &body.sha256, &family_id, "yara",
                ).await;
            }
            Err(e) => tracing::warn!("yara family assign failed: {e}"),
        }
        return StatusCode::OK.into_response();
    }

    // TLSH clustering: find nearest centroid below threshold.
    if let Some(tlsh_str) = &body.tlsh {
        let closest = families.iter()
            .filter_map(|f| {
                let centroid = f.tlsh_centroid.as_deref()?;
                let dist = tlsh_distance(tlsh_str, centroid)?;
                Some((dist, f.id.clone()))
            })
            .min_by_key(|(d, _)| *d);

        match closest {
            Some((dist, family_id))
                if dist < db::artifact_reputation::TLSH_CLUSTER_THRESHOLD =>
            {
                let _ = db::artifact_reputation::assign_family(
                    &state.db, &body.sha256, &family_id, "cluster",
                ).await;
            }
            _ => {
                // New cluster — create family with this hash as centroid.
                match db::artifact_reputation::create_tlsh_family(
                    &state.db, &body.sha256, tlsh_str,
                )
                .await
                {
                    Ok(family_id) => {
                        let _ = db::artifact_reputation::assign_family(
                            &state.db, &body.sha256, &family_id, "cluster",
                        ).await;
                    }
                    Err(e) => tracing::warn!("tlsh family create failed: {e}"),
                }
            }
        }
    }

    StatusCode::OK.into_response()
}

/// Compute TLSH distance between two ASCII-encoded TLSH strings.
/// Returns `None` if either string fails to parse.
fn tlsh_distance(a: &str, b: &str) -> Option<i32> {
    let ha: tlsh2::TlshDefault = a.parse().ok()?;
    let hb: tlsh2::TlshDefault = b.parse().ok()?;
    Some(ha.diff(&hb, false))
}
