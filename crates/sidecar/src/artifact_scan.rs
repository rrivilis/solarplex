/// Async artifact scan: YARA-X + TLSH, results reported to server.
///
/// Spawned as a background task at both create and read time so neither
/// operation blocks waiting for the scan.
pub fn spawn_artifact_scan(content: String, sha256: String, api_base: String) {
    tokio::spawn(async move {
        scan_and_report(content, sha256, api_base).await;
    });
}

async fn scan_and_report(content: String, sha256: String, api_base: String) {
    let data = content.as_bytes();

    // YARA-X (synchronous inside the spawned task)
    let yara_matches = crate::yara_scan::scan_content(data);

    // TLSH (minimum 50 bytes required)
    let tlsh = compute_tlsh(data);

    if yara_matches.is_empty() && tlsh.is_none() {
        return; // nothing to report — server already has the upsert from create path
    }

    let url = format!("{api_base}/api/artifact-hashes/scan-result");
    let payload = serde_json::json!({
        "sha256":       sha256,
        "tlsh":         tlsh,
        "yara_matches": yara_matches,
    });

    if let Err(e) = reqwest::Client::new()
        .post(&url)
        .json(&payload)
        .send()
        .await
    {
        tracing::warn!("artifact scan report failed: {e}");
    }
}

fn compute_tlsh(data: &[u8]) -> Option<String> {
    if data.len() < 50 {
        return None;
    }
    tlsh2::TlshDefaultBuilder::build_from(data)
        .map(|h| String::from_utf8_lossy(&h.hash()).into_owned())
}
