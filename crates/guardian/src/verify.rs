//! Independent approval verification — the guardian's second check.
//!
//! The guardian calls the Solarplex server directly to confirm an
//! `approval_id` is genuinely granted AND to fetch the server-canonical
//! command and declared effects.  The untrusted adapter never supplies the
//! command; the server is the only authority for what the guardian executes.
//!
//! ## Fail-closed default
//!
//! If the server is unreachable `verify_and_fetch` returns `Err(_)`, and
//! `handle_request` refuses to execute (returns an error response).  This is
//! fail-closed: an unreachable server is always treated as a denial.
//!
//! Set `SOLARPLEX_GUARDIAN_FAIL_OPEN=1` only in controlled development
//! environments where liveness matters more than security.  With the new
//! design this flag has no execution-path effect — there is no command to run
//! if the server fetch fails — but it changes the log level from ERROR to WARN
//! and is preserved for forward compatibility with command-caching mechanisms.
//!
//! ## Server endpoint
//!
//! `GET /api/approvals/{id}` — returns the approval record including:
//! - `decision`        : "granted" | "denied" | "pending"
//! - `approved_command`: the shell command the human approved
//! - `declared_effects`: sandbox policy (file_effects, network_access, etc.)

use anyhow::Result;
use protocol::effects::DeclaredEffects;

/// The server-canonical execution mandate, returned only when `decision == "granted"`.
pub struct ApprovedExecution {
    pub command: String,
    pub declared: DeclaredEffects,
}

/// Verify `approval_id` and fetch the approved command + declared effects.
///
/// Returns `Ok(Some(_))` when the server confirms "granted" and the response
/// contains a valid command.
/// Returns `Ok(None)` when the decision is anything other than "granted".
/// Returns `Err(_)` when the server is unreachable or returns unexpected data.
pub async fn verify_and_fetch(
    approval_id: &str,
    api_base: &str,
    session_id: &str,
    actor_id: &str,
) -> Result<Option<ApprovedExecution>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let url = format!("{api_base}/api/approvals/{approval_id}");
    // X-Session-Id and X-Actor-Id let the server verify session membership,
    // preventing cross-session IDOR on the guardian fetch endpoint.
    let resp = client
        .get(&url)
        .header("X-Session-Id", session_id)
        .header("X-Actor-Id", actor_id)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("approval fetch: server returned {}", resp.status());
    }

    let body: serde_json::Value = resp.json().await?;
    let decision = body["decision"].as_str().unwrap_or("unknown");
    tracing::info!(
        %approval_id,
        decision,
        "guardian: server-verified approval decision",
    );

    if decision != "granted" {
        return Ok(None);
    }

    let command = body["approved_command"]
        .as_str()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "approval {approval_id} is granted but server response is missing \
                 `approved_command` — server endpoint may need updating"
            )
        })?
        .to_string();

    let declared: DeclaredEffects =
        serde_json::from_value(body["declared_effects"].clone()).unwrap_or_default();

    Ok(Some(ApprovedExecution { command, declared }))
}
