use std::time::Duration;

use reqwest::Client;
use protocol::messages::ApprovalDecision;
use protocol::types::{AgentStatus, ToolCall};

use crate::Config;

pub struct SessionClient {
    config:   Config,
    api_base: String,
    http:     Client,
}

impl SessionClient {
    pub fn new(config: Config) -> Self {
        let api_base = config.server_ws
            .replace("ws://", "http://")
            .replace("wss://", "https://");
        Self { api_base, config, http: Client::new() }
    }

    fn session_url(&self, suffix: &str) -> String {
        format!("{}/api/sessions/{}{}", self.api_base, self.config.session_id, suffix)
    }

    /// Announce that a real MCP client has attached. Called in response to
    /// `AdapterMessage::ClientConnected` — the adapter observed a genuine SSE
    /// connection open, not merely "the shim process started" (which is not
    /// itself evidence anyone is actually there).
    pub async fn announce(&self) {
        let Some(cap_id) = self.config.cap_id.as_deref() else {
            tracing::error!("shim: agent-attach skipped — no cap_id (SOLARPLEX_TOKEN was never exchanged)");
            return;
        };
        let url = self.session_url("/agent-attach");
        match self.http.post(&url)
            .json(&serde_json::json!({ "actor_id": &self.config.actor_id, "cap_id": cap_id }))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                tracing::info!(
                    actor_id   = %self.config.actor_id,
                    session_id = %self.config.session_id,
                    "shim: announced to server",
                );
            }
            Ok(r) => tracing::error!(status = %r.status(), "shim: agent-attach non-2xx"),
            Err(e) => tracing::error!("shim: agent-attach failed: {e}"),
        }
    }

    /// Announce that the MCP client has disconnected. Called in response to
    /// `AdapterMessage::ClientDisconnected` — the adapter's SSE stream closed.
    pub async fn detach(&self) {
        let Some(cap_id) = self.config.cap_id.as_deref() else {
            tracing::error!("shim: agent-detach skipped — no cap_id (SOLARPLEX_TOKEN was never exchanged)");
            return;
        };
        let url = self.session_url("/agent-detach");
        match self.http.post(&url)
            .json(&serde_json::json!({ "actor_id": &self.config.actor_id, "cap_id": cap_id }))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                tracing::info!(
                    actor_id   = %self.config.actor_id,
                    session_id = %self.config.session_id,
                    "shim: detached from server",
                );
            }
            Ok(r) => tracing::error!(status = %r.status(), "shim: agent-detach non-2xx"),
            Err(e) => tracing::error!("shim: agent-detach failed: {e}"),
        }
    }

    /// Best-effort liveness ping. Agents never hold a WS connection to
    /// `/stream` (that's browser-only), so this periodic call is the only
    /// signal the server has that this shim is still alive — see
    /// `sweep_stale_agents` in the server crate, which marks an actor
    /// detached if this hasn't been called recently enough. Failures are
    /// logged at debug, not warn/error: a single missed beat is expected to
    /// happen occasionally and is not itself actionable.
    pub async fn heartbeat(&self) {
        let Some(cap_id) = self.config.cap_id.as_deref() else {
            tracing::debug!("shim: heartbeat skipped — no cap_id");
            return;
        };
        let url = self.session_url("/agent-heartbeat");
        if let Err(e) = self.http.post(&url)
            .json(&serde_json::json!({ "actor_id": &self.config.actor_id, "cap_id": cap_id }))
            .send().await
        {
            tracing::debug!("shim: heartbeat failed: {e}");
        }
    }

    pub async fn update_status(&self, status: AgentStatus) {
        let Some(cap_id) = self.config.cap_id.as_deref() else {
            tracing::warn!("shim: update_status skipped — no cap_id");
            return;
        };
        let status_str = match status {
            AgentStatus::Running => "running",
            AgentStatus::Waiting => "waiting",
            AgentStatus::Blocked => "blocked",
            AgentStatus::Idle    => "idle",
            AgentStatus::Error   => "error",
        };
        let url = self.session_url("/agent-status");
        if let Err(e) = self.http.post(&url)
            .json(&serde_json::json!({
                "actor_id": &self.config.actor_id,
                "cap_id":   cap_id,
                "status":   status_str,
            }))
            .send().await
        {
            tracing::warn!("shim: update_status failed: {e}");
        }
    }

    /// Fetch the session's server-configured standing approval policies —
    /// see crate::policy::Policy's doc comment for why this matters: without
    /// it, the legacy (non-ORB) approval path only ever consulted its own
    /// hardcoded local list, never whatever the session owner actually
    /// configured. Same X-Session-Id/X-Actor-Id header credential the shim
    /// already uses successfully for poll_approval — agents never hold an
    /// sp_token. Best-effort: an empty result (fetch failure, or no policies
    /// configured) just means the local fallback list decides everything,
    /// same as before this existed.
    pub async fn fetch_approval_policies(&self) -> Vec<crate::policy::ServerPolicy> {
        let url = self.session_url("/approval-policies");
        match self.http.get(&url)
            .header("X-Session-Id", &self.config.session_id)
            .header("X-Actor-Id",   &self.config.actor_id)
            .send().await
        {
            Ok(r) if r.status().is_success() => r.json().await.unwrap_or_else(|e| {
                tracing::warn!("shim: approval-policies parse error: {e}");
                Vec::new()
            }),
            Ok(r) => {
                tracing::warn!(status = %r.status(), "shim: fetch approval-policies non-2xx");
                Vec::new()
            }
            Err(e) => {
                tracing::warn!("shim: fetch approval-policies failed: {e}");
                Vec::new()
            }
        }
    }

    pub async fn create_approval_req(&self, tool_call: &ToolCall) -> Option<String> {
        let cap_id = self.config.cap_id.as_deref()?;
        let url = self.session_url("/approvals");
        let resp = self.http.post(&url)
            .json(&serde_json::json!({
                "actor_id":     &self.config.actor_id,
                "cap_id":       cap_id,
                "tool_name":    &tool_call.tool,
                "arguments":    &tool_call.args,
                "timeout_secs": 25u64,
            }))
            .send().await.ok()?;
        if !resp.status().is_success() {
            tracing::error!(tool = %tool_call.tool, status = %resp.status(), "shim: approval create non-2xx");
            return None;
        }
        let body: serde_json::Value = resp.json().await.ok()?;
        let id = body["approval_id"].as_str()?.to_string();
        tracing::debug!(tool = %tool_call.tool, approval_id = %id, "shim: approval created");
        Some(id)
    }

    pub async fn poll_approval(&self, approval_id: &str) -> ApprovalDecision {
        let timeout_secs = 25u64;
        let poll_url = format!(
            "{}/api/approvals/{}/resolution?timeout={}",
            self.api_base, approval_id, timeout_secs,
        );
        let client_timeout = Duration::from_secs(timeout_secs + 5);
        let poll_resp = match tokio::time::timeout(
            client_timeout,
            self.http.get(&poll_url)
                .header("X-Session-Id", &self.config.session_id)
                .header("X-Actor-Id",   &self.config.actor_id)
                .send(),
        ).await {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::error!(%approval_id, "shim: poll failed: {e}");
                return self.fallback_decision();
            }
            Err(_) => {
                tracing::warn!(%approval_id, "shim: poll client-side timeout");
                return ApprovalDecision::TimedOut;
            }
        };
        let result: serde_json::Value = match poll_resp.json().await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(%approval_id, "shim: poll parse error: {e}");
                return self.fallback_decision();
            }
        };
        let d = result["decision"].as_str().unwrap_or("denied");
        tracing::info!(%approval_id, decision = d, "shim: approval resolved");
        match d {
            "granted"   => ApprovalDecision::Granted,
            "timed_out" => ApprovalDecision::TimedOut,
            _           => ApprovalDecision::Denied,
        }
    }

    pub async fn patch_approval_declared_effects(
        &self,
        approval_id: &str,
        effects:     &protocol::effects::DeclaredEffects,
    ) {
        let url = format!("{}/api/approvals/{}/declared-effects", self.api_base, approval_id);
        if let Err(e) = self.http.patch(&url)
            .header("X-Session-Id", &self.config.session_id)
            .header("X-Actor-Id",   &self.config.actor_id)
            .json(&serde_json::json!({ "declared_effects": effects }))
            .send().await
        {
            tracing::warn!(%approval_id, "shim: patch declared_effects failed: {e}");
        }
    }

    pub async fn patch_approval_scout(
        &self,
        approval_id: &str,
        manifest:    &protocol::effects::ScoutManifest,
    ) {
        let url = format!("{}/api/approvals/{}/scout", self.api_base, approval_id);
        if let Err(e) = self.http.patch(&url)
            .header("X-Session-Id", &self.config.session_id)
            .header("X-Actor-Id",   &self.config.actor_id)
            .json(&serde_json::json!({ "scout_manifest": manifest }))
            .send().await
        {
            tracing::warn!(%approval_id, "shim: patch scout failed: {e}");
        }
    }

    pub async fn patch_approval_execution(
        &self,
        approval_id: &str,
        manifest:    &protocol::effects::ExecutionManifest,
        diverged:    bool,
    ) {
        let url = format!("{}/api/approvals/{}/execution", self.api_base, approval_id);
        if let Err(e) = self.http.patch(&url)
            .header("X-Session-Id", &self.config.session_id)
            .header("X-Actor-Id",   &self.config.actor_id)
            .json(&serde_json::json!({
                "execution_manifest": manifest,
                "diverged":           diverged,
            }))
            .send().await
        {
            tracing::warn!(%approval_id, "shim: patch execution failed: {e}");
        }
    }

    pub async fn post_message(&self, content: String) {
        let url = self.session_url("/messages");
        if let Err(e) = self.http.post(&url)
            .json(&serde_json::json!({
                "actor_id": &self.config.actor_id,
                "cap_id":   self.config.cap_id.as_deref(),
                "content":  content,
            }))
            .send().await
        {
            tracing::warn!("shim: post_message failed: {e}");
        }
    }

    pub async fn invoke_method(
        &self,
        cap_id:       &str,
        method:       &str,
        args:         &serde_json::Value,
        timeout_secs: u64,
    ) -> Option<InvokeResponse> {
        let url = self.session_url("/invoke");
        match self.http.post(&url)
            .json(&serde_json::json!({
                "cap_id":                cap_id,
                "method":                method,
                "args":                  args,
                "approval_timeout_secs": timeout_secs,
            }))
            .send().await
        {
            Ok(r) if r.status().is_success() => r.json::<InvokeResponse>().await.ok(),
            Ok(r) => {
                tracing::warn!(method, status = %r.status(), "shim: invoke non-2xx");
                None
            }
            Err(e) => {
                tracing::warn!(method, "shim: invoke failed: {e}");
                None
            }
        }
    }

    pub async fn consume_receipt(&self, receipt_id: &str) -> Option<serde_json::Value> {
        let url = self.session_url("/consume-receipt");
        match self.http.post(&url)
            .json(&serde_json::json!({ "receipt_id": receipt_id }))
            .send().await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.ok()?;
                Some(body["args"].clone())
            }
            Ok(r) => {
                tracing::warn!(%receipt_id, status = %r.status(), "shim: consume-receipt non-2xx");
                None
            }
            Err(e) => {
                tracing::warn!(%receipt_id, "shim: consume-receipt failed: {e}");
                None
            }
        }
    }

    pub async fn attest_file_write(
        &self,
        receipt_id:           &str,
        cap_id:               &str,
        tool:                 &str,
        path:                 &str,
        approved_hash_before: &str,
        approved_hash_after:  &str,
        observed_hash_before: &str,
        actual_hash_after:    &str,
    ) -> Option<AttestationResult> {
        let url = self.session_url("/attest");
        let body = serde_json::json!({
            "receipt_id":           receipt_id,
            "cap_id":               cap_id,
            "actor_id":             &self.config.actor_id,
            "tool":                 tool,
            "path":                 path,
            "approved_hash_before": approved_hash_before,
            "approved_hash_after":  approved_hash_after,
            "observed_hash_before": observed_hash_before,
            "actual_hash_after":    actual_hash_after,
        });
        match self.http.post(&url).json(&body).send().await {
            Ok(r) if r.status().is_success() || r.status() == 202 => {
                let body: serde_json::Value = r.json().await.ok()?;
                Some(AttestationResult {
                    attestation_id: body["attestation_id"].as_str().unwrap_or("").to_owned(),
                    hash_mismatch:  body["hash_mismatch"].as_bool().unwrap_or(false),
                })
            }
            Ok(r) => {
                tracing::warn!(%receipt_id, status = %r.status(), "shim: attest non-2xx");
                None
            }
            Err(e) => {
                tracing::warn!(%receipt_id, "shim: attest failed: {e}");
                None
            }
        }
    }

    fn fallback_decision(&self) -> ApprovalDecision {
        if self.config.fail_open {
            ApprovalDecision::Granted
        } else {
            ApprovalDecision::Denied
        }
    }
}

#[derive(Debug, serde::Deserialize)]
pub struct InvokeResponse {
    pub status:      String,
    pub receipt_id:  Option<String>,
    pub approval_id: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct AttestationResult {
    pub attestation_id: String,
    pub hash_mismatch:  bool,
}
