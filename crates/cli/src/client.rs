use anyhow::{Context, Result};
use serde_json::Value;

use crate::config::Ctx;

/// Thin async HTTP wrapper around the Solarplex REST API.
pub struct Client {
    http:       reqwest::Client,
    pub server: String,
    token:      Option<String>,
}

impl Client {
    pub fn new(ctx: &Ctx) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(35))
            .build()
            .context("build HTTP client")?;
        Ok(Self { http, server: ctx.server.clone(), token: ctx.token.clone() })
    }

    fn url(&self, path: &str) -> String {
        format!("{}/api{path}", self.server)
    }

    /// Attach `Authorization: Bearer <sp_token>` when we have one. Every
    /// request builder in this file passes through here — session-scoped
    /// routes on the server now reject anything without it.
    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => rb.bearer_auth(t),
            None    => rb,
        }
    }

    /// Turn a 401 into a message pointing at the fix, instead of the generic
    /// "HTTP error" a raw `error_for_status()` would produce — this is the
    /// one failure mode `sp login` actually introduces, so it earns a real
    /// error message rather than a passthrough of reqwest's.
    ///
    /// Every other non-2xx (403/404/422/500/...) reads the response body
    /// before it's dropped and folds it into the error — `error_for_status()`
    /// alone discards the body entirely, which is why every one of those used
    /// to surface as a bare "HTTP error" with no indication of which check
    /// actually failed (e.g. a 403 from `require_active_membership` saying
    /// "not a member of this session" was previously invisible to the user).
    async fn check_status(resp: reqwest::Response, method: &str, url: &str) -> Result<reqwest::Response> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            anyhow::bail!("Not signed in (or your session expired). Run `sp login`.");
        }
        let body = resp.text().await.unwrap_or_default();
        let body = body.trim();
        if body.is_empty() {
            anyhow::bail!("{method} {url} → {status}");
        }
        anyhow::bail!("{method} {url} → {status}: {body}");
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    pub async fn list_sessions(&self, actor_id: Option<&str>) -> Result<Value> {
        let mut url = self.url("/sessions");
        if let Some(a) = actor_id {
            url = format!("{url}?actor_id={a}");
        }
        self.get(&url).await
    }

    pub async fn get_session(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}"))).await
    }

    // ── Digest ────────────────────────────────────────────────────────────────

    /// `GET /api/sessions/:id/digest` — computed-on-read summary (recent
    /// activity, open approvals, artifacts), never a stored value.
    pub async fn get_digest(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/digest"))).await
    }

    // ── Remotes ───────────────────────────────────────────────────────────────

    pub async fn add_remote(&self, local_session_id: &str, remote_session_id: &str) -> Result<Value> {
        self.post(
            &self.url(&format!("/sessions/{local_session_id}/remotes")),
            &serde_json::json!({ "remote_session_id": remote_session_id }),
        ).await
    }

    pub async fn list_remotes(&self, local_session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{local_session_id}/remotes"))).await
    }

    /// Pulls events since the last watermark and advances it — never writes
    /// into the local session's own event log.
    pub async fn fetch_remote(&self, local_session_id: &str, remote_id: &str) -> Result<Value> {
        self.post(
            &self.url(&format!("/sessions/{local_session_id}/remotes/{remote_id}/fetch")),
            &serde_json::json!({}),
        ).await
    }

    pub async fn remove_remote(&self, local_session_id: &str, remote_id: &str) -> Result<()> {
        let url  = self.url(&format!("/sessions/{local_session_id}/remotes/{remote_id}"));
        let resp = self.authed(self.http.delete(&url)).send().await.context("remove_remote")?;
        Self::check_status(resp, "DELETE", &url).await?;
        Ok(())
    }

    pub async fn create_session(
        &self,
        name: &str,
        description: Option<&str>,
        approval_policy: &str,
        created_by: &str,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "name":            name,
            "description":     description,
            "approval_policy": approval_policy,
            "created_by":      created_by,
        });
        self.post(&self.url("/sessions"), &body).await
    }

    /// Rename a session — fires `session.renamed` on the WS bus.
    /// The ULID identity is stable; only the human name changes.
    pub async fn rename_session(
        &self,
        session_id: &str,
        new_name: &str,
        actor_id: Option<&str>,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "name":     new_name,
            "actor_id": actor_id,
        });
        self.patch(&self.url(&format!("/sessions/{session_id}")), &body).await
    }

    /// `PATCH /api/sessions/:id` `{status}` — Pause (`suspended`) / Resume
    /// (`active`) / Archive (`archived`). Server requires Collaborator+
    /// (`routes/sessions.rs::update_session`) — same bar as `rename_session`,
    /// since both go through that one handler.
    pub async fn update_session_status(&self, session_id: &str, status: &str) -> Result<Value> {
        let body = serde_json::json!({ "status": status });
        self.patch(&self.url(&format!("/sessions/{session_id}")), &body).await
    }

    pub async fn transfer_ownership(
        &self,
        session_id: &str,
        from: &str,
        to: &str,
    ) -> Result<()> {
        let body = serde_json::json!({ "from": from, "to": to });
        let url  = self.url(&format!("/sessions/{session_id}/transfer"));
        let resp = self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("transfer_ownership")?;
        Self::check_status(resp, "POST", &url).await?;
        Ok(())
    }

    // ── Mailbox ───────────────────────────────────────────────────────────────

    /// `GET /api/mailbox` — the authenticated actor's own inbox.
    pub async fn list_mailbox(&self) -> Result<Value> {
        self.get(&self.url("/mailbox")).await
    }

    pub async fn mailbox_mark_seen(&self, route_id: &str) -> Result<()> {
        let url  = self.url(&format!("/mailbox/{route_id}/seen"));
        let resp = self.authed(self.http.post(&url)).send().await.context("mailbox_mark_seen")?;
        Self::check_status(resp, "POST", &url).await?;
        Ok(())
    }

    // ── Invites ───────────────────────────────────────────────────────────────

    /// `GET /api/invites/:id` — deliberately unauthenticated server-side
    /// (mirrors the web `/invite/[id]` landing page: you can see what an
    /// invite is for before signing in). Still routed through `self.get`
    /// (attaches a bearer token if we have one) since the server just
    /// ignores it either way — no separate unauthenticated path needed here.
    pub async fn preview_invite(&self, invite_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/invites/{invite_id}"))).await
    }

    /// `POST /api/invites/:id/redeem` — unlike the rest of this client,
    /// the token goes in the JSON body, not the Authorization header
    /// (`routes/invites.rs::redeem` reads `body.sp_token` directly — it
    /// authenticates identity the same way the WS human-session path does,
    /// separately from the REST bearer-auth convention used everywhere else).
    pub async fn redeem_invite(&self, invite_id: &str) -> Result<Value> {
        let token = self.token.clone()
            .ok_or_else(|| anyhow::anyhow!("Not signed in. Run `sp login`."))?;
        let body = serde_json::json!({ "sp_token": token });
        self.post(&self.url(&format!("/invites/{invite_id}/redeem")), &body).await
    }

    /// `POST /api/sessions/:id/invites` — same body-carried-token pattern as
    /// redeem. Role ceiling + owner-only cap staging are enforced
    /// server-side (`crate::authz::can_create_invite`); this just sends it.
    pub async fn create_invite(
        &self,
        session_id: &str,
        role:       &str,
        email:      Option<&str>,
        ttl_secs:   i64,
    ) -> Result<Value> {
        let token = self.token.clone()
            .ok_or_else(|| anyhow::anyhow!("Not signed in. Run `sp login`."))?;
        let body = serde_json::json!({
            "sp_token":      token,
            "role":          role,
            "invitee_email": email,
            "ttl_secs":      ttl_secs,
        });
        self.post(&self.url(&format!("/sessions/{session_id}/invites")), &body).await
    }

    pub async fn revoke_invite(&self, invite_id: &str) -> Result<Value> {
        let url  = self.url(&format!("/invites/{invite_id}/revoke"));
        let resp = self.authed(self.http.post(&url)).send().await.context("revoke_invite")?;
        Self::check_status(resp, "POST", &url).await?
            .json::<Value>().await
            .with_context(|| format!("POST {url} decode"))
    }

    // ── Actors ────────────────────────────────────────────────────────────────

    /// `GET /api/actors/:id` — resolve an actor's real record (id, name,
    /// type). The `name` here is the mutable, self-chosen display name
    /// (`PATCH /auth/me`) — distinct from `id`, which is stable and, for
    /// humans, not something a user ever picks themselves.
    pub async fn get_actor(&self, actor_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/actors/{actor_id}"))).await
    }

    // ── Capability tokens ─────────────────────────────────────────────────────

    pub async fn issue_cap(
        &self,
        session_id: &str,
        actor_id: &str,
        role: &str,
        ttl_secs: u64,
        permissions: &[String],
        mcp_path: Option<&str>,
        parent_cap: Option<&str>,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "actor_id":    actor_id,
            "role":        role,
            "ttl_secs":    ttl_secs,
            "permissions": permissions,
            "mcp_path":    mcp_path,
            "parent_cap":  parent_cap,
        });
        self.post(&self.url(&format!("/sessions/{session_id}/attach-token")), &body).await
    }

    pub async fn list_caps(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/caps"))).await
    }

    // ── Approvals ─────────────────────────────────────────────────────────────

    pub async fn list_approvals(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/approvals"))).await
    }

    #[allow(dead_code)]
    pub async fn list_approvals_for_actor(&self, actor_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/approvals/pending?actor_id={actor_id}"))).await
    }

    /// Long-poll `GET /api/approvals/:id/resolution?timeout=N`.
    /// Returns the decision string: "granted" | "denied" | "timed_out".
    pub async fn poll_resolution(
        &self,
        approval_id: &str,
        timeout_secs: u64,
    ) -> Result<String> {
        let url = self.url(&format!("/approvals/{approval_id}/resolution?timeout={timeout_secs}"));
        // Use a longer client timeout than the server-side polling window
        let resp = self.authed(self.http.get(&url))
            .timeout(std::time::Duration::from_secs(timeout_secs + 10))
            .send()
            .await
            .context("poll_resolution")?;
        let resp = Self::check_status(resp, "GET", &url).await?
            .json::<Value>()
            .await
            .context("poll_resolution decode")?;
        Ok(resp["decision"].as_str().unwrap_or("timed_out").to_string())
    }

    /// POST /api/approvals/:id/vote  { actor_id, decision }
    pub async fn vote(
        &self,
        approval_id: &str,
        actor_id: &str,
        decision: &str, // "grant" | "deny"
    ) -> Result<()> {
        let body = serde_json::json!({ "actor_id": actor_id, "decision": decision });
        let url  = self.url(&format!("/approvals/{approval_id}/vote"));
        let resp = self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("vote")?;
        Self::check_status(resp, "POST", &url).await?;
        Ok(())
    }

    /// POST /api/sessions/:id/approvals — create an approval request.
    /// `POST /api/approvals/:id/delegate` — cross-session delegation. The
    /// target session must already be linked (see `add_remote`'s sibling
    /// authorization note: linking is the "these sessions know each other"
    /// precondition, not itself a grant of decision authority).
    pub async fn delegate_approval(&self, approval_id: &str, target_session_id: &str) -> Result<Value> {
        self.post(
            &self.url(&format!("/approvals/{approval_id}/delegate")),
            &serde_json::json!({ "target_session_id": target_session_id }),
        ).await
    }

    pub async fn create_approval(
        &self,
        session_id: &str,
        actor_id: &str,
        tool_name: &str,
        arguments: &Value,
        timeout_secs: u64,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "actor_id":    actor_id,
            "tool_name":   tool_name,
            "arguments":   arguments,
            "timeout_secs": timeout_secs,
        });
        self.post(&self.url(&format!("/sessions/{session_id}/approvals")), &body).await
    }

    // ── Artifacts ─────────────────────────────────────────────────────────────

    pub async fn list_artifacts(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/artifacts"))).await
    }

    pub async fn get_artifact(&self, session_id: &str, artifact_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/artifacts/{artifact_id}"))).await
    }

    pub async fn create_artifact(
        &self,
        session_id: &str,
        created_by: &str,
        name: &str,
        artifact_type: &str,
        content: &str,
    ) -> Result<Value> {
        let body = serde_json::json!({
            "created_by":    created_by,
            "name":          name,
            "artifact_type": artifact_type,
            "content":       content,
        });
        self.post(&self.url(&format!("/sessions/{session_id}/artifacts")), &body).await
    }

    /// `POST /api/sessions/:target_id/artifacts/import` — a real independent
    /// copy (publish/import, not a live reference), with an auto-fired
    /// context entry recording provenance.
    pub async fn import_artifact(&self, target_session_id: &str, source_session_id: &str, source_artifact_id: &str) -> Result<Value> {
        let body = serde_json::json!({
            "source_session_id":  source_session_id,
            "source_artifact_id": source_artifact_id,
        });
        self.post(&self.url(&format!("/sessions/{target_session_id}/artifacts/import")), &body).await
    }

    // ── Context ───────────────────────────────────────────────────────────────

    pub async fn add_context(
        &self,
        session_id: &str,
        actor_id: &str,
        kind: &str,
        content: &str,
    ) -> Result<()> {
        let body = serde_json::json!({
            "actor_id": actor_id,
            "kind":     kind,
            "content":  content,
        });
        let url  = self.url(&format!("/sessions/{session_id}/context"));
        let resp = self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("add_context")?;
        Self::check_status(resp, "POST", &url).await?;
        Ok(())
    }

    // ── Messages ──────────────────────────────────────────────────────────────

    /// POST /api/sessions/:id/messages  { actor_id, content }
    /// Server returns 204 No Content — do not try to decode a body.
    pub async fn post_message(&self, session_id: &str, actor_id: &str, content: &str) -> Result<()> {
        let body = serde_json::json!({ "actor_id": actor_id, "content": content });
        let url  = self.url(&format!("/sessions/{session_id}/messages"));
        let resp = self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("post_message")?;
        Self::check_status(resp, "POST", &url).await?;
        Ok(())
    }

    // ── Events ────────────────────────────────────────────────────────────────

    /// List events, optionally starting after a given sequence number.
    pub async fn list_events(&self, session_id: &str, limit: i64) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/events?limit={limit}"))).await
    }

    pub async fn list_events_after(&self, session_id: &str, after_seq: i64, limit: i64) -> Result<Value> {
        self.get(&self.url(&format!(
            "/sessions/{session_id}/events?after_seq={after_seq}&limit={limit}"
        ))).await
    }

    // ── Shell adapter ─────────────────────────────────────────────────────────

    /// POST /api/sessions/:id/shell/start  → { command_id }
    ///
    /// - `argv0`    — basename of the first token; always sent
    /// - `command`  — full argv string; `Some` only when tracked=true and the
    ///                credential seatbelt did not fire
    /// - `tracked`  — whether the user opted in to full-command logging
    /// - `redacted` — whether the seatbelt suppressed the full argv
    pub async fn shell_start(
        &self,
        session_id: &str,
        actor_id: &str,
        argv0: &str,
        command: Option<&str>,
        tracked: bool,
        redacted: bool,
    ) -> Result<String> {
        let mut body = serde_json::json!({
            "actor_id": actor_id,
            "argv0":    argv0,
            "tracked":  tracked,
            "redacted": redacted,
        });
        if let Some(cmd) = command {
            body["command"] = serde_json::Value::String(cmd.to_string());
        }
        let resp = self.post(&self.url(&format!("/sessions/{session_id}/shell/start")), &body).await?;
        Ok(resp["command_id"].as_str().unwrap_or("").to_string())
    }

    /// POST /api/sessions/:id/shell/complete  (fire-and-forget OK)
    pub async fn shell_complete(
        &self,
        session_id: &str,
        actor_id: &str,
        command_id: &str,
        exit_code: i32,
        duration_ms: u64,
    ) -> Result<()> {
        let body = serde_json::json!({
            "actor_id":   actor_id,
            "command_id": command_id,
            "exit_code":  exit_code,
            "duration_ms": duration_ms,
        });
        let url = self.url(&format!("/sessions/{session_id}/shell/complete"));
        self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("shell_complete")?;
        Ok(())
    }

    // ── Epoch revocation ──────────────────────────────────────────────────────

    /// `POST /api/sessions/:id/epoch/revoke` — revoke caps by strategy.
    pub async fn revoke_caps(
        &self,
        session_id:     &str,
        revoked_by:     &str,
        strategy:       &str,
        target_cap_id:  Option<&str>,
        target_stratum: Option<i64>,
        drain_window:   u64,
        reroot:         bool,
    ) -> Result<Value> {
        let mut body = serde_json::json!({
            "revoked_by":       revoked_by,
            "strategy":         strategy,
            "drain_window_secs": drain_window,
            "reroot":           reroot,
        });
        if let Some(cap) = target_cap_id   { body["target_cap_id"]  = cap.into(); }
        if let Some(s)   = target_stratum  { body["target_stratum"]  = s.into(); }
        self.post(&self.url(&format!("/sessions/{session_id}/epoch/revoke")), &body).await
    }

    /// `GET /api/sessions/:id/epoch` — current epoch + recent revocations.
    pub async fn session_epoch(&self, session_id: &str) -> Result<Value> {
        self.get(&self.url(&format!("/sessions/{session_id}/epoch"))).await
    }

    // ── Auth query (tuple-space explanatory layer) ────────────────────────────

    pub async fn auth_why(
        &self,
        session_id: &str,
        actor_id:   &str,
        entity:     Option<&str>,
    ) -> Result<Value> {
        let mut url = format!("{}/api/auth/why?session_id={session_id}&actor_id={actor_id}", self.server);
        if let Some(e) = entity { url.push_str(&format!("&entity={e}")); }
        self.get(&url).await
    }

    pub async fn auth_who_can(
        &self,
        session_id: &str,
        entity:     Option<&str>,
    ) -> Result<Value> {
        let mut url = format!("{}/api/auth/who-can?session_id={session_id}", self.server);
        if let Some(e) = entity { url.push_str(&format!("&entity={e}")); }
        self.get(&url).await
    }

    pub async fn auth_lineage(&self, cap_id: &str) -> Result<Value> {
        self.get(&format!("{}/api/auth/lineage?cap_id={cap_id}", self.server)).await
    }

    // ── Identity ──────────────────────────────────────────────────────────────

    /// `GET /auth/me` — resolve the identity behind the bearer token this
    /// client is carrying. Not under `/api`, unlike everything else here.
    pub async fn me(&self) -> Result<Value> {
        self.get(&format!("{}/auth/me", self.server)).await
    }

    /// `POST /auth/oidc/logout` — best-effort server-side token revoke.
    /// Mirrors the frontend's signOut(): callers should clear the local
    /// copy regardless of whether this call succeeds.
    pub async fn oidc_logout(&self, sp_token: &str) -> Result<()> {
        let body = serde_json::json!({ "sp_token": sp_token });
        let url  = format!("{}/auth/oidc/logout", self.server);
        self.authed(self.http.post(&url))
            .json(&body)
            .send()
            .await
            .context("oidc_logout")?;
        Ok(())
    }

    // ── Low-level helpers ─────────────────────────────────────────────────────

    async fn get(&self, url: &str) -> Result<Value> {
        let resp = self.authed(self.http.get(url))
            .send()
            .await
            .with_context(|| format!("GET {url}"))?;
        Self::check_status(resp, "GET", url).await?
            .json::<Value>()
            .await
            .with_context(|| format!("GET {url} decode"))
    }

    async fn post(&self, url: &str, body: &Value) -> Result<Value> {
        let resp = self.authed(self.http.post(url))
            .json(body)
            .send()
            .await
            .with_context(|| format!("POST {url}"))?;
        Self::check_status(resp, "POST", url).await?
            .json::<Value>()
            .await
            .with_context(|| format!("POST {url} decode"))
    }

    async fn patch(&self, url: &str, body: &Value) -> Result<Value> {
        let resp = self.authed(self.http.patch(url))
            .json(body)
            .send()
            .await
            .with_context(|| format!("PATCH {url}"))?;
        Self::check_status(resp, "PATCH", url).await?
            .json::<Value>()
            .await
            .with_context(|| format!("PATCH {url} decode"))
    }
}
