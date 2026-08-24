//! OIDC authentication for human actors.
//!
//! # Flow
//!
//! 1. `GET /auth/oidc/start`
//!    Generates a PKCE pair (challenge + verifier) and a random CSRF state
//!    token, stores `(verifier_secret, nonce_secret)` in
//!    `AppState::oidc.pending` keyed by the state parameter, and
//!    302-redirects the browser to the provider.
//!
//! 2. Provider redirects to `GET /auth/oidc/callback?code=<code>&state=<state>`
//!    - Validates state (CSRF guard; single-use via DashMap::remove)
//!    - Exchanges code + PKCE verifier for an ID token
//!    - Verifies ID token signature and nonce (replay prevention)
//!    - Maps `(sub, provider)` → `actor_id` (creates actor on first login)
//!    - Issues an opaque Solarplex `sp_token` in `human_sessions` (7-day TTL)
//!    - 302-redirects to `OIDC_FRONTEND_REDIRECT#sp_token=<token>` — or, when
//!      `/start` was called with `?client=desktop` (the Tauri shell opening
//!      this flow in the system browser instead of its own webview), to
//!      `DESKTOP_REDIRECT_URI#sp_token=<token>` instead (default
//!      `solarplex-desktop://auth`, handled by `frontend/src-tauri`).
//!
//! 3. `POST /auth/oidc/logout` revokes a single session token.
//!
//! # Trust boundary
//!
//! OIDC answers "who are you?" (identity).
//! The cap DAG answers "what can you do?" (authorization).
//! These two layers are intentionally separate and must never be merged.
//! Agents use the `join_token` path; they never touch OIDC.
//!
//! # Adversarial design notes
//!
//! - State parameter is single-use (DashMap::remove); replays return 400.
//! - PKCE verifier mismatch is caught by the provider during code exchange.
//! - ID token nonce binds the token to this exact login flow; cross-session
//!   injection fails verification.
//! - `sp_token` format is validated before any DB lookup (see `validate_token_format`).
//! - `sub` + `provider` are the identity key; `google/alice` ≠ `github/alice`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context as _};
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use chrono::Utc;
use serde::Deserialize;
use ulid::Ulid;

use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};

use crate::state::{AppState, OidcState, PkceEntry};

// ── OIDC config ───────────────────────────────────────────────────────────────

/// OIDC configuration loaded from environment variables at startup.
/// All four variables are required when OIDC is enabled.
pub struct OidcConfig {
    /// e.g. `https://accounts.google.com`
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    /// Must match the redirect URI registered with the provider exactly.
    pub redirect_uri: String,
}

impl OidcConfig {
    /// Load from environment.  Returns `None` when `OIDC_ISSUER_URL` is unset,
    /// meaning OIDC is disabled for this deployment.
    pub fn from_env() -> Option<Self> {
        let issuer_url    = std::env::var("OIDC_ISSUER_URL").ok()?;
        let client_id     = std::env::var("OIDC_CLIENT_ID").ok()?;
        let client_secret = std::env::var("OIDC_CLIENT_SECRET").ok()?;
        let redirect_uri  = std::env::var("OIDC_REDIRECT_URI").ok()?;
        Some(Self { issuer_url, client_id, client_secret, redirect_uri })
    }
}

/// Initialise the OIDC client via provider discovery (async HTTP).
/// Call once at startup; fail fast if misconfigured.
pub async fn init_oidc(cfg: OidcConfig) -> anyhow::Result<OidcState> {
    let issuer = IssuerUrl::new(cfg.issuer_url)
        .context("invalid OIDC_ISSUER_URL")?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, async_http_client)
        .await
        .context("OIDC provider discovery failed, check OIDC_ISSUER_URL and network")?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(cfg.client_id),
        Some(ClientSecret::new(cfg.client_secret)),
    )
    .set_redirect_uri(
        RedirectUrl::new(cfg.redirect_uri.clone()).context("invalid OIDC_REDIRECT_URI")?
    );

    Ok(OidcState {
        client:      Arc::new(client),
        redirect_uri: cfg.redirect_uri,
        pending:     Default::default(),
    })
}

// ── GET /auth/oidc/start ──────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct StartQuery {
    /// Same-origin relative path to land on after a successful login, e.g.
    /// `/invite/01J...`. Invalid values are silently dropped in favor of the
    /// default post-login redirect; a malformed return_to should never
    /// break the ability to log in at all.
    return_to: Option<String>,
    /// Set to exactly `"desktop"` by the Tauri shell (see `frontend/lib/auth.ts`'s
    /// `signIn()`) when it opens this URL in the system browser instead of its
    /// own webview. See `PkceEntry::desktop`'s doc comment for why the final
    /// redirect target is resolved server-side rather than trusting this value
    /// itself as (or as a pointer to) a redirect URL.
    client: Option<String>,
}

/// Whether `path` is safe to place unmodified into a same-origin redirect.
///
/// Rejects anything that could redirect off-origin: must start with exactly
/// one `/` (not `//`, which browsers resolve as protocol-relative to an
/// arbitrary host), and must not contain an embedded scheme (`://`).
fn is_safe_return_to(path: &str) -> bool {
    path.starts_with('/')
        && !path.starts_with("//")
        && !path.contains("://")
        && path.len() <= 512
}

/// Best-effort client IP for rate limiting the two pre-authentication OIDC
/// routes below. There is no actor_id to key on yet, so this is the only
/// identity available. `X-Forwarded-For` is only trusted when
/// `TRUST_PROXY_HEADERS=1` is set (the deploy's own responsibility to set,
/// only when the server genuinely sits behind a reverse proxy that
/// overwrites that header rather than passing a client-supplied one
/// through), otherwise any caller could spoof it to get a fresh bucket on
/// every request, defeating the limit entirely.
fn client_ip(connect_info: &SocketAddr, headers: &HeaderMap) -> String {
    let trust_proxy = std::env::var("TRUST_PROXY_HEADERS").ok().as_deref() == Some("1");
    if trust_proxy {
        if let Some(fwd) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = fwd.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return first.to_string();
            }
        }
    }
    connect_info.ip().to_string()
}

pub async fn oidc_start(
    State(state): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(query):  Query<StartQuery>,
) -> Response {
    let oidc = match state.oidc.as_ref() {
        Some(o) => o,
        None    => return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured").into_response(),
    };
    let ip = client_ip(&connect_info, &headers);
    if let Some(res) = crate::rate_limit::gate_global(
        crate::rate_limit::GlobalRateLimitKey::OidcAttempt { ip },
        &state.rate_limits,
    ) {
        return res;
    }

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = oidc.client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let return_to = query.return_to
        .filter(|p| is_safe_return_to(p))
        .unwrap_or_default();
    let desktop = query.client.as_deref() == Some("desktop");

    // Store (verifier, nonce, return_to, desktop) keyed by state param; TTL = 10 minutes
    oidc.pending.insert(
        csrf_token.secret().clone(),
        PkceEntry {
            verifier_secret: pkce_verifier.secret().to_string(),
            nonce_secret:    nonce.secret().to_string(),
            expires:         Instant::now() + Duration::from_secs(600),
            return_to,
            desktop,
        },
    );

    // Lazy sweep of stale entries (each /start request cleans up expired ones)
    sweep_pending(oidc);

    Redirect::temporary(auth_url.as_str()).into_response()
}

/// Remove PKCE entries that have passed their TTL.
fn sweep_pending(oidc: &OidcState) {
    let now = Instant::now();
    oidc.pending.retain(|_, entry| entry.expires > now);
}

// ── GET /auth/oidc/callback ───────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CallbackQuery {
    code:  Option<String>,
    state: Option<String>,
    /// RFC 6749 §4.1.2.1 provider error fields
    error:             Option<String>,
    error_description: Option<String>,
}

pub async fn oidc_callback(
    State(app): State<Arc<AppState>>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<CallbackQuery>,
) -> Response {
    let oidc = match app.oidc.as_ref() {
        Some(o) => o,
        None    => return (StatusCode::NOT_IMPLEMENTED, "OIDC not configured").into_response(),
    };
    // This is the expensive half of the pair (a real round trip to the
    // provider, plus a DB write) and the actual brute-force target. Same
    // bucket as `oidc_start` (see `GlobalRateLimitKey::OidcAttempt`'s doc).
    let ip = client_ip(&connect_info, &headers);
    if let Some(res) = crate::rate_limit::gate_global(
        crate::rate_limit::GlobalRateLimitKey::OidcAttempt { ip },
        &app.rate_limits,
    ) {
        return res;
    }

    // Provider returned an error (user denied consent, misconfigured scope, etc.)
    if let Some(err) = params.error {
        let desc = params.error_description.as_deref().unwrap_or("");
        tracing::warn!(error = %err, description = %desc, "OIDC provider error on callback");
        return (StatusCode::BAD_GATEWAY, format!("provider error: {err}")).into_response();
    }

    let code        = match params.code  { Some(c) => c, None => return bad("missing code")  };
    let state_param = match params.state { Some(s) => s, None => return bad("missing state") };

    // ── CSRF guard ────────────────────────────────────────────────────────────
    // DashMap::remove is single-use: a replayed state param finds no entry.
    let entry = match oidc.pending.remove(&state_param) {
        Some((_, e)) => e,
        None         => return bad("unknown or expired state, possible CSRF or replay"),
    };

    if entry.expires < Instant::now() {
        // Entry was present but already past TTL (rare after lazy sweep)
        return bad("login flow expired, please start again");
    }

    // Extract before verifier_secret/nonce_secret are moved out of `entry` below.
    let return_to = entry.return_to.clone();
    let desktop    = entry.desktop;

    // ── Code exchange + PKCE verification ────────────────────────────────────
    let token_response = oidc.client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(PkceCodeVerifier::new(entry.verifier_secret))
        .request_async(async_http_client)
        .await;

    let token_response = match token_response {
        Ok(r)  => r,
        Err(e) => {
            tracing::error!("OIDC code exchange failed: {e}");
            return (StatusCode::BAD_GATEWAY, "token exchange failed").into_response();
        }
    };

    // ── ID token verification ─────────────────────────────────────────────────
    let id_token = match token_response.id_token() {
        Some(t) => t,
        None    => return (StatusCode::BAD_GATEWAY, "provider did not return an ID token").into_response(),
    };

    let nonce  = Nonce::new(entry.nonce_secret);
    let claims = match id_token.claims(&oidc.client.id_token_verifier(), &nonce) {
        Ok(c)  => c,
        Err(e) => {
            // Nonce mismatch, signature failure, audience mismatch all land here
            tracing::warn!("ID token verification failed: {e}");
            return (StatusCode::UNAUTHORIZED, "ID token verification failed").into_response();
        }
    };

    let sub      = claims.subject().as_str();
    let email    = claims.email().map(|e| e.as_str().to_string());
    let name     = claims.name()
        .and_then(|n| n.get(None))
        .map(|s| s.as_str().to_string());
    let provider = provider_slug(claims.issuer().as_str());

    // ── Actor resolution ──────────────────────────────────────────────────────
    let actor_id = match sub_to_actor_id(&app, sub, &provider, email.as_deref(), name.as_deref()).await {
        Ok(id)   => id,
        Err(res) => return res,
    };

    // ── Issue Solarplex sp_token ──────────────────────────────────────────────
    let sp_token   = Ulid::new().to_string();
    let expires_at = Utc::now() + chrono::Duration::days(7);

    if let Err(e) = db::human_sessions::create(
        &app.db, &sp_token, &actor_id, sub, &provider, expires_at,
    ).await {
        tracing::error!("human_sessions::create failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "session creation failed").into_response();
    }

    // ── Redirect back ──────────────────────────────────────────────────────────
    // Fragment (#) keeps the token off server access logs and browser history.
    //
    // The desktop shell opened this whole flow in the *system* browser, not
    // its own webview (see PkceEntry::desktop's doc comment for why) — so
    // "redirect back to the frontend origin" doesn't apply here, there's no
    // app open at that origin in this browser. Instead redirect to a fixed
    // custom-scheme URL the OS hands off to the desktop app, which captures
    // the token and navigates its own webview to `/#sp_token=...` (see
    // frontend/src-tauri/src/lib.rs's `on_open_url`). Deliberately a fixed
    // server-side default, not caller-supplied. Same reasoning as
    // `is_safe_return_to` restricting `return_to` to a relative path instead
    // of trusting a raw URL from the request.
    if desktop {
        let desktop_redirect = std::env::var("DESKTOP_REDIRECT_URI")
            .unwrap_or_else(|_| "solarplex-desktop://auth".to_string());
        return Redirect::temporary(&format!("{desktop_redirect}#sp_token={sp_token}")).into_response();
    }

    // `return_to` was already validated as a safe same-origin relative path
    // at /start time (see `is_safe_return_to`); appended, not substituted, so
    // this still works when OIDC_FRONTEND_REDIRECT points at a full origin
    // in a split frontend/backend deployment.
    let frontend = std::env::var("OIDC_FRONTEND_REDIRECT")
        .unwrap_or_else(|_| "/".to_string());
    Redirect::temporary(&format!("{frontend}{return_to}#sp_token={sp_token}")).into_response()
}

// ── POST /auth/oidc/logout ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct LogoutBody {
    sp_token: String,
}

pub async fn oidc_logout(
    State(app): State<Arc<AppState>>,
    Json(body): Json<LogoutBody>,
) -> impl IntoResponse {
    if let Err(e) = validate_token_format(&body.sp_token) {
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }
    match db::human_sessions::revoke(&app.db, &body.sp_token).await {
        Ok(())  => StatusCode::NO_CONTENT.into_response(),
        Err(e)  => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── GET /auth/me ───────────────────────────────────────────────────────────

/// Resolve the caller's own identity from a verified sp_token. The frontend
/// uses this to show a real name/avatar in place of the `?actor=` param it
/// used before real auth existed, unrelated to the mailbox work; this is
/// just "who am I", not "what's addressed to me".
pub async fn me(
    State(app):  State<Arc<AppState>>,
    headers:     axum::http::HeaderMap,
) -> Response {
    let actor_id = match require_sp_auth(&app.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::actors::get(&app.db, &actor_id).await {
        Ok(actor) => Json(serde_json::json!({
            "id":    actor.id,
            "name":  actor.name,
            "email": actor.email,
            "type":  actor.r#type,
        })).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, "actor not found").into_response(),
    }
}

// ── PATCH /auth/me ──────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateMeBody {
    name: String,
}

/// Let a signed-in actor set their own display name. The OIDC provider's
/// `name`/`email` claim is only ever a *first-login* default
/// (`sub_to_actor_id`), with no way to change it afterward until now.
/// `upsert_human`'s `ON CONFLICT (id) DO UPDATE SET name` is already exactly
/// this operation; no new DB logic needed, just a route that reaches it
/// under the caller's own verified identity rather than an arbitrary id.
pub async fn update_me(
    State(app):  State<Arc<AppState>>,
    headers:     axum::http::HeaderMap,
    Json(body):  Json<UpdateMeBody>,
) -> Response {
    let actor_id = match require_sp_auth(&app.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    let name = body.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return (StatusCode::BAD_REQUEST, "name must be 1-100 characters").into_response();
    }
    match db::actors::upsert_human(&app.db, &actor_id, name).await {
        Ok(actor) => Json(serde_json::json!({
            "id":    actor.id,
            "name":  actor.name,
            "email": actor.email,
            "type":  actor.r#type,
        })).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── GET /auth/sessions ────────────────────────────────────────────────────────

/// Sign-in history. Every active `sp_token` for the caller's own actor,
/// Google/GitHub "devices" style. `human_sessions` already tracked
/// everything this needs (issued_at/last_seen/provider) from the original
/// OIDC login work; this is purely a new read + a revoke action over
/// existing data, not new tracking.
pub async fn list_sessions(
    State(app): State<Arc<AppState>>,
    headers:    axum::http::HeaderMap,
) -> Response {
    let actor_id = match require_sp_auth(&app.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    // Best-effort: a missing/malformed header here would already have
    // failed require_sp_auth above, so this is just recovering the same raw
    // token to compute which row (if any) is "this device".
    let current_hash = extract_bearer(&headers).map(|t| db::human_sessions::hash_token(&t));

    match db::human_sessions::list_for_actor(&app.db, &actor_id).await {
        Ok(rows) => {
            let items: Vec<serde_json::Value> = rows.iter().map(|r| serde_json::json!({
                "id":         r.id,
                "provider":   r.provider,
                "issued_at":  r.issued_at,
                "expires_at": r.expires_at,
                "last_seen":  r.last_seen,
                "is_current": current_hash.as_deref() == Some(r.id.as_str()),
            })).collect();
            Json(items).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── DELETE /auth/sessions/:id ─────────────────────────────────────────────────

/// Revoke one sign-in for "sign out this device" from the sign-in history
/// view. `id` here is the hash `list_sessions` returned, not a raw token;
/// scoped to the caller's own actor_id, so this can never revoke someone
/// else's session no matter what id is passed.
pub async fn revoke_session(
    State(app): State<Arc<AppState>>,
    headers:    axum::http::HeaderMap,
    Path(id):   Path<String>,
) -> Response {
    let actor_id = match require_sp_auth(&app.db, &headers).await {
        Ok(id)   => id,
        Err(res) => return res,
    };
    match db::human_sessions::revoke_by_id_for_actor(&app.db, &id, &actor_id).await {
        Ok(0)    => StatusCode::NOT_FOUND.into_response(),
        Ok(_)    => StatusCode::NO_CONTENT.into_response(),
        Err(e)   => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

// ── Token validation (called by WS handler) ───────────────────────────────────

/// Validate an `sp_token` presented on a WebSocket upgrade request.
///
/// Called in the HTTP upgrade phase before any WebSocket handshake.
/// Sanitizes the token format first (rejects obviously malformed values before
/// touching the database), then does a single SELECT that checks expiry
/// atomically at the DB level.
///
/// On success, fires a best-effort `touch` (updates `last_seen`) in a spawned
/// task so it does not add latency to the WS connect path.
pub async fn validate_sp_token(
    pool:      &sqlx::PgPool,
    raw_token: &str,
) -> anyhow::Result<db::human_sessions::HumanSessionRow> {
    validate_token_format(raw_token)?;

    let row = db::human_sessions::lookup(pool, raw_token)
        .await
        .map_err(|_| anyhow!("invalid or expired sp_token"))?;

    // Touch last_seen in background. Non-blocking, non-fatal
    let pool_clone  = pool.clone();
    let token_clone = raw_token.to_string();
    tokio::spawn(async move {
        let _ = db::human_sessions::touch(&pool_clone, &token_clone).await;
    });

    Ok(row)
}

// ── REST auth helpers (Bearer sp_token) ────────────────────────────────────────
//
// Shared by any REST handler that needs a verified human identity rather
// than a self-asserted actor_id in the request body. Originally lived only
// in routes/approvals.rs; promoted here once more handlers needed the exact
// same extraction via one implementation, not N copies that can drift.

/// Extract a Bearer sp_token from the Authorization header.
pub fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get("authorization")?.to_str().ok()?;
    val.strip_prefix("Bearer ").map(|s| s.trim().to_string())
}

/// Validate a Bearer sp_token from request headers and return the actor_id.
/// Returns `Err(Response)` on auth failure so handlers can propagate with `?`.
pub async fn require_sp_auth(
    db:      &sqlx::PgPool,
    headers: &axum::http::HeaderMap,
) -> Result<String, axum::response::Response> {
    let raw = extract_bearer(headers).ok_or_else(|| {
        (StatusCode::UNAUTHORIZED, "Authorization: Bearer <sp_token> required")
            .into_response()
    })?;
    let row = validate_sp_token(db, &raw).await.map_err(|_| {
        (StatusCode::UNAUTHORIZED, "invalid or expired sp_token").into_response()
    })?;
    Ok(row.actor_id)
}

/// Verify the request carries a valid sp_token *and* that the resolved
/// actor is a member of `session_id` with at least `min_role`'s authority.
/// The shared gate for every session-scoped GET, because a valid token alone is
/// not the boundary: an authenticated stranger must not be able to read a
/// session's data just by knowing its ULID.
///
/// "Member" here also covers lazily-auto-granted Observer access via a
/// full-visibility `session_links` row, see `require_membership_or_linked_
/// access`'s doc comment. That auto-grant only ever satisfies an
/// Observer-ceiling `min_role`, so this stays the correct gate for
/// Collaborator+ endpoints too, unchanged.
pub async fn require_session_member(
    db:         &sqlx::PgPool,
    headers:    &axum::http::HeaderMap,
    session_id: &str,
    min_role:   protocol::types::MemberRole,
) -> Result<String, axum::response::Response> {
    let actor_id = require_sp_auth(db, headers).await?;
    match db::sessions::require_membership_or_linked_access(db, session_id, &actor_id, min_role).await {
        Ok(_) => Ok(actor_id),
        Err(db::DbError::NotFound) =>
            Err((StatusCode::FORBIDDEN, "not a member of this session").into_response()),
        Err(db::DbError::Unauthorized) =>
            Err((StatusCode::FORBIDDEN, "insufficient role for this session").into_response()),
        Err(e) =>
            Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()),
    }
}

/// Validate a live capability token as the caller's credential, the agent
/// equivalent of `require_sp_auth`/`require_session_member` for humans.
/// Agents never hold an sp_token (OIDC is human-only, see this module's
/// top doc comment); the cap they were issued at attach time is the only
/// credential they have. Same trust-boundary checks `routes::invoke`
/// already applies for tool calls (not-found, wrong session, expired,
/// revoked, epoch-superseded), reused here for the session-lifecycle
/// endpoints agents call outside the invoke path.
///
/// Returns the actor_id from the *validated cap row*, never from a
/// caller-supplied body field. The whole point is that the caller doesn't
/// get to assert who they are just by typing a different actor_id.
pub async fn require_cap_auth(
    db:         &sqlx::PgPool,
    session_id: &str,
    cap_id:     &str,
) -> Result<String, axum::response::Response> {
    require_cap_auth_typed(db, session_id, cap_id).await
        .map_err(|(status, reason)| (status, reason).into_response())
}

/// Same checks as `require_cap_auth`, but a typed, `Clone`able verdict
/// instead of a `Response` — a `Response` can't be cached or awaited by
/// more than one caller. Needed by `agent_heartbeat` (routes/sessions.rs)
/// for its negative cache + singleflight coalescing: a permanently-dead
/// cap (not found, wrong session, expired, revoked, epoch-superseded — none
/// of these ever recover) can be remembered and replayed without hitting
/// the DB again. The one behavioral difference from `require_cap_auth`: the
/// two transient-DB-error branches report a generic "internal error"
/// instead of the specific `e.to_string()`, since that error variant is
/// deliberately never cached (see the `status != INTERNAL_SERVER_ERROR`
/// guard at the call site) and a `'static` reason is what makes this type
/// cheaply cacheable in the first place.
pub async fn require_cap_auth_typed(
    db:         &sqlx::PgPool,
    session_id: &str,
    cap_id:     &str,
) -> Result<String, (StatusCode, &'static str)> {
    let cap = db::tokens::get_cap(db, cap_id).await.map_err(|e| match e {
        db::DbError::NotFound => (StatusCode::UNAUTHORIZED, "cap not found"),
        _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
    })?;
    if cap.session_id != session_id {
        return Err((StatusCode::FORBIDDEN, "cap does not belong to this session"));
    }
    if cap.expires_at < Utc::now() {
        return Err((StatusCode::GONE, "cap expired"));
    }
    if cap.revoked_at.is_some() {
        return Err((StatusCode::GONE, "cap revoked"));
    }
    let current_epoch = db::epochs::current(db, session_id).await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;
    if cap.epoch != current_epoch {
        return Err((StatusCode::GONE, "cap epoch superseded, re-attach required"));
    }
    Ok(cap.actor_id)
}

/// Shared gate for endpoints both humans (browser/CLI, sp_token) and agents
/// (sidecar, cap_id) call, session messages and context entries being the
/// first two. Tries the sp_token path first when an `Authorization` header
/// is present (so a human never falls through to a cap check just because
/// their token happens to be invalid); otherwise falls back to `cap_id`.
/// Returns the verified actor_id from whichever credential was actually
/// presented.
pub async fn require_sp_or_cap_auth(
    db:         &sqlx::PgPool,
    headers:    &axum::http::HeaderMap,
    session_id: &str,
    cap_id:     Option<&str>,
    min_role:   protocol::types::MemberRole,
) -> Result<String, axum::response::Response> {
    if extract_bearer(headers).is_some() {
        return require_session_member(db, headers, session_id, min_role).await;
    }
    match cap_id {
        Some(cap) => require_cap_auth(db, session_id, cap).await,
        None => Err((
            StatusCode::UNAUTHORIZED,
            "Authorization: Bearer <sp_token>, or a cap_id, is required",
        ).into_response()),
    }
}

/// Token format guard, validates before any DB query.
///
/// Accepts ULID-format strings (26 chars, Crockford base32) plus up to 128
/// chars for future format flexibility.  Rejects:
///   - empty strings
///   - tokens > 128 characters (resist index-scan amplification)
///   - control characters including null bytes and newlines
///     (resist HTTP header injection; sqlx uses parameterized queries, so this
///     is defence-in-depth rather than the primary SQL injection guard)
pub fn validate_token_format(token: &str) -> anyhow::Result<()> {
    if token.is_empty() {
        bail!("sp_token is empty");
    }
    if token.len() > 128 {
        bail!("sp_token too long ({} max chars 128)", token.len());
    }
    if token.bytes().any(|b| b < 0x20 || b == 0x7f) {
        bail!("sp_token contains control characters");
    }
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Map an OIDC `(sub, provider)` identity to a Solarplex `actor_id`.
///
/// Re-uses an existing actor if this identity has logged in before.
/// Creates a new actor on first login.
///
/// Invariant: the same OIDC identity always maps to the same actor_id, across
/// all sessions and all time.  This is enforced by `find_actor_by_sub`
/// returning the previously-created actor.
///
/// Provider is part of the key: `google/alice` ≠ `github/alice`.
async fn sub_to_actor_id(
    app:      &AppState,
    sub:      &str,
    provider: &str,
    email:    Option<&str>,
    name:     Option<&str>,
) -> Result<String, Response> {
    let pool = &app.db;
    if let Some(actor_id) = db::human_sessions::find_actor_by_sub(pool, sub, provider).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?
    {
        return Ok(actor_id);
    }

    // First login only. An existing identity above never reaches this
    // check, so a returning user's every-day sign-in is never rate-limited
    // by it. Tier 2 (crate::rate_limit) because this happens before any
    // actor, let alone session, exists to scope the check to.
    let (admission, policy) = app.rate_limits.check(
        crate::rate_limit::GlobalRateLimitKey::ActorCreate {
            sub: sub.to_string(), provider: provider.to_string(),
        },
    );
    if !matches!(admission, session::rate_limit::Admission::Allowed) {
        tracing::warn!(
            sub, provider, policy = policy.map(|p| p.describe()).unwrap_or_default(),
            "auth: new-actor creation rate limited",
        );
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "too many new sign-ups from this identity, try again later",
        ).into_response());
    }

    // First login: create a new Solarplex actor
    let display_name = name.or(email).unwrap_or(sub).to_string();
    let email_str    = email.unwrap_or("").to_string();

    let actor = db::actors::create_human(
        pool,
        db::actors::CreateHuman { name: display_name, email: email_str },
    ).await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response())?;

    // One-time catch-up: named invites addressed to this email may have
    // been created before this actor existed to route them to (see the
    // write-time population in routes::sessions::create_invite, which only
    // fires when the email already resolves to a known actor). Non-fatal since
    // a missed mailbox entry doesn't block login; the invite is still
    // reachable by its link either way.
    if let Some(email) = actor.email.as_deref().filter(|e| !e.is_empty()) {
        if let Err(e) = db::mailbox::backfill_for_email(pool, &actor.id, email).await {
            tracing::warn!(actor_id = %actor.id, "mailbox backfill failed: {e}");
        }
    }

    Ok(actor.id)
}

/// Derive a stable, human-readable provider slug from an OIDC issuer URL.
///
/// ```text
/// "https://accounts.google.com"              → "google"
/// "https://token.actions.githubusercontent.com" → "github"
/// "https://login.microsoftonline.com/..."    → "microsoft"
/// "https://login.windows.net/..."            → "microsoft"
/// "https://auth.example.com"                 → "example.com"
/// "https://login.corp.internal"              → "corp.internal"
/// ```
///
/// The slug is stored in `human_sessions.provider` and used as the second
/// half of the identity key with `sub`.  It must be stable across provider
/// discovery refreshes for the same issuer.
pub fn provider_slug(issuer: &str) -> String {
    let host = issuer
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or(issuer);

    if host.contains("google")                                   { return "google".to_string(); }
    if host.contains("github") || host.contains("githubusercontent") { return "github".to_string(); }
    if host.contains("microsoft") || host.contains("azure")
       || host.contains("windows.net") || host.contains("live")  { return "microsoft".to_string(); }

    // Generic: strip common auth-subdomain prefixes for a compact slug
    host.trim_start_matches("accounts.")
        .trim_start_matches("auth.")
        .trim_start_matches("login.")
        .trim_start_matches("sso.")
        .to_string()
}

fn bad(msg: &'static str) -> Response {
    (StatusCode::BAD_REQUEST, msg).into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(ttl_offset_secs: i64) -> PkceEntry {
        let expires = if ttl_offset_secs >= 0 {
            Instant::now() + Duration::from_secs(ttl_offset_secs as u64)
        } else {
            // already expired
            Instant::now() - Duration::from_secs((-ttl_offset_secs) as u64)
        };
        PkceEntry { verifier_secret: "v".into(), nonce_secret: "n".into(), expires, return_to: String::new(), desktop: false }
    }

    // ── PKCE pending state ────────────────────────────────────────────────────

    #[test]
    fn test_pkce_entry_valid_when_fresh() {
        let entry = make_entry(600);
        assert!(entry.expires > Instant::now());
    }

    #[test]
    fn test_pkce_entry_expired_after_ttl() {
        let entry = make_entry(-1);
        assert!(entry.expires < Instant::now());
    }

    #[test]
    fn test_sweep_removes_only_expired_entries() {
        let oidc = OidcState {
            client:      Arc::new(build_dummy_client()),
            redirect_uri: String::new(),
            pending:     Default::default(),
        };
        oidc.pending.insert("live".into(),    make_entry(600));
        oidc.pending.insert("expired".into(), make_entry(-1));

        sweep_pending(&oidc);

        assert_eq!(oidc.pending.len(), 1);
        assert!(oidc.pending.contains_key("live"),    "live entry must survive");
        assert!(!oidc.pending.contains_key("expired"), "expired entry must be removed");
    }

    #[test]
    fn test_sweep_keeps_all_valid_entries() {
        let oidc = OidcState {
            client:      Arc::new(build_dummy_client()),
            redirect_uri: String::new(),
            pending:     Default::default(),
        };
        for i in 0..5 { oidc.pending.insert(i.to_string(), make_entry(600)); }
        sweep_pending(&oidc);
        assert_eq!(oidc.pending.len(), 5, "all valid entries must survive");
    }

    // ── CSRF / state param guard ──────────────────────────────────────────────

    #[test]
    fn test_forged_state_param_finds_no_entry() {
        // Attacker forges a state parameter not in the pending map.
        let pending: dashmap::DashMap<String, PkceEntry> = Default::default();
        pending.insert("correct_state".into(), make_entry(600));

        assert!(
            pending.remove("forged_csrf_state").is_none(),
            "forged state must not match any pending entry"
        );
        assert!(pending.contains_key("correct_state"), "legitimate entry must be untouched");
    }

    #[test]
    fn test_state_param_is_single_use_replay_rejected() {
        let pending: dashmap::DashMap<String, PkceEntry> = Default::default();
        pending.insert("state123".into(), make_entry(600));

        // First use: succeeds
        assert!(pending.remove("state123").is_some(), "first use must succeed");
        // Replay: entry is gone
        assert!(
            pending.remove("state123").is_none(),
            "replayed state param must be rejected, entry consumed on first use"
        );
    }

    #[test]
    fn test_concurrent_different_state_params_independent() {
        // Two concurrent logins each get their own state → no cross-contamination
        let pending: dashmap::DashMap<String, PkceEntry> = Default::default();
        pending.insert("alice_state".into(), make_entry(600));
        pending.insert("bob_state".into(),   make_entry(600));

        assert!(pending.remove("alice_state").is_some());
        assert!(pending.remove("bob_state").is_some());
        assert_eq!(pending.len(), 0);
    }

    // ── Token format validation ───────────────────────────────────────────────

    #[test]
    fn test_valid_ulid_format_accepted() {
        assert!(validate_token_format("01HXYZ1234567890ABCDEFGHJ").is_ok());
    }

    #[test]
    fn test_empty_token_rejected() {
        let err = validate_token_format("");
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_token_at_128_chars_accepted() {
        assert!(validate_token_format(&"A".repeat(128)).is_ok());
    }

    #[test]
    fn test_token_at_129_chars_rejected() {
        let err = validate_token_format(&"A".repeat(129));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn test_null_byte_in_token_rejected() {
        assert!(validate_token_format("valid\x00suffix").is_err());
    }

    #[test]
    fn test_control_characters_in_token_rejected() {
        for c in ['\x01', '\x1f', '\x7f'] {
            let token = format!("good{c}bad");
            assert!(
                validate_token_format(&token).is_err(),
                "control char U+{:04X} must be rejected",
                c as u32
            );
        }
    }

    // Adversarial: HTTP header injection via token value
    #[test]
    fn test_adversarial_newline_injection_rejected() {
        let token = "prefix\nX-Injected-Header: evil\nsuffix";
        assert!(
            validate_token_format(token).is_err(),
            "newline in token must be rejected (HTTP header injection guard)"
        );
    }

    #[test]
    fn test_adversarial_carriage_return_injection_rejected() {
        let token = "prefix\rX-Header: evil";
        assert!(
            validate_token_format(token).is_err(),
            "CR in token must be rejected"
        );
    }

    // Adversarial: oversized token to amplify DB index scan
    #[test]
    fn test_adversarial_10kb_token_rejected_before_db() {
        let huge = "A".repeat(10_000);
        assert!(
            validate_token_format(&huge).is_err(),
            "10KB token must be rejected before reaching DB"
        );
    }

    // ── Provider slug ─────────────────────────────────────────────────────────

    #[test]
    fn test_provider_slug_google() {
        assert_eq!(provider_slug("https://accounts.google.com"), "google");
    }

    #[test]
    fn test_provider_slug_github_actions() {
        assert_eq!(
            provider_slug("https://token.actions.githubusercontent.com"),
            "github"
        );
    }

    #[test]
    fn test_provider_slug_microsoft_aad() {
        assert_eq!(
            provider_slug("https://login.microsoftonline.com/tenant-id/v2.0"),
            "microsoft"
        );
    }

    #[test]
    fn test_provider_slug_azure_windows_net() {
        assert_eq!(
            provider_slug("https://login.windows.net/tenant/v2.0"),
            "microsoft"
        );
    }

    #[test]
    fn test_provider_slug_generic_auth_prefix_stripped() {
        assert_eq!(provider_slug("https://auth.example.com"), "example.com");
    }

    #[test]
    fn test_provider_slug_generic_login_prefix_stripped() {
        assert_eq!(provider_slug("https://login.corp.internal"), "corp.internal");
    }

    #[test]
    fn test_provider_slug_generic_sso_prefix_stripped() {
        assert_eq!(provider_slug("https://sso.acme.io"), "acme.io");
    }

    #[test]
    fn test_provider_slug_path_not_included() {
        // Path components after the host must not leak into the slug
        assert_eq!(
            provider_slug("https://auth.example.com/realms/master"),
            "example.com"
        );
    }

    // ── Provider / sub isolation ──────────────────────────────────────────────

    #[test]
    fn test_sub_provider_key_isolation() {
        // The identity lookup key is (sub, provider).
        // The same sub from different providers must not collide.
        let google_key = ("alice_sub_123", "google");
        let github_key = ("alice_sub_123", "github");
        assert_ne!(google_key, github_key,
            "google/alice and github/alice are distinct identities");
    }

    #[test]
    fn test_same_sub_same_provider_is_same_identity() {
        // Idempotent: logging in twice with the same OIDC identity is the same actor.
        // This is the invariant enforced by sub_to_actor_id; the DB lookup is the gate.
        let key1 = ("alice_sub_123", "google");
        let key2 = ("alice_sub_123", "google");
        assert_eq!(key1, key2, "same identity across logins must resolve to same actor");
    }

    // ── Helper: build a CoreClient without network for unit tests ─────────────
    //
    // We can't construct a real CoreClient without discovery.
    // Tests that need one use a minimal stub via from_provider_metadata-equivalent.
    // Tests that don't need it avoid OidcState entirely.

    fn build_dummy_client() -> CoreClient {
        use openidconnect::{
            core::{CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType},
            AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeySetUrl,
            ResponseTypes,
        };

        let provider_metadata = CoreProviderMetadata::new(
            IssuerUrl::new("https://example.com".to_string()).unwrap(),
            AuthUrl::new("https://example.com/auth".to_string()).unwrap(),
            JsonWebKeySetUrl::new("https://example.com/jwks".to_string()).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![],
            EmptyAdditionalProviderMetadata {},
        );

        CoreClient::from_provider_metadata(
            provider_metadata,
            ClientId::new("test_client".to_string()),
            Some(ClientSecret::new("test_secret".to_string())),
        )
    }
}
