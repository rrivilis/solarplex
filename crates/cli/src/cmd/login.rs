//! `sp login` / `sp logout` — loopback browser handoff for OIDC sign-in.
//!
//! The CLI never talks to the OIDC provider directly and no server code
//! changed to support this. Instead:
//!
//!   1. Bind an ephemeral `127.0.0.1` listener.
//!   2. Open (and print, as a guaranteed fallback) `{ui}/cli-auth?port=<port>`
//!      — a small frontend page that runs the *existing*, already-reviewed
//!      OIDC flow (PKCE, nonce, `is_safe_return_to`) completely unmodified,
//!      then hands the sp_token it ends up with back to this listener.
//!   3. Accept the one callback request, pull `token` off the query string,
//!      store it, and shut the listener down.
//!
//! This is a browser-mediated handoff of a token the frontend already has,
//! not a new auth protocol — nothing here needed a new OAuth client
//! registration or touched `oidc_start`/`oidc_callback`.

use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;
use ulid::Ulid;

use crate::{client::Client, config, config::Ctx, output::*};

#[derive(Args)]
pub struct LoginArgs {}

#[derive(Args)]
pub struct LogoutArgs {}

// ── sp login ─────────────────────────────────────────────────────────────────

pub async fn run_login(_args: LoginArgs, ctx: &Ctx) -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind loopback listener for sign-in callback")?;
    let port = listener.local_addr()?.port();

    // A per-invocation nonce, not just the port, gates the callback: the
    // port alone is loopback-only (unreachable off-machine) but *any* local
    // caller — including a malicious page in another tab that port-scans
    // localhost — could otherwise hand this listener an attacker-controlled
    // token and get `sp login` to "sign in" as them. Requiring the nonce
    // that only the tab we actually opened ever saw closes that off; this
    // is the same mitigation `gcloud`/`doctl`-style loopback OAuth uses.
    let nonce = Ulid::new().to_string();

    let url = format!("{}/cli-auth?port={port}&nonce={nonce}", ctx.ui);
    println!("{}", bold("Opening your browser to sign in..."));
    println!("{}", dim(&format!("If it doesn't open automatically, visit: {url}")));
    let _ = open_browser(&url); // best-effort only — the printed URL is the real fallback

    println!("{}", dim("Waiting for sign-in (5 min)..."));
    let token = timeout(Duration::from_secs(300), accept_token(listener, &nonce))
        .await
        .context("timed out waiting for sign-in — run `sp login` again")??;

    // Confirm identity *before* declaring success or persisting anything —
    // a token that fails /auth/me (e.g. the browser handed us a stale,
    // already-revoked token) isn't usable for anything else either, so
    // reporting "signed in" here would just relocate the failure to
    // whatever command the user runs next, with a much more confusing error.
    let mut confirm_ctx = ctx.clone();
    confirm_ctx.token = Some(token.clone());
    let me = Client::new(&confirm_ctx)?.me().await
        .context("received a token, but it didn't pass identity verification — it may already be expired or revoked; try signing in again in the browser (not just reusing an existing tab)")?;

    config::save_token(&token)?;
    let name = me["name"].as_str().unwrap_or("?");
    println!("{} Signed in as {}", green("✓"), bold(name));

    // `Ctx::load` reads `SOLARPLEX_TOKEN` from the environment *after* the
    // credentials file and lets it win unconditionally -- deliberate, for
    // CI/scripts, but it means a stale value left in an interactive shell
    // silently shadows the login that just succeeded, with no symptom until
    // the next command fails in a way that looks unrelated to this one
    // having worked. Catch it here, at the one moment it's cheap to explain.
    if std::env::var("SOLARPLEX_TOKEN").is_ok() {
        println!(
            "{} {}",
            yellow("Note:"),
            dim(
                "SOLARPLEX_TOKEN is set in your environment and will override this \
                 login on every future command. Unset it if you want the sign-in \
                 above to actually take effect (fish: `set -e SOLARPLEX_TOKEN`, \
                 bash/zsh: `unset SOLARPLEX_TOKEN`)."
            )
        );
    }
    Ok(())
}

/// Accept loopback connections until one is the real `/callback?token=...`
/// request carrying our nonce; anything else (a browser favicon probe, a
/// stray retry, a request with the wrong or missing nonce) gets a plain
/// 404/403 and we keep waiting rather than erroring out.
async fn accept_token(listener: TcpListener, expected_nonce: &str) -> Result<String> {
    loop {
        let (mut stream, _) = listener.accept().await.context("accept loopback connection")?;

        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await.context("read loopback request")?;
        let request = String::from_utf8_lossy(&buf[..n]);
        let path = request.lines().next().unwrap_or("")
            .split_whitespace().nth(1).unwrap_or("");

        match extract_callback(path) {
            Some((token, nonce)) if nonce == expected_nonce => {
                let body = "<html><body style=\"font-family:sans-serif\">\
                    Signed in \u{2014} you can close this tab and return to your terminal.\
                    </body></html>";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
                return Ok(token);
            }
            Some(_) => {
                // Right shape, wrong nonce — not the tab we opened. Reject
                // without leaking anything about why.
                let _ = stream.write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n").await;
            }
            None => {
                let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n").await;
            }
        }
    }
}

/// Parse `token` + `nonce` off `/callback?token=...&nonce=...`. Returns
/// `None` for any other path so callers can keep waiting instead of
/// erroring on a stray request.
fn extract_callback(path: &str) -> Option<(String, String)> {
    let (route, query) = path.split_once('?')?;
    if route != "/callback" { return None; }

    let mut token: Option<String> = None;
    let mut nonce: Option<String> = None;
    for kv in query.split('&') {
        if let Some(v) = kv.strip_prefix("token=") { token = Some(percent_decode(v)); }
        if let Some(v) = kv.strip_prefix("nonce=") { nonce = Some(percent_decode(v)); }
    }
    match (token, nonce) {
        (Some(t), Some(n)) if !t.is_empty() && !n.is_empty() => Some((t, n)),
        _ => None,
    }
}

/// Minimal percent-decoder — avoids pulling in a dependency for the one
/// query param this listener ever reads.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Best-effort OS-appropriate browser launch. Never fatal — the printed URL
/// above is the actual fallback for headless/SSH/sandboxed environments.
fn open_browser(url: &str) -> std::io::Result<()> {
    #[cfg(target_os = "windows")]
    {
        // Deliberately not `cmd /C start` here: cmd.exe re-parses its `/C`
        // tail as a batch command line, where `&` (present in our URL once
        // it carries both ?port= and &nonce=) is a command separator —
        // it'll happily launch the browser on the truncated URL and then
        // try to "run" the rest as a second command. `explorer.exe <url>`
        // takes the URL as one opaque argument and never does batch parsing.
        std::process::Command::new("explorer").arg(url).spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    Ok(())
}

// ── sp logout ────────────────────────────────────────────────────────────────

pub async fn run_logout(_args: LogoutArgs, ctx: &Ctx) -> Result<()> {
    if ctx.token.is_some() {
        // Best-effort server-side revoke, mirroring the frontend's signOut() —
        // clear locally regardless of whether this succeeds.
        let _ = Client::new(ctx)?.oidc_logout(ctx.token.as_deref().unwrap()).await;
    }
    config::clear_token()?;
    println!("{} Signed out.", green("✓"));
    Ok(())
}
