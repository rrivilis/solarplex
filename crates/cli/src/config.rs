use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Runtime context — assembled from env vars, config file, and CLI flags.
#[derive(Debug, Clone)]
pub struct Ctx {
    pub server:     String,
    pub session_id: Option<String>,
    pub actor_id:   Option<String>,
    /// The `--actor`/`SOLARPLEX_ACTOR_ID` value for *this invocation only* —
    /// `None` when the caller relied on a persisted config-file default
    /// instead of stating one explicitly. Distinct from `actor_id`, which
    /// also picks up that persisted file value; some flows (`session enter`)
    /// need to tell "you told me who you are right now" apart from "this is
    /// just whatever an earlier `--actor` left lying around," since the
    /// latter should defer to the logged-in identity instead of winning by
    /// default. See `cmd::session::enter`.
    pub actor_flag: Option<String>,
    /// Web UI base URL (for OSC-8 hyperlinks, and as the `sp login` handoff target).
    pub ui:         String,
    /// sp_token from `sp login`, if any. `SOLARPLEX_TOKEN` env (for CI/scripts)
    /// overrides the stored credentials file; there's no CLI flag for this one
    /// deliberately — flags land in shell history and process listings, which
    /// a bearer token shouldn't.
    pub token:      Option<String>,
}

impl Ctx {
    /// Build context: config file < env vars < explicit CLI flags.
    pub fn load(
        server_flag: Option<String>,
        session_flag: Option<String>,
        actor_flag:   Option<String>,
    ) -> Self {
        // 1. Defaults
        let mut server     = "http://localhost:8080".to_string();
        let mut session_id = None::<String>;
        let mut actor_id   = None::<String>;
        let mut ui         = "http://localhost:3000".to_string();

        // 2. Config file
        if let Some(cfg) = load_file() {
            if let Some(v) = cfg.server     { server     = v; }
            if let Some(v) = cfg.session_id { session_id = Some(v); }
            if let Some(v) = cfg.actor_id   { actor_id   = Some(v); }
            if let Some(v) = cfg.ui         { ui         = v; }
        }

        // 3. Env vars (override file)
        if let Ok(v) = std::env::var("SOLARPLEX_SERVER")     { server     = v; }
        if let Ok(v) = std::env::var("SOLARPLEX_SESSION_ID") { session_id = Some(v); }
        let env_actor = std::env::var("SOLARPLEX_ACTOR_ID").ok();
        if let Some(ref v) = env_actor { actor_id = Some(v.clone()); }
        if let Ok(v) = std::env::var("SOLARPLEX_UI")         { ui         = v; }

        // 4. Explicit CLI flags (highest priority)
        if let Some(v) = server_flag  { server     = v; }
        if let Some(v) = session_flag { session_id = Some(v); }
        // Deliberately NOT folding `env_actor` in here (unlike server/session
        // above) — `actor_flag` only ever holds a *literal* `--actor <value>`
        // now that main.rs's Cli struct dropped `env = "SOLARPLEX_ACTOR_ID"`
        // from that arg. See the field doc comment and main.rs's for why:
        // that env var is self-exported by our own `session.fish`/`session.sh`,
        // so treating it as "explicit" here would be the same self-poisoning
        // loop moved one level down instead of actually fixed.
        if let Some(ref v) = actor_flag { actor_id = Some(v.clone()); }

        // Token: stored credentials file, then SOLARPLEX_TOKEN env override.
        let mut token = load_token();
        if let Ok(v) = std::env::var("SOLARPLEX_TOKEN") { token = Some(v); }

        Self { server, session_id, actor_id, actor_flag, ui, token }
    }

    pub fn require_session(&self) -> Result<&str> {
        self.session_id.as_deref().ok_or_else(|| anyhow::anyhow!(
            "No session attached. Run `sp session attach <id>` or set SOLARPLEX_SESSION_ID."
        ))
    }

    pub fn require_actor(&self) -> Result<&str> {
        self.actor_id.as_deref().ok_or_else(|| anyhow::anyhow!(
            "No actor set. Run `sp session attach <id> --actor <name>` or set SOLARPLEX_ACTOR_ID."
        ))
    }
}

// ── Persisted config file ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FileConfig {
    pub server:     Option<String>,
    pub session_id: Option<String>,
    pub actor_id:   Option<String>,
    pub ui:         Option<String>,
}

/// Platform-appropriate config path:
///   Windows: %APPDATA%\solarplex\session.json
///   Unix:    ~/.config/solarplex/session.json
pub fn config_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok()
            .map(|v| PathBuf::from(v).join("solarplex").join("session.json"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok()
            .map(|v| PathBuf::from(v).join(".config").join("solarplex").join("session.json"))
    }
}

// ── Per-session cursor store ──────────────────────────────────────────────────

/// Cursor saved to disk by `sp watch`.  Mirrors `ReflectorCursor` in the
/// server crate but lives here to avoid a cross-crate dependency in the CLI.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct SavedCursor {
    pub seq:   i64,
    pub epoch: u32,
}

/// Path for the per-session cursor file.
///   Windows: %APPDATA%\solarplex\cursors\<session_id>.json
///   Unix:    ~/.config/solarplex/cursors/<session_id>.json
pub fn cursor_path(session_id: &str) -> Option<PathBuf> {
    config_path()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .map(|dir| dir.join("cursors").join(format!("{session_id}.json")))
}

/// Load the cursor for a session from disk.  Returns the zero cursor if the
/// file does not exist or cannot be parsed.
pub fn load_cursor(session_id: &str) -> SavedCursor {
    cursor_path(session_id)
        .and_then(|p| std::fs::read(&p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Persist the cursor for a session to disk.
pub fn save_cursor(session_id: &str, cursor: SavedCursor) -> Result<()> {
    let path = cursor_path(session_id)
        .ok_or_else(|| anyhow::anyhow!("cannot determine cursor dir"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(std::fs::write(&path, serde_json::to_string(&cursor)?)?)
}

/// Fish-sourceable env file written alongside the JSON config.
pub fn fish_env_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok()
            .map(|v| PathBuf::from(v).join("solarplex").join("session.fish"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok()
            .map(|v| PathBuf::from(v).join(".config").join("solarplex").join("session.fish"))
    }
}

/// POSIX-sourceable (bash/zsh/Oils-OSH) env file written alongside the JSON
/// config — the `session.sh` shell/solarplex.sh sources.
pub fn posix_env_path() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok()
            .map(|v| PathBuf::from(v).join("solarplex").join("session.sh"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok()
            .map(|v| PathBuf::from(v).join(".config").join("solarplex").join("session.sh"))
    }
}

/// Single-quote a string for safe embedding in POSIX shell source (bash,
/// zsh, dash, Oils' OSH). Single quotes are the only POSIX quoting form
/// with no escape processing at all inside them — the sole exception is an
/// embedded single quote itself, closed via the standard `'\''` trick
/// (close the quote, emit an escaped literal quote, reopen). Robust against
/// arbitrary content (`$`, backticks, spaces, other quotes) in a way a
/// double-quote+backslash scheme is not — matters here because `--server`/
/// `--ui` are user-supplied URLs, not values this code fully controls.
pub fn posix_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn load_file() -> Option<FileConfig> {
    let path = config_path()?;
    let bytes = std::fs::read(&path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

// ── Credentials (sp_token from `sp login`) ────────────────────────────────────
//
// Deliberately a separate file from session.json/session.fish: the fish
// companion gets `set -gx`'d into every shell that sources it, which is
// exactly wrong for a bearer credential (shell history, `env`, child
// processes would all see it). Nothing here is ever written to that file.

/// Path for the stored sp_token.
///   Windows: %APPDATA%\solarplex\credentials.json
///   Unix:    ~/.config/solarplex/credentials.json
pub fn credentials_path() -> Option<PathBuf> {
    config_path()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .map(|dir| dir.join("credentials.json"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Credentials {
    sp_token: String,
}

/// Load the stored sp_token, if `sp login` has been run and the file is
/// still readable/parseable. Silently `None` on any failure — an absent or
/// corrupt credentials file should read as "not logged in", not crash.
pub fn load_token() -> Option<String> {
    let path = credentials_path()?;
    let bytes = std::fs::read(&path).ok()?;
    let creds: Credentials = serde_json::from_slice(&bytes).ok()?;
    Some(creds.sp_token)
}

/// Persist the sp_token issued by `sp login`. `0600` on Unix so other local
/// users can't read a live bearer credential off disk; Windows gets the
/// default ACL for the user's own APPDATA (no equivalent narrowing attempted
/// here — same tradeoff the frontend documents for localStorage).
pub fn save_token(sp_token: &str) -> Result<()> {
    let path = credentials_path().ok_or_else(|| anyhow::anyhow!("cannot determine config dir"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&Credentials { sp_token: sp_token.to_string() })?;
    std::fs::write(&path, json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Remove the stored sp_token (`sp logout`). Not finding one to remove is
/// not an error — logging out when already logged out is a no-op.
pub fn clear_token() -> Result<()> {
    if let Some(path) = credentials_path() {
        match std::fs::remove_file(&path) {
            Ok(())                                            => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e)                                             => Err(e.into()),
        }
    } else {
        Ok(())
    }
}

/// Write the session config file plus a Fish-sourceable *and* a
/// POSIX-sourceable (bash/zsh/Oils-OSH) companion. Writing both
/// unconditionally — regardless of which shell is actually in use — is
/// cheap and means this function never needs to know or guess which shell
/// called it; whichever adapter script is active just sources the one file
/// it already knows how to read.
pub fn save(cfg: &FileConfig) -> Result<()> {
    let path = config_path().ok_or_else(|| anyhow::anyhow!("cannot determine config dir"))?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(cfg)?;
    std::fs::write(&path, json)?;

    // Write fish companion
    if let Some(fish_path) = fish_env_path() {
        let mut lines = Vec::new();
        if let Some(ref v) = cfg.server     { lines.push(format!("set -gx SOLARPLEX_SERVER {v:?}")); }
        if let Some(ref v) = cfg.session_id { lines.push(format!("set -gx SOLARPLEX_SESSION_ID {v:?}")); }
        if let Some(ref v) = cfg.actor_id   { lines.push(format!("set -gx SOLARPLEX_ACTOR_ID {v:?}")); }
        if let Some(ref v) = cfg.ui         { lines.push(format!("set -gx SOLARPLEX_UI {v:?}")); }
        std::fs::write(fish_path, lines.join("\n") + "\n")?;
    }

    // Write POSIX companion (bash/zsh/Oils-OSH)
    if let Some(posix_path) = posix_env_path() {
        let mut lines = Vec::new();
        if let Some(ref v) = cfg.server     { lines.push(format!("export SOLARPLEX_SERVER={}", posix_quote(v))); }
        if let Some(ref v) = cfg.session_id { lines.push(format!("export SOLARPLEX_SESSION_ID={}", posix_quote(v))); }
        if let Some(ref v) = cfg.actor_id   { lines.push(format!("export SOLARPLEX_ACTOR_ID={}", posix_quote(v))); }
        if let Some(ref v) = cfg.ui         { lines.push(format!("export SOLARPLEX_UI={}", posix_quote(v))); }
        std::fs::write(posix_path, lines.join("\n") + "\n")?;
    }

    Ok(())
}
