use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

use protocol::types::EntityHandle;

use crate::{client::Client, config::Ctx, output::*};
use super::{act, actor, approval, artifact, ask, cap, context, invite, session};

// ── Plumb command ─────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct PlumbArgs {
    #[command(subcommand)]
    pub cmd: PlumbCmd,
}

#[derive(Subcommand)]
pub enum PlumbCmd {
    /// Route text through plumbing rules and execute the matching action.
    /// Called by terminal URI handler and fish keybinding.
    #[command(name = "run")]
    Run {
        /// Text or URI to plumb (e.g. "artifact/01J...", "solarplex://approval/01J...")
        text: String,
        /// Print the matched action without executing it
        #[arg(long)]
        dry_run: bool,
        /// Mark the source as untrusted (set by the OS URI handler / WezTerm
        /// OSC-8 click path).  User-defined rules and state-mutating built-ins
        /// are skipped; only read-safe built-in rules with constrained captures
        /// are allowed to fire.
        #[arg(long)]
        untrusted: bool,
    },
    /// Resolve a bare ULID to its entity type (heuristic-first, API fallback)
    Resolve {
        id: String,
    },
}

pub async fn run(args: PlumbArgs, ctx: &Ctx) -> Result<()> {
    match args.cmd {
        PlumbCmd::Run { text, dry_run, untrusted } => plumb(&text, dry_run, untrusted, ctx).await,
        PlumbCmd::Resolve { id }                   => resolve(&id, ctx).await,
    }
}

// ── Typed actions ─────────────────────────────────────────────────────────────
//
// A resolved dispatch target, built directly from a match — never a template
// string handed to `sh -c`.  There is no shell in this path, so a capture
// can't smuggle shell metacharacters: it can only ever become a typed
// argument to an in-process handler call.

enum Action {
    ArtifactGet(String),
    ContextShow(String),
    ApprovalWait(String),
    CapGet(String),
    ActorShow(String),
    SessionAsk(String),
    SessionEnter(String),
    SessionWorkspace(String),
    SessionNewPane(String),
    SessionContext(String),
    /// Free-text `sp ask ...` — read-only by construction (see act.rs's own
    /// doc comment on the ask/act split), so untrusted dispatch is fine once
    /// there's no shell involved in getting here.
    Ask(Vec<String>),
    /// Free-text `sp act <entity> <transition>` — always state-mutating;
    /// never runs on the untrusted (foreign-URI-click) path.
    Act(String, String),
    Resolve(String),
    /// Preview an invite — read-only, no auth required, mirrors the
    /// default-action pattern every other entity uses (a bare click always
    /// shows, never mutates; redeeming is `sp invite redeem`, explicit).
    InviteShow(String),
    /// Hands off to the OS browser as a single argv element — never
    /// shell-interpolated.
    OpenUrl(String),
}

impl Action {
    fn describe(&self) -> String {
        match self {
            Action::ArtifactGet(id)      => format!("artifact get {id}"),
            Action::ContextShow(id)      => format!("context show {id}"),
            Action::ApprovalWait(id)     => format!("approval wait {id}"),
            Action::CapGet(id)           => format!("cap get {id}"),
            Action::ActorShow(id)        => format!("actor show {id}"),
            Action::SessionAsk(id)       => format!("ask session/{id}"),
            Action::SessionEnter(id)     => format!("session enter {id}"),
            Action::SessionWorkspace(id) => format!("session workspace {id}"),
            Action::SessionNewPane(id)   => format!("session new-pane {id}"),
            Action::SessionContext(id)   => format!("context ls {id}"),
            Action::Ask(argv)            => format!("ask {}", argv.join(" ")),
            Action::Act(entity, tr)      => format!("act {entity} {tr}"),
            Action::Resolve(id)          => format!("resolve {id}"),
            Action::InviteShow(id)       => format!("invite show {id}"),
            Action::OpenUrl(url)         => format!("xdg-open {url}"),
        }
    }
}

/// The default read action for a resolved entity handle. This is the single
/// place that decides what "the" command for an entity type is — previously
/// duplicated (and drifted) between this file's rule table and
/// `EntityHandle::trusted_sp_command`.
fn default_action(handle: &EntityHandle) -> Action {
    match handle {
        EntityHandle::Session(id)  => Action::SessionAsk(id.clone()),
        EntityHandle::Artifact(id) => Action::ArtifactGet(id.clone()),
        EntityHandle::Actor(id)    => Action::ActorShow(id.clone()),
        EntityHandle::Context(id)  => Action::ContextShow(id.clone()),
        EntityHandle::Cap(id)      => Action::CapGet(id.clone()),
        EntityHandle::Approval(id) => Action::ApprovalWait(id.clone()),
        EntityHandle::Invite(id)   => Action::InviteShow(id.clone()),
    }
}

/// Match `text` against the built-in, typed rule set.
///
/// Trust gating happens here, inline, while an `EntityHandle` is still in
/// scope — `EntityHandle::permits_untrusted_dispatch()` is the single
/// authority for entity-addressed actions; `Action::Act` is the one
/// unconditionally-trusted-only free-text action (it mutates state).
fn match_builtin(text: &str, is_untrusted: bool) -> Option<Action> {
    // Session verb suffixes — checked first, since "session/ID/enter" isn't
    // a bare entity address and would otherwise fail EntityHandle::from_uri.
    for (suffix, wrap) in [
        ("/enter",     Action::SessionEnter     as fn(String) -> Action),
        ("/workspace", Action::SessionWorkspace as fn(String) -> Action),
        ("/new-pane",  Action::SessionNewPane   as fn(String) -> Action),
        ("/context",   Action::SessionContext   as fn(String) -> Action),
    ] {
        if let Some(id) = text.strip_prefix("session/").and_then(|r| r.strip_suffix(suffix)) {
            if id.is_empty() { continue; }
            let handle = EntityHandle::Session(id.to_string());
            if is_untrusted && !handle.permits_untrusted_dispatch() { return None; }
            return Some(wrap(id.to_string()));
        }
    }

    // Generic entity address: session | artifact | actor | context | cap | approval
    if let Some(handle) = EntityHandle::from_uri(text) {
        if is_untrusted && !handle.permits_untrusted_dispatch() { return None; }
        return Some(default_action(&handle));
    }

    // Free-text navigation: `ask/<query...>` — read-only, safe untrusted.
    if let Some(rest) = text.strip_prefix("ask/") {
        return Some(Action::Ask(rest.split_whitespace().map(String::from).collect()));
    }

    // Free-text transition: `act/<kind>/<id>/<transition>` — always mutates
    // state, never runs from an untrusted (foreign-content) source.
    if let Some(rest) = text.strip_prefix("act/") {
        if is_untrusted { return None; }
        let parts: Vec<&str> = rest.split('/').collect();
        if parts.len() == 3 && parts.iter().all(|p| !p.is_empty()) {
            return Some(Action::Act(format!("{}/{}", parts[0], parts[1]), parts[2].to_string()));
        }
        return None;
    }

    // Bare 26-char ULID → resolve its type, then dispatch its default action.
    let is_ulid = text.len() == 26
        && text.chars().all(|c| "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c));
    if is_ulid {
        return Some(Action::Resolve(text.to_string()));
    }

    // HTTP(S) URLs — hand off to OS browser (argv, never shell-interpolated).
    if text.starts_with("http://") || text.starts_with("https://") {
        return Some(Action::OpenUrl(text.to_string()));
    }

    None
}

/// Which shell adapter (if any) is sourced into the calling interactive
/// shell — set by shell/solarplex.fish and shell/solarplex.sh themselves at
/// load time (`SOLARPLEX_SHELL_KIND=fish`/`posix`), never guessed from
/// `$SHELL` (that's the user's *login* shell, not necessarily the one
/// actually running this command). Only `Action::SessionEnter` needs this —
/// everything else plumb dispatches to is shell-syntax-agnostic. Falls back
/// to fish, matching this command's behavior before POSIX support existed.
fn detected_shell_kind() -> session::ShellKind {
    match std::env::var("SOLARPLEX_SHELL_KIND").as_deref() {
        Ok("posix") => session::ShellKind::Posix,
        _           => session::ShellKind::Fish,
    }
}

/// Execute a resolved `Action` in-process — no subshell, no re-parsed argv,
/// no second `sp` process spawned to do what the running one can call
/// directly.
async fn dispatch(action: Action, ctx: &Ctx, dry_run: bool, is_untrusted: bool) -> Result<()> {
    if dry_run {
        let trust_label = if is_untrusted { dim(" [untrusted]") } else { String::new() };
        println!("{} {}{}", dim("→"), cyan(&action.describe()), trust_label);
        return Ok(());
    }

    match action {
        Action::ArtifactGet(id) =>
            artifact::run(artifact::ArtifactArgs { cmd: artifact::ArtifactCmd::Get { id, save: None } }, ctx).await,
        Action::ContextShow(id) =>
            context::run(context::ContextArgs { cmd: context::ContextCmd::Show { entry_id: id, session_id: None } }, ctx).await,
        Action::ApprovalWait(id) =>
            approval::run(approval::ApprovalArgs { cmd: approval::ApprovalCmd::Wait { id: Some(id), timeout: 55, follow: false } }, ctx).await,
        Action::CapGet(id) =>
            cap::run(cap::CapArgs { cmd: cap::CapCmd::Get { id } }, ctx).await,
        Action::ActorShow(id) =>
            actor::run(actor::ActorArgs { cmd: actor::ActorCmd::Show { id } }, ctx).await,
        Action::SessionAsk(id) =>
            ask::run(ask::AskArgs { entity: Some(format!("session/{id}")), function: None, rest: vec![] }, ctx).await,
        Action::SessionEnter(id) =>
            session::run(session::SessionArgs {
                cmd: session::SessionCmd::Enter { id, shell: detected_shell_kind() },
            }, ctx).await,
        Action::SessionWorkspace(id) =>
            session::run(session::SessionArgs {
                cmd: session::SessionCmd::Workspace { id: Some(id), panes: "inspect,feed".to_string() },
            }, ctx).await,
        Action::SessionNewPane(id) =>
            session::run(session::SessionArgs {
                cmd: session::SessionCmd::NewPane { id: Some(id), split: "horizontal".to_string() },
            }, ctx).await,
        Action::SessionContext(id) =>
            context::run(context::ContextArgs {
                cmd: context::ContextCmd::Ls { id: Some(id) },
            }, ctx).await,
        Action::Ask(argv) => {
            let parsed = AskWrapper::try_parse_from(argv)?;
            ask::run(parsed.args, ctx).await
        }
        Action::Act(entity, transition) => {
            let parsed = ActWrapper::try_parse_from([entity, transition])?;
            act::run(parsed.args, ctx).await
        }
        // resolve() can call back into dispatch() (Session/Artifact/etc. all
        // route through here), so this leg needs boxing to break the cycle.
        Action::Resolve(id) => Box::pin(resolve(&id, ctx)).await,
        Action::InviteShow(id) =>
            invite::run(invite::InviteArgs { cmd: invite::InviteCmd::Show { id } }, ctx).await,
        Action::OpenUrl(url) => {
            std::process::Command::new("xdg-open").arg(&url).status()
                .map_err(|e| anyhow::anyhow!("xdg-open: {e}"))?;
            Ok(())
        }
    }
}

/// Parses a plumb-captured argv into the same typed `AskArgs` that
/// interactive `sp ask ...` uses — clap does the parsing, not a shell.
#[derive(Parser)]
#[command(no_binary_name = true)]
struct AskWrapper {
    #[command(flatten)]
    args: ask::AskArgs,
}

/// Same idea for `sp act <entity> <transition>`.
#[derive(Parser)]
#[command(no_binary_name = true)]
struct ActWrapper {
    #[command(flatten)]
    args: act::ActArgs,
}

// ── User-defined rules (trusted path only) ─────────────────────────────────────
//
// The one deliberate shell-out escape hatch: user rules are, by nature,
// arbitrary text patterns mapped to arbitrary shell commands. They're only
// ever loaded on the trusted path (never for a foreign URI click), so the
// injection surface here is scoped to commands the operator wrote themselves.

struct UserRule {
    pattern: regex::Regex,
    action:  String, // {0}=full match, {1}=first capture, etc.
}

fn load_user_rules() -> Vec<UserRule> {
    let Some(path) = user_plumb_path() else { return Vec::new() };
    let Ok(text) = std::fs::read_to_string(&path) else { return Vec::new() };
    parse_toml_rules(&text).unwrap_or_default()
}

fn match_user_rule(text: &str) -> Option<String> {
    for rule in load_user_rules() {
        if let Some(caps) = rule.pattern.captures(text) {
            let mut action = rule.action.clone();
            action = action.replace("{0}", caps.get(0).map_or("", |m| m.as_str()));
            for i in 1..caps.len() {
                action = action.replace(
                    &format!("{{{i}}}"),
                    caps.get(i).map_or("", |m| m.as_str()),
                );
            }
            return Some(action);
        }
    }
    None
}

fn parse_toml_rules(text: &str) -> Result<Vec<UserRule>> {
    // Minimal TOML parse — we don't want to add a toml dep just for this.
    // Format: [[rule]] sections with pattern = "..." and action = "..."
    let mut rules = Vec::new();
    let mut cur_pat: Option<String> = None;
    let mut cur_act: Option<String> = None;

    for line in text.lines() {
        let line = line.trim();
        if line == "[[rule]]" {
            if let (Some(p), Some(a)) = (cur_pat.take(), cur_act.take()) {
                if let Ok(re) = regex::Regex::new(&p) {
                    rules.push(UserRule { pattern: re, action: a });
                }
            }
        } else if let Some(rest) = line.strip_prefix("pattern") {
            cur_pat = extract_toml_string(rest);
        } else if let Some(rest) = line.strip_prefix("action") {
            cur_act = extract_toml_string(rest);
        }
    }
    // flush last rule
    if let (Some(p), Some(a)) = (cur_pat, cur_act) {
        if let Ok(re) = regex::Regex::new(&p) {
            rules.push(UserRule { pattern: re, action: a });
        }
    }
    Ok(rules)
}

fn extract_toml_string(s: &str) -> Option<String> {
    let s = s.trim().strip_prefix('=')?;
    let s = s.trim().trim_matches('"');
    Some(s.to_string())
}

fn user_plumb_path() -> Option<PathBuf> {
    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("HOME").ok()
            .map(|h| PathBuf::from(h).join(".config").join("solarplex").join("plumb.toml"))
    }
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok()
            .map(|a| PathBuf::from(a).join("solarplex").join("plumb.toml"))
    }
}

fn run_shell_action(action: &str, dry_run: bool, is_untrusted: bool) -> Result<()> {
    if dry_run {
        let trust_label = if is_untrusted { dim(" [untrusted]") } else { String::new() };
        println!("{} {}{}", dim("→"), cyan(action), trust_label);
        return Ok(());
    }

    tracing::debug!(action, is_untrusted, "plumb: matched user rule");

    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(action)
        .status();
    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => anyhow::bail!("plumb action exited {}", s.code().unwrap_or(-1)),
        Err(e) => anyhow::bail!("plumb action failed: {e}"),
    }
}

// ── Plumb execution ───────────────────────────────────────────────────────────

async fn plumb(text: &str, dry_run: bool, is_untrusted: bool, ctx: &Ctx) -> Result<()> {
    let text = text.trim();

    // Strip solarplex: URI prefix — a scheme prefix is a text operation, not
    // an action; no need to route it through rule matching at all.
    // Accept both `solarplex://entity/id` (canonical — the `//` is required
    // for Windows Terminal's WinRT Uri parser to accept custom-scheme
    // hyperlinks, see output.rs::link) and the older bare `solarplex:entity/id`
    // form, for anything that still emits it.
    if let Some(rest) = text.strip_prefix("solarplex://").or_else(|| text.strip_prefix("solarplex:")) {
        return Box::pin(plumb(rest, dry_run, is_untrusted, ctx)).await;
    }

    // User-defined rules always require trust; skip entirely on the
    // untrusted (foreign-URI-click) path rather than checking per-rule.
    if !is_untrusted {
        if let Some(action_str) = match_user_rule(text) {
            return run_shell_action(&action_str, dry_run, is_untrusted);
        }
    }

    if let Some(action) = match_builtin(text, is_untrusted) {
        tracing::debug!(text, action = %action.describe(), is_untrusted, "plumb: matched builtin");
        return dispatch(action, ctx, dry_run, is_untrusted).await;
    }

    // No rule matched. Text may have arrived via WezTerm's URI-click path
    // (i.e. from content the operator did not type) — sanitize before printing.
    // SANITIZATION AUDIT — plumb() no-match: FOREIGN path, sanitized.
    println!("{}", dim(&format!("(no plumb rule for: {})", sanitize_terminal(text))));
    Ok(())
}

// ── Resolve ───────────────────────────────────────────────────────────────────

async fn resolve(id: &str, ctx: &Ctx) -> Result<()> {
    // Heuristic first: check local context without a network round-trip.
    if let Some(handle) = heuristic_resolve(id, ctx).await {
        return dispatch(default_action(&handle), ctx, false, false).await;
    }

    // API fallback
    if let Ok(client) = Client::new(ctx) {
        if let Some(handle) = api_resolve(id, &client, ctx).await {
            return dispatch(default_action(&handle), ctx, false, false).await;
        }
    }

    println!("{}", dim(&format!("(could not resolve: {id})")));
    Ok(())
}

/// Try to identify the entity type from local context (session artifacts,
/// approvals) without a network round-trip.  Returns a typed `EntityHandle`
/// so the caller has a single value to route rather than a `(kind, id)` pair.
async fn heuristic_resolve(id: &str, ctx: &Ctx) -> Option<EntityHandle> {
    let client = Client::new(ctx).ok()?;
    let session_id = ctx.session_id.as_deref()?;

    // Try artifacts list (cheap GET, cached by server)
    if let Ok(arts) = client.list_artifacts(session_id).await {
        if let Some(arr) = arts.as_array() {
            if let Some(full_id) = arr.iter()
                .find(|a| a["id"].as_str().map(|s| s.starts_with(id)).unwrap_or(false))
                .and_then(|a| a["id"].as_str())
            {
                return Some(EntityHandle::Artifact(full_id.to_string()));
            }
        }
    }

    // Try pending approvals
    if let Ok(appr) = client.list_approvals(session_id).await {
        if let Some(arr) = appr.as_array() {
            if let Some(full_id) = arr.iter()
                .find(|a| a["id"].as_str().map(|s| s.starts_with(id)).unwrap_or(false))
                .and_then(|a| a["id"].as_str())
            {
                return Some(EntityHandle::Approval(full_id.to_string()));
            }
        }
    }

    None
}

/// API fallback resolver: try known GET endpoints to identify the entity type.
async fn api_resolve(id: &str, client: &Client, ctx: &Ctx) -> Option<EntityHandle> {
    // Try session directly
    if client.get_session(id).await.is_ok() {
        return Some(EntityHandle::Session(id.to_string()));
    }
    // Try artifact in current session
    if let Some(sid) = ctx.session_id.as_deref() {
        if client.get_artifact(sid, id).await.is_ok() {
            return Some(EntityHandle::Artifact(id.to_string()));
        }
    }
    None
}

// ── Install helpers (called by sp plumb install) ──────────────────────────────

#[cfg(not(target_os = "windows"))]
pub fn install_uri_handler() -> Result<()> {
    // Write .desktop file and register xdg-mime handler.
    // --untrusted is always passed for OS URI handler invocations: the URI
    // originates from external content (terminal hyperlink click), not the user.
    let desktop_dir = std::env::var("HOME")
        .map(|h| PathBuf::from(h).join(".local").join("share").join("applications"))
        .map_err(|_| anyhow::anyhow!("HOME not set"))?;
    std::fs::create_dir_all(&desktop_dir)?;

    let desktop = desktop_dir.join("solarplex-plumb.desktop");
    let sp_path = std::env::current_exe()?;
    std::fs::write(&desktop, format!(
        "[Desktop Entry]\nName=Solarplex Plumber\nExec={} plumb run --untrusted %u\nMimeType=x-scheme-handler/solarplex;\nType=Application\nNoDisplay=true\n",
        sp_path.display()
    ))?;

    // Register with xdg-mime
    let _ = std::process::Command::new("xdg-mime")
        .args(["default", "solarplex-plumb.desktop", "x-scheme-handler/solarplex"])
        .status();
    let _ = std::process::Command::new("update-desktop-database")
        .arg(desktop_dir)
        .status();

    println!("{} URI handler installed (solarplex:// → sp plumb --untrusted)", green("✓"));
    println!("  desktop: {}", dim(&desktop.display().to_string()));
    Ok(())
}

/// Windows counterpart: registers `solarplex://` as a URL protocol handler
/// under `HKEY_CURRENT_USER\Software\Classes` — per-user, no admin
/// privilege required (unlike `HKEY_LOCAL_MACHINE`, which is machine-wide
/// and admin-gated). `--untrusted` is always passed, same as the
/// xdg-mime path above and for the identical reason: whatever handed this
/// URI to Windows' `ShellExecute` is external content, not the user, so it
/// goes through the exact same restrictions regardless of which OS routed
/// the click here — `plumb.rs::plumb()` skips user-defined plumb.toml rules
/// entirely on the untrusted path, and `act/` (state-mutating) targets are
/// refused outright, never dispatched from a click.
///
/// The registered command embeds only the `sp.exe` path and fixed flags —
/// no token, no session id, nothing this process holds that a foreign
/// process reading the registry shouldn't see.
#[cfg(target_os = "windows")]
pub fn install_uri_handler() -> Result<()> {
    let sp_path = std::env::current_exe()?;
    let sp_path = sp_path.to_string_lossy();

    let proto_key = r"HKCU\Software\Classes\solarplex";
    reg_add(&[proto_key, "/ve", "/d", "URL:Solarplex Protocol", "/f"])?;
    reg_add(&[proto_key, "/v", "URL Protocol", "/d", "", "/f"])?;

    let command_key = r"HKCU\Software\Classes\solarplex\shell\open\command";
    let command = format!("\"{sp_path}\" plumb run --untrusted \"%1\"");
    reg_add(&[command_key, "/ve", "/d", &command, "/f"])?;

    println!("{} URI handler installed (solarplex:// → sp plumb --untrusted)", green("✓"));
    println!("  registry: {}", dim(proto_key));
    Ok(())
}

#[cfg(target_os = "windows")]
fn reg_add(args: &[&str]) -> Result<()> {
    let status = std::process::Command::new("reg")
        .arg("add")
        .args(args)
        .status()
        .map_err(|e| anyhow::anyhow!("reg.exe not found: {e}"))?;
    if !status.success() {
        anyhow::bail!("reg add {} failed", args[0]);
    }
    Ok(())
}

pub fn write_default_plumb_config() -> Result<()> {
    let path = user_plumb_path()
        .ok_or_else(|| anyhow::anyhow!("cannot determine config dir"))?;
    if path.exists() {
        println!("{} {} already exists — not overwriting", yellow("⚠"), path.display());
        return Ok(());
    }
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    std::fs::write(&path, DEFAULT_PLUMB_TOML)?;
    println!("{} Created {}", green("✓"), path.display());
    Ok(())
}

const DEFAULT_PLUMB_TOML: &str = r#"# Solarplex plumbing rules
# Rules are matched top-to-bottom; first match wins.
# {0} = full match, {1} = first capture group, etc.
#
# NOTE: custom rules here are only executed on the TRUSTED path
# (sp plumb run without --untrusted). URI clicks from the terminal
# handler always use --untrusted, which skips user-defined rules.

# Add your custom rules here — they take priority over builtins.
# Example: open GitHub URLs in browser
# [[rule]]
# pattern = "https://github\\.com/\\S+"
# action  = "xdg-open {0}"
"#;
