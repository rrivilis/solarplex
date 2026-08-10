use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::{client::Client, config::{self, Ctx, FileConfig}, output::*};

#[derive(Args)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub cmd: SessionCmd,
}

/// Which shell's syntax `env`/`enter` should emit — the adapter script for
/// each shell always passes its own kind explicitly (never left to guess),
/// so this only needs to distinguish the two syntaxes that actually differ:
/// fish's `set -gx` and everything else's `export` (bash, zsh, and Oils'
/// OSH mode, which is bash-compatible here — see shell/solarplex.sh).
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellKind {
    Fish,
    Posix,
}

#[derive(Subcommand)]
pub enum SessionCmd {
    /// List sessions (filtered to current actor if attached)
    Ls {
        /// Show all sessions, not just those for the current actor
        #[arg(long)]
        all: bool,
    },
    /// Create a new session
    New {
        /// Session name
        name: String,
        #[arg(long, short)]
        description: Option<String>,
        /// Approval policy: single_vote | majority | unanimous
        #[arg(long, default_value = "single_vote")]
        policy: String,
    },
    /// Attach to a session (saves to config + prints Fish env)
    Attach {
        /// Session ID to attach to
        session_id: String,
    },
    /// Detach from current session (clears config)
    Detach,
    /// Inspect a session by ID
    Inspect {
        /// Session ID (defaults to current session)
        id: Option<String>,
    },
    /// Print shell env-var commands for the current session
    Env {
        #[arg(long, value_enum, default_value_t = ShellKind::Fish)]
        shell: ShellKind,
    },
    /// Transfer session ownership to another actor
    Handoff {
        /// Actor to transfer to
        #[arg(long)]
        to: String,
        #[arg(long)]
        from: Option<String>,
    },
    /// Attach to a session and print the source command (used by the sp-enter shell function)
    Enter {
        /// Session ID
        id: String,
        #[arg(long, value_enum, default_value_t = ShellKind::Fish)]
        shell: ShellKind,
    },
    /// Live IRC-style message feed — shows session activity and lets you post messages
    Feed {
        /// Session ID (defaults to current session)
        id: Option<String>,
    },
    /// Open a WezTerm workspace layout for a session (requires $WEZTERM_PANE)
    Workspace {
        /// Session ID (defaults to current session)
        id: Option<String>,
        /// Comma-separated list of panes to open.
        /// Options: inspect, shell, actors, artifacts, context
        /// Default: inspect,shell
        #[arg(long, default_value = "inspect,feed")]
        panes: String,
    },
    /// Split a new pane already attached to this session
    NewPane {
        /// Session ID (defaults to current session)
        id: Option<String>,
        /// Split direction
        #[arg(long, default_value = "horizontal")]
        split: String,
    },
    /// Show the current epoch and recent revocation history for a session.
    ///
    /// The epoch is a generation counter that increments on every revocation.
    /// Each row in the revocation history shows the strategy, target, drain
    /// window, and the new epoch that became active.
    ///
    /// Example:
    ///   sp session epoch
    ///   sp session epoch 01J...
    Epoch {
        /// Session ID (defaults to current session)
        id: Option<String>,
    },
    /// Git-remote-style pointers to other sessions — durable, directional,
    /// with a per-remote watermark cursor. Fetching never copies events into
    /// the attached session's own log; it only displays what's new.
    Remote {
        #[command(subcommand)]
        cmd: RemoteCmd,
    },
}

#[derive(Subcommand)]
pub enum RemoteCmd {
    /// Add a session as a remote (fetch source) for the attached session
    Add {
        /// Remote session ref (ULID, prefix, or name)
        remote: String,
    },
    /// List remotes for the attached session
    Ls,
    /// Fetch events from a remote since the last watermark
    Fetch {
        /// Remote id, from `sp session remote ls`
        remote_id: String,
    },
    /// Remove a remote
    Rm {
        remote_id: String,
    },
}

pub async fn run(args: SessionArgs, ctx: &Ctx) -> Result<()> {
    // Commands that don't need the network — handle before creating Client.
    // Enter used to live here too, but resolving the actor from the logged-in
    // identity (see `enter`'s doc comment) needs a network round-trip now.
    match &args.cmd {
        SessionCmd::Attach { session_id }  => return attach(ctx, session_id),
        SessionCmd::Detach                 => return detach(),
        SessionCmd::Env { shell }          => return env(ctx, *shell),
        SessionCmd::NewPane { id, split }  => return new_pane(ctx, id.as_deref(), split),
        _ => {}
    }

    // Remaining commands require a network client.
    let client = Client::new(ctx)?;
    match args.cmd {
        SessionCmd::Ls { all } => ls(&client, ctx, all).await,
        SessionCmd::New { name, description, policy } => {
            new_session(&client, ctx, &name, description.as_deref(), &policy).await
        }
        SessionCmd::Inspect { id }   => inspect(&client, ctx, id.as_deref()).await,
        SessionCmd::Feed    { id }   => feed(&client, ctx, id.as_deref()).await,
        SessionCmd::Handoff { to, from } => handoff(&client, ctx, &to, from.as_deref()).await,
        SessionCmd::Workspace { id, panes } => workspace(&client, ctx, id.as_deref(), &panes).await,
        SessionCmd::Epoch   { id }   => epoch(&client, ctx, id.as_deref()).await,
        SessionCmd::Remote  { cmd }  => remote(&client, ctx, cmd).await,
        SessionCmd::Enter   { id, shell } => enter(&client, ctx, &id, shell).await,
        // Already handled above — unreachable, but keeps the compiler happy.
        SessionCmd::Attach { session_id }  => attach(ctx, &session_id),
        SessionCmd::Detach                 => detach(),
        SessionCmd::Env { shell }          => env(ctx, shell),
        SessionCmd::NewPane { id, split }  => new_pane(ctx, id.as_deref(), &split),
    }
}

pub async fn ls(client: &Client, ctx: &Ctx, all: bool) -> Result<()> {
    let actor = if all { None } else { ctx.actor_id.as_deref() };
    let sessions = client.list_sessions(actor).await?;
    let arr = sessions.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("No sessions."));
        return Ok(());
    }

    // Header
    println!(
        "  {}  {}  {}  {}",
        bold(&pad("SESSION", 10)),
        bold(&pad("NAME", 28)),
        bold(&pad("STATUS", 10)),
        bold("MEMBERS"),
    );

    for s in &arr {
        let id     = s["id"].as_str().unwrap_or("?");                        // ULID — safe
        let name   = sanitize_terminal(s["name"].as_str().unwrap_or("?")); // FOREIGN
        let status = s["status"].as_str().unwrap_or("active");

        let current = ctx.session_id.as_deref() == Some(id);
        let prefix = if current { cyan("▶") } else { " ".to_string() };

        let link = entity_link("session", id, id, &ctx.ui);
        // name is already sanitized; status_col derives from a server enum — safe
        let status_col = match status {
            "active"    => green(status),
            "archived"  => dim(status),
            "suspended" => yellow(status),
            _           => status.to_string(),
        };

        let enter_link = link_action("session", id, "enter", "enter");
        let ws_link    = link_action("session", id, "workspace", "ws");

        println!(
            "{} {}  {}  {}  {} {}",
            prefix,
            pad(&link, 10),
            pad(&name, 28),
            pad(&status_col, 10),
            enter_link,
            ws_link,
        );
    }
    Ok(())
}

pub async fn new_session(
    client: &Client,
    ctx: &Ctx,
    name: &str,
    description: Option<&str>,
    policy: &str,
) -> Result<()> {
    let actor = ctx.require_actor()?;

    let session = client.create_session(name, description, policy, actor).await?;
    let id       = session["id"].as_str().unwrap_or("?");
    let token    = session["join_token"].as_str().unwrap_or("");
    let link     = entity_link("session", id, id, &ctx.ui);

    println!("{} Created session {}", green("✓"), link);
    println!("  name:   {}", bold(name));
    println!("  policy: {policy}");
    if !token.is_empty() {
        println!("  token:  {}", dim(token));
    }
    println!();
    println!("Attach to it now?");
    println!("  {}", cyan(&format!("sp --actor {actor} session attach {id}")));
    Ok(())
}

fn attach(ctx: &Ctx, session_id: &str) -> Result<()> {
    let actor = ctx.require_actor()?;

    let cfg = FileConfig {
        server:     Some(ctx.server.clone()),
        session_id: Some(session_id.to_string()),
        actor_id:   Some(actor.to_string()),
        ui:         Some(ctx.ui.clone()),
    };
    config::save(&cfg)?;

    println!("{} Attached to {} as {}", green("✓"),
        entity_link("session", session_id, session_id, &ctx.ui),
        bold(actor));
    println!();
    println!("Reload in current shell:");
    println!("  {}", cyan("source (sp session env | psub)"));
    Ok(())
}

fn detach() -> Result<()> {
    let cfg = FileConfig::default();
    config::save(&cfg)?;
    println!("{} Detached. SOLARPLEX_SESSION_ID cleared.", green("✓"));
    Ok(())
}

/// Resolve a user-supplied token to a full session ULID.
/// Accepts: full ULID, short prefix (case-insensitive), or session name.
///
/// The prefix/name search is scoped to sessions the *currently
/// sp_token-authenticated* identity is a member of — `GET /api/sessions`
/// has no unscoped "list everything" mode ("like Slack — you only see
/// sessions you've joined", see routes/sessions.rs::list_sessions). So a
/// short token or name can fail to resolve for two very different reasons:
/// no such session exists, or it exists but isn't visible to whoever
/// `sp login` currently has you authenticated as. The error below says so
/// explicitly rather than reading like a typo.
pub async fn resolve_session_id(client: &Client, token: &str) -> Result<String> {
    // Fast path: already a full 26-char ULID
    if token.len() == 26 && token.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Ok(token.to_uppercase());
    }
    // Otherwise list sessions the authenticated caller is a member of, and
    // match by prefix or name within that set.
    let sessions = client.list_sessions(None).await?;
    let arr = sessions.as_array().cloned().unwrap_or_default();
    let upper = token.to_uppercase();
    // prefer prefix match on ID, then exact name match
    let found = arr.iter()
        .find(|s| s["id"].as_str().map(|id| id.to_uppercase().starts_with(&upper)).unwrap_or(false))
        .or_else(|| arr.iter().find(|s| s["name"].as_str() == Some(token)));
    found
        .and_then(|s| s["id"].as_str().map(|s| s.to_string()))
        .ok_or_else(|| anyhow::anyhow!(
            "No session matching {token:?} among sessions your current identity is a member \
             of. If this session belongs to a different actor, check `sp login` (wrong \
             sp_token identity) or `--actor`/SOLARPLEX_ACTOR_ID (wrong self-asserted actor \
             for message/context posting) — they're independent and can point at different \
             identities."
        ))
}

async fn inspect(client: &Client, ctx: &Ctx, id: Option<&str>) -> Result<()> {
    let raw = id.or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session. Pass <id> or attach first."))?;
    let session_id = resolve_session_id(client, raw).await?;
    let session_id = session_id.as_str();

    // Fetch everything in parallel (best-effort; failures show empty sections).
    let (session, artifacts, approvals, events) = tokio::join!(
        client.get_session(session_id),
        client.list_artifacts(session_id),
        client.list_approvals(session_id),
        client.list_events(session_id, 20),
    );

    let s = session?;
    print_session_full(
        &s,
        artifacts.ok().as_ref(),
        approvals.ok().as_ref(),
        events.ok().as_ref(),
        ctx,
    );
    Ok(())
}

/// IRC-style live session feed.
///
/// On startup: prints recent activity from the event log.
/// Loop: shows `actor > ` prompt, user types a message, it's posted via
/// POST /sessions/{id}/messages, then new events since last poll are shown.
/// Empty Enter = poll for new messages without posting.
/// `/quit` or EOF = exit.
async fn feed(client: &Client, ctx: &Ctx, id: Option<&str>) -> Result<()> {
    use std::io::{self, BufRead, Write};

    let raw = id.or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session. Pass <id> or attach first."))?;
    let session_id = resolve_session_id(client, raw).await?;
    let session_id = session_id.as_str();

    let actor_id = ctx.actor_id.as_deref().unwrap_or("anon");

    // ── Startup: show session header + recent events ──────────────────────────
    let s = client.get_session(session_id).await.ok();
    let name = s.as_ref().and_then(|v| v["name"].as_str()).unwrap_or(session_id);

    // actor_id -> display name, resolved once from the session snapshot's
    // members list — same principle as the frontend's actorNames map.
    // Events store the raw actor_id forever; this is purely a render-time
    // lookup so a rename shows up retroactively without touching history.
    let actor_names: HashMap<String, String> = s.as_ref()
        .and_then(|v| v["members"].as_array())
        .map(|members| {
            members.iter()
                .filter_map(|m| {
                    let id   = m["actor_id"].as_str()?;
                    let name = m["name"].as_str().filter(|n| !n.is_empty())?;
                    Some((id.to_string(), name.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    println!();
    println!("  {} {}  {}", bold(name), dim(&format!("session/{}", &session_id[..8])),
             dim("(type a message, Enter to poll, /quit to exit)"));
    println!("  {}", "─".repeat(56));

    // Fetch and display recent events
    let mut last_seq: i64 = 0;
    if let Ok(events) = client.list_events(session_id, 50).await {
        if let Some(arr) = events.as_array() {
            for e in arr {
                print_feed_event(e, &actor_names);
                if let Some(seq) = e["seq"].as_i64() {
                    last_seq = last_seq.max(seq);
                }
            }
        }
    }

    println!("  {}", dim(&"─".repeat(56)));
    println!();

    // ── Input loop ────────────────────────────────────────────────────────────
    let stdin = io::stdin();
    loop {
        // Prompt
        print!("  {} {} ", cyan(actor_id), dim(">"));
        io::stdout().flush().ok();

        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => break,        // EOF (Ctrl-D)
            Err(_) => break,
            Ok(_) => {}
        }
        let msg = line.trim();

        if msg == "/quit" || msg == "/exit" || msg == "q" {
            break;
        }

        // A stray click or copy-paste of a rendered `sp ...` link/command
        // (e.g. the artifact entity_link a voice-memo message now renders)
        // lands right here with nothing to distinguish it from a real chat
        // message — this loop posts *anything* non-empty with no
        // confirmation. Refuse the obvious case instead of silently
        // publishing what was very likely a mis-click, not a message.
        // `/say ` is the escape hatch for a message that genuinely starts
        // with "sp " on purpose.
        if let Some(literal) = msg.strip_prefix("/say ") {
            if let Err(e) = client.post_message(session_id, actor_id, literal).await {
                eprintln!("  {} {}", red("✗"), e);
            }
        } else if msg.starts_with("sp ") {
            eprintln!(
                "  {} that looks like a pasted `sp` command, not a chat message — not posting it.",
                yellow("⚠"),
            );
            eprintln!("  {}", dim("If you really meant to send this text, prefix it with /say."));
        } else if !msg.is_empty() {
            if let Err(e) = client.post_message(session_id, actor_id, msg).await {
                eprintln!("  {} {}", red("✗"), e);
            }
        }

        // Poll for new events since last seen seq
        match client.list_events_after(session_id, last_seq, 50).await {
            Ok(events) => {
                if let Some(arr) = events.as_array() {
                    for e in arr {
                        print_feed_event(e, &actor_names);
                        if let Some(seq) = e["seq"].as_i64() {
                            last_seq = last_seq.max(seq);
                        }
                    }
                }
            }
            Err(e) => eprintln!("  {} poll error: {e}", dim("·")),
        }
    }

    Ok(())
}

/// Voice-memo and file-upload messages embed the artifact id in the
/// human-readable message content (e.g. "🎙️ Voice memo · 0:15
/// [artifact:01ABC...]") so the event log stays a single plain-text stream
/// with no new wire format — same embedding the frontend's MessageBody.tsx
/// un-does for its renderers. This is the terminal-side equivalent: strip
/// the raw id out of the visible label and surface it instead as a proper
/// clickable OSC-8 entity link, so the feed doesn't just dump a bracketed
/// ULID into the middle of a chat line.
fn artifact_message_ref(content: &str) -> Option<(String, String)> {
    static VOICE_RE: OnceLock<regex::Regex> = OnceLock::new();
    static FILE_RE:  OnceLock<regex::Regex> = OnceLock::new();

    let voice_re = VOICE_RE.get_or_init(|| {
        regex::Regex::new(r"^🎙️ Voice memo · ([\d:]+) \[artifact:([A-Z0-9]+)\]$").unwrap()
    });
    if let Some(caps) = voice_re.captures(content) {
        return Some((format!("🎙️ Voice memo · {}", &caps[1]), caps[2].to_string()));
    }

    let file_re = FILE_RE.get_or_init(|| {
        regex::Regex::new(r"^📎 (.+?) \[artifact:([A-Z0-9]+)\]$").unwrap()
    });
    if let Some(caps) = file_re.captures(content) {
        return Some((format!("📎 {}", &caps[1]), caps[2].to_string()));
    }

    None
}

/// Format a single event for the feed view.
///
/// The DB `payload` column stores the FULL serialized WsMessage, so the
/// event-type-specific fields live at `e["payload"]["payload"]` (doubly nested).
///
/// SANITIZATION: all foreign-authored strings (actor IDs, content, tool names,
/// artifact names) are passed through sanitize_terminal() before being printed.
/// Event type strings are system-defined and safe; seq/id fields are ULIDs (safe).
fn print_feed_event(e: &Value, actor_names: &HashMap<String, String>) {
    // actor_id itself is a server-issued ULID (safe), but the resolved
    // display name is actor-chosen — FOREIGN, sanitize after lookup.
    let raw_actor_id = e["actor_id"].as_str().unwrap_or("?");
    let actor = sanitize_terminal(
        actor_names.get(raw_actor_id).map(|s| s.as_str()).unwrap_or(raw_actor_id),
    );
    let etype  = e["type"].as_str().unwrap_or(""); // system-defined, safe
    let inner  = &e["payload"]["payload"];

    match etype {
        t if t.contains("message.posted") => {
            // FOREIGN: content authored by any session participant.
            let content = sanitize_terminal(inner["content"].as_str().unwrap_or(""));
            if !content.is_empty() {
                if let Some((label, artifact_id)) = artifact_message_ref(&content) {
                    let alink = entity_link("artifact", &artifact_id, "", "");
                    println!("  {}  {}  {}", bold(&pad_right(&actor, 16)), label, dim(&alink));
                } else {
                    println!("  {}  {}", bold(&pad_right(&actor, 16)), content);
                }
            }
        }
        t if t.contains("context.entry.added") => {
            let event_id = e["id"].as_str().unwrap_or("?"); // ULID, safe
            // FOREIGN: both content and kind are actor-supplied.
            let content  = sanitize_terminal(inner["content"].as_str().unwrap_or(""));
            let kind     = sanitize_terminal(inner["kind"].as_str().unwrap_or("note"));
            if !content.is_empty() {
                let clink = entity_link("context", event_id, "", "");
                println!("  {}  {} {}  {}",
                    cyan(&pad_right(&actor, 16)),
                    dim(&format!("[{kind}]")),
                    content,
                    dim(&clink));
            }
        }
        t if t.contains("actor.joined") => {
            // actor already sanitized above
            println!("  {}", dim(&format!("── {actor} joined ──")));
        }
        t if t.contains("actor.detached") => {
            println!("  {}", dim(&format!("── {actor} left ──")));
        }
        t if t.contains("approval.requested") => {
            // FOREIGN: tool_name is agent-supplied.
            let tool = sanitize_terminal(inner["tool_name"].as_str().unwrap_or("?"));
            println!("  {}", yellow(&format!("⚑  {actor} requested approval: {tool}")));
        }
        t if t.contains("approval.granted") || t.contains("approval.denied") => {
            let decision = if t.contains("granted") { "granted" } else { "denied" };
            println!("  {}", dim(&format!("── approval {decision} by {actor} ──")));
        }
        t if t.contains("artifact.created") || t.contains("artifact.updated") => {
            // FOREIGN: artifact name is actor-supplied.
            let aname  = sanitize_terminal(inner["name"].as_str().unwrap_or("?"));
            let action = if t.contains("created") { "saved" } else { "updated" };
            println!("  {}", dim(&format!("── {actor} {action} artifact: {aname} ──")));
        }
        t if t.contains("shell.command.started") => {
            // SANITIZATION AUDIT — shell.command.started:
            // argv0: server-stored basename of first token. Still FOREIGN (actor can
            //        name their binary anything) — sanitize.
            // command: only present when tracked=true and seatbelt clear. FOREIGN.
            // redacted: bool set by client seatbelt — controls rendering label.
            let argv0    = sanitize_terminal(inner["argv0"].as_str().unwrap_or("?"));

            // Filter sp navigation events from the chat feed.
            // `sp ask`, `sp act`, `sp session`, etc. are session management,
            // not user work — they clutter the feed and bury chat messages.
            // The fish plugin no longer generates these, but old DB events
            // and any residual sp invocations still need to be suppressed here.
            if argv0 == "sp" {
                return;
            }

            let tracked  = inner["tracked"].as_bool().unwrap_or(false);
            let redacted = inner["redacted"].as_bool().unwrap_or(false);

            let label = if redacted {
                // Seatbelt fired: credential detected, full argv suppressed.
                format!("{} {}", argv0, yellow("[credential detected — argv suppressed]"))
            } else if tracked {
                // Full tracking opted in and seatbelt cleared.
                let cmd = sanitize_terminal(inner["command"].as_str().unwrap_or(&argv0));
                format!("{}", cmd)
            } else {
                // Default mode: only binary name recorded.
                format!("{} {}", argv0, dim("[argv not tracked]"))
            };
            println!("  {}", dim(&format!("$ {label}")));
        }
        t if t.contains("shell.command.completed") => {
            let exit = inner["exit_code"].as_i64().unwrap_or(0);
            let ms   = inner["duration_ms"].as_u64().unwrap_or(0);
            if exit != 0 {
                println!("  {}", dim(&format!("  ↳ exit {exit}  ({ms}ms)")));
            }
            // Suppress zero-exit completions to reduce noise.
        }
        _ => {}
    }
}

/// Right-pad a string to `width` visible chars (no ANSI).
fn pad_right(s: &str, width: usize) -> String {
    if s.len() >= width { s.to_string() }
    else { format!("{}{}", s, " ".repeat(width - s.len())) }
}

/// SANITIZATION AUDIT — print_session_full
/// All values extracted from the session API response are treated as foreign-authored
/// (any actor can set session names, artifact names, etc.) and sanitized before print.
/// ULIDs (id fields) are safe — alphabet-constrained by the server. Status and policy
/// strings are server-enum-constrained; sanitized for defense in depth.
fn print_session_full(
    s: &Value,
    artifacts: Option<&Value>,
    approvals: Option<&Value>,
    events:    Option<&Value>,
    ctx: &Ctx,
) {
    let id     = s["id"].as_str().unwrap_or("?");               // ULID — safe
    let name   = sanitize_terminal(s["name"].as_str().unwrap_or("?"));     // FOREIGN
    let status = s["status"].as_str().unwrap_or("active");      // server enum — sanitized below
    let policy = s["approval_policy"].as_str().unwrap_or("single_vote");   // server enum
    let link   = entity_link("session", id, id, &ctx.ui);
    let current_actor = ctx.actor_id.as_deref().unwrap_or("");

    // ── Header ────────────────────────────────────────────────────────────────
    println!("{} {}  {} {}", bold(&name), link, status_icon(status), dim(policy));
    println!("{}", dim(&"─".repeat(50)));

    // ── Members ───────────────────────────────────────────────────────────────
    if let Some(members) = s["members"].as_array() {
        println!("{}", bold("MEMBERS"));
        for m in members {
            let actor = sanitize_terminal(m["actor_id"].as_str().unwrap_or("?")); // FOREIGN
            let name  = sanitize_terminal(m["name"].as_str().unwrap_or(""));      // FOREIGN
            let role  = sanitize_terminal(m["role"].as_str().unwrap_or("?"));     // FOREIGN
            let marker = if actor == current_actor { cyan("▶") } else { " ".into() };
            println!("  {} {}  {}", marker, pad(&actor_link_named(&actor, &name), 28), dim(&role));
        }
        println!();
    }

    // ── Artifacts ─────────────────────────────────────────────────────────────
    let arts = artifacts.and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if arts.is_empty() {
        println!("{}", dim("ARTIFACTS  (none)"));
    } else {
        println!("{} {}", bold("ARTIFACTS"), dim(&format!("({})", arts.len())));
        for a in arts.iter().rev().take(8) {
            let aid  = a["id"].as_str().unwrap_or("?");                         // ULID — safe
            let name = sanitize_terminal(a["name"].as_str().unwrap_or("?"));    // FOREIGN
            let by   = sanitize_terminal(a["created_by"].as_str().unwrap_or("?")); // FOREIGN
            let link = entity_link("artifact", aid, id, &ctx.ui);
            println!("  {}  {}  {}", pad(&link, 14), pad(&name, 30), dim(&by));
        }
    }
    println!();

    // ── Pending approvals ─────────────────────────────────────────────────────
    let appr = approvals.and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if !appr.is_empty() {
        println!("{} {}", bold(&yellow("APPROVALS")), yellow(&format!("({} pending)", appr.len())));
        for a in &appr {
            let aid  = a["id"].as_str().unwrap_or("?");                          // ULID — safe
            let tool = sanitize_terminal(a["tool_name"].as_str().unwrap_or("?")); // FOREIGN
            let by   = sanitize_terminal(a["actor_id"].as_str().unwrap_or("?"));  // FOREIGN
            let link = entity_link("approval", aid, id, &ctx.ui);
            println!("  {}  {}  {}", pad(&link, 14), pad(&tool, 28), dim(&by));
        }
        println!();
    }

    // ── Recent activity ───────────────────────────────────────────────────────
    let evts = events.and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if evts.is_empty() {
        println!("{}", dim("ACTIVITY   (none yet)"));
    } else {
        println!("{}", bold("ACTIVITY"));
        for e in &evts {
            let actor      = sanitize_terminal(e["actor_id"].as_str().unwrap_or("?")); // FOREIGN
            let etype      = e["type"].as_str().unwrap_or("?"); // system-defined
            let payload    = &e["payload"];
            let summary    = sanitize_terminal(&event_summary(etype, payload));  // FOREIGN content
            let short_type = etype.split('.').last().unwrap_or(etype);
            println!("  {}  {}  {}",
                pad(&dim(&actor_link(&actor).to_string()), 22),
                pad(short_type, 16),
                dim(&summary));
        }
    }
}

/// Extract the most meaningful short string from an event payload.
///
/// `payload` is `e["payload"]` — the full WsMessage JSON stored in the DB.
/// The variant-specific fields are nested at `payload["payload"]`.
fn event_summary(event_type: &str, payload: &Value) -> String {
    // The actual event fields are one level deeper (WsMessage wraps them).
    let inner = &payload["payload"];

    // For shell events: prefer full `command` (tracked, seatbelt clear), fall
    // back to `argv0` (always present), or show a redacted label.
    if event_type.contains("shell.command.started") {
        let redacted = inner["redacted"].as_bool().unwrap_or(false);
        if redacted {
            return "[credential detected — argv suppressed]".to_string();
        }
        if let Some(cmd) = inner["command"].as_str() {
            let v = cmd.trim();
            return if v.len() > 48 { format!("{}…", &v[..47]) } else { v.to_string() };
        }
        if let Some(argv0) = inner["argv0"].as_str() {
            return argv0.to_string();
        }
        return String::new();
    }

    let candidates: &[&str] = match event_type {
        t if t.contains("shell")    => &["command", "argv0", "content"],
        t if t.contains("artifact") => &["name", "artifact_id"],
        t if t.contains("context")  => &["content"],
        t if t.contains("message")  => &["content"],
        t if t.contains("approval") => &["tool_name", "content"],
        _                           => &["content", "command", "name", "status"],
    };

    // Check inner (variant-specific) payload first.
    for field in candidates {
        if let Some(v) = inner[field].as_str() {
            let v = v.trim();
            return if v.len() > 48 { format!("{}…", &v[..47]) } else { v.to_string() };
        }
    }
    // Fallback: some events store fields directly on the outer payload.
    for field in candidates {
        if let Some(v) = payload[field].as_str() {
            let v = v.trim();
            return if v.len() > 48 { format!("{}…", &v[..47]) } else { v.to_string() };
        }
    }
    String::new()
}

#[allow(dead_code)]
fn print_session(s: &Value, ctx: &Ctx) {
    // Compact version used by session ls detail fallback.
    let id     = s["id"].as_str().unwrap_or("?");
    let name   = s["name"].as_str().unwrap_or("?");
    let status = s["status"].as_str().unwrap_or("active");
    let policy = s["approval_policy"].as_str().unwrap_or("single_vote");
    let link   = entity_link("session", id, id, &ctx.ui);
    println!("{} {}  {} {}", bold(name), link, status_icon(status), dim(policy));
    if let Some(members) = s["members"].as_array() {
        println!("  members:");
        for m in members {
            let actor = m["actor_id"].as_str().unwrap_or("?");
            let role  = m["role"].as_str().unwrap_or("?");
            println!("    {}  {}", pad(&actor_link(actor), 28), dim(role));
        }
    }
}

fn env(ctx: &Ctx, shell: ShellKind) -> Result<()> {
    // fish: piped through `psub` and sourced (`source (sp session env | psub)`).
    // posix (bash/zsh/Oils-OSH): piped straight to `source`/`.` — no psub
    // equivalent needed since POSIX shells can source a live pipe directly
    // via process substitution or, more portably, `source <(sp session env
    // --shell posix)`; shell/solarplex.sh's own bootstrap avoids even that
    // by sourcing the file config::save() writes instead of this directly.
    match shell {
        ShellKind::Fish => {
            println!("set -gx SOLARPLEX_SERVER {:?}", ctx.server);
            if let Some(ref sid) = ctx.session_id {
                println!("set -gx SOLARPLEX_SESSION_ID {sid:?}");
            }
            if let Some(ref aid) = ctx.actor_id {
                println!("set -gx SOLARPLEX_ACTOR_ID {aid:?}");
            }
            println!("set -gx SOLARPLEX_UI {:?}", ctx.ui);
        }
        ShellKind::Posix => {
            println!("export SOLARPLEX_SERVER={}", config::posix_quote(&ctx.server));
            if let Some(ref sid) = ctx.session_id {
                println!("export SOLARPLEX_SESSION_ID={}", config::posix_quote(sid));
            }
            if let Some(ref aid) = ctx.actor_id {
                println!("export SOLARPLEX_ACTOR_ID={}", config::posix_quote(aid));
            }
            println!("export SOLARPLEX_UI={}", config::posix_quote(&ctx.ui));
        }
    }
    Ok(())
}

/// Write the config file so the shell adapter can source it.  The actual
/// `source` must happen in the user's shell — this is called by the
/// `sp-enter` shell function (fish and shell/solarplex.sh's bash/zsh
/// version both define one) which runs the source after this returns.
///
/// Actor resolution, in order:
///   1. a literal `--actor <value>` typed on *this* command line
///      (`ctx.actor_flag`) always wins — e.g. an agent's harness explicitly
///      attaching as itself. Deliberately NOT `SOLARPLEX_ACTOR_ID` too: that
///      env var is self-exported by `config::save()` into `session.fish`/
///      `session.sh`, so a shell that already sourced one from a previous
///      `enter`/`attach` would otherwise re-poison every later invocation
///      into thinking it got an explicit override — see main.rs's `Cli`
///      struct and `Ctx::load` for the actual fix.
///   2. otherwise, if signed in (`sp login`), the logged-in identity —
///      resolved fresh via `GET /auth/me`, not carried forward from
///      whatever a previous `--actor` happened to leave in the config file.
///      `enter` is a fresh per-session bootstrap; silently forwarding a
///      stale value here is what let a leftover `--actor alice` from old
///      testing keep posting as "alice" long after that stopped being who
///      was actually logged in.
///   3. otherwise, whatever's already in config (or unset).
async fn enter(client: &Client, ctx: &Ctx, session_id: &str, shell: ShellKind) -> Result<()> {
    let actor_id = if let Some(explicit) = ctx.actor_flag.clone() {
        Some(explicit)
    } else if ctx.token.is_some() {
        match client.me().await {
            Ok(me) => me["id"].as_str().map(String::from).or_else(|| ctx.actor_id.clone()),
            Err(_) => ctx.actor_id.clone(), // network hiccup — don't block entering over it
        }
    } else {
        ctx.actor_id.clone()
    };

    let cfg = FileConfig {
        server:     Some(ctx.server.clone()),
        session_id: Some(session_id.to_string()),
        actor_id,
        ui:         Some(ctx.ui.clone()),
    };
    config::save(&cfg)?;
    // Stdout is piped to `source` in the calling shell — this one line is
    // what gets eval'd. config::save() always writes both companion files
    // (cheap, and means this is the only place that needs to know which
    // one the caller actually wants), so this just has to point at the
    // right one.
    match shell {
        ShellKind::Fish  => println!("source ~/.config/solarplex/session.fish"),
        ShellKind::Posix => println!("source ~/.config/solarplex/session.sh"),
    }
    Ok(())
}

/// Build a WezTerm workspace layout for the session.
///
/// Layout (all panes stay alive — no CloseOnCleanExit):
///   ┌──────────────────────────────────────┐
///   │  user's current pane  (unchanged)    │
///   ├──────────────────────────────────────┤
///   │  inspect  (auto-refreshes every 5s)  │ ← split-pane --bottom
///   ├────────────┬─────────────────────────┤
///   │ actor pane │ actor pane ...           │ ← split-pane --right (per member)
///   └────────────┴─────────────────────────┘
///
/// Each actor pane shows `sp actor show` then drops into an interactive fish
/// shell already attached to the session, so you can work in it immediately.
async fn workspace(client: &Client, ctx: &Ctx, id: Option<&str>, panes: &str) -> Result<()> {
    let raw = id.or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session. Pass <id> or attach first."))?;
    let session_id_owned = resolve_session_id(client, raw).await?;
    let session_id = session_id_owned.as_str();
    let s = client.get_session(session_id).await?;

    let name    = s["name"].as_str().unwrap_or(session_id).to_string();
    let members = s["members"].as_array().cloned().unwrap_or_default();
    let actors: Vec<String> = members.iter()
        .filter_map(|m| m["actor_id"].as_str().map(String::from))
        .collect();

    // Parse which panes to open.
    let want: Vec<&str> = panes.split(',').map(str::trim).collect();

    // $WEZTERM_PANE is injected by WezTerm per-pane; requires WSLENV in WSL.
    let anchor_env = std::env::var("WEZTERM_PANE").unwrap_or_default();
    let anchor: Option<&str> = if anchor_env.is_empty() { None } else { Some(&anchor_env) };

    // Build a WSL-safe path to the sp binary.
    // current_exe() returns a Windows path (C:\...\sp.exe). In WSL fish we need
    // either the WSL path (/mnt/c/...) or just `sp` from PATH.
    // We prefer the WSL path so it always points to the freshly-built binary.
    let sp_bin_raw = std::env::current_exe()?.to_string_lossy().to_string();
    let sp_bin = win_to_wsl_path(&sp_bin_raw);
    // Single-quote-escape for fish (handles spaces in OneDrive / path names).
    let sp_fish = format!("'{}'", sp_bin.replace('\'', "'\\''"));
    let bin = wezterm_bin();

    // Rename the current tab.
    let _ = run_wezterm(&["cli", "set-tab-title", &name]);

    // ── Layout strategy ───────────────────────────────────────────────────────
    //
    // All splits are from the ANCHOR pane only.  Never chain splits from panes
    // we just created — that causes exponential subdivision and duplicate views.
    //
    // Final layout (default: inspect + shell):
    //
    //   ┌──────────────┬──────────────────────────────────┐
    //   │  ANCHOR      │  SHELL (60% wide, full height)   │
    //   │  (40% wide,  │  Interactive session shell       │
    //   │  65% tall)   │                                  │
    //   ├──────────────┤                                  │
    //   │  INSPECT     │                                  │
    //   │  (35% tall)  │                                  │
    //   └──────────────┴──────────────────────────────────┘
    //
    // IMPORTANT: do NOT pass `-- fish -c "..."` to split-pane; WezTerm would
    // run `fish.exe` on Windows (domain "local"), which doesn't exist in WSL.
    // Instead, split with no PROG so WezTerm uses default_prog (wsl.exe -- fish),
    // then inject commands via `send-text --no-paste`.
    //
    // Anti-flicker: use ANSI cursor-home + erase-screen (printf '\033[H\033[J')
    // instead of `clear`, which scrolls the scrollback buffer.

    // ── 1. FEED pane — right split, full height ──────────────────────────────
    //
    // The "feed" pane is the primary interactive window: it enters the session,
    // shows the current inspect state once, then drops to an interactive prompt
    // so the user can type commands (sp context add, sp artifact ls, etc.).
    // Use double-quoted printf for ANSI escapes — fish single-quotes are literal.
    let mut feed_pane = String::new();
    if want.contains(&"feed") || want.contains(&"shell") {
        // Enter the session in that pane's env, then launch the live feed.
        let feed_cmd = format!(
            "{sp_fish} session enter '{session_id}' | source; {sp_fish} session feed '{session_id}'\r"
        );
        feed_pane = wezterm_split_run(&bin, anchor, "--right", Some("60"), &feed_cmd)?;
        println!("{} feed    → pane {feed_pane} (live IRC feed + post messages)", green("✓"));
    }

    // ── 2. INSPECT pane — bottom split from anchor ────────────────────────────
    //
    // Auto-refreshes every 10s. printf with double-quotes so fish interprets
    // \033 as ESC — cursor-home + erase avoids scrollback buffer flashing.
    if want.contains(&"inspect") {
        let inspect_cmd = format!(
            "while true; printf \"\\033[H\\033[J\"; {sp_fish} session inspect '{session_id}'; sleep 10; end\r"
        );
        let inspect_pane = wezterm_split_run(&bin, anchor, "--bottom", Some("35"), &inspect_cmd)?;
        println!("{} inspect → pane {inspect_pane} (auto-refresh 10s)", green("✓"));
    }

    // ── 3. ACTORS pane — bottom split from feed pane ─────────────────────────
    if want.contains(&"actors") && !feed_pane.is_empty() {
        let actor_cmds: Vec<String> = actors.iter()
            .map(|a| format!("{sp_fish} actor show '{}'", a.replace('\'', "'\\''")))
            .collect();
        let actors_body = actor_cmds.join("; echo \"\"; ");
        let actors_cmd = format!(
            "while true; printf \"\\033[H\\033[J\"; {actors_body}; sleep 15; end\r"
        );
        let pane = wezterm_split_run(&bin, Some(&feed_pane), "--bottom", Some("35"), &actors_cmd)?;
        println!("{} actors  → pane {pane}", green("✓"));
    }

    // ── 4. ARTIFACTS pane ─────────────────────────────────────────────────────
    if want.contains(&"artifacts") {
        let art_cmd = format!(
            "while true; printf \"\\033[H\\033[J\"; {sp_fish} artifact ls '{session_id}'; sleep 15; end\r"
        );
        let pane = wezterm_split_run(&bin, anchor, "--right", Some("40"), &art_cmd)?;
        println!("{} artifacts → pane {pane}", green("✓"));
    }

    // ── 5. CONTEXT pane ───────────────────────────────────────────────────────
    if want.contains(&"context") {
        let ctx_cmd = format!(
            "while true; printf \"\\033[H\\033[J\"; {sp_fish} context ls '{session_id}'; sleep 15; end\r"
        );
        let pane = wezterm_split_run(&bin, anchor, "--right", Some("40"), &ctx_cmd)?;
        println!("{} context  → pane {pane}", green("✓"));
    }

    println!();
    println!("  Panes open: {}",  dim(&want.join(",")));
    println!("  Available:  --panes inspect,feed,actors,artifacts,context");
    Ok(())
}

/// Split a pane using the default shell (no PROG — WezTerm uses default_prog,
/// which on WSL is `wsl.exe -- fish`), then send `command` as text input.
///
/// `percent` — optional size of the new pane as a percentage of available space
///             (e.g. "35" → 35%). None uses WezTerm's default (50%).
///
/// This avoids the "domain local" problem: specifying `-- fish -c "..."` makes
/// WezTerm look for `fish.exe` on Windows, which doesn't exist.
fn wezterm_split_run(
    bin:      &str,
    pane_id:  Option<&str>,
    direction: &str,
    percent:  Option<&str>,
    command:  &str,
) -> Result<String> {
    // 1. Create the pane with the default shell.
    let mut cmd = std::process::Command::new(bin);
    cmd.args(["cli", "split-pane", direction]);
    if let Some(id) = pane_id {
        cmd.args(["--pane-id", id]);
    }
    if let Some(pct) = percent {
        cmd.args(["--percent", pct]);
    }
    // No `-- PROG`: WezTerm inherits the WSL default_prog.
    let out = cmd.output()
        .map_err(|e| anyhow::anyhow!("{bin}: {e}\n  Is WezTerm installed?"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("wezterm split-pane {direction} failed: {err}");
    }
    let new_pane = String::from_utf8_lossy(&out.stdout).trim().to_string();

    // 2. Give the shell a moment to start, then send the command.
    //    The TTY input buffer holds the text until fish reads it.
    std::thread::sleep(std::time::Duration::from_millis(400));

    if !command.is_empty() && !new_pane.is_empty() {
        let send = std::process::Command::new(bin)
            .args(["cli", "send-text", "--no-paste", "--pane-id", &new_pane, command])
            .output()
            .map_err(|e| anyhow::anyhow!("{bin}: {e}"))?;
        if !send.status.success() {
            let err = String::from_utf8_lossy(&send.stderr);
            eprintln!("{} send-text warning: {err}", yellow("⚠"));
        }
    }

    Ok(new_pane)
}

/// Convert a Windows absolute path to its WSL mount path.
///   C:\Users\foo\sp.exe  →  /mnt/c/Users/foo/sp.exe
/// If the path doesn't look like a Windows drive path, return it unchanged
/// (already a POSIX path, or a bare command name).
fn win_to_wsl_path(p: &str) -> String {
    // Detect drive letter:  C:\ or C:/
    let bytes = p.as_bytes();
    if bytes.len() >= 3
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
        && bytes[0].is_ascii_alphabetic()
    {
        let drive = (bytes[0] as char).to_lowercase().to_string();
        let rest = p[3..].replace('\\', "/");
        format!("/mnt/{drive}/{rest}")
    } else {
        p.to_string()
    }
}

/// Resolve the wezterm binary.
///
/// In WSL, WezTerm is a Windows binary.  We try three locations in order:
///   1. `wezterm.exe` — works if Windows PATH is merged into WSL PATH
///   2. `/mnt/c/Program Files/WezTerm/wezterm.exe` — default install location
///   3. `wezterm` — native Linux (unlikely but harmless to try)
fn wezterm_bin() -> String {
    if std::env::var("WSL_DISTRO_NAME").is_ok() {
        // Check PATH first
        if std::process::Command::new("which")
            .arg("wezterm.exe")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return "wezterm.exe".into();
        }
        // Fall back to known install path
        let default = "/mnt/c/Program Files/WezTerm/wezterm.exe";
        if std::path::Path::new(default).exists() {
            return default.into();
        }
    }
    "wezterm".into()
}

fn run_wezterm(args: &[&str]) -> Result<()> {
    let bin = wezterm_bin();
    let status = std::process::Command::new(&bin).args(args).status()
        .map_err(|e| anyhow::anyhow!("{bin} not found: {e}\n  hint: ensure WezTerm is installed"))?;
    if !status.success() {
        anyhow::bail!("{bin} exited {}", status.code().unwrap_or(-1));
    }
    Ok(())
}

#[allow(dead_code)]
fn run_wezterm_output(args: &[&str]) -> Result<String> {
    let bin = wezterm_bin();
    let out = std::process::Command::new(&bin).args(args).output()
        .map_err(|e| anyhow::anyhow!("{bin} not found: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Spawn a new pane already attached to the given session.
fn new_pane(ctx: &Ctx, id: Option<&str>, split: &str) -> Result<()> {
    let session_id = id.or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session attached."))?;
    let anchor = std::env::var("WEZTERM_PANE").ok().filter(|s| !s.is_empty());
    let sp_bin = std::env::current_exe()?.to_string_lossy().to_string();
    let sp_fish = format!("'{}'", sp_bin.replace('\'', "'\\''"));
    let bin = wezterm_bin();

    let direction = if split == "vertical" { "--bottom" } else { "--right" };

    // Enter the session in the new pane, then leave it interactive.
    let cmd = format!("{sp_fish} session enter '{session_id}' | source\r");

    let pane_id = wezterm_split_run(&bin, anchor.as_deref(), direction, None, &cmd)?;
    println!("{} New pane {} attached to {}",
        green("✓"), dim(&pane_id),
        entity_link("session", session_id, session_id, &ctx.ui));
    Ok(())
}

/// Pause (`suspended`) / Resume (`active`) / Archive (`archived`) — real as
/// of the session-crate wiring work; previously a `sp act` stub claiming
/// "Phase 5" for what `PATCH /sessions/:id` had already implemented.
pub async fn set_status(client: &Client, ctx: &Ctx, session_id: &str, status: &str) -> Result<()> {
    let verb = match status {
        "suspended" => "Paused",
        "active"    => "Resumed",
        "archived"  => "Archived",
        other       => other,
    };
    client.update_session_status(session_id, status).await?;
    println!("{} {} {}", green("✓"), verb, entity_link("session", session_id, session_id, &ctx.ui));
    Ok(())
}

pub async fn handoff(client: &Client, ctx: &Ctx, to: &str, from: Option<&str>) -> Result<()> {
    let session_id = ctx.require_session()?;
    let from = from
        .or(ctx.actor_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("--from required (or set SOLARPLEX_ACTOR_ID)"))?;

    client.transfer_ownership(session_id, from, to).await?;
    println!("{} Ownership transferred from {} → {}", green("✓"), bold(from), bold(to));
    Ok(())
}

// ── sp session epoch ──────────────────────────────────────────────────────────

/// Computed-on-read summary — recent activity, open approvals, artifacts.
/// Never a stored value; recomputed on every call (the "SQL VIEW" analog).
pub async fn digest(client: &Client, ctx: &Ctx, id: Option<&str>) -> Result<()> {
    let session_id = id
        .or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("--session / SOLARPLEX_SESSION_ID required"))?;

    let data = client.get_digest(session_id).await?;

    let name       = sanitize_terminal(data["session_name"].as_str().unwrap_or(session_id));
    let events_24h = data["recent_event_count"].as_i64().unwrap_or(0);
    let open_appr  = data["open_approvals"].as_i64().unwrap_or(0);
    let artifacts  = data["artifacts_count"].as_i64().unwrap_or(0);
    let last_at    = data["last_activity_at"].as_str();

    println!("{} {}", bold("digest"), entity_link("session", session_id, session_id, &ctx.ui));
    println!("  {}", dim(&name));
    println!();
    println!("  events (24h)     {}", bold(&events_24h.to_string()));
    println!("  open approvals   {}", if open_appr > 0 { yellow(&open_appr.to_string()) } else { dim("0") });
    println!("  artifacts        {}", bold(&artifacts.to_string()));
    println!("  last activity    {}", dim(last_at.unwrap_or("(none)")));
    Ok(())
}

// ── Remotes ─────────────────────────────────────────────────────────────────

async fn remote(client: &Client, ctx: &Ctx, cmd: RemoteCmd) -> Result<()> {
    let local_id = ctx.session_id.as_deref()
        .ok_or_else(|| anyhow::anyhow!("No attached session. Run `sp session attach <id>` first."))?;
    match cmd {
        RemoteCmd::Add { remote } => remote_add(client, local_id, &remote).await,
        RemoteCmd::Ls             => remote_ls(client, ctx, local_id).await,
        RemoteCmd::Fetch { remote_id } => remote_fetch(client, local_id, &remote_id).await,
        RemoteCmd::Rm    { remote_id } => remote_rm(client, local_id, &remote_id).await,
    }
}

async fn remote_add(client: &Client, local_id: &str, remote_ref: &str) -> Result<()> {
    let remote_id = resolve_session_id(client, remote_ref).await?;
    let data = client.add_remote(local_id, &remote_id).await?;
    let id = data["id"].as_str().unwrap_or("?");
    println!("{} remote {} added ({})", green("✓"), bold(&remote_id), dim(id));
    Ok(())
}

async fn remote_ls(client: &Client, ctx: &Ctx, local_id: &str) -> Result<()> {
    let data = client.list_remotes(local_id).await?;
    let remotes = data.as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if remotes.is_empty() {
        println!("{}", dim("No remotes."));
        return Ok(());
    }
    println!("{}", bold("Remotes"));
    println!("  {:<28}  {:<20}  {:<10}  {}",
        dim("id"), dim("remote"), dim("watermark"), dim("last fetched"));
    for r in remotes {
        // Full id printed, not short_id()'d — fetch/rm need it verbatim and
        // there's no clickable link carrying the full value the way entity
        // refs elsewhere in this CLI do (remotes aren't an EntityHandle kind).
        let id       = r["id"].as_str().unwrap_or("?");
        let remote_s = r["remote_session_id"].as_str().unwrap_or("?");
        let wm       = r["last_fetched_seq"].as_i64().unwrap_or(0);
        let last_at  = r["last_fetched_at"].as_str().unwrap_or("never");
        println!("  {:<28}  {}  {:<10}  {}",
            dim(id),
            entity_link("session", remote_s, remote_s, &ctx.ui),
            wm,
            dim(last_at),
        );
    }
    Ok(())
}

async fn remote_fetch(client: &Client, local_id: &str, remote_id: &str) -> Result<()> {
    let data = client.fetch_remote(local_id, remote_id).await?;
    let events = data["events"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let new_wm = data["remote"]["last_fetched_seq"].as_i64().unwrap_or(0);
    if events.is_empty() {
        println!("{}", dim("Already up to date."));
        return Ok(());
    }
    println!("{} {} new event(s) — watermark now {}", green("✓"), events.len(), bold(&new_wm.to_string()));
    for e in events {
        let ty   = e["type"].as_str().unwrap_or("?");
        let seq  = e["seq"].as_i64().unwrap_or(0);
        let ts   = e["timestamp"].as_str().unwrap_or("?");
        println!("  {:<6}  {:<24}  {}", dim(&seq.to_string()), ty, dim(ts));
    }
    Ok(())
}

async fn remote_rm(client: &Client, local_id: &str, remote_id: &str) -> Result<()> {
    client.remove_remote(local_id, remote_id).await?;
    println!("{} remote {} removed", green("✓"), dim(remote_id));
    Ok(())
}

pub async fn epoch(client: &Client, ctx: &Ctx, id: Option<&str>) -> Result<()> {
    let session_id = id
        .or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("--session / SOLARPLEX_SESSION_ID required"))?;

    let data = client.session_epoch(session_id).await?;

    let current_epoch = data["epoch"].as_i64().unwrap_or(0);
    println!("{} {}", bold("session epoch"), entity_link("session", session_id, session_id, &ctx.ui));
    println!("  current epoch  {}", bold(&current_epoch.to_string()));
    println!();

    let revocations = data["revocations"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if revocations.is_empty() {
        println!("{}", dim("No revocations in this session."));
        return Ok(());
    }

    println!("{} ({})", bold("Revocation history"), revocations.len());
    println!("  {:<4}  {:<9}  {:<10}  {:<8}  {:<25}  {}",
        dim("epoch"), dim("strategy"), dim("revoked"), dim("drain_seq"), dim("deadline"), dim("by"));
    println!("  {}", dim(&"─".repeat(78)));

    for rev in revocations {
        let closed  = rev["closed_epoch"].as_i64().unwrap_or(0);
        let new_e   = rev["new_epoch"].as_i64().unwrap_or(0);
        let strat   = rev["strategy"].as_str().unwrap_or("?");
        let by      = rev["revoked_by"].as_str().unwrap_or("?");
        let at      = rev["revoked_at"].as_str().unwrap_or("?");
        let d_seq   = rev["drain_seq"].as_i64().unwrap_or(0);
        let d_dead  = rev["drain_deadline"].as_str().unwrap_or("?");

        // Format target column
        let target = if let Some(cap) = rev["target_cap_id"].as_str() {
            format!("cap/{}", &cap[..cap.len().min(8)])
        } else if let Some(s) = rev["target_stratum"].as_i64() {
            format!("stratum≥{s}")
        } else {
            "all".to_string()
        };

        let epoch_label = format!("{closed}→{new_e}");
        println!("  {:<4}  {:<9}  {:<10}  {:<8}  {:<25}  {} ({})",
            cyan(&epoch_label),
            strat,
            dim(&target),
            d_seq,
            dim(&d_dead[..d_dead.len().min(24)]),
            dim(by),
            dim(at),
        );
    }
    Ok(())
}
