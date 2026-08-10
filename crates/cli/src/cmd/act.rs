//! `sp act` — write path: fire transitions on entities.
//!
//! All mutations go through this surface.  The entity ref identifies what to act
//! on; the PascalCase transition name identifies the operation; named flags supply
//! the arguments.  This is the CLI incarnation of the session machine's
//! `transition(entity, verb, args) → effects` contract. See `ActArgs`' own
//! doc comment below (surfaced by `sp act --help`) for the full syntax and
//! examples — clap only reads doc comments attached to the args struct
//! itself, not this module-level one, so the syntax reference has to live
//! there to actually reach `--help`.
//!
//! # No write path in `sp ask`
//!
//! Functions reachable via `sp ask` are guaranteed read-only.  All mutations,
//! regardless of how trivial, go through `sp act`.  This boundary is structural:
//! `ask` handlers take `&Client` (reads only) while `act` handlers call the
//! client's POST/PUT methods.

use anyhow::{anyhow, Result};
use clap::Args;

use crate::{client::Client, config::Ctx, output::{bold, dim, short_id}};
use super::{approval, artifact, cap, context, session};

// ── Clap types ────────────────────────────────────────────────────────────────
//
// The long usage doc lives on `Commands::Act` in main.rs, not here — see
// ask.rs's identical note for why (clap reads the enum variant's doc
// comment for a tuple-variant subcommand's --help text, not this struct's).

#[derive(Args)]
pub struct ActArgs {
    /// Entity ref: `session/42`, `cap/01J...`, `approval/01J...`.
    /// Use bare `session` (no id) for the `New` transition.
    pub entity: String,

    /// Transition name (PascalCase):
    /// New | OwnershipTransfer | Delegate | Revoke | Grant | Deny |
    /// CreateArtifact | AddContext | Pause | Resume | Archive
    pub transition: String,

    // ── Shared ────────────────────────────────────────────────────────────────
    /// Target actor — required for OwnershipTransfer and Delegate
    #[arg(long)]
    pub to: Option<String>,

    // ── Session: New ──────────────────────────────────────────────────────────
    /// Session name (New)
    #[arg(long)]
    pub name: Option<String>,
    /// Approval policy: single_vote | majority | unanimous (New)
    #[arg(long, default_value = "single_vote")]
    pub policy: String,
    /// Session description (New)
    #[arg(long)]
    pub description: Option<String>,

    // ── Cap: Delegate ─────────────────────────────────────────────────────────
    /// Token lifetime in seconds (Delegate, default 15 min)
    #[arg(long, default_value = "900")]
    pub ttl: u64,
    /// Allowed tool names, comma-separated (Delegate; empty = all)
    #[arg(long, value_delimiter = ',')]
    pub permissions: Vec<String>,
    /// Delegated actor role: agent | collaborator (Delegate)
    #[arg(long, default_value = "agent")]
    pub role: String,
    /// MCP filesystem path exposed to the agent (Delegate)
    #[arg(long)]
    pub path: Option<String>,
    /// Parent cap to delegate from (Delegate)
    #[arg(long)]
    pub parent: Option<String>,

    // ── Cap: Revoke ───────────────────────────────────────────────────────────
    /// Revocation strategy: cap | stratum | epoch (Revoke)
    #[arg(long, default_value = "cap")]
    pub strategy: String,
    /// Minimum stratum depth to revoke (Revoke --strategy stratum)
    #[arg(long)]
    pub stratum: Option<i64>,
    /// Drain window in seconds — grace period for in-flight agents (Revoke)
    #[arg(long, default_value = "30")]
    pub drain: u64,
    /// Re-root surviving children before pruning (Revoke --strategy cap)
    #[arg(long)]
    pub reroot: bool,

    // ── Session: Pause ────────────────────────────────────────────────────────
    /// Human-readable reason (Pause)
    #[arg(long)]
    pub reason: Option<String>,

    // ── Artifact: CreateArtifact ──────────────────────────────────────────────
    /// Artifact type: document | code | plan | report | other
    #[arg(long, short = 't', default_value = "document")]
    pub artifact_type: String,
    /// Source file (CreateArtifact; omit to read from stdin)
    #[arg(long, short)]
    pub file: Option<std::path::PathBuf>,

    // ── Context: AddContext ───────────────────────────────────────────────────
    /// Context kind: fact | hypothesis | decision | question | constraint
    #[arg(long, default_value = "fact")]
    pub kind: String,
    /// Content words (AddContext — all trailing args joined with spaces)
    #[arg(trailing_var_arg = true)]
    pub words: Vec<String>,
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

pub async fn run(args: ActArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    let (kind, id_opt) = parse_entity(&args.entity);
    let transition = args.transition.as_str();

    match (kind, transition) {
        // ── session New ───────────────────────────────────────────────────────
        ("session", "New") | ("session", "Create") => {
            let name = args.name.as_deref()
                .ok_or_else(|| anyhow!("--name <session-name> required for New"))?;
            session::new_session(&client, ctx, name, args.description.as_deref(), &args.policy).await
        }

        // ── session OwnershipTransfer ─────────────────────────────────────────
        ("session", "OwnershipTransfer") | ("session", "Handoff") => {
            let to  = args.to.as_deref()
                .ok_or_else(|| anyhow!("--to <actor_id> required for OwnershipTransfer"))?;
            let id  = require_id(id_opt, "session", "OwnershipTransfer")?;
            let ctx2 = ctx_with_session(ctx, id);
            session::handoff(&client, &ctx2, to, ctx.actor_id.as_deref()).await
        }

        // ── session Delegate (issue a cap) ────────────────────────────────────
        ("session", "Delegate") => {
            let to  = args.to.as_deref()
                .ok_or_else(|| anyhow!("--to <actor_id> required for Delegate"))?;
            let id  = require_id(id_opt, "session", "Delegate")?;
            let ctx2 = ctx_with_session(ctx, id);
            cap::delegate(
                &client, &ctx2, to, &args.permissions, args.ttl,
                args.path.as_deref(), args.parent.as_deref(), &args.role,
            ).await
        }

        // ── session Rename — editable namespace (Plan 9 / Acme style) ───────────
        // Name is just mutable state on the entity; ULID identity stays stable.
        // Any member can rename; the new name resolves via `sp ask session/<name>`.
        //
        // --name is optional: when absent (e.g. invoked via a plumb link click)
        // we prompt interactively on stdin so the user can type the new name
        // in the same terminal.  The plumb subprocess inherits the parent tty,
        // so read_line() just works.
        ("session", "Rename") => {
            let id = require_id(id_opt, "session", "Rename")?;
            let actor = ctx.actor_id.as_deref();

            let name_buf;
            let new_name: &str = if let Some(n) = args.name.as_deref() {
                n
            } else {
                use std::io::Write as _;
                print!("✎  rename {} → ", dim(&short_id(id)));
                std::io::stdout().flush()?;
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    return Err(anyhow!("rename cancelled (empty name)"));
                }
                name_buf = trimmed.to_string();
                &name_buf
            };

            let session = client.rename_session(id, new_name, actor).await?;
            let confirmed = session["name"].as_str().unwrap_or(new_name);
            println!("✎  {} → {}  {}",
                dim(&short_id(id)),
                bold(confirmed),
                dim(&format!("(solarplex://session/{id})")),
            );
            Ok(())
        }

        // ── session Pause / Resume / Archive ──────────────────────────────────
        ("session", "Pause") => {
            let id = require_id(id_opt, "session", "Pause")?;
            session::set_status(&client, ctx, id, "suspended").await
        }
        ("session", "Resume") => {
            let id = require_id(id_opt, "session", "Resume")?;
            session::set_status(&client, ctx, id, "active").await
        }
        ("session", "Archive") => {
            let id = require_id(id_opt, "session", "Archive")?;
            session::set_status(&client, ctx, id, "archived").await
        }

        // ── session CreateArtifact ────────────────────────────────────────────
        ("session", "CreateArtifact") => {
            let name = args.name.as_deref()
                .ok_or_else(|| anyhow!("--name <artifact-name> required for CreateArtifact"))?;
            let id   = require_id(id_opt, "session", "CreateArtifact")?;
            let ctx2 = ctx_with_session(ctx, id);
            artifact::create(&client, &ctx2, name, &args.artifact_type, args.file.as_deref()).await
        }

        // ── session AddContext ─────────────────────────────────────────────────
        ("session", "AddContext") => {
            let id = require_id(id_opt, "session", "AddContext")?;
            if args.words.is_empty() {
                return Err(anyhow!(
                    "content required: sp act session/{id} AddContext [kind] <text...>"
                ));
            }
            let content = args.words.join(" ");
            let ctx2    = ctx_with_session(ctx, id);
            context::add(&client, &ctx2, &args.kind, &content).await
        }

        // ── cap Revoke ────────────────────────────────────────────────────────
        ("cap", "Revoke") | ("cap", "revoke") => {
            let id = require_id(id_opt, "cap", "Revoke")?;
            cap::revoke(
                &client, ctx, id,
                &args.strategy, args.stratum, args.drain, args.reroot,
            ).await
        }

        // ── approval Grant / Deny ─────────────────────────────────────────────
        ("approval", "Grant") | ("approval", "grant") => {
            let id = require_id(id_opt, "approval", "Grant")?;
            approval::vote(&client, ctx, id, "grant").await
        }
        ("approval", "Deny") | ("approval", "deny") => {
            let id = require_id(id_opt, "approval", "Deny")?;
            approval::vote(&client, ctx, id, "deny").await
        }

        // ── fallthrough ───────────────────────────────────────────────────────
        (k, t) => Err(anyhow!(
            "unknown transition `{t}` for entity type `{k}`\n  \
             hint: sp act <entity-ref> <PascalCaseTransition> [args]\n  \
             known: session New | session/<id> Rename --name <n> | session/<id> OwnershipTransfer |\n  \
                    session/<id> Delegate | session/<id> CreateArtifact | session/<id> AddContext |\n  \
                    session/<id> Pause | session/<id> Resume | session/<id> Archive |\n  \
                    cap/<id> Revoke | approval/<id> Grant | approval/<id> Deny"
        )),
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse `"session/42"` → `("session", Some("42"))`,
///       `"session"`    → `("session", None)`.
fn parse_entity(s: &str) -> (&str, Option<&str>) {
    if let Some((kind, id)) = s.split_once('/') {
        (kind, Some(id).filter(|s| !s.is_empty()))
    } else {
        (s, None)
    }
}

/// Require that `id_opt` is `Some` — gives a context-rich error if it's None.
fn require_id<'a>(
    id_opt:     Option<&'a str>,
    kind:       &str,
    transition: &str,
) -> Result<&'a str> {
    id_opt.ok_or_else(|| anyhow!(
        "`{transition}` requires an entity id\n  \
         use: sp act {kind}/<id> {transition}\n  \
         (exception: `session New` for creating a new session)"
    ))
}

/// Build a Ctx with a specific session_id, inheriting everything else.
fn ctx_with_session(ctx: &Ctx, session_id: &str) -> Ctx {
    Ctx {
        session_id: Some(session_id.to_string()),
        ..ctx.clone()
    }
}
