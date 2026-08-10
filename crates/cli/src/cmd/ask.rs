//! `sp ask` — read-only navigation of the entity object graph.
//!
//! Every entity is navigable by `type/id` ref.  Bare collection names (`sessions`,
//! `caps`, etc.) show the collection view.  A bare `ls` or no argument shows the
//! root namespace.  An optional function name after the entity ref invokes a
//! derived read-only projection over that entity's state. See `AskArgs`' own
//! doc comment below (surfaced by `sp ask --help`) for the full syntax and
//! examples — clap only reads doc comments attached to the args struct
//! itself, not this module-level one, so the syntax reference has to live
//! there to actually reach `--help`.
//!
//! # Bidirectional navigation
//!
//! Every entity view shows its parent refs as a clickable backtrace line at the
//! top, derived from FK edges in the entity data — not from CLI state.  An
//! approval always knows its session and requesting actor regardless of how you
//! navigated there.

use anyhow::{anyhow, Result};
use clap::Args;

use crate::{client::Client, config::Ctx, output::*};
use super::{actor, approval, artifact, auth, context, session};

// ── Clap types ────────────────────────────────────────────────────────────────
//
// The long usage doc lives on `Commands::Ask` in main.rs, not here — clap's
// derive reads the *enum variant's* doc comment for a tuple-variant
// subcommand's --help text, not the wrapped Args struct's own doc comment
// (confirmed empirically: a doc comment on AskArgs itself never reached
// `sp ask --help` at all).

#[derive(Args)]
pub struct AskArgs {
    /// Entity ref or collection: ls | sessions | session/42 | actor/alice |
    /// cap/01J... | approval/01J... | artifact/01J...
    /// Omit for root namespace view.
    pub entity: Option<String>,

    /// Derived read function: pending-approvals | artifacts | members | caps |
    /// context | epoch | why | lineage | who-can
    pub function: Option<String>,

    /// Extra arguments passed to the function (e.g. the entity arg for `why`)
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub rest: Vec<String>,
}

// ── Entity reference parser ───────────────────────────────────────────────────

enum Ref {
    Root,
    Collection(String),
    Entity { kind: String, id: String },
}

fn parse_ref(s: &str) -> Ref {
    let s = s.trim_end_matches('/');
    if s.is_empty() || s == "ls" {
        return Ref::Root;
    }
    if let Some((kind, id)) = s.split_once('/') {
        if id.is_empty() {
            return Ref::Collection(kind.to_lowercase());
        }
        return Ref::Entity { kind: kind.to_lowercase(), id: id.to_string() };
    }
    // No slash — check known collection names first
    match s.to_lowercase().as_str() {
        "sessions" | "actors" | "caps" | "approvals" | "artifacts" | "context" | "proposals" => {
            Ref::Collection(s.to_lowercase())
        }
        // Bare word: try as session name (most common bare lookup)
        other => Ref::Entity { kind: "session".to_string(), id: other.to_string() },
    }
}

// ── Main dispatcher ───────────────────────────────────────────────────────────

pub async fn run(args: AskArgs, ctx: &Ctx) -> Result<()> {
    let entity_str = args.entity.as_deref().unwrap_or("ls");
    let fn_name    = args.function.as_deref().unwrap_or("");
    let rest       = &args.rest;

    let client = Client::new(ctx)?;

    match parse_ref(entity_str) {
        Ref::Root => root(&client, ctx).await,

        Ref::Collection(kind) => collection(&client, ctx, &kind).await,

        Ref::Entity { kind, id } => match (kind.as_str(), fn_name) {
            // ── Session entity ─────────────────────────────────────────────────
            ("session", "") => {
                let sid = session::resolve_session_id(&client, &id).await?;
                entity_session(&client, ctx, &sid).await
            }
            ("session", "pending-approvals") => {
                let sid  = session::resolve_session_id(&client, &id).await?;
                let ctx2 = ctx_with_session(ctx, &sid);
                println!("{}", backtrace_links(&[("sessions", "", ""), ("session", &sid, &id)]));
                println!();
                approval::ls(&client, &ctx2).await
            }
            ("session", "artifacts") => {
                let sid  = session::resolve_session_id(&client, &id).await?;
                let ctx2 = ctx_with_session(ctx, &sid);
                println!("{}", backtrace_links(&[("sessions", "", ""), ("session", &sid, &id)]));
                println!();
                artifact::ls(&client, &ctx2).await
            }
            ("session", "members") => {
                let sid = session::resolve_session_id(&client, &id).await?;
                entity_session_members(&client, ctx, &sid).await
            }
            ("session", "caps") => {
                let sid = session::resolve_session_id(&client, &id).await?;
                entity_session_caps(&client, ctx, &sid).await
            }
            ("session", "context") => {
                let sid  = session::resolve_session_id(&client, &id).await?;
                let ctx2 = ctx_with_session(ctx, &sid);
                println!("{}", backtrace_links(&[("sessions", "", ""), ("session", &sid, &id)]));
                println!();
                context::ls(&client, &ctx2, Some(&sid)).await
            }
            ("session", "epoch") => {
                let sid  = session::resolve_session_id(&client, &id).await?;
                let ctx2 = ctx_with_session(ctx, &sid);
                println!("{}", backtrace_links(&[("sessions", "", ""), ("session", &sid, &id)]));
                println!();
                session::epoch(&client, &ctx2, None).await
            }
            ("session", "digest") => {
                let sid  = session::resolve_session_id(&client, &id).await?;
                let ctx2 = ctx_with_session(ctx, &sid);
                println!("{}", backtrace_links(&[("sessions", "", ""), ("session", &sid, &id)]));
                println!();
                session::digest(&client, &ctx2, None).await
            }

            // ── Actor entity ───────────────────────────────────────────────────
            ("actor", "") => actor::show(&id, ctx).await,
            ("actor", "why") => {
                let entity_arg = rest.first().cloned();
                auth::cmd_why(id, entity_arg, ctx).await
            }
            ("actor", "who-can") => {
                auth::cmd_who_can(rest.first().cloned(), ctx).await
            }

            // ── Cap entity ─────────────────────────────────────────────────────
            ("cap", "") | ("cap", "inspect") => entity_cap(ctx, &id).await,
            ("cap", "lineage") => {
                println!("{}", backtrace_links(&[("caps", "", "")]));
                println!();
                auth::cmd_lineage(id, ctx).await
            }

            // ── Approval entity ────────────────────────────────────────────────
            ("approval", "") => entity_approval(&client, ctx, &id).await,

            // ── Artifact entity ────────────────────────────────────────────────
            ("artifact", "") | ("artifact", "get") => {
                println!("{}", backtrace_links(&[("sessions", "", "")]));
                println!();
                artifact::get(&client, ctx, &id, None).await
            }

            // ── who-can as a function on any entity ref ────────────────────────
            (_, "who-can") => {
                auth::cmd_who_can(Some(format!("{kind}/{id}")), ctx).await
            }

            (k, f) if f.is_empty() => Err(anyhow!("unknown entity type `{k}` — try: sessions | session/<id> | actor/<id> | cap/<id> | approval/<id> | artifact/<id>")),
            (k, f)                 => Err(anyhow!("unknown function `{f}` for `{k}` — try `sp ask {k}/{id}`")),
        },
    }
}

// ── Root namespace view ───────────────────────────────────────────────────────

async fn root(client: &Client, ctx: &Ctx) -> Result<()> {
    // If attached to a session, show that session's subgraph first.
    if let Some(session_id) = ctx.session_id.as_deref() {
        let (sess, artifacts, approvals, caps) = tokio::join!(
            client.get_session(session_id),
            client.list_artifacts(session_id),
            client.list_approvals(session_id),
            client.list_caps(session_id),
        );

        if let Ok(s) = sess {
            let name   = sanitize_terminal(s["name"].as_str().unwrap_or(session_id));
            let status = s["status"].as_str().unwrap_or("active");
            let policy = s["approval_policy"].as_str().unwrap_or("single_vote");
            let link   = entity_link("session", session_id, "", "");
            println!("{}", dim(&format!("─── {name} {}  {status}  {policy} ", link)));
            println!();

            let art_count  = artifacts.ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
            let pend_count = approvals.as_ref().ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
            let cap_count  = caps.ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
            let mem_count  = s["members"].as_array().map(|a| a.len()).unwrap_or(0);

            let appr_link = link_action("session", session_id, "approvals", "approvals/");
            let art_link  = link_action("session", session_id, "artifacts", "artifacts/");
            let mem_link  = link_action("session", session_id, "members",   "members/");
            let cap_link  = link_action("session", session_id, "caps",      "caps/");
            let ctx_link  = link_action("session", session_id, "context",   "context/");

            let appr_col = if pend_count > 0 {
                yellow(&format!("{pend_count} pending"))
            } else {
                dim("(none)")
            };

            println!("  {}  {}", pad(&appr_link, 14), appr_col);
            println!("  {}  {art_count}", pad(&art_link, 14));
            println!("  {}  {mem_count}", pad(&mem_link, 14));
            println!("  {}  {cap_count} active", pad(&cap_link, 14));
            println!("  {}", ctx_link);
            println!();
        }
    }

    // All sessions listing.
    let sessions = client.list_sessions(None).await?;
    let arr = sessions.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("No sessions."));
        println!();
        println!("  {}", cyan("sp act session New --name \"My Session\""));
        return Ok(());
    }

    println!("{}", dim("─── sessions ────────────────────────────────────────────────────────────────────"));
    println!();

    for s in &arr {
        let id      = s["id"].as_str().unwrap_or("?");
        let name    = sanitize_terminal(s["name"].as_str().unwrap_or("?"));
        let status  = s["status"].as_str().unwrap_or("active");
        let current = ctx.session_id.as_deref() == Some(id);
        let prefix  = if current { cyan("▶") } else { " ".to_string() };
        let link    = entity_link("session", id, "", "");
        let status_col = match status {
            "active"    => green(status),
            "archived"  => dim(status),
            "suspended" => yellow(status),
            _           => status.to_string(),
        };
        println!("{} {}  {}  {}", prefix, pad(&link, 12), pad(&name, 28), status_col);
    }
    println!();
    println!("  {}  sp ask session/<id>", dim("→"));
    println!("  {}  sp act session New --name <name>", dim("→"));
    Ok(())
}

// ── Collection views ──────────────────────────────────────────────────────────

async fn collection(client: &Client, ctx: &Ctx, kind: &str) -> Result<()> {
    match kind {
        "sessions" => {
            println!("{}", backtrace_links(&[("sessions", "", "")]));
            println!();
            session::ls(client, ctx, false).await
        }
        "actors" => {
            // Actors are scoped to the current session.
            let session_id = ctx.require_session()?;
            println!("{}", backtrace_links(&[("actors", "", "")]));
            println!();
            entity_session_members(client, ctx, session_id).await
        }
        "approvals" => {
            println!("{}", backtrace_links(&[("approvals", "", "")]));
            println!();
            approval::ls(client, ctx).await
        }
        "artifacts" => {
            println!("{}", backtrace_links(&[("artifacts", "", "")]));
            println!();
            artifact::ls(client, ctx).await
        }
        "caps" => {
            let session_id = ctx.require_session()?;
            println!("{}", backtrace_links(&[("caps", "", "")]));
            println!();
            entity_session_caps(client, ctx, session_id).await
        }
        "context" => {
            println!("{}", backtrace_links(&[("context", "", "")]));
            println!();
            context::ls(client, ctx, None).await
        }
        _ => Err(anyhow!("unknown collection `{kind}/`")),
    }
}

// ── Entity views ──────────────────────────────────────────────────────────────

/// Full subgraph view for a session — the graph-navigation equivalent of
/// `sp session inspect`, organised around forward edges + available transitions.
async fn entity_session(client: &Client, ctx: &Ctx, session_id: &str) -> Result<()> {
    let (s, artifacts, approvals, caps, events) = tokio::join!(
        client.get_session(session_id),
        client.list_artifacts(session_id),
        client.list_approvals(session_id),
        client.list_caps(session_id),
        client.list_events(session_id, 8),
    );

    let s      = s?;
    let name   = sanitize_terminal(s["name"].as_str().unwrap_or("?"));
    let status = s["status"].as_str().unwrap_or("active");
    let policy = s["approval_policy"].as_str().unwrap_or("single_vote");

    // Backtrace — every session's parent is the sessions collection.
    println!("{}", backtrace_links(&[("sessions", "", "")]));
    println!();

    // Header — name is editable state (Plan 9 / Acme style): ULID stays stable.
    // The [rename] link fires `sp act session/<id> Rename --name <...>` so the
    // user can rename directly from the entity view.
    let rename_uri  = format!("solarplex://act/session/{session_id}/Rename");
    let rename_link = link(&rename_uri, "✎ rename");
    println!("{} {}  {} {}  {}",
        bold(&name),
        entity_link("session", session_id, "", ""),
        status_icon(status),
        dim(policy),
        dim(&rename_link),
    );
    println!("{}", dim(&"─".repeat(50)));
    println!();

    // Forward edges — members inline, everything else as clickable sub-paths.
    if let Some(members) = s["members"].as_array() {
        print!("  {}  ", pad("members/", 14));
        let labels: Vec<String> = members.iter().map(|m| {
            let actor    = sanitize_terminal(m["actor_id"].as_str().unwrap_or("?"));
            let name     = sanitize_terminal(m["name"].as_str().unwrap_or(""));
            let role     = m["role"].as_str().unwrap_or("?");
            let is_me    = ctx.actor_id.as_deref() == Some(&actor);
            let a_link   = actor_link_named(&actor, &name);
            if is_me { format!("{}{}", cyan("▶ "), a_link) } else { format!("{}:{}", a_link, dim(role)) }
        }).collect();
        println!("{}", labels.join("  "));
    }

    let art_count  = artifacts.as_ref().ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
    let pend_count = approvals.as_ref().ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);
    let cap_count  = caps.as_ref().ok().and_then(|v| v.as_array().map(|a| a.len())).unwrap_or(0);

    let appr_link = link_action("session", session_id, "approvals", "approvals/");
    let art_link  = link_action("session", session_id, "artifacts", "artifacts/");
    let cap_link  = link_action("session", session_id, "caps",      "caps/");
    let ctx_link  = link_action("session", session_id, "context",   "context/");
    let ep_link   = link_action("session", session_id, "epoch",     "epoch");

    let appr_col = if pend_count > 0 {
        yellow(&format!("{pend_count} pending"))
    } else {
        dim("(none)")
    };

    println!("  {}  {}", pad(&appr_link, 14), appr_col);
    println!("  {}  {art_count}", pad(&art_link, 14));
    println!("  {}  {cap_count} active", pad(&cap_link, 14));
    println!("  {}", ctx_link);
    println!("  {}", ep_link);
    println!();

    // Available transitions based on lifecycle state, filtered to what the
    // current actor's own role in *this* session actually clears server-side
    // — showing a mutating link nobody can act on isn't just noise, it's an
    // unearned affordance to click something that will just 403. Role floors
    // here mirror the real gates in routes/sessions.rs exactly (Collaborator+
    // for update_session/issue_attach_token, Owner-only for
    // transfer_ownership, any active/non-Observer member for
    // create_artifact/add_context) rather than inventing a separate policy.
    let my_role = s["members"].as_array()
        .and_then(|ms| ms.iter().find(|m| m["actor_id"].as_str() == ctx.actor_id.as_deref()))
        .and_then(|m| m["role"].as_str())
        .unwrap_or("");
    let owner_only        = my_role == "owner";
    let collaborator_plus = my_role == "owner" || my_role == "collaborator";
    let active_member     = !my_role.is_empty() && my_role != "observer";

    let candidates: &[(&str, &str, bool)] = match status {
        "active" => &[
            ("Rename",            "--name <new-name>",     collaborator_plus),
            ("OwnershipTransfer", "--to <actor>",           owner_only),
            ("Delegate",          "--to <actor> --ttl 900", collaborator_plus),
            ("CreateArtifact",    "--name <name>",          active_member),
            ("AddContext",        "[kind] <text...>",       active_member),
            ("Pause",             "",                       collaborator_plus),
            ("Archive",           "",                       collaborator_plus),
        ],
        "suspended" => &[
            ("Resume",  "", collaborator_plus),
            ("Archive", "", collaborator_plus),
        ],
        _ => &[],
    };
    let transitions: Vec<(&str, &str)> = candidates.iter()
        .filter(|(_, _, allowed)| *allowed)
        .map(|&(t, hint, _)| (t, hint))
        .collect();
    if !transitions.is_empty() {
        println!("  {}", dim("─ transitions ──────────────────────────────────"));
        for (t, hint) in transitions {
            let uri   = format!("solarplex://act/session/{session_id}/{t}");
            let tlink = link(&uri, t);
            println!("  {}  {}", pad(&tlink, 22), dim(hint));
        }
        println!();
    }

    // Recent activity (compact).
    if let Ok(evts) = events {
        if let Some(arr) = evts.as_array() {
            if !arr.is_empty() {
                println!("  {}", dim("─ recent activity ──────────────────────────────"));
                for e in arr.iter().rev().take(6) {
                    let actor = sanitize_terminal(e["actor_id"].as_str().unwrap_or("?"));
                    let etype = e["type"].as_str().unwrap_or("?");
                    let short = etype.split('.').last().unwrap_or(etype);
                    println!("  {}  {}", pad(&dim(&actor_link(&actor)), 22), dim(short));
                }
            }
        }
    }

    Ok(())
}

/// Members sub-view: `sp ask session/42 members`
async fn entity_session_members(client: &Client, ctx: &Ctx, session_id: &str) -> Result<()> {
    let s    = client.get_session(session_id).await?;
    let name = sanitize_terminal(s["name"].as_str().unwrap_or(session_id));

    println!("{}", backtrace_links(&[("sessions", "", ""), ("session", session_id, &name)]));
    println!();
    println!("{} {}", bold(&name), dim("members"));
    println!("{}", dim(&"─".repeat(42)));

    if let Some(members) = s["members"].as_array() {
        let current_actor = ctx.actor_id.as_deref().unwrap_or("");
        println!("  {}  {}  {}", bold(&pad("ACTOR", 26)), bold(&pad("ROLE", 16)), bold("STATUS"));
        for m in members {
            let actor    = sanitize_terminal(m["actor_id"].as_str().unwrap_or("?"));
            let name     = sanitize_terminal(m["name"].as_str().unwrap_or(""));
            let role     = sanitize_terminal(m["role"].as_str().unwrap_or("?"));
            let detached = m["detached"].as_bool().unwrap_or(false);
            let marker   = if actor == current_actor { cyan("▶") } else { " ".to_string() };
            let status   = if detached { dim("detached") } else { green("active") };
            println!("{} {}  {}  {}", marker, pad(&actor_link_named(&actor, &name), 26), pad(&role, 16), status);
        }
    } else {
        println!("{}", dim("(no members)"));
    }
    Ok(())
}

/// Caps sub-view: `sp ask session/42 caps`
async fn entity_session_caps(client: &Client, _ctx: &Ctx, session_id: &str) -> Result<()> {
    let s_name = client.get_session(session_id).await
        .ok()
        .and_then(|s| s["name"].as_str().map(|n| n.to_string()))
        .unwrap_or_else(|| short_id(session_id).to_string());

    println!("{}", backtrace_links(&[("sessions", "", ""), ("session", session_id, &s_name)]));
    println!();

    let caps = client.list_caps(session_id).await?;
    let arr  = caps.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("No active caps in this session."));
        return Ok(());
    }

    println!("{} ({})", bold("CAPS"), arr.len());
    println!("  {}  {}  {}", bold(&pad("CAP", 12)), bold(&pad("ACTOR", 24)), bold("SCOPE"));
    for c in &arr {
        let cap_id = c["id"].as_str().unwrap_or("?");
        let actor  = sanitize_terminal(
            c["grantee"].as_str()
                .or_else(|| c["actor_id"].as_str())
                .unwrap_or("?"),
        );
        let scope  = sanitize_terminal(c["scope"].as_str().unwrap_or("*"));
        let link   = entity_link("cap", cap_id, session_id, "");
        println!("  {}  {}  {}", pad(&link, 12), pad(&actor_link(&actor), 24), dim(&scope));
    }
    Ok(())
}

/// Cap entity view: shows lineage (delegates to `sp auth lineage`).
async fn entity_cap(ctx: &Ctx, cap_id: &str) -> Result<()> {
    println!("{}", backtrace_links(&[("caps", "", "")]));
    println!();
    println!("{} {}", bold("cap"), entity_link("cap", cap_id, "", ""));
    println!();
    // Lineage is the richest view available for a cap.
    auth::cmd_lineage(cap_id.to_string(), ctx).await
}

/// Approval entity view with backtrace to session + requesting actor.
async fn entity_approval(client: &Client, ctx: &Ctx, approval_id: &str) -> Result<()> {
    let session_id = ctx.session_id.as_deref().unwrap_or("");
    if session_id.is_empty() {
        anyhow::bail!(
            "viewing an approval requires session context\n  \
             hint: sp session attach <session_id>"
        );
    }

    let approvals = client.list_approvals(session_id).await?;
    let a = approvals.as_array()
        .and_then(|arr| arr.iter().find(|a| a["id"].as_str() == Some(approval_id)));

    match a {
        None => {
            println!("{} approval {} not found in session {}",
                red("✗"), approval_id, short_id(session_id));
            println!("{}", dim("hint: attach to the session containing this approval"));
        }
        Some(a) => {
            let actor  = sanitize_terminal(a["actor_id"].as_str().unwrap_or("?"));
            let tool   = sanitize_terminal(a["tool_name"].as_str().unwrap_or("?"));
            let status = a["status"].as_str().unwrap_or("pending");
            let sid    = a["session_id"].as_str().unwrap_or(session_id);

            // Backtrace: the approval knows its session and requesting actor.
            println!("{}", backtrace_links(&[
                ("session", sid, ""),
                ("actor",   &actor, &actor),
            ]));
            println!();

            // Header
            println!("{} {}  {}",
                bold(&tool),
                entity_link("approval", approval_id, sid, ""),
                status_icon(status),
            );
            println!("{}", dim(&"─".repeat(42)));
            println!("  tool:    {}", bold(&tool));
            println!("  actor:   {}", actor_link(&actor));
            println!("  status:  {}", match status {
                "granted" => green(status),
                "denied"  => red(status),
                "expired" => dim(status),
                _         => yellow(status),
            });

            if let Some(args) = a.get("arguments") {
                if let Ok(pretty) = serde_json::to_string_pretty(args) {
                    for line in pretty.lines().take(10) {
                        println!("  {}", dim(line));
                    }
                }
            }

            // Transitions (only for pending)
            if status == "pending" {
                println!();
                println!("  {}", dim("─ transitions ─────────────────────────────────"));
                let grant_uri = format!("solarplex://act/approval/{approval_id}/Grant");
                let deny_uri  = format!("solarplex://act/approval/{approval_id}/Deny");
                println!("  {}   {}",
                    link(&grant_uri, "Grant"),
                    link(&deny_uri, "Deny"),
                );
                println!("  {}", dim(&format!("sp act approval/{} Grant", &approval_id[..8])));
            }
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a Ctx with a specific session_id, inheriting everything else.
fn ctx_with_session(ctx: &Ctx, session_id: &str) -> Ctx {
    Ctx {
        session_id: Some(session_id.to_string()),
        ..ctx.clone()
    }
}
