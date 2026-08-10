//! `sp auth` — tuple-space query layer over the Solarplex cap DAG.
//!
//! These commands are **explanatory and read-only**.  They describe the current
//! authorization state but are not themselves enforcement points.  Useful for
//! debugging why something is allowed or denied, auditing delegation chains,
//! and building intuition about attenuation.
//!
//! # Commands
//!
//! ```text
//! sp auth why    actor/alice approval/01J…   # why can alice interact with this?
//! sp auth who-can artifact/01J…              # who has authority over this entity?
//! sp auth lineage cap/01K…                   # full delegation chain for a capability
//! ```

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output::*};

// ── Clap types ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct AuthArgs {
    #[command(subcommand)]
    pub cmd: AuthCmd,
}

#[derive(Subcommand)]
pub enum AuthCmd {
    /// Explain why an actor has (or lacks) authority over an entity.
    ///
    /// Shows the actor's session membership role and all active capability
    /// tokens with their delegation lineage, so you can trace exactly which
    /// grant makes an action possible.
    ///
    /// Examples:
    ///   sp auth why actor/alice approval/01J...
    ///   sp auth why actor/alice                   # all caps, no entity filter
    Why {
        /// Actor entity reference: "actor/alice" or just "alice"
        actor: String,
        /// Optional entity to check against: "approval/01J...", "artifact/01J...", etc.
        entity: Option<String>,
    },
    /// Show who has authority over an entity in the current session.
    ///
    /// Lists members by their formal role and actors with active capability
    /// tokens that cover the entity type's operations.
    ///
    /// Examples:
    ///   sp auth who-can artifact/01J...
    ///   sp auth who-can approval/01J...
    ///   sp auth who-can                           # all members + all cap holders
    #[command(name = "who-can")]
    WhoCan {
        /// Optional entity to filter by: "artifact/01J...", "approval/01J...", etc.
        entity: Option<String>,
    },
    /// Show the full delegation lineage of a capability token.
    ///
    /// Walks the parent_cap chain from the root (human-issued) to the
    /// leaf, showing actor, permissions, and attenuation at each hop.
    /// The root is always the original human grant; each subsequent hop
    /// is a delegation that can only narrow the permission set.
    ///
    /// Examples:
    ///   sp auth lineage cap/01K...
    ///   sp auth lineage 01K...                    # bare ULID also accepted
    Lineage {
        /// Cap entity reference: "cap/01K..." or just "01K..."
        cap: String,
    },
}

pub async fn run(args: AuthArgs, ctx: &Ctx) -> Result<()> {
    match args.cmd {
        AuthCmd::Why { actor, entity }   => cmd_why(actor, entity, ctx).await,
        AuthCmd::WhoCan { entity }       => cmd_who_can(entity, ctx).await,
        AuthCmd::Lineage { cap }         => cmd_lineage(cap, ctx).await,
    }
}

// ── sp auth why ───────────────────────────────────────────────────────────────

pub async fn cmd_why(actor: String, entity: Option<String>, ctx: &Ctx) -> Result<()> {
    let client     = Client::new(ctx)?;
    let session_id = require_session(ctx)?;

    // Normalise "actor/alice" → "alice", and "alice" stays "alice"
    let actor_id = actor.strip_prefix("actor/").unwrap_or(&actor);

    let data = client.auth_why(session_id, actor_id, entity.as_deref()).await?;

    // ── Header ────────────────────────────────────────────────────────────────
    let entity_label = entity.as_deref().unwrap_or("(all entities)");
    println!("{} {} → {}", bold("why"), cyan(&format!("actor/{actor_id}")), cyan(entity_label));
    println!("{} {}", dim("session"), dim(session_id));
    println!();

    // ── Membership ────────────────────────────────────────────────────────────
    if let Some(m) = data.get("membership") {
        let role   = m["role"].as_str().unwrap_or("?");
        let detached = m["detached"].as_bool().unwrap_or(false);
        let status = if detached { dim("detached") } else { green("active") };
        println!("{}", bold("Membership"));
        println!("  role     {}", cyan(role));
        println!("  status   {status}");
        println!("  approve  {}", yesno(m["can_approve"].as_bool().unwrap_or(false)));
        println!("  write    {}", yesno(m["can_write"].as_bool().unwrap_or(false)));
        println!();
    } else {
        println!("{} actor/{actor_id} is not a formal session member", yellow("⚠"));
        println!();
    }

    // ── Caps ──────────────────────────────────────────────────────────────────
    let caps = data["caps"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if caps.is_empty() {
        println!("{}", dim("No active capability tokens."));
        return Ok(());
    }
    println!("{} ({})", bold("Active capabilities"), caps.len());

    for cap in caps {
        let cap_id   = cap["id"].as_str().unwrap_or("?");
        let perms    = cap["permissions_label"].as_str().unwrap_or("?");
        let covered  = cap["entity_covered"].as_bool().unwrap_or(true);
        let used     = cap["used_at"].is_string();
        let expires  = cap["expires_at"].as_str().unwrap_or("?");
        let is_root  = cap["is_root"].as_bool().unwrap_or(false);

        let coverage_label = if entity.is_some() {
            if covered { green("  covers entity") } else { dim("  doesn't cover entity") }
        } else {
            String::new()
        };

        println!(
            "  {} {} [{}]{}  expires {}",
            if is_root { "◉" } else { "◎" },
            entity_link("cap", cap_id, session_id, ""),
            perms,
            coverage_label,
            dim(expires),
        );
        if used && is_root {
            println!("    {} root token exchanged (agent attached)", dim("→"));
        }

        // Lineage chain
        let lineage = cap["lineage"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
        if lineage.len() > 1 {
            println!("    delegation chain:");
            for (i, hop) in lineage.iter().enumerate() {
                let hop_id    = hop["id"].as_str().unwrap_or("?");
                let hop_actor = hop["actor_id"].as_str().unwrap_or("?");
                let hop_name  = hop["actor_name"].as_str().unwrap_or("?");
                let hop_perms = hop["permissions_label"].as_str().unwrap_or("?");
                let hop_seq   = hop["observed_seq"].as_i64().unwrap_or(0);
                let root_mark = if hop["is_root"].as_bool().unwrap_or(false) { " [root]" } else { "" };
                let prefix    = if i + 1 == lineage.len() { "└─" } else { "├─" };
                println!(
                    "    {prefix} {} {} ({}) [{}] seq={}{root_mark}",
                    entity_link("cap", hop_id, session_id, ""),
                    dim(&format!("actor/{hop_actor}")),
                    hop_name,
                    hop_perms,
                    hop_seq,
                );
            }
        }
    }
    Ok(())
}

// ── sp auth who-can ───────────────────────────────────────────────────────────

pub async fn cmd_who_can(entity: Option<String>, ctx: &Ctx) -> Result<()> {
    let client     = Client::new(ctx)?;
    let session_id = require_session(ctx)?;

    let data = client.auth_who_can(session_id, entity.as_deref()).await?;

    let entity_label = entity.as_deref().unwrap_or("(all entities)");
    println!("{} {}", bold("who-can"), cyan(entity_label));
    println!("{} {}", dim("session"), dim(session_id));
    println!();

    // ── By role ───────────────────────────────────────────────────────────────
    let by_role = data["by_role"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if by_role.is_empty() {
        println!("{}", dim("No members."));
    } else {
        println!("{}", bold("By role"));
        for m in by_role {
            let actor_id = m["actor_id"].as_str().unwrap_or("?");
            let name     = m["actor_name"].as_str().unwrap_or("?");
            let role     = m["role"].as_str().unwrap_or("?");
            let detached = m["detached"].as_bool().unwrap_or(false);
            let icon     = match role {
                "owner"        => green("●"),
                "collaborator" => cyan("●"),
                "observer"     => dim("○"),
                "agent"        => yellow("◆"),
                _              => dim("?"),
            };
            let det_suffix = if detached { dim(" (detached)") } else { String::new() };
            println!(
                "  {icon}  {}  {}  {}{}",
                entity_link("actor", actor_id, session_id, ""),
                name,
                dim(role),
                det_suffix,
            );
        }
        println!();
    }

    // ── By cap ────────────────────────────────────────────────────────────────
    let by_cap = data["by_cap"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if by_cap.is_empty() {
        println!("{}", dim("No active capability tokens in this session."));
    } else {
        println!("{}", bold("By capability"));
        for c in by_cap {
            let actor_id  = c["actor_id"].as_str().unwrap_or("?");
            let name      = c["actor_name"].as_str().unwrap_or("?");
            let cap_id    = c["cap_id"].as_str().unwrap_or("?");
            let perms     = c["permissions_label"].as_str().unwrap_or("?");
            let delegated = c["delegated"].as_bool().unwrap_or(false);
            let expires   = c["expires_at"].as_str().unwrap_or("?");
            let del_mark  = if delegated { dim(" delegated") } else { String::new() };
            println!(
                "  ◎  {}  {}  {}  [{}]{}  expires {}",
                entity_link("actor", actor_id, session_id, ""),
                name,
                entity_link("cap", cap_id, session_id, ""),
                perms,
                del_mark,
                dim(expires),
            );
        }
    }
    Ok(())
}

// ── sp auth lineage ───────────────────────────────────────────────────────────

pub async fn cmd_lineage(cap: String, ctx: &Ctx) -> Result<()> {
    let client     = Client::new(ctx)?;
    let session_id = ctx.session_id.as_deref().unwrap_or("");

    // Normalise "cap/01K..." → "01K..."
    let cap_id = cap.strip_prefix("cap/").unwrap_or(&cap);

    let data = client.auth_lineage(cap_id).await?;

    let depth = data["depth"].as_u64().unwrap_or(0);
    println!("{} {}", bold("lineage"), entity_link("cap", cap_id, session_id, ""));
    println!("{} hops from root to leaf", dim(&depth.to_string()));
    println!();

    let chain = data["chain"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    if chain.is_empty() {
        println!("{}", dim("(empty chain)"));
        return Ok(());
    }

    for hop in chain {
        let hop_idx   = hop["hop"].as_u64().unwrap_or(0);
        let hop_id    = hop["id"].as_str().unwrap_or("?");
        let actor_id  = hop["actor_id"].as_str().unwrap_or("?");
        let actor_name = hop["actor_name"].as_str().unwrap_or("?");
        let perms     = hop["permissions_label"].as_str().unwrap_or("?");
        let seq       = hop["observed_seq"].as_i64().unwrap_or(0);
        let status    = hop["status"].as_str().unwrap_or("?");
        let is_root   = hop["is_root"].as_bool().unwrap_or(false);
        let is_leaf   = hop["is_leaf"].as_bool().unwrap_or(false);
        let issued_at = hop["issued_at"].as_str().unwrap_or("?");

        let status_col = match status {
            "active"    => green(status),
            "exchanged" => cyan(status),
            "expired"   => red(status),
            s           => dim(s),
        };
        let marker = match (is_root, is_leaf) {
            (true,  true)  => "◉",   // root == leaf: single-hop chain
            (true,  false) => "◉",   // root
            (false, true)  => "◎",   // leaf
            (false, false) => "◎",   // intermediate
        };
        let tree_prefix = if is_root { "  ".to_string() } else { format!("  {}  ", "│ ".repeat((hop_idx as usize).saturating_sub(1))) };
        let connector   = if is_root { "" } else { "└─ " };

        println!(
            "{tree_prefix}{connector}{marker} {} [{}]  {status_col}  seq={}  {}",
            entity_link("cap", hop_id, session_id, ""),
            perms,
            seq,
            dim(issued_at),
        );
        println!(
            "{}    actor/{actor_id} ({actor_name})",
            tree_prefix,
        );
        if !is_leaf { println!("{tree_prefix}│"); }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn require_session(ctx: &Ctx) -> Result<&str> {
    ctx.session_id.as_deref()
        .ok_or_else(|| anyhow::anyhow!("--session / SOLARPLEX_SESSION_ID required for this command"))
}

fn yesno(b: bool) -> String {
    if b { green("yes") } else { dim("no") }
}
