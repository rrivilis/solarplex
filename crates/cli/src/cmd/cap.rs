use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct CapArgs {
    #[command(subcommand)]
    pub cmd: CapCmd,
}

#[derive(Subcommand)]
pub enum CapCmd {
    /// Inspect a capability token (bare-ref dispatch: cap/<id>)
    #[command(alias = "inspect")]
    Get { id: String },
    /// Delegate a capability token to an agent
    Delegate {
        /// Agent actor ID to delegate to
        #[arg(long)]
        to: String,
        /// Allowed tool names (comma-separated, empty = all)
        #[arg(long, value_delimiter = ',')]
        permissions: Vec<String>,
        /// Token lifetime in seconds (default 15 min)
        #[arg(long, default_value = "900")]
        ttl: u64,
        /// Filesystem path to expose via MCP server
        #[arg(long)]
        path: Option<String>,
        /// Parent cap this is delegated from
        #[arg(long)]
        parent: Option<String>,
        /// Role for the agent (agent | collaborator)
        #[arg(long, default_value = "agent")]
        role: String,
    },
    /// Revoke a capability token (and optionally its subtree or whole epoch).
    ///
    /// Revocation is immediate and permanent.  Connected agents whose caps are
    /// revoked receive the `cap.epoch.advanced` broadcast and are fenced after
    /// the drain window expires.
    ///
    /// Examples:
    ///   sp cap revoke 01JXXX...                          # revoke subtree
    ///   sp cap revoke 01JXXX... --strategy stratum --stratum 2
    ///   sp cap revoke 01JXXX... --strategy epoch          # close whole epoch
    ///   sp cap revoke 01JXXX... --reroot                  # reroot children first
    Revoke {
        /// Cap ID to revoke.  For strategy=stratum/epoch the session context
        /// determines which session's epoch is advanced; this cap's session is used.
        cap_id: String,
        /// Revocation strategy: `cap` (default) | `stratum` | `epoch`.
        ///   cap     — prune the subtree rooted at this cap
        ///   stratum — revoke all caps at delegation depth >= --stratum
        ///   epoch   — close the entire current generation of caps
        #[arg(long, default_value = "cap")]
        strategy: String,
        /// For --strategy stratum: revoke all caps at depth >= this value.
        #[arg(long)]
        stratum: Option<i64>,
        /// Grace window in seconds for in-flight agents (default 30).
        #[arg(long, default_value = "30")]
        drain: u64,
        /// When revoking a subtree (strategy=cap), first reroot surviving
        /// children to the revoked cap's parent before pruning.
        #[arg(long)]
        reroot: bool,
    },
}

pub async fn run(args: CapArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        CapCmd::Get { id } => {
            // Cap inspect — for now just print the ID and note it's in the session.
            let session_id = ctx.session_id.as_deref().unwrap_or("?");
            println!(
                "{}",
                crate::output::entity_link("cap", &id, session_id, &ctx.ui)
            );
            println!(
                "  {}",
                crate::output::dim("(cap detail endpoint not yet implemented)")
            );
            Ok(())
        }
        CapCmd::Delegate {
            to,
            permissions,
            ttl,
            path,
            parent,
            role,
        } => {
            delegate(
                &client,
                ctx,
                &to,
                &permissions,
                ttl,
                path.as_deref(),
                parent.as_deref(),
                &role,
            )
            .await
        }
        CapCmd::Revoke {
            cap_id,
            strategy,
            stratum,
            drain,
            reroot,
        } => revoke(&client, ctx, &cap_id, &strategy, stratum, drain, reroot).await,
    }
}

pub async fn delegate(
    client: &Client,
    ctx: &Ctx,
    to: &str,
    permissions: &[String],
    ttl: u64,
    mcp_path: Option<&str>,
    parent_cap: Option<&str>,
    role: &str,
) -> Result<()> {
    let session_id = ctx.require_session()?;

    let token = client
        .issue_cap(session_id, to, role, ttl, permissions, mcp_path, parent_cap)
        .await?;

    let token_id = token["token"].as_str().unwrap_or("?");
    let expires = token["expires_at"].as_str().unwrap_or("?");
    let launch = token["launch_cmd"].as_str().unwrap_or("");
    let perms = token["permissions"].as_array();

    println!("{} Cap delegated → {}", green("✓"), bold(to));
    println!(
        "  token:      {}",
        entity_link("cap", token_id, session_id, &ctx.ui)
    );
    println!("  expires_at: {}", dim(expires));
    println!("  ttl:        {ttl}s");

    if let Some(p) = perms {
        if p.is_empty() {
            println!("  permissions: {} (all tools)", dim("*"));
        } else {
            let names: Vec<&str> = p.iter().filter_map(|v| v.as_str()).collect();
            println!("  permissions: {}", names.join(", "));
        }
    }

    if !launch.is_empty() {
        println!();
        println!("{}", bold("Launch command:"));
        for line in launch.lines() {
            println!("  {}", cyan(line));
        }
    }

    Ok(())
}

pub async fn revoke(
    client: &Client,
    ctx: &Ctx,
    cap_id: &str,
    strategy: &str,
    stratum: Option<i64>,
    drain: u64,
    reroot: bool,
) -> Result<()> {
    let session_id = ctx.require_session()?;
    let actor_id = ctx.actor_id.as_deref().unwrap_or("?");
    let cap_id = cap_id.strip_prefix("cap/").unwrap_or(cap_id);

    // For stratum/epoch strategies the target_cap_id isn't sent, but we still
    // need the session_id — which comes from context, not from the cap arg.
    let target_cap_id = if strategy == "cap" {
        Some(cap_id)
    } else {
        None
    };

    let result = client
        .revoke_caps(
            session_id,
            actor_id,
            strategy,
            target_cap_id,
            stratum,
            drain,
            reroot,
        )
        .await?;

    let new_epoch = result["new_epoch"].as_i64().unwrap_or(0);
    let closed_epoch = result["closed_epoch"].as_i64().unwrap_or(0);
    let revoked_count = result["revoked_count"].as_u64().unwrap_or(0);
    let drain_deadline = result["drain_deadline"].as_str().unwrap_or("?");
    let drain_seq = result["drain_seq"].as_i64().unwrap_or(0);

    println!("{} Revocation complete", red("⊘"));
    println!();
    println!("  strategy       {}", cyan(strategy));
    if let Some(s) = stratum {
        println!("  stratum ≥      {s}");
    }
    println!("  closed epoch   {}", dim(&closed_epoch.to_string()));
    println!("  new epoch      {}", bold(&new_epoch.to_string()));
    println!("  revoked caps   {revoked_count}");
    println!("  drain seq      {drain_seq}  (caps observed ≤ this seq get grace window)");
    println!("  drain deadline {}", dim(drain_deadline));
    println!();
    println!(
        "{} Fenced agents will be closed with WS 4401 after drain window.",
        yellow("⚠")
    );

    Ok(())
}
