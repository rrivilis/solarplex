use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::{client::Client, config::Ctx, output::*};
use super::session;

#[derive(Args)]
pub struct ApprovalArgs {
    #[command(subcommand)]
    pub cmd: ApprovalCmd,
}

#[derive(Subcommand)]
pub enum ApprovalCmd {
    /// List pending approvals in the current session
    Ls,
    /// Block until an approval is resolved (or timeout)
    Wait {
        /// Approval ID to wait on (defaults to oldest pending)
        id: Option<String>,
        /// Seconds before giving up (max 60)
        #[arg(long, default_value = "55")]
        timeout: u64,
        /// Loop until resolved (re-polls after timeout)
        #[arg(long)]
        follow: bool,
    },
    /// Grant (approve) a pending approval
    Grant {
        /// Approval ID
        id: String,
    },
    /// Deny a pending approval
    Deny {
        /// Approval ID
        id: String,
    },
    /// Delegate an approval to another (linked) session — that session
    /// decides on your behalf, via its own approval_policy unchanged.
    Delegate {
        /// Approval ID
        id: String,
        /// Session to delegate to (ULID, prefix, or name) — must already be
        /// linked to the approval's own session (link via the frontend's
        /// Session Sync panel, or the direct-link REST route)
        #[arg(long = "to-session")]
        to_session: String,
    },
    /// Internal: create an approval request and block until resolved.
    /// Used by the fish shell adapter for command-gating.
    #[command(name = "gate", hide = true)]
    Gate {
        /// Command string to request approval for
        command: String,
        #[arg(long, default_value = "120")]
        timeout: u64,
    },
}

pub async fn run(args: ApprovalArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        ApprovalCmd::Ls          => ls(&client, ctx).await,
        ApprovalCmd::Wait { id, timeout, follow } => wait(&client, ctx, id.as_deref(), timeout, follow).await,
        ApprovalCmd::Grant { id } => vote(&client, ctx, &id, "grant").await,
        ApprovalCmd::Deny  { id } => vote(&client, ctx, &id, "deny").await,
        ApprovalCmd::Delegate { id, to_session } => delegate(&client, ctx, &id, &to_session).await,
        ApprovalCmd::Gate  { command, timeout } => gate(&client, ctx, &command, timeout).await,
    }
}

pub async fn ls(client: &Client, ctx: &Ctx) -> Result<()> {
    let session_id = ctx.require_session()?;
    let rows = client.list_approvals(session_id).await?;
    let arr  = rows.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("No pending approvals."));
        return Ok(());
    }

    println!(
        "  {}  {}  {}",
        bold(&pad("APPROVAL", 10)),
        bold(&pad("TOOL", 36)),
        bold("REQUESTED BY"),
    );
    for a in &arr {
        print_approval_row(a, ctx);
    }
    Ok(())
}

fn print_approval_row(a: &Value, ctx: &Ctx) {
    let id    = a["id"].as_str().unwrap_or("?");
    let tool  = a["tool_name"].as_str().unwrap_or("?");
    let actor = a["actor_id"].as_str().unwrap_or("?");
    let sid   = a["session_id"].as_str().unwrap_or(ctx.session_id.as_deref().unwrap_or("?"));
    let link  = entity_link("approval", id, sid, &ctx.ui);
    println!("  {}  {}  {}", pad(&link, 10), pad(tool, 36), actor_link(actor));
}

async fn wait(client: &Client, ctx: &Ctx, id: Option<&str>, timeout: u64, follow: bool) -> Result<()> {
    let session_id = ctx.require_session()?;

    // Resolve the approval ID: explicit, or oldest pending
    let approval_id = if let Some(id) = id {
        id.to_string()
    } else {
        let rows = client.list_approvals(session_id).await?;
        let arr  = rows.as_array().cloned().unwrap_or_default();
        arr.first()
            .and_then(|a| a["id"].as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("No pending approvals in session."))?
    };

    // Print the pending approval details
    println!("{} Waiting for approval {}", yellow("⏳"), entity_link("approval", &approval_id, session_id, &ctx.ui));
    let _ = print_approval_detail(client, ctx, &approval_id).await;
    println!();

    let hint_grant = cyan(&format!("sp approval grant {approval_id}"));
    let hint_deny  = cyan(&format!("sp approval deny  {approval_id}"));
    println!("  grant:  {hint_grant}");
    println!("  deny:   {hint_deny}");
    println!();

    loop {
        print!("  {} ", dim("polling..."));
        let decision = client.poll_resolution(&approval_id, timeout.min(60)).await?;
        println!();
        match decision.as_str() {
            "granted" => {
                println!("{} Approved.", green("✓"));
                break;
            }
            "denied" => {
                println!("{} Denied.", red("✗"));
                break;
            }
            "timed_out" if follow => {
                println!("{} Still pending — re-polling...", yellow("⋯"));
                continue;
            }
            _ => {
                println!("{} Timed out.", yellow("⋯"));
                break;
            }
        }
    }
    Ok(())
}

async fn print_approval_detail(client: &Client, ctx: &Ctx, approval_id: &str) -> Result<()> {
    // Try to find the approval in the session list for display
    if let Ok(session_id) = ctx.require_session() {
        if let Ok(rows) = client.list_approvals(session_id).await {
            if let Some(a) = rows.as_array()
                .and_then(|arr| arr.iter().find(|a| a["id"].as_str() == Some(approval_id)))
            {
                let tool = a["tool_name"].as_str().unwrap_or("?");
                let args = serde_json::to_string_pretty(&a["arguments"]).unwrap_or_default();
                let actor = a["actor_id"].as_str().unwrap_or("?");
                println!("  tool:  {}", bold(tool));
                println!("  by:    {}", actor_link(actor));
                for line in args.lines() {
                    println!("  {}", dim(line));
                }
            }
        }
    }
    Ok(())
}

pub async fn vote(client: &Client, ctx: &Ctx, approval_id: &str, decision: &str) -> Result<()> {
    let actor_id = ctx.require_actor()?;
    client.vote(approval_id, actor_id, decision).await?;
    let icon = if decision == "grant" { green("✓") } else { red("✗") };
    let word = if decision == "grant" { "Granted" } else { "Denied" };
    println!("{} {} — {}", icon, word, entity_link("approval", approval_id, "", &ctx.ui));
    Ok(())
}

async fn delegate(client: &Client, ctx: &Ctx, approval_id: &str, to_session_ref: &str) -> Result<()> {
    let target_id = session::resolve_session_id(client, to_session_ref).await?;
    let data = client.delegate_approval(approval_id, &target_id).await?;
    let saga_id = data["saga_id"].as_str().unwrap_or("?");
    println!(
        "{} Delegated {} to {} ({})",
        green("✓"),
        entity_link("approval", approval_id, "", &ctx.ui),
        entity_link("session", &target_id, &target_id, &ctx.ui),
        dim(saga_id),
    );
    println!("{}", dim("Waiting on that session's own decision — this approval resolves automatically once they decide."));
    Ok(())
}

/// Internal gate: create an approval for a shell command and block on it.
async fn gate(client: &Client, ctx: &Ctx, command: &str, timeout: u64) -> Result<()> {
    let session_id = ctx.require_session()?;
    let actor_id   = ctx.require_actor()?;

    let resp = client.create_approval(
        session_id,
        actor_id,
        "shell_command",
        &serde_json::json!({ "command": command }),
        timeout,
    ).await?;

    let approval_id = resp["approval_id"].as_str().unwrap_or("").to_string();
    if approval_id.is_empty() {
        // Creation failed silently — let command through
        println!("granted");
        return Ok(());
    }

    // Block until resolved (re-poll up to the total timeout)
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now()).as_secs();
        if remaining == 0 {
            println!("timed_out");
            return Ok(());
        }
        let poll_secs = remaining.min(55);
        let decision = client.poll_resolution(&approval_id, poll_secs).await?;
        match decision.as_str() {
            "granted" => { println!("granted"); return Ok(()); }
            "denied"  => { println!("denied");  return Ok(()); }
            _         => continue, // timed_out from poll — keep looping until deadline
        }
    }
}
