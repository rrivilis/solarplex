use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct ActorArgs {
    #[command(subcommand)]
    pub cmd: ActorCmd,
}

#[derive(Subcommand)]
pub enum ActorCmd {
    /// Show an actor: their sessions, caps, and recent activity.
    Show {
        /// Actor ID (e.g. "alice", "agent-01J...")
        id: String,
    },
}

pub async fn run(args: ActorArgs, ctx: &Ctx) -> Result<()> {
    match args.cmd {
        ActorCmd::Show { id } => show(&id, ctx).await,
    }
}

pub async fn show(actor_id: &str, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;

    // Resolve the actor's real record first. Previously this printed
    // whatever string was typed as if it *were* the display name (and never
    // checked the actor actually exists) — `id` and the actor's mutable,
    // self-chosen display `name` (PATCH /auth/me) are different fields, and
    // for a human actor the id is never something they picked themselves.
    //
    // Deliberately propagated via `?`, not caught-and-replaced with a
    // synthesized "not found": `check_status` already produces a real,
    // specific message per status (auth failure vs. a genuine 404 vs.
    // anything else) — swallowing that into one guessed message here would
    // undo the exact fix `client.rs::check_status` just made everywhere else.
    let actor = client.get_actor(actor_id).await?;
    let real_id = actor["id"].as_str().unwrap_or(actor_id).to_string();
    let name = actor["name"].as_str().map(sanitize_terminal);

    match &name {
        Some(n) => println!("{}  {}", bold(n), dim(&actor_link(&real_id))),
        None => println!("{}", bold(&actor_link(&real_id))),
    }
    println!();

    // List all sessions and filter to those where this actor appears
    let sessions = client.list_sessions(None).await?;
    let arr = sessions.as_array().cloned().unwrap_or_default();

    // Filter sessions where created_by matches or (in future) event log has actor
    let owned: Vec<_> = arr
        .iter()
        .filter(|s| s["created_by"].as_str() == Some(real_id.as_str()))
        .collect();

    if owned.is_empty() {
        println!(
            "  {} no sessions owned by {}",
            dim("·"),
            dim(name.as_deref().unwrap_or(&real_id))
        );
    } else {
        println!("  {} {}", bold(&pad("SESSION", 10)), bold("TITLE"));
        for s in &owned {
            let id = s["id"].as_str().unwrap_or("?");
            let title = s["name"].as_str().unwrap_or("(untitled)");
            let link = entity_link("session", id, "", "");
            println!("  {}  {}", pad(&link, 10), title);
        }
    }

    // If currently attached to a session, show their caps and approvals there
    if let Some(session_id) = ctx.session_id.as_deref() {
        println!();
        println!(
            "  {} in current session ({})",
            dim("─"),
            dim(&short_id(session_id).to_string())
        );

        if let Ok(caps) = client.list_caps(session_id).await {
            let caps_arr = caps.as_array().cloned().unwrap_or_default();
            let actor_caps: Vec<_> = caps_arr
                .iter()
                .filter(|c| c["grantee"].as_str() == Some(real_id.as_str()))
                .collect();
            if !actor_caps.is_empty() {
                println!("  caps granted:");
                for c in actor_caps {
                    let cid = c["id"].as_str().unwrap_or("?");
                    let scope = c["scope"].as_str().unwrap_or("?");
                    let link = entity_link("cap", cid, session_id, "");
                    println!("    {}  scope={}", link, dim(scope));
                }
            }
        }
    }

    Ok(())
}
