//! `sp mailbox` — the authenticated actor's personal inbox.
//!
//! `db::mailbox`'s own doc comment: "invite" is the only kind ever routed
//! today. Read-only browsing + mark-seen live here; actually acting on an
//! entry (redeeming an invite) goes through `sp invite`, matching the
//! ask/act split everywhere else in this CLI.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct MailboxArgs {
    #[command(subcommand)]
    pub cmd: MailboxCmd,
}

#[derive(Subcommand)]
pub enum MailboxCmd {
    /// List your mailbox — mostly session invites addressed to you.
    Ls,
    /// Mark an entry seen (dismiss it). Takes the mailbox entry id shown in
    /// `sp mailbox ls`, not the invite id.
    Seen { id: String },
}

pub async fn run(args: MailboxArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        MailboxCmd::Ls => ls(&client, ctx).await,
        MailboxCmd::Seen { id } => seen(&client, &id).await,
    }
}

async fn ls(client: &Client, ctx: &Ctx) -> Result<()> {
    let entries = client.list_mailbox().await?;
    let arr = entries.as_array().cloned().unwrap_or_default();

    if arr.is_empty() {
        println!("{}", dim("Mailbox empty."));
        return Ok(());
    }

    for e in &arr {
        let route_id = e["id"].as_str().unwrap_or("?");
        let kind = e["kind"].as_str().unwrap_or("?");
        let seen = e["seen_at"].is_string();
        let dot = if seen { " ".to_string() } else { yellow("●") };

        match kind {
            "invite" => {
                let inv = &e["invite"];
                let invite_id = inv["id"].as_str().unwrap_or("?");
                let session_name = sanitize_terminal(inv["session_name"].as_str().unwrap_or("?"));
                let role = sanitize_terminal(inv["role"].as_str().unwrap_or("?"));
                let inviter = sanitize_terminal(inv["invited_by_name"].as_str().unwrap_or("?"));
                let redeemed = inv["redeemed_at"].is_string();
                let revoked = inv["revoked_at"].is_string();
                let status = if revoked {
                    red("revoked")
                } else if redeemed {
                    dim("redeemed")
                } else {
                    green("pending")
                };
                let ilink = entity_link("invite", invite_id, "", &ctx.ui);
                println!(
                    "{} {}  invited to {} as {}  by {}  {}",
                    dot,
                    pad(&ilink, 14),
                    bold(&session_name),
                    role,
                    inviter,
                    status
                );
            }
            // Route pointed at something that no longer resolves (e.g. a
            // hard-deleted invite) — the server surfaces it rather than
            // silently dropping it, so this mirrors that instead of hiding it.
            _ => println!(
                "{} {}  {}",
                dot,
                pad(&short_id(route_id), 14),
                dim("(entry no longer resolves)")
            ),
        }
    }
    println!();
    println!(
        "  {}  sp invite show/redeem <invite-id>  ·  sp mailbox seen <entry-id>",
        dim("→")
    );
    Ok(())
}

async fn seen(client: &Client, id: &str) -> Result<()> {
    client.mailbox_mark_seen(id).await?;
    println!("{} marked seen", green("✓"));
    Ok(())
}
