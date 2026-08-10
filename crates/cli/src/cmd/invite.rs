//! `sp invite` — session membership invites: preview, redeem, create, revoke.
//!
//! `show` never mutates and needs no auth (mirrors the web `/invite/[id]`
//! landing page — you can see what an invite is for before signing in);
//! `redeem`/`create`/`revoke` all do and all require `sp login` first.

use anyhow::Result;
use clap::{Args, Subcommand};

use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct InviteArgs {
    #[command(subcommand)]
    pub cmd: InviteCmd,
}

#[derive(Subcommand)]
pub enum InviteCmd {
    /// Preview an invite — session, role, inviter, status. Read-only, no
    /// sp_token required.
    Show { id: String },
    /// Redeem an invite as the currently signed-in identity (`sp login` first).
    Redeem { id: String },
    /// Create a session invite for the attached session (`--session`/
    /// SOLARPLEX_SESSION_ID). Role ceiling + owner-only cap staging are
    /// enforced server-side — this just sends the request.
    Create {
        /// owner | collaborator | observer
        #[arg(long, default_value = "collaborator")]
        role: String,
        /// Address the invite to a specific email (omit for an anonymous,
        /// redeemable-by-anyone link)
        #[arg(long)]
        email: Option<String>,
        /// Invite lifetime in seconds (default 7 days)
        #[arg(long, default_value = "604800")]
        ttl: i64,
    },
    /// Revoke an invite before it's redeemed.
    Revoke { id: String },
}

pub async fn run(args: InviteArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        InviteCmd::Show { id }   => show(&client, ctx, &id).await,
        InviteCmd::Redeem { id } => redeem(&client, ctx, &id).await,
        InviteCmd::Create { role, email, ttl } => {
            let session_id = ctx.require_session()?.to_string();
            create(&client, ctx, &session_id, &role, email.as_deref(), ttl).await
        }
        InviteCmd::Revoke { id } => revoke(&client, &id).await,
    }
}

async fn show(client: &Client, ctx: &Ctx, id: &str) -> Result<()> {
    let inv = client.preview_invite(id).await?;

    let session_id   = inv["session_id"].as_str().unwrap_or("?");
    let session_name = sanitize_terminal(inv["session_name"].as_str().unwrap_or("?"));
    let role         = sanitize_terminal(inv["role"].as_str().unwrap_or("?"));
    let expires_at   = inv["expires_at"].as_str().unwrap_or("?");
    let redeemed     = inv["redeemed_at"].is_string();
    let revoked      = inv["revoked_at"].is_string();
    let email        = inv["invitee_email"].as_str();

    println!("{} {}", bold("invite"), entity_link("invite", id, "", &ctx.ui));
    println!("{}", dim(&"─".repeat(42)));
    println!("  session:  {}  {}", bold(&session_name), entity_link("session", session_id, session_id, &ctx.ui));
    println!("  role:     {role}");
    match email {
        Some(e) => println!("  for:      {}", sanitize_terminal(e)),
        None    => println!("  for:      {}", dim("anyone with the link")),
    }
    let status = if revoked { red("revoked") } else if redeemed { dim("redeemed") } else { green("pending") };
    println!("  status:   {status}");
    println!("  expires:  {}", dim(expires_at));

    if !redeemed && !revoked {
        println!();
        println!("  {}  sp invite redeem {}", dim("→"), short_id(id));
    }
    Ok(())
}

async fn redeem(client: &Client, ctx: &Ctx, id: &str) -> Result<()> {
    let result = client.redeem_invite(id).await?;
    let session_id = result["session_id"].as_str().unwrap_or("?");
    println!("{} joined {}", green("✓"), entity_link("session", session_id, session_id, &ctx.ui));
    if let Some(cap) = result.get("cap").filter(|c| !c.is_null()) {
        let token = cap["token"].as_str().unwrap_or("?");
        println!("  {} cap issued: {}", dim("·"), dim(token));
    }
    println!();
    println!("  {}  sp session attach {}", dim("→"), session_id);
    Ok(())
}

async fn create(
    client:  &Client,
    ctx:     &Ctx,
    session_id: &str,
    role:    &str,
    email:   Option<&str>,
    ttl:     i64,
) -> Result<()> {
    let inv = client.create_invite(session_id, role, email, ttl).await?;
    let id  = inv["id"].as_str().unwrap_or("?");
    println!("{} Created invite {}", green("✓"), entity_link("invite", id, "", &ctx.ui));
    println!("  session: {}", entity_link("session", session_id, session_id, &ctx.ui));
    println!("  role:    {role}");
    if let Some(e) = email {
        println!("  for:     {}", sanitize_terminal(e));
    } else {
        println!("  for:     {}", dim("anyone with the link"));
    }
    println!();
    println!("  {}  sp invite redeem {}", dim("→"), short_id(id));
    Ok(())
}

async fn revoke(client: &Client, id: &str) -> Result<()> {
    client.revoke_invite(id).await?;
    println!("{} revoked", green("✓"));
    Ok(())
}
