use anyhow::Result;
use clap::{Args, Subcommand};
use serde_json::Value;

use crate::{client::Client, config::Ctx, output::*};

#[derive(Args)]
pub struct ContextArgs {
    #[command(subcommand)]
    pub cmd: ContextCmd,
}

#[derive(Subcommand)]
pub enum ContextCmd {
    /// List context entries for the current session
    Ls {
        /// Session ID (defaults to current session)
        id: Option<String>,
    },
    /// Show a single context entry by its event ID
    Show {
        /// Event ID of the context entry (e.g. 01J...)
        entry_id: String,
        /// Session ID (defaults to current session)
        session_id: Option<String>,
    },
    /// Add a context entry to the current session.
    /// Kind is positional (fact | hypothesis | decision | question | constraint).
    /// Content words are joined — no quoting needed.
    ///
    /// Examples:
    ///   sp context add decided to use postgres for the queue
    ///   sp context add hypothesis the latency spike is from N+1 queries
    Add {
        /// fact | hypothesis | decision | question | constraint
        #[arg(default_value = "fact")]
        kind: String,
        /// Entry text (all remaining words joined)
        #[arg(trailing_var_arg = true, required = false)]
        words: Vec<String>,
    },
}

pub async fn run(args: ContextArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;
    match args.cmd {
        ContextCmd::Ls { id } => ls(&client, ctx, id.as_deref()).await,
        ContextCmd::Show {
            entry_id,
            session_id,
        } => show(&client, ctx, &entry_id, session_id.as_deref()).await,
        ContextCmd::Add { kind, words } => {
            // If the first word isn't a valid kind, treat the whole thing as content
            // with kind defaulting to "fact".
            let valid_kinds = ["fact", "hypothesis", "decision", "question", "constraint"];
            let (resolved_kind, content) = if valid_kinds.contains(&kind.as_str()) {
                (kind, words.join(" "))
            } else {
                let mut all = vec![kind];
                all.extend(words);
                ("fact".to_string(), all.join(" "))
            };
            if content.is_empty() {
                anyhow::bail!("content is required: sp context add [kind] <text...>");
            }
            add(&client, ctx, &resolved_kind, &content).await
        }
    }
}

/// Fetch all context.entry.added events for a session (up to 200).
async fn fetch_context_entries(client: &Client, session_id: &str) -> Vec<Value> {
    client
        .list_events(session_id, 200)
        .await
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter(|e| {
            e["type"]
                .as_str()
                .map_or(false, |t| t.contains("context.entry.added"))
        })
        .collect()
}

pub async fn ls(client: &Client, ctx: &Ctx, id: Option<&str>) -> Result<()> {
    let session_id = id
        .or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session. Pass <id> or attach first."))?;

    let entries = fetch_context_entries(client, session_id).await;

    if entries.is_empty() {
        println!("{}", dim("No context entries yet."));
        println!("  Add one: {}", cyan("sp context add <text>"));
        return Ok(());
    }

    println!(
        "  {}  {}  {}  {}",
        bold(&pad("ENTRY", 10)),
        bold(&pad("KIND", 12)),
        bold(&pad("ACTOR", 16)),
        bold("CONTENT"),
    );
    // SANITIZATION AUDIT — ls():
    // event_id is a ULID (safe). kind, actor, content are FOREIGN (actor-supplied).
    for e in &entries {
        let event_id = e["id"].as_str().unwrap_or("?"); // ULID — safe
        let actor = sanitize_terminal(e["actor_id"].as_str().unwrap_or("?")); // FOREIGN
        let inner = &e["payload"]["payload"];
        let kind = sanitize_terminal(inner["kind"].as_str().unwrap_or("fact")); // FOREIGN
        let content = sanitize_terminal(inner["content"].as_str().unwrap_or("")); // FOREIGN
        let link = entity_link("context", event_id, session_id, &ctx.ui);
        let preview = if content.len() > 60 {
            &content[..60]
        } else {
            &content[..]
        };
        println!(
            "  {}  {}  {}  {}",
            pad(&link, 10),
            pad(&kind, 12),
            pad(&actor, 16),
            dim(preview),
        );
    }
    Ok(())
}

async fn show(client: &Client, ctx: &Ctx, entry_id: &str, session: Option<&str>) -> Result<()> {
    let session_id = session
        .or(ctx.session_id.as_deref())
        .ok_or_else(|| anyhow::anyhow!("No session. Pass --session <id> or attach first."))?;

    let entries = fetch_context_entries(client, session_id).await;

    // Match by prefix or full ID
    let entry = entries.iter().find(|e| {
        e["id"]
            .as_str()
            .map(|id| id == entry_id || id.starts_with(entry_id))
            .unwrap_or(false)
    });

    match entry {
        None => {
            println!("{} context entry {} not found", red("✗"), entry_id);
        }
        Some(e) => {
            // SANITIZATION AUDIT — show():
            // event_id ULID safe. kind, actor, content are FOREIGN (actor-supplied).
            // content is printed verbatim (potentially multi-line) — highest risk here.
            let event_id = e["id"].as_str().unwrap_or("?"); // ULID — safe
            let actor = sanitize_terminal(e["actor_id"].as_str().unwrap_or("?")); // FOREIGN
            let inner = &e["payload"]["payload"];
            let kind = sanitize_terminal(inner["kind"].as_str().unwrap_or("fact")); // FOREIGN
            let content = sanitize_terminal(inner["content"].as_str().unwrap_or("")); // FOREIGN

            let icon = match kind.as_str() {
                "hypothesis" => "💡",
                "decision" => "✅",
                "question" => "❓",
                "constraint" => "🔒",
                _ => "📌",
            };

            println!();
            println!(
                "  {icon} {} {}",
                bold(&kind),
                entity_link("context", event_id, session_id, &ctx.ui)
            );
            println!("  by: {}", actor_link(&actor));
            println!();
            println!("{content}");
            println!();
        }
    }
    Ok(())
}

pub async fn add(client: &Client, ctx: &Ctx, kind: &str, content: &str) -> Result<()> {
    let session_id = ctx.require_session()?;
    let actor_id = ctx.require_actor()?;

    client
        .add_context(session_id, actor_id, kind, content)
        .await?;

    let icon = match kind {
        "hypothesis" => "💡",
        "decision" => "✅",
        "question" => "❓",
        "constraint" => "🔒",
        _ => "📌",
    };
    println!(
        "{icon} {} {} added to {}",
        bold(kind),
        dim(&format!("\"{}\"", truncate(content, 60))),
        entity_link("session", session_id, session_id, &ctx.ui),
    );
    Ok(())
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}
