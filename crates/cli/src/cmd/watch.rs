//! `sp watch` — cursor-oriented live event stream.
//!
//! Stateful read-only observation: reads and advances the per-session cursor
//! stored in `~/.config/solarplex/cursors/<session_id>.json`.
//!
//! Output is text lines (or `--json` for JSON lines) — pipe-friendly.
//! Ctrl-C saves the cursor and exits cleanly.
//!
//! # Examples
//!
//! ```text
//! sp watch                              # current attached session
//! sp watch session/payment-migration    # named session
//! sp watch --from 0                     # replay from the beginning
//! sp watch --json | jq .type            # machine-readable
//! sp watch --filter bundle              # only bundle-related events
//! ```

use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::Value;

use super::session::resolve_session_id;
use crate::{
    client::Client,
    config::{self, Ctx, SavedCursor},
    output::*,
};

#[derive(Args)]
pub struct WatchArgs {
    /// Session ref: `session/<id>` or session name.  Defaults to attached session.
    pub session: Option<String>,

    /// Start from this seq instead of the saved cursor (0 = beginning, replays all).
    #[arg(long)]
    pub from: Option<i64>,

    /// Print each event as a JSON line (pipeline-friendly, no ANSI).
    #[arg(long)]
    pub json: bool,

    /// Only show events whose type contains this substring (case-insensitive).
    #[arg(long)]
    pub filter: Option<String>,

    /// Poll interval in milliseconds.
    #[arg(long, default_value = "2000")]
    pub interval: u64,
}

pub async fn run(args: WatchArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;

    // Resolve session.
    let raw = args
        .session
        .as_deref()
        .or(ctx.session_id.as_deref())
        .ok_or_else(|| {
            anyhow!("no session — pass session/<id> or run `sp session attach <id>` first")
        })?;
    let token = raw.strip_prefix("session/").unwrap_or(raw);
    let session_id = resolve_session_id(&client, token).await?;

    // Determine starting cursor.
    let mut cursor = if let Some(seq) = args.from {
        SavedCursor { seq, epoch: 0 }
    } else {
        config::load_cursor(&session_id)
    };

    if !args.json {
        let name = client
            .get_session(&session_id)
            .await
            .ok()
            .and_then(|s| s["name"].as_str().map(str::to_string))
            .unwrap_or_else(|| session_id[..session_id.len().min(8)].to_string());
        eprintln!(
            "{} watching {}  {}  (Ctrl-C to stop)",
            green("◉"),
            bold(&sanitize_terminal(&name)),
            dim(&format!("cursor seq:{} epoch:{}", cursor.seq, cursor.epoch)),
        );
        eprintln!();
    }

    let interval = std::time::Duration::from_millis(args.interval);

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = tokio::time::sleep(interval) => {
                match client.list_events_after(&session_id, cursor.seq, 100).await {
                    Ok(events) => {
                        if let Some(arr) = events.as_array() {
                            for ev in arr {
                                let seq   = ev["seq"].as_i64().unwrap_or(cursor.seq + 1);
                                let etype = ev["type"].as_str().unwrap_or("?");

                                if let Some(ref f) = args.filter {
                                    if !etype.to_lowercase().contains(&f.to_lowercase()) {
                                        cursor.seq = cursor.seq.max(seq);
                                        continue;
                                    }
                                }

                                if args.json {
                                    println!("{}", serde_json::to_string(ev).unwrap_or_default());
                                } else {
                                    print_watch_event(ev, seq, etype);
                                }
                                cursor.seq = cursor.seq.max(seq);
                            }
                            if !arr.is_empty() {
                                let _ = config::save_cursor(&session_id, cursor);
                            }
                        }
                    }
                    Err(e) => {
                        if !args.json {
                            eprintln!("{} poll error: {e}", dim("·"));
                        }
                    }
                }
            }
        }
    }

    let _ = config::save_cursor(&session_id, cursor);
    if !args.json {
        eprintln!(
            "\n{} stopped  cursor seq:{} epoch:{}",
            dim("◎"),
            cursor.seq,
            cursor.epoch,
        );
    }
    Ok(())
}

// ── Display ───────────────────────────────────────────────────────────────────

fn print_watch_event(ev: &Value, seq: i64, etype: &str) {
    let actor = sanitize_terminal(ev["actor_id"].as_str().unwrap_or("system"));
    let inner = &ev["payload"]["payload"];
    let outer = &ev["payload"];
    // Use last dot-segment as the short name (e.g. "approval.requested" → "requested")
    let short = etype.rsplit('.').next().unwrap_or(etype);
    let summary = event_summary(etype, inner, outer);
    let summary_col = if summary.is_empty() {
        String::new()
    } else {
        format!("  {}", dim(&summary))
    };

    println!(
        "{}  {}  {}{}",
        dim(&format!("{seq:>6}")),
        dim(&actor_link(&actor)),
        cyan(short),
        summary_col,
    );
}

/// One-line summary for the watch column.  All strings through sanitize_terminal.
fn event_summary(etype: &str, inner: &Value, outer: &Value) -> String {
    let t = etype.to_lowercase();

    if t.contains("bundle") {
        let bid = inner["bundle_id"]
            .as_str()
            .or_else(|| outer["bundle_id"].as_str())
            .unwrap_or("?");
        let short = &bid[..bid.len().min(12)];
        if t.contains("defer") {
            let until = inner["until_ms"].as_u64().unwrap_or(0);
            return format!("bundle:{short}… defer until {until}ms");
        } else if t.contains("reject") {
            let reason = sanitize_terminal(inner["reason"].as_str().unwrap_or("?"));
            return format!("bundle:{short}… rejected: {reason}");
        } else if t.contains("gated") {
            let apid = inner["approval_id"].as_str().unwrap_or("?");
            let short_ap = &apid[..apid.len().min(10)];
            return format!("bundle:{short}… gated:{short_ap}");
        }
        return format!("bundle:{short}…");
    }

    if t.contains("policy") {
        let target = sanitize_terminal(inner["target"].as_str().unwrap_or("?"));
        let action = sanitize_terminal(
            inner["constraint"]
                .as_str()
                .or_else(|| inner["constraint"]["action"].as_str())
                .unwrap_or("?"),
        );
        return format!("{target} → {action}");
    }

    if t.contains("approval") {
        let tool = sanitize_terminal(inner["tool_name"].as_str().unwrap_or(""));
        let aid = inner["approval_id"]
            .as_str()
            .or_else(|| outer["approval_id"].as_str())
            .unwrap_or("?");
        let short_ap = &aid[..aid.len().min(10)];
        return if tool.is_empty() {
            format!("{short_ap}…")
        } else {
            format!("{short_ap}… {tool}")
        };
    }

    if t.contains("saga") {
        let sid = inner["saga_id"].as_str().unwrap_or("?");
        let step = inner["step_idx"]
            .as_u64()
            .map(|s| format!(" step:{s}"))
            .unwrap_or_default();
        return format!("{}{step}", &sid[..sid.len().min(16)]);
    }

    if t.contains("message") {
        let c = sanitize_terminal(inner["content"].as_str().unwrap_or(""));
        let v = c.trim().to_string();
        return if v.len() > 60 {
            format!("{}…", &v[..60])
        } else {
            v
        };
    }

    // Generic fallback: first non-empty scalar field.
    for field in &["name", "content", "command", "reason", "tool_name"] {
        if let Some(v) = inner[field].as_str() {
            let v = sanitize_terminal(v);
            let v = v.trim().to_string();
            if !v.is_empty() {
                return if v.len() > 60 {
                    format!("{}…", &v[..60])
                } else {
                    v
                };
            }
        }
    }
    String::new()
}
