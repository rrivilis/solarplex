//! `sp why` — causal explanation of session state from the cursor position.
//!
//! Read-only backward traversal of the event log.  Never mutates state.
//! The cursor pins the observation frame: the explanation covers events 0..cursor.seq,
//! the same window `sp watch` has already observed. See `WhyArgs`' own doc
//! comment below (surfaced by `sp why --help`) for the full syntax and
//! examples — clap only reads doc comments attached to the args struct
//! itself, not this module-level one, so the syntax reference has to live
//! there to actually reach `--help`.

use anyhow::{anyhow, Result};
use clap::Args;
use serde_json::Value;

use super::session::resolve_session_id;
use crate::{
    client::Client,
    config::{self, Ctx, SavedCursor},
    output::*,
};

// The long usage doc lives on `Commands::Why` in main.rs, not here — see
// ask.rs's identical note for why.
#[derive(Args)]
pub struct WhyArgs {
    /// Entity to explain: policy | bundle/<id> | approval/<id> | saga/<id>
    /// Omit for a session-level causal summary.
    pub subject: Option<String>,

    /// Fetch up to this many events from the log.
    #[arg(long, default_value = "500")]
    pub limit: i64,
}

pub async fn run(args: WhyArgs, ctx: &Ctx) -> Result<()> {
    let client = Client::new(ctx)?;

    // Session comes from the global --session flag or attached config.
    // Use `sp --session <id> why` to target a specific session.
    let raw = ctx.session_id.as_deref().ok_or_else(|| {
        anyhow!("no session — pass `sp --session <id> why` or run `sp session attach <id>` first")
    })?;
    let token = raw.strip_prefix("session/").unwrap_or(raw);
    let session_id = resolve_session_id(&client, token).await?;

    let cursor = config::load_cursor(&session_id);

    // Fetch events from seq=0 up to cursor.seq (or all if no cursor saved).
    let events_val = client.list_events_after(&session_id, 0, args.limit).await?;
    let all_events: Vec<&Value> = events_val
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|e| {
                    // If cursor is at zero, we have no saved position — show everything.
                    cursor.seq == 0 || e["seq"].as_i64().map(|s| s <= cursor.seq).unwrap_or(true)
                })
                .collect()
        })
        .unwrap_or_default();

    let session_val = client.get_session(&session_id).await.ok();
    let name = session_val
        .as_ref()
        .and_then(|s| s["name"].as_str())
        .unwrap_or(&session_id[..session_id.len().min(8)]);

    let subject = args.subject.as_deref().unwrap_or("");

    if subject.is_empty() {
        why_session(name, &session_id, &all_events, &cursor);
    } else if subject == "policy" {
        why_policy(name, &session_id, &all_events, &cursor);
    } else if let Some(bid) = subject.strip_prefix("bundle/") {
        why_bundle(bid, name, &session_id, &all_events, &cursor);
    } else if let Some(aid) = subject.strip_prefix("approval/") {
        why_approval(aid, name, &session_id, &all_events, &cursor);
    } else if let Some(sid) = subject.strip_prefix("saga/") {
        why_saga(sid, name, &session_id, &all_events, &cursor);
    } else {
        anyhow::bail!(
            "unknown subject {:?} — try: policy, bundle/<id>, approval/<id>, saga/<id>",
            subject
        );
    }

    Ok(())
}

// ── Formatters ────────────────────────────────────────────────────────────────

fn print_header(subject: &str, session_name: &str, session_id: &str, cursor: &SavedCursor) {
    let slink = entity_link("session", session_id, session_id, "");
    println!(
        "{} {}  {}  {}",
        bold("why"),
        bold(subject),
        dim(&format!("({slink} · {session_name})")),
        dim(&format!("cursor seq:{} epoch:{}", cursor.seq, cursor.epoch)),
    );
    println!();
}

fn print_why_row(e: &Value) {
    let seq = e["seq"].as_i64().unwrap_or(0);
    let actor = sanitize_terminal(e["actor_id"].as_str().unwrap_or("system"));
    let etype = e["type"].as_str().unwrap_or("?");
    let short = etype.rsplit('.').next().unwrap_or(etype);
    let inner = &e["payload"]["payload"];
    let outer = &e["payload"];

    let detail = row_detail(etype, inner, outer);
    let detail_col = if detail.is_empty() {
        String::new()
    } else {
        format!("  {}", dim(&sanitize_terminal(&detail)))
    };

    println!(
        "  {}  {}  {}{}",
        dim(&format!("seq:{seq:>5}")),
        dim(&actor_link(&actor)),
        cyan(short),
        detail_col,
    );
}

fn row_detail(etype: &str, inner: &Value, outer: &Value) -> String {
    let t = etype.to_lowercase();
    if t.contains("bundle") {
        let bid = inner["bundle_id"]
            .as_str()
            .or_else(|| outer["bundle_id"].as_str())
            .unwrap_or("?");
        let short = &bid[..bid.len().min(10)];
        if t.contains("reject") {
            let reason = inner["reason"].as_str().unwrap_or("?");
            return format!("bundle:{short}  reason:{reason}");
        }
        if t.contains("gated") {
            let apid = inner["approval_id"].as_str().unwrap_or("?");
            return format!("bundle:{short}  gate:{}", &apid[..apid.len().min(10)]);
        }
        if t.contains("defer") {
            let until = inner["until_ms"].as_u64().unwrap_or(0);
            return format!("bundle:{short}  until:{until}ms");
        }
        return format!("bundle:{short}");
    }
    if t.contains("policy") {
        let target = inner["target"].as_str().unwrap_or("?");
        let action = inner["constraint"]
            .as_str()
            .or_else(|| inner["constraint"]["action"].as_str())
            .unwrap_or("?");
        return format!("{target} → {action}");
    }
    if t.contains("approval") {
        let tool = inner["tool_name"].as_str().unwrap_or("");
        let aid = inner["approval_id"]
            .as_str()
            .or_else(|| outer["approval_id"].as_str())
            .unwrap_or("?");
        let short = &aid[..aid.len().min(10)];
        return if tool.is_empty() {
            format!("{short}")
        } else {
            format!("{short}  tool:{tool}")
        };
    }
    if t.contains("saga") {
        let sid = inner["saga_id"].as_str().unwrap_or("?");
        let step = inner["step_idx"]
            .as_u64()
            .map(|s| format!("  step:{s}"))
            .unwrap_or_default();
        return format!("{}{step}", &sid[..sid.len().min(16)]);
    }
    if t.contains("message") {
        let c = inner["content"].as_str().unwrap_or("").trim().to_string();
        return if c.len() > 50 {
            format!("{}…", &c[..50])
        } else {
            c
        };
    }
    String::new()
}

// ── Subject handlers ──────────────────────────────────────────────────────────

fn why_session(name: &str, session_id: &str, events: &[&Value], cursor: &SavedCursor) {
    print_header(name, name, session_id, cursor);

    // Events that shape the observable session state.
    let key_type_fragments: &[&str] = &[
        "session.created",
        "session.renamed",
        "actor.joined",
        "actor.detached",
        "policy",
        "policyset",
        "saga.begun",
        "sagabegun",
        "bundle.intercepted",
        "bundleintercepted",
        "bundle.approvalgated",
        "bundleapprovalgated",
        "bundle.deferred",
        "bundledeferred",
        "bundle.rejected",
        "bundlerejected",
        "bundle.delivered",
        "bundledelivered",
        "approval.granted",
        "approvalgranted",
        "approval.denied",
        "approvaldenied",
        "cap.delegated",
        "cap.revoked",
        "epoch.advanced",
    ];

    let key_events: Vec<&Value> = events
        .iter()
        .copied()
        .filter(|e| {
            let t = e["type"].as_str().unwrap_or("").to_lowercase();
            key_type_fragments.iter().any(|f| t.contains(f))
        })
        .take(25)
        .collect();

    if key_events.is_empty() {
        println!("  {}", dim("no key events in this window yet"));
        return;
    }

    println!("  {}:", dim("key events"));
    for e in &key_events {
        print_why_row(e);
    }
    println!();

    // Rough pending-state summary.
    let mut pending_approvals: usize = 0;
    let mut gated_bundles: usize = 0;
    for e in events {
        let t = e["type"].as_str().unwrap_or("").to_lowercase();
        if t.contains("approval.requested") || t.contains("approvalrequested") {
            pending_approvals += 1;
        }
        if t.contains("approval.granted")
            || t.contains("approvalgranted")
            || t.contains("approval.denied")
            || t.contains("approvaldenied")
            || t.contains("approval.expired")
            || t.contains("approvalexpired")
        {
            pending_approvals = pending_approvals.saturating_sub(1);
        }
        if t.contains("bundle.approvalgated")
            || t.contains("bundleapprovalgated")
            || t.contains("bundle.deferred")
            || t.contains("bundledeferred")
        {
            gated_bundles += 1;
        }
        if t.contains("bundle.delivered")
            || t.contains("bundledelivered")
            || t.contains("bundle.rejected")
            || t.contains("bundlerejected")
        {
            gated_bundles = gated_bundles.saturating_sub(1);
        }
    }

    if pending_approvals > 0 {
        println!(
            "  {} {pending_approvals} approval(s) pending  {}",
            yellow("⚑"),
            dim("(sp ask session pending-approvals)")
        );
    }
    if gated_bundles > 0 {
        println!("  {} {gated_bundles} bundle(s) gated", yellow("⏳"));
    }
    if pending_approvals == 0 && gated_bundles == 0 {
        println!("  {} no pending approvals or gated bundles", green("✓"));
    }
}

fn why_policy(name: &str, session_id: &str, events: &[&Value], cursor: &SavedCursor) {
    print_header("policy", name, session_id, cursor);

    let policy_events: Vec<&Value> = events
        .iter()
        .copied()
        .filter(|e| {
            let t = e["type"].as_str().unwrap_or("").to_lowercase();
            t.contains("policy") || t.contains("policyset")
        })
        .collect();

    if policy_events.is_empty() {
        println!(
            "  {} no PolicySet events found — session using defaults",
            dim("·")
        );
        return;
    }

    println!("  {} policy history  (most recent is current):", dim("→"));
    let n = policy_events.len();
    for (i, e) in policy_events.iter().enumerate() {
        let is_last = i == n - 1;
        let seq = e["seq"].as_i64().unwrap_or(0);
        let actor = sanitize_terminal(e["actor_id"].as_str().unwrap_or("system"));
        let inner = &e["payload"]["payload"];
        let target = sanitize_terminal(inner["target"].as_str().unwrap_or("?"));
        let action = sanitize_terminal(
            inner["constraint"]
                .as_str()
                .or_else(|| inner["constraint"]["action"].as_str())
                .unwrap_or("?"),
        );
        let tag = if is_last {
            cyan("← current")
        } else {
            dim("superseded")
        };
        println!(
            "  {}  {}  {} → {}  {}",
            dim(&format!("seq:{seq:>5}")),
            dim(&actor_link(&actor)),
            cyan(&target),
            yellow(&action),
            tag,
        );
    }
}

fn why_bundle(
    bundle_id: &str,
    name: &str,
    session_id: &str,
    events: &[&Value],
    cursor: &SavedCursor,
) {
    let short = &bundle_id[..bundle_id.len().min(12)];
    print_header(&format!("bundle/{short}…"), name, session_id, cursor);

    let relevant: Vec<&Value> = events
        .iter()
        .copied()
        .filter(|e| {
            let t = e["type"].as_str().unwrap_or("").to_lowercase();
            if !t.contains("bundle") {
                return false;
            }
            // Match bundle_id anywhere in the payload hierarchy.
            let id_at = |v: &Value| v["bundle_id"].as_str() == Some(bundle_id);
            id_at(&e["payload"]["payload"]) || id_at(&e["payload"]) || id_at(e)
        })
        .collect();

    if relevant.is_empty() {
        println!("  {} no events found for bundle/{bundle_id}", dim("·"));
        println!(
            "  {} the bundle may be outside the cursor window  {}",
            dim("hint:"),
            dim("(sp watch --from 0)"),
        );
        return;
    }

    for e in &relevant {
        print_why_row(e);
    }
    println!();

    // Infer current status from the last bundle event.
    if let Some(last) = relevant.last() {
        let t = last["type"].as_str().unwrap_or("").to_lowercase();
        let inner = &last["payload"]["payload"];
        if t.contains("delivered") {
            println!("  {} delivered", green("✓"));
        } else if t.contains("deferred") {
            let until = inner["until_ms"].as_u64().unwrap_or(0);
            println!("  {} deferred until {until}ms", yellow("⏳"));
        } else if t.contains("rejected") {
            let reason = sanitize_terminal(inner["reason"].as_str().unwrap_or("?"));
            println!("  {} rejected: {reason}", red("✗"));
        } else if t.contains("gated") {
            let apid = inner["approval_id"].as_str().unwrap_or("?");
            println!(
                "  {} gated — waiting for approval  {}",
                yellow("⚑"),
                dim(&format!("(sp act approval/{apid} Grant)")),
            );
        } else if t.contains("intercepted") {
            println!("  {} intercepted (disposition pending)", yellow("⋯"));
        }
    }
}

fn why_approval(
    approval_id: &str,
    name: &str,
    session_id: &str,
    events: &[&Value],
    cursor: &SavedCursor,
) {
    let short = &approval_id[..approval_id.len().min(12)];
    print_header(&format!("approval/{short}…"), name, session_id, cursor);

    let relevant: Vec<&Value> = events
        .iter()
        .copied()
        .filter(|e| {
            let id_at = |v: &Value| v["approval_id"].as_str() == Some(approval_id);
            id_at(&e["payload"]["payload"]) || id_at(&e["payload"]) || id_at(e)
        })
        .collect();

    if relevant.is_empty() {
        println!("  {} no events found for approval/{approval_id}", dim("·"));
        return;
    }

    for e in &relevant {
        print_why_row(e);
    }
    println!();

    if let Some(last) = relevant.last() {
        let t = last["type"].as_str().unwrap_or("").to_lowercase();
        let actor = sanitize_terminal(last["actor_id"].as_str().unwrap_or("?"));
        if t.contains("granted") {
            println!("  {} granted by {}", green("✓"), bold(&actor));
        } else if t.contains("denied") {
            println!("  {} denied by {}", red("✗"), bold(&actor));
        } else if t.contains("expired") {
            println!("  {} expired", dim("○"));
        } else {
            println!("  {} pending", yellow("⋯"));
            println!(
                "  hint: {}",
                dim(&format!("sp act approval/{approval_id} Grant"))
            );
        }
    }
}

fn why_saga(saga_id: &str, name: &str, session_id: &str, events: &[&Value], cursor: &SavedCursor) {
    let short = &saga_id[..saga_id.len().min(16)];
    print_header(&format!("saga/{short}…"), name, session_id, cursor);

    let relevant: Vec<&Value> = events
        .iter()
        .copied()
        .filter(|e| {
            let id_at = |v: &Value| v["saga_id"].as_str() == Some(saga_id);
            id_at(&e["payload"]["payload"]) || id_at(&e["payload"]) || id_at(e)
        })
        .collect();

    if relevant.is_empty() {
        println!("  {} no events found for saga/{saga_id}", dim("·"));
        return;
    }

    for e in &relevant {
        print_why_row(e);
    }
    println!();

    if let Some(last) = relevant.last() {
        let t = last["type"].as_str().unwrap_or("").to_lowercase();
        if t.contains("completed") || t.contains("sagacompleted") {
            println!("  {} completed", green("✓"));
        } else if t.contains("aborted") || t.contains("sagaaborted") {
            println!("  {} aborted", red("✗"));
        } else if t.contains("waiting") || t.contains("sagastepsent") {
            let inner = &last["payload"]["payload"];
            let step = inner["step_idx"].as_u64().unwrap_or(0);
            println!("  {} waiting on step {step}", yellow("⏳"));
        } else {
            println!("  {} in progress", yellow("⋯"));
        }
    }
}
