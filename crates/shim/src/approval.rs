//! Approval gating and ORB flow — extracted from the sidecar's proxy.rs.
//!
//! `handle_proposal` is the shim's core function: it receives a tool call
//! proposal from the adapter, runs the appropriate approval flow, and returns
//! a `ProposalDecision`.  The adapter has no visibility into which path was
//! taken — it only sees "granted / denied / exec_result".
//!
//! For `solarplex_exec` approvals, the shim coordinates with the guardian:
//! sends a `GuardianRequest` after the human votes, waits for the result,
//! and embeds it in the `ProposalDecision` before returning to the adapter.

use std::sync::Arc;
use std::time::Duration;

use protocol::ipc::{self, ExecResultIpc, Tier2Ctx};
use protocol::messages::ApprovalDecision;
use protocol::types::{AgentStatus, ToolCall};

use crate::policy::Policy;
use crate::scout::{self, ScoutPool};
use crate::session::SessionClient;
use crate::{Config, GuardianHandle};

/// Handle one proposal from the adapter.
///
/// Blocks until the approval resolves (human votes, ORB auto-approves, or timeout).
/// For `solarplex_exec`: also blocks until the guardian finishes executing.
pub async fn handle_proposal(
    req:        ipc::ProposalRequest,
    config:     &Config,
    session:    &Arc<SessionClient>,
    scout_pool: &ScoutPool,
    guardian:   &GuardianHandle,
    policy:     &Policy,
) -> ipc::ProposalDecision {
    let tool = &req.tool;

    // Cap permission check.
    if !config.permissions.is_empty() && !config.permissions.contains(&tool.tool) {
        tracing::warn!(tool = %tool.tool, "shim: blocked by cap permissions");
        return deny(&req.id, "tool not permitted under this capability scope");
    }

    // ── ORB path (cap_id present) ─────────────────────────────────────────────
    if let Some(ref cap_id) = config.cap_id {
        return orb_path(req, config, session, scout_pool, guardian, cap_id).await;
    }

    // ── Legacy path (no cap_id) ───────────────────────────────────────────────
    if !policy.requires_approval(&config.actor_id, &tool.tool) {
        tracing::debug!(tool = %tool.tool, "shim: auto-approved (allow-list)");
        session.update_status(AgentStatus::Running).await;
        return ipc::ProposalDecision {
            id: req.id, granted: true,
            canonical_rpc: Some(req.raw_rpc),
            approval_id: None, scout: None, exec_result: None, tier2_ctx: None, error: None,
        };
    }

    session.update_status(AgentStatus::Waiting).await;
    tracing::info!(tool = %tool.tool, "shim: awaiting human approval (legacy)");

    let approval_id = match session.create_approval_req(tool).await {
        Some(id) => id,
        None => {
            session.update_status(AgentStatus::Idle).await;
            return deny(&req.id, "failed to create approval request");
        }
    };

    let scout_rx = scout::extract_command(&tool.args).and_then(|cmd| {
        scout_pool.try_dispatch(cmd, approval_id.clone(), session.clone(), None)
    });

    match session.poll_approval(&approval_id).await {
        ApprovalDecision::Granted => {
            session.update_status(AgentStatus::Running).await;
            let manifest = collect_scout(scout_rx).await;

            // solarplex_exec: the guardian fetches the command from the server.
            if tool.tool == "solarplex_exec" {
                let exec = run_via_guardian(guardian, &approval_id).await;
                session.update_status(AgentStatus::Idle).await;
                return ipc::ProposalDecision {
                    id: req.id, granted: true,
                    approval_id: Some(approval_id), scout: manifest,
                    exec_result: Some(exec), canonical_rpc: None, tier2_ctx: None, error: None,
                };
            }

            ipc::ProposalDecision {
                id: req.id, granted: true,
                approval_id: Some(approval_id), scout: manifest,
                canonical_rpc: Some(req.raw_rpc),
                exec_result: None, tier2_ctx: None, error: None,
            }
        }
        other => {
            tracing::warn!(tool = %tool.tool, ?other, "shim: proposal blocked");
            session.update_status(AgentStatus::Idle).await;
            deny(&req.id, "tool call denied by Solarplex supervisor")
        }
    }
}

// ── ORB path ──────────────────────────────────────────────────────────────────

async fn orb_path(
    req:        ipc::ProposalRequest,
    config:     &Config,
    session:    &Arc<SessionClient>,
    scout_pool: &ScoutPool,
    guardian:   &GuardianHandle,
    cap_id:     &str,
) -> ipc::ProposalDecision {
    let tool = &req.tool;
    let slug  = actor_id_to_slug(&config.actor_id);
    let addr  = format!("mcp.{slug}.{}", tool.tool);

    session.update_status(AgentStatus::Waiting).await;

    let invoke_resp = session.invoke_method(cap_id, &addr, &tool.args, 25).await;

    match invoke_resp {
        Some(resp) if resp.status == "approved" => {
            // Auto-approved — consume receipt to get canonical args.
            let (canonical_rpc, tier2_ctx) = consume_and_patch(
                &req.raw_rpc, resp.receipt_id.as_deref(), cap_id, tool, session,
            ).await;
            session.update_status(AgentStatus::Running).await;
            ipc::ProposalDecision {
                id: req.id, granted: true, approval_id: None,
                canonical_rpc: Some(canonical_rpc), tier2_ctx,
                scout: None, exec_result: None, error: None,
            }
        }

        Some(resp) if resp.status == "pending" => {
            let orb_approval_id = match resp.approval_id {
                Some(id) => id,
                None => {
                    session.update_status(AgentStatus::Idle).await;
                    return deny(&req.id, "ORB: pending but no approval_id");
                }
            };

            // Row B — the one a human actually sees and votes on via the
            // normal session approval UI/CLI (session.poll_approval below
            // waits on *this* id, not orb_approval_id). It used to carry a
            // placeholder `{"_approval_id": orb_approval_id}` instead of the
            // real tool arguments — nothing anywhere in this codebase ever
            // reads that key back out, so a human voting on this approval
            // could see the real tool *name* but not what it was actually
            // going to be called with. Row A (orb_approval_id, created
            // server-side in routes/invoke.rs with the real args) still
            // exists and still binds the execution_receipts args that are
            // what actually executes — this only fixes what the human sees.
            tracing::debug!(
                tool = %tool.tool, %orb_approval_id,
                "shim: ORB dual approval row — creating human-facing row B for server-side row A",
            );
            let synthetic = ToolCall {
                tool: tool.tool.clone(),
                args: tool.args.clone(),
            };
            let sidecar_aid = match session.create_approval_req(&synthetic).await {
                Some(id) => id,
                None => {
                    session.update_status(AgentStatus::Idle).await;
                    return deny(&req.id, "ORB: failed to create sidecar approval");
                }
            };

            let scout_rx = scout::extract_command(&tool.args).and_then(|cmd| {
                scout_pool.try_dispatch(cmd, sidecar_aid.clone(), session.clone(), None)
            });

            match session.poll_approval(&sidecar_aid).await {
                ApprovalDecision::Granted => {
                    let manifest = collect_scout(scout_rx).await;
                    let (canonical_rpc, tier2_ctx) = consume_and_patch(
                        &req.raw_rpc, resp.receipt_id.as_deref(), cap_id, tool, session,
                    ).await;
                    session.update_status(AgentStatus::Running).await;

                    // solarplex_exec via guardian.
                    if tool.tool == "solarplex_exec" {
                        let exec = run_via_guardian(guardian, &sidecar_aid).await;
                        session.update_status(AgentStatus::Idle).await;
                        return ipc::ProposalDecision {
                            id: req.id, granted: true,
                            approval_id: Some(sidecar_aid), scout: manifest,
                            exec_result: Some(exec), canonical_rpc: None, tier2_ctx: None, error: None,
                        };
                    }

                    ipc::ProposalDecision {
                        id: req.id, granted: true,
                        approval_id: Some(sidecar_aid), scout: manifest,
                        canonical_rpc: Some(canonical_rpc), tier2_ctx,
                        exec_result: None, error: None,
                    }
                }
                other => {
                    tracing::warn!(tool = %tool.tool, ?other, "shim: ORB blocked");
                    session.update_status(AgentStatus::Idle).await;
                    deny(&req.id, "tool call denied by Solarplex supervisor")
                }
            }
        }

        Some(resp) => {
            tracing::error!(tool = %tool.tool, status = %resp.status, "shim: ORB unexpected status");
            session.update_status(AgentStatus::Idle).await;
            deny(&req.id, "ORB: unexpected invoke status")
        }

        None => {
            tracing::error!(tool = %tool.tool, "shim: ORB invoke transport error");
            session.update_status(AgentStatus::Idle).await;
            deny(&req.id, "ORB: server unreachable — tool call aborted")
        }
    }
}

// ── Guardian coordination ─────────────────────────────────────────────────────

async fn run_via_guardian(guardian: &GuardianHandle, approval_id: &str) -> ExecResultIpc {
    let req = ipc::GuardianRequest {
        id:          ulid::Ulid::new().to_string(),
        approval_id: approval_id.to_string(),
        // command and declared_effects are NOT sent; the guardian fetches
        // them from the server directly so the untrusted adapter cannot
        // substitute a different command than what was approved.
    };

    // Lock the shared socket for the duration of this request.
    // No new connection or ChannelHello needed — the socket is the inherited
    // fd-authority channel established at spawn time.
    let result: anyhow::Result<ipc::GuardianResponse> = async {
        let mut stream = guardian.socket.lock().await;
        ipc::write_frame(&mut *stream, &req).await?;
        Ok(ipc::read_frame(&mut *stream).await?)
    }.await;

    match result {
        Ok(resp) => {
            if let Some(e) = &resp.error {
                tracing::error!(approval_id, "guardian exec failed: {e}");
            }
            ExecResultIpc {
                stdout:    resp.stdout,
                stderr:    resp.stderr,
                exit_code: resp.exit_code,
            }
        }
        Err(e) => {
            tracing::error!(approval_id, "guardian IPC error: {e}");
            ExecResultIpc {
                stdout:    String::new(),
                stderr:    format!("guardian unreachable: {e}"),
                exit_code: -1,
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn collect_scout(rx: Option<tokio::sync::oneshot::Receiver<protocol::effects::ScoutManifest>>)
    -> Option<protocol::effects::ScoutManifest>
{
    if let Some(rx) = rx {
        tokio::time::timeout(Duration::from_secs(2), rx)
            .await.ok().and_then(|r| r.ok())
    } else { None }
}

async fn consume_and_patch(
    raw_rpc:    &serde_json::Value,
    receipt_id: Option<&str>,
    cap_id:     &str,
    tool:       &ToolCall,
    session:    &Arc<SessionClient>,
) -> (serde_json::Value, Option<Tier2Ctx>) {
    let Some(rid) = receipt_id else {
        return (raw_rpc.clone(), None);
    };
    let Some(canonical_args) = session.consume_receipt(rid).await else {
        return (raw_rpc.clone(), None);
    };
    let tier2_ctx = extract_tier2_ctx(rid, cap_id, &tool.tool, &canonical_args);
    let mut patched = raw_rpc.clone();
    if let Some(params) = patched.get_mut("params") {
        if let Some(args_field) = params.get_mut("arguments") {
            *args_field = canonical_args;
        }
    }
    (patched, tier2_ctx)
}

fn extract_tier2_ctx(
    receipt_id: &str,
    cap_id:     &str,
    tool:       &str,
    args:       &serde_json::Value,
) -> Option<Tier2Ctx> {
    let path     = args.get("path")?.as_str()?;
    let h_before = args.get("expected_hash_before")?.as_str()?;
    let h_after  = args.get("claimed_hash_after")?.as_str()?;
    Some(Tier2Ctx {
        receipt_id:      receipt_id.to_owned(),
        cap_id:          cap_id.to_owned(),
        tool:            tool.to_owned(),
        path:            path.to_owned(),
        approved_before: h_before.to_owned(),
        approved_after:  h_after.to_owned(),
    })
}

fn deny(id: &str, msg: &str) -> ipc::ProposalDecision {
    ipc::ProposalDecision {
        id:            id.to_string(),
        granted:       false,
        approval_id:   None,
        canonical_rpc: None,
        scout:         None,
        exec_result:   None,
        tier2_ctx:     None,
        error:         Some(msg.to_string()),
    }
}

fn actor_id_to_slug(actor_id: &str) -> String {
    actor_id.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect()
}

/// Handle a post-execution notice from the adapter: run Ring-2 divergence check
/// and Ring-1 attestation fire-and-forget.
pub async fn handle_exec_done(
    notice:  ipc::ExecDoneNotice,
    session: Arc<SessionClient>,
    config:  &Config,
) {
    // Ring-2 divergence check.
    let pre  = notice.pre_snap.iter()
        .map(|(k, v)| (k.clone(), (v.mtime, v.size))).collect();
    let post = notice.post_snap.iter()
        .map(|(k, v)| (k.clone(), (v.mtime, v.size))).collect();

    // Reconstruct a minimal scout to drive the manifest comparison.
    // We don't have the full scout manifest here, but post-exec divergence
    // only needs the pre/post snapshot delta; the scout was already stored server-side.
    let exec_manifest = scout::build_execution_manifest(&pre, &post, None);
    let diverged = exec_manifest.is_diverged();
    if diverged {
        tracing::warn!(
            approval_id = %notice.approval_id,
            unexpected  = ?exec_manifest.unexpected_writes,
            "shim: Ring-2 execution diverged from expectation",
        );
    }
    let sess = session.clone();
    let aid  = notice.approval_id.clone();
    tokio::spawn(async move {
        sess.patch_approval_execution(&aid, &exec_manifest, diverged).await;
    });

    // Ring-1 attestation.
    if let Some(ref t) = notice.tier2 {
        let t_clone = t.clone();
        let sess    = session.clone();
        let actor   = config.actor_id.clone();
        tokio::spawn(async move {
            if let Some(result) = sess.attest_file_write(
                &t_clone.receipt_id, &t_clone.cap_id, &t_clone.tool, &t_clone.path,
                &t_clone.approved_before, &t_clone.approved_after,
                &t_clone.observed_before_hash, &t_clone.actual_after_hash,
            ).await {
                if result.hash_mismatch {
                    tracing::warn!(
                        path           = %t_clone.path,
                        tool           = %t_clone.tool,
                        actor          = %actor,
                        attestation_id = %result.attestation_id,
                        "shim: Ring-1 hash mismatch — security event recorded",
                    );
                }
            }
        });
    }

    // Feed message: "agent called X".
    let content = format!("**{}** called `{}`", config.actor_id, notice.tool_name);
    session.post_message(content).await;
}
