//! Inter-process communication types and async framing for the
//! shim ↔ adapter ↔ guardian three-process authority model.
//!
//! ## Authority model
//!
//! IPC channels use Unix socketpairs created by the shim before exec-ing each
//! child.  One end of each pair is dup2'd to a well-known fd in the child:
//!
//! - fd 3: shim↔adapter authority socket (adapter side)
//! - fd 4: shim↔guardian authority socket (guardian side)
//!
//! Possession of the inherited fd IS the authority proof.  There is no
//! listening socket to discover, no channel secret to steal, and no
//! connection race to win — the kernel enforces that only a direct descendant
//! of the spawning process can hold the fd.  SO_PEERCRED and ChannelHello are
//! therefore not needed and are not used.
//!
//! Both children set O_CLOEXEC on their authority fd immediately after start so
//! that bwrap sandbox children and upstream MCP subprocesses cannot inherit it.
//!
//! ## Message flows
//!
//! ```text
//! Adapter → Shim : AdapterMessage  (propose tool call, exec-done notice)
//! Shim → Adapter : ShimMessage     (proposal decision, exec-done ack)
//! Shim → Guardian: GuardianRequest (execute approved command)
//! Guardian → Shim: GuardianResponse(execution result)
//! ```
//!
//! ## Wire framing
//!
//! All messages use 4-byte little-endian length prefix + JSON body.
//! Max frame size is 64 MiB; frames above that size are rejected with an I/O error.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::effects::ScoutManifest;
use crate::types::ToolCall;

// ── Adapter → Shim ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AdapterMessage {
    Propose(ProposalRequest),
    ExecDone(ExecDoneNotice),
    /// Fire-and-forget: a real MCP client opened its SSE stream against the
    /// adapter's proxy — the actual "an agent is here" milestone, as opposed
    /// to the shim process merely having started. The adapter is untrusted,
    /// so this is a request for the shim to announce, not the adapter
    /// announcing directly to the server itself.
    ClientConnected,
    /// Fire-and-forget: the adapter detected its SSE stream close
    /// (`Poll::Ready(None)` in `handle_sse_open`). Same trust reasoning as
    /// `ClientConnected` — the shim is the one that tells the server.
    ClientDisconnected,
}

/// Adapter requests that the shim gate this tool call through the approval flow.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProposalRequest {
    /// Correlation ID; echoed back in the matching ShimMessage::Decision.
    pub id:      String,
    pub tool:    ToolCall,
    /// The full JSON-RPC message as received from the agent; the shim may
    /// patch the args after receipt consumption and return the canonical form.
    pub raw_rpc: serde_json::Value,
}

/// Fire-and-forget post-execution notice sent after the upstream tool responds.
/// The shim uses this to run Ring-1 attestation and Ring-2 divergence checks.
#[derive(Debug, Serialize, Deserialize)]
pub struct ExecDoneNotice {
    pub approval_id: String,
    pub tool_name:   String,
    /// Filesystem snapshots before and after the upstream tool ran.
    /// Used by the shim to compute Ring-2 divergence vs. the scout manifest.
    pub pre_snap:    HashMap<String, SnapEntry>,
    pub post_snap:   HashMap<String, SnapEntry>,
    /// Present when the tool call opted into Ring-1 hash-fence attestation.
    pub tier2:       Option<Tier2Notice>,
}

/// Mtime + size snapshot of a single file path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapEntry {
    pub mtime: i64,
    pub size:  u64,
}

/// Ring-1 (Tier-2) hash attestation data captured by the adapter.
///
/// The adapter reads the file before and after the upstream call; the shim
/// submits the attestation to the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Notice {
    pub receipt_id:           String,
    pub cap_id:               String,
    pub tool:                 String,
    pub path:                 String,
    pub approved_before:      String,
    pub approved_after:       String,
    pub observed_before_hash: String,
    pub actual_after_hash:    String,
}

// ── Shim → Adapter ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShimMessage {
    Decision(ProposalDecision),
    ExecDoneAck,
}

/// Shim's decision on a ProposalRequest, matched by id.
#[derive(Debug, Serialize, Deserialize)]
pub struct ProposalDecision {
    pub id:      String,
    pub granted: bool,
    /// Set when the approval gate created a record (used for Ring-2 post-exec notice).
    pub approval_id:   Option<String>,
    /// The rpc to forward to the upstream (may have server-canonical args substituted).
    /// `None` for meta-tools handled inside the shim or denied calls.
    pub canonical_rpc: Option<serde_json::Value>,
    /// Scout manifest produced during the approval window (heuristic, not authoritative).
    pub scout:         Option<ScoutManifest>,
    /// Execution result for `solarplex_exec` only — the guardian ran the command;
    /// the adapter formats this into the MCP tool call response.
    pub exec_result:   Option<ExecResultIpc>,
    /// Ring-1 context extracted from canonical args after receipt consumption.
    /// The adapter uses this to read files before/after forwarding and populate Tier2Notice.
    pub tier2_ctx:     Option<Tier2Ctx>,
    pub error:         Option<String>,
}

/// Sandboxed execution result sent from the guardian to the shim and then to the adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResultIpc {
    pub stdout:    String,
    pub stderr:    String,
    pub exit_code: i32,
}

/// Ring-1 (Tier-2) context propagated from the shim to the adapter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tier2Ctx {
    pub receipt_id:      String,
    pub cap_id:          String,
    pub tool:            String,
    pub path:            String,
    pub approved_before: String,
    pub approved_after:  String,
}

// ── Shim → Guardian ──────────────────────────────────────────────────────────

/// Shim instructs the guardian to execute an approved sandboxed command.
///
/// The guardian independently verifies the approval_id with the server and
/// fetches the approved command + declared effects from the same response.
/// The adapter (untrusted) never supplies the command — only the server's
/// canonical record drives what the guardian executes.
#[derive(Debug, Serialize, Deserialize)]
pub struct GuardianRequest {
    /// Correlation ID; echoed back in GuardianResponse.
    pub id:          String,
    /// The server-side approval record the human voted on.
    pub approval_id: String,
    // No command or declared_effects: the guardian fetches these from the
    // server during verify_and_fetch(), so the untrusted adapter cannot
    // substitute a different command than what was approved.
}

// ── Guardian → Shim ──────────────────────────────────────────────────────────

/// Guardian's execution result for a GuardianRequest.
#[derive(Debug, Serialize, Deserialize)]
pub struct GuardianResponse {
    pub id:          String,
    pub approval_id: String,
    pub stdout:      String,
    pub stderr:      String,
    pub exit_code:   i32,
    /// Set when the guardian rejected the request (verification failed or sandbox error).
    pub error:       Option<String>,
}

// ── Wire framing (async, tokio) ───────────────────────────────────────────────

/// Write a length-prefixed JSON frame to an async writer.
///
/// Format: 4-byte LE u32 length, then JSON bytes.
/// The writer is flushed after every frame.
pub async fn write_frame<T, W>(w: &mut W, msg: &T) -> std::io::Result<()>
where
    T: Serialize,
    W: tokio::io::AsyncWriteExt + Unpin,
{
    let bytes = serde_json::to_vec(msg)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    w.write_all(&(bytes.len() as u32).to_le_bytes()).await?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

/// Read a length-prefixed JSON frame from an async reader.
pub async fn read_frame<T, R>(r: &mut R) -> std::io::Result<T>
where
    T: serde::de::DeserializeOwned,
    R: tokio::io::AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf) as usize;
    if len > 64 * 1024 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("IPC frame too large: {len} bytes"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}
