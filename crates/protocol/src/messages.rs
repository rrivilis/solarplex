use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::types::{AgentStatus, ContextEntryKind, SessionSnapshot, ToolCall, Vote};

/// Every WS frame. protocol_version on every message for forward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsMessage {
    pub protocol_version: u32,
    pub id: String,
    #[serde(flatten)]
    pub payload: WsPayload,
}

impl WsMessage {
    pub fn new(id: impl Into<String>, payload: WsPayload) -> Self {
        Self {
            protocol_version: 1,
            id: id.into(),
            payload,
        }
    }
}

/// All message types across commands, events, and snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsPayload {
    // ── Commands (imperative, directed) ──────────────────────────────────────
    #[serde(rename = "approval.request")]
    ApprovalRequest {
        session_id: String,
        actor_id: String,
        approval_id: String,
        tool_call: ToolCall,
        #[serde(skip_serializing_if = "Option::is_none")]
        expires_at: Option<DateTime<Utc>>,
    },

    #[serde(rename = "approval.claim")]
    ApprovalClaim {
        session_id: String,
        approval_id: String,
        actor_id: String,
    },

    #[serde(rename = "approval.grant")]
    ApprovalGrant {
        session_id: String,
        approval_id: String,
        actor_id: String,
    },

    #[serde(rename = "approval.deny")]
    ApprovalDeny {
        session_id: String,
        approval_id: String,
        actor_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    #[serde(rename = "approval.cancel")]
    ApprovalCancel {
        session_id: String,
        approval_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    #[serde(rename = "approval.delegate")]
    ApprovalDelegate {
        session_id: String,
        approval_id: String,
        from: String,
        to: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },

    #[serde(rename = "approval.dispute")]
    ApprovalDispute {
        session_id: String,
        approval_id: String,
        actor_id: String,
        reason: String,
    },

    /// Directed back to the requesting sidecar only.
    #[serde(rename = "approval.resolved")]
    ApprovalResolved {
        approval_id: String,
        decision: ApprovalDecision,
        #[serde(skip_serializing_if = "Option::is_none")]
        resolved_by: Option<String>,
        resolved_at: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        escalated_to: Option<String>,
    },

    #[serde(rename = "ownership.transfer")]
    OwnershipTransfer {
        session_id: String,
        from: String,
        to: String,
    },

    /// Human sends a chat message to the session.
    #[serde(rename = "message.post")]
    MessagePost { session_id: String, content: String },

    /// Agent reports its own status change (client→server command).
    #[serde(rename = "agent.status.update")]
    AgentStatusUpdate {
        session_id: String,
        actor_id: String,
        status: crate::types::AgentStatus,
    },

    /// Add a typed entry to the session's shared epistemic context.
    #[serde(rename = "context.entry.add")]
    ContextEntryAdd {
        session_id: String,
        actor_id: String,
        kind: ContextEntryKind,
        content: String,
    },

    /// Mark a context entry as resolved (answered, superseded, or withdrawn).
    #[serde(rename = "context.entry.resolve")]
    ContextEntryResolve {
        session_id: String,
        actor_id: String,
        entry_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },

    // ── Events (broadcast, timeline) ─────────────────────────────────────────
    #[serde(rename = "tool.call.requested")]
    ToolCallRequested {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ToolCallRequestedPayload,
    },

    #[serde(rename = "tool.call.executed")]
    ToolCallExecuted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ToolCallExecutedPayload,
    },

    #[serde(rename = "tool.call.blocked")]
    ToolCallBlocked {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ToolCallBlockedPayload,
    },

    #[serde(rename = "approval.requested")]
    ApprovalRequested {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalRequestedPayload,
    },

    #[serde(rename = "approval.claimed")]
    ApprovalClaimed {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalEventPayload,
    },

    #[serde(rename = "approval.granted")]
    ApprovalGranted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalEventPayload,
    },

    #[serde(rename = "approval.denied")]
    ApprovalDenied {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalDeniedPayload,
    },

    #[serde(rename = "approval.contested")]
    ApprovalContested {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalContestedPayload,
    },

    #[serde(rename = "approval.timed_out")]
    ApprovalTimedOut {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalEventPayload,
    },

    #[serde(rename = "approval.cancelled")]
    ApprovalCancelled {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalEventPayload,
    },

    #[serde(rename = "approval.delegated")]
    ApprovalDelegated {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalDelegatedPayload,
    },

    #[serde(rename = "approval.disputed")]
    ApprovalDisputed {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ApprovalDisputedPayload,
    },

    #[serde(rename = "actor.joined")]
    ActorJoined {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        /// Role of the actor in this session. Present when emitted by the REST
        /// add_member handler; absent (defaults to Collaborator) for legacy events.
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<crate::types::MemberRole>,
        /// The joining actor's display name, resolved server-side at emission
        /// time. Without this, a client that's already connected (receiving
        /// this as a live incremental patch, not a fresh snapshot) has no way
        /// to show anything but the raw actor_id for a brand-new member —
        /// `make_snapshot_msg`'s enrichment only runs at WS-connect time, so
        /// an already-open tab would otherwise show that raw id until its
        /// next reconnect. Absent (falls back to the id) only for whatever
        /// legacy event history predates this field.
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },

    /// Live-only presence signal for an *already-known* member's connection
    /// state changing (ordinary WS connect/disconnect — a route change, a
    /// tab reload, a brief network blip). Deliberately has no `seq`: unlike
    /// `ActorJoined`/`ActorDetached`, this never goes through
    /// `stamp_append_snapshot`/`commit_event` and is never written to the
    /// `events` table — see migration 033's doc comment. A genuinely new
    /// membership grant still emits a real `ActorJoined`; this is only for
    /// an existing member's connection flickering, which used to flood the
    /// event log/Activity Log with "joined"/"left" noise on every reconnect.
    #[serde(rename = "presence.changed")]
    PresenceChanged {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        attached: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        role: Option<crate::types::MemberRole>,
    },

    #[serde(rename = "actor.detached")]
    ActorDetached {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
    },

    /// Client -> server command: "I now have `tab` open in this session."
    /// `tab: None` means the sender switched away from any tracked tab (or
    /// is about to navigate away) -- receivers should stop showing them
    /// against whichever tab they last reported. Same split-naming
    /// convention as `MessagePost`/`MessagePosted`.
    #[serde(rename = "presence.focus.set")]
    PresenceFocusSet {
        session_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        tab: Option<String>,
    },

    /// Server -> every other connected client: `actor` now has `tab` open.
    /// Same posture as `PresenceChanged`: ephemeral, no `seq`, never goes
    /// through `stamp_append_snapshot`/the `events` table -- "who's looking
    /// at what right now" is live-only UI state, not an auditable fact.
    #[serde(rename = "presence.focus")]
    PresenceFocus {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tab: Option<String>,
    },

    #[serde(rename = "ownership.transferred")]
    OwnershipTransferred {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: OwnershipTransferredPayload,
    },

    #[serde(rename = "artifact.created")]
    ArtifactCreated {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ArtifactPayload,
    },

    #[serde(rename = "artifact.updated")]
    ArtifactUpdated {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ArtifactPayload,
    },

    #[serde(rename = "artifact.deleted")]
    ArtifactDeleted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ArtifactPayload,
    },

    #[serde(rename = "agent.status.changed")]
    AgentStatusChanged {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: AgentStatusPayload,
    },

    #[serde(rename = "session.status.changed")]
    SessionStatusChanged {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: SessionStatusPayload,
    },

    /// Fired when a session's human-readable name is changed.
    /// The ULID identity is stable — only the editable name changes.
    #[serde(rename = "session.renamed")]
    SessionRenamed {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: SessionRenamedPayload,
    },

    #[serde(rename = "message.posted")]
    MessagePosted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: MessagePostedPayload,
    },

    #[serde(rename = "context.entry.added")]
    ContextEntryAdded {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ContextEntryAddedPayload,
    },

    #[serde(rename = "context.entry.resolved")]
    ContextEntryResolved {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ContextEntryResolvedPayload,
    },

    // ── Shell adapter events ──────────────────────────────────────────────────
    /// Emitted when a shell command begins executing (from the fish adapter).
    #[serde(rename = "shell.command.started")]
    ShellCommandStarted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ShellCommandStartedPayload,
    },

    /// Emitted when a shell command finishes (exit code + duration).
    #[serde(rename = "shell.command.completed")]
    ShellCommandCompleted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ShellCommandCompletedPayload,
    },

    // ── Rate limiting ───────────────────────────────────────────────────────
    /// Emitted when a Tier-1 (session-scoped) rate limit denies an action.
    /// The REST handler returns 429 to the caller directly — this event is
    /// only the durable audit trail of that denial, log-only like the shell
    /// adapter events above: no dedicated panel, no snapshot projection
    /// change (`apply_event`'s catch-all covers it).
    #[serde(rename = "effect.rate_limited")]
    EffectRateLimited {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: EffectRateLimitedPayload,
    },

    // ── Three-tier commitment model ───────────────────────────────────────────
    /// Emitted when a Tier-1 (Solarplex-managed state) write proposal commits.
    ///
    /// The commit validated `H_before` and `H_after` inside a single Postgres
    /// transaction; this event is the immutable record that the transition
    /// landed against a known-good precondition.
    #[serde(rename = "proposal.committed")]
    ProposalCommitted {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: ProposalCommittedPayload,
    },

    /// Emitted when the sidecar attests a Tier-2 (filesystem) write.
    ///
    /// `hash_mismatch = true` means the filesystem was different from what the
    /// human approved (`H_before` diverged) or the write produced a different
    /// result (`H_after` diverged).  This is a security event — detectable in
    /// the audit log but not preventable at the filesystem layer.
    #[serde(rename = "proposal.file_write.attested")]
    FileWriteAttested {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: FileWriteAttestedPayload,
    },

    // ── Epoch revocation ──────────────────────────────────────────────────────
    /// Broadcast when a revocation fires and the session's epoch advances.
    ///
    /// All connected actors receive this message.  Agents whose caps are in
    /// the revoked set are fenced: writes are rejected with WS close 4401
    /// after `drain_deadline_ms` milliseconds from the timestamp of this event.
    ///
    /// During the drain window (`drain_deadline_ms`), agents that had already
    /// observed `seq <= drain_seq` at the time of revocation may complete
    /// in-flight work — drain-bounded liveness.
    #[serde(rename = "cap.epoch.advanced")]
    EpochAdvanced {
        session_id: String,
        actor: String,
        timestamp: DateTime<Utc>,
        seq: i64,
        payload: EpochAdvancedPayload,
    },

    // ── Snapshots ─────────────────────────────────────────────────────────────
    #[serde(rename = "session.snapshot")]
    SessionSnapshot {
        session_id: String,
        seq: i64,
        state: SessionSnapshot,
    },
}

impl WsPayload {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::ApprovalRequest { .. } => "approval.request",
            Self::ApprovalClaim { .. } => "approval.claim",
            Self::ApprovalGrant { .. } => "approval.grant",
            Self::ApprovalDeny { .. } => "approval.deny",
            Self::ApprovalCancel { .. } => "approval.cancel",
            Self::ApprovalDelegate { .. } => "approval.delegate",
            Self::ApprovalDispute { .. } => "approval.dispute",
            Self::ApprovalResolved { .. } => "approval.resolved",
            Self::OwnershipTransfer { .. } => "ownership.transfer",
            Self::ToolCallRequested { .. } => "tool.call.requested",
            Self::ToolCallExecuted { .. } => "tool.call.executed",
            Self::ToolCallBlocked { .. } => "tool.call.blocked",
            Self::ApprovalRequested { .. } => "approval.requested",
            Self::ApprovalClaimed { .. } => "approval.claimed",
            Self::ApprovalGranted { .. } => "approval.granted",
            Self::ApprovalDenied { .. } => "approval.denied",
            Self::ApprovalContested { .. } => "approval.contested",
            Self::ApprovalTimedOut { .. } => "approval.timed_out",
            Self::ApprovalCancelled { .. } => "approval.cancelled",
            Self::ApprovalDelegated { .. } => "approval.delegated",
            Self::ApprovalDisputed { .. } => "approval.disputed",
            Self::ActorJoined { .. } => "actor.joined",
            Self::PresenceChanged { .. } => "presence.changed",
            Self::ActorDetached { .. } => "actor.detached",
            Self::PresenceFocusSet { .. } => "presence.focus.set",
            Self::PresenceFocus { .. } => "presence.focus",
            Self::OwnershipTransferred { .. } => "ownership.transferred",
            Self::ArtifactCreated { .. } => "artifact.created",
            Self::ArtifactUpdated { .. } => "artifact.updated",
            Self::ArtifactDeleted { .. } => "artifact.deleted",
            Self::AgentStatusChanged { .. } => "agent.status.changed",
            Self::SessionStatusChanged { .. } => "session.status.changed",
            Self::SessionRenamed { .. } => "session.renamed",
            Self::MessagePost { .. } => "message.post",
            Self::MessagePosted { .. } => "message.posted",
            Self::AgentStatusUpdate { .. } => "agent.status.update",
            Self::ContextEntryAdd { .. } => "context.entry.add",
            Self::ContextEntryResolve { .. } => "context.entry.resolve",
            Self::ContextEntryAdded { .. } => "context.entry.added",
            Self::ContextEntryResolved { .. } => "context.entry.resolved",
            Self::ShellCommandStarted { .. } => "shell.command.started",
            Self::ShellCommandCompleted { .. } => "shell.command.completed",
            Self::EffectRateLimited { .. } => "effect.rate_limited",
            Self::ProposalCommitted { .. } => "proposal.committed",
            Self::FileWriteAttested { .. } => "proposal.file_write.attested",
            Self::EpochAdvanced { .. } => "cap.epoch.advanced",
            Self::SessionSnapshot { .. } => "session.snapshot",
        }
    }
}

// ── Command/Event payload types ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Granted,
    Denied,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallRequestedPayload {
    pub tool: String,
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallExecutedPayload {
    pub tool: String,
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallBlockedPayload {
    pub tool: String,
    pub approval_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequestedPayload {
    pub approval_id: String,
    pub tool: String,
    pub summary: String,
    pub requested_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The tool call's structured arguments — same value stored on the
    /// `approval_requests` row. Carried on the wire so clients can render
    /// tool-specific detail (e.g. cross-session sync's source object and
    /// session) without a second round-trip.
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalEventPayload {
    pub approval_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDeniedPayload {
    pub approval_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalContestedPayload {
    pub approval_id: String,
    pub votes: std::collections::HashMap<String, Vote>,
    pub pending_resolution: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDelegatedPayload {
    pub approval_id: String,
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDisputedPayload {
    pub approval_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnershipTransferredPayload {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactPayload {
    pub artifact_id: String,
    pub name: String,
    /// Artifact type slug (document | code | plan | report | spreadsheet | …).
    /// Optional for backwards compatibility; defaults to "other" in projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentStatusPayload {
    pub status: AgentStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatusPayload {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRenamedPayload {
    pub old_name: String,
    pub new_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePostedPayload {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntryAddedPayload {
    pub entry_id: String,
    pub kind: ContextEntryKind,
    pub content: String,
    /// "agent" when written via a cap-bound sidecar, "human" when written by
    /// a human operator.  None for legacy entries predating this field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub authored_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntryResolvedPayload {
    pub entry_id: String,
    pub resolved_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommandStartedPayload {
    /// Opaque ID linking start → complete.
    pub command_id: String,
    /// Basename of argv[0] — always logged, never contains arguments or path
    /// components.  Example: "git", "cargo", "psql".
    pub argv0: String,
    /// Full command string — present only when the user explicitly opted in to
    /// tracking (via SOLARPLEX_TRACK_COMMANDS=1 or the `track:` prefix) AND the
    /// credential seatbelt did not fire.  Absent in all other cases.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Whether the user explicitly requested full-command tracking for this
    /// invocation.  Does not imply the command field is populated — the seatbelt
    /// may have overridden it (see `redacted`).
    pub tracked: bool,
    /// True when the credential seatbelt fired: a known secret pattern was
    /// detected in the command argv and the full text was suppressed even though
    /// `tracked` was true.  The UI should render a distinct
    /// "[credential detected — argv suppressed]" label in this case.
    pub redacted: bool,
    /// Working directory at the time of execution, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShellCommandCompletedPayload {
    pub command_id: String,
    pub exit_code: i32,
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,
}

/// Payload for `effect.rate_limited`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectRateLimitedPayload {
    /// `RateLimitKey::label()` — e.g. "MessagePost", "AgentAttach".
    pub key_label: String,
    /// `Policy::describe()` — e.g. "30/60s".
    pub policy: String,
    pub retry_after_secs: u64,
}

/// Payload for `proposal.committed`.
///
/// Carries the CAS fingerprint so the event log is self-describing: an auditor
/// can verify the transition without re-reading the artifact history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalCommittedPayload {
    pub proposal_id: String,
    pub effect_type: String,
    /// For `artifact_patch`: the artifact that was updated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_id: Option<String>,
    /// Hash of the state *before* the effect was applied (sha256:<hex>).
    pub h_before: String,
    /// Hash of the state *after* the effect was applied (sha256:<hex>).
    pub h_after: String,
}

/// Payload for `proposal.file_write.attested`.
///
/// `hash_mismatch = true` is a security event: surface it in the UI and alert.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileWriteAttestedPayload {
    pub attestation_id: String,
    pub receipt_id: String,
    pub tool: String,
    pub path: String,
    /// True when observed_before ≠ approved_before or actual_after ≠ approved_after.
    pub hash_mismatch: bool,
    pub approved_hash_before: String,
    pub approved_hash_after: String,
    pub observed_hash_before: String,
    pub actual_hash_after: String,
}

/// Payload for the `cap.epoch.advanced` broadcast.
///
/// Sent to all connected actors when a revocation fires.  Agents whose caps
/// are in the revoked set should stop issuing writes after `drain_deadline_ms`
/// milliseconds have elapsed from the event timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochAdvancedPayload {
    /// The epoch that is now active after the revocation.
    pub new_epoch: i64,
    /// Revocation strategy: `"cap"` | `"stratum"` | `"epoch"`.
    pub strategy: String,
    /// For `strategy = "cap"`: the ULID of the revoked subtree root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_cap_id: Option<String>,
    /// For `strategy = "stratum"`: the depth threshold (all caps with
    /// stratum >= this value in the closed epoch were revoked).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_stratum: Option<i64>,
    /// The event seq at the moment revocation fired.  Agents that had
    /// already observed `seq <= drain_seq` are eligible for the drain window.
    pub drain_seq: i64,
    /// Milliseconds from the event timestamp until the drain window closes.
    /// After this deadline, fenced connections receive WS close 4401.
    pub drain_deadline_ms: u64,
    /// The epoch that was closed by this revocation.
    pub closed_epoch: i64,
    /// Count of caps that were revoked (including subtree members).
    pub revoked_count: u64,
}
