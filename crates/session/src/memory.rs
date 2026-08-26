use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use protocol::types::{
    ApprovalState, ArtifactSummary, ContextEntry, MemberRole, PendingApproval, SessionMember,
    SessionSnapshot, SessionStatus, Vote,
};

use crate::effects::{ReflectorCursor, SagaBundle};
use crate::events::{PolicyConstraint, PolicyTarget, SagaStepSpec};

// ── Member ────────────────────────────────────────────────────────────────────

/// A record for a session participant (human or agent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberRecord {
    pub actor_id: String,
    /// "owner" | "collaborator" | "observer" | "agent"
    pub role: String,
    pub joined_at: DateTime<Utc>,
    /// True when the participant has explicitly left or been detached.
    pub detached: bool,
    /// Active WebSocket connection ID, if connected right now.
    pub connection: Option<String>,
}

impl MemberRecord {
    pub fn can_approve(&self) -> bool {
        matches!(self.role.as_str(), "owner" | "collaborator")
    }
}

// ── Cap ───────────────────────────────────────────────────────────────────────

/// A node in the capability delegation DAG.
///
/// Invariants: child.permissions ⊆ parent.permissions; child.epoch == parent.epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapRecord {
    pub cap_id: String,
    pub actor_id: String,
    pub parent_cap: Option<String>,
    pub permissions: Vec<String>,
    pub epoch: i64,
    pub stratum: i64,
    pub issued_at: DateTime<Utc>,
    pub revoked: bool,
}

// ── Approval ──────────────────────────────────────────────────────────────────

/// Lifecycle state of an approval request.
///
/// Transitions are monotone — once terminal, cannot revert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Claimed,
    Granted,
    Denied,
    Expired,
    Interrupted,
}

impl ApprovalStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ApprovalStatus::Granted
                | ApprovalStatus::Denied
                | ApprovalStatus::Expired
                | ApprovalStatus::Interrupted
        )
    }
}

/// In-memory approval record with accumulated votes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub actor_id: String,
    pub tool: String,
    pub status: ApprovalStatus,
    pub requested_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// voter_id → "approve" | "deny"
    pub votes: BTreeMap<String, String>,
}

// ── Proposals ─────────────────────────────────────────────────────────────────

/// In-memory record for a Ring-0/1 write proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub proposal_id: String,
    pub effect_type: String,
    pub receipt_id: Option<String>,
    pub h_before: Option<String>,
    pub h_after: Option<String>,
    pub committed: bool,
    pub diverged: bool,
}

// ── Timer ─────────────────────────────────────────────────────────────────────

/// A timer that has been armed and not yet cancelled or fired.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimerRecord {
    pub id: String,
    pub armed_at: DateTime<Utc>,
    pub duration_ms: u64,
}

// ── Saga ──────────────────────────────────────────────────────────────────────

/// Observable lifecycle of a saga coordination protocol.
///
/// Transitions follow the monotone lattice:
///
/// ```text
///   Running ──→ Waiting ──(Committed)──→ Running ──→ … ──→ Completed
///                        └─(Rejected / Timeout)──→ Compensating ──→ Aborted
/// ```
///
/// `Completed` and `Aborted` are absorbing — no event can move a terminated
/// saga back to any non-terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaStatus {
    /// Coordinator is processing — transitioning between steps.
    Running,
    /// A forward step was dispatched; waiting for a `SagaAck`.
    ///
    /// Analogous to `ApprovalStatus::Claimed`: durable and observable.
    /// The `timer_id` lets the machine cancel the timeout on ack.
    Waiting { step_idx: usize, timer_id: String },
    /// A step was rejected or timed out; compensations are in-flight in
    /// reverse order.
    Compensating { from_step: usize, reason: String },
    /// All steps committed.  Terminal.
    Completed,
    /// Saga aborted; compensations dispatched.  Terminal.
    Aborted { reason: String },
}

impl SagaStatus {
    /// Returns `true` once the saga has reached a terminal state from which
    /// no recovery is possible.
    pub fn is_terminal(&self) -> bool {
        matches!(self, SagaStatus::Completed | SagaStatus::Aborted { .. })
    }
}

/// In-memory record for a saga coordination protocol.
///
/// Reconstructed on cold attach by replaying `SagaBegun` (which embeds the
/// full `steps` spec) and the subsequent step/ack/terminate events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaRecord {
    pub saga_id: String,
    /// Discriminator: "approval" | "ownership_transfer" | "custom".
    pub saga_type: String,
    /// Immutable step specs — set at begin time and never mutated.
    pub steps: Vec<SagaStepSpec>,
    pub status: SagaStatus,
    pub begun_at: DateTime<Utc>,
    /// Type-specific policy parameters for reducer reconstruction.
    ///
    /// Persisted verbatim from `SagaBegun.metadata`; used by `build_session_saga`
    /// to reconstruct the correct `SessionSaga` discriminant in `live_saga_ack`
    /// without any external lookup.
    pub metadata: serde_json::Value,
}

// ── Bundle gates (policy sub-algebra) ────────────────────────────────────────

/// Why a `SagaBundle` is currently held and not yet delivered to the saga machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateKind {
    /// Waiting for a human `ApprovalGranted` event before delivery.
    Approval { approval_id: String },
    /// Delivery deferred until epoch-ms `until_ms`.
    Deferred { until_ms: u64 },
}

/// A `SagaBundle` held at the adapter layer pending a gate condition.
///
/// Keyed by `bundle_id` in `SessionMemory::gated_bundles`.
///
/// `bundle` is `None` on cold replay (the in-memory reflector is cleared on
/// server restart).  The deferred-timer / approval re-delivery path logs a
/// warning and skips delivery when `bundle` is `None`.
///
/// `reflector_cursor` is the foothold for future durable re-fetch: it records
/// the exact log position so a Postgres-backed reflector (Phase 6+) can
/// re-deliver the bundle after a restart instead of silently dropping it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatedBundle {
    pub gate_kind: GateKind,
    /// The held bundle — present during live operation, absent on cold replay.
    #[serde(default)]
    pub bundle: Option<SagaBundle>,
    /// Reflector log position at which this bundle was appended.
    /// `None` on cold replay (cursor was never persisted); `Some` during live
    /// operation so the bundle can be re-fetched by position on restart.
    #[serde(default)]
    pub reflector_cursor: Option<ReflectorCursor>,
}

// ── SessionMemory ─────────────────────────────────────────────────────────────

/// The working memory of the session machine — Φ in the CSXM framing.
///
/// `SessionMemory` is a pure fold over the event log:
///   `memory = events.iter().fold(SessionMemory::new(…), apply_logged_event)`
///
/// All fields are plain data: no channels, no Arc, no handles.
/// The runtime maps actor IDs → WS senders and timer IDs → JoinHandles externally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMemory {
    pub session_id: String,
    pub session_name: String,

    /// Current position in the event log.  Strictly monotonically increasing.
    pub cursor: i64,

    /// Current cap epoch.  Advanced by `EpochAdvanced` events.
    pub epoch: i64,

    /// Current session owner actor ID.
    pub owner_id: String,

    /// Approval policy slug: "single_vote" | "majority" | "unanimous".
    pub session_policy: String,

    /// Count of non-detached members with approval rights (owner + collaborator).
    /// Updated by participation events.  Used for majority/unanimous evaluation.
    pub eligible_approvers: usize,

    /// All participants who have ever been attached (including detached ones).
    pub members: BTreeMap<String, MemberRecord>,

    /// All caps ever issued (including revoked).  `revoked` field gates enforcement.
    pub caps: BTreeMap<String, CapRecord>,

    /// Inverted children index: `parent_cap_id → [child_cap_id, …]`.
    ///
    /// Maintained alongside `caps` to make subtree revocation and lineage
    /// queries O(subtree_size) instead of O(n_caps × depth).
    ///
    /// Root caps (no parent) are not indexed here; the absence of an entry
    /// means the cap has no children.  Revoked caps are NOT removed from this
    /// index — tombstoned entries are cheap and preserve audit lineage.
    #[serde(default)]
    pub cap_children: BTreeMap<String, Vec<String>>,

    /// Pending and recently-resolved approval records (kept for audit).
    pub approvals: BTreeMap<String, ApprovalRecord>,

    /// Ring-0/1 write proposals tracked in memory.
    pub proposals: BTreeMap<String, ProposalRecord>,

    /// Artifacts, keyed by artifact_id. Shadow-persisted only today (see
    /// `session_task::is_machine_autonomous`) — `routes/sessions.rs` remains
    /// the authoritative writer. Stores `protocol::types::ArtifactSummary`
    /// directly rather than a parallel struct, since that's exactly the shape
    /// `build_snapshot` needs to project out.
    #[serde(default)]
    pub artifacts: BTreeMap<String, ArtifactSummary>,

    /// Shared epistemic context entries, keyed by entry_id. Shadow-persisted
    /// only today, same reasoning as `artifacts` above.
    #[serde(default)]
    pub context: BTreeMap<String, ContextEntry>,

    /// Active timers keyed by timer ID.
    pub timers: BTreeMap<String, TimerRecord>,

    /// Active and recently-terminated saga coordination records.
    pub sagas: BTreeMap<String, SagaRecord>,

    /// Bundles currently held at the adapter layer (deferred or approval-gated).
    ///
    /// Keyed by `bundle_id`.  Updated by policy events (`BundleDeferred`,
    /// `BundleApprovalGated`, `BundleRejected`).  `gated_bundles` is the
    /// *current reason* view — what is presently gated.  The event log is the
    /// *historical reason* view — why each disposition was taken.
    #[serde(default)]
    pub gated_bundles: BTreeMap<String, GatedBundle>,

    /// Active delivery policy constraints set by the adapter layer.
    ///
    /// Keyed by `PolicyTarget` (most-specific match wins at intercept time).
    /// Written by `PolicySet` events.  This is the *current reason* snapshot —
    /// `sp reflect policy` reads here; `sp policy set` appends `PolicySet` events.
    #[serde(default)]
    pub policies: BTreeMap<PolicyTarget, PolicyConstraint>,

    /// Cursor position of the last successfully persisted snapshot.
    pub snapshot_seq: i64,
}

impl SessionMemory {
    /// Construct fresh memory for a newly-created session.
    pub fn new(session_id: String, owner_id: String) -> Self {
        Self {
            session_id,
            session_name: String::new(),
            cursor: 0,
            epoch: 0,
            owner_id,
            session_policy: "single_vote".into(),
            eligible_approvers: 0,
            members: BTreeMap::new(),
            caps: BTreeMap::new(),
            cap_children: BTreeMap::new(),
            approvals: BTreeMap::new(),
            proposals: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            context: BTreeMap::new(),
            timers: BTreeMap::new(),
            sagas: BTreeMap::new(),
            gated_bundles: BTreeMap::new(),
            policies: BTreeMap::new(),
            snapshot_seq: 0,
        }
    }

    /// Advance the cursor.  `seq` must be ≥ the current cursor.
    pub fn advance_cursor(&mut self, seq: i64) {
        debug_assert!(
            seq >= self.cursor,
            "cursor regressed: {} → {}",
            self.cursor,
            seq
        );
        self.cursor = seq;
    }

    /// True if the cap is active (not revoked) and belongs to the current epoch.
    pub fn cap_is_active(&self, cap_id: &str) -> bool {
        self.caps
            .get(cap_id)
            .map(|c| !c.revoked && c.epoch == self.epoch)
            .unwrap_or(false)
    }

    /// Collect `root_cap_id` and all of its transitive descendants using the
    /// inverted children index.  O(subtree_size) — no full-scan over `caps`.
    ///
    /// Includes revoked caps (for audit use).  The returned vec is in BFS
    /// order: root first, then children layer by layer.
    pub fn cap_subtree(&self, root_cap_id: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut queue = vec![root_cap_id.to_string()];
        while let Some(current) = queue.pop() {
            result.push(current.clone());
            if let Some(children) = self.cap_children.get(&current) {
                queue.extend(children.iter().cloned());
            }
        }
        result
    }

    /// Return the delegation chain from `cap_id` up to the root.
    ///
    /// O(depth) — follows `parent_cap` pointers.  Returns `[cap_id, …, root]`
    /// (leaf first).  Stops at the first cap with no parent or a missing entry.
    pub fn cap_lineage(&self, cap_id: &str) -> Vec<String> {
        let mut chain = Vec::new();
        let mut current = cap_id.to_string();
        loop {
            chain.push(current.clone());
            match self
                .caps
                .get(&current)
                .and_then(|c| c.parent_cap.as_deref())
            {
                Some(parent) => current = parent.to_string(),
                None => break,
            }
        }
        chain
    }

    /// Recount eligible approvers from the current member set.
    /// Call after any membership change.
    pub fn recount_eligible(&mut self) {
        self.eligible_approvers = self
            .members
            .values()
            .filter(|m| !m.detached && m.can_approve())
            .count();
    }
}

// ── Snapshot projection ───────────────────────────────────────────────────────

/// Build a `SessionSnapshot` from the current (state, memory) pair.
///
/// Used by the Phase 3 effect runner to build real broadcast payloads
/// instead of the stub `{ "type": "session_updated" }` placeholder.
pub fn build_snapshot(
    lifecycle: &crate::state::SessionState,
    memory: &SessionMemory,
) -> SessionSnapshot {
    let status = match lifecycle {
        crate::state::SessionState::Suspended { .. } => SessionStatus::Suspended,
        crate::state::SessionState::Archived { .. } => SessionStatus::Archived,
        _ => SessionStatus::Active,
    };

    let members: Vec<SessionMember> = memory
        .members
        .values()
        .map(|m| {
            let role = match m.role.as_str() {
                "owner" => MemberRole::Owner,
                "collaborator" => MemberRole::Collaborator,
                "observer" => MemberRole::Observer,
                _ => MemberRole::Agent,
            };
            // Agents never hold a WS `connection` — AgentAttached/AgentDetached
            // only ever set `detached`, since they attach via a cap, not a
            // browser socket (see transition.rs). Deriving "attached" from
            // `connection.is_some()` for agents would report every agent as
            // permanently detached. Humans keep the connection-based signal:
            // a mere WS disconnect (page reload) deliberately does NOT set
            // `detached` for them, so `!m.detached` would be wrong in the
            // other direction — it'd stay "attached" through a dropped socket.
            let attached = match role {
                MemberRole::Agent => !m.detached,
                _ => m.connection.is_some(),
            };
            SessionMember {
                actor_id: m.actor_id.clone(),
                // This crate has no actor-name lookup access by design (zero
                // I/O deps — see the module docs). Left empty; the server
                // enriches it from `actors.name` before a snapshot ever
                // reaches a client — see ws::make_snapshot_msg.
                name: String::new(),
                role,
                attached,
                status: None,
            }
        })
        .collect();

    let pending_approvals: Vec<PendingApproval> = memory
        .approvals
        .values()
        .filter(|a| matches!(a.status, ApprovalStatus::Pending | ApprovalStatus::Claimed))
        .map(|a| {
            let votes: std::collections::HashMap<String, Vote> = a
                .votes
                .iter()
                .filter_map(|(voter_id, decision)| {
                    let v = match decision.as_str() {
                        "approve" => Vote::Approve,
                        _ => Vote::Deny,
                    };
                    Some((voter_id.clone(), v))
                })
                .collect();
            PendingApproval {
                approval_id: a.approval_id.clone(),
                tool: a.tool.clone(),
                requested_by: a.actor_id.clone(),
                state: match &a.status {
                    ApprovalStatus::Claimed => ApprovalState::Claimed,
                    _ => ApprovalState::Pending,
                },
                votes,
                claimed_by: None,
                expires_at: a.expires_at,
                // ApprovalRecord is a minimal timer/expiry mirror, not the
                // display source of truth (that's crates/server/src/ws.rs's
                // snapshot projection) — no structured arguments to carry.
                arguments: serde_json::Value::Null,
            }
        })
        .collect();

    SessionSnapshot {
        owner: memory.owner_id.clone(),
        owner_name: String::new(), // enriched server-side, see make_snapshot_msg
        name: memory.session_name.clone(),
        approval_policy: memory.session_policy.clone(),
        status,
        members,
        pending_approvals,
        artifacts: memory.artifacts.values().cloned().collect(),
        context: memory.context.values().cloned().collect(),
    }
}
