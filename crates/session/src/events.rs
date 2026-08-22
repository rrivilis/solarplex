//! `SessionEvent` — the loggable event alphabet of the Solarplex session machine.
//!
//! Every mutation that can occur in a session is expressed as a `SessionEvent`.
//! Events are persisted to the DB in causal order and are the sole source of truth
//! for session state (event sourcing).  `SessionMemory` is a pure fold over events:
//!
//! ```text
//! memory = events.iter().fold(SessionMemory::new(…), apply_logged)
//! ```
//!
//! ## The four sub-algebras
//!
//! Events are organized by which algebraic sub-system they belong to.
//!
//! ### 1. Participation algebra   { attach, leave, reconnect, detach }
//! Place-graph rewrites: insert / remove actor nodes in the session place hierarchy.
//!
//! ### 2. Approval algebra        { request, claim, vote, grant, deny, expire, interrupt }
//! Link-graph rewrites: approval edge (agent → approver set → resolution node).
//!
//! ### 3. Effect algebra          { propose, scout, attest, commit, diverge,
//! ###                              message posted, context added/resolved,
//! ###                              artifact created/updated/deleted }
//! Place-graph rewrites: proposal node, commitment edge, divergence annotation.
//! The message/context/artifact events share this bit
//! because they're the same "session-owned content mutated" shape — session
//! content nodes are inserted/updated/removed, same as a proposal committing.
//! All of these are currently shadow-persisted only (see
//! `session_task::is_machine_autonomous`). `ws.rs`/`routes/sessions.rs`
//! remain the authoritative writers; feeding them here keeps the machine's
//! own memory (and `SessionSnapshot` if ever built from it) accurate without
//! flipping write ownership, which would require the caller to also be able
//! to emit a synchronous REST response from inside the machine — not
//! attempted here.
//!
//! ### 4. Projection algebra      { snapshot, invalidate }
//! Cursor rewrites: subscriber delivery pointer advances monotonically.
//! (deliver/ack/backfill are runtime-only, not loggable events.)
//!
//! ## Cap sub-algebra             { delegate, revoke, epoch_advance }
//! Link-graph rewrites: delegation edge add/remove, epoch fence cuts stale edges.
//! Eventually merges with the participation and approval algebras into a unified
//! graph rewrite algebra alongside the cap DAG.
//!
//! ### 5. Saga algebra            { begin, step_sent, step_acked, compensated, terminated }
//! Cross-session coordination protocol: a coordinator drives a sequence of steps
//! to remote participant sessions, each of which must commit or reject.  On any
//! rejection the saga dispatches compensations in reverse order and terminates
//! as Aborted.  The full step spec is embedded in `SagaBegun` so cold replay
//! can reconstruct the `SagaRecord` without external lookup.
//!
//! ## Replay invariant
//!
//! Processing a `Replayed(SessionEvent)` MUST NOT produce a `Persist` effect.
//! The proptest harness in `tests/proptest_invariants.rs` enforces this.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use protocol::types::ContextEntryKind;

// ── Algebra mask ──────────────────────────────────────────────────────────────

bitflags::bitflags! {
    /// A bitmask identifying which sub-algebra a `SessionEvent` belongs to.
    ///
    /// Each event sets exactly one bit (one algebra per event — events don't
    /// span sub-systems).  Projection caches use this mask for coarse-grained
    /// invalidation: if `event.algebra_mask() & projection.depends_on == 0`
    /// the projection is still valid and `build_snapshot` can be skipped.
    ///
    /// # CGRA analogy
    ///
    /// Sub-algebras are like coarse-grained functional units on a CGRA grid.
    /// Projections are statically mapped onto the units they depend on at
    /// definition time.  Runtime dispatch is a single bitmask AND — no
    /// propagation graph, no fine-grained dependency tracking.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AlgebraMask: u64 {
        /// Session lifecycle: Created, Paused, Resumed, Archived.
        const LIFECYCLE  = 1 << 0;
        /// Participation: Joined, Left, OwnershipTransferred, Agent{Attached,Detached}.
        const MEMBERSHIP = 1 << 1;
        /// Cap DAG: Delegated, Revoked, EpochAdvanced.
        const AUTHORITY  = 1 << 2;
        /// Approval workflow: Requested, Claimed, Voted, Granted, Denied, Expired, Interrupted.
        const APPROVAL   = 1 << 3;
        /// Ring-0/1/2 effects (Proposed, Scouted, Attested, Committed, Diverged)
        /// plus the message/context/artifact content sub-shape (MessagePosted,
        /// ContextEntry{Added,Resolved}, Artifact{Created,Updated,Deleted}).
        const EFFECT     = 1 << 4;
        /// Snapshot projection: Created, Invalidated.
        const PROJECTION = 1 << 5;
        /// Cross-session saga coordination: Begun, StepSent, StepAcked, Compensated, Terminated.
        const SAGA       = 1 << 6;
        /// FMOA policy / adapter intercept: BundleAnnotated, BundleReshaped,
        /// BundleDeferred, BundleRejected, BundleApprovalGated.
        ///
        /// Historical reason lives in the event log (why a disposition was taken);
        /// current reason lives in `SessionMemory::gated_bundles` (what is pending).
        /// Mirrors the act/ask CLI split: `sp policy set` writes events, `sp reflect
        /// policy` reads the snapshot.
        const POLICY     = 1 << 7;
    }
}

/// The subset of sub-algebras whose events can change the output of `build_snapshot`.
///
/// An event whose `algebra_mask()` does not intersect this set leaves
/// the `SessionSnapshot` projection unchanged — the cached snapshot can
/// be reused without calling `build_snapshot`.
///
/// Currently: `LIFECYCLE | MEMBERSHIP | APPROVAL | EFFECT`.
/// - `EFFECT` is included because its message/context/artifact content
///   sub-shape *is* projected into `SessionSnapshot.{artifacts,context}` —
///   see `build_snapshot`. The Ring-0/1/2 proposal events sharing this bit
///   (EffectProposed/Scouted/Attested/Committed/Diverged) don't themselves
///   touch snapshot fields, so this over-invalidates slightly for those —
///   an extra (cheap) `build_snapshot` call, not a correctness issue. A
///   finer-grained mask isn't worth adding for that alone.
/// - `AUTHORITY` is not included because caps are not projected into
///   `SessionSnapshot` yet.
/// - `SAGA` is not included because saga state is not in `SessionSnapshot`.
/// - `PROJECTION` only updates `snapshot_seq`, which is not projected out.
/// - `POLICY` is not included because gated-bundle state is not in `SessionSnapshot`.
pub const SNAPSHOT_DEPENDS_ON: AlgebraMask =
    AlgebraMask::LIFECYCLE
        .union(AlgebraMask::MEMBERSHIP)
        .union(AlgebraMask::APPROVAL)
        .union(AlgebraMask::EFFECT);

// ── Policy algebra supporting types ──────────────────────────────────────────

/// Which class of inbound bundles a policy constraint applies to.
///
/// Used as the key in `SessionMemory::policies`.  More specific targets shadow
/// broader ones: `BundleStep` takes priority over `All` when both match.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyTarget {
    /// Applies to every inbound bundle regardless of kind.
    All,
    /// Applies only to `BundleKind::Step` bundles (coordinator → participant).
    BundleStep,
    /// Applies only to `BundleKind::Compensation` bundles (rollback path).
    BundleCompensation,
    /// Applies only to `BundleKind::Ack` bundles (participant → coordinator).
    BundleAck,
}

/// What the adapter layer should do when a matching bundle arrives.
///
/// Stored in `SessionMemory::policies` (current reason / snapshot view).
/// Written by `SessionEvent::PolicySet` events (historical reason / log view).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum PolicyConstraint {
    /// Pass bundles through without modification (explicit no-op / reset).
    Forward,
    /// Gate delivery on a human approval.
    ///
    /// The machine emits `BundleApprovalGated { approval_id }` where
    /// `approval_id = "gate:<bundle_id>"`.  The sidecar that set this policy
    /// observes the event and creates the corresponding `ApprovalRequested`
    /// so human approvers see it in the UI.
    RequireApproval,
    /// Defer delivery for `duration_ms` milliseconds.
    Defer { duration_ms: u64 },
    /// Reject bundles permanently.
    Reject { reason: String },
    /// Annotate bundles with metadata before forwarding.
    Annotate { metadata: serde_json::Value },
}

// ── Bundle transport (reshapeable adapter fields) ─────────────────────────────

/// Reshapeable transport fields of a `SagaBundle`.
///
/// Structural enforcement of the `BundleDisposition::Reshape` scope constraint:
/// the FMOA adapter may modify routing, TTL, and tracing metadata, but CANNOT
/// reach inside `BundleKind` to alter payload semantics (outcome, message,
/// compensation).  Keeping the two types separate makes this a compile-time
/// guarantee rather than a convention.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleTransport {
    /// Override the destination session (sub-bundle fan-out or redirect).
    pub to_session:  String,
    /// Adjusted hard expiry in milliseconds from epoch.
    pub ttl_ms:      u64,
    /// Tracing / QoS annotations added by the adapter layer.
    pub annotations: serde_json::Value,
}

// ── Saga supporting types ─────────────────────────────────────────────────────

/// Specification for one step in a saga coordination protocol.
///
/// Embedded verbatim in `SagaBegun` so that cold replay can reconstruct the
/// full `SagaRecord` without any external lookup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaStepSpec {
    pub step_idx:     usize,
    /// Session ID of the participant who must acknowledge this step.
    pub participant:  String,
    /// Payload delivered on the forward path ("do the work").
    pub message:      serde_json::Value,
    /// Payload delivered on the backward path if the saga aborts after this
    /// step was already committed ("undo the work").
    pub compensation: serde_json::Value,
    /// Milliseconds to wait for an ack before treating this step as rejected.
    pub timeout_ms:   u64,
}

/// Outcome reported by a participant when they acknowledge a saga step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaOutcome {
    /// The participant committed the step successfully.
    Committed,
    /// The participant rejected the step (or the step timed out).
    Rejected { reason: String },
}

/// How a saga reached a terminal state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SagaTermination {
    /// All steps committed — saga completed cleanly.
    Completed,
    /// A step was rejected or timed out; compensations have been dispatched.
    Aborted { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    // ── Session lifecycle ─────────────────────────────────────────────────────

    /// A new session was created.
    SessionCreated {
        session_id: String,
        owner_id:   String,
        name:       String,
        /// Approval policy slug: "single_vote" | "majority" | "unanimous"
        policy:     String,
        created_at: DateTime<Utc>,
    },

    /// The owner paused the session; agents are suspended.
    SessionPaused {
        paused_by: String,
        reason:    Option<String>,
        paused_at: DateTime<Utc>,
    },

    /// The session was resumed from a paused state.
    SessionResumed {
        resumed_by: String,
        resumed_at: DateTime<Utc>,
    },

    /// The session was permanently archived.
    SessionArchived {
        archived_by: String,
        archived_at: DateTime<Utc>,
    },

    // ── Participation algebra ─────────────────────────────────────────────────

    /// A human participant joined the session.
    ParticipantJoined {
        actor_id:  String,
        /// "owner" | "collaborator" | "observer"
        role:      String,
        joined_at: DateTime<Utc>,
    },

    /// A human participant left the session (voluntary or timeout).
    ParticipantLeft {
        actor_id: String,
        reason:   Option<String>,
        left_at:  DateTime<Utc>,
    },

    /// Session ownership was transferred to another participant.
    OwnershipTransferred {
        from_actor:     String,
        to_actor:       String,
        transferred_at: DateTime<Utc>,
    },

    /// An agent sidecar attached to the session with a validated capability.
    AgentAttached {
        actor_id:    String,
        cap_id:      String,
        attached_at: DateTime<Utc>,
    },

    /// An agent sidecar detached from the session.
    AgentDetached {
        actor_id:    String,
        reason:      Option<String>,
        detached_at: DateTime<Utc>,
    },

    // ── Cap algebra (link-graph rewrites) ─────────────────────────────────────

    /// A capability was delegated from a parent to a new actor.
    ///
    /// Invariant: child.permissions ⊆ parent.permissions.
    /// Invariant: child.epoch == parent.epoch == session.epoch at issue time.
    CapDelegated {
        cap_id:      String,
        parent_cap:  Option<String>,
        actor_id:    String,
        permissions: Vec<String>,
        epoch:       i64,
        stratum:     i64,
        issued_at:   DateTime<Utc>,
    },

    /// A capability (and optionally its subtree) was revoked.
    CapRevoked {
        cap_id:     String,
        /// "subtree" revokes cap + all descendants; "leaf" revokes only this cap.
        strategy:   String,
        revoked_by: String,
        revoked_at: DateTime<Utc>,
    },

    /// The session epoch was advanced, fencing all caps at the old epoch.
    ///
    /// All caps with `epoch < new_epoch` are implicitly invalid after this event.
    /// `fenced_actor_ids` lists actors whose active cap was at the old epoch —
    /// they are disconnected during the subsequent drain phase.
    EpochAdvanced {
        old_epoch:         i64,
        new_epoch:         i64,
        /// "hard_fence" | "graceful"
        strategy:          String,
        /// How long (ms) to wait for fenced actors to disconnect cleanly.
        drain_deadline_ms: u64,
        fenced_actor_ids:  Vec<String>,
        advanced_by:       String,
        advanced_at:       DateTime<Utc>,
    },

    // ── Approval algebra (link-graph rewrites) ────────────────────────────────

    /// An agent requested human approval for a Ring-2 effect.
    ApprovalRequested {
        approval_id:  String,
        actor_id:     String,
        tool:         String,
        arguments:    serde_json::Value,
        expires_at:   Option<DateTime<Utc>>,
        requested_at: DateTime<Utc>,
    },

    /// A human claimed the approval request to review it.
    ApprovalClaimed {
        approval_id: String,
        claimed_by:  String,
        claimed_at:  DateTime<Utc>,
    },

    /// A human cast a vote on the approval.
    ApprovalVoted {
        approval_id: String,
        voter_id:    String,
        /// "approve" | "deny"
        decision:    String,
        voted_at:    DateTime<Utc>,
    },

    /// The approval was resolved as granted (policy threshold met).
    ApprovalGranted {
        approval_id: String,
        resolved_by: String,
        granted_at:  DateTime<Utc>,
    },

    /// The approval was resolved as denied.
    ApprovalDenied {
        approval_id: String,
        resolved_by: String,
        reason:      Option<String>,
        denied_at:   DateTime<Utc>,
    },

    /// The approval expired before a resolution was reached.
    ApprovalExpired {
        approval_id: String,
        expired_at:  DateTime<Utc>,
    },

    /// The approval was interrupted (agent disconnected or cancelled it).
    ApprovalInterrupted {
        approval_id:    String,
        reason:         String,
        interrupted_at: DateTime<Utc>,
    },

    /// A human cancelled their own pending approval request.
    ///
    /// Shadow-persisted only (see `session_task::is_machine_autonomous`) —
    /// `ws.rs::handle_approval_cancel` remains the authoritative writer, and
    /// (matching it exactly) reuses `ApprovalStatus::Expired` rather than a
    /// distinct cancelled status — the DB row it writes does the same.
    ApprovalCancelled {
        approval_id:  String,
        cancelled_by: String,
        cancelled_at: DateTime<Utc>,
    },

    /// An approval was delegated to another actor for review.
    ///
    /// EventLog only — matches `ws.rs`'s own `apply_event`, which doesn't
    /// project delegation into `SessionSnapshot` either (delegation doesn't
    /// change who *can* resolve the approval, only who's been asked to).
    ApprovalDelegated {
        approval_id:  String,
        from:         String,
        to:           String,
        delegated_at: DateTime<Utc>,
    },

    /// An approval decision was disputed.
    ///
    /// EventLog only, same reasoning as `ApprovalDelegated`.
    ApprovalDisputed {
        approval_id: String,
        disputed_by: String,
        reason:      String,
        disputed_at: DateTime<Utc>,
    },

    // ── Cross-session approval delegation ─────────────────────────────────────
    //
    // Distinct from ApprovalDelegated above, which stays intra-session
    // (delegate to another actor in the *same* session). This crosses a
    // session boundary via a single-step SessionSaga::Custom dispatched
    // through Effect::Bundle/the reflector — the saga is purely plumbing:
    // the target session's decision reuses its own normal ApprovalRequest/
    // approval_policy machinery unchanged (see live_cross_session_delegate,
    // live_bundle_received's Step handling, and cross_session_delegations,
    // migration 028). EventLog only on both ends, same reasoning as
    // ApprovalDelegated — delegation doesn't itself change who can resolve
    // anything, only what's been asked of a peer session.

    /// The source session (A) began a cross-session delegation saga.
    CrossSessionDelegationRequested {
        saga_id:            String,
        approval_id:        String,
        target_session_id:  String,
        requested_by:       String,
        requested_at:       DateTime<Utc>,
    },

    /// The target session (B) received the delegation bundle. `target_
    /// approval_id` is always `None` here — the pure machine can't perform
    /// the async DB insert that creates the real local `ApprovalRequest`;
    /// that's server-side glue (`session_task.rs`) triggered by this same
    /// bundle delivery, recorded mutably in the `cross_session_delegations`
    /// table (not this immutable event) once it happens.
    CrossSessionDelegationReceived {
        saga_id:             String,
        source_session_id:   String,
        source_approval_id:  String,
        /// Carried through from the saga step's message so the server-side
        /// hook that creates B's real ApprovalRequest has something to show.
        arguments:           serde_json::Value,
        target_approval_id:  Option<String>,
        received_at:         DateTime<Utc>,
    },

    /// The source session (A) received B's decision via the saga Ack and
    /// resolved its original local approval to match.
    CrossSessionDelegationResolved {
        saga_id:      String,
        approval_id:  String,
        /// "granted" | "denied" — mirrors the decision B's own approval_policy reached.
        decision:     String,
        resolved_at:  DateTime<Utc>,
    },

    /// The target session received an artifact-import bundle from a linked
    /// source session. One-way — unlike delegation there is no ack leg back
    /// to the source, so (unlike `CrossSessionDelegationReceived`) there is
    /// no placeholder ID field here: the real local `Artifact` row is
    /// created and its ID assigned entirely inside the same server-side
    /// hook (`session_task.rs`) that this event triggers, with nothing to
    /// thread back into a later event.
    CrossSessionArtifactImportReceived {
        source_session_id:  String,
        source_artifact_id: String,
        source_seq:          i64,
        name:                String,
        artifact_type:       String,
        storage_ref:         String,
        content_hash:        String,
        source_created_by:   String,
        source_created_at:   DateTime<Utc>,
        imported_by:         String,
        link_id:             Option<String>,
        source_name:         String,
        target_name:         String,
        received_at:         DateTime<Utc>,
    },

    /// The target session received a context-summary-send bundle: an
    /// existing `ContextEntry` from a linked session, pushed here with
    /// provenance. There is no relational `context_entries` table (a
    /// `ContextEntry` lives entirely in the event log/snapshot projection,
    /// same as any other `ContextEntryAdded`) -- so unlike artifact import,
    /// there's no separate "target id" to record here at all: the target
    /// session's own `ContextEntryAdded` (built and broadcast by
    /// `session_task.rs`'s side-effect hook) *is* the durable write.
    CrossSessionContextReceived {
        source_session_id: String,
        source_entry_id:   String,
        kind:               ContextEntryKind,
        content:            String,
        source_authored_by: String,
        source_authored_at: DateTime<Utc>,
        imported_by:        String,
        link_id:             Option<String>,
        source_name:         String,
        target_name:         String,
        received_at:         DateTime<Utc>,
    },

    /// The target session received an annotation on one of its own objects
    /// (v1: artifacts only) from a member of a linked session. Same "no
    /// relational insert" reasoning as `CrossSessionContextReceived` -- the
    /// note lands as a `ContextEntryAdded` in the target, this event is the
    /// EventLog-only audit trail of the cross-session hop itself.
    CrossSessionAnnotationReceived {
        source_session_id: String,
        object_type:        String,
        object_id:           String,
        object_name:         String,
        note:                 String,
        authored_by:          String,
        link_id:              Option<String>,
        source_name:          String,
        received_at:          DateTime<Utc>,
    },

    // ── Effect algebra (place-graph rewrites) ─────────────────────────────────

    /// A Ring-0 write proposal was created.
    EffectProposed {
        proposal_id:          String,
        /// Ring-1: present (receipt bound); Ring-0: absent (server CAS).
        receipt_id:           Option<String>,
        effect_type:          String,
        expected_hash_before: Option<String>,
        claimed_hash_after:   Option<String>,
        proposed_at:          DateTime<Utc>,
    },

    /// A Ring-2 scout manifest was recorded during the approval window.
    EffectScouted {
        approval_id:    String,
        scout_manifest: serde_json::Value,
        scouted_at:     DateTime<Utc>,
    },

    /// A Ring-1 filesystem write attestation was recorded post-execution.
    EffectAttested {
        attestation_id: String,
        receipt_id:     String,
        tool:           String,
        path:           String,
        /// True when observed hashes diverged from approved hashes — security event.
        hash_mismatch:  bool,
        attested_at:    DateTime<Utc>,
    },

    /// A Ring-0 effect was committed with verified CAS hashes.
    EffectCommitted {
        proposal_id:  String,
        event_id:     String,
        h_before:     String,
        h_after:      String,
        committed_at: DateTime<Utc>,
    },

    /// A Ring-2 execution manifest diverged from the scout prediction.
    /// This is a security event — stored permanently for audit.
    EffectDiverged {
        approval_id:     String,
        /// "unexpected_writes" | "missing_writes" | "both"
        divergence_type: String,
        details:         serde_json::Value,
        detected_at:     DateTime<Utc>,
    },

    // ── Content sub-shape of the effect algebra ───────────────────────────────
    //
    // Shadow-persisted only today — see the module doc comment above.

    /// A human or agent posted a message to the session.
    ///
    /// EventLog only — matches `ws.rs`'s own `apply_event`, which also does
    /// not project message content into `SessionSnapshot`.
    MessagePosted {
        actor_id:  String,
        content:   String,
        posted_at: DateTime<Utc>,
    },

    /// A typed entry was added to the session's shared epistemic context.
    ContextEntryAdded {
        entry_id: String,
        actor_id: String,
        kind:     ContextEntryKind,
        content:  String,
        added_at: DateTime<Utc>,
    },

    /// A context entry was marked resolved.
    ContextEntryResolved {
        entry_id:    String,
        resolved_by: String,
        note:        Option<String>,
        resolved_at: DateTime<Utc>,
    },

    /// An artifact was created.
    ArtifactCreated {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
        created_at:    DateTime<Utc>,
    },

    /// An artifact's content was updated.
    ///
    /// Name-only projection, matching `ws.rs`'s own `apply_event` — the
    /// update event carries `artifact_type` but the hub doesn't currently
    /// project a type change either. Kept at parity rather than fixed here.
    ArtifactUpdated {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
        updated_at:    DateTime<Utc>,
    },

    /// An artifact was deleted.
    ///
    /// Carries `name`/`artifact_type` even though the delete itself doesn't
    /// need them (the DB row is just gone) — the caller (`delete_artifact`)
    /// already fetches them before deleting for its own event payload, and
    /// `session_broadcast::to_ws_payload`'s `ArtifactPayload` requires a name.
    ArtifactDeleted {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
        deleted_at:    DateTime<Utc>,
    },

    // ── Projection algebra ────────────────────────────────────────────────────

    /// A session snapshot was checkpointed at the given cursor.
    SnapshotCreated {
        snapshot_seq: i64,
        created_at:   DateTime<Utc>,
    },

    /// A previously valid snapshot was invalidated (e.g., membership change).
    SnapshotInvalidated {
        reason:         String,
        invalidated_at: DateTime<Utc>,
    },

    // ── Saga algebra (cross-session coordination) ─────────────────────────────

    /// A multi-step coordination saga was initiated in this session.
    ///
    /// The `steps` field embeds the full saga spec so cold replay can
    /// reconstruct the `SagaRecord` without any external lookup.
    /// `metadata` carries policy parameters (e.g. `policy`, `eligible`)
    /// needed to reconstruct the typed `SessionSaga` discriminant in
    /// `live_saga_ack` without any external lookup.
    SagaBegun {
        saga_id:   String,
        /// Discriminator: "approval" | "ownership_transfer" | "custom"
        saga_type: String,
        steps:     Vec<SagaStepSpec>,
        begun_at:  DateTime<Utc>,
        /// Type-specific parameters for reducer reconstruction on replay.
        /// Approval: `{ "policy": "...", "eligible": N, "approval_id": "..." }`
        /// OwnershipTransfer: `{ "from_session": "...", "to_session": "..." }`
        /// Custom / unknown: `{}`
        metadata:  serde_json::Value,
    },

    /// The coordinator dispatched a forward step to a participant session.
    SagaStepSent {
        saga_id:     String,
        step_idx:    usize,
        participant: String,
        sent_at:     DateTime<Utc>,
    },

    /// A participant returned an outcome for their step.
    SagaStepAcked {
        saga_id:  String,
        step_idx: usize,
        outcome:  SagaOutcome,
        acked_at: DateTime<Utc>,
    },

    /// A compensation message was dispatched for a previously-committed step
    /// during the abort path (backward traverse, reverse order).
    SagaCompensated {
        saga_id:  String,
        step_idx: usize,
        sent_at:  DateTime<Utc>,
    },

    /// The saga reached a terminal state (Completed or Aborted).
    SagaTerminated {
        saga_id:       String,
        outcome:       SagaTermination,
        terminated_at: DateTime<Utc>,
    },

    // ── Policy algebra (adapter intercept) ────────────────────────
    //
    // These events form the sixth sub-algebra.  Historical reason (why a
    // disposition was taken) lives here in the event log; current reason (what
    // is presently gated) lives in `SessionMemory::gated_bundles`.  This split
    // mirrors the act / ask CLI separation: `sp policy set` emits events,
    // `sp reflect policy` reads the snapshot.

    /// Bundle transport metadata was annotated by the adapter layer.
    BundleAnnotated {
        bundle_id: String,
        metadata:  serde_json::Value,
    },

    /// Bundle transport fields were reshaped by the adapter layer.
    ///
    /// `BundleKind` inner payload is structurally preserved — only routing,
    /// TTL, and tracing metadata are modifiable via `BundleTransport`.
    BundleReshaped {
        bundle_id: String,
        transport: BundleTransport,
        reason:    String,
    },

    /// Bundle delivery was deferred by the adapter layer.
    ///
    /// `defer_until_ms` is epoch-ms (not `Instant`) so this event is
    /// replayable on cold restart.  The transition function re-arms a
    /// `SetTimer` for the remaining duration; if the deadline has already
    /// passed it delivers immediately (1 ms minimum).
    BundleDeferred {
        bundle_id:          String,
        defer_until_ms:     u64,
        interceptor_cap_id: String,
    },

    /// Bundle was rejected by the adapter layer and will not be delivered.
    BundleRejected {
        bundle_id:          String,
        reason:             String,
        interceptor_cap_id: String,
    },

    /// Bundle delivery is gated on a human `ApprovalGranted` event.
    ///
    /// The reflector holds the bundle at its cursor; `ApprovalGranted`
    /// triggers re-delivery.  The participant session sees `BundleReceived`
    /// without knowing a human approved it — meta level governs base level
    /// transparently (RODS §4.2, FMOA object adapter pattern).
    BundleApprovalGated {
        bundle_id:          String,
        approval_id:        String,
        interceptor_cap_id: String,
    },

    /// A delivery policy was set or updated for a class of inbound bundles.
    ///
    /// `target` identifies which bundle class is affected; `constraint` is
    /// the new rule.  Setting `Forward` explicitly clears a prior constraint.
    ///
    /// This is the "act" side of the act/ask CLI split:
    /// - `sp policy set bundle.step require_approval` → writes this event.
    /// - `sp reflect policy` → reads `SessionMemory::policies` (the snapshot).
    PolicySet {
        target:     PolicyTarget,
        constraint: PolicyConstraint,
        /// Cap ID of the sidecar that issued the policy change.
        set_by_cap: String,
        set_at:     chrono::DateTime<chrono::Utc>,
    },
}

impl SessionEvent {
    /// The algebra this event belongs to — used for logging and future routing.
    pub fn algebra(&self) -> &'static str {
        match self {
            SessionEvent::SessionCreated { .. }
            | SessionEvent::SessionPaused { .. }
            | SessionEvent::SessionResumed { .. }
            | SessionEvent::SessionArchived { .. } => "lifecycle",

            SessionEvent::ParticipantJoined { .. }
            | SessionEvent::ParticipantLeft { .. }
            | SessionEvent::OwnershipTransferred { .. }
            | SessionEvent::AgentAttached { .. }
            | SessionEvent::AgentDetached { .. } => "participation",

            SessionEvent::CapDelegated { .. }
            | SessionEvent::CapRevoked { .. }
            | SessionEvent::EpochAdvanced { .. } => "cap",

            SessionEvent::ApprovalRequested { .. }
            | SessionEvent::ApprovalClaimed { .. }
            | SessionEvent::ApprovalVoted { .. }
            | SessionEvent::ApprovalGranted { .. }
            | SessionEvent::ApprovalDenied { .. }
            | SessionEvent::ApprovalExpired { .. }
            | SessionEvent::ApprovalInterrupted { .. }
            | SessionEvent::ApprovalCancelled { .. }
            | SessionEvent::ApprovalDelegated { .. }
            | SessionEvent::ApprovalDisputed { .. }
            | SessionEvent::CrossSessionDelegationRequested { .. }
            | SessionEvent::CrossSessionDelegationReceived { .. }
            | SessionEvent::CrossSessionDelegationResolved { .. } => "approval",

            SessionEvent::EffectProposed { .. }
            | SessionEvent::EffectScouted { .. }
            | SessionEvent::EffectAttested { .. }
            | SessionEvent::EffectCommitted { .. }
            | SessionEvent::EffectDiverged { .. }
            | SessionEvent::MessagePosted { .. }
            | SessionEvent::ContextEntryAdded { .. }
            | SessionEvent::ContextEntryResolved { .. }
            | SessionEvent::ArtifactCreated { .. }
            | SessionEvent::ArtifactUpdated { .. }
            | SessionEvent::ArtifactDeleted { .. }
            | SessionEvent::CrossSessionArtifactImportReceived { .. }
            | SessionEvent::CrossSessionContextReceived { .. }
            | SessionEvent::CrossSessionAnnotationReceived { .. } => "effect",

            SessionEvent::SnapshotCreated { .. }
            | SessionEvent::SnapshotInvalidated { .. } => "projection",

            SessionEvent::SagaBegun { .. }
            | SessionEvent::SagaStepSent { .. }
            | SessionEvent::SagaStepAcked { .. }
            | SessionEvent::SagaCompensated { .. }
            | SessionEvent::SagaTerminated { .. } => "saga",

            SessionEvent::BundleAnnotated     { .. }
            | SessionEvent::BundleReshaped    { .. }
            | SessionEvent::BundleDeferred    { .. }
            | SessionEvent::BundleRejected    { .. }
            | SessionEvent::BundleApprovalGated { .. }
            | SessionEvent::PolicySet           { .. } => "policy",
        }
    }

    /// The `AlgebraMask` bit for this event.
    ///
    /// Every event sets exactly one bit.  Use this for projection cache
    /// invalidation: `event.algebra_mask().intersects(projection.depends_on)`.
    pub fn algebra_mask(&self) -> AlgebraMask {
        match self.algebra() {
            "lifecycle"   => AlgebraMask::LIFECYCLE,
            "participation" | "membership" => AlgebraMask::MEMBERSHIP,
            "cap"         => AlgebraMask::AUTHORITY,
            "approval"    => AlgebraMask::APPROVAL,
            "effect"      => AlgebraMask::EFFECT,
            "projection"  => AlgebraMask::PROJECTION,
            "saga"        => AlgebraMask::SAGA,
            "policy"      => AlgebraMask::POLICY,
            // Unknown algebra — conservative: treat as invalidating everything.
            _             => AlgebraMask::all(),
        }
    }

    /// The `"type"` field value as it appears in the serialized JSON.
    ///
    /// Equivalent to `payload["type"].as_str()` after `serde_json::to_value`,
    /// but without allocating the intermediate `Value` tree.  Use this whenever
    /// only the type discriminator is needed (e.g. `session_events.type` column).
    ///
    /// The returned string is the variant name under `rename_all = "snake_case"`.
    pub fn type_name(&self) -> &'static str {
        match self {
            SessionEvent::SessionCreated    { .. } => "session_created",
            SessionEvent::SessionPaused     { .. } => "session_paused",
            SessionEvent::SessionResumed    { .. } => "session_resumed",
            SessionEvent::SessionArchived   { .. } => "session_archived",
            SessionEvent::ParticipantJoined { .. } => "participant_joined",
            SessionEvent::ParticipantLeft   { .. } => "participant_left",
            SessionEvent::OwnershipTransferred { .. } => "ownership_transferred",
            SessionEvent::AgentAttached     { .. } => "agent_attached",
            SessionEvent::AgentDetached     { .. } => "agent_detached",
            SessionEvent::CapDelegated      { .. } => "cap_delegated",
            SessionEvent::CapRevoked        { .. } => "cap_revoked",
            SessionEvent::EpochAdvanced     { .. } => "epoch_advanced",
            SessionEvent::ApprovalRequested  { .. } => "approval_requested",
            SessionEvent::ApprovalClaimed   { .. } => "approval_claimed",
            SessionEvent::ApprovalVoted     { .. } => "approval_voted",
            SessionEvent::ApprovalGranted   { .. } => "approval_granted",
            SessionEvent::ApprovalDenied    { .. } => "approval_denied",
            SessionEvent::ApprovalExpired   { .. } => "approval_expired",
            SessionEvent::ApprovalInterrupted { .. } => "approval_interrupted",
            SessionEvent::ApprovalCancelled { .. } => "approval_cancelled",
            SessionEvent::ApprovalDelegated { .. } => "approval_delegated",
            SessionEvent::ApprovalDisputed  { .. } => "approval_disputed",
            SessionEvent::CrossSessionDelegationRequested { .. } => "cross_session_delegation_requested",
            SessionEvent::CrossSessionDelegationReceived  { .. } => "cross_session_delegation_received",
            SessionEvent::CrossSessionDelegationResolved  { .. } => "cross_session_delegation_resolved",
            SessionEvent::CrossSessionArtifactImportReceived { .. } => "cross_session_artifact_import_received",
            SessionEvent::CrossSessionContextReceived { .. } => "cross_session_context_received",
            SessionEvent::CrossSessionAnnotationReceived { .. } => "cross_session_annotation_received",
            SessionEvent::EffectProposed    { .. } => "effect_proposed",
            SessionEvent::EffectScouted     { .. } => "effect_scouted",
            SessionEvent::EffectAttested    { .. } => "effect_attested",
            SessionEvent::EffectCommitted   { .. } => "effect_committed",
            SessionEvent::EffectDiverged    { .. } => "effect_diverged",
            SessionEvent::MessagePosted        { .. } => "message_posted",
            SessionEvent::ContextEntryAdded    { .. } => "context_entry_added",
            SessionEvent::ContextEntryResolved { .. } => "context_entry_resolved",
            SessionEvent::ArtifactCreated      { .. } => "artifact_created",
            SessionEvent::ArtifactUpdated      { .. } => "artifact_updated",
            SessionEvent::ArtifactDeleted      { .. } => "artifact_deleted",
            SessionEvent::SnapshotCreated   { .. } => "snapshot_created",
            SessionEvent::SnapshotInvalidated { .. } => "snapshot_invalidated",
            SessionEvent::SagaBegun             { .. } => "saga_begun",
            SessionEvent::SagaStepSent          { .. } => "saga_step_sent",
            SessionEvent::SagaStepAcked         { .. } => "saga_step_acked",
            SessionEvent::SagaCompensated       { .. } => "saga_compensated",
            SessionEvent::SagaTerminated        { .. } => "saga_terminated",
            SessionEvent::BundleAnnotated       { .. } => "bundle_annotated",
            SessionEvent::BundleReshaped        { .. } => "bundle_reshaped",
            SessionEvent::BundleDeferred        { .. } => "bundle_deferred",
            SessionEvent::BundleRejected        { .. } => "bundle_rejected",
            SessionEvent::BundleApprovalGated   { .. } => "bundle_approval_gated",
            SessionEvent::PolicySet             { .. } => "policy_set",
        }
    }

    /// Whether replaying this event might change the session lifecycle state.
    pub fn is_lifecycle_change(&self) -> bool {
        matches!(
            self,
            SessionEvent::SessionCreated { .. }
                | SessionEvent::SessionPaused { .. }
                | SessionEvent::SessionResumed { .. }
                | SessionEvent::SessionArchived { .. }
                | SessionEvent::EpochAdvanced { .. }
        )
    }
}
