//! `InboundEvent` — inputs to the session transition function.
//!
//! Every event that can cause a state transition arrives as one of two forms:
//!
//! - `Replayed` — a past event being replayed from the persisted event log.
//!   The machine MUST NOT produce `Persist` effects for these (they are already
//!   in the log).  Processing a replayed event only advances `SessionMemory`.
//!
//! - `Live(LiveEvent)` — a real-time event arriving from the runtime (WS
//!   connect/disconnect, timer fire, vote cast, etc.).  The machine MAY produce
//!   `Persist` effects.
//!
//! This split is the key invariant that makes event-sourced replay deterministic.
//! See `transition.rs` and the `proptest_invariants` test.

use protocol::types::ContextEntryKind;
use serde::{Deserialize, Serialize};
use crate::effects::{ReflectorCursor, SagaBundle};
use crate::events::{SessionEvent, SagaOutcome, SagaStepSpec};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InboundEvent {
    /// An event being replayed from the persisted event log during startup or
    /// after a crash.  The seq is the DB-assigned sequence number.
    Replayed {
        seq:   i64,
        event: SessionEvent,
    },

    /// A real-time event from the runtime.
    Live(LiveEvent),
}

/// Real-time events that arrive during normal operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LiveEvent {
    // ── Actor connection lifecycle ────────────────────────────────────────────

    /// An actor established a WebSocket connection.
    ActorConnected {
        actor_id:      String,
        connection_id: String,
    },

    /// An actor's WebSocket connection was closed.
    ActorDisconnected {
        actor_id:      String,
        connection_id: String,
        reason:        DisconnectReason,
    },

    /// An actor reconnected after a transient network drop.
    ActorReconnected {
        actor_id:          String,
        new_connection_id: String,
    },

    // ── Approval votes ────────────────────────────────────────────────────────

    /// A human actor cast a vote on a pending approval.
    VoteCast {
        approval_id: String,
        voter_id:    String,
        decision:    VoteDecision,
    },

    // ── Timer ─────────────────────────────────────────────────────────────────

    /// A previously armed timer fired.
    TimerFired {
        id: String,
    },

    // ── Ownership ─────────────────────────────────────────────────────────────

    /// The session owner transferred ownership to another actor.
    ///
    /// Currently always shadow-persisted (see `is_machine_autonomous` in
    /// `session_task.rs`) — `routes/sessions.rs::transfer_ownership` remains
    /// the authoritative writer and broadcaster; this feed exists so the
    /// machine's own memory (`owner_id`, `eligible_approvers`) stays correct
    /// without waiting for cold replay.
    OwnershipTransfer {
        from: String,
        to:   String,
    },

    // ── Approval claim ────────────────────────────────────────────────────────

    /// A human claimed a pending approval to review it.
    ///
    /// Currently always shadow-persisted, same reasoning as `OwnershipTransfer`
    /// above — `ws.rs::handle_approval_claim` remains the authoritative writer.
    ApprovalClaim {
        approval_id: String,
        actor_id:    String,
    },

    /// A human cancelled their own pending approval request. Shadow-persisted
    /// — see `ApprovalClaim`'s doc comment for why.
    ApprovalCancel {
        approval_id: String,
        actor_id:    String,
    },

    /// An approval was delegated to another actor for review. Shadow-persisted.
    ApprovalDelegate {
        approval_id: String,
        from:        String,
        to:          String,
    },

    /// An approval decision was disputed. Shadow-persisted.
    ApprovalDispute {
        approval_id: String,
        actor_id:    String,
        reason:      String,
    },

    /// Begin a cross-session approval delegation: session A asks session B
    /// to decide `approval_id` on its behalf. Distinct from `ApprovalDelegate`
    /// above (intra-session, another actor in the same session).
    ///
    /// Wraps `live_saga_begin` with a single-step `SessionSaga::Custom` saga
    /// whose step message carries `{"kind":"cross_session_delegation",
    /// "approval_id":..., "arguments":...}` — the target session's own
    /// `live_bundle_received` recognizes this kind and (via server-side glue
    /// in `session_task.rs`, since creating a real `ApprovalRequest` row is
    /// an async DB operation the pure machine can't perform) creates a real,
    /// normal local approval there. B's members decide using B's own
    /// approval_policy, entirely unchanged — the saga is purely the
    /// plumbing connecting A's original approval to B's synthetic one.
    CrossSessionDelegate {
        /// Caller-supplied — `crates/session` has no ulid/rand dependency by
        /// design (see `SagaBundle::bundle_id`'s own doc comment), so IDs
        /// here are always minted server-side and passed in, never generated.
        saga_id:           String,
        approval_id:       String,
        target_session_id: String,
        requested_by:      String,
        arguments:         serde_json::Value,
    },

    // ── Content sub-shape ─────────────────────────────────────────────────────
    //
    // All shadow-persisted (see is_machine_autonomous) — ws.rs/routes/sessions.rs
    // remain the authoritative writers. `entry_id`/`artifact_id` are always
    // caller-supplied (the ID the real write path already minted or the DB
    // already assigned) — the machine never invents IDs for content it isn't
    // the write-owner of.

    /// A human or agent posted a message to the session.
    MessagePost {
        actor_id: String,
        content:  String,
    },

    /// A typed entry was added to the session's shared epistemic context.
    ContextAdd {
        entry_id: String,
        actor_id: String,
        kind:     ContextEntryKind,
        content:  String,
    },

    /// A context entry was marked resolved.
    ContextResolve {
        entry_id:    String,
        resolved_by: String,
        note:        Option<String>,
    },

    /// An artifact was created.
    ArtifactCreate {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
    },

    /// An artifact's content was updated.
    ArtifactUpdate {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
    },

    /// An artifact was deleted. `name`/`artifact_type` are carried through
    /// from the caller (who already fetched them before deleting) — see
    /// `SessionEvent::ArtifactDeleted`'s doc comment for why.
    ArtifactDelete {
        artifact_id:   String,
        actor_id:      String,
        name:          String,
        artifact_type: Option<String>,
    },

    // ── Admin / session owner ─────────────────────────────────────────────────

    /// An admin or owner requested the session be paused.
    AdminPause {
        by:     String,
        reason: Option<String>,
    },

    /// An admin or owner requested the session be resumed from pause.
    AdminResume {
        by: String,
    },

    /// An admin or owner requested the session be permanently archived.
    AdminArchive {
        by: String,
    },

    // ── Sidecar events ────────────────────────────────────────────────────────

    /// A sidecar agent is requesting to attach with the given cap.
    SidecarAttach {
        actor_id: String,
        cap_id:   String,
    },

    /// A sidecar agent is voluntarily detaching.
    SidecarDetach {
        actor_id: String,
        reason:   Option<String>,
    },

    // ── Approval creation ─────────────────────────────────────────────────────

    /// An agent is creating a new approval request (Ring-2 human gate).
    ///
    /// The machine validates the requesting actor's cap, emits
    /// `Persist(ApprovalRequested)`, and arms an expiry timer.
    /// The server feeds this event from `POST /api/approvals` after the
    /// DB insert so the machine stays in sync without a WS round-trip.
    ApprovalCreate {
        approval_id: String,
        actor_id:    String,
        tool:        String,
        args:        serde_json::Value,
        /// Expiry window in milliseconds (None = no expiry timer armed).
        expires_ms:  Option<u64>,
    },

    // ── Inter-session routing ─────────────────────────────────────────────────

    /// A message forwarded from another session node via `Effect::Forward`.
    ///
    /// Inbound DOF coupling: Session A emitted `Forward { to_session: self }`;
    /// the runtime delivered it here as `ForwardedMessage { from_session: A }`.
    ///
    /// The receiving machine routes the payload to the appropriate domain handler
    /// based on payload type (saga step request, ownership transfer negotiation,
    /// etc.).  Routing is done in `live_forwarded_message` in `transition.rs`.
    ForwardedMessage {
        from_session: String,
        payload:      serde_json::Value,
    },

    // ── Saga coordination ─────────────────────────────────────────────────────

    /// Initiate a multi-step saga coordination protocol in this session.
    ///
    /// The machine records the saga, dispatches the first step to its
    /// participant, and arms a per-step timeout timer.
    SagaBegin {
        saga_id:   String,
        /// Discriminator: "approval" | "ownership_transfer" | "custom"
        saga_type: String,
        steps:     Vec<SagaStepSpec>,
        /// Type-specific policy parameters forwarded verbatim into `SagaBegun`
        /// so the reducer can be reconstructed from the event log on cold replay.
        metadata:  serde_json::Value,
    },

    /// A participant session acknowledged a saga step.
    ///
    /// Drives the saga forward (Committed) or triggers the compensating
    /// backward path (Rejected).  Also delivered internally when a step
    /// timer fires (treated as `Rejected { reason: "timed out" }`).
    SagaAck {
        saga_id:  String,
        step_idx: usize,
        outcome:  SagaOutcome,
    },

    // ── Bundle relay ──────────────────────────────────────────────────────────

    /// A `SagaBundle` intercepted by the FMOA adapter layer before delivery.
    ///
    /// Sent by `route_bundle` in place of `BundleReceived`.  The session machine
    /// decides the `BundleDisposition` (Forward / Defer / Reject / Reshape /
    /// ApprovalPending / Annotate) and emits the appropriate `PolicyEvent` for
    /// the audit log plus follow-up effects (`BundleDeliver`, `SetTimer`, etc.).
    ///
    /// `interceptor_cap_id` identifies the sidecar cap that registered the
    /// intercept policy; empty string means session-default policy (no specific
    /// cap constraint active).
    BundleIntercepted {
        bundle:             SagaBundle,
        interceptor_cap_id: String,
        /// Position in the reflector log at which this bundle was appended.
        ///
        /// Carried alongside the bundle so that `GatedBundle` can store the
        /// cursor as a fallback foothold: if the session restarts before a
        /// deferred or approval-gated bundle is delivered, the cursor provides
        /// the exact log position for re-fetch from a durable reflector (Phase 6+).
        reflector_cursor:   ReflectorCursor,
    },

    /// A `SagaBundle` ready for delivery to the saga machine.
    ///
    /// Emitted into `self_tx` by the server task when `Effect::BundleDeliver`
    /// is processed — after the adapter layer has resolved its disposition.
    /// The session's bundle unwrapper validates authority (cap_id check for
    /// `BundleKind::Ack`, TTL re-check for all variants) before routing to
    /// the appropriate saga handler.
    BundleReceived {
        bundle: SagaBundle,
    },
}

/// Why an actor's connection was closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisconnectReason {
    ClientClose,
    NetworkError,
    ServerClose,
    Timeout,
    /// Connection was closed because the actor's cap was fenced.
    Fenced,
}

/// A vote cast on an approval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteDecision {
    Approve,
    Deny,
}
