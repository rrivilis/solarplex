//! `Effect` — the output alphabet of the session transition function.
//!
//! The runtime (server crate) interprets effects after every `transition()` call.
//! The transition function never performs I/O directly, it only returns effects.
//!
//! ## The loggable / non-loggable split
//!
//! `Persist(SessionEvent)` is the only effect that writes to the event log.
//! It MUST NOT appear in effects produced by a `Replayed` transition.
//!
//! All other effects are runtime commands — ephemeral, not replayed.  Their
//! outcome is reflected in subsequent loggable events (e.g., a `Send` causes a
//! response that arrives as a new `InboundEvent::Live`).
//!
//! ## Routing planes
//!
//! There are two distinct message-routing planes, typed at the Effect level:
//!
//! | Effect    | Routing plane   | Keyed by    | Mechanism                        |
//! |-----------|-----------------|-------------|----------------------------------|
//! | `Send`    | Intra-session   | `actor_id`  | WebSocket sender map in SessionHub |
//! | `Forward` | Inter-session   | `session_id`| Session task mailbox in AppState |
//!
//!
//! ## Runtime protocol
//!
//! 1. Call `transition(state, memory, event)`.
//! 2. For each effect in order:
//!    - `Persist(e)` → write `e` to DB with next seq, then immediately call
//!      `transition(state', memory', Replayed { seq, event: e })` to sync memory.
//!    - `Send { to_actor, payload }` → forward to the WS sender for `to_actor`.
//!    - `Forward { to_session, payload }` → deliver to the target session's
//!      task mailbox as `LiveEvent::ForwardedMessage`; the target need not have
//!      any active WebSocket connections.
//!    - `Broadcast { payload }` → forward to all connected actor senders.
//!    - `SetTimer { id, duration_ms }` → arm a tokio sleep; on fire, call
//!      `transition(…, Live(TimerFired { id }))`.
//!    - `CancelTimer { id }` → drop the armed JoinHandle for `id` (no-op if absent).
//!    - `CloseConnection { actor_id, code, reason }` → send WS close frame.
//!    - `PersistSnapshot` → serialize current `SessionMemory` to DB snapshot table,
//!      then feed back `Replayed(SnapshotCreated { snapshot_seq: cursor })`.

use serde::{Deserialize, Serialize};
use crate::events::{BundleTransport, SessionEvent};

// ── Bundle relay types ────────────────────────────────────────────────────────

/// Discriminates the semantic role of a cross-session bundle.
///
/// - `Step` carries a forward saga step from coordinator → participant.
///   `compensation` is the rollback message to execute if the step is later
///   rejected (coordinator holds it; participant never sees it directly).
///
/// - `Compensation` carries a rollback request from coordinator → participant
///   after a downstream step was rejected.
///
/// - `Ack` is the participant → coordinator reply.  It carries `cap_id` so
///   the bundle unwrapper in the *coordinator* session can validate authority
///   before calling `live_saga_ack`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BundleKind {
    /// Forward saga step.
    Step {
        /// The message to deliver to the participant session.
        message:      serde_json::Value,
        /// Rollback payload stored on the coordinator for use if this step is
        /// later compensated.  Opaque to the participant.
        compensation: serde_json::Value,
    },
    /// Compensating rollback dispatched in reverse order.
    Compensation {
        message: serde_json::Value,
    },
    /// Acknowledgement from participant back to coordinator.
    Ack {
        outcome: crate::events::SagaOutcome,
        /// The cap that authorised the participant's decision.
        /// Validated by the coordinator's bundle unwrapper before being
        /// forwarded to `live_saga_ack`; the reducer never sees an invalid cap.
        cap_id:  String,
    },
}

/// A typed cross-session relay packet.
///
/// `SagaBundle` is the first-class runtime object that flows through the
/// reflector (append-only ordered log) between session tasks.  The reflector
/// assigns a monotonic `seq` to each bundle at `append` time; that seq is the
/// basis for `replay(from_seq)` and for cursor-based delivery on reconnect.
///
/// Authority model
/// ───────────────
/// Caps are validated in the *bundle unwrapper* (the entry-point of the
/// receiving session task) before any state transition occurs.  `SagaProtocol`
/// itself is a pure state machine that only runs after authority is established.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SagaBundle {
    /// Stable ULID assigned by the emitting session at emit time.
    pub bundle_id:    String,
    pub saga_id:      String,
    pub step_idx:     usize,
    /// The session that produced this bundle.
    pub from_session: String,
    /// The session that should receive and process this bundle.
    pub to_session:   String,
    pub kind:         BundleKind,
    /// Hard expiry in milliseconds from epoch.  The reflector drops bundles
    /// past their TTL on `replay`; the unwrapper re-checks on delivery.
    pub ttl_ms:       u64,
}

/// A typed position in the global bundle reflector log.
///
/// Replaces bare `i64` sequence numbers so that epoch and view mismatches
/// (after compaction, shard migration, or a membership change) are caught
/// at the type level rather than producing silent stale-cursor replays.
///
/// # Two independent staleness axes
///
/// `epoch` and `view` are invalidated by different events and call for
/// different recovery, which is why they're separate fields rather than one
/// combined generation counter:
///
/// - **`epoch`** — incremented by `Reflector::compact`. A cursor from epoch
///   `N` presented at epoch `M > N` means *this replica's own local history
///   was pruned* out from under the cursor. Recovery: relocalize — fall
///   back to full replay from seq 0 (or, on a replica that no longer has
///   that history, ask one that does) so no live bundles are silently
///   skipped. This is the SLAM loop-closure equivalent: stale pose →
///   relocalize.
/// - **`view`** — a membership generation. A stale view means *the set of
///   replicas the caller should even be talking to has changed* — who
///   currently owns what may be totally different, independent of whether
///   any local history was pruned. Recovery: revalidate against current
///   membership before trusting `epoch` at all. No membership protocol
///   exists yet (single replica, view is always `0`), so this is currently
///   a no-op check — the field and the distinction exist so a real
///   membership layer has something to compare against later instead of
///   overloading `epoch` for two unrelated kinds of staleness.
///
/// # Observer-relative framing
///
/// The pair `(session_id, ReflectorCursor)` is an observational frame: it
/// identifies *who* is observing and *where* in the causal history they last
/// looked.  Moving a cursor between nodes is cheaper than moving a bundle or
/// saga — bytes vs kilobytes — which makes cursor gossip the right primitive
/// for partition healing and saga migration rendezvous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReflectorCursor {
    /// Monotonic position in the reflector log.  `replay(cursor)` returns
    /// all bundles with `seq > cursor.seq` that have not expired.
    pub seq:   i64,
    /// Reflector epoch — incremented on compaction / shard migration.
    /// Stale epoch → full replay (relocalize).
    pub epoch: u32,
    /// Membership generation. Stale view → revalidate against current
    /// membership. See the struct doc for why this is separate from `epoch`.
    pub view:  u32,
}

impl ReflectorCursor {
    /// The zero cursor: no bundles seen, epoch 0, view 0.  Pass to `replay`
    /// to drain the entire live log from the beginning.
    pub const fn zero() -> Self {
        Self { seq: 0, epoch: 0, view: 0 }
    }

    /// Advance this cursor to a new position (same epoch, same view).
    pub fn advance(self, seq: i64) -> Self {
        Self { seq, ..self }
    }
}

/// Adapter-layer decision on how to handle an inbound `SagaBundle`.
///
/// Produced by the session machine's `live_bundle_intercepted` handler and
/// consumed immediately — not itself persisted.  The *consequences* of each
/// variant are persisted as policy `SessionEvent`s (`BundleDeferred`,
/// `BundleAnnotated`, etc.) so the policy sub-algebra remains fully replayable.
///
/// # Replayability constraint
///
/// `Defer` stores `until_ms: u64` (epoch-ms) rather than `std::time::Instant`
/// so the decision can be reconstructed on cold replay from the logged
/// `BundleDeferred` event.  On replay: if now ≥ until_ms, deliver immediately;
/// otherwise re-arm `SetTimer` for the remaining duration.
///
/// # Reshape scope
///
/// `Reshape` accepts only a `BundleTransport` — the adapter may modify routing,
/// TTL, and tracing metadata, but CANNOT touch `BundleKind` inner payload
/// (outcome, message, compensation).  This constraint is structural, not
/// conventional: `BundleTransport` simply does not expose those fields.
#[derive(Debug, Clone)]
pub enum BundleDisposition {
    /// Pass the bundle through to `BundleReceived` without modification.
    Forward,
    /// Hold delivery until epoch-ms `until_ms`.  Logged as `BundleDeferred`.
    Defer { until_ms: u64 },
    /// Drop the bundle permanently.  Logged as `BundleRejected` for audit.
    Reject { reason: String },
    /// Modify transport fields (routing, TTL, annotations) before delivery.
    Reshape { transport: BundleTransport },
    /// Gate on a human `ApprovalGranted` event.  Logged as `BundleApprovalGated`.
    ApprovalPending { approval_id: String },
    /// Attach tracing / QoS metadata and forward.  Logged as `BundleAnnotated`.
    Annotate { metadata: serde_json::Value },
}

/// A timer identifier — stable across the session lifetime.
/// Convention: `"approval:<approval_id>"`, `"bundle_defer:<bundle_id>"`.
pub type TimerId = String;

/// Output command from the session transition function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Effect {
    // ── Event log ─────────────────────────────────────────────────────────────

    /// Write a new event to the session event log.
    ///
    /// The runtime assigns the next sequence number, persists the event,
    /// then calls `transition(state', memory', Replayed { seq, event })` so the
    /// in-memory state always mirrors the DB.
    ///
    /// **Critical**: MUST NOT be produced by a `Replayed` transition.
    Persist(SessionEvent),

    // ── Intra-session messaging (actor routing plane) ─────────────────────────

    /// Send a payload to a single actor connected to this session via WebSocket.
    ///
    /// Keyed by `actor_id`.  The runtime looks up the actor's WS sender in the
    /// session hub.  No-op if the actor is not currently connected.
    Send {
        to:      String,   // actor_id
        payload: serde_json::Value,
    },

    /// Broadcast a payload to all actors currently connected to this session.
    Broadcast {
        payload: serde_json::Value,
    },

    // ── Inter-session messaging (session routing plane) ───────────────────────

    /// Route a message to another session node's task mailbox.
    ///
    /// Keyed by `session_id` — distinct from `Send` (actor routing).  The
    /// target session need not have any active WebSocket connections; delivery
    /// goes directly to the session actor's `mpsc` channel.
    ///
    /// In CBFEM terms this is the DOF coupling edge across component boundaries:
    /// Session A emits `Forward { to_session: B }`; the runtime looks up B in
    /// the session (`AppState::sessions`) and delivers the payload as
    /// `LiveEvent::ForwardedMessage { from_session: A, payload }` into B's mailbox.
    ///
    /// Primary use: saga step dispatch (coordinator → participant) and
    /// saga ack routing (participant → coordinator).
    Forward {
        to_session: String,
        payload:    serde_json::Value,
    },

    // ── Timer management ──────────────────────────────────────────────────────

    /// Arm a timer for `duration_ms` milliseconds.
    /// Fires as `LiveEvent::TimerFired { id }`.
    /// Replaces any existing timer with the same ID.
    SetTimer {
        id:          TimerId,
        duration_ms: u64,
    },

    /// Cancel a previously armed timer.  No-op if the timer has already fired
    /// or was never armed.
    CancelTimer {
        id: TimerId,
    },

    // ── Connection management ─────────────────────────────────────────────────

    /// Send a WebSocket close frame to the given actor and drop the handle.
    CloseConnection {
        actor_id: String,
        code:     u16,
        reason:   String,
    },

    // ── Snapshot ──────────────────────────────────────────────────────────────

    /// Serialize the current `SessionMemory` as a snapshot checkpoint.
    /// The runtime persists it, then feeds back `Replayed(SnapshotCreated { … })`.
    PersistSnapshot,

    // ── Bundle relay (cross-session saga protocol) ────────────────────────────

    /// Route a typed `SagaBundle` through the reflector to another session.
    ///
    /// The runtime appends the bundle to the global `Reflector` (which assigns
    /// a monotonic seq), then sends `LiveEvent::BundleIntercepted` to the target
    /// session's mailbox so the FMOA adapter layer can apply its disposition
    /// before the saga machine sees `BundleReceived`.
    ///
    /// Cap validation occurs in the *receiving* session's bundle unwrapper, not
    /// here.  The emitting session is not responsible for the recipient's policy.
    Bundle(SagaBundle),

    /// Deliver a `SagaBundle` to the current session as `LiveEvent::BundleReceived`.
    ///
    /// Emitted by `live_bundle_intercepted` after the adapter disposition resolves
    /// to `Forward`, `Annotate`, or `Reshape`.  The server task handles this by
    /// sending `BundleReceived` to `self_tx` — the bundle re-enters the session's
    /// own mailbox at the back of the FIFO queue after any in-flight events.
    ///
    /// Distinct from `Bundle` (inter-session, via reflector + topology map).
    /// `BundleDeliver` is intra-session only.
    BundleDeliver(SagaBundle),
}

impl Effect {
    /// True if this effect writes to the event log.
    /// Used by the proptest harness to verify the replay invariant.
    pub fn is_persist(&self) -> bool {
        matches!(self, Effect::Persist(_))
    }

    /// True if this effect routes a bundle through the reflector.
    pub fn is_bundle(&self) -> bool {
        matches!(self, Effect::Bundle(_))
    }

    /// True if this effect delivers a bundle to the current session.
    pub fn is_bundle_deliver(&self) -> bool {
        matches!(self, Effect::BundleDeliver(_))
    }
}
