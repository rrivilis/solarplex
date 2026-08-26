//! `session` — pure session state machine for Solarplex.
//!
//! # Architecture
//!
//! The single entrypoint is the pure transition function:
//!
//! ```text
//! transition(state, memory, event) → (state', memory', Vec<Effect>)
//! ```
//!
//! This crate has **zero tokio / axum / sqlx dependencies** by design.
//! The transition function is synchronous and allocation-only (BTreeMap / Vec).
//! This makes proptest testing trivial: no async runtime, no mocks, no fixtures.
//!
//! # The three machines
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Machine 1: Session Machine (this crate)                    │
//! │  transition(SessionState, SessionMemory, InboundEvent)      │
//! │  → (SessionState', SessionMemory', Vec<Effect>)             │
//! │                                                             │
//! │  Replayed events fold into memory (deterministic).          │
//! │  Live events emit Effects (non-deterministic outcomes).     │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Machine 2: Transport / Projection Machine (server crate)   │
//! │  Per-subscriber delivery cursors, WS fanout, backfill.      │
//! │  Interprets: Send, Broadcast, CloseConnection effects.      │
//! └─────────────────────────────────────────────────────────────┘
//!
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Machine 3: Effect Dispatch Machine (server + sidecar)      │
//! │  Ring-0 CAS, Ring-1 attest, Ring-2 scout / manifest.        │
//! │  Interprets: Persist, SetTimer, CancelTimer, PersistSnapshot│
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # The four sub-algebras
//!
//! The session machine eventually encodes four event sub-algebras,
//! each with its own graph rewrite rules on the bigraphical session model:
//!
//! | Algebra      | Events (partial)                                   |
//! |--------------|---------------------------------------------------|
//! | Participation| attach, leave, reconnect, detach                  |
//! | Approval     | request, claim, vote, grant, deny, expire, interrupt |
//! | Effect       | propose, scout, attest, commit, diverge           |
//! | Projection   | snapshot, invalidate                              |
//!
//! The cap sub-algebra (delegate, revoke, epoch_advance) is the graph rewrite
//! foundation that the others compose on top of.

pub mod arena;
pub mod effects;
pub mod events;
pub mod inbound;
pub mod memory;
pub mod rate_limit;
pub mod saga;
pub mod state;
pub mod transition;

pub use arena::{BumpWriter, SessionArena};
pub use effects::{BundleDisposition, BundleKind, Effect, ReflectorCursor, SagaBundle, TimerId};
pub use events::{
    AlgebraMask, BundleTransport, PolicyConstraint, PolicyTarget, SagaOutcome, SagaStepSpec,
    SagaTermination, SessionEvent, SNAPSHOT_DEPENDS_ON,
};
pub use inbound::{DisconnectReason, InboundEvent, LiveEvent, VoteDecision};
pub use memory::{
    build_snapshot, ApprovalRecord, ApprovalStatus, CapRecord, GateKind, GatedBundle, MemberRecord,
    ProposalRecord, SagaRecord, SagaStatus, SessionMemory,
};
pub use rate_limit::{Admission, FixedWindowBucket, Policy, RateLimitKey};
pub use saga::{ApprovalSaga, ProtocolOutcome, SagaProtocol, SessionSaga, TransferSaga};
pub use state::SessionState;
pub use transition::transition;
