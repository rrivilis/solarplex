//! `SagaProtocol` for cross-session ownership coordination.
//!
//! # CBFEM analogy
//!
//! In CBFEM (Component-Based Finite Element Method), local components own their
//! stiffness matrices exclusively and the sparse matrix reducer operates only at
//! the interface degrees of freedom (DOFs).  The component never touches the
//! global system; the reducer assembles from the boundary.
//!
//! Solarplex maps this as follows:
//!
//! | CBFEM                    | Solarplex                                    |
//! |--------------------------|----------------------------------------------|
//! | Local component          | Session machine (node)                       |
//! | Local stiffness matrix   | `(SessionState, SessionMemory)`              |
//! | Interface DOF            | `SagaStepSpec` — the typed boundary edge     |
//! | Sparse matrix reducer    | `SagaProtocol::reduce()`                     |
//! | Global assembly          | Saga coordinating Session A → B → A         |
//!
//! `reduce()` assembles participant acks (interface DOF contributions) into a
//! `ProtocolOutcome` **without inspecting the interior of any session**.  The
//! session machines never mutate each other; coordination lives entirely at the
//! boundary.
//!
//! # The three concrete impls
//!
//! - [`ApprovalSaga`]: policy-based reduction (`single_vote` / `majority` /
//!   `unanimous`).  Single step; the participant session collects votes and
//!   aggregates them into a single ack before returning an outcome.
//!
//! - [`TransferSaga`]: atomic two-party protocol.  Two steps (lock source,
//!   commit destination); any rejection triggers immediate abort and
//!   compensation of all prior committed steps.
//!
//! - [`SessionSaga`] enum: unified dispatch that routes to the right impl based
//!   on saga type.  Use this as the runtime discriminant.

use crate::events::{SagaOutcome, SagaStepSpec};
use crate::memory::SagaRecord;

// ── Protocol outcome ──────────────────────────────────────────────────────────

/// Result of the protocol reducer assembling participant acks.
///
/// Returned by `SagaProtocol::reduce()` after each incoming ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolOutcome {
    /// Threshold met — advance to the next step, or terminate `Completed` if
    /// this was the last step.
    Advance,
    /// Threshold met for rejection — dispatch compensations in reverse order
    /// and terminate `Aborted`.
    Abort { reason: String },
    /// More acks needed before a decision can be made (contested state).
    Pending,
}

// ── SagaProtocol trait ────────────────────────────────────────────────────────

/// Trait for a structured sequence of ownership edges with a reducer.
///
/// Each impl encodes:
/// - The forward-path step specs (what to send on the commit path).
/// - The policy for reducing participant acks into a `ProtocolOutcome`
///   
///
/// Compensation payloads are embedded in the `SagaStepSpec` fields; the saga
/// coordinator dispatches them automatically on `Abort`.
pub trait SagaProtocol {
    /// Total number of forward steps in this protocol.
    fn step_count(&self) -> usize;

    /// The forward-edge spec for a given step index.
    ///
    /// # Panics
    /// Panics if `idx >= step_count()`.  Callers must bound-check.
    fn step(&self, idx: usize) -> &SagaStepSpec;

    /// Then assemble participant acks into a protocol outcome.
    ///
    /// `acks` contains all acks received so far for `step_idx` (ordering
    /// preserved).  For single-ack protocols, the slice has exactly one element.
    /// For multi-ack protocols (majority, unanimous) it accumulates over time.
    ///
    /// The reducer MUST NOT inspect session state — it only sees acks.
    fn reduce(&self, step_idx: usize, acks: &[SagaOutcome]) -> ProtocolOutcome;

    /// Timeout window for a given step in milliseconds.
    ///
    /// Defaults to the spec's `timeout_ms`; override for dynamic timeout logic.
    fn timeout_ms(&self, step_idx: usize) -> u64 {
        self.step(step_idx).timeout_ms
    }
}

// ── ApprovalSaga ──────────────────────────────────────────────────────────────

/// Single-step approval saga with session-policy-driven reduction.
///
/// The participant session collects votes from eligible approvers and
/// returns a single aggregated ack.  `reduce()` mirrors `evaluate_policy()`
/// in `transition.rs` but operates on the saga ack slice rather than
/// the approval vote map.
#[derive(Debug, Clone)]
pub struct ApprovalSaga {
    pub approval_id: String,
    /// Approval policy slug: "single_vote" | "majority" | "unanimous"
    pub policy: String,
    /// Number of eligible approvers at saga begin time.
    /// Required for majority and unanimous threshold calculations.
    pub eligible: usize,
    pub step: SagaStepSpec,
}

impl SagaProtocol for ApprovalSaga {
    fn step_count(&self) -> usize {
        1
    }

    fn step(&self, _idx: usize) -> &SagaStepSpec {
        &self.step
    }

    fn reduce(&self, _step_idx: usize, acks: &[SagaOutcome]) -> ProtocolOutcome {
        let committed = acks
            .iter()
            .filter(|a| *a == &SagaOutcome::Committed)
            .count();
        let denials = acks
            .iter()
            .filter(|a| matches!(a, SagaOutcome::Rejected { .. }))
            .count();
        let deny_reason = || {
            acks.iter()
                .find_map(|a| {
                    if let SagaOutcome::Rejected { reason } = a {
                        Some(reason.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "denied".into())
        };

        match self.policy.as_str() {
            "single_vote" => {
                if committed > 0 {
                    ProtocolOutcome::Advance
                } else if denials > 0 {
                    ProtocolOutcome::Abort {
                        reason: deny_reason(),
                    }
                } else {
                    ProtocolOutcome::Pending
                }
            }
            "majority" => {
                let threshold = self.eligible / 2 + 1;
                if committed >= threshold {
                    ProtocolOutcome::Advance
                } else if denials >= threshold {
                    ProtocolOutcome::Abort {
                        reason: "denied by majority".into(),
                    }
                } else {
                    ProtocolOutcome::Pending
                }
            }
            "unanimous" => {
                if self.eligible > 0 && committed == self.eligible {
                    ProtocolOutcome::Advance
                } else if denials > 0 {
                    ProtocolOutcome::Abort {
                        reason: deny_reason(),
                    }
                } else {
                    ProtocolOutcome::Pending
                }
            }
            // Unknown policy → fall back to single_vote semantics
            _ => {
                if committed > 0 {
                    ProtocolOutcome::Advance
                } else if denials > 0 {
                    ProtocolOutcome::Abort {
                        reason: deny_reason(),
                    }
                } else {
                    ProtocolOutcome::Pending
                }
            }
        }
    }
}

// ── TransferSaga ──────────────────────────────────────────────────────────────

/// Atomic two-party ownership transfer protocol.
///
/// Two steps in strict order:
/// - Step 0: lock the source session ("begin transfer out").
/// - Step 1: commit the destination session ("begin transfer in").
///
/// Both parties must commit.  Any rejection triggers immediate abort and
/// compensation of all prior committed steps.
#[derive(Debug, Clone)]
pub struct TransferSaga {
    pub from_session: String,
    pub to_session: String,
    /// Must have exactly 2 elements: [step_lock_src, step_commit_dst].
    pub steps: Vec<SagaStepSpec>,
}

impl SagaProtocol for TransferSaga {
    fn step_count(&self) -> usize {
        self.steps.len()
    }

    fn step(&self, idx: usize) -> &SagaStepSpec {
        &self.steps[idx]
    }

    fn reduce(&self, _step_idx: usize, acks: &[SagaOutcome]) -> ProtocolOutcome {
        // Atomic: first ack determines the outcome immediately.
        for ack in acks {
            match ack {
                SagaOutcome::Committed => return ProtocolOutcome::Advance,
                SagaOutcome::Rejected { reason } => {
                    return ProtocolOutcome::Abort {
                        reason: reason.clone(),
                    }
                }
            }
        }
        ProtocolOutcome::Pending
    }
}

// ── SessionSaga — unified dispatch enum ──────────────────────────────────────

/// Unified saga discriminant — routes `SagaProtocol` calls to the right impl.
///
/// The `saga_type` field in `SagaRecord` identifies which variant to construct
/// when building a saga for dispatch.  The enum itself is the runtime
/// representation; it is not persisted (the `SagaStepSpec` list in `SagaBegun`
/// is the persisted form, which is always sufficient for cold replay).
#[derive(Debug, Clone)]
pub enum SessionSaga {
    Approval(ApprovalSaga),
    OwnershipTransfer(TransferSaga),
    /// Ad-hoc saga: first-ack-wins reduction with arbitrary step count.
    Custom {
        steps: Vec<SagaStepSpec>,
    },
}

impl SagaProtocol for SessionSaga {
    fn step_count(&self) -> usize {
        match self {
            Self::Approval(s) => s.step_count(),
            Self::OwnershipTransfer(s) => s.step_count(),
            Self::Custom { steps } => steps.len(),
        }
    }

    fn step(&self, idx: usize) -> &SagaStepSpec {
        match self {
            Self::Approval(s) => s.step(idx),
            Self::OwnershipTransfer(s) => s.step(idx),
            Self::Custom { steps } => &steps[idx],
        }
    }

    fn reduce(&self, step_idx: usize, acks: &[SagaOutcome]) -> ProtocolOutcome {
        match self {
            Self::Approval(s) => s.reduce(step_idx, acks),
            Self::OwnershipTransfer(s) => s.reduce(step_idx, acks),
            Self::Custom { .. } => first_ack_wins(acks),
        }
    }
}

// ── Reducer reconstruction ────────────────────────────────────────────────────

/// Reconstruct the typed protocol discriminant from a persisted `SagaRecord`.
///
/// Called in `live_saga_ack` to dispatch through the correct
/// `SagaProtocol::reduce()` impl (approval policy, atomic transfer, or
/// first-ack-wins) rather than hardcoding outcome logic in the transition
/// function.  The `metadata` field carries all policy parameters that cannot
/// be derived from the step specs alone.
pub(crate) fn build_session_saga(record: &SagaRecord) -> SessionSaga {
    let m = &record.metadata;
    match record.saga_type.as_str() {
        "approval" => SessionSaga::Approval(ApprovalSaga {
            approval_id: m["approval_id"].as_str().unwrap_or("").to_string(),
            policy: m["policy"].as_str().unwrap_or("single_vote").to_string(),
            eligible: m["eligible"].as_u64().unwrap_or(1) as usize,
            // step is only used for step_count/timeout; reduce() does not inspect it.
            step: record
                .steps
                .first()
                .cloned()
                .unwrap_or_else(|| SagaStepSpec {
                    step_idx: 0,
                    participant: String::new(),
                    message: serde_json::Value::Null,
                    compensation: serde_json::Value::Null,
                    timeout_ms: 30_000,
                }),
        }),
        "ownership_transfer" => SessionSaga::OwnershipTransfer(TransferSaga {
            from_session: m["from_session"].as_str().unwrap_or("").to_string(),
            to_session: m["to_session"].as_str().unwrap_or("").to_string(),
            steps: record.steps.clone(),
        }),
        // "custom" and any unknown type → first-ack-wins semantics.
        _ => SessionSaga::Custom {
            steps: record.steps.clone(),
        },
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Default reducer: the first ack determines the outcome.
///
/// Used by `Custom` sagas and as the fallback when no typed protocol is wired.
/// Equivalent to the approval "single_vote" policy.
pub(crate) fn first_ack_wins(acks: &[SagaOutcome]) -> ProtocolOutcome {
    for ack in acks {
        match ack {
            SagaOutcome::Committed => return ProtocolOutcome::Advance,
            SagaOutcome::Rejected { reason } => {
                return ProtocolOutcome::Abort {
                    reason: reason.clone(),
                }
            }
        }
    }
    ProtocolOutcome::Pending
}
