//! Proptest state-machine invariants for the session transition function.
//!
//! Each proptest generates a sequence of arbitrary events, runs them through
//! `transition`, and verifies that the invariant holds after every step.
//!
//! Invariants tested here:
//!
//! 1. **no_persist_from_replayed_event** — the replay invariant.
//!    `Replayed` events must never produce `Persist` effects.
//!
//! 2. **cursor_never_decreases** — monotonicity.
//!    `memory.cursor` must be non-decreasing across all replayed events.
//!
//! 3. **archived_is_terminal** — Archived absorbs everything.
//!    Once the state is `Archived`, no further event produces any effect.
//!
//! 4. **approval_status_monotone** — approval transitions are one-way.
//!    Once an approval reaches a terminal status (Granted / Denied / Expired /
//!    Interrupted) it must never revert to Pending or Claimed.
//!
//! 5. **draining_ejects_fenced_actors** — epoch fence is enforced.
//!    In `Draining` state, `ActorConnected` for an actor whose cap is revoked
//!    must produce a `CloseConnection` effect.
//!
//! 6. **suspended_rejects_archive_when_already_archived** — idempotent archive.
//!    `AdminArchive` on an already-archived session produces no effects.
//!
//! 7. **sidecar_attach_rejects_invalid_caps** — cap validation gate.
//!
//! 8. **admin_pause_noop_when_suspended** — state guard on pause.
//!
//! ## Saga algebra invariants (9–12)
//!
//! 9.  **saga_status_is_monotone** — once terminal (`Completed`/`Aborted`),
//!     no further event can revert a saga to a non-terminal status.
//!
//! 10. **saga_ack_after_terminal_is_noop** — `SagaAck` on a terminated saga
//!     produces no `Persist` effects and leaves the status unchanged.
//!
//! 11. **saga_compensation_is_backward_only** — when step N is rejected,
//!     only steps < N receive compensation messages (never step N or beyond).
//!
//! 12. **saga_last_step_committed_implies_completed** — acking the final step
//!     as `Committed` transitions the saga to `Completed`.

use chrono::Utc;
use proptest::prelude::*;

use session::{
    build_snapshot, transition, ApprovalRecord, ApprovalStatus, BundleKind, CapRecord,
    DisconnectReason, Effect, InboundEvent, LiveEvent, MemberRecord, SagaBundle, SagaOutcome,
    SagaRecord, SagaStatus, SagaStepSpec, SagaTermination, SessionArena, SessionEvent,
    SessionMemory, SessionState, VoteDecision, SNAPSHOT_DEPENDS_ON,
};

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn fresh_memory() -> SessionMemory {
    SessionMemory::new("sess_01".into(), "owner_01".into())
}

fn memory_with_owner() -> SessionMemory {
    let mut m = fresh_memory();
    m.members.insert(
        "owner_01".into(),
        MemberRecord {
            actor_id: "owner_01".into(),
            role: "owner".into(),
            joined_at: Utc::now(),
            detached: false,
            connection: Some("conn_01".into()),
        },
    );
    m
}

fn memory_with_pending_approval(approval_id: &str) -> SessionMemory {
    let mut m = memory_with_owner();
    m.approvals.insert(
        approval_id.into(),
        ApprovalRecord {
            approval_id: approval_id.into(),
            actor_id: "agent_01".into(),
            tool: "bash".into(),
            status: ApprovalStatus::Pending,
            requested_at: Utc::now(),
            expires_at: None,
            votes: std::collections::BTreeMap::new(),
        },
    );
    m
}

// ── Arbitrary generators ──────────────────────────────────────────────────────

fn arb_session_event() -> impl Strategy<Value = SessionEvent> {
    prop_oneof![
        // lifecycle
        Just(SessionEvent::SessionCreated {
            session_id: "sess_01".into(),
            owner_id: "owner_01".into(),
            name: "test session".into(),
            policy: "single_vote".into(),
            created_at: Utc::now(),
        }),
        Just(SessionEvent::SessionPaused {
            paused_by: "owner_01".into(),
            reason: None,
            paused_at: Utc::now(),
        }),
        Just(SessionEvent::SessionResumed {
            resumed_by: "owner_01".into(),
            resumed_at: Utc::now(),
        }),
        // participation
        Just(SessionEvent::ParticipantJoined {
            actor_id: "actor_01".into(),
            role: "collaborator".into(),
            joined_at: Utc::now(),
        }),
        Just(SessionEvent::ParticipantLeft {
            actor_id: "actor_01".into(),
            reason: None,
            left_at: Utc::now(),
        }),
        // approval
        Just(SessionEvent::ApprovalRequested {
            approval_id: "appr_01".into(),
            actor_id: "agent_01".into(),
            tool: "bash".into(),
            arguments: serde_json::Value::Null,
            expires_at: None,
            requested_at: Utc::now(),
        }),
        Just(SessionEvent::ApprovalVoted {
            approval_id: "appr_01".into(),
            voter_id: "owner_01".into(),
            decision: "approve".into(),
            voted_at: Utc::now(),
        }),
        Just(SessionEvent::ApprovalGranted {
            approval_id: "appr_01".into(),
            resolved_by: "owner_01".into(),
            granted_at: Utc::now(),
        }),
        Just(SessionEvent::ApprovalDenied {
            approval_id: "appr_01".into(),
            resolved_by: "owner_01".into(),
            reason: None,
            denied_at: Utc::now(),
        }),
        Just(SessionEvent::ApprovalExpired {
            approval_id: "appr_01".into(),
            expired_at: Utc::now(),
        }),
        // projection
        Just(SessionEvent::SnapshotCreated {
            snapshot_seq: 10,
            created_at: Utc::now(),
        }),
        Just(SessionEvent::SnapshotInvalidated {
            reason: "membership changed".into(),
            invalidated_at: Utc::now(),
        }),
    ]
}

fn arb_live_event() -> impl Strategy<Value = LiveEvent> {
    prop_oneof![
        Just(LiveEvent::ActorConnected {
            actor_id: "actor_01".into(),
            connection_id: "conn_01".into(),
        }),
        Just(LiveEvent::ActorDisconnected {
            actor_id: "actor_01".into(),
            connection_id: "conn_01".into(),
            reason: DisconnectReason::ClientClose,
        }),
        Just(LiveEvent::ActorReconnected {
            actor_id: "actor_01".into(),
            new_connection_id: "conn_02".into(),
        }),
        Just(LiveEvent::VoteCast {
            approval_id: "appr_01".into(),
            voter_id: "owner_01".into(),
            decision: VoteDecision::Approve,
        }),
        Just(LiveEvent::VoteCast {
            approval_id: "appr_01".into(),
            voter_id: "owner_01".into(),
            decision: VoteDecision::Deny,
        }),
        Just(LiveEvent::TimerFired {
            id: "approval:appr_01".into()
        }),
        Just(LiveEvent::AdminPause {
            by: "owner_01".into(),
            reason: None
        }),
        Just(LiveEvent::AdminResume {
            by: "owner_01".into()
        }),
        Just(LiveEvent::AdminArchive {
            by: "owner_01".into()
        }),
        Just(LiveEvent::SidecarAttach {
            actor_id: "agent_01".into(),
            cap_id: "cap_01".into()
        }),
        Just(LiveEvent::SidecarDetach {
            actor_id: "agent_01".into(),
            reason: None
        }),
    ]
}

// ── Invariant 1: no Persist from Replayed events ──────────────────────────────

proptest! {
    #[test]
    fn no_persist_from_replayed_event(
        events in prop::collection::vec(arb_session_event(), 1..30)
    ) {
        let mut state  = SessionState::Active;
        let mut memory = fresh_memory();

        for (i, event) in events.into_iter().enumerate() {
            let seq = (i + 1) as i64;
            let (s, m, effects) = transition(state, memory, InboundEvent::Replayed { seq, event });
            state  = s;
            memory = m;

            for eff in &effects {
                prop_assert!(
                    !eff.is_persist(),
                    "Replayed event produced Persist effect: {:?}", eff
                );
            }
        }
    }
}

// ── Invariant 2: cursor never decreases ──────────────────────────────────────

proptest! {
    #[test]
    fn cursor_never_decreases(
        events in prop::collection::vec(arb_session_event(), 1..30)
    ) {
        let mut state  = SessionState::Active;
        let mut memory = fresh_memory();
        let mut prev   = 0i64;

        for (i, event) in events.into_iter().enumerate() {
            let seq = (i + 1) as i64;
            let (s, m, _) = transition(state, memory, InboundEvent::Replayed { seq, event });
            state  = s;
            memory = m;
            prop_assert!(memory.cursor >= prev, "cursor regressed: {} → {}", prev, memory.cursor);
            prev = memory.cursor;
        }
    }
}

// ── Invariant 3: Archived is terminal ────────────────────────────────────────

proptest! {
    #[test]
    fn archived_is_terminal(
        events in prop::collection::vec(arb_live_event(), 0..20)
    ) {
        let state  = SessionState::Archived { at: Utc::now() };
        let memory = fresh_memory();

        for event in events {
            let (s, m, effects) = transition(
                state.clone(), memory.clone(),
                InboundEvent::Live(event),
            );
            prop_assert!(s.is_terminal(), "archived session transitioned away from terminal state");
            prop_assert!(effects.is_empty(), "archived session produced effects: {:?}", effects);
            let _ = (s, m);
        }
    }
}

// ── Invariant 4: approval status monotone ────────────────────────────────────

proptest! {
    #[test]
    fn approval_status_is_monotone(
        decisions in prop::collection::vec(
            prop_oneof![Just(VoteDecision::Approve), Just(VoteDecision::Deny)],
            1..8,
        )
    ) {
        let mut state  = SessionState::Active;
        let mut memory = memory_with_pending_approval("appr_01");

        let mut was_terminal = false;

        for decision in decisions {
            let (s, m, _) = transition(
                state, memory,
                InboundEvent::Live(LiveEvent::VoteCast {
                    approval_id: "appr_01".into(),
                    voter_id:    "owner_01".into(),
                    decision,
                }),
            );
            state  = s;
            memory = m;

            if let Some(a) = memory.approvals.get("appr_01") {
                if was_terminal {
                    prop_assert!(
                        a.status.is_terminal(),
                        "approval reverted from terminal to {:?}", a.status
                    );
                }
                if a.status.is_terminal() {
                    was_terminal = true;
                }
            }
        }
    }
}

// ── Invariant 5: draining ejects fenced actors ───────────────────────────────

proptest! {
    #[test]
    fn draining_ejects_fenced_actors(
        actor_id in "[a-z]{4,8}",
    ) {
        let drain_deadline = Utc::now() + chrono::Duration::seconds(30);
        let state  = SessionState::Draining { drain_deadline, drain_seq: 1 };
        let mut memory = fresh_memory();
        memory.epoch = 2;

        // Insert a revoked cap (from epoch 1) for this actor.
        let cap_id = format!("cap_{actor_id}");
        memory.caps.insert(cap_id.clone(), CapRecord {
            cap_id:      cap_id,
            actor_id:    actor_id.clone(),
            parent_cap:  None,
            permissions: vec!["write".into()],
            epoch:       1,    // stale epoch — will be fenced
            stratum:     0,
            issued_at:   Utc::now(),
            revoked:     true, // fenced by EpochAdvanced
        });

        let (_, _, effects) = transition(
            state, memory,
            InboundEvent::Live(LiveEvent::ActorConnected {
                actor_id:      actor_id.clone(),
                connection_id: "conn_test".into(),
            }),
        );

        let ejected = effects.iter().any(|e| {
            matches!(e, Effect::CloseConnection { actor_id: id, .. } if id == &actor_id)
        });
        prop_assert!(ejected, "fenced actor was not ejected during drain: {:?}", effects);
    }
}

// ── Invariant 6: AdminArchive is idempotent once terminal ────────────────────

#[test]
fn archive_is_idempotent() {
    let state = SessionState::Archived { at: Utc::now() };
    let memory = fresh_memory();

    let (s, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::AdminArchive {
            by: "owner_01".into(),
        }),
    );

    assert!(s.is_terminal());
    assert!(
        effects.is_empty(),
        "second archive produced effects: {:?}",
        effects
    );
}

// ── Invariant 7: SidecarAttach rejects invalid caps ──────────────────────────

#[test]
fn sidecar_attach_rejects_revoked_cap() {
    let mut memory = memory_with_owner();
    memory.epoch = 1;
    // Insert a revoked cap.
    memory.caps.insert(
        "cap_old".into(),
        CapRecord {
            cap_id: "cap_old".into(),
            actor_id: "agent_01".into(),
            parent_cap: None,
            permissions: vec!["write".into()],
            epoch: 0,
            stratum: 0,
            issued_at: Utc::now(),
            revoked: true,
        },
    );

    let (_, _, effects) = transition(
        SessionState::Active,
        memory,
        InboundEvent::Live(LiveEvent::SidecarAttach {
            actor_id: "agent_01".into(),
            cap_id: "cap_old".into(),
        }),
    );

    assert!(
        effects
            .iter()
            .any(|e| matches!(e, Effect::CloseConnection { code: 4001, .. })),
        "expected CloseConnection(4001), got: {:?}",
        effects
    );
}

// ── Invariant 8: AdminPause is guarded to Active state ───────────────────────

#[test]
fn admin_pause_noop_when_already_suspended() {
    let state = SessionState::Suspended {
        paused_by: "owner_01".into(),
        reason: None,
        since: Utc::now(),
    };
    let memory = fresh_memory();

    let (s, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::AdminPause {
            by: "owner_01".into(),
            reason: None,
        }),
    );

    assert!(matches!(s, SessionState::Suspended { .. }));
    assert!(
        effects.is_empty(),
        "pause of suspended session produced effects: {:?}",
        effects
    );
}

// ── Algebra mask invariants (13–15) ──────────────────────────────────────────

// ── Invariant 13: every event carries exactly one algebra bit ─────────────────
//
// Each SessionEvent belongs to exactly one sub-algebra; the mask must be a
// power of two.  Verified against one representative per algebra (static
// check — all variants are known at compile time).

#[test]
fn algebra_mask_each_event_has_single_bit() {
    let events = vec![
        // LIFECYCLE
        SessionEvent::SessionCreated {
            session_id: "s".into(),
            owner_id: "o".into(),
            name: "t".into(),
            policy: "single_vote".into(),
            created_at: Utc::now(),
        },
        // MEMBERSHIP (participation)
        SessionEvent::ParticipantJoined {
            actor_id: "a".into(),
            role: "collaborator".into(),
            joined_at: Utc::now(),
        },
        // AUTHORITY (cap)
        SessionEvent::CapDelegated {
            cap_id: "c".into(),
            parent_cap: None,
            actor_id: "a".into(),
            permissions: vec![],
            epoch: 0,
            stratum: 0,
            issued_at: Utc::now(),
        },
        // APPROVAL
        SessionEvent::ApprovalRequested {
            approval_id: "ap".into(),
            actor_id: "a".into(),
            tool: "bash".into(),
            arguments: serde_json::Value::Null,
            expires_at: None,
            requested_at: Utc::now(),
        },
        // EFFECT
        SessionEvent::EffectProposed {
            proposal_id: "p".into(),
            receipt_id: None,
            effect_type: "write".into(),
            expected_hash_before: None,
            claimed_hash_after: None,
            proposed_at: Utc::now(),
        },
        // PROJECTION
        SessionEvent::SnapshotCreated {
            snapshot_seq: 1,
            created_at: Utc::now(),
        },
        // SAGA
        SessionEvent::SagaBegun {
            saga_id: "sg".into(),
            saga_type: "custom".into(),
            steps: vec![],
            begun_at: Utc::now(),
            metadata: serde_json::Value::Null,
        },
    ];

    for event in &events {
        let mask = event.algebra_mask();
        assert_eq!(
            mask.bits().count_ones(),
            1,
            "event in algebra '{}' has {} bits set (expected exactly 1; mask={:#b})",
            event.algebra(),
            mask.bits().count_ones(),
            mask.bits(),
        );
    }
}

// ── Invariant 14: non-snapshot algebras leave build_snapshot unchanged ────────
//
// If event.algebra_mask() & SNAPSHOT_DEPENDS_ON == 0 then replaying the
// event must produce an identical SessionSnapshot.

proptest! {
    #[test]
    fn non_snapshot_algebra_leaves_projection_unchanged(
        outcomes in prop::collection::vec(
            prop_oneof![
                Just(SagaOutcome::Committed),
                Just(SagaOutcome::Rejected { reason: "injected".into() }),
            ],
            1..5,
        )
    ) {
        // Use saga events (SAGA algebra) as the test vector — they are the most
        // frequent non-snapshot events on the hot path.
        let saga_id = "saga_inv";
        let mut state  = SessionState::Active;
        let mut memory = fresh_memory();

        // Plant the saga record via replay.
        let (s, m, _) = transition(state, memory, InboundEvent::Replayed {
            seq: 1,
            event: SessionEvent::SagaBegun {
                saga_id:   saga_id.into(),
                saga_type: "custom".into(),
                steps:     vec![make_step(0), make_step(1)],
                begun_at:  Utc::now(),
                metadata:  serde_json::Value::Null,
            },
        });
        state = s; memory = m;

        // For each saga step event, verify it doesn't change the snapshot.
        let saga_events = vec![
            SessionEvent::SagaStepSent {
                saga_id: saga_id.into(), step_idx: 0,
                participant: "other".into(), sent_at: Utc::now(),
            },
            SessionEvent::SagaStepAcked {
                saga_id: saga_id.into(), step_idx: 0,
                outcome: outcomes[0].clone(), acked_at: Utc::now(),
            },
            SessionEvent::SagaTerminated {
                saga_id: saga_id.into(),
                outcome: SagaTermination::Completed,
                terminated_at: Utc::now(),
            },
        ];

        for event in saga_events {
            // Confirm algebra gate: these must NOT intersect SNAPSHOT_DEPENDS_ON.
            prop_assert!(
                !event.algebra_mask().intersects(SNAPSHOT_DEPENDS_ON),
                "test setup error: {:?} has SNAPSHOT_DEPENDS_ON bits", event.algebra(),
            );

            let snap_before = serde_json::to_value(build_snapshot(&state, &memory)).unwrap();

            let seq = memory.cursor + 1;
            let (s, m, _) = transition(state, memory, InboundEvent::Replayed { seq, event });
            state = s; memory = m;

            let snap_after = serde_json::to_value(build_snapshot(&state, &memory)).unwrap();
            prop_assert_eq!(
                snap_before, snap_after,
                "build_snapshot changed after SAGA event despite SNAPSHOT_DEPENDS_ON gate",
            );
        }
    }
}

// ── Invariant 16: arena allocation preserves string value ─────────────────────
//
// For any arbitrary string, `SessionArena::alloc_str` must return a slice
// that is byte-for-byte equal to the input.  Tests the value-preservation
// contract over the full utf-8 string space rather than just fixed fixtures.

proptest! {
    #[test]
    fn arena_alloc_preserves_value(s in ".*") {
        let arena = SessionArena::new();
        let allocated = arena.alloc_str(&s);
        prop_assert_eq!(allocated, s.as_str(), "arena-allocated string differs from original");
    }
}

// ── Invariant 17: arena reset clears allocation counter ──────────────────────
//
// After allocating N strings and calling `reset()`, the alloc_count must be 0
// and subsequent allocations must produce valid data.  This documents the
// O(1) reclaim contract: regardless of how many allocations were made, a
// single `reset()` clears the region.

proptest! {
    #[test]
    fn arena_reset_clears_alloc_count(
        strings in prop::collection::vec("[a-z0-9_]{0,32}", 0..16),
        after   in "[a-z0-9_]{1,32}",
    ) {
        let mut arena = SessionArena::new();

        // Allocate N strings, bump the count.
        let n = strings.len() as u64;
        for s in &strings {
            arena.alloc_str(s);
        }
        prop_assert_eq!(arena.alloc_count(), n, "alloc_count should equal number of allocs");

        // Reset: region reclaimed, counter zeroed.
        arena.reset();
        prop_assert_eq!(arena.alloc_count(), 0, "alloc_count should be 0 after reset");

        // Post-reset allocation must produce valid data.
        let result = arena.alloc_str(&after);
        prop_assert_eq!(result, after.as_str(), "post-reset alloc returned wrong value");
        prop_assert_eq!(arena.alloc_count(), 1, "alloc_count should be 1 after one post-reset alloc");
    }
}

// ── Invariant 15: build_snapshot is a pure deterministic function ─────────────
//
// Calling build_snapshot twice on the same (state, memory) must return
// identical JSON.  Catches any accidental non-determinism (Utc::now(), rand).

proptest! {
    #[test]
    fn build_snapshot_is_deterministic(
        events in prop::collection::vec(arb_session_event(), 1..20)
    ) {
        let mut state  = SessionState::Active;
        let mut memory = fresh_memory();

        for (i, event) in events.into_iter().enumerate() {
            let seq = (i + 1) as i64;
            let (s, m, _) = transition(state, memory, InboundEvent::Replayed { seq, event });
            state  = s;
            memory = m;
        }

        let snap_a = serde_json::to_value(build_snapshot(&state, &memory)).unwrap();
        let snap_b = serde_json::to_value(build_snapshot(&state, &memory)).unwrap();
        prop_assert_eq!(snap_a, snap_b, "build_snapshot is not deterministic");
    }
}

// ── Saga fixtures ─────────────────────────────────────────────────────────────

fn make_step(idx: usize) -> SagaStepSpec {
    SagaStepSpec {
        step_idx: idx,
        participant: "sess_other".into(),
        message: serde_json::json!({ "action": "commit", "idx": idx }),
        compensation: serde_json::json!({ "action": "rollback", "idx": idx }),
        timeout_ms: 5_000,
    }
}

/// Apply all `Persist` effects from a live transition back into `(state, memory)`
/// via the Replayed path (simulating the session task's effect runner).
fn apply_persisted(
    mut state: SessionState,
    mut memory: SessionMemory,
    effects: Vec<Effect>,
) -> (SessionState, SessionMemory) {
    for eff in effects {
        if let Effect::Persist(event) = eff {
            let seq = memory.cursor + 1;
            let (s, m, _) = transition(state, memory, InboundEvent::Replayed { seq, event });
            state = s;
            memory = m;
        }
    }
    (state, memory)
}

/// Build memory that already contains a saga in `Waiting { step_idx: 0 }` via
/// the Replayed path (SagaBegun → SagaStepSent), matching what the actual
/// event log would look like.
fn memory_with_saga_waiting(saga_id: &str, step_count: usize) -> (SessionState, SessionMemory) {
    let steps: Vec<SagaStepSpec> = (0..step_count).map(make_step).collect();
    let mut state = SessionState::Active;
    let mut memory = fresh_memory();

    // Replay SagaBegun → SagaRecord in Running state.
    let (s, m, _) = transition(
        state,
        memory,
        InboundEvent::Replayed {
            seq: 1,
            event: SessionEvent::SagaBegun {
                saga_id: saga_id.into(),
                saga_type: "custom".into(),
                steps: steps.clone(),
                begun_at: Utc::now(),
                metadata: serde_json::Value::Null,
            },
        },
    );
    state = s;
    memory = m;

    // Replay SagaStepSent → SagaRecord in Waiting { step_idx: 0 }.
    let (s, m, _) = transition(
        state,
        memory,
        InboundEvent::Replayed {
            seq: 2,
            event: SessionEvent::SagaStepSent {
                saga_id: saga_id.into(),
                step_idx: 0,
                participant: steps[0].participant.clone(),
                sent_at: Utc::now(),
            },
        },
    );
    state = s;
    memory = m;

    assert!(
        matches!(memory.sagas.get(saga_id), Some(r) if matches!(r.status, SagaStatus::Waiting { step_idx: 0, .. })),
        "fixture did not produce Waiting {{ step_idx: 0 }} state"
    );

    (state, memory)
}

// ── Invariant 9: saga status is monotone ─────────────────────────────────────
//
// Once a saga reaches Completed or Aborted, no further SagaAck can revert it.

proptest! {
    #[test]
    fn saga_status_is_monotone(
        outcomes in prop::collection::vec(
            prop_oneof![
                Just(SagaOutcome::Committed),
                Just(SagaOutcome::Rejected { reason: "injected failure".into() }),
            ],
            1..6,
        )
    ) {
        let saga_id = "saga_01";
        let (mut state, mut memory) = memory_with_saga_waiting(saga_id, 3);
        let mut was_terminal = false;
        let mut current_step = 0usize;

        for outcome in outcomes {
            let (s, m, effects) = transition(
                state, memory,
                InboundEvent::Live(LiveEvent::SagaAck {
                    saga_id:  saga_id.into(),
                    step_idx: current_step,
                    outcome:  outcome.clone(),
                }),
            );
            // Apply Persist effects so memory reflects the new saga status.
            let (s, m) = apply_persisted(s, m, effects);
            state  = s;
            memory = m;

            if let Some(saga) = memory.sagas.get(saga_id) {
                if was_terminal {
                    prop_assert!(
                        saga.status.is_terminal(),
                        "saga reverted from terminal to {:?}", saga.status
                    );
                }
                match &saga.status {
                    s if s.is_terminal() => was_terminal = true,
                    SagaStatus::Waiting { step_idx: next, .. } => current_step = *next,
                    _ => {}
                }
            }
        }
    }
}

// ── Invariant 10: SagaAck on a terminated saga is a no-op ────────────────────

#[test]
fn saga_ack_after_terminal_is_noop() {
    let saga_id = "saga_01";

    // Build memory with a 1-step saga that is already Aborted.
    let mut memory = fresh_memory();
    memory.sagas.insert(
        saga_id.into(),
        SagaRecord {
            saga_id: saga_id.into(),
            saga_type: "custom".into(),
            steps: vec![make_step(0)],
            status: SagaStatus::Aborted {
                reason: "previous failure".into(),
            },
            begun_at: Utc::now(),
            metadata: serde_json::Value::Null,
        },
    );

    let (_, _, effects) = transition(
        SessionState::Active,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 0,
            outcome: SagaOutcome::Committed,
        }),
    );

    let persist_count = effects.iter().filter(|e| e.is_persist()).count();
    assert_eq!(
        persist_count, 0,
        "SagaAck on terminated saga produced Persist effects: {:?}",
        effects
    );
}

// ── Invariant 11: compensation is backward-only ───────────────────────────────
//
// When step N is rejected, only steps < N receive compensation Send effects.

#[test]
fn saga_compensation_is_backward_only() {
    // 3-step saga: steps 0 and 1 committed, step 2 rejected.
    let saga_id = "saga_02";
    let (mut state, mut memory) = memory_with_saga_waiting(saga_id, 3);

    // Ack step 0 → Committed.
    let (s, m, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 0,
            outcome: SagaOutcome::Committed,
        }),
    );
    let (s, m) = apply_persisted(s, m, effects);
    state = s;
    memory = m;

    // Ack step 1 → Committed.
    let (s, m, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 1,
            outcome: SagaOutcome::Committed,
        }),
    );
    let (s, m) = apply_persisted(s, m, effects);
    state = s;
    memory = m;

    // Ack step 2 → Rejected.
    let (_, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 2,
            outcome: SagaOutcome::Rejected {
                reason: "step 2 failed".into(),
            },
        }),
    );

    // Collect which step_idx values received a SagaCompensated Persist effect.
    let compensated_steps: Vec<usize> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Persist(SessionEvent::SagaCompensated { step_idx, .. }) => Some(*step_idx),
            _ => None,
        })
        .collect();

    // Steps 0 and 1 must be compensated.
    assert!(
        compensated_steps.contains(&0),
        "step 0 missing from compensations: {:?}",
        compensated_steps
    );
    assert!(
        compensated_steps.contains(&1),
        "step 1 missing from compensations: {:?}",
        compensated_steps
    );
    // Step 2 (the rejected step) must NOT be compensated — it never committed.
    assert!(
        !compensated_steps.contains(&2),
        "step 2 (rejected) should not be compensated: {:?}",
        compensated_steps
    );
}

// ── Invariant 12: last step Committed → Completed ────────────────────────────

#[test]
fn saga_last_step_committed_implies_completed() {
    let saga_id = "saga_03";
    // 2-step saga.
    let (mut state, mut memory) = memory_with_saga_waiting(saga_id, 2);

    // Ack step 0 → Committed.
    let (s, m, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 0,
            outcome: SagaOutcome::Committed,
        }),
    );
    let (s, m) = apply_persisted(s, m, effects);
    state = s;
    memory = m;

    // Saga should now be Waiting on step 1.
    assert!(
        matches!(
            memory.sagas[saga_id].status,
            SagaStatus::Waiting { step_idx: 1, .. }
        ),
        "expected Waiting {{ step_idx: 1 }}, got {:?}",
        memory.sagas[saga_id].status
    );

    // Ack step 1 → Committed (the last step).
    let (_, m, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 1,
            outcome: SagaOutcome::Committed,
        }),
    );
    let (_, m) = apply_persisted(SessionState::Active, m, effects);

    assert!(
        matches!(m.sagas[saga_id].status, SagaStatus::Completed),
        "saga not Completed after last step: {:?}",
        m.sagas[saga_id].status
    );
}

// ── Invariant 13: saga dispatch goes through the reflector (Effect::Bundle) ──
//
// Phase 4 of "wire the session crate up as the runtime source of truth":
// live_saga_begin and the Advance/Abort arms of live_saga_ack used to
// construct Effect::Forward (direct inter-session mailbox delivery, no
// durable log, no offline-participant replay) for the cross-session hop.
// They now construct Effect::Bundle (routed through the reflector — see
// crates/server/src/reflector.rs and session_task.rs's route_bundle, whose
// consumer side was already correct and just needed a producer). These
// tests assert the effect list contains the right Bundle, not that no
// Effect::Forward exists elsewhere — Forward remains the correct choice for
// other inter-session uses (see effects.rs's own doc comment).

#[test]
fn live_saga_begin_dispatches_step_0_via_reflector_bundle() {
    let saga_id = "saga_04";
    let steps: Vec<SagaStepSpec> = (0..2).map(make_step).collect();

    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::SagaBegin {
            saga_id: saga_id.into(),
            saga_type: "custom".into(),
            steps: steps.clone(),
            metadata: serde_json::Value::Null,
        }),
    );

    let bundle = effects
        .iter()
        .find_map(|e| match e {
            Effect::Bundle(b) => Some(b),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an Effect::Bundle in {effects:?}"));

    assert_eq!(bundle.saga_id, saga_id);
    assert_eq!(bundle.step_idx, 0);
    assert_eq!(bundle.to_session, steps[0].participant);
    assert!(
        matches!(&bundle.kind, BundleKind::Step { message, compensation }
            if *message == steps[0].message && *compensation == steps[0].compensation),
        "unexpected bundle kind: {:?}",
        bundle.kind,
    );

    assert!(
        !effects.iter().any(|e| matches!(e, Effect::Forward { .. })),
        "live_saga_begin should no longer emit Effect::Forward for the cross-session hop, got {effects:?}",
    );
}

#[test]
fn live_saga_ack_advance_dispatches_next_step_via_reflector_bundle() {
    let saga_id = "saga_05";
    let (state, memory) = memory_with_saga_waiting(saga_id, 2);
    let steps: Vec<SagaStepSpec> = (0..2).map(make_step).collect();

    let (_, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 0,
            outcome: SagaOutcome::Committed,
        }),
    );

    let bundle = effects
        .iter()
        .find_map(|e| match e {
            Effect::Bundle(b) => Some(b),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an Effect::Bundle for step 1 in {effects:?}"));

    assert_eq!(bundle.step_idx, 1);
    assert!(matches!(&bundle.kind, BundleKind::Step { .. }));
    assert!(!effects.iter().any(|e| matches!(e, Effect::Forward { .. })));
    let _ = steps; // fixture parity with the begin test; not otherwise inspected here
}

#[test]
fn live_saga_ack_abort_dispatches_compensation_via_reflector_bundle() {
    let saga_id = "saga_06";
    let (mut state, mut memory) = memory_with_saga_waiting(saga_id, 3);

    for step_idx in 0..2 {
        let (s, m, effects) = transition(
            state,
            memory,
            InboundEvent::Live(LiveEvent::SagaAck {
                saga_id: saga_id.into(),
                step_idx,
                outcome: SagaOutcome::Committed,
            }),
        );
        let (s, m) = apply_persisted(s, m, effects);
        state = s;
        memory = m;
    }

    // Step 2 rejected — steps 0 and 1 must each get a Compensation bundle.
    let (_, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: saga_id.into(),
            step_idx: 2,
            outcome: SagaOutcome::Rejected {
                reason: "step 2 failed".into(),
            },
        }),
    );

    let comp_bundles: Vec<&SagaBundle> = effects
        .iter()
        .filter_map(|e| match e {
            Effect::Bundle(b) if matches!(b.kind, BundleKind::Compensation { .. }) => Some(b),
            _ => None,
        })
        .collect();

    let comp_steps: Vec<usize> = comp_bundles.iter().map(|b| b.step_idx).collect();
    assert!(
        comp_steps.contains(&0),
        "step 0 missing a compensation bundle: {comp_steps:?}"
    );
    assert!(
        comp_steps.contains(&1),
        "step 1 missing a compensation bundle: {comp_steps:?}"
    );
    assert!(
        !comp_steps.contains(&2),
        "rejected step 2 should not be compensated: {comp_steps:?}"
    );
    assert!(!effects.iter().any(|e| matches!(e, Effect::Forward { .. })));
}

// ── Cross-session approval delegation ─────────────────────────────────────────
//
// live_cross_session_delegate is the first live trigger for the saga engine
// in the product (previously LiveEvent::SagaBegin had zero live callers,
// tested only here and in the reflector-bundle tests above). It wraps
// live_saga_begin with a single-step SessionSaga::Custom, tagging the step
// message and the saga's own metadata so live_saga_ack's completion/abort
// branches can recognize this specific saga shape and resolve the source
// session's original approval to match B's decision — without needing a new
// SagaProtocol impl (Custom's first-ack-wins already gives the right
// Committed→grant / Rejected→deny split for a single-step saga).

#[test]
fn live_cross_session_delegate_dispatches_step_via_reflector_bundle() {
    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::CrossSessionDelegate {
            saga_id: "csd_01".into(),
            approval_id: "appr_01".into(),
            target_session_id: "sess_other".into(),
            requested_by: "owner_01".into(),
            arguments: serde_json::json!({ "tool": "solarplex_exec" }),
        }),
    );

    let requested = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionDelegationRequested {
                saga_id,
                approval_id,
                target_session_id,
                ..
            }) => Some((
                saga_id.clone(),
                approval_id.clone(),
                target_session_id.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionDelegationRequested in {effects:?}"));
    assert_eq!(
        requested,
        ("csd_01".into(), "appr_01".into(), "sess_other".into())
    );

    let bundle = effects
        .iter()
        .find_map(|e| match e {
            Effect::Bundle(b) => Some(b),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected an Effect::Bundle in {effects:?}"));
    assert_eq!(bundle.to_session, "sess_other");
    match &bundle.kind {
        BundleKind::Step { message, .. } => {
            assert_eq!(message["kind"], "cross_session_delegation");
            assert_eq!(message["approval_id"], "appr_01");
        }
        other => panic!("expected BundleKind::Step, got {other:?}"),
    }
}

#[test]
fn live_bundle_received_step_cross_session_delegation_persists_received() {
    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::BundleReceived {
            bundle: SagaBundle {
                bundle_id: "csd_02:0:step".into(),
                saga_id: "csd_02".into(),
                step_idx: 0,
                from_session: "sess_source".into(),
                to_session: "sess_this".into(),
                kind: BundleKind::Step {
                    message: serde_json::json!({
                        "kind": "cross_session_delegation", "approval_id": "appr_02",
                        "arguments": { "tool": "solarplex_exec", "command": "echo hi" },
                    }),
                    compensation: serde_json::Value::Null,
                },
                ttl_ms: Utc::now().timestamp_millis() as u64 + 60_000,
            },
        }),
    );

    let received = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionDelegationReceived {
                saga_id,
                source_session_id,
                source_approval_id,
                arguments,
                target_approval_id,
                ..
            }) => Some((
                saga_id.clone(),
                source_session_id.clone(),
                source_approval_id.clone(),
                arguments.clone(),
                target_approval_id.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionDelegationReceived in {effects:?}"));
    assert_eq!(received.0, "csd_02");
    assert_eq!(received.1, "sess_source");
    assert_eq!(received.2, "appr_02");
    assert_eq!(received.3["tool"], "solarplex_exec");
    assert_eq!(received.4, None);
}

#[test]
fn live_bundle_received_step_artifact_import_persists_received() {
    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::BundleReceived {
            bundle: SagaBundle {
                bundle_id: "ai_01:0:step".into(),
                saga_id: "ai_01".into(),
                step_idx: 0,
                from_session: "sess_source".into(),
                to_session: "sess_this".into(),
                kind: BundleKind::Step {
                    message: serde_json::json!({
                        "kind":               "artifact_import",
                        "source_artifact_id": "art_01",
                        "source_seq":         42,
                        "name":               "notes.md",
                        "artifact_type":      "text/markdown",
                        "storage_ref":        "blob://abc123",
                        "content_hash":       "deadbeef",
                        "source_created_by":  "actor_creator",
                        "source_created_at":  "2026-01-01T00:00:00Z",
                        "imported_by":        "actor_importer",
                        "link_id":            "link_01",
                        "source_name":        "Source Session",
                        "target_name":        "Target Session",
                    }),
                    compensation: serde_json::json!({}),
                },
                ttl_ms: Utc::now().timestamp_millis() as u64 + 60_000,
            },
        }),
    );

    let received = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionArtifactImportReceived {
                source_session_id,
                source_artifact_id,
                source_seq,
                name,
                artifact_type,
                storage_ref,
                content_hash,
                source_created_by,
                imported_by,
                link_id,
                source_name,
                target_name,
                ..
            }) => Some((
                source_session_id.clone(),
                source_artifact_id.clone(),
                *source_seq,
                name.clone(),
                artifact_type.clone(),
                storage_ref.clone(),
                content_hash.clone(),
                source_created_by.clone(),
                imported_by.clone(),
                link_id.clone(),
                source_name.clone(),
                target_name.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionArtifactImportReceived in {effects:?}"));
    assert_eq!(received.0, "sess_source"); // from bundle.from_session, not the message body
    assert_eq!(received.1, "art_01");
    assert_eq!(received.2, 42);
    assert_eq!(received.3, "notes.md");
    assert_eq!(received.4, "text/markdown");
    assert_eq!(received.5, "blob://abc123");
    assert_eq!(received.6, "deadbeef");
    assert_eq!(received.7, "actor_creator");
    assert_eq!(received.8, "actor_importer");
    assert_eq!(received.9, Some("link_01".to_string()));
    assert_eq!(received.10, "Source Session");
    assert_eq!(received.11, "Target Session");
}

#[test]
fn live_bundle_received_step_context_summary_send_persists_received() {
    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::BundleReceived {
            bundle: SagaBundle {
                bundle_id: "cs_01:0:step".into(),
                saga_id: "cs_01".into(),
                step_idx: 0,
                from_session: "sess_source".into(),
                to_session: "sess_this".into(),
                kind: BundleKind::Step {
                    message: serde_json::json!({
                        "kind":                "context_summary_send",
                        "source_entry_id":     "entry_01",
                        "entry_kind":          "hypothesis",
                        "content":             "The cache is stale after deploy.",
                        "source_authored_by":  "actor_author",
                        "source_authored_at":  "2026-01-01T00:00:00Z",
                        "imported_by":         "actor_importer",
                        "link_id":             "link_01",
                        "source_name":         "Source Session",
                        "target_name":         "Target Session",
                    }),
                    compensation: serde_json::json!({}),
                },
                ttl_ms: Utc::now().timestamp_millis() as u64 + 60_000,
            },
        }),
    );

    let received = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionContextReceived {
                source_session_id,
                source_entry_id,
                kind,
                content,
                source_authored_by,
                imported_by,
                link_id,
                source_name,
                target_name,
                ..
            }) => Some((
                source_session_id.clone(),
                source_entry_id.clone(),
                kind.clone(),
                content.clone(),
                source_authored_by.clone(),
                imported_by.clone(),
                link_id.clone(),
                source_name.clone(),
                target_name.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionContextReceived in {effects:?}"));
    assert_eq!(received.0, "sess_source"); // from bundle.from_session, not the message body
    assert_eq!(received.1, "entry_01");
    assert_eq!(received.2, protocol::types::ContextEntryKind::Hypothesis);
    assert_eq!(received.3, "The cache is stale after deploy.");
    assert_eq!(received.4, "actor_author");
    assert_eq!(received.5, "actor_importer");
    assert_eq!(received.6, Some("link_01".to_string()));
    assert_eq!(received.7, "Source Session");
    assert_eq!(received.8, "Target Session");
}

#[test]
fn live_bundle_received_step_annotation_persists_received() {
    let (_, _, effects) = transition(
        SessionState::Active,
        memory_with_owner(),
        InboundEvent::Live(LiveEvent::BundleReceived {
            bundle: SagaBundle {
                bundle_id: "an_01:0:step".into(),
                saga_id: "an_01".into(),
                step_idx: 0,
                from_session: "sess_source".into(),
                to_session: "sess_this".into(),
                kind: BundleKind::Step {
                    message: serde_json::json!({
                        "kind":        "annotation",
                        "object_type": "artifact",
                        "object_id":   "art_01",
                        "object_name": "notes.md",
                        "note":        "This looks stale, can we regenerate it?",
                        "authored_by": "actor_annotator",
                        "link_id":     "link_01",
                        "source_name": "Source Session",
                    }),
                    compensation: serde_json::json!({}),
                },
                ttl_ms: Utc::now().timestamp_millis() as u64 + 60_000,
            },
        }),
    );

    let received = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionAnnotationReceived {
                source_session_id,
                object_type,
                object_id,
                object_name,
                note,
                authored_by,
                link_id,
                source_name,
                ..
            }) => Some((
                source_session_id.clone(),
                object_type.clone(),
                object_id.clone(),
                object_name.clone(),
                note.clone(),
                authored_by.clone(),
                link_id.clone(),
                source_name.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionAnnotationReceived in {effects:?}"));
    assert_eq!(received.0, "sess_source"); // from bundle.from_session, not the message body
    assert_eq!(received.1, "artifact");
    assert_eq!(received.2, "art_01");
    assert_eq!(received.3, "notes.md");
    assert_eq!(received.4, "This looks stale, can we regenerate it?");
    assert_eq!(received.5, "actor_annotator");
    assert_eq!(received.6, Some("link_01".to_string()));
    assert_eq!(received.7, "Source Session");
}

#[test]
fn cross_session_delegation_committed_resolves_as_granted() {
    let (state, memory) = memory_with_delegation_saga_waiting("csd_03", "appr_03");
    let (_, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: "csd_03".into(),
            step_idx: 0,
            outcome: SagaOutcome::Committed,
        }),
    );

    let resolved = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionDelegationResolved {
                approval_id,
                decision,
                ..
            }) => Some((approval_id.clone(), decision.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionDelegationResolved in {effects:?}"));
    assert_eq!(resolved, ("appr_03".into(), "granted".into()));
}

#[test]
fn cross_session_delegation_rejected_resolves_as_denied() {
    let (state, memory) = memory_with_delegation_saga_waiting("csd_04", "appr_04");
    let (_, _, effects) = transition(
        state,
        memory,
        InboundEvent::Live(LiveEvent::SagaAck {
            saga_id: "csd_04".into(),
            step_idx: 0,
            outcome: SagaOutcome::Rejected {
                reason: "denied by B".into(),
            },
        }),
    );

    let resolved = effects
        .iter()
        .find_map(|e| match e {
            Effect::Persist(SessionEvent::CrossSessionDelegationResolved {
                approval_id,
                decision,
                ..
            }) => Some((approval_id.clone(), decision.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("expected CrossSessionDelegationResolved in {effects:?}"));
    assert_eq!(resolved, ("appr_04".into(), "denied".into()));
}

/// Like `memory_with_saga_waiting`, but a single-step saga tagged with the
/// cross-session-delegation metadata `live_saga_ack` checks for. Needs both
/// replays (SagaBegun → Running, then SagaStepSent → Waiting{0}) — a saga
/// isn't actually Waiting on a step until its dispatch is itself replayed.
fn memory_with_delegation_saga_waiting(
    saga_id: &str,
    approval_id: &str,
) -> (SessionState, SessionMemory) {
    let steps = vec![make_step(0)];
    let (state, memory) = (SessionState::Active, fresh_memory());
    let (state, memory, _) = transition(
        state,
        memory,
        InboundEvent::Replayed {
            seq: 1,
            event: SessionEvent::SagaBegun {
                saga_id: saga_id.into(),
                saga_type: "custom".into(),
                steps: steps.clone(),
                begun_at: Utc::now(),
                metadata: serde_json::json!({ "kind": "cross_session_delegation", "approval_id": approval_id }),
            },
        },
    );
    let (state, memory, _) = transition(
        state,
        memory,
        InboundEvent::Replayed {
            seq: 2,
            event: SessionEvent::SagaStepSent {
                saga_id: saga_id.into(),
                step_idx: 0,
                participant: steps[0].participant.clone(),
                sent_at: Utc::now(),
            },
        },
    );
    (state, memory)
}
