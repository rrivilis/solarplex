//! Criterion benchmarks for the `session` crate.
//!
//! All benchmarks are synchronous (no tokio).  Groups:
//!
//! - `transition/*`   — per-event throughput of the pure transition function
//! - `snapshot/*`     — algebra-gate ROI: gated vs unconditional build_snapshot
//! - `arena/*`        — SessionArena alloc/reset cycle vs heap
//! - `serialization/*`— BumpWriter arena serialization vs serde_json heap String
//! - `hash/*`         — FNV-1a session_numa_node throughput

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use chrono::Utc;

use session::{
    build_snapshot,
    transition,
    BumpWriter, SessionArena,
    InboundEvent, LiveEvent,
    SessionEvent, SessionMemory, SessionState, SagaOutcome,
    SagaStepSpec,
};
use session::CapRecord;

// ── Fixture builders ──────────────────────────────────────────────────────────

const SESSION_ID: &str  = "01HZXSESSION0000000000001";
const OWNER_ID:   &str  = "01HZXOWNER00000000000001";
const AGENT_ID:   &str  = "01HZXAGENT00000000000001";
const CAP_ID:     &str  = "01HZXCAP0000000000000001";
const COLLAB_ID:  &str  = "01HZXCOLLAB00000000000001";
const PART_ID:    &str  = "01HZXPART000000000000001";

/// Build a session with: owner + collaborator joined, both with caps.
/// Returns `(state, memory)` at the post-setup baseline.
fn baseline_memory() -> (SessionState, SessionMemory) {
    let now = Utc::now();
    let events = vec![
        InboundEvent::Replayed {
            seq: 1,
            event: SessionEvent::SessionCreated {
                session_id: SESSION_ID.into(),
                owner_id:   OWNER_ID.into(),
                name:       "bench-session".into(),
                policy:     "single_vote".into(),
                created_at: now,
            },
        },
        InboundEvent::Replayed {
            seq: 2,
            event: SessionEvent::ParticipantJoined {
                actor_id:  OWNER_ID.into(),
                role:      "owner".into(),
                joined_at: now,
            },
        },
        InboundEvent::Replayed {
            seq: 3,
            event: SessionEvent::ParticipantJoined {
                actor_id:  COLLAB_ID.into(),
                role:      "collaborator".into(),
                joined_at: now,
            },
        },
        // Owner cap
        InboundEvent::Replayed {
            seq: 4,
            event: SessionEvent::CapDelegated {
                cap_id:      CAP_ID.into(),
                parent_cap:  None,
                actor_id:    OWNER_ID.into(),
                permissions: vec!["*".into()],
                epoch:       0,
                stratum:     0,
                issued_at:   now,
            },
        },
        // Collab cap
        InboundEvent::Replayed {
            seq: 5,
            event: SessionEvent::CapDelegated {
                cap_id:      "cap-collab-001".into(),
                parent_cap:  Some(CAP_ID.into()),
                actor_id:    COLLAB_ID.into(),
                permissions: vec!["vote".into(), "view".into()],
                epoch:       0,
                stratum:     1,
                issued_at:   now,
            },
        },
    ];

    let mut state  = SessionState::Active;
    let mut memory = SessionMemory::new(SESSION_ID.into(), OWNER_ID.into());
    for event in events {
        let (s, m, _) = transition(state, memory, event);
        state  = s;
        memory = m;
    }
    (state, memory)
}

/// Advance memory to have a pending approval ready to vote on.
fn memory_with_pending_approval() -> (SessionState, SessionMemory) {
    let (state, memory) = baseline_memory();
    let (s, m, _) = transition(
        state, memory,
        InboundEvent::Live(LiveEvent::ApprovalCreate {
            approval_id: "appr-001".into(),
            actor_id:    AGENT_ID.into(),
            tool:        "bash".into(),
            args:        serde_json::json!({"cmd": "ls"}),
            expires_ms:  None,
        }),
    );
    (s, m)
}

/// Advance memory to have a running saga ready to ack.
fn memory_with_running_saga() -> (SessionState, SessionMemory) {
    let (state, memory) = baseline_memory();
    let (s, m, _) = transition(
        state, memory,
        InboundEvent::Live(LiveEvent::SagaBegin {
            saga_id:   "saga-001".into(),
            saga_type: "custom".into(),
            steps: vec![SagaStepSpec {
                step_idx:     0,
                participant:  PART_ID.into(),
                message:      serde_json::json!({"action": "greet"}),
                compensation: serde_json::json!({"action": "undo_greet"}),
                timeout_ms:   30_000,
            }],
            metadata: serde_json::json!({}),
        }),
    );
    (s, m)
}

// ── Transition benchmarks ─────────────────────────────────────────────────────

fn bench_transition(c: &mut Criterion) {
    let mut g = c.benchmark_group("transition");

    // Baseline: how fast is a single event that hits a no-op path?
    // `ActorConnected` for an already-connected actor updates one field.
    {
        let (state, memory) = baseline_memory();
        g.bench_function("actor_connected", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Live(LiveEvent::ActorConnected {
                        actor_id:      OWNER_ID.into(),
                        connection_id: "conn-001".into(),
                    })),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    // Approval request: cap lookup + BTreeMap insert + timer arm effect.
    {
        let (state, memory) = baseline_memory();
        g.bench_function("approval_create", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Live(LiveEvent::ApprovalCreate {
                        approval_id: "appr-bench".into(),
                        actor_id:    AGENT_ID.into(),
                        tool:        "bash".into(),
                        args:        serde_json::json!({"cmd": "ls"}),
                        expires_ms:  Some(30_000),
                    })),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    // Vote on a pending approval: BTreeMap lookup + vote accumulation + policy eval.
    {
        let (state, memory) = memory_with_pending_approval();
        g.bench_function("vote_cast", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Live(LiveEvent::VoteCast {
                        approval_id: "appr-001".into(),
                        voter_id:    COLLAB_ID.into(),
                        decision:    session::VoteDecision::Approve,
                    })),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    // Saga begin: SagaRecord allocation + step 0 dispatch.
    {
        let (state, memory) = baseline_memory();
        g.bench_function("saga_begin", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Live(LiveEvent::SagaBegin {
                        saga_id:   "saga-bench".into(),
                        saga_type: "custom".into(),
                        steps: vec![
                            SagaStepSpec {
                                step_idx:     0,
                                participant:  PART_ID.into(),
                                message:      serde_json::json!({"action": "greet"}),
                                compensation: serde_json::json!({"action": "undo"}),
                                timeout_ms:   30_000,
                            },
                            SagaStepSpec {
                                step_idx:     1,
                                participant:  PART_ID.into(),
                                message:      serde_json::json!({"action": "confirm"}),
                                compensation: serde_json::json!({"action": "cancel"}),
                                timeout_ms:   30_000,
                            },
                        ],
                        metadata: serde_json::json!({}),
                    })),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    // Saga ack (committed): BTreeMap lookup + protocol reduce + step advance.
    {
        let (state, memory) = memory_with_running_saga();
        g.bench_function("saga_ack_committed", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Live(LiveEvent::SagaAck {
                        saga_id:  "saga-001".into(),
                        step_idx: 0,
                        outcome:  SagaOutcome::Committed,
                    })),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    // Replayed event: the no-allocation path (memory advance only, no effects).
    {
        let (state, memory) = baseline_memory();
        let now = Utc::now();
        g.bench_function("replayed_cap_delegated", |b| {
            b.iter_batched(
                || (state.clone(), memory.clone()),
                |(s, m)| transition(
                    black_box(s), black_box(m),
                    black_box(InboundEvent::Replayed {
                        seq: 99,
                        event: SessionEvent::CapDelegated {
                            cap_id:      "cap-bench".into(),
                            parent_cap:  Some(CAP_ID.into()),
                            actor_id:    AGENT_ID.into(),
                            permissions: vec!["view".into()],
                            epoch:       0,
                            stratum:     1,
                            issued_at:   now,
                        },
                    }),
                ),
                BatchSize::SmallInput,
            )
        });
    }

    g.finish();
}

// ── Snapshot benchmarks ───────────────────────────────────────────────────────
//
// Measures the ROI of the AlgebraMask gate added in the real_persist path:
//   - gate_miss = algebra_mask().intersects(SNAPSHOT_DEPENDS_ON) is true → rebuild
//   - gate_hit  = false → skip rebuild, reuse cached value
//
// Since the gate is a bitflag check + optional function call, the bench
// here directly measures `build_snapshot` — the cost paid on a gate miss.

fn bench_snapshot(c: &mut Criterion) {
    let mut g = c.benchmark_group("snapshot");

    let (state, memory) = baseline_memory();

    // Full build_snapshot from a realistic populated memory.
    g.bench_function("build_snapshot", |b| {
        b.iter_batched(
            || (state.clone(), memory.clone()),
            |(s, m)| build_snapshot(black_box(&s), black_box(&m)),
            BatchSize::SmallInput,
        )
    });

    // Algebra mask check only — no rebuild.  This is what gate_hit costs.
    {
        let saga_event = SessionEvent::SagaStepSent {
            saga_id:     "saga-001".into(),
            step_idx:    0,
            participant: PART_ID.into(),
            sent_at:     Utc::now(),
        };
        let approval_event = SessionEvent::ParticipantJoined {
            actor_id:  COLLAB_ID.into(),
            role:      "collaborator".into(),
            joined_at: Utc::now(),
        };
        use session::SNAPSHOT_DEPENDS_ON;
        g.bench_function("algebra_mask_gate_hit", |b| {
            b.iter(|| {
                black_box(saga_event.algebra_mask().intersects(SNAPSHOT_DEPENDS_ON))
            })
        });
        g.bench_function("algebra_mask_gate_miss", |b| {
            b.iter(|| {
                black_box(approval_event.algebra_mask().intersects(SNAPSHOT_DEPENDS_ON))
            })
        });
    }

    g.finish();
}

// ── Arena benchmarks ──────────────────────────────────────────────────────────

fn bench_arena(c: &mut Criterion) {
    let mut g = c.benchmark_group("arena");

    // Alloc N strings of varying sizes, then reset.
    for n in [1usize, 16, 64, 256] {
        g.bench_with_input(BenchmarkId::new("alloc_reset_cycle", n), &n, |b, &n| {
            let mut arena = SessionArena::with_capacity(n * 64);
            b.iter(|| {
                for i in 0..n {
                    let s = format!("bench-string-{i:08}");
                    black_box(arena.alloc_str(&s));
                }
                arena.reset();
            });
        });
    }

    // BumpWriter: arena-backed JSON serialization of a SessionEvent.
    {
        let now = Utc::now();
        let event = SessionEvent::CapDelegated {
            cap_id:      CAP_ID.into(),
            parent_cap:  None,
            actor_id:    OWNER_ID.into(),
            permissions: vec!["*".into()],
            epoch:       0,
            stratum:     0,
            issued_at:   now,
        };
        let arena = SessionArena::with_capacity(4096);

        g.bench_function("bumpwriter_serialize", |b| {
            b.iter(|| {
                let mut w = BumpWriter::new(&arena);
                serde_json::to_writer(&mut w, black_box(&event)).unwrap();
                black_box(w.len())
            })
        });

        g.bench_function("heap_serialize_to_string", |b| {
            b.iter(|| {
                let s = serde_json::to_string(black_box(&event)).unwrap();
                black_box(s.len())
            })
        });
    }

    g.finish();
}

// ── Serialization benchmarks ──────────────────────────────────────────────────
//
// Compares the old to_value path (2 serializations) vs the new to_string path
// (1 serialization) used by real_persist.

fn bench_serialization(c: &mut Criterion) {
    let mut g = c.benchmark_group("serialization");

    let now = Utc::now();
    let event = SessionEvent::SagaStepAcked {
        saga_id:  "saga-bench".into(),
        step_idx: 0,
        outcome:  SagaOutcome::Committed,
        acked_at: now,
    };

    // Old path: to_value → sqlx re-serializes internally.
    g.bench_function("to_value_two_pass", |b| {
        b.iter(|| {
            let v = serde_json::to_value(black_box(&event)).unwrap();
            // Simulate sqlx re-serialization: serialize Value back to string.
            let s = serde_json::to_string(&v).unwrap();
            black_box(s.len())
        })
    });

    // New path: single to_string, postgres parses via ::jsonb cast.
    g.bench_function("to_string_one_pass", |b| {
        b.iter(|| {
            let s = serde_json::to_string(black_box(&event)).unwrap();
            black_box(s.len())
        })
    });

    // type_name() — static dispatch, verify it's free.
    g.bench_function("type_name_static", |b| {
        b.iter(|| {
            black_box(event.type_name())
        })
    });

    g.finish();
}

// ── Cap graph benchmarks ──────────────────────────────────────────────────────
//
// Worst-case depth benchmarks for subtree revocation and lineage queries.
//
// Old `collect_subtree`: O(n_caps × depth) — full BTreeMap scan per BFS level.
// New `cap_subtree`:     O(subtree_size)   — inverted children index, no scan.
//
// At depth=1000 the old path does 1_000_000 BTreeMap iterations; the new path
// does 1000.  The bench below uses a pure chain (branching factor = 1) which
// is the worst case for the old algorithm.

/// Build a delegation chain of `depth` caps: root → c1 → c2 → … → cN.
/// Returns the populated `SessionMemory` and the root cap ID.
fn cap_chain_memory(depth: usize) -> (SessionMemory, String) {
    let now = Utc::now();
    let mut memory = SessionMemory::new("s".into(), "owner".into());

    let root_cap = "cap-root".to_string();
    memory.caps.insert(root_cap.clone(), CapRecord {
        cap_id:      root_cap.clone(),
        actor_id:    "owner".into(),
        parent_cap:  None,
        permissions: vec!["*".into()],
        epoch:       0,
        stratum:     0,
        issued_at:   now,
        revoked:     false,
    });

    let mut parent = root_cap.clone();
    for i in 0..depth {
        let child = format!("cap-{i:06}");
        memory.cap_children
            .entry(parent.clone())
            .or_default()
            .push(child.clone());
        memory.caps.insert(child.clone(), CapRecord {
            cap_id:      child.clone(),
            actor_id:    format!("actor-{i}"),
            parent_cap:  Some(parent.clone()),
            permissions: vec!["view".into()],
            epoch:       0,
            stratum:     (i + 1) as i64,
            issued_at:   now,
            revoked:     false,
        });
        parent = child;
    }
    (memory, root_cap)
}

fn bench_cap_graph(c: &mut Criterion) {
    let mut g = c.benchmark_group("cap_graph");

    for depth in [10usize, 100, 1_000] {
        let (memory, root_cap) = cap_chain_memory(depth);

        // cap_subtree: BFS via inverted index — O(depth) for a chain.
        g.bench_with_input(
            BenchmarkId::new("subtree_revoke", depth),
            &depth,
            |b, _| {
                b.iter(|| {
                    black_box(memory.cap_subtree(black_box(&root_cap)))
                })
            },
        );

        // cap_lineage: follow parent pointers from leaf to root — O(depth).
        let leaf_cap = format!("cap-{:06}", depth - 1);
        g.bench_with_input(
            BenchmarkId::new("lineage_why", depth),
            &depth,
            |b, _| {
                b.iter(|| {
                    black_box(memory.cap_lineage(black_box(&leaf_cap)))
                })
            },
        );
    }

    g.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(
    benches,
    bench_transition,
    bench_snapshot,
    bench_arena,
    bench_serialization,
    bench_cap_graph,
);
criterion_main!(benches);
