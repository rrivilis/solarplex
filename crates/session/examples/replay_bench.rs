//! Replay path allocation benchmark.
//!
//! Measures wall time, heap allocations, and peak RSS across three paths:
//!
//! - **cold**:     replay N events from scratch (SessionMemory::new → fold).
//! - **snapshot**: jump to a mid-point snapshot, replay only the delta events.
//! - **warm**:     steady-state throughput — state already loaded, no snapshot.
//!
//! # Running
//!
//! ```text
//! # Wall time only:
//! cargo run -p session --example replay_bench --release -- 10000
//!
//! # With dhat heap profiling (writes dhat-heap.json):
//! cargo run -p session --example replay_bench -- --dhat 100000
//! # then open https://nnethercote.github.io/dh_view/dh_view.html
//!
//! # With heaptrack (Linux only):
//! heaptrack cargo run -p session --example replay_bench --release -- 1000000
//! heaptrack_gui heaptrack.*.gz
//! ```
//!
//! # Interpreting dhat output
//!
//! Focus on:
//! - "Total bytes":    total heap allocated across the run (allocation pressure)
//! - "Peak bytes":     maximum live heap (RSS proxy, ignoring stack + mmaps)
//! - "Total blocks":   number of individual allocations (fragmentation signal)
//!
//! The cold vs snapshot delta reveals how much allocation the snapshot path
//! avoids: fewer blocks = fewer BTreeMap node splits on replay.

use std::time::Instant;

use chrono::Utc;

use session::{
    transition, InboundEvent, SessionEvent, SessionMemory, SessionState,
    SagaOutcome, SagaStepSpec,
};

// ── dhat opt-in ──────────────────────────────────────────────────────────────
//
// When --dhat is passed, we swap in dhat's allocator and write a profile on
// drop.  On release builds without --dhat this is a zero-overhead noop.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// ── Event factory ─────────────────────────────────────────────────────────────

/// Generate a realistic sequence of N events cycling through:
/// CapDelegated × 1 → ApprovalRequested → ApprovalVoted → ApprovalGranted
/// → SagaBegun → SagaStepSent → SagaStepAcked → SagaTerminated  (× N/8)
fn generate_events(n: usize) -> Vec<SessionEvent> {
    let now = Utc::now();
    let mut events = Vec::with_capacity(n + 4);

    // Bootstrap: session + owner
    events.push(SessionEvent::SessionCreated {
        session_id: "bench-session".into(),
        owner_id:   "owner-001".into(),
        name:       "replay-bench".into(),
        policy:     "single_vote".into(),
        created_at: now,
    });
    events.push(SessionEvent::ParticipantJoined {
        actor_id:  "owner-001".into(),
        role:      "owner".into(),
        joined_at: now,
    });
    events.push(SessionEvent::CapDelegated {
        cap_id:      "cap-root".into(),
        parent_cap:  None,
        actor_id:    "owner-001".into(),
        permissions: vec!["*".into()],
        epoch:       0,
        stratum:     0,
        issued_at:   now,
    });

    // Cycle through event patterns
    let mut i = 0usize;
    while events.len() < n {
        let cycle = i % 4;
        let id = format!("{i:08}");
        match cycle {
            0 => {
                events.push(SessionEvent::CapDelegated {
                    cap_id:      format!("cap-{id}"),
                    parent_cap:  Some("cap-root".into()),
                    actor_id:    format!("agent-{id}"),
                    permissions: vec!["view".into()],
                    epoch:       0,
                    stratum:     1,
                    issued_at:   now,
                });
            }
            1 => {
                events.push(SessionEvent::SagaBegun {
                    saga_id:   format!("saga-{id}"),
                    saga_type: "custom".into(),
                    steps:     vec![SagaStepSpec {
                        step_idx:     0,
                        participant:  "participant-001".into(),
                        message:      serde_json::json!({"action": "do"}),
                        compensation: serde_json::json!({"action": "undo"}),
                        timeout_ms:   30_000,
                    }],
                    begun_at:  now,
                    metadata:  serde_json::json!({}),
                });
                events.push(SessionEvent::SagaStepSent {
                    saga_id:     format!("saga-{id}"),
                    step_idx:    0,
                    participant: "participant-001".into(),
                    sent_at:     now,
                });
            }
            2 => {
                let prev = i - 1;
                events.push(SessionEvent::SagaStepAcked {
                    saga_id:  format!("saga-{prev:08}"),
                    step_idx: 0,
                    outcome:  SagaOutcome::Committed,
                    acked_at: now,
                });
            }
            3 => {
                let prev2 = i - 2;
                events.push(SessionEvent::SagaTerminated {
                    saga_id:       format!("saga-{prev2:08}"),
                    outcome:       session::SagaTermination::Completed,
                    terminated_at: now,
                });
            }
            _ => unreachable!(),
        }
        i += 1;
    }

    events.truncate(n);
    events
}

// ── Replay paths ──────────────────────────────────────────────────────────────

/// Cold replay: fold all events from an empty `SessionMemory`.
fn replay_cold(events: &[SessionEvent]) -> (SessionState, SessionMemory) {
    let mut state  = SessionState::Active;
    let mut memory = SessionMemory::new("bench-session".into(), "owner-001".into());
    for (seq, event) in events.iter().enumerate() {
        let (s, m, _) = transition(
            state, memory,
            InboundEvent::Replayed { seq: seq as i64 + 1, event: event.clone() },
        );
        state  = s;
        memory = m;
    }
    (state, memory)
}

/// Snapshot-assisted replay: skip the first `snap_at` events, then replay delta.
///
/// In production the snapshot is loaded from DB; here we simulate it by running
/// the cold path to `snap_at` first (one-time setup, not included in timing),
/// then bench the delta replay only.
fn replay_snapshot_assisted(
    events:   &[SessionEvent],
    snap_at:  usize,
) -> (SessionState, SessionMemory) {
    // Setup (not timed): build state up to the snapshot point.
    let (snap_state, snap_memory) = replay_cold(&events[..snap_at]);

    // Timed: delta replay from snapshot.
    let mut state  = snap_state;
    let mut memory = snap_memory;
    for (i, event) in events[snap_at..].iter().enumerate() {
        let seq = (snap_at + i) as i64 + 1;
        let (s, m, _) = transition(
            state, memory,
            InboundEvent::Replayed { seq, event: event.clone() },
        );
        state  = s;
        memory = m;
    }
    (state, memory)
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let use_dhat = args.iter().any(|a| a == "--dhat");
    let n: usize = args.iter()
        .filter(|a| !a.starts_with("--") && *a != &args[0])
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    // dhat profiler must be alive for the duration of the measured region.
    // On non-dhat builds this is a zero-sized unit struct (no overhead).
    #[cfg(feature = "dhat-heap")]
    let _profiler = if use_dhat {
        Some(dhat::Profiler::new_heap())
    } else {
        None
    };
    #[cfg(not(feature = "dhat-heap"))]
    if use_dhat {
        eprintln!("warning: --dhat passed but binary not compiled with feature dhat-heap");
        eprintln!("         rebuild with: cargo run -p session --example replay_bench --features session/dhat-heap -- --dhat {n}");
    }

    println!("replay_bench: n={n}, dhat={use_dhat}");

    // Generate events once — not included in any timing.
    let events = generate_events(n);
    let snap_at = n / 2; // snapshot at halfway point

    // ── Cold path ─────────────────────────────────────────────────────────────
    let t0 = Instant::now();
    let (_, cold_mem) = replay_cold(&events);
    let cold_ms = t0.elapsed().as_secs_f64() * 1000.0;

    println!(
        "cold    : {n} events in {cold_ms:.2}ms  ({:.0} events/s)  cursor={}",
        n as f64 / (cold_ms / 1000.0),
        cold_mem.cursor,
    );

    // ── Snapshot-assisted path ────────────────────────────────────────────────
    // Pre-build snapshot (excluded from timing).
    let _ = replay_cold(&events[..snap_at]);

    let t1 = Instant::now();
    let (_, snap_mem) = replay_snapshot_assisted(&events, snap_at);
    let snap_ms = t1.elapsed().as_secs_f64() * 1000.0;
    let delta = n - snap_at;

    println!(
        "snapshot: {delta} delta events in {snap_ms:.2}ms  ({:.0} events/s)  cursor={}",
        delta as f64 / (snap_ms / 1000.0),
        snap_mem.cursor,
    );
    println!(
        "snapshot speedup vs cold: {:.1}×  (for the delta portion only)",
        (cold_ms / n as f64) / (snap_ms / delta as f64),
    );

    // ── Warm path (steady-state throughput) ───────────────────────────────────
    // Run the same delta N/delta times to measure steady-state memory reuse.
    let (warm_base_state, warm_base_mem) = replay_cold(&events[..snap_at]);
    let warm_reps = (100_000 / delta).max(1);
    let t2 = Instant::now();
    for _ in 0..warm_reps {
        let _ = replay_snapshot_assisted(&events, snap_at);
        // In a real impl the arena would reset here.
        let _ = (warm_base_state.clone(), warm_base_mem.clone());
    }
    let warm_ms = t2.elapsed().as_secs_f64() * 1000.0;
    println!(
        "warm    : {warm_reps} × {delta} events in {warm_ms:.2}ms  ({:.0} events/s steady-state)",
        (warm_reps * delta) as f64 / (warm_ms / 1000.0),
    );
}
