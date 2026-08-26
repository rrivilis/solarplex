//! Criterion benchmarks for the `server` crate.
//!
//! Async benchmarks embed a `tokio::Runtime` inside each group; criterion
//! itself is synchronous.  The pattern is:
//!
//! ```rust
//! let rt = tokio::runtime::Runtime::new().unwrap();
//! b.iter(|| rt.block_on(async { ... }))
//! ```
//!
//! This measures total async task overhead + the work being benchmarked.
//! For sub-microsecond primitives (like reflector append) the runtime overhead
//! is negligible compared to the measured operation.
//!
//! Groups:
//! - `reflector/*`  — append throughput, replay scaling, subscribe fan-out
//! - `numa/*`       — FNV-1a hash throughput (stateless, no runtime needed)

use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};

use server::numa::session_numa_node;
use server::reflector::Reflector;
use session::effects::{BundleKind, ReflectorCursor, SagaBundle};

// ── Fixture helpers ───────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn make_bundle(saga_id: &str, step_idx: usize) -> SagaBundle {
    SagaBundle {
        bundle_id: ulid::Ulid::new().to_string(),
        saga_id: saga_id.to_string(),
        step_idx,
        from_session: "session-a".into(),
        to_session: "session-b".into(),
        kind: BundleKind::Step {
            message: serde_json::json!({"action": "step"}),
            compensation: serde_json::json!({"action": "rollback"}),
        },
        ttl_ms: now_ms() + 30_000,
    }
}

/// Pre-populate a reflector with `n` bundles and return it.
fn reflector_with_n(n: usize) -> Reflector {
    let r = Reflector::new();
    for i in 0..n {
        r.append(make_bundle("saga-bench", i));
    }
    r
}

// ── Reflector benchmarks ──────────────────────────────────────────────────────

fn bench_reflector(c: &mut Criterion) {
    let mut g = c.benchmark_group("reflector");

    // append: the hot path — lock, push, broadcast.
    // Each append assigns a monotonic seq and fires the broadcast channel.
    {
        let r = Reflector::new();
        g.bench_function("append", |b| {
            b.iter(|| {
                let bundle = make_bundle("saga-bench", 0);
                black_box(r.append(bundle))
            })
        });
    }

    // append_arc: same but shared across threads (Arc overhead).
    {
        let r = Arc::new(Reflector::new());
        g.bench_function("append_arc", |b| {
            b.iter(|| {
                let bundle = make_bundle("saga-bench", 0);
                black_box(r.append(bundle))
            })
        });
    }

    // replay at various log sizes (cursor = 0 → drain full log).
    for n in [10usize, 100, 1_000, 10_000] {
        let r = Arc::new(reflector_with_n(n));
        g.bench_with_input(BenchmarkId::new("replay_full", n), &n, |b, _| {
            b.iter(|| black_box(r.replay(ReflectorCursor::zero())))
        });
    }

    // replay_cursor: incremental replay of last N entries (simulates reconnect).
    // The consumer already saw all but the last 10 entries.
    for n in [100usize, 1_000, 10_000] {
        let r = Arc::new(reflector_with_n(n));
        let cursor = ReflectorCursor {
            seq: (n - 10) as i64,
            epoch: 0,
            view: 0,
        };
        g.bench_with_input(BenchmarkId::new("replay_cursor_tail10", n), &n, |b, _| {
            b.iter(|| black_box(r.replay(cursor)))
        });
    }

    // subscribe: get a receiver, then immediately drop it (channel subscription overhead).
    {
        let r = Reflector::new();
        g.bench_function("subscribe", |b| {
            b.iter(|| {
                let rx = r.subscribe();
                black_box(rx)
            })
        });
    }

    // append_with_subscriber: append while N receivers are subscribed.
    // Measures broadcast overhead as subscriber count scales.
    let rt = tokio::runtime::Runtime::new().unwrap();
    for n_subs in [0usize, 1, 4, 16] {
        let r = Arc::new(Reflector::new());
        // Keep receivers alive so the broadcast must deliver to N subscribers.
        let _receivers: Vec<_> = (0..n_subs).map(|_| r.subscribe()).collect();
        let r2 = r.clone();
        g.bench_with_input(
            BenchmarkId::new("append_n_subscribers", n_subs),
            &n_subs,
            |b, _| {
                // Drain any pending wakeups before measuring.
                b.iter(|| {
                    let bundle = make_bundle("saga-bench", 0);
                    black_box(r2.append(bundle))
                })
            },
        );
        let _ = rt.block_on(async {}); // flush pending tasks
    }

    // compact: prune old entries from a 10K-entry log.
    {
        g.bench_function("compact_10k", |b| {
            b.iter_batched(
                || Arc::new(reflector_with_n(10_000)),
                |r| black_box(r.compact()),
                BatchSize::SmallInput,
            )
        });
    }

    g.finish();
}

// ── NUMA / hash benchmarks ────────────────────────────────────────────────────
//
// session_numa_node is called once per session creation and cached on the
// handle.  The cost should be trivially small — this bench verifies that.

fn bench_numa(c: &mut Criterion) {
    let mut g = c.benchmark_group("numa");

    // ULID-length session ID (26 chars) — typical hot-path input.
    let session_id = "01HZXSESSION0000000000001";

    for n_nodes in [1u8, 2, 4, 8, 16] {
        g.bench_with_input(
            BenchmarkId::new("session_numa_node", n_nodes),
            &n_nodes,
            |b, &n| b.iter(|| black_box(session_numa_node(black_box(session_id), n))),
        );
    }

    g.finish();
}

// ── Entry point ───────────────────────────────────────────────────────────────

criterion_group!(benches, bench_reflector, bench_numa);
criterion_main!(benches);
