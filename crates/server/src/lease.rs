//! Lease arbitration over conflict classes.
//!
//! Used today by `Reflector::compact` to serialize log reclamation; the
//! same mechanism is meant to eventually gate ordinary bundle dispatch and
//! session/actor migration (see `ConflictClass`'s variants) — ideas explored
//! from Lilac-TM (Hendler, Naiman, Peluso, Quaglia, Romano, Suissa —
//! "Exploiting Locality in Lease-Based Replicated Transactional Memory via
//! Task Migration"), adapted to this system's existing session/saga model.
//!
//! # Flat, not hierarchical — deliberately
//!
//! Conflict classes are independent keys in a map. Leasing `Session(X)`
//! does **not** block a `SagaStep` lease that happens to route through
//! session X, even though the two conceptually overlap. Making one class
//! subsume another needs a real conflict graph over the enum's own
//! variants, not just a bigger map — deferred until something actually
//! needs it, rather than built speculatively now.
//!
//! # Single-process today
//!
//! `holder` is a replica id (see `crate::reflector::ReplicationManager`).
//! With exactly one replica in existence, "I hold this lease" and "this
//! lease is held locally" are the same question — the holder field is what
//! a real multi-replica implementation would compare against to decide
//! local-vs-migrate, not dead weight kept around for its own sake.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// A named unit of exclusive access the lease system arbitrates over.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConflictClass {
    Session(String),
    Saga(String),
    SagaStep(String, usize),
    /// Not yet backed by a real partitioned log — the reflector has one
    /// segment (`0`) covering the whole log until it's actually sharded.
    ReflectorSegment(u64),
    /// Singleton class: exclusive right to advance the reflector epoch.
    ReflectorEpoch,
}

impl ConflictClass {
    /// Variant name only, never the inner id -- session/saga ids are
    /// unbounded and per-entity; using them as a Prometheus label value
    /// would mean a new time series per session forever, exactly the
    /// unbounded-cardinality mistake Prometheus labels are the one place
    /// you can't take back cheaply once it's in a scraped history.
    fn metric_label(&self) -> &'static str {
        match self {
            ConflictClass::Session(_) => "session",
            ConflictClass::Saga(_) => "saga",
            ConflictClass::SagaStep(_, _) => "saga_step",
            ConflictClass::ReflectorSegment(_) => "reflector_segment",
            ConflictClass::ReflectorEpoch => "reflector_epoch",
        }
    }
}

struct LeaseRecord {
    holder: String,
    acquired_at: Instant,
    ttl: Duration,
    /// Monotonically increasing across every real acquisition of *any*
    /// class in this `LeaseManager` (a shared counter, not per-class) — see
    /// `LeaseManager::next_fencing_token`. Lets a durable writer reject a
    /// holder that lost its lease without yet realizing it: compare the
    /// token it was issued against the current one before trusting a
    /// write, the same pattern Chubby/ZooKeeper-style fencing uses.
    fencing_token: u64,
}

impl LeaseRecord {
    fn new(holder: &str, ttl: Duration, fencing_token: u64) -> Self {
        Self {
            holder: holder.to_string(),
            acquired_at: Instant::now(),
            ttl,
            fencing_token,
        }
    }

    fn expired(&self) -> bool {
        self.acquired_at.elapsed() > self.ttl
    }
}

/// Default lease TTL. Expired leases are free on the next `try_acquire` —
/// there is no heartbeat/renewal protocol, so a holder that wants to keep
/// a lease past this must re-acquire before it elapses.
const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(30);

/// In-process lease table, keyed by `ConflictClass`.
pub struct LeaseManager {
    leases: DashMap<ConflictClass, LeaseRecord>,
    /// Source of every `LeaseRecord`'s `fencing_token`. Shared across all
    /// classes deliberately — a global, always-increasing sequence is
    /// simpler to reason about than per-class counters and costs nothing,
    /// since fencing only needs strict monotonicity, not contiguity.
    next_fencing_token: AtomicU64,
}

impl LeaseManager {
    pub fn new() -> Self {
        Self {
            leases: DashMap::new(),
            next_fencing_token: AtomicU64::new(0),
        }
    }

    /// Attempt to acquire `class` for `holder`. Returns a guard that
    /// releases the lease on drop, or `None` if another non-expired holder
    /// already has it. Atomic with respect to other `try_acquire` calls on
    /// the same class (goes through `DashMap::entry`, not a check-then-set).
    pub fn try_acquire(&self, class: ConflictClass, holder: &str) -> Option<LeaseGuard<'_>> {
        let mut acquired = false;
        // Reserved up front rather than inside the `and_modify`/
        // `or_insert_with` closures below -- computing it there would mean
        // capturing `self` into an `FnOnce` alongside the already-borrowed
        // `self.leases`, for no real benefit. A contended call still burns
        // a token value it never uses, which is fine (see the field doc:
        // gaps are fine, only monotonicity across *real* acquisitions matters).
        let candidate_token = self.next_fencing_token.fetch_add(1, Ordering::SeqCst) + 1;

        self.leases
            .entry(class.clone())
            .and_modify(|r| {
                if r.expired() {
                    *r = LeaseRecord::new(holder, DEFAULT_LEASE_TTL, candidate_token);
                    acquired = true;
                }
            })
            .or_insert_with(|| {
                acquired = true;
                LeaseRecord::new(holder, DEFAULT_LEASE_TTL, candidate_token)
            });

        metrics::counter!(
            "lease_acquire_total",
            "class"  => class.metric_label(),
            "result" => if acquired { "acquired" } else { "contended" },
        )
        .increment(1);

        // `then_some` (eager) would construct the LeaseGuard unconditionally
        // -- including on a failed/contended attempt -- and immediately drop
        // that discarded guard right here, which runs LeaseGuard::drop and
        // unconditionally removes *whichever* record currently sits at this
        // class, even though this caller never held it. That silently kicked
        // out the real holder on every single contended call: found via the
        // stress test in lease::tests, invisible to plain unit tests since
        // they only ever assert the loser's own return value, never that the
        // winner's lease survived a subsequent failed attempt. `then` (lazy)
        // only builds the guard when `acquired` is actually true.
        acquired.then(|| LeaseGuard {
            manager: self,
            class,
            fencing_token: candidate_token,
        })
    }

    /// Current holder of `class`, if any (and not expired). For logging /
    /// picking a migration target once there's somewhere to migrate to.
    pub fn holder_of(&self, class: &ConflictClass) -> Option<String> {
        self.leases
            .get(class)
            .and_then(|r| (!r.expired()).then(|| r.holder.clone()))
    }

    /// Current fencing token for `class`, if any (and not expired) —
    /// `holder_of`'s counterpart for the fencing value instead of the
    /// holder's name.
    pub fn fencing_token_of(&self, class: &ConflictClass) -> Option<u64> {
        self.leases
            .get(class)
            .and_then(|r| (!r.expired()).then_some(r.fencing_token))
    }

    /// Decide what a transaction needing `claims` should do, without
    /// acquiring anything yet. A transaction needs *all* of its claims
    /// satisfied in one place — it can't half-run with some leases local
    /// and some remote — so the first claim found held by someone else
    /// settles the whole plan as `Forward`, even if other claims in the
    /// list are free or already held by `local_replica`.
    pub fn plan(&self, claims: &[ConflictClass], local_replica: &str) -> Plan {
        let mut missing = Vec::new();
        for class in claims {
            match self.holder_of(class) {
                None => missing.push(class.clone()),
                Some(holder) if holder == local_replica => {}
                Some(other) => return Plan::Forward(other),
            }
        }
        if missing.is_empty() {
            Plan::ExecuteLocal
        } else {
            Plan::AcquireLeases(missing)
        }
    }
}

/// What a transaction needing a set of conflict-class claims should do.
/// Produced by `LeaseManager::plan`, consumed by `Reflector::dispatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// Every claim is already held by the local replica (or there were no
    /// claims at all) — nothing to acquire, go ahead.
    ExecuteLocal,
    /// Every claim is either already held locally or currently free; these
    /// specific classes still need acquiring before the transaction runs.
    AcquireLeases(Vec<ConflictClass>),
    /// At least one claim is held by a different replica — the whole
    /// transaction belongs there instead of here. Carries that replica's id.
    Forward(String),
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII lease handle — releases the lease when dropped.
pub struct LeaseGuard<'a> {
    manager: &'a LeaseManager,
    class: ConflictClass,
    fencing_token: u64,
}

impl LeaseGuard<'_> {
    /// The token this specific acquisition was issued. A future durable
    /// writer gated by this lease should carry it along and have the
    /// write itself reject a caller presenting a token lower than the
    /// latest one seen for this class — see `LeaseRecord::fencing_token`'s
    /// doc. Not consumed by anything yet; this is the primitive, not a
    /// wired-up enforcement point.
    pub fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}

impl Drop for LeaseGuard<'_> {
    fn drop(&mut self) {
        self.manager.leases.remove(&self.class);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncontended_acquire_succeeds() {
        let lm = LeaseManager::new();
        let guard = lm.try_acquire(ConflictClass::ReflectorEpoch, "replica-a");
        assert!(guard.is_some());
    }

    #[test]
    fn second_holder_is_blocked_while_first_holds_it() {
        let lm = LeaseManager::new();
        let _first = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
            .unwrap();
        let second = lm.try_acquire(ConflictClass::ReflectorEpoch, "replica-b");
        assert!(second.is_none());
    }

    #[test]
    fn releasing_the_guard_frees_the_lease() {
        let lm = LeaseManager::new();
        {
            let _first = lm
                .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
                .unwrap();
        } // dropped here
        let second = lm.try_acquire(ConflictClass::ReflectorEpoch, "replica-b");
        assert!(second.is_some());
    }

    #[test]
    fn fencing_token_is_assigned_on_acquire() {
        let lm = LeaseManager::new();
        let guard = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
            .unwrap();
        assert!(guard.fencing_token() > 0);
        assert_eq!(
            lm.fencing_token_of(&ConflictClass::ReflectorEpoch),
            Some(guard.fencing_token())
        );
    }

    #[test]
    fn fencing_token_increases_after_release_and_reacquire() {
        let lm = LeaseManager::new();
        let first_token = {
            let first = lm
                .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
                .unwrap();
            first.fencing_token()
        }; // dropped here, releasing the class
        let second = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-b")
            .unwrap();
        assert!(
            second.fencing_token() > first_token,
            "reacquiring after release must issue a strictly greater fencing token \
             (first={first_token}, second={})",
            second.fencing_token(),
        );
    }

    #[test]
    fn fencing_token_shared_sequence_across_independent_classes() {
        // The counter is deliberately global, not per-class -- acquiring
        // two different classes still yields two distinct, ordered tokens.
        let lm = LeaseManager::new();
        let a = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
            .unwrap();
        let b = lm
            .try_acquire(ConflictClass::ReflectorSegment(0), "replica-a")
            .unwrap();
        assert_ne!(a.fencing_token(), b.fencing_token());
        assert!(b.fencing_token() > a.fencing_token());
    }

    #[test]
    fn fencing_token_of_returns_none_for_unheld_class() {
        let lm = LeaseManager::new();
        assert_eq!(lm.fencing_token_of(&ConflictClass::ReflectorEpoch), None);
    }

    #[test]
    fn independent_classes_never_conflict() {
        let lm = LeaseManager::new();
        let _epoch = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
            .unwrap();
        // Flat and independent: a different class is unaffected even though
        // it conceptually overlaps (see module doc on hierarchy being
        // deliberately unhandled).
        let segment = lm.try_acquire(ConflictClass::ReflectorSegment(0), "replica-a");
        assert!(segment.is_some());
    }

    #[test]
    fn holder_of_reports_current_holder() {
        let lm = LeaseManager::new();
        assert_eq!(lm.holder_of(&ConflictClass::ReflectorEpoch), None);
        let _guard = lm
            .try_acquire(ConflictClass::ReflectorEpoch, "replica-a")
            .unwrap();
        assert_eq!(
            lm.holder_of(&ConflictClass::ReflectorEpoch),
            Some("replica-a".to_string())
        );
    }

    #[test]
    fn plan_with_no_claims_executes_local() {
        let lm = LeaseManager::new();
        assert_eq!(lm.plan(&[], "replica-a"), Plan::ExecuteLocal);
    }

    #[test]
    fn plan_with_only_free_claims_says_acquire() {
        let lm = LeaseManager::new();
        let claims = vec![ConflictClass::Session("s1".into())];
        assert_eq!(lm.plan(&claims, "replica-a"), Plan::AcquireLeases(claims));
    }

    #[test]
    fn plan_with_all_locally_held_claims_executes_local() {
        let lm = LeaseManager::new();
        let class = ConflictClass::Session("s1".into());
        let _guard = lm.try_acquire(class.clone(), "replica-a").unwrap();
        assert_eq!(lm.plan(&[class], "replica-a"), Plan::ExecuteLocal);
    }

    #[test]
    fn plan_forwards_whole_transaction_when_any_claim_is_held_elsewhere() {
        let lm = LeaseManager::new();
        let held_elsewhere = ConflictClass::Session("s1".into());
        let free = ConflictClass::Session("s2".into());
        let _guard = lm.try_acquire(held_elsewhere.clone(), "replica-b").unwrap();
        // s2 is free, but s1 is held by replica-b — the whole transaction
        // forwards, s2's freeness doesn't matter.
        assert_eq!(
            lm.plan(&[free, held_elsewhere], "replica-a"),
            Plan::Forward("replica-b".to_string())
        );
    }

    // ── Metrics stress test ──────────────────────────────────────────────
    //
    // Layer 1's whole value proposition is "the numbers are trustworthy
    // under real concurrency" -- this proves the `lease_acquire_total`
    // counter never drops an increment when hammered from many real OS
    // threads at once (try_acquire is sync, so this needs real thread
    // parallelism, not tokio tasks racing on one executor).
    //
    // Scoped to `ConflictClass::Saga`, a class none of the tests above ever
    // touch, and measured as a before/after delta rather than an absolute
    // value -- both because the underlying Prometheus recorder is a
    // process-wide singleton (`metrics_route::install_or_reuse_recorder`)
    // shared with every other test in this binary, and because a delta is
    // the only way to make this assertion robust to `cargo test`'s default
    // parallel test execution.

    fn read_counter_value(rendered: &str, line_prefix: &str) -> f64 {
        for line in rendered.lines() {
            if let Some(rest) = line.strip_prefix(line_prefix) {
                return rest.trim().parse().unwrap_or(0.0);
            }
        }
        0.0 // series doesn't exist yet — zero prior increments, not an error
    }

    #[test]
    fn stress_concurrent_acquire_never_loses_an_increment() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        const N: usize = 1000;

        let handle = crate::metrics_route::install_or_reuse_recorder();
        let before = handle.render();
        let before_acquired = read_counter_value(
            &before,
            "lease_acquire_total{class=\"saga\",result=\"acquired\"} ",
        );
        let before_contended = read_counter_value(
            &before,
            "lease_acquire_total{class=\"saga\",result=\"contended\"} ",
        );

        let lm = Arc::new(LeaseManager::new());
        let barrier = Arc::new(Barrier::new(N));

        let workers: Vec<_> = (0..N)
            .map(|i| {
                let lm = Arc::clone(&lm);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait(); // line every thread up so the burst actually overlaps
                    let class = ConflictClass::Saga("stress-test".into());
                    let holder = format!("thread-{i}");
                    let guard = lm.try_acquire(class, &holder);
                    let acquired = guard.is_some();
                    // Deliberately leaked, never dropped: if the winner's guard
                    // released mid-burst, a later contender could re-acquire
                    // and this test would see more than one "winner" even
                    // though the lease itself was never actually double-held
                    // at once — leaking pins the outcome for the whole burst.
                    std::mem::forget(guard);
                    acquired
                })
            })
            .collect();

        let acquired_count = workers
            .into_iter()
            .map(|w| w.join().expect("worker thread panicked"))
            .filter(|&acquired| acquired)
            .count();

        // LeaseManager-level invariant, independent of the metrics system
        // entirely: with every guard pinned for the test's duration, exactly
        // one of N real concurrent contenders on the same class can win.
        assert_eq!(
            acquired_count, 1,
            "expected exactly one winner across {N} concurrent contenders"
        );

        let after = handle.render();
        let after_acquired = read_counter_value(
            &after,
            "lease_acquire_total{class=\"saga\",result=\"acquired\"} ",
        );
        let after_contended = read_counter_value(
            &after,
            "lease_acquire_total{class=\"saga\",result=\"contended\"} ",
        );

        let delta_acquired = (after_acquired - before_acquired) as usize;
        let delta_contended = (after_contended - before_contended) as usize;

        // The actual metrics-correctness claim: every one of the N calls to
        // try_acquire landed exactly one counter increment -- none lost to a
        // race in the underlying registry under genuine concurrent access
        // from N distinct OS threads.
        assert_eq!(
            delta_acquired, 1,
            "acquired-result counter under-/over-counted"
        );
        assert_eq!(
            delta_contended,
            N - 1,
            "contended-result counter under-/over-counted"
        );
        assert_eq!(
            delta_acquired + delta_contended,
            N,
            "lost or duplicated an increment somewhere"
        );
    }
}
