//! Bundle reflector — append-only ordered log for cross-session saga bundles.
//!
//! # What is the reflector?
//!
//! The reflector is isomorphic to the session event log, but for *cross-session*
//! relay packets (`SagaBundle`) instead of within-session events.  Where each
//! session has its own `events` table in Postgres, all sessions share one
//! in-memory reflector.  (A persistent reflector layer is a natural follow-up
//! once the shape of the data is proven at runtime.)
//!
//! # API
//!
//! ```text
//! append(bundle) → cursor              — add a bundle, no lease check
//! dispatch(bundle, claims) → outcome   — add a bundle, lease-gated (see below)
//! replay(from) → Vec                   — return all bundles after a cursor
//! subscribe() → Receiver               — watch for new bundles in real time
//! compact() → usize                    — reclaim old entries, lease-gated (see below)
//! ```
//!
//! # Delivery semantics
//!
//! 1. The emitting session task calls `reflector.dispatch(bundle, claims)`
//!    (or `append` directly) in `run_effects`, via `route_bundle`.
//! 2. If `dispatch` reports `Committed` (the target's claims are held
//!    locally, or there's only ever been one replica), `route_bundle`
//!    immediately attempts online delivery: it sends
//!    `LiveEvent::BundleIntercepted` to the target session's mpsc mailbox --
//!    not `BundleReceived` directly, so it goes through the same policy/
//!    adapter layer a live arrival would.
//! 3. If the target is offline (not in the session map), the bundle stays
//!    in the log. On reconnect, `session_task.rs`'s `drain_reflector_backlog`
//!    calls `replay(cursor)` to deliver whatever was missed, using a durable
//!    per-session watermark (`db::reflector_cursors`) so a respawned task
//!    doesn't redeliver what it already drained in a previous lifetime.
//! 4. If `dispatch` reports `Forwarded` instead (the target's claims are
//!    held by a *different* replica), `route_bundle` does none of the
//!    above -- the bundle was durably handed off via
//!    `db::reflector_forwarding` and the owning replica's own
//!    `spawn_reflector_forward_listener` (woken by `pg_notify` on the
//!    `reflector_bundles` channel) picks it up, appends it to *its own*
//!    log, and runs steps 2-3 from there. Attempting local delivery for a
//!    `Forwarded` bundle on the wrong replica would be a no-op at best
//!    (the target genuinely isn't running here) and duplicate delivery at
//!    worst if it ever raced the real listener.
//!
//! # TTL filtering
//!
//! `replay` skips bundles whose `ttl_ms` is in the past — they are dead
//! deliveries that the coordinator's step-timeout timer has already handled.
//! The in-memory log grows monotonically; a periodic `compact` prunes entries
//! older than `MAX_AGE_MS` to bound memory.
//!
//! # Leases and the shape of a distributed reflector
//!
//! `compact` is gated by leases over `ConflictClass::ReflectorEpoch` and
//! `ConflictClass::ReflectorSegment` (see `crate::lease`) rather than just
//! grabbing the local mutex and going. Acquire the epoch lease, acquire
//! the segment lease, compact if both are held locally, otherwise forward
//! the compaction to whichever replica holds them instead. There is no
//! such forwarding implementation for this case. That branch logs
//! plainly that it isn't built, rather than pretending to migrate
//! anything. `is_sole_replica` is real (backed by
//! `db::session_placements::other_active_replicas`, refreshed on a timer
//! by `spawn_placement_heartbeat`), so with a second replica actually
//! running and holding a session somewhere, that forward-less branch is
//! now reachable; it logs and compacts locally anyway rather than
//! silently corrupting anything, but the honest gap (no compaction
//! forwarding transport) is unchanged. `replica_id` is now stable across
//! restarts (see `with_replica_id`) instead of a fresh random id every
//! time; `view` still never changes. Bumping it on a real membership
//! transition remains unbuilt.
//!
//! `dispatch` is the general form of the same idea for anything carrying
//! conflict-class claims (see `crate::lease::Plan`), not just compaction.
//! Its `Forward` case *does* have a real wire protocol now:
//! `db::reflector_forwarding`'s durable table plus a `reflector_bundles`
//! `pg_notify` channel, mirroring `notifier.rs`'s shape for
//! `session_events` but scoped to one replica id per notification instead
//! of fan-out to every connected client. This is a genuinely different
//! situation from `compact`'s still-unbuilt forwarding: a session-scoped
//! transaction has a natural durable home to travel through (the bundle
//! itself, addressed by `to_session`), where `compact`'s claims
//! (`ReflectorEpoch`/`ReflectorSegment`) aren't about a session at all.
//! There's nothing bundle-shaped to hand off, so that seam stays the
//! honest unimplemented gap it already was.
//!
//! One more piece had to change for any of this to matter: `crate::lease`'s
//! `LeaseManager` is purely in-process (see its own module doc's
//! "Single-process today" section); every real `try_acquire` call passes
//! *this* replica's own id as the holder, so its `plan()` can never by
//! itself discover that a genuinely different process holds a claim.
//! `dispatch` checks `db::session_placements` (populated when a session
//! task spawns; see `session_task.rs`'s `run_session_task`) for
//! `ConflictClass::Session` claims *before* consulting `LeaseManager` at
//! all, and only falls through to it when the durable directory doesn't
//! name a different owner. Without that check, `Plan::Forward` was
//! reachable only in tests that manually inject a fake foreign holder into
//! the same process's map, never through two real replicas running side
//! by side.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

use dashmap::DashMap;
use session::{ReflectorCursor, SagaBundle};
use sqlx::PgPool;
use tokio::sync::broadcast;
use ulid::Ulid;

use crate::lease::{ConflictClass, LeaseManager, Plan};

/// Broadcast channel capacity.  Consumers that fall more than this many
/// bundles behind will receive a `RecvError::Lagged` and must call `replay`
/// to catch up.
const BROADCAST_CAP: usize = 512;

/// Bundles older than this (wall-clock) are pruned by `compact`.
const MAX_AGE_MS: u64 = 10 * 60 * 1_000; // 10 minutes

/// A bundle entry in the log.
#[derive(Clone)]
struct Entry {
    seq:    i64,
    bundle: SagaBundle,
    /// Wall-clock milliseconds at append time, for TTL-based compaction.
    created_ms: u64,
}

/// This replica's local view of the reflector: the actual log plus the
/// pruning epoch. Named to match the eventual multi-replica shape — today
/// it's the whole reflector's durable state, since there's only one of it.
///
/// All critical sections are sub-microsecond (Vec push + broadcast send), so
/// a `std::sync::Mutex` is appropriate over a `tokio::sync::Mutex`. We never
/// hold the lock across an await point.
struct LocalReflector {
    log:      Vec<Entry>,
    next_seq: i64,
    /// Incremented by `compact`.  Stale cursors (epoch mismatch) trigger full
    /// replay rather than a silent delta replay over a pruned window.
    epoch:    u32,
}

/// This process's identity within the reflector cluster.
///
/// `is_sole_replica` is a cached, periodically-refreshed flag rather than a
/// live query per call. `spawn_placement_heartbeat` below is what actually
/// drives it, by checking `db::session_placements::other_active_replicas`
/// on a timer and calling `set_sole_replica`. Everything that reads it
/// (`compact`, `dispatch`) stays fully synchronous; only the refresh itself
/// touches Postgres. `view` still never changes; bumping it on a real
/// membership transition (not just "another replica exists somewhere") is
/// unbuilt, same honest-seam posture as `compact`'s missing forward path.
struct ReplicationManager {
    replica_id:      String,
    view:            AtomicU32,
    is_sole_replica: AtomicBool,
}

impl ReplicationManager {
    /// `replica_id` should be stable across restarts of the same process
    /// (see `crate::main`'s `REPLICA_ID` env var); a fresh random id every
    /// restart would make even a single replica look like a different one
    /// to the durable placement directory, breaking heartbeat renewal.
    fn new(replica_id: String) -> Self {
        Self {
            replica_id,
            view:            AtomicU32::new(0),
            // Optimistic default until the first heartbeat tick actually
            // checks: a brand-new process with no prior directory state has
            // no way to know otherwise, and "assume sole" matches today's
            // single-replica-only behavior rather than spuriously forwarding.
            is_sole_replica: AtomicBool::new(true),
        }
    }

    fn replica_id(&self) -> &str {
        &self.replica_id
    }

    fn view(&self) -> u32 {
        self.view.load(Ordering::Acquire)
    }

    fn is_sole_replica(&self) -> bool {
        self.is_sole_replica.load(Ordering::Acquire)
    }

    fn set_sole_replica(&self, value: bool) {
        self.is_sole_replica.store(value, Ordering::Release);
    }
}

/// Outcome of a lease-gated `Reflector::dispatch` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Committed to the local log, whether or not leases needed acquiring
    /// first. Same cursor a plain `append` would have returned.
    Committed(ReflectorCursor),
    /// At least one required conflict class was held by another replica.
    /// No local cursor: the bundle was durably handed off (see
    /// `db::reflector_forwarding`) rather than appended to *this*
    /// replica's log, so there is nothing local to report. The caller
    /// must not attempt local online delivery for this outcome. The
    /// owning replica's own `spawn_reflector_forward_listener` does that
    /// once it claims the bundle. When no `PgPool` is configured (`self.pool
    /// == None` tests, or any caller not going through `AppState`), this
    /// falls back to a plain local append instead, so the bundle isn't
    /// silently dropped; that fallback is still reported as `Forwarded`
    /// even though it did append locally, since the decision was still
    /// "this belongs elsewhere," only the transport was unavailable.
    Forwarded,
    /// A class `plan` saw as free was taken by something else before this
    /// call could acquire it. Nothing was committed; callers should
    /// re-dispatch, which re-plans against current lease state.
    Retry,
}

/// Append-only ordered log for cross-session `SagaBundle`s.
///
/// Clone-cheap: the `Arc` is implicit inside the `broadcast::Sender`; the
/// log itself is behind a `Mutex`.  Pass `Arc<Reflector>` across tasks.
pub struct Reflector {
    local:       Mutex<LocalReflector>,
    tx:          broadcast::Sender<(ReflectorCursor, SagaBundle)>,
    leases:      LeaseManager,
    replication: ReplicationManager,
    /// `None` for `Reflector::new()` (tests, or any caller that doesn't
    /// need durable cross-replica forwarding). `dispatch`'s `Forward`
    /// branch falls back to a plain local append when this is `None`,
    /// same "no transport, not pretending to migrate anything" honesty as
    /// `compact`'s unimplemented forward branch.
    pool: Option<PgPool>,
}

// `replay` now has a real caller (`session_task.rs`'s `drain_reflector_backlog`)
// and `len` does too (`main.rs`'s periodic metrics-sampling task, see
// `active_session_hubs`/etc.). `subscribe`/`compact`/`is_empty` still don't --
// `compact` is written but nothing schedules it periodically yet, `subscribe`
// and `is_empty` are exercised only by this module's own tests. Kept as one
// blanket allow rather than three narrower ones since which of these three
// is genuinely dead will keep shifting as more of this gets wired up.
#[allow(dead_code)]
impl Reflector {
    /// Create a new, empty reflector with a random, process-lifetime-only
    /// replica id and no durable-forwarding transport, which is fine for tests and
    /// any caller that doesn't need a stable cross-restart identity or
    /// real cross-replica forwarding. Real server startup uses
    /// `with_replica_id` instead.
    pub fn new() -> Self {
        Self::new_inner(Ulid::new().to_string(), None)
    }

    /// Same as `new`, but with an explicit, caller-supplied replica id and
    /// a real `PgPool` so `dispatch`'s `Forward` branch can actually
    /// durably hand bundles off instead of falling back to a local
    /// append. See `ReplicationManager::new`'s doc for why a stable id
    /// matters once anything durable depends on it.
    pub fn with_replica_id(replica_id: String, pool: PgPool) -> Self {
        Self::new_inner(replica_id, Some(pool))
    }

    fn new_inner(replica_id: String, pool: Option<PgPool>) -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            local:       Mutex::new(LocalReflector { log: Vec::new(), next_seq: 1, epoch: 0 }),
            tx,
            leases:      LeaseManager::new(),
            replication: ReplicationManager::new(replica_id),
            pool,
        }
    }

    /// This process's stable replica identity, see `with_replica_id`.
    pub fn replica_id(&self) -> &str {
        self.replication.replica_id()
    }

    /// Update the cached "is this the only replica" flag. Called by
    /// `spawn_placement_heartbeat` on a timer; not meant to be called
    /// directly from request-handling code.
    pub fn set_sole_replica(&self, value: bool) {
        self.replication.set_sole_replica(value);
    }

    /// Append a bundle to the log.
    ///
    /// Returns a `ReflectorCursor` pointing at the newly assigned position.
    /// The broadcast fires immediately; subscribers blocked on `recv` will
    /// wake before this call returns.
    pub fn append(&self, bundle: SagaBundle) -> ReflectorCursor {
        let cursor = {
            let mut guard = self.local.lock().unwrap();
            let seq = guard.next_seq;
            guard.next_seq += 1;
            guard.log.push(Entry { seq, bundle: bundle.clone(), created_ms: now_ms() });
            ReflectorCursor { seq, epoch: guard.epoch, view: self.replication.view() }
        };
        // Broadcast outside the lock. `send` is cheap and non-blocking.
        let _ = self.tx.send((cursor, bundle));
        cursor
    }

    /// Dispatch a bundle that carries conflict-class claims, gating
    /// delivery on whether this replica actually holds standing over
    /// everything the bundle touches. See the module doc's "Leases and the
    /// shape of a distributed reflector" section.
    ///
    /// `claims` is supplied by the caller rather than derived from the
    /// bundle, e.g. `[ConflictClass::Session(bundle.to_session.clone()),
    /// ConflictClass::SagaStep(bundle.saga_id.clone(), bundle.step_idx)]`.
    ///
    /// `async` because both the durable-ownership check below and the
    /// `Forward` branch may need a real Postgres round trip -- every other
    /// branch stays exactly as synchronous internally as before; nothing
    /// ever awaits while holding `self.local`'s mutex.
    pub async fn dispatch(&self, bundle: SagaBundle, claims: &[ConflictClass]) -> DispatchOutcome {
        let replica = self.replication.replica_id();

        // `self.leases` (crate::lease::LeaseManager) is purely in-process:
        // every real call to `try_acquire` passes `self.replication.replica_id()`
        // as the holder, so one process's LeaseManager can *never* organically
        // learn that a *different* process holds anything -- `Plan::Forward`
        // was unreachable through real activity before this check existed
        // (only ever exercised by tests manually injecting a fake foreign
        // holder into the same in-process map). For `ConflictClass::Session`
        // specifically, `db::session_placements` (populated when a session
        // task spawns, see session_task.rs's `run_session_task`) *is* real
        // cross-process state, so it's checked first and short-circuits
        // straight to `forward` when it names someone else. Every other
        // claim shape (`SagaStep`, `ReflectorEpoch`, `ReflectorSegment`)
        // still only needs same-process arbitration -- see module doc.
        if let Some(owner) = self.durable_session_owner_conflict(claims, replica).await {
            let outcome = self.forward(bundle, owner).await;
            metrics::counter!("reflector_dispatch_total", "outcome" => "forwarded").increment(1);
            return outcome;
        }

        // Single exit point (`outcome` computed, then returned below) rather
        // than a counter call at each branch -- one place to keep in sync
        // with `DispatchOutcome`'s variants as this function evolves, not
        // three or four scattered ones that are easy to leave stale.
        let outcome = match self.leases.plan(claims, replica) {
            Plan::ExecuteLocal => DispatchOutcome::Committed(self.append(bundle)),

            Plan::AcquireLeases(missing) => {
                let mut guards = Vec::with_capacity(missing.len());
                let mut raced = false;
                for class in missing {
                    match self.leases.try_acquire(class, replica) {
                        Some(guard) => guards.push(guard),
                        None => {
                            // Race: `plan` saw this class as free, but
                            // something else acquired it before we got
                            // here. We don't hold everything the
                            // transaction needs, since we can bail rather than run it
                            // partially. Dropping `guards` here releases
                            // whatever we did manage to acquire.
                            tracing::debug!(
                                "reflector dispatch: lease race during acquisition, deferring to caller retry"
                            );
                            raced = true;
                            break;
                        }
                    }
                }
                if raced {
                    DispatchOutcome::Retry
                } else {
                    // Leases held for exactly the append, not any longer:
                    // that's the actual race window (two dispatches racing
                    // to order the same claim's append), not the target
                    // session's own, independent, out-of-band processing of
                    // the delivered bundle. The reflector has no visibility
                    // into or control over that, so holding a lock across it
                    // would protect nothing while pretending to.
                    let cursor = self.append(bundle);
                    drop(guards);
                    DispatchOutcome::Committed(cursor)
                }
            }

            Plan::Forward(owner_replica) => {
                self.forward(bundle, owner_replica).await
            }
        };

        let outcome_label = match &outcome {
            DispatchOutcome::Committed(_) => "committed",
            DispatchOutcome::Forwarded    => "forwarded",
            DispatchOutcome::Retry        => "retry",
        };
        metrics::counter!("reflector_dispatch_total", "outcome" => outcome_label).increment(1);

        outcome
    }

    /// Checks the durable placement directory for any `ConflictClass::Session`
    /// claim owned by a *different*, non-stale replica, see `dispatch`'s
    /// doc for why this (not the in-process `LeaseManager`) is the only
    /// way `Plan::Forward` can ever reflect real cross-process state.
    /// Returns the first such owner found, or `None` if every session
    /// claim is either unclaimed, stale, ours, or there's no pool to check
    /// against at all.
    async fn durable_session_owner_conflict(&self, claims: &[ConflictClass], replica: &str) -> Option<String> {
        let pool = self.pool.as_ref()?;
        for class in claims {
            if let ConflictClass::Session(session_id) = class {
                match db::session_placements::current_owner(pool, session_id).await {
                    Ok(Some(owner)) if owner != replica => return Some(owner),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(session_id, "durable session-owner check failed: {e}"),
                }
            }
        }
        None
    }

    /// The `Plan::Forward` case: durably hand `bundle` off to
    /// `owner_replica` via `db::reflector_forwarding` and wake it with
    /// `pg_notify('reflector_bundles', owner_replica)`, instead of the old
    /// degenerate local append. Falls back to a local append (rather than
    /// losing the bundle) when there's no pool configured, or when the
    /// durable write itself fails.
    async fn forward(&self, bundle: SagaBundle, owner_replica: String) -> DispatchOutcome {
        let Some(pool) = &self.pool else {
            self.append(bundle);
            return DispatchOutcome::Forwarded;
        };

        let forward_id = Ulid::new().to_string();
        match db::reflector_forwarding::insert(pool, &forward_id, &owner_replica, &bundle).await {
            Ok(()) => {
                if let Err(e) = sqlx::query("SELECT pg_notify('reflector_bundles', $1)")
                    .bind(&owner_replica)
                    .execute(pool)
                    .await
                {
                    // The row is already durably written -- a failed notify
                    // only costs latency (the owning replica's own periodic
                    // heartbeat/backlog paths are not blocked on this),
                    // not correctness, so this is a warning, not a retry.
                    tracing::warn!(
                        bundle_id = %bundle.bundle_id, owner_replica,
                        "reflector forward: durable write succeeded but pg_notify failed: {e}",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    bundle_id = %bundle.bundle_id, owner_replica,
                    "reflector forward: durable write failed ({e}), falling back to local append -- \
                     delivery to a client connected to a *different* replica will not happen until \
                     that replica picks this up through some other path",
                );
                self.append(bundle);
            }
        }
        DispatchOutcome::Forwarded
    }

    /// Return all bundles after `from` that have not yet expired.
    ///
    /// # Staleness handling
    ///
    /// Checks `view` first (membership-level staleness, currently always a
    /// no-op, see `ReplicationManager`'s doc), then `epoch` (this replica's
    /// own pruning history). An epoch mismatch (i.e. a `compact` ran between
    /// when the cursor was issued and now) means the caller's position
    /// refers to a pruned window; the reflector falls back to a full replay
    /// from seq 0 so no live bundles are silently skipped.
    pub fn replay(&self, from: ReflectorCursor) -> Vec<(ReflectorCursor, SagaBundle)> {
        let now = now_ms();
        let guard = self.local.lock().unwrap();

        if from.view != self.replication.view() {
            // Would revalidate against current membership before trusting
            // `epoch` at all. Never fires today, since there is exactly one
            // replica and `view` never changes. But this is the first
            // check a real implementation needs, so it's here rather than
            // bolted on later as an afterthought.
            tracing::debug!(
                "reflector replay: cursor view is stale (no membership protocol \
                 implemented yet, so this has no effect beyond this log line)"
            );
        }

        let from_seq = if from.epoch == guard.epoch { from.seq } else { 0 };
        guard.log.iter()
            .filter(|e| e.seq > from_seq && e.bundle.ttl_ms >= now)
            .map(|e| (ReflectorCursor { seq: e.seq, epoch: guard.epoch, view: self.replication.view() }, e.bundle.clone()))
            .collect()
    }

    /// Subscribe to new bundles as they are appended.
    ///
    /// Returns a `broadcast::Receiver`.  Missed entries due to lag can be
    /// recovered via `replay(last_seen_cursor)`.
    pub fn subscribe(&self) -> broadcast::Receiver<(ReflectorCursor, SagaBundle)> {
        self.tx.subscribe()
    }

    /// Remove bundles older than `MAX_AGE_MS` and advance the epoch.
    ///
    /// Gated by leases over `ConflictClass::ReflectorEpoch` and the segment
    /// being reclaimed (see `crate::lease` and this module's doc). Skips
    /// the cycle rather than blocking if either lease is already held.
    /// Callers are expected to run this from a periodic background task, so
    /// the next tick is the retry.
    ///
    /// Advancing the epoch invalidates all outstanding cursors from the
    /// previous epoch, forcing full replay on their next `replay` call.
    /// Returns the number of entries pruned (0 if the cycle was skipped).
    pub fn compact(&self) -> usize {
        let replica = self.replication.replica_id();

        let Some(_epoch_lease) = self.leases.try_acquire(ConflictClass::ReflectorEpoch, replica) else {
            tracing::debug!("reflector compact: epoch lease held elsewhere, skipping this cycle");
            return 0;
        };

        // One segment covering the whole log. It isn't actually
        // partitioned into separately-leasable ranges yet (see
        // `ConflictClass::ReflectorSegment`'s doc).
        let segment = ConflictClass::ReflectorSegment(0);
        let Some(_segment_lease) = self.leases.try_acquire(segment, replica) else {
            tracing::debug!("reflector compact: segment lease held elsewhere, skipping this cycle");
            return 0;
        };

        if !self.replication.is_sole_replica() {
            // A real implementation forwards the compaction to whichever
            // replica actually holds these leases instead of running it
            // locally. That forwarding path doesn't exist -- unlike
            // `dispatch`'s Forward case (see module doc), there's no
            // bundle-shaped payload to durably hand off here, so this
            // branch stays an honest gap even though `is_sole_replica` is
            // real now and a second replica can genuinely make this
            // reachable.
            tracing::warn!(
                "reflector compact: not sole replica, but no remote-forwarding \
                 implementation exists, compacting locally anyway"
            );
        }

        let cutoff = now_ms().saturating_sub(MAX_AGE_MS);
        let mut guard = self.local.lock().unwrap();
        let before = guard.log.len();
        guard.log.retain(|e| e.created_ms >= cutoff);
        let pruned = before - guard.log.len();
        if pruned > 0 {
            guard.epoch += 1;
        }
        pruned
    }

    /// Current length of the in-memory log (for metrics / tests).
    pub fn len(&self) -> usize {
        self.local.lock().unwrap().log.len()
    }

    /// True if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Reflector {
    fn default() -> Self {
        Self::new()
    }
}

/// How long a placement claim stays valid without renewal. Twice the
/// heartbeat interval below, so a single missed/delayed tick doesn't cost
/// a session its claim. Also used by `session_task.rs`'s initial claim at
/// task-spawn time, hence `pub(crate)` rather than private.
pub(crate) const PLACEMENT_TTL_SECS: i32 = 30;

/// Renew this replica's durable claim on every session it's currently
/// running locally, and refresh `Reflector::set_sole_replica` from real
/// directory state. Generic over the session map's value type so this
/// module doesn't need to know about `session_task::SessionTaskHandle` since
/// only the keys (session ids) matter here.
///
/// Spawns its own background task; fire-and-forget from the caller's side,
/// same shape as `notifier::spawn_event_notifier` and `gc::spawn_gc_tasks`.
pub fn spawn_placement_heartbeat<V: Send + Sync + 'static>(
    pool:      PgPool,
    reflector: Arc<Reflector>,
    sessions:  Arc<DashMap<String, V>>,
) {
    let replica_id = reflector.replica_id().to_string();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            interval.tick().await;

            let ids: Vec<String> = sessions.iter().map(|e| e.key().clone()).collect();
            for id in ids {
                match db::session_placements::claim(&pool, &id, &replica_id, PLACEMENT_TTL_SECS).await {
                    Ok(Some(_)) => {}
                    Ok(None) => tracing::warn!(
                        session_id = %id,
                        "placement heartbeat: another replica holds a non-stale claim on a \
                         session this replica is actively running locally, possible split-brain"
                    ),
                    Err(e) => tracing::warn!(session_id = %id, "placement heartbeat failed: {e}"),
                }
            }

            match db::session_placements::other_active_replicas(&pool, &replica_id).await {
                Ok(others) => reflector.set_sole_replica(!others),
                Err(e) => tracing::warn!("placement membership check failed: {e}"),
            }

            // Keeps reflector_forwarded_bundles bounded -- every row this
            // replica has ever durably forwarded elsewhere otherwise
            // accumulates forever. Only ever deletes rows already marked
            // consumed (see db::reflector_forwarding::prune_consumed's doc).
            if let Err(e) = db::reflector_forwarding::prune_consumed(&pool, 1).await {
                tracing::warn!("reflector_forwarded_bundles prune failed: {e}");
            }
        }
    });
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use session::effects::{BundleKind, SagaBundle};

    fn make_bundle(from: &str, to: &str, saga_id: &str, step_idx: usize) -> SagaBundle {
        SagaBundle {
            bundle_id:    Ulid::new().to_string(),
            saga_id:      saga_id.to_string(),
            step_idx,
            from_session: from.to_string(),
            to_session:   to.to_string(),
            kind:         BundleKind::Step {
                message:      serde_json::json!({"action": "greet"}),
                compensation: serde_json::json!({"action": "undo_greet"}),
            },
            ttl_ms:       now_ms() + 30_000,
        }
    }

    #[test]
    fn append_assigns_monotonic_seq() {
        let r  = Reflector::new();
        let c1 = r.append(make_bundle("a", "b", "s1", 0));
        let c2 = r.append(make_bundle("a", "b", "s1", 1));
        assert_eq!(c1.seq, 1);
        assert_eq!(c2.seq, 2);
        assert_eq!(c1.epoch, c2.epoch, "epoch must be stable within a single compact cycle");
        assert_eq!(c1.view, c2.view, "view must be stable with no membership change");
    }

    #[test]
    fn replay_from_zero_returns_all() {
        let r = Reflector::new();
        r.append(make_bundle("a", "b", "s1", 0));
        r.append(make_bundle("a", "b", "s1", 1));
        let entries = r.replay(ReflectorCursor::zero());
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn replay_cursor_skips_seen() {
        let r      = Reflector::new();
        r.append(make_bundle("a", "b", "s1", 0));
        let cursor = r.append(make_bundle("a", "b", "s1", 1));
        r.append(make_bundle("a", "b", "s1", 2));
        let entries = r.replay(cursor);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0.seq, 3);
    }

    #[test]
    fn replay_drops_expired_bundles() {
        let r = Reflector::new();
        let mut expired = make_bundle("a", "b", "s1", 0);
        expired.ttl_ms = 0;
        r.append(expired);
        r.append(make_bundle("a", "b", "s1", 1));
        let entries = r.replay(ReflectorCursor::zero());
        assert_eq!(entries.len(), 1, "only the live bundle should be returned");
        assert_eq!(entries[0].0.seq, 2);
    }

    #[test]
    fn stale_epoch_triggers_full_replay() {
        let r = Reflector::new();
        r.append(make_bundle("a", "b", "s1", 0));
        let cursor = r.append(make_bundle("a", "b", "s1", 1));
        r.append(make_bundle("a", "b", "s1", 2));
        // Force-age the first entry and compact (advances epoch).
        { r.local.lock().unwrap().log[0].created_ms = 0; }
        r.compact();
        // cursor.epoch is now stale. replay should return everything still live.
        let entries = r.replay(cursor);
        // seq 1 was pruned; seq 2 and 3 survive TTL and are after the pruned window.
        // Full replay from seq=0 returns both.
        assert_eq!(entries.len(), 2, "stale epoch should trigger full replay");
    }

    #[tokio::test]
    async fn subscribe_receives_appended_bundle() {
        let r      = Reflector::new();
        let mut rx = r.subscribe();
        let bundle = make_bundle("a", "b", "s1", 0);
        let cursor = r.append(bundle.clone());
        let (recv_cursor, recv_bundle) = rx.recv().await.unwrap();
        assert_eq!(recv_cursor, cursor);
        assert_eq!(recv_bundle.bundle_id, bundle.bundle_id);
    }

    #[test]
    fn compact_removes_old_entries_and_advances_epoch() {
        let r = Reflector::new();
        {
            r.append(make_bundle("a", "b", "s1", 0));
            let mut guard = r.local.lock().unwrap();
            guard.log[0].created_ms = 0;
        }
        r.append(make_bundle("a", "b", "s1", 1));
        let epoch_before = r.local.lock().unwrap().epoch;
        let pruned = r.compact();
        let epoch_after = r.local.lock().unwrap().epoch;
        assert_eq!(pruned, 1);
        assert_eq!(r.len(), 1);
        assert_eq!(epoch_after, epoch_before + 1, "compact must advance epoch when entries are pruned");
    }

    #[test]
    fn compact_skips_when_epoch_lease_is_held_elsewhere() {
        let r = Reflector::new();
        {
            r.append(make_bundle("a", "b", "s1", 0));
            let mut guard = r.local.lock().unwrap();
            guard.log[0].created_ms = 0;
        }
        let _held = r.leases.try_acquire(ConflictClass::ReflectorEpoch, "some-other-replica").unwrap();
        let pruned = r.compact();
        assert_eq!(pruned, 0, "compact must not run while another replica holds the epoch lease");
        assert_eq!(r.len(), 1, "log must be untouched when compact is skipped");
    }

    #[tokio::test]
    async fn dispatch_with_no_claims_commits_immediately() {
        let r = Reflector::new();
        let outcome = r.dispatch(make_bundle("a", "b", "s1", 0), &[]).await;
        assert!(matches!(outcome, DispatchOutcome::Committed(_)));
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn dispatch_acquires_free_claims_then_commits() {
        let r = Reflector::new();
        let claims = [ConflictClass::Session("s1".to_string())];
        let outcome = r.dispatch(make_bundle("a", "s1", "saga1", 0), &claims).await;
        assert!(matches!(outcome, DispatchOutcome::Committed(_)));
        assert_eq!(r.len(), 1);
        // The lease was released after the append, not held indefinitely.
        assert_eq!(r.leases.holder_of(&claims[0]), None);
    }

    #[tokio::test]
    async fn dispatch_forwards_when_a_claim_is_held_by_another_replica() {
        // No pool configured (`Reflector::new()`) -- exercises the
        // no-transport fallback, which still reports `Forwarded` but
        // (unlike the real durable-forward path) lands the bundle in this
        // replica's own log rather than losing it. See `Reflector::forward`'s
        // doc for why that fallback exists and reports the outcome this way.
        let r = Reflector::new();
        let claim = ConflictClass::Session("s1".to_string());
        let _held = r.leases.try_acquire(claim.clone(), "some-other-replica").unwrap();
        let outcome = r.dispatch(make_bundle("a", "s1", "saga1", 0), &[claim]).await;
        assert_eq!(outcome, DispatchOutcome::Forwarded);
        // Fallback append still lands in the log when no pool is configured.
        assert_eq!(r.len(), 1);
    }

    /// Real-database proof that `dispatch`'s durable session-owner check
    /// actually gates on cross-process state, not just in-process
    /// `LeaseManager` entries -- the scenario every test above can't cover
    /// since they all use `Reflector::new()` (no pool). Simulates two
    /// replicas sharing one Postgres pool: "test-replica-b" durably claims
    /// a session (as its own `run_session_task` would on real startup),
    /// "test-replica-a"'s `Reflector` dispatches a bundle addressed to
    /// it, and this confirms (a) the outcome is `Forwarded`, not
    /// `Committed`, (b) replica-a's own log stays empty -- the bundle
    /// never lands there, (c) a real row reaches
    /// `reflector_forwarded_bundles` addressed to replica-b, and (d)
    /// replica-b's own `claim_pending` + `append` round-trips it back out
    /// exactly once (a second claim returns nothing).
    ///
    /// Requires a live Postgres with migrations applied -- not run by
    /// default:
    ///   DATABASE_URL=postgres://... cargo test -p server -- --ignored cross_replica_forward
    #[tokio::test]
    #[ignore = "requires a live Postgres (DATABASE_URL) with migrations 035/036 applied"]
    async fn cross_replica_forward_and_claim_end_to_end() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this test");
        let pool = sqlx::PgPool::connect(&database_url).await
            .expect("failed to connect to DATABASE_URL");

        let actor_id = Ulid::new().to_string();
        db::actors::ensure_human(&pool, &actor_id, "cross-replica-test-actor").await
            .expect("failed to seed test actor");

        let created = db::sessions::create(&pool, db::sessions::CreateSession {
            name: "cross-replica-test-session".to_string(),
            description: None,
            created_by: actor_id.clone(),
            approval_policy: None,
        }).await.expect("failed to seed test session");
        let session_id = created.session.id.clone();

        // replica-b durably claims the session, simulating its own
        // session task having spawned there.
        db::session_placements::claim(&pool, &session_id, "test-replica-b", 30).await
            .expect("claim query failed")
            .expect("replica-b's claim should succeed -- nothing else holds this fresh session");

        // replica-a's Reflector dispatches a bundle addressed to that session.
        let reflector_a = Reflector::with_replica_id("test-replica-a".to_string(), pool.clone());
        let bundle = make_bundle("test-replica-a-origin", &session_id, "cross-replica-saga", 0);
        let claims = [ConflictClass::Session(session_id.clone())];
        let outcome = reflector_a.dispatch(bundle.clone(), &claims).await;

        assert_eq!(
            outcome, DispatchOutcome::Forwarded,
            "replica-a must forward, not commit locally, for a session replica-b owns",
        );
        assert_eq!(
            reflector_a.len(), 0,
            "replica-a's own log must stay empty -- the bundle belongs to replica-b, not here",
        );

        // replica-b claims its pending forwarded bundles and appends them locally.
        let claimed = db::reflector_forwarding::claim_pending::<SagaBundle>(&pool, "test-replica-b").await
            .expect("claim_pending query failed");
        assert_eq!(claimed.len(), 1, "exactly one bundle should be pending for replica-b");
        assert_eq!(claimed[0].1.bundle_id, bundle.bundle_id);

        let reflector_b = Reflector::with_replica_id("test-replica-b".to_string(), pool.clone());
        reflector_b.append(claimed.into_iter().next().unwrap().1);
        assert_eq!(
            reflector_b.len(), 1,
            "replica-b's own log now has the bundle, appended from the durable handoff",
        );

        let claimed_again = db::reflector_forwarding::claim_pending::<SagaBundle>(&pool, "test-replica-b").await
            .expect("second claim_pending query failed");
        assert!(claimed_again.is_empty(), "a bundle must not be claimable twice");
    }
}
