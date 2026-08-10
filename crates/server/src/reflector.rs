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
//! append(bundle) → seq   — add a bundle and assign a monotonic sequence number
//! replay(from_seq) → Vec  — return all bundles with seq > from_seq (cursor replay)
//! subscribe() → Receiver  — watch for new bundles in real time
//! ```
//!
//! # Delivery semantics
//!
//! 1. The emitting session task calls `reflector.append(bundle)` in `run_effects`.
//! 2. `append` returns the assigned `seq` and broadcasts `(seq, bundle)` on the
//!    internal channel.
//! 3. `run_effects` immediately attempts online delivery: it sends
//!    `LiveEvent::BundleReceived` to the target session's mpsc mailbox.
//! 4. If the target is offline (not in the session map), delivery is skipped.
//!    On reconnect the target calls `replay(cursor)` to drain missed bundles.
//!
//! # TTL filtering
//!
//! `replay` skips bundles whose `ttl_ms` is in the past — they are dead
//! deliveries that the coordinator's step-timeout timer has already handled.
//! The in-memory log grows monotonically; a periodic `compact` prunes entries
//! older than `MAX_AGE_MS` to bound memory.

use std::sync::Mutex;
use std::time::SystemTime;

use session::{ReflectorCursor, SagaBundle};
use tokio::sync::broadcast;

/// Broadcast channel capacity.  Consumers that fall more than this many
/// bundles behind will receive a `RecvError::Lagged` and must call `replay`
/// to catch up.
const BROADCAST_CAP: usize = 512;

/// Bundles older than this (wall-clock) are pruned by `compact`.
// Suppressed: used by `compact` which is part of the planned GC API, not yet
// called from a production path.
#[allow(dead_code)]
const MAX_AGE_MS: u64 = 10 * 60 * 1_000; // 10 minutes

/// A bundle entry in the log.
#[derive(Clone)]
struct Entry {
    #[allow(dead_code)] // read by replay() iterator; linter misses it
    seq:     i64,
    bundle:  SagaBundle,
    /// Wall-clock milliseconds at append time, for TTL-based compaction.
    created_ms: u64,
}

/// The shared reflector state protected by a Mutex.
///
/// All critical sections are sub-microsecond (Vec push + broadcast send), so
/// a `std::sync::Mutex` is appropriate over a `tokio::sync::Mutex` — we never
/// hold the lock across an await point.
struct Inner {
    log:      Vec<Entry>,
    next_seq: i64,
    /// Incremented by `compact`.  Stale cursors (epoch mismatch) trigger full
    /// replay rather than a silent delta replay over a pruned window.
    epoch:    u32,
}

/// Append-only ordered log for cross-session `SagaBundle`s.
///
/// Clone-cheap: the `Arc` is implicit inside the `broadcast::Sender`; the
/// log itself is behind a `Mutex`.  Pass `Arc<Reflector>` across tasks.
pub struct Reflector {
    inner: Mutex<Inner>,
    tx:    broadcast::Sender<(ReflectorCursor, SagaBundle)>,
}

// replay / subscribe / compact / len / is_empty are not yet called from
// production paths — they are part of the planned reconnect-replay API and
// GC background task.  Suppress dead_code until those callers are wired.
#[allow(dead_code)]
impl Reflector {
    /// Create a new, empty reflector.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            inner: Mutex::new(Inner { log: Vec::new(), next_seq: 1, epoch: 0 }),
            tx,
        }
    }

    /// Append a bundle to the log.
    ///
    /// Returns a `ReflectorCursor` pointing at the newly assigned position.
    /// The broadcast fires immediately; subscribers blocked on `recv` will
    /// wake before this call returns.
    pub fn append(&self, bundle: SagaBundle) -> ReflectorCursor {
        let cursor = {
            let mut guard = self.inner.lock().unwrap();
            let seq = guard.next_seq;
            guard.next_seq += 1;
            guard.log.push(Entry { seq, bundle: bundle.clone(), created_ms: now_ms() });
            ReflectorCursor { seq, epoch: guard.epoch }
        };
        // Broadcast outside the lock — `send` is cheap and non-blocking.
        let _ = self.tx.send((cursor, bundle));
        cursor
    }

    /// Return all bundles with `seq > from.seq` that have not yet expired.
    ///
    /// # Epoch mismatch (stale cursor)
    ///
    /// If `from.epoch` differs from the current epoch (i.e. a `compact` ran
    /// between when the cursor was issued and now), the caller's position
    /// refers to a pruned window.  The reflector falls back to a full replay
    /// from seq 0 so no live bundles are silently skipped.  Callers should
    /// treat a longer-than-expected result as a relocalization signal.
    pub fn replay(&self, from: ReflectorCursor) -> Vec<(ReflectorCursor, SagaBundle)> {
        let now = now_ms();
        let guard = self.inner.lock().unwrap();
        let from_seq = if from.epoch == guard.epoch { from.seq } else { 0 };
        guard.log.iter()
            .filter(|e| e.seq > from_seq && e.bundle.ttl_ms >= now)
            .map(|e| (ReflectorCursor { seq: e.seq, epoch: guard.epoch }, e.bundle.clone()))
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
    /// Advancing the epoch invalidates all outstanding cursors from the
    /// previous epoch, forcing full replay on their next `replay` call.
    /// Call periodically (e.g. from a background GC task every few minutes).
    /// Returns the number of entries pruned.
    pub fn compact(&self) -> usize {
        let cutoff = now_ms().saturating_sub(MAX_AGE_MS);
        let mut guard = self.inner.lock().unwrap();
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
        self.inner.lock().unwrap().log.len()
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
    use ulid::Ulid;

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
        { r.inner.lock().unwrap().log[0].created_ms = 0; }
        r.compact();
        // cursor.epoch is now stale — replay should return everything still live.
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
            let mut guard = r.inner.lock().unwrap();
            guard.log[0].created_ms = 0;
        }
        r.append(make_bundle("a", "b", "s1", 1));
        let epoch_before = r.inner.lock().unwrap().epoch;
        let pruned = r.compact();
        let epoch_after = r.inner.lock().unwrap().epoch;
        assert_eq!(pruned, 1);
        assert_eq!(r.len(), 1);
        assert_eq!(epoch_after, epoch_before + 1, "compact must advance epoch when entries are pruned");
    }
}
