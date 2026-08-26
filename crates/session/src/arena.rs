//! Region allocator for the hot saga coordination path.
//!
//! `SessionArena` wraps a [`bumpalo::Bump`] region allocator and models the
//! shadow-paging invariant present in each saga step.
//!
//! # Shadow-paging model
//!
//! Each `SagaStepSpec` carries two allocations:
//!
//! - `message`      — the **forward (real) page**: delivered to the participant
//!   on the commit path.
//! - `compensation` — the **shadow page**: dispatched in reverse order if the
//!   saga aborts after this step was already committed.
//!
//! The arena holds both pages for all in-flight steps simultaneously inside
//! a single contiguous bump region.  On `SagaTerminated`, [`SessionArena::reset`]
//! frees the entire region in O(1) regardless of step count — this is the arena
//! analogue of "shadow page reclaim after commit": the forward path won, so
//! the shadow is discarded at zero per-step cost.
//!
//! # Parallel to the cap epoch registry
//!
//! The cap epoch registry does one global shadow swap on `EpochAdvanced`: old
//! region stays alive for the drain window, then is freed.  The saga arena does
//! the same at per-step granularity: the whole saga's region stays alive while
//! any step is in-flight (the "drain window" is the compensation dispatch), then
//! `reset()` frees it atomically on termination.
//!
//! # Integration notes
//!
//! The arena lives in the **server task loop**, not inside the pure `session`
//! crate transition function.  The transition function remains signature-stable;
//! the arena is used by the effect runner to pre-build event payloads before
//! they are owned (cloned out of the arena) and sent into the session machine.
//!
//! The next migration step — changing hot `SessionEvent` fields to `Arc<str>`
//! so clones inside the transition function are O(1) — is tracked separately.

use bumpalo::{collections::Vec as BumpVec, Bump};
use std::cell::Cell;
use std::io;

/// Region allocator for within-saga allocations.
///
/// Lifetime is tied to a single saga coordinator session task.
/// Call [`reset`](Self::reset) after every `SagaTerminated` event to reclaim
/// the entire region in O(1).
///
/// `SessionArena` is `!Send` (bumpalo uses `UnsafeCell` internally) and must
/// remain on the same thread as the session task that owns it.
pub struct SessionArena {
    bump: Bump,
    /// Allocation count since the last [`reset`](Self::reset).
    /// Not used for correctness — useful for capacity profiling and benchmarks.
    alloc_count: Cell<u64>,
}

impl SessionArena {
    /// Create a new arena with bumpalo's default initial capacity.
    pub fn new() -> Self {
        Self {
            bump: Bump::new(),
            alloc_count: Cell::new(0),
        }
    }

    /// Create a new arena pre-allocated to hold at least `capacity` bytes.
    ///
    /// Use this when the expected saga size is known (e.g. from step count ×
    /// average message size) to avoid the first reallocation on the hot path.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bump: Bump::with_capacity(capacity),
            alloc_count: Cell::new(0),
        }
    }

    /// Reset the region: reclaim all bump allocations in O(1).
    ///
    /// Call this on every `SagaTerminated` event.  The backing memory is
    /// returned to the bump pool and will be reused by the next saga without
    /// a heap allocation if the region is large enough.
    ///
    /// Any arena-lifetime references obtained before this call are invalidated;
    /// the borrow checker enforces this through the `'bump` lifetime parameter
    /// on allocation methods.
    pub fn reset(&mut self) {
        self.bump.reset();
        self.alloc_count.set(0);
    }

    /// Bump-allocate a string slice with arena lifetime.
    ///
    /// Returns a `&'bump str` valid until the next [`reset`](Self::reset).
    /// Cheaper than a heap allocation for short-lived saga IDs and participant
    /// session addresses that are cloned multiple times within one saga step.
    pub fn alloc_str<'bump>(&'bump self, s: &str) -> &'bump str {
        self.alloc_count.set(self.alloc_count.get() + 1);
        self.bump.alloc_str(s)
    }

    /// Bump-allocate a copy of a `Copy` slice with arena lifetime.
    ///
    /// `T: Copy` ensures no destructors run — the bump allocator cannot
    /// call `drop`, so only plain-data types are permitted.
    ///
    /// Useful for pre-allocating `&'bump [SagaStepSpec]` when step specs
    /// need to be referenced from multiple effects without cloning the Vec.
    pub fn alloc_slice_copy<'bump, T: Copy>(&'bump self, items: &[T]) -> &'bump [T] {
        self.alloc_count.set(self.alloc_count.get() + 1);
        self.bump.alloc_slice_copy(items)
    }

    /// Number of allocations since the last [`reset`](Self::reset).
    pub fn alloc_count(&self) -> u64 {
        self.alloc_count.get()
    }

    /// Total bytes allocated in the current region.
    ///
    /// Includes overhead from alignment padding and bumpalo's internal chunks.
    /// Use this for capacity profiling — compare against `expected_capacity`
    /// to tune [`with_capacity`](Self::with_capacity) pre-allocation.
    pub fn allocated_bytes(&self) -> usize {
        self.bump.allocated_bytes()
    }
}

impl Default for SessionArena {
    fn default() -> Self {
        Self::new()
    }
}

// ── BumpWriter ────────────────────────────────────────────────────────────────

/// An [`io::Write`] adapter that serializes directly into the bump region.
///
/// `BumpWriter` is the correct primitive for arena-backed JSON serialization:
/// ```rust,ignore
/// let mut w = BumpWriter::new(&arena);
/// serde_json::to_writer(&mut w, &event)?;
/// let json: &'bump str = w.into_str();   // zero-copy: lifetime is the arena
/// ```
///
/// The resulting `&'bump str` is valid until the next [`SessionArena::reset`]
/// call — exactly the saga region lifetime.
///
/// # Why `spawn_local` is required for the async persist path
///
/// `BumpWriter<'bump>` holds a `&'bump SessionArena` reference.  Because
/// `bumpalo::Bump: !Sync`, `&SessionArena: !Send`, which means any `async fn`
/// holding a `BumpWriter` across an `.await` point would produce a `!Send`
/// future — incompatible with [`tokio::spawn`].
///
/// The solution is [`tokio::task::spawn_local`] + `LocalSet`: tasks no longer
/// need to be `Send`, and `BumpWriter` can be held freely across `.await`.
/// Until that migration lands, serialize to a heap [`String`] via
/// [`serde_json::to_string`] and pass through the raw-string DB variants
/// (`append_raw_in_tx`, `insert_raw_in_tx`).  The per-event heap allocation
/// is still cheaper than the `to_value` Value-tree round-trip it replaces.
pub struct BumpWriter<'bump> {
    buf: BumpVec<'bump, u8>,
}

impl<'bump> BumpWriter<'bump> {
    /// Create a new writer backed by `arena`'s bump region.
    pub fn new(arena: &'bump SessionArena) -> Self {
        Self {
            buf: BumpVec::new_in(&arena.bump),
        }
    }

    /// Create a new writer with a pre-allocated capacity hint.
    ///
    /// Pass `capacity` roughly equal to the expected serialized size to avoid
    /// bumpalo's internal chunk-reallocation on large payloads.
    pub fn with_capacity(arena: &'bump SessionArena, capacity: usize) -> Self {
        let mut buf = BumpVec::with_capacity_in(capacity, &arena.bump);
        buf.reserve(capacity);
        Self { buf }
    }

    /// Consume the writer and return the serialized bytes as a `&'bump str`.
    ///
    /// The slice is valid until the owning arena is [`reset`](SessionArena::reset).
    ///
    /// # Panics
    ///
    /// Panics if the bytes are not valid UTF-8.  This cannot happen for
    /// `serde_json::to_writer` output, which is always valid UTF-8.
    pub fn into_str(self) -> &'bump str {
        let slice = self.buf.into_bump_slice();
        std::str::from_utf8(slice).expect("BumpWriter: serde_json always produces valid UTF-8")
    }

    /// Return a view of the written bytes without consuming the writer.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.buf).expect("BumpWriter: serde_json always produces valid UTF-8")
    }

    /// Number of bytes written so far.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// `true` if no bytes have been written yet.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

impl io::Write for BumpWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Arena-allocated strings are byte-for-byte equal to the originals.
    /// Documents the value-preservation contract (not just pointer identity).
    #[test]
    fn alloc_str_preserves_value() {
        let arena = SessionArena::new();
        let long = "a".repeat(256);
        let cases = ["saga_01", "", "session/01J7Z3...", long.as_str()];
        for s in cases {
            assert_eq!(arena.alloc_str(s), s, "arena string differs from original");
        }
    }

    /// `reset()` reclaims the region and subsequent allocations produce valid data.
    #[test]
    fn reset_then_alloc_is_clean() {
        let mut arena = SessionArena::new();
        arena.alloc_str("saga_abc");
        arena.alloc_str("saga_def");
        assert_eq!(arena.alloc_count(), 2);
        assert!(arena.allocated_bytes() > 0);

        arena.reset();
        assert_eq!(arena.alloc_count(), 0);

        // Allocating after reset must produce valid data.
        let fresh = arena.alloc_str("saga_xyz");
        assert_eq!(fresh, "saga_xyz");
        assert_eq!(arena.alloc_count(), 1);
    }

    /// Slice allocations preserve both length and element values.
    #[test]
    fn alloc_slice_copy_preserves_value() {
        let arena = SessionArena::new();
        let src: &[u8] = b"step_payload_bytes";
        let dst = arena.alloc_slice_copy(src);
        assert_eq!(src, dst);
    }

    /// `with_capacity` pre-allocates but behaves identically to `new()`.
    #[test]
    fn with_capacity_behaves_like_new() {
        let arena = SessionArena::with_capacity(4096);
        let s = arena.alloc_str("test");
        assert_eq!(s, "test");
        assert_eq!(arena.alloc_count(), 1);
    }
}
