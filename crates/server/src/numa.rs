//! NUMA-locality helpers for the session task mailbox.
//!
//! # Design
//!
//! Session tasks are assigned to NUMA nodes deterministically by hashing the
//! session ID with FNV-1a.  The assignment is stable since the same session always
//! maps to the same node for as long as `num_nodes` doesn't change, and there
//! is no runtime coordination required.
//!
//! The ownership model in the session task (single writer, mpsc channel) does
//! the heavy lifting for NUMA correctness. Because there is no lock contention
//! attack surface, cross-node traffic is limited to the inter-session
//! `Effect::Forward` path, and intra-session traffic stays entirely local.
//!
//! # Usage
//!
//! ```no_run
//! # use server::numa::{session_numa_node, route_kind, RouteKind};
//! # let session_id = "01HZXSESSION0000000000001";
//! # let numa_nodes = 4u8;
//! # let target_node = 1u8;
//! let local_node  = session_numa_node(session_id, numa_nodes);
//! let route       = route_kind(local_node, target_node);
//! match route {
//!     RouteKind::Local     => { /* enqueue to local mpsc */ }
//!     RouteKind::CrossNode => { /* enqueue to cross-node broker (future) */ }
//! }
//! ```
//!
//! When `num_nodes == 1` (the default), every session is assigned to node 0,
//! every forward is `Local`, and the fast-path remains unchanged.
//! 
//! As of now, multi-node brokering is designed for but remains future work.
//! Tokio's scheduler does not yet consult with env var on pinning threads to sockets 
//! or to control the DRAM bank memory allocation.

// ── Routing discriminant ──────────────────────────────────────────────────────

/// Routing decision for `Effect::Forward` at the NUMA level.
///
/// `Local` means the target session's task runs on the same NUMA node as the
/// source; `CrossNode` means a cross-socket message is required.
///
/// Current behaviour is identical for both variants. The `RouteKind` is
/// logged and will drive separate enqueue paths once the multi-node broker is
/// wired up (tracked as part of task 4, the bundle-relay implementation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    /// Source and target sessions share the same NUMA node.
    Local,
    /// Source and target sessions are on different NUMA nodes.
    CrossNode,
}

/// Compute the routing kind for a forward from `local_node` to `target_node`.
#[inline]
pub fn route_kind(local_node: u8, target_node: u8) -> RouteKind {
    if local_node == target_node {
        RouteKind::Local
    } else {
        RouteKind::CrossNode
    }
}

// ── Placement ─────────────────────────────────────────────────────────────────

/// Deterministically assign a session to a NUMA node using FNV-1a.
///
/// The returned value is in `[0, num_nodes)`.  When `num_nodes == 1` the
/// result is always 0 (fast path: no hash computation needed).
///
/// # FNV-1a constants
///
/// The 64-bit FNV-1a hash is used because:
/// - It is one multiplication + one XOR per byte — suitable for a hot task-
///   spawn path.
/// - It has excellent avalanche for short strings (ULID session IDs are 26
///   chars), giving a near-uniform distribution over NUMA node indices.
/// - No dependency on `std::collections::hash_map::DefaultHasher`, which is
///   explicitly randomised per-process for DoS resistance and would break the
///   stable-assignment property.
pub fn session_numa_node(session_id: &str, num_nodes: u8) -> u8 {
    if num_nodes <= 1 {
        return 0;
    }
    const OFFSET: u64 = 14_695_981_039_346_656_037;
    const PRIME:  u64 = 1_099_511_628_211;
    let hash = session_id
        .bytes()
        .fold(OFFSET, |h, b| h.wrapping_mul(PRIME) ^ b as u64);
    (hash % num_nodes as u64) as u8
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit tests ────────────────────────────────────────────────────────────

    #[test]
    fn single_node_always_zero() {
        assert_eq!(session_numa_node("",         1), 0);
        assert_eq!(session_numa_node("sess_01",  1), 0);
        assert_eq!(session_numa_node("01JABCDE", 1), 0);
    }

    #[test]
    fn node_always_in_bounds() {
        let ids = ["", "a", "sess_01", "01JABCDEFGHJKMNPQRSTVWXYZ0"];
        for num_nodes in [2u8, 4, 8, 16, 64, 127, 255] {
            for id in ids {
                let node = session_numa_node(id, num_nodes);
                assert!(
                    node < num_nodes,
                    "session_numa_node({id:?}, {num_nodes}) = {node} which is >= {num_nodes}"
                );
            }
        }
    }

    #[test]
    fn assignment_is_stable() {
        let id = "01JABCDEFGHJKMNPQRSTVWXYZ0";
        let first = session_numa_node(id, 4);
        for _ in 0..100 {
            assert_eq!(session_numa_node(id, 4), first, "assignment drifted");
        }
    }

    #[test]
    fn route_kind_local_when_same_node() {
        assert_eq!(route_kind(0, 0), RouteKind::Local);
        assert_eq!(route_kind(3, 3), RouteKind::Local);
    }

    #[test]
    fn route_kind_cross_node_when_different() {
        assert_eq!(route_kind(0, 1), RouteKind::CrossNode);
        assert_eq!(route_kind(2, 3), RouteKind::CrossNode);
    }

    // ── Proptest invariants ───────────────────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        /// Stability: `session_numa_node` is a pure function.
        /// Calling it twice on the same (session_id, num_nodes) always returns
        /// the same value.
        #[test]
        fn numa_assignment_is_stable(
            id       in "[a-zA-Z0-9_]{0,32}",
            n_nodes  in 1u8..=64,
        ) {
            let a = session_numa_node(&id, n_nodes);
            let b = session_numa_node(&id, n_nodes);
            prop_assert_eq!(a, b, "session_numa_node({:?}, {}) was not stable", id, n_nodes);
        }

        /// Bounds: returned node is always < num_nodes.
        #[test]
        fn numa_node_always_in_bounds(
            id      in "[a-zA-Z0-9_]{0,32}",
            n_nodes in 1u8..=255,
        ) {
            let node = session_numa_node(&id, n_nodes);
            prop_assert!(
                node < n_nodes,
                "session_numa_node({id:?}, {n_nodes}) = {node} which is out of bounds"
            );
        }

        /// Local-routing: two sessions on the same NUMA node → RouteKind::Local.
        #[test]
        fn route_is_local_when_nodes_match(node in 0u8..128) {
            prop_assert_eq!(route_kind(node, node), RouteKind::Local);
        }

        /// Cross-node routing: different nodes → RouteKind::CrossNode.
        #[test]
        fn route_is_cross_node_when_nodes_differ(
            a in 0u8..128,
            b in 0u8..128,
        ) {
            prop_assume!(a != b);
            prop_assert_eq!(route_kind(a, b), RouteKind::CrossNode);
        }
    }
}
