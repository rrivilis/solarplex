use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::sealed::SealedJson;

/// A standing policy fetched from the server
/// (`GET /sessions/:id/approval-policies`) — mirrors the server's own
/// `crate::state::StandingPolicy` shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerPolicy {
    pub actor_id:       Option<String>,
    pub method_pattern: String,
    /// "auto_approve" | "always_deny"
    pub decision:       String,
}

/// The plain, mutable shape used only while building a [`Policy`] at shim
/// startup — see [`Policy::build`]. Not reachable after that point;
/// `Policy` itself is sealed, read-only storage (see `crate::sealed`'s
/// module doc for why: this is the data that decides, entirely locally,
/// whether a tool call proceeds without any human vote at all on the
/// legacy approval path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyData {
    pub auto_approve:         HashSet<String>,
    pub always_require:       HashSet<String>,
    pub require_prefixes:     Vec<String>,
    pub default_timeout_secs: u64,
    /// Session-owner-configured standing policies, fetched once from the
    /// server at shim startup (see main.rs). These take priority over the
    /// fields above, which are only this shim's own safe-by-default
    /// fallback for a fixed list of read-only/informational tools — without
    /// this, whatever the session owner actually configured via the
    /// approval-policies UI/API was silently never consulted by the legacy
    /// (non-ORB) approval path; the shim just used its own hardcoded list
    /// regardless. The ORB path doesn't have this gap — routes/invoke.rs
    /// already checks server-side standing policy directly.
    pub server_policies: Vec<ServerPolicy>,
}

impl Default for PolicyData {
    fn default() -> Self {
        Self {
            auto_approve:         HashSet::new(),
            always_require:       HashSet::new(),
            require_prefixes:     vec![],
            default_timeout_secs: 300,
            server_policies:      vec![],
        }
    }
}

impl PolicyData {
    /// Server-configured standing policies win — first match wins (session-
    /// wide or scoped to this actor), same precedence
    /// `routes/invoke.rs`'s own standing-policy check already uses
    /// server-side for the ORB path. Falls back to the local safe list only
    /// when nothing from the server matches, so an unreachable server (or a
    /// session with no configured policy) still defaults to requiring
    /// approval for anything not on the fixed read-only list — fail-safe,
    /// not fail-open.
    fn requires_approval(&self, actor_id: &str, tool_name: &str) -> bool {
        for p in &self.server_policies {
            let actor_match = p.actor_id.as_deref().map_or(true, |a| a == actor_id);
            let method_match = p.method_pattern == "*"
                || p.method_pattern == tool_name
                || (p.method_pattern.ends_with('*')
                    && tool_name.starts_with(p.method_pattern.trim_end_matches('*')));
            if actor_match && method_match {
                return p.decision != "auto_approve";
            }
        }
        self.local_requires_approval(tool_name)
    }

    fn local_requires_approval(&self, tool_name: &str) -> bool {
        if self.auto_approve.contains(tool_name) {
            return false;
        }
        if self.always_require.contains(tool_name) {
            return true;
        }
        for prefix in &self.require_prefixes {
            if tool_name.starts_with(prefix.trim_end_matches('*')) {
                return true;
            }
        }
        true
    }
}

/// Sealed (`mmap` -> `mprotect(PROT_READ)` -> `mseal()`) standing-policy
/// cache — see `crate::sealed`'s module doc. Built once at shim startup via
/// [`Policy::build`] and never mutated again; `Clone` is a cheap `Arc`
/// clone, not a re-seal (there is exactly one sealed mapping for the
/// process's whole life).
#[derive(Clone)]
pub struct Policy(SealedJson<PolicyData>);

impl Policy {
    /// Builds the plain, mutable [`PolicyData`] via `build`, then seals it
    /// once. `build` is synchronous by design — any async fetch (e.g. the
    /// server-policy GET) must complete before calling this, its result
    /// moved into the closure, so the sealed region is written exactly
    /// once with the final values. See `main.rs`'s construction site.
    pub fn build(build: impl FnOnce(&mut PolicyData)) -> Self {
        let mut data = PolicyData::default();
        build(&mut data);
        Policy(SealedJson::new(&data))
    }

    pub fn requires_approval(&self, actor_id: &str, tool_name: &str) -> bool {
        self.0.get().requires_approval(actor_id, tool_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_auto_approve_list_skips_approval() {
        let policy = Policy::build(|p| {
            p.auto_approve.insert("read_file".to_string());
        });
        assert!(!policy.requires_approval("actor-1", "read_file"));
    }

    #[test]
    fn unknown_tool_defaults_to_requiring_approval() {
        // Fail-safe, not fail-open -- see PolicyData::local_requires_approval's doc.
        let policy = Policy::build(|_| {});
        assert!(policy.requires_approval("actor-1", "some_unlisted_tool"));
    }

    #[test]
    fn always_require_wins_over_prefix() {
        let policy = Policy::build(|p| {
            p.always_require.insert("solarplex_exec".to_string());
            p.require_prefixes.push("solarplex_*".to_string());
        });
        assert!(policy.requires_approval("actor-1", "solarplex_exec"));
    }

    #[test]
    fn server_policy_overrides_local_auto_approve() {
        // A server-configured always_deny for this actor must win even
        // though the local fallback list would otherwise auto-approve --
        // this is exactly the local-bypass risk sealing is meant to close:
        // server_policies must be the thing consulted first, unconditionally.
        let policy = Policy::build(|p| {
            p.auto_approve.insert("read_file".to_string());
            p.server_policies.push(ServerPolicy {
                actor_id:       Some("actor-1".to_string()),
                method_pattern: "read_file".to_string(),
                decision:       "always_deny".to_string(),
            });
        });
        assert!(policy.requires_approval("actor-1", "read_file"));
        // A different actor isn't covered by the actor-scoped server
        // policy, so it falls through to the local auto-approve list.
        assert!(!policy.requires_approval("actor-2", "read_file"));
    }

    #[test]
    fn server_wildcard_policy_matches_any_actor_and_prefix() {
        let policy = Policy::build(|p| {
            p.server_policies.push(ServerPolicy {
                actor_id:       None,
                method_pattern: "solarplex_*".to_string(),
                decision:       "auto_approve".to_string(),
            });
        });
        assert!(!policy.requires_approval("anyone", "solarplex_read_feed"));
        assert!(policy.requires_approval("anyone", "unrelated_tool"));
    }

    #[test]
    fn cloning_a_policy_preserves_behavior() {
        let policy = Policy::build(|p| {
            p.auto_approve.insert("list_directory".to_string());
        });
        let cloned = policy.clone();
        assert!(!cloned.requires_approval("actor-1", "list_directory"));
    }
}
