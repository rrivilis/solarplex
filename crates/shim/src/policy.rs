use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// A standing policy fetched from the server
/// (`GET /sessions/:id/approval-policies`) — mirrors the server's own
/// `crate::state::StandingPolicy` shape.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerPolicy {
    pub actor_id:       Option<String>,
    pub method_pattern: String,
    /// "auto_approve" | "always_deny"
    pub decision:       String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
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
    #[serde(skip)]
    pub server_policies: Vec<ServerPolicy>,
}

impl Default for Policy {
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

impl Policy {
    /// Server-configured standing policies win — first match wins (session-
    /// wide or scoped to this actor), same precedence
    /// `routes/invoke.rs`'s own standing-policy check already uses
    /// server-side for the ORB path. Falls back to the local safe list only
    /// when nothing from the server matches, so an unreachable server (or a
    /// session with no configured policy) still defaults to requiring
    /// approval for anything not on the fixed read-only list — fail-safe,
    /// not fail-open.
    pub fn requires_approval(&self, actor_id: &str, tool_name: &str) -> bool {
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
