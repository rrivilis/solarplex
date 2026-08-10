//! Protection ring type system for Solarplex effect algebra.
//!
//! Every mutation an agent can cause falls into one of three rings.  The ring
//! determines which commit primitive is available and therefore how strong the
//! guarantee can be.  This is not a policy layer — it is the honest location of
//! every guarantee-strength claim in the architecture.
//!
//! ```text
//! Ring 0 — Solarplex-managed state     Postgres CAS    prevention
//! Ring 1 — filesystem writes           POSIX write     detection-in-log
//! Ring 2 — shell / imperative          human approval  prevention (sandbox) + detection
//! ```
//!
//! The commit barrier checks two orthogonal invariants:
//!
//! - **Authority** (cap DAG): "may this principal cause this effect?"
//! - **Consistency** (CAS hash): "may this effect land against the state it claims to have read?"
//!
//! Ring 0 enforces both. Ring 1 enforces authority; consistency is detected
//! post-hoc. Ring 2 enforces authority; consistency is delegated to the human.
//!
//! See THREAT_MODEL.md §4.4 for the full three-tier analysis.

use serde::{Deserialize, Serialize};

// ── Ring 0: Solarplex-managed state ──────────────────────────────────────────

/// The effect types that Ring 0 commits with full atomic CAS guarantees.
///
/// Stored as snake_case strings in `write_proposals.effect_type`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier1Type {
    ArtifactPatch,
    ContextEntry,
}

impl Tier1Type {
    /// Parse from the DB wire representation.
    /// Returns `None` for unknown strings — the commit path returns 422.
    pub fn from_db_str(s: &str) -> Option<Self> {
        match s {
            "artifact_patch" => Some(Self::ArtifactPatch),
            "context_entry"  => Some(Self::ContextEntry),
            _                => None,
        }
    }

    pub fn as_db_str(&self) -> &'static str {
        match self {
            Self::ArtifactPatch => "artifact_patch",
            Self::ContextEntry  => "context_entry",
        }
    }
}

/// A Ring-0 effect: Solarplex-managed state mutation committed under server-side
/// Postgres CAS.  Cannot land against stale state.
///
/// Constructed by the commit handler after retrieving and locking the proposal.
/// The effect_type field drives dispatch to the correct commit path.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0Effect {
    pub proposal_id: String,
    pub effect_type: Tier1Type,
}

/// Receipt returned when a Ring-0 effect commits successfully.
///
/// The `h_before` / `h_after` fingerprints make the receipt self-describing:
/// an auditor can verify the transition from the receipt alone without re-reading
/// artifact history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring0Receipt {
    pub proposal_id: String,
    pub event_id:    String,
    /// Hash of state before the effect (sha256:<hex>).
    pub h_before:    String,
    /// Hash of state after the effect (sha256:<hex>).
    pub h_after:     String,
}

// ── Ring 1: filesystem writes ─────────────────────────────────────────────────

/// Before/after content hashes for a filesystem write.
/// Format: `"sha256:<hex>"`.
///
/// These are declared in the tool call args and bound by the execution receipt
/// before the human approves.  The sidecar reads both values before and after
/// the write and attests the result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashPair {
    /// Hash the agent claims the file has before the write (sha256:<hex>).
    pub before: String,
    /// Hash the agent claims the file will have after the write (sha256:<hex>).
    pub after:  String,
}

/// A Ring-1 effect: filesystem write authorized via receipt arg-binding with
/// before/after hashes.  Executed by the sidecar; verified by attestation.
///
/// Detection only — POSIX provides no atomic CAS primitive; neither the server
/// nor the sidecar can prevent a write to stale state at the filesystem layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring1Effect {
    pub receipt_id: String,
    pub cap_id:     String,
    pub tool:       String,
    pub path:       String,
    /// The approved hashes from the receipt (what the human saw).
    pub hashes:     HashPair,
}

/// Receipt returned by a Ring-1 attest call.
///
/// Always succeeds — the write already happened; the receipt records what occurred.
/// `hash_mismatch = true` is a security event: surface it for alerting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring1Receipt {
    pub attestation_id: String,
    /// True when observed hashes diverged from approved hashes.
    /// A security event recorded permanently in `file_write_attestations`.
    pub hash_mismatch:  bool,
}

// ── Ring 2: shell / imperative ────────────────────────────────────────────────

/// Per-path filesystem operations observed by the scout or declared in the receipt.
///
/// Maps to Landlock `AccessFs` flags at enforcement time:
/// - `create` → `MAKE_REG | MAKE_DIR | MAKE_FIFO | MAKE_SOCK | MAKE_CHAR | MAKE_BLOCK | MAKE_SYM`
/// - `write`  → `WRITE_FILE | TRUNCATE`
/// - `delete` → `REMOVE_FILE | REMOVE_DIR`
/// - `rename` → `REMOVE_FILE | REMOVE_DIR | MAKE_REG | MAKE_DIR | MAKE_SYM`
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileOps {
    pub create: bool,
    pub write:  bool,
    pub delete: bool,
    pub rename: bool,
}

impl FileOps {
    pub fn any(&self) -> bool {
        self.create || self.write || self.delete || self.rename
    }

    pub fn merge(&mut self, other: &FileOps) {
        self.create |= other.create;
        self.write  |= other.write;
        self.delete |= other.delete;
        self.rename |= other.rename;
    }
}

/// A raw file access event captured by the scout (concrete path + observed ops).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEvent {
    pub path: String,
    pub ops:  FileOps,
}

/// Declared file access for a specific path pattern (PathPattern + permitted ops).
/// The sandbox grants exactly the ops listed — no other write access is permitted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEffect {
    pub path: PathPattern,
    pub ops:  FileOps,
}

/// A filesystem access pattern used in `DeclaredEffects`.
///
/// Suffix determines match semantics:
/// - `/**` — recursive subtree match (path and all descendants)
/// - `/*`  — direct children only (non-recursive)
/// - else  — exact path match
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathPattern(pub String);

impl PathPattern {
    pub fn matches(&self, path: &str) -> bool {
        let pat = &self.0;
        if let Some(prefix) = pat.strip_suffix("/**") {
            path == prefix || path.starts_with(&format!("{prefix}/"))
        } else if let Some(prefix) = pat.strip_suffix("/*") {
            path.strip_prefix(&format!("{prefix}/"))
                .map(|rest| !rest.is_empty() && !rest.contains('/'))
                .unwrap_or(false)
        } else {
            path == pat
        }
    }

    /// Return the longest concrete path that anchors this pattern.
    /// Used as the bind-mount target and landlock rule path.
    pub fn anchor_path(&self) -> &str {
        let pat = &self.0;
        if let Some(p) = pat.strip_suffix("/**") { p }
        else if let Some(p) = pat.strip_suffix("/*") { p }
        else { pat }
    }
}

/// Effects a Ring-2 command is approved to produce, derived from the
/// runahead scout manifest and stored in the approval record before the
/// human votes.
///
/// The Ring-2 sandbox executor derives its entire policy — bwrap mounts,
/// seccomp denylist, landlock FS rules — from this struct alone.  Nothing
/// outside this struct determines what the sandboxed command is allowed to do.
/// This is the projection of the ORB receipt onto kernel enforcement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeclaredEffects {
    /// Per-path filesystem access effects declared at approval time.
    /// Landlock enforces exactly the ops listed for each path; all other
    /// paths in the sandbox are read-only.
    pub file_effects: Vec<FileEffect>,
    /// Whether the command may open network connections.
    /// Maps to bwrap `--unshare-net` + seccomp socket/connect/bind deny.
    pub network_access: bool,
    /// Whether the command may spawn additional subprocesses via execve.
    /// Maps to seccomp execve/execveat deny.
    pub subprocess_exec: bool,
    /// Cap-level override: allow writes to paths not declared at approval time.
    /// When true, per-path landlock rules are skipped (bwrap FS isolation still
    /// applies).  Requires explicit cap permission; false by default.
    pub allow_dynamic_paths: bool,
}

impl DeclaredEffects {
    /// Promote a scout manifest's predicted effects to declared effects.
    ///
    /// Merges events for the same path (union policy): if the scout saw both
    /// a CREATE and a WRITE to the same path across the exec tree, the declared
    /// effect grants both.
    pub fn from_scout(scout: &ScoutManifest) -> Self {
        // Union: merge FileOps for repeated paths.
        let mut map: std::collections::HashMap<String, FileOps> = std::collections::HashMap::new();
        for fe in &scout.file_effects {
            map.entry(fe.path.clone()).or_default().merge(&fe.ops);
        }
        let file_effects = map.into_iter()
            .map(|(path, ops)| FileEffect { path: PathPattern(path), ops })
            .collect();

        DeclaredEffects {
            file_effects,
            network_access:      !scout.network_connects.is_empty(),
            // Scout subprocesses[0] is the command itself; >1 means it spawns children.
            subprocess_exec:     scout.subprocesses.len() > 1,
            allow_dynamic_paths: false,
        }
    }
}

/// A Ring-2 effect: non-declarative, human-gated.
///
/// No automated primitive can verify this effect: a command plan is opaque,
/// its effect is not a declared content diff, and there is no hash fence
/// available.  The human approval decision is authoritative.
///
/// `declared_effects` carries the sandbox policy derived from the scout
/// manifest.  The executor uses this to build bwrap/landlock/seccomp
/// constraints before running the command.  `None` when the scout did not
/// run (non-Linux, strace absent, or queue-full degradation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ring2Effect {
    pub approval_id:      String,
    pub tool:             String,
    pub declared_effects: Option<DeclaredEffects>,
}

// ── Ring-2 scout manifests ────────────────────────────────────────────────────

/// Effect manifest produced by the Ring-2 runahead scout.
///
/// The scout speculatively executes a shell command during the human approval
/// window — idle latency that would otherwise be wasted.  The manifest describes
/// what the command was observed to access, modify, and spawn under sandboxed
/// observation, enriching the approval UI and providing a comparison surface
/// for post-execution divergence detection.
///
/// This is a heuristic signal, not a preventative gate.  Divergence between
/// `scout_manifest` and `execution_manifest` is a Ring-2 security event but
/// does not block execution — the human approval decision is authoritative.
///
/// `sandbox_backend = "strace"` on Linux when strace(1) is available.
/// `sandbox_backend = "none"` on other platforms or when strace is missing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScoutManifest {
    /// The command string that was scouted (as extracted from tool args).
    pub command:          String,
    /// Files the command opened for reading only.
    pub file_reads:       Vec<String>,
    /// Per-path filesystem effects observed (openat writes, unlink, rename).
    /// Replaces the old flat `file_writes` list; carries per-op granularity.
    pub file_effects:     Vec<FileEvent>,
    /// Network destinations the command attempted to connect to ("ip:port").
    pub network_connects: Vec<String>,
    /// Processes the command spawned (argv\[0\] of each execve).
    pub subprocesses:     Vec<String>,
    /// Wall-clock time the scout ran before completing or being killed (milliseconds).
    pub duration_ms:      u64,
    /// Observation backend used.
    pub sandbox_backend:  String,
    /// True when the event count hit the capture cap.  Manifest is partial.
    pub truncated:        bool,
}

/// Observed effects of a Ring-2 command's actual execution, captured post-hoc
/// by the sidecar for comparison against the runahead scout's manifest.
///
/// On platforms without syscall observation, only paths the scout predicted
/// would be written are stat-checked (before/after mtime + size comparison).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionManifest {
    /// Files that changed (mtime or size) relative to the pre-execution snapshot.
    pub files_changed:     Vec<String>,
    /// Paths the scout predicted would be written that were NOT changed.
    pub missing_writes:    Vec<String>,
    /// Paths that changed but were NOT in the scout's write list.
    pub unexpected_writes: Vec<String>,
}

impl ExecutionManifest {
    /// True when actual execution diverged from the scout's prediction.
    ///
    /// Divergence is a Ring-2 security event: the command did something
    /// different from what was observed during the approval window.
    pub fn is_diverged(&self) -> bool {
        !self.unexpected_writes.is_empty() || !self.missing_writes.is_empty()
    }
}
