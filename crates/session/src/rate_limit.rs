//! Rate-limit vocabulary — `RateLimitKey`, `Policy`, `Admission`, and the
//! `FixedWindowBucket` algorithm — shared between `crates/server`'s two
//! limiter tiers (session/entity-scoped and user/tenant-scoped).
//!
//! An earlier version of this module also owned Tier-1 bucket *storage*
//! (a field on `SessionMemory`) and was checked from inside the session
//! task's own effect-processing loop. That placement was wrong: every
//! action this was meant to gate (`MessagePosted`, `ArtifactCreated`, ...)
//! has its durable, user-visible write happen directly in the REST handler
//! via `emit_to_session` — *before* that handler ever feeds the action
//! into the session task. By the time the session task's effect loop saw
//! the event, the message was already persisted and broadcast to every
//! connected client; the gate could produce an accurate audit trail but
//! could never actually prevent anything.
//!
//! The fix is enforcement has to happen synchronously, at the REST
//! handler, before its own `emit_to_session` call — the same place Tier 2
//! (`ActorCreate`) was already correctly checking. Both tiers now live in
//! `crates/server::rate_limit`, checked synchronously against a shared
//! `DashMap`, before any durable write. This module keeps only the parts
//! that don't need axum/tokio/dashmap: the key taxonomy, the policy table,
//! and the bucket algorithm itself — `crates/session` has zero runtime
//! dependencies by design (see this crate's `lib.rs`), and a concurrent
//! map is exactly the kind of thing that doesn't belong here.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

// ── Key ──────────────────────────────────────────────────────────────────────

/// What's being rate-limited, scoped to one session. `crates/server` pairs
/// this with a `session_id` to form the actual storage key (a `DashMap`
/// key, so this derives `Hash` too, not just `Ord`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RateLimitKey {
    MessagePost      { actor_id: String },
    ContextAdd       { actor_id: String },
    ArtifactCreate   { actor_id: String },
    ApprovalRequest  { actor_id: String },
    AgentAttach      { actor_id: String },
    OwnershipTransfer,
    /// Editing or removing an existing artifact. Combines update+delete into
    /// one bucket, same risk profile (you already hold write access to the
    /// artifact; this bounds how fast you can churn through it).
    ArtifactMutate      { actor_id: String },
    /// Casting a vote on an approval request.
    ApprovalVote        { actor_id: String },
    /// Delegating an approval to another (linked) session's own decision
    /// process. More expensive than a normal approval action: it creates a
    /// saga and a synthetic approval in the target session.
    CrossSessionDelegate { actor_id: String },
    /// The three shim-originated PATCH endpoints that feed an approval's
    /// scout manifest, execution manifest, and declared-effects payload.
    /// Grouped into one key since they're all plumbing for a single
    /// approval's lifecycle, called by the shim, not directly by a human —
    /// this bound exists to catch a malfunctioning or compromised shim
    /// hammering the endpoint, not to constrain normal usage.
    ManifestPatch        { actor_id: String },
    /// Session-to-session linking: minting or redeeming a link invite, the
    /// direct-link fast path, and muting/unlinking an existing link.
    SessionLinkMutate    { actor_id: String },
    /// Session-to-session remotes: adding one, fetching new events through
    /// it, or removing it. `fetch` is the one that does real work (pulls up
    /// to 500 events from another session), so this key exists mainly to
    /// bound that.
    SessionRemoteMutate  { actor_id: String },
    /// Granting someone a future way into this session: creating a session
    /// invite, minting an attach (cap) token, or rotating the join token.
    /// Grouped because all three are "credential a newcomer can redeem"
    /// actions with the same abuse shape.
    MembershipGrant      { actor_id: String },
    /// Minting or delegating a capability from an authority-dsl s-expression
    /// via `POST /sessions/:id/authority/import`.
    AuthorityImport      { actor_id: String },
}

impl RateLimitKey {
    /// Discriminant name only — used in logs and in the durable audit
    /// event's `key_label` field.
    pub fn label(&self) -> &'static str {
        match self {
            RateLimitKey::MessagePost       { .. } => "MessagePost",
            RateLimitKey::ContextAdd        { .. } => "ContextAdd",
            RateLimitKey::ArtifactCreate    { .. } => "ArtifactCreate",
            RateLimitKey::ApprovalRequest   { .. } => "ApprovalRequest",
            RateLimitKey::AgentAttach       { .. } => "AgentAttach",
            RateLimitKey::OwnershipTransfer         => "OwnershipTransfer",
            RateLimitKey::ArtifactMutate         { .. } => "ArtifactMutate",
            RateLimitKey::ApprovalVote           { .. } => "ApprovalVote",
            RateLimitKey::CrossSessionDelegate   { .. } => "CrossSessionDelegate",
            RateLimitKey::ManifestPatch          { .. } => "ManifestPatch",
            RateLimitKey::SessionLinkMutate      { .. } => "SessionLinkMutate",
            RateLimitKey::SessionRemoteMutate    { .. } => "SessionRemoteMutate",
            RateLimitKey::MembershipGrant        { .. } => "MembershipGrant",
            RateLimitKey::AuthorityImport        { .. } => "AuthorityImport",
        }
    }

    /// The default policy for this key. `None` means unlimited — a key
    /// with no policy defined never blocks (fail-open on missing config,
    /// not fail-closed: an operator who hasn't configured a limit for some
    /// key shouldn't have every action silently blocked by omission).
    pub fn default_policy(&self) -> Option<Policy> {
        match self {
            RateLimitKey::MessagePost      { .. } => Some(Policy::Count { max: 30, window: Duration::from_secs(60) }),
            RateLimitKey::ContextAdd       { .. } => Some(Policy::Count { max: 20, window: Duration::from_secs(60) }),
            RateLimitKey::ArtifactCreate   { .. } => Some(Policy::Count { max: 10, window: Duration::from_secs(60) }),
            RateLimitKey::ApprovalRequest  { .. } => Some(Policy::Count { max: 10, window: Duration::from_secs(60) }),
            RateLimitKey::AgentAttach      { .. } => Some(Policy::Count { max: 5,  window: Duration::from_secs(3600) }),
            RateLimitKey::OwnershipTransfer         => Some(Policy::Count { max: 10, window: Duration::from_secs(3600) }),
            // Same scale as ArtifactCreate, slightly higher ceiling since
            // this bucket covers two actions (update + delete) sharing one
            // window.
            RateLimitKey::ArtifactMutate       { .. } => Some(Policy::Count { max: 20, window: Duration::from_secs(60) }),
            RateLimitKey::ApprovalVote         { .. } => Some(Policy::Count { max: 20, window: Duration::from_secs(60) }),
            // Creates a saga and a synthetic approval in another session —
            // same hourly scale as OwnershipTransfer, not a per-minute action.
            RateLimitKey::CrossSessionDelegate { .. } => Some(Policy::Count { max: 10, window: Duration::from_secs(3600) }),
            // Shim-originated, called repeatedly per approval lifecycle —
            // generous on purpose, this exists to catch a malfunctioning
            // loop, not to constrain normal use.
            RateLimitKey::ManifestPatch        { .. } => Some(Policy::Count { max: 60, window: Duration::from_secs(60) }),
            // Linking sessions is an infrequent admin action.
            RateLimitKey::SessionLinkMutate    { .. } => Some(Policy::Count { max: 20, window: Duration::from_secs(3600) }),
            // `fetch` can legitimately be polled a bit like any other read-
            // with-side-effects; the other two ops in this bucket are rare.
            RateLimitKey::SessionRemoteMutate  { .. } => Some(Policy::Count { max: 30, window: Duration::from_secs(60) }),
            // Minting a credential someone else can redeem — same bar as
            // AgentAttach.
            RateLimitKey::MembershipGrant      { .. } => Some(Policy::Count { max: 10, window: Duration::from_secs(3600) }),
            RateLimitKey::AuthorityImport      { .. } => Some(Policy::Count { max: 10, window: Duration::from_secs(3600) }),
        }
    }
}

// ── Policy ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Policy {
    /// Plain fixed-window count polcy with at most `max` admissions per `window`.
    Count { max: u32, window: Duration },
    /// Cost-weighted bucket. Tier 2's `LLMWrite`-style dollar/unit budgets
    /// use this shape; defined here so both tiers share one vocabulary
    /// even though only Tier 2 has a real `Budget` policy wired up today.
    Budget { max_units: u32, window: Duration },
}

impl Policy {
    fn window(&self) -> Duration {
        match self {
            Policy::Count { window, .. } | Policy::Budget { window, .. } => *window,
        }
    }

    fn capacity(&self) -> u32 {
        match self {
            Policy::Count { max, .. } => *max,
            Policy::Budget { max_units, .. } => *max_units,
        }
    }

    /// Human-readable form for logs and the durable audit event, e.g. "30/60s".
    pub fn describe(&self) -> String {
        format!("{}/{}s", self.capacity(), self.window().as_secs())
    }
}

// ── Admission ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Allowed,
    /// Always carries a concrete wait, computed from the bucket's actual
    /// window state, enough for a caller to return a real `Retry-After`
    /// rather than a made-up one. There's no separate "hold the connection
    /// open and retry server-side" mode here (an earlier version had one);
    /// every caller of this module is a synchronous REST handler that's
    /// going to return a 429 either way, so a soft/hard distinction never
    /// had a different code path to justify it.
    Denied { retry_after: Duration },
}

// ── Bucket ───────────────────────────────────────────────────────────────────

/// A fixed-window counter, deliberately chosen for simplicity over token refills, 
/// and the burst-at-window-boundary imprecision this trades away doesn't
/// matter at the request volumes these policies are sized for. Reset is
/// implicit: once `window_started_at` is more than `window` old, the count
/// is treated as zero rather than explicitly cleared.
///
/// Timed with `std::time::Instant`, not wall-clock `DateTime<Utc>` — this
/// bucket only ever compares two timestamps it produced itself in the same
/// process, so it should use the same clock every other in-process
/// staleness check in this codebase does (see `ws.rs`'s agent-heartbeat
/// sweeper). `Instant` is guaranteed monotonic; `Utc::now()` isn't. An NTP
/// step backward would let a bucket read `elapsed < window` for longer than
/// it should, extending an active window's effective length past what its
/// policy intends. Not serializable (no epoch reference makes sense across
/// a restart), which is also correct: this state is intentionally
/// ephemeral, see this crate's `lib.rs` doc comment and
/// this module's own doc comment above.
///
/// Not evicted automatically; an idle bucket's `window_started_at` simply
/// stops advancing, so it sits in its owning `DashMap` doing nothing until
/// something checks it again. Left alone forever, that's still unbounded
/// memory growth over the lifetime of a long-running process, since these
/// maps are keyed on caller-supplied identity (actor_id, sub, session_id) —
/// see `is_idle` below, which `crates/server::rate_limit`'s periodic sweep
/// uses to reclaim exactly these.
#[derive(Debug, Clone)]
pub struct FixedWindowBucket {
    count:             u32,
    window_started_at: Instant,
}

impl FixedWindowBucket {
    pub fn fresh(now: Instant) -> Self {
        Self { count: 0, window_started_at: now }
    }

    /// Attempt to admit one unit against `policy` at time `now`, mutating
    /// the bucket on success. Denial does not mutate the bucket. A
    /// rejected attempt shouldn't itself count against the quota it just
    /// failed to clear.
    pub fn check_and_consume(&mut self, policy: &Policy, now: Instant) -> Admission {
        let window = policy.window();
        let elapsed = now.saturating_duration_since(self.window_started_at);
        if elapsed >= window {
            self.count = 0;
            self.window_started_at = now;
        }
        if self.count < policy.capacity() {
            self.count += 1;
            Admission::Allowed
        } else {
            Admission::Denied { retry_after: window.saturating_sub(elapsed) }
        }
    }

    /// Whether this bucket has sat untouched for at least `idle_for` 
    /// safe to evict from its map, since a fresh bucket allocated on the
    /// next check behaves identically to this one (its window would have
    /// reset by then regardless). `idle_for` must be at least as long as
    /// the longest policy window in use, or a sweep could evict a bucket
    /// that's still legitimately mid-window.
    pub fn is_idle(&self, now: Instant, idle_for: Duration) -> bool {
        now.saturating_duration_since(self.window_started_at) >= idle_for
    }
}
