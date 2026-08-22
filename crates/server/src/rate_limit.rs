//! Both rate-limit tiers — Tier 1 (session/entity-scoped) and Tier 2 (user/
//! tenant-scoped, or fanning out across session tasks) — live in this one
//! module, both as a `DashMap` on `AppState`, both checked synchronously
//! before any durable write. They're split into two types (`GlobalLimiter`
//! below, `SessionRateLimiter` further down) only because their keys carry
//! different scope, not because they live in different places:
//!
//! - **Tier 2** keys exist before any session does (creating an actor) or
//!   span every session an identity touches (a tenant's LLM spend, an
//!   invite-sending rate) — no single session could see the whole picture
//!   even if it wanted to.
//! - **Tier 1** keys (message posting, artifact creation, ...) are scoped
//!   to one session, but still can't live inside that session's own
//!   `SessionMemory` / session task — see `session::rate_limit`'s module
//!   doc for why: the durable write these are meant to gate happens
//!   synchronously in the REST/WS handler, before the session task (fed
//!   fire-and-forget) ever sees the action, so a gate inside the session
//!   task's own effect loop is structurally too late to block anything.
//!
//! Both reuse the same `Policy`/`Admission`/`FixedWindowBucket` vocabulary
//! from `session::rate_limit`, not reinvented here.
//!
//! # A live example of the alternative
//!
//! `AppState::invoke_rate_limits` (`state.rs`) is the pattern this module
//! is deliberately *not* — a bucket keyed by `cap_id` (an infrastructural
//! identifier) with one fixed quota (60/min), not a semantic action. It
//! predates this module and still gates `routes/invoke.rs` as-is; folding
//! it into `GlobalRateLimitKey::ToolCallDispatch` is a natural follow-up,
//! not done here to avoid rewriting a live, working gate in the same pass
//! that introduces the vocabulary it would move to.

use dashmap::DashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use session::rate_limit::{Admission, FixedWindowBucket, Policy, RateLimitKey};
use ulid::Ulid;

use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a bucket must sit untouched before a sweep reclaims it — must
/// stay above the longest policy window either tier uses (currently 3600s,
/// `AgentAttach`/`OwnershipTransfer`/`ActorCreate`), or a sweep could evict
/// a bucket that's still legitimately mid-window. See `sweep_rate_limits`.
const IDLE_BUCKET_TTL: Duration = Duration::from_secs(2 * 3600);
const SWEEP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// Variant name only, from `Debug`, truncated at the first space/brace/paren
/// -- e.g. `MessagePost { actor_id: "01J..." }` becomes `"MessagePost"`.
/// Both `RateLimitKey` and `GlobalRateLimitKey` carry per-entity fields
/// (actor ids, an IP, an OIDC sub) that must never become a Prometheus
/// label value (unbounded cardinality, one time series per entity forever);
/// this stays correct as either enum grows new variants without needing a
/// hand-maintained match here, unlike an explicit label match would.
fn key_metric_label<T: std::fmt::Debug>(key: &T) -> String {
    let debug = format!("{key:?}");
    debug
        .split(|c: char| c == ' ' || c == '(' || c == '{')
        .next()
        .unwrap_or(&debug)
        .to_string()
}

/// What's being rate-limited at Tier 2. See this module's doc comment for
/// why these specifically can't live in any one session's `SessionMemory`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GlobalRateLimitKey {
    /// New-actor creation via OIDC first-login. Keyed by `(sub, provider)`
    /// — the same identity pair `sub_to_actor_id` already treats as the
    /// unique key for "have we seen this login before" — not by the actor
    /// id, which doesn't exist yet for the case this is guarding against.
    ///
    /// This blunts a scripted loop hammering *one* external identity; it
    /// does nothing against an attacker presenting many distinct valid
    /// identities (each gets its own fresh bucket). Accepted for v1 since
    /// OAuth-only auth already puts real friction in front of minting a new
    /// identity in the first place. If bulk signup abuse across many
    /// identities ever becomes a real problem, add a coarser IP/tenant
    /// admission layer for it rather than stretching this key to cover
    /// something it isn't scoped for.
    ActorCreate { sub: String, provider: String },
    /// Creating a brand-new session. Keyed by the creator's actor_id — there
    /// is no session_id yet for this to be a Tier-1 key against.
    SessionCreate { actor_id: String },
    /// `GET /auth/oidc/start` and `GET /auth/oidc/callback` — the one part
    /// of the API that is pre-authentication by definition, so there is no
    /// actor_id to key on either. Keyed by client IP instead (see
    /// `crate::client_ip`). Both routes share one bucket: `start` is cheap
    /// but grows the in-memory CSRF/PKCE state map on every hit; `callback`
    /// is the expensive one (a real network round trip to the provider) and
    /// the actual brute-force target.
    OidcAttempt { ip: String },
    /// Attempting to redeem a session invite. Keyed by the redeeming
    /// actor's id, checked immediately after `sp_token` validation and
    /// before the invite lookup — bounds how fast one signed-in identity
    /// can try invite ids against `POST /invites/:id/redeem`.
    InviteRedeemAttempt { actor_id: String },
    // Deliberately not adding SendMemberInvite / LLMWrite / ToolCallDispatch
    // stubs with no real call site behind them yet — an unenforced variant
    // is worse than no variant, since it reads as "covered" without being
    // covered. Add each alongside the call site that actually checks it.
}

impl GlobalRateLimitKey {
    pub fn label(&self) -> &'static str {
        match self {
            GlobalRateLimitKey::ActorCreate         { .. } => "ActorCreate",
            GlobalRateLimitKey::SessionCreate       { .. } => "SessionCreate",
            GlobalRateLimitKey::OidcAttempt         { .. } => "OidcAttempt",
            GlobalRateLimitKey::InviteRedeemAttempt { .. } => "InviteRedeemAttempt",
        }
    }

    pub fn default_policy(&self) -> Option<Policy> {
        match self {
            // 3 new actors/hour per (sub, provider) — this only fires for
            // the *first* login of a given identity; every login after
            // that resolves through find_actor_by_sub and never reaches
            // this check at all. Generous on purpose: it exists to blunt
            // a scripted account-creation loop, not to rate-limit real
            // sign-ins, which this key is never even consulted for.
            GlobalRateLimitKey::ActorCreate { .. } =>
                Some(Policy::Count { max: 3, window: Duration::from_secs(3600) }),
            // Bounds session-spam without getting in the way of a real
            // workflow that creates several sessions in a row.
            GlobalRateLimitKey::SessionCreate { .. } =>
                Some(Policy::Count { max: 20, window: Duration::from_secs(3600) }),
            // Pre-auth, so this is the direct brute-force/DoS target on the
            // whole API. Generous enough that a shared office/NAT IP with
            // several people signing in at once doesn't trip it, tight
            // enough to blunt a scripted loop.
            GlobalRateLimitKey::OidcAttempt { .. } =>
                Some(Policy::Count { max: 20, window: Duration::from_secs(60) }),
            // Invite ids are ULIDs (not practically guessable), so this is
            // defense in depth rather than the primary control.
            GlobalRateLimitKey::InviteRedeemAttempt { .. } =>
                Some(Policy::Count { max: 10, window: Duration::from_secs(60) }),
        }
    }
}

/// Shared bucket store for every Tier-2 key. One instance lives on
/// `AppState`; `DashMap` gives per-key locking so concurrent checks across
/// unrelated keys never contend.
#[derive(Default)]
pub struct GlobalLimiter {
    buckets: DashMap<GlobalRateLimitKey, FixedWindowBucket>,
}

impl GlobalLimiter {
    pub fn new() -> Self {
        Self { buckets: DashMap::new() }
    }

    /// Check and, on success, consume one unit against `key`'s policy.
    /// Fail-open on a missing policy — same reasoning as Tier 1's `check`.
    pub fn check(&self, key: GlobalRateLimitKey) -> (Admission, Option<Policy>) {
        let Some(policy) = key.default_policy() else {
            return (Admission::Allowed, None);
        };
        let label = key_metric_label(&key);
        let now = Instant::now();
        let mut bucket = self.buckets.entry(key).or_insert_with(|| FixedWindowBucket::fresh(now));
        let admission = bucket.check_and_consume(&policy, now);
        metrics::counter!(
            "rate_limit_admission_total",
            "tier"   => "global",
            "key"    => label,
            "result" => if matches!(admission, Admission::Allowed) { "allowed" } else { "denied" },
        ).increment(1);
        (admission, Some(policy))
    }

    /// Evict buckets idle for at least `idle_for` — see `sweep_rate_limits`.
    fn sweep_idle(&self, idle_for: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| !bucket.is_idle(now, idle_for));
    }
}

// ── Tier 1: session/entity-scoped ───────────────────────────────────────────

/// Shared bucket store for every Tier-1 key, keyed by `(session_id,
/// RateLimitKey)` so the same actor's `MessagePost` bucket in one session
/// never contends with or shares state with their bucket in another. Lives
/// on `AppState` (one instance for the whole process) rather than inside
/// any single session task's `SessionMemory` — see `session::rate_limit`'s
/// module doc for why: the durable write this is meant to gate happens in
/// the REST handler, synchronously, never inside the session task at all.
#[derive(Default)]
pub struct SessionRateLimiter {
    buckets: DashMap<(String, RateLimitKey), FixedWindowBucket>,
}

impl SessionRateLimiter {
    pub fn new() -> Self {
        Self { buckets: DashMap::new() }
    }

    /// Check and, on success, consume one unit against `key`'s policy
    /// within `session_id`. Fail-open on a missing policy, same as Tier 2.
    pub fn check(&self, session_id: &str, key: RateLimitKey) -> (Admission, Option<Policy>) {
        let Some(policy) = key.default_policy() else {
            return (Admission::Allowed, None);
        };
        let label = key_metric_label(&key);
        let now = Instant::now();
        let mut bucket = self
            .buckets
            .entry((session_id.to_string(), key))
            .or_insert_with(|| FixedWindowBucket::fresh(now));
        let admission = bucket.check_and_consume(&policy, now);
        metrics::counter!(
            "rate_limit_admission_total",
            "tier"   => "session",
            "key"    => label,
            "result" => if matches!(admission, Admission::Allowed) { "allowed" } else { "denied" },
        ).increment(1);
        (admission, Some(policy))
    }

    /// Evict buckets idle for at least `idle_for` — see `sweep_rate_limits`.
    fn sweep_idle(&self, idle_for: Duration) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| !bucket.is_idle(now, idle_for));
    }
}

/// Periodic reclamation for both tiers. Bucket keys carry caller-supplied
/// identity (`actor_id`, `(sub, provider)`, `session_id`) with unbounded
/// cardinality over a long-running process's lifetime — an idle bucket's
/// counter implicitly resets on next use, but the map entry itself sits
/// there forever unless something evicts it. Runs far less often than the
/// other sweepers in `main.rs` (approval timeouts, stale agents): those
/// bound user-visible staleness on a scale of seconds, this one only bounds
/// memory growth on a scale the `IDLE_BUCKET_TTL` itself already sets, so
/// there's nothing to gain from checking more often than that.
pub async fn sweep_rate_limits(state: Arc<crate::state::AppState>) {
    let mut interval = tokio::time::interval(SWEEP_INTERVAL);
    loop {
        interval.tick().await;
        state.rate_limits.sweep_idle(IDLE_BUCKET_TTL);
        state.session_rate_limits.sweep_idle(IDLE_BUCKET_TTL);
    }
}

// ── Shared REST-handler gates ────────────────────────────────────────────────
//
// One gate per tier, called synchronously before the durable write it's
// meant to block — same rule both tiers already follow (see this module's
// top doc comment). Moved here from routes/sessions.rs (which had the only
// caller when there was only one) now that approvals.rs, session_links.rs,
// session_remotes.rs, invites.rs, authority_import.rs, and auth.rs all need
// the same shape.

/// Tier-1 (session-scoped) gate. Returns `Some(response)` to return 429
/// immediately, or `None` to proceed. On denial, also emits the durable
/// `EffectRateLimited` audit event to the session — the REST handler is the
/// true "did this action happen" boundary, so this is where that record
/// belongs, not somewhere downstream that might never see the attempt.
pub async fn gate_session(
    state: &Arc<crate::state::AppState>,
    session_id: &str,
    actor_id: &str,
    key: RateLimitKey,
) -> Option<Response> {
    let key_label = key.label();
    let (admission, policy) = state.session_rate_limits.check(session_id, key);
    let Admission::Denied { retry_after } = admission else {
        return None;
    };
    let policy_desc = policy.map(|p| p.describe()).unwrap_or_default();
    let retry_after_secs = retry_after.as_secs();
    tracing::warn!(session_id, actor_id, key = key_label, policy = policy_desc, "rate limited");
    let event = protocol::messages::WsMessage::new(
        Ulid::new().to_string(),
        protocol::messages::WsPayload::EffectRateLimited {
            session_id: session_id.to_string(),
            actor: actor_id.to_string(),
            timestamp: Utc::now(),
            seq: 0,
            payload: protocol::messages::EffectRateLimitedPayload {
                key_label: key_label.to_string(),
                policy: policy_desc.clone(),
                retry_after_secs,
            },
        },
    );
    crate::ws::emit_to_session(state, session_id, actor_id, event).await;
    Some(rate_limited_response(key_label, &policy_desc, retry_after_secs))
}

/// Tier-2 (global) gate. Same contract as `gate_session`, but for keys that
/// exist before any session does (creating one) or aren't session-shaped at
/// all (an IP, pre-authentication). No session to emit an audit event to —
/// a `tracing::warn!` is the whole record for these.
pub fn gate_global(key: GlobalRateLimitKey, limiter: &GlobalLimiter) -> Option<Response> {
    let key_label = key.label();
    let (admission, policy) = limiter.check(key);
    let Admission::Denied { retry_after } = admission else {
        return None;
    };
    let policy_desc = policy.map(|p| p.describe()).unwrap_or_default();
    let retry_after_secs = retry_after.as_secs();
    tracing::warn!(key = key_label, policy = policy_desc, "rate limited (global)");
    Some(rate_limited_response(key_label, &policy_desc, retry_after_secs))
}

fn rate_limited_response(key_label: &str, policy_desc: &str, retry_after_secs: u64) -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        Json(serde_json::json!({
            "error": "rate_limited",
            "key": key_label,
            "policy": policy_desc,
            "retry_after_secs": retry_after_secs,
        })),
    )
        .into_response()
}
