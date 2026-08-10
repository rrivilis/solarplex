use std::sync::{Arc, Mutex};
use std::time::Instant;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use openidconnect::core::CoreClient;
use sqlx::PgPool;
use tokio::sync::{broadcast, mpsc};

// ── Invoke rate limiting ──────────────────────────────────────────────────────

/// Simple token-bucket rate limiter: tracks request count within a 60-second
/// rolling window per cap.  Resets on the next call after the window expires.
pub struct RateBucket {
    count:        u32,
    window_start: Instant,
}

impl RateBucket {
    pub fn new() -> Self {
        Self { count: 0, window_start: Instant::now() }
    }

    /// Returns `true` if the request is within the limit and increments the
    /// counter; `false` when the bucket is exhausted for this window.
    pub fn check_and_increment(&mut self, max_per_minute: u32) -> bool {
        if self.window_start.elapsed().as_secs() >= 60 {
            self.count = 0;
            self.window_start = Instant::now();
        }
        if self.count >= max_per_minute {
            return false;
        }
        self.count += 1;
        true
    }
}

// ── Standing approval policies ────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum PolicyDecision {
    AutoApprove,
    AlwaysDeny,
}

/// A standing approval policy for a session.
///
/// Checked after cap/method validation, before the human gate.
/// First matching policy wins (ordered by insertion order).
#[derive(Clone, Debug)]
pub struct StandingPolicy {
    pub id:             String,
    /// None = applies to all cap-bound actors in the session.
    pub actor_id:       Option<String>,
    /// Exact method address ("mcp.slug.tool_name") or prefix with trailing "*"
    /// ("mcp.slug.*" matches all tools for that slug).
    pub method_pattern: String,
    pub decision:       PolicyDecision,
}

// ── Count-Min Sketch for n-gram anomaly scoring ───────────────────────────────

const CMS_DEPTH: usize = 4;
const CMS_WIDTH: usize = 65536; // 2^16 — ~1 MB per row, 4 MB total

/// Number of artifacts that must be ingested before CMS scores are meaningful.
pub const CMS_BASELINE_SAMPLES: u64 = 500;

pub struct CmsState {
    table:        Vec<Vec<u32>>,
    pub samples:  u64,
}

impl CmsState {
    pub fn new() -> Self {
        Self { table: vec![vec![0u32; CMS_WIDTH]; CMS_DEPTH], samples: 0 }
    }

    fn slot(trigram: &[u8], row: usize) -> usize {
        // FNV-1a mix with a per-row constant seed
        const SEEDS: [u64; CMS_DEPTH] = [0x811c9dc5, 0xa5a5a5a5, 0x27d4eb2f, 0x5f4a7c1b];
        let mut h: u64 = SEEDS[row];
        for &b in trigram {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        (h as usize) % CMS_WIDTH
    }

    /// Feed artifact content into the sketch (call at artifact creation time).
    pub fn insert(&mut self, content: &str) {
        let b = content.as_bytes();
        for i in 0..b.len().saturating_sub(2) {
            let tri = &b[i..i + 3];
            for row in 0..CMS_DEPTH {
                let col = Self::slot(tri, row);
                self.table[row][col] = self.table[row][col].saturating_add(1);
            }
        }
        self.samples += 1;
    }

    /// Mean minimum frequency of trigrams in `content`.
    /// Returns `None` when baseline is not yet established.
    /// Low value → anomalous (rare n-grams).
    pub fn score(&self, content: &str) -> Option<f64> {
        if self.samples < CMS_BASELINE_SAMPLES {
            return None;
        }
        let b = content.as_bytes();
        let n = b.len().saturating_sub(2);
        if n == 0 {
            return Some(0.0);
        }
        let total: u64 = (0..n).map(|i| {
            let tri = &b[i..i + 3];
            (0..CMS_DEPTH)
                .map(|row| self.table[row][Self::slot(tri, row)] as u64)
                .min()
                .unwrap_or(0)
        }).sum();
        Some(total as f64 / n as f64)
    }
}

use protocol::types::SessionSnapshot;

use crate::reflector::Reflector;
use crate::session_task::{spawn_session_task, SessionTaskHandle};

/// Capacity for the per-session broadcast channel.
const BROADCAST_CAP: usize = 256;

/// The in-memory materialized view of a session.
///
/// `seq` is the sequence number of the last event that was applied to
/// `state` — i.e. both fields always agree on what Postgres has committed.
/// This is the source-of-truth for WS attach (no DB queries on the hot path).
pub struct LiveSnapshot {
    pub seq:   i64,
    pub state: SessionSnapshot,
}

/// Per-session runtime hub. Holds all live WS connection state.
pub struct SessionHub {
    #[allow(dead_code)]
    pub session_id: String,
    /// Fan-out to every connected actor.
    pub broadcast_tx: broadcast::Sender<Arc<String>>,
    /// Directed messages to a specific actor (e.g. approval.resolved to sidecar).
    pub actor_senders: DashMap<String, mpsc::UnboundedSender<Arc<String>>>,
    /// Atomically-updated snapshot of committed session state.
    ///
    /// `None` until the first WS attach triggers a DB rebuild.  After that,
    /// every committed event is projected onto it via `apply_event` before
    /// being broadcast, so subsequent attaches pay zero DB queries.
    pub snapshot: ArcSwap<Option<LiveSnapshot>>,
    /// Actors whose caps have been revoked and are inside the drain window.
    ///
    /// Key: actor_id.  Value: the wall-clock instant at which the drain window
    /// closes and writes from this actor must be rejected with WS close 4401.
    ///
    /// During the drain window, writes still succeed (drain-bounded liveness).
    /// After the deadline, `handle_ws` rejects writes and closes the connection.
    pub fenced_actors: DashMap<String, Instant>,
    /// Last heartbeat received from each shim-attached agent actor.
    ///
    /// Agents don't hold a WS connection to `/stream` (only human browsers do),
    /// so `actor_senders` never sees them — there was previously no liveness
    /// signal at all for agents beyond the one-shot `agent-attach` announcement.
    /// `sweep_stale_agents` (in ws.rs) periodically checks this map and emits
    /// `ActorDetached` for any actor whose heartbeat has lapsed.
    pub agent_heartbeats: DashMap<String, Instant>,
}

impl SessionHub {
    pub fn new(session_id: String) -> Self {
        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CAP);
        Self {
            session_id,
            broadcast_tx,
            actor_senders: DashMap::new(),
            snapshot: ArcSwap::new(Arc::new(None)),
            fenced_actors: DashMap::new(),
            agent_heartbeats: DashMap::new(),
        }
    }

    /// Broadcast a JSON message to all connected actors.
    pub fn broadcast(&self, msg: Arc<String>) {
        // send fails only if there are no subscribers — that's fine.
        let _ = self.broadcast_tx.send(msg);
    }

    /// Send a directed message to one actor (e.g. approval resolution to sidecar).
    pub fn send_to(&self, actor_id: &str, msg: Arc<String>) {
        if let Some(tx) = self.actor_senders.get(actor_id) {
            let _ = tx.send(msg);
        }
    }

    /// Fence a set of actors: their writes will be rejected after `deadline`.
    ///
    /// Called immediately after a revocation fires.  The drain window is the
    /// time between now and `deadline`; writes during this window still succeed.
    pub fn fence_actors(&self, actor_ids: impl IntoIterator<Item = String>, deadline: Instant) {
        for id in actor_ids {
            self.fenced_actors.insert(id, deadline);
        }
    }

    /// Returns `true` if an actor is fenced AND the drain window has closed.
    ///
    /// During the drain window this returns `false` (actor may still write).
    /// After the deadline it returns `true` and the write must be rejected.
    pub fn is_fenced_and_expired(&self, actor_id: &str) -> bool {
        self.fenced_actors
            .get(actor_id)
            .map(|deadline| Instant::now() > *deadline)
            .unwrap_or(false)
    }
}

// ── OIDC state ────────────────────────────────────────────────────────────────

/// A pending PKCE + nonce entry stored server-side between /auth/oidc/start
/// and /auth/oidc/callback.  Keyed by the CSRF state parameter.
pub struct PkceEntry {
    /// The PKCE code verifier secret — never sent to the provider.
    pub verifier_secret: String,
    /// The OIDC nonce secret — embedded in the ID token for replay prevention.
    pub nonce_secret: String,
    /// Wall-clock expiry.  Entries older than 10 minutes are swept lazily.
    pub expires: Instant,
    /// Where to send the browser after a successful callback, e.g.
    /// `/invite/01J...`. Empty = fall back to `OIDC_FRONTEND_REDIRECT`.
    /// Validated at `oidc_start` time to be a same-origin relative path —
    /// never trust this as an absolute URL (open-redirect risk).
    pub return_to: String,
}

/// OIDC runtime state shared across request handlers.
/// Wrapped in `Option` in AppState: `None` when OIDC is not configured.
pub struct OidcState {
    /// The configured OIDC client (holds provider metadata + credentials).
    pub client: Arc<CoreClient>,
    /// Callback URI registered with the provider.
    #[allow(dead_code)]
    pub redirect_uri: String,
    /// In-flight PKCE entries: state_param → (verifier, nonce, expiry).
    pub pending: DashMap<String, PkceEntry>,
}

pub struct AppState {
    pub db: PgPool,
    /// Per-cap-id invoke rate buckets.  Keyed by cap_id; reset every 60 s.
    pub invoke_rate_limits: DashMap<String, RateBucket>,
    /// Per-session standing approval policies.  Keyed by session_id.
    /// First matching policy wins; human gate is bypassed for auto_approve entries.
    pub approval_policies: DashMap<String, Vec<StandingPolicy>>,
    /// Live session hubs, created on first WS connect, dropped when empty.
    pub hubs: DashMap<String, Arc<SessionHub>>,
    /// Per-session actor tasks (Phase 4+5), replacing Phase 3 `MachineHandle`.
    /// Keyed by session_id; same lifecycle as hubs (created on first connect,
    /// removed when the last actor disconnects).
    ///
    /// Wrapped in `Arc` so the session topology can be shared with individual
    /// session task loops for `Effect::Forward` routing without passing
    /// `Arc<AppState>` into the task (which would create an awkward ownership cycle).
    pub sessions: Arc<DashMap<String, SessionTaskHandle>>,
    /// OIDC state — None when OIDC_ISSUER_URL is not set in the environment.
    pub oidc: Option<OidcState>,
    /// Physical NUMA node count.  Sessions are assigned to nodes deterministically
    /// via FNV-1a hash of the session ID.  Defaults to 1 (single-node, all local).
    /// Set `NUMA_NODES` environment variable to match physical topology on
    /// multi-socket hardware.
    pub numa_nodes: u8,
    /// Global bundle reflector — append-only ordered log for cross-session saga
    /// relay.  Shared across all session tasks via `Arc`.
    pub reflector: Arc<Reflector>,
    /// Global Count-Min Sketch for artifact n-gram anomaly scoring.
    /// Fed at artifact creation time; queried on reads after baseline is full.
    pub cms: Mutex<CmsState>,
    /// Tier-2 (user/tenant-scoped) rate limiter — see `crate::rate_limit`'s
    /// module doc for why these keys can't be scoped to any one session.
    pub rate_limits: crate::rate_limit::GlobalLimiter,
    /// Tier-1 (session/entity-scoped) rate limiter — checked synchronously
    /// in each REST handler before its `emit_to_session` call, so a denial
    /// prevents the durable write rather than just auditing it after the
    /// fact. See `crate::rate_limit`'s module doc and `session::rate_limit`'s.
    pub session_rate_limits: crate::rate_limit::SessionRateLimiter,
}

impl AppState {
    pub fn new(db: PgPool, oidc: Option<OidcState>) -> Self {
        Self {
            db,
            invoke_rate_limits:  DashMap::new(),
            approval_policies:   DashMap::new(),
            hubs:                DashMap::new(),
            sessions:            Arc::new(DashMap::new()),
            oidc,
            numa_nodes:          1,
            reflector:           Arc::new(Reflector::new()),
            cms:                 Mutex::new(CmsState::new()),
            rate_limits:         crate::rate_limit::GlobalLimiter::new(),
            session_rate_limits: crate::rate_limit::SessionRateLimiter::new(),
        }
    }

    /// Builder: set the NUMA node count.  Returns `self` for chaining.
    pub fn with_numa_nodes(mut self, numa_nodes: u8) -> Self {
        self.numa_nodes = numa_nodes.max(1); // clamp to at least 1
        self
    }

    pub fn get_or_create_hub(&self, session_id: &str) -> Arc<SessionHub> {
        self.hubs
            .entry(session_id.to_string())
            .or_insert_with(|| Arc::new(SessionHub::new(session_id.to_string())))
            .clone()
    }

    /// Get (or lazily spawn) the per-session actor task for a given session.
    ///
    /// `owner_id` is only used on first call to initialise `SessionMemory`;
    /// subsequent calls return the existing handle unchanged.
    pub fn get_or_create_session_task(
        &self,
        session_id: &str,
        owner_id:   &str,
        hub:        Arc<SessionHub>,
    ) -> SessionTaskHandle {
        self.sessions
            .entry(session_id.to_string())
            .or_insert_with(|| {
                spawn_session_task(
                    session_id.to_string(),
                    owner_id.to_string(),
                    self.db.clone(),
                    hub,
                    Arc::clone(&self.sessions),
                    Arc::clone(&self.reflector),
                    self.numa_nodes,
                )
            })
            .clone()
    }
}
