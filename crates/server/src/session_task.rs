//! Phase 4 / Phase 5: Per-session actor task.
//!
//! # Phase 4 — Actor task
//!
//! Replaces `MachineHandle` (Mutex-based Phase 3) with a dedicated tokio task
//! per live session.  The task owns `(SessionState, SessionMemory)` exclusively —
//! zero lock contention.  External callers send `InboundEvent`s through an
//! `mpsc::Sender`; the FIFO channel is the sole serialisation mechanism.
//!
//! Key advantages over Phase 3:
//! - No Mutex: the task loop is the only reader/writer of state+memory.
//! - Timer callbacks go through the channel (proper actor model); no risk of
//!   recursive `Mutex` deadlock from timer-spawned tasks.
//! - Clean shutdown: task exits when the channel closes (all senders dropped).
//!
//! # Phase 5 — Real Persist (partial)
//!
//! `Effect::Persist` writes to the DB for events the machine generates
//! autonomously — i.e. events the hub does NOT already write to `session_events`:
//!
//! | LiveEvent            | SessionEvent persisted       | Persisted by       |
//! |----------------------|------------------------------|--------------------|
//! | `TimerFired`         | `ApprovalExpired`            | machine (Phase 5)  |
//! | `ActorDisconnected`  | `ApprovalInterrupted` (×N)   | machine (Phase 5)  |
//! | `SidecarAttach`      | `AgentAttached`              | machine (Phase 5)  |
//! | `SidecarDetach`      | `AgentDetached`              | machine (Phase 5)  |
//! | `VoteCast`           | `ApprovalVoted/Granted/…`    | hub (shadow mode)  |
//! | `ApprovalCreate`     | `ApprovalRequested`          | hub (shadow mode)  |
//!
//! After a real Persist the machine updates `hub.snapshot` (ArcSwap) from
//! `build_snapshot(state, memory)`, making it the authoritative source for
//! machine-owned events.
//!
//! Full Phase 5 (machine owns ALL session_events writes) requires routing hub
//! WS handlers through the machine mailbox — tracked as a separate migration.

use std::mem;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::Utf8Bytes;
use chrono::Utc;
use dashmap::DashMap;
use db::approvals;
use protocol::messages::{ArtifactPayload, ContextEntryAddedPayload, WsMessage, WsPayload};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use ulid::Ulid;

use session::{
    build_snapshot, transition, DisconnectReason, Effect, InboundEvent, LiveEvent, ReflectorCursor,
    SagaBundle, SagaOutcome, SessionArena, SessionEvent, SessionMemory, SessionState, VoteDecision,
    SNAPSHOT_DEPENDS_ON,
};

use crate::lease::ConflictClass;
use crate::numa::{route_kind, session_numa_node};
use crate::reflector::{DispatchOutcome, Reflector};
use crate::session_broadcast;
use crate::state::{LiveSnapshot, SessionHub};
use autometrics::autometrics;

// ── Public handle ─────────────────────────────────────────────────────────────

/// Lightweight, cloneable handle to a running session actor task.
///
/// Dropping the last clone of the handle (and any senders derived from it)
/// closes the channel and causes the task to exit cleanly after draining queued
/// messages.
///
/// `numa_node` is the NUMA node to which this session's task was pinned at
/// spawn time.  Computed once via FNV-1a hash of the session ID and stored here
/// so callers can make routing decisions without re-computing the hash.
#[derive(Clone)]
pub struct SessionTaskHandle {
    sender: mpsc::Sender<InboundEvent>,
    /// NUMA node this session's task is assigned to.
    pub numa_node: u8,
}

impl SessionTaskHandle {
    /// Send an event to the session actor (async, back-pressured).
    ///
    /// Returns `Err` only if the task has already exited.
    pub async fn send(
        &self,
        event: InboundEvent,
    ) -> Result<(), mpsc::error::SendError<InboundEvent>> {
        self.sender.send(event).await
    }

    /// Non-blocking send — drops the event if the mailbox is full.
    #[allow(dead_code)]
    pub fn try_send(
        &self,
        event: InboundEvent,
    ) -> Result<(), mpsc::error::TrySendError<InboundEvent>> {
        self.sender.try_send(event)
    }

    /// Returns `true` if the actor task is still running.
    #[allow(dead_code)]
    pub fn is_alive(&self) -> bool {
        !self.sender.is_closed()
    }
}

// ── Spawn ─────────────────────────────────────────────────────────────────────

/// Spawn a per-session actor task and return a handle to its mailbox.
///
/// The task exits when:
/// - All `SessionTaskHandle` clones are dropped (channel closes).
/// - The session transitions to `Archived` (terminal state); pending messages
///   are drained without processing and the task exits.
///
/// `owner_id` is only used to initialise fresh `SessionMemory`; it is ignored
/// if cold-replay restores a different owner (Phase 6+).
///
/// `num_nodes` is the physical NUMA node count from `AppState::numa_nodes`.
/// The session's NUMA node is derived once here via FNV-1a hash of `session_id`
/// and carried in the returned handle for use by callers making routing decisions
/// (e.g. `Effect::Forward` → `RouteKind::Local` vs `RouteKind::CrossNode`).
pub fn spawn_session_task(
    session_id: String,
    owner_id: String,
    db: PgPool,
    hub: Arc<SessionHub>,
    // Session topology: keyed by session_id, used to route Effect::Forward.
    sessions: Arc<DashMap<String, SessionTaskHandle>>,
    // Global bundle reflector for cross-session saga relay.
    reflector: Arc<Reflector>,
    num_nodes: u8,
) -> SessionTaskHandle {
    let local_node = session_numa_node(&session_id, num_nodes);
    let (tx, rx) = mpsc::channel::<InboundEvent>(256);
    let self_tx = tx.clone();
    tokio::spawn(run_session_task(
        rx, self_tx, session_id, owner_id, db, hub, sessions, reflector, local_node,
    ));
    // (replica_id threads through via `reflector.replica_id()` inside
    // `run_session_task` rather than as its own parameter — it's already
    // reachable there and adding a second way to say the same thing would
    // just be one more place for the two to drift apart.)
    SessionTaskHandle {
        sender: tx,
        numa_node: local_node,
    }
}

// ── Actor task loop ───────────────────────────────────────────────────────────

async fn run_session_task(
    mut rx: mpsc::Receiver<InboundEvent>,
    self_tx: mpsc::Sender<InboundEvent>,
    session_id: String,
    owner_id: String,
    db: PgPool,
    hub: Arc<SessionHub>,
    sessions: Arc<DashMap<String, SessionTaskHandle>>,
    reflector: Arc<Reflector>,
    local_node: u8,
) {
    let timers: Arc<DashMap<String, JoinHandle<()>>> = Arc::new(DashMap::new());

    // Cold-start replay: fold this session's persisted history through
    // transition() before accepting any live input, so a freshly-spawned (or
    // post-restart) task's memory reflects what actually happened rather than
    // only what this task instance personally observes going forward.
    let (mut state, mut memory) = replay_history(
        &session_id,
        SessionState::Active,
        SessionMemory::new(session_id.clone(), owner_id),
        &db,
        &hub,
        &timers,
        &self_tx,
        &sessions,
        &reflector,
        local_node,
    )
    .await;

    // Reflector backlog: cross-session bundles addressed to this session
    // that arrived while no task was running to receive them online. The
    // counterpart to the own-history replay above, for bundles instead of
    // this session's own event log.
    drain_reflector_backlog(&session_id, &db, &self_tx, &reflector).await;

    // Durable cross-replica placement claim. Best-effort and non-blocking
    // on failure -- this replica starts serving the session either way,
    // same as today's single-replica behavior; the claim is directory
    // infrastructure for other replicas to consult, not yet a gate on this
    // replica's own local processing (see reflector.rs's module doc on
    // `dispatch`'s claims staying in-process-only for now).
    // `spawn_placement_heartbeat` renews this on a timer for as long as
    // this task stays alive.
    match db::session_placements::claim(
        &db,
        &session_id,
        reflector.replica_id(),
        crate::reflector::PLACEMENT_TTL_SECS,
    )
    .await
    {
        Ok(Some(_)) => {}
        Ok(None) => tracing::warn!(
            session_id,
            "session task starting, but another replica holds a non-stale placement \
             claim on it — possible split-brain"
        ),
        Err(e) => tracing::warn!(session_id, "initial placement claim failed: {e}"),
    }

    // Region allocator for the hot saga coordination path.
    //
    // Pre-allocate for 4 saga steps × ~256 bytes per step.  The arena is reset
    // in O(1) on every `SagaTerminated` event, so the backing region is reused
    // across successive sagas without additional heap allocation.
    let mut arena = SessionArena::with_capacity(4 * 256);

    tracing::debug!(
        session_id,
        local_node,
        cursor = memory.cursor,
        "session task: started"
    );

    while let Some(event) = rx.recv().await {
        let (new_state, new_memory, effects) = transition(state, memory, event);
        state = new_state;
        memory = new_memory;

        // Check before `run_effects` so the flag is correct even if `run_effects`
        // recursively processes replay effects that don't emit SagaTerminated.
        let saga_terminated = effects
            .iter()
            .any(|e| matches!(e, Effect::Persist(SessionEvent::SagaTerminated { .. })));

        Box::pin(run_effects(
            &session_id,
            &mut state,
            &mut memory,
            effects,
            &db,
            &hub,
            &timers,
            &self_tx,
            &sessions,
            &reflector,
            local_node,
        ))
        .await;

        // Arena reset: reclaim the saga region in O(1) once a saga terminates.
        // The region is valid until this point because `run_effects` may have
        // dispatched compensation messages that reference arena-lifetime strings.
        if saga_terminated {
            tracing::debug!(
                session_id,
                allocated_bytes = arena.allocated_bytes(),
                alloc_count = arena.alloc_count(),
                "session task: saga terminated — arena reset",
            );
            arena.reset();
        }

        // Terminal state: drain remaining enqueued messages without processing,
        // then exit.  Any timers will be cancelled below.
        if state.is_terminal() {
            tracing::info!(session_id, "session task: archived — draining and exiting");
            while rx.try_recv().is_ok() {}
            break;
        }
    }

    // Cancel all armed timers on shutdown so their spawned tasks don't linger.
    for kv in timers.iter() {
        kv.value().abort();
    }
    tracing::debug!(session_id, "session task: stopped");
}

// ── Cold-start replay ─────────────────────────────────────────────────────────

/// Fold a session's persisted history through `transition()` before the task
/// begins accepting live input.
///
/// This is the same primitive "deterministic replay to convergence" needs —
/// fold the log, and the result matches `hub.snapshot` by construction, since
/// both are built from the same pure `apply_logged` arms.
///
/// Only event rows whose `payload` deserializes as a `SessionEvent` are
/// folded in; rows written by a `ws.rs`/`routes/` handler not yet migrated
/// onto the session-crate persistence path (see docs/architecture.md, "The
/// session crate") fail to deserialize — a different JSON shape (the `ws.rs`
/// `WsMessage` envelope, dot-separated type tags like `"approval.granted"`)
/// and are silently skipped, not errored. Replay coverage grows automatically,
/// event-kind by event-kind, as more of `ws.rs` moves onto this path — no
/// change needed here when that happens.
async fn replay_history(
    session_id: &str,
    mut state: SessionState,
    mut memory: SessionMemory,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
    local_node: u8,
) -> (SessionState, SessionMemory) {
    let rows = match db::events::list(db, session_id, None, i64::MAX).await {
        Ok(rows) => rows,
        Err(e) => {
            tracing::error!(
                session_id,
                "session task: replay_history: failed to load event log: {e}"
            );
            return (state, memory);
        }
    };

    let mut replayed = 0usize;
    let mut skipped = 0usize;

    for row in rows {
        let event: SessionEvent = match serde_json::from_value(row.payload) {
            Ok(e) => e,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        // `transition()` itself debug-asserts a `Replayed` transition never
        // produces a `Persist` effect — safe to feed straight into the same
        // effect interpreter the live path uses (SetTimer/CancelTimer/
        // Broadcast are real runtime commands regardless of whether the
        // triggering event is historical or live; e.g. BundleDeferred
        // re-arms a timer for its remaining wall-clock duration on replay).
        let (s, m, effects) = transition(
            state,
            memory,
            InboundEvent::Replayed {
                seq: row.seq,
                event,
            },
        );
        state = s;
        memory = m;
        replayed += 1;

        Box::pin(run_effects(
            session_id,
            &mut state,
            &mut memory,
            effects,
            db,
            hub,
            timers,
            self_tx,
            sessions,
            reflector,
            local_node,
        ))
        .await;
    }

    tracing::debug!(
        session_id,
        replayed,
        skipped,
        cursor = memory.cursor,
        "session task: cold-start replay complete",
    );
    (state, memory)
}

// ── Reflector backlog drain ───────────────────────────────────────────────────

/// Drain the reflector for cross-session bundles addressed to `session_id`
/// that arrived while no task was running to receive them online.
///
/// # Why a persisted watermark, not always `ReflectorCursor::zero()`
///
/// A session_task exists only while at least one client is attached, and
/// can be dropped and respawned many times across a single server's uptime
/// without the server itself restarting. `replay()` returns *every* bundle
/// still in the log, not just ones this session hasn't seen; without a
/// remembered position, every respawn would re-drain the entire log and
/// re-inject bundles this session already fully processed in a previous
/// lifetime. There's no `bundle_id` dedup in the session state machine to
/// catch that downstream (checked before adding this: `gated_bundles`
/// only tracks *currently* gated bundles, not a permanent seen-set), so a
/// naive always-replay-from-zero here would risk duplicate saga steps,
/// duplicate delegated approvals, etc. `db::reflector_cursors` (see
/// migration 034) is the fix: the watermark persists across respawns, and
/// is harmless across an actual server restart too, since the reflector's
/// own in-memory log doesn't survive one either, so replaying any watermark
/// against a fresh, empty log just returns nothing.
///
/// Each surviving bundle is injected the same way live online delivery
/// already is (`LiveEvent::BundleIntercepted`, not `BundleReceived`
/// directly, so it goes through the same policy/adapter layer a live
/// arrival would), queued on `self_tx` so it's processed right after
/// cold-start replay, before any live traffic.
async fn drain_reflector_backlog(
    session_id: &str,
    db: &PgPool,
    self_tx: &mpsc::Sender<InboundEvent>,
    reflector: &Arc<Reflector>,
) {
    let (seq, epoch) = db::reflector_cursors::get(db, session_id)
        .await
        .unwrap_or((0, 0));
    let from = ReflectorCursor {
        seq,
        epoch: epoch as u32,
        view: 0,
    };

    let backlog = reflector.replay(from);
    if backlog.is_empty() {
        return;
    }

    let mut delivered = 0usize;
    let mut high_watermark = from;
    for (cursor, bundle) in backlog {
        high_watermark = cursor;
        if bundle.to_session != session_id {
            continue;
        }
        let msg = InboundEvent::Live(LiveEvent::BundleIntercepted {
            bundle,
            interceptor_cap_id: String::new(),
            reflector_cursor: cursor,
        });
        if let Err(e) = self_tx.send(msg).await {
            tracing::warn!(
                session_id,
                "session task: reflector backlog drain: send failed: {e}"
            );
            break;
        }
        delivered += 1;
    }

    if let Err(e) = db::reflector_cursors::upsert(
        db,
        session_id,
        high_watermark.seq,
        high_watermark.epoch as i32,
    )
    .await
    {
        tracing::warn!(
            session_id,
            "session task: reflector backlog drain: failed to persist watermark: {e}"
        );
    }

    if delivered > 0 {
        tracing::debug!(
            session_id,
            delivered,
            "session task: reflector backlog drained"
        );
    }
}

// ── Effect interpreter ────────────────────────────────────────────────────────

async fn run_effects(
    session_id: &str,
    state: &mut SessionState,
    memory: &mut SessionMemory,
    effects: Vec<Effect>,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
    local_node: u8,
) {
    for effect in effects {
        match effect {
            // ── Persist ─────────────────────────────────────────────────────
            Effect::Persist(event) => {
                handle_persist(
                    session_id, state, memory, event, db, hub, timers, self_tx, sessions,
                    reflector, local_node,
                )
                .await;
            }

            // ── Intra-session messaging (actor routing plane) ─────────────
            //
            // `Send` targets a connected WebSocket actor; `Broadcast` fans out
            // to all connected actors in this session.
            Effect::Broadcast { payload } => {
                if let Ok(json) = serde_json::to_string(&payload) {
                    hub.broadcast(Utf8Bytes::from(json));
                }
            }

            Effect::Send { to, payload } => {
                if let Ok(json) = serde_json::to_string(&payload) {
                    hub.send_to(&to, Utf8Bytes::from(json));
                }
            }

            // ── Inter-session messaging (session routing plane) ────────────
            //
            // `Forward` routes to a different session node's task mailbox.
            // Delivered as `LiveEvent::ForwardedMessage` into the target's
            // mpsc channel — the CBFEM DOF coupling edge.
            //
            // NUMA locality: compute `RouteKind` from the local node vs the
            // target's assigned node.  Currently both paths use the same mpsc
            // send; the `RouteKind` is logged and will drive a separate
            // cross-node broker queue once the bundle-relay is wired (task 4).
            Effect::Forward {
                to_session,
                payload,
            } => {
                if let Some(target) = sessions.get(&to_session) {
                    let kind = route_kind(local_node, target.numa_node);
                    tracing::debug!(
                        session_id,
                        %to_session,
                        local_node,
                        target_node = target.numa_node,
                        route       = ?kind,
                        "session task: Effect::Forward",
                    );
                    let msg = InboundEvent::Live(LiveEvent::ForwardedMessage {
                        from_session: session_id.to_string(),
                        payload,
                    });
                    if let Err(e) = target.send(msg).await {
                        tracing::warn!(
                            session_id,
                            %to_session,
                            "session task: Effect::Forward delivery failed: {e}",
                        );
                    }
                } else {
                    tracing::warn!(
                        session_id,
                        %to_session,
                        "session task: Effect::Forward: target session not in topology",
                    );
                }
            }

            // ── Timer management ─────────────────────────────────────────────
            Effect::SetTimer { id, duration_ms } => {
                arm_timer(session_id, id, duration_ms, timers, self_tx);
            }

            Effect::CancelTimer { id } => {
                if let Some((_, handle)) = timers.remove(&id) {
                    handle.abort();
                    tracing::debug!(session_id, timer_id = %id, "session task: timer cancelled");
                }
            }

            // ── Connection management ────────────────────────────────────────
            Effect::CloseConnection {
                actor_id,
                code,
                reason,
            } => {
                tracing::info!(
                    session_id, actor_id = %actor_id, code, reason = %reason,
                    "session task: sending close frame",
                );
                let frame = serde_json::json!({
                    "type":   "connection.closed",
                    "code":   code,
                    "reason": reason,
                });
                if let Ok(json) = serde_json::to_string(&frame) {
                    hub.send_to(&actor_id, Utf8Bytes::from(json));
                }
            }

            // ── Snapshot ─────────────────────────────────────────────────────
            Effect::PersistSnapshot => {
                persist_snapshot(session_id, state, memory, db, hub).await;
            }

            // ── Bundle relay (cross-session saga protocol) ────────────────────
            //
            // 1. Append to the global reflector (assigns a monotonic seq and
            //    fires the broadcast channel for any subscribers).
            // 2. Attempt online delivery: look up the target session in the
            //    topology and send `LiveEvent::BundleIntercepted` to its mailbox
            //    so the FMOA adapter layer can apply its disposition before the
            //    saga machine sees `BundleReceived`.
            // 3. If the target is offline, the bundle stays in the reflector log
            //    and the target drains it via `replay(cursor)` on reconnect.
            Effect::Bundle(bundle) => {
                route_bundle(session_id, bundle, reflector, sessions, local_node).await;
            }

            // ── Intra-session bundle delivery (post-intercept) ────────────────
            //
            // Emitted by `live_bundle_intercepted` after the adapter disposition
            // resolves to Forward / Annotate / Reshape.  Re-enters the bundle
            // into this session's own mailbox as `BundleReceived` so the saga
            // machine processes it on the next iteration of the task loop.
            Effect::BundleDeliver(bundle) => {
                let msg = InboundEvent::Live(LiveEvent::BundleReceived { bundle });
                if let Err(e) = self_tx.send(msg).await {
                    tracing::warn!(
                        session_id,
                        "session task: BundleDeliver: self_tx send failed: {e}",
                    );
                }
            }
        }
    }
}

// ── Persist effect ────────────────────────────────────────────────────────────

/// Classify whether the machine is the authoritative writer for this event.
///
/// Returns `true` for events the hub does NOT write to `session_events`,
/// i.e. events generated autonomously by the machine (timer expiry, sidecar
/// lifecycle, approval interruption on disconnect).
///
/// Returns `false` for events the hub also writes (vote outcomes, approval
/// creation).  Those stay in shadow mode to avoid double-writing the same
/// logical event to `session_events`.
#[inline]
fn is_machine_autonomous(event: &SessionEvent) -> bool {
    matches!(
        event,
        // Approval lifecycle events — machine-generated (timer or disconnect)
        SessionEvent::ApprovalExpired     { .. }
            | SessionEvent::ApprovalInterrupted { .. }
        // Sidecar lifecycle — machine-generated (sidecar protocol)
            | SessionEvent::AgentAttached { .. }
            | SessionEvent::AgentDetached { .. }
        // Saga sub-algebra — always machine-generated; hub never writes these
            | SessionEvent::SagaBegun       { .. }
            | SessionEvent::SagaStepSent    { .. }
            | SessionEvent::SagaStepAcked   { .. }
            | SessionEvent::SagaCompensated { .. }
            | SessionEvent::SagaTerminated  { .. }
        // Policy sub-algebra — always machine-generated (adapter intercept logic)
            | SessionEvent::BundleAnnotated     { .. }
            | SessionEvent::BundleReshaped      { .. }
            | SessionEvent::BundleDeferred      { .. }
            | SessionEvent::BundleRejected      { .. }
            | SessionEvent::BundleApprovalGated { .. }
            | SessionEvent::PolicySet           { .. }
    )
}

async fn handle_persist(
    session_id: &str,
    state: &mut SessionState,
    memory: &mut SessionMemory,
    event: SessionEvent,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
    local_node: u8,
) {
    // Cross-session glue: the real DB side effects (creating B's approval,
    // resolving A's approval, creating an imported Artifact) are async and
    // can't happen inside the pure session-crate transition — see each
    // event's own doc comment. All of these events stay shadow-persisted
    // (EventLog only, matches ApprovalDelegated's precedent); this runs
    // regardless, since it's not what decides real- vs shadow-persist.
    handle_cross_session_side_effects(session_id, &event, db, hub, sessions, reflector).await;

    if is_machine_autonomous(&event) {
        // Phase 5: real DB write for machine-owned events.
        let event_fallback = event.clone();
        match real_persist(
            session_id, state, memory, event, db, hub, timers, self_tx, sessions, reflector,
            local_node,
        )
        .await
        {
            Ok(()) => {}
            Err(e) => {
                tracing::error!(
                    session_id,
                    "session task: real Persist failed ({e}), shadow fallback",
                );
                shadow_persist(
                    session_id,
                    state,
                    memory,
                    event_fallback,
                    db,
                    hub,
                    timers,
                    self_tx,
                    sessions,
                    reflector,
                    local_node,
                )
                .await;
            }
        }
    } else {
        // Shadow mode: hub already writes this event; machine just advances memory.
        tracing::debug!(
            session_id,
            algebra = event.algebra(),
            "session task: shadow Persist (hub owns this event's DB write)",
        );
        shadow_persist(
            session_id, state, memory, event, db, hub, timers, self_tx, sessions, reflector,
            local_node,
        )
        .await;
    }
}

/// Real DB side effects for cross-session event kinds that need async work
/// the pure session-crate transition can't perform: the two cross-session-
/// delegation events, and cross-session artifact import.
/// Best-effort: logs and continues on failure rather than blocking the
/// surrounding persist pipeline — this mirrors how the rest of this file
/// treats snapshot writes and broadcasts as non-fatal side channels.
///
/// Authority model (deliberate, not incidental) — delegation:
///   - Session linkage never itself confers approval authority — it's only
///     the "these sessions have agreed to interact" precondition checked at
///     delegate-time (routes/approvals.rs::delegate_cross_session).
///   - B decides using B's own approval_policy on B's own, independently
///     created ApprovalRequest — never A's. A's row is never exposed to B's
///     session task in any form that would let it be mutated from there.
///   - A revalidates before applying B's decision (the resolve_if_pending_in_tx
///     CAS below) — a stale Ack can't resurrect/overwrite an approval A
///     already resolved through a direct vote, cancel, or timeout expiry.
///   - Single-step, single-target sagas only: one delegation asks exactly
///     one session, so this can't be used to aggregate quorum across
///     multiple sessions or shop a decision to whichever session answers
///     favorably — there is no mechanism here for a many-target ask at all.
///   - Known scope boundary, not yet covered: approvals aren't currently
///     tied to a specific cap/epoch in a way this hook checks, so an
///     in-flight delegation for an ORB/cap-authenticated call isn't yet
///     invalidated by a mid-flight epoch revocation the way a normal
///     cap-gated action would be. The Pending-state CAS guard is today's
///     revalidation net; epoch-awareness would need approval_requests to
///     carry its issuing epoch, which it doesn't yet.
async fn handle_cross_session_side_effects(
    session_id: &str,
    event: &SessionEvent,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
) {
    let replica_id = reflector.replica_id();
    match event {
        // Fired in B (the target session): create B's real, completely
        // normal ApprovalRequest — decided via B's own approval_policy,
        // unchanged. See the event's own doc comment for why this can't
        // happen inside transition() itself.
        SessionEvent::CrossSessionDelegationReceived {
            saga_id,
            source_session_id,
            source_approval_id,
            arguments,
            ..
        } => {
            let approval_id = Ulid::new().to_string();
            let timeout_at = Utc::now() + chrono::Duration::hours(24);

            let mut tx = match db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(session_id, %saga_id, "cross-session delegation: begin tx: {e}");
                    return;
                }
            };
            if let Err(e) = db::approvals::insert_in_tx(
                &mut tx,
                &approval_id,
                session_id,
                "system",
                "cross_session_delegation",
                arguments,
                Some(timeout_at),
            )
            .await
            {
                tracing::error!(session_id, %saga_id, "cross-session delegation: insert approval: {e}");
                return;
            }
            if let Err(e) = tx.commit().await {
                tracing::error!(session_id, %saga_id, "cross-session delegation: commit: {e}");
                return;
            }
            if let Err(e) =
                db::cross_session_delegations::set_target_approval_id(db, saga_id, &approval_id)
                    .await
            {
                tracing::error!(session_id, %saga_id, "cross-session delegation: set_target_approval_id: {e}");
            }

            let msg = WsMessage::new(Ulid::new().to_string(), WsPayload::ApprovalRequested {
                session_id: session_id.to_string(), actor: "system".to_string(),
                timestamp: Utc::now(), seq: 0,
                payload: protocol::messages::ApprovalRequestedPayload {
                    approval_id: approval_id.clone(),
                    tool: "cross_session_delegation".to_string(),
                    summary: format!("Delegated from session {source_session_id} (approval {source_approval_id})"),
                    requested_by: "system".to_string(),
                    expires_at: Some(timeout_at),
                    arguments: arguments.clone(),
                },
            });
            if let Ok(json) = serde_json::to_string(&msg) {
                hub.broadcast(Utf8Bytes::from(json));
            }
            tracing::info!(session_id, %saga_id, %approval_id, %source_session_id, "cross-session delegation: created local approval");
        }

        // Fired in A (the source session): B's decision arrived via the
        // saga Ack. A revalidates before applying it — a stale/late Ack must
        // not overwrite an approval A already resolved through some other
        // path (a direct vote, a cancel, a timeout expiry) while the
        // delegation was in flight. The CAS guard (resolve_if_pending_in_tx)
        // is the actual enforcement; this is not optional hardening, it's
        // the "source revalidates on return" invariant this feature must
        // hold — B can request a decision, it can never directly overwrite
        // A's row (B never even has A's DB handle in scope here; this whole
        // branch runs inside A's own session task).
        SessionEvent::CrossSessionDelegationResolved {
            saga_id,
            approval_id,
            decision,
            ..
        } => {
            let db_state = if decision == "granted" {
                "Approved"
            } else {
                "Denied"
            };
            let mut tx = match db.begin().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!(session_id, %saga_id, "cross-session delegation: resolve begin tx: {e}");
                    return;
                }
            };
            let resolved = match approvals::resolve_if_pending_in_tx(
                &mut tx,
                approval_id,
                db_state,
                "system",
            )
            .await
            {
                Ok(Some(row)) => row,
                Ok(None) => {
                    // Not Pending anymore — resolved/cancelled/expired via
                    // another path already. The delegation is moot; record
                    // it as such and stop, do not touch the approval.
                    tracing::info!(
                        session_id, %saga_id, approval_id,
                        "cross-session delegation: source approval no longer Pending, B's decision discarded",
                    );
                    let _ = tx.rollback().await;
                    if let Err(e) = db::cross_session_delegations::mark_resolved(db, saga_id).await
                    {
                        tracing::error!(session_id, %saga_id, "cross-session delegation: mark_resolved: {e}");
                    }
                    return;
                }
                Err(e) => {
                    tracing::error!(session_id, %saga_id, "cross-session delegation: resolve_if_pending_in_tx: {e}");
                    return;
                }
            };
            let _ = resolved;
            if let Err(e) = tx.commit().await {
                tracing::error!(session_id, %saga_id, "cross-session delegation: resolve commit: {e}");
                return;
            }
            if let Err(e) = db::cross_session_delegations::mark_resolved(db, saga_id).await {
                tracing::error!(session_id, %saga_id, "cross-session delegation: mark_resolved: {e}");
            }

            let payload = if decision == "granted" {
                WsPayload::ApprovalGranted {
                    session_id: session_id.to_string(),
                    actor: "system".to_string(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: protocol::messages::ApprovalEventPayload {
                        approval_id: approval_id.clone(),
                    },
                }
            } else {
                WsPayload::ApprovalDenied {
                    session_id: session_id.to_string(),
                    actor: "system".to_string(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: protocol::messages::ApprovalDeniedPayload {
                        approval_id: approval_id.clone(),
                        reason: Some("denied by delegated session".to_string()),
                    },
                }
            };
            let msg = WsMessage::new(Ulid::new().to_string(), payload);
            if let Ok(json) = serde_json::to_string(&msg) {
                hub.broadcast(Utf8Bytes::from(json));
            }
            tracing::info!(session_id, %saga_id, %approval_id, %decision, "cross-session delegation: resolved source approval");
        }

        // Fired in the target session: create the real, local Artifact copy
        // (and its artifact_imports receipt) — one-way, no ack leg back to
        // the source. Uses `emit_via_task` (not a bare `hub.broadcast`, and
        // not `emit_to_session` — this runs from inside the session task,
        // not an HTTP handler, so it has `db`/`hub` directly but no `state`)
        // so these land as real EventRows: cross-replica delivery
        // (notifier.rs) needs a durable write + pg_notify to pick them up,
        // the same requirement Part A fixed for ordinary session writes.
        SessionEvent::CrossSessionArtifactImportReceived {
            source_session_id,
            source_artifact_id,
            source_seq,
            name,
            artifact_type,
            storage_ref,
            content_hash,
            source_created_by,
            source_created_at,
            imported_by,
            link_id,
            source_name,
            target_name,
            ..
        } => {
            let new_artifact = match db::artifacts::create(
                db,
                db::artifacts::CreateArtifact {
                    session_id: session_id.to_string(),
                    created_by: imported_by.clone(),
                    name: name.clone(),
                    artifact_type: artifact_type.clone(),
                    storage_ref: storage_ref.clone(),
                },
            )
            .await
            {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!(session_id, %source_session_id, "artifact import: create artifact: {e}");
                    return;
                }
            };

            let receipt_id = Ulid::new().to_string();
            if let Err(e) = db::artifact_imports::insert(
                db,
                &receipt_id,
                source_session_id,
                source_artifact_id,
                *source_seq,
                session_id,
                &new_artifact.id,
                content_hash,
                source_created_by,
                *source_created_at,
                imported_by,
                link_id.as_deref(),
            )
            .await
            {
                // Lost a concurrent double-import race — the winning
                // request's row already carries a real target artifact.
                // `new_artifact` above is now a harmless orphan copy with no
                // receipt pointing at it (same non-atomic-but-safe posture
                // routes/sessions.rs's direct-write version had).
                if matches!(e, db::DbError::Conflict(_)) {
                    tracing::info!(
                        session_id, %source_session_id, %content_hash,
                        "artifact import: lost a concurrent double-import race, discarding orphan copy",
                    );
                } else {
                    tracing::error!(session_id, %source_session_id, "artifact import: insert receipt: {e}");
                }
                return;
            }

            let artifact_event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ArtifactCreated {
                    session_id: session_id.to_string(),
                    actor: imported_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ArtifactPayload {
                        artifact_id: new_artifact.id.clone(),
                        name: new_artifact.name.clone(),
                        artifact_type: Some(new_artifact.r#type.clone()),
                    },
                },
            );
            emit_via_task(db, hub, session_id, imported_by, artifact_event, replica_id).await;

            // Audit note — resolve display names first, same fix
            // routes/sessions.rs's original handler applied (raw ULIDs in a
            // human-facing note is exactly the bug already fixed everywhere
            // else names get surfaced).
            let name_ids = vec![source_created_by.clone(), imported_by.clone()];
            let names = db::actors::get_many(db, &name_ids)
                .await
                .unwrap_or_default();
            let source_creator_name = names
                .get(source_created_by)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| source_created_by.clone());
            let importer_name = names
                .get(imported_by)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| imported_by.clone());
            let note = format!(
                "Imported from {source_name}\nOriginally published by {source_creator_name} at {}\nImported by {importer_name} through session link {source_name} -> {target_name}",
                source_created_at.to_rfc3339(),
            );
            let entry_id = Ulid::new().to_string();
            let context_event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ContextEntryAdded {
                    session_id: session_id.to_string(),
                    actor: imported_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ContextEntryAddedPayload {
                        entry_id: entry_id.clone(),
                        kind: protocol::types::ContextEntryKind::Fact,
                        content: note.clone(),
                        authored_by: Some(imported_by.clone()),
                    },
                },
            );
            emit_via_task(db, hub, session_id, imported_by, context_event, replica_id).await;

            tracing::info!(
                session_id, %source_session_id, artifact_id = %new_artifact.id,
                "artifact import: delivered via reflector",
            );
        }

        // Fired in the target session: land a linked session's context
        // entry here, with provenance. Unlike artifact import there is no
        // relational insert at all -- ContextEntryAdded's own durable
        // write (via emit_via_task) IS the target-side record; see the
        // event's own doc comment.
        SessionEvent::CrossSessionContextReceived {
            source_session_id,
            kind,
            content,
            source_authored_by,
            source_authored_at,
            imported_by,
            source_name,
            target_name,
            ..
        } => {
            let names = db::actors::get_many(db, &[source_authored_by.clone()])
                .await
                .unwrap_or_default();
            let author_name = names
                .get(source_authored_by)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| source_authored_by.clone());
            let note = format!(
                "Sent from {source_name}\nOriginally added by {author_name} at {}\n\n{content}",
                source_authored_at.to_rfc3339(),
            );
            let entry_id = Ulid::new().to_string();
            let context_event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ContextEntryAdded {
                    session_id: session_id.to_string(),
                    actor: imported_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ContextEntryAddedPayload {
                        entry_id,
                        kind: kind.clone(),
                        content: note,
                        authored_by: Some(imported_by.clone()),
                    },
                },
            );
            emit_via_task(db, hub, session_id, imported_by, context_event, replica_id).await;
            tracing::info!(
                session_id, %source_session_id, %target_name,
                "context summary send: delivered via reflector",
            );
        }

        // Fired in the target session: land an annotation from a linked
        // session's member onto one of this session's own objects. Same
        // "no relational insert" posture as context-summary-send above.
        SessionEvent::CrossSessionAnnotationReceived {
            source_session_id,
            object_type,
            object_name,
            note,
            authored_by,
            source_name,
            ..
        } => {
            let names = db::actors::get_many(db, &[authored_by.clone()])
                .await
                .unwrap_or_default();
            let author_name = names
                .get(authored_by)
                .map(|a| a.name.clone())
                .unwrap_or_else(|| authored_by.clone());
            let full_note = format!(
                "Annotation from {source_name} ({author_name}) on {object_type} '{object_name}':\n{note}",
            );
            let entry_id = Ulid::new().to_string();
            let context_event = WsMessage::new(
                Ulid::new().to_string(),
                WsPayload::ContextEntryAdded {
                    session_id: session_id.to_string(),
                    actor: authored_by.clone(),
                    timestamp: Utc::now(),
                    seq: 0,
                    payload: ContextEntryAddedPayload {
                        entry_id,
                        kind: protocol::types::ContextEntryKind::Fact,
                        content: full_note,
                        authored_by: Some(authored_by.clone()),
                    },
                },
            );
            emit_via_task(db, hub, session_id, authored_by, context_event, replica_id).await;
            tracing::info!(
                session_id, %source_session_id, %object_name,
                "annotation: delivered via reflector",
            );
        }

        _ => {}
    }
    let _ = sessions; // reserved for a future reconnect-drain path; unused today
}

/// Durably persist + broadcast a `WsMessage` from inside the session task's
/// own async context, where `hub`/`db` are already in hand. Mirrors
/// `ws::emit_to_session`'s pipeline exactly (stamp + append + snapshot +
/// commit + notify + broadcast) so cross-replica delivery (`notifier.rs`)
/// picks these up the same way it picks up ordinary hub-originated writes.
/// Not `emit_to_session` itself: that function is HTTP-handler-specific,
/// looking its hub up from `state.hubs` — callers here already hold both.
async fn emit_via_task(
    db: &PgPool,
    hub: &Arc<SessionHub>,
    session_id: &str,
    actor_id: &str,
    event: WsMessage,
    replica_id: &str,
) {
    let snap_ref = crate::ws::current_snap(hub);
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(session_id, "emit_via_task: begin tx: {e}");
            return;
        }
    };
    let (seq, new_snap, stamped) = match crate::ws::stamp_append_snapshot(
        &mut tx,
        snap_ref.as_ref(),
        session_id,
        actor_id,
        event,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(session_id, "emit_via_task: stamp: {e}");
            return;
        }
    };
    if let Err(e) = tx.commit().await {
        tracing::error!(session_id, "emit_via_task: commit: {e}");
        return;
    }
    let _ = db::events::notify_session(db, session_id, seq, replica_id).await;
    crate::ws::store_and_broadcast(hub, seq, new_snap, &stamped).await;
}

// ── Real Persist ──────────────────────────────────────────────────────────────

/// Write a `SessionEvent` to `events` + `session_snapshots` atomically.
///
/// Strategy:
/// 1. Allocate seq, INSERT event row, build post-replay snapshot and INSERT it —
///    all in one transaction.  State/memory are not modified until after commit.
/// 2. On commit: apply the Replayed event in-place, update `hub.snapshot`.
/// 3. On any failure before commit: state/memory are unchanged; caller falls
///    back to shadow mode.
///
/// # Serialization strategy
///
/// The event and snapshot are serialized via `serde_json::to_string` and passed
/// as raw JSON strings to `append_raw_in_tx` / `insert_raw_in_tx`, avoiding the
/// `serde_json::Value` intermediate tree that the original `to_value` path built
/// only to have sqlx re-serialize it again.
///
/// Once the session task migrates to `tokio::task::spawn_local` (`LocalSet`),
/// `BumpWriter` replaces `to_string` here: the JSON bytes live in the arena
/// region for the saga lifetime (zero-copy, one fewer heap allocation per
/// committed event).
async fn real_persist(
    session_id: &str,
    state: &mut SessionState,
    memory: &mut SessionMemory,
    event: SessionEvent,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
    local_node: u8,
) -> anyhow::Result<()> {
    let type_name = event.type_name();
    let actor_id = actor_of(&event).to_owned();
    let event_json = serde_json::to_string(&event)?;
    // Capture before event is moved into the plan.
    let needs_snapshot = event.algebra_mask().intersects(SNAPSHOT_DEPENDS_ON);

    // Tier-1: compile and execute the persist plan.
    // 1 seq alloc + 1 UNNEST INSERT + 1 COMMIT + 1 pg_notify = constant round-trips.
    let seq = db::persist_plan::PersistPlan::new(session_id)
        .append(db::persist_plan::EventSpec {
            type_name,
            actor_id: &actor_id,
            payload_json: &event_json,
        })
        .notify()
        .execute(db)
        .await?;

    // ── Commit succeeded ─────────────────────────────────────────────────────

    // Typed broadcast: translate the just-persisted event into the same
    // WsPayload shape ws.rs's own handlers broadcast, so the frontend's
    // Timeline/activity feed renders it — not just the generic
    // session_updated ping transition()'s own effects may also emit below.
    // `event` hasn't moved yet at this point, so a reference is enough.
    if let Some(payload) = session_broadcast::to_ws_payload(session_id, seq, &event) {
        let msg = WsMessage::new(Ulid::new().to_string(), payload);
        if let Ok(json) = serde_json::to_string(&msg) {
            hub.broadcast(Utf8Bytes::from(json));
        }
    }

    // Advance state/memory in-place using the real seq.
    // transition() is pure and infallible — no clone needed because any
    // pre-commit failure would have returned early above.
    let (new_state, new_memory, replay_effects) = transition(
        mem::replace(state, SessionState::Active),
        mem::replace(memory, SessionMemory::new(String::new(), String::new())),
        InboundEvent::Replayed { seq, event },
    );
    *state = new_state;
    *memory = new_memory;

    // Build snapshot from the already-advanced state — no second transition call.
    let snap = if needs_snapshot {
        build_snapshot(state, memory)
    } else {
        let guard = hub.snapshot.load();
        (**guard)
            .as_ref()
            .map(|ls| ls.state.clone())
            .unwrap_or_else(|| build_snapshot(state, memory))
    };

    // Machine is now the authoritative in-memory snapshot source.
    hub.snapshot.store(Arc::new(Some(LiveSnapshot {
        seq,
        state: snap.clone(),
    })));

    // Tier-2: write snapshot asynchronously — it's a projection, always
    // recoverable from the event log; losing it on crash costs replay, not data.
    let snap_json = serde_json::to_string(&snap)?;
    let db_snap = db.clone();
    let sid_snap = session_id.to_string();
    tokio::spawn(async move {
        if let Err(e) = db::snapshots::write_async(&db_snap, &sid_snap, seq, &snap_json).await {
            tracing::warn!(session_id = %sid_snap, seq, "real_persist: snapshot write: {e}");
        }
    });

    tracing::debug!(
        session_id,
        seq,
        type_name,
        actor_id,
        "session task: real Persist committed",
    );

    // Replay effects never include Persist (enforced by transition()'s own
    // debug_assert) but can include CancelTimer, CloseConnection, or Broadcast
    // (e.g. AgentAttached/AgentDetached emit a broadcast here so already-
    // connected clients see the change, since apply_logged is where their
    // memory update actually lands).
    Box::pin(run_effects(
        session_id,
        state,
        memory,
        replay_effects,
        db,
        hub,
        timers,
        self_tx,
        sessions,
        reflector,
        local_node,
    ))
    .await;

    Ok(())
}

// ── Shadow Persist ────────────────────────────────────────────────────────────

/// Advance state/memory using a real seq allocated from the *same*
/// `session_sequences` counter `real_persist`/`PersistPlan` draws from.
///
/// Used for events the hub already writes to `session_events`. The machine's
/// memory advances to reflect the event, but no event row is inserted here —
/// the hub's own write already has one, at its own seq from the same counter.
///
/// This deliberately does NOT reuse the hub's already-assigned seq for this
/// specific event (the bridge functions in this file don't carry it through
/// today) — it allocates a fresh one from the same counter instead. That
/// leaves a small, permanent gap between this seq and the row the hub just
/// wrote (harmless — replay and `MAX(seq)` both tolerate gaps fine, see
/// `db::events::alloc_seq`'s doc comment), but critically keeps every seq
/// number, real-row-backed or not, strictly increasing from one shared
/// source. A locally-computed `memory.cursor + 1` doesn't. It free-invents
/// numbers with no relationship to the real counter, and CAN and DOES regress
/// `memory.cursor` the moment a later `real_persist` call is handed a real,
/// smaller seq than this event's shadow persist has already advanced past —
/// tripping the crate's own cursor-monotonicity invariant. In a release
/// build (where `debug_assert!` compiles out) that regression would corrupt
/// `memory.cursor` silently rather than panic — this was found live, not by
/// design; see git history around this comment for the reproduction.
async fn shadow_persist(
    session_id: &str,
    state: &mut SessionState,
    memory: &mut SessionMemory,
    event: SessionEvent,
    db: &PgPool,
    hub: &Arc<SessionHub>,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    reflector: &Arc<Reflector>,
    local_node: u8,
) {
    let seq = match db::events::alloc_seq(db, session_id).await {
        Ok(s) => s,
        Err(e) => {
            // Degraded mode: an actual DB outage would also be failing
            // real_persist calls around the same time. Fall back to the old
            // locally-computed value rather than dropping the event's memory
            // update entirely — still wrong in the same way the pre-fix code
            // always was, but no worse, and only reachable on connectivity
            // failure rather than on every shadow-persisted event.
            tracing::error!(
                session_id,
                "session task: shadow_persist: alloc_seq failed ({e}), \
                 falling back to a locally-computed seq",
            );
            memory.cursor + 1
        }
    };
    let (new_state, new_memory, replay_effects) = transition(
        mem::replace(state, SessionState::Active),
        mem::replace(memory, SessionMemory::new(String::new(), String::new())),
        InboundEvent::Replayed { seq, event },
    );
    *state = new_state;
    *memory = new_memory;
    Box::pin(run_effects(
        session_id,
        state,
        memory,
        replay_effects,
        db,
        hub,
        timers,
        self_tx,
        sessions,
        reflector,
        local_node,
    ))
    .await;
}

// ── PersistSnapshot effect ────────────────────────────────────────────────────

async fn persist_snapshot(
    session_id: &str,
    state: &SessionState,
    memory: &SessionMemory,
    db: &PgPool,
    hub: &Arc<SessionHub>,
) {
    let seq = memory.cursor;
    let snap = build_snapshot(state, memory);
    let snap_json = match serde_json::to_string(&snap) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(session_id, "session task: PersistSnapshot serialize: {e}");
            return;
        }
    };
    // Tier-2: async commit — snapshot is always recoverable from the event log.
    if let Err(e) = db::snapshots::write_async(db, session_id, seq, &snap_json).await {
        tracing::warn!(session_id, "session task: PersistSnapshot DB write: {e}");
        return;
    }
    hub.snapshot
        .store(Arc::new(Some(LiveSnapshot { seq, state: snap })));
    tracing::debug!(
        session_id,
        seq,
        "session task: PersistSnapshot committed (async)"
    );
}

// ── Bundle relay ──────────────────────────────────────────────────────────────

/// Dispatch a `SagaBundle` through the reflector's lease-gated path and
/// attempt online delivery.
///
/// Steps:
/// 1. Reflector dispatch, lease-gated on the bundle's session and saga-step
///    claims (see `crate::lease`), falling back to a plain append if a
///    lease race doesn't resolve within a few attempts. With no other
///    production caller contending for these specific classes today, this
///    is expected to commit on the first attempt every time; the gate is
///    real, just not yet meaningfully exercised (see `crate::reflector`'s
///    module doc).
/// 2. Look up target session in the topology map.
/// 3. If live: send `LiveEvent::BundleIntercepted` to the target's mpsc mailbox.
/// 4. If offline: log and leave the bundle in the reflector queue.
///    `drain_reflector_backlog` delivers it when the target reconnects.
/// `pub(crate)`: also called directly from `routes/sessions.rs`'s
/// `import_artifact` handler, which dispatches a `SagaBundle` straight from
/// the HTTP layer rather than through a session task's own `Effect::Bundle`
/// (there's no source-side saga state to track for a one-shot import, so it
/// skips `live_saga_begin`'s machinery entirely — see Part 3 of the plan).
pub(crate) async fn route_bundle(
    session_id: &str,
    bundle: SagaBundle,
    reflector: &Arc<Reflector>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    local_node: u8,
) {
    let to_session = bundle.to_session.clone();
    let bundle_id = bundle.bundle_id.clone();
    let saga_id = bundle.saga_id.clone();
    let step_idx = bundle.step_idx;

    // Step 1: dispatch through the lease-gated path.
    const MAX_DISPATCH_ATTEMPTS: u8 = 3;
    let claims = [
        ConflictClass::Session(to_session.clone()),
        ConflictClass::SagaStep(saga_id.clone(), step_idx),
    ];
    let mut outcome = None;
    for attempt in 0..MAX_DISPATCH_ATTEMPTS {
        match reflector.dispatch(bundle.clone(), &claims).await {
            DispatchOutcome::Retry => {
                tracing::debug!(
                    session_id, attempt, %bundle_id,
                    "session task: Effect::Bundle dispatch lease race, retrying",
                );
            }
            resolved => {
                outcome = Some(resolved);
                break;
            }
        }
    }

    match outcome {
        Some(DispatchOutcome::Committed(cursor)) => {
            tracing::debug!(
                session_id, %to_session, %bundle_id, %saga_id, step_idx,
                reflector_seq = cursor.seq, reflector_epoch = cursor.epoch,
                "session task: Effect::Bundle appended to reflector",
            );
            deliver_or_queue(
                session_id,
                &to_session,
                bundle,
                &bundle_id,
                cursor,
                sessions,
                local_node,
            )
            .await;
        }
        Some(DispatchOutcome::Forwarded) => {
            // Durably handed off to whichever replica actually holds this
            // bundle's claims -- see reflector.rs's module doc. This
            // replica must not also attempt local delivery: the target
            // almost certainly isn't running here, and the owning
            // replica's own spawn_reflector_forward_listener will append
            // it to *its* log and deliver from there.
            tracing::debug!(
                session_id, %to_session, %bundle_id, %saga_id, step_idx,
                "session task: Effect::Bundle durably forwarded to the replica that owns its claims",
            );
        }
        Some(DispatchOutcome::Retry) | None => {
            // Never observed in practice today (see the doc comment above),
            // but a bundle must not be silently dropped if it ever does
            // happen, so fall back to the ungated append rather than lose it.
            tracing::warn!(
                session_id, %to_session, %bundle_id,
                "session task: Effect::Bundle dispatch failed after {MAX_DISPATCH_ATTEMPTS} \
                 attempts (lease race did not resolve), falling back to a plain append",
            );
            let cursor = reflector.append(bundle.clone());
            deliver_or_queue(
                session_id,
                &to_session,
                bundle,
                &bundle_id,
                cursor,
                sessions,
                local_node,
            )
            .await;
        }
    }
}

/// Attempt immediate delivery to `to_session`'s locally-running task, or
/// leave the bundle queued in the reflector log for `drain_reflector_backlog`
/// to pick up on reconnect. Shared between `route_bundle` (bundles this
/// replica itself just committed) and `spawn_reflector_forward_listener`
/// (bundles handed off *to* this replica by another one via
/// `db::reflector_forwarding`) — same "is the target live right here,
/// right now" question either way, once a local cursor exists.
async fn deliver_or_queue(
    session_id: &str,
    to_session: &str,
    bundle: SagaBundle,
    bundle_id: &str,
    cursor: ReflectorCursor,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
    local_node: u8,
) {
    if let Some(target) = sessions.get(to_session) {
        let kind = route_kind(local_node, target.numa_node);
        tracing::debug!(
            session_id,
            %to_session,
            local_node,
            target_node     = target.numa_node,
            route           = ?kind,
            reflector_seq   = cursor.seq,
            reflector_epoch = cursor.epoch,
            "session task: Effect::Bundle online delivery",
        );
        let msg = InboundEvent::Live(LiveEvent::BundleIntercepted {
            bundle,
            interceptor_cap_id: String::new(),
            reflector_cursor: cursor,
        });
        if let Err(e) = target.send(msg).await {
            tracing::warn!(
                session_id,
                %to_session,
                %bundle_id,
                "session task: Effect::Bundle online delivery failed: {e} (bundle remains in reflector)",
            );
        }
    } else {
        tracing::debug!(
            session_id,
            %to_session,
            %bundle_id,
            reflector_seq   = cursor.seq,
            reflector_epoch = cursor.epoch,
            "session task: Effect::Bundle: target offline, queued in reflector",
        );
    }
}

/// Consumes bundles other replicas have durably forwarded to this one (see
/// `db::reflector_forwarding` and `reflector.rs`'s `Reflector::forward`).
/// Woken by `pg_notify` on the `reflector_bundles` channel (payload = a
/// replica id — every replica's listener receives every notification,
/// same as `notifier.rs`'s pattern, and just ignores ones not addressed to
/// its own `reflector.replica_id()`), with a periodic poll as a backstop
/// in case a notify is ever missed (Postgres LISTEN/NOTIFY has no
/// redelivery guarantee).
///
/// Spawns its own background task; fire-and-forget from the caller's side,
/// same shape as `notifier::spawn_event_notifier`.
pub fn spawn_reflector_forward_listener(
    pool: PgPool,
    reflector: Arc<Reflector>,
    sessions: Arc<DashMap<String, SessionTaskHandle>>,
) {
    tokio::spawn(async move {
        loop {
            if let Err(e) = run_reflector_forward_listener(&pool, &reflector, &sessions).await {
                tracing::warn!("reflector forward listener disconnected ({e}), reconnecting in 1s");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    });
}

async fn run_reflector_forward_listener(
    pool: &PgPool,
    reflector: &Arc<Reflector>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
) -> anyhow::Result<()> {
    let mut listener = sqlx::postgres::PgListener::connect_with(pool).await?;
    listener.listen("reflector_bundles").await?;
    tracing::info!(
        replica_id = reflector.replica_id(),
        "reflector forward listener: listening on reflector_bundles"
    );

    loop {
        let claim_deadline = tokio::time::sleep(Duration::from_secs(15));
        tokio::select! {
            notification = listener.recv() => { notification?; }
            _ = claim_deadline => {} // periodic backstop poll
        }
        drain_forwarded_bundles(pool, reflector, sessions).await;
    }
}

async fn drain_forwarded_bundles(
    pool: &PgPool,
    reflector: &Arc<Reflector>,
    sessions: &Arc<DashMap<String, SessionTaskHandle>>,
) {
    let claimed =
        match db::reflector_forwarding::claim_pending::<SagaBundle>(pool, reflector.replica_id())
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!("reflector forward listener: claim_pending failed: {e}");
                return;
            }
        };
    for (forward_id, bundle) in claimed {
        let to_session = bundle.to_session.clone();
        let from_session = bundle.from_session.clone();
        let bundle_id = bundle.bundle_id.clone();
        let cursor = reflector.append(bundle.clone());
        tracing::debug!(
            forward_id, %to_session, %bundle_id,
            reflector_seq = cursor.seq, reflector_epoch = cursor.epoch,
            "reflector forward listener: claimed and appended a forwarded bundle",
        );
        // No `session_id`/`local_node` context of our own here (this
        // listener isn't tied to any one session task) — `from_session`
        // is the closest real equivalent for the log line, and NUMA
        // routing is a no-op today either way (see numa.rs's module doc).
        deliver_or_queue(
            &from_session,
            &to_session,
            bundle,
            &bundle_id,
            cursor,
            sessions,
            0,
        )
        .await;
    }
}

// ── Timer management ──────────────────────────────────────────────────────────

fn arm_timer(
    session_id: &str,
    id: String,
    duration_ms: u64,
    timers: &Arc<DashMap<String, JoinHandle<()>>>,
    self_tx: &mpsc::Sender<InboundEvent>,
) {
    // Cancel any prior timer with the same ID before arming the new one.
    if let Some((_, old)) = timers.remove(&id) {
        old.abort();
    }

    let tx = self_tx.clone();
    let id_clone = id.clone();
    let timers_ref = Arc::clone(timers);
    let sid = session_id.to_string();

    let handle = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(duration_ms)).await;
        // Remove the handle before sending so the task doesn't race itself.
        timers_ref.remove(&id_clone);
        tracing::debug!(session_id = %sid, timer_id = %id_clone, "session task: timer fired");
        // Send via channel — correct actor-model ordering (FIFO after any
        // in-flight events that arrived before the timer expired).
        let _ = tx
            .send(InboundEvent::Live(LiveEvent::TimerFired { id: id_clone }))
            .await;
    });

    timers.insert(id.clone(), handle);
    tracing::debug!(session_id, timer_id = %id, duration_ms, "session task: timer armed");
}

// ── Helper: extract the actor_id field from a SessionEvent ───────────────────

fn actor_of(event: &SessionEvent) -> &str {
    match event {
        SessionEvent::SessionCreated { owner_id, .. } => owner_id,
        SessionEvent::SessionPaused { paused_by, .. } => paused_by,
        SessionEvent::SessionResumed { resumed_by, .. } => resumed_by,
        SessionEvent::SessionArchived { archived_by, .. } => archived_by,
        SessionEvent::ParticipantJoined { actor_id, .. } => actor_id,
        SessionEvent::ParticipantLeft { actor_id, .. } => actor_id,
        SessionEvent::OwnershipTransferred { from_actor, .. } => from_actor,
        SessionEvent::AgentAttached { actor_id, .. } => actor_id,
        SessionEvent::AgentDetached { actor_id, .. } => actor_id,
        SessionEvent::CapDelegated { actor_id, .. } => actor_id,
        SessionEvent::CapRevoked { revoked_by, .. } => revoked_by,
        SessionEvent::EpochAdvanced { advanced_by, .. } => advanced_by,
        SessionEvent::ApprovalRequested { actor_id, .. } => actor_id,
        SessionEvent::ApprovalClaimed { claimed_by, .. } => claimed_by,
        SessionEvent::ApprovalVoted { voter_id, .. } => voter_id,
        SessionEvent::ApprovalGranted { resolved_by, .. } => resolved_by,
        SessionEvent::ApprovalDenied { resolved_by, .. } => resolved_by,
        SessionEvent::ApprovalExpired { .. } => "system",
        SessionEvent::ApprovalInterrupted { .. } => "system",
        SessionEvent::MessagePosted { actor_id, .. } => actor_id,
        SessionEvent::ContextEntryAdded { actor_id, .. } => actor_id,
        SessionEvent::ContextEntryResolved { resolved_by, .. } => resolved_by,
        SessionEvent::ArtifactCreated { actor_id, .. } => actor_id,
        SessionEvent::ArtifactUpdated { actor_id, .. } => actor_id,
        SessionEvent::ArtifactDeleted { actor_id, .. } => actor_id,
        SessionEvent::ApprovalCancelled { cancelled_by, .. } => cancelled_by,
        SessionEvent::ApprovalDelegated { from, .. } => from,
        SessionEvent::ApprovalDisputed { disputed_by, .. } => disputed_by,
        SessionEvent::CrossSessionDelegationRequested { requested_by, .. } => requested_by,
        SessionEvent::CrossSessionDelegationReceived { .. } => "system",
        SessionEvent::CrossSessionDelegationResolved { .. } => "system",
        SessionEvent::CrossSessionArtifactImportReceived { imported_by, .. } => imported_by,
        SessionEvent::CrossSessionContextReceived { imported_by, .. } => imported_by,
        SessionEvent::CrossSessionAnnotationReceived { authored_by, .. } => authored_by,
        SessionEvent::EffectProposed { .. } => "system",
        SessionEvent::EffectScouted { .. } => "system",
        SessionEvent::EffectAttested { .. } => "system",
        SessionEvent::EffectCommitted { .. } => "system",
        SessionEvent::EffectDiverged { .. } => "system",
        SessionEvent::SnapshotCreated { .. } => "system",
        SessionEvent::SnapshotInvalidated { .. } => "system",
        // Saga events are emitted by the coordinator session machine itself.
        SessionEvent::SagaBegun { .. } => "system",
        SessionEvent::SagaStepSent { .. } => "system",
        SessionEvent::SagaStepAcked { .. } => "system",
        SessionEvent::SagaCompensated { .. } => "system",
        SessionEvent::SagaTerminated { .. } => "system",
        // Policy events are emitted by the adapter intercept layer.
        SessionEvent::BundleAnnotated { .. } => "system",
        SessionEvent::BundleReshaped { .. } => "system",
        SessionEvent::BundleDeferred { .. } => "system",
        SessionEvent::BundleRejected { .. } => "system",
        SessionEvent::BundleApprovalGated { .. } => "system",
        SessionEvent::PolicySet { set_by_cap, .. } => set_by_cap,
    }
}

// ── WS-event translation helpers ─────────────────────────────────────────────
//
// Called from ws.rs to feed events to the session task mailbox.
// These replace the `machine_*` functions in the former `session_machine.rs`.

/// Feed an actor connection event to the session task.
#[autometrics]
pub async fn task_actor_connected(
    handle: &SessionTaskHandle,
    actor_id: String,
    connection_id: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ActorConnected {
            actor_id,
            connection_id,
        }))
        .await;
}

/// Feed an actor disconnection event to the session task.
///
/// The machine uses this to interrupt pending approvals owned by the actor.
#[autometrics]
pub async fn task_actor_disconnected(
    handle: &SessionTaskHandle,
    actor_id: String,
    connection_id: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ActorDisconnected {
            actor_id,
            connection_id,
            reason: DisconnectReason::ServerClose,
        }))
        .await;
}

/// Feed a vote cast to the session task.
///
/// Hub already persists the outcome event; machine tracks votes for policy
/// evaluation and coverage bisimulation.
#[autometrics]
pub async fn task_vote_cast(
    handle: &SessionTaskHandle,
    approval_id: String,
    voter_id: String,
    approve: bool,
) {
    let decision = if approve {
        VoteDecision::Approve
    } else {
        VoteDecision::Deny
    };
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::VoteCast {
            approval_id,
            voter_id,
            decision,
        }))
        .await;
}

/// Feed an approval creation to the session task.
///
/// This arms the per-approval expiry timer.  Hub already persists the
/// `ApprovalRequested` event; machine shadow-persists it.
#[autometrics]
pub async fn task_approval_create(
    handle: &SessionTaskHandle,
    approval_id: String,
    actor_id: String,
    tool: String,
    args: serde_json::Value,
    expires_ms: Option<u64>,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ApprovalCreate {
            approval_id,
            actor_id,
            tool,
            args,
            expires_ms,
        }))
        .await;
}

/// Feed an ownership transfer to the session task.
///
/// Shadow-persisted (see `is_machine_autonomous`) — `routes/sessions.rs`
/// remains the authoritative writer; this keeps the machine's own
/// `owner_id`/`eligible_approvers` bookkeeping correct without waiting for
/// cold replay.
#[autometrics]
pub async fn task_ownership_transfer(handle: &SessionTaskHandle, from: String, to: String) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::OwnershipTransfer {
            from,
            to,
        }))
        .await;
}

/// Feed a session pause to the session task. Shadow-persisted — see
/// `task_ownership_transfer`'s doc comment for why.
#[autometrics]
pub async fn task_admin_pause(handle: &SessionTaskHandle, by: String, reason: Option<String>) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::AdminPause { by, reason }))
        .await;
}

/// Feed a session resume to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_admin_resume(handle: &SessionTaskHandle, by: String) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::AdminResume { by }))
        .await;
}

/// Feed a session archive to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_admin_archive(handle: &SessionTaskHandle, by: String) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::AdminArchive { by }))
        .await;
}

/// Feed an approval claim to the session task. Shadow-persisted — see
/// `task_ownership_transfer`'s doc comment for why.
#[autometrics]
pub async fn task_approval_claim(
    handle: &SessionTaskHandle,
    approval_id: String,
    actor_id: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ApprovalClaim {
            approval_id,
            actor_id,
        }))
        .await;
}

/// Feed an approval cancellation to the session task. Shadow-persisted — see
/// `task_ownership_transfer`'s doc comment for why.
#[autometrics]
pub async fn task_approval_cancel(
    handle: &SessionTaskHandle,
    approval_id: String,
    actor_id: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ApprovalCancel {
            approval_id,
            actor_id,
        }))
        .await;
}

/// Feed an approval delegation to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_approval_delegate(
    handle: &SessionTaskHandle,
    approval_id: String,
    from: String,
    to: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ApprovalDelegate {
            approval_id,
            from,
            to,
        }))
        .await;
}

/// Feed an approval dispute to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_approval_dispute(
    handle: &SessionTaskHandle,
    approval_id: String,
    actor_id: String,
    reason: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ApprovalDispute {
            approval_id,
            actor_id,
            reason,
        }))
        .await;
}

/// Begin a cross-session approval delegation. Shadow-persisted (EventLog
/// only — the real cross-session plumbing is the `Effect::Bundle` it
/// triggers, not a `SessionMemory` field). `saga_id` is minted by the
/// caller (route handler) — `crates/session` has no ulid dependency by design.
#[autometrics]
pub async fn task_cross_session_delegate(
    handle: &SessionTaskHandle,
    saga_id: String,
    approval_id: String,
    target_session_id: String,
    requested_by: String,
    arguments: serde_json::Value,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::CrossSessionDelegate {
            saga_id,
            approval_id,
            target_session_id,
            requested_by,
            arguments,
        }))
        .await;
}

/// Feed a saga ack to the session task that began the saga — the
/// coordinator-side half of `BundleKind::Ack`. Used by
/// `ws.rs::handle_vote`'s cross-session-delegation hook to send B's
/// decision back to A once B's own (completely normal) approval resolves;
/// not specific to cross-session delegation, reusable for any saga.
#[autometrics]
pub async fn task_saga_ack(
    handle: &SessionTaskHandle,
    saga_id: String,
    step_idx: usize,
    outcome: SagaOutcome,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::SagaAck {
            saga_id,
            step_idx,
            outcome,
        }))
        .await;
}

/// Feed a message post to the session task. Shadow-persisted — see
/// `task_ownership_transfer`'s doc comment for why.
#[autometrics]
pub async fn task_message_post(handle: &SessionTaskHandle, actor_id: String, content: String) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::MessagePost {
            actor_id,
            content,
        }))
        .await;
}

/// Feed a context-entry addition to the session task. `entry_id` must be the
/// same ID the real writer already minted. Shadow-persisted.
#[autometrics]
pub async fn task_context_add(
    handle: &SessionTaskHandle,
    entry_id: String,
    actor_id: String,
    kind: protocol::types::ContextEntryKind,
    content: String,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ContextAdd {
            entry_id,
            actor_id,
            kind,
            content,
        }))
        .await;
}

/// Feed a context-entry resolution to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_context_resolve(
    handle: &SessionTaskHandle,
    entry_id: String,
    resolved_by: String,
    note: Option<String>,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ContextResolve {
            entry_id,
            resolved_by,
            note,
        }))
        .await;
}

/// Feed an artifact creation to the session task. `artifact_id` must be the
/// same ID the real writer's DB insert already assigned. Shadow-persisted.
#[autometrics]
pub async fn task_artifact_create(
    handle: &SessionTaskHandle,
    artifact_id: String,
    actor_id: String,
    name: String,
    artifact_type: Option<String>,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ArtifactCreate {
            artifact_id,
            actor_id,
            name,
            artifact_type,
        }))
        .await;
}

/// Feed an artifact update to the session task. Shadow-persisted.
#[autometrics]
pub async fn task_artifact_update(
    handle: &SessionTaskHandle,
    artifact_id: String,
    actor_id: String,
    name: String,
    artifact_type: Option<String>,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ArtifactUpdate {
            artifact_id,
            actor_id,
            name,
            artifact_type,
        }))
        .await;
}

/// Feed an artifact deletion to the session task. `name`/`artifact_type` are
/// the caller's already-fetched values (see `SessionEvent::ArtifactDeleted`'s
/// doc comment for why). Shadow-persisted.
#[autometrics]
pub async fn task_artifact_delete(
    handle: &SessionTaskHandle,
    artifact_id: String,
    actor_id: String,
    name: String,
    artifact_type: Option<String>,
) {
    let _ = handle
        .send(InboundEvent::Live(LiveEvent::ArtifactDelete {
            artifact_id,
            actor_id,
            name,
            artifact_type,
        }))
        .await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use session::{PolicyConstraint, PolicyTarget};

    /// Live-DB test for `replay_history`. Requires `DATABASE_URL` to point at
    /// a real Postgres (see .env.example) — `#[ignore]`d so `cargo test
    /// --workspace` stays DB-free by default; run explicitly with
    /// `cargo test -p server --lib session_task::tests -- --ignored`.
    ///
    /// Seeds a throwaway session with three raw event rows: two in
    /// `SessionEvent`'s own JSON shape (what `real_persist` writes) and one in
    /// the `ws.rs` `WsMessage`-envelope shape (what the not-yet-migrated
    /// handlers write today) sandwiched between them, then calls
    /// `replay_history` directly and asserts the machine's memory reflects
    /// only the two parseable rows — the un-parseable row is skipped, not
    /// erroring the fold, and does not advance `memory.cursor`.
    #[tokio::test]
    #[ignore]
    async fn replay_history_folds_parseable_rows_and_skips_the_rest() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this live-DB test");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        // Seed the "system" actor (migration 026) directly rather than via
        // db::migrate(&pool) — this DB's _sqlx_migrations tracking table is
        // out of sync with its actual schema (a separate, pre-existing issue,
        // unrelated to this migration), so a full migrate() run fails on an
        // earlier migration's "constraint already exists" — not something to
        // paper over here.
        sqlx::query("INSERT INTO actors (id, type, name) VALUES ('system', 'agent', 'System') ON CONFLICT (id) DO NOTHING")
            .execute(&pool)
            .await
            .expect("failed to seed system actor");

        let human = db::actors::create_human(
            &pool,
            db::actors::CreateHuman {
                name: "phase0-replay-test-human".into(),
                email: format!("phase0-replay-test-{}@example.invalid", ulid::Ulid::new()),
            },
        )
        .await
        .expect("failed to create test human actor");
        let agent = db::actors::create_agent(
            &pool,
            db::actors::CreateAgent {
                name: "phase0-replay-test-agent".into(),
                provider: "custom".into(),
                model: "test".into(),
                config: None,
            },
        )
        .await
        .expect("failed to create test agent actor");

        let created = db::sessions::create(
            &pool,
            db::sessions::CreateSession {
                name: "phase0-replay-test".into(),
                description: None,
                created_by: human.id.clone(),
                approval_policy: None,
            },
        )
        .await
        .expect("failed to create test session");
        let session_id = created.session.id.clone();

        // seq 1: a real SessionEvent (PolicySet) — the shape `real_persist` writes.
        let policy_event = SessionEvent::PolicySet {
            target: PolicyTarget::All,
            constraint: PolicyConstraint::Forward,
            set_by_cap: "cap-test".into(),
            set_at: chrono::Utc::now(),
        };
        db::events::append(
            &pool,
            db::events::AppendEvent {
                session_id: session_id.clone(),
                actor_id: human.id.clone(),
                event_type: policy_event.type_name().into(),
                payload: serde_json::to_value(&policy_event).unwrap(),
                parent_event_id: None,
                seq: 1,
            },
        )
        .await
        .expect("failed to insert policy_event");

        // seq 2: NOT a SessionEvent shape — mimics a `ws.rs`-written row
        // (WsMessage envelope, dot-notation type tag). Must be skipped, not error.
        db::events::append(
            &pool,
            db::events::AppendEvent {
                session_id: session_id.clone(),
                actor_id: human.id.clone(),
                event_type: "message.posted".into(),
                payload: serde_json::json!({
                    "protocol_version": 1, "id": "01TEST", "type": "message.posted",
                    "content": "hi",
                }),
                parent_event_id: None,
                seq: 2,
            },
        )
        .await
        .expect("failed to insert legacy-shape row");

        // seq 3: a real SessionEvent (AgentAttached) — exercises apply_logged's
        // membership insert + its Broadcast effect through run_effects.
        let attach_event = SessionEvent::AgentAttached {
            actor_id: agent.id.clone(),
            cap_id: "cap-test".into(),
            attached_at: chrono::Utc::now(),
        };
        db::events::append(
            &pool,
            db::events::AppendEvent {
                session_id: session_id.clone(),
                actor_id: agent.id.clone(),
                event_type: attach_event.type_name().into(),
                payload: serde_json::to_value(&attach_event).unwrap(),
                parent_event_id: None,
                seq: 3,
            },
        )
        .await
        .expect("failed to insert attach_event");

        let hub = Arc::new(SessionHub::new(session_id.clone(), pool.clone()));
        let timers: Arc<DashMap<String, JoinHandle<()>>> = Arc::new(DashMap::new());
        let (self_tx, _self_rx) = mpsc::channel(8);
        let sessions = Arc::new(DashMap::new());
        let reflector = Arc::new(Reflector::new());

        let (_state, memory) = replay_history(
            &session_id,
            SessionState::Active,
            SessionMemory::new(session_id.clone(), human.id.clone()),
            &pool,
            &hub,
            &timers,
            &self_tx,
            &sessions,
            &reflector,
            0,
        )
        .await;

        assert!(
            matches!(
                memory.policies.get(&PolicyTarget::All),
                Some(PolicyConstraint::Forward)
            ),
            "PolicySet row (seq 1) should have been replayed, got {:?}",
            memory.policies.get(&PolicyTarget::All),
        );
        assert!(
            memory.members.contains_key(&agent.id),
            "AgentAttached row (seq 3) should have been replayed",
        );
        assert_eq!(
            memory.cursor, 3,
            "cursor should land on the last REPLAYED seq (3), skipping the \
             unparseable row (seq 2) entirely rather than advancing onto it",
        );

        // Best-effort cleanup so repeat runs don't accumulate test data.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM actors WHERE id = ANY($1)")
            .bind(&[human.id, agent.id][..])
            .execute(&pool)
            .await;
    }

    /// Drain broadcasts off `rx` for up to `timeout` looking for one containing
    /// Fully drain every broadcast currently available on `rx` within `window`.
    ///
    /// Each `apply_live`/`apply_logged` handler computes its `session_updated`
    /// broadcast payload from `memory` *before* its own `Persist` effect has
    /// advanced `memory.cursor` (see `session_updated_broadcast` call sites in
    /// `transition.rs`) — so consecutive steps' broadcasts land one step
    /// "behind" whichever step triggered them. A find-first-match-and-stop
    /// helper leaves that trailing message sitting in the channel for the
    /// *next* step to spuriously pick up. Draining everything each time and
    /// asserting on the whole batch avoids that drift entirely.
    async fn drain_broadcasts(
        rx: &mut tokio::sync::broadcast::Receiver<Utf8Bytes>,
        window: Duration,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(msg)) => out.push(msg.to_string()),
                _ => break, // timed out or channel closed — done draining
            }
        }
        out
    }

    /// Live-DB test for the Phase 1 bridges (ownership transfer, admin
    /// pause/resume/archive, approval claim — all shadow-persisted, see each
    /// `task_*` function's doc comment) plus the typed-broadcast layer
    /// (`session_broadcast::to_ws_payload`, wired into `real_persist`).
    ///
    /// Spawns a real session task (not just `replay_history` in isolation, as
    /// the Phase 0 test does) and observes it purely through `hub.broadcast_tx`
    /// — the only externally-visible effect of a shadow-persisted event, since
    /// shadow_persist touches neither Postgres nor `hub.snapshot`.
    ///
    /// Requires `DATABASE_URL` — see the Phase 0 test's doc comment for how to
    /// run this (`--ignored`).
    #[tokio::test]
    #[ignore]
    async fn phase1_bridges_and_typed_broadcast() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this live-DB test");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        // Seed the "system" actor (migration 026) directly rather than via
        // db::migrate(&pool) — this DB's _sqlx_migrations tracking table is
        // out of sync with its actual schema (a separate, pre-existing issue,
        // unrelated to this migration), so a full migrate() run fails on an
        // earlier migration's "constraint already exists" — not something to
        // paper over here.
        sqlx::query("INSERT INTO actors (id, type, name) VALUES ('system', 'agent', 'System') ON CONFLICT (id) DO NOTHING")
            .execute(&pool)
            .await
            .expect("failed to seed system actor");

        let human = db::actors::create_human(
            &pool,
            db::actors::CreateHuman {
                name: "phase1-test-human".into(),
                email: format!("phase1-test-{}@example.invalid", ulid::Ulid::new()),
            },
        )
        .await
        .expect("failed to create test human actor");
        let agent = db::actors::create_agent(
            &pool,
            db::actors::CreateAgent {
                name: "phase1-test-agent".into(),
                provider: "custom".into(),
                model: "test".into(),
                config: None,
            },
        )
        .await
        .expect("failed to create test agent actor");

        let created = db::sessions::create(
            &pool,
            db::sessions::CreateSession {
                name: "phase1-test".into(),
                description: None,
                created_by: human.id.clone(),
                approval_policy: None,
            },
        )
        .await
        .expect("failed to create test session");
        let session_id = created.session.id.clone();

        // Seed an AgentAttached row (real SessionEvent shape) so cold-start
        // replay (Phase 0) populates memory.members[agent.id] before the task
        // starts accepting live input — LiveEvent::ActorConnected only ever
        // *updates* an existing MemberRecord, it never inserts one, so
        // task_approval_create below would otherwise be rejected by
        // live_approval_create's "actor must be a present member" gate.
        let attach_event = SessionEvent::AgentAttached {
            actor_id: agent.id.clone(),
            cap_id: "test-cap".into(),
            attached_at: chrono::Utc::now(),
        };
        db::events::append(
            &pool,
            db::events::AppendEvent {
                session_id: session_id.clone(),
                actor_id: agent.id.clone(),
                event_type: attach_event.type_name().into(),
                payload: serde_json::to_value(&attach_event).unwrap(),
                parent_event_id: None,
                seq: 1,
            },
        )
        .await
        .expect("failed to seed attach_event");
        // db::events::append takes an explicit seq and does not consult/advance
        // session_sequences (unlike the real write path, which always allocates
        // through it) — bump it to match, or the first real live write below
        // collides on seq=1 (unique constraint events_session_seq).
        sqlx::query("UPDATE session_sequences SET next_seq = 2 WHERE session_id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await
            .expect("failed to advance session_sequences past the seeded row");

        let hub = Arc::new(SessionHub::new(session_id.clone(), pool.clone()));
        let sessions = Arc::new(DashMap::new());
        let reflector = Arc::new(Reflector::new());
        let handle = spawn_session_task(
            session_id.clone(),
            human.id.clone(),
            pool.clone(),
            Arc::clone(&hub),
            Arc::clone(&sessions),
            Arc::clone(&reflector),
            1,
        );

        let mut rx = hub.broadcast_tx.subscribe();

        // Cold-start replay of the seeded AgentAttached row (seq 1) fires its
        // own session_updated broadcast before any of this test's live events
        // are even sent — drain it now so it isn't mistaken for one of them.
        drain_broadcasts(&mut rx, Duration::from_secs(2)).await;

        // ── Shadow bridges: ownership transfer + admin pause/resume ─────────
        // Each should reach transition()'s live handlers and produce the
        // generic session_updated broadcast, without panicking the task
        // (a panic would silently kill the task; the batch coming back empty
        // is the observable symptom).
        task_ownership_transfer(&handle, human.id.clone(), agent.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "ownership transfer should reach the machine and broadcast, got {batch:?}",
        );

        task_admin_pause(&handle, human.id.clone(), None).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "admin pause should reach the machine and broadcast, got {batch:?}",
        );

        task_admin_resume(&handle, human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "admin resume should reach the machine and broadcast, got {batch:?}",
        );

        // ── Approval claim CAS guard ──────────────────────────────────────────
        // Claiming an approval_id the machine has never heard of must be a
        // silent no-op (mirrors ws.rs's claim_if_pending_in_tx CAS failure) —
        // no broadcast at all, not even the generic ping. The channel is fully
        // drained as of the previous step, so an empty batch here is
        // unambiguous.
        task_approval_claim(&handle, "nonexistent-approval".into(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_millis(500)).await;
        assert!(
            batch.is_empty(),
            "claiming a non-pending/unknown approval must not broadcast (CAS guard), got {batch:?}",
        );

        // ── Typed broadcast, exercised via the real autonomous path ─────────
        // ApprovalExpired is already machine-authoritative (is_machine_autonomous)
        // — real_persist runs, and session_broadcast::to_ws_payload should turn
        // it into a real "approval.timed_out" broadcast, not just the generic
        // ping. agent.id is already a present member via the seeded
        // AgentAttached row replayed at task startup (see setup above) — the
        // live_approval_create membership gate would otherwise reject this.
        task_approval_create(
            &handle,
            "phase1-test-approval".into(),
            agent.id.clone(),
            "test_tool".into(),
            serde_json::json!({}),
            Some(50), // 50ms expiry — fires almost immediately
        )
        .await;
        // ApprovalRequested is shadow-persisted (ws.rs's REST handler is the
        // real writer/broadcaster) — the machine only emits its own generic
        // ping here, not a typed "approval.requested". Window is wide enough
        // to also catch the timer firing ~50ms later, so this batch may
        // already include the typed approval.timed_out broadcast too.
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(3)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "approval creation should broadcast, got {batch:?}",
        );
        assert!(
            batch.iter().any(|m| m.contains("approval.timed_out")),
            "expired approval should produce a typed approval.timed_out broadcast \
             via real_persist + session_broadcast::to_ws_payload, not just the \
             generic session_updated ping, got {batch:?}",
        );

        // Let any timer this test armed fully settle before the runtime tears
        // down — a session task never exits on its own (self_tx keeps its own
        // mpsc channel open for the task's own lifetime, by design, so it
        // outlives `handle` going out of scope below), so ending the test
        // immediately after the last assertion can abruptly cancel it
        // mid-poll instead of letting it idle cleanly.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Best-effort cleanup.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM actors WHERE id = ANY($1)")
            .bind(&[human.id, agent.id][..])
            .execute(&pool)
            .await;
    }

    /// Live-DB test for Phase 2's content modeling (messages/context/
    /// artifacts). Unlike the Phase 1 test, this verifies actual *memory
    /// state* — `memory.artifacts`/`memory.context` and `build_snapshot`'s
    /// projection of them — not just "a broadcast fired", since that's the
    /// actual thing Phase 2 adds. Uses `replay_history` directly (same
    /// technique as the Phase 0 test) rather than spawning a live task,
    /// since `spawn_session_task`'s internal memory isn't externally
    /// observable — replay and live share the identical `apply_logged` arms,
    /// so this exercises the same logic a live task would run.
    ///
    /// Requires `DATABASE_URL` — see the Phase 0 test's doc comment for how
    /// to run this (`--ignored`).
    #[tokio::test]
    #[ignore]
    async fn phase2_content_events_populate_memory_and_snapshot() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this live-DB test");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        sqlx::query("INSERT INTO actors (id, type, name) VALUES ('system', 'agent', 'System') ON CONFLICT (id) DO NOTHING")
            .execute(&pool)
            .await
            .expect("failed to seed system actor");

        let human = db::actors::create_human(
            &pool,
            db::actors::CreateHuman {
                name: "phase2-test-human".into(),
                email: format!("phase2-test-{}@example.invalid", ulid::Ulid::new()),
            },
        )
        .await
        .expect("failed to create test human actor");

        let created = db::sessions::create(
            &pool,
            db::sessions::CreateSession {
                name: "phase2-test".into(),
                description: None,
                created_by: human.id.clone(),
                approval_policy: None,
            },
        )
        .await
        .expect("failed to create test session");
        let session_id = created.session.id.clone();

        // seq 1: MessagePosted — must not touch memory.artifacts/context (no-op,
        // matches ws.rs's own apply_event, which is EventLog-only for this kind).
        let msg_event = SessionEvent::MessagePosted {
            actor_id: human.id.clone(),
            content: "hello".into(),
            posted_at: chrono::Utc::now(),
        };
        // seq 2: ArtifactCreated — artifact "a1", type "document".
        let art_created = SessionEvent::ArtifactCreated {
            artifact_id: "a1".into(),
            actor_id: human.id.clone(),
            name: "Draft".into(),
            artifact_type: Some("document".into()),
            created_at: chrono::Utc::now(),
        };
        // seq 3: ArtifactUpdated — renames "a1" to "Draft v2".
        let art_updated = SessionEvent::ArtifactUpdated {
            artifact_id: "a1".into(),
            actor_id: human.id.clone(),
            name: "Draft v2".into(),
            artifact_type: Some("document".into()),
            updated_at: chrono::Utc::now(),
        };
        // seq 4: a second artifact "a2", later deleted.
        let art2_created = SessionEvent::ArtifactCreated {
            artifact_id: "a2".into(),
            actor_id: human.id.clone(),
            name: "Scratch".into(),
            artifact_type: None,
            created_at: chrono::Utc::now(),
        };
        // seq 5: ArtifactDeleted — removes "a2". memory.artifacts should end up
        // with exactly one entry ("a1"), confirming both the insert-if-absent
        // (ArtifactCreated) and remove (ArtifactDeleted) paths.
        let art2_deleted = SessionEvent::ArtifactDeleted {
            artifact_id: "a2".into(),
            actor_id: human.id.clone(),
            name: "Scratch".into(),
            artifact_type: None,
            deleted_at: chrono::Utc::now(),
        };
        // seq 6: ContextEntryAdded.
        let ctx_added = SessionEvent::ContextEntryAdded {
            entry_id: "c1".into(),
            actor_id: human.id.clone(),
            kind: protocol::types::ContextEntryKind::Decision,
            content: "use postgres".into(),
            added_at: chrono::Utc::now(),
        };
        // seq 7: ContextEntryResolved.
        let ctx_resolved = SessionEvent::ContextEntryResolved {
            entry_id: "c1".into(),
            resolved_by: human.id.clone(),
            note: Some("confirmed in review".into()),
            resolved_at: chrono::Utc::now(),
        };

        for (i, event) in [
            &msg_event as &SessionEvent,
            &art_created,
            &art_updated,
            &art2_created,
            &art2_deleted,
            &ctx_added,
            &ctx_resolved,
        ]
        .into_iter()
        .enumerate()
        {
            db::events::append(
                &pool,
                db::events::AppendEvent {
                    session_id: session_id.clone(),
                    actor_id: human.id.clone(),
                    event_type: event.type_name().into(),
                    payload: serde_json::to_value(event).unwrap(),
                    parent_event_id: None,
                    seq: (i + 1) as i64,
                },
            )
            .await
            .unwrap_or_else(|e| panic!("failed to insert event #{i}: {e}"));
        }

        let hub = Arc::new(SessionHub::new(session_id.clone(), pool.clone()));
        let timers: Arc<DashMap<String, JoinHandle<()>>> = Arc::new(DashMap::new());
        let (self_tx, _self_rx) = mpsc::channel(8);
        let sessions = Arc::new(DashMap::new());
        let reflector = Arc::new(Reflector::new());

        let (state, memory) = replay_history(
            &session_id,
            SessionState::Active,
            SessionMemory::new(session_id.clone(), human.id.clone()),
            &pool,
            &hub,
            &timers,
            &self_tx,
            &sessions,
            &reflector,
            0,
        )
        .await;

        assert_eq!(
            memory.artifacts.len(),
            1,
            "expected exactly one surviving artifact, got {:?}",
            memory.artifacts
        );
        let a1 = memory
            .artifacts
            .get("a1")
            .expect("artifact a1 should exist");
        assert_eq!(
            a1.name, "Draft v2",
            "ArtifactUpdated should have renamed a1"
        );
        assert_eq!(a1.artifact_type, "document");
        assert!(
            !memory.artifacts.contains_key("a2"),
            "a2 should have been removed by ArtifactDeleted"
        );

        assert_eq!(memory.context.len(), 1);
        let c1 = memory
            .context
            .get("c1")
            .expect("context entry c1 should exist");
        assert!(
            c1.resolved,
            "ContextEntryResolved should have set resolved=true"
        );
        assert_eq!(c1.resolved_by.as_deref(), Some(human.id.as_str()));
        assert_eq!(c1.resolution_note.as_deref(), Some("confirmed in review"));
        assert_eq!(c1.content, "use postgres");

        // build_snapshot must project the same data out.
        let snap = session::build_snapshot(&state, &memory);
        assert_eq!(snap.artifacts.len(), 1);
        assert_eq!(snap.artifacts[0].name, "Draft v2");
        assert_eq!(snap.context.len(), 1);
        assert!(snap.context[0].resolved);

        assert_eq!(
            memory.cursor, 7,
            "cursor should have advanced through all 7 seeded rows"
        );

        // Best-effort cleanup.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM actors WHERE id = $1")
            .bind(&human.id)
            .execute(&pool)
            .await;
    }

    /// Live-DB test for Phase 3's approval cancel/delegate/dispute bridges,
    /// specifically targeting the concern that motivated deferring this
    /// phase's live verification: the ORB `/invoke` path can create *two*
    /// separate approval rows for one logical gated tool call
    /// (`orb_approval_id` + a second `sidecar_aid`), both converging on the
    /// same `create_approval_for_session` (confirmed by direct source
    /// reading — see the architecture.md audit). This test calls that exact
    /// function twice, matching the real dual-row shape, then exercises
    /// claim/cancel independently on each row and confirms neither
    /// operation leaks into the other's state.
    ///
    /// `crates/shim`/`crates/guardian` don't compile on this Windows/WSL
    /// setup (Unix-only APIs — by design, see .env.example's platform note,
    /// not a bug) so a literal end-to-end run through the real binaries
    /// isn't possible here. This exercises the same server-side function
    /// those binaries would call, which is where the actual authorization
    /// and cross-contamination risk lives.
    ///
    /// Requires `DATABASE_URL` — see the Phase 0 test's doc comment for how
    /// to run this (`--ignored`).
    #[tokio::test]
    #[ignore]
    async fn phase3_orb_dual_approval_rows_do_not_cross_contaminate() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this live-DB test");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        sqlx::query("INSERT INTO actors (id, type, name) VALUES ('system', 'agent', 'System') ON CONFLICT (id) DO NOTHING")
            .execute(&pool)
            .await
            .expect("failed to seed system actor");

        let human = db::actors::create_human(
            &pool,
            db::actors::CreateHuman {
                name: "phase3-test-human".into(),
                email: format!("phase3-test-{}@example.invalid", ulid::Ulid::new()),
            },
        )
        .await
        .expect("failed to create test human actor");
        let agent = db::actors::create_agent(
            &pool,
            db::actors::CreateAgent {
                name: "phase3-test-agent".into(),
                provider: "custom".into(),
                model: "test".into(),
                config: None,
            },
        )
        .await
        .expect("failed to create test agent actor");

        let created = db::sessions::create(
            &pool,
            db::sessions::CreateSession {
                name: "phase3-test".into(),
                description: None,
                created_by: human.id.clone(),
                approval_policy: None,
            },
        )
        .await
        .expect("failed to create test session");
        let session_id = created.session.id.clone();

        // Seed AgentAttached (seq 1) so cold-start replay makes the agent a
        // present member — required for the approval-creation bridge, same
        // reasoning as the Phase 1 test's setup.
        let attach_event = SessionEvent::AgentAttached {
            actor_id: agent.id.clone(),
            cap_id: "test-cap".into(),
            attached_at: chrono::Utc::now(),
        };
        db::events::append(
            &pool,
            db::events::AppendEvent {
                session_id: session_id.clone(),
                actor_id: agent.id.clone(),
                event_type: attach_event.type_name().into(),
                payload: serde_json::to_value(&attach_event).unwrap(),
                parent_event_id: None,
                seq: 1,
            },
        )
        .await
        .expect("failed to seed attach_event");
        sqlx::query("UPDATE session_sequences SET next_seq = 2 WHERE session_id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await
            .expect("failed to advance session_sequences past the seeded row");

        let prometheus_handle = crate::metrics_route::install_or_reuse_recorder();
        let state = Arc::new(crate::state::AppState::new(
            pool.clone(),
            None,
            prometheus_handle,
            ulid::Ulid::new().to_string(),
        ));
        let hub = state.get_or_create_hub(&session_id);
        // Register the task under AppState's own `sessions` map — unlike the
        // earlier tests' manually-constructed map, `create_approval_for_session`
        // looks the task up via `state.sessions.get(...)` internally, so it
        // must be the SAME map the task was registered into.
        let _task = state.get_or_create_session_task(&session_id, &human.id, Arc::clone(&hub));

        let mut rx = hub.broadcast_tx.subscribe();
        drain_broadcasts(&mut rx, Duration::from_secs(2)).await; // drain cold-replay's own ping

        // Two approval rows for "the same" gated tool call — matching the ORB
        // orb_approval_id + sidecar_aid shape.
        let (approval_a, _) = crate::ws::create_approval_for_session(
            &state,
            &session_id,
            &agent.id,
            "test_tool",
            &serde_json::json!({"n": 1}),
            300,
        )
        .await
        .expect("create_approval_for_session (A) should succeed");
        let (approval_b, _) = crate::ws::create_approval_for_session(
            &state,
            &session_id,
            &agent.id,
            "test_tool",
            &serde_json::json!({"n": 1}),
            300,
        )
        .await
        .expect("create_approval_for_session (B) should succeed");
        assert_ne!(
            approval_a, approval_b,
            "the two ORB-style rows must be genuinely distinct approvals"
        );
        // Generous window: two create_approval_for_session calls back-to-back
        // (matching the real ORB dual-row shape) put enough simultaneous load
        // on the pool that establishing the next new connection has been
        // observed taking up to ~20s in this dev environment (Docker
        // Desktop/WSL2 port-forwarding latency, not a query or lock issue —
        // confirmed via direct timing: the alloc_seq call itself returns
        // near-instantly once connected, and pg_stat_activity shows no
        // long-running query during the delay). Not a bug to fix here.
        drain_broadcasts(&mut rx, Duration::from_secs(25)).await;

        let task = state
            .sessions
            .get(&session_id)
            .map(|e| e.value().clone())
            .expect("session task should be registered after create_approval_for_session");

        // Claim A — should broadcast (A: Pending -> Claimed).
        task_approval_claim(&task, approval_a.clone(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "claiming A should broadcast, got {batch:?}"
        );

        // Claim B independently — should ALSO broadcast, proving A's claim
        // didn't somehow already resolve B too.
        task_approval_claim(&task, approval_b.clone(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "claiming B should independently broadcast, got {batch:?}"
        );

        // Re-claiming A must now be a no-op (CAS: A is Claimed, not Pending) —
        // confirms A's own state stuck and wasn't reset by claiming B.
        task_approval_claim(&task, approval_a.clone(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_millis(500)).await;
        assert!(
            batch.is_empty(),
            "re-claiming an already-claimed A must not broadcast, got {batch:?}"
        );

        // Cancel B — cancel has no CAS guard (matches ws.rs's own unconditional
        // set_state_in_tx), so this always broadcasts regardless of B's state.
        task_approval_cancel(&task, approval_b.clone(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "cancelling B should broadcast, got {batch:?}"
        );

        // The cross-contamination check: re-claiming A must STILL be a no-op —
        // if cancelling B had leaked into A's state (e.g. both approval_ids
        // somehow aliased to the same memory.approvals entry), this would
        // incorrectly find A "Pending" again and broadcast.
        task_approval_claim(&task, approval_a.clone(), human.id.clone()).await;
        let batch = drain_broadcasts(&mut rx, Duration::from_millis(500)).await;
        assert!(
            batch.is_empty(),
            "cancelling B must not affect A's state — re-claiming A broadcast when it shouldn't have, got {batch:?}",
        );

        // Also verify delegate/dispute reach the machine without panicking
        // (both are unconditional EventLog-only no-ops memory-wise, so a
        // broadcast is the only observable signal either way).
        task_approval_delegate(
            &task,
            approval_a.clone(),
            human.id.clone(),
            agent.id.clone(),
        )
        .await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "delegating A should broadcast, got {batch:?}"
        );

        task_approval_dispute(
            &task,
            approval_a.clone(),
            human.id.clone(),
            "disagree".into(),
        )
        .await;
        let batch = drain_broadcasts(&mut rx, Duration::from_secs(2)).await;
        assert!(
            batch.iter().any(|m| m.contains("session_updated")),
            "disputing A should broadcast, got {batch:?}"
        );

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Best-effort cleanup.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM actors WHERE id = ANY($1)")
            .bind(&[human.id, agent.id][..])
            .execute(&pool)
            .await;
    }

    /// Live-DB test for Phase 4: confirms `Effect::Bundle` (now produced by
    /// `live_saga_begin`, see `transition.rs`) really flows all the way
    /// through `run_effects`' `Effect::Bundle` arm into a real
    /// `reflector.append()` call — the consumer side session_task.rs already
    /// had before this phase, now actually exercised by a producer.
    ///
    /// No bridge function exists for `LiveEvent::SagaBegin` (matches the
    /// approved plan's scope — this phase makes the plumbing correct, it
    /// does not add a new live saga-triggering feature), so this sends the
    /// `InboundEvent` directly — the same way a future real caller eventually
    /// would, just without a `task_*` convenience wrapper yet.
    ///
    /// Requires `DATABASE_URL` — see the Phase 0 test's doc comment for how
    /// to run this (`--ignored`).
    #[tokio::test]
    #[ignore]
    async fn phase4_saga_begin_reaches_the_reflector() {
        let database_url = std::env::var("DATABASE_URL")
            .expect("DATABASE_URL must be set to run this live-DB test");
        let pool = PgPool::connect(&database_url)
            .await
            .expect("failed to connect to DATABASE_URL");
        sqlx::query("INSERT INTO actors (id, type, name) VALUES ('system', 'agent', 'System') ON CONFLICT (id) DO NOTHING")
            .execute(&pool)
            .await
            .expect("failed to seed system actor");

        let human = db::actors::create_human(
            &pool,
            db::actors::CreateHuman {
                name: "phase4-test-human".into(),
                email: format!("phase4-test-{}@example.invalid", ulid::Ulid::new()),
            },
        )
        .await
        .expect("failed to create test human actor");

        let created = db::sessions::create(
            &pool,
            db::sessions::CreateSession {
                name: "phase4-test".into(),
                description: None,
                created_by: human.id.clone(),
                approval_policy: None,
            },
        )
        .await
        .expect("failed to create test session");
        let session_id = created.session.id.clone();

        let hub = Arc::new(SessionHub::new(session_id.clone(), pool.clone()));
        let sessions = Arc::new(DashMap::new());
        let reflector = Arc::new(Reflector::new());
        let handle = spawn_session_task(
            session_id.clone(),
            human.id.clone(),
            pool.clone(),
            Arc::clone(&hub),
            Arc::clone(&sessions),
            Arc::clone(&reflector),
            1,
        );

        let mut rx = hub.broadcast_tx.subscribe();
        drain_broadcasts(&mut rx, Duration::from_secs(2)).await; // drain cold-replay's own ping (empty session, but be consistent)

        let saga_id = "phase4-saga";
        let steps = vec![session::SagaStepSpec {
            step_idx: 0,
            participant: "some-other-session".into(),
            message: serde_json::json!({"action": "commit"}),
            compensation: serde_json::json!({"action": "rollback"}),
            timeout_ms: 30_000,
        }];
        handle
            .send(InboundEvent::Live(LiveEvent::SagaBegin {
                saga_id: saga_id.into(),
                saga_type: "custom".into(),
                steps,
                metadata: serde_json::Value::Null,
            }))
            .await
            .expect("session task should still be accepting messages");

        // SagaBegun/SagaStepSent are real_persist (autonomous) — allow for
        // the same kind of connection-establishment latency observed in the
        // Phase 3 test under concurrent load; this test has no concurrent
        // load, but generous is cheap and avoids reintroducing test flakiness.
        drain_broadcasts(&mut rx, Duration::from_secs(10)).await;

        let entries = reflector.replay(session::ReflectorCursor::zero());
        assert_eq!(
            entries.len(),
            1,
            "expected exactly one bundle appended to the reflector, got {}",
            entries.len(),
        );
        let (_, bundle) = &entries[0];
        assert_eq!(bundle.saga_id, saga_id);
        assert_eq!(bundle.step_idx, 0);
        assert_eq!(bundle.from_session, session_id);
        assert_eq!(bundle.to_session, "some-other-session");
        assert!(
            matches!(&bundle.kind, session::BundleKind::Step { message, .. }
                if message == &serde_json::json!({"action": "commit"})),
            "unexpected bundle kind: {:?}",
            bundle.kind,
        );

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Best-effort cleanup.
        let _ = sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(&session_id)
            .execute(&pool)
            .await;
        let _ = sqlx::query("DELETE FROM actors WHERE id = $1")
            .bind(&human.id)
            .execute(&pool)
            .await;
    }
}
