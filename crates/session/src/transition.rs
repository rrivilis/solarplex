//! Pure transition function: `(state, memory, event) → (state', memory', Vec<Effect>)`
//!
//! # Key invariant
//! `Replayed` events MUST NOT produce `Persist` effects.  Debug-asserted on every call,
//! and exhaustively proptest-ed in `tests/proptest_invariants.rs`.
//!
//! # Phase notes
//! Phase 2 (this): full approval policy evaluation, `ApprovalCreate` live handler,
//! effect algebra (Proposed/Committed/Diverged) tracked in `SessionMemory.proposals`,
//! `eligible_approvers` maintained across participation events.
//!
//! Phase 3: real snapshot payloads in Broadcast effects (uses `memory::build_snapshot`).
//! Phase 5: GC loops replaced by `SetTimer`-driven drain completion.

use chrono::Utc;
use std::collections::BTreeMap;

use crate::effects::{BundleDisposition, BundleKind, Effect, ReflectorCursor, SagaBundle};
use crate::events::{PolicyConstraint, PolicyTarget, SagaOutcome, SagaStepSpec, SagaTermination, SessionEvent};
use crate::inbound::{InboundEvent, LiveEvent, VoteDecision};
use crate::memory::{
    ApprovalRecord, ApprovalStatus, CapRecord, GateKind, GatedBundle, MemberRecord, ProposalRecord,
    SagaRecord, SagaStatus, SessionMemory,
};
use crate::saga::{build_session_saga, ProtocolOutcome, SagaProtocol};
use crate::state::SessionState;

// ── Public entrypoint ─────────────────────────────────────────────────────────

/// Pure session transition function.
///
/// Returns the successor `(state', memory', effects)`.  The caller must:
/// 1. Execute each `Effect` in order.
/// 2. For `Persist(e)`: persist `e`, get `seq`, then call
///    `transition(state', memory', Replayed { seq, event: e })` to advance memory.
pub fn transition(
    state:  SessionState,
    memory: SessionMemory,
    event:  InboundEvent,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    match event {
        InboundEvent::Replayed { seq, event } => {
            let (s, m, effects) = apply_logged(state, memory, seq, event);
            debug_assert!(
                !effects.iter().any(|e| e.is_persist()),
                "BUG: Replayed transition produced a Persist effect"
            );
            (s, m, effects)
        }
        InboundEvent::Live(live) => {
            if state.is_terminal() {
                return (state, memory, vec![]);
            }
            apply_live(state, memory, live)
        }
    }
}

// ── Replay: apply a logged event to advance memory ───────────────────────────
//
// MUST NOT produce Persist effects.
// MAY produce CancelTimer (idempotent) or CloseConnection (for drain fencing).

fn apply_logged(
    state:      SessionState,
    mut memory: SessionMemory,
    seq:        i64,
    event:      SessionEvent,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    memory.advance_cursor(seq);

    match event {
        // ── Lifecycle ─────────────────────────────────────────────────────────

        SessionEvent::SessionCreated { owner_id, name, policy, .. } => {
            memory.session_name   = name;
            memory.session_policy = policy;
            memory.owner_id       = owner_id.clone();
            memory.members.entry(owner_id.clone()).or_insert_with(|| MemberRecord {
                actor_id:   owner_id,
                role:       "owner".into(),
                joined_at:  Utc::now(),
                detached:   false,
                connection: None,
            });
            memory.recount_eligible();
            (state, memory, vec![])
        }

        SessionEvent::SessionPaused { paused_by, reason, paused_at } => (
            SessionState::Suspended { paused_by, reason, since: paused_at },
            memory,
            vec![],
        ),

        SessionEvent::SessionResumed { .. } => (SessionState::Active, memory, vec![]),

        SessionEvent::SessionArchived { archived_at, .. } => (
            SessionState::Archived { at: archived_at },
            memory,
            vec![],
        ),

        // ── Participation algebra ─────────────────────────────────────────────

        SessionEvent::ParticipantJoined { actor_id, role, joined_at } => {
            memory.members.entry(actor_id.clone()).or_insert_with(|| MemberRecord {
                actor_id,
                role,
                joined_at,
                detached:   false,
                connection: None,
            });
            memory.recount_eligible();
            (state, memory, vec![])
        }

        SessionEvent::ParticipantLeft { actor_id, .. } => {
            if let Some(m) = memory.members.get_mut(&actor_id) {
                m.detached   = true;
                m.connection = None;
            }
            memory.recount_eligible();
            (state, memory, vec![])
        }

        SessionEvent::OwnershipTransferred { from_actor, to_actor, .. } => {
            memory.owner_id = to_actor.clone();
            // Demote the outgoing owner *and* promote the incoming one — the
            // DB write path (db::sessions::transfer_ownership_in_tx) always
            // does both in the same transaction; this in-memory projection
            // only did the promotion, leaving the outgoing owner's member
            // record permanently stuck at role="owner" for the rest of this
            // session task's process lifetime (until a cold-start rebuild
            // from session_memberships re-derives it correctly). That's the
            // "two owners" state a member-role-colored view like the
            // sidebar's session minimap can end up displaying.
            if let Some(m) = memory.members.get_mut(&from_actor) {
                m.role = "collaborator".into();
            }
            if let Some(m) = memory.members.get_mut(&to_actor) {
                m.role = "owner".into();
            }
            memory.recount_eligible();
            (state, memory, vec![])
        }

        SessionEvent::AgentAttached { actor_id, .. } => {
            memory.members
                .entry(actor_id.clone())
                .and_modify(|m| { m.detached = false; })
                .or_insert_with(|| MemberRecord {
                    actor_id,
                    role:       "agent".into(),
                    joined_at:  Utc::now(),
                    detached:   false,
                    connection: None,
                });
            // Agents don't count as approvers; no recount needed.
            // Broadcast so already-connected browser tabs see the attach live —
            // mirrors live_actor_connected/live_actor_disconnected below, which
            // do this on their (unpersisted) live path. AgentAttached is
            // persisted, so its memory update happens here on replay instead;
            // this is the point where the durable fact actually lands.
            let broadcast = session_updated_broadcast(&memory);
            (state, memory, vec![broadcast])
        }

        SessionEvent::AgentDetached { actor_id, .. } => {
            if let Some(m) = memory.members.get_mut(&actor_id) {
                m.detached   = true;
                m.connection = None;
            }
            let broadcast = session_updated_broadcast(&memory);
            (state, memory, vec![broadcast])
        }

        // ── Cap algebra ───────────────────────────────────────────────────────

        SessionEvent::CapDelegated { cap_id, parent_cap, actor_id, permissions, epoch, stratum, issued_at } => {
            // Maintain inverted children index before inserting the record.
            if let Some(ref parent_id) = parent_cap {
                memory.cap_children
                    .entry(parent_id.clone())
                    .or_default()
                    .push(cap_id.clone());
            }
            memory.caps.insert(cap_id.clone(), CapRecord {
                cap_id, actor_id, parent_cap, permissions, epoch, stratum, issued_at, revoked: false,
            });
            (state, memory, vec![])
        }

        SessionEvent::CapRevoked { cap_id, strategy, .. } => {
            match strategy.as_str() {
                "subtree" => {
                    // O(subtree_size) via inverted children index.
                    for id in memory.cap_subtree(&cap_id) {
                        if let Some(c) = memory.caps.get_mut(&id) { c.revoked = true; }
                    }
                }
                _ => {
                    if let Some(c) = memory.caps.get_mut(&cap_id) { c.revoked = true; }
                }
            }
            (state, memory, vec![])
        }

        SessionEvent::EpochAdvanced { new_epoch, drain_deadline_ms, fenced_actor_ids, advanced_at, .. } => {
            memory.epoch = new_epoch;
            for cap in memory.caps.values_mut() {
                if cap.epoch < new_epoch { cap.revoked = true; }
            }
            if fenced_actor_ids.is_empty() {
                (state, memory, vec![])
            } else {
                let deadline = advanced_at
                    + chrono::Duration::milliseconds(drain_deadline_ms as i64);
                (SessionState::Draining { drain_deadline: deadline, drain_seq: seq }, memory, vec![])
            }
        }

        // ── Approval algebra ──────────────────────────────────────────────────

        SessionEvent::ApprovalRequested { approval_id, actor_id, tool, expires_at, requested_at, .. } => {
            memory.approvals.insert(approval_id.clone(), ApprovalRecord {
                approval_id,
                actor_id,
                tool,
                status:       ApprovalStatus::Pending,
                requested_at,
                expires_at,
                votes:        BTreeMap::new(),
            });
            (state, memory, vec![])
        }

        SessionEvent::ApprovalClaimed { approval_id, .. } => {
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                if !a.status.is_terminal() { a.status = ApprovalStatus::Claimed; }
            }
            (state, memory, vec![])
        }

        SessionEvent::ApprovalVoted { approval_id, voter_id, decision, .. } => {
            // Store the vote so policy evaluation in subsequent live events sees it.
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                a.votes.insert(voter_id, decision);
            }
            (state, memory, vec![])
        }

        SessionEvent::ApprovalGranted { approval_id, .. } => {
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                a.status = ApprovalStatus::Granted;
            }
            let timer_id = format!("approval:{approval_id}");
            memory.timers.remove(&timer_id);

            // Lift any bundle gates tied to this approval and re-deliver.
            // Collect first to avoid borrowing memory mutably while iterating.
            let gated: Vec<(String, Option<SagaBundle>)> = memory.gated_bundles
                .iter()
                .filter(|(_, g)| {
                    matches!(&g.gate_kind, GateKind::Approval { approval_id: aid } if aid == &approval_id)
                })
                .map(|(id, g)| (id.clone(), g.bundle.clone()))
                .collect();

            let mut effects = vec![Effect::CancelTimer { id: timer_id }];
            for (bundle_id, maybe_bundle) in gated {
                memory.gated_bundles.remove(&bundle_id);
                match maybe_bundle {
                    Some(bundle) => effects.push(Effect::BundleDeliver(bundle)),
                    None => tracing::warn!(
                        session_id = %memory.session_id,
                        %bundle_id,
                        "approval gate lifted but bundle unavailable (cold replay after restart)",
                    ),
                }
            }
            (state, memory, effects)
        }

        SessionEvent::ApprovalDenied { approval_id, .. } => {
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                a.status = ApprovalStatus::Denied;
            }
            let timer_id = format!("approval:{approval_id}");
            memory.timers.remove(&timer_id);
            (state, memory, vec![Effect::CancelTimer { id: timer_id }])
        }

        SessionEvent::ApprovalExpired { approval_id, .. } => {
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                if !a.status.is_terminal() { a.status = ApprovalStatus::Expired; }
            }
            let timer_id = format!("approval:{approval_id}");
            memory.timers.remove(&timer_id);
            (state, memory, vec![Effect::CancelTimer { id: timer_id }])
        }

        SessionEvent::ApprovalInterrupted { approval_id, .. } => {
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                if !a.status.is_terminal() { a.status = ApprovalStatus::Interrupted; }
            }
            let timer_id = format!("approval:{approval_id}");
            memory.timers.remove(&timer_id);
            (state, memory, vec![Effect::CancelTimer { id: timer_id }])
        }

        SessionEvent::ApprovalCancelled { approval_id, .. } => {
            // Reuses ApprovalStatus::Expired — matches ws.rs::handle_approval_cancel,
            // whose DB write also reuses "Expired" rather than a distinct status.
            if let Some(a) = memory.approvals.get_mut(&approval_id) {
                if !a.status.is_terminal() { a.status = ApprovalStatus::Expired; }
            }
            let timer_id = format!("approval:{approval_id}");
            memory.timers.remove(&timer_id);
            (state, memory, vec![Effect::CancelTimer { id: timer_id }])
        }

        // Delegation/dispute don't change who can resolve an approval or its
        // status — EventLog only, matching ws.rs's own apply_event (its
        // fallthrough comment names both explicitly).
        SessionEvent::ApprovalDelegated { .. } => (state, memory, vec![]),
        SessionEvent::ApprovalDisputed  { .. } => (state, memory, vec![]),
        // Cross-session delegation state lives in Postgres (cross_session_
        // delegations table), not SessionMemory — it must survive
        // independent of any one process's in-memory state, same reasoning
        // as session_remotes' watermark. EventLog only here too.
        SessionEvent::CrossSessionDelegationRequested { .. } => (state, memory, vec![]),
        SessionEvent::CrossSessionDelegationReceived  { .. } => (state, memory, vec![]),
        SessionEvent::CrossSessionDelegationResolved  { .. } => (state, memory, vec![]),

        // ── Effect algebra ────────────────────────────────────────────────────

        SessionEvent::EffectProposed { proposal_id, receipt_id, effect_type, expected_hash_before, claimed_hash_after, .. } => {
            memory.proposals.insert(proposal_id.clone(), ProposalRecord {
                proposal_id,
                effect_type,
                receipt_id,
                h_before:  expected_hash_before,
                h_after:   claimed_hash_after,
                committed: false,
                diverged:  false,
            });
            (state, memory, vec![])
        }

        SessionEvent::EffectScouted { .. } => {
            // Scout manifests are stored in the approvals DB table (via the PATCH /scout endpoint).
            // Nothing to update in memory-only state for now.
            (state, memory, vec![])
        }

        SessionEvent::EffectAttested { .. } => {
            // Ring-1 attestations are stored in the file_write_attestations DB table.
            // Phase 5: track hash mismatches in memory for alerting.
            (state, memory, vec![])
        }

        SessionEvent::EffectCommitted { proposal_id, h_before, h_after, .. } => {
            if let Some(p) = memory.proposals.get_mut(&proposal_id) {
                p.committed = true;
                p.h_before  = Some(h_before);
                p.h_after   = Some(h_after);
            }
            (state, memory, vec![])
        }

        SessionEvent::EffectDiverged { approval_id, .. } => {
            // Mark the matching proposal as diverged.  The approval_id ↔ proposal_id
            // link is tracked at the DB layer; in memory we mark by approval_id match.
            for p in memory.proposals.values_mut() {
                // In Phase 2 we don't track the approval→proposal link in memory yet.
                // Phase 5 will store this explicitly.
                let _ = &approval_id;
                p.diverged = true;
                break; // defensive: only mark one to avoid cascading
            }
            (state, memory, vec![])
        }

        // ── Content sub-shape of the effect algebra ───────────────────────────
        //
        // Mirrors ws.rs's own `apply_event` snapshot projector exactly —
        // same fields, same "name-only" ArtifactUpdated projection, same
        // MessagePosted no-op (EventLog only, not snapshot-visible).

        SessionEvent::MessagePosted { .. } => (state, memory, vec![]),

        SessionEvent::ContextEntryAdded { entry_id, actor_id, kind, content, added_at } => {
            memory.context.insert(entry_id.clone(), protocol::types::ContextEntry {
                id: entry_id,
                kind,
                content,
                actor_id,
                timestamp: added_at,
                resolved: false,
                resolved_by: None,
                resolution_note: None,
                seq,
            });
            (state, memory, vec![])
        }

        SessionEvent::ContextEntryResolved { entry_id, resolved_by, note, .. } => {
            if let Some(e) = memory.context.get_mut(&entry_id) {
                e.resolved = true;
                e.resolved_by = Some(resolved_by);
                e.resolution_note = note;
            }
            (state, memory, vec![])
        }

        SessionEvent::ArtifactCreated { artifact_id, name, artifact_type, .. } => {
            memory.artifacts.entry(artifact_id.clone()).or_insert_with(|| protocol::types::ArtifactSummary {
                id: artifact_id,
                name,
                artifact_type: artifact_type.unwrap_or_else(|| "other".to_string()),
            });
            (state, memory, vec![])
        }

        SessionEvent::ArtifactUpdated { artifact_id, name, .. } => {
            if let Some(a) = memory.artifacts.get_mut(&artifact_id) {
                a.name = name;
            }
            (state, memory, vec![])
        }

        SessionEvent::ArtifactDeleted { artifact_id, .. } => {
            memory.artifacts.remove(&artifact_id);
            (state, memory, vec![])
        }

        // ── Projection algebra ────────────────────────────────────────────────

        SessionEvent::SnapshotCreated { snapshot_seq, .. } => {
            memory.snapshot_seq = snapshot_seq;
            (state, memory, vec![])
        }

        SessionEvent::SnapshotInvalidated { .. } => {
            memory.snapshot_seq = 0;
            (state, memory, vec![])
        }

        // ── Saga algebra ──────────────────────────────────────────────────────

        SessionEvent::SagaBegun { saga_id, saga_type, steps, begun_at, metadata } => {
            // Insert a fresh SagaRecord in Running state.  The next replayed
            // SagaStepSent event will move it to Waiting.
            memory.sagas.insert(saga_id.clone(), SagaRecord {
                saga_id,
                saga_type,
                steps,
                status:   SagaStatus::Running,
                begun_at,
                metadata,
            });
            (state, memory, vec![])
        }

        SessionEvent::SagaStepSent { saga_id, step_idx, .. } => {
            if let Some(saga) = memory.sagas.get_mut(&saga_id) {
                let timer_id = format!("saga:{saga_id}:{step_idx}");
                saga.status = SagaStatus::Waiting { step_idx, timer_id };
            }
            (state, memory, vec![])
        }

        SessionEvent::SagaStepAcked { saga_id, step_idx, outcome, .. } => {
            let timer_id = format!("saga:{saga_id}:{step_idx}");
            if let Some(saga) = memory.sagas.get_mut(&saga_id) {
                // Only advance if the saga is actually waiting on this step.
                if matches!(&saga.status, SagaStatus::Waiting { step_idx: i, .. } if *i == step_idx) {
                    saga.status = match outcome {
                        SagaOutcome::Committed => SagaStatus::Running,
                        SagaOutcome::Rejected { reason } =>
                            SagaStatus::Compensating { from_step: step_idx, reason },
                    };
                }
            }
            // Cancel the per-step timer (idempotent if already fired).
            (state, memory, vec![Effect::CancelTimer { id: timer_id }])
        }

        SessionEvent::SagaCompensated { .. } => {
            // Audit record only.  The `Compensating` status persists until
            // the subsequent `SagaTerminated` event moves it to `Aborted`.
            (state, memory, vec![])
        }

        SessionEvent::SagaTerminated { saga_id, outcome, .. } => {
            if let Some(saga) = memory.sagas.get_mut(&saga_id) {
                saga.status = match outcome {
                    SagaTermination::Completed         => SagaStatus::Completed,
                    SagaTermination::Aborted { reason } => SagaStatus::Aborted { reason },
                };
            }
            (state, memory, vec![])
        }

        // ── Policy algebra (RODS / FMOA adapter intercept) ────────────────────

        SessionEvent::BundleAnnotated { .. } => {
            // Annotations are read from the event log for audit / tracing;
            // no snapshot-level memory state is maintained.
            (state, memory, vec![])
        }

        SessionEvent::BundleReshaped { .. } => {
            // Reshape decision is recorded for audit; delivery already occurred
            // via BundleDeliver in the same effect batch.
            (state, memory, vec![])
        }

        SessionEvent::BundleDeferred { bundle_id, defer_until_ms, .. } => {
            // Re-arm the defer timer using remaining wall-clock time.
            // If the deadline has already passed (cold replay after a long
            // outage), fire immediately with a 1 ms minimum.
            let now_ms    = Utc::now().timestamp_millis() as u64;
            let remaining = if now_ms >= defer_until_ms { 1 } else { defer_until_ms - now_ms };
            // Record the gate with no bundle — bundle is unavailable after a
            // server restart since the in-memory reflector is cleared.
            // The timer fires and logs a warning if the bundle is still None.
            memory.gated_bundles.entry(bundle_id.clone()).or_insert_with(|| GatedBundle {
                gate_kind:        GateKind::Deferred { until_ms: defer_until_ms },
                bundle:           None,
                reflector_cursor: None,
            });
            (state, memory, vec![Effect::SetTimer {
                id:          format!("bundle_defer:{bundle_id}"),
                duration_ms: remaining,
            }])
        }

        SessionEvent::BundleRejected { bundle_id, .. } => {
            memory.gated_bundles.remove(&bundle_id);
            (state, memory, vec![])
        }

        SessionEvent::BundleApprovalGated { bundle_id, approval_id, .. } => {
            // Record the gate.  Bundle is unavailable after cold replay — the
            // approval handler will log a warning if bundle is None when the
            // approval resolves.
            memory.gated_bundles.entry(bundle_id.clone()).or_insert_with(|| GatedBundle {
                gate_kind:        GateKind::Approval { approval_id },
                bundle:           None,
                reflector_cursor: None,
            });
            (state, memory, vec![])
        }

        SessionEvent::PolicySet { target, constraint, .. } => {
            memory.policies.insert(target, constraint);
            (state, memory, vec![])
        }
    }
}

// ── Live path ─────────────────────────────────────────────────────────────────

fn apply_live(
    state:  SessionState,
    memory: SessionMemory,
    event:  LiveEvent,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    match event {
        LiveEvent::ActorConnected { actor_id, connection_id } =>
            live_actor_connected(state, memory, actor_id, connection_id),

        LiveEvent::ActorDisconnected { actor_id, connection_id, .. } =>
            live_actor_disconnected(state, memory, actor_id, connection_id),

        LiveEvent::ActorReconnected { actor_id, new_connection_id } =>
            live_actor_reconnected(state, memory, actor_id, new_connection_id),

        LiveEvent::VoteCast { approval_id, voter_id, decision } =>
            live_vote_cast(state, memory, approval_id, voter_id, decision),

        LiveEvent::OwnershipTransfer { from, to } =>
            live_ownership_transfer(state, memory, from, to),

        LiveEvent::ApprovalClaim { approval_id, actor_id } =>
            live_approval_claim(state, memory, approval_id, actor_id),

        LiveEvent::ApprovalCancel { approval_id, actor_id } =>
            live_approval_cancel(state, memory, approval_id, actor_id),

        LiveEvent::ApprovalDelegate { approval_id, from, to } =>
            live_approval_delegate(state, memory, approval_id, from, to),

        LiveEvent::ApprovalDispute { approval_id, actor_id, reason } =>
            live_approval_dispute(state, memory, approval_id, actor_id, reason),

        LiveEvent::CrossSessionDelegate { saga_id, approval_id, target_session_id, requested_by, arguments } =>
            live_cross_session_delegate(state, memory, saga_id, approval_id, target_session_id, requested_by, arguments),

        LiveEvent::MessagePost { actor_id, content } =>
            live_message_post(state, memory, actor_id, content),

        LiveEvent::ContextAdd { entry_id, actor_id, kind, content } =>
            live_context_add(state, memory, entry_id, actor_id, kind, content),

        LiveEvent::ContextResolve { entry_id, resolved_by, note } =>
            live_context_resolve(state, memory, entry_id, resolved_by, note),

        LiveEvent::ArtifactCreate { artifact_id, actor_id, name, artifact_type } =>
            live_artifact_create(state, memory, artifact_id, actor_id, name, artifact_type),

        LiveEvent::ArtifactUpdate { artifact_id, actor_id, name, artifact_type } =>
            live_artifact_update(state, memory, artifact_id, actor_id, name, artifact_type),

        LiveEvent::ArtifactDelete { artifact_id, actor_id, name, artifact_type } =>
            live_artifact_delete(state, memory, artifact_id, actor_id, name, artifact_type),

        LiveEvent::TimerFired { id } =>
            live_timer_fired(state, memory, id),

        LiveEvent::AdminPause { by, reason } =>
            live_admin_pause(state, memory, by, reason),

        LiveEvent::AdminResume { by } =>
            live_admin_resume(state, memory, by),

        LiveEvent::AdminArchive { by } =>
            live_admin_archive(state, memory, by),

        LiveEvent::SidecarAttach { actor_id, cap_id } =>
            live_sidecar_attach(state, memory, actor_id, cap_id),

        LiveEvent::SidecarDetach { actor_id, reason } =>
            live_sidecar_detach(state, memory, actor_id, reason),

        LiveEvent::ApprovalCreate { approval_id, actor_id, tool, args, expires_ms } =>
            live_approval_create(state, memory, approval_id, actor_id, tool, args, expires_ms),

        LiveEvent::ForwardedMessage { from_session, payload } =>
            live_forwarded_message(state, memory, from_session, payload),

        LiveEvent::SagaBegin { saga_id, saga_type, steps, metadata } =>
            live_saga_begin(state, memory, saga_id, saga_type, steps, metadata),

        LiveEvent::SagaAck { saga_id, step_idx, outcome } =>
            live_saga_ack(state, memory, saga_id, step_idx, outcome),

        LiveEvent::BundleIntercepted { bundle, interceptor_cap_id, reflector_cursor } =>
            live_bundle_intercepted(state, memory, bundle, interceptor_cap_id, reflector_cursor),

        LiveEvent::BundleReceived { bundle } =>
            live_bundle_received(state, memory, bundle),
    }
}

// ── Live handlers ─────────────────────────────────────────────────────────────

fn live_actor_connected(
    state:         SessionState,
    mut memory:    SessionMemory,
    actor_id:      String,
    connection_id: String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if state.is_draining() {
        let is_fenced = memory.caps.values()
            .any(|c| c.actor_id == actor_id && c.revoked && c.epoch < memory.epoch);
        if is_fenced {
            return (state, memory, vec![Effect::CloseConnection {
                actor_id,
                code:   4003,
                reason: "epoch fenced — obtain a new cap before reconnecting".into(),
            }]);
        }
    }
    if let Some(m) = memory.members.get_mut(&actor_id) {
        m.connection = Some(connection_id);
        m.detached   = false;
    }
    let broadcast = session_updated_broadcast(&memory);
    (state, memory, vec![broadcast])
}

fn live_actor_disconnected(
    state:          SessionState,
    mut memory:     SessionMemory,
    actor_id:       String,
    _connection_id: String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if let Some(m) = memory.members.get_mut(&actor_id) {
        m.connection = None;
    }

    let to_interrupt: Vec<String> = memory.approvals.iter()
        .filter(|(_, a)| {
            a.actor_id == actor_id
                && matches!(a.status, ApprovalStatus::Pending | ApprovalStatus::Claimed)
        })
        .map(|(id, _)| id.clone())
        .collect();

    let mut effects: Vec<Effect> = to_interrupt
        .into_iter()
        .map(|approval_id| Effect::Persist(SessionEvent::ApprovalInterrupted {
            approval_id,
            reason:         "agent disconnected".into(),
            interrupted_at: Utc::now(),
        }))
        .collect();

    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

fn live_actor_reconnected(
    state:             SessionState,
    mut memory:        SessionMemory,
    actor_id:          String,
    new_connection_id: String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if let Some(m) = memory.members.get_mut(&actor_id) {
        m.connection = Some(new_connection_id);
        m.detached   = false;
    }
    let broadcast = session_updated_broadcast(&memory);
    (state, memory, vec![broadcast])
}

fn live_vote_cast(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    voter_id:    String,
    decision:    VoteDecision,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    // Gate: voter must have approval rights and not be detached.
    let can_vote = memory.members.get(&voter_id)
        .map(|m| m.can_approve() && !m.detached)
        .unwrap_or(false);
    if !can_vote { return (state, memory, vec![]); }

    // Gate: approval must be in a voteable state.
    let is_pending = memory.approvals.get(&approval_id)
        .map(|a| matches!(a.status, ApprovalStatus::Pending | ApprovalStatus::Claimed))
        .unwrap_or(false);
    if !is_pending { return (state, memory, vec![]); }

    let decision_str = match &decision {
        VoteDecision::Approve => "approve",
        VoteDecision::Deny    => "deny",
    };

    // Build the prospective vote set including this new vote.
    let mut projected_votes = memory.approvals[&approval_id].votes.clone();
    projected_votes.insert(voter_id.clone(), decision_str.into());

    let resolution = evaluate_policy(
        &memory.session_policy,
        &projected_votes,
        memory.eligible_approvers,
    );

    let mut effects = vec![
        Effect::Persist(SessionEvent::ApprovalVoted {
            approval_id: approval_id.clone(),
            voter_id,
            decision:    decision_str.into(),
            voted_at:    Utc::now(),
        }),
    ];

    match resolution {
        PolicyOutcome::Grant(by) => {
            let timer_id = format!("approval:{approval_id}");
            effects.push(Effect::Persist(SessionEvent::ApprovalGranted {
                approval_id,
                resolved_by: by,
                granted_at:  Utc::now(),
            }));
            effects.push(Effect::CancelTimer { id: timer_id });
        }
        PolicyOutcome::Deny(by) => {
            let timer_id = format!("approval:{approval_id}");
            effects.push(Effect::Persist(SessionEvent::ApprovalDenied {
                approval_id,
                resolved_by: by,
                reason:      None,
                denied_at:   Utc::now(),
            }));
            effects.push(Effect::CancelTimer { id: timer_id });
        }
        PolicyOutcome::Pending => { /* more votes needed */ }
    }

    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

fn live_ownership_transfer(
    state:  SessionState,
    memory: SessionMemory,
    from:   String,
    to:     String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::OwnershipTransferred {
            from_actor:     from,
            to_actor:       to,
            transferred_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_approval_claim(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    actor_id:    String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    // CAS: only claim if currently Pending — mirrors the DB-level
    // claim_if_pending_in_tx this feed runs alongside (ws.rs remains the
    // authoritative writer; see the LiveEvent::ApprovalClaim doc comment).
    let is_pending = memory.approvals.get(&approval_id)
        .map(|a| matches!(a.status, ApprovalStatus::Pending))
        .unwrap_or(false);
    if !is_pending { return (state, memory, vec![]); }

    let effects = vec![
        Effect::Persist(SessionEvent::ApprovalClaimed {
            approval_id,
            claimed_by: actor_id,
            claimed_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_approval_cancel(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    actor_id:    String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ApprovalCancelled {
            approval_id, cancelled_by: actor_id, cancelled_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_approval_delegate(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    from:        String,
    to:          String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ApprovalDelegated {
            approval_id, from, to, delegated_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_approval_dispute(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    actor_id:    String,
    reason:      String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ApprovalDisputed {
            approval_id, disputed_by: actor_id, reason, disputed_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_message_post(
    state:    SessionState,
    memory:   SessionMemory,
    actor_id: String,
    content:  String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::MessagePosted { actor_id, content, posted_at: Utc::now() }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_context_add(
    state:    SessionState,
    memory:   SessionMemory,
    entry_id: String,
    actor_id: String,
    kind:     protocol::types::ContextEntryKind,
    content:  String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ContextEntryAdded {
            entry_id, actor_id, kind, content, added_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_context_resolve(
    state:       SessionState,
    memory:      SessionMemory,
    entry_id:    String,
    resolved_by: String,
    note:        Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ContextEntryResolved {
            entry_id, resolved_by, note, resolved_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_artifact_create(
    state:         SessionState,
    memory:        SessionMemory,
    artifact_id:   String,
    actor_id:      String,
    name:          String,
    artifact_type: Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ArtifactCreated {
            artifact_id, actor_id, name, artifact_type, created_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_artifact_update(
    state:         SessionState,
    memory:        SessionMemory,
    artifact_id:   String,
    actor_id:      String,
    name:          String,
    artifact_type: Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ArtifactUpdated {
            artifact_id, actor_id, name, artifact_type, updated_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_artifact_delete(
    state:         SessionState,
    memory:        SessionMemory,
    artifact_id:   String,
    actor_id:      String,
    name:          String,
    artifact_type: Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let effects = vec![
        Effect::Persist(SessionEvent::ArtifactDeleted {
            artifact_id, actor_id, name, artifact_type, deleted_at: Utc::now(),
        }),
        session_updated_broadcast(&memory),
    ];
    (state, memory, effects)
}

fn live_timer_fired(
    state:      SessionState,
    mut memory: SessionMemory,
    id:         String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    memory.timers.remove(&id);

    if let Some(approval_id) = id.strip_prefix("approval:") {
        let still_open = memory.approvals.get(approval_id)
            .map(|a| !a.status.is_terminal())
            .unwrap_or(false);
        if still_open {
            let broadcast = session_updated_broadcast(&memory);
            return (state, memory, vec![
                Effect::Persist(SessionEvent::ApprovalExpired {
                    approval_id: approval_id.into(),
                    expired_at:  Utc::now(),
                }),
                broadcast,
            ]);
        }
    }

    if id.starts_with("drain:") {
        if let SessionState::Draining { .. } = state {
            let broadcast = session_updated_broadcast(&memory);
            return (SessionState::Active, memory, vec![broadcast]);
        }
    }

    // Deferred bundle re-delivery: timer ID format is "bundle_defer:<bundle_id>".
    if let Some(bundle_id) = id.strip_prefix("bundle_defer:") {
        if let Some(gate) = memory.gated_bundles.remove(bundle_id) {
            match gate.bundle {
                Some(bundle) => {
                    let now_ms = Utc::now().timestamp_millis() as u64;
                    if now_ms <= bundle.ttl_ms {
                        return (state, memory, vec![Effect::BundleDeliver(bundle)]);
                    } else {
                        tracing::warn!(
                            session_id = %memory.session_id,
                            %bundle_id,
                            "bundle defer: bundle expired before deferred delivery",
                        );
                    }
                }
                None => tracing::warn!(
                    session_id = %memory.session_id,
                    %bundle_id,
                    "bundle defer: timer fired but bundle unavailable (cold replay after restart)",
                ),
            }
        }
        return (state, memory, vec![]);
    }

    // Saga step timeout: timer ID format is "saga:{saga_id}:{step_idx}".
    // Use rsplitn so the saga_id (which may itself contain colons) is preserved.
    if let Some(rest) = id.strip_prefix("saga:") {
        let mut parts = rest.rsplitn(2, ':');
        if let (Some(step_str), Some(saga_id)) = (parts.next(), parts.next()) {
            if let Ok(step_idx) = step_str.parse::<usize>() {
                let is_waiting = memory.sagas.get(saga_id)
                    .map(|s| matches!(&s.status,
                        SagaStatus::Waiting { step_idx: i, .. } if *i == step_idx))
                    .unwrap_or(false);
                if is_waiting {
                    let reason = format!("step {step_idx} timed out");
                    return live_saga_ack(
                        state, memory,
                        saga_id.to_string(),
                        step_idx,
                        SagaOutcome::Rejected { reason },
                    );
                }
            }
        }
    }

    (state, memory, vec![])
}

fn live_admin_pause(
    state:  SessionState,
    memory: SessionMemory,
    by:     String,
    reason: Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if !state.is_active() { return (state, memory, vec![]); }
    let broadcast = session_updated_broadcast(&memory);
    (state, memory, vec![
        Effect::Persist(SessionEvent::SessionPaused {
            paused_by: by,
            reason,
            paused_at: Utc::now(),
        }),
        broadcast,
    ])
}

fn live_admin_resume(
    state:  SessionState,
    memory: SessionMemory,
    by:     String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if !matches!(state, SessionState::Suspended { .. }) { return (state, memory, vec![]); }
    let broadcast = session_updated_broadcast(&memory);
    (state, memory, vec![
        Effect::Persist(SessionEvent::SessionResumed {
            resumed_by: by,
            resumed_at: Utc::now(),
        }),
        broadcast,
    ])
}

fn live_admin_archive(
    state:  SessionState,
    memory: SessionMemory,
    by:     String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let mut effects: Vec<Effect> = memory.timers.keys()
        .map(|id| Effect::CancelTimer { id: id.clone() })
        .collect();
    effects.push(Effect::Persist(SessionEvent::SessionArchived {
        archived_by: by,
        archived_at: Utc::now(),
    }));
    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

fn live_sidecar_attach(
    state:    SessionState,
    memory:   SessionMemory,
    actor_id: String,
    cap_id:   String,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if !memory.cap_is_active(&cap_id) {
        return (state, memory, vec![Effect::CloseConnection {
            actor_id, code: 4001, reason: "invalid or revoked capability".into(),
        }]);
    }
    if memory.caps.get(&cap_id).map(|c| c.actor_id != actor_id).unwrap_or(true) {
        return (state, memory, vec![Effect::CloseConnection {
            actor_id, code: 4002, reason: "cap actor_id mismatch".into(),
        }]);
    }
    (state, memory, vec![Effect::Persist(SessionEvent::AgentAttached {
        actor_id, cap_id, attached_at: Utc::now(),
    })])
}

fn live_sidecar_detach(
    state:    SessionState,
    memory:   SessionMemory,
    actor_id: String,
    reason:   Option<String>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    (state, memory, vec![Effect::Persist(SessionEvent::AgentDetached {
        actor_id, reason, detached_at: Utc::now(),
    })])
}

fn live_approval_create(
    state:       SessionState,
    memory:      SessionMemory,
    approval_id: String,
    actor_id:    String,
    tool:        String,
    args:        serde_json::Value,
    expires_ms:  Option<u64>,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    // The requesting actor must be an active member of the session.
    let actor_present = memory.members.get(&actor_id)
        .map(|m| !m.detached)
        .unwrap_or(false);
    if !actor_present {
        tracing::warn!(
            session_id = %memory.session_id, actor_id = %actor_id,
            "ApprovalCreate rejected: actor not a session member"
        );
        return (state, memory, vec![]);
    }

    let expires_at = expires_ms.map(|ms| Utc::now() + chrono::Duration::milliseconds(ms as i64));
    let mut effects = vec![
        Effect::Persist(SessionEvent::ApprovalRequested {
            approval_id: approval_id.clone(),
            actor_id,
            tool,
            arguments:    args,
            expires_at,
            requested_at: Utc::now(),
        }),
    ];

    // Arm per-approval expiry timer (replaces the 30 s sweeper for this session).
    if let Some(ms) = expires_ms {
        effects.push(Effect::SetTimer {
            id:          format!("approval:{approval_id}"),
            duration_ms: ms,
        });
    }

    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

// ── Policy evaluation ─────────────────────────────────────────────────────────

/// Result of evaluating the approval policy against the current vote set.
enum PolicyOutcome {
    /// Threshold met — approval is granted.  Inner: the voter who tipped it.
    Grant(String),
    /// Threshold met for denial.
    Deny(String),
    /// More votes needed.
    Pending,
}

/// Evaluate the session's approval policy against a projected vote set.
///
/// `votes` is the complete vote set *after* the current vote is included.
/// Returns `None` when no resolution yet (e.g. contested under majority).
///
/// Contested state (majority policy, some approve + some deny, threshold not yet
/// met by either side) returns `Pending` — the approval stays open for more votes
/// or owner intervention.
fn evaluate_policy(
    policy:          &str,
    votes:           &BTreeMap<String, String>,
    eligible_count:  usize,
) -> PolicyOutcome {
    let approvals = votes.values().filter(|v| v.as_str() == "approve").count();
    let denials   = votes.values().filter(|v| v.as_str() == "deny").count();

    // Determine which voter (if any) was the deciding vote.
    // We use the last entry as an approximation (BTreeMap is sorted by key).
    let deciding = || votes.iter().next_back()
        .map(|(k, _)| k.clone())
        .unwrap_or_default();

    match policy {
        "single_vote" => {
            if approvals > 0 { PolicyOutcome::Grant(deciding()) }
            else if denials > 0 { PolicyOutcome::Deny(deciding()) }
            else { PolicyOutcome::Pending }
        }
        "majority" => {
            let threshold = eligible_count / 2 + 1;
            if approvals >= threshold { PolicyOutcome::Grant(deciding()) }
            else if denials >= threshold { PolicyOutcome::Deny(deciding()) }
            else { PolicyOutcome::Pending }
        }
        "unanimous" => {
            if eligible_count > 0 && approvals == eligible_count {
                PolicyOutcome::Grant(deciding())
            } else if denials > 0 {
                PolicyOutcome::Deny(deciding())
            } else {
                PolicyOutcome::Pending
            }
        }
        // Unknown policy slug → fall back to single_vote
        _ => {
            if approvals > 0 { PolicyOutcome::Grant(deciding()) }
            else { PolicyOutcome::Pending }
        }
    }
}

// ── Inter-session routing handler ────────────────────────────────────────────

/// Handle a message forwarded from another session node via `Effect::Forward`.
///
/// This is the inbound DOF coupling: Session A sent a `Forward { to_session: self }`;
/// the runtime delivered it as `ForwardedMessage { from_session: A }`.
///
/// Currently a no-op.  Future work: route on payload `"type"` field to
/// participant-side handlers for saga step acknowledgement, ownership transfer
/// negotiation, etc.  Participant sessions will in turn emit
/// `Effect::Forward { to_session: from_session, payload: ack }` to return an
/// outcome to the coordinator.
fn live_forwarded_message(
    state:         SessionState,
    memory:        SessionMemory,
    from_session:  String,
    _payload:      serde_json::Value,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    tracing::debug!(
        session_id = %memory.session_id,
        %from_session,
        "session machine: ForwardedMessage received (participant routing not yet wired)",
    );
    (state, memory, vec![])
}

// ── Saga live handlers ────────────────────────────────────────────────────────

/// Handle a typed `SagaBundle` delivered from the reflector.
///
/// # Authority model
///
/// Cap validation is the *first* thing we do here, before any state transition:
///
/// - `BundleKind::Ack { cap_id, .. }` — the participant must hold a valid,
///   non-revoked cap to send an ack.  Invalid → drop, warn, no effect.
/// - `BundleKind::Step` / `Compensation` — TTL is re-validated at delivery
///   time (the reflector pre-filters, but clock skew is possible).  Expired
///   bundles are silently dropped; the coordinator's step-timeout timer will
///   fire and self-heal.
///
/// After authority is established, dispatch to the appropriate saga handler:
///
/// - `Ack` → `live_saga_ack` (the coordinator path).
/// - `Step` / `Compensation` → not yet fully wired; emits a diagnostic for now.
fn live_bundle_received(
    state:  SessionState,
    memory: SessionMemory,
    bundle: SagaBundle,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    // TTL guard — always check first.
    let now_ms = Utc::now().timestamp_millis() as u64;
    if now_ms > bundle.ttl_ms {
        tracing::warn!(
            session_id = %memory.session_id,
            bundle_id  = %bundle.bundle_id,
            saga_id    = %bundle.saga_id,
            "bundle relay: dropping expired bundle (TTL {}ms, now {}ms)",
            bundle.ttl_ms, now_ms,
        );
        return (state, memory, vec![]);
    }

    match bundle.kind {
        // ── Ack: participant → coordinator ────────────────────────────────────
        BundleKind::Ack { ref outcome, ref cap_id } => {
            // Cap validation: the cap must exist and must not be revoked.
            let cap_valid = memory.caps.get(cap_id)
                .map(|c| !c.revoked)
                .unwrap_or(false);
            if !cap_valid {
                tracing::warn!(
                    session_id = %memory.session_id,
                    bundle_id  = %bundle.bundle_id,
                    %cap_id,
                    "bundle relay: dropping Ack — cap missing or revoked",
                );
                return (state, memory, vec![]);
            }
            // Authority established — delegate to the saga state machine.
            live_saga_ack(state, memory, bundle.saga_id, bundle.step_idx, outcome.clone())
        }

        // ── Step: coordinator → participant ───────────────────────────────────
        BundleKind::Step { ref message, .. } => {
            if message.get("kind").and_then(|k| k.as_str()) == Some("cross_session_delegation") {
                let source_approval_id = message.get("approval_id")
                    .and_then(|v| v.as_str()).unwrap_or_default().to_string();
                let arguments = message.get("arguments").cloned().unwrap_or(serde_json::Value::Null);
                let effects = vec![
                    // target_approval_id is always None here — see the event's
                    // own doc comment for why (pure fn, can't do the async
                    // DB insert; session_task.rs does that and records the
                    // real mapping in cross_session_delegations, not here).
                    Effect::Persist(SessionEvent::CrossSessionDelegationReceived {
                        saga_id:            bundle.saga_id.clone(),
                        source_session_id:  bundle.from_session.clone(),
                        source_approval_id,
                        arguments,
                        target_approval_id: None,
                        received_at:        Utc::now(),
                    }),
                    session_updated_broadcast(&memory),
                ];
                return (state, memory, effects);
            }
            // Other step kinds: full participant dispatch (routing to a
            // connected sidecar or human-gate approval) will be wired in a
            // follow-up once that's designed generically.
            tracing::debug!(
                session_id  = %memory.session_id,
                bundle_id   = %bundle.bundle_id,
                saga_id     = %bundle.saga_id,
                step_idx    = bundle.step_idx,
                from_session = %bundle.from_session,
                ?message,
                "bundle relay: Step received (participant dispatch not yet wired for this kind)",
            );
            (state, memory, vec![])
        }

        // ── Compensation: coordinator → participant ────────────────────────────
        BundleKind::Compensation { ref message } => {
            tracing::debug!(
                session_id  = %memory.session_id,
                bundle_id   = %bundle.bundle_id,
                saga_id     = %bundle.saga_id,
                step_idx    = bundle.step_idx,
                from_session = %bundle.from_session,
                ?message,
                "bundle relay: Compensation received (participant dispatch not yet wired)",
            );
            (state, memory, vec![])
        }
    }
}

/// Begin a saga: record the spec, dispatch step 0, arm its timeout timer.
fn live_saga_begin(
    state:     SessionState,
    memory:    SessionMemory,
    saga_id:   String,
    saga_type: String,
    steps:     Vec<SagaStepSpec>,
    metadata:  serde_json::Value,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    if steps.is_empty() {
        tracing::warn!(
            session_id = %memory.session_id,
            %saga_id,
            "SagaBegin ignored: no steps provided"
        );
        return (state, memory, vec![]);
    }

    let now  = Utc::now();
    let first = &steps[0];

    let mut effects = vec![
        // Persist the full spec so cold replay can reconstruct the SagaRecord.
        Effect::Persist(SessionEvent::SagaBegun {
            saga_id:   saga_id.clone(),
            saga_type: saga_type.clone(),
            steps:     steps.clone(),
            begun_at:  now,
            metadata,
        }),
        // Log that step 0 is now in-flight.
        Effect::Persist(SessionEvent::SagaStepSent {
            saga_id:     saga_id.clone(),
            step_idx:    0,
            participant: first.participant.clone(),
            sent_at:     now,
        }),
        // Deliver step 0 through the reflector (inter-session saga relay,
        // durable + replayable — see reflector.rs), not Effect::Forward
        // (direct mailbox delivery, no durable log, no offline-participant
        // replay) and not Effect::Send (intra-session actor plane, keyed by
        // actor_id — wrong plane entirely for a cross-session hop).
        Effect::Bundle(SagaBundle {
            bundle_id:    format!("{saga_id}:0:step"),
            saga_id:      saga_id.clone(),
            step_idx:     0,
            from_session: memory.session_id.clone(),
            to_session:   first.participant.clone(),
            kind:         BundleKind::Step {
                message:      first.message.clone(),
                compensation: first.compensation.clone(),
            },
            ttl_ms:       Utc::now().timestamp_millis() as u64 + first.timeout_ms,
        }),
        // Arm the step-0 expiry timer.
        Effect::SetTimer {
            id:          format!("saga:{saga_id}:0"),
            duration_ms: first.timeout_ms,
        },
    ];

    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

/// Begin a cross-session approval delegation: wraps `live_saga_begin` with a
/// single-step `SessionSaga::Custom` saga, prepending a
/// `CrossSessionDelegationRequested` marker so the EventLog records the
/// request distinctly from a generic saga begin. The step's `message`
/// carries the tagged payload `live_bundle_received`'s `Step` arm switches
/// on (`"kind": "cross_session_delegation"`).
fn live_cross_session_delegate(
    state:             SessionState,
    memory:            SessionMemory,
    saga_id:           String,
    approval_id:       String,
    target_session_id: String,
    requested_by:      String,
    arguments:         serde_json::Value,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let now = Utc::now();
    let step = SagaStepSpec {
        step_idx: 0,
        participant: target_session_id.clone(),
        message: serde_json::json!({
            "kind":        "cross_session_delegation",
            "approval_id": approval_id,
            "arguments":   arguments,
        }),
        compensation: serde_json::Value::Null,
        timeout_ms: 24 * 60 * 60 * 1000, // 24h — a human decision window, not a machine ack
    };

    let (state, memory, saga_effects) = live_saga_begin(
        state, memory, saga_id.clone(), "custom".to_string(), vec![step],
        serde_json::json!({ "kind": "cross_session_delegation", "approval_id": approval_id }),
    );

    let mut effects = vec![Effect::Persist(SessionEvent::CrossSessionDelegationRequested {
        saga_id, approval_id, target_session_id, requested_by, requested_at: now,
    })];
    effects.extend(saga_effects);
    (state, memory, effects)
}

/// Handle a participant ack (or a timer-induced synthetic rejection).
///
/// Dispatches through `SagaProtocol::reduce()` so the outcome is determined
/// by the typed protocol (approval policy, atomic transfer, or first-ack-wins)
/// rather than being hardcoded here.
///
/// - `ProtocolOutcome::Advance`   → persist ack, advance to next step or complete.
/// - `ProtocolOutcome::Abort`     → persist ack (raw participant outcome for audit),
///                                  dispatch compensations in reverse, terminate Aborted.
/// - `ProtocolOutcome::Pending`   → more acks required; no persistence yet.
///                                  Unreachable in the current single-participant model
///                                  but kept for forward-compatibility with multi-ack steps.
fn live_saga_ack(
    state:    SessionState,
    memory:   SessionMemory,
    saga_id:  String,
    step_idx: usize,
    outcome:  SagaOutcome,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    // Gate: saga must exist and be Waiting on exactly this step.
    let saga = match memory.sagas.get(&saga_id) {
        Some(s) => s,
        None    => return (state, memory, vec![]),
    };
    match &saga.status {
        SagaStatus::Waiting { step_idx: i, .. } if *i == step_idx => {}
        _ => return (state, memory, vec![]),
    }

    let now           = Utc::now();
    let steps         = saga.steps.clone();
    let metadata      = saga.metadata.clone();
    let timer_id      = format!("saga:{saga_id}:{step_idx}");
    // Cross-session delegation is tagged in SagaBegun's metadata (see
    // live_cross_session_delegate) rather than requiring its own SagaProtocol
    // impl — "custom" first-ack-wins already gives the right Advance/Abort
    // split (Committed → grant, Rejected → deny) for a single-step saga.
    let delegation_approval_id = (metadata.get("kind").and_then(|k| k.as_str()) == Some("cross_session_delegation"))
        .then(|| metadata.get("approval_id").and_then(|v| v.as_str()).unwrap_or_default().to_string());

    // Reconstruct the typed protocol discriminant and apply the reducer.
    // `reduce()` sees only the ack slice — never session internals.
    let protocol      = build_session_saga(saga);
    let proto_outcome = protocol.reduce(step_idx, std::slice::from_ref(&outcome));

    // Always cancel the per-step timer (idempotent if it already fired).
    let mut effects   = vec![Effect::CancelTimer { id: timer_id }];

    match proto_outcome {
        ProtocolOutcome::Pending => {
            // Threshold not yet met — accumulate and wait for more acks.
            // In the current single-participant model each step has exactly
            // one participant so this branch is unreachable; it exists for
            // forward-compatibility with future multi-ack steps.
            tracing::debug!(
                session_id = %memory.session_id,
                %saga_id,
                step_idx,
                "saga reducer returned Pending — accumulating acks",
            );
        }

        ProtocolOutcome::Advance => {
            effects.push(Effect::Persist(SessionEvent::SagaStepAcked {
                saga_id:  saga_id.clone(),
                step_idx,
                outcome:  SagaOutcome::Committed,
                acked_at: now,
            }));

            let next_idx = step_idx + 1;
            if next_idx < steps.len() {
                // Advance to the next step.
                let next = &steps[next_idx];
                effects.push(Effect::Persist(SessionEvent::SagaStepSent {
                    saga_id:     saga_id.clone(),
                    step_idx:    next_idx,
                    participant: next.participant.clone(),
                    sent_at:     now,
                }));
                // Through the reflector — see live_saga_begin's comment for why.
                effects.push(Effect::Bundle(SagaBundle {
                    bundle_id:    format!("{saga_id}:{next_idx}:step"),
                    saga_id:      saga_id.clone(),
                    step_idx:     next_idx,
                    from_session: memory.session_id.clone(),
                    to_session:   next.participant.clone(),
                    kind:         BundleKind::Step {
                        message:      next.message.clone(),
                        compensation: next.compensation.clone(),
                    },
                    ttl_ms:       Utc::now().timestamp_millis() as u64 + next.timeout_ms,
                }));
                effects.push(Effect::SetTimer {
                    id:          format!("saga:{saga_id}:{next_idx}"),
                    duration_ms: next.timeout_ms,
                });
            } else {
                // All steps committed — saga is done.
                effects.push(Effect::Persist(SessionEvent::SagaTerminated {
                    saga_id:       saga_id.clone(),
                    outcome:       SagaTermination::Completed,
                    terminated_at: now,
                }));
                if let Some(approval_id) = delegation_approval_id.clone() {
                    // Committed on a cross-session delegation's single step
                    // means B granted — resolve A's original approval to match.
                    // The real approval_requests DB write is server-side glue
                    // (session_task.rs), triggered by this same event kind,
                    // same reasoning as CrossSessionDelegationReceived above.
                    effects.push(Effect::Persist(SessionEvent::CrossSessionDelegationResolved {
                        saga_id: saga_id.clone(), approval_id, decision: "granted".to_string(), resolved_at: now,
                    }));
                }
            }
        }

        ProtocolOutcome::Abort { reason } => {
            // Persist the raw participant outcome for the audit trail.
            // The protocol-level reason (e.g. "denied by majority") goes into
            // SagaTerminated, while SagaStepAcked preserves what the participant
            // actually said.
            effects.push(Effect::Persist(SessionEvent::SagaStepAcked {
                saga_id:  saga_id.clone(),
                step_idx,
                outcome:  outcome.clone(),
                acked_at: now,
            }));

            // Dispatch compensations in strict reverse order for every step
            // that was already committed (steps 0 .. step_idx - 1).
            // The rejected step itself has no compensation (it never committed).
            for comp_idx in (0..step_idx).rev() {
                let comp = &steps[comp_idx];
                effects.push(Effect::Persist(SessionEvent::SagaCompensated {
                    saga_id:  saga_id.clone(),
                    step_idx: comp_idx,
                    sent_at:  now,
                }));
                // Backward path, also through the reflector. Reuses the
                // step's own declared timeout_ms as the compensation's TTL —
                // there's no separate compensation-specific timeout field on
                // SagaStepSpec, and the original step's window is a
                // reasonable default rather than inventing a fixed constant.
                effects.push(Effect::Bundle(SagaBundle {
                    bundle_id:    format!("{saga_id}:{comp_idx}:comp"),
                    saga_id:      saga_id.clone(),
                    step_idx:     comp_idx,
                    from_session: memory.session_id.clone(),
                    to_session:   comp.participant.clone(),
                    kind:         BundleKind::Compensation { message: comp.compensation.clone() },
                    ttl_ms:       Utc::now().timestamp_millis() as u64 + comp.timeout_ms,
                }));
            }

            effects.push(Effect::Persist(SessionEvent::SagaTerminated {
                saga_id:       saga_id.clone(),
                outcome:       SagaTermination::Aborted { reason },
                terminated_at: now,
            }));
            if let Some(approval_id) = delegation_approval_id.clone() {
                // Rejected on a cross-session delegation's single step means
                // B denied — resolve A's original approval to match.
                effects.push(Effect::Persist(SessionEvent::CrossSessionDelegationResolved {
                    saga_id: saga_id.clone(), approval_id, decision: "denied".to_string(), resolved_at: now,
                }));
            }
        }
    }

    effects.push(session_updated_broadcast(&memory));
    (state, memory, effects)
}

// ── Bundle intercept (FMOA adapter layer) ────────────────────────────────────

/// Handle a `SagaBundle` intercepted by the adapter before delivery.
///
/// Applies the `BundleDisposition` returned by `resolve_bundle_disposition` and
/// emits the appropriate policy `SessionEvent` for the audit log.  The saga
/// machine only sees `BundleReceived` after this layer has run.
///
/// # RODS framing
///
/// `live_bundle_intercepted` is the meta-level intercept point in the RORB
/// model.  Base-level sessions send `Effect::Bundle`; meta-level policy decides
/// whether / how the bundle reaches the servant.  The base level (saga machine)
/// remains unaware of any interception — meta governs base transparently.
fn live_bundle_intercepted(
    state:              SessionState,
    memory:             SessionMemory,
    bundle:             SagaBundle,
    interceptor_cap_id: String,
    reflector_cursor:   ReflectorCursor,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    let now_ms = Utc::now().timestamp_millis() as u64;
    if now_ms > bundle.ttl_ms {
        tracing::warn!(
            session_id = %memory.session_id,
            bundle_id  = %bundle.bundle_id,
            "bundle intercept: dropping expired bundle (TTL {}ms, now {}ms)",
            bundle.ttl_ms, now_ms,
        );
        return (state, memory, vec![]);
    }

    let disposition = resolve_bundle_disposition(&memory, &interceptor_cap_id, &bundle);
    apply_bundle_disposition(state, memory, bundle, interceptor_cap_id, reflector_cursor, disposition)
}

/// Determine the `BundleDisposition` for an inbound bundle.
///
/// Checks `memory.policies` with most-specific-target-wins precedence:
///   `BundleStep / BundleCompensation / BundleAck` > `All`
///
/// Returns `Forward` when no matching constraint is set.
fn resolve_bundle_disposition(
    memory:              &SessionMemory,
    _interceptor_cap_id: &str,
    bundle:              &SagaBundle,
) -> BundleDisposition {
    // Map BundleKind → specific PolicyTarget.
    let specific = match &bundle.kind {
        BundleKind::Step { .. }         => PolicyTarget::BundleStep,
        BundleKind::Compensation { .. } => PolicyTarget::BundleCompensation,
        BundleKind::Ack { .. }          => PolicyTarget::BundleAck,
    };

    // Most-specific match first, then fall back to All.
    let constraint = memory.policies
        .get(&specific)
        .or_else(|| memory.policies.get(&PolicyTarget::All));

    match constraint {
        None | Some(PolicyConstraint::Forward) => BundleDisposition::Forward,

        Some(PolicyConstraint::RequireApproval) => {
            // approval_id is derived from bundle_id so the sidecar can link
            // the BundleApprovalGated event to an ApprovalRequested it creates.
            BundleDisposition::ApprovalPending {
                approval_id: format!("gate:{}", bundle.bundle_id),
            }
        }

        Some(PolicyConstraint::Defer { duration_ms }) => {
            let until_ms = Utc::now().timestamp_millis() as u64 + duration_ms;
            BundleDisposition::Defer { until_ms }
        }

        Some(PolicyConstraint::Reject { reason }) => {
            BundleDisposition::Reject { reason: reason.clone() }
        }

        Some(PolicyConstraint::Annotate { metadata }) => {
            BundleDisposition::Annotate { metadata: metadata.clone() }
        }
    }
}

fn apply_bundle_disposition(
    state:              SessionState,
    mut memory:         SessionMemory,
    bundle:             SagaBundle,
    interceptor_cap_id: String,
    reflector_cursor:   ReflectorCursor,
    disposition:        BundleDisposition,
) -> (SessionState, SessionMemory, Vec<Effect>) {
    match disposition {
        BundleDisposition::Forward => {
            (state, memory, vec![Effect::BundleDeliver(bundle)])
        }

        BundleDisposition::Annotate { metadata } => {
            (state, memory, vec![
                Effect::Persist(SessionEvent::BundleAnnotated {
                    bundle_id: bundle.bundle_id.clone(),
                    metadata,
                }),
                Effect::BundleDeliver(bundle),
            ])
        }

        BundleDisposition::Reject { reason } => {
            tracing::info!(
                session_id         = %memory.session_id,
                bundle_id          = %bundle.bundle_id,
                %interceptor_cap_id,
                %reason,
                "bundle intercept: rejected by adapter",
            );
            (state, memory, vec![
                Effect::Persist(SessionEvent::BundleRejected {
                    bundle_id: bundle.bundle_id,
                    reason,
                    interceptor_cap_id,
                }),
            ])
        }

        BundleDisposition::Reshape { transport } => {
            let mut reshaped    = bundle.clone();
            reshaped.to_session = transport.to_session.clone();
            reshaped.ttl_ms     = transport.ttl_ms;
            (state, memory, vec![
                Effect::Persist(SessionEvent::BundleReshaped {
                    bundle_id: bundle.bundle_id,
                    transport,
                    reason:    "adapter reshape".into(),
                }),
                Effect::BundleDeliver(reshaped),
            ])
        }

        BundleDisposition::Defer { until_ms } => {
            let now_ms    = Utc::now().timestamp_millis() as u64;
            let remaining = if now_ms >= until_ms { 1 } else { until_ms - now_ms };
            let timer_id  = format!("bundle_defer:{}", bundle.bundle_id);
            memory.gated_bundles.insert(bundle.bundle_id.clone(), GatedBundle {
                gate_kind:        GateKind::Deferred { until_ms },
                bundle:           Some(bundle.clone()),
                reflector_cursor: Some(reflector_cursor),
            });
            (state, memory, vec![
                Effect::Persist(SessionEvent::BundleDeferred {
                    bundle_id:          bundle.bundle_id,
                    defer_until_ms:     until_ms,
                    interceptor_cap_id,
                }),
                Effect::SetTimer { id: timer_id, duration_ms: remaining },
            ])
        }

        BundleDisposition::ApprovalPending { approval_id } => {
            memory.gated_bundles.insert(bundle.bundle_id.clone(), GatedBundle {
                gate_kind:        GateKind::Approval { approval_id: approval_id.clone() },
                bundle:           Some(bundle.clone()),
                reflector_cursor: Some(reflector_cursor),
            });
            (state, memory, vec![
                Effect::Persist(SessionEvent::BundleApprovalGated {
                    bundle_id: bundle.bundle_id,
                    approval_id,
                    interceptor_cap_id,
                }),
            ])
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn session_updated_broadcast(memory: &SessionMemory) -> Effect {
    Effect::Broadcast {
        payload: serde_json::json!({
            "type":       "session_updated",
            "session_id": memory.session_id,
            "cursor":     memory.cursor,
        }),
    }
}

