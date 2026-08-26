//! `SessionEvent` → `WsPayload` translation.
//!
//! `crates/session` is deliberately protocol-agnostic (zero deps on
//! `protocol`/`sqlx`/etc. — see that crate's module doc). This is the seam
//! where a machine-persisted `SessionEvent` becomes the same properly-typed
//! broadcast the frontend's Timeline/activity feed already knows how to
//! render, instead of the machine's own generic `session_updated` ping
//! (`session_updated_broadcast()` in `transition.rs`).
//!
//! Only meant to be called from the REAL-persist path (`real_persist` in
//! `session_task.rs`) — shadow-persisted events already get a correctly-typed
//! broadcast from whichever `ws.rs`/`routes/` handler is still the
//! authoritative writer for them; adding one here too would just double the
//! (harmless but pointless) broadcast traffic for those.
//!
//! Returns `None` for `SessionEvent` kinds with no `WsPayload` equivalent yet
//! (`ApprovalInterrupted`, and the saga/bundle/policy sub-algebras) — callers
//! fall back to the generic ping, exactly matching today's behavior for those
//! kinds. Not a correctness gap to fix here: those kinds don't have a defined
//! wire shape to translate into.

use protocol::messages::{
    ApprovalDelegatedPayload, ApprovalDisputedPayload, ApprovalEventPayload, ArtifactPayload,
    ContextEntryAddedPayload, ContextEntryResolvedPayload, MessagePostedPayload,
    OwnershipTransferredPayload, SessionStatusPayload, WsPayload,
};
use protocol::types::MemberRole;
use session::SessionEvent;

pub fn to_ws_payload(session_id: &str, seq: i64, event: &SessionEvent) -> Option<WsPayload> {
    match event {
        SessionEvent::ApprovalExpired {
            approval_id,
            expired_at,
        } => Some(WsPayload::ApprovalTimedOut {
            session_id: session_id.to_string(),
            actor: "system".to_string(),
            timestamp: *expired_at,
            seq,
            payload: ApprovalEventPayload {
                approval_id: approval_id.clone(),
            },
        }),

        // AgentAttached/Detached have no dedicated WsPayload of their own —
        // ActorJoined/ActorDetached already cover "an actor (human or agent)
        // is now present/absent" generically, which is what the frontend's
        // membership rendering keys off regardless of how the actor attached.
        // name: None — this fn is pure/sync (no DB access), so it can't
        // resolve a display name the way the other ActorJoined emission
        // sites in ws.rs/routes now do. Narrower residual gap: an agent
        // attaching via the machine-autonomous path still shows its raw id
        // to an already-connected client until that client's next reconnect.
        SessionEvent::AgentAttached {
            actor_id,
            attached_at,
            ..
        } => Some(WsPayload::ActorJoined {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *attached_at,
            seq,
            role: Some(MemberRole::Agent),
            name: None,
        }),

        SessionEvent::AgentDetached {
            actor_id,
            detached_at,
            ..
        } => Some(WsPayload::ActorDetached {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *detached_at,
            seq,
        }),

        SessionEvent::OwnershipTransferred {
            from_actor,
            to_actor,
            transferred_at,
        } => Some(WsPayload::OwnershipTransferred {
            session_id: session_id.to_string(),
            actor: from_actor.clone(),
            timestamp: *transferred_at,
            seq,
            payload: OwnershipTransferredPayload {
                from: from_actor.clone(),
                to: to_actor.clone(),
            },
        }),

        SessionEvent::ApprovalClaimed {
            approval_id,
            claimed_by,
            claimed_at,
        } => Some(WsPayload::ApprovalClaimed {
            session_id: session_id.to_string(),
            actor: claimed_by.clone(),
            timestamp: *claimed_at,
            seq,
            payload: ApprovalEventPayload {
                approval_id: approval_id.clone(),
            },
        }),

        SessionEvent::SessionPaused {
            paused_by,
            paused_at,
            ..
        } => Some(WsPayload::SessionStatusChanged {
            session_id: session_id.to_string(),
            actor: paused_by.clone(),
            timestamp: *paused_at,
            seq,
            payload: SessionStatusPayload {
                status: "suspended".into(),
            },
        }),

        SessionEvent::SessionResumed {
            resumed_by,
            resumed_at,
        } => Some(WsPayload::SessionStatusChanged {
            session_id: session_id.to_string(),
            actor: resumed_by.clone(),
            timestamp: *resumed_at,
            seq,
            payload: SessionStatusPayload {
                status: "active".into(),
            },
        }),

        SessionEvent::SessionArchived {
            archived_by,
            archived_at,
        } => Some(WsPayload::SessionStatusChanged {
            session_id: session_id.to_string(),
            actor: archived_by.clone(),
            timestamp: *archived_at,
            seq,
            payload: SessionStatusPayload {
                status: "archived".into(),
            },
        }),

        SessionEvent::MessagePosted {
            actor_id,
            content,
            posted_at,
        } => Some(WsPayload::MessagePosted {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *posted_at,
            seq,
            payload: MessagePostedPayload {
                content: content.clone(),
            },
        }),

        // authored_by has no SessionEvent-side source (the field distinguishes
        // "written by a cap-bound sidecar" vs "written by a human", which this
        // event doesn't carry) — None, same as any other legacy entry.
        SessionEvent::ContextEntryAdded {
            entry_id,
            actor_id,
            kind,
            content,
            added_at,
        } => Some(WsPayload::ContextEntryAdded {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *added_at,
            seq,
            payload: ContextEntryAddedPayload {
                entry_id: entry_id.clone(),
                kind: kind.clone(),
                content: content.clone(),
                authored_by: None,
            },
        }),

        SessionEvent::ContextEntryResolved {
            entry_id,
            resolved_by,
            note,
            resolved_at,
        } => Some(WsPayload::ContextEntryResolved {
            session_id: session_id.to_string(),
            actor: resolved_by.clone(),
            timestamp: *resolved_at,
            seq,
            payload: ContextEntryResolvedPayload {
                entry_id: entry_id.clone(),
                resolved_by: resolved_by.clone(),
                note: note.clone(),
            },
        }),

        SessionEvent::ArtifactCreated {
            artifact_id,
            actor_id,
            name,
            artifact_type,
            created_at,
        } => Some(WsPayload::ArtifactCreated {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *created_at,
            seq,
            payload: ArtifactPayload {
                artifact_id: artifact_id.clone(),
                name: name.clone(),
                artifact_type: artifact_type.clone(),
            },
        }),

        SessionEvent::ArtifactUpdated {
            artifact_id,
            actor_id,
            name,
            artifact_type,
            updated_at,
        } => Some(WsPayload::ArtifactUpdated {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *updated_at,
            seq,
            payload: ArtifactPayload {
                artifact_id: artifact_id.clone(),
                name: name.clone(),
                artifact_type: artifact_type.clone(),
            },
        }),

        SessionEvent::ApprovalCancelled {
            approval_id,
            cancelled_by,
            cancelled_at,
        } => Some(WsPayload::ApprovalCancelled {
            session_id: session_id.to_string(),
            actor: cancelled_by.clone(),
            timestamp: *cancelled_at,
            seq,
            payload: ApprovalEventPayload {
                approval_id: approval_id.clone(),
            },
        }),

        SessionEvent::ApprovalDelegated {
            approval_id,
            from,
            to,
            delegated_at,
        } => Some(WsPayload::ApprovalDelegated {
            session_id: session_id.to_string(),
            actor: from.clone(),
            timestamp: *delegated_at,
            seq,
            payload: ApprovalDelegatedPayload {
                approval_id: approval_id.clone(),
                from: from.clone(),
                to: to.clone(),
            },
        }),

        SessionEvent::ApprovalDisputed {
            approval_id,
            disputed_by,
            reason,
            disputed_at,
        } => Some(WsPayload::ApprovalDisputed {
            session_id: session_id.to_string(),
            actor: disputed_by.clone(),
            timestamp: *disputed_at,
            seq,
            payload: ApprovalDisputedPayload {
                approval_id: approval_id.clone(),
                reason: reason.clone(),
            },
        }),

        SessionEvent::ArtifactDeleted {
            artifact_id,
            actor_id,
            name,
            artifact_type,
            deleted_at,
        } => Some(WsPayload::ArtifactDeleted {
            session_id: session_id.to_string(),
            actor: actor_id.clone(),
            timestamp: *deleted_at,
            seq,
            payload: ArtifactPayload {
                artifact_id: artifact_id.clone(),
                name: name.clone(),
                artifact_type: artifact_type.clone(),
            },
        }),

        _ => None,
    }
}
