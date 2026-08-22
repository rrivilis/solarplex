//! Per-event visibility classification for the live broadcast (`ws.rs`'s
//! `store_and_broadcast`) and REST event-history (`routes::sessions::list_events`)
//! paths — closes the "no per-event ACL, Observer sees everything" gap
//! (docs/threat-model.md §11.2).
//!
//! Two of the six event types classified below (`tool.call.blocked`,
//! `proposal.file_write.attested`) are declared in `WsPayload` but have no
//! live emission call site anywhere in the workspace yet — included here for
//! correctness once they're wired up, not because anything exercises them
//! today.
//!
//! `cap.epoch.advanced` is deliberately absent from this table. `MemberRole`'s
//! own doc comment says Agent always ranks lowest, below Observer — gating
//! that event on any role floor would make a revoked agent unable to see its
//! own fencing notice, breaking the drain-window mechanism for exactly the
//! actor that depends on it. It stays universally broadcast, unconditionally,
//! by simply never appearing in `GATED_TYPES` below.

use protocol::messages::{
    ApprovalContestedPayload, ApprovalRequestedPayload, WsMessage, WsPayload,
};
use protocol::types::MemberRole;

/// Wire type-name strings requiring at least `MemberRole::Collaborator` to
/// see the full event. Single source of truth for both the typed (`WsPayload`)
/// and raw-JSON (`EventRow`) classification below, so the two paths can't
/// silently drift apart.
const GATED_TYPES: &[&str] = &[
    "approval.requested",
    "approval.contested",
    "approval.delegated",
    "effect.rate_limited",
    "tool.call.blocked",
    "proposal.file_write.attested",
];

/// Minimum role required to receive the *full* (unredacted) event. `None`
/// means unrestricted — broadcast/returned to everyone, exactly as today.
pub fn min_role(payload: &WsPayload) -> Option<MemberRole> {
    min_role_for_type(payload.type_name())
}

/// Same classification, keyed by the wire type-name string directly — for
/// the REST event-history path, which stores raw `(type, payload: Value)`
/// rows rather than typed `WsPayload`s.
pub fn min_role_for_type(type_name: &str) -> Option<MemberRole> {
    if GATED_TYPES.contains(&type_name) {
        Some(MemberRole::Collaborator)
    } else {
        None
    }
}

/// The safe residual to send to a connection below `min_role`'s bar, if any.
/// `None` means there is no safe residual — the event is withheld entirely
/// (its existence isn't disclosed, not just its detail), since the payload
/// has nothing left worth showing once the sensitive field is stripped.
pub fn redact(msg: &WsMessage) -> Option<WsMessage> {
    let payload = match &msg.payload {
        WsPayload::ApprovalRequested { session_id, actor, timestamp, seq, payload } => {
            WsPayload::ApprovalRequested {
                session_id: session_id.clone(),
                actor: actor.clone(),
                timestamp: *timestamp,
                seq: *seq,
                payload: ApprovalRequestedPayload {
                    approval_id: payload.approval_id.clone(),
                    tool: payload.tool.clone(),
                    summary: payload.summary.clone(),
                    requested_by: payload.requested_by.clone(),
                    expires_at: payload.expires_at,
                    // The actual sensitive content — see this module's doc.
                    arguments: serde_json::Value::Null,
                },
            }
        }
        WsPayload::ApprovalContested { session_id, actor, timestamp, seq, payload } => {
            WsPayload::ApprovalContested {
                session_id: session_id.clone(),
                actor: actor.clone(),
                timestamp: *timestamp,
                seq: *seq,
                payload: ApprovalContestedPayload {
                    approval_id: payload.approval_id.clone(),
                    // Per-actor vote disclosure — the sensitive part.
                    votes: std::collections::HashMap::new(),
                    pending_resolution: payload.pending_resolution.clone(),
                },
            }
        }
        // approval.delegated / effect.rate_limited / tool.call.blocked /
        // proposal.file_write.attested: thin payloads with no non-sensitive
        // residual once the gated field is stripped — withheld entirely.
        _ => return None,
    };
    Some(WsMessage::new(msg.id.clone(), payload))
}

/// Redacts a raw JSON event payload in place for a below-bar REST caller.
/// Returns `false` if there's no safe residual (caller should drop the row
/// entirely, mirroring `redact`'s `None` case above).
pub fn redact_value(type_name: &str, payload: &mut serde_json::Value) -> bool {
    match type_name {
        "approval.requested" => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("arguments".into(), serde_json::Value::Null);
            }
            true
        }
        "approval.contested" => {
            if let Some(obj) = payload.as_object_mut() {
                obj.insert("votes".into(), serde_json::json!({}));
            }
            true
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn approval_requested() -> WsMessage {
        WsMessage::new("evt1", WsPayload::ApprovalRequested {
            session_id: "s1".into(),
            actor: "a1".into(),
            timestamp: Utc::now(),
            seq: 1,
            payload: ApprovalRequestedPayload {
                approval_id: "ap1".into(),
                tool: "shell.exec".into(),
                summary: "run a command".into(),
                requested_by: "a1".into(),
                expires_at: None,
                arguments: serde_json::json!({"cmd": "rm -rf /secrets"}),
            },
        })
    }

    #[test]
    fn approval_requested_is_gated_at_collaborator() {
        assert_eq!(min_role(&approval_requested().payload), Some(MemberRole::Collaborator));
    }

    #[test]
    fn approval_requested_redaction_strips_arguments_keeps_narrative_fields() {
        let redacted = redact(&approval_requested()).expect("should have a safe residual");
        match redacted.payload {
            WsPayload::ApprovalRequested { payload, .. } => {
                assert_eq!(payload.arguments, serde_json::Value::Null);
                assert_eq!(payload.tool, "shell.exec");
                assert_eq!(payload.approval_id, "ap1");
            }
            other => panic!("expected ApprovalRequested, got {other:?}"),
        }
    }

    #[test]
    fn approval_contested_redaction_clears_votes_keeps_resolution() {
        let mut votes = std::collections::HashMap::new();
        votes.insert("a1".to_string(), protocol::types::Vote::Approve);
        votes.insert("a2".to_string(), protocol::types::Vote::Deny);
        let msg = WsMessage::new("evt2", WsPayload::ApprovalContested {
            session_id: "s1".into(),
            actor: "a1".into(),
            timestamp: Utc::now(),
            seq: 2,
            payload: ApprovalContestedPayload {
                approval_id: "ap1".into(),
                votes,
                pending_resolution: "owner".into(),
            },
        });
        let redacted = redact(&msg).expect("should have a safe residual");
        match redacted.payload {
            WsPayload::ApprovalContested { payload, .. } => {
                assert!(payload.votes.is_empty());
                assert_eq!(payload.pending_resolution, "owner");
            }
            other => panic!("expected ApprovalContested, got {other:?}"),
        }
    }

    #[test]
    fn approval_delegated_has_no_safe_residual() {
        let msg = WsMessage::new("evt3", WsPayload::ApprovalDelegated {
            session_id: "s1".into(),
            actor: "a1".into(),
            timestamp: Utc::now(),
            seq: 3,
            payload: protocol::messages::ApprovalDelegatedPayload {
                approval_id: "ap1".into(), from: "a1".into(), to: "a2".into(),
            },
        });
        assert_eq!(min_role(&msg.payload), Some(MemberRole::Collaborator));
        assert!(redact(&msg).is_none());
    }

    #[test]
    fn cap_epoch_advanced_is_never_gated() {
        let msg = WsMessage::new("evt4", WsPayload::EpochAdvanced {
            session_id: "s1".into(),
            actor: "system".into(),
            timestamp: Utc::now(),
            seq: 4,
            payload: protocol::messages::EpochAdvancedPayload {
                new_epoch: 2, strategy: "cap".into(), target_cap_id: Some("c1".into()),
                target_stratum: None, drain_seq: 3, drain_deadline_ms: 5000,
                closed_epoch: 1, revoked_count: 1,
            },
        });
        assert_eq!(min_role(&msg.payload), None);
    }

    #[test]
    fn ordinary_events_are_unrestricted() {
        let msg = WsMessage::new("evt5", WsPayload::MessagePosted {
            session_id: "s1".into(),
            actor: "a1".into(),
            timestamp: Utc::now(),
            seq: 5,
            payload: protocol::messages::MessagePostedPayload { content: "hi".into() },
        });
        assert_eq!(min_role(&msg.payload), None);
    }
}
