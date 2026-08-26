use protocol::MemberRole;
use serde::Serialize;

/// Mirrors the CLI's existing governance verb set (`crates/cli/src/cmd/
/// session.rs`'s `SessionCmd`, `approval.rs`'s `ApprovalCmd`) rather than
/// inventing a parallel action taxonomy — this and `sp` are two front-ends
/// over the same action space.
///
/// `Serialize` (tagged, snake_case) is for `crates/server`'s `/intent/parse`
/// endpoint — the wire shape a frontend caller sees, e.g.
/// `{"kind":"invite","role":"collaborator","invitee":"bob"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Intent {
    Pause,
    Resume,
    Archive,
    Approve,
    Deny,
    Claim,
    Invite {
        role: MemberRole,
        invitee: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<i64>,
    },
    TransferOwnership {
        to: String,
    },
    /// Plain "take me to session X" — no CLI analog (this is the one verb
    /// that exists only because a command bar needs it, not because `sp`
    /// has an equivalent), and unlike every other variant here its
    /// `ParsedIntent::target_session` is never `None` — parsing fails
    /// entirely rather than producing a `Navigate` with nowhere to go (see
    /// lib.rs's `parse_intent`).
    Navigate,
    /// Mint an attach token for a new agent identity. `name` is *not*
    /// resolved against any existing actor the way `Invite::invitee` is —
    /// it's what the new agent gets called, chosen fresh, same as typing it
    /// into the Attach Agent modal's own "Agent ID" field.
    AttachAgent {
        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_secs: Option<i64>,
    },
}

/// A parsed action plus, orthogonally, *which session it targets* — every
/// verb is addressable against a session other than the one the caller
/// happens to be sitting in ("pause session in roman-room1"), same as the
/// CLI's own commands aren't tied to whatever session `sp` was last attached
/// to. `target_session` is a raw, unresolved name (or `None` when the text
/// carried no target-session clause, meaning "the session I'm already in")
/// — this crate has no DB access to resolve it against real sessions; that
/// happens server-side (see `crates/server/src/routes/intent.rs`), same
/// division of labor as the actor-name slots below (`Invite::invitee`,
/// `TransferOwnership::to`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParsedIntent {
    pub intent: Intent,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_session: Option<String>,
}
