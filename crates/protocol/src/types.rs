use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Context layer ─────────────────────────────────────────────────────────────

/// The epistemic kind of a context entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextEntryKind {
    Fact,
    Hypothesis,
    Question,
    Constraint,
    Decision,
}

/// A single typed entry in the session's shared epistemic context.
/// Carries full provenance (actor, timestamp, seq) so the belief trail is auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntry {
    pub id: String,
    pub kind: ContextEntryKind,
    pub content: String,
    /// Actor who asserted this entry (human or agent id).
    pub actor_id: String,
    pub timestamp: DateTime<Utc>,
    pub resolved: bool,
    /// Actor who marked this entry resolved.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolved_by: Option<String>,
    /// Optional free-text note explaining the resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolution_note: Option<String>,
    pub seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Active,
    Suspended,
    Archived,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberRole {
    Owner,
    Collaborator,
    Observer,
    Agent,
}

impl MemberRole {
    pub fn can_approve(&self) -> bool {
        matches!(self, MemberRole::Owner | MemberRole::Collaborator)
    }

    pub fn can_transfer_ownership(&self) -> bool {
        matches!(self, MemberRole::Owner)
    }

    pub fn can_delete_artifact(&self, is_creator: bool) -> bool {
        matches!(self, MemberRole::Owner)
            || (matches!(self, MemberRole::Collaborator) && is_creator)
    }

    /// Authority ranking for role-ceiling checks (e.g. "does this member
    /// have at least Collaborator-level authority"). Owner > Collaborator >
    /// Observer. Agent is not part of this human-authority ladder — it
    /// always ranks lowest, so a `min_role` of Collaborator or higher can
    /// never be satisfied by an Agent membership. Kept private: callers use
    /// `satisfies`/`can_invite_as` rather than comparing ranks directly.
    fn rank(&self) -> u8 {
        match self {
            MemberRole::Owner => 3,
            MemberRole::Collaborator => 2,
            MemberRole::Observer => 1,
            MemberRole::Agent => 0,
        }
    }

    /// Whether this role meets or exceeds `min_role`'s authority.
    pub fn satisfies(&self, min_role: &MemberRole) -> bool {
        self.rank() >= min_role.rank()
    }

    /// Whether this role may create an invite offering `target_role`. You
    /// can't delegate authority you don't hold — a Collaborator cannot
    /// invite someone in as Owner.
    pub fn can_invite_as(&self, target_role: &MemberRole) -> bool {
        self.rank() >= target_role.rank()
    }
}

impl std::str::FromStr for MemberRole {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(MemberRole::Owner),
            "collaborator" => Ok(MemberRole::Collaborator),
            "observer" => Ok(MemberRole::Observer),
            "agent" => Ok(MemberRole::Agent),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalState {
    Pending,
    Claimed,
    Approved,
    Denied,
    Contested,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Vote {
    Approve,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalPolicy {
    SingleVote,
    Majority,
    Unanimous,
}

impl ApprovalPolicy {
    pub fn evaluate(&self, votes: &HashMap<String, Vote>, eligible_count: usize) -> ApprovalState {
        let approve = votes.values().filter(|v| **v == Vote::Approve).count();
        let deny = votes.values().filter(|v| **v == Vote::Deny).count();

        match self {
            ApprovalPolicy::SingleVote => match (approve, deny) {
                (a, 0) if a > 0 => ApprovalState::Approved,
                (0, d) if d > 0 => ApprovalState::Denied,
                (a, d) if a > 0 && d > 0 => ApprovalState::Contested,
                _ => ApprovalState::Pending,
            },
            ApprovalPolicy::Majority => {
                let threshold = eligible_count / 2 + 1;
                if approve >= threshold {
                    ApprovalState::Approved
                } else if deny >= threshold {
                    ApprovalState::Denied
                } else if approve > 0 && deny > 0 {
                    ApprovalState::Contested
                } else {
                    ApprovalState::Pending
                }
            }
            ApprovalPolicy::Unanimous => {
                if approve == eligible_count {
                    ApprovalState::Approved
                } else if deny > 0 {
                    ApprovalState::Denied
                } else if approve > 0 {
                    ApprovalState::Pending
                } else {
                    ApprovalState::Pending
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentStatus {
    Running,
    Waiting,
    Blocked,
    Idle,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub args: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Actor {
    pub id: String,
    #[serde(rename = "type")]
    pub actor_type: ActorType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMember {
    pub actor_id: String,
    /// Display name, resolved from `actors.name` at snapshot-send time —
    /// see `ws::make_snapshot_msg`. Empty when produced by the pure
    /// `session` crate or the cold DB-rebuild path, both of which have no
    /// actor-name lookup access by design; always populated by the time a
    /// snapshot actually reaches a client. Falls back to `actor_id` if a
    /// lookup ever misses (e.g. a deleted actor), never left blank on the wire.
    #[serde(default)]
    pub name: String,
    pub role: MemberRole,
    pub attached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<AgentStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingApproval {
    pub approval_id: String,
    pub tool: String,
    pub requested_by: String,
    pub state: ApprovalState,
    pub votes: HashMap<String, Vote>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claimed_by: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Structured tool-call arguments — lets clients render tool-specific
    /// detail instead of just the bare tool name.
    #[serde(default)]
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
}

/// A computed, read-only summary of a session — recent activity, open
/// approvals, artifacts produced. Always computed fresh from the session's
/// own tables at request time, never stored: this is the `solarplex`
/// analog of a SQL `VIEW`, not a materialized copy. See `db::sessions::
/// compute_digest` and `GET /sessions/:id/digest`. Authorized the same way
/// every other session-scoped read is (`require_session_member`, Observer
/// minimum) — a linked session already satisfies this with no special-casing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDigest {
    pub session_id: String,
    pub session_name: String,
    /// Events in the last 24h — a fixed window, not "since some cursor".
    pub recent_event_count: i64,
    pub open_approvals: i64,
    pub artifacts_count: i64,
    pub last_activity_at: Option<DateTime<Utc>>,
}

// ── Entity handle — typed kernel object reference ─────────────────────────────

/// A typed, unforgeable reference to a Solarplex kernel primitive.
///
/// `EntityHandle` is the protocol-layer analog of a C-list entry: it binds
/// an entity type with its opaque ID into a single value that can be routed,
/// dispatched, and eventually cap-checked without passing raw `&str` pairs.
///
/// **Relationship to C-list / cap DAG (v1 design note)**
///
/// Currently the inner `String` is the global ULID, which is both the
/// descriptor and the object identity.  When per-actor descriptor tables are
/// added (post-OIDC identity verification), the `String` becomes a local
/// descriptor that maps to the global ULID server-side — call sites need not
/// change, only the server-side lookup layer.
///
/// **Trust source distinction**
///
/// `permits_untrusted_dispatch()` controls whether plumb dispatch from a
/// foreign-authored URI (OSC-8 click, xdg-open) is allowed for this type.
/// It is the insertion point for step 2 of the build order (read-only plumb
/// on untrusted source) and for future cap-level enforcement.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum EntityHandle {
    Session(String),
    Artifact(String),
    Actor(String),
    Context(String),
    Cap(String),
    Approval(String),
    Invite(String),
}

impl EntityHandle {
    /// Parse from a bare `"entity/id"` URI segment (no scheme prefix).
    ///
    /// ```text
    /// from_uri("artifact/01J...")  → Some(Artifact("01J..."))
    /// from_uri("session/01J...")   → Some(Session("01J..."))
    /// from_uri("unknown/xyz")      → None
    /// from_uri("missing-slash")    → None
    /// ```
    pub fn from_uri(uri: &str) -> Option<Self> {
        let (kind, id) = uri.split_once('/')?;
        if id.is_empty() {
            return None;
        }
        let id = id.to_string();
        match kind {
            "session" => Some(Self::Session(id)),
            "artifact" => Some(Self::Artifact(id)),
            "actor" => Some(Self::Actor(id)),
            "context" => Some(Self::Context(id)),
            "cap" => Some(Self::Cap(id)),
            "approval" => Some(Self::Approval(id)),
            "invite" => Some(Self::Invite(id)),
            _ => None,
        }
    }

    /// The canonical entity type string ("session", "artifact", …).
    pub fn entity_type(&self) -> &'static str {
        match self {
            Self::Session(_) => "session",
            Self::Artifact(_) => "artifact",
            Self::Actor(_) => "actor",
            Self::Context(_) => "context",
            Self::Cap(_) => "cap",
            Self::Approval(_) => "approval",
            Self::Invite(_) => "invite",
        }
    }

    /// The opaque ID (ULID or actor identifier string).
    pub fn id(&self) -> &str {
        match self {
            Self::Session(id)
            | Self::Artifact(id)
            | Self::Actor(id)
            | Self::Context(id)
            | Self::Cap(id)
            | Self::Approval(id)
            | Self::Invite(id) => id,
        }
    }

    /// Bare URI: `"entity/id"` — no scheme.  Prepend `"solarplex://"` for the
    /// full clickable URI understood by the plumb handler.
    pub fn uri(&self) -> String {
        format!("{}/{}", self.entity_type(), self.id())
    }

    /// Whether this handle type may be dispatched from an **untrusted** source
    /// (OSC-8 click, `plumb run` invoked by a foreign URI).
    ///
    /// All current types are read-safe for inspection.  This method is the
    /// hook for narrowing that in the future — e.g. requiring explicit human
    /// confirmation before a Cap handle can be acted on from a click.
    ///
    /// **Step 2 of the build order**: when read-only plumb is implemented,
    /// `plumb()` will call this before executing a matched action and refuse
    /// if the resolved entity type does not permit untrusted dispatch.
    pub fn permits_untrusted_dispatch(&self) -> bool {
        matches!(
            self,
            Self::Session(_)
                | Self::Artifact(_)
                | Self::Context(_)
                | Self::Approval(_)
                | Self::Actor(_)
                | Self::Cap(_)
                | Self::Invite(_)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSnapshot {
    pub owner: String,
    /// Resolved display name for `owner` — same enrichment/fallback rules
    /// as `SessionMember::name`. Kept as a sibling field rather than folding
    /// `owner` into a `{id, name}` struct so existing `actor_id == owner`
    /// comparisons (e.g. StatusPanel's `isOwner` check) don't need to change.
    #[serde(default)]
    pub owner_name: String,
    pub status: SessionStatus,
    /// Session display name — carried in snapshot so the frontend avoids a
    /// separate GET /sessions/:id round-trip on attach.
    pub name: String,
    /// Approval policy slug (single_vote | majority | unanimous).
    pub approval_policy: String,
    pub members: Vec<SessionMember>,
    pub pending_approvals: Vec<PendingApproval>,
    pub artifacts: Vec<ArtifactSummary>,
    /// Shared epistemic context — typed belief entries with full provenance.
    /// Defaults to empty so sessions created before this field was added still deserialize.
    #[serde(default)]
    pub context: Vec<ContextEntry>,
}
