use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Control state of the session — the "mode" the state machine is in.
///
/// `SessionState` drives which inbound events are accepted and which transitions
/// are valid.  Complex sub-state (members, caps, approvals, cursors) lives in
/// `SessionMemory` — not here.  This is the Σ (finite state control) of the CSXM.
///
/// Transitions:
/// ```text
///  Active      ──pause──────────► Suspended
///  Suspended   ──resume───────────► Active
///  Active      ──epoch_revoke───► Draining
///  Draining    ──drain_complete──► Active   (fenced actors ejected)
///  *           ──archive────────► Archived  (terminal)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "lifecycle", rename_all = "snake_case")]
pub enum SessionState {
    /// Session is running normally.  All event types are accepted.
    Active,

    /// Owner has paused the session.
    /// Agent-originated events are dropped; human WS messages may still arrive.
    Suspended {
        paused_by: String,
        reason: Option<String>,
        since: DateTime<Utc>,
    },

    /// Epoch revocation is in progress.
    /// Fenced actors are being disconnected.  No new connections from fenced
    /// actor IDs are admitted until the drain completes or the deadline passes.
    Draining {
        drain_deadline: DateTime<Utc>,
        /// Event log sequence at which the epoch was advanced.
        drain_seq: i64,
    },

    /// Session is permanently closed.  No further transitions are possible.
    Archived { at: DateTime<Utc> },
}

impl SessionState {
    /// Whether the session admits new actor connections.
    pub fn admits_connections(&self) -> bool {
        matches!(self, SessionState::Active | SessionState::Suspended { .. })
    }

    /// Whether the session is in a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, SessionState::Archived { .. })
    }

    /// Whether the session is actively running (not suspended/draining/archived).
    pub fn is_active(&self) -> bool {
        matches!(self, SessionState::Active)
    }

    /// Whether the session is draining after an epoch revocation.
    pub fn is_draining(&self) -> bool {
        matches!(self, SessionState::Draining { .. })
    }
}
