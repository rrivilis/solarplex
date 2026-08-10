// Mirror of protocol crate types

export type ActorType = "human" | "agent";
export type SessionStatus = "active" | "suspended" | "archived";
export type MemberRole = "owner" | "collaborator" | "observer" | "agent";
export type ApprovalState = "Pending" | "Claimed" | "Approved" | "Denied" | "Contested" | "Expired";
export type Vote = "approve" | "deny";
export type AgentStatus = "running" | "waiting" | "blocked" | "idle" | "error";

export interface ToolCall {
  tool: string;
  args: Record<string, unknown>;
}

export interface SessionMember {
  actor_id: string;
  /** Resolved display name — see protocol::types::SessionMember's doc comment. */
  name: string;
  role: MemberRole;
  attached: boolean;
  status?: AgentStatus;
}

export interface PendingApproval {
  approval_id: string;
  tool: string;
  requested_by: string;
  state: ApprovalState;
  votes: Record<string, Vote>;
  claimed_by?: string;
  expires_at?: string;
  requested_at?: string;
  /** Structured tool-call arguments — e.g. cross_session.accept_ref's
   *  {source_uri, source_session_id}. Defaults to {} server-side when absent. */
  arguments?: Record<string, unknown>;
}

/** Shape of `PendingApproval.arguments` when `tool === "cross_session.accept_ref"`. */
export interface CrossSessionAcceptRefArgs {
  source_uri: string;
  source_session_id: string;
}

export interface ArtifactSummary {
  id: string;
  name: string;
  type: string;
}

export type ContextEntryKind = "fact" | "hypothesis" | "question" | "constraint" | "decision";

export interface ContextEntry {
  id: string;
  kind: ContextEntryKind;
  content: string;
  actor_id: string;
  timestamp: string;
  resolved: boolean;
  resolved_by?: string;
  resolution_note?: string;
  seq: number;
}

export interface SessionSnapshot {
  owner: string;
  /** Resolved display name for `owner` — see protocol::types::SessionSnapshot. */
  owner_name: string;
  status: SessionStatus;
  /** Session display name — now included in every snapshot message. */
  name: string;
  /** approval policy slug — now included in every snapshot message. */
  approval_policy: string;
  members: SessionMember[];
  pending_approvals: PendingApproval[];
  artifacts: ArtifactSummary[];
  context: ContextEntry[];
}

export interface SessionRow {
  id: string;
  name: string;
  description?: string;
  status: SessionStatus;
  created_by: string;
  /** Resolved display name for created_by — see routes::sessions::list_sessions. */
  created_by_name?: string;
  approval_policy: string;
  join_token: string;
  created_at: string;
  updated_at: string;
}

// WS message shapes

export interface WsEnvelope {
  protocol_version: number;
  id: string;
  type: string;
  session_id?: string;
  actor?: string;
  timestamp?: string;
  seq?: number;
  state?: SessionSnapshot;
  payload?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface MessageEntry {
  id: string;
  actor: string;
  content: string;
  timestamp: string;
  seq: number;
}

export type EventType =
  | "tool.call.requested"
  | "tool.call.executed"
  | "tool.call.blocked"
  | "approval.requested"
  | "approval.claimed"
  | "approval.granted"
  | "approval.denied"
  | "approval.contested"
  | "approval.timed_out"
  | "approval.cancelled"
  | "approval.delegated"
  | "approval.disputed"
  | "actor.joined"
  | "actor.detached"
  | "ownership.transferred"
  | "artifact.created"
  | "artifact.updated"
  | "artifact.deleted"
  | "agent.status.changed"
  | "session.status.changed"
  | "message.posted"
  | "context.entry.added"
  | "context.entry.resolved"
  | "session.snapshot";
