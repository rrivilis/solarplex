import { WsEnvelope } from "@/lib/types";

// Pure event-type lookup tables and formatting, split out of Timeline.tsx.
// Timeline.tsx also statically imports MarkdownContent/MessageBody (pulling
// in react-markdown/rehype-highlight/highlight.js, ~330kB parsed / ~95kB
// gzip) — /activity and /search only ever needed these three exports for
// their own event-feed rendering and never render markdown, but importing
// from Timeline.tsx dragged that whole chunk onto both routes anyway since
// webpack's tree-shaking of a component-bearing module isn't reliable here.
// This module has no component imports, so pages that only need the
// taxonomy/formatting no longer pay for the markdown toolchain.

export const EVENT_COLOR: Record<string, string> = {
  "tool.call.requested":   "text-accent-blue",
  "tool.call.executed":    "text-accent-green",
  "tool.call.blocked":     "text-accent-red",
  "approval.requested":    "text-accent-amber",
  "approval.granted":      "text-accent-green",
  "approval.denied":       "text-accent-red",
  "approval.contested":    "text-accent-amber",
  "approval.claimed":      "text-accent-purple",
  "approval.timed_out":    "text-muted",
  "approval.cancelled":    "text-muted",
  "actor.joined":          "text-subtle",
  "actor.detached":        "text-muted",
  "ownership.transferred": "text-accent-purple",
  "artifact.created":      "text-accent-blue",
  "artifact.updated":      "text-accent-blue",
  "artifact.deleted":      "text-accent-red",
  "agent.status.changed":  "text-subtle",
  "session.status.changed":"text-subtle",
  "message.posted":        "text-subtle",
  "context.entry.added":   "text-accent-purple",
  "context.entry.resolved":"text-accent-green",
};

export const DOT_COLOR: Record<string, string> = {
  "tool.call.requested":   "bg-accent-blue",
  "tool.call.executed":    "bg-accent-green",
  "tool.call.blocked":     "bg-accent-red",
  "approval.requested":    "bg-accent-amber",
  "approval.granted":      "bg-accent-green",
  "approval.denied":       "bg-accent-red",
  "approval.contested":    "bg-accent-amber",
  "approval.claimed":      "bg-accent-purple",
  "approval.timed_out":    "bg-surface-4",
  "actor.joined":          "bg-subtle",
  "actor.detached":        "bg-surface-4",
  "ownership.transferred": "bg-accent-purple",
  "artifact.created":      "bg-accent-blue",
  "artifact.updated":      "bg-accent-blue",
  "artifact.deleted":      "bg-accent-red",
  "message.posted":        "bg-surface-4",
  "context.entry.added":   "bg-accent-purple",
  "context.entry.resolved":"bg-accent-green",
};

export const EVENT_LABEL: Record<string, string> = {
  "tool.call.requested":    "Tool requested",
  "tool.call.executed":     "Tool executed",
  "tool.call.blocked":      "Tool blocked",
  "approval.requested":     "Approval requested",
  "approval.granted":       "Approved",
  "approval.denied":        "Denied",
  "approval.contested":     "Contested",
  "approval.timed_out":     "Timed out",
  "approval.claimed":       "Claimed",
  "approval.cancelled":     "Cancelled",
  "approval.delegated":     "Delegated",
  "approval.disputed":      "Disputed",
  "actor.joined":           "Joined",
  "actor.detached":         "Detached",
  "ownership.transferred":  "Ownership transferred",
  "artifact.created":       "Artifact created",
  "artifact.updated":       "Artifact updated",
  "artifact.deleted":       "Artifact deleted",
  "agent.status.changed":   "Status changed",
  "session.status.changed": "Session status changed",
  "message.posted":         "Message",
  "context.entry.added":   "Context added",
  "context.entry.resolved":"Context resolved",
};

export function eventSummary(event: WsEnvelope, actorNames: Record<string, string> = {}): string {
  const p = (event.payload ?? {}) as Record<string, unknown>;
  // Events correctly store the immutable actor_id forever — resolved to a
  // current display name here, at render time, so a rename is reflected
  // retroactively across all history without ever touching the event log.
  const resolve = (id: unknown): string =>
    typeof id === "string" ? (actorNames[id] ?? id) : String(id ?? "");
  const actor = resolve(event.actor);
  switch (event.type) {
    case "tool.call.requested":
    case "approval.requested":
      return `${actor} → ${(p.tool as string) ?? "unknown"}`;
    case "tool.call.executed":
      return `${actor} executed ${(p.tool as string) ?? ""}`;
    case "tool.call.blocked":
      return `${actor}: ${(p.tool as string) ?? ""} blocked`;
    case "approval.granted":
      return `${actor} approved`;
    case "approval.denied":
      return `${actor} denied${p.reason ? `: ${p.reason}` : ""}`;
    case "approval.contested":
      return `Vote conflict — owner resolution needed`;
    case "approval.claimed":
      return `${actor} is reviewing`;
    case "ownership.transferred":
      return `${resolve(p.from)} → ${resolve(p.to)}`;
    case "session.status.changed": {
      // Backend already carries the specific new status (session_broadcast.rs
      // maps SessionPaused/Resumed/Archived all onto this one wire event) —
      // this was previously falling through to the generic `default: actor`
      // case below, i.e. just "rr_test" with no indication of what changed.
      const status = String(p.status ?? "");
      const verb: Record<string, string> = {
        suspended: "paused the session",
        active:    "reactivated the session",
        archived:  "archived the session",
      };
      return `${actor} ${verb[status] ?? `changed session status to ${status}`}`;
    }
    case "actor.joined":
      return `${actor} attached`;
    case "actor.detached":
      return `${actor} detached`;
    case "artifact.created":
    case "artifact.updated":
      return `${actor}: ${p.name ?? ""}`;
    case "artifact.deleted":
      return `${actor} deleted ${p.name ?? ""}`;
    case "message.posted":
      return actor;
    case "context.entry.added": {
      const kindLabel: Record<string, string> = {
        fact: "FACT", hypothesis: "HYPO", question: "Q?",
        constraint: "CSTR", decision: "DCSN",
      };
      const k = String(p.kind ?? "fact");
      return `${actor} [${kindLabel[k] ?? k.toUpperCase()}]`;
    }
    case "context.entry.resolved":
      return `${actor} resolved context entry`;
    default:
      return actor;
  }
}

// ── Internal WS plumbing — not real activity log entries ──────────────────────
// Saga events (actor "system") are cross-session-delegation/reflector
// plumbing — meaningful for debugging the coordination protocol, not for a
// lay user's view of "what happened in this session." `agent.status.changed`
// and `approval.timed_out` belong here too even though they're ordinary,
// non-plumbing SessionEvents: an agent's Waiting/Running/Idle status fires on
// every single tool call, and a timeout is just the transient state a still-
// pending approval passes through — real signal for the live status badges
// (StatusPanel) elsewhere, but pure noise as its own Activity Log row. Still
// fully present in the event log / DB for debugging; only excluded from this
// user-facing rendering.
export const INTERNAL_WS = new Set([
  "session.snapshot",
  "saga_begun",
  "saga_step_sent",
  "saga_step_acked",
  "saga_compensated",
  "saga_terminated",
  "agent.status.changed",
  "approval.timed_out",
]);
