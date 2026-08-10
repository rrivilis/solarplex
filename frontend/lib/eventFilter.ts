"use client";

// ── Event-type filter — shared between the in-session Timeline and the
// cross-session Activity page ────────────────────────────────────────────
//
// One localStorage-persisted preference for both surfaces: turning off
// "Presence" once (actor.joined/actor.detached — the dominant noise in any
// active session's log) sticks everywhere, not just in the view you
// happened to be looking at.

import { useCallback, useState } from "react";

export type EventCategory = "messages" | "approvals" | "artifacts" | "context" | "presence" | "tools" | "session";

export const EVENT_CATEGORIES: { key: EventCategory; label: string }[] = [
  { key: "messages",  label: "Messages" },
  { key: "approvals", label: "Approvals" },
  { key: "artifacts", label: "Artifacts" },
  { key: "context",   label: "Context" },
  { key: "presence",  label: "Presence" },
  { key: "tools",     label: "Tool calls" },
  { key: "session",   label: "Session" },
];

const TYPE_TO_CATEGORY: Record<string, EventCategory> = {
  "message.posted":         "messages",
  "approval.requested":     "approvals",
  "approval.granted":       "approvals",
  "approval.denied":        "approvals",
  "approval.contested":     "approvals",
  "approval.claimed":       "approvals",
  "approval.timed_out":     "approvals",
  "approval.cancelled":     "approvals",
  "approval.delegated":     "approvals",
  "approval.disputed":      "approvals",
  "artifact.created":       "artifacts",
  "artifact.updated":       "artifacts",
  "artifact.deleted":       "artifacts",
  "context.entry.added":    "context",
  "context.entry.resolved": "context",
  "actor.joined":           "presence",
  "actor.detached":         "presence",
  "agent.status.changed":   "presence",
  "tool.call.requested":    "tools",
  "tool.call.executed":     "tools",
  "tool.call.blocked":      "tools",
  "ownership.transferred":  "session",
  "session.status.changed": "session",
};

export function categoryOf(type: string): EventCategory | null {
  return TYPE_TO_CATEGORY[type] ?? null;
}

const STORAGE_KEY = "sol-event-type-filter";
const ALL_CATEGORIES = EVENT_CATEGORIES.map(c => c.key);
// Presence (actor.joined/detached, agent.status.changed) is the dominant
// noise in any active session and is the one category most people want
// filed away rather than surfaced — same instinct that moved human
// reconnects out of the event log entirely (session_connections). Everyone
// without a saved preference starts with it off; the toggle bar still lets
// anyone turn it back on.
const DEFAULT_CATEGORIES = ALL_CATEGORIES.filter(c => c !== "presence");

function loadEnabled(): Set<EventCategory> {
  if (typeof window === "undefined") return new Set(DEFAULT_CATEGORIES);
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return new Set(DEFAULT_CATEGORIES);
    const arr: unknown = JSON.parse(raw);
    if (!Array.isArray(arr)) return new Set(DEFAULT_CATEGORIES);
    const valid = arr.filter((c): c is EventCategory => ALL_CATEGORIES.includes(c as EventCategory));
    return new Set(valid);
  } catch { return new Set(DEFAULT_CATEGORIES); }
}

export function useEventTypeFilter() {
  const [enabled, setEnabled] = useState<Set<EventCategory>>(loadEnabled);

  const toggle = useCallback((cat: EventCategory) => {
    setEnabled(prev => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, JSON.stringify([...next]));
      return next;
    });
  }, []);

  // Event types with no category mapping (shouldn't happen given the
  // taxonomy above is exhaustive over EventType, but a future event kind
  // added to one and not the other should stay visible, not silently
  // vanish) always pass.
  const isEnabled = useCallback((type: string) => {
    const cat = categoryOf(type);
    return cat === null ? true : enabled.has(cat);
  }, [enabled]);

  return { enabled, toggle, isEnabled };
}
