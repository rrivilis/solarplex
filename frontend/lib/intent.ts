"use client";

// ── Deterministic command parsing — GET /api/intent/parse?text=... ──────────
//
// Server-side wraps the `intent` crate (NFST/rustfst grammar match, not an
// LLM) — see crates/server/src/routes/intent.rs. A parse is a *proposal*:
// callers surface the recognized command distinctly and let the user pick
// it, then route to the same already-authorized UI flow a manual click
// would use (StatusPanel's Manage dropdown, OwnershipPanel, NeedsAction,
// the Invite modal) — never execute anything directly off free text.
//
// `target_session`/actor names (invitee, transfer recipient) come back as
// raw strings from the grammar — resolution against real sessions/actors is
// a *separate* step the server does against the caller's own membership
// (never a global lookup, same boundary as Teammates/Search), surfaced here
// as `resolution.target_session` / `resolution.actor`. A name that doesn't
// resolve isn't an error — the caller just shows the raw text.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export type Intent =
  | { kind: "pause" }
  | { kind: "resume" }
  | { kind: "archive" }
  | { kind: "approve" }
  | { kind: "deny" }
  | { kind: "claim" }
  | { kind: "invite"; role: "owner" | "collaborator" | "observer" | "agent"; invitee: string | null; ttl_secs: number | null }
  | { kind: "transfer_ownership"; to: string }
  | { kind: "navigate" }
  | { kind: "attach_agent"; name: string | null; ttl_secs: number | null };

export type NameResolution =
  | { status: "matched"; id: string; name: string; email?: string }
  | { status: "ambiguous"; candidates: { id: string; name: string; email?: string }[] }
  | { status: "not_found" };

export interface ParsedIntent {
  intent: Intent;
  target_session: string | null;
  resolution: {
    target_session?: NameResolution;
    actor?: NameResolution;
  };
}

const EMPTY: ParsedIntent | null = null;

/** Server floors identically to lib/search.ts's search() — skip the
 *  round-trip for input too short to plausibly match a grammar. */
export async function parseIntent(text: string): Promise<ParsedIntent | null> {
  if (text.trim().length < 3) return EMPTY;
  const res = await authFetch(`${API_BASE}/intent/parse?text=${encodeURIComponent(text)}`);
  if (!res.ok) return EMPTY;
  const data = await res.json();
  if (!data.intent) return EMPTY;
  return { intent: data.intent, target_session: data.target_session ?? null, resolution: data.resolution ?? {} };
}
