"use client";

// ── Cross-session search — GET /api/search?q=... ────────────────────────────
//
// Sessions/artifacts/events are scoped server-side to the caller's own
// membership (same boundary as lib/activity.ts's cross-session feed);
// actors are a global lookup. See crates/db/src/search.rs for the query
// detail.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export interface SessionHit {
  id: string;
  name: string;
  description: string | null;
  status: string;
  created_by: string;
}

export interface ArtifactHit {
  id: string;
  session_id: string;
  session_name: string;
  name: string;
  type: string;
  created_by: string;
  created_by_name: string;
}

export interface ActorHit {
  id: string;
  name: string;
  email: string | null;
  type: "human" | "agent";
}

export interface EventHit {
  id: string;
  session_id: string;
  session_name: string;
  actor_id: string;
  actor_name: string;
  type: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface SearchResults {
  sessions: SessionHit[];
  artifacts: ArtifactHit[];
  actors: ActorHit[];
  events: EventHit[];
}

const EMPTY: SearchResults = { sessions: [], artifacts: [], actors: [], events: [] };

/** Server floors queries under 2 chars to an empty result — matched here so
 *  callers can skip the round-trip entirely for a 0-1 char query. */
export async function search(q: string, limit = 10): Promise<SearchResults> {
  if (q.trim().length < 2) return EMPTY;
  const res = await authFetch(`${API_BASE}/search?q=${encodeURIComponent(q)}&limit=${limit}`);
  if (!res.ok) return EMPTY;
  return res.json();
}
