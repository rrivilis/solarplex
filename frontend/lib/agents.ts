"use client";

// ── Agent directory — GET /api/agents ────────────────────────────────────────
//
// Read-only: every agent-type actor who currently shares an active session
// with the caller — same co-membership boundary as lib/team.ts, same shape
// (see crates/db/src/actors.rs::list_agent_directory). Provider/model/tool-
// policy configuration is a real, separate, larger feature this doesn't
// attempt — this is just "which agents am I already working alongside,"
// the same read-only-directory bar Teammates cleared first.
//
// `live`: whether the agent has a heartbeat within the staleness threshold
// in any session hub right now — see
// crates/server/src/routes/agents.rs::list_agents. Revoking access is a
// Settings action (credential-scoped, owner-only); this is just "is it
// here right now."

import { authFetch } from "./auth";
import { API_BASE } from "./env";
import type { Teammate } from "./team";

export interface Agent extends Teammate {
  live: boolean;
}

export async function getAgents(): Promise<Agent[]> {
  const res = await authFetch(`${API_BASE}/agents`);
  if (!res.ok) return [];
  return res.json();
}
