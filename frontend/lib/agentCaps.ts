"use client";

// ── Active agent attach-tokens ───────────────────────────────────────────────
//
// GET/DELETE /api/agent-caps[/:id] — every live agent attach-credential
// across every session you own, with a revoke action. Server-scoped to
// sessions you actually own (crates/db/src/tokens.rs::list_root_caps_for_owner/
// revoke_owned_root_cap) — the id here can never revoke a cap in a session
// you don't own no matter what's passed.

import { API_BASE } from "./env";
import { authFetch } from "./auth";

export type AgentCap = {
  cap_id: string;
  session_id: string;
  session_name: string;
  actor_id: string;
  created_at: string;
  expires_at: string;
  used_at: string | null;
};

export async function listAgentCaps(): Promise<AgentCap[]> {
  const res = await authFetch(`${API_BASE}/agent-caps`);
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
  return res.json();
}

export async function revokeAgentCap(capId: string): Promise<void> {
  const res = await authFetch(`${API_BASE}/agent-caps/${encodeURIComponent(capId)}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
}
