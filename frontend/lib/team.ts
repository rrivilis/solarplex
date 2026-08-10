"use client";

// ── Workspace member directory — GET /api/team ───────────────────────────────
//
// Read-only v1: every human actor who currently shares an active session
// with the caller — not workspace-wide (see crates/server/src/routes/team.rs
// and db::actors::list_teammates for why). Role management, escalation
// chains, and approval-authority scoping are a separate, larger piece of
// work — they need a workspace-level default-role concept that doesn't
// exist in the schema yet.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export interface Teammate {
  id: string;
  name: string;
  email: string | null;
  created_at: string;
  session_count: number;
  roles: string[];
  last_active_at: string | null;
}

export async function getTeammates(): Promise<Teammate[]> {
  const res = await authFetch(`${API_BASE}/team`);
  if (!res.ok) return [];
  return res.json();
}
