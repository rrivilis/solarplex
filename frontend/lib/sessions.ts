"use client";

// ── Sessions the signed-in actor belongs to ──────────────────────────────────
//
// Promoted out of app/page.tsx (was inlined there) so the cross-session sync
// workspace can reuse the exact same fetch to populate its "add a session
// window" picker, rather than duplicating the request.

import { authFetch } from "./auth";
import { API_BASE } from "./env";
import { SessionRow } from "./types";

export async function getSessions(): Promise<SessionRow[]> {
  // Scoped server-side to the caller's sp_token identity — no actor_id
  // param anymore; list_sessions dropped the unauthenticated "list every
  // session in the deployment" branch this used to hit when it was omitted.
  const res = await authFetch(`${API_BASE}/sessions`);
  if (res.status === 401) throw new Error("Sign-in expired");
  if (!res.ok) throw new Error(`GET /sessions failed: ${res.status}`);
  return res.json();
}
