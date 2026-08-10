"use client";

// ── Cross-session activity feed — read-only, polled ─────────────────────────
//
// GET /api/activity returns rows already enriched server-side (session_name,
// actor_name) but with `payload` still the raw DB column — the full
// serialized WsMessage, same shape lib/ws.ts's rowToEnvelope unwraps for the
// single-session history fetch. Unwrapped here the same way, so the result
// is a ready-to-use WsEnvelope that Timeline's exported eventSummary/
// EVENT_COLOR/EVENT_LABEL helpers work on unmodified.

import { authFetch } from "./auth";
import { API_BASE } from "./env";
import { WsEnvelope } from "./types";

interface ActivityRow {
  id: string;
  session_id: string;
  session_name: string;
  actor_id: string;
  actor_name: string;
  type: string;
  payload: Record<string, unknown>;
  timestamp: string;
}

export interface ActivityItem {
  id: string;
  session_id: string;
  session_name: string;
  actor_id: string;
  actor_name: string;
  type: string;
  timestamp: string;
  /** Ready for Timeline's eventSummary/EVENT_COLOR/EVENT_LABEL. */
  event: WsEnvelope;
}

export async function getActivity(limit = 150): Promise<ActivityItem[]> {
  const res = await authFetch(`${API_BASE}/activity?limit=${limit}`);
  if (!res.ok) return [];
  const rows: ActivityRow[] = await res.json();
  return rows.map(r => {
    const outer = r.payload as Record<string, unknown>;
    const event: WsEnvelope = {
      protocol_version: 1,
      id: r.id,
      session_id: r.session_id,
      type: r.type,
      actor: r.actor_id,
      timestamp: r.timestamp,
      payload: (outer?.payload as Record<string, unknown>) ?? {},
    };
    return {
      id: r.id,
      session_id: r.session_id,
      session_name: r.session_name,
      actor_id: r.actor_id,
      actor_name: r.actor_name,
      type: r.type,
      timestamp: r.timestamp,
      event,
    };
  });
}
