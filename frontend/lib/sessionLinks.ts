"use client";

// ── Session-to-session linking ───────────────────────────────────────────────
//
// The single mechanism for cross-session sync — supersedes the old
// lib/sessionSync.ts single-artifact propose/approve flow. A link is an
// authorization relationship, not a data copy: once linked, opening a peer
// pane in the workspace is just a second real WS connection (useSession),
// authorized server-side by the link (see db::sessions::require_membership_
// or_linked_access). Nothing here is "live" itself — it only creates/lists/
// mutes/removes the link record.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export interface SessionLinkInvite {
  id: string;
  source_session_id: string;
  invited_by: string;
  expires_at: string;
  redeemed_by_session: string | null;
  redeemed_by_actor: string | null;
  redeemed_at: string | null;
  created_at: string;
}

export interface SessionLink {
  id: string;
  session_a: string;
  session_b: string;
  linked_by: string;
  visibility: "full" | "muted";
  created_at: string;
}

export interface SessionLinkListItem {
  id: string;
  peer_session_id: string;
  peer_session_name: string;
  visibility: "full" | "muted";
  linked_by: string;
  created_at: string;
}

export async function mintLinkInvite(sourceSessionId: string, ttlSecs = 259_200): Promise<SessionLinkInvite> {
  const res = await authFetch(`${API_BASE}/sessions/${sourceSessionId}/link-invites`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ttl_secs: ttlSecs }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

export async function redeemLinkInvite(inviteId: string, targetSessionId: string): Promise<SessionLink> {
  const res = await authFetch(`${API_BASE}/link-invites/${inviteId}/redeem`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target_session_id: targetSessionId }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

/** Direct fast path — succeeds only if the caller holds Collaborator+ in both sessions. */
export async function directLink(sessionA: string, sessionB: string): Promise<SessionLink> {
  const res = await authFetch(`${API_BASE}/sessions/${sessionA}/link/${sessionB}`, { method: "POST" });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

export async function listLinks(sessionId: string): Promise<SessionLinkListItem[]> {
  const res = await authFetch(`${API_BASE}/sessions/${sessionId}/links`);
  if (!res.ok) return [];
  return res.json();
}

export async function setLinkVisibility(linkId: string, visibility: "full" | "muted"): Promise<SessionLink> {
  const res = await authFetch(`${API_BASE}/links/${linkId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ visibility }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

export async function unlink(linkId: string): Promise<void> {
  const res = await authFetch(`${API_BASE}/links/${linkId}`, { method: "DELETE" });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
}

// ── Digest ────────────────────────────────────────────────────────────────
//
// Computed-on-read session summary — the SQL-VIEW analog for cross-session
// communication. Deliberately not a stored/copied value: recomputed on every
// call, authorized the same way any other session read is (a linked session
// already satisfies this with no special-casing). See crates/db/src/sessions.rs
// ::compute_digest and protocol::types::SessionDigest.

export interface SessionDigest {
  session_id: string;
  session_name: string;
  recent_event_count: number;
  open_approvals: number;
  artifacts_count: number;
  last_activity_at: string | null;
}

export async function getDigest(sessionId: string): Promise<SessionDigest> {
  const res = await authFetch(`${API_BASE}/sessions/${sessionId}/digest`);
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
  return res.json();
}

// ── Context-summary-send (Part 4B) ───────────────────────────────────────────
//
// Push one of your own session's existing context entries into a linked
// session's context log, with provenance. There's no server-side re-read —
// the caller already has the entry's own fields from its own live
// state.contextEntries, so they're sent as-is (see crates/server/src/
// routes/sessions.rs::send_context_entry's doc comment for why).

export async function sendContextEntry(
  targetSessionId: string,
  sourceSessionId: string,
  entry: { id: string; kind: string; content: string; actor_id: string; timestamp: string },
): Promise<void> {
  const res = await authFetch(`${API_BASE}/sessions/${targetSessionId}/context/send`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      source_session_id: sourceSessionId,
      source_entry_id: entry.id,
      kind: entry.kind,
      content: entry.content,
      source_authored_by: entry.actor_id,
      source_authored_at: entry.timestamp,
    }),
  });
  if (!res.ok) throw new Error(await res.text().catch(() => `HTTP ${res.status}`));
}
