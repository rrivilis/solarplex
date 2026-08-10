"use client";

// ── Mailbox — receiver-specific edge routes, read-only from the frontend ────
//
// The backend resolves each mailbox_routes row's entity_uri back to the real
// object (currently only "invite" kinds exist) and returns an already-
// enriched summary — this module just types and fetches that, no client-side
// resolution logic.

import { authFetch } from "./auth";
import { API_BASE } from "./env";

export interface MailboxInviteEntry {
  id: string;
  kind: "invite";
  entity_uri: string;
  created_at: string;
  seen_at: string | null;
  invite: {
    id: string;
    session_id: string;
    session_name: string;
    role: string;
    invited_by: string;
    invited_by_name: string;
    expires_at: string;
    redeemed_at: string | null;
    revoked_at: string | null;
  };
}

export interface MailboxUnknownEntry {
  id: string;
  kind: "unknown";
  entity_uri: string;
  created_at: string;
  seen_at: string | null;
}

export type MailboxEntry = MailboxInviteEntry | MailboxUnknownEntry;

export async function getMailbox(): Promise<MailboxEntry[]> {
  const res = await authFetch(`${API_BASE}/mailbox`);
  if (!res.ok) return [];
  return res.json();
}

export async function markMailboxSeen(id: string): Promise<void> {
  await authFetch(`${API_BASE}/mailbox/${id}/seen`, { method: "POST" });
}
