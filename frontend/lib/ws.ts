"use client";

import { useEffect, useRef, useCallback, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  WsEnvelope, SessionSnapshot, PendingApproval, MessageEntry, ArtifactSummary, ContextEntry,
} from "./types";
import { authFetch, getSpToken, isAuthenticated } from "./auth";
import { API_BASE, WS_BASE } from "./env";

// Maximum number of events kept in memory.  Older entries are evicted from the
// front of the array.  Prevents unbounded memory growth in long-running sessions.
const MAX_EVENTS = 500;

/**
 * Discrete connection lifecycle, replacing ad hoc combinations of booleans.
 *
 * - "connecting"   — the very first attempt, before any snapshot has ever
 *                     arrived. Gates the skeleton loader (see SessionSkeleton).
 * - "connected"    — the socket is currently open.
 * - "reconnecting" — was connected (or attempting) before, lost the socket,
 *                     currently retrying with backoff. Once a snapshot has
 *                     ever arrived, the last-known content stays visible
 *                     during this phase instead of falling back to a skeleton.
 * - "rejected"     — a terminal failure (not a member, session not found).
 *                     Retrying can't self-heal either of those, so reconnect
 *                     attempts stop.
 */
export type ConnectionPhase = "connecting" | "connected" | "reconnecting" | "rejected";

export interface SessionState {
  snapshot:        SessionSnapshot | null;
  events:          WsEnvelope[];
  messages:        MessageEntry[];
  pendingApprovals: PendingApproval[];
  /** Live artifact list, maintained entirely from WS events — no HTTP polling. */
  artifacts:       ArtifactSummary[];
  /** Shared epistemic context — typed entries with provenance. */
  contextEntries:  ContextEntry[];
  /** Session display name extracted from the snapshot — eliminates the
   *  GET /sessions/:id HTTP round-trip on page load. */
  sessionName:     string | null;
  connected:       boolean;
  /** True when the server rejected the WS connection with close code 4403
   *  (actor is not a member of this session). Stops reconnect attempts. */
  notMember:       boolean;
  phase:           ConnectionPhase;
}

function appendEvent(events: WsEnvelope[], msg: WsEnvelope): WsEnvelope[] {
  const next = [...events, msg];
  return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
}

// ── Historical event types (from REST GET /sessions/:id/events) ───────────────
interface HistoricalEventRow {
  id: string;
  session_id: string;
  actor_id: string;
  type: string;
  payload: Record<string, unknown>;
  seq: number;
  timestamp: string;
}

function rowToEnvelope(r: HistoricalEventRow): WsEnvelope {
  // The DB `payload` column stores the ENTIRE serialized WsMessage.
  // The inner payload struct (message content, artifact id, etc.) lives
  // under the nested `.payload` key inside that JSON blob.
  const outerMsg = r.payload as Record<string, unknown>;
  return {
    protocol_version: 1,
    id: r.id,
    session_id: r.session_id,
    type: r.type,
    actor: r.actor_id,
    timestamp: r.timestamp,
    seq: r.seq,
    payload: (outerMsg.payload as Record<string, unknown>) ?? {},
  };
}

/** Merge historical events with any live events already in state.
 *  Deduplicates by id and sorts by seq ascending. */
function mergeEventArrays(historical: WsEnvelope[], live: WsEnvelope[]): WsEnvelope[] {
  const liveIds = new Set(live.map(e => e.id));
  const merged = [...historical.filter(e => !liveIds.has(e.id)), ...live];
  merged.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  return merged.length > MAX_EVENTS ? merged.slice(-MAX_EVENTS) : merged;
}

/** Merge historical messages with live messages, dedup by id, sort by seq. */
function mergeMessages(historical: MessageEntry[], live: MessageEntry[]): MessageEntry[] {
  const liveIds = new Set(live.map(m => m.id));
  const merged = [...historical.filter(m => !liveIds.has(m.id)), ...live];
  merged.sort((a, b) => (a.seq ?? 0) - (b.seq ?? 0));
  return merged;
}

/** React Query cache key for a session's last-known snapshot. Shared between
 *  the lazy initial-state seed below and the live snapshot handler so a
 *  re-visit to a recently-viewed session renders real content immediately
 *  (stale-while-revalidate) instead of the skeleton, while the WS reconnects
 *  underneath it. Not fetched via useQuery's own lifecycle — this is the
 *  documented pattern for bridging a push-based source (WS) into the cache:
 *  plain setQueryData/getQueryData, since there's no query function to run. */
function snapshotQueryKey(sessionId: string) {
  return ["session-snapshot", sessionId] as const;
}

/** Derive the snapshot-dependent slice of SessionState from a SessionSnapshot.
 *  Shared by the lazy initial-state seed and the live "session.snapshot"
 *  handler so both paths compute identically — no risk of the two drifting. */
function deriveFromSnapshot(snapshot: SessionSnapshot | null, fallbackName: string | null) {
  return {
    snapshot,
    pendingApprovals: snapshot?.pending_approvals ?? [],
    artifacts: (snapshot?.artifacts ?? []).map(a => ({
      id:   a.id,
      name: a.name,
      type: (a as unknown as Record<string, string>).artifact_type ?? a.type,
    })),
    contextEntries: snapshot?.context ?? [],
    sessionName: snapshot?.name ?? fallbackName,
  };
}

export function useSession(sessionId: string, actorId: string, token?: string | null) {
  const ws = useRef<WebSocket | null>(null);
  const queryClient = useQueryClient();
  const [state, setState] = useState<SessionState>(() => {
    // Seed from the cache if this exact session was visited before in this
    // tab's lifetime — instant real content instead of the skeleton.
    const cached = queryClient.getQueryData<SessionSnapshot>(snapshotQueryKey(sessionId)) ?? null;
    return {
      ...deriveFromSnapshot(cached, null),
      events:          [],
      messages:        [],
      connected:       false,
      notMember:       false,
      // If we have stale content to show, treat the phase as "reconnecting"
      // (content visible, connecting in the background) rather than
      // "connecting" (which would otherwise be indistinguishable from a
      // fresh, content-less first visit).
      phase: cached ? "reconnecting" : "connecting",
    };
  });

  const send = useCallback((payload: Record<string, unknown>) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify({
        protocol_version: 1,
        id: crypto.randomUUID(),
        ...payload,
      }));
    }
  }, []);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let retryAttempt = 0;

    // Track whether we've already loaded history for this connection.
    let historyLoaded = false;

    const BASE_BACKOFF_MS = 1_000;
    const MAX_BACKOFF_MS  = 30_000;

    /** Close codes that mean retrying can't self-heal — the identity/access
     *  problem is permanent (or would need a human to fix it), not transient.
     *  Everything else (network blips, server restarts, an already-cleared
     *  stale token, etc.) is assumed retryable — indefinite backoff rather
     *  than a hard attempt cap, since we'd rather keep trying quietly than
     *  strand the user with no path back in. */
    function isTerminalCloseCode(code: number): boolean {
      return code === 4403 /* not_member */ || code === 4404 /* session_not_found */;
    }

    function scheduleReconnect() {
      if (cancelled) return;
      const delay = Math.min(BASE_BACKOFF_MS * 2 ** retryAttempt, MAX_BACKOFF_MS);
      retryAttempt += 1;
      retryTimer = setTimeout(() => {
        retryTimer = null;
        if (!cancelled) connect();
      }, delay);
    }

    async function connect() {
      // Signed in via OIDC: connect with sp_token, which the server verifies
      // and derives the real actor identity from directly — actor_id in the
      // query string is ignored entirely on this path (see ws.rs::handler),
      // and critically, unlike the join_token path below, this never
      // silently auto-registers a new "collaborator" member. If you're not
      // already a member, it correctly rejects (4403) instead of joining
      // you. None of the join_token minting/caching dance applies here.
      let url: string;
      if (isAuthenticated()) {
        const spToken = getSpToken();
        url = `${WS_BASE}/sessions/${sessionId}/stream?sp_token=${encodeURIComponent(spToken ?? "")}`;
      } else {
        // No explicit token (no agent cap / invite-link token in the URL or
        // cached from a prior visit) — mint a fresh session join_token so a
        // human can still attach. The raw token is only ever revealed once
        // (at session creation, or here); GET /sessions/:id never returns it
        // (SessionRow.join_token is #[serde(skip)]'d — only its hash is
        // persisted). Cache the minted token in sessionStorage so repeated
        // connects/reconnects in this tab reuse it instead of rotating the
        // session's invite token on every attach.
        let effectiveToken = token ?? null;
        const cacheKey = `sol-human-jointoken-${sessionId}`;
        let mintedFresh = false;
        if (!effectiveToken) {
          effectiveToken = typeof window !== "undefined" ? sessionStorage.getItem(cacheKey) : null;
          if (!effectiveToken) {
            try {
              // Deduped: concurrent callers (e.g. StrictMode's double-invoke)
              // share this one in-flight rotation instead of each minting
              // their own and invalidating each other's.
              effectiveToken = await regenerateJoinTokenDeduped(sessionId);
              mintedFresh = true;
            } catch {
              // best-effort — fall through and let the server reject as before
            }
          }
        }
        // Check cancellation BEFORE any further side effect (cache write,
        // socket creation) — a cleaned-up mount must never touch shared state.
        if (cancelled) return;
        if (mintedFresh && effectiveToken && typeof window !== "undefined") {
          sessionStorage.setItem(cacheKey, effectiveToken);
        }

        const tokenParam = effectiveToken ? `&token=${encodeURIComponent(effectiveToken)}` : "";
        url = `${WS_BASE}/sessions/${sessionId}/stream?actor_id=${actorId}${tokenParam}`;
      }
      if (cancelled) return;
      const sock = new WebSocket(url);
      socket = sock;
      ws.current = sock;

    /** Fetch historical events from the REST API and merge into state.
     *  Called once after the first snapshot arrives so messages and the
     *  activity log persist across page re-entry. */
    async function loadHistory() {
      try {
        const resp = await authFetch(`${API_BASE}/sessions/${sessionId}/events?limit=500`);
        if (!resp.ok) return;
        const rows: HistoricalEventRow[] = await resp.json();
        const historical = rows.map(rowToEnvelope);
        const messages: MessageEntry[] = rows
          .filter(r => r.type === "message.posted")
          .map(r => ({
            id:        r.id,
            actor:     r.actor_id,
            // r.payload is the full WsMessage JSON; message content is nested at .payload.content
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            content:   ((r.payload as any)?.payload?.content as string) ?? "",
            timestamp: r.timestamp,
            seq:       r.seq,
          }));
        setState(s => ({
          ...s,
          events:   mergeEventArrays(historical, s.events),
          // Only seed messages from history if we don't already have them live.
          messages: s.messages.length === 0 ? messages : mergeMessages(messages, s.messages),
        }));
      } catch { /* network error — silently ignore */ }
    }

    sock.onopen  = () => {
      retryAttempt = 0; // reset backoff — this connection succeeded
      setState(s => ({ ...s, connected: true, notMember: false, phase: "connected" }));
    };
    sock.onclose = (event) => {
      // We tore this socket down ourselves (cleanup/deps change) — the new
      // mount (if any) owns reconnection from here, not this stale closure.
      if (cancelled) return;

      // Code 4403 = server rejected because actor is not a member of the session.
      // Mark it explicitly so the UI can show a proper "access denied" message
      // instead of a generic "Reconnecting..." indicator.
      const notMember = event.code === 4403;
      // Code 4405 = the cached join_token no longer matches the server's hash
      // (e.g. it was rotated elsewhere). Clear it so the retry mints a fresh
      // one instead of retrying the same dead token forever.
      if (event.code === 4405 && typeof window !== "undefined") {
        sessionStorage.removeItem(`sol-human-jointoken-${sessionId}`);
      }

      const terminal = isTerminalCloseCode(event.code);
      setState(s => ({
        ...s,
        connected: false,
        notMember,
        phase: terminal ? "rejected" : "reconnecting",
      }));

      if (!terminal) {
        scheduleReconnect();
      }
    };

    sock.onmessage = (e) => {
      try {
        const msg: WsEnvelope = JSON.parse(e.data);
        handleMessage(msg);
      } catch { /* malformed frame — ignore */ }
    };

    function handleMessage(msg: WsEnvelope) {
      switch (msg.type) {

        // ── Snapshot: full authoritative state on attach ─────────────────────
        case "session.snapshot": {
          const derived = deriveFromSnapshot(msg.state ?? null, null);
          setState(s => ({ ...s, ...derived, sessionName: msg.state?.name ?? s.sessionName }));
          // Keep the cache current for the next time this session is visited —
          // see the lazy useState initializer above.
          if (msg.state) {
            queryClient.setQueryData(snapshotQueryKey(sessionId), msg.state);
          }
          // Load historical events once per connection so the activity log and
          // messages survive page re-entry (snapshot gives state, not history).
          if (!historyLoaded) {
            historyLoaded = true;
            loadHistory();
          }
          break;
        }

        // ── Approval lifecycle ───────────────────────────────────────────────
        case "approval.requested":
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            pendingApprovals: [
              ...s.pendingApprovals,
              {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                approval_id: (msg.payload as any)?.approval_id,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                tool: (msg.payload as any)?.tool,
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                requested_by: (msg.payload as any)?.requested_by,
                state: "Pending" as const,
                votes: {},
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                expires_at: (msg.payload as any)?.expires_at,
                requested_at: msg.timestamp,
              },
            ],
          }));
          break;

        case "approval.granted":
        case "approval.denied":
        case "approval.timed_out":
        case "approval.cancelled": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const resolvedId = (msg.payload as any)?.approval_id;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            pendingApprovals: s.pendingApprovals.filter(a => a.approval_id !== resolvedId),
          }));
          break;
        }

        case "approval.contested": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const contestedId = (msg.payload as any)?.approval_id;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const votes = (msg.payload as any)?.votes ?? {};
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            pendingApprovals: s.pendingApprovals.map(a =>
              a.approval_id === contestedId ? { ...a, state: "Contested" as const, votes } : a
            ),
          }));
          break;
        }

        case "approval.claimed": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const claimedId = (msg.payload as any)?.approval_id;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            pendingApprovals: s.pendingApprovals.map(a =>
              a.approval_id === claimedId
                ? { ...a, state: "Claimed" as const, claimed_by: msg.actor }
                : a
            ),
          }));
          break;
        }

        // ── Artifact lifecycle — kept live from WS, no HTTP poll ─────────────
        case "artifact.created": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg.payload as any;
          const newArtifact: ArtifactSummary = {
            id:   p?.artifact_id ?? "",
            name: p?.name        ?? "(unnamed)",
            type: p?.artifact_type ?? p?.type ?? "other",
          };
          setState(s => ({
            ...s,
            events:    appendEvent(s.events, msg),
            // Avoid duplicates in case the snapshot already included this artifact.
            artifacts: s.artifacts.some(a => a.id === newArtifact.id)
              ? s.artifacts
              : [...s.artifacts, newArtifact],
          }));
          break;
        }

        case "artifact.updated": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const updatedId = (msg.payload as any)?.artifact_id;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const updatedName = (msg.payload as any)?.name;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            artifacts: updatedName
              ? s.artifacts.map(a => a.id === updatedId ? { ...a, name: updatedName } : a)
              : s.artifacts,
          }));
          break;
        }

        case "artifact.deleted": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const deletedId = (msg.payload as any)?.artifact_id;
          setState(s => ({
            ...s,
            events:    appendEvent(s.events, msg),
            artifacts: s.artifacts.filter(a => a.id !== deletedId),
          }));
          break;
        }

        // ── Messages ─────────────────────────────────────────────────────────
        case "message.posted": {
          const entry: MessageEntry = {
            id:      msg.id,
            actor:   msg.actor ?? "unknown",
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            content: (msg.payload as any)?.content ?? "",
            timestamp: msg.timestamp ?? new Date().toISOString(),
            seq:     msg.seq ?? 0,
          };
          setState(s => ({
            ...s,
            events:   appendEvent(s.events, msg),
            messages: [...s.messages, entry],
          }));
          break;
        }

        // ── Context layer ─────────────────────────────────────────────────────
        case "context.entry.added": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg.payload as any;
          const entry: ContextEntry = {
            id:         p?.entry_id   ?? "",
            kind:       p?.kind       ?? "fact",
            content:    p?.content    ?? "",
            actor_id:   msg.actor     ?? "unknown",
            timestamp:  msg.timestamp ?? new Date().toISOString(),
            resolved:   false,
            seq:        msg.seq       ?? 0,
          };
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            contextEntries: s.contextEntries.some(e => e.id === entry.id)
              ? s.contextEntries
              : [...s.contextEntries, entry],
          }));
          break;
        }

        case "context.entry.resolved": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg.payload as any;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            contextEntries: s.contextEntries.map(e =>
              e.id === p?.entry_id
                ? { ...e, resolved: true, resolved_by: p?.resolved_by, resolution_note: p?.note ?? undefined }
                : e
            ),
          }));
          break;
        }

        // ── Session lifecycle ─────────────────────────────────────────────────
        case "session.status.changed": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const newStatus = (msg.payload as any)?.status as string | undefined;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            snapshot: s.snapshot && newStatus
              ? { ...s.snapshot, status: newStatus as SessionSnapshot["status"] }
              : s.snapshot,
          }));
          break;
        }

        // ── Presence ─────────────────────────────────────────────────────────
        case "actor.joined": {
          // msg.actor just (re)attached. If they're already in members, flip
          // attached and update their role. If they're brand-new (e.g. an agent
          // that attached after the initial snapshot was sent), add them.
          const joinedId = msg.actor;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg as any;
          const joinedRole = p.role ?? "collaborator";
          // Server now resolves this at emission time (see WsPayload::ActorJoined's
          // name field) so an already-open tab shows the real name immediately
          // instead of the raw id — previously this only got corrected on the
          // tab's next reconnect, since that's the only other time a full,
          // server-enriched snapshot gets sent. Still falls back to the id for
          // whatever event history predates this field.
          const joinedName: string = p.name || joinedId;
          setState(s => {
            if (!s.snapshot || !joinedId) return s;
            const existing = s.snapshot.members.some(m => m.actor_id === joinedId);
            // Mirrors ws.rs's own apply_event: db::sessions::add_member demotes
            // whoever currently holds owner at the DB level the instant this
            // role is granted, but that fact never reaches this snapshot on
            // its own — without demoting here too, the sidebar's Owner badge
            // just stays pinned to whoever it used to be until a reload.
            const grantsOwner = joinedRole === "owner";
            const updatedMembers = (existing
              ? s.snapshot.members.map(m =>
                  m.actor_id === joinedId
                    ? { ...m, attached: true, role: joinedRole, name: p.name || m.name }
                    : m
                )
              : [
                  ...s.snapshot.members,
                  { actor_id: joinedId, name: joinedName, role: joinedRole, attached: true, status: undefined },
                ]
            ).map(m =>
              grantsOwner && m.actor_id !== joinedId && m.role === "owner"
                ? { ...m, role: "collaborator" }
                : m
            );
            return {
              ...s,
              events: appendEvent(s.events, msg),
              snapshot: {
                ...s.snapshot,
                members: updatedMembers,
                owner: grantsOwner ? joinedId : s.snapshot.owner,
                owner_name: grantsOwner ? (p.name || s.snapshot.owner_name) : s.snapshot.owner_name,
              },
            };
          });
          break;
        }

        case "agent.status.changed": {
          // Update the live status badge shown in the Agents panel.
          const statusActor = msg.actor;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const agentStatus = (msg.payload as any)?.status ?? null;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            snapshot: s.snapshot && statusActor ? {
              ...s.snapshot,
              members: s.snapshot.members.map(m =>
                m.actor_id === statusActor ? { ...m, status: agentStatus } : m
              ),
            } : s.snapshot,
          }));
          break;
        }

        case "actor.detached": {
          const detachedId = msg.actor;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            snapshot: s.snapshot && detachedId ? {
              ...s.snapshot,
              members: s.snapshot.members.map(m =>
                m.actor_id === detachedId ? { ...m, attached: false } : m
              ),
            } : s.snapshot,
          }));
          break;
        }

        // Ordinary WS connect/disconnect for an *already-known* member (a
        // route change, a tab reload, a brief network blip) — server-side
        // this is emitted by broadcast_presence, not commit_event, so it
        // was never written to the events table and has no seq. Deliberately
        // does NOT call appendEvent: this must never enter the Activity Log/
        // Messages feed, which is the whole point (see PresenceChanged's
        // doc comment server-side) — only the live attached/role flags update.
        case "presence.changed": {
          const presenceId = msg.actor;
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg as any;
          const attached: boolean = !!p.attached;
          const role = p.role;
          setState(s => ({
            ...s,
            snapshot: s.snapshot && presenceId ? {
              ...s.snapshot,
              members: s.snapshot.members.map(m =>
                m.actor_id === presenceId ? { ...m, attached, role: role ?? m.role } : m
              ),
            } : s.snapshot,
          }));
          break;
        }

        // ── Ownership transfer ────────────────────────────────────────────────
        case "ownership.transferred": {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const p = msg.payload as any;
          const fromActor = p?.from as string | undefined;
          const toActor   = p?.to   as string | undefined;
          setState(s => ({
            ...s,
            events: appendEvent(s.events, msg),
            // owner_name is a separate field from owner (the id) — OwnershipPanel
            // displays owner_name directly rather than re-deriving it from
            // members on every render, so it has to be patched here too or it
            // stays pinned to the old owner's name after a live transfer
            // (isOwner/the id itself updated correctly, only the displayed
            // name was stale — the transfer really had gone through).
            snapshot: s.snapshot && fromActor && toActor ? {
              ...s.snapshot,
              owner: toActor,
              owner_name: s.snapshot.members.find(m => m.actor_id === toActor)?.name || toActor,
              members: s.snapshot.members.map(m => {
                if (m.actor_id === fromActor) return { ...m, role: "collaborator" };
                if (m.actor_id === toActor)   return { ...m, role: "owner" };
                return m;
              }),
            } : s.snapshot,
          }));
          break;
        }

        // ── Shell adapter events ──────────────────────────────────────────────
        // Append to event log so the activity timeline shows shell history;
        // no additional state projection needed (no dedicated shell panel yet).
        case "shell.command.started":
        case "shell.command.completed":
          setState(s => ({ ...s, events: appendEvent(s.events, msg) }));
          break;

        // ── Rate limiting ──────────────────────────────────────────────────
        // Durable audit trail for a Tier-1 denial (see crate::rate_limit's
        // module doc) — broadcast to the whole hub like any other event, so
        // only surface a toast for the actor who actually got denied; other
        // connected members just see it land in the log, same as a shell event.
        case "effect.rate_limited": {
          setState(s => ({ ...s, events: appendEvent(s.events, msg) }));
          if (msg.actor === actorId) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const p = msg.payload as any;
            const retryAfter = typeof p?.retry_after_secs === "number" ? p.retry_after_secs : null;
            toast.error(
              `Rate limit reached${p?.key_label ? ` for ${p.key_label}` : ""}`,
              {
                description: [
                  p?.policy ? `Limit: ${p.policy}` : null,
                  retryAfter !== null ? `Try again in ${retryAfter}s` : null,
                ].filter(Boolean).join(" · ") || undefined,
              },
            );
          }
          break;
        }

        // ── Internal wakeup pings — never persisted, never displayed ──────────
        // "session_updated" (session_task's shadow-mode broadcast — see
        // live_admin_pause/resume/archive and session_updated_broadcast) and
        // "session.events_available" (notifier.rs's pg_notify wakeup, fired
        // for every persisted event so `sp watch`-style pollers can drop
        // their interval to 0) both exist purely to tell a client "something
        // changed, go check" — neither carries a real seq/row of its own.
        // Falling through to the catch-all below appended them to the same
        // `events` array the Activity Log counts and renders, so one real
        // action (e.g. one pause) could show up as three: the actual
        // SessionStatusChanged event, plus one of each of these pings that
        // its own persist triggered.
        case "session_updated":
        case "session.events_available":
          break;

        default:
          setState(s => ({ ...s, events: appendEvent(s.events, msg) }));
      }
    }

    }

    connect();

    return () => {
      cancelled = true;
      if (retryTimer) clearTimeout(retryTimer);
      socket?.close();
    };
  }, [sessionId, actorId, token]);

  const approve = useCallback((approvalId: string) => {
    send({ type: "approval.grant", session_id: sessionId, approval_id: approvalId, actor_id: actorId });
  }, [send, sessionId, actorId]);

  const deny = useCallback((approvalId: string, reason?: string) => {
    send({ type: "approval.deny", session_id: sessionId, approval_id: approvalId, actor_id: actorId, reason });
  }, [send, sessionId, actorId]);

  const claim = useCallback((approvalId: string) => {
    send({ type: "approval.claim", session_id: sessionId, approval_id: approvalId, actor_id: actorId });
  }, [send, sessionId]);

  const sendMessage = useCallback((content: string) => {
    send({ type: "message.post", session_id: sessionId, content });
  }, [send, sessionId]);

  const addContextEntry = useCallback((kind: string, content: string) => {
    send({ type: "context.entry.add", session_id: sessionId, actor_id: actorId, kind, content });
  }, [send, sessionId, actorId]);

  const resolveContextEntry = useCallback((entryId: string, note?: string) => {
    send({ type: "context.entry.resolve", session_id: sessionId, actor_id: actorId, entry_id: entryId, note });
  }, [send, sessionId, actorId]);

  return { state, approve, deny, claim, sendMessage, addContextEntry, resolveContextEntry };
}

export async function fetchSessions() {
  // Scoped to the caller's own sp_token identity server-side — there's no
  // actor_id query param anymore (list_sessions dropped the "list every
  // session in the deployment" branch that used to answer for a bare GET).
  const resp = await authFetch(`${API_BASE}/sessions`);
  return resp.json();
}

/** Mint a fresh raw join_token for a session. Rotates the stored hash —
 *  any previously-issued raw token for this session stops working. */
export async function regenerateJoinToken(sessionId: string): Promise<string | null> {
  const resp = await authFetch(`${API_BASE}/sessions/${sessionId}/regenerate-join-token`, {
    method: "POST",
  });
  if (!resp.ok) return null;
  const body = await resp.json();
  return body.join_token ?? null;
}

/** Module-level (not per-hook-instance) cache of in-flight regenerations,
 *  keyed by session_id.
 *
 *  regenerateJoinToken is NOT idempotent — every call rotates the server's
 *  stored hash, invalidating whatever the previous call minted. React 18
 *  StrictMode deliberately double-invokes effects in dev mode (mount ->
 *  cleanup -> mount again), so without this dedup, useSession's connect()
 *  would fire two independent, racing rotate-token calls on a single fresh
 *  mount — whichever response lands last silently invalidates the token the
 *  other one just used to open its WebSocket. Routing every caller through
 *  the same in-flight promise makes exactly one rotation happen per session,
 *  regardless of how many times the effect is invoked. */
const pendingRegenerate = new Map<string, Promise<string | null>>();

export function regenerateJoinTokenDeduped(sessionId: string): Promise<string | null> {
  let p = pendingRegenerate.get(sessionId);
  if (!p) {
    p = regenerateJoinToken(sessionId).finally(() => {
      // Only clear if we're still the current in-flight promise for this
      // session — defensive against a newer call having raced in.
      if (pendingRegenerate.get(sessionId) === p) {
        pendingRegenerate.delete(sessionId);
      }
    });
    pendingRegenerate.set(sessionId, p);
  }
  return p;
}

export async function fetchSession(id: string) {
  const resp = await authFetch(`${API_BASE}/sessions/${id}`);
  return resp.json();
}

export async function createSession(body: {
  name: string;
  description?: string;
  approval_policy: string;
}) {
  // created_by is no longer accepted — the server derives the owner from
  // the sp_token attached by authFetch.
  const resp = await authFetch(`${API_BASE}/sessions`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}
