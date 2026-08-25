"use client";

import { useParams, useRouter, useSearchParams } from "next/navigation";
import { useEffect, useCallback, useState, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import dynamic from "next/dynamic";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { useSession } from "@/lib/ws";
import { authFetch, getMe, getSpToken, isAuthenticated, maybeToastRateLimited, signIn } from "@/lib/auth";
import { useModalA11y } from "@/hooks/useModalA11y";
import Timeline, { INTERNAL_WS } from "@/components/Timeline";
import Messages from "@/components/Messages";
import NeedsAction from "@/components/NeedsAction";
import StatusPanel from "@/components/StatusPanel";
import SessionSkeleton from "@/components/SessionSkeleton";
import { API_BASE } from "@/lib/env";
import { getActorOverride } from "@/lib/actorOverride";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

// Lazy, same as Whiteboard below: only one center-panel tab renders at a
// time (see the `tab === "..."` guards further down), but a plain static
// import still ships every tab's code in this route's initial bundle
// regardless of which one a visitor actually opens. ArtifactsTab and
// ContextTab are secondary tabs (Messages is the default) — ArtifactsTab
// also drags in react-markdown + remark-gfm, which have no reason to load
// before someone actually opens that tab.
const Whiteboard   = dynamic(() => import("@/components/Whiteboard"),   { ssr: false });
const ArtifactsTab = dynamic(() => import("@/components/ArtifactsTab"), { ssr: false });
const ContextTab   = dynamic(() => import("@/components/ContextTab"),   { ssr: false });

type CenterTab = "messages" | "log" | "artifacts" | "whiteboard" | "context";

// Below this width the two fixed-width side panels (240px + 288px) are
// rendered as off-canvas overlays instead of static columns — together
// they already exceed a 320px viewport, which is a hard WCAG 1.4.10
// Reflow failure if left as a static 3-column flex row. Matches Tailwind's
// `lg` breakpoint so the same number drives both the JS toggle-button
// logic here and the `lg:` CSS in StatusPanel/NeedsAction.
const DESKTOP_BREAKPOINT_PX = 1024;

function useIsDesktop(minWidthPx: number): boolean {
  // Defaults to true so SSR/first client render agree (no window on the
  // server) — same hydration-safety pattern as the actor-identity chip
  // above: the real value can only be known after mount, so it's read in
  // an effect rather than during render.
  const [isDesktop, setIsDesktop] = useState(
    () => typeof window !== "undefined" ? window.matchMedia(`(min-width: ${minWidthPx}px)`).matches : true,
  );
  useEffect(() => {
    const mql = window.matchMedia(`(min-width: ${minWidthPx}px)`);
    const recompute = () => setIsDesktop(mql.matches);
    recompute();
    // Both listeners recompute from the same mql.matches rather than
    // trusting either event's own payload — belt-and-suspenders in case
    // one path lags behind the other in a given embedding.
    mql.addEventListener("change", recompute);
    window.addEventListener("resize", recompute);
    return () => {
      mql.removeEventListener("change", recompute);
      window.removeEventListener("resize", recompute);
    };
  }, [minWidthPx]);
  return isDesktop;
}

// ── Status color config ───────────────────────────────────────────────────────
const STATUS_STRIPE: Record<string, string> = {
  active:               "bg-accent-green",
  attention_requested:  "bg-accent-amber",
  action_needed:        "bg-accent-red",
  policy_update:        "bg-accent-blue",
  suspended:            "bg-surface-4",
  archived:             "bg-surface-4",
};

export default function SessionPage() {
  const params = useParams();
  const searchParams = useSearchParams();
  const router = useRouter();
  const sessionId = params.id as string;

  // Real identity takes priority once signed in — without this, the WS
  // connection below falls back to the ?actor= dev model even for an
  // authenticated user, which silently auto-registers a second, unrelated
  // "collaborator" member (whatever ?actor= happened to resolve to) instead
  // of connecting as the actual OIDC-verified owner/member. Same safe
  // pattern as AppNav's user card: `data` is undefined on both the server
  // render and the client's first hydration pass regardless, so this can't
  // produce a hydration mismatch — only the resolved actor_id can differ,
  // once, right after mount.
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    enabled: isAuthenticated(),
    staleTime: 60_000,
  });

  // Actor identity: real signed-in actor first; ?actor=/NEXT_PUBLIC_ACTOR_ID
  // let multiple dev actors share one server pre-auth (or when signed out)
  // — dev-only, compiled out in production builds (see lib/actorOverride.ts).
  const ACTOR_ID = me?.id ?? getActorOverride(searchParams) ?? "user";

  // Resolve join token: prefer URL param, fall back to sessionStorage.
  // sessionStorage is tab-scoped and cleared when the tab closes;
  // localStorage is avoided because it is XSS-accessible and persists indefinitely.
  const token: string | null =
    searchParams.get("token") ??
    (typeof window !== "undefined" ? sessionStorage.getItem(`sol-tok-${sessionId}-${ACTOR_ID}`) : null);

  // Persist token in sessionStorage for same-tab navigation without the URL param.
  useEffect(() => {
    if (token && typeof window !== "undefined") {
      sessionStorage.setItem(`sol-tok-${sessionId}-${ACTOR_ID}`, token);
    }
  }, [token, sessionId, ACTOR_ID]);

  const { state, approve, deny, claim, sendMessage, addContextEntry, resolveContextEntry } = useSession(sessionId, ACTOR_ID, token);

  // Deep-link into a specific tab (e.g. from a Search result or the ⌘K
  // palette) via ?tab=artifacts — read once on mount as the initial value,
  // not kept in sync afterward; ordinary in-page tab clicks stay local
  // state, same as before this existed.
  const CENTER_TABS: readonly CenterTab[] = ["messages", "log", "artifacts", "whiteboard", "context"];
  const initialTabParam = searchParams.get("tab") as CenterTab | null;
  const [tab, setTab] = useState<CenterTab>(
    initialTabParam && CENTER_TABS.includes(initialTabParam) ? initialTabParam : "messages",
  );

  // ── Off-canvas side panels (below DESKTOP_BREAKPOINT_PX) ──────────────────
  const isDesktop = useIsDesktop(DESKTOP_BREAKPOINT_PX);
  const [statusPanelOpen, setStatusPanelOpen] = useState(false);
  const [needsActionOpen, setNeedsActionOpen] = useState(false);
  // Resizing (or rotating) past the breakpoint mid-session shouldn't leave
  // an overlay+backdrop stuck open behind what's now a static column.
  useEffect(() => {
    if (isDesktop) {
      setStatusPanelOpen(false);
      setNeedsActionOpen(false);
    }
  }, [isDesktop]);

  // ── Invite User modal ─────────────────────────────────────────────────────
  const [inviteOpen, setInviteOpen]       = useState(false);
  const inviteModalRef = useModalA11y<HTMLDivElement>(inviteOpen, () => setInviteOpen(false));
  const [inviteRole, setInviteRole]       = useState("collaborator");
  const [inviteEmail, setInviteEmail]     = useState("");
  const [inviteTtl, setInviteTtl]         = useState(259200); // 3 days, matches server default
  const [inviteResult, setInviteResult]   = useState<{
    id: string; role: string; expires_at: string;
    mailbox_status: "not_addressed" | "delivered" | "pending_first_login" | "delivery_failed";
  } | null>(null);
  const [inviteLoading, setInviteLoading] = useState(false);

  const handleInvite = useCallback(async () => {
    if (!isAuthenticated()) {
      // OIDC is real now — send the user through it instead of failing.
      signIn(window.location.pathname + window.location.search);
      return;
    }
    setInviteLoading(true);
    setInviteResult(null);
    try {
      const res = await fetch(`${API_BASE}/sessions/${sessionId}/invites`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          sp_token: getSpToken(),
          role: inviteRole,
          ...(inviteEmail.trim() ? { invitee_email: inviteEmail.trim() } : {}),
          ttl_secs: inviteTtl,
        }),
      });
      if (res.status === 401) throw new Error("Sign-in expired — please sign in again");
      if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
      const data = await res.json();
      setInviteResult(data);
    } catch (e) {
      toast.error(`Failed to create invite: ${e instanceof Error ? e.message : "unknown"}`);
    } finally {
      setInviteLoading(false);
    }
  }, [sessionId, inviteRole, inviteEmail, inviteTtl]);

  // ── Attach Agent modal ────────────────────────────────────────────────────
  const [attachOpen, setAttachOpen]       = useState(false);
  const attachModalRef = useModalA11y<HTMLDivElement>(attachOpen, () => setAttachOpen(false));
  const [attachActorId, setAttachActorId] = useState("fs-agent");
  const [attachTtl, setAttachTtl]         = useState(900);
  const [attachMcpPath, setAttachMcpPath] = useState("");
  const [attachResult, setAttachResult]   = useState<{ token: string; launch_cmd: string; expires_at: string; sidecar_port: number } | null>(null);
  const [attachLoading, setAttachLoading] = useState(false);

  const handleAttach = useCallback(async () => {
    setAttachLoading(true);
    setAttachResult(null);
    try {
      const res = await authFetch(`${API_BASE}/sessions/${sessionId}/attach-token`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          actor_id: attachActorId,
          role: "agent",
          ttl_secs: attachTtl,
          ...(attachMcpPath.trim() ? { mcp_path: attachMcpPath.trim() } : {}),
        }),
      });
      if (res.status === 401 || res.status === 403) throw new Error("You need Collaborator access or higher to attach an agent");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();
      setAttachResult(data);
    } catch (e) {
      toast.error(`Failed to issue token: ${e instanceof Error ? e.message : "unknown"}`);
    } finally {
      setAttachLoading(false);
    }
  }, [sessionId, attachActorId, attachTtl, attachMcpPath]);

  // ── Visit summary: track when user last viewed this session ──────────────
  // Keyed per-actor so Alice and Bob each get their own "since last visit" marker.
  const visitKey = `sol-lastvisit-${sessionId}-${ACTOR_ID}`;
  // Capture the timestamp from the previous visit on first mount only.
  const [lastVisitTime] = useState<string | null>(() => {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(visitKey);
  });

  // Record the current visit time (so next attach shows "since your last visit").
  const visitRecorded = useRef(false);
  useEffect(() => {
    if (visitRecorded.current) return;
    visitRecorded.current = true;
    if (typeof window !== "undefined") {
      localStorage.setItem(visitKey, new Date().toISOString());
    }
  }, [visitKey]);

  const handleDismissVisitSummary = useCallback(() => {
    // Already recorded on mount; nothing extra needed here.
  }, []);

  // ── Global sol:switch-tab event (dispatched by GlobalCommandPalette) ──────
  useEffect(() => {
    function handler(e: Event) {
      const tabName = (e as CustomEvent<string>).detail as CenterTab;
      if (tabName) setTab(tabName);
    }
    window.addEventListener("sol:switch-tab", handler);
    return () => window.removeEventListener("sol:switch-tab", handler);
  }, []);

  // ── Global command-palette bridge events — a parsed intent (crates/intent)
  // or the static "Transfer Ownership" action opens the surface where the
  // real, already-authorized action lives; none of these execute anything
  // by themselves. sol:open-transfer previously had no listener at all
  // (CommandPalette's Transfer action was a silent no-op) — StatusPanel's
  // OwnershipPanel section is always rendered, so surfacing the panel is
  // enough to fix that in the same stroke. ──────────────────────────────────
  const [openManageSignal, setOpenManageSignal] = useState(0);
  useEffect(() => {
    function openTransfer() { setStatusPanelOpen(true); }
    function openManage() { setStatusPanelOpen(true); setOpenManageSignal(n => n + 1); }
    function openNeedsAction() { setNeedsActionOpen(true); }
    function openInvite(e: Event) {
      const { role, email, ttlSecs } = (e as CustomEvent<{ role?: string; email?: string; ttlSecs?: number }>).detail ?? {};
      setInviteOpen(true);
      setInviteResult(null);
      setInviteEmail(email ?? "");
      if (role) setInviteRole(role);
      if (ttlSecs) setInviteTtl(ttlSecs);
    }
    function openAttach(e: Event) {
      const { name, ttlSecs } = (e as CustomEvent<{ name?: string; ttlSecs?: number }>).detail ?? {};
      setAttachOpen(true);
      setAttachResult(null);
      if (name) setAttachActorId(name);
      if (ttlSecs) setAttachTtl(ttlSecs);
    }
    window.addEventListener("sol:open-transfer", openTransfer);
    window.addEventListener("sol:open-manage", openManage);
    window.addEventListener("sol:open-needs-action", openNeedsAction);
    window.addEventListener("sol:open-invite", openInvite);
    window.addEventListener("sol:open-attach", openAttach);
    return () => {
      window.removeEventListener("sol:open-transfer", openTransfer);
      window.removeEventListener("sol:open-manage", openManage);
      window.removeEventListener("sol:open-needs-action", openNeedsAction);
      window.removeEventListener("sol:open-invite", openInvite);
      window.removeEventListener("sol:open-attach", openAttach);
    };
  }, []);

  // ── Arriving here from a cross-session command proposal ────────────────────
  // CommandPalette can't dispatch a same-page window event when the parsed
  // command named a *different* session than wherever the palette was
  // opened from — there's no page there yet to listen for it. Instead it
  // navigates here with `?open=manage|needs-action|invite|transfer`
  // (+`role`/`email`/`ttl` for invite), and this fires the exact same actions as the
  // sol:open-* bridge above once the destination session has actually
  // mounted. One-shot: the params are stripped immediately after so a
  // refresh or back-navigation doesn't re-open anything.
  useEffect(() => {
    const openParam = searchParams.get("open");
    if (!openParam) return;
    switch (openParam) {
      case "manage":
        setStatusPanelOpen(true);
        setOpenManageSignal(n => n + 1);
        break;
      case "needs-action":
        setNeedsActionOpen(true);
        break;
      case "invite": {
        setInviteOpen(true);
        setInviteResult(null);
        setInviteEmail(searchParams.get("email") ?? "");
        const role = searchParams.get("role");
        if (role) setInviteRole(role);
        const ttl = Number(searchParams.get("ttl"));
        if (ttl) setInviteTtl(ttl);
        break;
      }
      case "transfer":
        setStatusPanelOpen(true);
        break;
      case "attach": {
        setAttachOpen(true);
        setAttachResult(null);
        const name = searchParams.get("name");
        if (name) setAttachActorId(name);
        const ttl = Number(searchParams.get("ttl"));
        if (ttl) setAttachTtl(ttl);
        break;
      }
    }
    const rest = new URLSearchParams(searchParams.toString());
    rest.delete("open");
    rest.delete("role");
    rest.delete("email");
    rest.delete("name");
    rest.delete("ttl");
    const qs = rest.toString();
    router.replace(`/sessions/${sessionId}${qs ? `?${qs}` : ""}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams.toString(), sessionId]);

  // ── Derived state from the WS connection ─────────────────────────────────
  //
  // Previously: two HTTP calls (GET /sessions/:id + GET /sessions/:id/artifacts)
  // Now:        both come through the initial WS snapshot, zero extra RTTs.
  //
  // Artifacts are kept live via artifact.created / artifact.updated /
  // artifact.deleted events in useSession; no polling interval needed.

  const artifacts    = state.artifacts;
  const sessionName  = state.sessionName ?? sessionId;
  // Deliberately reads state.sessionName directly rather than the
  // sessionName const above — that one falls back to the raw session ID,
  // which must never end up in the tab title (unlike the in-page <h1>,
  // where a brief ID flash before the WS snapshot lands is acceptable).
  useDocumentTitle(state.sessionName ?? "Session");
  const sessionStatus = state.snapshot?.status ?? "active";
  const stripeClass  = STATUS_STRIPE[sessionStatus] ?? "bg-surface-4";

  const pendingCount   = state.pendingApprovals.length;
  const logEventCount  = state.events.filter(e => !INTERNAL_WS.has(e.type)).length;

  // Events/messages correctly keep storing the raw actor_id forever.
  // Resolved here from the same already-enriched members list StatusPanel
  // uses, so a rename shows up retroactively across all history instead of
  // needing the event log itself touched.
  const actorNames = Object.fromEntries(
    (state.snapshot?.members ?? []).map(m => [m.actor_id, m.name]),
  );

  // refreshArtifacts: the Whiteboard's onSaveSuccess hook. After a whiteboard
  // save the server emits artifact.created / artifact.updated which updates
  // state.artifacts automatically; this is now a no-op kept for API compat.
  const refreshArtifacts = useCallback(() => { /* WS keeps artifacts in sync */ }, []);

  const handleTransfer = useCallback(async (to: string, note?: string) => {
    try {
      const res = await authFetch(`${API_BASE}/sessions/${sessionId}/transfer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        // `from` is no longer trusted server-side (derived from the bearer
        // token instead) — kept here only so an old cached client build
        // doesn't send a request the server can't deserialize.
        body: JSON.stringify({ from: ACTOR_ID, to }),
      });
      if (await maybeToastRateLimited(res)) return;
      if (res.status === 401 || res.status === 403) throw new Error("Only the current owner can transfer this session");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      if (note?.trim()) sendMessage(`[Handoff] ${note.trim()}`);
      toast.success(`Ownership transferred to ${to}`);
      // Snapshot will refresh automatically via ownership.transferred WS event.
    } catch (e) {
      toast.error(`Transfer failed: ${e instanceof Error ? e.message : "unknown error"}`);
    }
  }, [sessionId, sendMessage, ACTOR_ID]);

  const activeContextCount = state.contextEntries.filter(e => !e.resolved).length;

  const TABS: { key: CenterTab; label: string; badge?: number }[] = [
    { key: "messages",   label: "Messages"                                        },
    { key: "log",        label: "Activity Log",  badge: logEventCount             },
    { key: "artifacts",  label: "Artifacts",     badge: artifacts.length          },
    { key: "context",    label: "Context",       badge: activeContextCount || undefined },
    { key: "whiteboard", label: "Whiteboard"                                      },
  ];

  // Only pre-first-snapshot: gate on state.snapshot, not state.connected, so
  // later reconnects (phase "reconnecting") keep showing real content instead
  // of blanking back out to a skeleton on every brief network blip.
  if (state.snapshot === null) {
    return <SessionSkeleton />;
  }

  return (
    <div className="flex h-full bg-surface-0 text-primary">
      {/* Shared backdrop for the off-canvas side panels. The isDesktop
          effect resets both open states on a breakpoint crossing, but that
          depends on a matchMedia "change" event actually firing — lg:hidden
          here means a full-screen click-blocking overlay can never survive
          into the static desktop layout even if that JS path is ever
          delayed or missed (e.g. an extremely rapid resize). */}
      {(statusPanelOpen || needsActionOpen) && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => { setStatusPanelOpen(false); setNeedsActionOpen(false); }}
        />
      )}

      {/* Left: Status Panel */}
      <StatusPanel
        sessionId={sessionId}
        sessionName={sessionName}
        snapshot={state.snapshot}
        events={state.events}
        connected={state.connected}
        notMember={state.notMember}
        actorIdReserved={state.actorIdReserved}
        phase={state.phase}
        actorId={ACTOR_ID}
        onTransfer={handleTransfer}
        openManageSignal={openManageSignal}
        mobileOpen={statusPanelOpen}
        onMobileClose={() => setStatusPanelOpen(false)}
      />

      {/* Main column */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Status stripe removed */}

        {/* Top bar: session name + tab strip */}
        <div className="h-[42px] px-5 border-b border-border flex items-center gap-2 md:gap-4 shrink-0">
          {/* Status panel toggle — hidden at lg+, where it's already a
              static column and this button would be redundant. */}
          <button
            onClick={() => setStatusPanelOpen(true)}
            aria-label="Open session status panel"
            aria-expanded={statusPanelOpen}
            aria-controls="status-panel"
            className="lg:hidden shrink-0 text-muted hover:text-subtle p-1 -ml-1"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="6" x2="21" y2="6" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="3" y1="18" x2="21" y2="18" />
            </svg>
          </button>

          <h1 className="text-sm font-semibold text-primary truncate min-w-0 max-w-[140px] md:max-w-[260px]">
            {sessionName}
          </h1>
          <div className="flex items-center gap-0.5 flex-1 overflow-x-auto">
            {TABS.map(t => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                aria-label={t.badge != null && t.badge > 0 ? `${t.label}, ${t.badge}` : undefined}
                className={`relative shrink-0 text-2xs px-3 py-1.5 rounded font-medium transition-colors ${
                  tab === t.key
                    ? "bg-surface-3 text-primary"
                    : "text-muted hover:text-subtle"
                }`}
              >
                {t.label}
                {/* text-subtle on bg-surface-4 measured 4.08:1, just under
                    the 4.5:1 AA floor — text-primary clears 9.8:1 on the
                    same background. */}
                {t.badge != null && t.badge > 0 && (
                  <span aria-hidden="true" className="ml-1.5 text-2xs bg-surface-4 text-primary px-1 py-0.5 rounded font-mono">
                    {t.badge}
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Right-side meta */}
          <div className="flex items-center gap-2 md:gap-3 shrink-0">
            {tab === "log" && logEventCount > 0 && (
              <span className="hidden md:inline text-2xs text-muted font-mono">
                {logEventCount} events · seq {state.events[state.events.length - 1]?.seq ?? 0}
              </span>
            )}
            {tab === "messages" && state.messages.length > 0 && (
              <span className="hidden md:inline text-2xs text-muted">
                {state.messages.length} messages
              </span>
            )}
            {/* Invite User button — label collapses to icon-only below md;
                aria-label keeps the accessible name in sync with the
                visually-hidden text rather than relying on title alone. */}
            <button
              onClick={() => { setInviteOpen(true); setInviteResult(null); setInviteEmail(""); }}
              aria-label="Invite a person to this session"
              className="flex items-center gap-1.5 text-2xs font-medium text-muted hover:text-subtle border border-border hover:border-subtle rounded px-2 py-1 transition-colors"
              title="Invite a person to this session"
            >
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
                <path d="M19 8v6M22 11h-6" />
              </svg>
              <span className="hidden md:inline">Invite User</span>
            </button>

            {/* Attach Agent button — same icon-only collapse below md */}
            <button
              onClick={() => { setAttachOpen(true); setAttachResult(null); setAttachMcpPath(""); }}
              aria-label="Attach an AI agent to this session"
              className="flex items-center gap-1.5 text-2xs font-medium text-muted hover:text-subtle border border-border hover:border-subtle rounded px-2 py-1 transition-colors"
              title="Attach an AI agent to this session"
            >
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 5v14M5 12h14" />
              </svg>
              <span className="hidden md:inline">Attach Agent</span>
            </button>

            {/* Actor identity chip — shows which user this tab is acting as.
                me?.name falls back to the raw id pre-auth or while /me is
                still loading, same pattern as AppNav's card. */}
            <div className="hidden sm:flex items-center gap-1.5 pl-2 border-l border-border">
              <div className="w-4 h-4 rounded-full bg-accent-blue/20 text-accent-blue flex items-center justify-center text-2xs font-semibold shrink-0">
                {(me?.name ?? ACTOR_ID).slice(0, 1).toUpperCase()}
              </div>
              <span className="text-2xs text-muted font-mono">{me?.name ?? ACTOR_ID}</span>
            </div>

            {/* Needs Action panel toggle — hidden at lg+; badges the
                pending-approval count so it stays useful when collapsed. */}
            <button
              onClick={() => setNeedsActionOpen(true)}
              aria-label={`Open needs action panel${pendingCount > 0 ? ` (${pendingCount} pending)` : ""}`}
              aria-expanded={needsActionOpen}
              aria-controls="needs-action-panel"
              className="lg:hidden relative shrink-0 text-muted hover:text-subtle p-1"
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22c1.1 0 2-.9 2-2h-4a2 2 0 0 0 2 2Z" />
                <path d="M18 16v-5a6 6 0 1 0-12 0v5l-2 2h16l-2-2Z" />
              </svg>
              {pendingCount > 0 && (
                <span className="absolute top-0 right-0 w-3.5 h-3.5 rounded-full bg-accent-amber text-surface-0 text-[9px] font-bold leading-[14px] text-center">
                  {pendingCount > 9 ? "9+" : pendingCount}
                </span>
              )}
            </button>
          </div>
        </div>

        <div className="flex flex-1 min-h-0">
          {/* Center panel */}
          <div className="flex-1 flex flex-col min-w-0 border-r border-border overflow-hidden">
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={tab}
                className="flex-1 flex flex-col min-h-0 h-full"
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.12, ease: "easeOut" }}
              >
                {tab === "messages" && (
                  <Messages
                    sessionId={sessionId}
                    messages={state.messages}
                    events={state.events}
                    actorId={ACTOR_ID}
                    actorNames={actorNames}
                    members={state.snapshot?.members.filter(m => m.role !== "agent").map(m => m.actor_id) ?? []}
                    onSend={sendMessage}
                    onArtifactCreated={refreshArtifacts}
                  />
                )}
                {tab === "log" && (
                  <Timeline
                    events={state.events}
                    sessionId={sessionId}
                    pendingCount={pendingCount}
                    actorId={ACTOR_ID}
                    actorNames={actorNames}
                    lastVisitTime={lastVisitTime}
                    onDismissVisitSummary={handleDismissVisitSummary}
                  />
                )}
                {tab === "artifacts" && (
                  <ArtifactsTab artifacts={artifacts} events={state.events} sessionId={sessionId} actorNames={actorNames} />
                )}
                {tab === "context" && (
                  <ContextTab
                    entries={state.contextEntries}
                    onAdd={addContextEntry}
                    onResolve={resolveContextEntry}
                    actorNames={actorNames}
                  />
                )}
                {tab === "whiteboard" && (
                  <Whiteboard
                    sessionId={sessionId}
                    actorId={ACTOR_ID}
                    onSaveSuccess={refreshArtifacts}
                  />
                )}
              </motion.div>
            </AnimatePresence>
          </div>

          {/* Right: Needs Action panel */}
          <NeedsAction
            approvals={state.pendingApprovals}
            snapshot={state.snapshot}
            pastEvents={state.events}
            onApprove={approve}
            onDeny={deny}
            onClaim={claim}
            mobileOpen={needsActionOpen}
            onMobileClose={() => setNeedsActionOpen(false)}
          />
        </div>
      </div>

      {/* ── Invite User modal ────────────────────────────────────────────── */}
      {inviteOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={e => { if (e.target === e.currentTarget) { setInviteOpen(false); } }}
        >
          <div
            ref={inviteModalRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="invite-modal-title"
            className="bg-surface-1 border border-border rounded-xl w-[420px] shadow-elevation-modal overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div>
                <h2 id="invite-modal-title" className="text-sm font-semibold text-primary">Invite User</h2>
                <p className="text-2xs text-muted mt-0.5">Mints a redemption-gated link. Membership is granted only when it's redeemed, not now.</p>
              </div>
              <button onClick={() => setInviteOpen(false)} aria-label="Close" className="text-muted hover:text-subtle text-sm leading-none p-1">✕</button>
            </div>

            <div className="px-4 py-4 space-y-3">
              {/* Role */}
              <div>
                <label htmlFor="invite-role" className="block text-2xs text-muted mb-1 font-medium">Role</label>
                <select
                  id="invite-role"
                  value={inviteRole}
                  onChange={e => setInviteRole(e.target.value)}
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary focus:outline-none focus:border-subtle"
                  disabled={!!inviteResult}
                >
                  <option value="observer">Observer (read-only access)</option>
                  <option value="collaborator">Collaborator (can write to session)</option>
                  <option value="owner">Owner (full administration)</option>
                </select>
              </div>

              {/* Email (optional, named invite) */}
              <div>
                <label htmlFor="invite-email" className="block text-2xs text-muted mb-1 font-medium">
                  Email <span className="text-muted font-normal">(optional)</span>
                </label>
                <input
                  id="invite-email"
                  type="email"
                  value={inviteEmail}
                  onChange={e => setInviteEmail(e.target.value)}
                  placeholder="Leave blank for an anonymous link invite"
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary placeholder:text-muted focus:outline-none focus:border-subtle"
                  disabled={!!inviteResult}
                />
                <p className="text-2xs text-muted mt-1">If set, only that signed-in identity can redeem this invite.</p>
              </div>

              {/* TTL */}
              <div>
                <label htmlFor="invite-ttl" className="block text-2xs text-muted mb-1 font-medium">Invite expires in</label>
                <select
                  id="invite-ttl"
                  value={inviteTtl}
                  onChange={e => setInviteTtl(Number(e.target.value))}
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary focus:outline-none focus:border-subtle"
                  disabled={!!inviteResult}
                >
                  <option value={86400}>1 day</option>
                  <option value={259200}>3 days</option>
                  <option value={604800}>7 days</option>
                </select>
              </div>

              {/* Result */}
              {inviteResult ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-2xs text-accent-green font-medium">Invite created ✓</span>
                    <span className="text-2xs text-muted">
                      expires {new Date(inviteResult.expires_at).toLocaleString()}
                    </span>
                  </div>
                  <div className="relative">
                    <pre className="bg-surface-0 border border-border rounded p-3 text-2xs font-mono text-subtle overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {`${typeof window !== "undefined" ? window.location.origin : ""}/invite/${inviteResult.id}`}
                    </pre>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(`${window.location.origin}/invite/${inviteResult.id}`);
                        toast.success("Copied to clipboard");
                      }}
                      className="absolute top-2 right-2 text-2xs text-muted hover:text-subtle border border-border rounded px-1.5 py-0.5 bg-surface-1"
                    >
                      copy
                    </button>
                  </div>
                  <p className="text-2xs text-muted leading-relaxed">
                    Nothing is added to the session yet. Membership is only granted once this link is redeemed.
                  </p>
                  {inviteResult.mailbox_status !== "not_addressed" && (
                    <p className={`text-2xs leading-relaxed flex items-center gap-1 ${
                      inviteResult.mailbox_status === "delivered" ? "text-accent-green"
                        : inviteResult.mailbox_status === "pending_first_login" ? "text-accent-amber"
                        : "text-accent-red"
                    }`}>
                      {inviteResult.mailbox_status === "delivered" && <>✓ Also added to their Inbox.</>}
                      {inviteResult.mailbox_status === "pending_first_login" && (
                        <>⏳ They haven&apos;t signed in yet — this&apos;ll land in their Inbox the moment they do. The link works either way.</>
                      )}
                      {inviteResult.mailbox_status === "delivery_failed" && (
                        <>⚠ Couldn&apos;t add this to their inbox. the link itself still works, just share it directly.</>
                      )}
                    </p>
                  )}
                </div>
              ) : (
                <button
                  onClick={handleInvite}
                  disabled={inviteLoading}
                  className="w-full py-2 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {inviteLoading ? "Creating invite…" : "Create Invite"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Attach Agent modal ────────────────────────────────────────────── */}
      {attachOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
          onClick={e => { if (e.target === e.currentTarget) { setAttachOpen(false); } }}
        >
          <div
            ref={attachModalRef}
            role="dialog"
            aria-modal="true"
            aria-labelledby="attach-modal-title"
            className="bg-surface-1 border border-border rounded-xl w-[420px] shadow-elevation-modal overflow-hidden"
          >
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div>
                <h2 id="attach-modal-title" className="text-sm font-semibold text-primary">Attach Agent</h2>
                <p className="text-2xs text-muted mt-0.5">Issues a session-scoped token. Paste the command into a fish shell (WSL/Linux) to start the shim.</p>
              </div>
              <button onClick={() => setAttachOpen(false)} aria-label="Close" className="text-muted hover:text-subtle text-sm leading-none p-1">✕</button>
            </div>

            <div className="px-4 py-4 space-y-3">
              {/* Agent ID */}
              <div>
                <label htmlFor="attach-actor-id" className="block text-2xs text-muted mb-1 font-medium">Agent ID</label>
                <input
                  id="attach-actor-id"
                  type="text"
                  value={attachActorId}
                  onChange={e => setAttachActorId(e.target.value)}
                  placeholder="fs-agent"
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary placeholder:text-muted focus:outline-none focus:border-subtle"
                  disabled={!!attachResult}
                />
              </div>

              {/* Filesystem path */}
              <div>
                <label htmlFor="attach-mcp-path" className="block text-2xs text-muted mb-1 font-medium">Filesystem path</label>
                <input
                  id="attach-mcp-path"
                  type="text"
                  value={attachMcpPath}
                  onChange={e => setAttachMcpPath(e.target.value)}
                  placeholder="/mnt/c/Users/you/Documents"
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary placeholder:text-muted focus:outline-none focus:border-subtle font-mono"
                  disabled={!!attachResult}
                />
                <p className="text-2xs text-muted mt-1">The directory the agent will have read or write access to.</p>
              </div>

              {/* TTL */}
              <div>
                <label htmlFor="attach-ttl" className="block text-2xs text-muted mb-1 font-medium">Token expires in</label>
                <select
                  id="attach-ttl"
                  value={attachTtl}
                  onChange={e => setAttachTtl(Number(e.target.value))}
                  className="w-full bg-surface-2 border border-border rounded px-2.5 py-1.5 text-xs text-primary focus:outline-none focus:border-subtle"
                  disabled={!!attachResult}
                >
                  <option value={300}>5 minutes</option>
                  <option value={900}>15 minutes</option>
                  <option value={3600}>1 hour</option>
                </select>
              </div>

              {/* Result */}
              {attachResult ? (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-2xs text-accent-green font-medium">Token issued ✓</span>
                    <span className="text-2xs text-muted">
                      expires {new Date(attachResult.expires_at).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="relative">
                    <pre className="bg-surface-0 border border-border rounded p-3 text-2xs font-mono text-subtle overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {attachResult.launch_cmd}
                    </pre>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(attachResult.launch_cmd);
                        toast.success("Copied to clipboard");
                      }}
                      className="absolute top-2 right-2 text-2xs text-muted hover:text-subtle border border-border rounded px-1.5 py-0.5 bg-surface-1"
                    >
                      copy
                    </button>
                  </div>
                  {/* Called out on its own, not just embedded in the shell
                      snippet above: this cap's SIDECAR_PORT is a per-cap hash,
                      not the fixed 7777 every agent used to share (that was a
                      real bug — two agents minted close together silently
                      collided on the same port, so whichever shim/adapter held
                      it was who your MCP client actually ended up talking to,
                      with zero indication anything had switched). Whatever you
                      point your MCP client at needs to match this exactly. */}
                  <div>
                    <label className="block text-2xs text-muted mb-1 font-medium">MCP URL — point your client here</label>
                    <div className="relative">
                      <pre className="bg-surface-0 border border-border rounded p-2 pr-14 text-2xs font-mono text-accent-blue overflow-x-auto whitespace-pre">
                        {`http://localhost:${attachResult.sidecar_port}`}
                      </pre>
                      <button
                        onClick={() => {
                          navigator.clipboard.writeText(`http://localhost:${attachResult.sidecar_port}`);
                          toast.success("Copied to clipboard");
                        }}
                        className="absolute top-1.5 right-2 text-2xs text-muted hover:text-subtle border border-border rounded px-1.5 py-0.5 bg-surface-1"
                      >
                        copy
                      </button>
                    </div>
                  </div>
                  <p className="text-2xs text-muted leading-relaxed">
                    Requires WSL/Linux with <code className="font-mono bg-surface-2 px-1 rounded">bwrap</code> installed
                    (guardian's sandbox backend). Paste the command as-is since it's already scoped to this agent.
                  </p>
                </div>
              ) : (
                <button
                  onClick={handleAttach}
                  disabled={attachLoading || !attachActorId.trim()}
                  className="w-full py-2 rounded bg-accent-blue text-white text-xs font-medium hover:bg-accent-blue/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                  {attachLoading ? "Issuing token…" : "Issue Token & Attach"}
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
