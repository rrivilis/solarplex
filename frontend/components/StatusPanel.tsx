"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { toast } from "sonner";
import { AnimatePresence, motion } from "framer-motion";
import { SessionSnapshot, WsEnvelope } from "@/lib/types";
import { ConnectionPhase } from "@/lib/ws";
import SessionMinimap, { SessionMinimapLegend } from "@/components/SessionMinimap";
import OwnershipPanel from "@/components/OwnershipPanel";
import SolarplexLogo from "@/components/SolarplexLogo";
import RelativeTime from "@/components/RelativeTime";
import { API_BASE } from "@/lib/env";
import { authFetch } from "@/lib/auth";
import { useModalA11y } from "@/hooks/useModalA11y";

interface Props {
  sessionId: string;
  sessionName: string;
  snapshot: SessionSnapshot | null;
  events: WsEnvelope[];
  connected: boolean;
  notMember?: boolean;
  actorIdReserved?: boolean;
  phase?: ConnectionPhase;
  actorId: string;
  onTransfer: (to: string, note?: string) => Promise<void>;
  // Bumped (any change, value itself unused) by the CommandPalette
  // "Command" bridge (GlobalCommandPalette's sol:open-manage event) to
  // force the lifecycle Manage dropdown open — e.g. after parsing "pause
  // session" as a command. Purely a request to open; the user still picks
  // Pause/Resume/Archive and confirms themselves.
  openManageSignal?: number;
  // Below the lg breakpoint this panel renders as an off-canvas overlay
  // instead of a static column (the fixed 240px + 288px of both side
  // panels alone exceeds a 320px viewport — WCAG 1.4.10 Reflow). The
  // parent owns open state so it can also render the shared backdrop.
  mobileOpen: boolean;
  onMobileClose: () => void;
}

const STATUS_CFG: Record<string, { dot: string; label: string; color: string; glow?: string }> = {
  active:              { dot: "bg-accent-green", label: "Active",        color: "text-accent-green", glow: "shadow-[0_0_8px_rgba(62,207,142,0.5)]" },
  attention_requested: { dot: "bg-accent-amber", label: "Attention",     color: "text-accent-amber", glow: "shadow-[0_0_8px_rgba(245,166,35,0.6)]" },
  action_needed:       { dot: "bg-accent-red",   label: "Action Needed", color: "text-accent-red",   glow: "shadow-[0_0_8px_rgba(245,101,101,0.7)]" },
  policy_update:       { dot: "bg-accent-blue",  label: "Policy Update", color: "text-accent-blue",  glow: "shadow-[0_0_8px_rgba(79,142,247,0.5)]" },
  suspended:           { dot: "bg-accent-amber", label: "Suspended",     color: "text-accent-amber" },
  archived:            { dot: "bg-muted",        label: "Archived",      color: "text-muted"        },
};

const AGENT_CFG: Record<string, { dot: string; label: string; color: string }> = {
  running: { dot: "bg-accent-green",             label: "Running", color: "text-accent-green" },
  waiting: { dot: "bg-accent-amber",             label: "Waiting", color: "text-accent-amber" },
  blocked: { dot: "bg-accent-red",               label: "Blocked", color: "text-accent-red"   },
  error:   { dot: "bg-accent-red animate-pulse", label: "Error",   color: "text-accent-red"   },
  idle:    { dot: "bg-surface-4",                label: "Idle",    color: "text-muted"        },
};

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="py-3.5 border-b border-border last:border-0">
      <p className="text-2xs uppercase tracking-widest text-muted font-medium mb-2">{label}</p>
      {children}
    </div>
  );
}

export default function StatusPanel({ sessionId, sessionName, snapshot, events, connected, notMember, actorIdReserved, phase, actorId, onTransfer, openManageSignal, mobileOpen, onMobileClose }: Props) {
  const containerRef = useModalA11y<HTMLElement>(mobileOpen, onMobileClose);
  const snapshotStatus = snapshot?.status ?? "active";
  const owner = snapshot?.owner;
  const members = snapshot?.members ?? [];
  const humans = members.filter(m => m.role !== "agent");
  const agents = members.filter(m => m.role === "agent");
  // Events (Last Event, below) correctly keep storing the raw actor_id
  // forever — resolved here from the same already-enriched members list
  // used for Owner/Humans/Agents, so a rename shows up retroactively.
  const actorNames = Object.fromEntries(members.map(m => [m.actor_id, m.name]));
  const pendingCount = snapshot?.pending_approvals.length ?? 0;
  const attachedCount = humans.filter(h => h.attached).length;

  const agentCounts = agents.reduce<Record<string, number>>((acc, a) => {
    const s = a.status ?? "idle";
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {});

  const lastEvents = [...events]
    .filter(e => e.actor && e.type !== "session.snapshot" && e.timestamp)
    .slice(-6)
    .reverse()
    .slice(0, 3);

  // ── Lifecycle Manage state ─────────────────────────────────────────────────
  const [manageOpen,    setManageOpen]    = useState(false);
  const [pauseConfirm,  setPauseConfirm]  = useState(false);
  const [archiveConfirm, setArchiveConfirm] = useState(false);
  const [lifecycleBusy, setLifecycleBusy] = useState(false);
  // Optimistic local override so the button swaps immediately on API success
  // without waiting for the WS event round-trip.
  const [localStatus, setLocalStatus]    = useState<string | null>(null);

  // When the WS event arrives and the snapshot prop updates, clear the optimistic value.
  useEffect(() => { setLocalStatus(null); }, [snapshotStatus]);

  useEffect(() => { if (openManageSignal) setManageOpen(true); }, [openManageSignal]);

  // Collapse the manage panel immediately when this actor loses ownership
  // (ownership.transferred WS event updates snapshot → isOwner flips → this fires).
  const isOwner = !!owner && actorId === owner;
  useEffect(() => {
    if (!isOwner) {
      setManageOpen(false);
      setPauseConfirm(false);
      setArchiveConfirm(false);
    }
  }, [isOwner]);

  const status      = localStatus ?? snapshotStatus;
  const sCfg        = STATUS_CFG[status] ?? STATUS_CFG.active;
  const isSuspended = status === "suspended";
  const isArchived  = status === "archived";

  function openManage() {
    setManageOpen(v => !v);
    setPauseConfirm(false);
    setArchiveConfirm(false);
  }

  async function applyLifecycle(next: string) {
    setLifecycleBusy(true);
    try {
      const res = await authFetch(`${API_BASE}/sessions/${sessionId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: next, actor_id: actorId }),
      });
      if (res.status === 401 || res.status === 403) throw new Error("You need Collaborator access or higher to change session status");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // Optimistic update — swap immediately, WS event will confirm
      setLocalStatus(next);
      setPauseConfirm(false);
      setArchiveConfirm(false);
      if (next === "archived") setManageOpen(false);
      const label: Record<string, string> = {
        suspended: "Session paused",
        active:    "Session reactivated",
        archived:  "Session archived",
      };
      toast.success(label[next] ?? "Status updated");
    } catch (e) {
      toast.error(`Failed: ${e instanceof Error ? e.message : "unknown"}`);
    } finally {
      setLifecycleBusy(false);
    }
  }

  return (
    <aside
      id="status-panel"
      ref={containerRef}
      role={mobileOpen ? "dialog" : undefined}
      aria-modal={mobileOpen ? true : undefined}
      aria-label={mobileOpen ? "Session status" : undefined}
      className={`fixed inset-y-0 left-0 z-50 w-[240px] shrink-0 border-r border-border sidebar-surface panel-shine flex flex-col overflow-y-auto transform transition-transform duration-200 ease-out ${
        mobileOpen ? "translate-x-0" : "-translate-x-full"
      } lg:static lg:z-auto lg:translate-x-0 lg:transition-none`}
    >
      {/* Logo */}
      <div className="h-11 shrink-0 flex items-center gap-2.5 px-3.5 border-b border-border">
        <Link
          href="/"
          className="flex items-center gap-2.5 select-none group"
          aria-label="Solarplex — back to sessions"
        >
          <SolarplexLogo size={26} className="opacity-90 group-hover:opacity-100 transition-opacity" />
          <span className="flex items-baseline gap-0">
            <span className="font-serif font-light text-[14px] tracking-[-0.01em] text-subtle leading-none group-hover:text-subtle/80 transition-colors">
              Solar
            </span>
            <span className="font-grotesk font-semibold text-[14px] tracking-[-0.03em] text-primary leading-none group-hover:text-accent-blue transition-colors">
              plex
            </span>
          </span>
        </Link>
        {mobileOpen && (
          <button
            onClick={onMobileClose}
            aria-label="Close session status panel"
            className="ml-auto text-muted hover:text-subtle text-sm leading-none p-1"
          >
            ✕
          </button>
        )}
      </div>

      {/* tabIndex: a scrollable region with no focusable way in is
          unreachable by keyboard — Tab now lands here, then native
          arrow/Page Up/Down/Space scrolling works without a mouse. */}
      <div tabIndex={0} className="flex-1 overflow-y-auto px-4">

        {/* ── Session Status — with owner-only lifecycle Manage ──────────────── */}
        <div className="py-3.5 border-b border-border">
          {/* Header row */}
          <div className="flex items-center justify-between mb-2">
            <p className="text-2xs uppercase tracking-widest text-muted font-medium">Session Status</p>
            <AnimatePresence>
              {isOwner && !isArchived && (
                <motion.button
                  key="manage-btn"
                  initial={{ opacity: 0, scale: 0.85 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.85 }}
                  transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
                  onClick={openManage}
                  className="flex items-center gap-1 text-2xs text-muted hover:text-subtle transition-colors"
                >
                  <span>Manage</span>
                  <motion.span
                    animate={{ rotate: manageOpen ? 90 : 0 }}
                    transition={{ duration: 0.18, ease: "easeInOut" }}
                    className="inline-block leading-none"
                    style={{ fontSize: 10 }}
                  >
                    ▶
                  </motion.span>
                </motion.button>
              )}
            </AnimatePresence>
          </div>

          {/* Status dot + label */}
          <div className="flex items-center gap-2">
            <span className={`w-2 h-2 rounded-full shrink-0 ${sCfg.dot} ${sCfg.glow ?? ""}`} />
            <span className={`text-sm font-semibold ${sCfg.color}`}>{sCfg.label}</span>
          </div>
          <p className="text-2xs text-muted mt-1 font-mono">{sessionId.slice(0, 12)}</p>
          <div className="flex items-center gap-1.5 mt-1">
            <span className={`w-1 h-1 rounded-full ${
              connected ? "bg-accent-green" : (notMember || actorIdReserved || phase === "rejected") ? "bg-accent-red" : "bg-muted"
            }`} />
            {/* aria-live: this text already existed, but its transitions
                (Connected -> Reconnecting… mid-session, say) went
                unannounced — a screen reader user only found out by
                navigating back here manually. */}
            <span
              aria-live="polite"
              className={`text-2xs ${(notMember || actorIdReserved || phase === "rejected") ? "text-accent-red" : "text-muted"}`}
            >
              {connected ? "Connected"
                : notMember ? "Not a member"
                : actorIdReserved ? "Name unavailable"
                : phase === "rejected" ? "Connection rejected"
                : phase === "connecting" ? "Connecting…"
                : "Reconnecting…"}
            </span>
          </div>
          {notMember && (
            <p className="text-2xs text-muted mt-2 leading-relaxed">
              You are not a member of this session. Ask the owner to add you, or join via an invite link containing a token.
            </p>
          )}
          {actorIdReserved && (
            <p className="text-2xs text-muted mt-2 leading-relaxed">
              That name is already registered to a signed-in account. Pick a different name, or sign in if it&rsquo;s yours.
            </p>
          )}

          {/* Lifecycle controls — animated collapse */}
          <AnimatePresence initial={false}>
            {manageOpen && (
              <motion.div
                key="lifecycle-body"
                initial={{ height: 0, opacity: 0 }}
                animate={{ height: "auto", opacity: 1 }}
                exit={{ height: 0, opacity: 0 }}
                transition={{ duration: 0.22, ease: [0.4, 0, 0.2, 1] }}
                style={{ overflow: "hidden" }}
              >
                <div className="mt-3 pt-2.5 border-t border-border/50 space-y-2">

                  {/* Pause / Reactivate */}
                  {isSuspended ? (
                    <button
                      disabled={lifecycleBusy}
                      onClick={() => applyLifecycle("active")}
                      className="w-full text-left text-xs px-3 py-2 rounded-lg border border-accent-green/30 bg-accent-green/10 text-accent-green hover:bg-accent-green/20 transition-colors disabled:opacity-50"
                    >
                      Reactivate Session
                    </button>
                  ) : !pauseConfirm ? (
                    <button
                      disabled={lifecycleBusy}
                      onClick={() => { setPauseConfirm(true); setArchiveConfirm(false); }}
                      className="w-full text-left text-xs px-3 py-2 rounded-lg border border-accent-amber/30 bg-accent-amber/10 text-accent-amber hover:bg-accent-amber/20 transition-colors disabled:opacity-50"
                    >
                      Pause Session
                    </button>
                  ) : (
                    <div className="rounded-lg border border-accent-amber/30 bg-accent-amber/5 p-2.5 space-y-2">
                      <p className="text-2xs text-accent-amber leading-relaxed">
                        Pause this session? This will suspend operations until reactivated.
                      </p>
                      <div className="flex gap-1.5">
                        <button
                          disabled={lifecycleBusy}
                          onClick={() => applyLifecycle("suspended")}
                          className="flex-1 text-2xs font-medium py-1.5 rounded-lg bg-accent-amber/10 border border-accent-amber/30 text-accent-amber hover:bg-accent-amber/20 transition-colors disabled:opacity-50"
                        >
                          Pause
                        </button>
                        <button
                          onClick={() => setPauseConfirm(false)}
                          className="px-3 text-2xs font-medium py-1.5 rounded-lg bg-surface-3 border border-border text-muted hover:text-subtle transition-colors"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Archive */}
                  {!archiveConfirm ? (
                    <button
                      disabled={lifecycleBusy}
                      onClick={() => { setArchiveConfirm(true); setPauseConfirm(false); }}
                      className="w-full text-left text-xs px-3 py-2 rounded-lg border border-border text-muted hover:text-subtle hover:border-subtle transition-colors disabled:opacity-50"
                    >
                      Archive Session
                    </button>
                  ) : (
                    <div className="rounded-lg border border-accent-red/30 bg-accent-red/5 p-2.5 space-y-2">
                      <p className="text-2xs text-accent-red leading-relaxed">
                        Archive this session? It will become read-only and cannot be reactivated.
                      </p>
                      <div className="flex gap-1.5">
                        <button
                          disabled={lifecycleBusy}
                          onClick={() => applyLifecycle("archived")}
                          className="flex-1 text-2xs font-medium py-1.5 rounded-lg bg-accent-red/10 border border-accent-red/30 text-accent-red hover:bg-accent-red/20 transition-colors disabled:opacity-50"
                        >
                          Archive
                        </button>
                        <button
                          onClick={() => setArchiveConfirm(false)}
                          className="px-3 text-2xs font-medium py-1.5 rounded-lg bg-surface-3 border border-border text-muted hover:text-subtle transition-colors"
                        >
                          Cancel
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Cross-session sync — opens the live multi-session workspace */}
                  <Link
                    href={`/sessions/${sessionId}/sync`}
                    className="w-full text-left text-xs px-3 py-2 rounded-lg border border-accent-blue/30 bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 transition-colors flex items-center justify-between"
                  >
                    <span>Session Sync</span>
                    <span className="text-2xs opacity-70">↗</span>
                  </Link>

                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        <OwnershipPanel
          sessionId={sessionId}
          snapshot={snapshot}
          actorId={actorId}
          onTransfer={onTransfer}
        />

        <Section label="Humans">
          {humans.length === 0 ? (
            <div className="flex items-center gap-2 py-0.5">
              <div className="w-4 h-4 rounded bg-surface-3 border border-border flex items-center justify-center shrink-0">
                <span className="text-muted text-2xs leading-none">+</span>
              </div>
              <span className="text-xs text-muted">No collaborators yet</span>
            </div>
          ) : (
            <>
              <p className="text-xs text-subtle mb-2">
                {attachedCount} of {humans.length} attached
              </p>
              <div className="space-y-1">
                {humans.map(h => (
                  <div key={h.actor_id} className="flex items-center gap-2">
                    <div className={`w-4 h-4 rounded-full flex items-center justify-center text-2xs font-semibold shrink-0 ${
                      h.attached ? "bg-accent-blue/20 text-accent-blue" : "bg-surface-3 text-muted"
                    }`}>
                      {(h.name || h.actor_id).slice(0, 2).toUpperCase()}
                    </div>
                    <span className="text-xs text-subtle flex-1 truncate">{h.name || h.actor_id}</span>
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${h.attached ? "bg-accent-green" : "bg-surface-4"}`} />
                  </div>
                ))}
              </div>
            </>
          )}
        </Section>

        <Section label="Agents">
          {agents.length === 0 ? (
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <div className="w-4 h-4 rounded bg-surface-3 border border-border flex items-center justify-center shrink-0">
                  <span className="text-muted text-2xs leading-none">+</span>
                </div>
                <span className="text-xs text-muted">No agents attached</span>
              </div>
              <p className="text-2xs text-muted leading-relaxed pl-6">
                Attach an agent to begin supervised execution.
              </p>
            </div>
          ) : (
            <>
              <div className="flex flex-wrap gap-x-2.5 gap-y-0.5 mb-2">
                {Object.entries(agentCounts).map(([s, n]) => {
                  const cfg = AGENT_CFG[s] ?? AGENT_CFG.idle;
                  return (
                    <span key={s} className={`text-2xs font-medium ${cfg.color}`}>
                      {n} {cfg.label.toLowerCase()}
                    </span>
                  );
                })}
              </div>
              <div className="space-y-1">
                {agents.map(a => {
                  const cfg = AGENT_CFG[a.status ?? "idle"] ?? AGENT_CFG.idle;
                  return (
                    <div key={a.actor_id} className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full shrink-0 ${cfg.dot}`} />
                      <span className="text-xs text-subtle flex-1 truncate">{a.name || a.actor_id}</span>
                      <span className={`text-2xs font-medium ${cfg.color}`}>{cfg.label}</span>
                    </div>
                  );
                })}
              </div>
            </>
          )}
        </Section>

        <Section label="Approvals">
          {pendingCount === 0 ? (
            <span className="text-xs text-muted">None pending</span>
          ) : (
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-accent-amber animate-pulse shrink-0" />
              <span className="text-xs font-semibold text-accent-amber">
                {pendingCount} pending
              </span>
            </div>
          )}
        </Section>

        <Section label="Last Event">
          {lastEvents.length === 0 ? (
            <span className="text-xs text-muted">No events yet</span>
          ) : (
            <div className="space-y-1.5">
              {lastEvents.map(e => (
                <div key={e.id} className="flex items-center justify-between gap-2">
                  <span className="text-xs text-subtle truncate">{(e.actor && actorNames[e.actor]) ?? e.actor}</span>
                  <RelativeTime
                    date={e.timestamp}
                    className="text-2xs text-muted shrink-0 tabular-nums"
                  />
                </div>
              ))}
            </div>
          )}
        </Section>

        <Section label="Legend">
          <SessionMinimap snapshot={snapshot} events={events} />
          <SessionMinimapLegend />
        </Section>

      </div>
    </aside>
  );
}
