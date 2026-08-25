"use client";

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import RelativeTime from "@/components/RelativeTime";
import {
  AuthSession, listAuthSessions,
  revokeAuthSession, signIn, signOut,
} from "@/lib/auth";
import { AgentCap, listAgentCaps, revokeAgentCap } from "@/lib/agentCaps";
import {
  Density, getDefaultLanding, getDensity, getSessionSortBy, getSessionSortDirection,
  getSessionView, getTimestampMode, LANDING_OPTIONS, LandingPage,
  resetAllWorkspaceLayouts, SESSION_SORT_OPTIONS, SESSION_VIEW_OPTIONS, SessionSortBy,
  SessionSortDirection, SessionView, setDefaultLanding, setDensity, setSessionSortBy,
  setSessionSortDirection, setSessionView, setTimestampMode, TimestampMode,
} from "@/lib/preferences";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

function SettingsIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="8" cy="8" r="2.5" />
      <path d="M8 1.5V3.2M8 12.8V14.5M1.5 8H3.2M12.8 8H14.5" />
      <path d="M3.4 3.4L4.5 4.5M11.5 11.5L12.6 12.6M12.6 3.4L11.5 4.5M4.5 11.5L3.4 12.6" />
    </svg>
  );
}

const SHORTCUTS: { keys: string[]; description: string }[] = [
  { keys: ["⌘/Ctrl", "K"],     description: "Open the command palette to jump to any session or action" },
  { keys: ["Esc"],             description: "Close the command palette, an open menu, or a session-sync pane" },
  { keys: ["⌘/Ctrl", "Enter"], description: "Submit the current form (message composer, context entry)" },
  { keys: ["@"],               description: "Mention a session member. ↑↓ to navigate matches, Tab to select" },
];

const SECTION_LABEL = "text-[10px] uppercase tracking-[0.10em] text-muted font-semibold mb-3";
const ROW = "flex items-center gap-3 px-4 py-3 rounded-xl border border-border bg-surface-1 panel-shine";
const REVOKE_BTN = "shrink-0 text-2xs px-2 py-1 rounded text-muted hover:text-accent-red hover:bg-surface-3 transition-colors";

export default function SettingsPage() {
  useDocumentTitle("Settings");
  const { authed } = useShellAuth();

  // Preference controls read from localStorage. Start at the same default
  // the server would render, then sync in an effect. Same hydration-mismatch
  // reasoning as RelativeTime's absolute-mode flag.
  const [landing, setLanding]             = useState<LandingPage>("sessions");
  const [timestampMode, setTsMode]        = useState<TimestampMode>("relative");
  const [density, setDensityValue]        = useState<Density>("comfortable");
  const [sessionSort, setSessionSortValue]           = useState<SessionSortBy>("date");
  const [sessionSortDir, setSessionSortDirValue]      = useState<SessionSortDirection>("desc");
  const [sessionView, setSessionViewValue]            = useState<SessionView>("list");
  useEffect(() => {
    setLanding(getDefaultLanding());
    setTsMode(getTimestampMode());
    setDensityValue(getDensity());
    setSessionSortValue(getSessionSortBy());
    setSessionSortDirValue(getSessionSortDirection());
    setSessionViewValue(getSessionView());
  }, []);

  const queryClient = useQueryClient();

  const { data: sessions, isPending: sessionsPending, isError: sessionsError } = useQuery({
    queryKey: ["auth-sessions"],
    queryFn: listAuthSessions,
    enabled: authed,
  });

  const { data: agentCaps, isPending: capsPending, isError: capsError } = useQuery({
    queryKey: ["agent-caps"],
    queryFn: listAgentCaps,
    enabled: authed,
  });

  async function handleRevokeSession(session: AuthSession) {
    try {
      await revokeAuthSession(session.id);
      queryClient.invalidateQueries({ queryKey: ["auth-sessions"] });
      toast.success("Signed out of that device");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to sign out that device");
    }
  }

  async function handleRevokeCap(cap: AgentCap) {
    try {
      await revokeAgentCap(cap.cap_id);
      queryClient.invalidateQueries({ queryKey: ["agent-caps"] });
      toast.success("Agent access revoked");
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to revoke agent access");
    }
  }

  function handleResetLayouts() {
    const n = resetAllWorkspaceLayouts();
    toast.success(n > 0 ? `Cleared ${n} saved workspace layout${n === 1 ? "" : "s"}` : "No saved layouts to clear");
  }

  if (!authed) {
    return (
      <div className="flex h-full items-center justify-center bg-surface-0 text-primary">
        <div className="text-center max-w-sm px-6">
          <h1 className="text-base font-semibold text-primary mb-2">Sign in to Solarplex</h1>
          <button
            onClick={() => signIn("/settings")}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Sign in
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-[740px] mx-auto py-10 px-8">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-3">
          <div className="w-8 h-8 rounded-lg bg-surface-2 border border-border flex items-center justify-center text-subtle">
            <SettingsIcon />
          </div>
          <h1 className="text-base font-semibold text-primary">Settings</h1>
        </div>
        <p className="text-xs text-muted leading-relaxed max-w-md">
          Workspace-level configuration: default approval policies, escalation timeouts,
          identity and authentication, notification transports, and external integrations.
        </p>
      </div>

      {/* ── Preferences ──────────────────────────────────────────────────── */}
      <div className="mb-8">
        <p className={SECTION_LABEL}>Preferences</p>
        <div className={`${ROW} flex-col items-stretch gap-4 !py-4`}>
          <PreferenceRow
            id="pref-landing-page"
            label="Default landing page"
            description="Where a fresh tab lands after signing in"
          >
            <select
              id="pref-landing-page"
              value={landing}
              onChange={e => { const v = e.target.value as LandingPage; setLanding(v); setDefaultLanding(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              {LANDING_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-timestamps"
            label="Timestamps"
            description="Relative (“3 minutes ago”) or absolute dates everywhere"
          >
            <select
              id="pref-timestamps"
              value={timestampMode}
              onChange={e => { const v = e.target.value as TimestampMode; setTsMode(v); setTimestampMode(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              <option value="relative">Relative</option>
              <option value="absolute">Absolute</option>
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-density"
            label="List density"
            description="Row spacing in Sessions, Activity, and Inbox"
          >
            <select
              id="pref-density"
              value={density}
              onChange={e => { const v = e.target.value as Density; setDensityValue(v); setDensity(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              <option value="comfortable">Comfortable</option>
              <option value="compact">Compact</option>
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-session-sort"
            label="Sort sessions by"
            description="Order of the Sessions list"
          >
            <select
              id="pref-session-sort"
              value={sessionSort}
              onChange={e => { const v = e.target.value as SessionSortBy; setSessionSortValue(v); setSessionSortBy(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              {SESSION_SORT_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-session-sort-dir"
            label="Sort direction"
            description="Oldest/A first, or newest/Z first"
          >
            <select
              id="pref-session-sort-dir"
              value={sessionSortDir}
              onChange={e => { const v = e.target.value as SessionSortDirection; setSessionSortDirValue(v); setSessionSortDirection(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              <option value="asc">Ascending</option>
              <option value="desc">Descending</option>
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-session-view"
            label="Session view"
            description="List rows, or a grid of tiles"
          >
            <select
              id="pref-session-view"
              value={sessionView}
              onChange={e => { const v = e.target.value as SessionView; setSessionViewValue(v); setSessionView(v); }}
              className="text-xs bg-surface-2 border border-border rounded px-2 py-1 text-primary"
            >
              {SESSION_VIEW_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </PreferenceRow>

          <PreferenceRow
            id="pref-reset-layouts"
            label="Session-sync layouts"
            description="Clear every saved pane position/size across all sessions"
          >
            <button
              id="pref-reset-layouts"
              onClick={handleResetLayouts}
              className="text-2xs px-2.5 py-1 rounded border border-border text-muted hover:text-subtle hover:bg-surface-3 transition-colors"
            >
              Reset layouts
            </button>
          </PreferenceRow>
        </div>
      </div>

      {/* ── Active agent sessions ───────────────────────────────────────── */}
      <div className="mb-8">
        <p className={SECTION_LABEL}>Active agent sessions</p>
        {capsPending ? (
          <div className="space-y-2">
            <div className="h-[58px] rounded-xl border border-border bg-surface-1 animate-pulse" />
          </div>
        ) : capsError ? (
          <div className="rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
            <p className="text-xs text-muted">Couldn&apos;t load active agent sessions.</p>
          </div>
        ) : (agentCaps ?? []).length === 0 ? (
          <div className="rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
            <p className="text-xs text-muted">No agents currently attached to a session you own.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {(agentCaps ?? []).map(cap => (
              <div key={cap.cap_id} className={ROW}>
                <div className="w-8 h-8 rounded-lg bg-surface-2 border border-border flex items-center justify-center text-subtle shrink-0 text-xs">
                  🤖
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-primary truncate">{cap.actor_id}</span>
                    <span className={`text-2xs px-1.5 py-0.5 rounded border font-medium ${
                      cap.used_at
                        ? "text-accent-green bg-accent-green/10 border-accent-green/20"
                        : "text-accent-amber bg-accent-amber/10 border-accent-amber/20"
                    }`}>
                      {cap.used_at ? "Attached" : "Pending"}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-2xs text-muted">
                    <span className="truncate">{cap.session_name}</span>
                    <span className="text-border select-none">·</span>
                    <span>Expires</span>
                    <RelativeTime date={cap.expires_at} className="text-2xs text-muted" />
                  </div>
                </div>
                <button onClick={() => handleRevokeCap(cap)} className={REVOKE_BTN}>
                  Revoke access
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Sign-in history ─────────────────────────────────────────────── */}
      <div className="mb-8">
        <p className={SECTION_LABEL}>Sign-in history</p>

        {sessionsPending ? (
          <div className="space-y-2">
            {[0, 1].map(i => (
              <div key={i} className="h-[58px] rounded-xl border border-border bg-surface-1 animate-pulse" />
            ))}
          </div>
        ) : sessionsError ? (
          <div className="rounded-xl border border-border bg-surface-1 panel-shine p-6 text-center">
            <p className="text-xs text-muted">Couldn&apos;t load sign-in history.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {(sessions ?? []).map(s => (
              <div key={s.id} className={ROW}>
                <div className="w-8 h-8 rounded-lg bg-surface-2 border border-border flex items-center justify-center text-subtle shrink-0 text-2xs font-semibold uppercase">
                  {s.provider.slice(0, 2)}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-primary capitalize">{s.provider}</span>
                    {s.is_current && (
                      <span className="text-2xs px-1.5 py-0.5 rounded border font-medium text-accent-green bg-accent-green/10 border-accent-green/20">
                        This device
                      </span>
                    )}
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-2xs text-muted">
                    <span>Last active</span>
                    <RelativeTime date={s.last_seen} className="text-2xs text-muted" />
                    <span className="text-border select-none">·</span>
                    <span>Signed in</span>
                    <RelativeTime date={s.issued_at} className="text-2xs text-muted" />
                  </div>
                </div>
                {s.is_current ? (
                  <button onClick={signOut} className={REVOKE_BTN}>Sign out</button>
                ) : (
                  <button onClick={() => handleRevokeSession(s)} className={REVOKE_BTN}>Sign out this device</button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* ── Keyboard shortcuts ──────────────────────────────────────────── */}
      <div className="mb-8">
        <p className={SECTION_LABEL}>Keyboard shortcuts</p>
        <div className="rounded-xl border border-border bg-surface-1 panel-shine divide-y divide-border">
          {SHORTCUTS.map(s => (
            <div key={s.description} className="flex items-center gap-4 px-4 py-2.5">
              <div className="flex items-center gap-1 shrink-0 w-28">
                {s.keys.map((k, i) => (
                  <kbd key={i} className="text-2xs px-1.5 py-0.5 rounded border border-border bg-surface-2 text-subtle font-mono">
                    {k}
                  </kbd>
                ))}
              </div>
              <span className="text-xs text-muted">{s.description}</span>
            </div>
          ))}
        </div>
        <p className="mt-2 text-2xs text-muted leading-relaxed">
          In WezTerm specifically: click any <code className="text-2xs font-mono text-accent-blue">solarplex://</code> link
          to jump straight to that entity, or select text and press Alt+Enter to plumb it.
        </p>
      </div>
    </div>
  );
}

function PreferenceRow({
  id, label, description, children,
}: {
  /** Paired with the control's own `id` via htmlFor — the control (passed
   *  as children) is responsible for setting `id={id}` on itself. */
  id: string;
  label: string;
  description: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="min-w-0">
        <label htmlFor={id} className="block text-xs font-medium text-primary">{label}</label>
        <p className="text-2xs text-muted">{description}</p>
      </div>
      {children}
    </div>
  );
}
