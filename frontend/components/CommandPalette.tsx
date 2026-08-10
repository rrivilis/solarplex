"use client";

import { useEffect, useRef, useState } from "react";
import { Command } from "cmdk";
import { useQuery } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useDebounced } from "@/hooks/useDebounced";
import { search as searchApi } from "@/lib/search";
import { parseIntent } from "@/lib/intent";

interface Action {
  id: string;
  label: string;
  hint?: string;
  group: string;
  run: () => void;
}

interface Props {
  sessionId?: string;
  onSwitchTab?: (tab: string) => void;
  onTransfer?: () => void;
  onOpenManage?: () => void;
  onOpenNeedsAction?: () => void;
  onOpenInvite?: (role?: string, email?: string, ttlSecs?: number) => void;
  onNewSession?: () => void;
  onOpenAttach?: (name?: string, ttlSecs?: number) => void;
}

/** The Invite modal's TTL <select> only offers these three fixed options
 *  (see app/sessions/[id]/page.tsx) — a parsed duration ("2 days") gets
 *  rounded up to the nearest one it can actually prefill, capped at 7 days
 *  rather than silently allowing something the dropdown can't represent. */
function clampInviteTtl(secs: number): 86400 | 259200 | 604800 {
  if (secs <= 86400) return 86400;
  if (secs <= 259200) return 259200;
  return 604800;
}
const INVITE_TTL_LABEL: Record<number, string> = { 86400: "1 day", 259200: "3 days", 604800: "7 days" };

/** Same idea, the Attach Agent modal's own three fixed options — a much
 *  shorter scale than invite's (these are live agent tokens, not standing
 *  invitations). */
function clampAttachTtl(secs: number): 300 | 900 | 3600 {
  if (secs <= 300) return 300;
  if (secs <= 900) return 900;
  return 3600;
}
const ATTACH_TTL_LABEL: Record<number, string> = { 300: "5 minutes", 900: "15 minutes", 3600: "1 hour" };

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export default function CommandPalette({ sessionId, onSwitchTab, onTransfer, onOpenManage, onOpenNeedsAction, onOpenInvite, onNewSession, onOpenAttach }: Props) {
  const [open, setOpen]   = useState(false);
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounced(query, 200);
  const router = useRouter();

  // ⌘K / Ctrl+K to open
  useEffect(() => {
    function handleKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen(o => !o);
      }
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, []);

  // Reset the input each time the palette closes — reopening should never
  // show a stale query from the last time it was used.
  useEffect(() => {
    if (!open) setQuery("");
  }, [open]);

  // Return focus to whatever triggered the palette once it closes. No Tab
  // trap here (unlike the other modals in this app, via useModalA11y) —
  // cmdk's Command.Input/Command.List already implement full combobox
  // keyboard semantics (arrow-key navigation with focus staying on the
  // input), and layering a generic trap on top risks fighting that model
  // rather than helping it. Escape-to-close is likewise already handled by
  // the ⌘K listener above.
  const triggerRef = useRef<Element | null>(null);
  useEffect(() => {
    if (open) {
      triggerRef.current = document.activeElement;
    } else if (triggerRef.current instanceof HTMLElement) {
      triggerRef.current.focus();
    }
  }, [open]);

  // Live cross-session search — sessions and artifacts only (not people or
  // raw events): a command palette's job is "take me somewhere," and
  // there's no per-actor destination page to jump to yet. Deep event
  // search stays on the dedicated Search page. Same 2-char floor the
  // server enforces (see lib/search.ts).
  const { data: results } = useQuery({
    queryKey: ["palette-search", debouncedQuery],
    queryFn: () => searchApi(debouncedQuery, 5),
    enabled: open && debouncedQuery.trim().length >= 2,
    staleTime: 10_000,
  });

  // Deterministic governance-command parse (crates/intent — grammar match,
  // not fuzzy search). Not gated on sessionId — a command can name its own
  // target session ("pause session in roman-room1"), so this needs to work
  // from anywhere (e.g. the sessions list), not just from inside a session.
  // A parse always *proposes*: selecting it opens the existing,
  // already-authorized UI surface for that action (or navigates to the
  // target session) rather than executing anything off free text directly.
  const { data: parsedIntent } = useQuery({
    queryKey: ["palette-intent", debouncedQuery],
    queryFn: () => parseIntent(debouncedQuery),
    enabled: open && debouncedQuery.trim().length >= 3,
    staleTime: 10_000,
  });

  const intentAction: Action | null = (() => {
    if (!parsedIntent) return null;
    const { intent, target_session, resolution } = parsedIntent;
    const targetResolved = resolution.target_session;

    // Which session does this command actually act on? An explicit,
    // resolved target session wins; otherwise fall back to wherever the
    // palette was opened from.
    let effectiveSessionId: string | undefined;
    let hint = "command";
    if (target_session) {
      if (targetResolved?.status === "matched") {
        effectiveSessionId = targetResolved.id;
      } else {
        hint = targetResolved?.status === "ambiguous" ? "ambiguous session" : "session not found";
      }
    } else {
      effectiveSessionId = sessionId;
    }
    // Nothing to act on: no current session context, and no (or unresolved)
    // named target — recognizing the verb alone isn't useful.
    if (!effectiveSessionId && !target_session) return null;

    const suffix = target_session
      ? ` in ${targetResolved?.status === "matched" ? targetResolved.name : `"${target_session}"`}`
      : "";

    // Same session as the current context → drive the local UI surface
    // (Manage dropdown, Invite modal, ...) directly. A different (or
    // unresolved) target → navigate there instead, carrying `?open=...`
    // (+`role` for invite) so the destination session page opens the same
    // surface on arrival — see the matching effect in
    // app/sessions/[id]/page.tsx, keyed off that query param.
    function dispatch(localAction: () => void, remoteOpen: string) {
      if (effectiveSessionId && effectiveSessionId === sessionId) { localAction(); return; }
      if (effectiveSessionId) { router.push(`/sessions/${effectiveSessionId}${remoteOpen ? `?${remoteOpen}` : ""}`); return; }
      router.push("/");
    }

    switch (intent.kind) {
      case "pause":
        return { id: "intent-pause", label: `Pause session${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenManage?.(), "open=manage") };
      case "resume":
        return { id: "intent-resume", label: `Resume session${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenManage?.(), "open=manage") };
      case "archive":
        return { id: "intent-archive", label: `Archive session${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenManage?.(), "open=manage") };
      case "approve":
        return { id: "intent-approve", label: `Approve — open pending approvals${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenNeedsAction?.(), "open=needs-action") };
      case "deny":
        return { id: "intent-deny", label: `Deny — open pending approvals${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenNeedsAction?.(), "open=needs-action") };
      case "claim":
        return { id: "intent-claim", label: `Claim — open pending approvals${suffix}`, hint, group: "Command", run: () => dispatch(() => onOpenNeedsAction?.(), "open=needs-action") };
      case "invite": {
        const who = intent.invitee ? ` ${intent.invitee}` : "";
        // The invitee text itself might just *be* an email ("invite
        // bob@gmail.com") — an external invite, not necessarily anyone
        // already a co-member. Otherwise, if it resolved to a real
        // co-member, use *their* actual email rather than just echoing
        // back the typed name.
        const resolvedActor = resolution.actor?.status === "matched" ? resolution.actor : undefined;
        const email = (intent.invitee && EMAIL_RE.test(intent.invitee)) ? intent.invitee : resolvedActor?.email;
        const ttlSecs = intent.ttl_secs ? clampInviteTtl(intent.ttl_secs) : undefined;
        const emailHint = email ? ` (${email})` : "";
        const ttlHint = ttlSecs ? `, expires in ${INVITE_TTL_LABEL[ttlSecs]}` : "";
        const remoteOpen = `open=invite&role=${encodeURIComponent(intent.role)}`
          + (email ? `&email=${encodeURIComponent(email)}` : "")
          + (ttlSecs ? `&ttl=${ttlSecs}` : "");
        return {
          id: "intent-invite", label: `Invite${who} as ${intent.role}${emailHint}${ttlHint}${suffix}`, hint, group: "Command",
          run: () => dispatch(() => onOpenInvite?.(intent.role, email, ttlSecs), remoteOpen),
        };
      }
      case "transfer_ownership":
        return { id: "intent-transfer", label: `Transfer ownership to ${intent.to}${suffix}`, hint, group: "Command", run: () => dispatch(() => onTransfer?.(), "open=transfer") };
      case "navigate": {
        const dest = targetResolved?.status === "matched" ? targetResolved.name : (target_session ?? "");
        return { id: "intent-navigate", label: `Go to ${dest}`, hint, group: "Command", run: () => dispatch(() => {}, "") };
      }
      case "attach_agent": {
        const who = intent.name ? ` ${intent.name}` : "";
        const ttlSecs = intent.ttl_secs ? clampAttachTtl(intent.ttl_secs) : undefined;
        const ttlHint = ttlSecs ? `, expires in ${ATTACH_TTL_LABEL[ttlSecs]}` : "";
        const remoteOpen = "open=attach"
          + (intent.name ? `&name=${encodeURIComponent(intent.name)}` : "")
          + (ttlSecs ? `&ttl=${ttlSecs}` : "");
        return {
          id: "intent-attach", label: `Attach agent${who}${ttlHint}${suffix}`, hint, group: "Command",
          run: () => dispatch(() => onOpenAttach?.(intent.name ?? undefined, ttlSecs), remoteOpen),
        };
      }
      default:
        return null;
    }
  })();

  const staticActions: Action[] = [
    // Navigate — mirrors AppNav's full route list, not just the two spots
    // this palette knew about before (Sessions/New Session only).
    { id: "home",      label: "Go to Sessions",        hint: "Home", group: "Navigate", run: () => router.push("/") },
    { id: "new",       label: "New Session",           hint: "⌘N",   group: "Navigate", run: () => onNewSession?.() },
    { id: "inbox",     label: "Go to Inbox",           group: "Navigate", run: () => router.push("/inbox") },
    { id: "activity",  label: "Go to Recent Activity", group: "Navigate", run: () => router.push("/activity") },
    { id: "search",    label: "Go to Search",          group: "Navigate", run: () => router.push("/search") },
    { id: "team",      label: "Go to Teammates",       group: "Navigate", run: () => router.push("/team") },
    { id: "agents",    label: "Go to Agents",          group: "Navigate", run: () => router.push("/agents") },
    { id: "settings",  label: "Go to Settings",        group: "Navigate", run: () => router.push("/settings") },
    ...(sessionId ? [
      // Tabs
      { id: "tab-msg",  label: "Open Messages",     hint: "tab",    group: "Session", run: () => onSwitchTab?.("messages") },
      { id: "tab-log",  label: "Open Activity Log", hint: "tab",    group: "Session", run: () => onSwitchTab?.("log") },
      { id: "tab-art",  label: "Open Artifacts",    hint: "tab",    group: "Session", run: () => onSwitchTab?.("artifacts") },
      { id: "tab-ctx",  label: "Open Context",      hint: "tab",    group: "Session", run: () => onSwitchTab?.("context") },
      { id: "tab-wb",   label: "Open Whiteboard",   hint: "tab",    group: "Session", run: () => onSwitchTab?.("whiteboard") },
      // Cross-session
      { id: "sync",     label: "Open Sync Workspace", hint: "cross-session", group: "Session", run: () => router.push(`/sessions/${sessionId}/sync`) },
      // Ownership
      { id: "transfer", label: "Transfer Ownership", hint: "action", group: "Session", run: () => onTransfer?.() },
    ] : []),
  ];

  const filteredStatic = query.trim()
    ? staticActions.filter(a => a.label.toLowerCase().includes(query.toLowerCase()))
    : staticActions;

  // Search-result actions are already server-filtered by `debouncedQuery` —
  // re-filtering them against the raw (not-yet-debounced) `query` would
  // flicker them out on every keystroke ahead of the query settling, so
  // they're appended as-is rather than run through the same label filter.
  const dynamicActions: Action[] = results ? [
    ...results.sessions.map(s => ({
      id: `s-${s.id}`, label: s.name, hint: "session",
      group: "Jump to session",
      run: () => router.push(`/sessions/${s.id}`),
    })),
    ...results.artifacts.map(a => ({
      id: `a-${a.id}`, label: `${a.name} — ${a.session_name}`, hint: "artifact",
      group: "Jump to artifact",
      run: () => router.push(`/sessions/${a.session_id}?tab=artifacts`),
    })),
  ] : [];

  const filtered = [...(intentAction ? [intentAction] : []), ...filteredStatic, ...dynamicActions];
  // "Command" always leads when present — a parsed intent is the most
  // specific match for whatever was just typed.
  const groups = [...new Set(filtered.map(a => a.group))].sort((a, b) => (a === "Command" ? -1 : b === "Command" ? 1 : 0));

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]"
      onClick={(e) => { if (e.target === e.currentTarget) setOpen(false); }}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setOpen(false)} />

      {/* Panel */}
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="relative w-full max-w-lg mx-4 bg-surface-1 border border-border rounded-2xl shadow-elevation-modal overflow-hidden"
      >
        <Command shouldFilter={false}>
          {/* Search input */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" className="text-muted shrink-0">
              <circle cx="7" cy="7" r="5" />
              <path d="M11 11l3 3" />
            </svg>
            <Command.Input
              autoFocus
              value={query}
              onValueChange={setQuery}
              placeholder="Search commands, sessions, artifacts…"
              className="flex-1 bg-transparent text-sm text-primary outline-none placeholder:text-muted"
            />
            <kbd className="text-2xs text-muted bg-surface-2 border border-border px-1.5 py-0.5 rounded font-mono">
              esc
            </kbd>
          </div>

          <Command.List className="max-h-80 overflow-y-auto py-2">
            {filtered.length === 0 && (
              <Command.Empty className="py-8 text-center text-xs text-muted">
                No commands found
              </Command.Empty>
            )}

            {groups.map(group => (
              <Command.Group
                key={group}
                heading={group}
                className="[&>[cmdk-group-heading]]:px-4 [&>[cmdk-group-heading]]:py-1.5 [&>[cmdk-group-heading]]:text-2xs [&>[cmdk-group-heading]]:text-muted [&>[cmdk-group-heading]]:uppercase [&>[cmdk-group-heading]]:tracking-widest [&>[cmdk-group-heading]]:font-medium"
              >
                {filtered.filter(a => a.group === group).map(action => (
                  <Command.Item
                    key={action.id}
                    onSelect={() => { action.run(); setOpen(false); setQuery(""); }}
                    className="flex items-center justify-between gap-3 px-4 py-2.5 cursor-pointer text-sm text-subtle hover:text-primary data-[selected=true]:bg-surface-2 data-[selected=true]:text-primary transition-colors"
                  >
                    <span className="truncate">{action.label}</span>
                    {action.hint && (
                      <kbd className="text-2xs text-muted bg-surface-3 border border-border px-1.5 py-0.5 rounded font-mono shrink-0">
                        {action.hint}
                      </kbd>
                    )}
                  </Command.Item>
                ))}
              </Command.Group>
            ))}
          </Command.List>

          {/* Footer */}
          <div className="border-t border-border px-4 py-2 flex items-center gap-4">
            <span className="text-2xs text-muted">
              <kbd className="bg-surface-2 border border-border px-1 rounded font-mono">↑↓</kbd> navigate
            </span>
            <span className="text-2xs text-muted">
              <kbd className="bg-surface-2 border border-border px-1 rounded font-mono">↵</kbd> select
            </span>
            <span className="text-2xs text-muted ml-auto">
              <kbd className="bg-surface-2 border border-border px-1 rounded font-mono">⌘K</kbd> to close
            </span>
          </div>
        </Command>
      </div>
    </div>
  );
}
