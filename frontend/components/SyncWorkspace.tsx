"use client";

// ── Cross-session sync workspace ─────────────────────────────────────────────
//
// A desktop of session panes, each a genuinely independent, live WS
// connection (useSession) to its own session — not a summary, not polled.
// Once two sessions are linked (lib/sessionLinks.ts), a member of one gets
// lazily auto-granted real Observer membership in the other the moment they
// open its pane (server-side: db::sessions::require_membership_or_linked_
// access) — after that this is just the normal single-session experience,
// running twice, side by side. "Workspace layout is personal" (explicit
// product call): pane position/size lives in localStorage only, never sent
// to the backend.

import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, useDragControls, useMotionValue } from "framer-motion";
import { toast } from "sonner";
import { useSession } from "@/lib/ws";
import { getSessions } from "@/lib/sessions";
import {
  directLink, listLinks, mintLinkInvite, redeemLinkInvite, setLinkVisibility, unlink as unlinkSession,
  getDigest, sendContextEntry, SessionLinkListItem,
} from "@/lib/sessionLinks";
import { getArtifact, importArtifact, annotateArtifact, whiteboardPreview } from "@/lib/artifacts";
import { DOT_COLOR, EVENT_LABEL, eventSummary, INTERNAL_WS } from "@/lib/eventTaxonomy";
import MessageBody from "@/components/MessageBody";
import { SessionRow, ArtifactSummary } from "@/lib/types";

interface Props {
  sessionId: string;
  actorId: string;
  token: string | null;
}

interface PaneLayout { x: number; y: number; w: number; h: number }

const DEFAULT_SIZE = { w: 380, h: 460 };
// lib/preferences.ts's "reset workspace layouts" settings action sweeps
// localStorage for this same prefix (kept as a literal there rather than
// imported, to avoid pulling this whole component into that tiny module) —
// keep the two in sync if this ever changes.
const WORKSPACE_LAYOUT_KEY_PREFIX = "sol-workspace-layout-";
const layoutKey = (workspaceId: string) => `${WORKSPACE_LAYOUT_KEY_PREFIX}${workspaceId}`;

function loadLayouts(workspaceId: string): Record<string, PaneLayout> {
  if (typeof window === "undefined") return {};
  try {
    const raw = localStorage.getItem(layoutKey(workspaceId));
    return raw ? JSON.parse(raw) : {};
  } catch { return {}; }
}

function saveLayouts(workspaceId: string, layouts: Record<string, PaneLayout>) {
  if (typeof window === "undefined") return;
  localStorage.setItem(layoutKey(workspaceId), JSON.stringify(layouts));
}

/** Keep at least a corner of the title bar reachable even if a layout was
 *  saved against a since-shrunk viewport (different monitor, resized
 *  window) — otherwise a pane can reopen fully off-screen with no way to
 *  grab it back. */
function clampToViewport(layout: PaneLayout): PaneLayout {
  if (typeof window === "undefined") return layout;
  const maxX = Math.max(8, window.innerWidth - 120);
  const maxY = Math.max(8, window.innerHeight - 60);
  return {
    ...layout,
    x: Math.min(Math.max(layout.x, 0), maxX),
    y: Math.min(Math.max(layout.y, 0), maxY),
  };
}

// Pane spawn/close animation timing — must match the CSS transition
// duration applied in SessionPaneWindow below (see the note there on why
// this is a plain CSS transition and not AnimatePresence).
const POP_MS = 200;

// ── Cross-pane artifact drag payload ─────────────────────────────────────────
// Custom MIME type so drops from outside the app (files, browser tabs, text
// selections) don't get misread as an artifact-import gesture — only a
// dataTransfer item written by ArtifactChip's own onDragStart matches this.
const ARTIFACT_DRAG_MIME = "application/x-solarplex-artifact";

interface ArtifactDragPayload {
  sourceSessionId: string;
  artifactId: string;
  artifactName: string;
}

export default function SyncWorkspace({ sessionId, actorId }: Props) {
  // Panes currently open on the desktop — always starts with the home
  // session; linked sessions get added on top.
  const [openPanes, setOpenPanes] = useState<string[]>([sessionId]);
  const [layouts, setLayouts] = useState<Record<string, PaneLayout>>(() => loadLayouts(sessionId));
  const [pickerOpen, setPickerOpen] = useState(false);
  const [zOrder, setZOrder] = useState<string[]>([sessionId]);
  // Panes mid-close: still mounted (so the pop-out transition can play and
  // each pane's own WS connection tears down gracefully) but flagged so
  // SessionPaneWindow renders its "closing" CSS state instead of "open".
  const [closingIds, setClosingIds] = useState<Set<string>>(new Set());
  // Drag bounds — panes are constrained to this element by framer-motion's
  // own dragConstraints, so a drag physically cannot carry a pane off-screen.
  const workspaceRef = useRef<HTMLDivElement | null>(null);

  // Which panes are actually scrolled into view right now (IntersectionObserver-
  // reported by each pane itself against workspaceRef, see SessionPaneWindow) —
  // deliberately *not* the same as "open" (openPanes): a pane you opened
  // earlier but dragged/scrolled out of view shouldn't show up as a target
  // in another pane's "send to..." picker, since you can't see it landed
  // there without hunting for it. Scoping to visible-on-screen keeps that
  // picker legible instead of listing every pane ever opened this session.
  const [visiblePaneIds, setVisiblePaneIds] = useState<Set<string>>(new Set());
  const handleVisibilityChange = useCallback((id: string, visible: boolean) => {
    setVisiblePaneIds(prev => {
      if (prev.has(id) === visible) return prev;
      const next = new Set(prev);
      if (visible) next.add(id); else next.delete(id);
      return next;
    });
  }, []);

  const { data: links, refetch: refetchLinks } = useQuery({
    queryKey: ["session-links", sessionId],
    queryFn: () => listLinks(sessionId),
    staleTime: 30_000,
  });
  const { data: mySessions } = useQuery({ queryKey: ["sessions"], queryFn: getSessions });

  // Session id -> display name, for anywhere a pane needs to refer to
  // *another* pane by name (the context-summary-send target picker) without
  // its own live WS connection to resolve it. Every pane ever opened here
  // came from either mySessions (the actor's own sessions) or the home
  // session's own links (peer_session_name), so this covers every id that
  // can appear in openPanes.
  const paneNames: Record<string, string> = {};
  (mySessions ?? []).forEach(s => { paneNames[s.id] = s.name; });
  (links ?? []).forEach(l => { paneNames[l.peer_session_id] = l.peer_session_name; });

  const updateLayout = useCallback((id: string, partial: Partial<PaneLayout>) => {
    setLayouts(prev => {
      const next = { ...prev, [id]: { ...(prev[id] ?? { x: 40, y: 40, ...DEFAULT_SIZE }), ...partial } };
      saveLayouts(sessionId, next);
      return next;
    });
  }, [sessionId]);

  const bringToFront = useCallback((id: string) => {
    setZOrder(z => [...z.filter(x => x !== id), id]);
  }, []);

  const closeTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  const addPane = useCallback((id: string) => {
    // Re-adding a pane that's mid-close (e.g. a fast click-close-then-
    // reopen) cancels the pending removal instead of no-op'ing just
    // because it's technically still in openPanes.
    clearTimeout(closeTimers.current[id]);
    delete closeTimers.current[id];
    setClosingIds(prev => { if (!prev.has(id)) return prev; const next = new Set(prev); next.delete(id); return next; });
    setOpenPanes(p => (p.includes(id) ? p : [...p, id]));
    setZOrder(z => (z.includes(id) ? z : [...z, id]));
    setPickerOpen(false);
  }, []);

  const closePane = useCallback((id: string) => {
    if (id === sessionId) return; // home always stays open
    setClosingIds(prev => (prev.has(id) ? prev : new Set(prev).add(id)));
    closeTimers.current[id] = setTimeout(() => {
      setOpenPanes(p => p.filter(x => x !== id));
      setClosingIds(prev => { const next = new Set(prev); next.delete(id); return next; });
      delete closeTimers.current[id];
    }, POP_MS);
  }, [sessionId]);

  // Any pending close timers must not fire after unmount.
  useEffect(() => () => { Object.values(closeTimers.current).forEach(clearTimeout); }, []);

  const addableFromMySessions = (mySessions ?? []).filter(
    s => s.id !== sessionId && s.status !== "archived" && !(links ?? []).some(l => l.peer_session_id === s.id),
  );

  return (
    <div className="flex flex-col h-full">
      {/* ── Top rail — lives above the pane canvas so a pane can never spawn
          or drift underneath the link control. ─────────────────────────── */}
      <div className="shrink-0 h-12 flex items-center justify-end px-4 border-b border-border bg-surface-0 relative z-40">
        <LinkPickerToggle
          open={pickerOpen}
          onToggle={() => setPickerOpen(v => !v)}
          onClose={() => setPickerOpen(false)}
        >
          <LinkPicker
            homeSessionId={sessionId}
            addableSessions={addableFromMySessions}
            onAddPane={addPane}
            onLinked={() => refetchLinks()}
            onUnlink={async (linkId) => { await unlinkSession(linkId); refetchLinks(); }}
            onMute={async (linkId, visibility) => { await setLinkVisibility(linkId, visibility); refetchLinks(); }}
            links={links ?? []}
            openPaneIds={openPanes}
            onOpenExistingLink={addPane}
          />
        </LinkPickerToggle>
      </div>

      {/* ── Pane canvas ───────────────────────────────────────────────────── */}
      <div ref={workspaceRef} className="relative flex-1 min-h-0 overflow-auto bg-surface-0" style={{ backgroundImage: "radial-gradient(var(--color-border) 1px, transparent 1px)", backgroundSize: "24px 24px" }}>
        {openPanes.map((id, idx) => (
          <SessionPaneWindow
            key={id}
            sessionId={id}
            actorId={actorId}
            isHome={id === sessionId}
            isClosing={closingIds.has(id)}
            initialLayout={layouts[id] ?? { x: 40 + idx * 32, y: 40 + idx * 32, ...DEFAULT_SIZE }}
            zIndex={10 + zOrder.indexOf(id)}
            dragConstraintsRef={workspaceRef}
            onLayoutChange={p => updateLayout(id, p)}
            onFocus={() => bringToFront(id)}
            onClose={() => closePane(id)}
            otherPaneIds={openPanes.filter(p => p !== id && visiblePaneIds.has(p))}
            homeSessionId={sessionId}
            paneNames={paneNames}
            onVisibilityChange={handleVisibilityChange}
          />
        ))}
      </div>
    </div>
  );
}

// ── Link picker toggle — button + animated dropdown, closes on outside click ─

function LinkPickerToggle({
  open, onToggle, onClose, children,
}: {
  open: boolean;
  onToggle: () => void;
  onClose: () => void;
  children: React.ReactNode;
}) {
  const rootRef = useRef<HTMLDivElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  // Set imperatively, not as a JSX `inert` prop: React 18 doesn't forward
  // `inert` to the DOM at all (silently dropped — this codebase is on
  // 18.3.1; proper passthrough landed in React 19). `HTMLElement.inert` is
  // a real, standard DOM property in every current browser regardless, so
  // setting it directly on the node sidesteps React's prop whitelist gap.
  useEffect(() => {
    if (panelRef.current) panelRef.current.inert = !open;
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function handlePointerDown(e: PointerEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) onCloseRef.current();
    }
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onCloseRef.current();
    }
    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  return (
    <div ref={rootRef} className="relative">
      <motion.button
        onClick={onToggle}
        whileTap={{ scale: 0.96 }}
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium shadow-lg transition-colors ${
          open ? "bg-surface-2 text-subtle border border-border" : "bg-accent-blue text-surface-0 hover:bg-accent-blue/90"
        }`}
      >
        <span>Link a session</span>
        <motion.span
          animate={{ rotate: open ? 45 : 0 }}
          transition={{ duration: 0.18, ease: "easeInOut" }}
          className="inline-block leading-none text-sm"
        >
          +
        </motion.span>
      </motion.button>
      {/* Always mounted, plain CSS transition — not framer-motion's `animate`
          prop. Two JS-animation-driven approaches (AnimatePresence exit,
          then a controlled `animate` prop) both proved unreliable here: the
          AnimatePresence exit would reach opacity 0 but never unmount, and
          `animate` would go 1→0 correctly but not reliably re-target 0→1 on
          a fast reopen. A plain CSS transition has no separate animation
          state machine that can desync from `open` — the browser just
          diffs the class on every render, so it can't get stuck. Bonus:
          whatever the user typed into the redeem-code field survives a
          close/reopen instead of resetting, since this never unmounts.
          `absolute` (anchored to the `relative` root above) is load-bearing,
          not cosmetic: staying mounted-but-hidden only works visually if it
          doesn't also occupy real space in whatever normal-flow layout this
          toggle sits in — inside the rail's `items-center` flex row, an
          in-flow invisible block this tall dragged the *button* wildly out
          of position, centered against a phantom height nobody could see. */}
      <div
        ref={panelRef}
        style={{ transformOrigin: "top right" }}
        className={`absolute right-0 top-full mt-2 transition-[opacity,transform] duration-150 ease-out ${
          open ? "opacity-100 scale-100 translate-y-0 pointer-events-auto" : "opacity-0 scale-[0.96] -translate-y-1.5 pointer-events-none"
        }`}
        aria-hidden={!open}
      >
        {children}
      </div>
    </div>
  );
}

// ── Link picker panel ────────────────────────────────────────────────────────

function LinkPicker({
  homeSessionId, addableSessions, onAddPane, onLinked, onUnlink, onMute, links, openPaneIds, onOpenExistingLink,
}: {
  homeSessionId: string;
  addableSessions: SessionRow[];
  onAddPane: (id: string) => void;
  onLinked: () => void;
  onUnlink: (linkId: string) => void;
  onMute: (linkId: string, visibility: "full" | "muted") => void;
  links: SessionLinkListItem[];
  openPaneIds: string[];
  onOpenExistingLink: (id: string) => void;
}) {
  const [redeemCode, setRedeemCode] = useState("");
  const [mintedCode, setMintedCode] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function handleDirectLink(targetId: string) {
    setBusy(true);
    try {
      await directLink(homeSessionId, targetId);
      toast.success("Linked");
      onLinked();
      onAddPane(targetId);
    } catch (e) {
      toast.error(`Not authorized to link directly — try creating an invite instead. (${e instanceof Error ? e.message : "error"})`);
    } finally { setBusy(false); }
  }

  async function handleMint() {
    setBusy(true);
    try {
      const invite = await mintLinkInvite(homeSessionId);
      setMintedCode(invite.id);
    } catch (e) {
      toast.error(`Couldn't create invite: ${e instanceof Error ? e.message : "error"}`);
    } finally { setBusy(false); }
  }

  async function handleRedeem() {
    if (!redeemCode.trim()) return;
    setBusy(true);
    try {
      const link = await redeemLinkInvite(redeemCode.trim(), homeSessionId);
      toast.success("Linked");
      setRedeemCode("");
      onLinked();
      onAddPane(link.session_a === homeSessionId ? link.session_b : link.session_a);
    } catch (e) {
      toast.error(`Couldn't redeem: ${e instanceof Error ? e.message : "error"}`);
    } finally { setBusy(false); }
  }

  return (
    <div className="mt-2 w-80 rounded-xl border border-border bg-surface-1 panel-shine shadow-elevation-float p-3 space-y-3 text-left">
      {links.length > 0 && (
        <div>
          <p className="text-2xs uppercase tracking-widest text-muted font-medium mb-1.5">Linked sessions</p>
          <div className="space-y-1">
            {links.map(l => (
              <div key={l.id} className="flex items-center gap-1.5">
                <button
                  onClick={() => onOpenExistingLink(l.peer_session_id)}
                  disabled={openPaneIds.includes(l.peer_session_id)}
                  className="flex-1 text-left text-xs text-subtle hover:text-accent-blue disabled:text-muted disabled:hover:text-muted truncate transition-colors"
                >
                  {l.peer_session_name}
                </button>
                <button
                  onClick={() => onMute(l.id, l.visibility === "full" ? "muted" : "full")}
                  className="text-2xs text-muted hover:text-subtle transition-colors"
                  title={l.visibility === "full" ? "Mute (stop new access grants)" : "Unmute"}
                  aria-label={l.visibility === "full" ? "Mute (stop new access grants)" : "Unmute"}
                >
                  {l.visibility === "full" ? "🔊" : "🔇"}
                </button>
                <button
                  onClick={() => onUnlink(l.id)}
                  aria-label="Unlink session"
                  className="text-2xs text-muted hover:text-accent-red transition-colors"
                >✕</button>
              </div>
            ))}
          </div>
        </div>
      )}

      {addableSessions.length > 0 && (
        <div>
          <p className="text-2xs uppercase tracking-widest text-muted font-medium mb-1.5">Link one of your sessions</p>
          <div className="space-y-1 max-h-32 overflow-y-auto">
            {addableSessions.map(s => (
              <button
                key={s.id}
                disabled={busy}
                onClick={() => handleDirectLink(s.id)}
                className="w-full text-left text-xs px-2 py-1.5 rounded-lg text-subtle hover:bg-surface-2 transition-colors truncate disabled:opacity-50"
              >
                {s.name}
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="pt-2 border-t border-border/50">
        <p className="text-2xs uppercase tracking-widest text-muted font-medium mb-1.5">Invite another admin</p>
        {mintedCode ? (
          <div className="rounded-lg bg-surface-2 px-2 py-1.5">
            <p className="text-2xs text-muted mb-1">Share this code — they redeem it below:</p>
            <code className="text-2xs text-accent-blue break-all select-all">{mintedCode}</code>
          </div>
        ) : (
          <button disabled={busy} onClick={handleMint} className="text-xs px-2.5 py-1.5 rounded-lg border border-border text-subtle hover:border-subtle transition-colors disabled:opacity-50">
            Create invite code
          </button>
        )}
      </div>

      <div>
        <p className="text-2xs uppercase tracking-widest text-muted font-medium mb-1.5">Redeem a link code</p>
        <div className="flex gap-1.5">
          <input
            value={redeemCode}
            onChange={e => setRedeemCode(e.target.value)}
            placeholder="paste code…"
            aria-label="Link code"
            className="flex-1 min-w-0 text-xs px-2 py-1.5 rounded-lg bg-surface-2 border border-border text-subtle placeholder:text-muted focus:outline-none focus:border-accent-blue"
          />
          <button disabled={busy || !redeemCode.trim()} onClick={handleRedeem} className="text-xs px-2.5 py-1.5 rounded-lg bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors disabled:opacity-50">
            Redeem
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Draggable, resizable session pane ────────────────────────────────────────

type PaneTab = "activity" | "artifacts" | "context" | "approvals" | "digest";

function tabLabel(t: PaneTab, counts: { artifacts: number; context: number; approvals: number }): string {
  switch (t) {
    case "activity":  return "Activity";
    case "artifacts": return `Artifacts${counts.artifacts ? ` (${counts.artifacts})` : ""}`;
    case "context":   return `Context${counts.context ? ` (${counts.context})` : ""}`;
    case "approvals": return `Approvals${counts.approvals ? ` (${counts.approvals})` : ""}`;
    case "digest":    return "Digest";
  }
}

function SessionPaneWindow({
  sessionId, actorId, isHome, isClosing, initialLayout, zIndex, dragConstraintsRef, onLayoutChange, onFocus, onClose,
  otherPaneIds, homeSessionId, paneNames, onVisibilityChange,
}: {
  sessionId: string;
  actorId: string;
  isHome: boolean;
  isClosing: boolean;
  initialLayout: PaneLayout;
  zIndex: number;
  dragConstraintsRef: React.RefObject<HTMLElement>;
  onLayoutChange: (p: Partial<PaneLayout>) => void;
  onFocus: () => void;
  onClose: () => void;
  /** Every other pane currently *scrolled into view* on this desktop
   *  (session ids) — for the context-summary-send target picker (Part 4B).
   *  Scoped to visible-on-screen, not just "opened at some point", so the
   *  picker can't list a pane you'd have to hunt for after sending to it.
   *  This pane's own id is excluded by the caller. */
  otherPaneIds: string[];
  /** The workspace's own home session — the attributed sender for an
   *  annotation left from this (non-home) pane (Part 4C). */
  homeSessionId: string;
  /** Session id -> display name, for the target picker (otherwise it can
   *  only show raw ids — see the parent's own doc comment on this map). */
  paneNames: Record<string, string>;
  /** Reports this pane's own on-screen visibility (via IntersectionObserver
   *  against the workspace canvas) up to the parent, which aggregates every
   *  pane's report into the `visiblePaneIds` set `otherPaneIds` is derived
   *  from. */
  onVisibilityChange: (id: string, visible: boolean) => void;
}) {
  const { state, approve, deny, sendMessage, resolveContextEntry, setFocus } = useSession(sessionId, actorId, null);
  const [tab, setTab] = useState<PaneTab>("activity");

  // Part 4A: report which tab this pane has open so other live viewers of
  // the same session (including via a linked pane) see a presence
  // indicator. Two separate effects, deliberately: a mount-only cleanup
  // (empty deps) for "clear on unmount", separate from the tab-change
  // effect below — combining them would fire the cleanup on every tab
  // switch too (React re-runs an effect's cleanup before every re-run,
  // not just on unmount), flickering focus to undefined and back on each
  // switch instead of just moving cleanly from one tab to the next.
  useEffect(() => setFocus(tab), [tab, setFocus]);
  useEffect(() => () => setFocus(undefined), [setFocus]);
  // Computed-on-read, not part of the live WS stream — only fetched once the
  // tab is actually opened, then kept lightly fresh like the cross-session
  // activity feed (short staleTime + refetch-on-focus).
  const { data: digest } = useQuery({
    queryKey: ["session-digest", sessionId],
    queryFn: () => getDigest(sessionId),
    enabled: tab === "digest",
    staleTime: 30_000,
    refetchOnWindowFocus: true,
  });
  const [draft, setDraft] = useState("");
  const dragControls = useDragControls();

  // Part 4B: which context entry currently has its "send to..." target
  // picker open (null = none). One at a time, closed after a successful
  // send or an explicit dismiss.
  const [sendingEntryId, setSendingEntryId] = useState<string | null>(null);
  const [sending, setSending] = useState(false);

  const handleSendContextEntry = useCallback(async (entry: typeof state.contextEntries[number], targetId: string) => {
    setSending(true);
    try {
      await sendContextEntry(targetId, sessionId, entry);
      toast.success(`Sent to ${paneNames[targetId] ?? targetId.slice(0, 10)}`);
      setSendingEntryId(null);
    } catch (err) {
      toast.error(`Send failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSending(false);
    }
  }, [sessionId, paneNames]);

  // ── Cross-pane artifact drop target ──────────────────────────────────────
  // Native HTML5 drag-and-drop, deliberately separate from framer-motion's
  // pointer-based pane dragging above (different event system entirely —
  // dragOver/drop never sees framer's pointer handlers, so the two don't
  // fight). `dragDepth` (not a bool) because dragenter/dragleave fire on
  // every descendant element as the pointer crosses child boundaries —
  // without counting enter/leave pairs, the highlight flickers off the
  // instant the pointer passes over a child like the title bar or a tab.
  const [dragDepth, setDragDepth] = useState(0);
  const [importing, setImporting] = useState(false);
  const isDragTarget = dragDepth > 0;

  const handleArtifactDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault();
    setDragDepth(0);
    const raw = e.dataTransfer.getData(ARTIFACT_DRAG_MIME);
    if (!raw) return; // not an artifact drag (e.g. an OS file drop) — ignore
    let payload: ArtifactDragPayload;
    try {
      payload = JSON.parse(raw);
    } catch {
      return;
    }
    if (payload.sourceSessionId === sessionId) {
      toast.error("That artifact is already in this session.");
      return;
    }
    setImporting(true);
    try {
      const { alreadyImported } = await importArtifact(sessionId, payload.sourceSessionId, payload.artifactId);
      // No manual refetch needed — the server broadcasts ArtifactCreated +
      // a provenance context entry over this pane's own live WS connection
      // (only on a genuine new import; already-imported is a read-only echo).
      toast.success(
        alreadyImported
          ? `"${payload.artifactName}" was already imported here`
          : `Imported "${payload.artifactName}"`,
      );
    } catch (err) {
      toast.error(`Import failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setImporting(false);
    }
  }, [sessionId]);

  // onLayoutChange's identity is fresh every parent render (it closes over
  // `id` inline in the .map() above) — mirrored into a ref so the effect
  // below can stay mount-only without capturing a stale copy of it.
  const onLayoutChangeRef = useRef(onLayoutChange);
  onLayoutChangeRef.current = onLayoutChange;

  // ── Spawn/close pop animation ────────────────────────────────────────────
  // Plain CSS transition on a class flip, deliberately not framer-motion's
  // AnimatePresence/`animate` prop — see LinkPickerToggle's comment on why:
  // JS-driven animation state got stuck mid-transition in this environment
  // (never reaching its resolved state), where a browser-native CSS
  // transition, which the browser drives itself rather than a JS scheduler,
  // does not. `entered` flips true one tick after mount so the initial
  // render paints at the "closed" (scaled down/transparent) state first —
  // without that first paint, the browser has nothing to transition *from*
  // and the pop-in wouldn't animate, it'd just appear.
  const [entered, setEntered] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setEntered(true), 10);
    return () => clearTimeout(t);
  }, []);
  const popVisible = entered && !isClosing;

  // ── Position ──────────────────────────────────────────────────────────────
  // Plain MotionValues, not React state: framer-motion owns these entirely
  // once a drag starts, mutating them outside React's render cycle. This is
  // the actual fix for "drag it and it slides off over time" — the old
  // version mixed React-controlled `left`/`top` with framer's own internal
  // drag transform, and since that transform is never reset after a drag
  // ends, each subsequent drag's offset got applied on top of an offset
  // that was already baked into `left`/`top`, compounding every time. Seeded
  // once from the persisted layout (clamped so a pane saved off-screen by a
  // since-resized viewport doesn't reopen unreachable), then framer-motion
  // is the sole owner — we only *read* the value, in onDragEnd, to persist
  // it back to localStorage.
  const clampedInitial = clampToViewport(initialLayout);
  const x = useMotionValue(clampedInitial.x);
  const y = useMotionValue(clampedInitial.y);

  // ── Size ──────────────────────────────────────────────────────────────────
  // Native CSS `resize: both` only ever exposes a single bottom-right
  // handle in every browser — there's no CSS-only way to get edge/corner
  // resize like a real desktop window, which is what this needs. Built by
  // hand instead: 8 invisible handles (4 edges, 4 corners), each driving a
  // raw pointermove listener that mutates the container's style directly —
  // same "uncontrolled during the gesture, commit on release" principle as
  // the drag handling above, just done by hand instead of via framer-motion
  // since there's no built-in resize primitive to lean on. `w`/`h` live in
  // a ref (not React state) so nothing re-renders — and therefore nothing
  // can fight the gesture — while it's in progress; north/west edges also
  // adjust the position MotionValues directly so the *opposite* edge stays
  // anchored, exactly like dragging a window border in a real OS.
  const containerRef = useRef<HTMLDivElement | null>(null);
  const sizeRef = useRef({ w: clampedInitial.w, h: clampedInitial.h });

  useEffect(() => {
    const el = containerRef.current;
    if (el) {
      el.style.width = `${sizeRef.current.w}px`;
      el.style.height = `${sizeRef.current.h}px`;
    }
  }, []);

  // Report on-screen visibility to the parent (Part 4B's "send to..."
  // picker scope). `root: dragConstraintsRef.current` is the scrollable
  // pane canvas itself, not the browser viewport — a pane can be fully
  // within the browser window but still scrolled out of the canvas's own
  // visible area, and that should count as not-visible here.
  useEffect(() => {
    const el = containerRef.current;
    const root = dragConstraintsRef.current;
    if (!el || !root) return;
    const observer = new IntersectionObserver(
      ([entry]) => onVisibilityChange(sessionId, entry.isIntersecting),
      { root, threshold: 0.05 },
    );
    observer.observe(el);
    return () => {
      observer.disconnect();
      onVisibilityChange(sessionId, false);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  const MIN_W = 280;
  const MIN_H = 220;

  // Shared by the pointer drag loop below and the keyboard handler on each
  // resize handle (see KEYBOARD_RESIZE_STEP usage further down) — same
  // per-edge math either way, just fed a (dx, dy) that comes from
  // pointermove deltas in one case and a fixed step per arrow-key press in
  // the other. This is the WCAG 2.5.7/2.1.1 fix: resizing a pane was
  // pointer-drag-only with no keyboard path at all before this.
  const applyResizeDelta = useCallback((edge: ResizeEdge, dx: number, dy: number, startW: number, startH: number, startX: number, startY: number) => {
    let w = startW, h = startH;
    if (edge.includes("e")) w = Math.max(MIN_W, startW + dx);
    if (edge.includes("s")) h = Math.max(MIN_H, startH + dy);
    if (edge.includes("w")) {
      w = Math.max(MIN_W, startW - dx);
      x.set(startX + (startW - w));
    }
    if (edge.includes("n")) {
      h = Math.max(MIN_H, startH - dy);
      y.set(startY + (startH - h));
    }
    sizeRef.current = { w, h };
    const el = containerRef.current;
    if (el) { el.style.width = `${w}px`; el.style.height = `${h}px`; }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const startResize = useCallback((edge: ResizeEdge) => (
    downEvent: React.PointerEvent,
  ) => {
    downEvent.preventDefault();
    onFocus();
    const startClientX = downEvent.clientX;
    const startClientY = downEvent.clientY;
    const startW = sizeRef.current.w;
    const startH = sizeRef.current.h;
    const startX = x.get();
    const startY = y.get();

    function onMove(moveEvent: PointerEvent) {
      applyResizeDelta(edge, moveEvent.clientX - startClientX, moveEvent.clientY - startClientY, startW, startH, startX, startY);
    }
    function onUp() {
      document.removeEventListener("pointermove", onMove);
      document.removeEventListener("pointerup", onUp);
      onLayoutChangeRef.current({ w: sizeRef.current.w, h: sizeRef.current.h, x: x.get(), y: y.get() });
    }
    document.addEventListener("pointermove", onMove);
    document.addEventListener("pointerup", onUp);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [x, y, onFocus]);

  function handleDragEnd() {
    onLayoutChangeRef.current({ x: x.get(), y: y.get() });
  }

  // ── Keyboard move/resize — WCAG 2.1.1 (Keyboard) + 2.5.7 (Dragging
  // Movements) ────────────────────────────────────────────────────────────
  // Both the title bar (move) and the 8 resize handles are pointer-drag-
  // only otherwise — a keyboard or switch-device user would have no way to
  // reposition or resize a pane at all. Same increment either way: arrow
  // keys step by KEY_STEP, Shift+arrow steps by KEY_STEP_LARGE, matching
  // the coarse/fine-adjustment convention most OS window managers use for
  // keyboard-driven move/resize.
  const KEY_STEP = 12;
  const KEY_STEP_LARGE = 48;

  // Keyboard move/resize mutate MotionValues/a ref directly (see the Position
  // and Size comments above) specifically so nothing re-renders mid-gesture —
  // but that also means nothing on screen tells a screen-reader user a move
  // actually happened. This announcement is the one deliberate exception:
  // plain React state, same sr-only + aria-live="polite" pattern Messages.tsx
  // already uses for new-message announcements, set once per discrete keydown
  // rather than continuously (there's no pointermove-style stream to fight).
  const [moveAnnouncement, setMoveAnnouncement] = useState("");

  const handleMoveKeyDown = useCallback((e: React.KeyboardEvent) => {
    const arrows: Record<string, [number, number]> = {
      ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1],
    };
    const dir = arrows[e.key];
    if (!dir) return;
    e.preventDefault();
    const step = e.shiftKey ? KEY_STEP_LARGE : KEY_STEP;
    let nextX = x.get() + dir[0] * step;
    let nextY = y.get() + dir[1] * step;
    // Clamp to the workspace bounds, same intent as framer-motion's
    // `dragConstraints` on the pointer path (not the identical algorithm —
    // just close enough that a pane can't be keyboard-moved fully offscreen).
    const bounds = dragConstraintsRef.current?.getBoundingClientRect();
    const el = containerRef.current?.getBoundingClientRect();
    if (bounds && el) {
      nextX = Math.min(Math.max(nextX, 0), Math.max(0, bounds.width - el.width));
      nextY = Math.min(Math.max(nextY, 0), Math.max(0, bounds.height - el.height));
    }
    x.set(nextX);
    y.set(nextY);
    onLayoutChangeRef.current({ x: nextX, y: nextY });
    setMoveAnnouncement(`Pane moved to ${Math.round(nextX)}, ${Math.round(nextY)}`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [x, y]);

  const handleResizeKeyDown = useCallback((edge: ResizeEdge) => (e: React.KeyboardEvent) => {
    const arrows: Record<string, [number, number]> = {
      ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1],
    };
    const dir = arrows[e.key];
    if (!dir) return;
    e.preventDefault();
    const step = e.shiftKey ? KEY_STEP_LARGE : KEY_STEP;
    // Arrow direction maps to (dx, dy) the same way a pointer-drag delta
    // would for this edge: e.g. the east handle grows on ArrowRight,
    // shrinks on ArrowLeft; north/south are inverted from screen-down
    // being +y, same as applyResizeDelta already assumes.
    const dx = dir[0] * step;
    const dy = dir[1] * step;
    applyResizeDelta(edge, dx, dy, sizeRef.current.w, sizeRef.current.h, x.get(), y.get());
    onLayoutChangeRef.current({ w: sizeRef.current.w, h: sizeRef.current.h, x: x.get(), y: y.get() });
    setMoveAnnouncement(`Pane resized to ${Math.round(sizeRef.current.w)} by ${Math.round(sizeRef.current.h)} pixels`);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applyResizeDelta, x, y]);

  const pendingApprovals = state.pendingApprovals;
  // Events only ever store the immutable actor_id — resolved to a display
  // name here from the snapshot's already-resolved members list, same
  // pattern as the main session page's Timeline. Passing {} here (the
  // earlier bug) meant eventSummary's fallback (`actorNames[id] ?? id`)
  // always hit the raw id, showing the ULID instead of a name.
  const actorNames = Object.fromEntries((state.snapshot?.members ?? []).map(m => [m.actor_id, m.name]));

  return (
    <motion.div
      drag
      dragControls={dragControls}
      dragListener={false}
      dragMomentum={false}
      dragElastic={0.05}
      dragConstraints={dragConstraintsRef}
      onDragEnd={handleDragEnd}
      onPointerDownCapture={onFocus}
      style={{ position: "absolute", left: 0, top: 0, x, y, zIndex }}
      className="pointer-events-auto"
    >
      {/* Pop wrapper — separate from containerRef on purpose: this element
          owns the spawn/close `transform: scale(...)`, containerRef below
          owns its own imperative width/height (see the Size comment
          above). Two different elements each independently animating/
          setting `transform`-adjacent properties would fight if merged
          into one; nesting them means the effects compose instead
          (outer motion.div translates for position, this scales for pop,
          containerRef sizes itself) rather than one clobbering the other. */}
      <div
        style={{ transformOrigin: "top left" }}
        className={`transition-[opacity,transform] duration-200 ease-out ${popVisible ? "opacity-100 scale-100" : "opacity-0 scale-90"}`}
      >
      <div
        ref={containerRef}
        style={{ overflow: "hidden", position: "relative" }}
        onDragEnter={e => { e.preventDefault(); setDragDepth(d => d + 1); }}
        onDragLeave={e => { e.preventDefault(); setDragDepth(d => Math.max(0, d - 1)); }}
        onDragOver={e => { e.preventDefault(); e.dataTransfer.dropEffect = "copy"; }}
        onDrop={handleArtifactDrop}
        className={`rounded-xl border sidebar-surface panel-shine flex flex-col shadow-2xl transition-colors ${
          isDragTarget ? "border-accent-blue ring-2 ring-accent-blue/40" : "border-border"
        }`}
      >
        <div aria-live="polite" role="status" className="sr-only">{moveAnnouncement}</div>
        {isDragTarget && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-accent-blue/10 backdrop-blur-[1px] pointer-events-none">
            <span className="text-xs font-medium text-accent-blue bg-surface-0/90 px-3 py-1.5 rounded-lg border border-accent-blue/40 shadow-lg">
              Drop to import
            </span>
          </div>
        )}
        {importing && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-surface-0/70 pointer-events-none">
            <span className="text-xs font-medium text-subtle">Importing…</span>
          </div>
        )}
        {/* Title bar — the drag handle. Also keyboard-operable (arrow keys
            move, Shift+arrow for a larger step) — see handleMoveKeyDown's
            comment for why: pointer-drag had no keyboard equivalent at all. */}
        <div
          onPointerDown={e => dragControls.start(e)}
          onKeyDown={handleMoveKeyDown}
          tabIndex={0}
          role="button"
          aria-label={`Move pane: ${state.sessionName ?? sessionId}. Arrow keys to move, Shift+arrow for a larger step.`}
          className="shrink-0 flex items-center justify-between gap-2 px-3 py-2 border-b border-border cursor-grab active:cursor-grabbing select-none focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-blue/60 focus-visible:ring-inset"
        >
          <div className="min-w-0 flex items-center gap-1.5">
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${state.connected ? "bg-accent-green" : "bg-surface-4"}`} />
            <p className="text-xs font-semibold text-primary truncate">{state.sessionName ?? (isHome ? "This session" : sessionId.slice(0, 10))}</p>
            {isHome && <span className="text-2xs text-muted shrink-0">(home)</span>}
          </div>
          {!isHome && (
            <button onClick={onClose} className="text-muted hover:text-accent-red transition-colors text-xs shrink-0" aria-label="Close pane">✕</button>
          )}
        </div>

        {/* Tabs */}
        <div className="shrink-0 flex gap-1 px-2 pt-1.5 border-b border-border">
          {(["activity", "artifacts", "context", "approvals", "digest"] as PaneTab[]).map(t => {
            // Part 4A: who else (not me) is currently looking at this same
            // tab, live-only via presence.focus — no snapshot/events involved.
            const here = Object.entries(state.focusByActor)
              .filter(([id, focusedTab]) => id !== actorId && focusedTab === t)
              .map(([id]) => actorNames[id] ?? id);
            return (
              <button
                key={t}
                onClick={() => setTab(t)}
                title={here.length ? `Also viewing: ${here.join(", ")}` : undefined}
                className={`relative text-2xs px-2 py-1 rounded-t-md transition-colors ${tab === t ? "text-accent-blue border-b-2 border-accent-blue" : "text-muted hover:text-subtle"}`}
              >
                {tabLabel(t, { artifacts: state.artifacts.length, context: state.contextEntries.length, approvals: pendingApprovals.length })}
                {here.length > 0 && (
                  <span className="ml-1 inline-block w-1.5 h-1.5 rounded-full bg-accent-purple align-middle" aria-hidden />
                )}
              </button>
            );
          })}
        </div>

        {/* Content — tabIndex: a scrollable region with no other focusable
            way in is unreachable by keyboard. */}
        <div tabIndex={0} className="flex-1 min-h-0 overflow-y-auto p-2.5">
          {tab === "activity" && (
            <div className="space-y-1.5">
              {state.events.filter(e => !INTERNAL_WS.has(e.type)).length === 0 ? (
                <p className="text-2xs text-muted px-1">No activity yet.</p>
              ) : (
                [...state.events].filter(e => !INTERNAL_WS.has(e.type)).slice(-40).reverse().map(e => {
                  // eventSummary() deliberately returns just the actor name
                  // for message.posted — Timeline.tsx renders the actual
                  // content in a separate block below its summary line, and
                  // the pane wasn't doing that at all, so messages showed a
                  // "Message" label + a name and nothing else. Surfacing the
                  // real content here is the whole point of this tab.
                  const content = (e.type === "message.posted" || e.type === "context.entry.added")
                    ? String((e.payload as Record<string, unknown> | undefined)?.content ?? "")
                    : "";
                  return (
                    <div key={e.id} className="space-y-0.5">
                      <div className="flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${DOT_COLOR[e.type] ?? "bg-surface-4"}`} />
                        <span className="text-2xs text-muted shrink-0">{EVENT_LABEL[e.type] ?? e.type}</span>
                        <span className="text-2xs text-subtle truncate flex-1">{eventSummary(e, actorNames)}</span>
                      </div>
                      {content && (
                        <div className="pl-3 text-2xs text-subtle">
                          <MessageBody sessionId={sessionId} content={content} />
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}
          {tab === "artifacts" && (
            <div className="space-y-1.5">
              {state.artifacts.length === 0 ? (
                <p className="text-2xs text-muted px-1">No artifacts yet.</p>
              ) : state.artifacts.map(a => (
                <ArtifactChip key={a.id} sessionId={sessionId} artifact={a} isHome={isHome} homeSessionId={homeSessionId} />
              ))}
            </div>
          )}
          {tab === "context" && (
            <div className="space-y-1.5">
              {state.contextEntries.length === 0 ? (
                <p className="text-2xs text-muted px-1">No context yet.</p>
              ) : state.contextEntries.map(entry => (
                <div
                  key={entry.id}
                  className={`rounded-lg border px-2.5 py-1.5 ${entry.resolved ? "border-border/50 bg-surface-2/50" : "border-border bg-surface-2"}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-2xs uppercase tracking-wide text-muted">{entry.kind}</span>
                    <div className="flex items-center gap-2 shrink-0">
                      {otherPaneIds.length > 0 && (
                        <button
                          onClick={() => setSendingEntryId(v => (v === entry.id ? null : entry.id))}
                          title="Send to another open session"
                          aria-label="Send to another open session"
                          className="text-2xs text-muted hover:text-accent-blue transition-colors"
                        >
                          Send ↗
                        </button>
                      )}
                      {entry.resolved ? (
                        <span className="text-2xs text-accent-green">✓ resolved</span>
                      ) : (
                        <button
                          onClick={() => resolveContextEntry(entry.id)}
                          className="text-2xs text-muted hover:text-accent-green transition-colors"
                        >
                          Resolve
                        </button>
                      )}
                    </div>
                  </div>
                  <p className={`text-xs mt-0.5 whitespace-pre-wrap break-words ${entry.resolved ? "text-muted" : "text-subtle"}`}>
                    {entry.content}
                  </p>
                  {sendingEntryId === entry.id && (
                    <div className="mt-2 p-2 rounded-lg bg-surface-0 border border-border space-y-1">
                      <p className="text-2xs text-muted px-0.5">Send to:</p>
                      {otherPaneIds.map(id => (
                        <button
                          key={id}
                          disabled={sending}
                          onClick={() => handleSendContextEntry(entry, id)}
                          className="w-full text-left text-2xs px-2 py-1 rounded-md text-subtle hover:bg-surface-2 transition-colors disabled:opacity-50"
                        >
                          {paneNames[id] ?? `${id.slice(0, 10)}…`}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
          {tab === "approvals" && (
            <div className="space-y-2">
              {pendingApprovals.length === 0 ? (
                <p className="text-2xs text-muted px-1">None pending.</p>
              ) : pendingApprovals.map(a => (
                <div key={a.approval_id} className="rounded-lg border border-accent-amber/30 bg-accent-amber/5 px-2.5 py-1.5">
                  <p className="text-2xs text-subtle mb-1.5">{a.tool}</p>
                  <div className="flex gap-1.5">
                    <button onClick={() => approve(a.approval_id)} className="flex-1 text-2xs font-medium py-1 rounded-md bg-accent-green/10 border border-accent-green/30 text-accent-green hover:bg-accent-green/20 transition-colors">Approve</button>
                    <button onClick={() => deny(a.approval_id)} className="flex-1 text-2xs font-medium py-1 rounded-md bg-accent-red/10 border border-accent-red/30 text-accent-red hover:bg-accent-red/20 transition-colors">Deny</button>
                  </div>
                </div>
              ))}
            </div>
          )}
          {tab === "digest" && (
            <div className="space-y-2">
              {!digest ? (
                <p className="text-2xs text-muted px-1">Loading…</p>
              ) : (
                <>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5">
                      <p className="text-2xs text-muted">Events (24h)</p>
                      <p className="text-sm font-semibold text-primary">{digest.recent_event_count}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5">
                      <p className="text-2xs text-muted">Open approvals</p>
                      <p className={`text-sm font-semibold ${digest.open_approvals > 0 ? "text-accent-amber" : "text-primary"}`}>{digest.open_approvals}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5">
                      <p className="text-2xs text-muted">Artifacts</p>
                      <p className="text-sm font-semibold text-primary">{digest.artifacts_count}</p>
                    </div>
                    <div className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5">
                      <p className="text-2xs text-muted">Last activity</p>
                      <p className="text-2xs text-subtle">{digest.last_activity_at ? new Date(digest.last_activity_at).toLocaleString() : "—"}</p>
                    </div>
                  </div>
                  <p className="text-2xs text-muted px-1">Computed fresh on every view — not a copy of {digest.session_name}&rsquo;s data.</p>
                </>
              )}
            </div>
          )}
        </div>

        {/* Compact message composer */}
        <div className="shrink-0 flex gap-1.5 p-2 border-t border-border">
          <input
            value={draft}
            onChange={e => setDraft(e.target.value)}
            onKeyDown={e => {
              if (e.key === "Enter" && draft.trim()) { sendMessage(draft.trim()); setDraft(""); }
            }}
            placeholder="Message…"
            aria-label="Message"
            className="flex-1 min-w-0 text-xs px-2 py-1.5 rounded-lg bg-surface-2 border border-border text-subtle placeholder:text-muted focus:outline-none focus:border-accent-blue"
          />
        </div>
      </div>
      </div>

      {/* Resize handles — 4 edges + 4 corners, corners on top so they win
          the overlap in each corner region. Each is its own keyboard focus
          stop (arrow keys resize from that edge, Shift+arrow for a larger
          step) — see handleResizeKeyDown's comment. Invisible by design
          (thin pointer-hover strips), so the focus ring is the only visual
          cue they exist at all for a keyboard user; deliberately not
          suppressed. */}
      {EDGE_HANDLES.map(h => (
        <div
          key={h.edge}
          onPointerDown={startResize(h.edge)}
          onKeyDown={handleResizeKeyDown(h.edge)}
          tabIndex={0}
          role="button"
          aria-label={`Resize pane from ${RESIZE_EDGE_LABEL[h.edge]}. Arrow keys to resize, Shift+arrow for a larger step.`}
          style={{ position: "absolute", ...h.style, cursor: h.cursor, zIndex: 1 }}
          className="focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-blue/60 rounded-sm"
        />
      ))}
      {CORNER_HANDLES.map(h => (
        <div
          key={h.edge}
          onPointerDown={startResize(h.edge)}
          onKeyDown={handleResizeKeyDown(h.edge)}
          tabIndex={0}
          role="button"
          aria-label={`Resize pane from ${RESIZE_EDGE_LABEL[h.edge]}. Arrow keys to resize, Shift+arrow for a larger step.`}
          style={{ position: "absolute", ...h.style, cursor: h.cursor, zIndex: 2 }}
          className="focus:outline-none focus-visible:ring-2 focus-visible:ring-accent-blue/60 rounded-sm"
        />
      ))}
    </motion.div>
  );
}

// ── Artifact chip — hover-preview (truncated) + click-to-expand (full) ────────
//
// Both interactions share one query: hovering fetches (react-query caches
// by [sessionId, artifact.id]), so a click right after a hover renders
// instantly instead of re-fetching. Preview renders inline below the chip
// rather than as a floating tooltip — the pane's content area is
// `overflow-y-auto` at a fairly small default size (380×460), and an
// absolutely-positioned tooltip risks clipping against that scroll
// container; growing the chip in place has no such edge case.

const ARTIFACT_PREVIEW_CHARS = 140;

function ArtifactChip({
  sessionId, artifact, isHome, homeSessionId,
}: {
  sessionId: string;
  artifact: ArtifactSummary;
  /** Whether this chip is rendered in the workspace's own home pane. The
   *  annotate affordance (Part 4C) only makes sense for a *linked* pane's
   *  artifact — annotating your own session's own artifact is just a
   *  normal context entry, already covered by the Context tab. */
  isHome: boolean;
  homeSessionId: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const [hovered, setHovered] = useState(false);
  const [annotating, setAnnotating] = useState(false);
  const [note, setNote] = useState("");
  const [submittingNote, setSubmittingNote] = useState(false);
  const showContent = expanded || hovered;

  async function submitAnnotation() {
    const trimmed = note.trim();
    if (!trimmed) return;
    setSubmittingNote(true);
    try {
      await annotateArtifact(sessionId, homeSessionId, artifact.id, artifact.name, trimmed);
      toast.success("Annotation sent");
      setNote("");
      setAnnotating(false);
    } catch (err) {
      toast.error(`Annotate failed: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSubmittingNote(false);
    }
  }

  const { data, isLoading } = useQuery({
    queryKey: ["artifact", sessionId, artifact.id],
    queryFn: () => getArtifact(sessionId, artifact.id),
    enabled: showContent,
    staleTime: 30_000,
  });

  const full = data?.storage_ref ?? "";
  const isWhiteboard = artifact.type === "whiteboard";
  // Whiteboard storage_ref is raw Excalidraw scene/appState JSON — never
  // meant for direct display (huge, and not human-readable). Only the
  // rendered `preview` PNG half of the dual-format is shown, same rule
  // ArtifactsTab.tsx's ContentPreview already follows for the main session
  // view. Other artifact types don't have this problem — their content is
  // already plain text — so only whiteboard gets a special case here.
  const whiteboardImg = isWhiteboard && full ? whiteboardPreview(full) : null;
  // Same rule ArtifactsTab.tsx's ContentPreview follows: an image data URL
  // (or bare image URL) renders as an <img>, never dumped as raw text — a
  // base64 JPEG can be hundreds of KB of unreadable characters.
  const isImage = !isWhiteboard && full.length > 0 &&
    (full.startsWith("data:image/") || /\.(png|jpe?g|gif|webp|svg)$/i.test(full));
  // Same rule again for voice memos — a base64 audio/webm data URL is even
  // less readable as text than an image one, and was falling through to the
  // raw-text branch below with no case for it at all (unlike ArtifactsTab.tsx's
  // ContentPreview, which already has this case for the in-session drawer).
  const isAudio = !isWhiteboard && !isImage && full.length > 0 &&
    (artifact.type === "voice_memo" || artifact.type === "audio" || full.startsWith("data:audio/"));
  const shown = expanded || full.length <= ARTIFACT_PREVIEW_CHARS
    ? full
    : `${full.slice(0, ARTIFACT_PREVIEW_CHARS)}…`;

  return (
    <div
      role="button"
      tabIndex={0}
      draggable
      onDragStart={e => {
        const payload: ArtifactDragPayload = {
          sourceSessionId: sessionId, artifactId: artifact.id, artifactName: artifact.name,
        };
        e.dataTransfer.setData(ARTIFACT_DRAG_MIME, JSON.stringify(payload));
        e.dataTransfer.effectAllowed = "copy";
      }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      onClick={() => setExpanded(v => !v)}
      onKeyDown={e => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setExpanded(v => !v); } }}
      title="Drag onto another session pane to import a copy there"
      className="rounded-lg border border-border bg-surface-2 px-2.5 py-1.5 cursor-grab active:cursor-grabbing hover:border-subtle transition-colors"
    >
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs text-subtle truncate">{artifact.name}</p>
        <div className="flex items-center gap-1.5 shrink-0">
          {!isHome && (
            <button
              onClick={e => { e.stopPropagation(); setAnnotating(v => !v); }}
              title="Leave a note on this artifact (in its own session)"
              aria-label="Leave a note on this artifact"
              className="text-2xs text-muted hover:text-accent-blue transition-colors"
            >
              ✎
            </button>
          )}
          <span className="text-2xs text-muted">{expanded ? "▾" : "▸"}</span>
        </div>
      </div>
      <p className="text-2xs text-muted">{artifact.type}</p>
      {annotating && (
        <div
          className="mt-1.5 p-2 rounded-lg bg-surface-0 border border-border space-y-1.5"
          onClick={e => e.stopPropagation()}
          onPointerDown={e => e.stopPropagation()}
        >
          <textarea
            autoFocus
            value={note}
            onChange={e => setNote(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submitAnnotation(); if (e.key === "Escape") setAnnotating(false); }}
            placeholder="Note for this artifact's own session…"
            rows={2}
            className="w-full resize-none bg-surface-1 border border-border rounded-md px-2 py-1 text-2xs text-primary placeholder:text-muted focus:outline-none focus:border-accent-blue/50 transition-colors"
          />
          <div className="flex gap-1.5">
            <button
              disabled={submittingNote || !note.trim()}
              onClick={submitAnnotation}
              className="flex-1 text-2xs font-medium py-1 rounded-md bg-accent-blue/10 border border-accent-blue/25 text-accent-blue hover:bg-accent-blue/20 transition-colors disabled:opacity-40"
            >
              Send note
            </button>
            <button
              onClick={() => setAnnotating(false)}
              className="px-2 text-2xs font-medium py-1 rounded-md bg-surface-3 border border-border text-muted hover:text-subtle transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {showContent && (
        <div className="mt-1 pt-1 border-t border-border/50">
          {isWhiteboard ? (
            whiteboardImg ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={whiteboardImg}
                alt="Whiteboard preview"
                className="max-w-full object-contain rounded mx-auto"
                style={{ maxHeight: expanded ? 240 : 80 }}
              />
            ) : (
              <p className="text-2xs text-muted">
                {isLoading ? "Loading…" : "Save the whiteboard to generate a preview."}
              </p>
            )
          ) : isImage ? (
            // eslint-disable-next-line @next/next/no-img-element
            <img
              src={full}
              alt={artifact.name}
              className="max-w-full object-contain rounded mx-auto"
              style={{ maxHeight: expanded ? 240 : 80 }}
            />
          ) : isAudio ? (
            // stopPropagation so clicking play/seek doesn't also toggle the
            // chip's own expand/collapse (parent div's onClick) or start a drag.
            <div onClick={e => e.stopPropagation()} onPointerDown={e => e.stopPropagation()}>
              <audio
                controls
                src={full}
                preload="metadata"
                className="w-full"
                style={{ colorScheme: "dark", height: "32px" }}
              />
            </div>
          ) : (
            <p className="text-2xs text-subtle whitespace-pre-wrap break-words">
              {isLoading ? "Loading…" : shown || "(empty)"}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

type ResizeEdge = "n" | "s" | "e" | "w" | "ne" | "nw" | "se" | "sw";

const RESIZE_EDGE_LABEL: Record<ResizeEdge, string> = {
  n: "top edge", s: "bottom edge", e: "right edge", w: "left edge",
  ne: "top-right corner", nw: "top-left corner", se: "bottom-right corner", sw: "bottom-left corner",
};

const EDGE_HANDLES: { edge: ResizeEdge; cursor: string; style: React.CSSProperties }[] = [
  { edge: "n", cursor: "ns-resize", style: { top: -3, left: 10, right: 10, height: 6 } },
  { edge: "s", cursor: "ns-resize", style: { bottom: -3, left: 10, right: 10, height: 6 } },
  { edge: "e", cursor: "ew-resize", style: { right: -3, top: 10, bottom: 10, width: 6 } },
  { edge: "w", cursor: "ew-resize", style: { left: -3, top: 10, bottom: 10, width: 6 } },
];

// 24x24 (not the original 14x14) — WCAG 2.5.8 Target Size minimum. Still
// anchored at the same -3px outside-bleed corner point as before, just
// extending further inward; invisible either way (hover/focus strip with
// no background), so the larger box doesn't visually clip anything.
const CORNER_HANDLES: { edge: ResizeEdge; cursor: string; style: React.CSSProperties }[] = [
  { edge: "nw", cursor: "nwse-resize", style: { top: -3, left: -3, width: 24, height: 24 } },
  { edge: "ne", cursor: "nesw-resize", style: { top: -3, right: -3, width: 24, height: 24 } },
  { edge: "sw", cursor: "nesw-resize", style: { bottom: -3, left: -3, width: 24, height: 24 } },
  { edge: "se", cursor: "nwse-resize", style: { bottom: -3, right: -3, width: 24, height: 24 } },
];
