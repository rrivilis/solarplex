"use client";

import { useState } from "react";
import { useAutoAnimate } from "@formkit/auto-animate/react";
import { WsEnvelope } from "@/lib/types";
import MarkdownContent from "@/components/MarkdownContent";
import MessageBody from "@/components/MessageBody";
import RelativeTime from "@/components/RelativeTime";
import HandoffSummary from "@/components/HandoffSummary";
import EventTypeFilterBar from "@/components/EventTypeFilterBar";
import { useEventTypeFilter } from "@/lib/eventFilter";
import { EVENT_COLOR, DOT_COLOR, EVENT_LABEL, eventSummary, INTERNAL_WS } from "@/lib/eventTaxonomy";

// Re-exported for existing consumers (SyncWorkspace, app/sessions/[id]) —
// the actual definitions now live in lib/eventTaxonomy.ts, which has no
// component imports. /activity and /search import directly from there
// instead of through here, so they no longer drag in MarkdownContent's
// react-markdown/rehype-highlight/highlight.js chain (~330kB parsed) just
// for three lookup tables they never rendered markdown from anyway.
export { EVENT_COLOR, DOT_COLOR, EVENT_LABEL, eventSummary, INTERNAL_WS };

// ── Markdown rendering — see MarkdownContent.tsx ─────────────────────────────
const MessageContent = MarkdownContent;

// ── Visit summary helpers ─────────────────────────────────────────────────────

interface VisitSummaryItem {
  icon: string;
  color: string;
  text: string;
}

function buildVisitSummary(
  events: WsEnvelope[],
  since: string,
  actorId?: string,
  actorNames: Record<string, string> = {},
): VisitSummaryItem[] {
  const resolve = (id: unknown): string =>
    typeof id === "string" ? (actorNames[id] ?? id) : String(id ?? "");
  const cutoff = new Date(since).getTime();
  const fresh = events.filter(
    e => e.timestamp && new Date(e.timestamp).getTime() > cutoff,
  );
  if (fresh.length === 0) return [];

  const items: VisitSummaryItem[] = [];

  const transfers = fresh.filter(e => e.type === "ownership.transferred");
  if (transfers.length > 0) {
    const last = transfers[transfers.length - 1];
    const p = (last.payload ?? {}) as Record<string, unknown>;
    items.push({
      icon: "⇄",
      color: "text-accent-purple",
      text: `Ownership transferred${p.to ? ` to ${resolve(p.to)}` : ""}`,
    });
  }

  const approvals = fresh.filter(
    e => e.type === "approval.granted" || e.type === "approval.denied",
  );
  if (approvals.length > 0) {
    items.push({
      icon: "✓",
      color: "text-accent-green",
      text: `${approvals.length} approval${approvals.length > 1 ? "s" : ""} resolved`,
    });
  }

  const artifacts = fresh.filter(e => e.type === "artifact.created");
  if (artifacts.length > 0) {
    items.push({
      icon: "◈",
      color: "text-accent-blue",
      text: `${artifacts.length} artifact${artifacts.length > 1 ? "s" : ""} created`,
    });
  }

  const joins = fresh.filter(e => e.type === "actor.joined");
  if (joins.length > 0) {
    const actors = [...new Set(joins.map(e => resolve(e.actor)))];
    items.push({
      icon: "⊕",
      color: "text-subtle",
      text: actors.length === 1
        ? `${actors[0]} joined`
        : `${actors.length} actors joined`,
    });
  }

  // @ mentions of the current user
  if (actorId) {
    const mentionPattern = new RegExp(`@${actorId}(?:\\b|$)`, "i");
    const mentions = fresh.filter(
      e => e.type === "message.posted" &&
           e.actor !== actorId &&
           mentionPattern.test(String((e.payload as Record<string, unknown>)?.content ?? "")),
    );
    if (mentions.length > 0) {
      const mentioners = [...new Set(mentions.map(e => resolve(e.actor)))];
      items.push({
        icon: "@",
        color: "text-accent-blue",
        text: mentions.length === 1
          ? `${mentioners[0]} mentioned you`
          : `${mentioners.length > 1 ? mentioners.slice(0, 2).join(", ") : mentioners[0]} mentioned you ${mentions.length} times`,
      });
    }
  }

  return items;
}

// ── Visit summary card ────────────────────────────────────────────────────────

function VisitSummaryCard({
  events,
  since,
  actorId,
  actorNames,
  onDismiss,
}: {
  events: WsEnvelope[];
  actorId?: string;
  since: string;
  actorNames?: Record<string, string>;
  onDismiss: () => void;
}) {
  const items = buildVisitSummary(events, since, actorId, actorNames);
  if (items.length === 0) return null;

  return (
    <div className="mx-6 my-3 rounded-xl border border-accent-blue/20 bg-accent-blue/5 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-3.5 py-2.5 border-b border-accent-blue/15">
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-blue shrink-0" />
          <span className="text-2xs font-semibold text-accent-blue uppercase tracking-widest">
            Since your last visit
          </span>
        </div>
        <button
          onClick={onDismiss}
          className="text-muted hover:text-subtle transition-colors text-xs leading-none p-0.5"
          title="Dismiss"
          aria-label="Dismiss"
        >
          ✕
        </button>
      </div>

      {/* Items */}
      <div className="px-3.5 py-2.5 space-y-1.5">
        {items.map((item, i) => (
          <div key={i} className="flex items-center gap-2.5 text-xs">
            <span className={`text-sm leading-none shrink-0 ${item.color}`}>{item.icon}</span>
            <span className="text-subtle">{item.text}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Timeline({
  events,
  sessionId,
  pendingCount = 0,
  actorId,
  actorNames,
  lastVisitTime,
  onDismissVisitSummary,
}: {
  events: WsEnvelope[];
  /** Needed so a voice-memo message.posted event can render its
   *  VoiceMemoPlayer instead of leaking the raw "[artifact:ID]" text —
   *  see MessageBody's doc comment. */
  sessionId: string;
  pendingCount?: number;
  actorId?: string;
  /** actor_id -> display name, derived from the session snapshot's already-
   *  resolved members list. Events keep storing the raw id forever; this is
   *  what lets a rename show up retroactively across all history. */
  actorNames?: Record<string, string>;
  lastVisitTime?: string | null;
  onDismissVisitSummary?: () => void;
}) {
  const filtered = events.filter(e => !INTERNAL_WS.has(e.type));
  const [listRef] = useAutoAnimate<HTMLDivElement>();
  const [visitDismissed, setVisitDismissed] = useState(false);
  const { enabled: enabledCategories, toggle: toggleCategory, isEnabled } = useEventTypeFilter();

  const handleDismiss = () => {
    setVisitDismissed(true);
    onDismissVisitSummary?.();
  };

  if (filtered.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center gap-2.5 text-center px-8">
        <div className="w-10 h-10 rounded-xl bg-surface-2 border border-border flex items-center justify-center mb-1">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
            className="text-muted">
            <path d="M12 2L2 7l10 5 10-5-10-5z" />
            <path d="M2 17l10 5 10-5" />
            <path d="M2 12l10 5 10-5" />
          </svg>
        </div>
        <p className="text-xs font-medium text-subtle">No events yet</p>
        <p className="text-2xs text-muted leading-relaxed">
          Events appear here as agents act and humans respond.
          <br />
          Every tool call, approval, and handoff is recorded.
        </p>
      </div>
    );
  }

  // Category filter narrows what's *rendered*; the visit summary above
  // stays computed off the full unfiltered history — it's a distinct,
  // already-curated digest, not something the type toggles should thin out.
  const categoryFiltered = filtered.filter(e => isEnabled(e.type));

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="shrink-0 px-6 py-2.5 border-b border-border/60">
        <EventTypeFilterBar enabled={enabledCategories} onToggle={toggleCategory} />
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Visit summary — shown once per session attach, dismissed by user */}
        {lastVisitTime && !visitDismissed && (
          <VisitSummaryCard
            events={filtered}
            since={lastVisitTime}
            actorId={actorId}
            actorNames={actorNames}
            onDismiss={handleDismiss}
          />
        )}

        {categoryFiltered.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-1.5 text-center px-8 py-14">
            <p className="text-xs font-medium text-subtle">No activity matches your filter</p>
            <p className="text-2xs text-muted">Turn a category back on above to see it.</p>
          </div>
        ) : (
        <div ref={listRef}>
        {[...categoryFiltered].sort((a, b) => (b.seq ?? 0) - (a.seq ?? 0)).map((event, i) => {
          const isApproval = event.type.startsWith("approval.");
          const isTool = event.type.startsWith("tool.");
          const isHandoff = event.type === "ownership.transferred";

          return (
            <div key={event.id}>
              {isHandoff && (
                <HandoffSummary
                  event={event}
                  allEvents={events}
                  pendingCount={pendingCount}
                  actorNames={actorNames}
                />
              )}
              <div
                className={`flex items-start gap-3 px-6 py-2.5 border-b border-border/40 hover:bg-surface-1 transition-colors group ${
                  isApproval ? "hover:bg-accent-amber/3" : ""
                }`}
              >
                {/* Seq */}
                <span className="text-2xs text-muted w-9 shrink-0 mt-0.5 font-mono text-right tabular-nums select-none">
                  {event.seq ?? i}
                </span>

                {/* Dot */}
                <div className="flex flex-col items-center shrink-0 mt-1.5">
                  <span
                    className={`w-1.5 h-1.5 rounded-full ${DOT_COLOR[event.type] ?? "bg-surface-4"}`}
                  />
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-baseline gap-2 flex-wrap">
                    <span
                      className={`text-xs font-medium ${EVENT_COLOR[event.type] ?? "text-subtle"}`}
                    >
                      {EVENT_LABEL[event.type] ?? event.type}
                    </span>
                    <span className="text-xs text-subtle truncate">
                      {eventSummary(event, actorNames)}
                    </span>
                  </div>

                  {/* Extra detail for tool calls */}
                  {isTool && !!(event.payload as Record<string, unknown>)?.tool && (() => {
                    const p = event.payload as Record<string, unknown>;
                    const toolName = p.tool as string;
                    const args = p.args as Record<string, unknown> | undefined;
                    const argKeys = args ? Object.keys(args) : [];
                    return (
                      <div className="mt-0.5">
                        <code className="text-2xs font-mono text-muted bg-surface-2 px-1.5 py-0.5 rounded">
                          {toolName}
                          {argKeys.length > 0 && ` (${argKeys.join(", ")})`}
                        </code>
                      </div>
                    );
                  })()}

                  {/* Message content — MessageBody renders the actual
                      VoiceMemoPlayer/file chip for voice-memo and file
                      uploads instead of the raw "[artifact:ID]" text. */}
                  {event.type === "message.posted" && (() => {
                    const content = String((event.payload as Record<string, unknown>)?.content ?? "");
                    return content ? (
                      <div className="mt-1.5">
                        <MessageBody sessionId={event.session_id ?? sessionId} content={content} />
                      </div>
                    ) : null;
                  })()}

                  {/* Markdown content for context entries */}
                  {event.type === "context.entry.added" && (() => {
                    const content = String((event.payload as Record<string, unknown>)?.content ?? "");
                    return content ? (
                      <div className="mt-1.5 border-l border-accent-purple/30 pl-2.5">
                        <MessageContent content={content} />
                      </div>
                    ) : null;
                  })()}
                </div>

                {/* Live-ticking timestamp */}
                {event.timestamp && (
                  <RelativeTime
                    date={event.timestamp}
                    className="text-2xs text-muted shrink-0 mt-0.5 tabular-nums"
                  />
                )}
              </div>
            </div>
          );
        })}
        </div>
        )}
      </div>
    </div>
  );
}
