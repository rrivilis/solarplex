"use client";

import { useState } from "react";
import { ContextEntry, ContextEntryKind } from "@/lib/types";
import RelativeTime from "@/components/RelativeTime";

interface Props {
  entries: ContextEntry[];
  onAdd: (kind: ContextEntryKind, content: string) => void;
  onResolve: (entryId: string, note?: string) => void;
  actorNames?: Record<string, string>;
}

// ── Kind config ───────────────────────────────────────────────────────────────

const KIND_CONFIG: Record<ContextEntryKind, {
  label: string;
  abbr: string;
  color: string;         // badge colors
  border: string;        // card border when active
  description: string;
}> = {
  fact: {
    label: "Fact",
    abbr: "FACT",
    color: "text-accent-blue bg-accent-blue/10 border-accent-blue/30",
    border: "border-accent-blue/20",
    description: "Verified, ground-truth observation",
  },
  hypothesis: {
    label: "Hypothesis",
    abbr: "HYPO",
    color: "text-accent-purple bg-accent-purple/10 border-accent-purple/30",
    border: "border-accent-purple/20",
    description: "Working theory, not yet confirmed",
  },
  question: {
    label: "Question",
    abbr: "Q?",
    color: "text-accent-amber bg-accent-amber/10 border-accent-amber/30",
    border: "border-accent-amber/20",
    description: "Open unknown that needs resolution",
  },
  constraint: {
    label: "Constraint",
    abbr: "CSTR",
    color: "text-accent-red bg-accent-red/10 border-accent-red/30",
    border: "border-accent-red/20",
    description: "Hard boundary on what we can do",
  },
  decision: {
    label: "Decision",
    abbr: "DCSN",
    color: "text-accent-green bg-accent-green/10 border-accent-green/30",
    border: "border-accent-green/20",
    description: "Committed choice, closes open questions",
  },
};

const KINDS = Object.keys(KIND_CONFIG) as ContextEntryKind[];

// ── Resolve dialog ────────────────────────────────────────────────────────────

function ResolveDialog({
  entry,
  onConfirm,
  onCancel,
}: {
  entry: ContextEntry;
  onConfirm: (note: string) => void;
  onCancel: () => void;
}) {
  const [note, setNote] = useState("");
  return (
    <div className="mt-2 p-3 rounded-lg bg-surface-0 border border-border space-y-2">
      <p className="text-2xs text-muted">Resolution note (optional)</p>
      <input
        autoFocus
        value={note}
        onChange={e => setNote(e.target.value)}
        onKeyDown={e => { if (e.key === "Enter") onConfirm(note); if (e.key === "Escape") onCancel(); }}
        placeholder="e.g. Confirmed by logs, superseded by decision #4…"
        className="w-full bg-surface-1 border border-border rounded-lg px-3 py-1.5 text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent-blue/50 transition-colors"
      />
      <div className="flex gap-2">
        <button
          onClick={() => onConfirm(note)}
          className="flex-1 text-2xs font-medium py-1.5 rounded-lg bg-accent-green/10 border border-accent-green/30 text-accent-green hover:bg-accent-green/20 transition-colors"
        >
          Mark resolved
        </button>
        <button
          onClick={onCancel}
          className="px-3 text-2xs font-medium py-1.5 rounded-lg bg-surface-3 border border-border text-muted hover:text-subtle transition-colors"
        >
          Cancel
        </button>
      </div>
    </div>
  );
}

// ── Entry card ────────────────────────────────────────────────────────────────

function EntryCard({
  entry,
  onResolve,
  actorNames = {},
}: {
  entry: ContextEntry;
  onResolve: (entryId: string, note?: string) => void;
  actorNames?: Record<string, string>;
}) {
  const [resolving, setResolving] = useState(false);
  const cfg = KIND_CONFIG[entry.kind];

  return (
    <div
      className={`rounded-xl border px-4 py-3.5 transition-all ${
        entry.resolved
          ? "bg-surface-0 border-border opacity-45"
          : `bg-surface-1 ${cfg.border}`
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        {/* Left: stacked label → content → attribution */}
        <div className="flex-1 min-w-0 space-y-1.5">
          {/* Kind label — uppercase, colored, small mono */}
          <p className={`text-2xs font-mono font-bold tracking-widest ${
            entry.resolved ? "opacity-50 " : ""
          }${cfg.color.split(" ")[0]}`}>
            {cfg.label.toUpperCase()}
          </p>

          {/* Content */}
          <p className={`text-sm leading-relaxed ${
            entry.resolved ? "text-muted line-through decoration-1" : "text-primary"
          }`}>
            {entry.content}
          </p>

          {/* Attribution */}
          <p className="text-2xs text-muted">
            Added by {actorNames[entry.actor_id] ?? entry.actor_id}
            {" · "}
            <RelativeTime date={entry.timestamp} as="span" className="text-2xs text-muted" />
            {entry.resolved && entry.resolved_by && (
              <span className="text-accent-green"> · resolved by {actorNames[entry.resolved_by] ?? entry.resolved_by}</span>
            )}
          </p>

          {/* Resolution note */}
          {entry.resolved && entry.resolution_note && (
            <p className="text-2xs text-muted italic border-l-2 border-border pl-2 mt-1">
              {entry.resolution_note}
            </p>
          )}

          {/* Resolve dialog */}
          {!entry.resolved && resolving && (
            <ResolveDialog
              entry={entry}
              onConfirm={(note) => {
                onResolve(entry.id, note || undefined);
                setResolving(false);
              }}
              onCancel={() => setResolving(false)}
            />
          )}
        </div>

        {/* Resolve button */}
        {!entry.resolved && !resolving && (
          <button
            onClick={() => setResolving(true)}
            title="Mark resolved"
            aria-label="Mark resolved"
            className="shrink-0 mt-0.5 w-6 h-6 flex items-center justify-center rounded-md text-border hover:text-accent-green hover:bg-accent-green/10 transition-all"
          >
            <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
              <path d="M3 8l4 4 6-7" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ContextTab({ entries, onAdd, onResolve, actorNames = {} }: Props) {
  const [kind, setKind] = useState<ContextEntryKind>("fact");
  const [content, setContent] = useState("");
  const [showResolved, setShowResolved] = useState(false);

  const active   = entries.filter(e => !e.resolved);
  const resolved = entries.filter(e => e.resolved);

  function handleSubmit() {
    const trimmed = content.trim();
    if (!trimmed) return;
    onAdd(kind, trimmed);
    setContent("");
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 overflow-hidden">

      {/* ── Composer ── */}
      <div className="px-5 pt-4 pb-3 border-b border-border shrink-0">
        <p className="text-2xs font-semibold text-subtle uppercase tracking-widest mb-3">
          Add entry
        </p>

        {/* Kind selector */}
        <div className="flex gap-1.5 flex-wrap mb-3">
          {KINDS.map(k => {
            const c = KIND_CONFIG[k];
            return (
              <button
                key={k}
                onClick={() => setKind(k)}
                title={c.description}
                className={`text-2xs font-mono font-semibold px-2 py-1 rounded border transition-all ${
                  kind === k ? c.color : "text-muted bg-surface-2 border-border hover:border-subtle hover:text-subtle"
                }`}
              >
                {c.abbr}
              </button>
            );
          })}
        </div>

        {/* Text + submit */}
        <div className="flex gap-2">
          <textarea
            value={content}
            onChange={e => setContent(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) handleSubmit(); }}
            placeholder={`${KIND_CONFIG[kind].description}…`}
            rows={2}
            className="flex-1 resize-none bg-surface-1 border border-border rounded-xl px-3 py-2 text-sm text-primary placeholder:text-muted
                       focus:outline-none focus:border-accent-blue/50 transition-colors leading-relaxed"
          />
          <button
            onClick={handleSubmit}
            disabled={!content.trim()}
            className="shrink-0 self-end px-3 py-2 rounded-xl text-xs font-medium
                       bg-accent-blue/10 border border-accent-blue/25 text-accent-blue
                       hover:bg-accent-blue/20 hover:border-accent-blue/40
                       transition-all disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Add
          </button>
        </div>
        <p className="text-2xs text-muted mt-1.5">⌘↵ to submit</p>
      </div>

      {/* ── Entry list ── */}
      <div className="flex-1 overflow-y-auto px-5 py-4 space-y-2">

        {active.length === 0 && resolved.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-2 h-32 text-center">
            <p className="text-xs text-muted font-medium">No context entries yet</p>
            <p className="text-2xs text-muted leading-relaxed">
              Capture operational context for participating humans and agents.
              <br /><br />
              Facts, hypotheses, questions, constraints, and decisions
              <br />persist with the session.
            </p>
          </div>
        )}

        {active.map(e => (
          <EntryCard key={e.id} entry={e} onResolve={onResolve} actorNames={actorNames} />
        ))}

        {resolved.length > 0 && (
          <div className="pt-2">
            <button
              onClick={() => setShowResolved(v => !v)}
              className="flex items-center gap-2 text-2xs text-muted hover:text-subtle transition-colors mb-2 w-full"
            >
              <span className={`transition-transform duration-150 ${showResolved ? "rotate-90" : ""}`}>▶</span>
              {resolved.length} resolved
            </button>
            {showResolved && (
              <div className="space-y-2">
                {resolved.map(e => (
                  <EntryCard key={e.id} entry={e} onResolve={onResolve} actorNames={actorNames} />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
