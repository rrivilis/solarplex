"use client";

import { useState } from "react";
import { WsEnvelope } from "@/lib/types";

interface Props {
  event: WsEnvelope;
  allEvents: WsEnvelope[];
  pendingCount: number;
  actorNames?: Record<string, string>;
}

export default function HandoffSummary({ event, allEvents, pendingCount, actorNames = {} }: Props) {
  const [open, setOpen] = useState(true);

  const p = (event.payload ?? {}) as Record<string, unknown>;
  const fromId = p.from as string | undefined;
  const toId   = p.to   as string | undefined;
  const from = fromId ? (actorNames[fromId] ?? fromId) : undefined;
  const to   = toId   ? (actorNames[toId]   ?? toId)   : undefined;

  // Events prior to this transfer (chronologically earlier)
  const earlier = allEvents.filter(
    e => e.timestamp && event.timestamp && e.timestamp <= event.timestamp && e.id !== event.id
  );

  const decisions = earlier
    .filter(e => e.type === "approval.granted" || e.type === "approval.denied")
    .slice(-5)
    .map(e => ({
      id: e.id,
      approved: e.type === "approval.granted",
      tool: (e.payload as any)?.tool ?? (e.payload as any)?.approval_id?.slice(0, 8) ?? "unknown",
    }));

  const artifacts = earlier
    .filter(e => e.type === "artifact.created" || e.type === "artifact.updated")
    .reduce<{ id: string; name: string }[]>((acc, e) => {
      const name = (e.payload as any)?.name as string | undefined;
      if (name && !acc.find(a => a.name === name)) acc.push({ id: e.id, name });
      return acc;
    }, [])
    .slice(-5);

  const blockedApprovals = allEvents.filter(
    e => e.type === "approval.requested" &&
    !allEvents.some(e2 =>
      (e2.type === "approval.granted" || e2.type === "approval.denied") &&
      (e2.payload as any)?.approval_id === (e.payload as any)?.approval_id
    )
  ).slice(-3);

  return (
    <div className="mx-4 my-4 rounded-xl border border-accent-purple/25 bg-accent-purple/5 overflow-hidden">
      <button
        className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-accent-purple/5 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        <div className="flex items-center gap-2.5">
          <span className="w-2 h-2 rounded-full bg-accent-purple shrink-0" />
          <span className="text-xs font-semibold text-accent-purple">Session Handoff</span>
          {from && to && (
            <span className="text-2xs text-muted">{from} → {to}</span>
          )}
        </div>
        <span className="text-muted text-xs select-none">{open ? "▲" : "▼"}</span>
      </button>

      {open && (
        <div className="border-t border-accent-purple/15 px-4 pb-4 pt-3 space-y-3.5">
          {/* New owner */}
          <div>
            <p className="text-2xs text-muted uppercase tracking-widest mb-1.5">Current Owner</p>
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded-full bg-accent-blue/20 text-accent-blue flex items-center justify-center text-2xs font-semibold">
                {(to ?? "?").slice(0, 2).toUpperCase()}
              </div>
              <span className="text-sm font-semibold text-primary">{to ?? "Unknown"}</span>
            </div>
          </div>

          {/* Blocked / pending */}
          {(blockedApprovals.length > 0 || pendingCount > 0) && (
            <div>
              <p className="text-2xs text-muted uppercase tracking-widest mb-1.5">Blocked</p>
              {blockedApprovals.length > 0 ? (
                <div className="space-y-1">
                  {blockedApprovals.map(e => (
                    <div key={e.id} className="flex items-center gap-1.5 text-xs text-subtle">
                      <span className="w-1.5 h-1.5 rounded-full bg-accent-amber animate-pulse shrink-0" />
                      <span>{e.actor} waiting on </span>
                      <code className="text-accent-blue font-mono text-2xs">
                        {(e.payload as any)?.tool ?? "approval"}
                      </code>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-2 text-xs text-accent-amber">
                  <span className="w-1.5 h-1.5 rounded-full bg-accent-amber animate-pulse shrink-0" />
                  {pendingCount} approval request{pendingCount > 1 ? "s" : ""} pending
                </div>
              )}
            </div>
          )}

          {/* Recent artifacts */}
          {artifacts.length > 0 && (
            <div>
              <p className="text-2xs text-muted uppercase tracking-widest mb-1.5">Recent Artifacts</p>
              <div className="space-y-1">
                {artifacts.map(a => (
                  <div key={a.id} className="flex items-center gap-1.5 text-xs text-subtle">
                    <span className="text-border">⬡</span>
                    <span>{a.name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Recent decisions */}
          {decisions.length > 0 && (
            <div>
              <p className="text-2xs text-muted uppercase tracking-widest mb-1.5">Recent Decisions</p>
              <div className="space-y-1">
                {decisions.map(d => (
                  <div key={d.id} className="flex items-center gap-1.5 text-xs">
                    <span className={`font-semibold ${d.approved ? "text-accent-green" : "text-accent-red"}`}>
                      {d.approved ? "✓" : "✗"}
                    </span>
                    <span className="text-subtle">
                      {d.approved ? "Approved" : "Denied"}{" "}
                      <code className="text-accent-blue font-mono text-2xs">{d.tool}</code>
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {artifacts.length === 0 && decisions.length === 0 && pendingCount === 0 && blockedApprovals.length === 0 && (
            <p className="text-xs text-muted">Session is clear — no pending items at handoff.</p>
          )}
        </div>
      )}
    </div>
  );
}
