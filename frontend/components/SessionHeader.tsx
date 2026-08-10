"use client";

import { SessionSnapshot } from "@/lib/types";

interface Props {
  sessionId: string;
  sessionName: string;
  snapshot: SessionSnapshot | null;
  connected: boolean;
}

export default function SessionHeader({ sessionId, sessionName, snapshot, connected }: Props) {
  const pendingCount = snapshot?.pending_approvals.length ?? 0;
  const owner = snapshot?.owner;
  const ownerName = snapshot?.owner_name ?? owner;
  const status = snapshot?.status ?? "active";

  const statusLabel: Record<string, string> = {
    active: "Active",
    suspended: "Suspended",
    archived: "Archived",
  };

  const statusColor: Record<string, string> = {
    active: "text-accent-green",
    suspended: "text-accent-amber",
    archived: "text-muted",
  };

  return (
    <div className="h-11 shrink-0 border-b border-border px-5 flex items-center gap-5 bg-surface-1">
      {/* Session identity */}
      <div className="flex items-center gap-2 min-w-0">
        <span
          className={`w-1.5 h-1.5 rounded-full shrink-0 ${
            connected ? "bg-accent-green" : "bg-surface-4"
          }`}
        />
        <span className="font-medium text-sm text-primary truncate">{sessionName}</span>
        <span className="text-muted text-2xs font-mono shrink-0">{sessionId.slice(0, 8)}</span>
      </div>

      {/* Status badge */}
      <span className={`text-2xs font-medium shrink-0 ${statusColor[status]}`}>
        {statusLabel[status] ?? status}
      </span>

      <div className="flex-1" />

      {/* Owner */}
      {owner && ownerName && (
        <div className="flex items-center gap-1.5 shrink-0">
          <span className="text-2xs text-muted">owner</span>
          <div className="w-5 h-5 rounded-full bg-accent-blue/20 text-accent-blue flex items-center justify-center text-2xs font-semibold">
            {ownerName.slice(0, 2).toUpperCase()}
          </div>
          <span className="text-xs text-subtle">{ownerName}</span>
        </div>
      )}

      {/* Pending approvals indicator */}
      {pendingCount > 0 && (
        <div className="flex items-center gap-1.5 shrink-0 px-2 py-1 rounded bg-accent-amber/10 border border-accent-amber/20">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-amber animate-pulse shrink-0" />
          <span className="text-2xs text-accent-amber font-medium">
            {pendingCount} pending
          </span>
        </div>
      )}

      {/* Connection indicator */}
      <div className="flex items-center gap-1.5 shrink-0">
        <span className={`text-2xs ${connected ? "text-muted" : "text-accent-red"}`}>
          {connected ? "Connected" : "Reconnecting…"}
        </span>
      </div>
    </div>
  );
}
