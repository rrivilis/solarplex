"use client";

import { PendingApproval } from "@/lib/types";
import RelativeTime from "@/components/RelativeTime";

interface Props {
  approvals: PendingApproval[];
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onClaim: (id: string) => void;
}

function ExpiryCountdown({ expiresAt }: { expiresAt: string }) {
  const remaining = new Date(expiresAt).getTime() - Date.now();
  if (remaining < 0) return <span className="text-accent-red">Expired</span>;
  return (
    <span className="flex items-center gap-1">
      expires <RelativeTime date={expiresAt} as="span" />
    </span>
  );
}

function StateBadge({ state }: { state: string }) {
  const styles: Record<string, string> = {
    Pending:   "text-subtle bg-surface-3 border-border",
    Claimed:   "text-accent-purple bg-accent-purple/10 border-accent-purple/20",
    Contested: "text-accent-amber bg-accent-amber/10 border-accent-amber/20",
  };
  return (
    <span
      className={`text-2xs px-1.5 py-0.5 rounded border font-medium ${
        styles[state] ?? "text-muted bg-surface-3 border-border"
      }`}
    >
      {state}
    </span>
  );
}

function ApprovalCard({
  approval,
  onApprove,
  onDeny,
  onClaim,
}: {
  approval: PendingApproval;
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onClaim: (id: string) => void;
}) {
  const { approval_id, tool, requested_by, state, votes, claimed_by, expires_at } = approval;

  const borderAccent =
    state === "Contested"
      ? "border-accent-amber/40"
      : state === "Claimed"
      ? "border-accent-purple/30"
      : "border-border";

  const topBar =
    state === "Contested"
      ? "bg-accent-amber"
      : state === "Claimed"
      ? "bg-accent-purple"
      : "bg-border";

  const voteEntries = Object.entries(votes ?? {});

  return (
    <div
      className={`mx-3 mb-2.5 rounded-lg border ${borderAccent} bg-surface-2 overflow-hidden`}
    >
      {/* State indicator bar */}
      <div className={`h-0.5 w-full ${topBar}`} />

      <div className="p-3">
        {/* Tool + state */}
        <div className="flex items-start justify-between gap-2 mb-2">
          <code className="text-accent-blue text-xs font-mono font-medium truncate flex-1 leading-tight">
            {tool}
          </code>
          <StateBadge state={state} />
        </div>

        {/* Requested by + expiry */}
        <div className="text-2xs text-muted mb-1">
          by{" "}
          <span className="text-subtle">{requested_by}</span>
          {expires_at && (
            <>
              {" · "}
              <ExpiryCountdown expiresAt={expires_at} />
            </>
          )}
        </div>

        {/* Contested: vote breakdown */}
        {state === "Contested" && voteEntries.length > 0 && (
          <div className="mt-2 pt-2 border-t border-border space-y-1">
            <p className="text-2xs text-accent-amber font-medium mb-1">
              Owner resolution required
            </p>
            {voteEntries.map(([actor, vote]) => (
              <div key={actor} className="flex items-center gap-1.5 text-2xs">
                <span
                  className={`font-mono font-medium ${
                    vote === "approve" ? "text-accent-green" : "text-accent-red"
                  }`}
                >
                  {vote === "approve" ? "+" : "−"}
                </span>
                <span className="text-subtle">{actor}</span>
                <span className="text-muted">·</span>
                <span className="text-muted">{vote}</span>
              </div>
            ))}
          </div>
        )}

        {/* Claimed by */}
        {state === "Claimed" && claimed_by && (
          <div className="mt-1 text-2xs text-accent-purple">
            Being reviewed by {claimed_by}
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-1.5 mt-3">
          {state !== "Claimed" && (
            <button
              onClick={() => onClaim(approval_id)}
              className="text-2xs py-1 px-2 rounded bg-surface-3 border border-border text-subtle hover:text-primary hover:bg-surface-4 transition-colors font-medium"
            >
              Claim
            </button>
          )}
          <button
            onClick={() => onApprove(approval_id)}
            className="flex-1 text-2xs py-1 px-2 rounded bg-accent-green/10 border border-accent-green/20 text-accent-green hover:bg-accent-green/20 transition-colors font-semibold"
          >
            Approve
          </button>
          <button
            onClick={() => onDeny(approval_id)}
            className="flex-1 text-2xs py-1 px-2 rounded bg-accent-red/10 border border-accent-red/20 text-accent-red hover:bg-accent-red/20 transition-colors font-semibold"
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  );
}

export default function ApprovalPanel({ approvals, onApprove, onDeny, onClaim }: Props) {
  const pendingCount = approvals.filter((a) => a.state === "Pending").length;
  const contestedCount = approvals.filter((a) => a.state === "Contested").length;

  return (
    <aside className="w-72 shrink-0 flex flex-col bg-surface-0">
      {/* Header */}
      <div className="h-9 px-4 border-b border-border flex items-center justify-between shrink-0">
        <span className="text-2xs text-muted uppercase tracking-widest font-medium">
          Approvals
        </span>
        <div className="flex items-center gap-1.5">
          {contestedCount > 0 && (
            <span className="text-2xs bg-accent-amber/15 text-accent-amber border border-accent-amber/25 px-1.5 py-0.5 rounded font-medium">
              {contestedCount} contested
            </span>
          )}
          {pendingCount > 0 && (
            <span className="text-2xs bg-surface-3 text-subtle border border-border px-1.5 py-0.5 rounded font-medium">
              {pendingCount}
            </span>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto py-3">
        {approvals.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-1.5 px-6 text-center">
            <span className="text-xl text-border select-none">✓</span>
            <p className="text-xs text-muted">No pending approvals</p>
            <p className="text-2xs text-muted">
              Agents will pause here when a tool requires your review
            </p>
          </div>
        ) : (
          approvals.map((a) => (
            <ApprovalCard
              key={a.approval_id}
              approval={a}
              onApprove={onApprove}
              onDeny={onDeny}
              onClaim={onClaim}
            />
          ))
        )}
      </div>
    </aside>
  );
}
