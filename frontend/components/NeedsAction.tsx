"use client";

import { useState } from "react";
import { useAutoAnimate } from "@formkit/auto-animate/react";
import {
  useFloating,
  useClick,
  useDismiss,
  useRole,
  useInteractions,
  FloatingPortal,
  offset,
  flip,
  shift,
} from "@floating-ui/react";
import { PendingApproval, SessionSnapshot, WsEnvelope } from "@/lib/types";
import RelativeTime from "@/components/RelativeTime";
import { useModalA11y } from "@/hooks/useModalA11y";

interface Props {
  approvals: PendingApproval[];
  snapshot?: SessionSnapshot | null;
  pastEvents?: WsEnvelope[];
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onClaim: (id: string) => void;
  // Off-canvas overlay below the lg breakpoint — see StatusPanel's Props
  // comment for why (WCAG 1.4.10 Reflow).
  mobileOpen: boolean;
  onMobileClose: () => void;
}

const STATE_BADGE: Record<string, string> = {
  Pending:   "text-subtle bg-surface-3 border-border",
  Claimed:   "text-accent-purple bg-accent-purple/10 border-accent-purple/20",
  Contested: "text-accent-amber  bg-accent-amber/10  border-accent-amber/20",
};

const TOP_BAR: Record<string, string> = {
  Pending:   "bg-border",
  Claimed:   "bg-accent-purple",
  Contested: "bg-accent-amber",
};

const POLICY_LABEL: Record<string, string> = {
  single_vote: "Single vote",
  majority:    "Majority",
  unanimous:   "Unanimous",
};

// ── Chevron icon ──────────────────────────────────────────────────────────────
function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      width="10" height="10" viewBox="0 0 10 10" fill="none"
      stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"
      className={`text-muted transition-transform duration-150 ${open ? "rotate-180" : ""}`}
    >
      <path d="M2 4l3 3 3-3" />
    </svg>
  );
}

// ── Collapsible disclosure section ───────────────────────────────────────────
function DisclosureSection({
  label,
  defaultOpen = false,
  children,
}: {
  label: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border-b border-border/60 last:border-0">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-2.5 text-left hover:bg-surface-1 transition-colors group"
      >
        <span className="text-2xs uppercase tracking-widest text-muted font-medium group-hover:text-subtle transition-colors">
          {label}
        </span>
        <Chevron open={open} />
      </button>
      {open && (
        <div className="px-4 pb-3.5">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Floating action menu ──────────────────────────────────────────────────────
function ActionMenu({
  approvalId,
  state,
  onApprove,
  onDeny,
  onClaim,
}: {
  approvalId: string;
  state: string;
  onApprove: (id: string) => void;
  onDeny: (id: string) => void;
  onClaim: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);

  const { refs, floatingStyles, context } = useFloating({
    open,
    onOpenChange: setOpen,
    middleware: [offset(6), flip(), shift({ padding: 8 })],
    placement: "bottom-end",
  });

  const click   = useClick(context);
  const dismiss = useDismiss(context);
  const role    = useRole(context, { role: "menu" });
  const { getReferenceProps, getFloatingProps } = useInteractions([click, dismiss, role]);

  function act(fn: () => void) {
    fn();
    setOpen(false);
  }

  return (
    <>
      <button
        ref={refs.setReference}
        {...getReferenceProps()}
        aria-label="Actions"
        className="p-1.5 rounded-lg text-muted hover:text-subtle hover:bg-surface-3 transition-colors text-xs leading-none select-none"
        title="Actions"
      >
        ⋯
      </button>

      {open && (
        <FloatingPortal>
          <div
            ref={refs.setFloating}
            style={floatingStyles}
            {...getFloatingProps()}
            className="z-50 min-w-[140px] bg-surface-2 border border-border rounded-xl shadow-elevation-float overflow-hidden"
          >
            <button
              role="menuitem"
              onClick={() => act(() => onApprove(approvalId))}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-accent-green hover:bg-accent-green/8 transition-colors text-left"
            >
              <span className="text-sm leading-none">✓</span>
              Approve
            </button>
            <button
              role="menuitem"
              onClick={() => act(() => onDeny(approvalId))}
              className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-accent-red hover:bg-accent-red/8 transition-colors text-left"
            >
              <span className="text-sm leading-none">✕</span>
              Deny
            </button>
            {state !== "Claimed" && (
              <>
                <div className="h-px bg-border mx-2" />
                <button
                  role="menuitem"
                  onClick={() => act(() => onClaim(approvalId))}
                  className="w-full flex items-center gap-2.5 px-3 py-2 text-xs text-accent-purple hover:bg-accent-purple/8 transition-colors text-left"
                >
                  <span className="text-sm leading-none">⚑</span>
                  Claim review
                </button>
              </>
            )}
          </div>
        </FloatingPortal>
      )}
    </>
  );
}

// ── Card ──────────────────────────────────────────────────────────────────────
function ActionCard({
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
  const { approval_id, tool, requested_by, state, votes, claimed_by, expires_at, requested_at } = approval;
  const voteEntries = Object.entries(votes ?? {});

  return (
    <div className={`mx-3 mb-3 rounded-xl border overflow-hidden ${
      state === "Contested" ? "border-accent-amber/35" :
      state === "Claimed"   ? "border-accent-purple/30" :
                              "border-border"
    } bg-surface-2`}>
      <div className={`h-0.5 ${TOP_BAR[state] ?? "bg-border"}`} />

      <div className="p-3.5">
        {/* Header row */}
        <div className="flex items-start justify-between gap-2 mb-2.5">
          <div className="min-w-0">
            <p className="text-xs font-semibold text-primary truncate">{requested_by}</p>
            <p className="text-2xs text-muted mt-0.5">Requesting:</p>
          </div>
          <div className="flex items-center gap-1.5 shrink-0">
            <span className={`text-2xs px-1.5 py-0.5 rounded border font-medium ${
              STATE_BADGE[state] ?? STATE_BADGE.Pending
            }`}>
              {state}
            </span>
            <ActionMenu
              approvalId={approval_id}
              state={state}
              onApprove={onApprove}
              onDeny={onDeny}
              onClaim={onClaim}
            />
          </div>
        </div>

        {/* Tool */}
        <code className="block text-xs font-mono text-accent-blue bg-surface-3 px-2.5 py-1.5 rounded-lg mb-2.5 truncate">
          {tool}
        </code>

        {/* Age / expiry — live-ticking */}
        <div className="text-2xs text-muted space-y-0.5">
          {requested_at && (
            <p className="flex items-center gap-1">
              <span>Pending</span>
              <RelativeTime date={requested_at} as="span" />
            </p>
          )}
          {expires_at && (
            <p className="flex items-center gap-1">
              <span>Expires</span>
              <RelativeTime date={expires_at} as="span" />
            </p>
          )}
        </div>

        {/* Contested votes */}
        {state === "Contested" && voteEntries.length > 0 && (
          <div className="mt-2.5 pt-2.5 border-t border-border">
            <p className="text-2xs text-accent-amber font-semibold mb-1.5">Owner resolution required</p>
            {voteEntries.map(([actor, vote]) => (
              <div key={actor} className="flex items-center gap-1.5 text-2xs mb-0.5">
                <span className={vote === "approve" ? "text-accent-green font-bold" : "text-accent-red font-bold"}>
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
          <p className="mt-2 text-2xs text-accent-purple">Reviewing: {claimed_by}</p>
        )}
      </div>
    </div>
  );
}

// ── Recent decisions section ──────────────────────────────────────────────────
//
// Aggregates the three event types that matter most for session governance:
//   approval.granted / approval.denied — gate decisions
//   ownership.transferred              — responsibility shifts
//   artifact.created                   — notable output produced
//
// Each renders as a two-line entry: subject on line 1, actor + timestamp on 2.

interface DecisionEntry {
  id: string;
  /** Accent color class for the leading mark */
  accent: string;
  /** Short mark character */
  mark: string;
  /** Primary line — what happened */
  primary: string;
  /** Secondary line — who / from→to */
  secondary: string;
  timestamp?: string;
}

function buildDecisions(events: WsEnvelope[], actorNames: Record<string, string>): DecisionEntry[] {
  const DECISION_TYPES = new Set([
    "approval.granted",
    "approval.denied",
    "ownership.transferred",
    "artifact.created",
  ]);

  return events
    .filter(e => DECISION_TYPES.has(e.type))
    .slice(-12)           // keep plenty, the section caps display anyway
    .reverse()
    .map(e => {
      const p = (e.payload ?? {}) as Record<string, unknown>;

      switch (e.type) {
        case "approval.granted":
          return {
            id:        e.id,
            accent:    "text-accent-green",
            mark:      "✓",
            primary:   `Approved: ${(p.tool as string) ?? "request"}`,
            secondary: (e.actor && actorNames[e.actor]) || e.actor || "",
            timestamp: e.timestamp,
          };

        case "approval.denied":
          return {
            id:        e.id,
            accent:    "text-accent-red",
            mark:      "✕",
            primary:   `Denied: ${(p.tool as string) ?? "request"}`,
            secondary: (e.actor && actorNames[e.actor]) || e.actor || "",
            timestamp: e.timestamp,
          };

        case "ownership.transferred": {
          const fromId = (p.from as string) ?? "";
          const toId   = (p.to   as string) ?? "";
          const from   = actorNames[fromId] ?? fromId;
          const to     = actorNames[toId] ?? toId;
          return {
            id:        e.id,
            accent:    "text-accent-purple",
            mark:      "⇄",
            primary:   "Ownership transferred",
            secondary: from && to ? `${from} → ${to}` : (from || to),
            timestamp: e.timestamp,
          };
        }

        case "artifact.created":
          return {
            id:        e.id,
            accent:    "text-accent-blue",
            mark:      "◈",
            primary:   "Artifact generated",
            secondary: (p.name as string) ?? "unnamed",
            timestamp: e.timestamp,
          };

        default:
          return null;
      }
    })
    .filter(Boolean) as DecisionEntry[];
}

function RecentDecisionsSection({ events, actorNames }: { events: WsEnvelope[]; actorNames: Record<string, string> }) {
  const decisions = buildDecisions(events, actorNames).slice(0, 8);

  if (decisions.length === 0) {
    return (
      <p className="text-2xs text-muted">
        No decisions recorded yet.
      </p>
    );
  }

  return (
    <div>
      {decisions.map((d, i) => (
        <div key={d.id}>
          {/* Thin divider between entries, not before the first */}
          {i > 0 && <div className="border-t border-border/40 my-2.5" />}

          <div className="flex items-start gap-2.5">
            {/* Coloured leading mark */}
            <span className={`text-xs leading-none mt-[2px] shrink-0 ${d.accent}`}>
              {d.mark}
            </span>

            <div className="flex-1 min-w-0">
              {/* Primary: what happened */}
              <p className="text-2xs font-medium text-subtle truncate">{d.primary}</p>

              {/* Secondary: who + timestamp */}
              <div className="flex items-center gap-1 mt-0.5 flex-wrap">
                {d.secondary && (
                  <span className="text-2xs text-muted truncate">{d.secondary}</span>
                )}
                {d.secondary && d.timestamp && (
                  <span className="text-2xs text-border select-none">·</span>
                )}
                {d.timestamp && (
                  <RelativeTime
                    date={d.timestamp}
                    as="span"
                    className="text-2xs text-muted tabular-nums shrink-0"
                  />
                )}
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Policy section helper ─────────────────────────────────────────────────────
function PolicySection({ snapshot }: { snapshot: SessionSnapshot | null | undefined }) {
  const policy = snapshot?.approval_policy ?? "single_vote";
  const members = snapshot?.members ?? [];
  const humans  = members.filter(m => m.role !== "agent");
  const quorum  = policy === "majority" ? Math.ceil(humans.length / 2) : humans.length;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-2xs text-muted">Policy</span>
        <span className="text-2xs font-medium text-subtle">
          {POLICY_LABEL[policy] ?? policy}
        </span>
      </div>
      {humans.length > 0 && policy !== "single_vote" && (
        <div className="flex items-center justify-between">
          <span className="text-2xs text-muted">Quorum</span>
          <span className="text-2xs font-medium text-subtle">
            {quorum} of {humans.length}
          </span>
        </div>
      )}
      <div className="flex items-center gap-1.5 pt-0.5">
        {["single_vote", "majority", "unanimous"].map(p => (
          <div
            key={p}
            className={`h-1 flex-1 rounded-full transition-colors ${
              p === policy ? "bg-accent-blue" : "bg-surface-3"
            }`}
          />
        ))}
      </div>
    </div>
  );
}

// ── Escalation chain helper ───────────────────────────────────────────────────
function EscalationSection({ snapshot }: { snapshot: SessionSnapshot | null | undefined }) {
  const owner     = snapshot?.owner;
  const ownerName = snapshot?.owner_name ?? owner;
  const members   = snapshot?.members ?? [];
  const humans    = members.filter(m => m.role !== "agent");

  if (!owner && humans.length === 0) {
    return <p className="text-2xs text-muted">No members assigned.</p>;
  }

  return (
    <div className="space-y-1.5">
      {owner && ownerName && (
        <div className="flex items-center gap-2">
          <div className="w-4 h-4 rounded-full bg-accent-blue/20 flex items-center justify-center shrink-0">
            <span className="text-2xs font-semibold text-accent-blue">
              {ownerName.slice(0, 1).toUpperCase()}
            </span>
          </div>
          <span className="text-2xs text-subtle flex-1 truncate">{ownerName}</span>
          <span className="text-2xs text-muted">owner</span>
        </div>
      )}
      {humans
        .filter(h => h.actor_id !== owner)
        .map(h => (
          <div key={h.actor_id} className="flex items-center gap-2">
            <div className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 ${
              h.attached ? "bg-accent-green/15" : "bg-surface-3"
            }`}>
              <span className={`text-2xs font-semibold ${h.attached ? "text-accent-green" : "text-muted"}`}>
                {h.name.slice(0, 1).toUpperCase()}
              </span>
            </div>
            <span className="text-2xs text-subtle flex-1 truncate">{h.name}</span>
            <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${h.attached ? "bg-accent-green" : "bg-surface-4"}`} />
          </div>
        ))}
    </div>
  );
}

// ── Panel ─────────────────────────────────────────────────────────────────────
export default function NeedsAction({
  approvals,
  snapshot,
  pastEvents = [],
  onApprove,
  onDeny,
  onClaim,
  mobileOpen,
  onMobileClose,
}: Props) {
  const contested = approvals.filter(a => a.state === "Contested").length;
  const [listRef] = useAutoAnimate<HTMLDivElement>();
  const actorNames = Object.fromEntries((snapshot?.members ?? []).map(m => [m.actor_id, m.name]));
  const containerRef = useModalA11y<HTMLElement>(mobileOpen, onMobileClose);

  return (
    <aside
      id="needs-action-panel"
      ref={containerRef}
      role={mobileOpen ? "dialog" : undefined}
      aria-modal={mobileOpen ? true : undefined}
      aria-label={mobileOpen ? "Needs action" : undefined}
      className={`fixed inset-y-0 right-0 z-50 w-72 shrink-0 flex flex-col bg-surface-0 border-l border-border transform transition-transform duration-200 ease-out ${
        mobileOpen ? "translate-x-0" : "translate-x-full"
      } lg:static lg:z-auto lg:translate-x-0 lg:transition-none`}
    >
      {/* Header */}
      <div className="h-9 px-4 border-b border-border flex items-center justify-between shrink-0">
        <span className="text-2xs text-muted uppercase tracking-widest font-medium">
          Needs Action
        </span>
        <div className="flex items-center gap-1.5">
          {contested > 0 && (
            <span className="text-2xs bg-accent-amber/15 text-accent-amber border border-accent-amber/25 px-1.5 py-0.5 rounded font-semibold">
              {contested} contested
            </span>
          )}
          {approvals.length > 0 && (
            <span className="text-2xs bg-surface-3 text-subtle border border-border px-1.5 py-0.5 rounded font-semibold">
              {approvals.length}
            </span>
          )}
          {mobileOpen && (
            <button
              onClick={onMobileClose}
              aria-label="Close needs action panel"
              className="text-muted hover:text-subtle text-sm leading-none p-1"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* Body */}
      <div className="flex-1 overflow-y-auto">
        {approvals.length === 0 ? (
          <>
            {/* All-clear indicator */}
            <div className="flex flex-col items-center gap-2 px-5 py-6 text-center border-b border-border/60">
              <div className="w-8 h-8 rounded-full bg-accent-green/10 border border-accent-green/20 flex items-center justify-center mb-0.5">
                <span className="text-accent-green text-sm">✓</span>
              </div>
              <p className="text-xs font-medium text-subtle">No intervention required</p>
              <p className="text-2xs text-muted leading-relaxed">
                All agents operating normally.
              </p>
            </div>

            {/* Progressive disclosure */}
            <DisclosureSection label="Approval Policy">
              <PolicySection snapshot={snapshot} />
            </DisclosureSection>

            <DisclosureSection label="Escalation Chain">
              <EscalationSection snapshot={snapshot} />
            </DisclosureSection>

            <DisclosureSection label="Recent Decisions" defaultOpen={pastEvents.length > 0}>
              <RecentDecisionsSection events={pastEvents} actorNames={actorNames} />
            </DisclosureSection>
          </>
        ) : (
          <div ref={listRef} className="py-3">
            {approvals.map(a => (
              <ActionCard
                key={a.approval_id}
                approval={a}
                onApprove={onApprove}
                onDeny={onDeny}
                onClaim={onClaim}
              />
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}
