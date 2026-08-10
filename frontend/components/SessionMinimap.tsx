"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, type Transition } from "framer-motion";
import { SessionSnapshot, WsEnvelope } from "@/lib/types";

interface Props {
  snapshot: SessionSnapshot | null;
  events?: WsEnvelope[];
}

// ── Color config ───────────────────────────────────────────────────────────────
// Accent hex values mirror tailwind.config.ts's `accent` palette exactly (SVG
// fill/stroke can't reach Tailwind classes) — keep the two in sync if either
// changes. Neutrals (text/border/surface below) do the same against that
// file's `surface`/`border`/`muted`/`subtle` tokens, which is what this
// component was missing before: its grays were ad-hoc guesses, not the
// app's actual palette, which is a big part of why it read as slapped-on
// next to everything else in the sidebar.
const ROLE_COLOR: Record<string, string> = {
  owner:        "#3ecf8e",
  collaborator: "#4f8ef7",
  observer:     "#a78bfa",
};

const AGENT_COLOR: Record<string, string> = {
  running: "#3ecf8e",
  waiting: "#f5a623",
  blocked: "#f56565",
  error:   "#f56565",
  idle:    "#5e626e",
};

const FLASH_COLOR: Record<string, string> = {
  context:  "#f5a623",  // amber  — context entry added
  artifact: "#a78bfa",  // purple — artifact created/updated
  approval: "#f5a623",  // amber  — approval requested
  message:  "#4f8ef7",  // blue   — message posted (actor ripple)
  transfer: "#3ecf8e",  // green  — ownership transferred
};

const DETACHED_COLOR = "#3a3d4a";

// Neutrals — from tailwind.config.ts
const C = {
  surface2: "#1f2129",
  border:   "#252833",
  muted:    "#5e626e",
  subtle:   "#8c909b",
};

function humanColor(role: string, attached: boolean): string {
  if (!attached) return DETACHED_COLOR;
  return ROLE_COLOR[role] ?? ROLE_COLOR.observer;
}

// ── Layout constants ───────────────────────────────────────────────────────────
const W = 200;
const H = 128;

const SESSION_X = W / 2;
const SESSION_Y = H / 2;
// Wide enough for the longest status word ("suspended"/"archived") at
// STATUS_FONT_SIZE without spilling past the box's own rounded-rect edge —
// SVG text isn't clipped by its container by default.
const SESSION_W = 64;
const SESSION_H = 26;

const HUMAN_X = 26;
const AGENT_X = W - 26;
const DOT_R   = 6;

// The SVG renders at `width="100%"` inside a ~208px sidebar column against
// this viewBox's 200-unit coordinate space — effectively a ~1.04x scale, not
// the 1:1 it's easy to assume when picking font sizes in viewBox units. A
// font-size of 6.5 here was rendering at ~6.8 actual px, well under the
// app's own smallest text class (text-2xs = 10.4px) — which is why it still
// read as smushed even after the first size pass. These are chosen to land
// close to that floor once the scale factor is accounted for.
const LABEL_FONT_SIZE  = 9;
const STATUS_FONT_SIZE = 9.5;

// ── Transitions ────────────────────────────────────────────────────────────────
const COLOR_TRANSITION: Transition = { duration: 0.4, ease: "easeInOut" };
const ENTER_EXIT = {
  initial:    { opacity: 0 },
  animate:    { opacity: 1 },
  exit:       { opacity: 0 },
  transition: { duration: 0.3 } satisfies Transition,
};

// ── Flash state ────────────────────────────────────────────────────────────────
interface Flash {
  id: string;
  type: "context" | "artifact" | "approval" | "message" | "transfer";
  actorId?: string;   // set for actor-specific (message, transfer) ripples
  side?: "human" | "agent";
}

// Map event type → flash descriptor
function eventToFlash(e: WsEnvelope): Flash | null {
  const base = { id: e.id ?? `${e.type}-${Date.now()}` };
  switch (e.type) {
    case "context.entry.added":
      return { ...base, type: "context", actorId: e.actor };
    case "artifact.created":
    case "artifact.updated":
      return { ...base, type: "artifact", actorId: e.actor };
    case "approval.requested":
      return { ...base, type: "approval", actorId: e.actor, side: "agent" };
    case "message.posted":
      return { ...base, type: "message", actorId: e.actor, side: "human" };
    case "ownership.transferred":
      return { ...base, type: "transfer" };
    default:
      return null;
  }
}

// ── Pulse overlay elements ─────────────────────────────────────────────────────

/** Expanding ring around the session rectangle */
function SessionPulse({ color }: { color: string }) {
  return (
    <motion.rect
      x={SESSION_X - SESSION_W / 2 - 5}
      y={SESSION_Y - SESSION_H / 2 - 5}
      width={SESSION_W + 10}
      height={SESSION_H + 10}
      rx={8}
      fill="none"
      stroke={color}
      strokeWidth={1.5}
      initial={{ opacity: 0.85, strokeWidth: 2 }}
      animate={{ opacity: 0, strokeWidth: 0 }}
      transition={{ duration: 1.1, ease: "easeOut" }}
      pointerEvents="none"
    />
  );
}

/** Expanding ring around an actor dot */
function ActorPulse({ cx, cy, color }: { cx: number; cy: number; color: string }) {
  return (
    <motion.circle
      cx={cx}
      cy={cy}
      r={DOT_R + 1}
      fill="none"
      stroke={color}
      strokeWidth={1.5}
      initial={{ opacity: 0.9, r: DOT_R + 1 }}
      animate={{ opacity: 0, r: DOT_R + 7 }}
      transition={{ duration: 0.9, ease: "easeOut" }}
      pointerEvents="none"
    />
  );
}

export default function SessionMinimap({ snapshot, events = [] }: Props) {
  const [flashes, setFlashes] = useState<Flash[]>([]);
  const lastSeqRef = useRef<number>(0);

  // Detect new events and queue flash animations
  useEffect(() => {
    if (events.length === 0) return;
    const maxSeq = Math.max(...events.map(e => e.seq ?? 0));
    const newEvents = events.filter(e => (e.seq ?? 0) > lastSeqRef.current);
    if (newEvents.length === 0) return;
    lastSeqRef.current = maxSeq;

    const incoming: Flash[] = newEvents
      .map(eventToFlash)
      .filter((f): f is Flash => f !== null);

    if (incoming.length === 0) return;

    setFlashes(prev => [...prev, ...incoming]);
    const ids = incoming.map(f => f.id);
    // Auto-expire after animation completes
    setTimeout(() => {
      setFlashes(prev => prev.filter(f => !ids.includes(f.id)));
    }, 1400);
  }, [events]);

  if (!snapshot) {
    return (
      <div className="w-full flex items-center justify-center py-6 rounded-lg border border-border bg-surface-2/40">
        <span className="text-2xs text-muted">No session data</span>
      </div>
    );
  }

  const humans = snapshot.members.filter(m => m.role !== "agent");
  const agents = snapshot.members.filter(m => m.role === "agent");

  // Cap set to comfortably clear one node's label descender before the next
  // node's dot at LABEL_FONT_SIZE — bumping the font without this would
  // start crowding labels into neighboring dots for 3+ member sessions.
  const humanSpacing = humans.length > 1 ? Math.min(28, (H - 28) / (humans.length - 1)) : 0;
  const agentSpacing = agents.length > 1 ? Math.min(28, (H - 28) / (agents.length - 1)) : 0;
  const humanStartY  = humans.length > 1 ? SESSION_Y - ((humans.length - 1) * humanSpacing) / 2 : SESSION_Y;
  const agentStartY  = agents.length > 1 ? SESSION_Y - ((agents.length - 1) * agentSpacing)  / 2 : SESSION_Y;

  // Build position lookup for actor pulses
  const actorY = new Map<string, { x: number; y: number }>();
  humans.forEach((h, i) => actorY.set(h.actor_id, { x: HUMAN_X, y: humanStartY + i * humanSpacing }));
  agents.forEach((a, i) => actorY.set(a.actor_id, { x: AGENT_X, y: agentStartY + i * agentSpacing }));

  return (
    <svg
      viewBox={`0 0 ${W} ${H}`}
      width="100%"
      height={H}
      className="rounded-lg border border-border bg-surface-2/40"
      style={{ display: "block", overflow: "visible" }}
    >
      {/* Session rect */}
      <rect
        x={SESSION_X - SESSION_W / 2}
        y={SESSION_Y - SESSION_H / 2}
        width={SESSION_W}
        height={SESSION_H}
        rx={6}
        fill={C.surface2}
        stroke={C.border}
        strokeWidth={1.25}
      />
      <text
        x={SESSION_X}
        y={SESSION_Y + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={STATUS_FONT_SIZE}
        fill={C.subtle}
        fontFamily="Inter, sans-serif"
      >
        {snapshot.status}
      </text>

      {/* Session-level flash overlays (context, artifact, approval, transfer) */}
      <AnimatePresence>
        {flashes
          .filter(f => !f.actorId || f.type === "transfer" || f.type === "context" || f.type === "artifact" || f.type === "approval")
          .map(f => (
            <SessionPulse key={f.id} color={FLASH_COLOR[f.type]} />
          ))}
      </AnimatePresence>

      {/* Human nodes */}
      <AnimatePresence>
        {humans.map((h, i) => {
          const y   = humanStartY + i * humanSpacing;
          const col = humanColor(h.role, h.attached);
          const isOwner = h.actor_id === snapshot.owner || h.role === "owner";
          return (
            <motion.g key={h.actor_id} {...ENTER_EXIT}>
              <motion.line
                x1={HUMAN_X + DOT_R} y1={y}
                x2={SESSION_X - SESSION_W / 2} y2={SESSION_Y}
                animate={{ stroke: col, opacity: h.attached ? 0.7 : 0.3 }}
                transition={COLOR_TRANSITION}
                strokeWidth={isOwner ? 1.5 : 0.75}
                strokeDasharray={h.attached ? undefined : "3 2"}
                stroke={col}
                opacity={h.attached ? 0.7 : 0.3}
              />
              <motion.circle
                cx={HUMAN_X} cy={y}
                r={DOT_R}
                animate={{ fill: col, opacity: h.attached ? 0.9 : 0.4 }}
                transition={COLOR_TRANSITION}
                fill={col}
                opacity={h.attached ? 0.9 : 0.4}
              >
                <title>{`${h.name || h.actor_id} · ${h.role}${h.attached ? "" : " · detached"}`}</title>
              </motion.circle>
              {isOwner && (
                <motion.circle
                  cx={HUMAN_X} cy={y}
                  r={DOT_R + 2.5}
                  fill="none"
                  animate={{ stroke: col, opacity: h.attached ? 0.35 : 0 }}
                  transition={COLOR_TRANSITION}
                  stroke={col}
                  strokeWidth={1}
                  opacity={h.attached ? 0.35 : 0}
                />
              )}
              <text
                x={HUMAN_X}
                y={y + DOT_R + 9}
                textAnchor="middle"
                fontSize={LABEL_FONT_SIZE}
                fill={h.attached ? C.subtle : C.muted}
                fontFamily="Inter, sans-serif"
                style={{ transition: "fill 0.4s" }}
              >
                {(h.name || h.actor_id).length > 8 ? `${(h.name || h.actor_id).slice(0, 7)}…` : (h.name || h.actor_id)}
              </text>
            </motion.g>
          );
        })}
      </AnimatePresence>

      {/* Actor-specific ripples (message posted, actor-sourced events) */}
      <AnimatePresence>
        {flashes
          .filter(f => f.actorId && f.type === "message" && actorY.has(f.actorId!))
          .map(f => {
            const pos = actorY.get(f.actorId!)!;
            return (
              <ActorPulse key={f.id} cx={pos.x} cy={pos.y} color={FLASH_COLOR[f.type]} />
            );
          })}
      </AnimatePresence>

      {/* Agent nodes */}
      <AnimatePresence>
        {agents.map((a, i) => {
          const y   = agentStartY + i * agentSpacing;
          const col = AGENT_COLOR[a.status ?? "idle"] ?? AGENT_COLOR.idle;
          return (
            <motion.g key={a.actor_id} {...ENTER_EXIT}>
              <motion.line
                x1={SESSION_X + SESSION_W / 2} y1={SESSION_Y}
                x2={AGENT_X - DOT_R} y2={y}
                animate={{ stroke: col, opacity: a.status === "idle" ? 0.3 : 0.6 }}
                transition={COLOR_TRANSITION}
                stroke={col}
                strokeWidth={0.75}
                strokeDasharray={a.status === "idle" ? "3 2" : undefined}
                opacity={0.6}
              />
              <motion.circle
                cx={AGENT_X} cy={y}
                r={DOT_R}
                animate={{ fill: col, opacity: a.status === "idle" ? 0.4 : 0.85 }}
                transition={COLOR_TRANSITION}
                fill={col}
                opacity={0.85}
              >
                <title>{`${a.name || a.actor_id} · ${a.status ?? "idle"}`}</title>
              </motion.circle>
              {/* Pulse ring for blocked/waiting agents */}
              {(a.status === "blocked" || a.status === "waiting") && (
                <motion.circle
                  cx={AGENT_X} cy={y}
                  r={DOT_R + 2.5}
                  fill="none"
                  stroke={col}
                  strokeWidth={0.75}
                  animate={{ opacity: [0.5, 0.1, 0.5] }}
                  transition={{ duration: 1.8, repeat: Infinity, ease: "easeInOut" }}
                />
              )}
              <text
                x={AGENT_X}
                y={y + DOT_R + 9}
                textAnchor="middle"
                fontSize={LABEL_FONT_SIZE}
                fill={a.status === "idle" ? C.muted : C.subtle}
                fontFamily="Inter, sans-serif"
              >
                {(a.name || a.actor_id).length > 8 ? `${(a.name || a.actor_id).slice(0, 7)}…` : (a.name || a.actor_id)}
              </text>
            </motion.g>
          );
        })}
      </AnimatePresence>

      {/* Approval pending dots above session box */}
      <AnimatePresence>
        {snapshot.pending_approvals.slice(0, 3).map((ap, i) => (
          <motion.circle
            key={ap.approval_id}
            cx={SESSION_X - 8 + i * 8}
            cy={SESSION_Y - SESSION_H / 2 - 7}
            r={3}
            fill="#f5a623"
            initial={{ opacity: 0, r: 1 }}
            animate={{ opacity: 0.9, r: 3 }}
            exit={{ opacity: 0, r: 0 }}
            transition={{ duration: 0.3 }}
          >
            <title>Pending approval</title>
          </motion.circle>
        ))}
      </AnimatePresence>
    </svg>
  );
}

// ── Legend ─────────────────────────────────────────────────────────────────────
// A real HTML row, not SVG text — the diagram above used to cram this into
// its bottom-right corner at 4.5px font, which was most of why the whole
// widget read as smushed. Only covers the colors this specific diagram
// uses (member-role dots + the detached convention); agent status colors
// already have their own legend via the labeled badges in the Agents
// section above this one, so repeating them here would just be noise.
const LEGEND_ITEMS: { color: string; label: string }[] = [
  { color: ROLE_COLOR.owner,        label: "Owner" },
  { color: ROLE_COLOR.collaborator, label: "Collaborator" },
  { color: ROLE_COLOR.observer,     label: "Observer" },
];

export function SessionMinimapLegend() {
  return (
    <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1">
      {LEGEND_ITEMS.map(({ color, label }) => (
        <span key={label} className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
          <span className="text-2xs text-muted">{label}</span>
        </span>
      ))}
      <span className="flex items-center gap-1.5">
        <span className="w-3 border-t border-dashed border-muted" />
        <span className="text-2xs text-muted">Detached</span>
      </span>
    </div>
  );
}
