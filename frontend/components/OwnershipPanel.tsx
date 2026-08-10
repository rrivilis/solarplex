"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { SessionSnapshot } from "@/lib/types";
import { authFetch, maybeToastRateLimited } from "@/lib/auth";
import { API_BASE } from "@/lib/env";

interface Props {
  sessionId: string;
  snapshot: SessionSnapshot | null;
  actorId: string;
  onTransfer: (to: string, note?: string) => Promise<void>;
}

type View = null | "menu" | "transfer" | "schedule" | "escalation" | "policy";

interface EscalationEntry {
  actor_id: string;
  timeout_minutes: number;
}

interface ScheduledTransfer {
  to: string;
  scheduled_at: string;
  note: string;
}

// ── Shared primitives ────────────────────────────────────────────────────────

function Back({ label = "← back", onBack }: { label?: string; onBack: () => void }) {
  return (
    <button
      onClick={onBack}
      className="flex items-center gap-1 text-2xs text-muted hover:text-subtle transition-colors mb-2.5"
    >
      {label}
    </button>
  );
}

function PrimaryBtn({
  onClick,
  disabled,
  children,
  color = "blue",
}: {
  onClick: () => void;
  disabled?: boolean;
  children: React.ReactNode;
  color?: "blue" | "green" | "purple" | "red";
}) {
  const cls: Record<string, string> = {
    blue:   "bg-accent-blue/10   border-accent-blue/25   text-accent-blue   hover:bg-accent-blue/20",
    green:  "bg-accent-green/10  border-accent-green/25  text-accent-green  hover:bg-accent-green/20",
    purple: "bg-accent-purple/10 border-accent-purple/25 text-accent-purple hover:bg-accent-purple/20",
    red:    "bg-accent-red/10    border-accent-red/25    text-accent-red    hover:bg-accent-red/20",
  };
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`w-full text-xs py-1.5 rounded-lg border font-semibold transition-colors disabled:opacity-50 ${cls[color]}`}
    >
      {children}
    </button>
  );
}

function GhostBtn({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      onClick={onClick}
      className="flex-1 text-xs py-1.5 rounded-lg bg-surface-3 border border-border text-subtle hover:text-primary transition-colors"
    >
      {children}
    </button>
  );
}

function NoteArea({
  value,
  onChange,
  placeholder = "Add a handoff note… (optional)",
  rows = 3,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  rows?: number;
}) {
  return (
    <textarea
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder}
      rows={rows}
      className="w-full text-xs bg-surface-3 border border-border rounded-lg px-2.5 py-2 text-primary placeholder-muted resize-none focus:outline-none focus:border-accent-blue/50 transition-colors"
    />
  );
}

function Loading({ onBack }: { onBack: () => void }) {
  return (
    <div>
      <Back onBack={onBack} />
      <p className="text-2xs text-muted">Loading…</p>
    </div>
  );
}

// ── Artifact helpers ─────────────────────────────────────────────────────────

async function loadArtifact(
  sessionId: string,
  artifactType: string,
): Promise<{ id: string; content: string } | null> {
  const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`);
  // API returns ArtifactRow which serializes `type` (not `artifact_type`)
  const list: { id: string; type: string }[] = await res.json();
  const found = list.find(a => a.type === artifactType);
  if (!found) return null;
  const detail = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${found.id}`);
  const full: { storage_ref: string } = await detail.json();
  return { id: found.id, content: full.storage_ref };
}

async function saveArtifact(
  sessionId: string,
  artifactId: string | null,
  name: string,
  artifactType: string,
  content: string,
): Promise<string> {
  if (artifactId) {
    await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${artifactId}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
    return artifactId;
  }
  const res = await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, artifact_type: artifactType, content }),
  });
  if (await maybeToastRateLimited(res)) throw new Error("rate_limited");
  const a: { id: string } = await res.json();
  return a.id;
}

// ── Transfer Now ─────────────────────────────────────────────────────────────

function TransferNow({
  candidates,
  actorNames,
  onTransfer,
  onBack,
}: {
  candidates: string[];
  actorNames: Record<string, string>;
  onTransfer: (to: string, note?: string) => Promise<void>;
  onBack: () => void;
}) {
  const [target, setTarget]       = useState<string | null>(null);
  const [note, setNote]           = useState("");
  const [submitting, setSubmitting] = useState(false);

  async function confirm() {
    if (!target) return;
    setSubmitting(true);
    await onTransfer(target, note || undefined);
    setSubmitting(false);
    onBack();
  }

  // Step 1: pick a member
  if (!target) {
    return (
      <div className="space-y-1">
        <Back onBack={onBack} />
        {candidates.length === 0 ? (
          <p className="text-2xs text-muted">No other members to transfer to.</p>
        ) : (
          candidates.map(id => {
            const label = actorNames[id] ?? id;
            return (
              <button
                key={id}
                onClick={() => setTarget(id)}
                className="w-full flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-surface-3 transition-colors text-left"
              >
                <div className="w-5 h-5 rounded-full bg-surface-3 text-subtle flex items-center justify-center text-2xs font-semibold shrink-0">
                  {label.slice(0, 2).toUpperCase()}
                </div>
                <span className="text-xs text-subtle">{label}</span>
              </button>
            );
          })
        )}
      </div>
    );
  }

  // Step 2: confirm + note
  return (
    <div className="space-y-2">
      <Back onBack={() => setTarget(null)} />
      <p className="text-xs text-subtle">
        Transfer to <span className="font-semibold text-primary">{actorNames[target] ?? target}</span>
      </p>
      <NoteArea value={note} onChange={setNote} />
      <div className="flex gap-1.5">
        <GhostBtn onClick={() => setTarget(null)}>Cancel</GhostBtn>
        <button
          onClick={confirm}
          disabled={submitting}
          className="flex-1 text-xs py-1.5 rounded-lg bg-accent-purple/10 border border-accent-purple/25 text-accent-purple hover:bg-accent-purple/20 transition-colors font-semibold disabled:opacity-50"
        >
          {submitting ? "Transferring…" : "Transfer →"}
        </button>
      </div>
    </div>
  );
}

// ── Schedule Transfer ────────────────────────────────────────────────────────

function ScheduleTransfer({
  sessionId,
  actorId,
  candidates,
  actorNames,
  onBack,
}: {
  sessionId: string;
  actorId: string;
  candidates: string[];
  actorNames: Record<string, string>;
  onBack: () => void;
}) {
  const [to, setTo]             = useState(candidates[0] ?? "");
  const [date, setDate]         = useState("");
  const [time, setTime]         = useState("");
  const [note, setNote]         = useState("");
  const [existing, setExisting] = useState<ScheduledTransfer | null>(null);
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [loaded, setLoaded]     = useState(false);
  const [saving, setSaving]     = useState(false);

  useEffect(() => {
    loadArtifact(sessionId, "scheduled_transfer")
      .then(result => {
        if (result) {
          setArtifactId(result.id);
          const data: ScheduledTransfer = JSON.parse(result.content);
          setExisting(data);
          setTo(data.to);
          const dt = new Date(data.scheduled_at);
          setDate(dt.toISOString().slice(0, 10));
          setTime(dt.toISOString().slice(11, 16));
          setNote(data.note ?? "");
        }
      })
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, [sessionId]);

  async function handleSave() {
    if (!to || !date || !time) return;
    setSaving(true);
    const scheduled_at = new Date(`${date}T${time}:00`).toISOString();
    const payload: ScheduledTransfer = { to, scheduled_at, note };
    try {
      const id = await saveArtifact(
        sessionId, artifactId,
        "Scheduled Transfer", "scheduled_transfer",
        JSON.stringify(payload),
      );
      setArtifactId(id);
      setExisting(payload);
    } catch {}
    setSaving(false);
  }

  async function handleCancel() {
    if (!artifactId) return;
    await authFetch(`${API_BASE}/sessions/${sessionId}/artifacts/${artifactId}`, { method: "DELETE" });
    setArtifactId(null);
    setExisting(null);
    setTo(candidates[0] ?? "");
    setDate(""); setTime(""); setNote("");
  }

  if (!loaded) return <Loading onBack={onBack} />;

  return (
    <div className="space-y-2">
      <Back onBack={onBack} />

      {existing && (
        <div className="px-2.5 py-2 rounded-lg bg-accent-purple/5 border border-accent-purple/20 space-y-0.5">
          <p className="text-2xs text-accent-purple font-semibold">Scheduled</p>
          <p className="text-2xs text-subtle">
            → {actorNames[existing.to] ?? existing.to} · {new Date(existing.scheduled_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
          </p>
          {existing.note && (
            <p className="text-2xs text-muted italic">"{existing.note}"</p>
          )}
          <button
            onClick={handleCancel}
            className="mt-1 text-2xs text-accent-red hover:opacity-75 transition-opacity"
          >
            Cancel scheduled transfer
          </button>
        </div>
      )}

      <select
        value={to}
        onChange={e => setTo(e.target.value)}
        aria-label="Transfer ownership to"
        className="w-full text-xs bg-surface-3 border border-border rounded-lg px-2 py-1.5 text-primary focus:outline-none focus:border-accent-blue/50"
      >
        {candidates.map(id => <option key={id} value={id}>{actorNames[id] ?? id}</option>)}
      </select>

      <div className="flex gap-1.5">
        <input
          type="date"
          value={date}
          onChange={e => setDate(e.target.value)}
          aria-label="Transfer date"
          className="flex-1 min-w-0 text-xs bg-surface-3 border border-border rounded-lg px-2 py-1.5 text-primary focus:outline-none focus:border-accent-blue/50"
        />
        <input
          type="time"
          value={time}
          onChange={e => setTime(e.target.value)}
          aria-label="Transfer time"
          className="w-28 shrink-0 text-xs bg-surface-3 border border-border rounded-lg px-2 py-1.5 text-primary focus:outline-none focus:border-accent-blue/50"
        />
      </div>

      <NoteArea value={note} onChange={setNote} placeholder="Handoff note… (optional)" rows={2} />

      <PrimaryBtn onClick={handleSave} disabled={saving || !to || !date || !time} color="blue">
        {saving ? "Saving…" : existing ? "Update Schedule" : "Schedule Transfer"}
      </PrimaryBtn>
    </div>
  );
}

// ── Escalation Chain ─────────────────────────────────────────────────────────

function EscalationChain({
  sessionId,
  actorId,
  allHumans,
  actorNames,
  onBack,
}: {
  sessionId: string;
  actorId: string;
  allHumans: string[];
  actorNames: Record<string, string>;
  onBack: () => void;
}) {
  const [chain, setChain]           = useState<EscalationEntry[]>([]);
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [loaded, setLoaded]         = useState(false);
  const [saving, setSaving]         = useState(false);
  const defaultRef                  = useRef(allHumans);

  useEffect(() => {
    loadArtifact(sessionId, "escalation_chain")
      .then(result => {
        if (result) {
          setArtifactId(result.id);
          setChain(JSON.parse(result.content));
        } else {
          setChain(defaultRef.current.map(id => ({ actor_id: id, timeout_minutes: 30 })));
        }
      })
      .catch(() => {
        setChain(defaultRef.current.map(id => ({ actor_id: id, timeout_minutes: 30 })));
      })
      .finally(() => setLoaded(true));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessionId]);

  function swap(i: number, j: number) {
    setChain(c => {
      const next = [...c];
      [next[i], next[j]] = [next[j], next[i]];
      return next;
    });
  }

  function setTimeoutFor(i: number, val: number) {
    setChain(c => c.map((e, idx) => idx === i ? { ...e, timeout_minutes: val } : e));
  }

  async function handleSave() {
    setSaving(true);
    try {
      const id = await saveArtifact(
        sessionId, artifactId,
        "Escalation Chain", "escalation_chain",
        JSON.stringify(chain),
      );
      setArtifactId(id);
    } catch {}
    setSaving(false);
  }

  if (!loaded) return <Loading onBack={onBack} />;

  return (
    <div className="space-y-2">
      <Back onBack={onBack} />
      <p className="text-2xs text-muted leading-relaxed">
        Escalation order when approval times out. Set per-step timeout in minutes.
      </p>

      <div className="space-y-1">
        {chain.map((entry, i) => {
          const label = actorNames[entry.actor_id] ?? entry.actor_id;
          return (
          <div key={entry.actor_id} className="flex items-center gap-1.5">
            <span className="text-2xs text-muted w-3.5 text-right tabular-nums shrink-0 select-none">{i + 1}</span>
            <div className="w-4 h-4 rounded-full bg-surface-3 text-muted flex items-center justify-center text-2xs font-semibold shrink-0">
              {label.slice(0, 1).toUpperCase()}
            </div>
            <span className="flex-1 text-xs text-subtle truncate min-w-0">{label}</span>
            <input
              type="number"
              min={0}
              value={entry.timeout_minutes}
              onChange={e => setTimeoutFor(i, Number(e.target.value))}
              className="w-9 text-2xs text-center bg-surface-3 border border-border rounded px-1 py-0.5 text-subtle focus:outline-none focus:border-accent-blue/50"
              title="Timeout minutes"
            />
            <span className="text-2xs text-muted shrink-0">m</span>
            <div className="flex flex-col shrink-0">
              <button
                onClick={() => swap(i, i - 1)}
                disabled={i === 0}
                aria-label="Move up"
                className="text-2xs text-muted hover:text-subtle disabled:opacity-20 leading-none"
              >▲</button>
              <button
                onClick={() => swap(i, i + 1)}
                disabled={i === chain.length - 1}
                aria-label="Move down"
                className="text-2xs text-muted hover:text-subtle disabled:opacity-20 leading-none"
              >▼</button>
            </div>
          </div>
          );
        })}
      </div>

      <PrimaryBtn onClick={handleSave} disabled={saving} color="green">
        {saving ? "Saving…" : "Save Chain"}
      </PrimaryBtn>
    </div>
  );
}

// ── Rotation Policy ──────────────────────────────────────────────────────────

function RotationPolicy({
  sessionId,
  actorId,
  onBack,
}: {
  sessionId: string;
  actorId: string;
  onBack: () => void;
}) {
  const [text, setText]             = useState("");
  const [artifactId, setArtifactId] = useState<string | null>(null);
  const [loaded, setLoaded]         = useState(false);
  const [saving, setSaving]         = useState(false);

  useEffect(() => {
    loadArtifact(sessionId, "rotation_policy")
      .then(result => {
        if (result) {
          setArtifactId(result.id);
          setText(result.content);
        }
      })
      .catch(() => {})
      .finally(() => setLoaded(true));
  }, [sessionId]);

  async function handleSave() {
    if (!text.trim()) return;
    setSaving(true);
    try {
      const id = await saveArtifact(
        sessionId, artifactId,
        "Rotation Policy", "rotation_policy",
        text,
      );
      setArtifactId(id);
    } catch {}
    setSaving(false);
  }

  if (!loaded) return <Loading onBack={onBack} />;

  return (
    <div className="space-y-2">
      <Back onBack={onBack} />
      <p className="text-2xs text-muted leading-relaxed">
        Describe the ownership rotation in plain text. Saved as a session artifact.
      </p>
      <NoteArea
        value={text}
        onChange={setText}
        placeholder={"e.g. Alice → Bob on US Pacific nights\nCarol on-call for urgent escalations\nRotate weekly starting Monday"}
        rows={5}
      />
      <PrimaryBtn onClick={handleSave} disabled={saving || !text.trim()} color="blue">
        {saving ? "Saving…" : artifactId ? "Update Policy" : "Save Policy"}
      </PrimaryBtn>
    </div>
  );
}

// ── Main ─────────────────────────────────────────────────────────────────────

const MENU_ITEMS: {
  key: Exclude<View, null | "menu">;
  label: string;
  color: string;
  last?: boolean;
}[] = [
  { key: "transfer",   label: "Transfer Now",      color: "text-accent-purple" },
  { key: "schedule",   label: "Schedule Transfer",  color: "text-accent-blue"   },
  { key: "escalation", label: "Escalation Chain",   color: "text-accent-amber"  },
  { key: "policy",     label: "Rotation Policy",    color: "text-accent-green", last: true },
];

export default function OwnershipPanel({
  sessionId,
  snapshot,
  actorId,
  onTransfer,
}: Props) {
  const [view, setView] = useState<View>(null);

  const owner      = snapshot?.owner ?? null;
  // Display only — comparisons below stay on the stable id, never the name.
  const ownerName  = snapshot?.owner_name || owner;
  const isOwner    = !!owner && actorId === owner;
  const humans     = (snapshot?.members ?? []).filter(m => m.role !== "agent");
  const allHumans  = humans.map(h => h.actor_id);
  const candidates = allHumans.filter(id => id !== owner);
  const actorNames = Object.fromEntries(humans.map(h => [h.actor_id, h.name]));

  const open   = view !== null;
  const goMenu = useCallback(() => setView("menu"), []);
  const goBack = useCallback(() => setView("menu"), []);

  // Collapse the ownership panel immediately when this actor loses ownership
  // (ownership.transferred WS event updates snapshot → isOwner flips → this fires).
  useEffect(() => {
    if (!isOwner) setView(null);
  }, [isOwner]);

  return (
    <div className="py-3.5 border-b border-border">

      {/* Header row */}
      <div className="flex items-center justify-between mb-2">
        <p className="text-2xs uppercase tracking-widest text-muted font-medium">Owner</p>
        <AnimatePresence>
          {isOwner && (
            <motion.button
              key="ownership-manage-btn"
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.85 }}
              transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
              onClick={() => setView(v => v === null ? "menu" : null)}
              className="flex items-center gap-1 text-2xs text-muted hover:text-subtle transition-colors"
            >
              <span>Manage</span>
              <motion.span
                animate={{ rotate: open ? 90 : 0 }}
                transition={{ duration: 0.18, ease: "easeInOut" }}
                className="inline-block leading-none"
              >
                ▶
              </motion.span>
            </motion.button>
          )}
        </AnimatePresence>
      </div>

      {/* Owner display */}
      {owner ? (
        <div className="flex items-center gap-2">
          <div className="w-5 h-5 rounded-full bg-accent-blue/20 text-accent-blue flex items-center justify-center text-2xs font-semibold shrink-0">
            {(ownerName ?? owner).slice(0, 2).toUpperCase()}
          </div>
          <span className="text-xs text-primary font-medium">{ownerName}</span>
          {isOwner && <span className="text-2xs text-muted">(you)</span>}
        </div>
      ) : (
        <span className="text-xs text-muted">Unassigned</span>
      )}

      {/* Expandable region — height-animated container */}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="ownership-body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.22, ease: [0.4, 0, 0.2, 1] }}
            style={{ overflow: "hidden" }}
          >
            <div className="mt-3 pt-2.5 border-t border-border/50">
              {/* Sub-view crossfade */}
              <AnimatePresence mode="wait" initial={false}>
                <motion.div
                  key={view ?? "null"}
                  initial={{ opacity: 0, x: 6 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -6 }}
                  transition={{ duration: 0.12, ease: "easeOut" }}
                >
                  {view === "menu" && (
                    <div className="space-y-0.5">
                      {MENU_ITEMS.map(item => (
                        <button
                          key={item.key}
                          onClick={() => setView(item.key)}
                          className="w-full flex items-center gap-2 px-1.5 py-1.5 rounded-lg hover:bg-surface-3 transition-colors text-left group"
                        >
                          <span className="text-border text-2xs select-none shrink-0 group-hover:text-muted transition-colors">
                            {item.last ? "└─" : "├─"}
                          </span>
                          <span className={`text-xs font-medium ${item.color}`}>{item.label}</span>
                        </button>
                      ))}
                    </div>
                  )}

                  {view === "transfer" && (
                    <TransferNow candidates={candidates} actorNames={actorNames} onTransfer={onTransfer} onBack={goBack} />
                  )}
                  {view === "schedule" && (
                    <ScheduleTransfer
                      sessionId={sessionId}
                      actorId={actorId}
                      candidates={candidates}
                      actorNames={actorNames}
                      onBack={goBack}
                    />
                  )}
                  {view === "escalation" && (
                    <EscalationChain
                      sessionId={sessionId}
                      actorId={actorId}
                      allHumans={allHumans}
                      actorNames={actorNames}
                      onBack={goBack}
                    />
                  )}
                  {view === "policy" && (
                    <RotationPolicy sessionId={sessionId} actorId={actorId} onBack={goBack} />
                  )}
                </motion.div>
              </AnimatePresence>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
