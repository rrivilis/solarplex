"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useQueryClient } from "@tanstack/react-query";
import { Drawer } from "vaul";
import { authFetch, isAuthenticated, signIn } from "@/lib/auth";
import { getActorOverride } from "@/lib/actorOverride";

const API_BASE  = process.env.NEXT_PUBLIC_API_URL  ?? "http://localhost:8080/api";

// ── Policy definitions ───────────────────────────────────────────────────────

const POLICIES = [
  {
    id: "single_vote",
    label: "Single vote",
    description: "Any one approver can unblock the agent.",
    quorum: 1,          // filled dots out of 3
    icon: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor" aria-hidden>
        <circle cx="10" cy="6" r="4" />
        <path d="M3 19c0-3.866 3.134-7 7-7s7 3.134 7 7" opacity=".55" />
      </svg>
    ),
  },
  {
    id: "majority",
    label: "Majority",
    description: "More than half of eligible approvers must agree.",
    quorum: 2,
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden>
        <circle cx="12" cy="5.5" r="3.5" />
        <circle cx="4.5"  cy="7.5" r="2.5" opacity=".5" />
        <circle cx="19.5" cy="7.5" r="2.5" opacity=".5" />
        <path d="M6 19c0-3.314 2.686-6 6-6s6 2.686 6 6" opacity=".65" />
        <path d="M0.5 20.5c.5-2.5 2.3-4.2 4.5-4.2" opacity=".35" />
        <path d="M23.5 20.5c-.5-2.5-2.3-4.2-4.5-4.2" opacity=".35" />
      </svg>
    ),
  },
  {
    id: "unanimous",
    label: "Unanimous",
    description: "Everyone must approve. Maximum oversight.",
    quorum: 3,
    icon: (
      <svg width="18" height="18" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
        <path d="M3 11l3.5 3.5L17 5" />
        <path d="M8 11l3.5 3.5" opacity=".4" />
      </svg>
    ),
  },
] as const;

// ── Props ────────────────────────────────────────────────────────────────────

interface Props {
  /** Whatever element triggers the drawer (button, link, etc.) */
  trigger: React.ReactNode;
  /** Bumped (any change, value itself unused) to force the drawer open from
   *  outside — e.g. GlobalCommandPalette's "New Session" action, which has
   *  no `trigger` element of its own to click. Same one-way-signal pattern
   *  as StatusPanel's openManageSignal. */
  openSignal?: number;
}

// ── Component ────────────────────────────────────────────────────────────────

export default function NewSessionDrawer({ trigger, openSignal }: Props) {
  const router = useRouter();
  const queryClient = useQueryClient();
  const searchParams = useSearchParams();
  // Resolve actor from ?actor= URL param → env var → default "alice"
  // (dev-only override; compiled out in production — see lib/actorOverride.ts)
  const ACTOR_ID = getActorOverride(searchParams) ?? "alice";
  const [open,        setOpen]        = useState(false);
  const [name,        setName]        = useState("");
  const [description, setDescription] = useState("");
  const [policy,      setPolicy]      = useState("single_vote");
  const [loading,     setLoading]     = useState(false);
  const [error,       setError]       = useState<string | null>(null);

  function reset() {
    setName(""); setDescription(""); setPolicy("single_vote");
    setError(null); setLoading(false);
  }

  useEffect(() => { if (openSignal) setOpen(true); }, [openSignal]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    if (!isAuthenticated()) {
      // Session creation now derives the owner from a verified sp_token —
      // send the user through OIDC rather than failing with an opaque 401.
      signIn(window.location.pathname + window.location.search);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await authFetch(`${API_BASE}/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: name.trim(),
          description: description.trim() || undefined,
          approval_policy: policy,
        }),
      });
      if (res.status === 401) throw new Error("Sign-in required to create a session");
      if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
      const session = await res.json();
      // sessionStorage only — tab-scoped, cleared on close, not XSS-persistent.
      if (typeof window !== "undefined" && session.join_token) {
        sessionStorage.setItem(`sol-tok-${session.id}`, session.join_token);
      }
      setOpen(false);
      reset();
      // Invalidate rather than trusting staleTime — without this, navigating
      // back to the list within the 30s staleTime window would show the
      // pre-creation cached list, since react-query has no way to know a
      // POST just changed the underlying data. Sessions are now sp_token-
      // identity-scoped, not actor-param-scoped — one cache key, not per-actor.
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      // Include ?actor= so identity is preserved after redirect.
      const actorParam = ACTOR_ID !== "alice" ? `&actor=${encodeURIComponent(ACTOR_ID)}` : "";
      router.push(`/sessions/${session.id}?token=${encodeURIComponent(session.join_token ?? "")}${actorParam}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create session");
      setLoading(false);
    }
  }

  return (
    <Drawer.Root
      direction="right"
      open={open}
      onOpenChange={(v) => { setOpen(v); if (!v) reset(); }}
    >
      <Drawer.Trigger asChild>{trigger}</Drawer.Trigger>

      <Drawer.Portal>
        <Drawer.Overlay className="fixed inset-0 z-40 bg-black/55 backdrop-blur-[2px]" />

        {/*
          Right-side panel — ~1/3 screen width, full height.
          direction="right" means Vaul will slide in from the right edge
          and drag-to-dismiss goes rightward.
        */}
        <Drawer.Content
          className="
            fixed inset-y-0 right-0 z-50
            flex flex-row
            w-[420px] max-w-[92vw]
            bg-surface-1 panel-shine
            border-l border-border
            focus:outline-none
          "
        >
          {/* Left-edge drag grip */}
          <div className="flex items-center justify-center w-5 shrink-0 cursor-grab active:cursor-grabbing select-none">
            <div className="w-[3px] h-10 rounded-full bg-surface-4" />
          </div>

          {/* Content column */}
          <div className="flex-1 flex flex-col overflow-y-auto py-7 pr-7 pl-3">
            <Drawer.Title className="text-sm font-semibold text-primary mb-1">
              New session
            </Drawer.Title>
            <p className="text-xs text-muted mb-7 leading-relaxed">
              A session is the root object — agents, humans,
              events, and artifacts all live here.
            </p>

            <form onSubmit={handleSubmit} className="space-y-6 flex-1">

              {/* Session name */}
              <div>
                <label htmlFor="new-session-name" className="block text-xs font-medium text-subtle mb-1.5">
                  Session name
                </label>
                <input
                  id="new-session-name"
                  type="text"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  placeholder="e.g. customer-research, deployment-review"
                  autoFocus
                  className="
                    w-full bg-surface-2 border border-border rounded-lg
                    px-3 py-2 text-sm text-primary placeholder:text-muted
                    outline-none transition-all
                    focus:border-accent-blue/50 focus:ring-1 focus:ring-accent-blue/20
                  "
                />
              </div>

              {/* Description */}
              <div>
                <label htmlFor="new-session-description" className="block text-xs font-medium text-subtle mb-1.5">
                  Description{" "}
                  <span className="text-muted font-normal">(optional)</span>
                </label>
                <textarea
                  id="new-session-description"
                  value={description}
                  onChange={e => setDescription(e.target.value)}
                  placeholder="What is this session for?"
                  rows={2}
                  className="
                    w-full bg-surface-2 border border-border rounded-lg
                    px-3 py-2 text-sm text-primary placeholder:text-muted
                    outline-none transition-all resize-none
                    focus:border-accent-blue/50 focus:ring-1 focus:ring-accent-blue/20
                  "
                />
              </div>

              {/* Approval policy */}
              <div>
                <label className="block text-xs font-medium text-subtle mb-2">
                  Approval policy
                </label>
                <div className="space-y-2">
                  {POLICIES.map(p => {
                    const active = policy === p.id;
                    return (
                      <label
                        key={p.id}
                        className={`
                          flex items-start gap-3 px-3.5 py-3 rounded-xl border cursor-pointer
                          transition-all duration-150
                          ${active
                            ? "border-accent-blue/40 bg-accent-blue/[0.07] shadow-[inset_0_1px_0_rgba(79,142,247,0.08)]"
                            : "border-border bg-surface-2 hover:bg-surface-3 hover:border-surface-4"}
                        `}
                      >
                        {/* Visually hidden real radio */}
                        <input
                          type="radio"
                          name="policy"
                          value={p.id}
                          checked={active}
                          onChange={() => setPolicy(p.id)}
                          className="sr-only"
                        />

                        {/* Icon badge */}
                        <div className={`
                          mt-0.5 shrink-0 w-7 h-7 rounded-lg flex items-center justify-center transition-colors
                          ${active
                            ? "bg-accent-blue/20 text-accent-blue"
                            : "bg-surface-3 text-muted"}
                        `}>
                          {p.icon}
                        </div>

                        {/* Label + description + quorum dots */}
                        <div className="flex-1 min-w-0">
                          <p className={`text-xs font-semibold transition-colors ${active ? "text-primary" : "text-subtle"}`}>
                            {p.label}
                          </p>
                          <p className="text-2xs text-muted mt-0.5 leading-relaxed">
                            {p.description}
                          </p>

                          {/* Quorum visualiser — e.g. ●●○ for majority */}
                          <div className="flex gap-1 mt-2" aria-hidden>
                            {[0, 1, 2].map(i => (
                              <span
                                key={i}
                                className={`
                                  inline-block w-2 h-2 rounded-full transition-colors duration-150
                                  ${i < p.quorum
                                    ? active ? "bg-accent-blue" : "bg-surface-4"
                                    : "bg-surface-2 border border-surface-3"}
                                `}
                              />
                            ))}
                          </div>
                        </div>

                        {/* Selection indicator */}
                        <div className={`
                          mt-1 shrink-0 w-3.5 h-3.5 rounded-full border-2 flex items-center justify-center
                          transition-all duration-150
                          ${active ? "border-accent-blue" : "border-surface-4"}
                        `}>
                          {active && <div className="w-1.5 h-1.5 rounded-full bg-accent-blue" />}
                        </div>
                      </label>
                    );
                  })}
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="text-xs text-accent-red bg-accent-red/10 border border-accent-red/20 rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              {/* Actions */}
              <div className="flex items-center gap-3 pt-1">
                <button
                  type="submit"
                  disabled={loading || !name.trim()}
                  className="
                    px-4 py-2 rounded-lg bg-accent-blue text-surface-0
                    text-xs font-semibold hover:bg-accent-blue/90
                    transition-colors disabled:opacity-40 disabled:cursor-not-allowed
                  "
                >
                  {loading ? "Creating…" : "Create session"}
                </button>
                <button
                  type="button"
                  onClick={() => setOpen(false)}
                  className="text-xs text-muted hover:text-subtle transition-colors"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </Drawer.Content>
      </Drawer.Portal>
    </Drawer.Root>
  );
}
