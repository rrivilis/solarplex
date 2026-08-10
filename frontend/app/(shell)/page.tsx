"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";
import { SessionRow } from "@/lib/types";
import { motion } from "framer-motion";
import { Tooltip, TooltipContent, TooltipTrigger } from "@radix-ui/react-tooltip";
import NewSessionDrawer from "@/components/NewSessionDrawer";
import OnboardingNameModal from "@/components/OnboardingNameModal";
import SolarplexLogo from "@/components/SolarplexLogo";
import { signIn } from "@/lib/auth";
import { getActorOverride } from "@/lib/actorOverride";
import { getSessions } from "@/lib/sessions";
import {
  consumeLandingRedirect, getSessionSortBy, getSessionSortDirection, getSessionView,
  SessionSortBy, SessionSortDirection, SessionView,
} from "@/lib/preferences";
import { useShellAuth } from "@/lib/shellAuth";
import { useDocumentTitle } from "@/hooks/useDocumentTitle";

const PAGE_SIZE = 10;

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const STATUS_DOT: Record<string, string> = {
  active:               "bg-accent-green",
  attention_requested:  "bg-accent-amber",
  action_needed:        "bg-accent-red",
  policy_update:        "bg-accent-blue",
  suspended:            "bg-surface-4",
  archived:             "bg-muted",
};

// Glow on the high-signal statuses helps them stand out in the list.
const STATUS_GLOW: Record<string, string> = {
  active:              "shadow-[0_0_6px_rgba(62,207,142,0.6)]",
  attention_requested: "shadow-[0_0_6px_rgba(245,166,35,0.7)]",
  action_needed:       "shadow-[0_0_6px_rgba(245,101,101,0.8)]",
  policy_update:       "shadow-[0_0_6px_rgba(79,142,247,0.6)]",
};

const STATUS_BADGE: Record<string, string> = {
  active:              "text-accent-green  bg-accent-green/10  border-accent-green/20",
  attention_requested: "text-accent-amber  bg-accent-amber/10  border-accent-amber/20",
  action_needed:       "text-accent-red    bg-accent-red/10    border-accent-red/20",
  policy_update:       "text-accent-blue   bg-accent-blue/10   border-accent-blue/20",
  suspended:           "text-muted         bg-surface-3        border-border",
  archived:            "text-muted         bg-surface-3        border-border",
};

const STATUS_LABEL: Record<string, string> = {
  active:              "Active",
  attention_requested: "Attention",
  action_needed:       "Action Needed",
  policy_update:       "Policy Update",
  suspended:           "Suspended",
  archived:            "Archived",
};

const POLICY_LABEL: Record<string, string> = {
  single_vote: "Single vote",
  majority:    "Majority",
  unanimous:   "Unanimous",
};

// ─────────────────────────────────────────────────────────────────────────────
// Page
// ─────────────────────────────────────────────────────────────────────────────

export default function Home() {
  useDocumentTitle("Sessions");
  const router = useRouter();
  const searchParams = useSearchParams();
  // ?actor= still threads through into a session's WS connection (join_token
  // model, unchanged by this pass) — it no longer has anything to do with
  // which sessions this list shows, which is now sp_token-identity-scoped.
  const actorId = getActorOverride(searchParams) ?? "alice";

  const { authed } = useShellAuth();

  // Sort/view read from localStorage (set in Settings, same hydration-
  // mismatch reasoning as every other preference read this way) — start at
  // the default that preserves pre-existing behavior (newest-first list),
  // sync in an effect.
  const [sortBy, setSortBy]           = useState<SessionSortBy>("date");
  const [sortDirection, setSortDir]   = useState<SessionSortDirection>("desc");
  const [view, setView]               = useState<SessionView>("list");
  useEffect(() => {
    setSortBy(getSessionSortBy());
    setSortDir(getSessionSortDirection());
    setView(getSessionView());
  }, []);

  // Page position is working state, not a preference — it resets on
  // re-sort (the row under your cursor moves anyway) and isn't persisted,
  // so returning to Sessions later always starts at page 1.
  const [page, setPage] = useState(1);
  useEffect(() => { setPage(1); }, [sortBy, sortDirection]);

  // Only ever consumed on a genuinely-authenticated pass — see
  // consumeLandingRedirect's doc comment for why an unauthenticated render
  // must not burn the one-shot flag (it'd skip the real post-login one).
  // Fires once, when the shared shell layout's auth check flips `authed`
  // to true — that check itself only runs once per app session now (see
  // app/(shell)/layout.tsx), not once per visit to this page.
  useEffect(() => {
    if (!authed) return;
    const redirect = consumeLandingRedirect();
    if (redirect) router.replace(redirect);
  }, [authed, router]);

  // Stale-while-revalidate: revisiting this page (e.g. navigating back from a
  // session) renders the last-known list instantly from cache, then silently
  // refetches in the background — no full-page blank/loading flash on every
  // return trip, only on first-ever visit in the tab's lifetime.
  const { data: sessions, isPending, isError } = useQuery({
    queryKey: ["sessions"],
    queryFn: getSessions,
    enabled: authed,
  });

  const sortedSessions = useMemo(() => {
    const list = [...(sessions ?? [])];
    list.sort((a, b) => {
      const cmp = sortBy === "name"
        ? a.name.localeCompare(b.name)
        : new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      return sortDirection === "asc" ? cmp : -cmp;
    });
    return list;
  }, [sessions, sortBy, sortDirection]);

  const totalPages = Math.max(1, Math.ceil(sortedSessions.length / PAGE_SIZE));
  // Clamps a page left stranded past the end (e.g. after switching to a
  // sort/view that arrived mid-session and the list happened to be shorter
  // than expected) rather than rendering an empty slice.
  useEffect(() => { setPage(p => Math.min(p, totalPages)); }, [totalPages]);
  const pageSessions = sortedSessions.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  // Real gate, not cosmetic: no data fetch happens above (enabled: authed)
  // when there's no valid sp_token, and the server rejects list_sessions
  // without one regardless — this is the "return visit" auth boundary.
  if (!authed) {
    return (
      <div className="relative flex h-full items-center justify-center bg-surface-0 text-primary overflow-hidden">
        {/* Ambient glow — echoes the logo's own indigo palette instead of a flat background */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            background: "radial-gradient(circle at 50% 42%, rgba(92,107,192,0.16), transparent 55%)",
          }}
        />

        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, ease: "easeOut" }}
          className="relative text-center max-w-sm px-6"
        >
          <motion.div
            className="mx-auto mb-5 w-16 h-16"
            animate={{ rotate: 360 }}
            transition={{ duration: 90, repeat: Infinity, ease: "linear" }}
          >
            <SolarplexLogo size={64} />
          </motion.div>

          <div className="flex items-baseline justify-center gap-0 mb-3 select-none" aria-label="Solarplex">
            <span className="font-serif font-light text-2xl tracking-[-0.01em] text-subtle leading-none">
              Solar
            </span>
            <span className="font-grotesk font-semibold text-2xl tracking-[-0.03em] text-primary leading-none">
              plex
            </span>
          </div>

          <p className="text-xs text-muted mb-6 leading-relaxed">
            Sessions, artifacts, and activity are tied to your signed-in identity.
            Nothing loads until you&apos;re authenticated.
          </p>
          <button
            onClick={() => signIn("/")}
            className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue text-surface-0 hover:bg-accent-blue/90 transition-colors"
          >
            Sign in
          </button>
        </motion.div>
      </div>
    );
  }

  return (
    <>
      <OnboardingNameModal />

      <div className="max-w-[740px] mx-auto py-10 px-8">

        {/* Header */}
        <div className="mb-7 flex items-end justify-between">
          <div>
            <h1 className="text-base font-semibold text-primary mb-0.5">
              Sessions
            </h1>
            <p className="text-xs text-muted">
              Persistent workspaces for shared human and agent workflows
            </p>
          </div>
          <NewSessionDrawer
            trigger={
              <button className="
                text-xs px-3 py-1.5 rounded-md font-medium
                bg-accent-blue/10 text-accent-blue
                hover:bg-accent-blue/20
                border border-accent-blue/20
                transition-colors duration-100
              ">
                + New session
              </button>
            }
          />
        </div>

        {/* Loading state: only on this actor's first-ever visit this tab —
            a cached list from a prior visit renders instantly instead. */}
        {isPending ? (
          <div className="space-y-2">
            {[0, 1, 2].map(i => (
              <div key={i} className="h-[70px] rounded-xl border border-border bg-surface-1 animate-pulse" />
            ))}
          </div>
        ) : isError ? (
          <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
            <p className="text-sm font-medium text-subtle mb-1">Couldn&apos;t load sessions</p>
            <p className="text-xs text-muted mb-6">Your sign-in may have expired.</p>
            <button
              onClick={() => signIn("/")}
              className="text-xs px-4 py-2 rounded-lg font-medium bg-accent-blue/10 text-accent-blue hover:bg-accent-blue/20 border border-accent-blue/20 transition-colors"
            >
              Sign in again
            </button>
          </div>
        ) : (sessions ?? []).length === 0 ? (
          <div className="rounded-xl border border-border bg-surface-1 panel-shine p-14 text-center">
            <div className="text-4xl mb-4 text-border select-none leading-none">⬡</div>
            <p className="text-sm font-medium text-subtle mb-1">No sessions yet</p>
            <p className="text-xs text-muted mb-6 leading-relaxed">
              Create a session to start supervising AI agents collaboratively.
              <br />
              Attach agents, invite collaborators, and track every action.
            </p>
            <NewSessionDrawer
              trigger={
                <button className="
                  inline-flex items-center gap-1.5
                  text-xs px-4 py-2 rounded-lg font-medium
                  bg-accent-blue/10 text-accent-blue
                  hover:bg-accent-blue/20
                  border border-accent-blue/20
                  transition-colors duration-100
                ">
                  Create first session
                </button>
              }
            />
          </div>
        ) : view === "tiles" ? (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
              {pageSessions.map(s => <SessionTile key={s.id} session={s} actorId={actorId} />)}
            </div>
            <Pager page={page} totalPages={totalPages} onChange={setPage} />
          </>
        ) : (
          <>
            <div className="space-y-2">
              {pageSessions.map(s => <SessionCard key={s.id} session={s} actorId={actorId} />)}
            </div>
            <Pager page={page} totalPages={totalPages} onChange={setPage} />
          </>
        )}
      </div>
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Session card
// ─────────────────────────────────────────────────────────────────────────────

function SessionCard({ session, actorId }: { session: SessionRow; actorId: string }) {
  const created = new Date(session.created_at);
  const isToday  = new Date().toDateString() === created.toDateString();
  const dateStr  = isToday
    ? `Today at ${created.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`
    : created.toLocaleDateString([], { month: "short", day: "numeric", year: "numeric" });

  // Preserve ?actor= so identity is retained when navigating into a session.
  // Omit the param when it's the default (alice) to keep URLs clean.
  const actorParam = actorId !== "alice" ? `?actor=${encodeURIComponent(actorId)}` : "";

  const card = (
    <a
      href={`/sessions/${session.id}${actorParam}`}
      className="
        density-row
        group flex items-start gap-4
        px-4 py-3.5 rounded-xl
        border border-border bg-surface-1
        hover:bg-surface-2 hover:border-surface-4
        panel-shine
        transition-all duration-100
      "
    >
      {/* Status dot with per-status glow */}
      <span
        className={`
          mt-[5px] shrink-0 w-2 h-2 rounded-full
          ${STATUS_DOT[session.status] ?? "bg-muted"}
          ${STATUS_GLOW[session.status] ?? ""}
        `}
      />

      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-4">
          <span className="
            font-medium text-sm text-primary truncate
            group-hover:text-accent-blue transition-colors duration-100
          ">
            {session.name}
          </span>
          <span className={`
            shrink-0 text-2xs px-1.5 py-0.5 rounded border font-medium
            ${STATUS_BADGE[session.status] ?? "text-muted bg-surface-3 border-border"}
          `}>
            {STATUS_LABEL[session.status] ?? session.status}
          </span>
        </div>

        <div className="mt-1 flex items-center gap-3 text-2xs text-muted">
          <span className="font-mono">{session.id.slice(0, 8)}</span>
          <Dot />
          <span>{POLICY_LABEL[session.approval_policy] ?? session.approval_policy}</span>
          <Dot />
          <span>{dateStr}</span>
          {session.created_by && (
            <><Dot /><span>by {session.created_by_name ?? session.created_by}</span></>
          )}
        </div>
      </div>

      <span className="shrink-0 mt-0.5 text-muted group-hover:text-subtle transition-colors text-xs">
        →
      </span>
    </a>
  );

  // Radix Tooltip rather than a native `title` attribute — title tooltips
  // are slow to appear, don't respond to keyboard focus at all, and don't
  // meet WCAG 1.4.13 (dismissible/hoverable/persistent), all of which
  // Tooltip's own primitive already handles correctly. Only sessions that
  // actually have a description pay for the extra wrapper.
  if (!session.description) return card;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{card}</TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-xs text-2xs bg-surface-3 border border-border text-subtle px-2.5 py-1.5 rounded-lg shadow-elevation-float">
        {session.description}
      </TooltipContent>
    </Tooltip>
  );
}

function Dot() {
  return <span className="text-border select-none">·</span>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Session tile — same data as SessionCard, grid-card layout instead of a row
// ─────────────────────────────────────────────────────────────────────────────

function SessionTile({ session, actorId }: { session: SessionRow; actorId: string }) {
  const created = new Date(session.created_at);
  const dateStr = created.toLocaleDateString([], { month: "short", day: "numeric" });
  const actorParam = actorId !== "alice" ? `?actor=${encodeURIComponent(actorId)}` : "";

  const tile = (
    <a
      href={`/sessions/${session.id}${actorParam}`}
      className="
        group flex flex-col gap-2
        p-3.5 rounded-xl
        border border-border bg-surface-1
        hover:bg-surface-2 hover:border-surface-4
        panel-shine
        transition-all duration-100
      "
    >
      <div className="flex items-center justify-between gap-2">
        <span
          className={`
            shrink-0 w-2 h-2 rounded-full
            ${STATUS_DOT[session.status] ?? "bg-muted"}
            ${STATUS_GLOW[session.status] ?? ""}
          `}
        />
        <span className={`
          shrink-0 text-2xs px-1.5 py-0.5 rounded border font-medium
          ${STATUS_BADGE[session.status] ?? "text-muted bg-surface-3 border-border"}
        `}>
          {STATUS_LABEL[session.status] ?? session.status}
        </span>
      </div>

      <span className="
        font-medium text-sm text-primary truncate
        group-hover:text-accent-blue transition-colors duration-100
      ">
        {session.name}
      </span>

      <div className="mt-auto flex items-center gap-1.5 text-2xs text-muted">
        <span className="font-mono">{session.id.slice(0, 8)}</span>
        <Dot />
        <span>{dateStr}</span>
      </div>
    </a>
  );

  if (!session.description) return tile;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{tile}</TooltipTrigger>
      <TooltipContent side="bottom" className="max-w-xs text-2xs bg-surface-3 border border-border text-subtle px-2.5 py-1.5 rounded-lg shadow-elevation-float">
        {session.description}
      </TooltipContent>
    </Tooltip>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Pager — capped at PAGE_SIZE sessions per page, hidden when everything fits
// on one page
// ─────────────────────────────────────────────────────────────────────────────

function Pager({ page, totalPages, onChange }: { page: number; totalPages: number; onChange: (page: number) => void }) {
  if (totalPages <= 1) return null;
  return (
    <div className="mt-5 flex items-center justify-center gap-3 text-xs text-muted">
      <button
        onClick={() => onChange(page - 1)}
        disabled={page <= 1}
        className="px-2.5 py-1 rounded-md border border-border hover:bg-surface-2 hover:text-subtle disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
      >
        ‹ Prev
      </button>
      <span>Page {page} of {totalPages}</span>
      <button
        onClick={() => onChange(page + 1)}
        disabled={page >= totalPages}
        className="px-2.5 py-1 rounded-md border border-border hover:bg-surface-2 hover:text-subtle disabled:opacity-40 disabled:hover:bg-transparent transition-colors"
      >
        Next ›
      </button>
    </div>
  );
}
