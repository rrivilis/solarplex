"use client";

import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { toast } from "sonner";
import NewSessionDrawer from "@/components/NewSessionDrawer";
import SolarplexLogo from "@/components/SolarplexLogo";
import { getMe, isAuthenticated, signOut, updateMyName } from "@/lib/auth";
import { getActorOverride } from "@/lib/actorOverride";
import { getMailbox } from "@/lib/mailbox";

// ─────────────────────────────────────────────────────────────────────────────
// Icons — 14 × 14 display, 16 × 16 viewBox, 1.5 stroke
// ─────────────────────────────────────────────────────────────────────────────

function IconSessions() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <rect x="2"   y="2"   width="5.5" height="5.5" rx="1.2" />
      <rect x="8.5" y="2"   width="5.5" height="5.5" rx="1.2" />
      <rect x="2"   y="8.5" width="5.5" height="5.5" rx="1.2" />
      <rect x="8.5" y="8.5" width="5.5" height="5.5" rx="1.2" />
    </svg>
  );
}

function IconInbox() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <path d="M1.5 8.5h3.8l1.2 2h2.5l1.2-2h3.8" />
      <path d="M2.3 8.5 3.6 3a1 1 0 0 1 1-.75h6.8a1 1 0 0 1 1 .75l1.3 5.5" />
      <rect x="1.5" y="8.5" width="13" height="5" rx="1.2" />
    </svg>
  );
}

function IconActivity() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {/* ECG / heartbeat line */}
      <polyline points="1,8 3.5,8 5,4.5 7,11.5 9,8 10.5,8 12,5.5 13.5,8 15,8" />
    </svg>
  );
}

function IconSearch() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="6.5" cy="6.5" r="4.5" />
      <line x1="10.1" y1="10.1" x2="14.5" y2="14.5" />
    </svg>
  );
}

function IconTeam() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {/* Primary person */}
      <circle cx="6" cy="5.5" r="2.5" />
      <path d="M1 14c0-2.76 2.24-5 5-5h2c2.76 0 5 2.24 5 5" />
      {/* Secondary person (faded) */}
      <circle cx="12" cy="5" r="2" opacity="0.55" />
      <path d="M14 14c0-1.85-1.15-3.44-2.8-4.1" opacity="0.55" />
    </svg>
  );
}

function IconAgents() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      {/* CPU chip outline */}
      <rect x="3.5" y="3.5" width="9" height="9" rx="1.5" />
      {/* Pins */}
      <path d="M6 1.5V3.5M10 1.5V3.5" />
      <path d="M6 12.5V14.5M10 12.5V14.5" />
      <path d="M1.5 6H3.5M1.5 10H3.5" />
      <path d="M12.5 6H14.5M12.5 10H14.5" />
      {/* Inner core */}
      <rect x="5.5" y="5.5" width="5" height="5" rx="0.8"
        fill="currentColor" stroke="none" fillOpacity="0.35" />
    </svg>
  );
}

function IconSettings() {
  return (
    <svg width="14" height="14" viewBox="0 0 16 16" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden>
      <circle cx="8" cy="8" r="2.5" />
      {/* 8 spokes */}
      <path d="M8 1.5V3.2M8 12.8V14.5M1.5 8H3.2M12.8 8H14.5" />
      <path d="M3.4 3.4L4.5 4.5M11.5 11.5L12.6 12.6M12.6 3.4L11.5 4.5M4.5 11.5L3.4 12.6" />
    </svg>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Nav data
// ─────────────────────────────────────────────────────────────────────────────

const NAV_OVERVIEW = [
  { href: "/",         label: "Sessions",       Icon: IconSessions },
  { href: "/inbox",    label: "Inbox",          Icon: IconInbox    },
  { href: "/activity", label: "Recent Activity", Icon: IconActivity },
  { href: "/search",   label: "Search",          Icon: IconSearch   },
] as const;

const NAV_ADMIN = [
  { href: "/team",     label: "Teammates", Icon: IconTeam     },
  { href: "/agents",   label: "Agents",    Icon: IconAgents   },
  { href: "/settings", label: "Settings",  Icon: IconSettings },
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Sub-components
// ─────────────────────────────────────────────────────────────────────────────

function NavSection({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="mb-1">
      <p className="
        px-3 pt-3 pb-1
        text-[11px] uppercase tracking-[0.10em]
        text-muted font-semibold select-none
      ">
        {label}
      </p>
      <div className="space-y-px">{children}</div>
    </div>
  );
}

function NavItem({
  href,
  label,
  Icon,
  active,
  badge,
}: {
  href: string;
  label: string;
  Icon: React.ComponentType;
  active: boolean;
  badge?: number;
}) {
  return (
    <Link
      href={href}
      className={`
        flex items-center gap-2.5
        mx-2 px-2.5 py-[7px]
        rounded-md text-xs font-medium
        transition-colors duration-100 group
        ${active
          ? "bg-surface-3 text-primary shadow-[inset_0_1px_0_rgba(255,255,255,0.035)]"
          : "text-muted hover:text-primary hover:bg-surface-2"}
      `}
    >
      <span className={`
        shrink-0 transition-colors duration-100
        ${active ? "text-subtle" : "text-muted group-hover:text-primary"}
      `}>
        <Icon />
      </span>
      <span className="truncate flex-1">{label}</span>
      {!!badge && badge > 0 && (
        <span className="
          shrink-0 min-w-[16px] h-4 px-1 rounded-full
          bg-accent-blue text-surface-0
          text-[10px] font-bold leading-4 text-center
        ">
          {badge > 99 ? "99+" : badge}
        </span>
      )}
    </Link>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Status config
// ─────────────────────────────────────────────────────────────────────────────

const USER_STATUS = {
  online:  { dot: "bg-accent-green shadow-[0_0_5px_rgba(62,207,142,0.5)]", label: "Online",  text: "text-accent-green" },
  away:    { dot: "bg-accent-amber",                                        label: "Away",    text: "text-accent-amber" },
  offline: { dot: "bg-muted",                                               label: "Offline", text: "text-muted"        },
} as const;

// ─────────────────────────────────────────────────────────────────────────────
// UserCard — reads actor from prop (server-rendered home) or URL param (client)
// Isolated into its own component so useSearchParams() doesn't block AppNav's
// hydration — Suspense handles the async param resolution.
// ─────────────────────────────────────────────────────────────────────────────

function UserCardInner({ actorIdProp }: { actorIdProp?: string }) {
  const searchParams = useSearchParams();
  const actorId = actorIdProp ?? getActorOverride(searchParams) ?? "alice";

  // Real identity once signed in, via GET /auth/me. `enabled: isAuthenticated()`
  // is safe to read directly here (unlike app/page.tsx's auth gate) because
  // `data` is undefined on both the server render and the client's first
  // hydration pass regardless — react-query never resolves synchronously on
  // mount, so the rendered *structure* never differs, only text content
  // once the query resolves post-hydration, which is an ordinary update.
  const { data: me } = useQuery({
    queryKey: ["me"],
    queryFn: getMe,
    enabled: isAuthenticated(),
    staleTime: 60_000,
  });

  // Falls back to the ?actor= placeholder pre-auth or while /me is loading —
  // e.g. "alice" → "Alice" / "AL" — otherwise uses the resolved actor's own name.
  const displayName = me?.name ?? (actorId.charAt(0).toUpperCase() + actorId.slice(1));
  const initials = (me?.name ?? actorId).slice(0, 2).toUpperCase();

  // Still a placeholder: no real presence signal exists yet (this is a
  // separate, pre-existing gap from the identity fix above — see the
  // `// until real auth` history on this line).
  const status = USER_STATUS.online;

  // ── Rename ────────────────────────────────────────────────────────────────
  // Only reachable once `me` has actually resolved — no point offering to
  // "rename" the ?actor= dev placeholder, which isn't a real account.
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft]     = useState("");
  const [saving, setSaving]   = useState(false);

  function startEditing() {
    if (!me) return;
    setDraft(me.name);
    setEditing(true);
  }

  async function commitEdit() {
    const next = draft.trim();
    if (!next || next === me?.name) {
      setEditing(false);
      return;
    }
    setSaving(true);
    try {
      await updateMyName(next);
      queryClient.invalidateQueries({ queryKey: ["me"] });
      // Session cards show `created_by_name`, resolved server-side at fetch
      // time from the actor row this rename just changed — without this,
      // the list keeps showing the old name until something unrelated
      // forces a refetch (reload, navigating away and back).
      queryClient.invalidateQueries({ queryKey: ["sessions"] });
      setEditing(false);
    } catch (e) {
      toast.error(`Couldn't update name: ${e instanceof Error ? e.message : "unknown error"}`);
    } finally {
      setSaving(false);
    }
  }

  // ── Overflow menu (rename / sign out) ───────────────────────────────────────
  // The chevron used to be purely decorative — a hover hint with nothing behind
  // it. Sign-out had no UI affordance anywhere; this is the one place a signed-
  // in user's own identity is surfaced, so it's the natural home for it.
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    function onPointerDown(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
      }
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") setMenuOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [menuOpen]);

  function handleSignOut() {
    signOut();
    // Hard navigation, not router.push: every page holding auth-derived
    // react-query state (sessions list, this card's own `me` query) needs a
    // full reset, not a client-side transition that could briefly render
    // stale "signed in" content against a token that's already gone.
    window.location.href = "/";
  }

  return (
    <div ref={menuRef} className="relative">
    <div
      onClick={() => setMenuOpen(v => !v)}
      className="
      flex items-center gap-2.5
      px-2 py-2.5
      rounded-lg
      hover:bg-surface-2 cursor-pointer
      transition-colors duration-100 group
    ">
      {/* Avatar */}
      <div className="
        w-7 h-7 rounded-full shrink-0
        bg-accent-blue/15 text-accent-blue
        ring-1 ring-accent-blue/20
        flex items-center justify-center
        text-[10px] font-bold tracking-wide
      ">
        {initials}
      </div>

      {/* Name · status */}
      <div className="flex-1 min-w-0">
        {editing ? (
          <input
            autoFocus
            value={draft}
            disabled={saving}
            onChange={e => setDraft(e.target.value)}
            onBlur={commitEdit}
            onKeyDown={e => {
              if (e.key === "Enter") { e.currentTarget.blur(); }
              if (e.key === "Escape") { setEditing(false); }
            }}
            onClick={e => e.stopPropagation()}
            className="w-full text-xs font-semibold text-primary bg-surface-3 rounded px-1 -mx-1 leading-tight outline-none focus:ring-1 focus:ring-accent-blue/40"
          />
        ) : me ? (
          <button
            type="button"
            className="block w-full text-left text-xs font-semibold text-primary leading-tight truncate hover:underline decoration-dotted underline-offset-2"
            title="Click to rename"
            onClick={e => { e.stopPropagation(); startEditing(); }}
          >
            {displayName}
          </button>
        ) : (
          <p className="text-xs font-semibold text-primary leading-tight truncate">
            {displayName}
          </p>
        )}
        <div className="flex items-center gap-1.5 mt-[3px]">
          <span className={`flex items-center gap-1 text-2xs leading-none ${status.text}`}>
            <span className={`w-[5px] h-[5px] rounded-full shrink-0 ${status.dot}`} />
            {status.label}
          </span>
        </div>
      </div>

      {/* Overflow chevron — opens the account menu */}
      <button
        onClick={e => { e.stopPropagation(); setMenuOpen(v => !v); }}
        aria-label="Account menu"
        aria-haspopup="menu"
        aria-expanded={menuOpen}
        className={`
          shrink-0 p-0.5 rounded transition-opacity duration-100
          ${menuOpen ? "opacity-60" : "opacity-0 group-hover:opacity-60"}
          text-muted hover:text-subtle
        `}
      >
        <motion.svg
          width="11" height="11" viewBox="0 0 12 12" fill="none"
          stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
          aria-hidden
          animate={{ rotate: menuOpen ? 180 : 0 }}
          transition={{ duration: 0.15, ease: [0.4, 0, 0.2, 1] }}
        >
          <path d="M2 4.5L6 8l4-3.5" />
        </motion.svg>
      </button>
    </div>

    {/* Account menu */}
    <AnimatePresence>
      {menuOpen && (
        <motion.div
          role="menu"
          aria-label="Account menu"
          initial={{ opacity: 0, y: 4, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 4, scale: 0.97 }}
          transition={{ duration: 0.15, ease: [0.4, 0, 0.2, 1] }}
          style={{ transformOrigin: "bottom" }}
          className="
          absolute left-2 right-2 bottom-full mb-1 z-10
          rounded-lg border border-border bg-surface-2 panel-shine
          shadow-elevation-float overflow-hidden
        ">
          {me && (
            <button
              role="menuitem"
              onClick={() => { setMenuOpen(false); startEditing(); }}
              className="w-full text-left px-3 py-2 text-xs text-subtle hover:bg-surface-3 transition-colors"
            >
              Rename
            </button>
          )}
          <button
            role="menuitem"
            onClick={() => { setMenuOpen(false); handleSignOut(); }}
            className="w-full text-left px-3 py-2 text-xs text-accent-red hover:bg-surface-3 transition-colors"
          >
            Sign out
          </button>
        </motion.div>
      )}
    </AnimatePresence>
    </div>
  );
}

function UserCardFallback() {
  return (
    <div className="flex items-center gap-2.5 px-2 py-2.5 rounded-lg">
      <div className="w-7 h-7 rounded-full shrink-0 bg-surface-3 animate-pulse" />
      <div className="flex-1 min-w-0 space-y-1">
        <div className="h-2.5 bg-surface-3 rounded animate-pulse w-16" />
        <div className="h-2 bg-surface-3 rounded animate-pulse w-10" />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AppNav
// ─────────────────────────────────────────────────────────────────────────────

export default function AppNav({ actorId }: { actorId?: string }) {
  const pathname = usePathname();

  // Exact match for "/" so /sessions/xyz doesn't activate Sessions nav item
  const isActive = (href: string) =>
    href === "/" ? pathname === "/" : pathname.startsWith(href);

  // Inbox badge — refetch-on-focus (react-query default) is enough to keep
  // this reasonably fresh without a live-push transport; see the mailbox
  // design note on deferring SSE until the relational model proves itself.
  const { data: mailbox } = useQuery({
    queryKey: ["mailbox"],
    queryFn: getMailbox,
    enabled: isAuthenticated(),
    staleTime: 30_000,
  });
  const unseenCount = mailbox?.filter(e => !e.seen_at).length ?? 0;

  // GlobalCommandPalette's "New Session" action has no trigger element of
  // its own to click — AppNav's drawer instance is mounted on every page
  // (unlike app/page.tsx's, which only exists on the sessions list), so
  // it's the one this bridges to. Previously CommandPalette just routed to
  // /sessions/new, a full-page route left over from before this drawer
  // existed — nothing else in the app links there anymore.
  const [newSessionSignal, setNewSessionSignal] = useState(0);
  useEffect(() => {
    function open() { setNewSessionSignal(n => n + 1); }
    window.addEventListener("sol:open-new-session", open);
    return () => window.removeEventListener("sol:open-new-session", open);
  }, []);

  return (
    <aside className="
      w-[228px] shrink-0 h-full
      border-r border-border
      sidebar-surface panel-shine
      flex flex-col
    ">
      {/* ── Wordmark ────────────────────────────────────────────────── */}
      <div className="h-11 flex items-center gap-2.5 px-3.5 border-b border-border shrink-0">
        <SolarplexLogo size={26} />
        <span className="flex items-baseline gap-0 select-none" aria-label="Solarplex">
          {/* Merriweather Light — warm, organic, celestial */}
          <span className="font-serif font-light text-[14px] tracking-[-0.01em] text-subtle leading-none">
            Solar
          </span>
          {/* Figtree SemiBold — systematic, precise, network */}
          <span className="font-grotesk font-semibold text-[14px] tracking-[-0.03em] text-primary leading-none">
            plex
          </span>
        </span>
      </div>

      {/* ── Primary nav ─────────────────────────────────────────────── */}
      <nav className="flex-1 overflow-y-auto py-1">
        <NavSection label="Overview">
          {NAV_OVERVIEW.map(item => (
            <NavItem
              key={item.href}
              href={item.href}
              label={item.label}
              Icon={item.Icon}
              active={isActive(item.href)}
              badge={item.href === "/inbox" ? unseenCount : undefined}
            />
          ))}
        </NavSection>

        <NavSection label="Admin">
          {NAV_ADMIN.map(item => (
            <NavItem
              key={item.href}
              href={item.href}
              label={item.label}
              Icon={item.Icon}
              active={isActive(item.href)}
            />
          ))}
        </NavSection>
      </nav>

      {/* ── New session CTA ─────────────────────────────────────────── */}
      <div className="shrink-0 px-3 py-3 border-t border-border">
        <NewSessionDrawer
          openSignal={newSessionSignal}
          trigger={
            <button className="
              flex items-center justify-center gap-1.5
              w-full py-[7px] px-3
              rounded-md text-xs font-medium
              bg-surface-2 hover:bg-surface-3
              text-muted hover:text-subtle
              border border-border hover:border-surface-4
              transition-colors duration-100
            ">
              {/* Plus icon */}
              <svg width="10" height="10" viewBox="0 0 10 10" fill="none"
                stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" aria-hidden>
                <line x1="5" y1="1" x2="5" y2="9" />
                <line x1="1" y1="5" x2="9" y2="5" />
              </svg>
              New session
            </button>
          }
        />
      </div>

      {/* ── User card ───────────────────────────────────────────────── */}
      <div className="shrink-0 px-3 pb-3 pt-1 border-t border-border">
        <Suspense fallback={<UserCardFallback />}>
          <UserCardInner actorIdProp={actorId} />
        </Suspense>
      </div>
    </aside>
  );
}
