"use client";

// ── Reset workspace layouts ──────────────────────────────────────────────────
//
// SyncWorkspace persists each session's pane positions/sizes to localStorage
// under its own key, one per session ever opened as a workspace — there's no
// single "clear it all" entry point today short of clearing the whole
// origin's storage. This is that entry point: sweep every key with the
// shared prefix, not just the current session's.
//
// Deliberately a literal string, not an import from SyncWorkspace.tsx (which
// also exports WORKSPACE_LAYOUT_KEY_PREFIX) — pulling that whole component
// module (framer-motion, react-query, drag/resize logic) into this tiny,
// widely-imported preferences module just to share one constant isn't worth
// the bundle coupling. Keep the two literals in sync if either changes.
const WORKSPACE_LAYOUT_KEY_PREFIX = "sol-workspace-layout-";

/** Returns the number of saved layouts cleared. */
export function resetAllWorkspaceLayouts(): number {
  if (typeof window === "undefined") return 0;
  const keys = Object.keys(localStorage).filter(k => k.startsWith(WORKSPACE_LAYOUT_KEY_PREFIX));
  keys.forEach(k => localStorage.removeItem(k));
  return keys.length;
}

// ── Default landing page ─────────────────────────────────────────────────────
//
// Governs where a *fresh tab* lands after sign-in — not what "/" always
// means. The Sessions nav item in AppNav points at "/" too, so redirecting
// unconditionally on every visit to "/" would break clicking "Sessions"
// (it'd just bounce you straight back to your landing page). Instead this
// is a one-shot-per-tab redirect, consumed via sessionStorage: it fires once
// when the tab first becomes authenticated, then gets out of the way for
// every subsequent in-tab navigation, including clicking "Sessions" itself.

export type LandingPage = "sessions" | "activity" | "inbox";

const LANDING_KEY = "sol-default-landing";
const LANDING_APPLIED_KEY = "sol-landing-applied";

const LANDING_PATH: Record<LandingPage, string> = {
  sessions: "/",
  activity: "/activity",
  inbox: "/inbox",
};

export const LANDING_OPTIONS: { value: LandingPage; label: string }[] = [
  { value: "sessions", label: "Sessions" },
  { value: "activity", label: "Recent Activity" },
  { value: "inbox",    label: "Inbox" },
];

export function getDefaultLanding(): LandingPage {
  if (typeof window === "undefined") return "sessions";
  const v = localStorage.getItem(LANDING_KEY);
  return v === "activity" || v === "inbox" ? v : "sessions";
}

export function setDefaultLanding(page: LandingPage): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(LANDING_KEY, page);
}

/**
 * Call once, from "/", only after confirming the tab is authenticated.
 * Returns the path to redirect to, or null if no redirect should happen
 * (preference is "sessions", or this tab already consumed its one-shot
 * redirect this session — e.g. the user then clicked "Sessions" in the nav,
 * which also points at "/" and must not get bounced right back out).
 */
export function consumeLandingRedirect(): string | null {
  if (typeof window === "undefined") return null;
  if (sessionStorage.getItem(LANDING_APPLIED_KEY)) return null;
  sessionStorage.setItem(LANDING_APPLIED_KEY, "1");
  const pref = getDefaultLanding();
  return pref === "sessions" ? null : LANDING_PATH[pref];
}

// ── Absolute vs. relative timestamps ─────────────────────────────────────────
//
// Shared preference read by RelativeTime, applied app-wide with no per-call-
// site changes needed — every existing <RelativeTime date=.../> usage picks
// this up automatically.

const TIMESTAMP_KEY = "sol-timestamp-mode";
export type TimestampMode = "relative" | "absolute";

export function getTimestampMode(): TimestampMode {
  if (typeof window === "undefined") return "relative";
  return localStorage.getItem(TIMESTAMP_KEY) === "absolute" ? "absolute" : "relative";
}

export function setTimestampMode(mode: TimestampMode): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(TIMESTAMP_KEY, mode);
  // No listener/observer infrastructure exists for cross-component reactivity
  // here (unlike React Query's cache) — a full reload is the simplest way to
  // guarantee every already-mounted RelativeTime picks up the new mode, and
  // this is a low-frequency settings change, not a live toggle worth wiring
  // a pub/sub for.
  window.location.reload();
}

// ── List density ──────────────────────────────────────────────────────────────
//
// Toggles a `data-density` attribute on <html>; globals.css defines the
// spacing each value maps to. Applied to the Sessions, Activity, and Inbox
// list rows specifically (the highest-traffic dense lists) — not a claim
// that every surface in the app respects it.

const DENSITY_KEY = "sol-density";
export type Density = "comfortable" | "compact";

export function getDensity(): Density {
  if (typeof window === "undefined") return "comfortable";
  return localStorage.getItem(DENSITY_KEY) === "compact" ? "compact" : "comfortable";
}

export function setDensity(density: Density): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(DENSITY_KEY, density);
  document.documentElement.setAttribute("data-density", density);
}

/** Call once on mount (e.g. in Providers) so a saved preference applies
 *  before the lists that read it render, not just after the next toggle. */
export function applyStoredDensity(): void {
  if (typeof window === "undefined") return;
  document.documentElement.setAttribute("data-density", getDensity());
}

// ── Session list sort + view ─────────────────────────────────────────────────
//
// Read (and set) from Settings only — unlike density, which touches an
// <html> attribute other already-mounted pages could be looking at right
// now, these are consumed solely by the Sessions page itself, so there's
// no live cross-page reactivity to wire: changing a value in Settings
// takes effect the next time Sessions mounts and reads it, same as the
// default-landing-page preference above.

const SESSION_SORT_KEY = "sol-session-sort";
export type SessionSortBy = "date" | "name";

export const SESSION_SORT_OPTIONS: { value: SessionSortBy; label: string }[] = [
  { value: "date", label: "Date" },
  { value: "name", label: "Name" },
];

export function getSessionSortBy(): SessionSortBy {
  if (typeof window === "undefined") return "date";
  return localStorage.getItem(SESSION_SORT_KEY) === "name" ? "name" : "date";
}

export function setSessionSortBy(sortBy: SessionSortBy): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(SESSION_SORT_KEY, sortBy);
}

const SESSION_SORT_DIR_KEY = "sol-session-sort-dir";
export type SessionSortDirection = "asc" | "desc";

// Default "desc" matches the order sessions rendered in before this
// preference existed (newest first) — introducing the preference doesn't
// silently reorder anyone's list.
export function getSessionSortDirection(): SessionSortDirection {
  if (typeof window === "undefined") return "desc";
  return localStorage.getItem(SESSION_SORT_DIR_KEY) === "asc" ? "asc" : "desc";
}

export function setSessionSortDirection(direction: SessionSortDirection): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(SESSION_SORT_DIR_KEY, direction);
}

const SESSION_VIEW_KEY = "sol-session-view";
export type SessionView = "list" | "tiles";

export const SESSION_VIEW_OPTIONS: { value: SessionView; label: string }[] = [
  { value: "list",  label: "List" },
  { value: "tiles", label: "Tiles" },
];

export function getSessionView(): SessionView {
  if (typeof window === "undefined") return "list";
  return localStorage.getItem(SESSION_VIEW_KEY) === "tiles" ? "tiles" : "list";
}

export function setSessionView(view: SessionView): void {
  if (typeof window === "undefined") return;
  localStorage.setItem(SESSION_VIEW_KEY, view);
}
