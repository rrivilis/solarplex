"use client";

// ── sp_token — the OIDC-issued human session token ──────────────────────────
//
// Session-scoped reads and mutations now require this (see the server's
// crate::auth::require_session_member / require_sp_auth gates) rather than
// a self-asserted actor_id. This module is the single place that reads,
// writes, and attaches it — no other file should touch its storage slot
// directly.
//
// localStorage, not sessionStorage: the server issues this token with a
// 7-day TTL (crates/server/src/auth.rs::oidc_callback) — it's meant to
// outlive a single tab. sessionStorage would force a fresh OIDC round-trip
// on every new tab or browser restart, which doesn't match what the server
// already committed to. The tradeoff being made deliberately: localStorage
// is readable by any script on the origin (XSS-accessible) where
// sessionStorage is marginally more contained — acceptable here because
// the token is already a bearer credential with a real expiry and a
// server-side revoke path (signOut), not a long-lived secret with no
// blast-radius control.

import { toast } from "sonner";
import { isTauri } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

import { API_BASE } from "./env";

const SP_TOKEN_KEY = "sol-sp-token";

function apiOrigin(): string {
  // /auth/oidc/* is mounted at the server's top level, not under /api.
  return API_BASE.replace(/\/api\/?$/, "");
}

/**
 * Capture an sp_token delivered via location.hash after the OIDC callback
 * redirect (`#sp_token=...` — a fragment, so it never touches server access
 * logs or gets forwarded in a Referer header). Call once on app mount;
 * idempotent, safe to call on every page load even when there's no hash.
 */
export function captureSpTokenFromHash(): void {
  if (typeof window === "undefined") return;
  const hash = window.location.hash;
  if (!hash.startsWith("#")) return;
  const params = new URLSearchParams(hash.slice(1));
  const token = params.get("sp_token");
  if (!token) return;
  localStorage.setItem(SP_TOKEN_KEY, token);
  // Strip the token out of the visible URL so it doesn't linger in browser
  // history or get shared accidentally via copy-pasting the address bar.
  window.history.replaceState(null, "", window.location.pathname + window.location.search);
}

export function getSpToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem(SP_TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return getSpToken() !== null;
}

function clearSpToken(): void {
  if (typeof window === "undefined") return;
  localStorage.removeItem(SP_TOKEN_KEY);
}

/**
 * Fired (on `window`) after the server rejected the stored sp_token and it was
 * cleared, so the app shell can fall back to the signed-out screen without a
 * reload. Without it, `isAuthenticated()` (which only asks "is a token
 * stored?") keeps answering yes for a token that expired a month ago, and
 * every page just shows an error card instead of the sign-in prompt.
 */
export const SIGNED_OUT_EVENT = "sol:signed-out";

/**
 * Drop a token the server just refused. Only if it is still the token we
 * sent: a sign-in that completed while this request was in flight must not
 * be wiped out by the stale 401 of the request that predated it.
 */
function dropRejectedToken(sent: string): void {
  if (typeof window === "undefined") return;
  if (localStorage.getItem(SP_TOKEN_KEY) !== sent) return;
  clearSpToken();
  window.dispatchEvent(new Event(SIGNED_OUT_EVENT));
}

/**
 * Can the OIDC flow start? Asks `/auth/oidc/start` without following its
 * redirect: a working server answers with a redirect to the identity provider
 * (an "opaque redirect" to fetch). Anything else readable (e.g. the 501 a
 * server started without OIDC configured returns) is an answer we can show
 * the user in place, rather than navigating them away to a bare text page
 * with no way back.
 *
 * If the probe itself can't tell (network or CORS failure), it does NOT block:
 * navigating anyway is exactly what happened before, and a genuinely
 * unreachable server then gets the browser's own error page.
 *
 * Costs one extra start request (and one PKCE entry that simply expires),
 * which the start endpoint's rate limit comfortably allows.
 */
async function probeSignIn(
  url: URL,
): Promise<{ ok: true } | { ok: false; title: string; detail?: string }> {
  try {
    const res = await fetch(url, { redirect: "manual", cache: "no-store" });
    if (res.type === "opaqueredirect") return { ok: true };
    if (res.status === 501) {
      return {
        ok: false,
        title: "Sign-in isn't set up on this server",
        detail: (await res.text()).slice(0, 400),
      };
    }
    if (res.status === 429) {
      return { ok: false, title: "Too many sign-in attempts", detail: "Wait a minute and try again." };
    }
    return {
      ok: false,
      title: "Sign-in is unavailable right now",
      detail: `The server answered HTTP ${res.status}.`,
    };
  } catch {
    return { ok: true };
  }
}

/**
 * Redirect to the OIDC login flow.
 * `returnTo` must be a same-origin relative path (e.g. "/invite/01J...") —
 * validated again server-side (`auth::is_safe_return_to`) before use.
 *
 * On the web this first checks that sign-in can actually start (see
 * `probeSignIn`) and, if it can't, says why in a toast and stays on the page.
 *
 * Inside the Tauri desktop shell this opens the flow in the system browser
 * instead of navigating the app's own webview — RFC 8252's recommendation
 * for native-app OAuth (the user's existing browser session/autofill/
 * passkeys apply, and the app never sees credential entry), not just a
 * workaround for embedded-webview blocks some providers apply on mobile.
 * The server's callback (`?client=desktop` → `PkceEntry::desktop`) redirects
 * back via a `solarplex-desktop://` deep link instead of this origin;
 * `frontend/src-tauri/src/lib.rs`'s `on_open_url` catches that and forwards
 * the token into this same webview by navigating to `/#sp_token=...`, which
 * `captureSpTokenFromHash` below already knows how to pick up — no separate
 * desktop capture path needed here.
 */
export async function signIn(returnTo?: string): Promise<void> {
  if (typeof window === "undefined") return;
  const url = new URL(`${apiOrigin()}/auth/oidc/start`);
  if (returnTo) url.searchParams.set("return_to", returnTo);

  if (isTauri()) {
    url.searchParams.set("client", "desktop");
    openUrl(url.toString()).catch(() => {
      // System browser failed to launch (no default browser configured,
      // etc.) — falling back to in-webview navigation still gets the user
      // signed in, just without the system-browser benefits above.
      window.location.href = url.toString();
    });
    return;
  }

  const probe = await probeSignIn(url);
  if (!probe.ok) {
    toast.error(probe.title, { description: probe.detail });
    return;
  }
  window.location.href = url.toString();
}

/** Best-effort server-side revoke, then clear locally regardless of outcome. */
export function signOut(): void {
  const token = getSpToken();
  clearSpToken();
  if (!token) return;
  fetch(`${apiOrigin()}/auth/oidc/logout`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ sp_token: token }),
  }).catch(() => {});
}

/**
 * fetch() wrapper that attaches `Authorization: Bearer <sp_token>` when one
 * exists. Use for every call to a session-scoped endpoint — those now
 * reject requests with no valid token.
 */
export async function authFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const token = getSpToken();
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(url, { ...init, headers });
  // 401 = the server looked at this token and refused it (expired, revoked,
  // never issued). A server that merely couldn't check answers 503 instead
  // (see `require_sp_auth`), so a database blip never lands here and never
  // signs anyone out.
  if (token && res.status === 401) dropRejectedToken(token);
  return res;
}

/**
 * Check a response from a Tier-1 rate-limited endpoint (message post,
 * context add, artifact create, approval request, agent attach, ownership
 * transfer — see the server's `crate::rate_limit` module doc) for a 429,
 * and if so, show `toast.error` with the policy/retry-after info from the
 * response body. Mirrors `lib/ws.ts`'s "effect.rate_limited" handler, which
 * covers the same denial when it arrives as a broadcast event instead of a
 * direct response (message post and context add go over the WS connection,
 * not REST, from this frontend — see that handler's doc comment).
 *
 * Returns true if this was a 429 (so the caller should stop, not fall
 * through to its normal success/error handling). Pass `toastId` to morph an
 * existing loading/pending toast in place rather than opening a new one.
 */
export async function maybeToastRateLimited(res: Response, toastId?: string | number): Promise<boolean> {
  if (res.status !== 429) return false;
  let key = "", policy = "", retryAfter = 0;
  try {
    const body = await res.json();
    key = typeof body?.key === "string" ? body.key : "";
    policy = typeof body?.policy === "string" ? body.policy : "";
    retryAfter = typeof body?.retry_after_secs === "number" ? body.retry_after_secs : 0;
  } catch { /* fall through with a generic message */ }
  toast.error(`Rate limit reached${key ? ` for ${key}` : ""}`, {
    id: toastId,
    description: [
      policy ? `Limit: ${policy}` : null,
      retryAfter > 0 ? `Try again in ${retryAfter}s` : null,
    ].filter(Boolean).join(" · ") || undefined,
  });
  return true;
}

export type CurrentActor = {
  id: string;
  name: string;
  email: string | null;
  type: "human" | "agent";
};

/**
 * Resolve the signed-in actor's own identity via GET /auth/me. Not related
 * to the mailbox work — this answers "who am I", the mailbox answers
 * "what's addressed to me". Returns null when unauthenticated or the
 * request fails; callers should treat that as "show the placeholder", not
 * as an error worth surfacing.
 */
export async function getMe(): Promise<CurrentActor | null> {
  if (!isAuthenticated()) return null;
  try {
    const res = await authFetch(`${apiOrigin()}/auth/me`);
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

/**
 * Set the signed-in actor's own display name via PATCH /auth/me. The OIDC
 * provider's name/email claim is only ever a first-login default — this is
 * the only way to change it afterward. Throws on failure so callers can
 * show a real error instead of silently no-op'ing (unlike getMe, where
 * "couldn't resolve" and "not signed in" are meant to look the same).
 */
export async function updateMyName(name: string): Promise<CurrentActor> {
  const res = await authFetch(`${apiOrigin()}/auth/me`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
  return res.json();
}

// ── Sign-in history ──────────────────────────────────────────────────────────
//
// GET/DELETE /auth/sessions — a Google/GitHub-style "devices" list over the
// same human_sessions rows the OIDC login flow has always written. `id`
// below is a one-way hash of the raw sp_token (never the token itself, and
// never reversible to it) — safe to display and to send back for revoke.

export type AuthSession = {
  id: string;
  provider: string;
  issued_at: string;
  expires_at: string;
  last_seen: string;
  is_current: boolean;
};

export async function listAuthSessions(): Promise<AuthSession[]> {
  const res = await authFetch(`${apiOrigin()}/auth/sessions`);
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
  return res.json();
}

/** Revoke one sign-in ("sign out this device"). Not for the current
 *  session — use signOut() for that, which also clears local storage. */
export async function revokeAuthSession(id: string): Promise<void> {
  const res = await authFetch(`${apiOrigin()}/auth/sessions/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });
  if (!res.ok) throw new Error(await res.text() || `HTTP ${res.status}`);
}
