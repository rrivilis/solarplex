// ── Dev-only actor override ──────────────────────────────────────────────────
//
// Before real OIDC auth existed, every page resolved "who am I" from a
// ?actor= URL param (or NEXT_PUBLIC_ACTOR_ID) so multiple dev actors could
// share one local server. Every route that actually matters (session list,
// session-scoped GETs, WS attach when signed in) now derives identity
// server-side from the verified sp_token and already ignores this — but the
// value still surfaces in a few pre-auth/dev display fallbacks, and a query
// param any live visitor can set at will has no business being live in a
// public deployment even as a cosmetic fallback. Hard-disabled outside
// development, not just discouraged by convention or env-file hygiene;
// see next.config.mjs, which also refuses to build production with
// NEXT_PUBLIC_ACTOR_ID set at all.
import type { ReadonlyURLSearchParams } from "next/navigation";

export function getActorOverride(searchParams: ReadonlyURLSearchParams): string | null {
  if (process.env.NODE_ENV === "production") return null;
  return searchParams.get("actor") ?? process.env.NEXT_PUBLIC_ACTOR_ID ?? null;
}
