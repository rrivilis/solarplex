// Single source of truth for the required public env vars — every call site
// used to duplicate its own `process.env.NEXT_PUBLIC_API_URL ?? "http://
// localhost:8080/api"` fallback independently (14 copies). The fallback here
// is a `next dev`-only convenience: the actual hard-fail-on-missing-in-
// production check lives in next.config.mjs, since NEXT_PUBLIC_* values are
// inlined into the client bundle at build time — by the time this module
// runs in a browser the value is already permanently baked in either way,
// so build time is the only point where "missing" can still be stopped.
export const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080/api";
export const WS_BASE  = process.env.NEXT_PUBLIC_WS_URL  ?? "ws://localhost:8080";
