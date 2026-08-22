import withBundleAnalyzerInit from "@next/bundle-analyzer";

// ANALYZE=true next build emits a static treemap to .next/analyze/*.html
// instead of changing runtime behavior — dev-only tooling, not something
// that affects a real deploy. openAnalyzer stays false: this is meant to
// be inspected as a generated file (or scripted against), not to pop a
// browser tab open on a headless build box.
const withBundleAnalyzer = withBundleAnalyzerInit({
  enabled: process.env.ANALYZE === "true",
  openAnalyzer: false,
});

const isProd = process.env.NODE_ENV === "production";

// NEXT_PUBLIC_* values are inlined into the client bundle at `next build`
// time — by the time this code is running in a visitor's browser, whatever
// value lands here is permanent for that build. A silent localhost default
// is a harmless dev convenience; the same silent default in a production
// build means every visitor's browser tries to talk to *their own*
// localhost, and previously this config unconditionally supplied one
// regardless of environment. Fail the build loudly instead.
if (isProd) {
  const missing = ["NEXT_PUBLIC_API_URL", "NEXT_PUBLIC_WS_URL"].filter(k => !process.env[k]);
  if (missing.length > 0) {
    throw new Error(
      `Missing required env var(s) for a production build: ${missing.join(", ")}. ` +
      "These are baked into the client bundle at build time — there is no safe default for a public deployment."
    );
  }
  if (process.env.NEXT_PUBLIC_ACTOR_ID) {
    throw new Error(
      "NEXT_PUBLIC_ACTOR_ID must not be set for a production build — it overrides every " +
      "visitor's identity with one static value. It's a dev-only convenience for local " +
      "multi-actor testing pre-auth; see .env.example. Unset it before building for production."
    );
  }
}

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Allow each dev-server instance to use its own build directory so two
  // concurrent servers (e.g. alice on :3000, bob on :3001) don't corrupt
  // each other's webpack cache.  Set NEXT_DIST_DIR=.next-bob when starting
  // the second instance.
  distDir: process.env.NEXT_DIST_DIR ?? ".next",
  transpilePackages: ["@excalidraw/excalidraw"],
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080/api",
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8080",
    // No fallback in production — the guard above already guarantees it's
    // unset there (or the build already failed); `next dev` keeps the
    // "alice" convenience default so local multi-actor testing still works
    // with zero setup.
    NEXT_PUBLIC_ACTOR_ID: isProd ? process.env.NEXT_PUBLIC_ACTOR_ID : (process.env.NEXT_PUBLIC_ACTOR_ID ?? "alice"),
  },
};

export default withBundleAnalyzer(nextConfig);
