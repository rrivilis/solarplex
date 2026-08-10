import { defineConfig, devices } from "@playwright/test";

// Accessibility regression suite (see tests/a11y/). Runs against a real
// `next dev` server — no mocked backend — because a11y issues in this app
// live mostly in client-rendered, WS-driven UI that a static export or a
// component-only test runner wouldn't exercise faithfully.
//
// Scope note: only the pre-authentication surface is covered here (see
// tests/a11y/README.md). The authenticated app (session list, session
// detail, settings, ...) requires a real OIDC round trip this suite can't
// perform unattended — that surface gets its rigor from a manual
// axe-core + keyboard/AT audit instead, not from this CI job. Extending
// this suite to authenticated routes needs a seeded test actor + a way to
// mint a real sp_token without a live IdP (Playwright storageState reuse
// from a one-time manual login, or a dev-only token-mint endpoint) — real
// test-infrastructure work, deliberately not built speculatively here.
export default defineConfig({
  testDir: "./tests/a11y",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // 1 retry unconditionally, not just in CI: this sandbox showed the same
  // transient flake locally (Firefox specifically, likely resource
  // contention running 3 browser projects at once) — same test, same
  // code, passed clean on a bare rerun. Genuine a11y regressions are
  // deterministic; a flake that clears on retry isn't one.
  retries: 1,
  reporter: [["html", { open: "never" }], ["list"]],
  use: {
    baseURL: "http://localhost:3000",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: true,
    timeout: 60_000,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox",  use: { ...devices["Desktop Firefox"] } },
    { name: "msedge",   use: { ...devices["Desktop Edge"], channel: "msedge" } },
  ],
});
