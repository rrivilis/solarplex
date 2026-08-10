# Accessibility regression suite

`npm run test:a11y` — Playwright + `@axe-core/playwright`, checked against
WCAG 2.1 A/AA (`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`). Runs against a
real `next dev` server across Chromium, Firefox, and Edge.

## Scope

Covers the **pre-authentication surface only**: the signed-out landing
page, the public invite-preview page (`/invite/:id`, including its
not-found branch), `/cli-auth`'s error branch, and the generic 404 page.
That's everything reachable without a real OIDC login.

The authenticated app (session list, session detail and all its tabs,
settings, team, search, activity, inbox, agents) is **not** covered by
this automated suite — there's no way to complete a real OIDC round trip
unattended in CI today, and no seeded test actor / dev-only token-mint
path exists yet to fake one. That surface is covered by a manual
axe-core + keyboard/screen-reader audit instead (see the accessibility
audit report), not by this CI job.

## Extending to authenticated routes

Two ways to close this gap, neither built here because both are real
test-infrastructure decisions, not a one-line addition:

1. **`storageState` reuse** — do one real interactive login (locally, by
   hand), export Playwright's `storageState` (which captures the
   `sol-sp-token` localStorage entry), and have future authenticated
   tests load that state. Simple, but the exported token expires (7-day
   TTL — see `crates/server/src/auth.rs::oidc_callback`) and needs
   periodic manual refresh.
2. **A dev-only token-mint endpoint**, gated behind `cfg!(debug_assertions)`
   or an explicit `DEV_AUTH=1` env var, that mints a real `sp_token` for a
   seeded test actor without an IdP round trip. More upfront work, but
   gives CI a stable, unattended fixture instead of a token someone has
   to remember to refresh.

## Adding a new page/state to this suite

Add a `test(...)` block in `public-routes.spec.ts` (or a new spec file)
that navigates to the route, waits for its real content (not just
`networkidle` — assert on something meaningful, the way the existing
tests assert on the sign-in button or the error text) and calls
`expectNoViolations(page)`. Keep new authenticated-route tests in a
separate file once one of the two options above exists, so it's obvious
at a glance which tests need the extra fixture and which don't.
