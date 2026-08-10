import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

// WCAG 2.1 A/AA is the baseline this app targets (see docs/architecture.md
// accessibility section); wcag22aa is included too so the automated pass
// covers what axe-core can check of 2.2's new criteria (e.g. target-size,
// focus-not-obscured) without waiting on a formal target bump. "best-
// practice" is excluded deliberately — those are Deque opinions, not WCAG
// requirements, and failing on them would conflate "not conformant" with
// "not to Deque's taste."
const WCAG_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];

async function expectNoViolations(page: import("@playwright/test").Page) {
  const results = await new AxeBuilder({ page }).withTags(WCAG_TAGS).analyze();
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([]);
}

test.describe("public / pre-authentication surface", () => {
  test("/ — signed-out landing", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
    // The card this button lives in has a 0.5s Framer Motion entrance
    // fade/slide (opacity 0→1). Scanning mid-transition was observed to
    // make axe on msedge misattribute the button's effective background —
    // reported #182131, which matches neither its rest-state bg-accent-blue
    // (#4f8ef7, 5.79:1 against its text) nor its hover state (composited
    // ~#4982e1, 4.92:1) — both comfortably pass AA. Real colors are fine;
    // this just waits the animation out so the scan reads the settled DOM.
    await page.waitForTimeout(600);
    await expectNoViolations(page);
  });

  test("/invite/:id — unknown invite (not-found branch)", async ({ page }) => {
    await page.goto("/invite/nonexistent-invite-id-000000000000");
    // Give the client fetch a beat to resolve to the not-found state.
    await page.waitForLoadState("networkidle");
    await expectNoViolations(page);
  });

  test("/cli-auth — missing port/nonce (error branch)", async ({ page }) => {
    await page.goto("/cli-auth");
    await expect(page.getByText(/missing or invalid/i)).toBeVisible();
    await expectNoViolations(page);
  });

  test("unknown route — not-found.tsx", async ({ page }) => {
    await page.goto("/this-route-does-not-exist");
    await expectNoViolations(page);
  });
});
