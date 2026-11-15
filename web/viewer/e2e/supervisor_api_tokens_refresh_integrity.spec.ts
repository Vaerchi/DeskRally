/**
 * API tokens panel — overlapping listings, mocked-API browser regressions.
 *
 *   1. A slow OLDER listing (taken before a revoke) landing after the newer post-revoke re-list cannot
 *      make the revoked token reappear as "active".
 *   2. Busy ("Loading…") stays on while the NEWEST listing is pending even after an older one finishes,
 *      and clears only when the newest listing completes.
 *   3. When the NEWER re-list fails, the older listing (arriving afterwards) is not applied: the failure
 *      stays shown and the prior rows are kept.
 *
 * The panel has no Refresh control, so the older listing is the re-list that follows minting a token
 * (it observes the pre-revoke state); the newer one follows revoking the seeded "legacy" token.
 *
 * Every /cp/ call is routed here. The api-tokens handler is keyed by BEHAVIOR (which gates are armed + the
 * server-side state the request observed), never by GET counters, so React StrictMode's replayed mount
 * effect cannot skew it. A released response is confirmed delivered to the browser, then the page is
 * flushed, before any stale-result assertion — no fixed sleeps. Loopback only. Named supervisor_* so the
 * mocked headless profile runs it.
 */

import { test, expect, type Page, type Request } from "@playwright/test";
import { consoleTab } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** A request held by the mock until released. */
class Hold {
  armed = false;
  arrived = false;
  request: Request | null = null;
  private resolve!: () => void;
  readonly gate = new Promise<void>((r) => (this.resolve = r));
  release() {
    this.resolve();
  }
}

async function mount(page: Page) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const server = { legacyRevoked: false, minted: false };
  const older = new Hold(); // applies to listings that observe the PRE-revoke state
  const newer = new Hold(); // applies to listings that observe the POST-revoke state
  const failNewer = { armed: false };

  const rows = (legacyRevoked: boolean, minted: boolean) => [
    {
      id: "at-legacy",
      name: "legacy",
      capabilities: ["view_machines"],
      created_at: "2026-01-01T00:00:00Z",
      expires_at: null,
      revoked_at: legacyRevoked ? "2026-01-02T00:00:00Z" : null,
    },
    ...(minted
      ? [
          {
            id: "at-minted",
            name: "minted",
            capabilities: ["view_machines"],
            created_at: "2026-01-01T00:00:00Z",
            expires_at: null,
            revoked_at: null,
          },
        ]
      : []),
  ];

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/api-tokens" && method === "GET") {
      const observedRevoked = server.legacyRevoked; // the state this request sees, fixed at arrival
      const observedMinted = server.minted;
      const hold = observedRevoked ? newer : older;
      if (hold.armed) {
        hold.armed = false; // only the first matching request is held
        hold.request = route.request();
        hold.arrived = true;
        await hold.gate;
        await route.fulfill({ json: { api_tokens: rows(observedRevoked, observedMinted) } });
      } else if (observedRevoked && failNewer.armed) {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        await route.fulfill({ json: { api_tokens: rows(observedRevoked, observedMinted) } });
      }
    } else if (url.pathname === "/cp/api-tokens" && method === "POST") {
      server.minted = true;
      await route.fulfill({
        json: { token: "secret-value", api_token: rows(false, true)[1] },
      });
    } else if (url.pathname === "/cp/api-tokens/at-legacy" && method === "DELETE") {
      server.legacyRevoked = true;
      await route.fulfill({ json: {} });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // machines, sessions, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "API tokens", exact: true })).click();
  await expect(page.getByTestId("token-row-legacy")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("token-status-legacy")).toHaveText("active");
  return { older, newer, failNewer };
}

/** Release a held request, wait until the browser has received its response, then let React flush. */
async function releaseAndSettle(page: Page, hold: Hold) {
  expect(hold.request).not.toBeNull();
  hold.release();
  const response = await hold.request!.response();
  expect(response).not.toBeNull();
  await response!.finished();
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(resolve, 0))),
      ),
  );
}

/** Mint a token: its post-write re-list is the (older) listing. */
async function mint(page: Page) {
  await page.getByTestId("token-name").fill("minted");
  await page.getByTestId("token-cap-view_machines").check();
  await page.getByTestId("token-create").click();
}

test("a slow older listing cannot make a revoked token reappear as active", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;

  // Older listing: observes the pre-revoke state and is held.
  await mint(page);
  await expect.poll(() => m.older.arrived).toBe(true);

  // Revoke → post-revoke re-list observes "revoked" and completes while the older one is still held.
  await page.getByTestId("token-revoke-legacy").click();
  await expect(page.getByTestId("token-status-legacy")).toHaveText("revoked");

  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("token-status-legacy")).toHaveText("revoked");
  // The newer list (taken after the mint POST) already contains the minted token; it stays.
  await expect(page.getByTestId("token-row-minted")).toBeVisible();
  await expect(page.getByTestId("token-status-minted")).toHaveText("active");
  await expect(page.getByTestId("token-create")).toBeEnabled();
  await expect(page.getByTestId("tokens-empty")).toHaveCount(0);
});

test("an older listing finishing does not clear busy while the newest is still loading", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;
  m.newer.armed = true;
  // A search nothing matches turns the empty-state row into the only busy indicator.
  await page.getByTestId("api-tokens-search").fill("zzz-no-match");
  await expect(page.getByTestId("tokens-empty")).toHaveText("No tokens match this search.");

  await mint(page);
  await expect.poll(() => m.older.arrived).toBe(true);
  await page.getByTestId("api-tokens-search").fill("");
  await page.getByTestId("token-revoke-legacy").click();
  await expect.poll(() => m.newer.arrived).toBe(true);
  await page.getByTestId("api-tokens-search").fill("zzz-no-match");
  await expect(page.getByTestId("tokens-empty")).toHaveText("Loading…");

  // The older one lands first: it must neither apply its rows nor clear busy.
  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("tokens-empty")).toHaveText("Loading…");

  // The newest lands: its rows apply and busy clears.
  await releaseAndSettle(page, m.newer);
  await expect(page.getByTestId("tokens-empty")).toHaveText("No tokens match this search.");
  await page.getByTestId("api-tokens-search").fill("");
  await expect(page.getByTestId("token-status-legacy")).toHaveText("revoked");
  await expect(page.getByTestId("token-error")).toHaveCount(0);
});

test("when the newer re-list fails, the older listing is not applied and the failure stays shown", async ({
  page,
}) => {
  const m = await mount(page);
  m.older.armed = true;
  m.failNewer.armed = true;

  await mint(page);
  await expect.poll(() => m.older.arrived).toBe(true);

  // Newer re-list (post-revoke) fails; the prior rows are kept.
  await page.getByTestId("token-revoke-legacy").click();
  await expect(page.getByTestId("token-error")).toBeVisible();
  await expect(page.getByTestId("token-row-legacy")).toBeVisible();

  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("token-error")).toBeVisible();
  await expect(page.getByTestId("token-row-legacy")).toBeVisible();
  await expect(page.getByTestId("token-row-minted")).toHaveCount(0);
});
