/**
 * Platform panel — overlapping tenant listings, mocked-API browser regressions.
 *
 *   1. A slow OLDER listing (taken before a tenant is created) landing after the newer post-create re-list
 *      cannot make the just-provisioned tenant vanish.
 *   2. Busy ("Loading…") stays on while the NEWEST listing is pending even after an older one finishes,
 *      and clears only when the newest listing completes.
 *   3. When the NEWER re-list fails, the older listing (arriving afterwards) is not applied: the failure
 *      stays shown, the prior rows are kept, and Refresh is enabled again.
 *
 * Every /cp/ call is routed here. The tenants handler is keyed by BEHAVIOR (which gates are armed + the
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

const BASE_TENANT = {
  id: "t-base",
  slug: "base",
  name: "Base Org",
  deployment_mode: "saas",
  created_at: "2026-01-01T00:00:00Z",
  user_count: 2,
  unleased_machines: false,
};
const NEW_TENANT = {
  id: "t-acme",
  slug: "acme",
  name: "Acme Corp",
  deployment_mode: "saas",
  created_at: "2026-10-12T00:00:00Z",
  user_count: 0,
  unleased_machines: false,
};

async function mount(page: Page) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const server = { created: false };
  const older = new Hold(); // applies to listings that observe the PRE-create state
  const newer = new Hold(); // applies to listings that observe the POST-create state
  const failNewer = { armed: false };

  const rows = (created: boolean) => (created ? [BASE_TENANT, NEW_TENANT] : [BASE_TENANT]);

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/platform/me") {
      await route.fulfill({ json: { operator: true, mfa_ok: true, mfa_fresh: true } });
    } else if (url.pathname === "/cp/platform/tenants" && method === "GET") {
      const observed = server.created; // the state this request sees, fixed at arrival
      const hold = observed ? newer : older;
      if (hold.armed) {
        hold.armed = false; // only the first matching request is held
        hold.request = route.request();
        hold.arrived = true;
        await hold.gate;
        await route.fulfill({ json: { tenants: rows(observed) } });
      } else if (observed && failNewer.armed) {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        await route.fulfill({ json: { tenants: rows(observed) } });
      }
    } else if (url.pathname === "/cp/platform/tenants" && method === "POST") {
      server.created = true;
      await route.fulfill({ status: 201, json: { tenant: NEW_TENANT } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // machines, sessions, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Platform", exact: true })).click();
  await expect(cell(page, "base")).toBeVisible({ timeout: 15_000 });
  // Initial (StrictMode-doubled) loads are done once the toolbar button is idle.
  await expect(refreshBtn(page)).toBeEnabled();
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

const refreshBtn = (page: Page) => page.getByRole("button", { name: "Refresh", exact: true });
const loadingBtn = (page: Page) => page.getByRole("button", { name: "Loading…", exact: true });
const cell = (page: Page, text: string) => page.getByRole("cell", { name: text, exact: true });

/** Provision the "acme" tenant through the create form. */
async function createAcme(page: Page) {
  await page.getByTestId("tenant-slug").fill("acme");
  await page.getByTestId("tenant-name").fill("Acme Corp");
  await page.getByRole("button", { name: "Create", exact: true }).click();
}

test("a slow older listing cannot hide a just-created tenant", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;

  // Older listing: observes the pre-create state and is held.
  await refreshBtn(page).click();
  await expect.poll(() => m.older.arrived).toBe(true);

  // Create → post-create re-list observes the new tenant and completes while the older one is still held.
  await createAcme(page);
  await expect(cell(page, "acme")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();

  await releaseAndSettle(page, m.older);
  await expect(cell(page, "acme")).toBeVisible();
  await expect(cell(page, "base")).toBeVisible();
  await expect(page.getByTestId("tenants-error")).toHaveCount(0);
  await expect(refreshBtn(page)).toBeEnabled();
});

test("an older listing finishing does not clear busy while the newest is still loading", async ({ page }) => {
  const m = await mount(page);
  m.older.armed = true;
  m.newer.armed = true;

  await refreshBtn(page).click();
  await expect.poll(() => m.older.arrived).toBe(true);

  // Create → the post-create re-list is held too, so two listings are in flight.
  await createAcme(page);
  await expect.poll(() => m.newer.arrived).toBe(true);
  await expect(loadingBtn(page)).toBeDisabled();

  // The older one lands first: it must neither apply its rows nor clear busy.
  await releaseAndSettle(page, m.older);
  await expect(loadingBtn(page)).toBeDisabled();
  await expect(cell(page, "acme")).toHaveCount(0);

  // The newest lands: its rows apply and busy clears.
  await releaseAndSettle(page, m.newer);
  await expect(cell(page, "acme")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();
  await expect(page.getByTestId("tenants-error")).toHaveCount(0);
});

test("when the newer re-list fails, the older listing is not applied and the failure stays shown", async ({
  page,
}) => {
  const m = await mount(page);
  m.older.armed = true;
  m.failNewer.armed = true;

  await refreshBtn(page).click();
  await expect.poll(() => m.older.arrived).toBe(true);

  // Newer re-list (post-create) fails.
  await createAcme(page);
  await expect(page.getByTestId("tenants-error")).toBeVisible();
  // Prior rows are kept (the newest failure does not blank the table), and busy cleared on the failure.
  await expect(cell(page, "base")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();

  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("tenants-error")).toBeVisible();
  await expect(cell(page, "base")).toBeVisible();
  await expect(cell(page, "acme")).toHaveCount(0);
  await expect(refreshBtn(page)).toBeEnabled();
});
