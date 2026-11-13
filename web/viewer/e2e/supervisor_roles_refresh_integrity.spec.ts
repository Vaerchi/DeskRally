/**
 * Roles panel — overlapping role-catalog listings, mocked-API browser regressions.
 *
 * The panel's mount effect runs twice under React StrictMode, so the first GET /roles is the OLDER request
 * and the second the NEWER one (the Refresh button is disabled while busy, so StrictMode is the natural way
 * to overlap two listings).
 *
 *   1. A slow OLDER listing landing after the newer one cannot replace the newer capability set, and busy
 *      clears once the newest listing completes.
 *   2. Busy ("Loading…") stays on while the NEWEST listing is pending even after an older one finishes,
 *      and clears only when the newest listing completes.
 *   3. A real Refresh click loads a different capability set (the mock catalog is mutable); the older held
 *      mount listing arriving afterwards cannot replace it.
 *   4. A failing Refresh shows the specific error, keeps the previously displayed rows and clears busy;
 *      the older success arriving afterwards neither clears the error nor replaces the rows.
 *
 * Every /cp/ call is routed here. The roles handler is keyed by BEHAVIOR (which hold is armed and not yet
 * taken, whether failure mode is on), never by GET counters. A released response is confirmed delivered to
 * the browser, then the page is flushed, before any stale-result assertion — no fixed sleeps. Loopback only.
 * Named supervisor_* so the mocked headless profile runs it.
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

const STALE_CATALOG = [{ role: "owner", capabilities: ["view_machines"] }];
const FRESH_CATALOG = [
  { role: "owner", capabilities: ["manage_tenant"] },
  { role: "readonly", capabilities: ["view_machines"] },
];
// What a later Refresh returns once the server-side catalog has changed.
const REFRESHED_CATALOG = [
  { role: "owner", capabilities: ["manage_roles", "manage_users"] },
  { role: "readonly", capabilities: ["view_machines"] },
];

/** Mutable server state: which catalog unheld listings return, and whether they fail. */
interface Server {
  catalog: unknown;
  fail: boolean;
}

async function mount(page: Page, arm: { older?: boolean; newer?: boolean; failNewest?: boolean }) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);

  const older = new Hold(); // the first listing: holds a STALE catalog
  const newer = new Hold(); // the second listing, when also held: holds the FRESH catalog
  older.armed = arm.older ?? false;
  newer.armed = arm.newer ?? false;
  const server: Server = { catalog: FRESH_CATALOG, fail: arm.failNewest ?? false };

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/roles" && method === "GET") {
      if (older.armed) {
        older.armed = false; // only the first listing is held
        older.request = route.request();
        older.arrived = true;
        await older.gate;
        await route.fulfill({ json: { roles: STALE_CATALOG } });
      } else if (newer.armed) {
        newer.armed = false; // only the next listing is held
        newer.request = route.request();
        newer.arrived = true;
        await newer.gate;
        await route.fulfill({ json: { roles: FRESH_CATALOG } });
      } else if (server.fail) {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        await route.fulfill({ json: { roles: server.catalog } });
      }
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // machines, sessions, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Roles", exact: true })).click();
  await expect(page.getByTestId("roles")).toBeVisible({ timeout: 15_000 });
  return { older, newer, server };
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

test("a slow older listing cannot overwrite the newer capability set", async ({ page }) => {
  const m = await mount(page, { older: true });
  await expect.poll(() => m.older.arrived).toBe(true);

  // The newer listing completes with the fresh catalog while the older one is still held.
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();

  // The older (stale) listing lands afterwards: it must not replace the fresh capabilities.
  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-caps-owner")).not.toContainText("view machines");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(page.getByTestId("roles-error")).toHaveCount(0);
  await expect(refreshBtn(page)).toBeEnabled();
});

test("an older listing finishing does not clear busy while the newest is still loading", async ({ page }) => {
  const m = await mount(page, { older: true, newer: true });
  await expect.poll(() => m.older.arrived).toBe(true);
  await expect.poll(() => m.newer.arrived).toBe(true);
  await expect(loadingBtn(page)).toBeDisabled();

  // The older one lands first: it must neither apply its rows nor clear busy.
  await releaseAndSettle(page, m.older);
  await expect(loadingBtn(page)).toBeDisabled();
  await expect(page.getByTestId("role-row-owner")).toHaveCount(0);
  await expect(page.getByTestId("roles-empty")).toBeVisible();

  // The newest lands: its rows apply and busy clears.
  await releaseAndSettle(page, m.newer);
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();
  await expect(page.getByTestId("roles-error")).toHaveCount(0);
});

test("a Refresh that loads a different catalog is not overwritten by the older held mount listing", async ({
  page,
}) => {
  const m = await mount(page, { older: true });
  await expect.poll(() => m.older.arrived).toBe(true);

  // The current mount listing completes while the older one is held.
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(refreshBtn(page)).toBeEnabled();

  // The server catalog changes; an explicit Refresh loads the different capability set.
  m.server.catalog = REFRESHED_CATALOG;
  await refreshBtn(page).click();
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage roles");
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage users");
  await expect(page.getByTestId("role-caps-owner")).not.toContainText("manage tenant");
  await expect(refreshBtn(page)).toBeEnabled();

  // The older held response now lands: it must not replace the refreshed capabilities.
  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage roles");
  await expect(page.getByTestId("role-caps-owner")).not.toContainText("view machines");
  await expect(page.getByTestId("role-caps-owner")).not.toContainText("manage tenant");
  await expect(page.getByTestId("roles-error")).toHaveCount(0);
  await expect(refreshBtn(page)).toBeEnabled();
});

test("a failing Refresh shows the error, keeps the prior rows, and the older listing is not applied", async ({
  page,
}) => {
  const m = await mount(page, { older: true });
  await expect.poll(() => m.older.arrived).toBe(true);

  // The mount listing succeeded with rows while the older one is held.
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();

  // The next Refresh fails: specific error shown, previous rows retained, busy cleared.
  m.server.fail = true;
  await refreshBtn(page).click();
  await expect(page.getByTestId("roles-error")).toContainText("could not list roles");
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(page.getByTestId("roles-empty")).toHaveCount(0);
  await expect(refreshBtn(page)).toBeEnabled();

  // The older success lands afterwards: neither the stale rows nor a cleared error may appear.
  await releaseAndSettle(page, m.older);
  await expect(page.getByTestId("roles-error")).toContainText("could not list roles");
  await expect(page.getByTestId("role-caps-owner")).toContainText("manage tenant");
  await expect(page.getByTestId("role-caps-owner")).not.toContainText("view machines");
  await expect(page.getByTestId("role-row-readonly")).toBeVisible();
  await expect(refreshBtn(page)).toBeEnabled();
});
