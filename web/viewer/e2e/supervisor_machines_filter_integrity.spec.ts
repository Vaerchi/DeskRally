/**
 * Machines panel — overlapping listing requests, mocked-API browser regressions.
 *
 *   1. A delayed response for an OLDER property filter cannot replace the rows of the newer (cleared) listing.
 *   2. When the NEWER listing fails, the older filter's rows (even if they arrive afterwards) are neither shown
 *      nor is its failure/success state replaced; the newer failure stays visible.
 *   3. An older request finishing cannot clear the busy state while a newer one is still loading.
 *
 * Every /cp/ call is routed here, keyed by the property_key query parameter (not request counters, so React
 * StrictMode's replayed mount effect cannot skew it). The overlap is made with the Clear button, which stays
 * enabled while a filtered listing is loading. Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

const machine = (id: string, name: string) => ({
  id,
  tenant_id: "t-1",
  device_id: `dev-${id}`,
  group_id: "g-1",
  name,
});

type Handler = (route: Route) => Promise<void>;

function held(json: unknown) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let arrived = false;
  let answered = false;
  const handler: Handler = async (route) => {
    arrived = true;
    await gate;
    await route.fulfill({ json });
    answered = true;
  };
  return { handler, release: () => release(), arrived: () => arrived, answered: () => answered };
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const FILTER_OLDER = "older-site";

const listing = (...machines: ReturnType<typeof machine>[]) => ({ machines, presence_known: true });
const baseHandler: Handler = async (route) => route.fulfill({ json: listing(machine("b-1", "base-machine")) });

async function mount(page: Page, byKey: Record<string, Handler>, status?: Handler) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/machines" && route.request().method() === "GET") {
      const handler = byKey[url.searchParams.get("property_key") ?? ""];
      if (handler) await handler(route);
      else await route.fulfill({ json: listing() });
    } else if (status && /^\/cp\/machines\/[^/]+\/status$/.test(url.pathname) && route.request().method() === "POST") {
      await status(route);
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // sessions, groups, users, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.locator(".panel--machines table tbody")).toContainText("base-machine", { timeout: 15_000 });
}

async function applyFilter(page: Page, key: string) {
  await page.getByTestId("machine-filter-key").fill(key);
  await page.getByTestId("machine-filter-apply").click();
}

test("a delayed older filter response cannot replace the newer listing's rows", async ({ page }) => {
  const older = held(listing(machine("o-1", "older-machine")));
  await mount(page, { "": baseHandler, [FILTER_OLDER]: older.handler });
  const tbody = page.locator(".panel--machines table tbody");

  await applyFilter(page, FILTER_OLDER);
  await expect.poll(older.arrived).toBe(true);
  await page.getByTestId("machine-filter-clear").click();
  await expect(tbody).toContainText("base-machine");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("base-machine");
  await expect(tbody).not.toContainText("older-machine");
  await expect(page.getByTestId("machine-filter-active")).toHaveCount(0);
});

test("when the newer listing fails, the older filter's rows never appear and the failure stays shown", async ({ page }) => {
  // StrictMode replays the mount effect, so the initial request count is not fixed: the unfiltered listing
  // succeeds until mount() has observed the rows, and only then is the mock switched to failure.
  let failing = false;
  const older = held(listing(machine("o-1", "older-machine")));
  await mount(page, {
    "": async (route) => {
      if (failing) await route.fulfill({ status: 500, json: { error: "boom" } });
      else await baseHandler(route);
    },
    [FILTER_OLDER]: older.handler,
  });
  const tbody = page.locator(".panel--machines table tbody");

  await applyFilter(page, FILTER_OLDER);
  await expect.poll(older.arrived).toBe(true);
  failing = true;
  await page.getByTestId("machine-filter-clear").click();
  await expect(page.getByTestId("machines-error")).toBeVisible();

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).not.toContainText("older-machine");
  await expect(page.getByTestId("machines-error")).toBeVisible();
});

test("a held row mutation's re-list uses the filter applied NOW, not the one in force when it started", async ({ page }) => {
  const FILTER_FIRST = "first-site";
  const FILTER_SECOND = "second-site";
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let mutationArrived = false;
  let mutationAnswered = false;
  await mount(
    page,
    {
      "": baseHandler,
      [FILTER_FIRST]: async (route) => route.fulfill({ json: listing(machine("f-1", "first-machine")) }),
      [FILTER_SECOND]: async (route) => route.fulfill({ json: listing(machine("s-1", "second-machine")) }),
    },
    async (route) => {
      mutationArrived = true;
      await gate;
      await route.fulfill({ json: { machine: machine("f-1", "first-machine") } });
      mutationAnswered = true;
    },
  );
  const tbody = page.locator(".panel--machines table tbody");

  await applyFilter(page, FILTER_FIRST);
  await expect(tbody).toContainText("first-machine");
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByTestId("machine-status-select-f-1").selectOption("quarantined");
  await expect.poll(() => mutationArrived).toBe(true);

  // Change the filter while the mutation is still pending.
  await applyFilter(page, FILTER_SECOND);
  await expect(tbody).toContainText("second-machine");

  release();
  await expect.poll(() => mutationAnswered).toBe(true);
  await page.waitForTimeout(500);
  // The post-action re-list must have asked for the CURRENT filter, so the first filter's rows never return.
  await expect(tbody).toContainText("second-machine");
  await expect(tbody).not.toContainText("first-machine");
  await expect(page.getByTestId("machine-filter-active")).toContainText(FILTER_SECOND);

  await expect(page.getByTestId("machines-error")).toHaveCount(0);
});

test("an older request finishing does not clear busy while a newer one is still loading", async ({ page }) => {
  const older = held(listing(machine("o-1", "older-machine")));
  const newer = held(listing(machine("n-1", "newer-machine")));
  let newerPhase = false;
  await mount(page, {
    "": async (route) => {
      if (newerPhase) await newer.handler(route);
      else await baseHandler(route);
    },
    [FILTER_OLDER]: older.handler,
  });
  const tbody = page.locator(".panel--machines table tbody");
  const filterBtn = page.getByTestId("machine-filter-apply");

  await applyFilter(page, FILTER_OLDER);
  await expect.poll(older.arrived).toBe(true);
  newerPhase = true;
  await page.getByTestId("machine-filter-clear").click();
  await expect.poll(newer.arrived).toBe(true);

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  // The newer request is still in flight: busy holds, and the older rows are not shown.
  await expect(filterBtn).toBeDisabled();
  await expect(tbody).not.toContainText("older-machine");

  newer.release();
  await expect(tbody).toContainText("newer-machine");
  await expect(filterBtn).toBeEnabled();
  await expect(tbody).not.toContainText("older-machine");
});
