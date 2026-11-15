/**
 * Machine properties panel — overlapping per-machine listings, mocked-API browser regressions.
 *
 *   1. A slow listing for machine A that lands after the user selected machine B cannot replace B's
 *      property rows (and does not flash A's rows even transiently after release).
 *   2. When B's (newer) listing FAILS, the late A listing is still dropped: B's error stays shown and
 *      no A rows appear.
 *
 * Every /cp/ call is routed here. The properties handler is keyed by the machine id in the URL path
 * (/machines/{id}/properties), never by GET counters, so React StrictMode's replayed mount effect
 * cannot skew it. A released response is confirmed delivered to the browser, then the page is flushed,
 * before any stale-result assertion — no fixed sleeps. Loopback only. Named supervisor_* so the mocked
 * headless profile runs it.
 */

import { test, expect, type Page, type Request } from "@playwright/test";
import { consoleTab } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const MACHINE_A = "m-aaaa";
const MACHINE_B = "m-bbbb";

/** A request held by the mock until released. */
class Hold {
  armed = false;
  arrived = false;
  requests: Request[] = [];
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

  const holds = new Map<string, Hold>([
    [MACHINE_A, new Hold()],
    [MACHINE_B, new Hold()],
  ]);
  const fail = new Set<string>(); // machine ids whose listing answers 500
  const props: Record<string, { key: string; value: string }[]> = {
    [MACHINE_A]: [{ key: "owner-a", value: "Alice" }],
    [MACHINE_B]: [{ key: "site-b", value: "Branch" }],
  };

  const machine = (id: string, name: string) => ({
    id,
    tenant_id: "t-1",
    device_id: `dev-${id}`,
    group_id: "g-1",
    name,
  });

  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const propsMatch = /^\/cp\/machines\/([^/]+)\/properties$/.exec(url.pathname);
    const propWrite = /^\/cp\/machines\/([^/]+)\/properties\/([^/]+)$/.exec(url.pathname);
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/machines" && method === "GET") {
      await route.fulfill({
        json: { machines: [machine(MACHINE_A, "HOST-A"), machine(MACHINE_B, "HOST-B")] },
      });
    } else if (propsMatch && method === "GET") {
      const id = decodeURIComponent(propsMatch[1]);
      const hold = holds.get(id);
      if (hold?.armed) {
        // Every listing for this machine is held until released (StrictMode replays the mount fetch).
        // The body is snapshotted on arrival, so a late release delivers the OLD listing.
        const snapshot = (props[id] ?? []).map((p) => ({ ...p }));
        hold.requests.push(route.request());
        hold.arrived = true;
        await hold.gate;
        await route.fulfill({ json: { properties: snapshot } });
      } else if (fail.has(id)) {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        await route.fulfill({ json: { properties: props[id] ?? [] } });
      }
    } else if (propWrite && method === "PUT") {
      const id = decodeURIComponent(propWrite[1]);
      const key = decodeURIComponent(propWrite[2]);
      const { value } = route.request().postDataJSON() as { value: string };
      props[id] = [...(props[id] ?? []).filter((p) => p.key !== key), { key, value }];
      // Later listings (the write's re-list) are NEWER than anything still held: let them through.
      const hold = holds.get(id);
      if (hold) hold.armed = false;
      await route.fulfill({ json: { property: { key, value } } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // sessions, agent version, groups: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId(`machine-props-${MACHINE_A}`)).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId(`machine-props-${MACHINE_B}`)).toBeVisible();
  return { holds, fail };
}

/** Release a held request, wait until the browser has received its response, then let React flush. */
async function releaseAndSettle(page: Page, hold: Hold) {
  expect(hold.requests.length).toBeGreaterThan(0);
  hold.armed = false;
  hold.release();
  for (const req of hold.requests) {
    const response = await req.response();
    expect(response).not.toBeNull();
    await response!.finished();
  }
  await page.evaluate(
    () =>
      new Promise<void>((resolve) =>
        requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(resolve, 0))),
      ),
  );
}

test("a slow listing for machine A cannot replace machine B's properties", async ({ page }) => {
  const m = await mount(page);
  const a = m.holds.get(MACHINE_A)!;
  a.armed = true;

  // Select A: its listing is held. The panel is loading.
  await page.getByTestId(`machine-props-${MACHINE_A}`).click();
  await expect.poll(() => a.arrived).toBe(true);
  await expect(page.getByTestId("properties-empty")).toHaveText("Loading…");

  // Switch to B while A is still pending: B's rows load and busy clears.
  await page.getByTestId(`machine-props-${MACHINE_B}`).click();
  await expect(page.getByTestId("property-row-site-b")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toHaveCount(0);

  // A's response lands late: it must not touch B's panel.
  await releaseAndSettle(page, a);
  await expect(page.getByTestId("property-row-site-b")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toHaveCount(0);
  await expect(page.getByTestId("properties-error")).toHaveCount(0);
  await expect(page.getByTestId("machine-properties")).toContainText("HOST-B");
});

// MachinesPanel mounts the panel with key={machine.id}, so the A→B tests above remount rather than
// overlap. The two tests below overlap requests inside ONE panel instance, which is what fails
// against an unguarded refresh().
async function addProperty(page: Page, key: string, value: string) {
  await page.getByTestId("property-key").fill(key);
  await page.getByTestId("property-value").fill(value);
  await page.getByTestId("property-add").click();
}

test("a held initial listing cannot overwrite a newer add re-list in the same panel", async ({ page }) => {
  const m = await mount(page);
  const a = m.holds.get(MACHINE_A)!;
  a.armed = true;

  await page.getByTestId(`machine-props-${MACHINE_A}`).click();
  await expect.poll(() => a.arrived).toBe(true);
  await expect(page.getByTestId("properties-empty")).toHaveText("Loading…");

  // Add while the initial listing is still pending: its re-list is newer and lands first.
  await addProperty(page, "added-1", "X");
  await expect(page.getByTestId("property-row-added-1")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toBeVisible();
  await expect(page.getByTestId("property-key")).toHaveValue("");

  // The older listing (snapshot without added-1) arrives late and must be dropped.
  await releaseAndSettle(page, a);
  await expect(page.getByTestId("property-row-added-1")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toBeVisible();
  await expect(page.getByTestId("properties-error")).toHaveCount(0);
});

test("a newer re-list failure keeps its error and rows when an older listing lands late", async ({ page }) => {
  const m = await mount(page);
  const a = m.holds.get(MACHINE_A)!;
  a.armed = true;

  await page.getByTestId(`machine-props-${MACHINE_A}`).click();
  await expect.poll(() => a.arrived).toBe(true);

  // A first add succeeds (newer than the held listing), giving the panel two rows.
  await addProperty(page, "added-1", "X");
  await expect(page.getByTestId("property-row-added-1")).toBeVisible();

  // A second add's re-list fails: error shown, prior rows kept.
  m.fail.add(MACHINE_A);
  await addProperty(page, "added-2", "Y");
  await expect(page.getByTestId("properties-error")).toBeVisible();
  await expect(page.getByTestId("property-row-added-1")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toBeVisible();

  // The oldest listing lands now: neither its rows nor a cleared error may replace the newer outcome.
  await releaseAndSettle(page, a);
  await expect(page.getByTestId("properties-error")).toBeVisible();
  await expect(page.getByTestId("property-row-added-1")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toBeVisible();
});

test("when machine B's listing fails, a late machine A listing is not applied", async ({ page }) => {
  const m = await mount(page);
  const a = m.holds.get(MACHINE_A)!;
  a.armed = true;
  m.fail.add(MACHINE_B);

  await page.getByTestId(`machine-props-${MACHINE_A}`).click();
  await expect.poll(() => a.arrived).toBe(true);

  // B is the newest request and fails: error shown, no rows, no stuck "Loading…".
  await page.getByTestId(`machine-props-${MACHINE_B}`).click();
  await expect(page.getByTestId("properties-error")).toBeVisible();
  await expect(page.getByTestId("properties-empty")).toHaveText("No properties set.");

  await releaseAndSettle(page, a);
  await expect(page.getByTestId("properties-error")).toBeVisible();
  await expect(page.getByTestId("property-row-owner-a")).toHaveCount(0);
  await expect(page.getByTestId("properties-empty")).toHaveText("No properties set.");
});
