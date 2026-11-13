/**
 * Smart groups panel — overlapping member resolves, mocked-API browser regressions.
 *
 *   1. A slow members response for group A, landing after group B was resolved, cannot replace B's members.
 *   2. A resolve still in flight when its group is deleted cannot reopen the deleted group's members.
 *   3. When the NEWER resolve fails, the older group's members (arriving afterwards) are not shown and the
 *      newer failure stays visible.
 *
 * Every /cp/ call is routed here, keyed by the group id in the URL path (not request counters, so React
 * StrictMode's replayed mount effect cannot skew it). Loopback only. Named supervisor_* so the mocked
 * headless profile runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

type Handler = (route: Route) => Promise<void>;

const GROUP_A = { id: "grp-a", name: "Alpha", property_key: "site", property_value: "A" };
const GROUP_B = { id: "grp-b", name: "Bravo", property_key: "site", property_value: "B" };

const machine = (id: string, name: string) => ({
  id,
  tenant_id: "t-1",
  device_id: `dev-${id}`,
  group_id: "g-1",
  name,
});

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

async function mount(page: Page, resolveById: Record<string, Handler>, groups: { id: string }[] = [GROUP_A, GROUP_B]) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  const live = [...groups];
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const members = /^\/cp\/dynamic-groups\/([^/]+)\/machines$/.exec(url.pathname);
    const one = /^\/cp\/dynamic-groups\/([^/]+)$/.exec(url.pathname);
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/dynamic-groups" && method === "GET") {
      await route.fulfill({ json: { groups: live } });
    } else if (members && method === "GET") {
      const handler = resolveById[decodeURIComponent(members[1])];
      if (handler) await handler(route);
      else await route.fulfill({ json: { machines: [] } });
    } else if (one && method === "DELETE") {
      const i = live.findIndex((g) => g.id === decodeURIComponent(one[1]));
      if (i >= 0) live.splice(i, 1);
      await route.fulfill({ json: {} });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} }); // machines, sessions, users, agent version: best-effort loads
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Smart groups", exact: true })).click();
  await expect(page.getByTestId("group-row-Alpha")).toBeVisible({ timeout: 15_000 });
}

test("a slow older group's members cannot replace the newer group's members", async ({ page }) => {
  const a = held({ machines: [machine("a-1", "alpha-machine")] });
  await mount(page, {
    [GROUP_A.id]: a.handler,
    [GROUP_B.id]: async (route) => route.fulfill({ json: { machines: [machine("b-1", "bravo-machine")] } }),
  });
  const members = page.getByTestId("group-members");

  await page.getByTestId("group-resolve-Alpha").click();
  await expect.poll(a.arrived).toBe(true);
  await page.getByTestId("group-resolve-Bravo").click();
  await expect(members).toContainText("bravo-machine");

  a.release();
  await expect.poll(a.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(members).toContainText("bravo-machine");
  await expect(members).not.toContainText("alpha-machine");
  await expect(page.getByTestId("group-error")).toHaveCount(0);
});

test("a resolve in flight when its group is deleted never reopens the deleted group's members", async ({ page }) => {
  const a = held({ machines: [machine("a-1", "alpha-machine")] });
  await mount(page, { [GROUP_A.id]: a.handler });

  await page.getByTestId("group-resolve-Alpha").click();
  await expect.poll(a.arrived).toBe(true);
  await page.getByTestId("group-delete-Alpha").click();
  await expect(page.getByTestId("group-row-Alpha")).toHaveCount(0);
  await expect(page.getByTestId("group-row-Bravo")).toBeVisible();

  a.release();
  await expect.poll(a.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(page.getByTestId("group-members")).toHaveCount(0);
  await expect(page.getByTestId("group-row-Alpha")).toHaveCount(0);
});

test("when the newer resolve fails, the older group's members never appear and the failure stays shown", async ({ page }) => {
  const a = held({ machines: [machine("a-1", "alpha-machine")] });
  await mount(page, {
    [GROUP_A.id]: a.handler,
    [GROUP_B.id]: async (route) => route.fulfill({ status: 500, json: { error: "boom" } }),
  });

  await page.getByTestId("group-resolve-Alpha").click();
  await expect.poll(a.arrived).toBe(true);
  await page.getByTestId("group-resolve-Bravo").click();
  await expect(page.getByTestId("group-error")).toBeVisible();

  a.release();
  await expect.poll(a.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(page.getByTestId("group-members")).toHaveCount(0);
  await expect(page.getByTestId("group-error")).toBeVisible();
});
