/**
 * Audit panel — overlapping filter requests, mocked-API browser regressions.
 *
 *   1. A delayed response for an OLDER filter cannot replace the rows of a newer filter, and the CSV export
 *      carries the newer filter's rows only.
 *   2. When the NEWER filter's request fails, the older filter's rows (even if they arrive afterwards) are
 *      neither shown nor exportable under the new controls; the failure is shown.
 *
 * Every /cp/ call is routed here. Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

const ev = (id: string, action: string) => ({
  id,
  tenant_id: "t-1",
  occurred_at: "2026-08-17T12:00:00Z",
  action,
  actor_user_id: "u-1",
  target_kind: "machine",
  target_id: id,
  metadata: {},
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

async function mount(page: Page, byAction: Record<string, Handler>) {
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
    } else if (url.pathname === "/cp/audit" && route.request().method() === "GET") {
      const handler = byAction[url.searchParams.get("action") ?? ""];
      if (handler) await handler(route);
      else await route.fulfill({ json: { events: [] } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Audit" })).click();
  await expect(page.locator(".panel--audit table tbody")).toContainText("base.event", { timeout: 15_000 });
}

async function applyAction(page: Page, action: string) {
  await page.getByTestId("audit-filter-action").fill(action);
  await page.getByTestId("audit-filter-apply").click();
}

async function exportedCsv(page: Page): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("audit-export").click()]);
  const stream = await download.createReadStream();
  let text = "";
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

test("a delayed older filter response cannot replace or be exported as the newer filter's rows", async ({ page }) => {
  const older = held({ events: [ev("old-1", "older.event")] });
  await mount(page, {
    "": async (route) => route.fulfill({ json: { events: [ev("base-1", "base.event")] } }),
    older: older.handler,
    newer: async (route) => route.fulfill({ json: { events: [ev("new-1", "newer.event")] } }),
  });

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  await applyAction(page, "newer");
  const tbody = page.locator(".panel--audit table tbody");
  await expect(tbody).toContainText("newer.event");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("newer.event");
  await expect(tbody).not.toContainText("older.event");
  await expect(tbody).not.toContainText("base.event");

  const csv = await exportedCsv(page);
  expect(csv).toContain("newer.event");
  expect(csv).not.toContain("older.event");
  expect(csv).not.toContain("base.event");
});

test("a failed refresh of the same query keeps its rows labelled stale and not exportable", async ({ page }) => {
  // React StrictMode replays the mount effect, so the initial request count is not fixed: every request
  // succeeds until mount() has observed the rows, and only then is the mock switched to failure.
  let failing = false;
  await mount(page, {
    "": async (route) => {
      if (failing) await route.fulfill({ status: 500, json: { error: "boom" } });
      else await route.fulfill({ json: { events: [ev("base-1", "base.event")] } });
    },
  });
  const tbody = page.locator(".panel--audit table tbody");
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  failing = true;

  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("audit-error")).toBeVisible();
  await expect(page.getByTestId("audit-stale")).toBeVisible();
  await expect(tbody).toContainText("base.event");
  await expect(page.getByTestId("audit-export")).toBeDisabled();
});

test("when the newer filter fails, older rows are neither shown nor exportable under the new controls", async ({ page }) => {
  const older = held({ events: [ev("old-1", "older.event")] });
  await mount(page, {
    "": async (route) => route.fulfill({ json: { events: [ev("base-1", "base.event")] } }),
    older: older.handler,
    broken: async (route) => route.fulfill({ status: 500, json: { error: "boom" } }),
  });
  const tbody = page.locator(".panel--audit table tbody");

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  await applyAction(page, "broken");
  await expect(page.getByTestId("audit-error")).toBeVisible();
  // The previous filter's (base) rows are not presented under the new, failed filter.
  await expect(tbody).not.toContainText("base.event");
  await expect(page.getByTestId("audit-export")).toBeDisabled();

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).not.toContainText("older.event");
  await expect(page.getByTestId("audit-error")).toBeVisible();
  await expect(page.getByTestId("audit-empty")).toContainText("could not be loaded");
  await expect(page.getByTestId("audit-export")).toBeDisabled();
});
