/**
 * Reports panel — overlapping requests, mocked-API browser regressions.
 *
 *   1. A delayed response for an OLDER audit filter cannot replace the rows/total of a newer filter, and the CSV
 *      export carries the newer filter's rows only.
 *   2. The same for the sessions-by-machine report and its date window.
 *   3. A delayed audit response that lands after the user switched report type is never shown under the new report.
 *   4. When the NEWER filter's request fails, the older filter's rows (even if they arrive afterwards) are
 *      neither shown nor exportable under the new controls; the failure is shown.
 *
 * Every /cp/ call is routed here, keyed by the action / since query parameters (not request counters, so React
 * StrictMode's replayed mount effect cannot skew it). Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

const act = (action: string, count: number) => ({ action, count });
const mach = (id: string, name: string, count: number) => ({
  machine_id: id,
  machine_name: name,
  count,
  total_seconds: 60,
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

const SINCE_OLDER = "2026-01-01T00:00";
const SINCE_NEWER = "2026-02-01T00:00";
const key = (local: string) => `${local}:00Z`;

interface Routes {
  /** GET /cp/audit/summary handlers keyed by the `action` query parameter ("" = unfiltered). */
  audit: Record<string, Handler>;
  /** GET /cp/reports/sessions-by-machine handlers keyed by the `since` query parameter ("" = all-time). */
  machines?: Record<string, Handler>;
}

const baseAudit: Handler = async (route) => route.fulfill({ json: { summary: [act("base.action", 1)] } });
const baseMachines: Handler = async (route) =>
  route.fulfill({ json: { sessions_by_machine: [mach("m-base", "base-machine", 1)] } });

async function mount(page: Page, routes: Routes) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  // Network isolation: the test may only talk to a loopback origin.
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const get = route.request().method() === "GET";
    if (url.origin !== baseUrl.origin) {
      await route.abort(); // anything outside the approved local origin
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/audit/summary" && get) {
      const handler = routes.audit[url.searchParams.get("action") ?? ""];
      if (handler) await handler(route);
      else await route.fulfill({ json: { summary: [] } });
    } else if (url.pathname === "/cp/reports/sessions-by-machine" && get) {
      const handler = routes.machines?.[url.searchParams.get("since") ?? ""];
      if (handler) await handler(route);
      else await route.fulfill({ json: { sessions_by_machine: [] } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Reports", exact: true })).click();
  await expect(page.locator("[data-testid=reports] table tbody")).toContainText("base.action", { timeout: 15_000 });
}

async function applyAction(page: Page, action: string) {
  await page.getByTestId("report-action").fill(action);
  await page.getByTestId("report-apply").click();
}

async function selectMachines(page: Page) {
  await page.getByTestId("report-type").selectOption("sessions");
}

async function applySince(page: Page, local: string) {
  await page.getByTestId("session-report-since").fill(local);
  await page.getByTestId("session-report-apply").click();
}

async function exportedCsv(page: Page): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("report-export").click()]);
  const stream = await download.createReadStream();
  let text = "";
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

test("a delayed older audit filter response cannot replace or be exported as the newer filter's rows", async ({ page }) => {
  const older = held({ summary: [act("older.action", 7)] });
  await mount(page, {
    audit: {
      "": baseAudit,
      older: older.handler,
      newer: async (route) => route.fulfill({ json: { summary: [act("newer.action", 2)] } }),
    },
  });
  const tbody = page.locator("[data-testid=reports] table tbody");

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  // Apply is disabled while busy; Clear stays enabled and supersedes the held request.
  await page.getByTestId("report-clear").click();
  await expect(tbody).toContainText("base.action");
  await expect(page.getByTestId("report-apply")).toBeEnabled();
  await applyAction(page, "newer");
  await expect(tbody).toContainText("newer.action");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 2");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("newer.action");
  await expect(tbody).not.toContainText("older.action");
  await expect(tbody).not.toContainText("base.action");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 2");

  const csv = await exportedCsv(page);
  expect(csv).toContain("newer.action");
  expect(csv).not.toContain("older.action");
  expect(csv).not.toContain("base.action");
});

test("a delayed older sessions window response cannot replace or be exported as the newer window's rows", async ({ page }) => {
  const older = held({ sessions_by_machine: [mach("m-old", "older-machine", 9)] });
  await mount(page, {
    audit: { "": baseAudit },
    machines: {
      "": baseMachines,
      [key(SINCE_OLDER)]: older.handler,
      [key(SINCE_NEWER)]: async (route) =>
        route.fulfill({ json: { sessions_by_machine: [mach("m-new", "newer-machine", 4)] } }),
    },
  });
  const tbody = page.locator("[data-testid=reports] table tbody");
  await selectMachines(page);
  await expect(tbody).toContainText("base-machine");

  await applySince(page, SINCE_OLDER);
  await expect.poll(older.arrived).toBe(true);
  await page.getByTestId("session-report-clear").click();
  await expect(tbody).toContainText("base-machine");
  await expect(page.getByTestId("session-report-apply")).toBeEnabled();
  await applySince(page, SINCE_NEWER);
  await expect(tbody).toContainText("newer-machine");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 4");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("newer-machine");
  await expect(tbody).not.toContainText("older-machine");
  await expect(tbody).not.toContainText("base-machine");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 4");

  const csv = await exportedCsv(page);
  expect(csv).toContain("newer-machine");
  expect(csv).not.toContain("older-machine");
  expect(csv).not.toContain("base-machine");
});

test("a delayed audit response landing after a report-type switch is never shown as the new report", async ({ page }) => {
  const older = held({ summary: [act("older.action", 7)] });
  await mount(page, {
    audit: { "": baseAudit, older: older.handler },
    machines: { "": baseMachines },
  });
  const tbody = page.locator("[data-testid=reports] table tbody");

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  await selectMachines(page);
  await expect(tbody).toContainText("base-machine");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("base-machine");
  await expect(tbody).not.toContainText("older.action");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 1");
  // The newest request finished, so busy was cleared by it and export is the sessions report only.
  await expect(page.getByTestId("report-export")).toBeEnabled();
  const csv = await exportedCsv(page);
  expect(csv).toContain("base-machine");
  expect(csv).not.toContain("older.action");
});

test("when the newer filter fails, older rows are neither shown nor exportable under the new controls", async ({ page }) => {
  const older = held({ summary: [act("older.action", 7)] });
  await mount(page, {
    audit: {
      "": baseAudit,
      older: older.handler,
      broken: async (route) => route.fulfill({ status: 500, json: { error: "boom" } }),
    },
  });
  const tbody = page.locator("[data-testid=reports] table tbody");

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  await page.getByTestId("report-clear").click();
  await expect(tbody).toContainText("base.action");
  await expect(page.getByTestId("report-apply")).toBeEnabled();
  await applyAction(page, "broken");
  await expect(page.getByTestId("report-error")).toBeVisible();
  // The previous (base) rows are not presented under the new, failed filter.
  await expect(tbody).not.toContainText("base.action");
  await expect(page.getByTestId("report-export")).toBeDisabled();

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).not.toContainText("older.action");
  await expect(page.getByTestId("report-error")).toBeVisible();
  await expect(page.getByTestId("reports-empty")).toContainText("could not be loaded");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 0");
  await expect(page.getByTestId("report-export")).toBeDisabled();
});

test("a superseded older completion cannot clear busy or enable export while the newest request is pending", async ({ page }) => {
  const older = held({ summary: [act("older.action", 7)] });
  const newer = held({ summary: [act("newer.action", 2)] });
  await mount(page, { audit: { "": baseAudit, older: older.handler, newer: newer.handler } });
  const tbody = page.locator("[data-testid=reports] table tbody");

  await applyAction(page, "older");
  await expect.poll(older.arrived).toBe(true);
  await page.getByTestId("report-clear").click();
  await expect(tbody).toContainText("base.action");
  await expect(page.getByTestId("report-apply")).toBeEnabled();
  await applyAction(page, "newer");
  await expect.poll(newer.arrived).toBe(true);
  await expect(page.getByTestId("report-export")).toBeDisabled();

  // The older response lands FIRST while the newest is still pending.
  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).not.toContainText("older.action");
  await expect(tbody).not.toContainText("base.action");
  await expect(page.getByTestId("report-apply")).toBeDisabled();
  await expect(page.getByTestId("report-export")).toBeDisabled();
  await expect(page.getByTestId("report-total")).toHaveText("Total: 0");

  newer.release();
  await expect(tbody).toContainText("newer.action");
  await expect(page.getByTestId("report-total")).toHaveText("Total: 2");
  await expect(page.getByTestId("report-export")).toBeEnabled();
  const csv = await exportedCsv(page);
  expect(csv).toContain("newer.action");
  expect(csv).not.toContain("older.action");
  expect(csv).not.toContain("base.action");
});

test("a failed refresh of the same query keeps its rows labelled stale and not exportable", async ({ page }) => {
  // StrictMode replays the mount effect: succeed until mount() has seen the rows, then switch to failure.
  let failing = false;
  await mount(page, {
    audit: {
      "": async (route) => {
        if (failing) await route.fulfill({ status: 500, json: { error: "boom" } });
        else await baseAudit(route);
      },
    },
  });
  const tbody = page.locator("[data-testid=reports] table tbody");
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  failing = true;

  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("report-error")).toBeVisible();
  await expect(page.getByTestId("report-stale")).toBeVisible();
  await expect(tbody).toContainText("base.action");
  await expect(page.getByTestId("report-export")).toBeDisabled();
});
