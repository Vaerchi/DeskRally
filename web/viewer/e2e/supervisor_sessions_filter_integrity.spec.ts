/**
 * Sessions panel — overlapping filter requests, mocked-API browser regressions.
 *
 *   1. A delayed response for an OLDER date filter cannot replace the rows of a newer filter, and the CSV
 *      export carries the newer filter's rows only.
 *   2. A failed refresh of the same query keeps its rows labelled stale and not exportable.
 *   3. When the NEWER filter's request fails, the older filter's rows (even if they arrive afterwards) are
 *      neither shown nor exportable under the new controls; the failure is shown.
 *
 * Every /cp/ call is routed here, keyed by the since query parameter (not request counters, so React
 * StrictMode's replayed mount effect cannot skew it). Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

const sess = (id: string, machine: string) => ({
  id,
  tenant_id: "t-1",
  machine_id: `m-${id}`,
  technician_id: "u-1",
  started_at: "2026-08-17T12:00:00Z",
  ended_at: "2026-08-17T13:00:00Z",
  consent_policy: "attended",
  granted_caps: [],
  machine_group_id: "g-1",
  machine_device_id: `dev-${id}`,
  machine_name: machine,
  machine_alias: "",
  note: "",
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

// Distinct filters: the handler key is the `since` value the panel sends (datetime-local read as UTC).
const SINCE_OLDER = "2026-01-01T00:00";
const SINCE_NEWER = "2026-02-01T00:00";
const SINCE_BROKEN = "2026-03-01T00:00";
const key = (local: string) => `${local}:00Z`;

async function mount(page: Page, bySince: Record<string, Handler>) {
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
    } else if (url.pathname === "/cp/sessions" && route.request().method() === "GET") {
      const handler = bySince[url.searchParams.get("since") ?? ""];
      if (handler) await handler(route);
      else await route.fulfill({ json: { sessions: [] } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue(); // the local app's own static assets
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Sessions" })).click();
  await expect(page.locator(".panel--sessions table tbody")).toContainText("base-machine", { timeout: 15_000 });
}

async function applySince(page: Page, local: string) {
  await page.getByTestId("sessions-since").fill(local);
  await page.getByTestId("sessions-apply").click();
}

async function exportedCsv(page: Page): Promise<string> {
  const [download] = await Promise.all([page.waitForEvent("download"), page.getByTestId("sessions-export").click()]);
  const stream = await download.createReadStream();
  let text = "";
  for await (const chunk of stream) text += chunk.toString();
  return text;
}

const baseHandler: Handler = async (route) => route.fulfill({ json: { sessions: [sess("b-1", "base-machine")] } });

test("a delayed older filter response cannot replace or be exported as the newer filter's rows", async ({ page }) => {
  const older = held({ sessions: [sess("o-1", "older-machine")] });
  await mount(page, {
    "": baseHandler,
    [key(SINCE_OLDER)]: older.handler,
    [key(SINCE_NEWER)]: async (route) => route.fulfill({ json: { sessions: [sess("n-1", "newer-machine")] } }),
  });

  await applySince(page, SINCE_OLDER);
  await expect.poll(older.arrived).toBe(true);
  await applySince(page, SINCE_NEWER);
  const tbody = page.locator(".panel--sessions table tbody");
  await expect(tbody).toContainText("newer-machine");

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).toContainText("newer-machine");
  await expect(tbody).not.toContainText("older-machine");
  await expect(tbody).not.toContainText("base-machine");

  const csv = await exportedCsv(page);
  expect(csv).toContain("newer-machine");
  expect(csv).not.toContain("older-machine");
  expect(csv).not.toContain("base-machine");
});

test("a failed refresh of the same query keeps its rows labelled stale and not exportable", async ({ page }) => {
  // StrictMode replays the mount effect, so the initial request count is not fixed: every request succeeds
  // until mount() has observed the rows, and only then is the mock switched to failure.
  let failing = false;
  await mount(page, {
    "": async (route) => {
      if (failing) await route.fulfill({ status: 500, json: { error: "boom" } });
      else await baseHandler(route);
    },
  });
  const tbody = page.locator(".panel--sessions table tbody");
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  failing = true;

  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("sessions-error")).toBeVisible();
  await expect(page.getByTestId("sessions-stale")).toBeVisible();
  await expect(tbody).toContainText("base-machine");
  await expect(page.getByTestId("sessions-export")).toBeDisabled();
});

test("starting a note edit after a failed refresh keeps the listing stale and not exportable", async ({ page }) => {
  let failing = false;
  await mount(page, {
    "": async (route) => {
      if (failing) await route.fulfill({ status: 500, json: { error: "boom" } });
      else await baseHandler(route);
    },
  });
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  failing = true;
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("sessions-stale")).toBeVisible();
  await expect(page.getByTestId("sessions-export")).toBeDisabled();

  // Starting an edit clears the action error, but no fresh listing was fetched.
  await page.getByTestId("session-note-edit-b-1").click();
  await expect(page.getByTestId("session-note-input-b-1")).toBeVisible();
  await expect(page.getByTestId("sessions-error")).toHaveCount(0);
  await expect(page.getByTestId("sessions-stale")).toBeVisible();
  await expect(page.getByTestId("sessions-export")).toBeDisabled();
});

test("a held retry cannot make a failed listing exportable before a successful reload", async ({ page }) => {
  let mode: "ok" | "fail" | "hold" = "ok";
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let heldArrived = false;
  await mount(page, {
    "": async (route) => {
      if (mode === "fail") await route.fulfill({ status: 500, json: { error: "boom" } });
      else if (mode === "hold") {
        heldArrived = true;
        await gate;
        await baseHandler(route);
      } else await baseHandler(route);
    },
  });
  const exportBtn = page.getByTestId("sessions-export");
  await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();
  mode = "fail";
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect(page.getByTestId("sessions-stale")).toBeVisible();
  await expect(exportBtn).toBeDisabled();

  // Retry is held in flight: the stale listing must still not be exportable.
  mode = "hold";
  await page.getByRole("button", { name: "Refresh" }).click();
  await expect.poll(() => heldArrived).toBe(true);
  await expect(exportBtn).toBeDisabled();

  // Only the successful reload re-enables export and clears the stale label.
  release();
  await expect(page.getByTestId("sessions-stale")).toHaveCount(0);
  await expect(exportBtn).toBeEnabled();
});

test("when the newer filter fails, older rows are neither shown nor exportable under the new controls", async ({ page }) => {
  const older = held({ sessions: [sess("o-1", "older-machine")] });
  await mount(page, {
    "": baseHandler,
    [key(SINCE_OLDER)]: older.handler,
    [key(SINCE_BROKEN)]: async (route) => route.fulfill({ status: 500, json: { error: "boom" } }),
  });
  const tbody = page.locator(".panel--sessions table tbody");

  await applySince(page, SINCE_OLDER);
  await expect.poll(older.arrived).toBe(true);
  await applySince(page, SINCE_BROKEN);
  await expect(page.getByTestId("sessions-error")).toBeVisible();
  // The previous filter's (base) rows are not presented under the new, failed filter.
  await expect(tbody).not.toContainText("base-machine");
  await expect(page.getByTestId("sessions-export")).toBeDisabled();

  older.release();
  await expect.poll(older.answered).toBe(true);
  await page.waitForTimeout(500);
  await expect(tbody).not.toContainText("older-machine");
  await expect(page.getByTestId("sessions-error")).toBeVisible();
  await expect(page.getByTestId("sessions-empty")).toContainText("could not be loaded");
  await expect(page.getByTestId("sessions-export")).toBeDisabled();
});
