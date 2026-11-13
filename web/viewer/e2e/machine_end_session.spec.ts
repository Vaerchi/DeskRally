/**
 * MachinesPanel "End session" button — behavioral Playwright acceptance tests.
 *
 * Proves that `handleEndSession` in MachinesPanel:
 *   1. Shows a danger "End session" button only on rows that have an active session.
 *   2. Calls POST /sessions/{id}/end on click, then refreshes the machine + session lists via
 *      `refresh(applied)` — so the badge disappears on success.
 *   3. Disables ALL end-session buttons while the call is in flight (double-click prevention).
 *   4. On failure (403) re-enables the button, surfaces the shared `machines-error` banner, and
 *      leaves the badge in place (the session was not ended).
 *   5. Clears the error banner on a successful retry.
 *
 * Mutation evidence:
 *   - Removing the `endSessionPending !== null` early-return guard would still look correct here,
 *     but test 3 (disabled-while-in-flight) would fail if the button were re-enabled while the
 *     gate is open.
 *   - Replacing `refresh(applied)` with a no-op would leave the badge after a successful end —
 *     test 2 fails.
 *   - Swallowing the catch would leave the button disabled after a 403 and never show the error
 *     banner — tests 4 and 5 both fail.
 *
 * Follows the fleet_end_session.spec.ts mocked-API pattern: all /cp/ calls are routed by
 * Playwright, so no real control plane or agent is required.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { clickMachineAction, openMachineActions } from "./machine_actions";

const MACHINE_PK = "aaaaaaaa-1111-4111-8111-111111111111";
const DEVICE_ID = "bbbbbbbb-2222-4222-8222-222222222222";
const SESSION_ID = "cccccccc-3333-4333-8333-333333333333";

const MACHINE = {
  id: MACHINE_PK,
  tenant_id: "t-1",
  device_id: DEVICE_ID,
  group_id: "g-1",
  group_name: "Office",
  name: "END-BOX",
  os: "Windows 11",
  online: true,
};

const LIVE_SESSION = {
  id: SESSION_ID,
  tenant_id: "t-1",
  machine_id: MACHINE_PK,
  machine_device_id: DEVICE_ID,
  technician_id: "alice@example.test",
  started_at: "2026-09-26T10:00:00Z",
};

// Menu redesign wave 9: End session asks first (window.confirm naming the machine and who is disconnected).
// Every test answers it; `confirmAnswer` lets one test decline, and `confirms` records what was asked.
let confirmAnswer: "accept" | "dismiss" = "accept";
let confirms: string[] = [];
test.beforeEach(({ page }) => {
  confirmAnswer = "accept";
  confirms = [];
  page.on("dialog", (d) => { confirms.push(d.message()); void (confirmAnswer === "accept" ? d.accept() : d.dismiss()); });
});

async function fixture(page: Page) {
  const state = { endStatus: 200, sessionsAlive: true, endCalls: 0 };

  await page.route("**/cp/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();

    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (path === "/cp/machines" && method === "GET") {
      await route.fulfill({ json: { machines: [MACHINE], presence_known: true } });
    } else if (path === "/cp/sessions" && method === "GET") {
      const sessions = state.sessionsAlive ? [LIVE_SESSION] : [];
      await route.fulfill({ json: { sessions } });
    } else if (path.startsWith("/cp/sessions/") && path.endsWith("/end") && method === "POST") {
      state.endCalls++;
      if (state.endStatus === 200) {
        state.sessionsAlive = false;
        await route.fulfill({
          json: { session: { ...LIVE_SESSION, ended_at: "2026-09-26T11:00:00Z" } },
        });
      } else {
        await route.fulfill({ status: state.endStatus, json: { error: "Forbidden" } });
      }
    } else {
      await route.fulfill({ json: {} });
    }
  });

  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  await page.goto(BASE);
  // Navigate to the management-console Machines tab.
  await (await consoleTab(page, { name: "Machines" })).click();
  // Wait for the active-session badge to confirm the panel loaded and the session fetch resolved.
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toBeVisible({
    timeout: 10_000,
  });
  return state;
}

test("End session button appears on rows with an active session", async ({ page }) => {
  await fixture(page);
  await openMachineActions(page, MACHINE_PK);
  await expect(page.getByTestId(`machine-end-session-${MACHINE_PK}`)).toBeVisible();
});

test("End session asks first, naming the machine; declining sends nothing and leaves the session", async ({ page }) => {
  const state = await fixture(page);
  confirmAnswer = "dismiss";
  await clickMachineAction(page, MACHINE_PK, `machine-end-session-${MACHINE_PK}`);
  await expect.poll(() => confirms.length).toBe(1);
  expect(confirms[0]).toContain("End the session on END-BOX?");
  expect(confirms[0]).toContain("is disconnected at once");
  // Give a request the chance to be made, then prove none was.
  await page.waitForTimeout(300);
  expect(state.endCalls).toBe(0);
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toBeVisible();
});

test("End button calls the API; on success the badge and button disappear", async ({ page }) => {
  await fixture(page);
  await clickMachineAction(page, MACHINE_PK, `machine-end-session-${MACHINE_PK}`);
  // refresh() re-fetches machines + sessions; sessions now empty → badge and button gone.
  // Mutation: replacing refresh() with a no-op leaves the badge — this assertion fails.
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toHaveCount(0);
  await expect(page.getByTestId(`machine-end-session-${MACHINE_PK}`)).toHaveCount(0);
});

test("End button is disabled while the API call is in flight", async ({ page }) => {
  const state = await fixture(page);
  let release!: () => void;
  const gate = new Promise<void>((r) => {
    release = r;
  });
  let callStarted = false;
  await page.route("**/cp/sessions/*/end", async (route) => {
    callStarted = true;
    await gate;
    state.sessionsAlive = false;
    await route.fulfill({
      json: { session: { ...LIVE_SESSION, ended_at: "2026-09-26T11:00:00Z" } },
    });
  });
  const endBtn = page.getByTestId(`machine-end-session-${MACHINE_PK}`);
  await openMachineActions(page, MACHINE_PK);
  await endBtn.click();
  await expect.poll(() => callStarted).toBe(true);
  // Disabled while in-flight — `endSessionPending` is set.
  await expect(endBtn).toBeDisabled();
  release();
  // On success the badge disappears (session list re-fetched).
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toHaveCount(0);
});

test("403 re-enables the button, shows machines-error, and leaves the badge", async ({ page }) => {
  const state = await fixture(page);
  state.endStatus = 403;
  await clickMachineAction(page, MACHINE_PK, `machine-end-session-${MACHINE_PK}`);
  // machines-error banner shows the failure. Mutation: swallowing the catch keeps the button
  // disabled and never shows the banner — both assertions below would fail.
  await expect(page.getByTestId("machines-error")).toBeVisible();
  await expect(page.getByTestId(`machine-end-session-${MACHINE_PK}`)).toBeEnabled();
  // Badge stays — the session was not ended.
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toBeVisible();
});

test("retrying after a failure clears the error banner and succeeds", async ({ page }) => {
  const state = await fixture(page);
  // First attempt fails.
  state.endStatus = 403;
  await clickMachineAction(page, MACHINE_PK, `machine-end-session-${MACHINE_PK}`);
  await expect(page.getByTestId("machines-error")).toBeVisible();
  // Second attempt succeeds — error cleared before the call, badge gone after.
  state.endStatus = 200;
  await clickMachineAction(page, MACHINE_PK, `machine-end-session-${MACHINE_PK}`);
  await expect(page.getByTestId(`machine-session-active-${MACHINE_PK}`)).toHaveCount(0);
  await expect(page.getByTestId("machines-error")).toHaveCount(0);
});
