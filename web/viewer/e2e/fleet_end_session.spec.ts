/**
 * Fleet "End session" button — behavioral Playwright acceptance tests.
 *
 * Proves that `handleEndFleetSession` and `AccessPanel.handleEndClick` together:
 *   1. Call the control-plane API on click.
 *   2. Disable the button while the call is in flight (double-click prevention).
 *   3. Bump `fleetEpoch` on success so the listing re-fetches and the session badge disappears.
 *   4. Catch the rejection on failure (403 or network abort) — re-enable the button, surface an
 *      inline error, leave the badge in place, and produce NO unhandled rejection.
 *   5. Clear the error on a subsequent retry.
 *
 * Mutation evidence: removing the `.catch(...)` handler from `handleEndClick` would cause the
 * button to remain disabled (`.finally` never runs on an unhandled rejection in void context)
 * and `end-error-{device}` would never appear — tests 4 and 5 both fail.
 * Removing `setFleetEpoch((n) => n + 1)` from `handleEndFleetSession` leaves the badge after
 * a successful end — test 1 fails.
 *
 * Follows the auth_expiry.spec.ts fixture pattern: routes all /cp/ API calls, no real agent required.
 */

import { test, expect, type Page } from "@playwright/test";
import { clickAccessAction, openAccessActions } from "./machine_actions";

const DEVICE = "11223344-5566-4778-8990-aabbccddeeff";
const SESSION_ID = "live-session-001";

const MACHINE = {
  id: "pk-1",
  tenant_id: "t-1",
  device_id: DEVICE,
  group_id: "g-1",
  group_name: "Office",
  name: "OFFICE-01",
  os: "Windows 11",
  online: true,
};

const LIVE_SESSION = {
  id: SESSION_ID,
  tenant_id: "t-1",
  machine_id: "pk-1",
  machine_device_id: DEVICE,
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
  const state = { endStatus: 200, sessionsAlive: true };

  await page.route("**/cp/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();

    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: [MACHINE], presence_known: true } });
    } else if (path === "/cp/sessions" && method === "GET") {
      const sessions = state.sessionsAlive ? [LIVE_SESSION] : [];
      await route.fulfill({ json: { sessions } });
    } else if (path.startsWith("/cp/sessions/") && path.endsWith("/end") && method === "POST") {
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

  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  // App loads; machine list shows with the live-session badge.
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toBeVisible();
  return state;
}

test("End session asks first, naming the machine; declining sends nothing", async ({ page }) => {
  await fixture(page);
  let ended = 0;
  await page.route("**/cp/sessions/*/end", (route) => { ended++; return route.fulfill({ json: {} }); });
  confirmAnswer = "dismiss";
  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  await expect.poll(() => confirms.length).toBe(1);
  expect(confirms[0]).toContain("End the session on OFFICE-01?");
  await page.waitForTimeout(300);
  expect(ended).toBe(0);
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toBeVisible();
});

test("End button calls the API; on success the session badge disappears", async ({ page }) => {
  await fixture(page);
  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  // fleetEpoch bumps on success → re-fetch → session gone → badge disappears.
  // Mutation: removing `setFleetEpoch((n) => n + 1)` from handleEndFleetSession keeps the badge.
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toHaveCount(0);
});

test("End button is disabled while the API call is in flight (double-click prevention)", async ({ page }) => {
  const state = await fixture(page);
  let release!: () => void;
  const gate = new Promise<void>((r) => { release = r; });
  let callStarted = false;
  await page.route("**/cp/sessions/*/end", async (route) => {
    callStarted = true;
    await gate;
    // Clear state so the fleet re-fetch returns no sessions after release.
    state.sessionsAlive = false;
    await route.fulfill({ json: { session: { ...LIVE_SESSION, ended_at: "2026-09-26T11:00:00Z" } } });
  });
  const endBtn = page.getByTestId(`end-session-${DEVICE}`);
  await openAccessActions(page, DEVICE);
  await endBtn.click();
  await expect.poll(() => callStarted).toBe(true);
  // Button disabled while in-flight — `endingSessionIds` contains the sessionId.
  await expect(endBtn).toBeDisabled();
  release();
  // On success the card disappears entirely (fleet re-fetch removes the row).
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toHaveCount(0);
});

test("403 re-enables the button, shows an inline error, and leaves the badge in place", async ({ page }) => {
  const state = await fixture(page);
  state.endStatus = 403;
  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  // Mutation: removing `.catch(...)` from handleEndClick means the rejection is unhandled,
  // `.finally()` never fires, and the button stays disabled — this assertion fails.
  await expect(page.getByTestId(`end-error-${DEVICE}`)).toBeVisible();
  await expect(page.getByTestId(`end-session-${DEVICE}`)).toBeEnabled();
  // Badge stays — session was not ended.
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toBeVisible();
});

test("network abort re-enables the button and shows an error (no unhandled rejection)", async ({ page }) => {
  await fixture(page);
  // Route abort simulates a network failure. The fetch() rejects; the rejection must be caught
  // by handleEndClick's .catch() so it never surfaces as an unhandled-rejection pageerror.
  const pageErrors: string[] = [];
  page.on("pageerror", (e) => pageErrors.push(String(e)));
  await page.route("**/cp/sessions/*/end", (route) => route.abort());

  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  // Error shown (proves .catch ran → rejection was handled, not unhandled).
  await expect(page.getByTestId(`end-error-${DEVICE}`)).toBeVisible();
  await expect(page.getByTestId(`end-session-${DEVICE}`)).toBeEnabled();
  // Allow any late-firing unhandledrejection events to settle.
  await page.waitForTimeout(300);
  // No page-level uncaught error matching the fetch failure should have fired.
  expect(pageErrors.filter((e) => /AbortError|Failed to fetch/i.test(e))).toHaveLength(0);
});

test("retrying End after a failure clears the previous error", async ({ page }) => {
  const state = await fixture(page);
  // First attempt fails.
  state.endStatus = 403;
  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  await expect(page.getByTestId(`end-error-${DEVICE}`)).toBeVisible();
  // Second attempt succeeds — error cleared before the call, badge gone after.
  state.endStatus = 200;
  await clickAccessAction(page, DEVICE, `end-session-${DEVICE}`);
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toHaveCount(0);
  await expect(page.getByTestId(`end-error-${DEVICE}`)).toHaveCount(0);
});
