/**
 * The access panel must never invent a fleet (docs/01 §6).
 *
 * WHAT THIS CATCHES, and why it needed a browser to catch it at all.
 *
 * `App.tsx` loads the real fleet with `listMachinesWithPresence()` and passes it to `<AccessPanel
 * machines={fleet} />`. On ANY failure — no control plane, a 401 because the technician is not
 * logged in, the box offline — the load's `catch` deliberately does nothing and `fleet` stays
 * `undefined`, because the manual connect-by-DeviceId form inside the panel has to keep working
 * without a control plane. That part is right.
 *
 * What was wrong is what `undefined` then meant. `AccessPanel`'s signature defaulted the prop to a
 * three-machine demo fleet — RECEPTION-01 / ACCT-WS-07 / CEO-LAPTOP under "Acme Corp" — so the
 * console rendered a plausible, fully-populated, fabricated fleet with a working-looking Connect
 * button on each row, and a header reading "2/3 online". Every one of those machines is a UUID that
 * exists nowhere; connecting to one is a session attempt against a device that has never existed.
 *
 * No test in the suite could have caught it:
 *   * the vitest suite runs `environment: "node"` over `*.test.ts` only — the panel components are
 *     never rendered, so a DEFAULT PARAMETER VALUE is not observable there at all;
 *   * every other e2e reaches the panel through the manual-connect form, which behaves identically
 *     whether the list beside it is real or invented.
 * So this spec asserts on what the operator's eyes actually receive, which is the only place the
 * defect existed.
 *
 * It needs no signaling server, no agent and no control plane — an ABSENT control plane is the
 * condition under test. It is also robust to one being up: an unauthenticated `GET /machines`
 * throws just the same, so `fleet` is `undefined` either way.
 */
import { test, expect } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

const APP_URL = "http://127.0.0.1:5173/";

/** The demo names that must never reach an operator's screen. */
const FABRICATED = ["RECEPTION-01", "ACCT-WS-07", "CEO-LAPTOP", "Acme Corp"];

test("with no control plane the panel says the fleet is unavailable instead of inventing one", async ({
  page,
}) => {
  await page.goto(APP_URL);

  // The panel itself must be present — the failure mode being guarded against is NOT "the panel
  // vanished", and an assertion that passed because nothing rendered would be worthless.
  const count = page.getByTestId("access-count");
  await expect(count).toBeVisible();

  // 1. The header states the truth: not loaded. Never a fabricated tally like "2/3 online".
  await expect(count).toHaveText(/unavailable|not loaded|sign in/i);

  // 2. An explicit notice, so the operator knows why the list is empty rather than concluding the
  //    fleet is empty.
  await expect(page.getByTestId("access-unloaded")).toBeVisible();

  // 3. NOT ONE fabricated machine anywhere in the document.
  const body = await page.locator("body").innerText();
  for (const name of FABRICATED) {
    expect(body, `fabricated fleet entry "${name}" is on screen`).not.toContain(name);
  }

  // 4. The escape hatch still works — this is the whole reason the load failure is swallowed, and a
  //    "fix" that removed the manual form would break the operator's only way in without a control plane. The form is
  //    folded behind one link (Ed, 2026-11-07), and the unloaded notice offers it too: the notice's own link opens it.
  await expect(page.getByTestId("manual-device")).toHaveCount(0);
  await page.getByTestId("access-unloaded").getByRole("button", { name: /device ID/i }).click();
  await expect(page.getByTestId("manual-device")).toBeVisible();
  await expect(page.getByTestId("signaling-url")).toBeVisible();
  const connect = page.getByTestId("manual-connect");
  await expect(connect).toBeDisabled(); // empty field is not a valid DeviceId
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("11111111-1111-4111-8111-111111111111");
  await expect(connect).toBeEnabled();
});
