/**
 * The machine list's rows in the 320px sidebar: a name that wraps must never be drawn under the
 * ACTIVE badge or the buttons.
 *
 * VM's screenshot (2026-10-19): "VM's Desktop" with a live session wrapped to "VM's" / "Desktop",
 * and the ACTIVE badge sat ON TOP of "Desktop". The badge, End, Connect, Observe and new-tab link
 * were separate non-shrinking row items, so in 320px they left the name column narrower than its
 * longest word, which then overflowed onto the badge. They are now one cluster that wraps below
 * the name instead.
 *
 * Mutation evidence: reverting `.access__machine` to `flex-wrap: nowrap` (or dropping the
 * `.access__actions` wrapper) makes the name overflow its box and intersect the badge, so both
 * geometry assertions fail.
 */

import { test, expect, type Locator, type Page } from "@playwright/test";
import { openAccessActions } from "./machine_actions";

const DEVICE = "2b948dba-5566-4778-8990-aabbccddeeff";
const MACHINE = {
  id: "pk-1", tenant_id: "t-1", device_id: DEVICE, group_id: "g-1", group_name: "Home Computers",
  name: "VM's Desktop", os: "Windows 11", online: true, multi_session_capable: true,
};
const LIVE_SESSION = {
  id: "live-1", tenant_id: "t-1", machine_id: "pk-1", machine_device_id: DEVICE,
  technician_id: "ed@example.test", started_at: "2026-10-19T10:00:00Z",
};

async function fixture(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") await route.fulfill({ status: 204 });
    else if (path === "/cp/machines") await route.fulfill({ json: { machines: [MACHINE], presence_known: true } });
    else if (path === "/cp/sessions") await route.fulfill({ json: { sessions: [LIVE_SESSION] } });
    else await route.fulfill({ json: {} });
  });
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await expect(page.getByTestId(`session-badge-${DEVICE}`)).toBeVisible();
}

type Box = { x: number; y: number; width: number; height: number };
const box = async (l: Locator): Promise<Box> => {
  const b = await l.boundingBox();
  if (!b) throw new Error("element has no box");
  return b;
};
const intersects = (a: Box, b: Box) =>
  a.x < b.x + b.width - 0.5 && b.x < a.x + a.width - 0.5 && a.y < b.y + b.height - 0.5 && b.y < a.y + a.height - 0.5;

test("a wrapping machine name never sits under the ACTIVE badge or the buttons", async ({ page }) => {
  await fixture(page);
  const name = page.locator(".access__name", { hasText: "VM's Desktop" });
  const row = page.locator(".access__machine").filter({ has: name });
  // Menu redesign wave 8b: the row shows the badge, Connect and "⋯"; End, View only and new tab are in the menu.
  const actions = [
    page.getByTestId(`session-badge-${DEVICE}`),
    page.getByTestId(`connect-${DEVICE}`),
    page.getByTestId(`access-actions-${DEVICE}`),
  ];
  await row.screenshot({ path: test.info().outputPath("access-row.png") });

  // The name's text fits its own box (no overflow onto neighbours)...
  const overflow = await name.evaluate((el) => el.scrollWidth - el.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  // ...and that box intersects none of the actions.
  const nameBox = await box(name);
  for (const a of actions) {
    await expect(a).toBeVisible();
    expect(intersects(nameBox, await box(a)), `name overlaps ${await a.getAttribute("data-testid")}`).toBe(false);
  }
  // Every action stays inside the row (nothing pushed out of the 320px sidebar).
  const rowBox = await box(row);
  for (const a of actions) {
    const b = await box(a);
    expect(b.x).toBeGreaterThanOrEqual(rowBox.x - 0.5);
    expect(b.x + b.width).toBeLessThanOrEqual(rowBox.x + rowBox.width + 0.5);
  }
});

test("the row's ⋯ menu offers View only, Open in new tab and End session, inside the window", async ({ page }) => {
  await fixture(page);
  const trigger = page.getByTestId(`access-actions-${DEVICE}`);
  await expect(trigger).toHaveAttribute("aria-label", "More actions for VM's Desktop");
  // Premise: closed, the actions are on the page (offered) but not shown.
  await expect(page.getByTestId(`end-session-${DEVICE}`)).toBeHidden();
  await openAccessActions(page, DEVICE);
  const items = [`observe-${DEVICE}`, `new-tab-${DEVICE}`, `end-session-${DEVICE}`].map((id) => page.getByTestId(id));
  const vp = page.viewportSize()!;
  for (const item of items) {
    await expect(item).toBeVisible();
    const b = await box(item);
    expect(b.x).toBeGreaterThanOrEqual(0);
    expect(b.x + b.width).toBeLessThanOrEqual(vp.width);
  }
  await expect(page.getByTestId(`end-session-${DEVICE}`)).toHaveText("End session");
  // Choosing an action closes the menu.
  await page.getByTestId(`observe-${DEVICE}`).click();
  await expect(trigger).toHaveAttribute("aria-expanded", "false");
});
