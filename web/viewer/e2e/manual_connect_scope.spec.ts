import { test, expect } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

// The "Connect by device ID" form is folded behind one link (Ed, 2026-11-07), and the signaling URL typed in it applies to
// that form's Connect only. Before, every machine row's Connect, View only and new-tab link used the same field, so a value
// left in the now-hidden form silently redirected the whole list (Codex menu review). The row's new-tab link carries the
// signaling URL in its address, which makes the scope visible without a live session.
const DEVICE = "00112233-4455-6677-8899-aabbccddeeff";
const DEFAULT_LOCAL = "ws://127.0.0.1:8080/ws"; // DEV_SIGNALING_URL: the e2e page is served from 127.0.0.1

test("the device-ID form folds behind a link, and its signaling URL never redirects the machine rows", async ({ page }) => {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") {
      return route.fulfill({ json: { machines: [{ id: "m-1", device_id: DEVICE, name: "Office laptop", group_id: "g1", os: "windows", online: true }], presence_known: true } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto(test.info().project.use.baseURL!);

  const newTab = page.getByTestId(`new-tab-${DEVICE}`);
  await expect(newTab).toHaveCount(1); // in the row's "⋯" menu (menu redesign wave 8b); its href is what matters here
  // Folded: the form's fields are not on the page until the link is used.
  await expect(page.getByTestId("manual-device")).toHaveCount(0);
  await expect(page.getByTestId("manual-toggle")).toBeVisible();

  const before = await newTab.getAttribute("href");
  expect(before).toContain(encodeURIComponent(DEFAULT_LOCAL));

  // A different signaling URL in the form...
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill("ws://somewhere-else.invalid/ws");
  // ...changes nothing on the rows (the negative control is the old code, where this href changed).
  await expect(newTab).toHaveAttribute("href", before!);
  expect(await newTab.getAttribute("href")).not.toContain("somewhere-else.invalid");

  // Hide folds it again.
  await page.getByTestId("manual-close").click();
  await expect(page.getByTestId("manual-device")).toHaveCount(0);
});
