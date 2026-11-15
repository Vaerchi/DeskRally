/**
 * Menu redesign wave 7c: on a phone the session menus are bottom sheets, and an unavailable control says why on
 * screen (a tooltip never shows on a touch screen).
 *
 * The desktop case is the NEGATIVE CONTROL: at desktop width the same panel is a small box under its trigger, so
 * a sheet assertion that passed there would be measuring nothing.
 */
import { test, expect, type Page } from "@playwright/test";
import { PINNED } from "./chrome_pinned";
import { openViewerPanel } from "./nav";

const HARNESS = "http://127.0.0.1:5173/e2e/viewer_chrome.html";

async function panelAndViewer(page: Page) {
  return page.evaluate(() => {
    const v = document.querySelector(".viewer")!.getBoundingClientRect();
    const p = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
    return { v: { left: v.left, right: v.right, bottom: v.bottom, width: v.width }, p: { left: p.left, right: p.right, bottom: p.bottom, width: p.width } };
  });
}

test("on a phone the View panel is a full-width sheet at the bottom of the viewer", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();
  await openViewerPanel(page, "view");
  await expect(page.locator(".viewer__menupanel")).toBeVisible();
  const { v, p } = await panelAndViewer(page);
  expect(Math.abs(p.left - v.left)).toBeLessThanOrEqual(1);
  expect(Math.abs(p.right - v.right)).toBeLessThanOrEqual(1);
  expect(Math.abs(p.bottom - v.bottom)).toBeLessThanOrEqual(1);
});

test("at desktop width the View panel stays a box under its trigger (negative control)", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();
  await openViewerPanel(page, "view");
  await expect(page.locator(".viewer__menupanel")).toBeVisible();
  const { v, p } = await panelAndViewer(page);
  expect(p.width).toBeLessThan(v.width * 0.6);
  expect(v.bottom - p.bottom).toBeGreaterThan(20);
});

test("on a phone the app menu is a full-width sheet at the bottom of the window", async ({ browser }) => {
  const context = await browser.newContext({ ...PINNED, viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.goto(`${HARNESS}?docked`);
  await page.getByRole("button", { name: "DeskRally", exact: true }).click();
  const panel = page.getByRole("dialog", { name: "DeskRally", exact: true });
  await expect(panel).toBeVisible();
  const box = (await panel.boundingBox())!;
  const vp = page.viewportSize()!;
  expect(box.x).toBeLessThanOrEqual(1);
  expect(Math.abs(box.x + box.width - vp.width)).toBeLessThanOrEqual(1);
  expect(Math.abs(box.y + box.height - vp.height)).toBeLessThanOrEqual(1);
  await context.close();
});

test("a disabled Pan says why on screen, and the reason goes once Pan is possible", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();
  await openViewerPanel(page, "view");
  const pan = page.getByTestId("viewer-pan");
  const reason = page.getByTestId("viewer-pan-reason");
  // Premise: at Fit the whole desktop shows, so Pan is unavailable.
  await expect(pan).toBeDisabled();
  await expect(reason).toBeVisible();
  await expect(reason).toHaveText("Zoom in first: the whole screen is already showing.");
  // Tied to the control for assistive tech.
  const id = await reason.getAttribute("id");
  expect(id).toBeTruthy();
  await expect(pan).toHaveAttribute("aria-describedby", id!);
  // Zoomed in, Pan is available and the reason is gone.
  for (let i = 0; i < 3; i++) await page.getByTestId("viewer-zoom-in").click();
  await expect(pan).toBeEnabled();
  await expect(reason).toHaveCount(0);
  await expect(pan).not.toHaveAttribute("aria-describedby", /.+/);
});
