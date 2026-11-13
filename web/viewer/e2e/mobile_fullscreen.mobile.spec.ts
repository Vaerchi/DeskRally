/**
 * Full screen on a phone (Ed, 11-06): the inline toolbar and special-key strip are replaced by ONE
 * compact floating bar with the monitor buttons, a Trackpad toggle, a Keyboard toggle and Exit.
 * Runs the real Viewer (e2e/trackpad.html, two monitors via `?monitors`) under the mobile-phone and
 * mobile-foldable projects; the decision rule itself is unit-tested in src/lib/mobile_fullscreen.test.ts.
 *
 * Full screen is entered through the product's own Full screen button (a real tap, so the browser
 * grants requestFullscreen); nothing here fakes `isFullscreen`.
 */
import { test, expect, type Page } from "@playwright/test";

const URL_ = "/e2e/trackpad.html?monitors";

async function ready(page: Page) {
  await page.goto(URL_);
  await expect.poll(() => page.locator("video").first().evaluate((v: HTMLVideoElement) => v.videoWidth)).toBe(400);
}
async function enterFullscreen(page: Page) {
  // Full screen is in the View panel (menu redesign wave 7b; it was under "More").
  if ((await page.getByTestId("viewer-view-menu").getAttribute("aria-expanded")) !== "true") await page.getByTestId("viewer-view-menu").tap();
  await page.getByTestId("viewer-fullscreen").tap();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.className ?? "")).toContain("viewer");
  await expect(page.getByTestId("viewer-mfs-bar")).toBeVisible();
}

test("normal toolbar before full screen, no compact bar", async ({ page }) => {
  await ready(page);
  await expect(page.getByTestId("viewer-view-menu")).toBeVisible();
  await expect(page.getByTestId("viewer-mfs-bar")).toHaveCount(0);
});

test("full screen shows only the compact bar; exit brings the toolbar back", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  for (const id of ["viewer-view-menu", "viewer-input-menu", "viewer-tools-menu", "viewer-fullscreen", "viewer-special-keys"]) {
    await expect(page.getByTestId(id)).toBeHidden();
  }
  const bar = page.getByTestId("viewer-mfs-bar");
  await expect(page.getByTestId("viewer-mfs-status")).toBeVisible();
  await expect(page.getByTestId("viewer-mfs-trackpad")).toBeVisible();
  await expect(page.getByTestId("viewer-mfs-keyboard")).toBeVisible();
  // Touch targets, and no horizontal scroll.
  for (const id of ["viewer-mfs-monitor-1", "viewer-mfs-monitor-2", "viewer-mfs-monitor-All", "viewer-mfs-trackpad", "viewer-mfs-keyboard", "viewer-mfs-exit"]) {
    const b = (await page.getByTestId(id).boundingBox())!;
    expect(b.height).toBeGreaterThanOrEqual(43.5);
    expect(b.width).toBeGreaterThanOrEqual(43.5);
  }
  const bb = (await bar.boundingBox())!;
  const vw = page.viewportSize()!.width;
  expect(bb.x).toBeGreaterThanOrEqual(0);
  expect(bb.x + bb.width).toBeLessThanOrEqual(vw);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);

  await page.getByTestId("viewer-mfs-exit").tap();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement == null)).toBe(true);
  await expect(page.getByTestId("viewer-mfs-bar")).toHaveCount(0);
  await expect(page.getByTestId("viewer-view-menu")).toBeVisible();
});

test("Pan on before full screen: the Pan badge turns it off and Keyboard comes back", async ({ page }) => {
  await ready(page);
  await page.getByTestId("viewer-view-menu").tap();
  await page.getByTestId("viewer-zoom-in").tap();
  await page.getByTestId("viewer-pan").tap(); // turning Pan on closes the panel
  await expect(page.getByTestId("viewer-pan-active")).toBeVisible();
  await enterFullscreen(page);
  await expect(page.getByTestId("viewer-mfs-keyboard")).toBeDisabled();
  const b = (await page.getByTestId("viewer-mfs-pan").boundingBox())!;
  expect(b.height).toBeGreaterThanOrEqual(43.5);
  await page.getByTestId("viewer-mfs-pan").tap();
  await expect(page.getByTestId("viewer-mfs-pan")).toHaveCount(0);
  await expect(page.getByTestId("viewer-mfs-keyboard")).toBeEnabled();
});

test("monitor buttons switch the monitor", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  await expect(page.getByTestId("viewer-mfs-monitor-1")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("viewer-mfs-monitor-2").tap();
  await expect(page.getByTestId("viewer-mfs-monitor-2")).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("viewer-mfs-monitor-1")).toHaveAttribute("aria-pressed", "false");
});

test("trackpad toggle turns the trackpad on and off, and the bar does not overlap its controls", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  const toggle = page.getByTestId("viewer-mfs-trackpad");
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await toggle.tap();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  await expect(page.getByTestId("trackpad-bar")).toBeVisible();
  const a = (await page.getByTestId("viewer-mfs-bar").boundingBox())!;
  const b = (await page.getByTestId("trackpad-bar").boundingBox())!;
  expect(a.y + a.height).toBeLessThanOrEqual(b.y);
  await toggle.tap();
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await expect(page.getByTestId("trackpad-cursor")).toHaveCount(0);
});

test("keyboard toggle opens the typing field, focused, inside full screen", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  await page.getByTestId("viewer-mfs-keyboard").tap();
  const field = page.getByTestId("viewer-typing-field");
  await expect(field).toBeVisible();
  await expect(field).toBeFocused();
  await expect(page.getByTestId("viewer-mfs-keyboard")).toHaveAttribute("aria-expanded", "true");
  // The bar's buttons do not steal focus from the field.
  await page.getByTestId("viewer-mfs-trackpad").tap();
  await expect(field).toBeFocused();
  await page.getByTestId("viewer-mfs-keyboard").tap();
  await expect(field).toHaveCount(0);
});

test("tapping the bar sends nothing to the remote, even with the trackpad on", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  await page.getByTestId("viewer-mfs-trackpad").tap();
  await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  await page.evaluate(() => ((window as unknown as { __logs: unknown[] }).__logs.length = 0));
  for (const id of ["viewer-mfs-monitor-2", "viewer-mfs-monitor-All", "viewer-mfs-keyboard", "viewer-mfs-keyboard", "viewer-mfs-trackpad", "viewer-mfs-trackpad"]) {
    await page.getByTestId(id).tap();
  }
  expect(await page.evaluate(() => (window as unknown as { __logs: unknown[] }).__logs.length)).toBe(0);
});

test("a pinned monitor disables the monitor buttons", async ({ page }) => {
  await page.goto(URL_ + "&pinned");
  await expect.poll(() => page.locator("video").first().evaluate((v: HTMLVideoElement) => v.videoWidth)).toBe(400);
  await enterFullscreen(page);
  for (const id of ["viewer-mfs-monitor-1", "viewer-mfs-monitor-2", "viewer-mfs-monitor-All"]) {
    await expect(page.getByTestId(id)).toBeDisabled();
  }
  await expect(page.getByTestId("viewer-mfs-trackpad")).toBeEnabled();
});

test("view-only shows why the keyboard is off", async ({ page }) => {
  await page.goto(URL_ + "&viewonly");
  await expect.poll(() => page.locator("video").first().evaluate((v: HTMLVideoElement) => v.videoWidth)).toBe(400);
  await enterFullscreen(page);
  await expect(page.getByTestId("viewer-mfs-keyboard")).toBeDisabled();
  await expect(page.getByTestId("viewer-mfs-inputoff")).toContainText("View only");
});

test("leaving full screen without the Exit button (system back / Esc) removes the bar", async ({ page }) => {
  await ready(page);
  await enterFullscreen(page);
  await page.evaluate(() => document.exitFullscreen());
  await expect.poll(() => page.evaluate(() => document.fullscreenElement == null)).toBe(true);
  await expect(page.getByTestId("viewer-mfs-bar")).toHaveCount(0);
  await expect(page.getByTestId("viewer-view-menu")).toBeVisible();
});
