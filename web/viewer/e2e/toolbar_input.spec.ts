import { PINNED } from "./chrome_pinned";
import { test, expect, type Page } from "@playwright/test";
// The app menu, and the viewer's View panel ("More" was folded into it in menu redesign wave 7b).
const MENUS: [string, (page: Page) => ReturnType<Page["getByTestId"]>][] = [
  ["DeskRally", (page) => page.getByRole("button", { name: "DeskRally", exact: true })],
  ["View", (page) => page.getByTestId("viewer-view-menu")],
];
for (const [menu, trigger] of MENUS) {
  test(`${menu} releases held remote keys and keeps menu typing local`, async ({ page }) => {
    await page.goto('/e2e/viewer_chrome.html?docked');
    await expect(page.locator('.app__toolbar-host .viewer__statusbar')).toBeVisible();
    const keys = () => page.evaluate(() => (window as unknown as { __inputLog: { json: { t: string; c: { code: number; down: boolean } } }[] }).__inputLog.filter(e => e.json?.t === 'Key').map(e => e.json.c));
    await page.keyboard.down('ControlLeft');
    await expect.poll(keys).toContainEqual({ code: 162, down: true });
    await trigger(page).click();
    await expect.poll(keys).toContainEqual({ code: 162, down: false });
    const count = (await keys()).length;
    await page.keyboard.press('a');
    await page.keyboard.up('ControlLeft');
    expect((await keys()).length).toBe(count);
    await page.keyboard.press('Escape');
    await expect(trigger(page)).toHaveAttribute('aria-expanded', 'false');
    await page.keyboard.press('b');
    await expect.poll(keys).toContainEqual({ code: 66, down: true });
    await expect.poll(keys).toContainEqual({ code: 66, down: false });
  });
}
test('recording and disconnect remain visible on a narrow touch screen', async ({ browser }) => {
  const context = await browser.newContext({ ...PINNED, viewport: { width: 390, height: 844 }, hasTouch: true, isMobile: true });
  const page = await context.newPage();
  await page.goto('/e2e/viewer_chrome.html?docked');
  for (const selector of ['.viewer__recording-indicator', '.app__toolbar-end .viewer__disconnect']) {
    await expect(page.locator(selector)).toBeVisible();
    const box = await page.locator(selector).boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(390);
  }
  const trigger = await page.getByRole('button', { name: 'DeskRally', exact: true }).boundingBox();
  expect(trigger!.width).toBeGreaterThanOrEqual(40);
  expect(trigger!.height).toBeGreaterThanOrEqual(40);
  expect((await page.locator('.app__topbar').boundingBox())!.height).toBe(46);
  await context.close();
});

for (const kind of ['view', 'input', 'tools']) {
  test(`docked ${kind} panel stays on screen`, async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 700 });
    await page.goto('/e2e/viewer_chrome.html?docked');
    await page.getByTestId(`viewer-${kind}-menu`).click();
    const panel = page.locator(".viewer__menupanel");
    await expect(panel).toBeVisible();
    const box = await panel.boundingBox();
    expect(box!.x).toBeGreaterThanOrEqual(0);
    expect(box!.y).toBeGreaterThanOrEqual(0);
    expect(box!.x + box!.width).toBeLessThanOrEqual(1024);
    expect(box!.y + box!.height).toBeLessThanOrEqual(700);
  });
}
