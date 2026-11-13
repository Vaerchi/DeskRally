import { test, expect } from "@playwright/test";
import { openViewerPanel } from "./nav";

test.beforeEach(async ({ page }) => {
  await page.route('**/cp/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/cp/auth/session') return route.fulfill({ status: 204 });
    if (path === '/cp/machines') return route.fulfill({ json: { machines: [{ id: 'machine', tenant_id: 'tenant', device_id: '00112233-4455-6677-8899-aabbccddeeff', group_id: 'group', name: 'Office laptop', online: true }], presence_known: true } });
    if (path === '/cp/sessions' && route.request().method() === 'POST') return route.fulfill({ status: 403, json: { error: 'not authorized' } });
    return route.fulfill({ json: { sessions: [], groups: [], roles: [], users: [] } });
  });
  await page.goto('/console');
  await page.getByRole('button', { name: 'DeskRally', exact: true }).click();
  await page.getByRole('combobox', { name: 'Connect in', exact: true }).selectOption('browser');
  await page.keyboard.press('Escape');
  // Open the drawer only where the list IS a drawer; in two-pane widths ☰ would collapse the list.
  if (await page.locator('.app').getAttribute('data-pane-mode') === 'stacked') await page.getByTestId('app-nav-toggle').click();
  await page.locator('.access__connect').click();
  await expect(page.getByRole('combobox', { name: 'Session view' })).toBeVisible();
});

for (const width of [1440, 1024, 700, 390]) {
  test(`one row above the remote screen at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    const header = page.locator('.app__topbar');
    await expect(header.locator('.viewer__statusbar')).toHaveCount(1);
    // Menu redesign wave 10: the page bar is for outside a session; the session row gains nothing.
    await expect(page.getByTestId('area-bar')).toHaveCount(0);
    expect((await header.boundingBox())!.height).toBeLessThanOrEqual(46);
    await expect(page.locator('.app__session > .app__viewswitch')).toHaveCount(0);
    await expect(page.locator('.app__session > .conn-diag')).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.getByRole('button', { name: 'Session', exact: true }).click();
    await page.getByText('Connection details', { exact: true }).click();
    await expect(page.getByRole('region', { name: 'Connection diagnostic details' })).toContainText('State: Failed');
    const panel = await page.getByRole('dialog', { name: 'Session', exact: true }).boundingBox();
    expect(panel!.x).toBeGreaterThanOrEqual(0);
    expect(panel!.x + panel!.width).toBeLessThanOrEqual(width);
    await page.keyboard.press('Escape');
    const disconnect = await page.getByRole('button', { name: 'Disconnect', exact: true }).boundingBox();
    expect(disconnect!.x + disconnect!.width).toBeLessThanOrEqual(width);
    await expect(page.getByRole('button', { name: 'Session', exact: true })).toBeFocused();
    await page.screenshot({ path: `test-results/single-row-${width}.png` });
  });
}

test('session switching and fullscreen retain reachable controls', async ({ page }) => {
  await page.getByRole('combobox', { name: 'Session view' }).selectOption('files');
  await expect(page.locator('.app__toolbar-host .viewer__statusbar')).toHaveCount(0);
  await page.getByRole('combobox', { name: 'Session view' }).selectOption('screen');
  // Zoom and Full screen are in the View panel (menu redesign wave 7b folded "More" into it). The panel is
  // drawn only while open, so what must hold is that they are reachable before, in and after full screen.
  await openViewerPanel(page, 'view');
  await expect(page.getByTestId('viewer-zoom-readout')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByTestId('viewer-view-menu')).toHaveAttribute('aria-expanded', 'false');
  await openViewerPanel(page, 'view');
  await page.getByTestId('viewer-fullscreen').click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement?.className)).toBe('viewer');
  await expect(page.locator('.viewer .viewer__statusbar')).toHaveCount(1);
  await openViewerPanel(page, 'view');
  await expect(page.getByTestId('viewer-zoom-readout')).toBeVisible();
  await page.getByTestId('viewer-fullscreen').click();
  await expect(page.locator('.app__toolbar-host .viewer__statusbar')).toHaveCount(1);
  await openViewerPanel(page, 'view');
  await expect(page.getByTestId('viewer-zoom-readout')).toBeVisible();
});

test('connection details stay expanded after closing and reopening Session', async ({ page }) => {
  await page.getByRole('button', { name: 'Session', exact: true }).click();
  await page.getByText('Connection details', { exact: true }).click();
  const details = await page.locator('.conn-diag').elementHandle();
  await page.keyboard.press('Escape');
  expect(await details!.evaluate(el => el.isConnected)).toBe(true);
  await page.getByRole('button', { name: 'Session', exact: true }).click();
  await expect(page.locator('.conn-diag')).toHaveAttribute('open', '');
});

test('overflow menus close on outside focus and pop-out can return', async ({ page }) => {
  await page.getByRole('button', { name: 'DeskRally', exact: true }).click();
  await expect(page.getByRole('tab', { name: 'My account', exact: true })).toBeVisible();
  await page.getByRole('combobox', { name: 'Session view' }).focus();
  await expect(page.getByRole('dialog', { name: 'DeskRally', exact: true })).not.toBeVisible();
  await openViewerPanel(page, 'view');
  const popupPromise = page.waitForEvent('popup');
  await page.getByTestId('viewer-popout').click();
  const popup = await popupPromise;
  await expect(popup.locator('body')).toContainText('Return');
  await popup.close();
  await openViewerPanel(page, 'view'); // Pop out closed the panel on its way out
  await expect(page.getByTestId('viewer-popout')).toBeVisible();
});
