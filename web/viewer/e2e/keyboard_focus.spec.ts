import { test, expect } from '@playwright/test';
import { clickPopOut, openViewerPanel } from "./nav";

test('clicking the remote desktop restores typing after selecting a monitor', async ({ page }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  const monitor = page.locator('.viewer__monitor select');
  await monitor.selectOption('1');
  await monitor.focus();
  await expect(monitor).toBeFocused();
  const surface = page.getByTestId('viewer-surface');
  await surface.click();
  await page.keyboard.press('a');
  await expect(page.getByTestId('viewer-last-event')).toContainText('key KeyA up');
  await expect(surface).toBeFocused();
});

test('console text stays local until the operator clicks the desktop', async ({ page }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  await openViewerPanel(page, "tools");
  await page.getByTestId('viewer-command-toggle').click();
  const command = page.getByTestId('viewer-command-input');
  await command.click();
  const lastEvent = page.getByTestId('viewer-last-event');
  const before = await lastEvent.textContent();
  await page.keyboard.type('local draft');
  await expect(command).toHaveValue('local draft');
  await expect(lastEvent).toHaveText(before ?? '');
  await page.getByTestId('viewer-surface').click();
  await page.keyboard.press('a');
  await expect(lastEvent).toContainText('key KeyA up');
  await expect(command).toHaveValue('local draft');
});

test('desktop clicks do not reenable disabled input capture', async ({ page }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  await openViewerPanel(page, "input");
  await page.getByTestId('viewer-capture-input').uncheck();
  await page.getByTestId('viewer-surface').click();
  // An open panel also stops typing, so prove it closed: otherwise the silence below would not be
  // evidence that capture stayed off.
  await expect(page.getByTestId('viewer-input-menu')).toHaveAttribute('aria-expanded', 'false');
  const lastEvent = page.getByTestId('viewer-last-event');
  const before = await lastEvent.textContent();
  await page.keyboard.press('a');
  await expect(lastEvent).toHaveText(before ?? '');
});

test('pop-out desktop click takes focus in its own document', async ({ page, context }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  const [popup] = await Promise.all([
    context.waitForEvent('page'), clickPopOut(page),
  ]);
  const surface = popup.getByTestId('viewer-surface');
  await surface.click();
  await expect(surface).toBeFocused();
  await popup.keyboard.press('a');
  await expect(page.getByTestId('viewer-last-event')).toContainText('key KeyA up');
});
