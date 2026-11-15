import { test, expect } from '@playwright/test';
import { clickPopOut } from './nav';

test('pop-out monitor picker shares selection and handles display removal', async ({ page, context }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  const [popup] = await Promise.all([context.waitForEvent('page'), clickPopOut(page)]);
  const picker = popup.getByRole('combobox', { name: 'Monitor', exact: true });
  await expect(picker.locator('option')).toHaveCount(4);
  await picker.selectOption('2');
  await expect(page.getByTestId('viewer-monitor')).toHaveValue('2');
  await expect.poll(() => page.evaluate(() => (window as any).__selectMonitorCalls)).toEqual([2]);
  await page.getByTestId('viewer-monitor').selectOption('1');
  await expect(picker).toHaveValue('1');
  const all = await picker.locator('option').filter({ hasText: 'View all' }).getAttribute('value');
  await picker.selectOption(all!);
  await expect(page.getByTestId('viewer-monitor')).toHaveValue(all!);
  await page.evaluate(() => (window as any).__setMonitors([
    { id: 0, label: 'Remaining monitor', width: 1920, height: 1080, primary: true },
  ]));
  await expect(picker.locator('option')).toHaveCount(1);
  await expect(picker).toHaveValue('0');
  await expect.poll(() => page.evaluate(() => (window as any).__selectMonitorCalls)).toEqual([2, 1, Number(all), 0]);
  await popup.getByRole('button', { name: 'Return to tab', exact: true }).click();
  await expect(page.getByTestId('viewer-monitor')).toHaveValue('0');
});

test('live media survives repeated pop-out and return to tab', async ({ page, context }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  await page.waitForFunction(() => typeof (window as any).__setStream === 'function');
  await page.evaluate(() => {
    const canvas = document.createElement('canvas');
    canvas.width = 640; canvas.height = 360;
    const ctx = canvas.getContext('2d')!;
    let frame = 0;
    setInterval(() => { ctx.fillStyle = frame++ % 2 ? 'green' : 'blue'; ctx.fillRect(0, 0, 640, 360); }, 50);
    (window as any).__setStream(canvas.captureStream(20));
  });
  const assertPlaying = async (p: typeof page) => {
    await expect.poll(() => p.locator('video').evaluate(v => ({ width: v.videoWidth, paused: v.paused, media: !!v.srcObject })))
      .toEqual({ width: 640, paused: false, media: true });
    const before = await p.locator('video').evaluate(v => v.currentTime);
    await expect.poll(() => p.locator('video').evaluate(v => v.currentTime)).toBeGreaterThan(before);
  };
  await assertPlaying(page);
  for (let i = 0; i < 3; i++) {
    const [popup] = await Promise.all([context.waitForEvent('page'), clickPopOut(page)]);
    await assertPlaying(popup);
    if (i === 0) await popup.getByRole('button', { name: 'Return to tab', exact: true }).click();
    else if (i === 1) await page.getByTestId('viewer-popin').click();
    else await popup.close();
    await assertPlaying(page);
  }
});

test('pop-out exposes working zoom, maximize and return controls with an arrow cursor', async ({ page, context }) => {
  await page.goto('http://127.0.0.1:5173/e2e/viewer_chrome.html');
  const [popup] = await Promise.all([context.waitForEvent('page'), clickPopOut(page)]);
  const bar = popup.getByTestId('popout-controls');
  await expect(bar).toBeVisible();
  await popup.evaluate(async () => {
    const c = document.createElement('canvas'); c.width = 1920; c.height = 1080;
    c.getContext('2d')!.fillRect(0, 0, c.width, c.height);
    const video = document.querySelector('video')!;
    video.srcObject = c.captureStream(1); await video.play();
  });
  await expect.poll(() => popup.evaluate(() => document.querySelector('video')!.videoWidth)).toBe(1920);
  const transform = () => popup.locator('video').evaluate(el => el.style.transform);
  await bar.getByRole('button', { name: 'Zoom in', exact: true }).click();
  await expect.poll(transform).not.toContain('scale(1)');
  await bar.getByRole('button', { name: 'Fit', exact: true }).click();
  await expect.poll(transform).toContain('scale(1)');
  await bar.getByRole('button', { name: '1:1', exact: true }).click();
  await expect.poll(transform).not.toContain('scale(1)');
  await bar.getByRole('button', { name: 'Zoom out', exact: true }).click();
  await bar.getByRole('button', { name: 'Fit', exact: true }).click();
  await expect(popup.getByTestId('viewer-surface')).toHaveCSS('cursor', 'default');
  await bar.getByRole('button', { name: 'Maximize', exact: true }).click();
  await expect.poll(() => popup.evaluate(() => !!document.fullscreenElement)).toBe(true);
  await bar.getByRole('button', { name: 'Restore', exact: true }).click();
  await expect.poll(() => popup.evaluate(() => !!document.fullscreenElement)).toBe(false);
  await bar.getByRole('button', { name: 'Return to tab', exact: true }).click();
  await expect(page.getByTestId('viewer-surface')).toBeVisible();
});
