import { test, expect } from '@playwright/test';
import { clickInViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

test('Fit shows the entire remote video inside the real embedded session layout', async ({ page }) => {
  // Block any non-loopback request that escapes the specific mocks below. Registered first so that
  // the more-specific cp mock (registered after) takes priority in Playwright's LIFO route order.
  await page.route(/.*/, route => {
    const { hostname } = new URL(route.request().url());
    if (hostname !== '127.0.0.1') route.abort();
    else route.continue();
  });
  await page.route('**/cp/**', async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/cp/auth/session') await route.fulfill({ status: 204 });
    else if (path === '/cp/machines') await route.fulfill({ json: { machines: [], presence_known: true } });
    else if (path === '/cp/sessions') await route.fulfill({ status: 503, json: {} });
    else await route.fulfill({ json: {} });
  });
  await page.routeWebSocket('ws://127.0.0.1:5188/ws', () => {});
  await page.setViewportSize({ width: 1280, height: 720 });
  // The supervised runner supplies a dedicated local port; the repo config uses 5173.
  await page.goto(test.info().project.use.baseURL ?? 'http://127.0.0.1:5173/');
  await openManualConnect(page);
  await page.getByTestId('signaling-url').fill('ws://127.0.0.1:5188/ws');
  await page.getByTestId('manual-device').fill('00112233-4455-6677-8899-aabbccddeeff');
  await page.getByTestId('manual-connect').click();
  await expect(page.locator('.app__session video')).toBeVisible();
  for (const remote of [{ width: 2560, height: 1440 }, { width: 1440, height: 2560 }]) {
    await page.evaluate(async dimensions => {
      const video = document.querySelector('video')!;
      (video.srcObject as MediaStream | null)?.getTracks().forEach(track => track.stop());
      const canvas = document.createElement('canvas');
      canvas.width = dimensions.width; canvas.height = dimensions.height;
      const ctx = canvas.getContext('2d')!;
      ctx.fillStyle = 'green'; ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = 'red'; ctx.fillRect(0, canvas.height - 40, canvas.width, 40);
      video.srcObject = canvas.captureStream(1);
      await video.play();
    }, remote);
    for (const viewport of [{ width: 1280, height: 720 }, { width: 960, height: 540 }]) {
      await page.setViewportSize(viewport);
      await clickInViewerPanel(page, "view", page.getByTestId('viewer-zoom-in'));
      await clickInViewerPanel(page, "view", page.getByTestId('viewer-zoom-fit'));
      await expect.poll(() => page.evaluate(() => {
        const surface = document.querySelector('.viewer__surface')!.getBoundingClientRect();
        const video = document.querySelector('video')!;
        const rect = video.getBoundingClientRect();
        const scale = Math.min(rect.width / video.videoWidth, rect.height / video.videoHeight);
        const imageTop = rect.top + (rect.height - video.videoHeight * scale) / 2;
        const imageBottom = imageTop + video.videoHeight * scale;
        return surface.height > 0 && surface.bottom <= innerHeight + 1 &&
          imageTop >= surface.top - 1 && imageBottom <= Math.min(surface.bottom, innerHeight) + 1 &&
          document.documentElement.scrollHeight <= innerHeight + 1;
      })).toBe(true);
    }
  }
});
