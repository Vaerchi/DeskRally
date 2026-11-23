import { expect, test } from "@playwright/test";
import { openViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

test.beforeEach(async ({ page }) => {
  await page.setViewportSize({ width: 1000, height: 760 });
  await page.route("**/*", route => {
    const url = new URL(route.request().url());
    if (url.origin !== "http://127.0.0.1:5173") return route.abort();
    if (url.pathname.startsWith("/cp/")) return route.fulfill({ status: 503, body: "{}" });
    return route.continue();
  });
  await page.goto("http://127.0.0.1:5173/e2e/download_app.html");
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
  await page.getByTestId("signaling-url").fill("ws://127.0.0.1:9/ws");
  await page.getByTestId("manual-connect").click();
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeVisible();
});

for (const width of [412, 700, 1000, 1600]) {
  test(`the actual App has no page-level horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 760 });
    await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
    // Hidden labels remain available to accessibility APIs; controls still scroll into view.
    const disconnect = page.getByRole("button", { name: "Disconnect", exact: true });
    await disconnect.scrollIntoViewIfNeeded();
    await expect(disconnect).toBeInViewport();
    await openViewerPanel(page, "tools");
    await expect(page.getByRole("button", { name: /Screenshot/ })).toHaveCount(1);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
