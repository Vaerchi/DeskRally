import { expect, test, type Download, type Page } from "@playwright/test";
import { selectSessionView } from "./nav";
import { openManualConnect } from "./manual_connect";

const ORIGIN = "http://127.0.0.1:5173";
const DEVICE = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const ID = "11111111-2222-3333-4444-555555555555";

async function connect(page: Page, count: number) {
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill(DEVICE);
  await page.getByTestId("signaling-url").fill("ws://127.0.0.1:9/ws");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).__downloadConnections())).toBe(count);
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeVisible();
}

test.beforeEach(async ({ page }) => {
  await page.route("**/*", route => {
    const url = new URL(route.request().url());
    if (url.origin !== ORIGIN) return route.abort();
    if (url.pathname.startsWith("/cp/")) return route.fulfill({ status: 503, contentType: "application/json", body: '{"error":"synthetic offline control plane"}' });
    return route.continue();
  });
  await page.goto(`${ORIGIN}/e2e/download_app.html`);
  await connect(page, 1);
});

test("actual App cleans bidi overrides from a rejected filename in its error banner", async ({ page }) => {
  await page.evaluate(() => (window as any).__rejectDownload("report\u202Egnp.exe\u202C\n確認-👩‍💻.txt"));
  await expect(page.getByTestId("app-error").locator("span")).toHaveText("Download reportgnp.exe確認-👩‍💻.txt rejected: invalid offer size");
  await expect(page.getByTestId("incoming-download-prompt")).toHaveCount(0);
});

test("actual App saves an unmatched file only after its Save button is clicked", async ({ page }) => {
  const downloads: Download[] = [];
  page.on("download", d => downloads.push(d));
  await page.evaluate(id => (window as any).__sendDownload("screenshot-123.png", id), ID);
  await expect(page.getByTestId("incoming-download-name")).toHaveText("screenshot-123.png");
  expect(downloads).toHaveLength(0);
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("incoming-download-save").click(),
  ]);
  expect(download.suggestedFilename()).toBe("screenshot-123.png");
  await expect(page.getByTestId("incoming-download-prompt")).toHaveCount(0);
  expect(downloads).toHaveLength(1);
});

test("Dismiss removes the real prompt without starting a download", async ({ page }) => {
  const downloads: Download[] = [];
  page.on("download", d => downloads.push(d));
  await page.evaluate(() => (window as any).__sendDownload("unrequested.exe"));
  await page.getByTestId("incoming-download-dismiss").click();
  await expect(page.getByTestId("incoming-download-prompt")).toHaveCount(0);
  expect(downloads).toHaveLength(0);
});

test("requested screenshot-named files use the Files panel and the requested basename", async ({ page }) => {
  await selectSessionView(page, "Files");
  await page.getByTestId("ft-download-path").fill("C:\\reports\\screenshot-123.png");
  await page.getByTestId("ft-download-btn").click();
  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.evaluate(() => (window as any).__sendDownload("attacker.exe", (window as any).__downloadRequest())),
  ]);
  expect(download.suggestedFilename()).toBe("screenshot-123.png");
  await expect(page.getByTestId("ft-download-status")).toContainText('Downloaded "screenshot-123.png"');
  await expect(page.getByTestId("incoming-download-prompt")).toHaveCount(0);
});

test("old session frames cannot overwrite a new session's approval prompt", async ({ page }) => {
  await page.evaluate(id => (window as any).__sendDownload("old.bin", id), ID);
  await expect(page.getByTestId("incoming-download-name")).toHaveText("old.bin");
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.getByTestId("incoming-download-prompt")).toHaveCount(0);
  await connect(page, 2);
  await page.evaluate(id => (window as any).__sendDownload("new.bin", id), ID);
  await expect(page.getByTestId("incoming-download-name")).toHaveText("new.bin");
  await page.evaluate(id => (window as any).__sendDownload("stale.bin", id, 0), ID);
  await expect(page.getByTestId("incoming-download-name")).toHaveText("new.bin");
});

test("long incoming names stay within the real App layout", async ({ page }) => {
  await page.setViewportSize({ width: 1000, height: 760 });
  await page.evaluate(() => (window as any).__sendDownload("a".repeat(4000) + ".exe"));
  await expect(page.getByTestId("incoming-download-prompt")).toBeVisible();
  const shape = await page.evaluate(() => ({
    width: document.documentElement.scrollWidth, viewport: innerWidth,
    prompt: document.querySelector('[data-testid="incoming-download-prompt"]')!.getBoundingClientRect().height,
    promptRight: document.querySelector('[data-testid="incoming-download-prompt"]')!.getBoundingClientRect().right,
  }));
  await page.screenshot({ path: test.info().outputPath("incoming-download.png") });
  expect(shape.width).toBeLessThanOrEqual(shape.viewport + 1);
  expect(shape.promptRight).toBeLessThanOrEqual(shape.viewport + 1);
  expect(shape.prompt).toBeLessThanOrEqual(250);
});
