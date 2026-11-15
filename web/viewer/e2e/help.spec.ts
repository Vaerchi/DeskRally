import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

// The console Help area: reachable from the DeskRally menu and by /console/help?topic=…, searchable,
// readable at phone width. The control plane is mocked — Help makes no requests of its own.
async function signedIn(page: Page) {
  await page.route("**/cp/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/me") return route.fulfill({ json: { email: "tech@example.test" } });
    return route.fulfill({ json: { sessions: [], groups: [], users: [], roles: [] } });
  });
}

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`Help opens from the menu, switches topics and searches at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await signedIn(page);
    await page.goto("http://127.0.0.1:5173/console");
    await (await consoleTab(page, { name: "Help", exact: true })).click();
    const article = page.getByTestId("help-article");
    await expect(article.getByRole("heading", { level: 2 })).toHaveText("Finding your way around");

    await page.getByTestId("help-topic-attended").click();
    await expect(article.getByRole("heading", { level: 2 })).toHaveText("Helping someone once (attended support)");
    await expect(article).toContainText("Start support session");
    // On a phone the article sits below the topic list; choosing a topic must bring it into view.
    await expect(article.getByRole("heading", { level: 2 })).toBeInViewport();
    await page.screenshot({ path: test.info().outputPath(`help-${viewport.width}.png`), fullPage: false });

    await page.getByTestId("help-search").fill("provisioning");
    await expect(page.getByTestId("help-topic-silent-install")).toBeVisible();
    await expect(page.getByTestId("help-topic-attended")).toHaveCount(0);
    await expect(article.getByRole("heading", { level: 2 })).toHaveText("Install agents silently");

    await page.getByTestId("help-search").fill("zzzz-nothing");
    await expect(page.getByTestId("help-no-match")).toBeVisible();

    // Nothing may overflow the viewport sideways.
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
}

test("a /console/help?topic= link opens that topic", async ({ page }) => {
  await signedIn(page);
  await page.goto("http://127.0.0.1:5173/console/help?topic=security-settings");
  await expect(page.getByTestId("help-article").getByRole("heading", { level: 2 })).toHaveText("Security settings");
});

// Ed, 2026-10-18: Help must be easy to find — a button at the RIGHT end of the top bar on every
// console page. It opens a side panel over the current view (never navigates away, which would end
// a live session), closes with its button or Escape, and fits at phone width.
for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`the top-bar Help button opens Help over the current view at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await signedIn(page);
    await page.goto("http://127.0.0.1:5173/console");
    const button = page.getByTestId("app-help");
    await expect(button).toBeInViewport();
    // Rightmost control in the bar.
    const bar = await page.locator(".app__topbar").boundingBox();
    const box = await button.boundingBox();
    expect(bar && box && bar.x + bar.width - (box.x + box.width)).toBeLessThan(40);

    const before = page.url();
    await button.click();
    const drawer = page.getByTestId("help-drawer");
    await expect(drawer).toBeVisible();
    await expect(drawer.getByTestId("help-article").getByRole("heading", { level: 2 })).toHaveText("Finding your way around");
    await drawer.getByTestId("help-topic-connect").click();
    await expect(drawer.getByTestId("help-article")).toContainText("Disconnect");
    expect(page.url()).toBe(before);
    await page.screenshot({ path: test.info().outputPath(`help-drawer-${viewport.width}.png`) });

    await page.keyboard.press("Escape");
    await expect(drawer).toHaveCount(0);
    await button.click();
    await page.getByTestId("help-drawer-close").click();
    await expect(drawer).toHaveCount(0);
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });
}
