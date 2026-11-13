import { test, expect } from "@playwright/test";

// These cases pin the F08 behaviour, which is what "Share clipboard automatically" OFF means. The
// automatic (default) behaviour is covered at the end of this file.
test.beforeEach(async ({ page }, info) => {
  const auto = info.title.startsWith("automatic");
  // "automatic (default)" starts with NOTHING stored, so it proves the shipped default.
  if (!info.title.startsWith("automatic (default)")) await page.addInitScript(on => { try { localStorage.setItem("deskrally.clipboard.auto", on ? "1" : "0"); } catch { /* none */ } }, auto);
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === "http://127.0.0.1:5173") return route.continue();
    return route.abort();
  });
  await page.goto("http://127.0.0.1:5173/e2e/clipboard_control.html");
  await expect(page.getByTestId("clipboard-receive")).toBeVisible();
});

test("incoming text requires the real receive checkbox and stops when unchecked", async ({ page }) => {
  const receive = page.getByTestId("clipboard-receive");
  await expect(receive).not.toBeChecked();
  await page.evaluate(() => window.__clipboardInput("unsolicited synthetic text"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
  await receive.check();
  await page.evaluate(() => window.__clipboardInput("accepted synthetic text"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual(["accepted synthetic text"]);
  await expect(page.getByTestId("clipboard-status")).toContainText("Applied remote clipboard");
  await expect(page.getByTestId("clipboard-status")).not.toContainText("accepted synthetic text");
  await receive.uncheck();
  await page.evaluate(() => window.__clipboardInput("disabled synthetic text"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual(["accepted synthetic text"]);
});

test("a replacement session starts off while outgoing send remains usable", async ({ page }) => {
  await page.getByTestId("clipboard-receive").check();
  await page.getByTestId("replace-session").click();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();
  await page.evaluate(() => window.__clipboardInput("new session unsolicited"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
  await page.getByTestId("clipboard-send").click();
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
});

test("an old clipboard read cannot send or update the next session UI", async ({ page }) => {
  await page.evaluate(() => { window.__clipboardBlockRead = true; });
  await page.getByTestId("clipboard-send").click();
  await expect(page.getByTestId("clipboard-status")).toContainText("Reading clipboard");
  await page.getByTestId("replace-session").click();
  await page.evaluate(async () => {
    window.__clipboardResolveRead();
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual([]);
  await expect(page.getByTestId("clipboard-status")).toHaveCount(0);
});

test("unmounting the receive control cannot leave a hidden enabled writer", async ({ page }) => {
  await page.getByTestId("clipboard-receive").check();
  await page.getByTestId("toggle-control").click();
  await page.evaluate(() => window.__clipboardInput("while control hidden"));
  await page.getByTestId("toggle-control").click();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();
  await page.evaluate(() => window.__clipboardInput("after control returns"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
});

test("oversized remote text is rejected without reaching the fake clipboard", async ({ page }) => {
  await page.getByTestId("clipboard-receive").check();
  await page.evaluate(() => window.__clipboardInput("x".repeat(65537)));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
  await expect(page.getByTestId("clipboard-status")).toContainText("size limit");
});

test("both clipboard controls remain reachable in a narrow viewport", async ({ page }) => {
  await page.setViewportSize({ width: 412, height: 700 });
  await expect(page.getByTestId("clipboard-send")).toBeVisible();
  await expect(page.getByTestId("clipboard-receive")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await page.getByTestId("clipboard-receive").check();
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
});

test("automatic (default): with nothing stored it is on, and every new session receives without a click", async ({ page }) => {
  expect(await page.evaluate(() => localStorage.getItem("deskrally.clipboard.auto"))).toBeNull();
  await expect(page.getByTestId("clipboard-auto")).toBeChecked();
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
  await page.evaluate(() => window.__clipboardInput("remote copied this"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual(["remote copied this"]);
  await page.getByTestId("replace-session").click();
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
});

test("automatic: a press on the remote screen sends the local clipboard once; elsewhere sends nothing", async ({ page }) => {
  await page.getByTestId("replace-session").click(); // a press OUTSIDE the remote screen
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual([]);
  await page.getByTestId("viewer-surface").click();
  await expect.poll(() => page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
  await expect(page.getByTestId("clipboard-status")).toContainText("shared automatically");
  await expect(page.getByTestId("clipboard-status")).not.toContainText("synthetic local clipboard");
  await page.getByTestId("viewer-surface").click(); // unchanged clipboard: nothing new to send
  await page.evaluate(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
});

test("automatic: Send says WHICH no-send happened: already sent vs could not read (Ed, 10-24)", async ({ page }) => {
  await page.getByTestId("replace-session").click(); // same setup as the automatic-send test above
  await page.getByTestId("viewer-surface").click(); // automatic send of the current clipboard
  await expect.poll(() => page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
  await page.getByTestId("clipboard-send").click();
  await expect(page.getByTestId("clipboard-status")).toContainText("Already sent");
  await page.evaluate(() => { (window as unknown as { __clipboardFailRead?: boolean }).__clipboardFailRead = true; });
  await page.getByTestId("clipboard-send").click();
  await expect(page.getByTestId("clipboard-status")).toContainText("Could not read your clipboard");
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
});

test("automatic: turning it off stops receiving and sending now, and is remembered", async ({ page }) => {
  await page.getByTestId("clipboard-auto").uncheck();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();
  await page.evaluate(() => window.__clipboardInput("after switching off"));
  await page.getByTestId("viewer-surface").click();
  await page.evaluate(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
  expect(await page.evaluate(() => window.__clipboardSends)).toEqual([]);
  expect(await page.evaluate(() => localStorage.getItem("deskrally.clipboard.auto"))).toBe("0");
  await page.getByTestId("clipboard-auto").check();
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
  expect(await page.evaluate(() => localStorage.getItem("deskrally.clipboard.auto"))).toBe("1");
});

test.describe("in a desktop app older than 0.8.3", () => {
  test.use({ userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/141.0 DeskRallyDesktop/0.8.2 DeskRallySSO/1" });
  test("automatic: a press on the remote screen reads nothing (that app would prompt on every read); receive still starts on", async ({ page }) => {
    await expect(page.getByTestId("clipboard-receive")).toBeChecked();
    await page.getByTestId("viewer-surface").click();
    await page.evaluate(async () => { for (let i = 0; i < 6; i++) await Promise.resolve(); });
    expect(await page.evaluate(() => window.__clipboardSends)).toEqual([]);
    await page.getByTestId("clipboard-send").click();
    await expect.poll(() => page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
  });
});

test("automatic: the Input menu's quick switch turns receiving off and on in the live session", async ({ page }) => {
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
  await page.getByTestId("clipboard-quick-auto").uncheck();
  await expect(page.getByTestId("clipboard-auto")).not.toBeChecked();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();
  await page.evaluate(() => window.__clipboardInput("while off"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual([]);
  await page.getByTestId("clipboard-quick-auto").check();
  await expect(page.getByTestId("clipboard-receive")).toBeChecked();
  await page.evaluate(() => window.__clipboardInput("back on"));
  expect(await page.evaluate(() => window.__clipboardWrites)).toEqual(["back on"]);
});

test("automatic: Send clipboard now in the Input menu sends the local clipboard", async ({ page }) => {
  await page.getByTestId("clipboard-quick-send").click();
  await expect.poll(() => page.evaluate(() => window.__clipboardSends)).toEqual(["synthetic local clipboard"]);
  await expect(page.getByTestId("clipboard-quick-status")).toContainText("Sent");
});
