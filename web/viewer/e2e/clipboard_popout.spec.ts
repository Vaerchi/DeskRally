/**
 * E2E coverage for the popout-clipboard feature (pass 52).
 *
 * Harness mirrors App.tsx: {!poppedOut && <ClipboardControl>} in main chrome, and
 * <Viewer popoutControls={<ClipboardControl>} onPopoutChange={...}> so the no-duplicate assertion
 * is non-tautological — the control IS rendered in main chrome before popout.
 *
 * navigator.clipboard is mocked in the popup window via Object.defineProperty after the popup
 * opens (same-origin about:blank, so popup.evaluate works). The main window uses a different
 * in-harness mock so tests can prove ownership by checking which side received the write.
 */
import { test, expect } from "@playwright/test";

const BASE = "http://127.0.0.1:5173/e2e/clipboard_popout.html";

// ── helpers ──────────────────────────────────────────────────────────────────

/** Grant permissions and navigate; only origins needed for the dev server. */
test.beforeEach(async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  // These cases pin receive ownership with automatic sharing OFF (the F08 behaviour).
  await context.addInitScript(() => { try { localStorage.setItem("deskrally.clipboard.auto", "0"); } catch { /* none */ } });
  await page.route("**/*", route => {
    if (new URL(route.request().url()).origin === "http://127.0.0.1:5173") return route.continue();
    return route.abort();
  });
});

/**
 * Open the popup window and install a mocked navigator.clipboard in it.
 * Returns the popup Page plus arrays that accumulate reads/writes from inside the popup.
 *
 * The popup is opened via window.open("","rmt-remote-desktop") — same-origin about:blank —
 * so popup.evaluate and popup.exposeFunction both work without restriction.
 *
 * readValue: what popup clipboard.readText() returns (distinct from main's "main local clipboard")
 */
async function popAndMock(page: import("@playwright/test").Page, context: import("@playwright/test").BrowserContext, readValue = "popup clipboard value") {
  const popupWrites: string[] = [];
  const popupReads: string[] = [];

  // Register a recorder before the popup page receives any JS; waitForEvent resolves
  // as soon as the Page object exists, giving us access before user interaction runs.
  const popupPromise = context.waitForEvent("page");
  await page.getByTestId("viewer-view-menu").click(); // Pop out is in the View panel (menu redesign wave 7b)
  await page.getByTestId("viewer-popout").click();
  const popup = await popupPromise;

  // exposeFunction wires a host-side function into the popup window's global scope.
  await popup.exposeFunction("__recordPopupWrite", async (text: string) => {
    popupWrites.push(text);
  });
  await popup.exposeFunction("__recordPopupRead", async () => {
    popupReads.push(readValue);
    return readValue;
  });

  // Replace navigator.clipboard with a controlled stub. configurable:true is required by the spec
  // to allow redefinition; the popup is same-origin so this evaluates in its window context.
  await popup.evaluate(() => {
    Object.defineProperty(navigator, "clipboard", {
      configurable: true,
      value: {
        readText: async () => (window as Window & { __recordPopupRead: () => Promise<string> }).__recordPopupRead(),
        writeText: async (text: string) =>
          (window as Window & { __recordPopupWrite: (t: string) => Promise<void> }).__recordPopupWrite(text),
      },
    });
  });

  return { popup, popupWrites, popupReads };
}

// ── ClipboardControl presence ─────────────────────────────────────────────────

test("ClipboardControl is visible in main chrome before any popout", async ({ page }) => {
  await page.goto(BASE);
  // The harness renders {!poppedOut && <ClipboardControl>} in main chrome — it must be visible.
  await expect(page.getByTestId("clipboard-control")).toBeVisible();
  await expect(page.getByTestId("clipboard-send")).toBeEnabled();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();
});

test("ClipboardControl moves to popup on pop-out, disappears from main chrome", async ({ page, context }) => {
  await page.goto(BASE);
  await expect(page.getByTestId("clipboard-control")).toBeVisible();

  const { popup } = await popAndMock(page, context);

  await expect(popup.getByTestId("clipboard-control")).toBeVisible();
  // Main chrome control must be hidden — !viewerPoppedOut guard removed it.
  await expect(page.getByTestId("clipboard-control")).not.toBeVisible();
  expect(await page.evaluate(() => window.__poppedOut)).toBe(true);
});

test("exactly one clipboard-control across both windows while popped out", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup } = await popAndMock(page, context);

  const popupCount = await popup.getByTestId("clipboard-control").count();
  const mainCount = await page.getByTestId("clipboard-control").count();
  expect(popupCount).toBe(1);
  expect(mainCount).toBe(0);
});

// ── Send: reads popup clipboard, not main ─────────────────────────────────────

test("send in popup reads popup clipboard value, not main-window value", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup, popupReads } = await popAndMock(page, context, "popup clipboard value");

  await popup.getByTestId("clipboard-send").click();

  // The send must have gone through — sends array contains the popup value, not main's.
  await expect.poll(() => page.evaluate(() => window.__clipboardSends)).toContain("popup clipboard value");
  expect(await page.evaluate(() => window.__clipboardSends)).not.toContain("main local clipboard");
  expect(popupReads).toContain("popup clipboard value");
});

// ── Receive: default-off, writes correct clipboard ────────────────────────────

test("receive is unchecked by default in popup", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup } = await popAndMock(page, context);
  await expect(popup.getByTestId("clipboard-receive")).not.toBeChecked();
});

test("inbound text is not written anywhere when receive is off", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup, popupWrites } = await popAndMock(page, context);
  await expect(popup.getByTestId("clipboard-receive")).not.toBeChecked();

  await page.evaluate(() => window.__clipboardInput("dropped text"));
  // Brief settle — ensure no async write slips through.
  await popup.waitForTimeout(100);

  expect(popupWrites).toEqual([]);
  expect(await page.evaluate(() => window.__clipboardMainWrites)).toEqual([]);
});

test("inbound text is written to popup clipboard when receive is on", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup, popupWrites } = await popAndMock(page, context);

  await popup.getByTestId("clipboard-receive").check();
  await expect(popup.getByTestId("clipboard-receive")).toBeChecked();

  await page.evaluate(() => window.__clipboardInput("agent text"));

  // Popup clipboard receives the write; main-window clipboard does NOT.
  await expect.poll(() => popupWrites).toEqual(["agent text"]);
  expect(await page.evaluate(() => window.__clipboardMainWrites)).toEqual([]);
});

// ── Return to tab: resets opt-in, subsequent inbound ignored ─────────────────

test("return to tab: ClipboardControl re-appears in main chrome with receive unchecked", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup, popupWrites } = await popAndMock(page, context);

  await popup.getByTestId("clipboard-receive").check();
  await expect(popup.getByTestId("clipboard-receive")).toBeChecked();

  await popup.getByRole("button", { name: "Return to tab", exact: true }).click();

  await expect.poll(() => page.evaluate(() => window.__poppedOut)).toBe(false);
  // Main-chrome ClipboardControl is back and its checkbox is unchecked.
  await expect(page.getByTestId("clipboard-control")).toBeVisible();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();

  // Subsequent inbound must be ignored (receive was reset by unmount cleanup).
  await page.evaluate(() => window.__clipboardInput("post-return text"));
  await page.waitForTimeout(100);
  expect(popupWrites).toEqual([]);
  expect(await page.evaluate(() => window.__clipboardMainWrites)).toEqual([]);
});

// ── Close popup: same guarantees as return ────────────────────────────────────

test("closing the popup: main ClipboardControl restored, receive reset, inbound ignored", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup, popupWrites } = await popAndMock(page, context);

  await popup.getByTestId("clipboard-receive").check();

  await popup.close();

  await expect.poll(() => page.evaluate(() => window.__poppedOut)).toBe(false);
  await expect(page.getByTestId("clipboard-control")).toBeVisible();
  await expect(page.getByTestId("clipboard-receive")).not.toBeChecked();

  await page.evaluate(() => window.__clipboardInput("post-close text"));
  await page.waitForTimeout(100);
  expect(popupWrites).toEqual([]);
  expect(await page.evaluate(() => window.__clipboardMainWrites)).toEqual([]);
});

// ── Reopen starts off ─────────────────────────────────────────────────────────

test("reopening popup after return starts with receive unchecked", async ({ page, context }) => {
  await page.goto(BASE);
  // First popout: enable receive, then return.
  const { popup: popup1 } = await popAndMock(page, context);
  await popup1.getByTestId("clipboard-receive").check();
  await popup1.getByRole("button", { name: "Return to tab", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.__poppedOut)).toBe(false);

  // Second popout: receive must be off.
  const { popup: popup2 } = await popAndMock(page, context);
  await expect(popup2.getByTestId("clipboard-receive")).not.toBeChecked();
});

// ── Monitor picker lock ───────────────────────────────────────────────────────

test("monitor picker is disabled in popup when pinnedMonitorId is set", async ({ page, context }) => {
  await page.goto(BASE + "?pinned=1");
  const { popup } = await popAndMock(page, context);
  const picker = popup.getByTestId("popout-monitor");
  await expect(picker).toBeDisabled();
  await expect(picker).toHaveAttribute("title", /pinned/i);
});

test("monitor picker is enabled in popup when no pinnedMonitorId", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup } = await popAndMock(page, context);
  await expect(popup.getByTestId("popout-monitor")).toBeEnabled();
});

// ── Keyboard from ClipboardControl does not emit remote input ─────────────────

test("key press inside ClipboardControl in popup is not forwarded to remote", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup } = await popAndMock(page, context);

  // Focus the send button — it is inside PopoutControls which has onKeyDown stopPropagation.
  await popup.getByTestId("clipboard-send").focus();
  const logBefore = (await page.evaluate(() => window.__inputLog.length));

  await popup.keyboard.press("a");
  await popup.waitForTimeout(80);

  // No input frame should have been emitted.
  const logAfter = await page.evaluate(() => window.__inputLog.length);
  expect(logAfter).toBe(logBefore);
});

// ── Narrow-width geometry ─────────────────────────────────────────────────────

test("ClipboardControl controls are reachable in a narrow viewport before popout", async ({ page }) => {
  await page.goto(BASE);
  await page.setViewportSize({ width: 412, height: 700 });
  await expect(page.getByTestId("clipboard-send")).toBeVisible();
  await expect(page.getByTestId("clipboard-receive")).toBeVisible();
  // No horizontal scroll.
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test("ClipboardControl controls are reachable inside popup at narrow viewport", async ({ page, context }) => {
  await page.goto(BASE);
  const { popup } = await popAndMock(page, context);
  await popup.setViewportSize({ width: 412, height: 700 });
  await expect(popup.getByTestId("clipboard-send")).toBeVisible();
  await expect(popup.getByTestId("clipboard-receive")).toBeVisible();
  expect(await popup.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});
