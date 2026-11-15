/**
 * The console on a phone, and on a foldable that changes shape mid-session.
 *
 * Runs under the `mobile-phone` and `mobile-foldable` projects (playwright.config.ts), which is why
 * this file is named `*.mobile.spec.ts` — the `desktop` project ignores that pattern, so the rest of
 * the suite is unaffected and does not run twice.
 *
 * IT USES THE `page` FIXTURE, NOT `chromium.launch()`. Every other spec in this directory launches
 * its own browser, which bypasses a project's `use` entirely: under a device profile that would look
 * like emulation and be none — same viewport, no `hasTouch`. The fixture is what makes the profile
 * real.
 *
 * WHAT THIS COVERS, AND WHAT IT DOES NOT. The layout bands, the drawer, and the fold transition are
 * here. The GESTURES are not: turning a finger into a click, right click, drag, pinch or scroll is
 * 29 unit tests in `src/lib/touch_gestures.test.ts`, because the recogniser is a pure reducer and a
 * unit test can advance time by arithmetic instead of waiting. A true end-to-end "tap the canvas and
 * the guest's mouse moves" test needs a live agent and a WebRTC session; that is a heavier fixture
 * and is deliberately not attempted here. Do not read a green run of this file as proof that touch
 * input reaches a guest.
 */
import { test, expect } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { stopProc } from "./devcp";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { CP_PORT, CP_BASE } from "./ports";
import { openAppMenu } from "./nav";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "..", "..", "..");
const CP_DIR = resolve(REPO, "control-plane");
const CP_EXE = resolve(CP_DIR, "controlplane.exe");
const CP_LISTEN = `127.0.0.1:${CP_PORT}`;
const APP_URL = "http://127.0.0.1:5173/";

/** Must match `src/lib/layout_breakpoints.ts`. Duplicated so a drift shows up as a test failure.
 *  Raised 599 -> 767 on 2026-09-05: the operator reported the machine list still taking most of an
 *  unfolded foldable (~700 CSS px), which used to be `split-narrow`. This is the THIRD copy of the
 *  number — the module, the CSS prose, and here — and the drift it is meant to catch is real. */
const STACKED_MAX_WIDTH = 767;
const SPLIT_WIDE_MIN_WIDTH = 960;

let cpProc: ChildProcess | null = null;
let skipReason: string | null = null;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitFor(pred: () => Promise<boolean>, timeoutMs: number, stepMs = 200): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await pred()) return true;
    if (Date.now() > deadline) return false;
    await sleep(stepMs);
  }
}

const tcpUp = (url: string, timeoutMs: number): Promise<boolean> =>
  fetch(url, { signal: AbortSignal.timeout(timeoutMs) }).then(() => true).catch(() => false);

/** The band a width belongs to, stated independently of the app's own module. */
function expectedPaneMode(width: number): "stacked" | "split-narrow" | "split-wide" {
  if (width <= STACKED_MAX_WIDTH) return "stacked";
  if (width >= SPLIT_WIDE_MIN_WIDTH) return "split-wide";
  return "split-narrow";
}

test.beforeAll(async () => {
  test.setTimeout(120_000);
  if (!existsSync(CP_EXE)) {
    skipReason = `${CP_EXE} is missing — globalSetup should have built it`;
    return;
  }
  cpProc = spawn(CP_EXE, [], {
    cwd: CP_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, CP_LISTEN, DATABASE_URL: "", CP_INSECURE_DEV: "1" },
  });
  cpProc.stdout?.on("data", (d: Buffer) => process.stdout.write(`[cp] ${d.toString()}`));
  cpProc.stderr?.on("data", (d: Buffer) => process.stderr.write(`[cp:err] ${d.toString()}`));
  if (!(await waitFor(() => tcpUp(`${CP_BASE}/machines`, 500), 15_000))) {
    skipReason = `control plane did not come up on ${CP_BASE}`;
  }
});

test.afterAll(async () => {
  await stopProc(cpProc);
});

test("the shell picks the layout band its own viewport calls for", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.goto(APP_URL);

  const shell = page.locator(".app");
  await expect(shell).toBeVisible({ timeout: 15_000 });

  const size = page.viewportSize();
  expect(size, "the mobile projects always set a viewport").not.toBeNull();
  const want = expectedPaneMode(size!.width);

  // The attribute is how the shell reports its band, and it is what the CSS and this test both key
  // on rather than measuring pixels and hoping.
  await expect(shell).toHaveAttribute("data-pane-mode", want);

  // Sanity that the emulation is real: these projects are touch devices.
  const touch = await page.evaluate(() => "ontouchstart" in window || navigator.maxTouchPoints > 0);
  expect(touch, "the mobile projects must emulate touch, or this file proves nothing").toBe(true);
});

test("the machine list is a drawer when stacked and a permanent pane when not", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.goto(APP_URL);

  const shell = page.locator(".app");
  await expect(shell).toBeVisible({ timeout: 15_000 });
  const toggle = page.getByTestId("app-nav-toggle");
  const stacked = expectedPaneMode(page.viewportSize()!.width) === "stacked";

  if (!stacked) {
    // Wider: the list is a column beside the session, and ☰ is its CLOSE control (collapse), never
    // conditionally rendered (which is what lets a fold survive).
    await expect(toggle).toBeVisible();
    await expect(toggle).toHaveAttribute("aria-label", "Hide machine list");
    await expect(page.locator("#access-panel")).toBeVisible();
    await expect(shell).toHaveAttribute("data-nav-open", "false");
    return;
  }

  await expect(toggle).toBeVisible();
  await expect(shell).toHaveAttribute("data-nav-open", "false");

  // TAP, not click: on a touch device the tap path is the one an operator actually uses.
  await toggle.tap();
  await expect(shell).toHaveAttribute("data-nav-open", "true");
  await expect(toggle).toHaveAttribute("aria-expanded", "true");
  await expect(page.getByTestId("app-nav-backdrop")).toBeVisible();

  // Tapping the backdrop closes it — the gesture everyone tries first.
  // The backdrop spans the full viewport (z-30) while the drawer (#access-panel) covers the left
  // portion (min(86vw, 340px), z-40). Tapping centre would land inside the drawer and be intercepted
  // by it. Compute the exposed right strip and tap its centre instead.
  // Measure only once the drawer has FINISHED sliding in. Read mid-transition its box is still partly
  // off-screen (x < 0), the computed strip lands inside the drawer once it settles, and the tap is
  // intercepted — a race that flaked as soon as render timing shifted (2026-10-19).
  await expect.poll(async () => (await page.locator("#access-panel").boundingBox())?.x).toBe(0);
  const drawerBox = await page.locator("#access-panel").boundingBox();
  const viewSize = page.viewportSize()!;
  const drawerRight = drawerBox ? drawerBox.x + drawerBox.width : Math.min(viewSize.width * 0.86, 340);
  const stripCentreX = drawerRight + (viewSize.width - drawerRight) / 2;
  await page.getByTestId("app-nav-backdrop").tap({ position: { x: stripCentreX, y: viewSize.height / 2 } });
  await expect(shell).toHaveAttribute("data-nav-open", "false");
  await expect(page.getByTestId("app-nav-backdrop")).toBeHidden();
});

/**
 * THE FOLD TRANSITION, and the reason the shell may not branch on width in React.
 *
 * Unfolding is a live resize of a page that is mid-session. If the layout were expressed as
 * `{stacked ? <A/> : <B/>}`, the resize would unmount a subtree — and unmounting the session pane
 * destroys the `<video>`, the RTCPeerConnection and the zoom/pan state, i.e. opening the phone would
 * drop the call.
 *
 * A remount is detected DIRECTLY: a property is set on the live DOM node before the resize, and a
 * remount replaces that node and takes the property with it. Asserting "the element is still
 * visible" would pass against a full remount and prove nothing.
 */
test("unfolding reflows the layout WITHOUT remounting the session pane", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.goto(APP_URL);
  await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });

  // Start folded/phone, whatever the project's own size is.
  await page.setViewportSize({ width: 412, height: 915 });
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked");

  // Mark the live nodes. `.app__main` is the container the session renders into.
  const marked = await page.evaluate(() => {
    const main = document.querySelector(".app__main");
    const list = document.querySelector("#access-panel");
    if (!main || !list) return false;
    (main as unknown as Record<string, unknown>).__foldMarker = "survived";
    (list as unknown as Record<string, unknown>).__foldMarker = "survived";
    return true;
  });
  expect(marked, "both panes must exist before the resize").toBe(true);

  // Unfold. 800, not the 700 this used to use: since 2026-09-05 a ~700 px unfolded foldable is
  // STACKED, so resizing 412 -> 700 no longer crosses a band and the test would have proved nothing
  // while still passing. The point is a live resize ACROSS a band boundary, so the width has to be
  // one that still crosses it.
  await page.setViewportSize({ width: 800, height: 900 });
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "split-narrow");

  const survived = await page.evaluate(() => ({
    main: (document.querySelector(".app__main") as unknown as Record<string, unknown> | null)?.__foldMarker,
    list: (document.querySelector("#access-panel") as unknown as Record<string, unknown> | null)?.__foldMarker,
  }));
  expect(survived.main, "the session pane was REMOUNTED by the resize — a live session would have been dropped").toBe("survived");
  expect(survived.list, "the machine list was remounted by the resize").toBe("survived");

  // And fold back again: the band returns, still without a remount.
  await page.setViewportSize({ width: 412, height: 915 });
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked");
  const stillThere = await page.evaluate(
    () => (document.querySelector(".app__main") as unknown as Record<string, unknown> | null)?.__foldMarker,
  );
  expect(stillThere, "folding back remounted the session pane").toBe("survived");
});

test("a drawer left open is forced shut when the viewport widens", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.goto(APP_URL);
  await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });

  await page.setViewportSize({ width: 412, height: 915 });
  await page.getByTestId("app-nav-toggle").tap();
  await expect(page.locator(".app")).toHaveAttribute("data-nav-open", "true");

  // Unfold with the drawer open. Leaving the flag set would strand a backdrop over a two-pane view.
  // 800 rather than 700 since 2026-09-05: ~700 is now STACKED, so widening to it does not leave the
  // band and there is correctly nothing to force shut — the test needs a width that still splits.
  await page.setViewportSize({ width: 800, height: 900 });
  await expect(page.locator(".app")).toHaveAttribute("data-nav-open", "false");
  await expect(page.getByTestId("app-nav-backdrop")).toBeHidden();
  await expect(page.locator("#access-panel")).toBeVisible();
});

/**
 * THE COMPACT OVERRIDE. It exists because the automatic band was right and still not what the
 * operator wanted: they reported the compact bar missing on their foldable, whose unfolded inner
 * screen is ~700px and was then `split-narrow`, so it correctly kept two panes and the full bar.
 * (Since 2026-09-05 that width stacks on its own, so the override is no longer what rescues a
 * foldable — it remains the escape hatch for a real tablet or a desktop.)
 *
 * Asserted at a WIDE width on purpose. At a phone width the override is a no-op (already stacked),
 * so a test that only checked a phone would pass against a toggle that did nothing at all.
 */
test("the compact toggle forces the stacked layout at a desktop width, and is remembered", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.goto(APP_URL);
  await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });

  // A width that would never stack on its own.
  await page.setViewportSize({ width: 1440, height: 900 });
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "split-wide");
  await expect(page.getByTestId("app-nav-toggle")).toHaveAttribute("aria-label", "Hide machine list");

  const toggle = page.getByTestId("app-compact-toggle");
  await expect(toggle).toHaveAttribute("aria-pressed", "false");
  await openAppMenu(page);
  await toggle.click();

  // Forced stacked despite 1440px: the list becomes a drawer and the menu button appears.
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked");
  await expect(page.getByTestId("app-nav-toggle")).toBeVisible();
  await expect(toggle).toHaveAttribute("aria-pressed", "true");

  // The drawer still works in forced-compact mode, and is NOT slammed shut by a resize while the
  // override is on — the regression the mode-based shouldForceDrawerClosed exists for.
  await page.getByTestId("app-nav-toggle").click();
  await expect(page.locator(".app")).toHaveAttribute("data-nav-open", "true");
  await page.setViewportSize({ width: 1600, height: 900 });
  await expect(page.locator(".app")).toHaveAttribute("data-nav-open", "true");
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked");

  // Remembered across a reload, which is the whole value of a preference.
  await page.reload();
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "stacked", { timeout: 15_000 });
  await openAppMenu(page);
  await expect(page.getByTestId("app-compact-toggle")).toHaveAttribute("aria-pressed", "true");

  // And turning it off returns to following the viewport — the negative control, without which a
  // one-way switch would pass everything above.
  await openAppMenu(page);
  await page.getByTestId("app-compact-toggle").click();
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", "split-wide");
  await expect(page.getByTestId("app-nav-toggle")).toHaveAttribute("aria-label", "Hide machine list");
});

/**
 * Ed, 2026-10-22: "the phone in tablet mode - there is no way to close/minimize the left hand tab that
 * has the computers listed". In the two-pane layouts the list had no visible close control (☰ was
 * hidden there; Compact sat inside the DeskRally menu). ☰ now collapses it, the drawer then reopens it,
 * and "Keep list open" puts the pane back.
 */
for (const width of [800, 1024]) {
  test(`at ${width}px the machine list can be collapsed with ☰, reopened as a drawer, and pinned back`, async ({ page }) => {
    test.skip(skipReason !== null, skipReason ?? "");
    await page.goto(APP_URL);
    const shell = page.locator(".app");
    await expect(shell).toBeVisible({ timeout: 15_000 });
    await page.setViewportSize({ width, height: 900 });
    await expect(shell).not.toHaveAttribute("data-pane-mode", "stacked");
    const list = page.locator("#access-panel");
    const main = page.locator(".app__main");
    await expect(list).toBeInViewport();
    const mainBefore = (await main.boundingBox())!.width;

    const toggle = page.getByTestId("app-nav-toggle");
    await expect(toggle).toBeVisible();
    await toggle.tap();
    await expect(shell).toHaveAttribute("data-pane-mode", "stacked");
    await expect(list).not.toBeInViewport();
    expect((await main.boundingBox())!.width, "the session gets the list's width").toBeGreaterThan(mainBefore + 100);

    await toggle.tap();
    await expect(shell).toHaveAttribute("data-nav-open", "true");
    await expect.poll(async () => (await list.boundingBox())?.x).toBe(0);
    await expect(page.getByTestId("access-pin")).toBeVisible();
    await page.getByTestId("access-pin").tap();
    await expect(shell).not.toHaveAttribute("data-pane-mode", "stacked");
    await expect(shell).toHaveAttribute("data-nav-open", "false");
    await expect(list).toBeInViewport();
    expect(await page.evaluate(() => localStorage.getItem("deskrally.layout.paneMode"))).toBe("auto");
  });
}

test("on a phone-width screen the pin is not offered (the list is always a drawer there)", async ({ page }) => {
  test.skip(skipReason !== null, skipReason ?? "");
  await page.addInitScript(() => { try { localStorage.setItem("deskrally.layout.paneMode", "compact"); } catch { /* none */ } });
  await page.goto(APP_URL);
  await expect(page.locator(".app")).toBeVisible({ timeout: 15_000 });
  await page.setViewportSize({ width: 412, height: 915 });
  await page.getByTestId("app-nav-toggle").tap();
  await expect(page.locator(".app")).toHaveAttribute("data-nav-open", "true");
  await expect(page.getByTestId("access-pin")).toBeHidden();
});
