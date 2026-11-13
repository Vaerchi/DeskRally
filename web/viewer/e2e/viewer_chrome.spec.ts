/**
 * How much of the window the Viewer's own chrome eats, and whether any of it wrapped.
 *
 * THE DEFECT CLASS THIS EXISTS FOR. The console had geometry assertions and no render test at all.
 * They all passed while the top bar rendered "Sign / out" on two lines and grew from ~40px to 67px —
 * geometry cannot see that, because the numbers it reports are the ones the broken layout produced.
 * So this measures two DIFFERENT things: the chrome BUDGET (how many pixels the bars cost), and
 * WRAPPING (whether any single control grew past one line). A change that trades the first for the
 * second — the exact trap the top-bar change fell into — fails here.
 *
 * SCREENSHOTS ARE ARTIFACTS, NOT ASSERTIONS. `toHaveScreenshot()` would pixel-diff against a
 * baseline committed from one machine, and font rasterisation differs across machines and Chrome
 * builds; in a gate that treats any failure as a hard stop, that is a flake generator. The images are
 * written to `test-results/` for a human to look at, and everything ASSERTED here is a number the
 * layout engine produced. See docs/07 on why a screenshot is still worth having even unasserted.
 *
 * WIDTHS. These are the width available to the VIEWER, which in the real shell is the viewport minus
 * the 320px access pane unless Compact is on. So 960 here is roughly a 1280px desktop with the
 * machine list showing, and 412 is a phone in the stacked layout where the list is a drawer.
 */
import { test, expect } from "@playwright/test";
import { openViewerPanel } from "./nav";
import { mkdirSync } from "fs";

const HARNESS = "http://127.0.0.1:5173/e2e/viewer_chrome.html";

/** Screenshots written here persist across Playwright runs (test-results/ is wiped each run). */
const EVIDENCE_DIR = "../evidence-menu-pass9";
try { mkdirSync(EVIDENCE_DIR, { recursive: true }); } catch { /* exists or not writable */ }

/** Width available to the Viewer, and what it stands for in the real shell. */
const WIDTHS = [
  { w: 1600, note: "wide desktop, machine list showing" },
  { w: 960, note: "1280px desktop, machine list showing" },
  { w: 700, note: "unfolded foldable, compact layout" },
  { w: 412, note: "phone, stacked layout" },
];

interface BarReport {
  present: boolean;
  height: number;
  /** Distinct flex rows, clustered from the children's vertical centres. */
  rows: number;
  /** Controls whose box is taller than one line of their own text — i.e. the label wrapped. */
  wrapped: string[];
}

interface ChromeReport {
  bars: Record<string, BarReport>;
  chromeTotal: number;
  surfaceHeight: number;
  viewportHeight: number;
}

/**
 * Measure in the browser. A control counts as WRAPPED when its content box exceeds 1.6 line-heights:
 * one line plus generous slack for descenders and differing metrics, well under the 2.0 a real second
 * line costs. Reported by label so a failure names the control, not just a number.
 */
async function measureChrome(page: import("@playwright/test").Page): Promise<ChromeReport> {
  return page.evaluate(() => {
    const barOf = (sel: string) => {
      const el = document.querySelector(sel) as HTMLElement | null;
      if (!el) return { present: false, height: 0, rows: 0, wrapped: [] as string[] };
      // Cluster children by their vertical CENTRE, not offsetTop. These bars are
      // `align-items: center`, so every child on the SAME visual row sits at a different offsetTop
      // according to its own height — the first version of this counted 11 "rows" inside an 89px
      // bar, which is three rows' worth of pixels. Centres of one row agree within a few px.
      const kids = Array.from(el.children) as HTMLElement[];
      const centres = kids
        .map((k) => {
          const r = k.getBoundingClientRect();
          return r.top + r.height / 2;
        })
        .sort((a, b) => a - b);
      let rowCount = 0;
      let rowAt = -Infinity;
      for (const c of centres) {
        if (c - rowAt > 6) {
          rowCount++;
          rowAt = c;
        }
      }
      const tops = { size: rowCount };
      const wrapped: string[] = [];
      const walk = (node: HTMLElement) => {
        for (const child of Array.from(node.children) as HTMLElement[]) {
          const cs = getComputedStyle(child);
          // `line-height: normal` is the CSS default and `parseFloat("normal")` is NaN, which the
          // finite-check below then skipped — so the FIRST version of this detector examined nothing
          // at all and every `wrapped` array was empty for that reason rather than because the layout
          // was sound. The negative control at the bottom of this file is what caught it. Fall back
          // to the usual ~1.2x font-size that "normal" resolves to.
          const lh = Number.isFinite(parseFloat(cs.lineHeight))
            ? parseFloat(cs.lineHeight)
            : parseFloat(cs.fontSize) * 1.2;
          const content =
            child.getBoundingClientRect().height -
            parseFloat(cs.paddingTop) -
            parseFloat(cs.paddingBottom) -
            parseFloat(cs.borderTopWidth) -
            parseFloat(cs.borderBottomWidth);
          const text = (child.textContent ?? "").trim();
          // Only leaf-ish controls: a container is SUPPOSED to be taller than one line.
          if (text && child.children.length === 0 && Number.isFinite(lh) && content > lh * 1.6) {
            wrapped.push(text.slice(0, 24));
          }
          walk(child);
        }
      };
      walk(el);
      return {
        present: true,
        height: Math.round(el.getBoundingClientRect().height),
        rows: tops.size,
        wrapped,
      };
    };

    const bars = {
      statusbar: barOf(".viewer__statusbar"),
      keys: barOf(".viewer__keys"),
    };
    const surface = document.querySelector(".viewer__surface") as HTMLElement | null;
    return {
      bars,
      chromeTotal: bars.statusbar.height + bars.keys.height,
      surfaceHeight: surface ? Math.round(surface.getBoundingClientRect().height) : 0,
      viewportHeight: window.innerHeight,
    };
  });
}

/**
 * The ceiling, in pixels, for the Viewer's own chrome at each width.
 *
 * These are NOT aspirational: they are the measured cost plus a small margin, so the test passes on
 * the code it was written against and fails on a regression. Tightening them is the point of any
 * chrome work — lower the number in the same commit that earns it, or the budget stops meaning
 * anything.
 */
const CHROME_BUDGET_PX: Record<number, number> = { 1600: 55, 960: 55, 700: 55, 412: 55 };

for (const { w, note } of WIDTHS) {
  test(`viewer chrome at ${w}px (${note}) stays inside its budget and nothing wraps`, async ({
    page,
  }) => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(HARNESS);
    // The status bar is the whole subject; without it the measurement below would report a
    // cheerful zero and pass.
    await expect(page.locator(".viewer__statusbar")).toBeVisible();

    const r = await measureChrome(page);

    // eslint-disable-next-line no-console -- the measurement IS the deliverable; a passing run that
    // printed nothing would leave the next person re-deriving these numbers by hand.
    console.log(
      `[chrome ${w}px] statusbar ${r.bars.statusbar.height}px/${r.bars.statusbar.rows} rows, ` +
        `keys ${r.bars.keys.height}px/${r.bars.keys.rows} rows, ` +
        `total ${r.chromeTotal}px of ${r.viewportHeight}px ` +
        `(${Math.round((r.chromeTotal / r.viewportHeight) * 100)}% of the window)`,
    );
    await page.screenshot({
      path: `${EVIDENCE_DIR}/viewer-chrome-closed-${w}.png`,
      clip: { x: 0, y: 0, width: w, height: Math.min(360, r.viewportHeight) },
    });

    expect(r.bars.statusbar.present, "the status bar must render at all").toBe(true);
    expect(r.bars.keys.present, "the special-keys bar must render at all").toBe(true);

    expect(
      r.bars.statusbar.wrapped,
      `status-bar controls wrapped onto a second line at ${w}px — this is the "Sign / out" failure, ` +
        `where the bar grows while every geometry check still passes`,
    ).toEqual([]);
    expect(r.bars.keys.wrapped, `special-keys controls wrapped at ${w}px`).toEqual([]);

    expect(
      r.chromeTotal,
      `the Viewer's chrome costs ${r.chromeTotal}px at ${w}px wide, over its ` +
        `${CHROME_BUDGET_PX[w]}px budget. That is space the remote desktop does not get.`,
    ).toBeLessThanOrEqual(CHROME_BUDGET_PX[w]);
  });
}

/**
 * NEGATIVE CONTROL for the wrap detector.
 *
 * Every assertion above expects `wrapped` to be EMPTY, and an empty array is exactly what a detector
 * that never fires returns. Without this test the whole wrapping half of this file could be dead code
 * pinning a constant, which is the failure [[inert-feature-caught-by-render-test]] describes: pair a
 * positive with a negative control or you are asserting nothing.
 *
 * It squeezes ONE real control until its label has to break, and asserts the detector names it.
 */
test("the wrap detector actually fires when a control is forced onto two lines", async ({ page }) => {
  await page.setViewportSize({ width: 1600, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  const clean = await measureChrome(page);
  expect(clean.bars.statusbar.wrapped, "premise: nothing wraps at 1600px before we break it").toEqual(
    [],
  );

  // Squeeze the "View ▾" trigger, whose label is two parts — the same shape as the real defect,
  // where "Sign out" broke after the space into "Sign / out".
  //
  // The first attempt squeezed "Disconnect" and the detector correctly stayed silent: a single
  // unbreakable word does not wrap, it overflows, and the box stays one line tall. That is a true
  // negative, not a miss — but it also meant this control was proving nothing, so it had to be a
  // label that genuinely CAN break.
  await page.addStyleTag({
    content: '[data-testid="viewer-view-menu"] { width: 20px !important; white-space: normal !important; }',
  });
  const broken = await measureChrome(page);

  expect(
    broken.bars.statusbar.wrapped.length,
    "the detector must report a control whose label was forced onto two lines",
  ).toBeGreaterThan(0);
  expect(broken.bars.statusbar.wrapped.join(" ")).toContain("View");
});

/**
 * Popping the desktop into its own window.
 *
 * THE FAILURE THIS IS REALLY GUARDING. React binds a tree's event listeners to its ROOT CONTAINER, so
 * the obvious implementation — `createPortal` into the child document — produces a desktop that
 * renders perfectly and silently ignores every click, because native events in the child bubble to
 * the CHILD document and never reach this one's container. A screenshot cannot see that and neither
 * can a height measurement. So this asserts the surface is present in the popup AND that a pointer
 * event on it is actually received, which is the half that would break.
 */
test("the desktop pops out into its own window, keeps its input, and comes back", async ({
  page,
  context,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();
  await expect(page.getByTestId("viewer-surface")).toBeVisible();

  await openViewerPanel(page, "view");
  const [popup] = await Promise.all([
    context.waitForEvent("page"),
    page.getByTestId("viewer-popout").click(),
  ]);
  await popup.waitForLoadState("domcontentloaded");

  // The desktop is THERE...
  const poppedSurface = popup.getByTestId("viewer-surface");
  await expect(poppedSurface).toBeVisible();
  // ...and it took the styling with it. A child window inherits no stylesheet at all, so this also
  // pins that the style cloning ran: an unstyled surface has no background of its own.
  const bg = await popup.evaluate(
    () => getComputedStyle(document.body).backgroundColor,
  );
  expect(bg, "the child document must have the app's styles cloned into it").not.toBe(
    "rgba(0, 0, 0, 0)",
  );

  // The console shows WHY it is not painting a desktop, rather than going blank.
  await expect(page.getByTestId("viewer-popped-placeholder")).toBeVisible();
  await expect(page.getByTestId("viewer-surface")).toHaveCount(0);

  // THE LOAD-BEARING ASSERTION: React events still reach the surface in the other window. Preview
  // mode reports the last input in the status bar, so a click in the POPUP has to change something
  // in the OPENER — which can only happen if the popped-out tree is live.
  //
  // It asserts the BUTTON-PRESS label ("btn 0 down"), not merely that the readout changed. The first
  // version checked `.not.toBe(before)` and a mutation that unwired `onMouseDown` entirely still
  // passed it: Playwright's `click()` moves the pointer first, so `onMouseMove` alone changed the
  // readout to "move x,y" and the test called that success. Only a mousedown can produce "btn".
  await poppedSurface.click({ position: { x: 60, y: 60 } });
  await expect
    .poll(async () => (await page.getByTestId("viewer-last-event").textContent()) ?? "", {
      message:
        "a CLICK inside the pop-out must reach the session — a move alone would prove only that the " +
        "pointer entered the window",
      timeout: 5000,
    })
    .toContain("btn");

  // KEYBOARD, which is a SEPARATE path from the pointer and broke independently. Keystrokes are
  // captured at WINDOW level, not on the surface, so a listener bound only to the opener sees nothing
  // once the desktop has its own window — the technician types and the guest receives nothing. The
  // same is true of the button-UP listener, whose absence leaves a mouse button stuck down on the
  // customer's machine after a drag released in the pop-out.
  await poppedSurface.click({ position: { x: 60, y: 60 } });
  await popup.keyboard.press("KeyA");
  await expect
    .poll(async () => (await page.getByTestId("viewer-last-event").textContent()) ?? "", {
      message: "a keystroke in the pop-out window must reach the session",
      timeout: 5000,
    })
    .toContain("key");

  // And it comes home.
  await page.getByTestId("viewer-popin").click();
  await expect(page.getByTestId("viewer-surface")).toBeVisible();
  await expect(page.getByTestId("viewer-popped-placeholder")).toHaveCount(0);
});


test("fit contains a live high-resolution video below the toolbars", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto(HARNESS);
  await page.locator(".viewer__video").waitFor();
  await page.evaluate(async () => {
    const canvas = document.createElement("canvas");
    canvas.width = 2560;
    canvas.height = 1440;
    canvas.getContext("2d")!.fillRect(0, 0, canvas.width, canvas.height);
    const video = document.querySelector("video")!;
    video.srcObject = canvas.captureStream(1);
    await video.play();
  });
  for (const size of [{ width: 1280, height: 720 }, { width: 960, height: 600 }]) {
    await page.setViewportSize(size);
    // A resize closes the View panel (it is placed for the old size), and it can land just after the panel
    // opened: open-and-click is retried as one step.
    await expect(async () => {
      await openViewerPanel(page, "view");
      await page.getByTestId("viewer-zoom-fit").click({ timeout: 2_000 });
    }).toPass({ timeout: 15_000 });
    await expect.poll(() => page.evaluate(() => {
      const surface = document.querySelector(".viewer__surface")!.getBoundingClientRect();
      const video = document.querySelector("video")!;
      return video.videoWidth === 2560 && surface.height > 0 &&
        surface.bottom <= innerHeight + 1 &&
        document.documentElement.scrollHeight <= innerHeight + 1;
    })).toBe(true);
  }
});

/** Fit must reset a zoomed live video and remain contained when the pop-out changes shape. */
test("pop-out Fit resets zoom and stays contained after both-axis resize", async ({ page, context }) => {
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto(HARNESS);
  await openViewerPanel(page, "view");
  const [popup] = await Promise.all([
    context.waitForEvent("page"),
    page.getByTestId("viewer-popout").click(),
  ]);
  await expect(popup.getByTestId("viewer-surface")).toBeVisible();
  await popup.evaluate(async () => {
    const canvas = document.createElement("canvas");
    canvas.width = 1920;
    canvas.height = 1080;
    canvas.getContext("2d")!.fillRect(0, 0, canvas.width, canvas.height);
    const video = document.querySelector("video")!;
    video.srcObject = canvas.captureStream(1);
    await video.play();
  });
  await expect.poll(() => popup.evaluate(() => {
    const video = document.querySelector("video")!;
    return [video.videoWidth, video.videoHeight];
  })).toEqual([1920, 1080]);

  const expectFit = async () => {
    await expect.poll(() => popup.evaluate(() => {
      const video = document.querySelector("video")!;
      const surface = document.querySelector<HTMLElement>(".viewer__surface")!;
      const sr = surface.getBoundingClientRect();
      const vr = video.getBoundingClientRect();
      const style = getComputedStyle(video);
      const matrix = new DOMMatrix(style.transform);
      const toolbar = document.querySelector<HTMLElement>('[data-testid="popout-controls"]')!.getBoundingClientRect();
      const close = (a: number, b: number) => Math.abs(a - b) <= 1;
      return {
        identity: matrix.isIdentity,
        contain: style.objectFit === "contain",
        videoFillsSurface: close(vr.left, sr.left) && close(vr.top, sr.top) &&
          close(vr.width, sr.width) && close(vr.height, sr.height),
        surfaceFillsWindow: close(sr.left, 0) && close(sr.top, toolbar.bottom) &&
          close(sr.width, innerWidth) && close(sr.bottom, innerHeight),
        // overflow:hidden can conceal an oversized child, so inspect each scroll extent too.
        noOverflow: [document.documentElement, document.body, surface].every(el =>
          el.scrollWidth <= el.clientWidth + 1 && el.scrollHeight <= el.clientHeight + 1),
      };
    }), { message: "Fit must show the whole video inside the pop-out on both axes" }).toEqual({
      identity: true, contain: true, videoFillsSurface: true,
      surfaceFillsWindow: true, noOverflow: true,
    });
  };

  for (const [width, height] of [[800, 600], [600, 800], [900, 400], [400, 700]]) {
    await popup.setViewportSize({ width, height });
    await openViewerPanel(page, "view");
    await page.getByTestId("viewer-zoom-in").click();
    await expect.poll(() => popup.evaluate(() =>
      new DOMMatrix(getComputedStyle(document.querySelector("video")!).transform).a,
    )).toBeGreaterThan(1.2);
    await openViewerPanel(page, "view");
    await page.getByTestId("viewer-zoom-fit").click();
    await expectFit();
    // Resizing at Fit must preserve the video geometry without another Fit click.
    await popup.setViewportSize({ width: width + 100, height: height + 80 });
    await expectFit();
  }
  await page.getByTestId("viewer-popin").click();
  await expect(popup.isClosed()).toBe(true);
});

/**
 * Narrow statusbar: the @container rule's overflow-x:auto is actually scrollable by wheel, and
 * Disconnect scrolls into view and is hittable. The existing chrome-budget tests cannot catch
 * overflow-x:hidden replacing overflow-x:auto — both keep the bar one row, within budget, unwrapped —
 * but hidden would make every off-screen control unreachable. This test exercises the scroll path
 * as the operator does: horizontal mouse-wheel, then an actual click, verified by a harness counter.
 */
test("the narrow statusbar scrolls by wheel and Disconnect is clickable after scrolling into view", async ({
  page,
}) => {
  await page.setViewportSize({ width: 412, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Computed overflow-x must be auto or scroll — hidden would pass scrollWidth>clientWidth but
  // refuse wheel input, so asserting the value pins the mechanism, not just the symptom.
  const overflowX = await page.evaluate(() =>
    getComputedStyle(document.querySelector(".viewer__statusbar")!).overflowX,
  );
  expect(overflowX, "statusbar overflow-x must be auto or scroll at 412px").toMatch(/^(auto|scroll)$/);

  // Content must actually overflow so the scroll is non-trivial.
  const overflows = await page.evaluate(() => {
    const b = document.querySelector(".viewer__statusbar") as HTMLElement;
    return b.scrollWidth > b.clientWidth;
  });
  expect(overflows, "statusbar content must exceed bar width at 412px").toBe(true);

  // Wheel right over the bar — this is how the operator reaches clipped controls on a pointer device.
  const { x, y } = await page.evaluate(() => {
    const r = document.querySelector(".viewer__statusbar")!.getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
  });
  await page.mouse.move(x, y);
  await page.mouse.wheel(5000, 0);

  // Poll until Disconnect is within the bar's visible bounds.
  await expect.poll(
    () => page.evaluate(() => {
      const barR = document.querySelector(".viewer__statusbar")!.getBoundingClientRect();
      const btnR = document.querySelector(".viewer__disconnect")!.getBoundingClientRect();
      return btnR.left >= barR.left - 1 && btnR.right <= barR.right + 1;
    }),
    { message: "Disconnect must scroll into the bar's visible area after wheeling right", timeout: 3000 },
  ).toBe(true);

  // Click and confirm the handler fires — geometrically in-bounds is necessary but not sufficient.
  const before = await page.evaluate(
    () => (window as unknown as { __disconnectClicks: number }).__disconnectClicks,
  );
  await page.click(".viewer__disconnect");
  expect(
    await page.evaluate(
      () => (window as unknown as { __disconnectClicks: number }).__disconnectClicks,
    ),
    "clicking Disconnect must invoke the handler",
  ).toBe(before + 1);
});

/**
 * Monitor-selection recovery.
 *
 * The Viewer must call onSelectMonitor exactly once with the new valid selection when the current
 * selection becomes invalid (monitor removed, or view-all shrinks to one screen). It must NOT call
 * it when the selection stays valid — even if dimensions, order, or the primary flag change — and
 * must NOT call it when monitors=[] (pre-discovery fallback) even though the local picker resets.
 *
 * The harness exposes window.__setMonitors(list) to drive list changes. setMonitorList() below
 * awaits window.__monitorUpdateCount (bumped by useEffect([monitors]) in the harness) so every
 * assertion runs after the relevant React commit with no sleeps.
 *
 * LIMITS: agent-side capture switching is covered by the live-session multimonitor e2e, not here.
 */

// COMPOSITE_MONITOR_ID = u32::MAX, the "view all" sentinel shared with the Rust agent.
const COMPOSITE_ID = 4294967295;
const HARNESS_EMPTY = HARNESS + "?start=empty";

type TMonitor = { id: number; label: string; width: number; height: number; primary?: boolean };

type HW = {
  __setMonitors: (m: TMonitor[]) => void;
  __monitorUpdateCount: number;
  __selectMonitorCalls: number[];
};

async function waitReady(page: import("@playwright/test").Page) {
  await page.waitForFunction(
    () => typeof (window as unknown as HW).__setMonitors === "function",
  );
}

/** Sets the monitor list and waits for the harness useEffect([monitors]) commit. */
async function setMonitorList(page: import("@playwright/test").Page, monitors: TMonitor[]) {
  const before = await page.evaluate(() => (window as unknown as HW).__monitorUpdateCount);
  await page.evaluate((m) => (window as unknown as HW).__setMonitors(m), monitors);
  await page.waitForFunction(
    (n) => (window as unknown as HW).__monitorUpdateCount > n,
    before,
  );
}

async function getSelectCalls(page: import("@playwright/test").Page): Promise<number[]> {
  return page.evaluate(() => [...(window as unknown as HW).__selectMonitorCalls]);
}

test("calls onSelectMonitor when the active monitor is removed from the list", async ({ page }) => {
  await page.goto(HARNESS);
  await waitReady(page);
  // Harness starts with monitors [0,1,2], primary=id0. activeMonitor=0 matches the primary so
  // no initial onSelectMonitor call.
  expect(await getSelectCalls(page)).toEqual([]);

  // Remove id 0 — the currently-selected monitor.
  await setMonitorList(page, [
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
  ]);

  // Viewer effect fires synchronously during the commit (before the counter bumps), so by the time
  // setMonitorList resolves the call is already recorded; poll is a safety net for the render cycle.
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([1]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("1");
});

test("calls onSelectMonitor when view-all becomes invalid after the list shrinks to one", async ({
  page,
}) => {
  await page.goto(HARNESS);
  await waitReady(page);

  // Select "View all" via the picker — the existing onMonitorChange wiring fires onSelectMonitor.
  await page.selectOption('[data-testid="viewer-monitor"]', String(COMPOSITE_ID));
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([COMPOSITE_ID]);

  // Shrink to one monitor — composite is now invalid.
  await setMonitorList(page, [
    { id: 0, label: "Monitor 1 (1920×1080)", width: 1920, height: 1080, primary: true },
  ]);

  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([COMPOSITE_ID, 0]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("0");
});

test("does not call onSelectMonitor when monitors=[] after a real selection; real list recovers once", async ({
  page,
}) => {
  await page.goto(HARNESS);
  await waitReady(page);

  // Pick id 2 so the selection is non-zero before discovery is lost.
  await page.selectOption('[data-testid="viewer-monitor"]', "2");
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([2]);

  // Drop the monitor list (agent restarting / pre-re-announcement).
  await setMonitorList(page, []);
  // Local picker must fall back to Display 1 (id 0) for presentation.
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("0");
  // No synthetic replacement must have been sent to the agent.
  expect(await getSelectCalls(page)).toEqual([2]);

  // Real list arrives with only id 1 → exactly one recovery callback.
  await setMonitorList(page, [{ id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 }]);
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([2, 1]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("1");
});

test("does not call onSelectMonitor when only dimensions change and the selection stays valid", async ({
  page,
}) => {
  await page.goto(HARNESS);
  await waitReady(page);
  expect(await getSelectCalls(page)).toEqual([]);

  // Same ids, different sizes — id 0 is still present so selection is valid.
  await setMonitorList(page, [
    { id: 0, label: "Monitor 1 (1920×1080)", width: 3840, height: 2160, primary: true },
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
  ]);
  // setMonitorList awaited the commit; the Viewer effect ran and found the selection valid.
  expect(await getSelectCalls(page)).toEqual([]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("0");
});

test("does not call onSelectMonitor when order or primary flag changes but selected id is still present", async ({
  page,
}) => {
  await page.goto(HARNESS);
  await waitReady(page);

  // Explicitly pick id 1.
  await page.selectOption('[data-testid="viewer-monitor"]', "1");
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([1]);

  // Reverse the order and flip the primary — id 1 is still present.
  await setMonitorList(page, [
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200, primary: true },
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 0, label: "Monitor 1 (1920×1080)", width: 1920, height: 1080 },
  ]);
  // Selection must remain id 1; no further callback.
  expect(await getSelectCalls(page)).toEqual([1]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("1");
});

test("does not call onSelectMonitor when the identical list is re-applied", async ({ page }) => {
  await page.goto(HARNESS);
  await waitReady(page);
  expect(await getSelectCalls(page)).toEqual([]);

  // Re-apply the exact same list the harness started with (new array reference, identical content).
  await setMonitorList(page, [
    { id: 0, label: "Monitor 1 (1920×1080)", width: 1920, height: 1080, primary: true },
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
  ]);
  expect(await getSelectCalls(page)).toEqual([]);
});

test("does not duplicate onSelectMonitor when the recovery list is re-applied", async ({ page }) => {
  await page.goto(HARNESS);
  await waitReady(page);

  // Trigger a recovery.
  await setMonitorList(page, [
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
  ]);
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([1]);

  // Re-apply the same list — id 1 is now the active and valid selection; no second callback.
  await setMonitorList(page, [
    { id: 1, label: "Monitor 2 (2560×1440)", width: 2560, height: 1440 },
    { id: 2, label: "Monitor 3 (1920×1200)", width: 1920, height: 1200 },
  ]);
  expect(await getSelectCalls(page)).toEqual([1]);
});

test("calls onSelectMonitor with the primary on the first real monitor announcement", async ({
  page,
}) => {
  // ?start=empty: component uses fallback Display1 (id 0) and holds off on any callback.
  await page.goto(HARNESS_EMPTY);
  await waitReady(page);
  expect(await getSelectCalls(page)).toEqual([]);

  // Primary is id 1 — leftmost monitor (id 0) is NOT the primary, the realistic case.
  await setMonitorList(page, [
    { id: 0, label: "Display 1", width: 1280, height: 1024 },
    { id: 1, label: "Display 2", width: 1920, height: 1080, primary: true },
  ]);
  await expect.poll(() => getSelectCalls(page), { timeout: 3000 }).toEqual([1]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("1");
});

test("does not call onSelectMonitor on first announcement when primary is already id 0", async ({
  page,
}) => {
  await page.goto(HARNESS_EMPTY);
  await waitReady(page);

  // Primary is id 0 — matches the component's initial activeMonitor; the two sides already agree.
  await setMonitorList(page, [
    { id: 0, label: "Display 1", width: 1920, height: 1080, primary: true },
    { id: 1, label: "Display 2", width: 2560, height: 1440 },
  ]);
  expect(await getSelectCalls(page)).toEqual([]);
  await expect(page.locator('[data-testid="viewer-monitor"]')).toHaveValue("0");
});

// ---------------------------------------------------------------------------
// Menu interaction tests — new for pass8 (codex-review-pass5 requirements)
// ---------------------------------------------------------------------------

/**
 * P1: Held modifier key must be released on the remote when a menu opens.
 *
 * Sequence: hold ControlLeft → click View menu (removes key listeners, must flush keyup)
 * → release ControlLeft (no listener, but flush already sent it).
 *
 * Assertions are against window.__inputLog (transport.send calls on ChannelId.Input=1), not
 * just viewer-last-event text. This ensures the flush path actually called transport.send — the
 * text label would update regardless of whether send was called, so it is insufficient alone.
 * No menu navigation events (non-Input channel) must appear between the keydown and flush.
 */
test("held modifier key is flushed as keyup when a menu opens", async ({ page }) => {
  // ControlLeft → Windows VK 0xa2 (162). Must match dom_input.ts keyCodeMap entry.
  const VK_CONTROL_LEFT = 0xa2;
  type InputLogEntry = { channel: number; byteLength: number; json: unknown };
  type InputLog = InputLogEntry[];
  const inputLog = () =>
    page.evaluate(() => (window as unknown as { __inputLog: InputLogEntry[] }).__inputLog);

  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Give focus to the main page body (not inside any input field).
  await page.locator("body").click();

  const logBeforeDown = await inputLog();
  const lenBeforeDown = logBeforeDown.length;

  // Hold ControlLeft — the keyboard capture effect should forward the keydown.
  await page.keyboard.down("ControlLeft");

  // Assert a send on ChannelId.Input (=1) appeared in the log for the keydown.
  await expect.poll(() => inputLog().then((l) => l.length), { timeout: 3000 }).toBeGreaterThan(lenBeforeDown);
  const logAfterDown: InputLog = await inputLog();
  const downEntry = logAfterDown[logAfterDown.length - 1];
  expect(
    downEntry.channel,
    "keydown must be sent on ChannelId.Input (1)",
  ).toBe(1);
  // Verify the actual key code and down=true in the decoded payload, not just channel/byteLength.
  // encodeInput produces { t: "Key", c: { code: VK, down: boolean } } — this pins the wire format.
  expect(
    downEntry.json,
    `keydown payload must encode ControlLeft (0x${VK_CONTROL_LEFT.toString(16)}) with down=true`,
  ).toMatchObject({ t: "Key", c: { code: VK_CONTROL_LEFT, down: true } });
  const lenAfterDown = logAfterDown.length;

  // Open a menu — this re-runs the keyboard effect; cleanup flushes the held key.
  await page.getByTestId("viewer-view-menu").click();

  // Assert another ChannelId.Input send appeared (the keyup flush from cleanup).
  await expect.poll(() => inputLog().then((l) => l.length), {
    message: "keyup flush must produce at least one more transport.send call",
    timeout: 3000,
  }).toBeGreaterThan(lenAfterDown);

  const logAfterFlush: InputLog = await inputLog();
  const flushEntries = logAfterFlush.slice(lenAfterDown);
  expect(
    flushEntries.every((e) => e.channel === 1),
    "every send between keydown and flush must be on ChannelId.Input — no menu navigation leaked",
  ).toBe(true);

  // Decode the flush payload and verify it is a keyup for ControlLeft (down=false).
  const flushEntry = flushEntries[flushEntries.length - 1];
  expect(
    flushEntry.json,
    `keyup flush must encode ControlLeft (0x${VK_CONTROL_LEFT.toString(16)}) with down=false`,
  ).toMatchObject({ t: "Key", c: { code: VK_CONTROL_LEFT, down: false } });

  // viewer-last-event must also confirm the keyup label (belt-and-suspenders).
  await expect
    .poll(
      () => page.getByTestId("viewer-last-event").textContent(),
      { message: "keyup for ControlLeft must be flushed when the menu opens", timeout: 3000 },
    )
    .toContain("key ControlLeft up");

  // Release the physical key (no-op since listeners are detached).
  await page.keyboard.up("ControlLeft");
});

/**
 * P2: All three overlay panels must stay within the visible viewer area when opened.
 *
 * Verified at 412px (phone / narrow mode where statusbar scrolls) and at a short embedded
 * height (600px) to catch vertical overflow. Screenshots of each open panel are saved as
 * evidence for the human reviewer.
 */
for (const { w, h, label } of [
  { w: 412, h: 900, label: "narrow-412" },
  { w: 1280, h: 300, label: "short-embedded" },
  { w: 1280, h: 900, label: "fullscreen-1280" },
]) {
  test(`all menu panels stay within viewer bounds at ${label} (${w}×${h})`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: h });
    await page.goto(HARNESS);
    await expect(page.locator(".viewer__statusbar")).toBeVisible();

    for (const trigger of ["viewer-view-menu", "viewer-input-menu", "viewer-tools-menu"] as const) {
      // Open the panel by clicking its trigger.
      await page.getByTestId(trigger).click();
      await expect(page.locator(".viewer__menupanel")).toBeVisible();

      const inBounds = await page.evaluate(() => {
        const viewer = document.querySelector(".viewer")!.getBoundingClientRect();
        const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
        return {
          leftOk: panel.left >= viewer.left - 1,
          rightOk: panel.right <= viewer.right + 1,
          topOk: panel.top >= viewer.top - 1,
          bottomOk: panel.bottom <= viewer.bottom + 1,
        };
      });

      // Save evidence screenshot with panel open.
      const name = trigger.replace("viewer-", "");
      await page.screenshot({
        path: `${EVIDENCE_DIR}/menu-bounds-${label}-${name}.png`,
        clip: { x: 0, y: 0, width: w, height: Math.min(h, 600) },
      });

      expect(
        inBounds.leftOk,
        `${trigger} panel left edge must not be outside viewer at ${label}`,
      ).toBe(true);
      expect(
        inBounds.rightOk,
        `${trigger} panel right edge must not overflow viewer at ${label}`,
      ).toBe(true);
      expect(
        inBounds.topOk,
        `${trigger} panel top must not be above viewer top at ${label}`,
      ).toBe(true);
      expect(
        inBounds.bottomOk,
        `${trigger} panel bottom must not exceed viewer bottom at ${label}`,
      ).toBe(true);

      // Close panel before opening the next.
      await page.keyboard.press("Escape");
      await expect(page.locator(".viewer__menupanel")).toHaveCount(0);
    }
  });
}

/**
 * P1+P2 (embedded viewer): panel must stay within the viewer's own bounds when it is a short
 * component embedded mid-page, and must be trigger-adjacent (not floating 650px above it).
 *
 * Scenario: viewport=900px, viewer pushed to y=650, height=200px (viewer.bottom=850). The
 * trigger is near the viewport floor, so the panel must FLIP ABOVE the trigger instead of opening
 * a zero-height slot below it. panelPos() detects available-below < PANEL_MIN_USEFUL_H and places
 * the panel above, anchored by `bottom` not `top`.
 *
 * The critical regression: without position:relative on .viewer, the panel anchors to the
 * viewport (a non-positioned ancestor), so "top: 35px" puts the panel at viewport y=35 — 650px
 * above the trigger. The screenshot in evidence-menu-pass9/menu-embedded-tools-menu.png shows
 * this exact failure.
 */
test("menu panel stays within embedded short viewer bounds when viewer is mid-page", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Push the viewer to y=650, constrain it to 200px — so viewer.bottom=850 < viewport.bottom=900.
  await page.addStyleTag({
    content: `#root { margin-top: 650px !important; height: 200px !important; }`,
  });
  // Wait for layout to settle after style injection.
  await page.waitForFunction(() => {
    const r = document.querySelector(".viewer")?.getBoundingClientRect();
    return r && r.top > 600;
  });
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  for (const trigger of ["viewer-view-menu", "viewer-input-menu", "viewer-tools-menu"] as const) {
    await page.getByTestId(trigger).click();
    await expect(page.locator(".viewer__menupanel")).toBeVisible();

    const bounds = await page.evaluate((testId) => {
      const viewer = document.querySelector(".viewer")!.getBoundingClientRect();
      const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
      const triggerEl = document.querySelector(`[data-testid="${testId}"]`)!.getBoundingClientRect();
      return {
        viewerTop: viewer.top,
        viewerBottom: viewer.bottom,
        viewerLeft: viewer.left,
        viewerRight: viewer.right,
        panelTop: panel.top,
        panelBottom: panel.bottom,
        panelLeft: panel.left,
        panelRight: panel.right,
        triggerTop: triggerEl.top,
        triggerBottom: triggerEl.bottom,
      };
    }, trigger);

    const name = trigger.replace("viewer-", "");
    await page.screenshot({ path: `${EVIDENCE_DIR}/menu-embedded-${name}.png` });

    // All 4 edges: panel must stay within the viewer rectangle.
    expect(bounds.panelTop, `${trigger} panel top must not be above viewer top (embedding fix)`).toBeGreaterThanOrEqual(bounds.viewerTop - 1);
    expect(bounds.panelBottom, `${trigger} panel bottom must not exceed viewer bottom (embedding fix)`).toBeLessThanOrEqual(bounds.viewerBottom + 1);
    expect(bounds.panelLeft, `${trigger} panel left must not be outside viewer left`).toBeGreaterThanOrEqual(bounds.viewerLeft - 1);
    expect(bounds.panelRight, `${trigger} panel right must not exceed viewer right`).toBeLessThanOrEqual(bounds.viewerRight + 1);

    // Trigger adjacency: the panel must be near the trigger (within the viewer), not 600px away.
    // With the flip, the panel appears ABOVE the trigger; panelBottom ≤ triggerTop.
    // Without position:relative fix, the panel floats at viewport y=35 while the trigger is at y≈660.
    const gapFromTrigger = Math.min(
      Math.abs(bounds.panelBottom - bounds.triggerTop),
      Math.abs(bounds.panelTop - bounds.triggerBottom),
    );
    expect(
      gapFromTrigger,
      `${trigger} panel must be near the trigger (<= viewer height away), not floating 600px above it. ` +
        `Gap was ${gapFromTrigger.toFixed(0)}px — a large gap means the containing block is wrong.`,
    ).toBeLessThanOrEqual(bounds.viewerBottom - bounds.viewerTop + 1);

    await page.keyboard.press("Escape");
    await expect(page.locator(".viewer__menupanel")).toHaveCount(0);
  }
});

/**
 * P2 (expanded content): opening the View panel and expanding advanced quality settings must not
 * push the panel outside the viewer. The old code clamped left by PANEL_MIN_W=200 with no
 * maxWidth, so content wider than 200px would overflow the viewer's right edge.
 */
test("View panel stays within viewer bounds after advanced quality is expanded", async ({ page }) => {
  await page.setViewportSize({ width: 700, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  await page.getByTestId("viewer-view-menu").click();
  await expect(page.locator(".viewer__menupanel")).toBeVisible();

  // Expand advanced quality rows — these controls can make the panel wider than PANEL_MIN_W.
  await page.getByTestId("viewer-quality-advanced").click();
  await expect(page.getByTestId("viewer-quality-panel")).toBeVisible();

  const bounds = await page.evaluate(() => {
    const viewer = document.querySelector(".viewer")!.getBoundingClientRect();
    const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
    return {
      viewerRight: viewer.right,
      panelRight: panel.right,
      viewerBottom: viewer.bottom,
      panelBottom: panel.bottom,
    };
  });

  await page.screenshot({ path: `${EVIDENCE_DIR}/menu-quality-expanded.png` });

  expect(
    bounds.panelRight,
    `View panel right (${bounds.panelRight.toFixed(0)}) must not exceed viewer right ` +
      `(${bounds.viewerRight.toFixed(0)}) after advanced quality is expanded`,
  ).toBeLessThanOrEqual(bounds.viewerRight + 1);
  expect(
    bounds.panelBottom,
    "View panel bottom must stay within viewport after advanced quality expansion",
  ).toBeLessThanOrEqual(bounds.viewerBottom + 1);
});

/**
 * P2 (trigger near right edge — very narrow viewer): at 280px the viewer is only 80px wider than
 * PANEL_MIN_W. The Tools trigger, which is the rightmost compact dropdown, may sit close to the
 * right boundary. With no maxWidth a panel whose content exceeds 200px would overflow; with the
 * fix the panel is capped to v.width − left and cannot spill past the viewer's right edge.
 */
test("all panels stay within bounds at 280px wide (trigger near right edge)", async ({ page }) => {
  await page.setViewportSize({ width: 280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  for (const trigger of ["viewer-view-menu", "viewer-input-menu", "viewer-tools-menu"] as const) {
    await page.getByTestId(trigger).click();
    // If the trigger is scrolled out of view at 280px it may not open — skip gracefully.
    const panelVisible = await page.locator(".viewer__menupanel").isVisible();
    if (!panelVisible) {
      continue;
    }

    const bounds = await page.evaluate(() => {
      const viewer = document.querySelector(".viewer")!.getBoundingClientRect();
      const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
      return {
        viewerRight: viewer.right,
        panelRight: panel.right,
        viewerLeft: viewer.left,
        panelLeft: panel.left,
        viewerBottom: viewer.bottom,
        panelBottom: panel.bottom,
      };
    });

    const name = trigger.replace("viewer-", "");
    await page.screenshot({ path: `${EVIDENCE_DIR}/menu-narrow280-${name}.png` });

    expect(
      bounds.panelRight,
      `${trigger} panel right (${bounds.panelRight.toFixed(0)}) must not exceed viewer right ` +
        `(${bounds.viewerRight.toFixed(0)}) at 280px`,
    ).toBeLessThanOrEqual(bounds.viewerRight + 1);
    expect(bounds.panelLeft, `${trigger} panel left must be within viewer at 280px`).toBeGreaterThanOrEqual(
      bounds.viewerLeft - 1,
    );

    await page.keyboard.press("Escape");
    await expect(page.locator(".viewer__menupanel")).toHaveCount(0);
  }
});

/**
 * Focus/lifecycle: Escape must close the panel AND return focus to the trigger button.
 */
test("Escape closes menu and restores keyboard focus to the trigger button", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  for (const { trigger, testId } of [
    { trigger: "viewer-view-menu", testId: "viewer-view-menu" },
    { trigger: "viewer-input-menu", testId: "viewer-input-menu" },
    { trigger: "viewer-tools-menu", testId: "viewer-tools-menu" },
  ]) {
    await page.getByTestId(trigger).click();
    await expect(page.locator(".viewer__menupanel")).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(page.locator(".viewer__menupanel")).toHaveCount(0);

    const focused = await page.evaluate(
      () => document.activeElement?.getAttribute("data-testid") ?? "",
    );
    expect(
      focused,
      `focus must return to ${testId} after Escape`,
    ).toBe(testId);
  }
});

/**
 * Focus/lifecycle: dismissing the Tools panel via outside-click must reset shutdown armed state
 * so reopening never shows the confirm dialog from a previous session.
 */
test("outside-click dismissal resets shutdown armed state before Tools panel is reopened", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Open Tools panel.
  await page.getByTestId("viewer-tools-menu").click();
  await expect(page.locator(".viewer__menupanel")).toBeVisible();

  // Arm Shut Down.
  await page.getByTestId("viewer-shutdown").click();
  await expect(page.getByTestId("viewer-shutdown-confirm")).toBeVisible();

  // Click outside panel to dismiss.
  await page.mouse.click(10, 10);
  await expect(page.locator(".viewer__menupanel")).toHaveCount(0);

  // Reopen — should start fresh, not armed.
  await page.getByTestId("viewer-tools-menu").click();
  await expect(page.locator(".viewer__menupanel")).toBeVisible();
  await expect(page.getByTestId("viewer-shutdown")).toBeVisible();
  await expect(page.getByTestId("viewer-shutdown-confirm")).toHaveCount(0);
});

/**
 * Focus/lifecycle: the command toggle remains visible in the Tools panel and the elevated-run
 * button is present in the command bar. When command text is entered and the session is not
 * view-only, elevated-run is enabled — this guards the viewOnly gate that moved with the code.
 */
test("command toggle is visible in Tools panel; elevated-run is enabled after typing when not view-only", async ({
  page,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  await page.getByTestId("viewer-tools-menu").click();
  await expect(page.getByTestId("viewer-command-toggle")).toBeVisible();

  // Open command bar (clicking toggle closes the Tools panel and opens the command bar inline).
  await page.getByTestId("viewer-command-toggle").click();
  await expect(page.getByTestId("viewer-command-panel")).toBeVisible();
  await expect(page.getByTestId("viewer-command-run")).toBeVisible();
  await expect(page.getByTestId("viewer-command-elevate")).toBeVisible();

  // Without text both buttons are disabled by design (empty command is meaningless).
  await expect(page.getByTestId("viewer-command-elevate")).toBeDisabled();

  // Type a command — elevated-run must become enabled because viewOnly=false in the harness.
  await page.getByTestId("viewer-command-input").fill("whoami");
  await expect(page.getByTestId("viewer-command-elevate")).not.toBeDisabled();
});

/**
 * P1 + popout: keyboard input in the popout window must still reach the remote while a menu is
 * open in the main console window. This tests that anyMenuOpen only suppresses the MAIN window's
 * keyboard listeners, not the popout's.
 */
test("popout keyboard still reaches remote while a menu is open in the main console", async ({
  page,
  context,
}) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Pop the desktop out.
  await openViewerPanel(page, "view");
  const [popup] = await Promise.all([
    context.waitForEvent("page"),
    page.getByTestId("viewer-popout").click(),
  ]);
  await popup.waitForLoadState("domcontentloaded");
  await expect(popup.getByTestId("viewer-surface")).toBeVisible();

  // Open a menu in the main window.
  await page.getByTestId("viewer-view-menu").click();
  await expect(page.locator(".viewer__menupanel")).toBeVisible();

  // Click the popout surface so popout has focus for keyboard events.
  await popup.getByTestId("viewer-surface").click({ position: { x: 60, y: 60 } });

  // Type in the popout — the keyboard effect must still be active for the popout window.
  await popup.keyboard.press("KeyA");

  // The last-event readout in the OPENER updates because keyboard listeners run in this component.
  await expect
    .poll(
      async () => (await page.getByTestId("viewer-last-event").textContent()) ?? "",
      { message: "keystroke in popout must reach the remote even while main menu is open", timeout: 5000 },
    )
    .toContain("key");

  // Close the popout cleanly.
  await page.getByTestId("viewer-popin").click();
  await expect(popup.isClosed()).toBe(true);
});

/**
 * P2 (expanded system tools): every SYSTEM_TOOLS button inside the Tools panel must be reachable
 * by pointer at 280px and 412px. Without the flex-wrap fix, the buttons form a single horizontal
 * row that gets clipped by overflow-x:hidden — they are present in the DOM but pointer events
 * land on the overflow edge rather than the button face.
 *
 * Flow: open Tools panel → click inner "Tools ▾" to expand SYSTEM_TOOLS → assert each button is
 * within the panel's visible rectangle → click each to confirm the handler fires (panel closes).
 */
for (const w of [280, 412]) {
  test(`all system-tool buttons are within panel bounds and clickable at ${w}px`, async ({ page }) => {
    await page.setViewportSize({ width: w, height: 900 });
    await page.goto(HARNESS);
    await expect(page.locator(".viewer__statusbar")).toBeVisible();

    const toolsTrigger = page.getByTestId("viewer-tools-menu");
    // The statusbar scrolls at narrow widths — scroll the trigger into view before clicking.
    await toolsTrigger.scrollIntoViewIfNeeded();
    await toolsTrigger.click();
    const panelVisible = await page.locator(".viewer__menupanel").isVisible();
    if (!panelVisible) return; // Tools trigger scrolled off at extreme narrow width — skip.

    // Expand the system-tools submenu inside the panel.
    await page.getByTestId("viewer-tools").click();
    await expect(page.getByTestId("viewer-tool-task_manager")).toBeVisible();

    // Every tool button must lie INSIDE the panel's visible rectangle (all 4 edges).
    // overflow-x:hidden would clip a single-row expansion so the rightmost buttons are invisible.
    const toolsInPanel = await page.evaluate(() => {
      const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
      const tools = Array.from(
        document.querySelectorAll("[data-testid^='viewer-tool-']"),
      );
      return tools.map((el) => {
        const r = el.getBoundingClientRect();
        return {
          id: el.getAttribute("data-testid") ?? "",
          inBounds:
            r.left >= panel.left - 1 &&
            r.right <= panel.right + 1 &&
            r.top >= panel.top - 1 &&
            r.bottom <= panel.bottom + 1 &&
            r.width > 0 &&
            r.height > 0,
        };
      });
    });

    await page.screenshot({
      path: `${EVIDENCE_DIR}/menu-tools-expanded-${w}.png`,
      clip: { x: 0, y: 0, width: w, height: 900 },
    });

    for (const tool of toolsInPanel) {
      expect(
        tool.inBounds,
        `${tool.id} must be within panel bounds at ${w}px — a single-row expansion clipped by overflow-x:hidden would fail here`,
      ).toBe(true);
    }

    // Close the panel before the click loop (it is still open from the in-bounds check above).
    await page.keyboard.press("Escape");
    await expect(page.locator(".viewer__menupanel")).toHaveCount(0);

    // Click each tool to confirm the pointer event actually reaches the button face.
    // Each click calls setToolsPanelOpen(false) → panel disappears (confirms the click landed).
    for (const testId of ["viewer-tool-task_manager", "viewer-tool-registry_editor", "viewer-tool-event_viewer"]) {
      // Reopen for each click since clicking a tool closes the panel.
      await toolsTrigger.scrollIntoViewIfNeeded();
      await toolsTrigger.click();
      await expect(page.locator(".viewer__menupanel")).toBeVisible();
      await page.getByTestId("viewer-tools").click();
      await expect(page.getByTestId(testId)).toBeVisible();
      await page.getByTestId(testId).click();
      await expect(page.locator(".viewer__menupanel"), `clicking ${testId} must close the panel`).toHaveCount(0);
    }
  });
}

/**
 * P2 (near-bottom trigger): a trigger near the viewer floor must flip the panel ABOVE the trigger
 * with usable height, not open a zero-content-height slot below it.
 *
 * Setup: 900px viewport, viewer pushed to y=400 via margin-top so viewer.bottom≈480px.
 * The trigger (statusbar) sits near viewer.bottom; below-space ≈ 500px - 480 - 16 = 4px < 80px
 * (PANEL_MIN_USEFUL_H), so panelPos() must flip above where ~400px of space is available.
 *
 * panelPos() condition: belowH < PANEL_MIN_USEFUL_H AND belowH < aboveH → use above placement.
 * aboveH = t.top - max(v.top,0) - 16 ≈ 470 - 400 - 16 = 54px (trigger at v.top + ~70px).
 * Actually trigger is within 80px viewer, so aboveH can be small too — but belowH is ~4px which
 * is less than aboveH (~54px), so above wins and panel.bottom ≤ triggerTop.
 */
test("near-bottom trigger flips panel above the trigger with usable height", async ({ page }) => {
  // 900px viewport with viewer pushed 400px down — trigger is near viewer.bottom, lots above.
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();

  // Push the viewer element down so its bottom is near the middle of the viewport.
  await page.addStyleTag({
    content: `#root { margin-top: 400px !important; height: 80px !important; overflow: visible !important; }`,
  });

  await page.getByTestId("viewer-view-menu").click();
  await expect(page.locator(".viewer__menupanel")).toBeVisible();

  const result = await page.evaluate(() => {
    const viewer = document.querySelector(".viewer")!.getBoundingClientRect();
    const panel = document.querySelector(".viewer__menupanel")!.getBoundingClientRect();
    const trigger = document.querySelector("[data-testid='viewer-view-menu']")!.getBoundingClientRect();
    return {
      panelTop: panel.top,
      panelBottom: panel.bottom,
      panelHeight: panel.height,
      triggerTop: trigger.top,
      triggerBottom: trigger.bottom,
      viewerTop: viewer.top,
      viewerBottom: viewer.bottom,
    };
  });

  await page.screenshot({
    path: `${EVIDENCE_DIR}/menu-near-bottom-flip.png`,
    clip: { x: 0, y: 390, width: 1280, height: 510 },
  });

  // Panel must have usable height — a maxHeight:0 fit that renders empty is not a success.
  expect(result.panelHeight, "panel must have positive height when it flips above the trigger").toBeGreaterThan(0);

  // Panel must not go above the viewport (y=0), even though it may exceed viewer.top.
  expect(result.panelTop, "flipped panel must not exceed the top of the viewport").toBeGreaterThanOrEqual(0);

  // Flip assertion: when the trigger is near viewer.bottom, the panel appears above the trigger.
  // panelBottom ≤ triggerTop confirms the panel is fully above the trigger row.
  expect(
    result.panelBottom,
    `panel bottom (${result.panelBottom.toFixed(0)}) must be at or above trigger top ` +
      `(${result.triggerTop.toFixed(0)}) when flip is active`,
  ).toBeLessThanOrEqual(result.triggerTop + 1);
});

/**
 * Menu redesign wave 9: Log off is two-step. It asks, naming the consequence; Cancel and an outside click send nothing
 * and leave it unarmed; Confirm sends exactly one LogOff.
 */
test("Log off asks first; Cancel and dismissal send nothing, Confirm sends one", async ({ page }) => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(HARNESS);
  await expect(page.locator(".viewer__statusbar")).toBeVisible();
  const logoffs = () => page.evaluate(() => (window as unknown as { __logoffs?: number }).__logoffs ?? 0);

  await page.getByTestId("viewer-tools-menu").click();
  await page.getByTestId("viewer-logoff").click();
  await expect(page.getByTestId("viewer-logoff-question")).toContainText("Their open apps close and unsaved work is lost.");
  await page.getByTestId("viewer-logoff-cancel").click();
  await expect(page.getByTestId("viewer-logoff")).toBeVisible();
  expect(await logoffs()).toBe(0);

  // Armed, then dismissed by an outside click: reopening starts unarmed.
  await page.getByTestId("viewer-logoff").click();
  await page.mouse.click(10, 10);
  await expect(page.locator(".viewer__menupanel")).toHaveCount(0);
  await page.getByTestId("viewer-tools-menu").click();
  await expect(page.getByTestId("viewer-logoff-confirm")).toHaveCount(0);
  expect(await logoffs()).toBe(0);

  await page.getByTestId("viewer-logoff").click();
  await page.getByTestId("viewer-logoff-confirm").click();
  await expect.poll(logoffs).toBe(1);
  await expect(page.locator(".viewer__menupanel")).toHaveCount(0);
});
