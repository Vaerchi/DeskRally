/**
 * Trackpad pointer mode on a phone: toggle -> move -> click -> right click -> scroll -> hold-drag ->
 * Left press-and-hold -> scroll strip, against the real Viewer with a recording transport
 * (e2e/trackpad.tsx), under the `mobile-phone` and `mobile-foldable` projects (touch emulation).
 *
 * Touches go through CDP `Input.dispatchTouchEvent`, the only way Playwright can send MULTI-touch
 * (two-finger tap / scroll). What reaches the agent is read from the transport's `window.__logs`.
 * The pure rules (acceleration, clamping, the stuck-button invariant) are unit-tested in
 * `src/lib/trackpad.test.ts`; this proves the wiring: the cursor drawn, taps landing at the CURSOR
 * not the finger, the controls' down/up pairing, and the mode switch releasing a held button.
 */
import { test, expect, type Page, type CDPSession } from "@playwright/test";
import { openViewerPanel } from "./nav";

const URL_ = "/e2e/trackpad.html";
type Ev = { t: string; c: Record<string, unknown> };
type P = { x: number; y: number };

const logs = (page: Page) => page.evaluate(() => (window as unknown as { __logs: Ev[] }).__logs.slice());
const clearLogs = (page: Page) =>
  page.evaluate(() => {
    (window as unknown as { __logs: Ev[] }).__logs.length = 0;
  });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const centre = async (page: Page, id: string): Promise<P> => {
  const b = (await page.getByTestId(id).boundingBox())!;
  return { x: b.x + b.width / 2, y: b.y + b.height / 2 };
};

async function touchApi(page: Page) {
  const cdp: CDPSession = await page.context().newCDPSession(page);
  const pts = (ps: P[]) => ps.map((p, i) => ({ x: p.x, y: p.y, id: i + 1 }));
  const api = {
    start: (ps: P[]) => cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: pts(ps) }),
    move: (ps: P[]) => cdp.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: pts(ps) }),
    end: () => cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] }),
    /** A one-finger drag from a to b in paced steps. */
    async drag(a: P, b: P, steps = 8) {
      await api.start([a]);
      for (let i = 1; i <= steps; i++) {
        await api.move([{ x: a.x + ((b.x - a.x) * i) / steps, y: a.y + ((b.y - a.y) * i) / steps }]);
        await sleep(25);
      }
      await api.end();
    },
  };
  return api;
}

const moves = (evs: Ev[]) => evs.filter((e) => e.t === "MouseMove");
const buttons = (evs: Ev[]) =>
  evs.filter((e) => e.t === "MouseButton").map((e) => `${e.c.button}:${e.c.down ? "down" : "up"}`);
const scrolls = (evs: Ev[]) => evs.filter((e) => e.t === "Scroll");

async function ready(page: Page) {
  await page.goto(URL_);
  await expect.poll(() => page.locator("video").first().evaluate((v: HTMLVideoElement) => v.videoWidth)).toBe(400);
}
async function enableTrackpad(page: Page) {
  await openViewerPanel(page, "input");
  await page.getByTestId("viewer-trackpad-toggle").tap();
  await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  await expect(page.getByTestId("trackpad-bar")).toBeVisible();
}

test("off by default: direct touch is untouched and there is no cursor or bar", async ({ page }) => {
  await ready(page);
  await expect(page.getByTestId("trackpad-cursor")).toHaveCount(0);
  await expect(page.getByTestId("trackpad-bar")).toHaveCount(0);
});

test("toggle, move, click at the cursor, right click, scroll", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const surface = (await page.getByTestId("viewer-surface").boundingBox())!;
  const t = await touchApi(page);

  // Move: drag the finger in the upper-left area; the cursor (initially centre) moves by the travel.
  const fx0 = Number(await page.getByTestId("trackpad-cursor").getAttribute("data-fx"));
  await clearLogs(page);
  const from = { x: surface.x + 60, y: surface.y + 100 };
  await t.drag(from, { x: from.x + 80, y: from.y }, 8);
  const afterMove = await logs(page);
  expect(moves(afterMove).length).toBeGreaterThan(0);
  expect(buttons(afterMove), "a drag must not click").toEqual([]);
  const fx1 = Number(await page.getByTestId("trackpad-cursor").getAttribute("data-fx"));
  expect(fx1).toBeGreaterThan(fx0);
  const cursorAbs = moves(afterMove).at(-1)!.c as { x: number; y: number };

  // Tap FAR from the cursor (top-left corner): the click lands at the cursor, never under the finger.
  await clearLogs(page);
  await page.touchscreen.tap(surface.x + 6, surface.y + 6);
  await expect.poll(async () => buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
  const tap = await logs(page);
  const at = moves(tap)[0].c as { x: number; y: number };
  expect(Math.abs(at.x - cursorAbs.x)).toBeLessThan(400);
  expect(at.x, "not the top-left corner the finger touched").toBeGreaterThan(5000);
  await sleep(1200); // the touch-echo mouse events must not add a second click
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);

  // Two-finger tap = right click.
  await clearLogs(page);
  const c = { x: surface.x + surface.width / 2, y: surface.y + 120 };
  await t.start([
    { x: c.x - 30, y: c.y },
    { x: c.x + 30, y: c.y },
  ]);
  await sleep(60);
  await t.end();
  await expect.poll(async () => buttons(await logs(page))).toEqual(["Right:down", "Right:up"]);

  // Two-finger drag UP scrolls the page DOWN (natural direction): agent Scroll dy < 0.
  await clearLogs(page);
  await t.start([
    { x: c.x - 30, y: c.y + 100 },
    { x: c.x + 30, y: c.y + 100 },
  ]);
  for (let i = 1; i <= 8; i++) {
    await t.move([
      { x: c.x - 30, y: c.y + 100 - i * 15 },
      { x: c.x + 30, y: c.y + 100 - i * 15 },
    ]);
    await sleep(20);
  }
  await t.end();
  const sc = scrolls(await logs(page));
  expect(sc.length).toBeGreaterThan(0);
  expect(sc.every((e) => (e.c.dy as number) < 0)).toBe(true);
  expect(buttons(await logs(page)), "a scroll must not click").toEqual([]);
});

test("Hold latches the button so a one-finger drag drags, and tapping it again releases", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const surface = (await page.getByTestId("viewer-surface").boundingBox())!;
  const t = await touchApi(page);

  await clearLogs(page);
  await page.getByTestId("trackpad-hold").tap();
  await expect(page.getByTestId("trackpad-hold")).toHaveAttribute("aria-pressed", "true");
  await t.drag({ x: surface.x + 60, y: surface.y + 100 }, { x: surface.x + 140, y: surface.y + 100 });
  await sleep(1100); // echo mouse events after the touches must not release the latch
  let evs = await logs(page);
  expect(buttons(evs)).toEqual(["Left:down"]);
  expect(evs.map((e) => e.t).indexOf("MouseButton")).toBeLessThan(evs.map((e) => e.t).lastIndexOf("MouseMove"));
  // Release via a click, not a touch tap: after a CDP touch drag, Chrome intermittently (about 3 in 10)
  // delivers pointerdown/pointerup/touchend for the next tap but NEVER generates its click (confirmed
  // with capture listeners), so no page code could react. That is a gesture-detector artifact of the
  // emulation, not a defect; the first Hold tap and every other tap in this file are unaffected.
  await page.getByTestId("trackpad-hold").dispatchEvent("click");
  await expect(page.getByTestId("trackpad-hold")).toHaveAttribute("aria-pressed", "false");
  evs = await logs(page);
  expect(buttons(evs)).toEqual(["Left:down", "Left:up"]);
});

test("Left press-and-hold is one down and one up", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const t = await touchApi(page);
  const left = await centre(page, "trackpad-left");
  await clearLogs(page);
  await t.start([left]); // thumb on [Left]
  await sleep(150);
  expect(buttons(await logs(page))).toEqual(["Left:down"]);
  await t.end();
  await expect.poll(async () => buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
});

test("the scroll strip scrolls on drag and steps on tap", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const t = await touchApi(page);
  const sb = (await page.getByTestId("trackpad-scroll").boundingBox())!;
  const mid = { x: sb.x + sb.width / 2, y: sb.y + sb.height / 2 };

  await clearLogs(page);
  await t.drag(mid, { x: mid.x, y: mid.y - 60 }, 6); // drag UP -> page scrolls DOWN
  let sc = scrolls(await logs(page));
  expect(sc.length).toBeGreaterThan(0);
  expect(sc.every((e) => (e.c.dy as number) < 0)).toBe(true);

  await clearLogs(page);
  await page.touchscreen.tap(mid.x, sb.y + sb.height - 12); // bottom half: one notch down
  await expect.poll(async () => scrolls(await logs(page)).length).toBe(1);
  sc = scrolls(await logs(page));
  expect(sc[0].c.dy).toBe(-1);
});

test("turning the mode off while Hold is latched releases the button", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  await clearLogs(page);
  await page.getByTestId("trackpad-hold").tap();
  expect(buttons(await logs(page))).toEqual(["Left:down"]);
  await openViewerPanel(page, "input");
  await page.getByTestId("viewer-trackpad-toggle").tap();
  await expect(page.getByTestId("trackpad-cursor")).toHaveCount(0);
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
});

test("the choice is remembered per device, and sensitivity is offered", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  await openViewerPanel(page, "input");
  await expect(page.getByTestId("viewer-trackpad-sens-normal")).toHaveAttribute("aria-pressed", "true");
  await page.getByTestId("viewer-trackpad-sens-high").tap();
  await expect(page.getByTestId("viewer-trackpad-sens-high")).toHaveAttribute("aria-pressed", "true");
  await page.reload();
  await expect(page.getByTestId("trackpad-cursor")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("deskrally.trackpad.sensitivity"))).toBe("high");
});

test("the controls are labelled, at least 44px, and collapsible", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  for (const id of ["trackpad-left", "trackpad-hold", "trackpad-right", "trackpad-collapse"]) {
    const b = (await page.getByTestId(id).boundingBox())!;
    expect(b.height, id).toBeGreaterThanOrEqual(44);
    expect(b.width, id).toBeGreaterThanOrEqual(44);
    await expect(page.getByTestId(id)).toHaveAttribute("aria-label", /.+/);
  }
  await expect(page.getByTestId("trackpad-scroll")).toHaveAttribute("aria-label", /scroll/i);
  await page.getByTestId("trackpad-collapse").tap();
  await expect(page.getByTestId("trackpad-left")).toHaveCount(0);
  await page.getByTestId("trackpad-expand").tap();
  await expect(page.getByTestId("trackpad-left")).toBeVisible();
});

test("a physical mouse press and release during Hold neither re-presses nor releases the remote button", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const surface = (await page.getByTestId("viewer-surface").boundingBox())!;
  await clearLogs(page);
  await page.getByTestId("trackpad-hold").tap();
  expect(buttons(await logs(page))).toEqual(["Left:down"]);
  await page.mouse.move(surface.x + 40, surface.y + 60);
  await page.mouse.down();
  await page.mouse.up();
  expect(buttons(await logs(page)), "Hold still owns the button").toEqual(["Left:down"]);
  await page.getByTestId("trackpad-hold").tap();
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
});

test("keyboard Left: tabbing away while Space is held releases the button", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  await clearLogs(page);
  await page.getByTestId("trackpad-left").focus();
  await page.keyboard.down("Space");
  expect(buttons(await logs(page))).toEqual(["Left:down"]);
  // Space/Tab on a trackpad control belong to the control: nothing may leak to the guest as a key.
  const nonPointer = async () => (await logs(page)).filter((e) => e.t !== "MouseButton" && e.t !== "MouseMove");
  expect(await nonPointer()).toEqual([]);
  await page.keyboard.press("Tab"); // focus leaves [Left]; the Space keyup will land elsewhere
  await expect.poll(async () => buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
  await page.keyboard.up("Space");
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
  expect(await nonPointer()).toEqual([]);
});

test("a bare click on Left (assistive tech) is a full click", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  await clearLogs(page);
  await page.getByTestId("trackpad-left").dispatchEvent("click");
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
});

test("a burst of finger moves is coalesced, not forwarded one for one", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  const surface = (await page.getByTestId("viewer-surface").boundingBox())!;
  const t = await touchApi(page);
  await clearLogs(page);
  const a = { x: surface.x + 40, y: surface.y + 100 };
  await t.start([a]);
  for (let i = 1; i <= 60; i++) await t.move([{ x: a.x + i * 2, y: a.y }]);
  await t.end();
  await sleep(100);
  const n = moves(await logs(page)).length;
  expect(n).toBeGreaterThan(0);
  expect(n).toBeLessThan(60);
});

test("Left: a tapped press yields exactly one down/up, and an independent click after Tab still activates", async ({ page }) => {
  await ready(page);
  await enableTrackpad(page);
  await clearLogs(page);
  await page.getByTestId("trackpad-left").tap();
  await sleep(600); // the click generated by that press must have been suppressed, not doubled
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
  await clearLogs(page);
  await sleep(500); // let the press window lapse
  await page.getByTestId("trackpad-hold").focus();
  await page.keyboard.press("Tab"); // Tab arrives on the next control; not a press of [Left]
  await page.getByTestId("trackpad-left").dispatchEvent("click"); // screen-reader style activation
  expect(buttons(await logs(page))).toEqual(["Left:down", "Left:up"]);
});
