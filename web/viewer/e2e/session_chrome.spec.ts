/**
 * Session chrome (lib/session_chrome.ts): during a live session the top bar collapses behind a small
 * tab on the top edge, Chrome Remote Desktop style, with the monitor switcher kept one click away.
 *
 * This spec deliberately opts OUT of the "pinned" seed every other spec gets (e2e/chrome_pinned.ts) —
 * it tests the product default. The fake peer follows admin_rights.spec.ts: RTCPeerConnection is
 * stubbed, no agent or signaling server, and the session itself succeeds (no app error, which would
 * force the bar open).
 */

import { test, expect, type Page } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

// Empty storage = the real default (minimal), overriding the config-level pinned seed.
test.use({ storageState: { cookies: [], origins: [] } });

async function connect(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions" && method === "POST") {
      return route.fulfill({ json: { session: { id: "s1" }, signaling: { url: "ws://127.0.0.1:5189/ws", ticket: {} } } });
    }
    if (path.endsWith("/policy")) {
      return route.fulfill({
        status: 200,
        json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9_999_999_999_999 } },
      });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5189/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class FakeDC {
      readyState = "open";
      sent: any[] = [];
      onmessage: any = null;
      onclose: any = null;
      send(bytes: ArrayBuffer): void {
        this.sent.push(bytes);
      }
      close(): void {
        this.readyState = "closed";
        this.onclose?.();
      }
    }
    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      dc = new FakeDC();
      constructor() {
        w.peers.push(this);
      }
      createDataChannel() {
        return this.dc;
      }
      addTransceiver() {}
      close() {
        this.connectionState = "closed";
        this.onconnectionstatechange?.();
      }
      getStats() {
        return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 1 }]]));
      }
      connected() {
        this.connectionState = "connected";
        this.onconnectionstatechange?.();
      }
      control(message: unknown) {
        const bytes = new TextEncoder().encode(JSON.stringify(message));
        const frame = new Uint8Array(5 + bytes.length);
        new DataView(frame.buffer).setUint32(1, bytes.length);
        frame.set(bytes, 5);
        this.dc.onmessage?.({ data: frame.buffer });
      }
      controlSent(): unknown[] {
        return this.dc.sent.flatMap((b: ArrayBuffer) => {
          const v = new Uint8Array(b);
          if (v[0] !== 0) return [];
          try {
            return [JSON.parse(new TextDecoder().decode(v.slice(5)))];
          } catch {
            return [];
          }
        });
      }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
}

const TWO_MONITORS = [
  { id: 10, width: 1920, height: 1080, primary: true },
  { id: 20, width: 2560, height: 1440, primary: false },
];

async function advertise(page: Page, monitors: unknown[]) {
  await page.evaluate((m) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors: m } }), monitors);
}

const selectsSent = (page: Page) =>
  page.evaluate(() => (window as any).peers[0].controlSent().filter((m: any) => m.t === "SelectMonitor").map((m: any) => m.c.id));

test("a live session collapses the top bar behind the tab", async ({ page }) => {
  await connect(page);
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
  await expect(page.getByTestId("session-tab")).toBeVisible();
  await expect(page.getByTestId("session-tab-status")).toBeVisible();
  // The whole row is gone, so the remote screen starts at the top of the window.
  await expect(page.locator(".app__topbar")).toBeHidden();
  await expect(page.getByRole("button", { name: "Session", exact: true })).toBeHidden();
});

test("the tab switches monitors in one click", async ({ page }) => {
  await connect(page);
  await advertise(page, TWO_MONITORS);
  const two = page.getByTestId("session-tab-monitor-2");
  await expect(page.getByTestId("session-tab-monitor-1")).toBeVisible();
  await expect(two).toBeVisible();
  await expect(page.getByTestId("session-tab-monitor-All")).toBeVisible();
  await two.click();
  // The SECOND advertised monitor (id 20) — numbering is by position, the id is what is sent.
  await expect.poll(() => selectsSent(page)).toContain(20);
  await expect(two).toHaveAttribute("aria-pressed", "true");
  // Still collapsed: switching displays did not need the bar.
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
});

test("the tab enters full screen in one click; Exit brings the tab back", async ({ page }) => {
  await connect(page);
  const fs = page.getByTestId("session-tab-fullscreen");
  await expect(fs).toBeVisible();
  await fs.click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement !== null)).toBe(true);
  // In full screen the inline bar carries Exit in the View panel (the tab is not shown there).
  await expect(fs).toBeHidden();
  await page.getByTestId("viewer-view-menu").click();
  const exit = page.getByTestId("viewer-fullscreen");
  await expect(exit).toHaveAttribute("aria-pressed", "true");
  await exit.click();
  await expect.poll(() => page.evaluate(() => document.fullscreenElement === null)).toBe(true);
  await expect(page.getByTestId("session-tab-fullscreen")).toBeVisible();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
});

test("a single monitor shows no monitor buttons", async ({ page }) => {
  await connect(page);
  await advertise(page, [TWO_MONITORS[0]]);
  await expect(page.getByTestId("session-tab-status")).toBeVisible();
  await expect(page.locator(".session-tab__monitor")).toHaveCount(0);
});

test("▾ drops the bar over the screen without moving it, ▴ collapses it again", async ({ page }) => {
  await connect(page);
  await advertise(page, TWO_MONITORS);
  const before = await page.getByTestId("viewer-surface").boundingBox();

  await page.getByTestId("session-tab-toggle").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "overlay");
  await expect(page.locator(".app__topbar")).toBeVisible();
  await expect(page.getByTestId("session-tab")).toBeHidden();
  // Every control is reachable from the dropped bar.
  await expect(page.getByRole("button", { name: "Session", exact: true })).toBeVisible();
  await expect(page.getByTestId("viewer-monitor")).toBeVisible();
  // OVERLAY: the remote image did not resize or jump.
  const during = await page.getByTestId("viewer-surface").boundingBox();
  expect(during!.y).toBeCloseTo(before!.y, 0);
  expect(during!.height).toBeCloseTo(before!.height, 0);

  await page.getByTestId("session-chrome-collapse").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
  await expect(page.getByTestId("session-tab")).toBeVisible();
});

test("Pin keeps today's bar and persists; Hide bar returns to the tab", async ({ page }) => {
  await connect(page);
  await page.getByTestId("session-tab-toggle").click();
  await page.getByTestId("session-chrome-pin").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "pinned");
  await expect(page.locator(".app__topbar")).toBeVisible();
  await expect(page.getByTestId("session-tab")).toHaveCount(0);
  expect(await page.evaluate(() => localStorage.getItem("deskrally.sessionChrome"))).toBe("pinned");

  // "Hide toolbar" lives in the Session menu (the row has no room for another button).
  await page.getByRole("button", { name: "Session", exact: true }).click();
  await page.getByTestId("session-chrome-unpin").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
  expect(await page.evaluate(() => localStorage.getItem("deskrally.sessionChrome"))).toBe("minimal");
});

// Menu redesign wave 7: the Session menu is labelled sections; "More" is gone (wave 7b), its controls in the
// View panel ("Size and window", beside the quality readout) and the Tools panel (Recording).
test("the Session menu groups its controls in labelled sections, and More is folded into View", async ({ page }) => {
  await connect(page);
  await page.getByTestId("session-tab-toggle").click();
  await page.getByTestId("session-chrome-pin").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "pinned");

  await page.getByRole("button", { name: "Session", exact: true }).click();
  await expect(page.getByTestId("session-menu-identity")).toBeVisible();
  const clipboard = page.getByRole("group", { name: "Clipboard", exact: true });
  await expect(clipboard).toBeVisible();
  const connection = page.getByRole("group", { name: "Connection", exact: true });
  await expect(connection.getByTestId("session-chrome-unpin")).toBeVisible();
  await page.getByRole("button", { name: "Session", exact: true }).click();

  await expect(page.getByRole("button", { name: "More", exact: true })).toHaveCount(0);
  await page.getByTestId("viewer-view-menu").click();
  await expect(page.getByTestId("viewer-view-window").getByTestId("viewer-zoom-fit")).toBeVisible();
  await expect(page.getByTestId("viewer-quality-readout")).toBeVisible();
  await page.getByTestId("viewer-view-menu").click();
});

// Focus follows each transition rather than falling to <body> when the pressed button disappears.
// Transitions are triggered by CLICK: while input capture is on, the keyboard belongs to the remote
// (Viewer's window-level capture sends Enter on a focused toolbar button to the guest, by design), so
// keyboard activation is not the path under test — where focus LANDS is.
test("focus follows the bar instead of dropping to the page", async ({ page }) => {
  await connect(page);
  const toggle = page.getByTestId("session-tab-toggle");
  await toggle.click();
  // ▾ vanished with the overlay open: focus is on ▴, ready to close it again.
  await expect(page.getByTestId("session-chrome-collapse")).toBeFocused();
  await page.getByTestId("session-chrome-collapse").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
  await expect(toggle).toBeFocused();
  // Pin: the hanging Pin button disappears; focus lands on a control in the now-pinned bar.
  await toggle.click();
  await page.getByTestId("session-chrome-pin").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "pinned");
  await expect(page.getByTestId("app-help")).toBeFocused();
});

test("the session ending while focus is in the dropped bar does not drop focus to the page", async ({ page }) => {
  await connect(page);
  await page.getByTestId("session-tab-toggle").click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "overlay");
  // Disconnect lives in the dropped bar; ending the session removes the bar's session controls.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "normal");
  await expect(page.getByTestId("app-help")).toBeFocused();
  expect(await page.evaluate(() => document.activeElement === document.body)).toBe(false);
});

test("a session starting never pulls focus into the chrome (negative control)", async ({ page }) => {
  await connect(page);
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
  // Focus was never in the chrome (the operator clicked Connect in the machine pane), so the mode change
  // to "collapsed" must not have moved it onto the tab.
  await expect(page.getByTestId("session-tab-toggle")).not.toBeFocused();
});

for (const width of [390, 412]) {
  test(`no horizontal overflow at ${width}px, collapsed or dropped`, async ({ page }) => {
    // Connect at the default width (the manual-connect field is in the machine drawer on phones),
    // then narrow the window; the layout reflows live.
    await connect(page);
    await page.setViewportSize({ width, height: 900 });
    const fits = () => page.evaluate(() => document.documentElement.scrollWidth <= innerWidth);
    await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
    expect(await fits()).toBe(true);
    await page.getByTestId("session-tab-toggle").click();
    await expect(page.locator(".app")).toHaveAttribute("data-chrome", "overlay");
    await expect(page.getByTestId("session-chrome-collapse")).toBeInViewport();
    expect(await fits()).toBe(true);
  });
}

test("no live session: the ordinary console bar, no tab", async ({ page }) => {
  await page.route("**/cp/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    return route.fulfill({ json: { machines: [], presence_known: true } });
  });
  await page.goto(test.info().project.use.baseURL!);
  await expect(page.locator(".app")).toHaveAttribute("data-chrome", "normal");
  await expect(page.locator(".app__topbar")).toBeVisible();
  await expect(page.getByTestId("session-tab")).toHaveCount(0);
});
