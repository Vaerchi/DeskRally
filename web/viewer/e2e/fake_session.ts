/**
 * A fake live session for specs that drive the REAL App without an agent or signaling server: the control
 * plane is routed, RTCPeerConnection is stubbed (admin_rights.spec.ts did it first), and the session
 * succeeds with no app error (an error would force the session bar open). Copied from
 * session_chrome.spec.ts, which keeps its own copy so that spec stays exactly as it was.
 *
 * window.peers[0] is the fake peer; controlSent() and inputSent() decode what the viewer sent.
 */
import { expect, test, type Page } from "@playwright/test";

import { openManualConnect } from "./manual_connect";

export async function connect(page: Page) {
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
      frames = 0;
      getStats() {
        // A counter that keeps moving: a constant one reads as a stalled stream after 20 s (session_recovery.ts)
        // and pauses input, which these specs need to type.
        this.frames += 1;
        return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }]]));
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
      framesOn(channel: number): unknown[] {
        return this.dc.sent.flatMap((b: ArrayBuffer) => {
          const v = new Uint8Array(b);
          if (v[0] !== channel) return [];
          try {
            return [JSON.parse(new TextDecoder().decode(v.slice(5)))];
          } catch {
            return [];
          }
        });
      }
      controlSent(): unknown[] {
        return this.framesOn(0);
      }
      /** Input channel (1): the events the agent would receive. */
      inputSent(): unknown[] {
        return this.framesOn(1);
      }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  // At phone widths the machine list is an off-canvas drawer: open it before reaching the connect form.
  await expect(page.locator(".app")).toHaveAttribute("data-pane-mode", /.+/);
  const drawer = page.getByTestId("app-nav-toggle");
  if ((await drawer.isVisible()) && (await drawer.getAttribute("aria-expanded")) !== "true") await drawer.click();
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
}

export const TWO_MONITORS = [
  { id: 10, width: 1920, height: 1080, primary: true },
  { id: 20, width: 2560, height: 1440, primary: false },
];

export async function advertise(page: Page, monitors: unknown[]) {
  await page.evaluate((m) => (window as any).peers[0].control({ t: "MonitorList", c: { monitors: m } }), monitors);
}


export const selectsSent = (page: Page) =>
  page.evaluate(() => (window as any).peers[0].controlSent().filter((m: any) => m.t === "SelectMonitor").map((m: any) => m.c.id));

export const inputSent = (page: Page): Promise<any[]> => page.evaluate(() => (window as any).peers[0].inputSent());
