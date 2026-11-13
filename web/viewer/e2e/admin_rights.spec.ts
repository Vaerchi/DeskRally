/**
 * docs/53: "Request admin rights" in the real App, against a fake agent peer.
 *
 * Proves App.tsx wires AdminRightsAvailable → the Session menu control, the click → a
 * RequestAdminRights frame on the control channel, each AdminRightsResult → its status, and that
 * teardown clears it all for the next session.
 *
 * Mutation evidence per test:
 *   1: dropping onAdminRightsAvailable's setAdminRights → no control; dropping requestAdminRights()
 *      → no frame; dropping onAdminRightsResult's setAdminRights → status never reaches "granted".
 *   2: (the view rule) an unavailable agent's reason is the disabled button's title.
 *   3: dropping setAdminRights(NO_ADMIN_RIGHTS) from teardown → the old control survives.
 *
 * Follows download_wiring.spec.ts: RTCPeerConnection is stubbed, no agent or signaling server.
 */

import { test, expect, type Page } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

async function fixture(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions" && method === "POST") {
      return route.fulfill({ json: { session: { id: "s1" }, signaling: { url: "ws://127.0.0.1:5188/ws", ticket: {} } } });
    }
    if (path.endsWith("/policy")) {
      return route.fulfill({
        status: 200,
        json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9_999_999_999_999 } },
      });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
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
      // The control messages the App sent (channel 0), decoded.
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

const agent = (page: Page, i: number, message: unknown) =>
  page.evaluate(([n, m]) => (window as any).peers[n as number].control(m), [i, message] as const);

async function openSessionMenu(page: Page) {
  await page.getByRole("button", { name: "Session", exact: true }).click();
}

test("advertised, requested, granted, ended: the control follows the agent", async ({ page }) => {
  await fixture(page);
  await openSessionMenu(page);
  await expect(page.getByTestId("admin-rights")).toHaveCount(0);

  await agent(page, 0, { t: "AdminRightsAvailable", c: { available: true, reason: null } });
  const button = page.getByTestId("admin-rights-request");
  await expect(button).toBeEnabled();
  await button.click();
  await expect
    .poll(() => page.evaluate(() => (window as any).peers[0].controlSent().filter((m: any) => m.t === "RequestAdminRights").length))
    .toBe(1);
  await expect(page.getByTestId("admin-rights-status")).toHaveText("Waiting for the guest to approve…");
  await expect(page.getByTestId("admin-rights-hint")).toContainText("only on the guest's screen");
  await expect(button).toBeDisabled();

  await agent(page, 0, { t: "AdminRightsResult", c: { state: "pending", reason: null } });
  await agent(page, 0, { t: "AdminRightsResult", c: { state: "granted", reason: null } });
  await expect(page.getByTestId("admin-rights-status")).toHaveText("Admin rights granted");
  await expect(button).toBeDisabled();

  await agent(page, 0, { t: "AdminRightsResult", c: { state: "ended", reason: null } });
  await expect(page.getByTestId("admin-rights-status")).toHaveText("Admin rights ended");
  await expect(page.getByTestId("admin-rights-hint")).toHaveCount(0);
  await expect(button).toBeEnabled();
});

test("an agent that cannot says why, and the button stays disabled", async ({ page }) => {
  await fixture(page);
  await agent(page, 0, { t: "AdminRightsAvailable", c: { available: false, reason: "the signed-in user is not an administrator" } });
  await openSessionMenu(page);
  const button = page.getByTestId("admin-rights-request");
  await expect(button).toBeDisabled();
  await expect(button).toHaveAttribute("title", "the signed-in user is not an administrator");
});

test("teardown clears it: the next session shows nothing until its own agent advertises", async ({ page }) => {
  await fixture(page);
  await agent(page, 0, { t: "AdminRightsAvailable", c: { available: true, reason: null } });
  await openSessionMenu(page);
  await expect(page.getByTestId("admin-rights-request")).toBeEnabled();
  await page.keyboard.press("Escape");
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers[1].connected());
  await openSessionMenu(page);
  await expect(page.getByTestId("admin-rights")).toHaveCount(0);
});
