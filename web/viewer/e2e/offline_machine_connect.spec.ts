import { test, expect, type Page } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

// Connecting to a machine whose agent is not registered with signaling: signaling answers the
// connect_request with exactly one `rejected` ("device … is not registered or offline"). The viewer
// used to reach recovery only through the transport's own timeout, with a generic "Connection
// lost". It now says the machine is OFFLINE immediately, retries with backoff (each retry ending
// the previous record), and connects as soon as the agent is back. Negative control: on the old
// App.tsx this spec fails at the "is offline" assertion.
const DEVICE = "00112233-4455-6677-8899-aabbccddeeff";

async function fixture(page: Page) {
  await page.clock.install();
  const state = { starts: 0, ended: [] as string[], renewals: 0, renewalPaths: [] as string[], offline: true, connectRequests: 0 };
  await page.route(/.*/, (route) => (new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort()));
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") {
      if (route.request().method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      state.starts++;
      return route.fulfill({ json: { session: { id: `session-${state.starts}` }, signaling: { url: "ws://127.0.0.1:5189/ws", ticket: {} } } });
    }
    if (path.endsWith("/policy")) {
      state.renewals++;
      state.renewalPaths.push(path);
      return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    }
    if (path.endsWith("/end")) state.ended.push(path);
    return route.fulfill({ json: { session: { id: "ended" } } });
  });
  await page.routeWebSocket("ws://127.0.0.1:5189/ws", (ws) => {
    ws.onMessage((raw) => {
      const msg = JSON.parse(String(raw)) as { type?: string };
      if (msg.type !== "connect_request") return;
      state.connectRequests++;
      if (state.offline) ws.send(JSON.stringify({ type: "rejected", reason: `device ${DEVICE} is not registered or offline` }));
    });
  });
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class Peer {
      connectionState = "new"; onconnectionstatechange: any; ontrack: any; onicecandidate: any;
      dc: any = { readyState: "open", sent: [] as ArrayBuffer[], send(b: ArrayBuffer) { this.sent.push(b); }, close() { this.readyState = "closed"; this.onclose?.(); } };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; } addTransceiver() {} close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() { return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 1 }]])); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill(DEVICE);
  await page.getByTestId("manual-connect").click();
  return state;
}

test("an offline machine says so and connects once its agent is back", async ({ page }) => {
  const state = await fixture(page);
  await expect.poll(() => state.connectRequests).toBe(1);
  // The rejection is explained, not left as "connecting".
  await expect(page.getByTestId("viewer-recovery")).toContainText("is offline");
  await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnecting");
  // Still offline at the first retry (2 s): a second attempt, which replaces (ends) the first record.
  await page.clock.runFor(2500);
  await expect.poll(() => state.connectRequests).toBe(2);
  await expect.poll(() => state.ended.includes("/cp/sessions/session-1/end")).toBe(true);
  await expect(page.getByTestId("viewer-recovery")).toContainText("is offline");
  // The agent comes back: the next retry brokers and connects, and the notice clears.
  state.offline = false;
  await page.clock.runFor(4500);
  await expect.poll(() => state.connectRequests).toBe(3);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBeGreaterThan(0);
  await page.evaluate(() => { const w = window as any; w.peers[w.peers.length - 1].connected(); });
  await expect(page.getByTestId("viewer-recovery")).toHaveCount(0);
});
