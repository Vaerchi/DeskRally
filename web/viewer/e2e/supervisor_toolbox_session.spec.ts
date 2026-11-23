import { test, expect, type Page } from "@playwright/test";
import { openViewerPanel } from "./nav";
import { openManualConnect } from "./manual_connect";

const FIRST = {
  id: "t-first", name: "Disk usage", description: "free space", scope: "shared", shell: "powershell", run_as: "system",
  body: "Get-PSDrive", body_sha256: "0".repeat(64), version: 1, updated_at: "2026-10-16T00:00:00Z", mine: false,
};
const SECOND = { ...FIRST, id: "t-second", name: "Processes", body: "Get-Process" };

async function fixture(page: Page, status = 200) {
  await page.clock.install();
  const server = { items: [FIRST], status, gets: 0, hold: false, release: () => {} };
  await page.route(/.*/, route => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") {
      if (route.request().method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      return route.fulfill({ json: { session: { id: "session-1" }, signaling: { url: "ws://127.0.0.1:5188/ws", ticket: {} } } });
    }
    if (path === "/cp/toolbox" && route.request().method() === "GET") {
      server.gets++;
      if (server.hold) await new Promise<void>(resolve => { server.release = resolve; });
      return route.fulfill({ status: server.status, json: server.status === 200
        ? { items: server.items, can_manage_shared: false, max_powershell_bytes: 16384, max_cmd_units: 7800 }
        : { error: "temporary listing failure" } });
    }
    if (path.endsWith("/policy")) return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    return route.fulfill({ json: { session: { id: "session-1" } } });
  });
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any; w.peers = [];
    class Peer {
      connectionState = "new"; onconnectionstatechange: any; ontrack: any; onicecandidate: any; frames = 1;
      dc: any = { readyState: "open", sent: [] as ArrayBuffer[], send(bytes: ArrayBuffer) { this.sent.push(bytes); }, close() { this.readyState = "closed"; this.onclose?.(); } };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; } addTransceiver() {} close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() { return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }]])); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  // The Command panel lives in the Tools dropdown; open it before inspecting its Toolbox row.
  await openViewerPanel(page, "tools");
  await page.getByTestId("viewer-command-toggle").click();
  await expect.poll(() => server.gets).toBe(1);
  return server;
}

test("refresh replaces the listing and clears a removed selection", async ({ page }) => {
  const server = await fixture(page);
  const select = page.getByTestId("viewer-toolbox-select");
  await expect(select.locator("option")).toHaveText(["Toolbox…", "Disk usage"]);
  await select.selectOption(FIRST.id);
  await expect(page.getByTestId("viewer-toolbox-run")).toBeEnabled();
  server.items = [SECOND];
  server.hold = true;
  await page.getByTestId("viewer-toolbox-refresh").click();
  await expect.poll(() => server.gets).toBe(2);
  await expect(select).toHaveValue(FIRST.id);
  await expect(select.locator("option")).toHaveText(["Toolbox…", "Disk usage"]);
  await expect(page.getByTestId("viewer-toolbox-loading")).toHaveCount(0);
  server.release();
  await expect(select.locator("option")).toHaveText(["Toolbox…", "Processes"]);
  await expect(select).toHaveValue("");
  await expect(page.getByTestId("viewer-toolbox-run")).toBeDisabled();
  expect(server.gets).toBe(2);
});

test("a failed first listing can be retried from the unavailable row", async ({ page }) => {
  const server = await fixture(page, 500);
  const unavailable = page.getByTestId("viewer-toolbox-unavailable");
  await expect(unavailable).toBeVisible();
  server.status = 200;
  await unavailable.getByTestId("viewer-toolbox-refresh").click();
  await expect(page.getByTestId("viewer-toolbox-select").locator("option")).toHaveText(["Toolbox…", "Disk usage"]);
  await expect(unavailable).toHaveCount(0);
  expect(server.gets).toBe(2);
});

test("a server change alone does not update the session listing", async ({ page }) => {
  const server = await fixture(page);
  const select = page.getByTestId("viewer-toolbox-select");
  await expect(select.locator("option")).toHaveText(["Toolbox…", "Disk usage"]);
  server.items = [SECOND];
  await select.selectOption(FIRST.id);
  await page.clock.runFor(1000);
  await expect(page.getByTestId("viewer-toolbox-preview")).toBeVisible();
  await expect(select.locator("option")).toHaveText(["Toolbox…", "Disk usage"]);
  expect(server.gets).toBe(1);
});
