import { consoleTab } from "./nav";
import { test, expect, type Page } from "@playwright/test";

// Toolbox script parameters in a bulk run (docs/75 D8): the confirm step shows one input per name in the script's
// own param() block, Run waits for the Mandatory ones, and every machine's run request carries the same values.

const ITEM = {
  id: "t-params", name: "Reset account", description: "", scope: "shared", shell: "powershell", run_as: "system",
  body: "param(\n  [Parameter(Mandatory)][string]$User,\n  [string]$NewPassword,\n  [int]$Days = 30\n)\nWrite-Output $User",
  body_sha256: "0".repeat(64), version: 3, updated_at: "2026-11-24T00:00:00Z", mine: false,
};

async function fixture(page: Page) {
  const server = { runs: [] as { session_id: string; expected_version: number; params?: Record<string, string> }[] };
  const machines = [
    { device_id: "device-1", name: "First" },
    { device_id: "device-2", name: "Second" },
  ].map(machine => ({ id: machine.device_id, tenant_id: "tenant", group_id: "group", online: true, status: "active", ...machine }));
  await page.route(/.*/, route => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  let starts = 0;
  await page.route("**/cp/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines, presence_known: true } });
    if (path === "/cp/sessions") {
      if (request.method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      starts++;
      return route.fulfill({ json: { session: { id: `session-${starts}` }, signaling: { url: "ws://127.0.0.1:5187/ws", ticket: {} } } });
    }
    if (/\/sessions\/[^/]+\/end$/.test(path)) return route.fulfill({ json: {} });
    if (path === "/cp/toolbox") return route.fulfill({ json: { items: [ITEM], can_manage_shared: false } });
    if (path === `/cp/toolbox/${ITEM.id}/runs`) {
      server.runs.push(request.postDataJSON());
      return route.fulfill({ json: { request_id: `run-${server.runs.length}`, shell: ITEM.shell, run_as: ITEM.run_as, command: "AUTHORIZED" } });
    }
    if (path === "/cp/audit/ingest") return route.fulfill({ json: {} });
    if (path.endsWith("/policy")) return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5187/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      onicecandidate: any;
      dc: any = {
        readyState: "open", sent: [] as ArrayBuffer[],
        send(bytes: ArrayBuffer) { this.sent.push(bytes); },
        close() { this.readyState = "closed"; this.onclose?.(); },
      };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; }
      addTransceiver() {}
      getStats() { return Promise.resolve(new Map()); }
      close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  await (await consoleTab(page, { name: "Toolbox", exact: true })).click();
  await page.getByTestId(`toolbox-bulk-${ITEM.id}`).click();
  await expect(page.getByTestId("bulk-machine-device-1")).toBeChecked();
  return server;
}

test("a bulk run shows the script's parameters, requires Mandatory ones, and sends the values to every machine", async ({ page }) => {
  const server = await fixture(page);
  await page.getByTestId("bulk-confirm").click();
  await expect(page.getByTestId("bulk-params")).toBeVisible();
  // One input per param() name; a secret-looking name is a password field; the default shows as a placeholder.
  await expect(page.getByTestId("bulk-param-User")).toHaveAttribute("type", "text");
  await expect(page.getByTestId("bulk-param-NewPassword")).toHaveAttribute("type", "password");
  await expect(page.getByTestId("bulk-param-Days")).toHaveAttribute("placeholder", "30");
  // Mandatory User is empty: Run is held and says why.
  await expect(page.getByTestId("bulk-run")).toBeDisabled();
  await expect(page.getByTestId("bulk-param-issue")).toHaveText("User is required.");
  await page.getByTestId("bulk-param-User").fill("alice");
  await page.getByTestId("bulk-param-NewPassword").fill("it's $(x)");
  await expect(page.getByTestId("bulk-run")).toBeEnabled();
  await page.getByTestId("bulk-run").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers.forEach((peer: any) => { peer.connected(); peer.dc.onopen?.(); }));
  await expect.poll(() => server.runs.length).toBe(2);
  // Same values on every machine; the untouched Days is left to the script's default (not sent).
  for (const run of server.runs) {
    expect(run.expected_version).toBe(3);
    expect(run.params).toEqual({ User: "alice", NewPassword: "it's $(x)" });
  }
});
