import { consoleTab } from "./nav";
import { test, expect, type Page } from "@playwright/test";

const ITEM = {
  id: "t-bulk", name: "Disk usage", description: "free space", scope: "shared", shell: "powershell", run_as: "system",
  body: "Get-PSDrive", body_sha256: "0".repeat(64), version: 1, updated_at: "2026-10-16T00:00:00Z", mine: false,
};
const OUTPUT = '<img src=x onerror="window.bulkInjected=true">';

async function fixture(page: Page) {
  const server = { starts: [] as string[], runs: [] as string[], ends: [] as string[] };
  const machines = [
    { device_id: "device-1", name: "=FORMULA" },
    { device_id: "device-2", name: "Second" },
    { device_id: "device-3", name: "Third" },
    { device_id: "device-4", name: "Fourth" },
    { device_id: "busy", name: "Busy" },
    { device_id: "offline", name: "Offline", online: false },
    { device_id: "unknown", name: "Unknown", online: undefined },
    { device_id: "attended", name: "Attended", ephemeral: true },
    { device_id: "quarantined", name: "Quarantined", status: "quarantined" },
    { device_id: "retired", name: "Retired", status: "retired" },
  ].map(machine => ({ id: machine.device_id, tenant_id: "tenant", group_id: "group", online: true, status: "active", ...machine }));
  await page.route(/.*/, route => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines, presence_known: true } });
    if (path === "/cp/sessions") {
      if (request.method() !== "POST") return route.fulfill({ json: { sessions: [{ id: "busy-session", machine_id: "busy", machine_device_id: "busy", ended_at: null }] } });
      server.starts.push(request.postDataJSON().machine_id);
      const id = `session-${server.starts.length}`;
      return route.fulfill({ json: { session: { id }, signaling: { url: "ws://127.0.0.1:5188/ws", ticket: {} } } });
    }
    if (/\/sessions\/[^/]+\/end$/.test(path)) {
      server.ends.push(path);
      return route.fulfill({ json: {} });
    }
    if (path === "/cp/toolbox") return route.fulfill({ json: { items: [ITEM], can_manage_shared: false } });
    if (path === `/cp/toolbox/${ITEM.id}/runs`) {
      server.runs.push(request.postDataJSON().session_id);
      return route.fulfill({ json: { request_id: `run-${server.runs.length}`, shell: ITEM.shell, run_as: ITEM.run_as, command: ITEM.body } });
    }
    if (path === "/cp/audit/ingest") return route.fulfill({ json: {} });
    if (path.endsWith("/policy")) return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
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

async function choose(page: Page, ids: string[]) {
  for (const id of ["device-1", "device-2", "device-3", "device-4", "busy"]) {
    await page.getByTestId(`bulk-machine-${id}`).setChecked(ids.includes(id));
  }
}

async function run(page: Page) {
  await page.getByTestId("bulk-confirm").click();
  await page.getByTestId("bulk-run").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(3);
  // A real data channel fires onopen once negotiated; the core waits for it (design v2 readiness).
  await page.evaluate(() => (window as any).peers.forEach((peer: any) => { peer.connected(); peer.dc.onopen?.(); }));
}

// Use the production codec so results traverse the actual data-channel and ControlClient path.
async function control(page: Page, peerIndex: number, message: unknown) {
  // The wire frame the agent sends: channel byte (Control = 0), u32 big-endian length, JSON payload
  // (the same hand-built frame supervisor_session_recovery.spec.ts uses).
  await page.evaluate(({ peerIndex, message }) => {
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    const frame = new Uint8Array(5 + bytes.length);
    new DataView(frame.buffer).setUint32(1, bytes.length);
    frame.set(bytes, 5);
    (window as any).peers[peerIndex].dc.onmessage({ data: frame.buffer });
  }, { peerIndex, message });
}

async function results(page: Page) {
  for (let index = 0; index < 3; index++) {
    await control(page, index, { t: "CommandResult", c: { exit_code: index, stdout: `${OUTPUT}\npeer-${index}`, stderr: "", truncated: index === 2, timed_out: false } });
  }
}

test("only eligible machines are selectable and busy machines start unselected", async ({ page }) => {
  await fixture(page);
  for (const id of ["offline", "unknown", "attended", "quarantined", "retired"]) {
    await expect(page.getByTestId(`bulk-machine-${id}`)).toBeDisabled();
    await expect(page.getByTestId(`bulk-machine-${id}`)).not.toBeChecked();
  }
  await expect(page.getByTestId("bulk-machine-busy")).toBeEnabled();
  await expect(page.getByTestId("bulk-machine-busy")).not.toBeChecked();
  await expect(page.getByTestId("bulk-machine-busy").locator("..")).toContainText("in session");
});

test("three machines finish with output, close their sessions, and export safe CSV", async ({ page }) => {
  const server = await fixture(page);
  await choose(page, ["device-1", "device-2", "device-3"]);
  await run(page);
  await expect.poll(() => server.runs.length).toBe(3);
  await results(page);
  for (let index = 0; index < 3; index++) {
    const row = page.getByTestId(`bulk-row-device-${index + 1}`);
    await expect(row).toHaveAttribute("data-state", "done");
    await expect(row.locator("td").nth(2)).toHaveText(String(index));
    await expect(row.locator("pre")).toHaveText(`${OUTPUT}\npeer-${index}`);
  }
  await expect.poll(() => server.ends.length).toBe(3);
  expect(server.starts).toEqual(["device-1", "device-2", "device-3"]);
  expect(new Set(server.runs).size).toBe(3);
  expect(new Set(server.ends).size).toBe(3);
  await expect(page.getByTestId("bulk-dialog").locator("img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).bulkInjected)).toBeUndefined();
  await expect(page.getByTestId("bulk-row-device-3")).toContainText("Agent truncated");
  const downloaded = page.waitForEvent("download");
  await page.getByTestId("bulk-export-csv").click();
  const download = await downloaded;
  const stream = await download.createReadStream();
  if (!stream) throw new Error("CSV download had no stream");
  let csv = "";
  for await (const chunk of stream) csv += chunk.toString();
  expect(csv).toContain('device-1,"[text] =FORMULA",');
  expect(csv).not.toMatch(/(^|,)=FORMULA/m);
  expect(csv).toContain("peer-0");
  await page.getByTestId("bulk-close").click();
  await expect(page.getByTestId("bulk-dialog")).toHaveCount(0);
});

test("cancel leaves queued machines without sessions and awaits dispatched results", async ({ page }) => {
  const server = await fixture(page);
  await choose(page, ["device-1", "device-2", "device-3", "device-4", "busy"]);
  await run(page);
  await expect.poll(() => server.runs.length).toBe(3);
  await page.getByTestId("bulk-cancel").click();
  for (const id of ["device-4", "busy"]) await expect(page.getByTestId(`bulk-row-${id}`)).toHaveAttribute("data-state", "cancelled");
  await results(page);
  await expect.poll(() => server.ends.length).toBe(3);
  expect(server.starts).toEqual(["device-1", "device-2", "device-3"]);
  expect(server.runs).toHaveLength(3);
});
