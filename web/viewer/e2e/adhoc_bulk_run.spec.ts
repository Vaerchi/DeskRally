import { consoleTab } from "./nav";
import { test, expect, type Page } from "@playwright/test";

// Ad-hoc bulk command run (docs/01 "Bulk actions"): the operator TYPES a command and runs it across
// machines. It reuses the toolbox bulk machinery but authorizes through the command-run grant
// (POST /sessions/{id}/command-run) rather than a saved item, so the fan-out is centrally audited.

async function fixture(page: Page) {
  const server = { starts: [] as string[], commandRuns: [] as { sessionId: string; shell: string; runAs: string; body: string }[], ends: [] as string[] };
  const machines = [
    { device_id: "device-1", name: "First" },
    { device_id: "device-2", name: "Second" },
    { device_id: "device-3", name: "Third" },
    { device_id: "busy", name: "Busy" },
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
      return route.fulfill({ json: { session: { id }, signaling: { url: "ws://127.0.0.1:5189/ws", ticket: {} } } });
    }
    const cmdMatch = path.match(/\/sessions\/([^/]+)\/command-run$/);
    if (cmdMatch) {
      const b = request.postDataJSON();
      server.commandRuns.push({ sessionId: cmdMatch[1], shell: b.shell, runAs: b.run_as, body: b.body });
      // Echo an authoritative command the viewer must send verbatim.
      return route.fulfill({ json: { request_id: `cmd-${server.commandRuns.length}`, shell: b.shell, run_as: b.run_as, command: `AUTHORIZED:${b.body}` } });
    }
    if (/\/sessions\/[^/]+\/end$/.test(path)) {
      server.ends.push(path);
      return route.fulfill({ json: {} });
    }
    if (path === "/cp/toolbox") return route.fulfill({ json: { items: [], can_manage_shared: false } });
    if (path === "/cp/audit/ingest") return route.fulfill({ json: {} });
    if (path.endsWith("/policy")) return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5189/ws", () => {});
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
  await page.getByTestId("toolbox-adhoc-bulk").click();
  return server;
}

async function control(page: Page, peerIndex: number, message: unknown) {
  await page.evaluate(({ peerIndex, message }) => {
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    const frame = new Uint8Array(5 + bytes.length);
    new DataView(frame.buffer).setUint32(1, bytes.length);
    frame.set(bytes, 5);
    (window as any).peers[peerIndex].dc.onmessage({ data: frame.buffer });
  }, { peerIndex, message });
}

// Decode the first Control RunCommand a peer was sent, to prove the viewer dispatched the grant's command.
async function firstRunCommand(page: Page, peerIndex: number): Promise<{ command: string; shell: string } | null> {
  return page.evaluate((peerIndex) => {
    for (const buf of (window as any).peers[peerIndex].dc.sent as ArrayBuffer[]) {
      const view = new Uint8Array(buf);
      if (view[0] !== 0) continue; // Control channel only
      const len = new DataView(buf).getUint32(1);
      const msg = JSON.parse(new TextDecoder().decode(view.slice(5, 5 + len)));
      if (msg.t === "RunCommand") return { command: msg.c.command, shell: msg.c.shell };
    }
    return null;
  }, peerIndex);
}

test("compose a command, run it on machines, and each run is a command-run grant with the typed command", async ({ page }) => {
  const server = await fixture(page);

  // Compose a cmd command.
  await page.getByTestId("bulk-cmd-shell").selectOption("cmd");
  await page.getByTestId("bulk-cmd-runas").selectOption("system");
  await page.getByTestId("bulk-cmd-body").fill("ipconfig /all");
  await page.getByTestId("bulk-cmd-next").click();

  // Picker: the three online, not-in-session machines come preselected; busy is unselected.
  await expect(page.getByTestId("bulk-machine-device-1")).toBeChecked();
  await expect(page.getByTestId("bulk-machine-busy")).not.toBeChecked();

  // Confirm shows the typed command, then run.
  await page.getByTestId("bulk-confirm").click();
  await expect(page.getByTestId("bulk-dialog")).toContainText("ipconfig /all");
  await page.getByTestId("bulk-run").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(3);
  await page.evaluate(() => (window as any).peers.forEach((peer: any) => { peer.connected(); peer.dc.onopen?.(); }));

  // Each machine authorized through the command-run grant with the composed command.
  await expect.poll(() => server.commandRuns.length).toBe(3);
  for (const r of server.commandRuns) {
    expect(r.shell).toBe("cmd");
    expect(r.runAs).toBe("system");
    expect(r.body).toBe("ipconfig /all");
  }
  expect(new Set(server.commandRuns.map(r => r.sessionId)).size).toBe(3);

  // The viewer dispatched the authoritative command the grant returned (not the raw body).
  expect(await firstRunCommand(page, 0)).toEqual({ command: "AUTHORIZED:ipconfig /all", shell: "Cmd" });

  // Results render and sessions close.
  for (let index = 0; index < 3; index++) {
    await control(page, index, { t: "CommandResult", c: { exit_code: index, stdout: `peer-${index}`, stderr: "", truncated: false, timed_out: false } });
  }
  for (let index = 0; index < 3; index++) {
    const row = page.getByTestId(`bulk-row-device-${index + 1}`);
    await expect(row).toHaveAttribute("data-state", "done");
    await expect(row.locator("pre")).toHaveText(`peer-${index}`);
  }
  await expect.poll(() => server.ends.length).toBe(3);
});

test("an empty command cannot proceed past compose", async ({ page }) => {
  await fixture(page);
  await expect(page.getByTestId("bulk-cmd-next")).toBeDisabled();
  await page.getByTestId("bulk-cmd-body").fill("whoami");
  await expect(page.getByTestId("bulk-cmd-next")).toBeEnabled();
  // A multi-line cmd command is refused client-side before any session opens.
  await page.getByTestId("bulk-cmd-shell").selectOption("cmd");
  await page.getByTestId("bulk-cmd-body").fill("echo a\necho b");
  await expect(page.getByTestId("bulk-cmd-next")).toBeDisabled();
});
