import { consoleTab } from "./nav";
import { test, expect, type Page } from "@playwright/test";

// Bulk file transfer (docs/01 "Bulk actions"): the operator picks a file and pushes it to many
// machines. It reuses the bulk machinery; each machine's upload rides the file-transfer channel (the
// agent's session dispatcher gates + audits it, ADR-008) — no control-plane grant. The fake agent here
// acks each upload so the real FileTransferClient upload path (Offer → Chunks → Done → Ack) is driven.

async function fixture(page: Page) {
  const server = {
    starts: [] as string[],
    ends: [] as string[],
    commandRuns: [] as { sessionId: string; shell: string; runAs: string; body: string }[],
  };
  const machines = [
    { device_id: "device-1", name: "First" },
    { device_id: "device-2", name: "Second" },
    { device_id: "device-3", name: "Third" },
  ].map(machine => ({ id: machine.device_id, tenant_id: "tenant", group_id: "group", online: true, status: "active", ...machine }));
  await page.route(/.*/, route => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async route => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines, presence_known: true } });
    if (path === "/cp/sessions") {
      if (request.method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      server.starts.push(request.postDataJSON().machine_id);
      const id = `session-${server.starts.length}`;
      return route.fulfill({ json: { session: { id }, signaling: { url: "ws://127.0.0.1:5190/ws", ticket: {} } } });
    }
    const cmdMatch = path.match(/\/sessions\/([^/]+)\/command-run$/);
    if (cmdMatch) {
      const b = request.postDataJSON();
      server.commandRuns.push({ sessionId: cmdMatch[1], shell: b.shell, runAs: b.run_as, body: b.body });
      // Echo a distinctive authoritative command the viewer must dispatch verbatim (the real CP
      // returns the base64 scriptblock transform of the body).
      return route.fulfill({ json: { request_id: `cmd-${server.commandRuns.length}`, shell: b.shell, run_as: b.run_as, command: `PSWRAPPED-${server.commandRuns.length}` } });
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
  await page.routeWebSocket("ws://127.0.0.1:5190/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    w.uploads = []; // {name, size} recorded from each Offer
    class FakeDC {
      readyState = "open";
      sent: ArrayBuffer[] = [];
      onmessage: any = null;
      onclose: any = null;
      offerNames: Record<string, string> = {};
      constructor(public index: number) {}
      send(bytes: ArrayBuffer) {
        this.sent.push(bytes);
        const view = new Uint8Array(bytes);
        if (view[0] !== 5) return; // FileTransfer channel only
        const payload = view.slice(5);
        if (payload[0] !== 0x7b) return; // 0x7b = '{' JSON control; 0x01 = binary chunk (ignore)
        let msg: any;
        try { msg = JSON.parse(new TextDecoder().decode(payload)); } catch { return; }
        if (msg.t === "Offer") {
          this.offerNames[msg.c.id] = msg.c.name;
          w.uploads.push({ name: msg.c.name, size: msg.c.size });
        } else if (msg.t === "Done") {
          // Landed name carries the agent's never-replace dedup suffix: "hello.txt" -> "hello (2).txt".
          const offered = this.offerNames[msg.c.id] ?? "file.bin";
          const dot = offered.lastIndexOf(".");
          const landed = dot > 0 ? offered.slice(0, dot) + " (2)" + offered.slice(dot) : offered + " (2)";
          const refused = w.refuseUploadAt === this.index;
          const body = refused
            ? { t: "Ack", c: { id: msg.c.id, ok: false, message: "upload refused by policy" } }
            : { t: "Ack", c: { id: msg.c.id, ok: true, message: landed } };
          const ack = new TextEncoder().encode(JSON.stringify(body));
          const frame = new Uint8Array(5 + ack.length);
          frame[0] = 5;
          new DataView(frame.buffer).setUint32(1, ack.length);
          frame.set(ack, 5);
          const dc = this;
          setTimeout(() => dc.onmessage?.({ data: frame.buffer }), 0);
        }
      }
      close() { this.readyState = "closed"; this.onclose?.(); }
    }
    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      dc: any;
      constructor() { this.dc = new FakeDC(w.peers.length); w.peers.push(this); }
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
  return server;
}

// Bring every peer up and, in the SAME synchronous block as channel-open, advertise the transfer
// folder (the agent sends TransferDir right after the channel opens; doing it synchronously here
// guarantees the core has it before any upload ack can trigger the run step).
async function connectPeers(page: Page, dir = "C:\\rmt-agent\\transfers") {
  await page.evaluate((path) => {
    const w = window as any;
    for (const peer of w.peers) {
      peer.connected();
      peer.dc.onopen?.();
      const bytes = new TextEncoder().encode(JSON.stringify({ t: "TransferDir", c: { path } }));
      const frame = new Uint8Array(5 + bytes.length);
      new DataView(frame.buffer).setUint32(1, bytes.length);
      frame.set(bytes, 5);
      peer.dc.onmessage?.({ data: frame.buffer });
    }
  }, dir);
}

async function feedControl(page: Page, peerIndex: number, message: unknown) {
  await page.evaluate(({ peerIndex, message }) => {
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    const frame = new Uint8Array(5 + bytes.length);
    new DataView(frame.buffer).setUint32(1, bytes.length);
    frame.set(bytes, 5);
    (window as any).peers[peerIndex].dc.onmessage?.({ data: frame.buffer });
  }, { peerIndex, message });
}

async function runCommandsSentTo(page: Page, peerIndex: number): Promise<{ command: string; shell: string }[]> {
  return page.evaluate((peerIndex) => {
    const out: { command: string; shell: string }[] = [];
    for (const buf of (window as any).peers[peerIndex].dc.sent as ArrayBuffer[]) {
      const view = new Uint8Array(buf);
      if (view[0] !== 0) continue; // Control channel
      const len = new DataView(buf).getUint32(1);
      try {
        const msg = JSON.parse(new TextDecoder().decode(view.slice(5, 5 + len)));
        if (msg.t === "RunCommand") out.push({ command: msg.c.command, shell: msg.c.shell });
      } catch { /* non-JSON */ }
    }
    return out;
  }, peerIndex);
}

test("pick a file and send it to machines; each machine gets the upload and it lands", async ({ page }) => {
  const server = await fixture(page);

  // Pick a file (the hidden input the "Send a file to machines…" button triggers).
  await page.getByTestId("toolbox-file-input").setInputFiles({
    name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from("hello world"),
  });

  // The dialog opens at the machine picker with the three machines preselected.
  await expect(page.getByTestId("bulk-dialog")).toBeVisible();
  await expect(page.getByTestId("bulk-machine-device-1")).toBeChecked();

  // Confirm shows the file + size, then run.
  await page.getByTestId("bulk-confirm").click();
  await expect(page.getByTestId("bulk-dialog")).toContainText("hello.txt");
  await expect(page.getByTestId("bulk-dialog")).toContainText("11 bytes");
  await page.getByTestId("bulk-run").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(3);
  await page.evaluate(() => (window as any).peers.forEach((peer: any) => { peer.connected(); peer.dc.onopen?.(); }));

  // Each machine received the file-transfer Offer with the real name and size.
  await expect.poll(() => page.evaluate(() => (window as any).uploads.length)).toBe(3);
  const uploads = await page.evaluate(() => (window as any).uploads);
  for (const u of uploads) {
    expect(u.name).toBe("hello.txt");
    expect(u.size).toBe(11);
  }

  // Every row completes (the fake acked each upload) and the sessions close.
  for (let index = 0; index < 3; index++) {
    await expect(page.getByTestId(`bulk-row-device-${index + 1}`)).toHaveAttribute("data-state", "done");
  }
  await expect.poll(() => server.ends.length).toBe(3);
  expect(server.starts).toEqual(["device-1", "device-2", "device-3"]);
});

test("push-and-run: each landed file is executed via a per-machine audited command grant; a refused upload never runs", async ({ page }) => {
  const server = await fixture(page);
  // The third machine's agent refuses the upload (policy): it must never receive a run grant.
  await page.evaluate(() => { (window as any).refuseUploadAt = 2; });

  await page.getByTestId("toolbox-file-input").setInputFiles({
    name: "hello.txt", mimeType: "text/plain", buffer: Buffer.from("hello world"),
  });
  await expect(page.getByTestId("bulk-dialog")).toBeVisible();
  await page.getByTestId("bulk-confirm").click();
  await page.getByTestId("bulk-run-after").check();
  await page.getByTestId("bulk-run-args").fill("/S");
  await page.getByTestId("bulk-run").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(3);
  await connectPeers(page);

  // Exactly two grants (never one for the refused upload), each carrying the composed PowerShell
  // line built from the agent-returned landed name (dedup suffix included), verbatim.
  await expect.poll(() => server.commandRuns.length).toBe(2);
  for (const r of server.commandRuns) {
    expect(r.shell).toBe("powershell");
    expect(r.runAs).toBe("system");
    expect(r.body).toBe("& 'C:\\rmt-agent\\transfers\\hello (2).txt' /S; exit $LASTEXITCODE");
  }
  expect(new Set(server.commandRuns.map(r => r.sessionId)).size).toBe(2);

  // The viewer dispatched the grant's AUTHORITATIVE command (not the raw body), as PowerShell.
  await expect.poll(async () => (await runCommandsSentTo(page, 0)).length).toBe(1);
  const sent = (await runCommandsSentTo(page, 0))[0];
  expect(sent.shell).toBe("PowerShell");
  expect(sent.command.startsWith("PSWRAPPED-")).toBe(true);

  // Results: the two run machines finish with the exit code and both phase facts visible; the
  // refused machine reports the upload refusal and never ran.
  await feedControl(page, 0, { t: "CommandResult", c: { exit_code: 0, stdout: "installed", stderr: "", truncated: false, timed_out: false } });
  await feedControl(page, 1, { t: "CommandResult", c: { exit_code: 3010, stdout: "reboot required", stderr: "", truncated: false, timed_out: false } });

  const row1 = page.getByTestId("bulk-row-device-1");
  await expect(row1).toHaveAttribute("data-state", "done");
  await expect(row1).toContainText("uploaded as hello (2).txt");
  await expect(row1).toContainText("installed");
  await expect(row1.locator("td").nth(2)).toHaveText("0");

  const row2 = page.getByTestId("bulk-row-device-2");
  await expect(row2).toHaveAttribute("data-state", "done");
  await expect(row2.locator("td").nth(2)).toHaveText("3010");

  const row3 = page.getByTestId("bulk-row-device-3");
  await expect(row3).toHaveAttribute("data-state", "failed");
  await expect(row3).toContainText("upload refused by policy");

  await expect.poll(() => server.ends.length).toBe(3);
});
