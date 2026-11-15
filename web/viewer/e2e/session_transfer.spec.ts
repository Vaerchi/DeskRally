// docs/51 session transfer, console side, against a mocked control plane and a fake RTCPeerConnection
// (the same harness as supervisor_session_recovery.spec.ts). The server's sequencing is the CP's own
// tested contract; this spec proves the console drives it: the sender's dialog, banner and final message,
// and the receiver's accept -> wait -> ticket -> connect, with S2 owned like an ordinary session.
import { test, expect, type Page } from "@playwright/test";
import { openManualConnect } from "./manual_connect";

const offer = (state: string, extra: Record<string, unknown> = {}) => ({
  id: "t1", session_id: "session-1", machine_id: "m1", from_user_id: "alice", to_user_id: "bob",
  note: "printer is jammed", state, created_at: "", expires_at: "", machine_name: "Front desk",
  from_name: "Alice", to_name: "Bob", ...extra,
});

async function harness(page: Page) {
  await page.clock.install();
  const cp = {
    starts: 0, policy: 200 as number, policyBody: {} as Record<string, unknown>,
    transferReads: [] as string[], offered: null as unknown, ended: [] as string[],
    incoming: [] as unknown[], acceptCalls: 0, ticketCalls: 0,
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") {
      if (req.method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      cp.starts++;
      return route.fulfill({ json: { session: { id: `session-${cp.starts}` }, signaling: { url: "ws://127.0.0.1:5188/ws", device_id: "dev-1", session_id: `session-${cp.starts}`, ticket: {} } } });
    }
    if (/^\/cp\/sessions\/[^/]+\/policy$/.test(path)) {
      return route.fulfill({ status: cp.policy, json: cp.policy === 200
        ? { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } }
        : cp.policyBody });
    }
    if (/^\/cp\/sessions\/[^/]+\/end$/.test(path)) { cp.ended.push(path.split("/")[3]); return route.fulfill({ json: { session: { id: "ended" } } }); }
    if (path === "/cp/sessions/session-1/transfer-candidates") {
      return route.fulfill({ json: { candidates: [{ id: "bob", email: "bob@example.com", display_name: "Bob" }], group: { id: "g1", name: "Front office" } } });
    }
    if (path === "/cp/sessions/session-1/transfer") {
      cp.offered = req.postDataJSON();
      return route.fulfill({ status: 201, json: { transfer: offer("pending") } });
    }
    if (path === "/cp/session-transfers/incoming") return route.fulfill({ json: { transfers: cp.incoming } });
    if (path === "/cp/session-transfers/t1/accept") { cp.acceptCalls++; return route.fulfill({ json: { transfer: offer("releasing", { accepted_by: "bob", accepted_by_name: "Bob" }) } }); }
    if (path === "/cp/session-transfers/t1/ticket") {
      cp.ticketCalls++;
      return route.fulfill({ json: { session: { id: "s2" }, signaling: { url: "ws://127.0.0.1:5188/ws", device_id: "dev-2", session_id: "s2", ticket: {} } } });
    }
    if (path === "/cp/session-transfers/t1") {
      const next = cp.transferReads.shift() ?? "releasing";
      return route.fulfill({ json: { transfer: offer(next, { accepted_by: "bob", accepted_by_name: "Bob", new_session_id: next === "accepted" ? "s2" : undefined }) } });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", () => {});
  await page.addInitScript(() => {
    const w = window as any; w.peers = [];
    class Peer {
      connectionState = "new"; onconnectionstatechange: any; ontrack: any; onicecandidate: any; frames = 1;
      dc: any = { readyState: "open", sent: [] as ArrayBuffer[], send(bytes: ArrayBuffer) { this.sent.push(bytes); }, close() { this.readyState = "closed"; this.onclose?.(); } };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; } addTransceiver() {} close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() { return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames++ }]])); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
      control(message: unknown) { const bytes = new TextEncoder().encode(JSON.stringify(message)); const frame = new Uint8Array(5 + bytes.length); new DataView(frame.buffer).setUint32(1, bytes.length); frame.set(bytes, 5); this.dc.onmessage?.({ data: frame.buffer }); }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  return cp;
}

test("sender: Transfer… offers to a colleague, the banner follows it, and the 409 names the recipient", async ({ page }) => {
  const cp = await harness(page);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  const renewed = page.waitForResponse("**/cp/sessions/session-1/policy");
  await page.evaluate(() => (window as any).peers[0].control({ t: "SessionLeaseRequired", c: { renew_within_ms: 30000 } }));
  await renewed;

  await page.getByRole("button", { name: "Session", exact: false }).first().click();
  await page.getByTestId("session-transfer").click();
  await expect(page.getByTestId("transfer-dialog")).toBeVisible();
  await expect(page.getByTestId("transfer-dialog")).toContainText("Anyone in Front office");
  await expect(page.getByTestId("transfer-send")).toBeDisabled();
  await page.getByTestId("transfer-to-bob").check();
  await page.getByTestId("transfer-note").fill("printer is jammed");
  // Keys typed in the dialog never reach the remote machine.
  const sentBefore = await page.evaluate(() => (window as any).peers[0].dc.sent.length);
  await page.getByTestId("transfer-send").click();
  await expect(page.getByTestId("transfer-dialog")).toHaveCount(0);
  expect(cp.offered).toEqual({ to_user_id: "bob", note: "printer is jammed" });
  const typed = await page.evaluate((n) => (window as any).peers[0].dc.sent.slice(n).map((b: ArrayBuffer) =>
    JSON.parse(new TextDecoder().decode(new Uint8Array(b).slice(5))).t), sentBefore);
  expect(typed.filter((t: string) => /Key|Text/.test(t))).toEqual([]);
  await expect(page.getByTestId("transfer-banner")).toContainText("Waiting for Bob to accept");

  // Bob accepts: the sender's read shows it, then S1's renewal is refused with the reason.
  cp.transferReads.push("releasing");
  await page.clock.runFor(3500);
  await expect(page.getByTestId("transfer-banner")).toContainText("Bob accepted");
  cp.policy = 409; cp.policyBody = { error: "session transferred", transferred_to: "Bob" };
  await page.clock.runFor(16000);
  await expect(page.getByTestId("app-error")).toContainText("Session transferred to Bob.");
  await page.clock.runFor(180000);
  expect(cp.starts).toBe(1); // never "recovered" into a fresh session
});

test("receiver: an incoming offer is accepted, waits for the hand-off, and connects to S2 as an owned session", async ({ page }) => {
  const cp = await harness(page);
  cp.incoming = [offer("pending")];
  cp.transferReads.push("releasing", "accepted");
  await expect(page.getByTestId("incoming-transfer-t1")).toContainText("Alice");
  await expect(page.getByTestId("incoming-transfer-t1")).toContainText("Front desk");
  await expect(page.getByTestId("incoming-transfer-t1")).toContainText("printer is jammed");
  cp.incoming = [];
  await page.getByTestId("incoming-transfer-accept-t1").click();
  await expect(page.getByTestId("incoming-transfer-status")).toContainText("Waiting for Alice");
  await page.clock.runFor(2100);
  await page.clock.runFor(2100);
  await expect.poll(() => cp.ticketCalls).toBe(1);
  expect(cp.acceptCalls).toBe(1);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  expect(cp.starts).toBe(0); // S2 came from the transfer ticket, not POST /sessions
  await page.evaluate(() => (window as any).peers[0].connected());
  // Owned: disconnecting ends S2's record, exactly like an ordinary session.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect.poll(() => cp.ended).toContain("s2");
});

test("receiver: a failed hand-off is explained and nothing connects", async ({ page }) => {
  const cp = await harness(page);
  cp.incoming = [offer("pending")];
  cp.transferReads.push("failed");
  await page.getByTestId("incoming-transfer-accept-t1").click();
  await page.clock.runFor(2100);
  await expect(page.getByTestId("incoming-transfer-error")).toContainText("did not complete");
  expect(cp.ticketCalls).toBe(0);
  expect(await page.evaluate(() => (window as any).peers.length)).toBe(0);
});

test("receiver: Dismiss hides an offer locally without declining it", async ({ page }) => {
  const cp = await harness(page);
  cp.incoming = [offer("pending")];
  await page.getByTestId("incoming-transfer-dismiss-t1").click();
  await expect(page.getByTestId("incoming-transfers")).toHaveCount(0);
  expect(cp.acceptCalls).toBe(0);
});
