// docs/64 guest help requests, console side, against a mocked control plane and a fake RTCPeerConnection
// (the harness of session_transfer.spec.ts). The control plane's rules (current-group authorization,
// single-use accept, admission) are its own tested contract (control-plane/http_help_request_test.go);
// this spec proves the console: the badge and list are separate from the audit bell, the note is plain text
// under its label, an offline machine has no Accept, Accept connects to the session the SERVER created
// (never a second POST /sessions), and a 409 is shown in the server's own words.
//
// The `page` fixture is already pinned (playwright.config.ts applies PINNED_STORAGE from
// e2e/chrome_pinned.ts), so the session toolbar is the always-visible bar these assertions use.
import { test, expect, type Page } from "@playwright/test";

type Row = Record<string, unknown>;

const request = (id: string, extra: Row = {}): Row => ({
  id, machine_id: `m-${id}`, machine_name: `HOST-${id}`, group_id: "g1", note: "printer is jammed",
  note_source: "guest_machine", requested_from: "machine", status: "open",
  created_at: "2026-10-31T10:00:00Z", expires_at: "2026-10-31T10:30:00Z", online: true, can_accept: true, ...extra,
});

async function harness(page: Page, opts: { clock?: boolean } = {}) {
  if (opts.clock) await page.clock.install();
  const cp = {
    list: [] as Row[], listStatus: 200, listCalls: 0,
    accepts: [] as { id: string; body: unknown }[], acceptStatus: 201, acceptBody: null as unknown,
    // the server COMMITS the accept (the request leaves the queue) but the response is lost, this many times
    loseAccepts: 0,
    starts: 0, ended: [] as string[], audit: [] as Row[],
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") return route.fulfill({ json: { email: "tech@example.test" } });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/audit") return route.fulfill({ json: { events: cp.audit } });
    if (path === "/cp/help-requests") {
      cp.listCalls++;
      return cp.listStatus === 200
        ? route.fulfill({ json: { requests: cp.list } })
        : route.fulfill({ status: cp.listStatus, json: { error: "not found" } });
    }
    const accept = /^\/cp\/help-requests\/([^/]+)\/accept$/.exec(path);
    if (accept) {
      cp.accepts.push({ id: accept[1], body: req.postDataJSON() });
      if (cp.loseAccepts > 0) {
        cp.loseAccepts--;
        cp.list = cp.list.filter((r) => r.id !== accept[1]); // committed: the queue no longer lists it
        return route.abort("connectionreset");
      }
      if (cp.acceptStatus !== 201) return route.fulfill({ status: cp.acceptStatus, json: cp.acceptBody });
      return route.fulfill({
        status: 201,
        json: {
          session: { id: "help-session-1" },
          signaling: { url: "ws://127.0.0.1:5188/ws", device_id: "dev-help", session_id: "help-session-1", ticket: {} },
          help_request: request(accept[1], { status: "accepted" }),
        },
      });
    }
    if (path === "/cp/sessions") {
      if (req.method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      cp.starts++;
      return route.fulfill({ json: { session: { id: `plain-${cp.starts}` }, signaling: { url: "ws://127.0.0.1:5188/ws", device_id: "dev-1", session_id: `plain-${cp.starts}`, ticket: {} } } });
    }
    if (/^\/cp\/sessions\/[^/]+\/end$/.test(path)) { cp.ended.push(path.split("/")[3]); return route.fulfill({ json: { session: { id: "ended" } } }); }
    if (/^\/cp\/sessions\/[^/]+\/policy$/.test(path)) {
      return route.fulfill({ json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9999999999999 } } });
    }
    if (path === "/cp/session-transfers/incoming") return route.fulfill({ json: { transfers: [] } });
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
    }
    w.RTCPeerConnection = Peer;
  });
  return cp;
}

// The badge and the audit bell live in the "DeskRally" menu (single-row App chrome: nothing is added to the
// always-visible row), so the menu is opened first, like every other console control.
// Wave 10b: outside a session, on a desktop-width screen, the bells sit at the page bar's right end, so nothing needs
// opening. On a phone (or in a session) they are inside the DeskRally menu; the badge tests below cover that case.
const open = async (page: Page) => { await page.goto(test.info().project.use.baseURL!); };

test("the badge counts open requests; the list is separate from the audit bell and shows the note as plain text under its label", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [
    request("a", { note: "<b>urgent</b> <img src=x onerror=window.__pwned=1> **not bold**", machine_alias: "Reception PC" }),
    request("b", { online: false, can_accept: false, note: "" }),
  ];
  await open(page);
  await expect(page.getByTestId("help-requests-badge")).toHaveText("2");
  // Two separate controls: the audit bell is still there and has no help-request count.
  await expect(page.getByTestId("notifications-bell")).toBeVisible();
  await expect(page.getByTestId("notifications-badge")).toHaveCount(0);

  await page.getByTestId("help-requests-button").click();
  const a = page.getByTestId("help-request-a");
  await expect(a).toContainText("Reception PC");
  await expect(a).toContainText("HOST-a");
  const note = page.getByTestId("help-request-note-a");
  await expect(note).toContainText("From the guest's machine");
  // Markup in the note is TEXT: no element was created from it and no handler ran.
  await expect(note).toContainText("<b>urgent</b> <img src=x onerror=window.__pwned=1> **not bold**");
  await expect(note.locator("b, img")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__pwned)).toBeUndefined();

  // An offline machine is listed, says so, and offers no Accept.
  await expect(page.getByTestId("help-request-offline-b")).toContainText("Offline");
  await expect(page.getByTestId("help-request-accept-b")).toHaveCount(0);
  await expect(page.getByTestId("help-request-accept-a")).toBeEnabled();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(1);
});

test("with nothing open there is no control; a 404 (no such route) quietly shows none", async ({ page }) => {
  const cp = await harness(page);
  cp.listStatus = 404;
  await open(page);
  await expect.poll(() => cp.listCalls).toBeGreaterThan(0);
  await expect(page.getByTestId("help-requests-button")).toHaveCount(0);
  await expect(page.getByTestId("notifications-bell")).toBeVisible();
});

test("Accept posts once with an idempotency key, then connects to the session the SERVER created (no second POST /sessions) and owns it", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a")];
  await open(page);
  await page.getByTestId("help-requests-button").click();
  cp.list = []; // the request leaves the queue once accepted
  await page.getByTestId("help-request-accept-a").click();
  await expect.poll(() => cp.accepts.length).toBe(1);
  expect(cp.accepts[0].id).toBe("a");
  expect((cp.accepts[0].body as { op_id: string }).op_id).toMatch(/^acc-/);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  expect(cp.starts).toBe(0); // the session came from the accept, not from POST /sessions
  await page.evaluate(() => (window as any).peers[0].connected());
  // Owned like any ordinary session: Disconnect ends its record.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect.poll(() => cp.ended).toContain("help-session-1");
});

test("a 409 is shown in the server's own words and nothing connects", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a")];
  cp.acceptStatus = 409;
  cp.acceptBody = { error: "help request is accepted", state: "accepted" };
  await open(page);
  await page.getByTestId("help-requests-button").click();
  cp.list = []; // someone else took it: the refreshed queue is empty, the explanation must remain
  await page.getByTestId("help-request-accept-a").click();
  await expect(page.getByTestId("help-requests-error")).toContainText("help request is accepted");
  expect(await page.evaluate(() => (window as any).peers.length)).toBe(0);
  expect(cp.starts).toBe(0);
  // The control stays up while there is something to explain, even though the queue is now empty.
  await expect(page.getByTestId("help-requests-button")).toBeVisible();
  await page.getByTestId("help-requests-error").getByRole("button", { name: "OK" }).click();
  await expect(page.getByTestId("help-requests-error")).toHaveCount(0);

  // Other refusals read the same way: verbatim.
  cp.list = [request("b")];
  cp.acceptBody = { error: "concurrent session limit reached for this machine group" };
  await page.getByTestId("help-requests-button").click(); // close
  await page.getByTestId("help-requests-button").click(); // open: refreshes
  await expect(page.getByTestId("help-request-accept-b")).toBeVisible();
  await page.getByTestId("help-request-accept-b").click();
  await expect(page.getByTestId("help-requests-error")).toContainText("concurrent session limit reached for this machine group");
});

test("the audit bell maps the two notable help actions for tenant-wide auditors", async ({ page }) => {
  const cp = await harness(page, { clock: true });
  await open(page);
  await expect(page.getByTestId("notifications-bell")).toBeVisible();
  // The first poll only primes the baseline; the next one surfaces genuinely new events.
  cp.audit = [
    { id: "e1", tenant_id: "t", action: "help.requested", target_kind: "help_request", target_id: "r1", occurred_at: "2026-10-31T10:00:00Z" },
    { id: "e2", tenant_id: "t", action: "help.accepted", target_kind: "help_request", target_id: "r1", occurred_at: "2026-10-31T10:01:00Z" },
    { id: "e3", tenant_id: "t", action: "help.cancelled", target_kind: "help_request", target_id: "r2", occurred_at: "2026-10-31T10:02:00Z" },
  ];
  await page.clock.runFor(21_000);
  await expect(page.getByTestId("notifications-badge")).toHaveText("2");
  await page.getByTestId("notifications-bell").click();
  const items = page.getByTestId("notifications-item");
  await expect(items).toHaveCount(2);
  await expect(page.getByTestId("notifications-panel")).toContainText("A machine asked for help");
  await expect(page.getByTestId("notifications-panel")).toContainText("A help request was taken");
});

test("the help topic is in the console's Help", async ({ page }) => {
  await harness(page);
  await page.goto("http://127.0.0.1:5173/console/help?topic=help-requests");
  const article = page.getByTestId("help-article");
  await expect(article.getByRole("heading", { level: 2 })).toHaveText("When a guest asks for help");
  await expect(article).toContainText("From the guest's machine");
});

// Review finding 6: the queue is invisible while the "DeskRally" menu is closed, so the EXISTING trigger
// carries a small count. It is a child of that trigger (no new control in the single-row chrome), it tracks
// the open requests, and the trigger keeps its exact accessible name.
// Wave 10b: this is now the phone case (and the in-session one): wider than 600px outside a session, the bells are on
// the bar itself and the trigger carries no count (the next test).
test("the DeskRally menu trigger carries the open-request count while the menu is closed", async ({ page }) => {
  const cp = await harness(page, { clock: true });
  cp.list = [request("a"), request("b"), request("c", { status: "accepted" })];
  await page.setViewportSize({ width: 560, height: 900 });
  await page.goto(test.info().project.use.baseURL!);
  await expect(page.getByTestId("area-bar-end")).toHaveCount(0);
  const trigger = page.getByRole("button", { name: "DeskRally", exact: true });
  await expect(trigger).toHaveAttribute("aria-expanded", "false"); // the menu is CLOSED
  const badge = trigger.getByTestId("toolbar-menu-badge");
  await expect(badge).toBeVisible();
  await expect(badge).toHaveText("2"); // the accepted request does not count
  await expect(trigger).toHaveAttribute("title", /2 help requests waiting/);
  // nothing was added to the row: the only help-request control is inside the (closed) menu panel
  await expect(page.getByTestId("help-requests-button")).toBeHidden();
  // it follows the queue
  cp.list = [request("a")];
  await page.clock.runFor(16_000);
  await expect(badge).toHaveText("1");
  cp.list = [];
  await page.clock.runFor(16_000);
  await expect(trigger.getByTestId("toolbar-menu-badge")).toHaveCount(0);
  await expect(trigger).toHaveAttribute("title", "DeskRally");
});

test("on a desktop-width screen the bells are at the bar's right end and the DeskRally trigger carries no count", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a"), request("b")];
  await page.setViewportSize({ width: 1280, height: 800 });
  await open(page);
  const end = page.getByTestId("area-bar-end");
  await expect(end.getByTestId("help-requests-button")).toBeVisible();
  await expect(end.getByTestId("help-requests-badge")).toHaveText("2");
  await expect(end.getByTestId("notifications-bell")).toBeVisible();
  const trigger = page.getByRole("button", { name: "DeskRally", exact: true });
  await expect(trigger.getByTestId("toolbar-menu-badge")).toHaveCount(0);
  // each control is drawn once: none is left inside the DeskRally menu
  await expect(page.getByTestId("help-requests-button")).toHaveCount(1);
  await expect(page.getByTestId("notifications-bell")).toHaveCount(1);
  // the open panel drops down past the bar and is not clipped by it: the point near its bottom is the panel itself
  await end.getByTestId("help-requests-button").click();
  await expect(page.getByTestId("help-request-a")).toBeVisible();
  const bar = (await page.locator(".app__topbar").boundingBox())!;
  const panel = (await page.getByTestId("help-requests-panel").boundingBox())!;
  expect(panel.y + panel.height).toBeGreaterThan(bar.y + bar.height + 40);
  const hit = await page.evaluate(([x, y]) => !!document.elementFromPoint(x, y)?.closest('[data-testid="help-requests-panel"]'),
    [panel.x + 12, panel.y + panel.height - 8]);
  expect(hit).toBe(true);
});

// Review r2 #7: the accept COMMITS but its response is lost. The queue refresh then hides the accepted request,
// so the unresolved attempt is kept on its own: it shows Retry (same request id and op_id) until it connects
// to the bound session, and counts on the DeskRally trigger meanwhile.
test("a lost accept response leaves a Retry (same request id + op_id) that connects to the bound session", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a", { machine_alias: "Reception PC" })];
  cp.loseAccepts = 1;
  await open(page);
  await page.getByTestId("help-requests-button").click();
  await page.getByTestId("help-request-accept-a").click();
  await expect.poll(() => cp.accepts.length).toBe(1);
  // the queue is empty now (the server committed), yet the attempt is still there to retry
  await expect(page.getByTestId("help-requests-unresolved")).toContainText("Reception PC");
  await expect(page.getByTestId("help-request-a")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).peers.length)).toBe(0);
  await page.getByTestId("help-requests-retry").click();
  await expect.poll(() => cp.accepts.length).toBe(2);
  expect(cp.accepts[1].id).toBe("a");
  expect((cp.accepts[1].body as { op_id: string }).op_id).toBe((cp.accepts[0].body as { op_id: string }).op_id);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  expect(cp.starts).toBe(0); // the bound session, never a second POST /sessions
});

test("an unresolved accept counts on the help-request bell, and a terminal answer to the retry clears it", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a")];
  cp.loseAccepts = 1;
  await open(page);
  await page.getByTestId("help-requests-button").click();
  await page.getByTestId("help-request-accept-a").click();
  await expect(page.getByTestId("help-requests-unresolved")).toBeVisible();
  // queue is empty; the unresolved accept counts (on the bar's bell outside a session: wave 10b)
  await expect(page.getByTestId("help-requests-badge")).toHaveText("1");
  cp.acceptStatus = 409;
  cp.acceptBody = { error: "help request is expired", state: "expired" };
  await page.getByTestId("help-requests-retry").click();
  await expect(page.getByTestId("help-requests-error")).toContainText("help request is expired");
  await expect(page.getByTestId("help-requests-unresolved")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).peers.length)).toBe(0);
});

// Review r3: while an accept is unresolved, no OTHER request may be accepted: starting one would drop the
// retained Retry of a request that may already have committed (its session unreachable through recovery).
test("while an accept is unresolved, Accept on another request is disabled with a reason, and Retry still works", async ({ page }) => {
  const cp = await harness(page);
  cp.list = [request("a", { machine_alias: "Reception PC" }), request("b")];
  cp.loseAccepts = 1;
  await open(page);
  await page.getByTestId("help-requests-button").click();
  await page.getByTestId("help-request-accept-a").click();
  await expect(page.getByTestId("help-requests-unresolved")).toContainText("Reception PC");
  // b is still in the queue but cannot be accepted; the reason points at the pending Retry
  const acceptB = page.getByTestId("help-request-accept-b");
  await expect(acceptB).toBeDisabled();
  await expect(acceptB).toHaveAttribute("title", /Retry/);
  await expect(page.getByTestId("help-requests-blocked")).toContainText("pending accept");
  expect(cp.accepts.map((x) => x.id)).toEqual(["a"]); // nothing was sent for b
  await page.getByTestId("help-requests-retry").click();
  await expect.poll(() => cp.accepts.length).toBe(2);
  expect(cp.accepts[1].id).toBe("a");
  expect((cp.accepts[1].body as { op_id: string }).op_id).toBe((cp.accepts[0].body as { op_id: string }).op_id);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
});
