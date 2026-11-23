/**
 * The relay-limit notice, end to end (lib/relay_notice.ts, components/RelayNotice.tsx).
 *
 * Security batch 3 caps the TURN credentials OUTSTANDING per technician and per tenant. At the cap signaling
 * still brokers the session, but issues no relay credential and puts `relay_notice` on the `ice_servers`
 * message it sends the requester. A technician behind a strict NAT used to get a session that simply never
 * connected, with nothing to say why. Now the viewer says so in plain words, in a dismissible strip below
 * the picture, and a connection that then fails names the relay limit as the likely cause.
 *
 * The signaling fixture is `page.routeWebSocket`, sending the REAL message order (server/signaling/
 * broker.go: `ice_servers` first, then `brokered`); the peer connection is a fake (supervisor_session_
 * recovery.spec.ts), so no agent or signaling server runs.
 *
 * Session specs run with the session bar PINNED by default (e2e/chrome_pinned.ts). This one says so
 * explicitly, and the last test opts OUT to prove the notice does not depend on the top bar: with the
 * product-default collapsed bar the whole top row is hidden, so a notice in it would be invisible.
 */
import { test, expect, type Page } from "@playwright/test";
import { PINNED_STORAGE } from "./chrome_pinned";
import { openManualConnect } from "./manual_connect";

test.use({ storageState: PINNED_STORAGE });

const DEVICE = "00112233-4455-6677-8899-aabbccddeeff";
const OTHER_DEVICE = "ffeeddcc-bbaa-9988-7766-554433221100";
const WS = "ws://127.0.0.1:5191/ws";
// What server/signaling/turn.go sends the requester when its account is at the cap.
const SERVER_NOTICE = "relay capacity exhausted for your account; direct connection only";
// What the agent says when the machine's monitors change (supervisor_session_recovery.spec.ts): the viewer then
// starts a fresh session by ITSELF, after a short pause, with no technician involved.
const LAYOUT_END =
  "session ended: the display layout on this machine changed (a monitor was connected, disconnected or woke up, or the resolution changed); reconnect to continue";

/**
 * Connect to a machine through a fake signaling server. `notice: null` is an older server (or an account
 * under its cap): it sends `ice_servers` without `relay_notice`, exactly as before this feature. Any other
 * value is sent as `relay_notice` verbatim, including values the wire type forbids (the server is untrusted).
 * `failOffer` makes the peer's `createOffer` reject: a negotiation error, which is not a connectivity failure.
 */
async function fixture(page: Page, options: { notice?: unknown; failOffer?: boolean } = {}) {
  const state = {
    starts: 0,
    connectRequests: 0,
    notice: options.notice === undefined ? SERVER_NOTICE : options.notice,
  };
  await page.clock.install();
  await page.route(/.*/, (route) => (new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort()));
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") {
      // GET /cp/sessions is the live-session badge listing: not a start.
      if (route.request().method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      state.starts++;
      return route.fulfill({ json: { session: { id: `session-${state.starts}` }, signaling: { url: WS, ticket: {} } } });
    }
    if (path.endsWith("/policy")) {
      return route.fulfill({
        json: { session_policy: { access: "control", signed: "test", lease_ttl_ms: 30000, expires_at_ms: 9_999_999_999_999 } },
      });
    }
    return route.fulfill({ json: { session: { id: "ended" } } });
  });
  await page.routeWebSocket(WS, (ws) => {
    ws.onMessage((raw) => {
      const msg = JSON.parse(String(raw)) as { type?: string };
      if (msg.type === "register_agent") ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      if (msg.type !== "connect_request") return;
      state.connectRequests++;
      // STUN only: over the cap, signaling issues no TURN credential. The notice rides on the same message.
      ws.send(
        JSON.stringify({
          type: "ice_servers",
          session: "sig-1",
          servers: [{ urls: ["stun:stun.example:3478"] }],
          ...(state.notice === null ? {} : { relay_notice: state.notice }),
        }),
      );
      ws.send(JSON.stringify({ type: "brokered", session: "sig-1", peer_device: DEVICE, peer_pubkey: "ed25519:agent-mock" }));
    });
  });
  if (options.failOffer) await page.addInitScript(() => { (window as any).__failOffer = true; });
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class Peer {
      connectionState = "new";
      onconnectionstatechange: any;
      ontrack: any;
      onicecandidate: any;
      frames = 1;
      config: any = {};
      dc: any = {
        readyState: "open",
        sent: [] as ArrayBuffer[],
        send(bytes: ArrayBuffer) { this.sent.push(bytes); },
        close() { this.readyState = "closed"; this.onclose?.(); },
      };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; }
      addTransceiver() {}
      createOffer() {
        return w.__failOffer ? Promise.reject(new Error("offer failed")) : Promise.resolve({ type: "offer", sdp: "v=0 mock-offer" });
      }
      setLocalDescription() { return Promise.resolve(); }
      getConfiguration() { return { ...this.config }; }
      setConfiguration(config: any) { this.config = config; }
      close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() { return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: this.frames }]])); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
      fail() { this.connectionState = "failed"; this.onconnectionstatechange?.(); }
      // A message from the agent on the control channel (frame = channel byte, u32 length, JSON), as the agent sends it.
      control(message: unknown) {
        const bytes = new TextEncoder().encode(JSON.stringify(message));
        const frame = new Uint8Array(5 + bytes.length);
        new DataView(frame.buffer).setUint32(1, bytes.length);
        frame.set(bytes, 5);
        this.dc.onmessage?.({ data: frame.buffer });
      }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  await connect(page);
  return state;
}

async function connect(page: Page, device = DEVICE) {
  const before = await page.evaluate(() => (window as any).peers.length);
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill(device);
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(before + 1);
}

const peer = (page: Page, index: number) => ({
  connected: () => page.evaluate((i) => (window as any).peers[i].connected(), index),
  fail: () => page.evaluate((i) => (window as any).peers[i].fail(), index),
  control: (message: unknown) => page.evaluate(([i, m]) => (window as any).peers[i].control(m), [index, message] as const),
});

/**
 * How many ICE servers the peer at `index` has been given. It is 1 once that attempt's `ice_servers` message has
 * been applied, which the transport does right AFTER it reports the relay notice. A peer connection exists from
 * `connect()`, before the server has answered, so "the peer exists" and "signaling has seen the request" say
 * nothing about whether the page has handled the answer: wait for THIS before asserting that a notice is absent.
 */
const iceServerCount = (page: Page, index: number) =>
  page.evaluate((i) => (window as any).peers[i]?.getConfiguration().iceServers?.length ?? 0, index);

test("the notice appears in plain words, takes nothing from the picture's top, and stays until dismissed", async ({ page }) => {
  await fixture(page);
  const notice = page.getByTestId("relay-notice");
  await expect(notice).toBeVisible();

  // What happened, what it means, what to do.
  await expect(notice).toContainText("No relay connection is available");
  await expect(notice).toContainText("This account has reached its limit of relay credentials");
  await expect(notice).toContainText("only a direct connection can be tried");
  await expect(notice).toContainText("may fail on restrictive networks");
  // Not "close sessions you no longer need": signaling counts issued, unexpired credentials, so closing frees none.
  await expect(notice).toContainText("Closing sessions will not free a relay credential");
  await expect(notice).not.toContainText("Close sessions you no longer need");
  await expect(notice).toContainText("older relay credentials expire");
  await expect(notice).toContainText("within 2 hours");
  await expect(notice).toContainText("Ask an administrator if this keeps happening");
  // The server's own words, as a labelled aside.
  await expect(page.getByTestId("relay-notice-server")).toHaveText(`Server message: ${SERVER_NOTICE}`);

  // Non-blocking: it sits BELOW the remote picture, covering none of it, and it is not an alert.
  await expect(notice).toHaveAttribute("role", "status");
  const surface = (await page.getByTestId("viewer-surface").boundingBox())!;
  const strip = (await notice.boundingBox())!;
  expect(strip.y).toBeGreaterThanOrEqual(surface.y + surface.height - 1);

  // The notice changes what the technician is told, not what ICE gets: the server's STUN is still applied.
  expect(await page.evaluate(() => (window as any).peers[0].getConfiguration().iceServers)).toEqual([
    { urls: ["stun:stun.example:3478"] },
  ]);

  // The session still connects with the notice on screen, and the notice does not time itself out. (Kept well
  // inside the 20 s stall window: this fake peer's frame counter never advances.)
  await peer(page, 0).connected();
  await page.clock.runFor(5_000);
  await expect(notice).toBeVisible();

  // Dismissible, and it stays dismissed as the connection changes state.
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(notice).toHaveCount(0);
  await peer(page, 0).fail();
  await expect(page.getByTestId("viewer-recovery")).toBeVisible();
  await expect(notice).toHaveCount(0);
});

test("a connection that fails names the relay limit as the likely cause", async ({ page }) => {
  await fixture(page);
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  await peer(page, 0).fail();

  const recovery = page.getByTestId("viewer-recovery");
  await expect(recovery).toContainText("Connection lost");
  await expect(recovery).toContainText("likely cause");
  await expect(recovery).toContainText("this account has reached its limit of relay credentials");
  // It composes with the recovery wording rather than replacing it.
  await expect(recovery).toContainText("Reconnecting in 2s");
  await expect(recovery).not.toContainText("..");
});

test("dismissing the notice does not hide the cause from the failure that follows", async ({ page }) => {
  await fixture(page);
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  await peer(page, 0).fail();

  await expect(page.getByTestId("viewer-recovery")).toContainText("limit of relay credentials");
});

test("a connection that never establishes times out naming the relay limit, in the error and in the recovery notice", async ({ page }) => {
  await fixture(page);
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  await page.clock.runFor(30_000);

  const error = page.getByTestId("app-error");
  await expect(error).toContainText("Connection timed out");
  await expect(error).toContainText("likely cause");
  await expect(error).toContainText("limit of relay credentials");
  await expect(page.getByTestId("viewer-recovery")).toContainText("limit of relay credentials");
});

test("no notice (an older server, or an account under its cap): no banner, and every message is as it was", async ({ page }) => {
  await fixture(page, { notice: null });
  // Let the ice_servers and brokered messages arrive and the offer go out before asserting an absence.
  await expect.poll(() => page.evaluate(() => (window as any).peers[0].getConfiguration().iceServers?.length ?? 0)).toBe(1);
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  await peer(page, 0).fail();
  const recovery = page.getByTestId("viewer-recovery");
  await expect(recovery).toContainText("Connection lost. Reconnecting in 2s");
  await expect(recovery).not.toContainText("relay");
  await expect(recovery).not.toContainText("likely cause");
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // The 30 s timeout of a connection that never came up is the bare message, as before.
  await page.clock.runFor(2_000);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.clock.runFor(30_000);
  const error = page.getByTestId("app-error");
  await expect(error).toContainText("Connection timed out");
  await expect(error).not.toContainText("relay");
});

test("a negotiation error while the notice is set is not blamed on the relay, in the error or in the recovery notice", async ({ page }) => {
  await fixture(page, { failOffer: true });

  // The error banner says what actually failed...
  const error = page.getByTestId("app-error");
  await expect(error).toContainText("Connection negotiation failed: offer failed");
  await expect(error).not.toContainText("relay");
  // ...and so does the recovery notice: a missing relay says nothing about a refused offer.
  const recovery = page.getByTestId("viewer-recovery");
  await expect(recovery).toContainText("Connection lost");
  await expect(recovery).not.toContainText("likely cause");
  await expect(recovery).not.toContainText("limit of relay credentials");
  // The notice itself is a fact about how the session was brokered, and stays.
  await expect(page.getByTestId("relay-notice")).toBeVisible();
});

test("once the connection has come up, a later failure is not blamed on the relay", async ({ page }) => {
  await fixture(page);
  await peer(page, 0).connected();
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  await peer(page, 0).fail();

  const recovery = page.getByTestId("viewer-recovery");
  await expect(recovery).toContainText("Connection lost");
  await expect(recovery).not.toContainText("likely cause");
  await expect(recovery).not.toContainText("limit of relay credentials");
});

test("dismissal survives the automatic reconnect, while a fresh connect shows the notice again", async ({ page }) => {
  const state = await fixture(page);
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // The connection fails; recovery builds a NEW transport, and signaling again says the account is at its cap.
  await peer(page, 0).fail();
  await expect(page.getByTestId("viewer-recovery")).toContainText("Reconnecting in 2s");
  await page.clock.runFor(2_000);
  await expect.poll(() => state.connectRequests).toBe(2);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  // The peer exists from connect(), before signaling has answered, so neither of the waits above says the page has
  // handled the new attempt's ice_servers (and its notice). Wait for that: an absence checked before it would pass
  // while a resurrected banner was still on its way.
  await expect.poll(() => iceServerCount(page, 1)).toBe(1);

  // Not resurrected for the same session of the technician's...
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);
  // ...but the new attempt knows its own cause, so ITS failure still names it.
  await peer(page, 1).fail();
  await expect(page.getByTestId("viewer-recovery")).toContainText("limit of relay credentials");
  // That wording is the new transport's own notice at work, so the notice has certainly reached the page by now:
  // the banner is still dismissed, not merely not yet back.
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // Disconnect, then connect again: a fresh session, so the notice is back (the account is still at its cap).
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);
  await connect(page);
  await expect(page.getByTestId("relay-notice")).toBeVisible();
});

test("dismissal survives the display-layout reconnect, which starts a fresh session by itself", async ({ page }) => {
  const state = await fixture(page);
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // The agent ends the session because the machine's monitors changed, and the viewer reconnects on its own. That is
  // not recovery (it cancels it): it is a fresh connect, the same road as the Reconnect button.
  await peer(page, 0).control({ t: "Error", c: { message: LAYOUT_END } });
  await expect(page.getByText("reconnecting automatically", { exact: false })).toBeVisible();
  await page.clock.runFor(1_600);
  await expect.poll(() => state.starts).toBe(2);
  await expect.poll(() => state.connectRequests).toBe(2);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  // The new session has been brokered and told about the cap: only now does an absent banner mean anything.
  await expect.poll(() => iceServerCount(page, 1)).toBe(1);

  // The technician closed it; a layout change on the machine is not a reason to open it again.
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);
  // The new session does know its cause (a failure names it), and the banner is STILL closed once that has rendered.
  await peer(page, 1).fail();
  await expect(page.getByTestId("viewer-recovery")).toContainText("limit of relay credentials");
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // Leaving the machine ends the dismissal: connecting again is a new session.
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await connect(page);
  await expect(page.getByTestId("relay-notice")).toBeVisible();
});

test("a dismissal is for the machine it was made on: another machine gets its own notice, and so does coming back", async ({ page }) => {
  await fixture(page);
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);

  // Straight to another machine, with no Disconnect in between: its session is brokered without a relay too.
  await connect(page, OTHER_DEVICE);
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  // And back to the first: connecting to the other machine ended the first one's dismissal.
  await connect(page, DEVICE);
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  // A reconnect to the SAME machine keeps a new dismissal, whichever way it is made.
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);
  await peer(page, 2).fail();
  await expect(page.getByTestId("viewer-reconnect")).toBeVisible();
  await page.getByTestId("viewer-reconnect").click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(4);
  await expect.poll(() => iceServerCount(page, 3)).toBe(1);
  await peer(page, 3).fail();
  await expect(page.getByTestId("viewer-recovery")).toContainText("limit of relay credentials");
  await expect(page.getByTestId("relay-notice")).toHaveCount(0);
});

test("the server's own text is shown as TEXT: no element is created and no script runs", async ({ page }) => {
  const payload = '<img src=x onerror="window.__relayXss=1"><script>window.__relayXss=1</script>';
  await fixture(page, { notice: payload });
  const notice = page.getByTestId("relay-notice");
  await expect(notice).toBeVisible();

  // The characters are on screen, literally, in the labelled aside...
  await expect(page.getByTestId("relay-notice-server")).toContainText(payload);
  // ...and nothing was parsed out of them.
  await expect(notice.locator("img, script")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).__relayXss)).toBeUndefined();
  // The notice's own explanation is untouched by it.
  await expect(notice).toContainText("No relay connection is available");
});

// The wire type says `relay_notice` is a string, but nothing enforces it and the server is untrusted. Each of
// these is truthy to a bare `if (msg.relay_notice)`, so each would reach the UI if the transport did not check.
for (const [name, malformed] of [
  ["an object", { message: "x" }],
  ["a number", 5],
  ["an array", ["x"]],
  ["whitespace only", "   "],
] as const) {
  test(`a malformed relay_notice (${name}) is ignored like an absent one, and the console is unharmed`, async ({ page }) => {
    await fixture(page, { notice: malformed });
    // Let the ice_servers and brokered messages arrive and be applied before asserting an absence.
    await expect.poll(() => page.evaluate(() => (window as any).peers[0].getConfiguration().iceServers?.length ?? 0)).toBe(1);
    await expect(page.getByTestId("relay-notice")).toHaveCount(0);
    await expect(page.getByTestId("viewer-surface")).toBeVisible();

    // Nor does it leave a cause behind: the failure is the plain one.
    await peer(page, 0).fail();
    const recovery = page.getByTestId("viewer-recovery");
    await expect(recovery).toContainText("Connection lost. Reconnecting in 2s");
    await expect(recovery).not.toContainText("relay");
  });
}

test("at phone width the notice wraps inside the window, drops the server's aside, and still dismisses", async ({ page }) => {
  await fixture(page);
  await expect(page.getByTestId("relay-notice")).toBeVisible();

  await page.setViewportSize({ width: 412, height: 800 });

  const notice = page.getByTestId("relay-notice");
  await expect(notice).toBeVisible();
  const width = await page.evaluate(() => ({ document: document.documentElement.scrollWidth, window: window.innerWidth }));
  expect(width.document).toBeLessThanOrEqual(width.window);
  const strip = (await notice.boundingBox())!;
  expect(strip.x).toBeGreaterThanOrEqual(0);
  expect(strip.x + strip.width).toBeLessThanOrEqual(412);
  // Nothing is cut off or scrolls sideways INSIDE the strip either (it scrolls on its own, so the page-level
  // check above cannot see an overflow there).
  expect(await notice.evaluate((el) => el.scrollWidth - el.clientWidth)).toBeLessThanOrEqual(0);
  // The wording stays; the server's own line is dropped to give the picture the room.
  await expect(notice).toContainText("No relay connection is available");
  await expect(notice).toContainText("Ask an administrator");
  await expect(page.getByTestId("relay-notice-server")).toBeHidden();
  // It must not eat the screen: a strip, well under half of the window.
  expect(strip.height).toBeLessThan(400);
  await page.getByTestId("relay-notice-dismiss").click();
  await expect(notice).toHaveCount(0);
});

test.describe("with the product-default collapsed session bar", () => {
  // Empty storage = the real default (minimal), overriding the pinned seed above.
  test.use({ storageState: { cookies: [], origins: [] } });

  test("the notice shows although the whole top row is hidden, clear of the tab, and the picture keeps its top edge", async ({ page }) => {
    await fixture(page);
    // A live session with no app error (which would force the bar open).
    await peer(page, 0).connected();
    await expect(page.locator(".app")).toHaveAttribute("data-chrome", "collapsed");
    await expect(page.locator(".app__topbar")).toBeHidden();

    // A notice in the top row would be invisible here. This one is in the session area.
    const notice = page.getByTestId("relay-notice");
    await expect(notice).toBeVisible();
    const tab = (await page.getByTestId("session-tab").boundingBox())!;
    const strip = (await notice.boundingBox())!;
    expect(strip.y).toBeGreaterThan(tab.y + tab.height);

    // It takes its room from the bottom of the picture, not the top, and Dismiss gives it back.
    const before = (await page.getByTestId("viewer-surface").boundingBox())!;
    await page.getByTestId("relay-notice-dismiss").click();
    await expect(notice).toHaveCount(0);
    const after = (await page.getByTestId("viewer-surface").boundingBox())!;
    expect(after.y).toBeCloseTo(before.y, 0);
    expect(after.height).toBeGreaterThan(before.height);
  });
});
