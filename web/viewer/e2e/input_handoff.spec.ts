/**
 * docs/61 stage 3d: handing input control between technicians, in the real App against a fake agent
 * peer and a fake signaling socket.
 *
 * Proves App.tsx wires: our own signaling id (brokered) + the participant list → the hand targets;
 * InputHandoffAvailable → the Session-menu control; the click → a HandInputControl frame naming the
 * target's SIGNALING id; InputControlChanged → the badge and the control's state (never inferred from
 * the click); an "input control:" Error → shown on the control, not as a session error; locked input →
 * a claim naming our own id; and an observer never being offered the action while seeing the badge.
 *
 * Mutation evidence per test:
 *   1: dropping onInputControlChanged's setInputHandoff → the badge never appears; dropping
 *      handInputControl() → no frame; dropping the isInputControlError branch in onError → the refusal
 *      lands in app-error instead of the control.
 *   2: removing `!observing` from inputHandoffView's show → the observer sees the hand button.
 *   3: sending the claim to a target instead of ownSignalingId → the frame names the wrong session.
 *   4: (negative control) offering the action without the agent's advertisement → it appears.
 *   5: falling back to a remaining target when the pick leaves → the hand goes to PEER2 unasked
 *      (Codex 3d review).
 *   6: dropping the routing-layer isCurrent() in App's transport onMessage → the old session's frames
 *      land (the hand-off callbacks rely on that guard, like every other control callback).
 *
 * Follows supervisor_observe.spec.ts: RTCPeerConnection is stubbed, signaling is a routed socket.
 */
import { test, expect, type Page } from "@playwright/test";
import { clickAccessAction, openAccessActions } from "./machine_actions";

const DEVICE = "00112233-4455-6677-8899-aabbccddeeff";
const WS = "ws://127.0.0.1:5188/ws";
const OWN = "aaaaaaaa-0000-4000-8000-000000000001";
const PEER = "bbbbbbbb-0000-4000-8000-000000000002";
const WATCHER = "cccccccc-0000-4000-8000-000000000003";

async function fixture(page: Page, observe = false) {
  let socket: { send: (message: string) => void } | null = null;
  let brokered = false;
  await page.route(/.*/, (route) =>
    new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") {
      return route.fulfill({ json: { machines: [{ id: "machine", device_id: DEVICE, name: "Machine", group_id: "group", os: "windows", online: true, multi_session_capable: true }], presence_known: true } });
    }
    if (path === "/cp/sessions") {
      if (route.request().method() !== "POST") return route.fulfill({ json: { sessions: [] } });
      const body = route.request().postDataJSON();
      return route.fulfill({ json: { session: { id: "cp-session" }, ...(body.access ? { session_policy: { access: "view_only", signed: "signed-policy" } } : {}), signaling: { url: WS, ticket: {} } } });
    }
    return route.fulfill({ json: {} });
  });
  await page.routeWebSocket(WS, (ws) => {
    socket = ws;
    ws.onMessage((message) => {
      const msg = JSON.parse(String(message));
      if (msg.type === "connect_request") {
        brokered = true;
        ws.send(JSON.stringify({
          type: "brokered", session: OWN, peer_device: DEVICE, peer_pubkey: "ed25519:agent-mock",
          ...(observe ? { access: "view_only", access_version: 1 } : {}),
        }));
      }
    });
  });
  await page.addInitScript(() => {
    const w = window as any;
    w.peers = [];
    class Peer {
      connectionState = "new"; onconnectionstatechange: any; ontrack: any; onicecandidate: any;
      dc: any = { readyState: "open", sent: [] as ArrayBuffer[], send(b: ArrayBuffer) { this.sent.push(b); }, close() { this.readyState = "closed"; this.onclose?.(); } };
      constructor() { w.peers.push(this); }
      createDataChannel() { return this.dc; } addTransceiver() {}
      createOffer() { return Promise.resolve({ type: "offer", sdp: "v=0 mock-offer" }); } setLocalDescription() { return Promise.resolve(); }
      close() { this.connectionState = "closed"; this.onconnectionstatechange?.(); }
      getStats() { return Promise.resolve(new Map([["video", { type: "inbound-rtp", kind: "video", framesDecoded: 1 }]])); }
      connected() { this.connectionState = "connected"; this.onconnectionstatechange?.(); }
      control(message: unknown) {
        const bytes = new TextEncoder().encode(JSON.stringify(message));
        const frame = new Uint8Array(5 + bytes.length);
        new DataView(frame.buffer).setUint32(1, bytes.length);
        frame.set(bytes, 5);
        this.dc.onmessage?.({ data: frame.buffer });
      }
      controlSent(): unknown[] {
        return this.dc.sent.flatMap((b: ArrayBuffer) => {
          const v = new Uint8Array(b);
          if (v[0] !== 0) return [];
          try { return [JSON.parse(new TextDecoder().decode(v.slice(5)))]; } catch { return []; }
        });
      }
    }
    w.RTCPeerConnection = Peer;
  });
  await page.goto(test.info().project.use.baseURL!);
  if (observe) await clickAccessAction(page, DEVICE, `observe-${DEVICE}`);
  else await page.getByTestId(`connect-${DEVICE}`).click();
  await expect.poll(() => brokered).toBe(true);
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(1);
  await page.evaluate(() => (window as any).peers[0].connected());
  return {
    participants: (list: Array<{ session_id: string; access: string; technician_id?: string }>) =>
      socket!.send(JSON.stringify({ type: "session_participants", device_id: DEVICE, participants: list })),
  };
}

const agent = (page: Page, message: unknown) =>
  page.evaluate((m) => (window as any).peers[0].control(m), message);
const handsSent = (page: Page) =>
  page.evaluate(() => (window as any).peers[0].controlSent().filter((m: any) => m.t === "HandInputControl"));
const openSessionMenu = (page: Page) => page.getByRole("button", { name: "Session", exact: true }).click();

const everyone = [
  { session_id: OWN, access: "control", technician_id: "11111111-aaaa" },
  { session_id: PEER, access: "control", technician_id: "22222222-bbbb" },
  { session_id: WATCHER, access: "view_only", technician_id: "33333333-cccc" },
];

test("hand to a co-technician: the frame names their signaling id, and only the agent's snapshot moves control", async ({ page }) => {
  const sig = await fixture(page);
  sig.participants(everyone);
  await agent(page, { t: "InputHandoffAvailable", c: { available: true } });
  await openSessionMenu(page);
  await expect(page.getByTestId("input-handoff-status")).toContainText("shared");
  const hand = page.getByTestId("input-handoff-hand");
  // The observer is not a target: one target means no picker, and the button names it.
  await expect(page.getByTestId("input-handoff-target")).toHaveCount(0);
  await expect(hand).toHaveText("Hand input control to Technician 22222222 · session bbbbbbbb");
  await hand.click();
  await expect.poll(() => handsSent(page)).toEqual([{ t: "HandInputControl", c: { to_session: PEER } }]);
  await expect(hand).toBeDisabled(); // pending: the agent ignores repeats meanwhile
  // The click alone changes nothing — no badge until the agent's snapshot.
  await expect(page.getByTestId("input-control-badge")).toHaveCount(0);

  await agent(page, { t: "InputControlChanged", c: { owner_session: PEER, owner_name: null, mode: "owned" } });
  await expect(page.getByTestId("input-control-badge")).toHaveText("Another technician has input control");
  await expect(page.getByTestId("input-handoff-status")).toHaveText("Another technician has input control.");
  await expect(hand).toBeDisabled(); // only the owner can hand on

  // It comes back: we own input, and a refusal of our next hand lands on the control, not as a
  // session error, and leaves ownership exactly as it was.
  await agent(page, { t: "InputControlChanged", c: { owner_session: OWN, owner_name: null, mode: "owned" } });
  await expect(page.getByTestId("input-control-badge")).toHaveText("You have input control");
  await expect(hand).toBeEnabled();
  await hand.click();
  await agent(page, { t: "Error", c: { message: "input control: that technician is no longer in this session" } });
  await expect(page.getByTestId("input-handoff-error")).toHaveText("that technician is no longer in this session");
  // ...and in the toolbar row too, so it is seen even with the Session menu closed.
  await expect(page.getByTestId("input-control-error")).toHaveText("that technician is no longer in this session");
  await expect(page.getByTestId("app-error")).toHaveCount(0);
  await expect(page.getByTestId("input-control-badge")).toHaveText("You have input control");
  await expect(hand).toBeEnabled();
});

test("an observer is never offered the action, but sees who has control", async ({ page }) => {
  const sig = await fixture(page, true);
  sig.participants(everyone);
  // Even an agent claiming availability (it tells observers false) must not surface the action.
  await agent(page, { t: "InputHandoffAvailable", c: { available: true } });
  await agent(page, { t: "InputControlChanged", c: { owner_session: PEER, owner_name: null, mode: "owned" } });
  await expect(page.getByTestId("input-control-badge")).toHaveText("Another technician has input control");
  await openSessionMenu(page);
  await expect(page.getByTestId("input-handoff")).toHaveCount(0);
  await expect(page.getByTestId("input-handoff-hand")).toHaveCount(0);
});

test("locked input is claimed with our OWN signaling id", async ({ page }) => {
  const sig = await fixture(page);
  sig.participants(everyone);
  await agent(page, { t: "InputHandoffAvailable", c: { available: true } });
  await agent(page, { t: "InputControlChanged", c: { owner_session: null, owner_name: null, mode: "blocked" } });
  await expect(page.getByTestId("input-control-badge")).toHaveText("Input locked");
  await openSessionMenu(page);
  await expect(page.getByTestId("input-handoff-hand")).toHaveCount(0);
  await page.getByTestId("input-handoff-claim").click();
  await expect.poll(() => handsSent(page)).toEqual([{ t: "HandInputControl", c: { to_session: OWN } }]);
});

test("negative control: an agent that never advertises gets no hand-off action", async ({ page }) => {
  const sig = await fixture(page);
  sig.participants(everyone);
  await openSessionMenu(page);
  // The menu is open (its own status line renders), so an absent control is a real absence.
  await expect(page.getByRole("button", { name: "Session", exact: true })).toBeVisible();
  await expect(page.getByTestId("input-handoff")).toHaveCount(0);
  await expect(page.getByTestId("input-control-badge")).toHaveCount(0);
});

const PEER2 = "dddddddd-0000-4000-8000-000000000004";

test("a picked technician who leaves voids the pick: control is never handed to someone else", async ({ page }) => {
  const sig = await fixture(page);
  const four = [...everyone, { session_id: PEER2, access: "control", technician_id: "44444444-dddd" }];
  sig.participants(four);
  await agent(page, { t: "InputHandoffAvailable", c: { available: true } });
  await openSessionMenu(page);
  const hand = page.getByTestId("input-handoff-hand");
  const pick = page.getByTestId("input-handoff-target");
  await expect(hand).toBeDisabled(); // two targets: an explicit pick is required
  await pick.selectOption(PEER);
  await expect(hand).toBeEnabled();
  // The picked technician leaves; one other remains. The pick is VOID — not moved to the survivor.
  sig.participants(four.filter((p) => p.session_id !== PEER));
  await expect(hand).toBeDisabled();
  await expect(pick).toBeVisible(); // still there, so the technician can choose again
  expect(await handsSent(page)).toEqual([]);
  await pick.selectOption(PEER2);
  await expect(hand).toBeEnabled();
  await hand.click();
  await expect.poll(() => handsSent(page)).toEqual([{ t: "HandInputControl", c: { to_session: PEER2 } }]);
});

test("a superseded session's late frames cannot advertise or report ownership in the next session", async ({ page }) => {
  const sig = await fixture(page);
  sig.participants(everyone);
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await page.getByTestId(`connect-${DEVICE}`).click();
  await expect.poll(() => page.evaluate(() => (window as any).peers.length)).toBe(2);
  await page.evaluate(() => (window as any).peers[1].connected());
  sig.participants(everyone);
  // Late frames on the OLD session's control channel.
  await page.evaluate((peer) => {
    const old = (window as any).peers[0];
    old.control({ t: "InputHandoffAvailable", c: { available: true } });
    old.control({ t: "InputControlChanged", c: { owner_session: peer, owner_name: null, mode: "owned" } });
  }, PEER);
  await openSessionMenu(page);
  await expect(page.getByTestId("input-handoff")).toHaveCount(0);
  await expect(page.getByTestId("input-control-badge")).toHaveCount(0);
  // Positive control: the same frames on the CURRENT session do land.
  await page.evaluate((peer) => {
    const cur = (window as any).peers[1];
    cur.control({ t: "InputHandoffAvailable", c: { available: true } });
    cur.control({ t: "InputControlChanged", c: { owner_session: peer, owner_name: null, mode: "owned" } });
  }, PEER);
  await expect(page.getByTestId("input-control-badge")).toHaveText("Another technician has input control");
  await expect(page.getByTestId("input-handoff")).toHaveCount(1);
});

test("a view-only session is not offered the action (the agent would refuse it)", async ({ page }) => {
  const sig = await fixture(page);
  sig.participants(everyone);
  await agent(page, { t: "InputHandoffAvailable", c: { available: true } });
  await agent(page, { t: "ViewOnlyApplied", c: { enabled: true } });
  await agent(page, { t: "InputControlChanged", c: { owner_session: PEER, owner_name: null, mode: "owned" } });
  await expect(page.getByTestId("input-control-badge")).toHaveText("Another technician has input control");
  await openSessionMenu(page);
  await expect(page.getByTestId("input-handoff")).toHaveCount(0);
  // Positive control: view-only lifted -> offered again.
  await agent(page, { t: "ViewOnlyApplied", c: { enabled: false } });
  await expect(page.getByTestId("input-handoff")).toHaveCount(1);
});
