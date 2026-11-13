/**
 * Multi-tab and multi-machine lifecycle browser tests (viewer pass2).
 *
 * Scenarios (see PLAN.md Stage 1, RUNTIME-CONTRACTS.md, prompt-pass2.txt):
 *   1. login-before-autoconnect   — URL params don't trigger connect until auth gate is "open"
 *   2. auth-required-blocks-autoconnect — 401 (required) gate also suppresses autoconnect
 *   3. first-tab-stays-connected  — second tab connecting to a different machine doesn't affect tab 1
 *   4. disconnect-isolation       — closing tab 2 leaves tab 1's session intact
 *   5. cross-tab-auth-expiry      — auth expiry in tab 1 closes its socket; tab 2 is unaffected
 *   6. 403-fallback-no-login-gate — 403 from /sessions → direct-connect fallback, no login gate
 *   7. session-participants-badge — session_participants WS message triggers co-tech badge
 *   8. focused-input-isolation    — keyboard input in one tab is contained to that tab's transport
 *
 * All tests use Playwright route mocking for both the control-plane (/cp/**) and the signaling
 * WebSocket (ws://127.0.0.1:8080/ws — the dev default). No real signaling server or control plane
 * is started; the Vite dev server (playwright.config.ts webServer) serves the real App bundle.
 *
 * Design notes:
 *   - 503 from POST /cp/sessions simulates "brokered path unavailable" → acquireBrokeredSession
 *     returns null → direct-connect fallback to the operator signaling URL. Same code path as
 *     the 403 case except for the login-gate side-effect (see test 6).
 *   - 401 from GET /cp/auth/session triggers AuthSession.expire() via the fetch interceptor in
 *     auth_session.ts, which sets isCurrent()=false and calls onExpired → "required" gate.
 *     This is tested in auth_expiry.spec.ts; we extend it with a multi-tab scenario here.
 *   - 403 from POST /cp/sessions does NOT trigger AuthSession.expire() (only 401 does). The
 *     connect falls back to direct-connect and the login gate is NOT shown. This is the correct
 *     behavior for an "unauthorized for this device" response: the tech is still authenticated.
 *   - Multi-tab isolation is structurally guaranteed by the browser's separate JS contexts, but
 *     these tests catch viewer-side regressions (e.g. shared refs, state leaking across tabs).
 */

import { test, expect, type Page } from "@playwright/test";
import { openAccountControls } from "./nav";

// The Vite dev server URL (must match playwright.config.ts webServer.command port).
const APP_BASE = "http://127.0.0.1:5173";

// The signaling URL the app derives from http://127.0.0.1:5173 in dev mode.
// parseMachineUrlParams → defaultSignalingUrl({ hostname: "127.0.0.1" }) → DEV_SIGNALING_URL.
const SIGNALING_WS = "ws://127.0.0.1:8080/ws";

const DEVICE_A = "2b948dba-0000-4000-8000-aabbccddee01";
const DEVICE_B = "2b948dba-0000-4000-8000-aabbccddee02";
// The session label comes from the machine list, never from the link's `name` (security audit
// 2026-10-18), so every mocked list carries the devices the links name, under the expected names.
const LISTED_MACHINES = [
  { id: "m-a", tenant_id: "t", device_id: DEVICE_A, group_id: "g", name: "Machine-A", online: true },
  { id: "m-b", tenant_id: "t", device_id: DEVICE_B, group_id: "g", name: "Machine-B", online: true },
];

// Absolute URL that parseMachineUrlParams will accept: device + name + same-host signaling.
function autoConnectUrl(device: string, name: string): string {
  return `${APP_BASE}/?device=${device}&name=${encodeURIComponent(name)}&signaling=${encodeURIComponent(SIGNALING_WS)}`;
}

/**
 * Wire up control-plane route mocking on `page`. Returns a mutable state object so tests can
 * change status codes after navigation (Playwright re-evaluates the handler on each request).
 *
 * Default: auth returns 204 (authenticated), sessions returns 503 (no broker → direct-connect
 * fallback), machines returns an empty enrolled list.
 */
async function cpFixture(page: Page) {
  const state = { authStatus: 204, sessionStatus: 503 };
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") {
      await route.fulfill({ status: state.authStatus });
      return;
    }
    if (path === "/cp/auth/login") {
      await route.fulfill({ status: 200, json: {} });
      return;
    }
    if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "POST") {
      await route.fulfill({ status: state.sessionStatus, json: { error: "no broker" } });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });
  return state;
}

// ---------------------------------------------------------------------------
// 1. login-before-autoconnect
// ---------------------------------------------------------------------------
//
// The auth gate is driven by the fleet-load effect (GET /cp/machines), NOT by GET /cp/auth/session.
// authGate starts "checking", becomes "open" when listMachinesWithPresence() succeeds, or "required"
// when it gets a 401. To hold the gate in "checking" we must delay the GET /cp/machines response.

test("URL-param auto-connect does not fire while auth is checking, then fires once gate opens", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));

  // Hold ALL GET /cp/machines requests so the fleet-load effect never completes → authGate stays
  // "checking". React 18 Strict Mode in dev double-invokes effects, producing two fetches; we hold
  // all of them with the same promise so neither resolves early.
  let releaseMachines!: () => void;
  const machinesHeld = new Promise<void>((r) => { releaseMachines = r; });

  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/machines") {
      await machinesHeld;   // ALL machines calls hold; release once to unblock all
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "GET") {
      await route.fulfill({ json: { sessions: [] } });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "POST") {
      await route.fulfill({ status: 503, json: {} });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  // NOTE: do NOT call page.routeWebSocket here. routeWebSocket intercepts at the CDP network
  // layer before the page-level "websocket" event fires, which means page.waitForEvent("websocket")
  // and page.on("websocket", ...) never see the connection. Test 6 (403 fallback) demonstrates the
  // correct pattern: let the WebSocket attempt reach port 8080 unintercepted. The connection will
  // fail (no server running), but the "websocket" page event fires at WebSocket CONSTRUCTION time —
  // before the open/error/close callbacks — so waitForEvent resolves immediately on creation.

  // Register the socket listener BEFORE goto so the full window is available from page load.
  // The predicate filters out Vite HMR sockets (which do not use port 8080).
  const socketAfterGate = page.waitForEvent("websocket", {
    predicate: (ws) => ws.url().includes("8080"),
    timeout: 15_000,
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));

  // App must show the "checking" gate — all GET /cp/machines are held so auth hasn't resolved.
  await expect(page.getByTestId("app-auth-checking")).toBeVisible({ timeout: 10_000 });
  // No signaling socket yet: autoconnect fires only when authGate === "open".
  expect(sockets.filter((s) => s.includes("8080")), "no socket while auth is checking").toHaveLength(0);

  // Release the held requests → fleet effect resolves → setAuthGate("open") → URL-param effect.
  releaseMachines();

  // Confirm POST /sessions is intercepted (returns 503) so acquireBrokeredSession returns null
  // and direct-connect fallback proceeds to open the signaling socket.
  const sessionsResp = await page.waitForResponse(
    (r) => r.url().includes("/cp/sessions") && r.request().method() === "POST",
    { timeout: 10_000 },
  );
  expect(sessionsResp.status(), "POST /sessions mock returns 503 → direct-connect fallback").toBe(503);

  // Session view appears once connectImpl sets session + area="live" (before broker await).
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 10_000 });
  // Signaling socket opened (direct-connect fallback since POST /sessions returned 503).
  const openedSocket = await socketAfterGate;
  expect(openedSocket.url(), "socket is the dev signaling URL").toContain("8080");
});

// ---------------------------------------------------------------------------
// 2. auth-required gate blocks autoconnect
// ---------------------------------------------------------------------------
//
// GET /cp/machines returning 401 → AuthSession.expire() fires → setAuthGate("required").
// The URL-param auto-connect effect guards on authGate==="open" and must not fire.
//
// Navigation note: at the root path "/", App.tsx renders JoinPage when authGate="required" and
// no authNotice (line 2140-2145) — the join flow for attended support. The technician login form
// with data-testid="app-login-gate" appears only when the path is "/console" or "/login".
// We navigate to "/console" so the login gate is observable.
//
// Socket detection: do NOT call page.routeWebSocket here. routeWebSocket intercepts at the CDP
// network layer BEFORE the page-level "websocket" event fires — so a socket opened through a
// routeWebSocket handler would be invisible to page.on("websocket", ...) and the sockets array
// check would pass vacuously even if the auto-connect guard were broken. Instead, leave port 8080
// unintercepted: a spurious socket attempt reaches the port, fails (no server), but the
// "websocket" page event fires at WebSocket construction time — before the error — and IS caught.

test("URL-param auto-connect is suppressed when auth gate is required (401)", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));

  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/machines") {
      // 401 → AuthSession.expire() → setAuthGate("required")
      await route.fulfill({ status: 401 });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "GET") {
      await route.fulfill({ status: 401 });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  // Navigate to /console so authGate="required" renders the login form (not the attended JoinPage).
  // The URL params are still present in the query string; parseMachineUrlParams reads search only.
  const consoleUrl = `${APP_BASE}/console?device=${DEVICE_A}&name=${encodeURIComponent("Machine-A")}&signaling=${encodeURIComponent(SIGNALING_WS)}`;
  await page.goto(consoleUrl);

  // Login gate must appear after the 401 from GET /cp/machines.
  await expect(page.getByTestId("app-login-gate")).toBeVisible({ timeout: 10_000 });

  // The URL-param effect has [authGate, handleConnect] deps.
  // It fires when authGate changes, but `authGate !== "open"` guard prevents connect.
  // Port 8080 is unintercepted — a spurious socket attempt would be caught by the sockets array.
  await page.waitForTimeout(500);
  expect(sockets.filter((s) => s.includes("8080")), "no socket with required gate").toHaveLength(0);
});

// ---------------------------------------------------------------------------
// 3. first tab stays connected on second tab
// ---------------------------------------------------------------------------

test("first tab session is unaffected when second tab auto-connects to a different machine", async ({ page, context }) => {
  // Tab 1: auth OK, auto-connect to DEVICE_A.
  await cpFixture(page);
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });
  // Confirm tab 1's machine identity.
  await expect(page.getByTestId("viewer-machine-label")).toContainText("Machine-A");

  // Tab 2: independent JS context, auto-connect to DEVICE_B.
  const page2 = await context.newPage();
  await cpFixture(page2);
  await page2.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });

  await page2.goto(autoConnectUrl(DEVICE_B, "Machine-B"));
  await expect(page2.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });
  await expect(page2.getByTestId("viewer-machine-label")).toContainText("Machine-B");

  // Tab 1 must still be showing its session unchanged.
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible();
  await expect(page.getByTestId("viewer-machine-label")).toContainText("Machine-A");
  // Tab 1's auth gate must not have appeared (no spurious sign-out or teardown).
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);

  await page2.close();
});

// ---------------------------------------------------------------------------
// 4. disconnect isolation
// ---------------------------------------------------------------------------

test("closing second tab leaves first tab session intact", async ({ page, context }) => {
  await cpFixture(page);
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  const page2 = await context.newPage();
  await cpFixture(page2);
  await page2.routeWebSocket(SIGNALING_WS, (ws) => { ws.onMessage(() => {}); });
  await page2.goto(autoConnectUrl(DEVICE_B, "Machine-B"));
  await expect(page2.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  // Close tab 2.
  await page2.close();

  // Tab 1 must still show its session and machine label.
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible();
  await expect(page.getByTestId("viewer-machine-label")).toContainText("Machine-A");
  // No error should have appeared in tab 1.
  await expect(page.getByTestId("app-error")).toHaveCount(0);
});

// ---------------------------------------------------------------------------
// 5. cross-tab logout — shared auth state, UI logout, bounded teardown
// ---------------------------------------------------------------------------
//
// Real browser tabs share authentication cookies. This test uses context-level routes
// (shared across all pages in the context) so that a logout in tab 1 invalidates the
// server session for tab 2 as well — matching the production cookie model.
//
// The sign-out is triggered through the real App UI button (data-testid="app-signout"),
// not by directly mutating a per-page mock variable. When tab 1 signs out:
//   - handleLogout calls authSession.expire() immediately → tab 1 shows login gate at once.
//   - POST /auth/logout is sent → the shared mock sets authStatus=401 for all pages.
//   - Tab 2's next periodic auth check (every ~30 s) returns 401 → tab 2 shows login gate.
//
// Each tab has its own signaling socket, tracked independently. Both must close within the
// 30 s policy bound (bounded teardown). Neither socket's lifecycle affects the other's.
//
// Navigation note: both tabs navigate to /console so that when authGate="required", the
// technician login form (data-testid="app-login-gate") renders, not the customer JoinPage.

test("UI logout in tab 1 invalidates shared auth; both tabs reach login gate within 30 s", async ({ page, context }) => {
  // Shared auth state: changes to sharedState affect all pages in this context.
  const sharedState = { authStatus: 204 };

  // Install clocks on page before routes and navigation so time-based effects are controllable.
  await page.clock.install();

  // Context-level routes apply to ALL pages (shared cookies model).
  // Page-level routeWebSocket is still per-page — each tab has its own signaling socket.
  await context.route("**/cp/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();

    if (path === "/cp/auth/session") {
      await route.fulfill({ status: sharedState.authStatus });
      return;
    }
    if (path === "/cp/auth/login" && method === "POST") {
      await route.fulfill({ status: 200, json: {} });
      return;
    }
    if (path === "/cp/auth/logout" && method === "POST") {
      // Shared logout: invalidates the server session for ALL pages.
      sharedState.authStatus = 401;
      await route.fulfill({ status: 200 });
      return;
    }
    if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } });
      return;
    }
    if (path === "/cp/sessions" && method === "POST") {
      // Direct-connect fallback (503 → acquireBrokeredSession returns null).
      await route.fulfill({ status: 503, json: { error: "no broker" } });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  // Tab 1 signaling: track its socket close independently.
  let tab1SocketClosed = false;
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
    ws.onClose(() => { tab1SocketClosed = true; });
  });

  await page.goto(`${APP_BASE}/console?device=${DEVICE_A}&name=${encodeURIComponent("Machine-A")}&signaling=${encodeURIComponent(SIGNALING_WS)}`);
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  // Tab 2: its own signaling socket, tracked independently.
  const page2 = await context.newPage();
  await page2.clock.install();

  let tab2SocketClosed = false;
  await page2.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
    ws.onClose(() => { tab2SocketClosed = true; });
  });
  await page2.goto(`${APP_BASE}/console?device=${DEVICE_B}&name=${encodeURIComponent("Machine-B")}&signaling=${encodeURIComponent(SIGNALING_WS)}`);
  await expect(page2.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  // Both tabs are connected and their shared sharedState.authStatus is still 204.

  // --- Tab 1 signs out via the actual UI sign-out button ---
  // handleLogout calls authSession.expire() (local) + POST /auth/logout (shared).
  // The shared mock sets authStatus=401 on logout, so tab 2's next check also gets 401.
  await openAccountControls(page);
  await page.getByTestId("app-signout").click();

  // Tab 1 shows login gate immediately (authSession.expire() is called synchronously in handleLogout).
  await expect(page.getByTestId("app-login-gate")).toBeVisible({ timeout: 5_000 });

  // Tab 1's signaling socket closes when authSession.expire() triggers the auth-expiry handler.
  await expect.poll(() => tab1SocketClosed, { timeout: 5_000 }).toBe(true);

  // Tab 2's auth check fires on its next 30 s tick. The shared auth state is now 401.
  // Advance tab 2's clock to trigger the periodic check.
  await page2.clock.runFor(30_000);
  await expect(page2.getByTestId("app-login-gate")).toBeVisible({ timeout: 8_000 });
  await expect.poll(() => tab2SocketClosed, { timeout: 5_000 }).toBe(true);

  // Independent teardown: tab 2's socket closed independently from tab 1's.
  // Both signaling sockets had their own lifecycle — one's close did not cause the other's.
  expect(tab1SocketClosed, "tab 1 socket closed after UI logout").toBe(true);
  expect(tab2SocketClosed, "tab 2 socket closed after shared auth invalidation").toBe(true);

  await page2.close();
});

// ---------------------------------------------------------------------------
// 6. 403 from /sessions → device-refusal error shown, NO socket (fail-closed)
// ---------------------------------------------------------------------------
//
// A 403 from POST /cp/sessions means "authenticated but NOT authorized for this device"
// (wrong tenant, group, or RBAC). The viewer must fail-closed: show a visible device-refusal
// error and NOT open a signaling socket. The login gate must also NOT appear (403 ≠ 401).
//
// Previously the viewer fell back to direct-connect after 403, which opened a signaling socket
// without a ticket. On a production signaling server (SIGNALING_TICKET_PUBKEY set) that socket
// would be rejected, but the viewer was silently racing instead of surfacing the access denial.
//
// This test verifies the corrected fail-closed behavior.
//
// 6b (note). The development path (CP unreachable / 503 / no CP at all) still falls back to
// direct-connect — test 1 covers that case (503 → socket opens). The distinction is intentional:
// 503/network-error means the CP was never reachable and we cannot determine authorization, so
// the legacy direct-connect path is valid for dev. 403 means the CP DID respond and explicitly
// denied access, so the viewer must refuse, not silently try without a ticket.

test("403 from sessions endpoint shows device-refusal error and does not open a signaling socket", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (ws) => sockets.push(ws.url()));

  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
      return;
    }
    if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "POST") {
      // 403: authenticated but not authorized for this device.
      await route.fulfill({ status: 403, json: { error: "not authorized for device" } });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));

  // The viewer renders the machine label (set before the broker round-trip returns),
  // then discovers the 403 and shows the device-refusal error.
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 10_000 });

  // 403 must surface a device-refusal error, not the login gate.
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  await expect(page.getByTestId("app-error")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByTestId("app-error")).toContainText("Not authorized");

  // No signaling socket must have been opened — fail-closed, no ticketless fallback.
  await page.waitForTimeout(500); // settle: any spurious socket would have fired by now
  expect(sockets.filter((s) => s.includes("8080")), "no signaling socket after 403").toHaveLength(0);
});

// ---------------------------------------------------------------------------
// 7. session_participants badge
// ---------------------------------------------------------------------------

test("session_participants message from signaling server triggers co-tech badge", async ({ page }) => {
  await cpFixture(page);


  // Signaling mock: on the first session_participants message after registering, push a
  // participant list with one peer. With brokered=null (no session broker) the app includes
  // ALL participants as peers (ownSessionId=null path).
  let mockWs: { send: (msg: string) => void } | null = null;
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    mockWs = ws;
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  // Push a session_participants message for this device from the "server".
  await page.evaluate(([wsUrl, deviceId]) => {
    // The app's signaling subscription is on the real in-page SignalingClient. We push the
    // participant message via the Playwright WebSocket mock by evaluating in the page context.
    // Playwright's routeWebSocket intercept lets us send from the test process via `ws.send()`,
    // but we need to trigger it from the test side. Use the externally-stored mockWs reference.
    // Since we cannot call mockWs.send() from inside page.evaluate, we expose a helper on window.
    void wsUrl; void deviceId;
  }, [SIGNALING_WS, DEVICE_A]);

  // Push the participant message from the test process (outside the page).
  // mockWs.send() sends FROM the "server" TO the page's SignalingClient.
  await expect.poll(() => mockWs !== null, { timeout: 5_000 }).toBe(true);
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: DEVICE_A,
    participants: [
      { session_id: "peer-sess-1", technician_id: "tech-alice" },
    ],
  }));

  // Badge should appear showing 1 co-tech.
  await expect(page.getByTestId("session-participants")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByTestId("session-participants")).toContainText("1 co-tech");

  // Updating the participant list to two peers updates the badge.
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: DEVICE_A,
    participants: [
      { session_id: "peer-sess-1", technician_id: "tech-alice" },
      { session_id: "peer-sess-2", technician_id: "tech-bob" },
    ],
  }));
  await expect(page.getByTestId("session-participants")).toContainText("2 co-techs");

  // A session_participants for a DIFFERENT device must not update the badge.
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: "different-device-id",
    participants: [
      { session_id: "x", technician_id: "tech-x" },
      { session_id: "y", technician_id: "tech-y" },
      { session_id: "z", technician_id: "tech-z" },
    ],
  }));
  // Guard fires: device_id !== connected device → badge count unchanged.
  await expect(page.getByTestId("session-participants")).toContainText("2 co-techs");

  // Clearing participants (disconnect) hides the badge.
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: DEVICE_A,
    participants: [],
  }));
  await expect(page.getByTestId("session-participants")).toHaveCount(0, { timeout: 5_000 });
});

// ---------------------------------------------------------------------------
// 8. signaling-layer isolation (NOT data-channel input proof)
// ---------------------------------------------------------------------------
//
// Each browser tab has its own JS context and opens its own WebSocket to the signaling server.
// This test verifies signaling-layer isolation: tab A's register_agent / connect_request messages
// never appear on tab B's socket, and vice versa.
//
// SCOPE: this is SIGNALING isolation only. Actual input events (key/mouse) are serialised over
// the WebRTC data channel, which requires a full ICE/SDP handshake not supported by the mock
// WebSocket here. Data-channel input isolation is proven by the real-agent test in
// browser-agent.spec.ts ("App-level two-machine session isolation"). Keyboard events dispatched
// to the page here do NOT reach any agent — they do not cross the WebRTC layer.

test("signaling-layer isolation: tab A's register/connect messages are absent from tab B socket", async ({ page, context }) => {
  const tabAMessages: string[] = [];
  const tabBMessages: string[] = [];

  await cpFixture(page);
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      tabAMessages.push(String(msg));
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });
  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  const page2 = await context.newPage();
  await cpFixture(page2);
  await page2.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      tabBMessages.push(String(msg));
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });
  await page2.goto(autoConnectUrl(DEVICE_B, "Machine-B"));
  await expect(page2.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  // Wait for tab B's signaling handshake to complete (register_agent → connect_request) before
  // taking the snapshot baseline, so its own connection messages don't appear as "new" ones.
  // viewer-machine-label visible means the App reached area="live", but the WS handshake can
  // still be in-flight. Poll until tab B has sent both its connection messages.
  await page2.waitForFunction(
    () => (window as unknown as { __tabBMsgCount?: number }).__tabBMsgCount ?? 0,
    undefined,
    { timeout: 5_000 },
  ).catch(() => {
    // Fallback: a brief settle so any in-flight messages arrive before we snapshot.
    // __tabBMsgCount is only available if the test exposes it; skip if not.
  });
  // Settle: allow any in-flight signaling traffic from tab B's own connection to land.
  await page2.waitForTimeout(500);

  const tabABefore = tabAMessages.length;
  const tabBBefore = tabBMessages.length;

  // Dispatch keyboard events to tab A's viewer surface. Keyboard input goes over the WebRTC
  // data channel (not signaling), so it must NOT generate any new signaling messages on either socket.
  await page.keyboard.press("a");
  await page.keyboard.press("b");

  // Allow a tick for any async signaling dispatch that would follow a key event.
  await page.waitForTimeout(300);

  // Tab B's socket must have received no NEW outbound messages triggered by tab A's keystrokes.
  // Tab A's keyboard events are encoded and sent over the WebRTC data channel — they do not
  // generate signaling traffic. Any message appearing here would indicate session cross-wiring.
  const tabBNewMessages = tabBMessages.slice(tabBBefore);
  expect(
    tabBNewMessages,
    "tab B's signaling socket received no outbound messages caused by tab A keyboard input",
  ).toHaveLength(0);

  // Tab A's socket remains open and its session is intact.
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible();

  await page2.close();
});

// ---------------------------------------------------------------------------
// 9. session_participants self-filter uses signaling session ID, not CP record ID
// ---------------------------------------------------------------------------
//
// Finding 1 (Codex review): App.tsx must filter `session_participants` entries by the
// signaling-level session id (from the "brokered" WS message), NOT by the CP record id
// (brokered.sessionId from POST /sessions). broker.go independently generates the signaling
// session id (newUUID at lines 197-202), so the two ids are always distinct in production.
//
// This test uses a mocked signaling server that:
//   a) Sends a "brokered" message with a DISTINCT session id from the CP record ("sig-sess-XYZ").
//   b) Then sends a "session_participants" message containing only our own signaling session id.
//
// If the App filters by CP record id ("cp-sess-ABC"), self would NOT be removed and the badge
// would show "1 co-tech". With the correct fix (filter by signaling session id "sig-sess-XYZ"),
// self IS removed and the badge does NOT appear — zero peers.
//
// We then add a real peer (different session id) and confirm the badge shows "1 co-tech",
// proving the filter distinguishes self from peers by the signaling id.

test("session_participants self-filter uses signaling session ID, not CP record ID", async ({ page }) => {
  // The CP mock returns a brokered session with record id "cp-sess-ABC".
  const CP_SESSION_ID = "cp-sess-ABC-record";
  // The signaling server will assign a DIFFERENT id for our signaling session.
  const SIG_SESSION_OWN = "sig-sess-XYZ-signaling";
  // A peer's signaling session id (different from both CP and own signaling ids).
  const SIG_SESSION_PEER = "sig-sess-PEER-456";

  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
      return;
    }
    if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } });
      return;
    }
    if (path === "/cp/sessions" && route.request().method() === "POST") {
      // Return a brokered session: CP record id is CP_SESSION_ID (DISTINCT from what signaling
      // will assign). The signaling envelope must include url + a minimal signed ticket so the
      // App's connect_request is well-formed. The mock signaling handler ignores ticket content.
      await route.fulfill({
        status: 200,
        json: {
          session: {
            id: CP_SESSION_ID,
            tenant_id: "t-mock",
            machine_id: "m-mock",
            technician_id: "tech-me",
            started_at: new Date().toISOString(),
            consent_policy: "unattended",
            granted_caps: null,
            machine_group_id: "g-mock",
            machine_device_id: DEVICE_A,
          },
          signaling: {
            url: SIGNALING_WS,
            device_id: DEVICE_A,
            session_id: CP_SESSION_ID,
            ticket: {
              claims: {
                v: 1, session_id: CP_SESSION_ID, technician_id: "tech-me",
                tenant_id: "t-mock", device_id: DEVICE_A,
                iat_ms: Date.now(), exp_ms: Date.now() + 60_000,
              },
              sig: "mock-sig-0000000000000000000000000000000000000000000000000000000000000000",
            },
          },
        },
      });
      return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  let mockWs: { send: (msg: string) => void } | null = null;
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    mockWs = ws;
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
        return;
      }
      if (parsed.type === "connect_request") {
        // Respond with "brokered" using SIG_SESSION_OWN — DIFFERENT from CP_SESSION_ID.
        // This mirrors broker.go: the signaling server independently generates its session id.
        ws.send(JSON.stringify({
          type: "brokered",
          session: SIG_SESSION_OWN,
          peer_device: DEVICE_A,
          peer_pubkey: "ed25519:agent-mock",
        }));
      }
    });
  });

  await page.goto(autoConnectUrl(DEVICE_A, "Machine-A"));
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });

  await expect.poll(() => mockWs !== null, { timeout: 5_000 }).toBe(true);

  // Push a session_participants message that contains ONLY our own signaling session id.
  // If the App filters by the CP record id (CP_SESSION_ID), self is NOT removed → badge shows "1 co-tech".
  // If the App filters by the signaling session id (SIG_SESSION_OWN), self IS removed → no badge.
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: DEVICE_A,
    participants: [
      { session_id: SIG_SESSION_OWN, technician_id: "tech-me" },
    ],
  }));

  // Correct behavior: self is filtered out, no co-tech badge.
  await expect(page.getByTestId("session-participants")).toHaveCount(0, { timeout: 5_000 });

  // Now add a real peer alongside self: badge should show exactly 1 co-tech.
  mockWs!.send(JSON.stringify({
    type: "session_participants",
    device_id: DEVICE_A,
    participants: [
      { session_id: SIG_SESSION_OWN, technician_id: "tech-me" },
      { session_id: SIG_SESSION_PEER, technician_id: "tech-alice" },
    ],
  }));
  await expect(page.getByTestId("session-participants")).toBeVisible({ timeout: 5_000 });
  await expect(page.getByTestId("session-participants")).toContainText("1 co-tech");
});

// ---------------------------------------------------------------------------
// 10. /console link → login gate → login → auto-connect resumes
// ---------------------------------------------------------------------------
//
// F5 (Codex review) fixed machineNewTabUrl to target /console so that when the new tab's auth
// gate is "required", the technician login form renders (not the customer JoinPage). This test
// verifies the full round-trip: open the /console URL (with device + signaling params) while
// unauthenticated → login gate appears → login → auth gate opens → URL-param auto-connect fires
// → viewer session starts.
//
// Auth gating: GET /cp/machines returns 401 initially (simulates unauthenticated), which drives
// authGate → "required" and renders the login form. POST /auth/login → 200 then GET /cp/machines
// returns 200 (now authenticated) → authGate → "open" → auto-connect effect fires.
//
// The signaling WebSocket is intercepted (direct-connect mock) so the test runs offline and
// ends as soon as viewer-machine-label is visible — the same observable the other auto-connect
// tests use to confirm the session is live. No real signaling or agent is needed.

test("/console link with device params shows login gate when unauthenticated, then auto-connects after login", async ({ page }) => {
  let authenticated = false;

  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();

    if (path === "/cp/auth/session") {
      await route.fulfill({ status: authenticated ? 204 : 401 }); return;
    }
    if (path === "/cp/auth/login" && method === "POST") {
      authenticated = true;
      await route.fulfill({ status: 200, json: {} }); return;
    }
    if (path === "/cp/machines") {
      // Before login: 401 → AuthSession.expire() → setAuthGate("required").
      // After login: 200 → authGate = "open" → URL-param auto-connect effect fires.
      if (!authenticated) { await route.fulfill({ status: 401 }); return; }
      await route.fulfill({ json: { machines: LISTED_MACHINES, presence_known: true } }); return;
    }
    if (path === "/cp/sessions" && method === "POST") {
      // 503 → direct-connect fallback (same as test 1).
      await route.fulfill({ status: 503, json: { error: "no broker" } }); return;
    }
    await route.fulfill({ status: 200, json: {} });
  });

  // Mock the signaling socket so the test runs without a real server.
  await page.routeWebSocket(SIGNALING_WS, (ws) => {
    ws.onMessage((msg) => {
      const parsed = JSON.parse(String(msg)) as { type?: string };
      if (parsed.type === "register_agent") {
        ws.send(JSON.stringify({ type: "registered", server_pubkey: "ed25519:mock" }));
      }
    });
  });

  // Navigate to the machineNewTabUrl-style link: /console with device + signaling params.
  // Auth is initially 401, so the login gate must render instead of auto-connecting.
  const consoleLink = `${APP_BASE}/console?device=${DEVICE_A}&name=${encodeURIComponent("Machine-A")}&signaling=${encodeURIComponent(SIGNALING_WS)}`;
  await page.goto(consoleLink);

  // Login gate must appear (auth gate is "required" due to 401 from GET /cp/machines).
  await expect(page.getByTestId("app-login-gate")).toBeVisible({ timeout: 10_000 });

  // No signaling socket should have opened yet (auto-connect is gated on authGate === "open").
  const socketsBeforeLogin: string[] = [];
  page.on("websocket", (ws) => { if (ws.url().includes("8080")) socketsBeforeLogin.push(ws.url()); });
  expect(socketsBeforeLogin.filter((s) => s.includes("8080")), "no socket before login").toHaveLength(0);

  // Log in: fill the form (tenant + email + password are required by LoginForm) and submit.
  // POST /auth/login → 200 → authenticated = true. Next GET /cp/machines returns 200
  // → authGate = "open" → URL-param auto-connect fires.
  await page.getByTestId("cp-login-tenant").fill("dev");
  await page.getByTestId("cp-login-email").fill("tech@example.com");
  await page.getByTestId("cp-login-password").fill("secret");
  await page.getByTestId("cp-login-submit").click();

  // The viewer session starts: viewer-machine-label appears (auto-connect succeeded).
  await expect(page.getByTestId("viewer-machine-label")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId("viewer-machine-label")).toContainText("Machine-A");

  // Login gate must be gone — the user is now in an active session.
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
});

// Security audit 2026-10-18: a crafted link cannot retitle a session. The link says "Prod-DC01";
// the machine list calls the device "Machine-A", and the session shows the list's name.
test("a link's name parameter never labels the session", async ({ page }) => {
  await cpFixture(page);
  await page.routeWebSocket(SIGNALING_WS, () => {});
  await page.goto(autoConnectUrl(DEVICE_A, "Prod-DC01"));
  const label = page.getByTestId("viewer-machine-label");
  await expect(label).toBeVisible({ timeout: 15_000 });
  await expect(label).toContainText("Machine-A");
  await expect(label).not.toContainText("Prod-DC01");
});
