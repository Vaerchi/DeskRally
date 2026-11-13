import { test, expect, type Page } from "@playwright/test";
import { clickInViewerPanel, openAccountControls } from "./nav";
import { openManualConnect } from "./manual_connect";

async function consoleFixture(page: Page) {
  const state = { status: 204, checks: 0, loginStatus: 200, sessionStatus: 401 };
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") {
      state.checks++;
      await route.fulfill({ status: state.status });
    } else if (path === "/cp/auth/login") {
      await route.fulfill({ status: state.loginStatus, json: { error: "Invalid credentials" } });
    } else if (path === "/cp/machines") {
      await route.fulfill({ json: { machines: [], presence_known: true } });
    } else if (path === "/cp/sessions" && route.request().method() === "POST") {
      await route.fulfill({ status: state.sessionStatus, json: { error: "expired" } });
    } else {
      await route.fulfill({ status: 200, json: {} });
    }
  });
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await expect(page.getByTestId("access-none-enrolled")).toBeVisible();
  return state;
}

test("idle expiry shows sign-in and a successful login returns to a disconnected console", async ({ page }) => {
  await page.clock.install();
  const state = await consoleFixture(page);
  state.status = 401;
  await page.clock.runFor(30_000);
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  await expect(page.getByText("Your sign-in has expired. Sign in again to continue.")).toBeVisible();
  await expect(page.getByTestId("manual-connect")).toHaveCount(0);
  await page.getByTestId("cp-login-tenant").fill("test");
  await page.getByTestId("cp-login-email").fill("user@example.test");
  await page.getByTestId("cp-login-password").fill("test-password");
  state.loginStatus = 401;
  await page.getByTestId("cp-login").getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("cp-login-error")).toBeVisible();
  state.loginStatus = 200;
  state.status = 204;
  await page.getByTestId("cp-login").getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  await expect(page.getByTestId("access-none-enrolled")).toBeVisible();
});

test("focus checks expiry immediately; forbidden and server errors do not sign out", async ({ page }) => {
  const state = await consoleFixture(page);
  for (const status of [403, 503]) {
    state.status = status;
    const response = page.waitForResponse("**/cp/auth/session");
    await page.evaluate(() => window.dispatchEvent(new Event("focus")));
    await response;
    await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  }
  state.status = 401;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
});

test("401 during Connect returns to sign-in without dialing a fallback socket", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await consoleFixture(page);
  const before = sockets.length; // Vite HMR is allowed; remote signaling is not.
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  expect(sockets.slice(before)).toEqual([]);
});

test("expiry closes an open signaling connection even when the main tab is hidden", async ({ page }) => {
  await page.clock.install();
  let closed = false;
  let requested = false;
  await page.routeWebSocket("ws://127.0.0.1:5188/ws", (socket) => {
    socket.onMessage((message) => {
      // App.tsx:996 sends register_agent synchronously after signaling.open(), before
      // transport.connect() is called. connect_request (transport.ts:159) is only reached if
      // RTCPeerConnection, createDataChannel and addTransceiver all succeed — which is not
      // guaranteed in every headless context. register_agent is the unconditional first message.
      if (String(message).includes("register_agent")) requested = true;
    });
    socket.onClose(() => { closed = true; });
  });
  const state = await consoleFixture(page);
  state.sessionStatus = 503; // The existing development direct-connect fallback.
  await openManualConnect(page);
  await page.getByTestId("signaling-url").fill("ws://127.0.0.1:5188/ws");
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => requested).toBe(true);
  const popupOpened = page.waitForEvent("popup");
  await clickInViewerPanel(page, "view", page.getByTestId("viewer-popout"));
  const popup = await popupOpened;
  state.status = 401;
  await page.evaluate(() => Object.defineProperty(document, "visibilityState", { configurable: true, get: () => "hidden" }));
  await page.clock.runFor(30_000);
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  await expect.poll(() => closed).toBe(true);
  await expect.poll(() => popup.isClosed()).toBe(true);
});

test("an in-flight connect cannot resume after expiry and a fresh login", async ({ page }) => {
  const state = await consoleFixture(page);
  let release!: () => void;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  let started = false;
  await page.route("**/cp/sessions", async (route) => {
    // GET /cp/sessions is the live-session badge listing — do not block it.
    if (route.request().method() !== "POST") {
      return route.fulfill({ json: { sessions: [] } });
    }
    started = true;
    await pending;
    await route.fulfill({ status: 503, json: {} });
  });
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await openManualConnect(page);
  await page.getByTestId("manual-device").fill("00112233-4455-6677-8899-aabbccddeeff");
  await page.getByTestId("manual-connect").click();
  await expect.poll(() => started).toBe(true);
  state.status = 401;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  state.status = 204;
  await page.getByTestId("cp-login-tenant").fill("test");
  await page.getByTestId("cp-login-email").fill("user@example.test");
  await page.getByTestId("cp-login-password").fill("test-password");
  await page.getByTestId("cp-login").getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("access-none-enrolled")).toBeVisible();
  const response = page.waitForResponse("**/cp/sessions");
  release();
  await response;
  await expect(page.getByRole("heading", { name: "Select a machine to control" })).toBeVisible();
  expect(sockets).toEqual([]);
});

test("observation request timeout alone does not trigger sign-out", async ({ page }) => {
  await page.clock.install();
  const state = await consoleFixture(page);

  // Override auth/session to hang; last-added route wins in Playwright.
  let releaseHang!: () => void;
  await page.route("**/cp/auth/session", async (route) => {
    await new Promise<void>((resolve) => { releaseHang = resolve; });
    // Client aborts after 25 s — fulfill is a no-op but cleans up the Playwright route lifecycle.
    await route.fulfill({ status: 204 }).catch(() => {});
  });

  const firstRequest = page.waitForRequest("**/cp/auth/session");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await firstRequest; // setTimeout(abort, 25_000) is already registered in the page by this point.
  await page.clock.runFor(25_000); // per-request timeout fires; boundedAuthCheck returns null.

  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  releaseHang();
  void state; // suppress unused-variable lint; state is wired in via consoleFixture.
});

test("after observation timeout a subsequent focus check issues a new request and a genuine 401 signs out", async ({ page }) => {
  await page.clock.install();
  const state = await consoleFixture(page);

  let releaseHang!: () => void;
  let requestCount = 0;
  await page.route("**/cp/auth/session", async (route) => {
    requestCount++;
    if (requestCount === 1) {
      await new Promise<void>((resolve) => { releaseHang = resolve; });
      await route.fulfill({ status: 204 }).catch(() => {});
    } else {
      await route.fulfill({ status: state.status });
    }
  });

  const firstRequest = page.waitForRequest("**/cp/auth/session");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await firstRequest;
  await page.clock.runFor(25_000); // timeout fires; pending flag resets to false.
  await expect(page.getByTestId("app-login-gate")).toHaveCount(0);

  // A genuine 401 on the next check must sign out.
  state.status = 401;
  const secondResponse = page.waitForResponse("**/cp/auth/session");
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await secondResponse;
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  releaseHang();
});

test("sign-out gates immediately and a new login waits for cookie clearing", async ({ page }) => {
  await consoleFixture(page);
  let finishLogout!: () => void;
  const pending = new Promise<void>((resolve) => { finishLogout = resolve; });
  let logoutFinished = false;
  let loginRacedLogout = false;
  await page.route("**/cp/auth/logout", async (route) => {
    await pending;
    logoutFinished = true;
    await route.fulfill({ status: 204 });
  });
  await page.route("**/cp/auth/login", async (route) => {
    loginRacedLogout = !logoutFinished;
    await route.fulfill({ json: {} });
  });
  await openAccountControls(page);
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  await page.getByTestId("cp-login-tenant").fill("test");
  await page.getByTestId("cp-login-email").fill("user@example.test");
  await page.getByTestId("cp-login-password").fill("test-password");
  await page.getByTestId("cp-login").getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByTestId("cp-login").getByRole("button")).toBeDisabled();
  finishLogout();
  await expect(page.getByTestId("access-none-enrolled")).toBeVisible();
  expect(loginRacedLogout).toBe(false);
});
