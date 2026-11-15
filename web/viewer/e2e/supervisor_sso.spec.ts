import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const PENDING = "550e8400-e29b-41d4-a716-446655440000";
// Exactly the server contract (http_oidc.go oidcConnectionResponse), including profile.
const CONNECTION = {
  profile: "entra",
  entra_tenant_id: "11111111-1111-4111-8111-111111111111",
  client_id: "22222222-2222-4222-8222-222222222222",
  enabled: true, trust_entra_mfa: false, has_secret: true, version: 1,
  redirect_uri: "http://127.0.0.1:5173/cp/auth/oidc/callback", last_test: null,
};
const LINK_URL = "https://login.microsoftonline.com/mock-link";
type Call = { method: string; path: string; body: unknown };

async function mount(page: Page, options: {
  login?: boolean; discovery?: "entra" | "empty" | "missing";
  totpStatus?: number; returnPath?: string; forbidden?: boolean; putFailures?: number; probeForbidden?: boolean;
} = {}) {
  const base = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const origin = new URL(base).origin;
  expect(["127.0.0.1", "localhost", "[::1]"]).toContain(new URL(base).hostname);
  const calls: Call[] = [];
  let authenticated = !options.login;
  let steppedUp = false;
  let version = 1;
  // Same interception shape as the other mocked console specs: every /cp request is answered here, so
  // nothing reaches the dev server's proxy (which would make the console look signed in).
  await page.route("**/cp/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const method = request.method();
    const body: unknown = request.postData() ? request.postDataJSON() : null;
    calls.push({ method, path: url.pathname, body });
    if (url.pathname === "/cp/auth/session") {
      return route.fulfill({ status: authenticated ? 204 : 401 });
    }
    // The console's sign-in gate is decided by the machine listing: only a 401 there shows the login
    // form (App.tsx), so a signed-out mock must refuse it — and an empty fleet once signed in.
    if (url.pathname === "/cp/machines") {
      return authenticated
        ? route.fulfill({ json: { machines: [], presence_known: true } })
        : route.fulfill({ status: 401, json: { error: "unauthenticated" } });
    }
    if (url.pathname === "/cp/auth/sso-info") {
      if (options.discovery === "missing") return route.fulfill({ status: 404, json: { error: "not found" } });
      return route.fulfill({ json: { providers: options.discovery === "entra" ? [{ id: "entra", label: "Microsoft" }] : [] } });
    }
    if (url.pathname === "/cp/auth/login" && method === "POST") {
      authenticated = true;
      return route.fulfill({ json: {
        user_id: "owner", tenant_id: "tenant", expires_at: "2099-01-01T00:00:00Z", csrf_token: "t",
      } });
    }
    if (url.pathname === "/cp/auth/oidc/totp" && method === "POST") {
      if (options.totpStatus) return route.fulfill({ status: options.totpStatus, json: { error: "Code rejected" } });
      authenticated = true;
      return route.fulfill({ json: {
        user_id: "owner", tenant_id: "tenant", expires_at: "2099-01-01T00:00:00Z",
        csrf_token: "t", return_path: options.returnPath ?? "/console?x=1",
      } });
    }
    if (url.pathname === "/cp/auth/oidc/step-up-status" && method === "GET") {
      if (options.probeForbidden) return route.fulfill({ status: 403, json: { error: "not permitted" } });
      return route.fulfill({ json: { fresh: steppedUp } });
    }
    if (url.pathname === "/cp/auth/step-up" && method === "POST") {
      steppedUp = true;
      return route.fulfill({ status: 204 });
    }
    if (url.pathname === "/cp/tenant/sso" && method === "GET") {
      return route.fulfill(options.forbidden
        ? { status: 403, json: { error: "forbidden" } }
        : { json: { ...CONNECTION, version } });
    }
    if (url.pathname === "/cp/tenant/sso" && method === "PUT") {
      expect(steppedUp).toBe(true);
      if ((options.putFailures ?? 0) > 0) {
        options.putFailures!--;
        return route.fulfill({ status: 503, json: { outcome: "unavailable" } });
      }
      version++;
      return route.fulfill({ json: { ...CONNECTION, version } });
    }
    if (url.pathname === "/cp/auth/oidc/link/start" && method === "POST") {
      expect(steppedUp).toBe(true);
      return route.fulfill({ json: { url: LINK_URL } });
    }
    return route.fulfill({ json: {} });
  });
  return { calls, base };
}

async function openArea(page: Page, name: string) {
  await (await consoleTab(page, { name, exact: true })).click();
}

async function verify(page: Page) {
  await page.getByTestId("sso-stepup-code").fill("123456");
  await page.getByTestId("sso-stepup-submit").click();
}

async function expectSecretAbsent(page: Page, secret: string) {
  await expect(page.getByTestId("sso-client-secret")).toHaveValue("");
  expect(await page.content()).not.toContain(secret);
  expect(await page.locator("input").evaluateAll(inputs => inputs.map(input => input.value))).not.toContain(secret);
}

test("Microsoft discovery offers a document navigation to the CP", async ({ page }) => {
  const server = await mount(page, { login: true, discovery: "entra" });
  await page.goto(new URL("/console?from=sso", server.base).href);
  await page.getByTestId("cp-login-tenant").fill("acme");
  const button = page.getByTestId("sso-microsoft");
  await expect(button).toHaveText("Sign in with Microsoft");
  const returnPath = await page.evaluate(() => location.pathname + location.search + location.hash);
  await page.route("**/cp/auth/oidc/start?**", route => route.fulfill({ contentType: "text/html", body: "SSO started" }));
  const requested = page.waitForRequest(request => new URL(request.url()).pathname === "/cp/auth/oidc/start");
  await button.click();
  const request = await requested;
  expect(request.method()).toBe("GET");
  const url = new URL(request.url());
  expect([...url.searchParams.entries()]).toEqual([["return", returnPath]]);
});

// Ed, 2026-11-09: "Remember this app for 30 days" did nothing for Microsoft sign-in. In the Hello-unlocked desktop app
// the ticked box now rides the start link as remember=1 (the CP keeps it on the attempt: migrations/0080); unticked, or
// in any other client, the link is unchanged.
test.describe("in the Hello-unlocked desktop app", () => {
  test.use({ userAgent: "Windows DeskRallyDesktop/0.8.4 DeskRallyHello/1 DeskRallySSO/1" });
  for (const ticked of [false, true]) {
    test(`Microsoft sign-in ${ticked ? "carries" : "omits"} remember=1 when the box is ${ticked ? "" : "not "}ticked`, async ({ page }) => {
      const server = await mount(page, { login: true, discovery: "entra" });
      await page.goto(new URL("/console", server.base).href);
      await page.getByTestId("cp-login-tenant").fill("acme");
      const remember = page.getByTestId("cp-login-remember");
      await expect(remember).not.toBeChecked();
      if (ticked) await remember.check();
      await page.route("**/cp/auth/oidc/start?**", route => route.fulfill({ contentType: "text/html", body: "SSO started" }));
      const requested = page.waitForRequest(request => new URL(request.url()).pathname === "/cp/auth/oidc/start");
      await page.getByTestId("sso-microsoft").click();
      const url = new URL((await requested).url());
      expect(url.searchParams.getAll("remember")).toEqual(ticked ? ["1"] : []);
      expect(url.searchParams.get("return")).toBe("/console");
    });
  }
});

for (const discovery of ["empty", "missing"] as const) {
  test(`password login remains available when discovery is ${discovery}`, async ({ page }) => {
    const server = await mount(page, { login: true, discovery });
    await page.goto(new URL("/console", server.base).href);
    const discovered = page.waitForResponse(response => {
      const url = new URL(response.url());
      return url.pathname === "/cp/auth/sso-info" && url.searchParams.get("tenant") === "acme";
    });
    await page.getByTestId("cp-login-tenant").fill("acme");
    await discovered;
    await expect(page.getByTestId("sso-microsoft")).toHaveCount(0);
    await page.getByTestId("cp-login-email").fill("owner@example.test");
    await page.getByTestId("cp-login-password").fill("password-for-test");
    await page.getByTestId("cp-login-submit").click();
    await expect(page.getByTestId("cp-login")).toHaveCount(0);
    expect(server.calls.filter(call => call.method === "POST" && call.path === "/cp/auth/login")).toHaveLength(1);
  });
}

for (const returnPath of ["/console?x=1", "//evil"]) {
  test(`SSO TOTP completes with safe destination for ${returnPath}`, async ({ page }) => {
    const server = await mount(page, { returnPath });
    await page.goto(new URL(`/console/sso-totp?p=${PENDING}`, server.base).href);
    await page.getByTestId("sso-totp-code").fill(" 123456 ");
    await page.getByTestId("sso-totp-submit").click();
    await expect(page).toHaveURL(new URL(returnPath === "//evil" ? "/console" : returnPath, server.base).href);
    expect(server.calls.filter(call => call.path === "/cp/auth/oidc/totp")).toEqual([
      { method: "POST", path: "/cp/auth/oidc/totp", body: { pending_id: PENDING, totp_code: "123456" } },
    ]);
  });
}

for (const status of [401, 403]) {
  test(`SSO TOTP ${status} preserves the form with an error`, async ({ page }) => {
    const server = await mount(page, { totpStatus: status });
    const destination = new URL(`/console/sso-totp?p=${PENDING}`, server.base).href;
    await page.goto(destination);
    await page.getByTestId("sso-totp-code").fill("123456");
    await page.getByTestId("sso-totp-submit").click();
    const form = page.getByTestId("sso-totp-form");
    await expect(form).toBeVisible();
    await expect(form.getByRole("alert")).toBeVisible();
    await expect(form.getByRole("alert")).not.toBeEmpty();
    await expect(page.getByTestId("sso-totp-code")).toHaveValue("");
    await expect(page).toHaveURL(destination);
  });
}

test("owner saves SSO only after step-up and clears the secret", async ({ page }) => {
  const server = await mount(page);
  await page.goto(new URL("/console", server.base).href);
  await openArea(page, "Security");
  await expect(page.getByTestId("sso-client-id")).toHaveValue(CONNECTION.client_id);
  await expect(page.getByTestId("sso-has-secret")).toContainText("Configured");
  await expect(page.getByTestId("sso-client-secret")).toHaveValue("");
  expect(CONNECTION).not.toHaveProperty("client_secret");
  const secret = "unique-client-secret-C3-9f12";
  await page.getByTestId("sso-client-secret").fill(secret);
  await page.getByTestId("sso-save").click();
  await expect(page.getByTestId("sso-stepup-form")).toBeVisible();
  await expectSecretAbsent(page, secret);
  const sensitive = () => server.calls.filter(call => call.path === "/cp/auth/step-up" || (call.path === "/cp/tenant/sso" && call.method === "PUT"));
  expect(sensitive()).toEqual([]);
  await verify(page);
  await expect(page.getByTestId("sso-notice")).toHaveText("Microsoft sign-in settings saved.");
  expect(sensitive()).toEqual([
    { method: "POST", path: "/cp/auth/step-up", body: { code: "123456" } },
    { method: "PUT", path: "/cp/tenant/sso", body: {
      entra_tenant_id: CONNECTION.entra_tenant_id, client_id: CONNECTION.client_id,
      enabled: true, trust_entra_mfa: false, client_secret: secret,
    } },
  ]);
  await expectSecretAbsent(page, secret);
});

// A failed save that carried a NEW secret must not be retried without it (Codex impl review C v1): the
// form closes, says the secret was not stored, and no further PUT is sent until the owner saves again.
test("a failed secret rotation is never retried without the secret", async ({ page }) => {
  const server = await mount(page, { putFailures: 1 });
  await page.goto(new URL("/console", server.base).href);
  await openArea(page, "Security");
  await expect(page.getByTestId("sso-client-id")).toHaveValue(CONNECTION.client_id);
  const secret = "rotation-secret-C3-retry";
  await page.getByTestId("sso-client-secret").fill(secret);
  await page.getByTestId("sso-save").click();
  await verify(page);
  await expect(page.getByTestId("sso-notice")).toHaveText(
    "Saving failed and the new client secret was not stored. Enter the secret again and save.");
  await expect(page.getByTestId("sso-stepup-form")).toHaveCount(0);
  const puts = () => server.calls.filter(call => call.path === "/cp/tenant/sso" && call.method === "PUT");
  expect(puts()).toHaveLength(1);
  expect((puts()[0].body as { client_secret?: string }).client_secret).toBe(secret);
  await expectSecretAbsent(page, secret);
});

// Production 2026-10-17: Save then Test asked for two codes, and reusing the first failed as a replay.
// While the verification is fresh, the next action runs without the prompt.
test("one code covers the next action while the verification is fresh", async ({ page }) => {
  const server = await mount(page);
  await page.goto(new URL("/console", server.base).href);
  await openArea(page, "Security");
  await expect(page.getByTestId("sso-client-id")).toHaveValue(CONNECTION.client_id);
  await page.getByTestId("sso-save").click();
  await verify(page);
  await expect(page.getByTestId("sso-notice")).toHaveText("Microsoft sign-in settings saved.");
  const puts = () => server.calls.filter(call => call.path === "/cp/tenant/sso" && call.method === "PUT");
  const stepUps = () => server.calls.filter(call => call.path === "/cp/auth/step-up");
  expect(puts()).toHaveLength(1);
  await page.getByTestId("sso-save").click();
  await expect.poll(() => puts().length).toBe(2);
  await expect(page.getByTestId("sso-stepup-form")).toHaveCount(0);
  expect(stepUps()).toHaveLength(1);
});

// Codex UX review v1: a 403 from the freshness probe must hide the section, not offer a code prompt.
test("a forbidden freshness probe hides the SSO section", async ({ page }) => {
  const server = await mount(page, { probeForbidden: true });
  await page.goto(new URL("/console", server.base).href);
  await openArea(page, "Security");
  await expect(page.getByTestId("sso-client-id")).toHaveValue(CONNECTION.client_id);
  await page.getByTestId("sso-save").click();
  await expect(page.getByTestId("tenant-sso-section")).toHaveCount(0);
  expect(server.calls.filter(call => call.path === "/cp/tenant/sso" && call.method === "PUT")).toEqual([]);
});

test("a forbidden settings response hides the SSO section", async ({ page }) => {
  const server = await mount(page, { forbidden: true });
  await page.goto(new URL("/console", server.base).href);
  const response = page.waitForResponse(response => new URL(response.url()).pathname === "/cp/tenant/sso" && response.status() === 403);
  await openArea(page, "Security");
  await response;
  await expect(page.getByTestId("tenant-sso-section")).toHaveCount(0);
});

test("My Account links through step-up before navigating to Microsoft", async ({ page }) => {
  const server = await mount(page);
  await page.route(LINK_URL, route => route.fulfill({ contentType: "text/html", body: "Microsoft mock" }));
  await page.goto(new URL("/console", server.base).href);
  await openArea(page, "My account");
  await page.getByTestId("sso-link").click();
  await expect(page.getByTestId("sso-stepup-form")).toBeVisible();
  expect(server.calls.filter(call => call.path === "/cp/auth/oidc/link/start")).toEqual([]);
  const requested = page.waitForRequest(LINK_URL);
  await verify(page);
  expect((await requested).isNavigationRequest()).toBe(true);
  expect(server.calls.filter(call => ["/cp/auth/step-up", "/cp/auth/oidc/link/start"].includes(call.path))).toEqual([
    { method: "POST", path: "/cp/auth/step-up", body: { code: "123456" } },
    { method: "POST", path: "/cp/auth/oidc/link/start", body: null },
  ]);
});
