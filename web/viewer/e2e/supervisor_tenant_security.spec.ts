/**
 * Tenant security panel — read-gating, mocked-API browser regressions.
 *
 *   1. GET /tenant/security-policy fails -> the 2FA checkbox is disabled and NOT checked (never an invented
 *      "off"), with an unknown note and the error shown.
 *   2. GET /tenant/session-policy fails or is malformed -> the session-limit inputs and Save are disabled, and
 *      no "Currently ..." note is shown.
 *   3. Every read succeeds -> controls are enabled and show the server values (require_2fa true = checked).
 *
 * Handlers are keyed by a behavior MODE, not a request counter, so React StrictMode's double mount cannot
 * shift which request gets which answer. Every /cp/ call is routed; only the loopback origin is reachable.
 * Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

type ReadMode = "ok" | "fail" | "malformed";

interface Modes {
  security: ReadMode;
  session: ReadMode;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

async function mount(page: Page, modes: Modes) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const isGet = route.request().method() === "GET";
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/tenant/security-policy" && isGet) {
      if (modes.security === "fail") await route.fulfill({ status: 500, json: { error: "boom" } });
      else if (modes.security === "malformed") await route.fulfill({ json: { require_2fa: "yes" } });
      else await route.fulfill({ json: { require_2fa: true } });
    } else if (url.pathname === "/cp/tenant/session-policy" && isGet) {
      if (modes.session === "fail") await route.fulfill({ status: 500, json: { error: "boom" } });
      else if (modes.session === "malformed") await route.fulfill({ json: {} });
      else await route.fulfill({ json: { max_concurrent_sessions: 5, max_session_seconds: 3600 } });
    } else if (url.pathname === "/cp/tenant/ip-allowlist" && isGet) {
      await route.fulfill({ json: { cidrs: [], your_ip: "127.0.0.1" } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(page.getByTestId("tenant-security")).toBeVisible({ timeout: 15_000 });
}

test("a failed 2FA policy read leaves the checkbox disabled and unchecked, with the error shown", async ({ page }) => {
  await mount(page, { security: "fail", session: "ok" });

  await expect(page.getByTestId("2fa-policy-error")).toBeVisible();
  const checkbox = page.getByTestId("require-2fa-checkbox");
  await expect(checkbox).toBeDisabled();
  await expect(checkbox).not.toBeChecked();
  await expect(page.getByTestId("2fa-policy-unknown")).toContainText(/unknown/i);
});

test("a failed or malformed session policy read disables the inputs and Save", async ({ page }) => {
  await mount(page, { security: "ok", session: "fail" });
  await expect(page.getByTestId("session-limit-error")).toBeVisible();
  await expect(page.getByTestId("session-limit-input")).toBeDisabled();
  await expect(page.getByTestId("session-maxage-input")).toBeDisabled();
  await expect(page.getByTestId("session-default-idle-input")).toBeDisabled();
  await expect(page.getByTestId("session-limit-save")).toBeDisabled();
  await expect(page.getByTestId("session-limit-current")).toHaveCount(0);
  await expect(page.getByTestId("session-maxage-current")).toHaveCount(0);
});

test("a malformed session policy body is treated as unread", async ({ page }) => {
  await mount(page, { security: "ok", session: "malformed" });
  await expect(page.getByTestId("session-limit-error")).toBeVisible();
  await expect(page.getByTestId("session-limit-input")).toBeDisabled();
  await expect(page.getByTestId("session-maxage-input")).toBeDisabled();
  await expect(page.getByTestId("session-default-idle-input")).toBeDisabled();
  await expect(page.getByTestId("session-limit-save")).toBeDisabled();
  await expect(page.getByTestId("session-limit-current")).toHaveCount(0);
});

test("when every read succeeds the controls are enabled and show the server values", async ({ page }) => {
  await mount(page, { security: "ok", session: "ok" });

  const checkbox = page.getByTestId("require-2fa-checkbox");
  await expect(checkbox).toBeEnabled();
  await expect(checkbox).toBeChecked();
  await expect(page.getByTestId("2fa-policy-unknown")).toHaveCount(0);
  await expect(page.getByTestId("2fa-policy-error")).toHaveCount(0);

  await expect(page.getByTestId("session-limit-input")).toBeEnabled();
  await expect(page.getByTestId("session-limit-input")).toHaveValue("5");
  await expect(page.getByTestId("session-maxage-input")).toBeEnabled();
  await expect(page.getByTestId("session-maxage-input")).toHaveValue("3600");
  await expect(page.getByTestId("session-limit-save")).toBeEnabled();
  await expect(page.getByTestId("session-limit-current")).toContainText("5");
});

test("saves the organization idle timeout in seconds and reads it back in minutes", async ({ page }) => {
  await mount(page, { security: "ok", session: "ok" });

  let policy = { max_concurrent_sessions: 5, max_session_seconds: 3600, default_max_idle_seconds: 0 };
  await page.route("**/cp/tenant/session-policy", async (route) => {
    if (route.request().method() === "PUT") {
      policy = { ...policy, ...route.request().postDataJSON() };
    }
    await route.fulfill({ json: policy });
  });

  const idle = page.getByTestId("session-default-idle-input");
  await expect(idle).toHaveValue("0");
  await idle.fill("12");
  const saved = page.waitForResponse((response) =>
    response.url().endsWith("/cp/tenant/session-policy") && response.request().method() === "PUT",
  );
  await page.getByTestId("session-limit-save").click();
  await saved;
  expect(policy.default_max_idle_seconds).toBe(720);

  await page.reload();
  await (await consoleTab(page, { name: "Security" })).click();
  await expect(idle).toBeEnabled();
  await expect(idle).toHaveValue("12");
});

// docs/69 step 4: turning on "Require verified sessions" PUTs require WITH the saved limits (the PUT replaces the
// whole policy), and a failed read leaves the toggle disabled.
test("the session verification toggle saves require and keeps the saved limits", async ({ page }) => {
  await mount(page, { security: "ok", session: "ok" });
  // Registered AFTER mount: Playwright tries the newest route first, so this one sees the PUT before mount's catch-all.
  let putBody: unknown = null;
  await page.route("**/cp/tenant/session-policy", async (route) => {
    if (route.request().method() === "PUT") {
      putBody = route.request().postDataJSON();
      await route.fulfill({ json: { ...(putBody as object) } });
    } else {
      await route.fallback();
    }
  });
  const box = page.getByTestId("require-session-binding-checkbox");
  await expect(box).toBeEnabled();
  await expect(box).not.toBeChecked();
  // A controlled checkbox: it reflects the SERVER's echo, so click and then wait for the saved state.
  const put = page.waitForRequest((r) => r.url().endsWith("/cp/tenant/session-policy") && r.method() === "PUT", { timeout: 5_000 });
  await box.click();
  await put;
  await expect(box).toBeChecked();
  expect(putBody).toEqual({ max_concurrent_sessions: 5, max_session_seconds: 3600, session_binding: "require" });
});

test("a failed session policy read disables the session verification toggle", async ({ page }) => {
  await mount(page, { security: "ok", session: "fail" });
  await expect(page.getByTestId("require-session-binding-checkbox")).toBeDisabled();
});