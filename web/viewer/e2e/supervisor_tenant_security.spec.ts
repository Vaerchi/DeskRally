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
  await expect(page.getByTestId("session-limit-save")).toBeDisabled();
  await expect(page.getByTestId("session-limit-current")).toHaveCount(0);
  await expect(page.getByTestId("session-maxage-current")).toHaveCount(0);
});

test("a malformed session policy body is treated as unread", async ({ page }) => {
  await mount(page, { security: "ok", session: "malformed" });
  await expect(page.getByTestId("session-limit-error")).toBeVisible();
  await expect(page.getByTestId("session-limit-input")).toBeDisabled();
  await expect(page.getByTestId("session-maxage-input")).toBeDisabled();
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
