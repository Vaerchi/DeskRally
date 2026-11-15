import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

async function accountFixture(page: Page) {
  const state = { status: 200, error: "", requests: [] as unknown[], delay: false, passwordCSRF: "" };
  let release: (() => void) | undefined;
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/me/password") {
      state.passwordCSRF = route.request().headers()["x-csrf-token"] ?? "";
      return route.fulfill({ json: { changed: true } });
    }
    if (path === "/cp/me/email") {
      state.requests.push(route.request().postDataJSON());
      if (state.delay) await new Promise<void>((resolve) => { release = resolve; });
      return route.fulfill({ status: state.status,
        headers: state.status === 200 ? { "set-cookie": "rmt_csrf=email-rotated; Path=/; SameSite=Lax" } : {},
        json: state.status === 200
        ? { changed: true, email: "keith@personal.test", sessions_revoked: 2 }
        : { error: state.error } });
    }
    return route.fulfill({ json: { sessions: [], groups: [], users: [], roles: [] } });
  });
  await page.goto("http://127.0.0.1:5173/console");
  await (await consoleTab(page, { name: "My account", exact: true })).click();
  await expect(page.getByTestId("change-email-form")).toBeVisible();
  return { state, release: () => release?.() };
}

async function fillEmail(page: Page, confirmation = "keith@personal.test") {
  await page.getByTestId("new-login-email").fill("keith@personal.test");
  await page.getByTestId("confirm-login-email").fill(confirmation);
  await page.getByTestId("email-current-password").fill("Current-password-42!");
}

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`email change confirms the address and clears credentials at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const { state } = await accountFixture(page);
    await fillEmail(page);
    await page.getByTestId("change-email-submit").click();
    await expect(page.getByTestId("change-email-success")).toContainText("keith@personal.test");
    expect(state.requests).toEqual([{ current_password: "Current-password-42!", new_email: "keith@personal.test" }]);
    await expect(page.getByTestId("email-current-password")).toHaveValue("");
    await expect(page.getByTestId("new-login-email")).toHaveValue("");
    await expect(page.getByTestId("confirm-login-email")).toHaveValue("");
    await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
    await expect(page.getByTestId("change-password-form")).toBeAttached();
    await expect(page.getByTestId("totp-section")).toBeAttached();
    // The next account mutation must read the replacement CSRF cookie, not a
    // value cached before the email change rotated this browser's session.
    await page.getByTestId("current-password").fill("Current-password-42!");
    await page.getByTestId("new-password").fill("Replacement-password-42!");
    await page.getByTestId("confirm-password").fill("Replacement-password-42!");
    await page.getByTestId("change-password-submit").click();
    await expect(page.getByTestId("change-password-success")).toBeVisible();
    expect(state.passwordCSRF).toBe("email-rotated");
  });
}

test("mismatched confirmation never sends a request; repeated submit sends only once", async ({ page }) => {
  const { state, release } = await accountFixture(page);
  await fillEmail(page, "typo@personal.test");
  await page.getByTestId("change-email-submit").click();
  await expect(page.getByTestId("change-email-error")).toHaveText("Email addresses do not match.");
  expect(state.requests).toHaveLength(0);
  await page.getByTestId("confirm-login-email").fill("keith@personal.test");
  state.delay = true;
  await page.getByTestId("change-email-form").evaluate((form: HTMLFormElement) => {
    form.requestSubmit();
    form.requestSubmit();
  });
  await expect.poll(() => state.requests.length).toBe(1);
  await expect(page.getByTestId("change-email-submit")).toBeDisabled();
  release();
  await expect(page.getByTestId("change-email-success")).toBeVisible();
});

test("duplicate email and rejected password show recoverable errors without signing out", async ({ page }) => {
  const { state } = await accountFixture(page);
  for (const [status, error] of [[409, "email already in use"], [403, "current password is incorrect"]] as const) {
    state.status = status;
    state.error = error;
    await fillEmail(page);
    await page.getByTestId("change-email-submit").click();
    await expect(page.getByTestId("change-email-error")).toContainText(error);
    await expect(page.getByTestId("change-email-success")).toHaveCount(0);
    await expect(page.getByTestId("email-current-password")).toHaveValue("");
    await expect(page.getByTestId("app-login-gate")).toHaveCount(0);
  }
  state.status = 200;
  await fillEmail(page);
  await page.getByTestId("change-email-submit").click();
  await expect(page.getByTestId("change-email-success")).toBeVisible();
});

test("an expired session returns to sign-in instead of reporting a successful email change", async ({ page }) => {
  const { state } = await accountFixture(page);
  state.status = 401;
  state.error = "unauthorized";
  await fillEmail(page);
  await page.getByTestId("change-email-submit").click();
  await expect(page.getByTestId("app-login-gate")).toBeVisible();
  await expect(page.getByTestId("change-email-success")).toHaveCount(0);
});
