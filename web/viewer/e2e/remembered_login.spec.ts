import { PINNED } from "./chrome_pinned";
import { test, expect } from "@playwright/test";

for (const mode of ["browser", "desktop", "hello"] as const) {
  test(`${mode}: remembered sign-in requires explicit eligible opt-in`, async ({ browser }) => {
    const context = await browser.newContext({ ...PINNED, userAgent: mode === "browser" ? "Browser" :
      `Windows DeskRallyDesktop/0.4.0${mode === "hello" ? " DeskRallyHello/1" : ""}` });
    const page = await context.newPage();
    const requests: Record<string, unknown>[] = [];
    await page.route("**/cp/**", async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/cp/auth/login") {
        requests.push(route.request().postDataJSON());
        return route.fulfill({ status: 401, json: { error: "invalid credentials" } });
      }
      return route.fulfill({ status: 401, json: { error: "sign in" } });
    });
    await page.goto("http://127.0.0.1:5173/console");
    await page.getByTestId("cp-login-tenant").fill("loam");
    await page.getByTestId("cp-login-email").fill("owner@example.test");
    await page.getByTestId("cp-login-password").fill("test-only-password");
    await page.getByTestId("cp-login-totp").fill("123456");
    const remember = page.getByTestId("cp-login-remember");
    if (mode === "hello") await expect(remember).not.toBeChecked();
    else await expect(remember).toHaveCount(0);
    await expect(page.getByTestId("cp-login-hello-hint")).toHaveCount(mode === "desktop" ? 1 : 0);
    await page.getByTestId("cp-login-submit").click();
    await expect.poll(() => requests.length).toBe(1);
    expect(requests[0]).toEqual({ tenant: "loam", email: "owner@example.test",
      password: "test-only-password", totp_code: "123456" });
    if (mode === "hello") {
      await remember.check();
      await page.getByTestId("cp-login-submit").click();
      await expect.poll(() => requests.length).toBe(2);
      expect(requests[1]).toEqual({ tenant: "loam", email: "owner@example.test",
        password: "test-only-password", totp_code: "123456", remember_device: true });
    }
    await context.close();
  });
}
