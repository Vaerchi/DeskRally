/**
 * Appearance panel — edit-overwrite guard, mocked-API browser regressions.
 *
 *   (a) While GET /tenant/branding is held, the inputs, "Use default accent" and Save are disabled; after
 *       release they are enabled and show the server values.
 *   (b) While PUT /tenant/branding is held, the inputs are disabled; the final displayed values equal the
 *       PUT echo (not what was typed).
 *   (c) A failed GET leaves the inputs and Save disabled with the error shown.
 *
 * Handlers are keyed by a behavior MODE with a release gate, not a request counter, so React StrictMode's
 * double mount cannot shift which request gets which answer. Every /cp/ call is routed; only the loopback
 * origin is reachable. Named supervisor_* so the mocked headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

type GetMode = "ok" | "hold" | "fail";
type PutMode = "echo" | "hold";

interface Modes {
  get: GetMode;
  put: PutMode;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const SERVER = { product_name: "Server Name", accent_color: "#112233" };
const ECHO = { product_name: "Echoed Name", accent_color: "#00ff00" };

function gate() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}

async function mount(page: Page, modes: Modes, getGate = gate(), putGate = gate()) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/tenant/branding" && method === "GET") {
      if (modes.get === "fail") {
        await route.fulfill({ status: 500, json: { error: "boom" } });
      } else {
        if (modes.get === "hold") await getGate.promise;
        await route.fulfill({ json: SERVER });
      }
    } else if (url.pathname === "/cp/tenant/branding" && method === "PUT") {
      if (modes.put === "hold") await putGate.promise;
      await route.fulfill({ json: ECHO });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Appearance" })).click();
  await expect(page.getByTestId("appearance")).toBeVisible({ timeout: 15_000 });
  return { getGate, putGate };
}

async function expectControls(page: Page, enabled: boolean) {
  for (const id of ["appearance-name", "appearance-accent", "appearance-accent-clear", "appearance-save"]) {
    if (enabled) await expect(page.getByTestId(id)).toBeEnabled();
    else await expect(page.getByTestId(id)).toBeDisabled();
  }
}

test("while the branding GET is held the controls are disabled, then enable with the server values", async ({ page }) => {
  const { getGate } = await mount(page, { get: "hold", put: "echo" });

  await expectControls(page, false);
  await expect(page.getByTestId("appearance-name")).toHaveValue("");

  getGate.release();

  await expectControls(page, true);
  await expect(page.getByTestId("appearance-name")).toHaveValue(SERVER.product_name);
  await expect(page.getByTestId("appearance-accent")).toHaveValue(SERVER.accent_color);
  await expect(page.getByTestId("appearance-error")).toHaveCount(0);
});

test("while the branding PUT is held the inputs are disabled and the final values equal the echo", async ({ page }) => {
  const { putGate } = await mount(page, { get: "ok", put: "hold" });

  await expectControls(page, true);
  await page.getByTestId("appearance-name").fill("Typed Name");
  await page.getByTestId("appearance-accent").fill("#ff0000");
  await page.getByTestId("appearance-save").click();

  await expectControls(page, false);
  await expect(page.getByTestId("appearance-saved")).toHaveCount(0);

  putGate.release();

  await expect(page.getByTestId("appearance-saved")).toBeVisible();
  await expect(page.getByTestId("appearance-name")).toHaveValue(ECHO.product_name);
  await expect(page.getByTestId("appearance-accent")).toHaveValue(ECHO.accent_color);
  await expectControls(page, true);
});

test("a failed branding GET leaves the controls disabled with the error shown", async ({ page }) => {
  await mount(page, { get: "fail", put: "echo" });

  await expect(page.getByTestId("appearance-error")).toBeVisible();
  await expectControls(page, false);
  await expect(page.getByTestId("appearance-name")).toHaveValue("");
});
