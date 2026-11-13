/**
 * Sites — the site-name limit is UTF-8 BYTES (the control plane compares Go `len`), mocked-API browser test.
 *
 *   1. The panel states the limit in bytes.
 *   2. A multibyte name under 4096 UTF-16 units but over 4096 bytes is refused in the console, with no PUT sent.
 *   3. A multibyte name of exactly 4096 bytes is sent untruncated and shown after the server echoes it back.
 *
 * Every /cp/ call is routed here and non-loopback origins are aborted. Named supervisor_* so the mocked
 * headless profile runs it.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const M1 = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

async function mount(page: Page, puts: { path: string; value: string }[]) {
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
    } else if (url.pathname === "/cp/machines" && method === "GET") {
      const filtered = url.searchParams.has("property_key");
      await route.fulfill({
        json: { machines: filtered ? [] : [{ id: M1, tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "Desk" }] },
      });
    } else if (url.pathname === `/cp/machines/${M1}/properties/site` && method === "PUT") {
      const { value } = route.request().postDataJSON() as { value: string };
      puts.push({ path: url.pathname, value });
      await route.fulfill({ json: { property: { key: "site", value } } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Sites", exact: true })).click();
  await expect(page.getByTestId(`site-row-${M1}`)).toBeVisible({ timeout: 15_000 });
}

test("site names are limited by UTF-8 bytes: refused over, sent whole at the limit", async ({ page }) => {
  const puts: { path: string; value: string }[] = [];
  await mount(page, puts);

  await expect(page.getByTestId("sites-limit-hint")).toContainText("4096 bytes");

  const input = page.getByTestId(`site-input-${M1}`);

  // 2049 UTF-16 units but 4097 bytes: the old length check accepted this, the server would reject it.
  await input.fill("é".repeat(2048) + "x");
  await page.getByTestId(`site-save-${M1}`).click();
  await expect(page.getByTestId(`site-error-${M1}`)).toContainText("4097 bytes");
  expect(puts).toEqual([]);

  // Exactly 4096 bytes (2048 x 2-byte characters) goes out untouched.
  const atLimit = "é".repeat(2048);
  await input.fill(atLimit);
  await page.getByTestId(`site-save-${M1}`).click();
  await expect(page.getByTestId(`site-value-${M1}`)).toHaveText(atLimit);
  expect(puts).toEqual([{ path: `/cp/machines/${M1}/properties/site`, value: atLimit }]);
});
