/**
 * Toolbox area (docs/design-shared-toolbox.md), mocked API, loopback only. Named supervisor_* so the
 * mocked profile runs it.
 *
 *   1. Shared and personal items are listed; Edit/Delete are offered only where the server would allow.
 *   2. Creating a personal script sends exactly the fields + scope; the size counter counts PowerShell
 *      in UTF-8 bytes and cmd in characters; client-side rules refuse before any request.
 *   3. A version conflict (409) is shown verbatim and the editor stays open; a double submit saves once.
 *   4. Delete asks first and sends the version.
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

const SHARED = {
  id: "t-shared", name: "Disk usage", description: "free space", scope: "shared", shell: "powershell", run_as: "system",
  body: "Get-PSDrive", body_sha256: "0".repeat(64), version: 2, updated_at: "2026-10-16T00:00:00Z", mine: false,
};
const MINE = {
  id: "t-mine", name: "My ipconfig", description: "", scope: "personal", shell: "cmd", run_as: "user",
  body: "ipconfig /all", body_sha256: "1".repeat(64), version: 1, updated_at: "2026-10-16T00:00:00Z", mine: true,
};

interface Server {
  canManageShared: boolean;
  posts: unknown[];
  puts: { url: string; body: unknown }[];
  deletes: string[];
  putStatus: number;
}

async function mount(page: Page, canManageShared: boolean): Promise<Server> {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  const server: Server = { canManageShared, posts: [], puts: [], deletes: [], putStatus: 200 };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/toolbox" && method === "GET") {
      await route.fulfill({ json: { items: [SHARED, MINE], can_manage_shared: server.canManageShared, max_powershell_bytes: 16384, max_cmd_units: 7800 } });
    } else if (url.pathname === "/cp/toolbox" && method === "POST") {
      server.posts.push(route.request().postDataJSON());
      await route.fulfill({ status: 201, json: { item: { ...MINE, id: "t-new", name: "new" } } });
    } else if (url.pathname.startsWith("/cp/toolbox/") && method === "PUT") {
      server.puts.push({ url: url.pathname, body: route.request().postDataJSON() });
      if (server.putStatus === 409) {
        await route.fulfill({ status: 409, json: { error: "this item was changed since you loaded it; reload and try again" } });
      } else {
        await route.fulfill({ json: { item: SHARED } });
      }
    } else if (url.pathname.startsWith("/cp/toolbox/") && method === "DELETE") {
      server.deletes.push(url.pathname + url.search);
      await route.fulfill({ status: 204 });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Toolbox", exact: true })).click();
  await expect(page.getByTestId("toolbox-row-Disk usage")).toBeVisible({ timeout: 15_000 });
  return server;
}

const settle = (page: Page) =>
  page.evaluate(() => new Promise<void>((r) => requestAnimationFrame(() => requestAnimationFrame(() => setTimeout(r, 50)))));

test("lists shared and personal items, offering changes only where allowed", async ({ page }) => {
  await mount(page, false);
  const shared = page.getByTestId("toolbox-row-Disk usage");
  const mine = page.getByTestId("toolbox-row-My ipconfig");
  await expect(shared).toContainText("Shared");
  await expect(mine).toContainText("Personal");
  await expect(shared.getByRole("button", { name: "Edit" })).toHaveCount(0); // no manage_toolbox
  await expect(mine.getByRole("button", { name: "Edit" })).toBeVisible();
  await page.getByTestId("toolbox-new").click();
  await expect(page.getByTestId("toolbox-scope").locator("option")).toHaveCount(1); // personal only
});

test("creates a personal script with exact fields; counters and client rules match the server's", async ({ page }) => {
  const server = await mount(page, true);
  await page.getByTestId("toolbox-new").click();
  await page.getByTestId("toolbox-scope").selectOption("personal");
  await page.getByTestId("toolbox-name").fill("Euro");
  await page.getByTestId("toolbox-body").fill("€€");
  await expect(page.getByTestId("toolbox-size")).toContainText("6 / 16384 bytes"); // PowerShell: UTF-8 bytes
  await page.getByTestId("toolbox-shell").selectOption("cmd");
  await expect(page.getByTestId("toolbox-size")).toContainText("2 / 7800 characters"); // cmd: UTF-16 units

  await page.getByTestId("toolbox-body").fill("echo a\necho b");
  await page.getByTestId("toolbox-save").click();
  await expect(page.getByTestId("toolbox-form-error")).toContainText("single line");
  expect(server.posts).toHaveLength(0);

  await page.getByTestId("toolbox-body").fill("echo €");
  await page.getByTestId("toolbox-runas").selectOption("user");
  await page.getByTestId("toolbox-save").click();
  await expect(page.getByTestId("toolbox-editor")).toHaveCount(0);
  expect(server.posts).toEqual([{ name: "Euro", description: "", shell: "cmd", run_as: "user", body: "echo €", scope: "personal" }]);
});

test("a version conflict is shown and the editor stays open; a double submit saves once", async ({ page }) => {
  const server = await mount(page, true);
  server.putStatus = 409;
  await page.getByTestId("toolbox-row-Disk usage").getByRole("button", { name: "Edit" }).click();
  await page.getByTestId("toolbox-name").fill("Disk usage v2");
  await page.getByTestId("toolbox-editor").evaluate((f) => {
    (f as HTMLFormElement).requestSubmit();
    (f as HTMLFormElement).requestSubmit();
  });
  await expect(page.getByTestId("toolbox-form-error")).toContainText("changed since you loaded it");
  await settle(page);
  expect(server.puts).toHaveLength(1);
  expect(server.puts[0].url).toBe("/cp/toolbox/t-shared");
  expect(server.puts[0].body).toMatchObject({ name: "Disk usage v2", expected_version: 2 });
  await expect(page.getByTestId("toolbox-editor")).toBeVisible();
});

test("delete asks first and sends the version", async ({ page }) => {
  const server = await mount(page, false);
  await page.getByTestId("toolbox-row-My ipconfig").getByRole("button", { name: "Delete" }).click();
  await expect(page.getByTestId("toolbox-confirm-delete")).toContainText("My ipconfig");
  expect(server.deletes).toHaveLength(0);
  await page.getByTestId("toolbox-delete-confirm").click();
  await expect(page.getByTestId("toolbox-confirm-delete")).toHaveCount(0);
  expect(server.deletes).toEqual(["/cp/toolbox/t-mine?expected_version=1"]);
});
