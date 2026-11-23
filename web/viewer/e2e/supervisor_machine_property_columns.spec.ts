import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";
import { consoleTab } from "./nav";

test("machine property columns persist, follow bulk edits, and export to CSV", async ({ page }) => {
  const base = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const origin = new URL(base).origin;
  expect(["127.0.0.1", "localhost", "[::1]"]).toContain(new URL(base).hostname);

  const machines = ["m-a", "m-b"].map((id) => ({
    id,
    name: `HOST-${id}`,
    device_id: `dev-${id}`,
    group_id: "g-1",
    tenant_id: "t-1",
    properties: { site: "HQ" } as Record<string, string>,
  }));
  const ids = machines.map((machine) => machine.id);
  const writes: unknown[] = [];
  let includedProperties = false;

  await page.route("**/*", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.origin !== origin) {
      await route.abort();
    } else if (url.pathname === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (url.pathname === "/cp/machines" && request.method() === "GET") {
      const include = url.searchParams.get("include") === "properties";
      includedProperties ||= include;
      await route.fulfill({
        json: {
          machines: machines.map((machine) => ({ ...machine, properties: include ? machine.properties : undefined })),
          presence_known: true,
        },
      });
    } else if (url.pathname === "/cp/machines/bulk-property" && request.method() === "POST") {
      const body = request.postDataJSON() as { machine_ids: string[]; key: string; value: string; delete: boolean };
      writes.push(body);
      for (const machine of machines) {
        if (!body.machine_ids.includes(machine.id)) continue;
        if (body.delete) delete machine.properties[body.key];
        else machine.properties[body.key] = body.value;
      }
      await route.fulfill({ json: { results: body.machine_ids.map((id) => ({ machine_id: id, ok: true })) } });
    } else if (url.pathname.startsWith("/cp/")) {
      await route.fulfill({ json: {} });
    } else {
      await route.continue();
    }
  });

  await page.goto(base);
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(page.getByTestId("machine-name-m-a")).toBeVisible();
  expect(includedProperties).toBe(true);
  const table = page.locator(".panel--machines table");
  const column = table.getByRole("columnheader", { name: "site", exact: true });
  await expect(column).toHaveCount(0);
  await page.getByRole("button", { name: "Columns", exact: true }).click();
  await page.getByRole("dialog", { name: "Columns" }).getByRole("checkbox", { name: "site" }).check();
  await expect(column).toBeVisible();
  await expect(table.getByRole("cell", { name: "HQ", exact: true })).toHaveCount(2);

  await page.reload();
  await (await consoleTab(page, { name: "Machines" })).click();
  await expect(column).toBeVisible();
  await page.getByTestId("bulk-select-all").check();
  await page.getByRole("button", { name: "Set property…" }).click();
  await page.getByLabel("Property key", { exact: true }).fill("site");
  await page.getByLabel("Property value", { exact: true }).fill("Branch");
  await page.getByRole("button", { name: "Set on 2 selected" }).click();
  await expect(page.getByTestId("bulk-property-result")).toHaveText("2 updated");
  await expect(table.getByRole("cell", { name: "Branch", exact: true })).toHaveCount(2);
  expect(writes).toEqual([{ machine_ids: ids, key: "site", value: "Branch", delete: false }]);

  const [download] = await Promise.all([
    page.waitForEvent("download"),
    page.getByTestId("machines-export").click(),
  ]);
  expect(download.suggestedFilename()).toBe("machines.csv");
  const csv = readFileSync(await download.path(), "utf8");
  expect(csv.split("\r\n")[0]).toBe("name,alias,device_id,group,status,os,online,last_seen,id,site");
  for (const id of ids) expect(csv).toContain(`,${id},Branch\r\n`);

  await page.getByTestId("bulk-select-all").check();
  await page.getByRole("button", { name: "Remove property…" }).click();
  await page.getByLabel("Property key", { exact: true }).fill("site");
  await page.getByRole("button", { name: "Remove from 2 selected" }).click();
  await expect(column).toHaveCount(0);
  await expect(table.getByRole("cell", { name: "Branch", exact: true })).toHaveCount(0);
  expect(writes[1]).toEqual({ machine_ids: ids, key: "site", value: "", delete: true });
});
