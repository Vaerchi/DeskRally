import { consoleTab } from "./nav";
import { test, expect, type Page } from "@playwright/test";

// Toolbox folders (decision 2026-11-24): "Folder/Name" files a script in a folder. The Toolbox area groups by
// folder with collapsible headings; a search shows matches even inside collapsed folders.

const item = (id: string, name: string) => ({
  id, name, description: "", scope: "shared", shell: "powershell", run_as: "system", body: "Get-Date",
  body_sha256: "0".repeat(64), version: 1, updated_at: "2026-11-24T00:00:00Z", mine: false,
});
const ITEMS = [item("a", "Maintenance/Clear temp"), item("b", "maintenance/Disk check"), item("c", "Network/DNS/Flush"), item("d", "Loose script")];

async function open(page: Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") return route.fulfill({ json: { sessions: [] } });
    if (path === "/cp/toolbox") return route.fulfill({ json: { items: ITEMS, can_manage_shared: true } });
    return route.fulfill({ json: {} });
  });
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await (await consoleTab(page, { name: "Toolbox", exact: true })).click();
}

test("scripts are grouped by folder; folders collapse; search reaches into collapsed folders", async ({ page }) => {
  await open(page);
  // Unfiled first, then folders A-Z; case-variant folder names are one folder.
  const rows = page.locator("tbody tr");
  await expect(rows.nth(0)).toContainText("Loose script");
  await expect(page.getByTestId("toolbox-folder-Maintenance")).toContainText("Maintenance (2)");
  await expect(page.getByTestId("toolbox-folder-Network/DNS")).toContainText("Network/DNS (1)");
  // Rows inside a folder show the short name; the full name is the tooltip.
  const clear = page.getByTestId("toolbox-row-Maintenance/Clear temp");
  await expect(clear.locator("td").first()).toHaveText("Clear temp");
  await expect(clear.locator("td").first()).toHaveAttribute("title", "Maintenance/Clear temp");

  await page.getByTestId("toolbox-folder-toggle-Maintenance").click();
  await expect(page.getByTestId("toolbox-folder-toggle-Maintenance")).toHaveAttribute("aria-expanded", "false");
  await expect(clear).toHaveCount(0);
  await expect(page.getByTestId("toolbox-row-Network/DNS/Flush")).toBeVisible();

  await page.getByTestId("toolbox-search").fill("disk");
  await expect(page.getByTestId("toolbox-row-maintenance/Disk check")).toBeVisible();
  await page.getByTestId("toolbox-search").fill("");
  await expect(clear).toHaveCount(0);
});
