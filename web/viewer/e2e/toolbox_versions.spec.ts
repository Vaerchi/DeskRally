import { consoleTab } from "./nav";
import { test, expect } from "@playwright/test";

// Toolbox version history (migration 0089): the editor lists saved versions; "Load into editor" copies an old one into
// the form, and Save sends it as an ordinary update at the CURRENT version (a restore is a new, audited version).

const ITEM = {
  id: "t-ver", name: "Clear temp", description: "", scope: "shared", shell: "powershell", run_as: "system",
  body: "Get-Date", body_sha256: "0".repeat(64), version: 3, updated_at: "2026-11-24T10:00:00Z", mine: false,
};
const VERSIONS = [
  { version: 3, name: "Clear temp", description: "", shell: "powershell", run_as: "system", body: "Get-Date", body_sha256: "c", saved_by: "owner@acme.test", saved_at: "2026-11-24T10:00:00Z" },
  { version: 2, name: "Clear temp", description: "", shell: "powershell", run_as: "system", body: "Get-ChildItem $env:TEMP", body_sha256: "b", saved_by: "owner@acme.test", saved_at: "2026-11-23T10:00:00Z" },
  { version: 1, name: "Temp cleaner", description: "old", shell: "powershell", run_as: "system", body: "Remove-Item $env:TEMP\\*", body_sha256: "a", saved_by: "tech@acme.test", saved_at: "2026-11-22T10:00:00Z" },
];

test("the editor lists versions and restores one through an ordinary save", async ({ page }) => {
  const puts: { url: string; body: Record<string, unknown> }[] = [];
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [], presence_known: true } });
    if (path === "/cp/sessions") return route.fulfill({ json: { sessions: [] } });
    if (path === "/cp/toolbox") return route.fulfill({ json: { items: [ITEM], can_manage_shared: true } });
    if (path === `/cp/toolbox/${ITEM.id}/versions`) return route.fulfill({ json: { versions: VERSIONS } });
    if (path === `/cp/toolbox/${ITEM.id}` && req.method() === "PUT") {
      puts.push({ url: path, body: req.postDataJSON() });
      return route.fulfill({ json: { item: { ...ITEM, version: 4, body: "Remove-Item $env:TEMP\\*", name: "Temp cleaner" } } });
    }
    return route.fulfill({ json: {} });
  });
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await (await consoleTab(page, { name: "Toolbox", exact: true })).click();
  await page.getByTestId(`toolbox-row-${ITEM.name}`).getByRole("button", { name: "Edit" }).click();

  await page.getByTestId("toolbox-versions-toggle").click();
  await expect(page.getByTestId("toolbox-version-3")).toContainText("(current)");
  await expect(page.getByTestId("toolbox-version-load-3")).toHaveCount(0);
  await expect(page.getByTestId("toolbox-version-1")).toContainText('by tech@acme.test (as "Temp cleaner")');

  await page.getByTestId("toolbox-version-load-1").click();
  await expect(page.getByTestId("toolbox-body")).toHaveValue("Remove-Item $env:TEMP\\*");
  await expect(page.getByTestId("toolbox-name")).toHaveValue("Temp cleaner");
  await expect(page.getByTestId("toolbox-version-loaded")).toContainText("Version 1 is in the editor");

  await page.getByTestId("toolbox-save").click();
  await expect.poll(() => puts.length).toBe(1);
  expect(puts[0].body).toMatchObject({ name: "Temp cleaner", body: "Remove-Item $env:TEMP\\*", expected_version: 3 });
});
