import { test, expect } from "@playwright/test";
import { consoleTab } from "./nav";

// Menu redesign wave 3: ONE connect rule for the sidebar and the Machines page (lib/connect_rule.ts). Before, the Machines page
// disabled Connect on a machine that merely LOOKED offline while the sidebar deliberately kept it, and the sidebar offered Connect
// on an out-of-service machine the Machines page refused. Now presence never disables Connect; only an out-of-service status does,
// on both surfaces, with the reason in the tooltip.
const ONLINE = "11111111-1111-4111-8111-111111111111";
const OFFLINE = "22222222-2222-4222-8222-222222222222";
const QUARANTINED = "33333333-3333-4333-8333-333333333333";
const machines = [
  { id: "m1", tenant_id: "t1", device_id: ONLINE, name: "Office PC", group_id: "g1", group_name: "Office", online: true, status: "active", os: "Windows" },
  { id: "m2", tenant_id: "t1", device_id: OFFLINE, name: "Laptop", group_id: "g1", group_name: "Office", online: false, status: "active", os: "Windows" },
  { id: "m3", tenant_id: "t1", device_id: QUARANTINED, name: "Kiosk", group_id: "g1", group_name: "Office", online: true, status: "quarantined", os: "Windows" },
];

test("presence never disables Connect; out of service does, on both machine lists", async ({ page }) => {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines, presence_known: true } });
    if (path === "/cp/machine-groups") return route.fulfill({ json: { machine_groups: [{ id: "g1", name: "Office" }] } });
    return route.fulfill({ json: {} });
  });
  await page.goto("/");

  // Sidebar.
  if (!(await page.locator(".access__search").isVisible())) await page.getByTestId("app-nav-toggle").click();
  await expect(page.getByTestId(`connect-${ONLINE}`)).toBeEnabled();
  await expect(page.getByTestId(`connect-${OFFLINE}`)).toBeEnabled();
  await expect(page.getByTestId(`connect-${OFFLINE}`)).toHaveAttribute("title", /looked offline/);
  await expect(page.getByTestId(`connect-${QUARANTINED}`)).toBeDisabled();
  await expect(page.getByTestId(`connect-${QUARANTINED}`)).toHaveAttribute("title", /Out of service \(quarantined\)/);

  // Machines page: the same answers.
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("machine-connect-m1")).toBeEnabled();
  await expect(page.getByTestId("machine-connect-m2")).toBeEnabled();
  await expect(page.getByTestId("machine-connect-m2")).toHaveAttribute("title", /looked offline/);
  await expect(page.getByTestId("machine-connect-m3")).toBeDisabled();
  await expect(page.getByTestId("machine-connect-m3")).toHaveAttribute("title", /Out of service \(quarantined\)/);
});
