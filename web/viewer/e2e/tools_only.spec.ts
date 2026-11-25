import { test, expect } from "@playwright/test";
import { openAccessActions } from "./machine_actions";

// "Under the Hood only" (2026-11-24): the machine row's ⋯ menu connects straight into Under the Hood (the SYSTEM
// tools view) instead of the screen.

const DEVICE = "7a7a7a7a-1111-4222-8333-444455556666";
const MACHINE = {
  id: "pk-t", tenant_id: "t-1", device_id: DEVICE, group_id: "g-1", group_name: "Home Computers",
  name: "Office PC", os: "Windows 11", online: true, multi_session_capable: true,
};

async function fixture(page: import("@playwright/test").Page) {
  await page.route("**/cp/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machines") return route.fulfill({ json: { machines: [MACHINE], presence_known: true } });
    if (path === "/cp/sessions") return route.fulfill({ json: { sessions: [] } });
    return route.fulfill({ json: {} });
  });
  await page.goto(test.info().project.use.baseURL ?? "http://127.0.0.1:5173");
  await expect(page.getByTestId(`connect-${DEVICE}`)).toBeVisible();
}

test("Under the Hood only connects straight into the tools view", async ({ page }) => {
  await fixture(page);
  await openAccessActions(page, DEVICE);
  const item = page.getByTestId(`tools-only-${DEVICE}`);
  await expect(item).toHaveText("Under the Hood only");
  await expect(item).toHaveAttribute("title", /still shows that a technician is connected/);
  await item.click();
  const view = page.getByRole("combobox", { name: "Session view", exact: true });
  await expect(view).toHaveValue("backstage");
  await expect(page.getByRole("tab", { name: "Processes", exact: true })).toBeVisible();
});
