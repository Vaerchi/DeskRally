import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { clickMachineAction, openMachineActions } from "./machine_actions";

type Row = Record<string, unknown>;

const machine = (id: string, name: string, extra: Row): Row => ({
  id, tenant_id: "t1", device_id: `dev-${id}`, group_id: "g1", name, status: "active", online: false, ...extra,
});

async function harness(page: Page, response = { status: 202, json: { status: "requested" } as Row }) {
  const cp = {
    machines: [
      machine("m-ready", "READY-PC", { wake: "ready" }),
      machine("m-no-relay", "NO-RELAY-PC", { wake: "no_relay" }),
      machine("m-online", "ONLINE-PC", { online: true }),
    ],
    calls: [] as { method: string; path: string; body: string | null }[],
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") {
      return route.fulfill({ json: {
        email: "owner@example.test", user_id: "u-me",
        capabilities: [
          { capability: "view_machines", all_groups: true, group_ids: [] },
          { capability: "wake_machine", all_groups: false, group_ids: ["g1"] },
        ],
      } });
    }
    if (path === "/cp/machines") return route.fulfill({ json: { machines: cp.machines, presence_known: true } });
    if (/^\/cp\/machines\/[^/]+\/wake$/.test(path)) {
      cp.calls.push({ method: req.method(), path, body: req.postData() });
      return route.fulfill(response);
    }
    return route.fulfill({ json: {} });
  });
  return cp;
}

async function openMachines(page: Page) {
  await page.goto(test.info().project.use.baseURL!);
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("machine-status-m-ready")).toBeVisible();
}

test("an offline ready machine can request Wake", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  await openMachineActions(page, "m-ready");
  const wake = page.getByRole("button", { name: "Wake", exact: true });
  await expect(wake).toBeEnabled();
  await wake.click();

  const notice = page.getByTestId("directive-note");
  await expect(notice).toContainText("Wake requested. It only works if Wake-on-LAN is turned on for this machine.");
  await expect(notice.getByRole("link", { name: "See which power states DeskRally has verified" }))
    .toHaveAttribute("href", "/docs/wake-on-lan");
  expect(cp.calls).toEqual([{ method: "POST", path: "/cp/machines/m-ready/wake", body: null }]);
});

test("Wake is disabled without a relay and hidden for an online machine", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  await openMachineActions(page, "m-no-relay");
  const wake = page.getByTestId("machine-wake-m-no-relay");
  await expect(wake).toBeVisible();
  await expect(wake).toBeDisabled();
  await expect(wake).toHaveAttribute("title", "No online machine you manage is on its network");
  await openMachineActions(page, "m-online");
  await expect(page.getByTestId("machine-wake-m-online")).toHaveCount(0);
  expect(cp.calls).toEqual([]);
});

test("a changed Wake request asks the operator to retry", async ({ page }) => {
  await harness(page, { status: 409, json: { error: "changed" } });
  await openMachines(page);
  await clickMachineAction(page, "m-ready", "machine-wake-m-ready");
  await expect(page.getByTestId("directive-note")).toContainText("Something changed while sending the request. Try again.");
});
