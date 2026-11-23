// docs/65 sec. 8 "Forget this machine", console side, against a MOCKED control plane (no Go server, no agent). The control
// plane's rules (retired only, step-up freshness, the typed name, group scope, the closure of an active directive, the
// tombstone) are its own tested contract (control-plane/forget_test.go and forget_race_test.go); this spec proves the console:
// who is offered the action and where, the plain-words dialog, the typed name and the authenticator code BEFORE the call,
// the call itself, the refresh afterwards (the machine reads "removed", the pending removal is gone), and the server's
// refusals shown in friendly words. Same mocking approach as fleet_directives.spec.ts.
import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { clickMachineAction, openMachineActions } from "./machine_actions";

type Row = Record<string, unknown>;

const machine = (id: string, name: string, status: string, extra: Row = {}): Row => ({
  id, tenant_id: "t1", device_id: `dev-${id}`, group_id: "g1", name, status, online: false, ...extra,
});

const directive = (id: string, machineId: string, extra: Row = {}): Row => ({
  id, machine_id: machineId, kind: "uninstall", state: "removal_unconfirmed", requested_by: "u-other",
  requested_at: "2026-10-31T10:00:00Z", not_before: "2026-10-31T10:15:00Z", request_expires_at: "2026-10-31T11:00:00Z",
  require_approval: false, issued_at: "2026-10-31T10:16:00Z", ...extra,
});

const ACTIVE = ["requested", "issued", "accepted", "executing", "reboot_pending", "removal_unconfirmed"];

// scope: "all" = remove_agent tenant-wide; [] = not held at all; ["g2"] = held for those groups only.
async function harness(page: Page, opts: { scope?: string[] | "all" } = {}) {
  const scope = opts.scope ?? "all";
  const cap = scope === "all" || scope.length > 0;
  const covers = (group: string) => scope === "all" || scope.includes(group);
  const cp = {
    machines: [
      machine("m-act", "ACTIVE-PC", "active"),
      machine("m-ret", "RETIRED-PC", "retired", { alias: "Old reception" }),
      machine("m-q", "QUARANTINE-PC", "quarantined"),
      machine("m-g2", "OTHER-GROUP-PC", "retired", { group_id: "g2" }),
      machine("m-gone", "GONE-PC", "removed"),
    ] as Row[],
    directives: {} as Record<string, Row[]>,
    calls: [] as string[], // "METHOD path" in order
    bodies: {} as Record<string, unknown>,
    stepUpOk: true,
    forgetStatus: 200, forgetBody: null as unknown, // a non-200 status answers forgetBody instead of doing it
    forgetOutcome: "forgotten" as "forgotten" | "already_removed",
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const key = `${req.method()} ${path}`;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") {
      return route.fulfill({ json: {
        email: "owner@example.test", user_id: "u-me",
        capabilities: [
          { capability: "view_machines", all_groups: true, group_ids: [] },
          ...(!cap ? [] : scope === "all"
            ? [{ capability: "remove_agent", all_groups: true, group_ids: [] }]
            : [{ capability: "remove_agent", all_groups: false, group_ids: scope }]),
        ],
      } });
    }
    if (path === "/cp/machines") return route.fulfill({ json: { machines: cp.machines, presence_known: true } });
    if (path === "/cp/users") return route.fulfill({ json: { users: [] } });
    if (path === "/cp/directives") {
      cp.calls.push(key);
      const rows = Object.entries(cp.directives).flatMap(([mid, ds]) => ds.map((d) => ({ d, m: cp.machines.find((x) => x.id === mid)! })))
        .filter(({ d, m }) => ACTIVE.includes(d.state as string) && covers(m.group_id as string))
        .map(({ d, m }) => ({ ...d, machine_name: m.name, ...(m.alias ? { machine_alias: m.alias } : {}), machine_status: m.status }));
      return route.fulfill({ json: { directives: rows } });
    }
    if (path === "/cp/tenant/directive-policy") {
      return cap ? route.fulfill({ json: { policy: { require_second_approver: false, version: 1 } } })
        : route.fulfill({ status: 403, json: { error: "forbidden: requires remove_agent" } });
    }
    if (path === "/cp/auth/step-up") {
      cp.calls.push(key);
      cp.bodies[key] = req.postDataJSON();
      return cp.stepUpOk ? route.fulfill({ status: 204 }) : route.fulfill({ status: 403, json: { error: "invalid code" } });
    }
    const forget = /^\/cp\/machines\/([^/]+)\/forget$/.exec(path);
    if (forget) {
      cp.calls.push(key);
      cp.bodies[key] = req.postDataJSON();
      if (cp.forgetStatus !== 200) return route.fulfill({ status: cp.forgetStatus, json: cp.forgetBody });
      const m = cp.machines.find((x) => x.id === forget[1])!;
      const closed = (cp.directives[forget[1]] ?? []).filter((d) => ACTIVE.includes(d.state as string));
      if (cp.forgetOutcome === "forgotten") {
        m.status = "removed";
        for (const d of closed) Object.assign(d, { state: "forgotten" });
      }
      return route.fulfill({ json: { outcome: cp.forgetOutcome, machine: m, closed_directives: closed } });
    }
    if (/^\/cp\/machines\/[^/]+\/directives$/.test(path)) return route.fulfill({ json: { directives: [] } });
    if (path === "/cp/audit") return route.fulfill({ json: { events: [] } });
    return route.fulfill({ json: {} });
  });
  return cp;
}

async function openMachines(page: Page) {
  await page.goto(test.info().project.use.baseURL!);
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("machine-status-m-act")).toBeVisible();
}

test("Forget is offered beside Remove on RETIRED machines only, and only with remove_agent for the machine's group", async ({ page }) => {
  await harness(page);
  await openMachines(page);
  await openMachineActions(page, "m-ret");
  await expect(page.getByTestId("machine-forget-m-ret")).toBeVisible();
  await expect(page.getByTestId("machine-forget-m-ret")).toHaveText("Forget this machine…");
  await openMachineActions(page, "m-ret");
  await expect(page.getByTestId("machine-remove-agent-m-ret")).toBeVisible(); // next to it, not instead of it
  await openMachineActions(page, "m-g2");
  await expect(page.getByTestId("machine-forget-m-g2")).toBeVisible();
  await expect(page.getByTestId("machine-forget-m-act")).toHaveCount(0); // retire first, then forget
  await expect(page.getByTestId("machine-forget-m-q")).toHaveCount(0);
  await expect(page.getByTestId("machine-forget-m-gone")).toHaveCount(0); // nothing left to forget
  // A removed machine has no status to choose: its dropdown would read "active".
  await expect(page.getByTestId("machine-status-m-gone")).toHaveText("removed");
  await expect(page.getByTestId("machine-status-select-m-gone")).toHaveCount(0);
  await expect(page.getByTestId("machine-status-select-m-ret")).toBeVisible();
});

test("a group-scoped holder is offered Forget only for machines in their groups; without remove_agent there is no Forget and no directive call", async ({ page }) => {
  const scoped = await harness(page, { scope: ["g2"] });
  await openMachines(page);
  await openMachineActions(page, "m-g2");
  await expect(page.getByTestId("machine-forget-m-g2")).toBeVisible();
  await expect(page.getByTestId("machine-forget-m-ret")).toHaveCount(0); // retired, but in g1
  expect(scoped.calls.filter((c) => c.startsWith("POST") && c.includes("/forget"))).toEqual([]);
});

test("without remove_agent (absent from /me) there is no Forget at all", async ({ page }) => {
  const cp = await harness(page, { scope: [] });
  await openMachines(page);
  await expect(page.getByTestId("machine-props-m-ret")).toBeVisible();
  await expect(page.getByTestId("machine-forget-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("machine-forget-m-g2")).toHaveCount(0);
  await expect(page.getByTestId("pending-removals")).toHaveCount(0);
  expect(cp.calls.filter((c) => c.includes("forget") || c.includes("directive"))).toEqual([]);
});

test("Forget: plain words, the typed name and the authenticator code, the step-up BEFORE the call, then the machine reads removed and its pending removal is gone", async ({ page }) => {
  const cp = await harness(page);
  cp.directives["m-ret"] = [directive("silent", "m-ret")];
  await openMachines(page);
  await expect(page.getByTestId("removal-state-silent")).toHaveText("Removal unconfirmed");

  await clickMachineAction(page, "m-ret", "machine-forget-m-ret");
  const dialog = page.getByTestId("forget-machine-dialog");
  await expect(dialog.getByRole("heading")).toHaveText("Forget Old reception");
  await expect(dialog.getByTestId("forget-machine-effect")).toHaveText(
    "This permanently removes Old reception from DeskRally. The machine can never reconnect with its current identity, and this cannot be undone. Reinstalling the agent on it enrolls it as a new machine.",
  );
  await expect(dialog.getByTestId("forget-machine-when")).toHaveText("Use this when the machine is gone, or when its removal will never be confirmed by the agent.");
  await expect(dialog.getByTestId("forget-machine-notice")).toHaveText("It does not uninstall anything on the machine itself.");

  const submit = page.getByTestId("forget-machine-submit");
  await expect(submit).toBeDisabled();
  await page.getByTestId("forget-machine-code").fill("123456");
  await expect(submit).toBeDisabled(); // the code alone is not enough
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED");
  await expect(submit).toBeDisabled(); // a partial name is not enough
  await page.getByTestId("forget-machine-confirm-input").fill("retired-pc");
  await expect(submit).toBeDisabled(); // the wrong case
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED-PC");
  await expect(submit).toBeEnabled();
  await page.getByTestId("forget-machine-code").fill("12345");
  await expect(submit).toBeDisabled(); // five digits
  await page.getByTestId("forget-machine-code").fill("123456");
  expect(cp.calls.filter((c) => c.includes("forget"))).toHaveLength(0);

  await submit.click();
  await expect(page.getByTestId("forget-machine-result")).toHaveText("Old reception was forgotten. It can no longer connect; reinstalling the agent on it enrolls it as a new machine.");
  const sent = cp.calls.filter((c) => c === "POST /cp/auth/step-up" || c === "POST /cp/machines/m-ret/forget");
  expect(sent).toEqual(["POST /cp/auth/step-up", "POST /cp/machines/m-ret/forget"]);
  expect(cp.bodies["POST /cp/auth/step-up"]).toEqual({ code: "123456" });
  expect(cp.bodies["POST /cp/machines/m-ret/forget"]).toEqual({ confirm: "RETIRED-PC" });

  await page.getByTestId("forget-machine-close").click();
  await expect(page.getByTestId("forget-machine-dialog")).toHaveCount(0);
  await expect(page.getByTestId("machine-status-m-ret")).toHaveText("removed");
  await expect(page.getByTestId("machine-forget-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("machine-remove-agent-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("machine-status-select-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("removal-silent")).toHaveCount(0); // closed: the panel stops listing it
  await expect(page.getByTestId("pending-removals-empty")).toBeVisible();
  await expect(page.getByTestId("directive-note")).toContainText("was forgotten");
});

test("the alias also confirms the forget", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-forget-m-ret");
  await page.getByTestId("forget-machine-confirm-input").fill("Old reception");
  await page.getByTestId("forget-machine-code").fill("654321");
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-result")).toBeVisible();
  expect(cp.bodies["POST /cp/machines/m-ret/forget"]).toEqual({ confirm: "Old reception" });
  await page.keyboard.press("Escape"); // the result view keeps focus inside the dialog, so Escape closes it
  await expect(page.getByTestId("forget-machine-dialog")).toHaveCount(0);
});

test("the pending-removals row of an unconfirmed removal offers the same action; no other state does", async ({ page }) => {
  const cp = await harness(page);
  cp.directives["m-ret"] = [directive("silent", "m-ret")];
  cp.directives["m-g2"] = [directive("running", "m-g2", { state: "executing" })];
  await openMachines(page);
  await expect(page.getByTestId("removal-forget-silent")).toBeVisible();
  await expect(page.getByTestId("removal-forget-silent")).toHaveText("Forget this machine…");
  await expect(page.getByTestId("removal-forget-running")).toHaveCount(0); // the agent may still be removing itself

  await page.getByTestId("removal-forget-silent").click();
  await expect(page.getByTestId("forget-machine-dialog").getByRole("heading")).toHaveText("Forget Old reception");
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("forget-machine-code").fill("112233");
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-result")).toBeVisible();
  expect(cp.calls.filter((c) => c === "POST /cp/auth/step-up" || c === "POST /cp/machines/m-ret/forget")).toEqual(["POST /cp/auth/step-up", "POST /cp/machines/m-ret/forget"]);
  await page.getByTestId("forget-machine-close").click();
  await expect(page.getByTestId("removal-silent")).toHaveCount(0);
  await expect(page.getByTestId("removal-running")).toBeVisible(); // another machine's removal is untouched
  await expect(page.getByTestId("machine-status-m-ret")).toHaveText("removed");
});

test("a wrong authenticator code stops before any forget call; Escape closes the dialog without calling anything", async ({ page }) => {
  const cp = await harness(page);
  cp.stepUpOk = false;
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-forget-m-ret");
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("forget-machine-code").fill("000000");
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-error")).toContainText("That code was not accepted");
  expect(cp.calls.filter((c) => c.includes("/forget"))).toHaveLength(0);
  await expect(page.getByTestId("machine-status-m-ret")).toHaveText("retired");
  await page.keyboard.press("Escape");
  await expect(page.getByTestId("forget-machine-dialog")).toHaveCount(0);
  expect(cp.calls.filter((c) => c.includes("/forget"))).toHaveLength(0);
});

test("the server's refusals are shown in friendly words and change nothing on screen", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-forget-m-ret");
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("forget-machine-code").fill("123456");

  cp.forgetStatus = 403;
  cp.forgetBody = { error: "a recent second-factor verification is required", code: "step_up_required" };
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-error")).toContainText("authenticator code is needed");

  cp.forgetStatus = 409;
  cp.forgetBody = { error: "a machine can only be forgotten after it is retired" };
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-error")).toContainText("Retire the machine first");

  cp.forgetStatus = 422;
  cp.forgetBody = { error: "type the machine's name to confirm that it is forgotten" };
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-error")).toContainText("Type the machine's name exactly to confirm");

  cp.forgetStatus = 403;
  cp.forgetBody = { error: "forbidden: requires remove_agent" };
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-error")).toContainText("Not allowed");

  await expect(page.getByTestId("forget-machine-done")).toHaveCount(0);
  await expect(page.getByTestId("machine-status-m-ret")).toHaveText("retired");
});

test("a machine that was already removed (someone else forgot it first) is reported as such, never as a second forget", async ({ page }) => {
  const cp = await harness(page);
  cp.forgetOutcome = "already_removed";
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-forget-m-ret");
  await page.getByTestId("forget-machine-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("forget-machine-code").fill("123456");
  await page.getByTestId("forget-machine-submit").click();
  await expect(page.getByTestId("forget-machine-result")).toHaveText("Old reception was already removed. Nothing changed.");
});
