// docs/65 fleet agent directives, console side, against a MOCKED control plane (no Go server, no agent). The
// control plane's rules (retired-only, step-up freshness, typed name, caps, approver != requester, windows) are
// its own tested contract (control-plane/directive*_test.go); this spec proves the console: what is offered to
// whom, the typed confirmation, the step-up before the request, the live cancel window, approve hidden from
// the requester, and the server's refusals shown in friendly words.
import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { clickMachineAction, openMachineActions } from "./machine_actions";

type Row = Record<string, unknown>;

const machine = (id: string, name: string, status: string, extra: Row = {}): Row => ({
  id, tenant_id: "t1", device_id: `dev-${id}`, group_id: "g1", name, status, online: false, ...extra,
});

const directive = (id: string, extra: Row = {}): Row => ({
  id, machine_id: "m-ret", kind: "uninstall", state: "requested", requested_by: "u-other",
  requested_at: "2026-10-31T10:00:00Z", not_before: "2026-10-31T10:15:00Z", request_expires_at: "2026-10-31T11:00:00Z",
  require_approval: false, ...extra,
});

// scope: undefined = remove_agent tenant-wide; [] = not held at all; ["g2"] = held for those groups only.
async function harness(page: Page, opts: { scope?: string[] | "all"; clock?: boolean } = {}) {
  const scope = opts.scope ?? "all";
  const cap = scope === "all" || scope.length > 0;
  const covers = (group: string) => scope === "all" || scope.includes(group);
  if (opts.clock) await page.clock.install({ time: new Date("2026-10-31T10:00:00Z") });
  const cp = {
    machines: [machine("m-act", "ACTIVE-PC", "active"), machine("m-ret", "RETIRED-PC", "retired", { alias: "Old reception" }), machine("m-q", "QUARANTINE-PC", "quarantined"), machine("m-g2", "OTHER-GROUP-PC", "retired", { group_id: "g2" })] as Row[],
    policy: { require_second_approver: false, version: 1 },
    directives: {} as Record<string, Row[]>,
    users: [{ id: "u-me", email: "owner@example.test", display_name: "Owner", disabled: false, roles: ["owner"] }, { id: "u-other", email: "other@example.test", display_name: "Other", disabled: false, roles: ["owner"] }] as Row[],
    meUserId: "u-me" as string | undefined,
    calls: [] as string[], // "METHOD path" in order
    bodies: {} as Record<string, unknown>,
    stepUpOk: true,
    requestStatus: 201, requestBody: null as unknown,
    reinstallStatus: 201, reinstallBody: null as unknown,
    approveStatus: 200, approveBody: null as unknown,
  };
  await page.route(/.*/, (route) => new URL(route.request().url()).hostname === "127.0.0.1" ? route.continue() : route.abort());
  await page.route("**/cp/**", async (route) => {
    const req = route.request();
    const path = new URL(req.url()).pathname;
    const key = `${req.method()} ${path}`;
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/me") {
      return route.fulfill({ json: {
        email: "owner@example.test", ...(cp.meUserId ? { user_id: cp.meUserId } : {}),
        capabilities: [
          { capability: "view_machines", all_groups: true, group_ids: [] },
          ...(!cap ? [] : scope === "all"
            ? [{ capability: "remove_agent", all_groups: true, group_ids: [] }]
            : [{ capability: "remove_agent", all_groups: false, group_ids: scope }]),
        ],
      } });
    }
    if (path === "/cp/machines") return route.fulfill({ json: { machines: cp.machines, presence_known: true } });
    if (path === "/cp/users") return route.fulfill({ json: { users: cp.users } });
    if (path === "/cp/directives") {
      cp.calls.push(`${key}${new URL(req.url()).search}`);
      const active = ["requested", "issued", "accepted", "executing", "reboot_pending", "removal_unconfirmed"];
      const rows = Object.entries(cp.directives).flatMap(([mid, ds]) => ds.map((d) => ({ d, m: cp.machines.find((x) => x.id === mid)! })))
        .filter(({ d, m }) => active.includes(d.state as string) && covers(m.group_id as string))
        .map(({ d, m }) => ({ ...d, machine_name: m.name, ...(m.alias ? { machine_alias: m.alias } : {}), machine_status: m.status }));
      return route.fulfill({ json: { directives: rows } });
    }
    if (path === "/cp/tenant/directive-policy") {
      if (!cap) return route.fulfill({ status: 403, json: { error: "forbidden: requires remove_agent" } });
      if (req.method() === "PUT") {
        cp.calls.push(key);
        cp.bodies[key] = req.postDataJSON();
        cp.policy = { require_second_approver: (req.postDataJSON() as { require_second_approver: boolean }).require_second_approver, version: cp.policy.version + 1 };
      }
      return route.fulfill({ json: { policy: cp.policy } });
    }
    if (path === "/cp/auth/step-up") {
      cp.calls.push(key);
      cp.bodies[key] = req.postDataJSON();
      return cp.stepUpOk ? route.fulfill({ status: 204 }) : route.fulfill({ status: 403, json: { error: "invalid code" } });
    }
    const list = /^\/cp\/machines\/([^/]+)\/directives$/.exec(path);
    if (list) {
      if (req.method() === "POST") {
        const body = req.postDataJSON() as { kind: string };
        cp.calls.push(`${key} ${body.kind}`);
        cp.bodies[`${key} ${body.kind}`] = body;
        if (body.kind === "reinstall") {
          return cp.reinstallStatus === 201
            ? route.fulfill({ status: 201, json: { directive: directive("r1", { kind: "reinstall", state: "issued", machine_id: list[1] }) } })
            : route.fulfill({ status: cp.reinstallStatus, json: cp.reinstallBody });
        }
        if (cp.requestStatus !== 201) return route.fulfill({ status: cp.requestStatus, json: cp.requestBody });
        const d = directive("d-new", { requested_by: "u-me", machine_id: list[1], require_approval: cp.policy.require_second_approver });
        cp.directives[list[1]] = [d, ...(cp.directives[list[1]] ?? [])];
        return route.fulfill({ status: 201, json: { directive: d } });
      }
      return route.fulfill({ json: { directives: cp.directives[list[1]] ?? [] } });
    }
    const act = /^\/cp\/directives\/([^/]+)\/(approve|cancel)$/.exec(path);
    if (act) {
      cp.calls.push(key);
      cp.bodies[key] = req.postDataJSON();
      const all = Object.values(cp.directives).flat();
      const d = all.find((x) => x.id === act[1])!;
      if (act[2] === "approve") {
        if (cp.approveStatus !== 200) return route.fulfill({ status: cp.approveStatus, json: cp.approveBody });
        Object.assign(d, { approved_by: "u-me", approved_at: "2026-10-31T10:05:00Z", not_before: "2026-10-31T10:20:00Z" });
      } else {
        Object.assign(d, { state: "cancelled", cancelled_by: "u-me", cancelled_at: "2026-10-31T10:01:00Z" });
      }
      return route.fulfill({ json: { directive: d } });
    }
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

test("Reinstall is offered on active machines only and Remove on RETIRED ones only, and only with remove_agent", async ({ page }) => {
  await harness(page);
  await openMachines(page);
  // Menu redesign wave 8: the row shows Properties and a "⋯" menu named for its machine; the actions are in the
  // menu, mounted but hidden until it opens.
  await expect(page.getByTestId("machine-props-m-act")).toBeVisible();
  await expect(page.getByTestId("machine-actions-m-act")).toHaveAttribute("aria-label", /^More actions for /);
  await expect(page.getByTestId("machine-reinstall-m-act")).toBeHidden();
  await openMachineActions(page, "m-act");
  await expect(page.getByTestId("machine-reinstall-m-act")).toBeVisible();
  await expect(page.getByTestId("machine-reinstall-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("machine-reinstall-m-q")).toHaveCount(0);
  await openMachineActions(page, "m-ret");
  await expect(page.getByTestId("machine-remove-agent-m-ret")).toBeVisible();
  await expect(page.getByTestId("machine-remove-agent-m-act")).toHaveCount(0);
  await expect(page.getByTestId("machine-remove-agent-m-q")).toHaveCount(0);
  await expect(page.getByTestId("pending-removals")).toBeVisible();
  await expect(page.getByTestId("directive-policy")).toBeVisible();
});

test("without remove_agent (absent from /me) there is no reinstall, no remove, no removals view, and no directive route is called", async ({ page }) => {
  const cp = await harness(page, { scope: [] });
  await openMachines(page);
  await expect(page.getByTestId("machine-props-m-ret")).toBeVisible();
  await expect(page.getByTestId("machine-reinstall-m-act")).toHaveCount(0);
  await expect(page.getByTestId("machine-remove-agent-m-ret")).toHaveCount(0);
  await expect(page.getByTestId("pending-removals")).toHaveCount(0);
  await expect(page.getByTestId("directive-policy")).toHaveCount(0);
  expect(cp.calls.filter((c) => c.includes("directive"))).toEqual([]);
});

test("a group-scoped holder is offered Remove/Reinstall only for machines in their groups (the server's own per-group rule)", async ({ page }) => {
  const cp = await harness(page, { scope: ["g2"] });
  cp.directives["m-ret"] = [directive("hidden", { requested_by: "u-other" })];
  cp.directives["m-g2"] = [directive("shown", { machine_id: "m-g2", requested_by: "u-other" })];
  await openMachines(page);
  await openMachineActions(page, "m-g2");
  await expect(page.getByTestId("machine-remove-agent-m-g2")).toBeVisible();
  await expect(page.getByTestId("machine-remove-agent-m-ret")).toHaveCount(0); // retired, but in g1
  await expect(page.getByTestId("machine-reinstall-m-act")).toHaveCount(0); // active, but in g1
  await expect(page.getByTestId("removal-shown")).toBeVisible();
  await expect(page.getByTestId("removal-hidden")).toHaveCount(0);
});

test("Remove: the typed name is required, the step-up runs BEFORE the request, then the countdown ticks and Cancel works", async ({ page }) => {
  const cp = await harness(page, { clock: true });
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-remove-agent-m-ret");
  const dialog = page.getByTestId("remove-agent-dialog");
  await expect(dialog.getByTestId("remove-agent-effect")).toContainText("never reconnect with this identity");
  await expect(dialog.getByTestId("remove-agent-effect")).toContainText("Recordings stored only on the machine are deleted");

  const submit = page.getByTestId("remove-agent-submit");
  await expect(submit).toBeDisabled();
  await page.getByTestId("remove-agent-code").fill("123456");
  await expect(submit).toBeDisabled(); // code alone is not enough
  await page.getByTestId("remove-agent-confirm-input").fill("RETIRED");
  await expect(submit).toBeDisabled(); // a partial name is not enough
  await page.getByTestId("remove-agent-confirm-input").fill("retired-pc");
  await expect(submit).toBeDisabled(); // wrong case
  await page.getByTestId("remove-agent-confirm-input").fill("RETIRED-PC");
  await expect(submit).toBeEnabled();
  expect(cp.calls.filter((c) => c.includes("directives") && c.startsWith("POST"))).toHaveLength(0);

  await submit.click();
  await expect(page.getByTestId("remove-agent-requested")).toBeVisible();
  const posts = cp.calls.filter((c) => c === "POST /cp/auth/step-up" || c === "POST /cp/machines/m-ret/directives uninstall");
  expect(posts).toEqual(["POST /cp/auth/step-up", "POST /cp/machines/m-ret/directives uninstall"]);
  expect(cp.bodies["POST /cp/auth/step-up"]).toEqual({ code: "123456" });
  expect(cp.bodies["POST /cp/machines/m-ret/directives uninstall"]).toEqual({ kind: "uninstall", confirm: "RETIRED-PC" });

  const countdown = page.getByTestId("remove-agent-countdown");
  await expect(countdown).toContainText(/(15:00|14:5\d)/);
  await page.clock.fastForward(5 * 60_000);
  await expect(countdown).toContainText(/9:[0-5]\d/);
  await expect(page.getByTestId("remove-agent-state")).toContainText("Requested");

  await page.getByTestId("remove-agent-cancel").click();
  await expect(page.getByTestId("remove-agent-state")).toContainText("Cancelled");
  expect(cp.calls).toContain("POST /cp/directives/d-new/cancel");
  await expect(page.getByTestId("remove-agent-countdown")).toHaveCount(0);
  await expect(page.getByTestId("remove-agent-cancel")).toHaveCount(0);
});

test("a typed alias also confirms; a 403 step_up_required from the server is shown as a request for the code", async ({ page }) => {
  const cp = await harness(page);
  cp.requestStatus = 403;
  cp.requestBody = { error: "a recent second-factor verification is required", code: "step_up_required" };
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-remove-agent-m-ret");
  await page.getByTestId("remove-agent-confirm-input").fill("Old reception");
  await page.getByTestId("remove-agent-code").fill("654321");
  await page.getByTestId("remove-agent-submit").click();
  await expect(page.getByTestId("remove-agent-error")).toContainText("authenticator code is needed");
  await expect(page.getByTestId("remove-agent-requested")).toHaveCount(0);
  expect(cp.calls).toContain("POST /cp/auth/step-up");
});

test("a wrong authenticator code stops before any request is made", async ({ page }) => {
  const cp = await harness(page);
  cp.stepUpOk = false;
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-remove-agent-m-ret");
  await page.getByTestId("remove-agent-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("remove-agent-code").fill("000000");
  await page.getByTestId("remove-agent-submit").click();
  await expect(page.getByTestId("remove-agent-error")).toContainText("That code was not accepted");
  expect(cp.calls.filter((c) => c.startsWith("POST") && c.includes("/directives"))).toHaveLength(0);
});

test("409 / 429 / 410 refusals are shown in friendly words", async ({ page }) => {
  const cp = await harness(page);
  cp.requestStatus = 409;
  cp.requestBody = { error: "machine already has an active directive" };
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-remove-agent-m-ret");
  await page.getByTestId("remove-agent-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("remove-agent-code").fill("123456");
  await page.getByTestId("remove-agent-submit").click();
  await expect(page.getByTestId("remove-agent-error")).toContainText("already has an agent action in progress");
  cp.requestStatus = 429;
  cp.requestBody = { error: "directive quota exceeded" };
  await page.getByTestId("remove-agent-submit").click();
  await expect(page.getByTestId("remove-agent-error")).toContainText("10 removals per hour");
});

test("Reinstall: one confirm, then the server's refusals show (retired race 409, tenant cap 429)", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  const confirms: string[] = [];
  page.on("dialog", (d) => { confirms.push(d.message()); void d.accept(); });

  await clickMachineAction(page, "m-act", "machine-reinstall-m-act");
  await expect(page.getByTestId("directive-note")).toContainText("Reinstall requested");
  expect(confirms).toHaveLength(1);
  expect(cp.calls).toContain("POST /cp/machines/m-act/directives reinstall");
  expect(cp.calls).not.toContain("POST /cp/auth/step-up"); // a repair needs no second factor

  // The machine was retired by someone else since this list loaded: the server refuses and the console says why.
  cp.reinstallStatus = 409;
  cp.reinstallBody = { error: "an agent on a retired machine can only be removed, not reinstalled" };
  await clickMachineAction(page, "m-act", "machine-reinstall-m-act");
  await expect(page.getByTestId("directive-note")).toContainText("can only be removed, not reinstalled");

  cp.reinstallStatus = 429;
  cp.reinstallBody = { error: "directive quota exceeded" };
  await clickMachineAction(page, "m-act", "machine-reinstall-m-act");
  await expect(page.getByTestId("directive-note")).toContainText("20 reinstalls per hour");
});

test("Pending removals: approve is hidden from the requester, offered to another person with its own step-up, and Cancel shows where allowed", async ({ page }) => {
  const cp = await harness(page);
  cp.policy = { require_second_approver: true, version: 2 };
  cp.directives["m-ret"] = [
    directive("mine", { requested_by: "u-me", require_approval: true }),
    directive("theirs", { requested_by: "u-other", require_approval: true }),
    directive("running", { requested_by: "u-other", state: "executing", issued_at: "2026-10-31T10:16:00Z" }),
  ];
  await openMachines(page);
  await expect(page.getByTestId("removal-state-mine")).toHaveText("Awaiting approval");
  await expect(page.getByTestId("removal-requester-mine")).toHaveText("you");
  await expect(page.getByTestId("removal-approve-mine")).toHaveCount(0);
  await expect(page.getByTestId("removal-cancel-mine")).toBeVisible();
  await expect(page.getByTestId("removal-approve-theirs")).toBeVisible();
  // A directive past the window can no longer be cancelled or approved.
  await expect(page.getByTestId("removal-state-running")).toHaveText("Executing");
  await expect(page.getByTestId("removal-approve-running")).toHaveCount(0);
  await expect(page.getByTestId("removal-cancel-running")).toHaveCount(0);

  await page.getByTestId("removal-approve-theirs").click();
  await expect(page.getByTestId("removal-approve-confirm-theirs")).toBeDisabled();
  await page.getByTestId("removal-approve-code-theirs").fill("112233");
  await page.getByTestId("removal-approve-confirm-theirs").click();
  await expect(page.getByTestId("removal-approver-theirs")).toContainText("you");
  const order = cp.calls.filter((c) => c === "POST /cp/auth/step-up" || c === "POST /cp/directives/theirs/approve");
  expect(order).toEqual(["POST /cp/auth/step-up", "POST /cp/directives/theirs/approve"]);
  expect(cp.bodies["POST /cp/auth/step-up"]).toEqual({ code: "112233" });
  await expect(page.getByTestId("removal-approve-theirs")).toHaveCount(0); // approved: nothing left to approve
});

test("the requester check is /me's user_id: a request made here is never approvable by its maker; an older server without user_id leaves it to the server's 403", async ({ page }) => {
  const cp = await harness(page);
  cp.policy = { require_second_approver: true, version: 2 };
  await page.route("**/cp/users", (route) => route.fulfill({ status: 403, json: { error: "forbidden" } })); // the user list plays no part
  await openMachines(page);
  await clickMachineAction(page, "m-ret", "machine-remove-agent-m-ret");
  await page.getByTestId("remove-agent-confirm-input").fill("RETIRED-PC");
  await page.getByTestId("remove-agent-code").fill("123456");
  await page.getByTestId("remove-agent-submit").click();
  await expect(page.getByTestId("remove-agent-needs-approval")).toBeVisible();
  await expect(page.getByTestId("remove-agent-countdown")).toHaveCount(0); // the window has not started
  await page.getByTestId("remove-agent-close").click();
  await expect(page.getByTestId("removal-state-d-new")).toHaveText("Awaiting approval");
  await expect(page.getByTestId("removal-requester-d-new")).toHaveText("you");
  await expect(page.getByTestId("removal-approve-d-new")).toHaveCount(0);

  // An older server sends no user_id: Approve is offered and the server (403 self-approval) is the backstop.
  cp.meUserId = undefined;
  cp.approveStatus = 403;
  cp.approveBody = { error: "the requester cannot approve their own directive" };
  await page.reload();
  await (await consoleTab(page, { name: "Machines", exact: true })).click();
  await expect(page.getByTestId("removal-approve-d-new")).toBeVisible();
  await page.getByTestId("removal-approve-d-new").click();
  await page.getByTestId("removal-approve-code-d-new").fill("778899");
  await page.getByTestId("removal-approve-confirm-d-new").click();
  await expect(page.getByTestId("removal-error-d-new")).toContainText("cannot approve your own request");
});

test("a 409/410 on approve is shown; removal_unconfirmed is explained", async ({ page }) => {
  const cp = await harness(page);
  cp.directives["m-ret"] = [
    directive("late", { requested_by: "u-other", require_approval: true }),
    directive("silent", { requested_by: "u-other", state: "removal_unconfirmed", issued_at: "2026-10-31T10:16:00Z", state_detail: "no report from the agent" }),
  ];
  cp.approveStatus = 410;
  cp.approveBody = { error: "directive expired" };
  await openMachines(page);
  await expect(page.getByTestId("removal-explain-silent")).toHaveText("The agent has not reported back; the machine stays retired and locked until it does, or until an owner forgets it.");
  await page.getByTestId("removal-approve-late").click();
  await page.getByTestId("removal-approve-code-late").fill("445566");
  await page.getByTestId("removal-approve-confirm-late").click();
  await expect(page.getByTestId("removal-error-late")).toContainText("expired (requests last 1 hour)");
});

test("policy toggle: recommended copy while off, saved with a step-up", async ({ page }) => {
  const cp = await harness(page);
  await openMachines(page);
  const toggle = page.getByTestId("directive-policy-toggle");
  await expect(page.getByTestId("directive-policy")).toContainText("Require a second approver for agent removal (recommended)");
  await expect(page.getByTestId("directive-policy-recommend")).toBeVisible();
  await expect(toggle).not.toBeChecked();
  await toggle.check();
  await page.getByTestId("directive-policy-code").fill("123123");
  await page.getByTestId("directive-policy-save").click();
  await expect(page.getByTestId("directive-policy-saved")).toBeVisible();
  expect(cp.calls.filter((c) => c === "POST /cp/auth/step-up" || c === "PUT /cp/tenant/directive-policy")).toEqual(["POST /cp/auth/step-up", "PUT /cp/tenant/directive-policy"]);
  expect(cp.bodies["PUT /cp/tenant/directive-policy"]).toEqual({ require_second_approver: true });
  await expect(page.getByTestId("directive-policy-recommend")).toHaveCount(0);
});
