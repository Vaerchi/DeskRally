/**
 * Machine groups editor — mocked-API browser regressions for the group session-policy row.
 *
 *   1. A max-sessions cap with a 0 max duration is refused IN THE CONSOLE, with the fix named, and no PUT
 *      is sent (it used to go out and come back as an opaque server 400). Fixing the duration sends the
 *      full policy body.
 *   2. While the policies read is outstanding, the row shows "loading…" with no inputs and no Set button,
 *      rather than unchecked boxes and 0s that look like a real, editable "nothing is set".
 *   3. An OLDER refresh that finishes after a newer one cannot put back its stale policies.
 *   4. A malformed policy row fails the read: the row shows "unknown" and cannot be submitted.
 *
 * Every /cp/ call is routed here (machine_end_session.spec.ts pattern). Named supervisor_* so the mocked
 * headless profile (playwright.support.config.ts) runs it.
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";
import { openGroupPolicy } from "./group_policy";

const G1 = "11111111-1111-4111-8111-111111111111";
const G2 = "22222222-2222-4222-8222-222222222222";
const group = (id: string, name: string) => ({ id, tenant_id: "t-1", name });
const policy = (group_id: string, over: Record<string, unknown> = {}) => ({
  group_id,
  max_concurrent_sessions: 0,
  enforce_view_only: false,
  allow_backstage_under_view_only: false,
  prohibit_recording: false,
  require_recording: false,
  max_session_duration_seconds: 0,
  max_idle_seconds: 0,
  ...over,
});

type Handler = (route: Route) => Promise<void>;

interface Mock {
  groups: unknown[];
  /** Answers GET /cp/machine-groups/session-policies; replaced per test to hold or vary responses. */
  policies: Handler;
  puts: { url: string; body: unknown }[];
  groupGets: number;
}

async function mount(page: Page, mock: Mock) {
  await page.route("**/cp/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") {
      await route.fulfill({ status: 204 });
    } else if (path === "/cp/machine-groups/session-policies" && method === "GET") {
      await mock.policies(route);
    } else if (path === "/cp/machine-groups" && method === "GET") {
      mock.groupGets++;
      await route.fulfill({ json: { machine_groups: mock.groups } });
    } else if (path.endsWith("/session-policy") && method === "PUT") {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      mock.puts.push({ url: path, body });
      await route.fulfill({ json: { group_id: path.split("/")[3], ...body } });
    } else {
      await route.fulfill({ json: {} });
    }
  });
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Machine groups", exact: true })).click();
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
}

/** A route handler that waits for `release()` before answering with `json`. */
function held(json: unknown) {
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  let arrived = false;
  let answered = false;
  const handler: Handler = async (route) => {
    arrived = true;
    await gate;
    await route.fulfill({ json });
    answered = true;
  };
  return { handler, release: () => release(), arrived: () => arrived, answered: () => answered };
}

test("a session cap without a max duration is refused in the console, then the corrected policy is sent whole", async ({ page }) => {
  const mock: Mock = {
    groups: [group(G1, "Front Office")],
    policies: async (route) => route.fulfill({ json: { policies: [policy(G1, { enforce_view_only: true, max_idle_seconds: 300 })] } }),
    puts: [],
    groupGets: 0,
  };
  await mount(page, mock);
  await openGroupPolicy(page, G1);
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toBeChecked();

  await page.getByTestId(`mgroup-cap-${G1}`).fill("2");
  await expect(page.getByTestId(`mgroup-maxduration-${G1}`)).toHaveValue("0");
  await page.getByTestId(`mgroup-cap-save-${G1}`).click();
  await expect(page.getByTestId("mgroup-error")).toContainText(
    "Front Office: a group with a max sessions limit also needs a max session duration",
  );
  // Refused locally: nothing reached the server.
  expect(mock.puts).toHaveLength(0);

  // An out-of-range duration is refused too, rather than coerced to 0 (= unlimited) and sent.
  await page.getByTestId(`mgroup-maxduration-${G1}`).fill("90000");
  await page.getByTestId(`mgroup-cap-save-${G1}`).click();
  await expect(page.getByTestId("mgroup-error")).toContainText("from 0 to 86400");
  expect(mock.puts).toHaveLength(0);

  await page.getByTestId(`mgroup-maxduration-${G1}`).fill("3600");
  await page.getByTestId(`mgroup-cap-save-${G1}`).click();
  await expect.poll(() => mock.puts.length).toBe(1);
  expect(mock.puts[0]).toEqual({
    url: `/cp/machine-groups/${G1}/session-policy`,
    body: {
      max_concurrent_sessions: 2,
      enforce_view_only: true,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 3600,
      max_idle_seconds: 300,
    },
  });
  await expect(page.getByTestId("mgroup-error")).toHaveCount(0);
});

test("while the policies read is outstanding the row is 'loading…', not editable defaults", async ({ page }) => {
  const read = held({ policies: [policy(G1, { enforce_view_only: true, max_concurrent_sessions: 4, max_session_duration_seconds: 600 })] });
  const mock: Mock = { groups: [group(G1, "Front Office")], policies: read.handler, puts: [], groupGets: 0 };
  await mount(page, mock);

  // The group is listed before its policy arrives…
  await expect(page.getByTestId(`mgroup-row-${G1}`)).toContainText("Front Office");
  await expect.poll(read.arrived).toBe(true);
  // …but no setting is drawn or editable yet.
  await expect(page.getByTestId(`mgroup-policy-unknown-${G1}`)).toHaveText("loading…");
  await expect(page.getByTestId(`mgroup-policy-edit-${G1}`)).toHaveCount(0);
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toHaveCount(0);
  await expect(page.getByTestId(`mgroup-cap-save-${G1}`)).toHaveCount(0);

  read.release();
  await openGroupPolicy(page, G1);
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toBeChecked();
  await expect(page.getByTestId(`mgroup-cap-${G1}`)).toHaveValue("4");
  await expect(page.getByTestId(`mgroup-maxduration-${G1}`)).toHaveValue("600");
  expect(mock.puts).toHaveLength(0);
});

test("an older refresh that finishes last cannot restore stale policies", async ({ page }) => {
  let policyGets = 0;
  const stale = held({ policies: [] });
  const mock: Mock = {
    groups: [group(G1, "Front Office")],
    policies: async (route) => {
      policyGets++;
      if (policyGets === 1) return route.fulfill({ json: { policies: [] } });
      if (policyGets === 2) return stale.handler(route);
      return route.fulfill({ json: { policies: [policy(G1, { enforce_view_only: true })] } });
    },
    puts: [],
    groupGets: 0,
  };
  await mount(page, mock);
  await openGroupPolicy(page, G1);
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).not.toBeChecked();

  // Refresh #2 reads the group list as it is NOW, then stalls on its policies read.
  await page.getByTestId("mgroup-refresh").click();
  await expect.poll(stale.arrived).toBe(true);

  // Meanwhile the data changes and a newer refresh (#3, after a create) reads it completely.
  mock.groups = [group(G1, "Front Office"), group(G2, "Warehouse")];
  await page.route("**/cp/machine-groups", async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    await route.fulfill({ json: { machine_group: group(G2, "Warehouse") } });
  });
  await page.getByTestId("mgroup-name").fill("Warehouse");
  await page.getByTestId("mgroup-create").click();
  await expect(page.getByTestId(`mgroup-row-${G2}`)).toContainText("Warehouse");
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toBeChecked();

  // The stale refresh now completes with policies read before the mandate was set, seeded for a group list
  // that did not yet include Warehouse. It must be ignored: the mandate stays ticked, and Warehouse keeps
  // its editable policy rather than dropping to "unknown".
  stale.release();
  await expect.poll(stale.answered).toBe(true);
  // Give the page time to apply that response if it were going to (it resolves on the page's own tick).
  await page.waitForTimeout(500);
  await expect(page.getByTestId(`mgroup-row-${G2}`)).toContainText("Warehouse");
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toBeChecked();
  await openGroupPolicy(page, G2);
  await expect(page.getByTestId(`mgroup-cap-${G2}`)).toHaveValue("0");
  await expect(page.getByTestId("mgroup-refresh")).toBeEnabled();
});

test("a malformed policy row fails the read: 'unknown', and no editor", async ({ page }) => {
  const mock: Mock = {
    groups: [group(G1, "Front Office")],
    policies: async (route) => route.fulfill({ json: { policies: [policy(G1, { enforce_view_only: "yes" })] } }),
    puts: [],
    groupGets: 0,
  };
  await mount(page, mock);
  await expect(page.getByTestId("mgroup-cap-error")).toContainText("bad policy row");
  await expect(page.getByTestId(`mgroup-policy-unknown-${G1}`)).toHaveText("unknown");
  await expect(page.getByTestId(`mgroup-policy-edit-${G1}`)).toHaveCount(0);
  await expect(page.getByTestId(`mgroup-cap-save-${G1}`)).toHaveCount(0);
  expect(mock.puts).toHaveLength(0);
});

test("the policy editor: one recording choice, Save only when changed, Cancel puts back, one open edit at a time", async ({ page }) => {
  const mock: Mock = {
    groups: [group(G1, "Front Office"), group(G2, "Warehouse")],
    policies: async (route) => route.fulfill({ json: { policies: [policy(G1, { prohibit_recording: true, max_idle_seconds: 300 })] } }),
    puts: [],
    groupGets: 0,
  };
  await mount(page, mock);
  // The table no longer carries the policy columns: the settings live behind Edit policy.
  await expect(page.getByTestId(`mgroup-viewonly-${G1}`)).toHaveCount(0);
  await openGroupPolicy(page, G1);
  const save = page.getByTestId(`mgroup-cap-save-${G1}`);
  const recording = page.getByTestId(`mgroup-recording-${G1}`);
  await expect(recording).toHaveValue("blocked");
  await expect(page.getByTestId(`mgroup-maxduration-words-${G1}`)).toHaveText("unlimited");
  await expect(save).toBeDisabled();

  // An edit enables Save, says so, and locks the other group's editor until it is saved or cancelled.
  await recording.selectOption("required");
  await expect(save).toBeEnabled();
  await expect(page.getByTestId(`mgroup-policy-status-${G1}`)).toHaveText("Unsaved changes");
  await expect(page.getByTestId(`mgroup-policy-edit-${G2}`)).toBeDisabled();
  await expect(page.getByTestId(`mgroup-policy-edit-${G1}`)).toBeDisabled();

  // Cancel puts back what is saved and closes; nothing was sent.
  await page.getByTestId(`mgroup-policy-cancel-${G1}`).click();
  await expect(page.getByTestId(`mgroup-policy-editor-${G1}`)).toHaveCount(0);
  await openGroupPolicy(page, G1);
  await expect(recording).toHaveValue("blocked");
  await expect(save).toBeDisabled();
  expect(mock.puts).toHaveLength(0);

  // Required is sent as require_recording alone, with every other setting carried through.
  await recording.selectOption("required");
  await page.getByTestId(`mgroup-maxduration-${G1}`).fill("5400");
  await expect(page.getByTestId(`mgroup-maxduration-words-${G1}`)).toHaveText("1 h 30 min");
  await save.click();
  await expect.poll(() => mock.puts.length).toBe(1);
  expect(mock.puts[0].body).toEqual({
    max_concurrent_sessions: 0,
    enforce_view_only: false,
    allow_backstage_under_view_only: false,
    prohibit_recording: false,
    require_recording: true,
    max_session_duration_seconds: 5400,
    max_idle_seconds: 300,
  });
});
