/**
 * Nested machine groups in the console (docs/62 stage C) — mocked-API browser tests. Every /cp/ call is
 * routed here (supervisor_machine_group_policy.spec.ts pattern); no control plane, agent or Postgres is
 * used, so it can run beside a spec that has them.
 *
 *   1. The Groups panel is an indented TREE (depth-first, paths shown); a group whose parent the caller
 *      cannot see renders at the top level; equal names under different parents stay distinct.
 *   2. "New subgroup" creates under that row (parent_id sent), a top-level create sends no parent_id.
 *   3. "Move…" offers "Top level" and EXCLUDES the group's own subtree; the server's 409 reason is shown
 *      verbatim and the picker stays open; a good move re-renders the tree.
 *   4. The text filter keeps the ancestors of a match.
 *   5. The session-policy row shows the inherited effective values, and an explicit conflict warning when
 *      require + block recording are both in force through inheritance.
 *   6. The Users scope label says "(and subgroups)" and uses the path; the scope picker, the machine move
 *      pickers, Deploy and Attended all list PATH labels, so the two "Lab" groups never merge.
 *
 * Asymmetric on purpose: P > C > GC, with S a sibling of C holding a second group ALSO named "Lab".
 */

import { test, expect, type Page, type Route } from "@playwright/test";
import { consoleTab } from "./nav";

const P = "00000000-0000-4000-8000-0000000000a1"; // Acme
const C = "00000000-0000-4000-8000-0000000000a2"; // Acme > Site A
const GC = "00000000-0000-4000-8000-0000000000a3"; // Acme > Site A > Lab
const S = "00000000-0000-4000-8000-0000000000a4"; // Acme > Site B (C's sibling)
const GC2 = "00000000-0000-4000-8000-0000000000a5"; // Acme > Site B > Lab  (same NAME as GC)
const H = "00000000-0000-4000-8000-0000000000a6"; // parent is not visible to this caller
const MISSING = "00000000-0000-4000-8000-0000000000ff";

interface G {
  id: string;
  tenant_id: string;
  name: string;
  parent_id: string | null;
}
const group = (id: string, name: string, parent_id: string | null): G => ({ id, tenant_id: "t-1", name, parent_id });
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

interface Mock {
  groups: G[];
  policies: unknown[];
  /** When set, the session-policies list also carries the server-computed effective map (a current server). */
  effective: Record<string, unknown> | null;
  posts: { path: string; body: Record<string, unknown> }[];
  /** When set, POST .../move answers 409 with this reason. */
  moveError: string | null;
  nextId: number;
}

const newMock = (): Mock => ({
  groups: [
    group(P, "Acme", null),
    group(C, "Site A", P),
    group(GC, "Lab", C),
    group(S, "Site B", P),
    group(GC2, "Lab", S),
    group(H, "Hidden Child", MISSING),
  ],
  policies: [],
  effective: null,
  posts: [],
  moveError: null,
  nextId: 1,
});

async function mount(page: Page, mock: Mock, tab: string) {
  await page.route("**/cp/**", async (route: Route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    const method = route.request().method();
    if (path === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (path === "/cp/machine-groups/session-policies" && method === "GET") {
      return route.fulfill({ json: mock.effective === null ? { policies: mock.policies } : { policies: mock.policies, effective: mock.effective } });
    }
    if (path === "/cp/machine-groups" && method === "GET") return route.fulfill({ json: { machine_groups: mock.groups } });
    if (path === "/cp/machine-groups" && method === "POST") {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      mock.posts.push({ path, body });
      const created = group(
        `10000000-0000-4000-8000-${String(mock.nextId++).padStart(12, "0")}`,
        String(body.name),
        typeof body.parent_id === "string" ? body.parent_id : null,
      );
      mock.groups.push(created);
      return route.fulfill({ status: 201, json: { machine_group: created } });
    }
    const move = /^\/cp\/machine-groups\/([^/]+)\/move$/.exec(path);
    if (move && method === "POST") {
      const body = route.request().postDataJSON() as Record<string, unknown>;
      mock.posts.push({ path, body });
      if (mock.moveError !== null) return route.fulfill({ status: 409, json: { error: mock.moveError } });
      const g = mock.groups.find((x) => x.id === move[1]);
      if (g) g.parent_id = (body.parent_id as string | null) ?? null;
      return route.fulfill({ json: { machine_group: g } });
    }
    if (path === "/cp/machines" && method === "GET") {
      return route.fulfill({
        json: {
          presence_known: true,
          machines: [
            { id: "m-1", tenant_id: "t-1", device_id: "d-1", group_id: GC, name: "BOX-1", os: "Windows", group_name: "Lab", online: true },
            { id: "m-2", tenant_id: "t-1", device_id: "d-2", group_id: GC2, name: "BOX-2", os: "Windows", group_name: "Lab", online: true },
          ],
        },
      });
    }
    if (path === "/cp/users" && method === "GET") {
      return route.fulfill({
        json: {
          users: [
            { id: "u-1", email: "tech@dev.local", display_name: "Tech", disabled: false, roles: ["technician"], scoped_group_ids: [C] },
            { id: "u-2", email: "ops@dev.local", display_name: "Ops", disabled: false, roles: ["technician"], scoped_group_ids: [] },
          ],
        },
      });
    }
    if (path === "/cp/roles") {
      return route.fulfill({ json: { roles: [{ role: "technician", capabilities: [] }] } });
    }
    if (path === "/cp/enrollment-tokens") return route.fulfill({ json: { enrollment_tokens: [] } });
    return route.fulfill({ json: {} });
  });
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  await page.goto(BASE);
  await (await consoleTab(page, { name: tab, exact: tab !== "Install DeskRally" })).click();
}

async function mountGroups(page: Page, mock: Mock) {
  await mount(page, mock, "Machine groups");
  await expect(page.getByTestId("machine-groups")).toBeVisible({ timeout: 15_000 });
  await expect(page.getByTestId(`mgroup-row-${P}`)).toBeVisible();
}

const rowIds = (page: Page) =>
  page
    .locator("tbody tr[data-testid^='mgroup-row-']")
    .evaluateAll((els) => els.map((e) => (e.getAttribute("data-testid") ?? "").replace("mgroup-row-", "")));
const depths = (page: Page) =>
  page.locator("tbody tr[data-testid^='mgroup-row-']").evaluateAll((els) => els.map((e) => e.getAttribute("data-depth")));
const optionTexts = (sel: ReturnType<Page["getByTestId"]>) => sel.locator("option").allTextContents();

test("the Groups panel is an indented tree; a hidden parent renders top-level; equal names stay distinct", async ({ page }) => {
  const mock = newMock();
  await mountGroups(page, mock);

  // Depth-first, siblings by name: Acme, Site A, Lab, Site B, Lab, then the other root (Hidden Child).
  expect(await rowIds(page)).toEqual([P, C, GC, S, GC2, H]);
  expect(await depths(page)).toEqual(["0", "1", "2", "1", "2", "0"]);
  // Paths come from the groups this caller can see: the two "Lab" rows are told apart by them.
  await expect(page.getByTestId(`mgroup-path-${GC}`)).toHaveText("Acme › Site A › Lab");
  await expect(page.getByTestId(`mgroup-path-${GC2}`)).toHaveText("Acme › Site B › Lab");
  // The group whose parent is not in the list is a ROOT with no invented ancestor.
  await expect(page.getByTestId(`mgroup-row-${H}`)).toHaveAttribute("data-depth", "0");
  await expect(page.getByTestId(`mgroup-path-${H}`)).toHaveCount(0);
});

test("New subgroup sends parent_id; a top-level create sends none", async ({ page }) => {
  const mock = newMock();
  await mountGroups(page, mock);

  await page.getByTestId(`mgroup-subgroup-${S}`).click();
  await expect(page.getByTestId("mgroup-parent")).toHaveValue(S);
  await page.getByTestId("mgroup-name").fill("Rack");
  await page.getByTestId("mgroup-create").click();
  await expect.poll(() => mock.posts.length).toBe(1);
  expect(mock.posts[0]).toEqual({ path: "/cp/machine-groups", body: { name: "Rack", parent_id: S } });
  // The new group appears one level under Site B (depth 2), with its path.
  const rack = mock.groups.find((x) => x.name === "Rack")!;
  await expect(page.getByTestId(`mgroup-row-${rack.id}`)).toHaveAttribute("data-depth", "2");
  await expect(page.getByTestId(`mgroup-path-${rack.id}`)).toHaveText("Acme › Site B › Rack");

  // Back to the top level: the body carries no parent_id at all.
  await page.getByTestId("mgroup-parent").selectOption("");
  await page.getByTestId("mgroup-name").fill("Solo");
  await page.getByTestId("mgroup-create").click();
  await expect.poll(() => mock.posts.length).toBe(2);
  expect(mock.posts[1]).toEqual({ path: "/cp/machine-groups", body: { name: "Solo" } });
});

test("Move… excludes the group's own subtree, shows a 409 reason verbatim, then moves to the top level", async ({ page }) => {
  const mock = newMock();
  await mountGroups(page, mock);

  await page.getByTestId(`mgroup-move-${C}`).click();
  const picker = page.getByTestId(`mgroup-move-parent-${C}`);
  // Site A's parent (Acme) is preselected. Site A and its child Lab are NOT offered; its sibling Site B, the
  // sibling's Lab, and unrelated groups are.
  await expect(picker).toHaveValue(P);
  // Untouched, "Move here" is disabled and no request goes out; it enables once another parent is chosen.
  const apply = page.getByTestId(`mgroup-move-apply-${C}`);
  await expect(apply).toBeDisabled();
  await apply.click({ force: true });
  expect(mock.posts.filter((p) => p.path.endsWith("/move"))).toEqual([]);
  await picker.selectOption(S);
  await expect(apply).toBeEnabled();
  await picker.selectOption(P);
  await expect(apply).toBeDisabled();
  expect(await optionTexts(picker)).toEqual(["Top level", "Acme", "Acme › Site B", "Acme › Site B › Lab", "Hidden Child"]);

  // The server refuses (409): its reason is shown VERBATIM and the picker stays open for another choice.
  mock.moveError = "subgroups nest at most 4 levels";
  await picker.selectOption(GC2);
  await page.getByTestId(`mgroup-move-apply-${C}`).click();
  await expect(page.getByTestId("mgroup-error")).toHaveText("could not move machine group: subgroups nest at most 4 levels");
  expect(mock.posts.at(-1)).toEqual({ path: `/cp/machine-groups/${C}/move`, body: { parent_id: GC2 } });
  await expect(picker).toBeVisible();
  // Nothing moved.
  expect(await depths(page)).toEqual(["0", "1", "2", "1", "2", "0"]);

  // The same picker, retried after the server stops refusing: "Top level" sends parent_id null.
  mock.moveError = null;
  await picker.selectOption("");
  await page.getByTestId(`mgroup-move-apply-${C}`).click();
  expect(mock.posts.at(-1)).toEqual({ path: `/cp/machine-groups/${C}/move`, body: { parent_id: null } });
  await expect(page.getByTestId("mgroup-error")).toHaveCount(0);
  await expect(picker).toHaveCount(0);
  // Site A is now a root with Lab beneath it; Acme keeps only Site B.
  await expect(page.getByTestId(`mgroup-row-${C}`)).toHaveAttribute("data-depth", "0");
  await expect(page.getByTestId(`mgroup-path-${GC}`)).toHaveText("Site A › Lab");
  expect(await rowIds(page)).toEqual([P, S, GC2, H, C, GC]);
});

test("the text filter keeps the ancestors of a match", async ({ page }) => {
  const mock = newMock();
  await mountGroups(page, mock);

  await page.getByTestId("mgroup-search").fill("lab");
  // Both Labs match; Acme, Site A and Site B stay as their ancestors; the unrelated root is gone.
  expect(await rowIds(page)).toEqual([P, C, GC, S, GC2]);
  await expect(page.getByTestId(`mgroup-row-${GC}`)).toHaveAttribute("data-matched", "true");
  await expect(page.getByTestId(`mgroup-row-${C}`)).toHaveAttribute("data-matched", "false");
  await expect(page.getByTestId(`mgroup-row-${H}`)).toHaveCount(0);

  // A match on a mid-level group keeps its parent but not its (non-matching) child or its sibling.
  await page.getByTestId("mgroup-search").fill("site a");
  expect(await rowIds(page)).toEqual([P, C]);
});

test("the policy row shows inherited effective values and an explicit require/block conflict", async ({ page }) => {
  const mock = newMock();
  // Acme requires recording and a 1h cap; Site A BLOCKS recording; Site B only has its own idle limit.
  mock.policies = [
    policy(P, { require_recording: true, max_session_duration_seconds: 3600 }),
    policy(C, { prohibit_recording: true }),
    policy(S, { max_idle_seconds: 300 }),
  ];
  await mountGroups(page, mock);

  // Acme itself: its own settings, none inherited, no conflict.
  await expect(page.getByTestId(`mgroup-effective-chips-${P}`)).toHaveText("Recording required · Max 1 h");
  await expect(page.getByTestId(`mgroup-conflict-${P}`)).toHaveCount(0);
  // Site B (the sibling branch) inherits Acme's requirement and limit and adds its own idle limit.
  await expect(page.getByTestId(`mgroup-effective-chips-${S}`)).toHaveText(
    "Recording required (inherited) · Max 1 h (inherited) · Idle 5 min",
  );
  await expect(page.getByTestId(`mgroup-conflict-${S}`)).toHaveCount(0);
  // Site A: require (from Acme) + block (its own) = unsatisfiable, with an explicit warning on it AND its child.
  for (const id of [C, GC]) {
    const warn = page.getByTestId(`mgroup-conflict-${id}`);
    await expect(warn).toContainText("required (Acme)");
    await expect(warn).toContainText("blocked (Acme › Site A)");
    await expect(warn).toContainText("refused");
  }
  // The unrelated root has no policy at all.
  await expect(page.getByTestId(`mgroup-effective-none-${H}`)).toHaveText("No restrictions");
});

test("a group whose parent is hidden preselects Top level but cannot be moved until another parent is chosen", async ({ page }) => {
  const mock = newMock();
  await mountGroups(page, mock);
  await page.getByTestId(`mgroup-move-${H}`).click();
  const picker = page.getByTestId(`mgroup-move-parent-${H}`);
  const apply = page.getByTestId(`mgroup-move-apply-${H}`);
  await expect(picker).toHaveValue("");
  await expect(apply).toBeDisabled();
  await apply.click({ force: true });
  expect(mock.posts.filter((p) => p.path.endsWith("/move"))).toEqual([]);
  await picker.selectOption(P);
  await expect(apply).toBeEnabled();
  await apply.click();
  expect(mock.posts.at(-1)).toEqual({ path: `/cp/machine-groups/${H}/move`, body: { parent_id: P } });
});

test("the effective cell shows an inherited restriction only the server knew about", async ({ page }) => {
  const mock = newMock();
  // A scoped admin: the hidden parent's policy row is absent from "policies", but the server's effective
  // map says the group inherits view-only and a seat cap. (H stands in for the scoped admin's subtree root.)
  mock.policies = [];
  mock.effective = {
    [H]: { group_id: "", max_concurrent_sessions: 5, enforce_view_only: true, seat_caps: [{ group_id: "", cap: 5 }] },
    [P]: { group_id: "", require_recording: true, prohibit_recording: true, conflict: "recording is required and blocked" },
  };
  await mountGroups(page, mock);
  await expect(page.getByTestId(`mgroup-effective-chips-${H}`)).toHaveText(
    "View only (inherited) · Under the Hood refused · 5 sessions (inherited)",
  );
  await expect(page.getByTestId(`mgroup-conflict-${P}`)).toContainText("recording is required and blocked");
  // A group the server sent no entry for is not drawn as "No restrictions".
  await expect(page.getByTestId(`mgroup-effective-none-${C}`)).toHaveCount(0);
});

test("Users: the scope label uses the path and says '(and subgroups)'; the scope picker lists paths", async ({ page }) => {
  const mock = newMock();
  await mount(page, mock, "Users");
  await expect(page.getByTestId("user-scope-tech@dev.local")).toHaveText("Acme › Site A (and subgroups)");
  await expect(page.getByTestId("user-scope-ops@dev.local")).toHaveText("All groups");

  // The invite scope picker is a tree of path labels: the two Labs are different checkboxes.
  await page.getByTestId("user-create-scope").locator("summary").click();
  const labels = page.getByTestId("user-create-scope").locator("label.panel__scope-group");
  expect((await labels.allTextContents()).map((t) => t.trim())).toEqual([
    "Acme",
    "Acme › Site A",
    "Acme › Site A › Lab",
    "Acme › Site B",
    "Acme › Site B › Lab",
    "Hidden Child",
  ]);
  await page.getByTestId(`user-create-scope-${GC2}`).check();
  await expect(page.getByTestId("user-create-scope").locator("summary")).toHaveText(
    "Scope: Acme › Site B › Lab (and subgroups)",
  );
});

test("machine move, Deploy and Attended pickers all list path labels", async ({ page }) => {
  const mock = newMock();
  const expected = ["Acme", "Acme › Site A", "Acme › Site A › Lab", "Acme › Site B", "Acme › Site B › Lab", "Hidden Child"];

  await mount(page, mock, "Machines");
  // The Live machine list buckets by group ID and titles each section with the PATH, so the two "Lab" groups
  // are two sections (merging them by name was the defect this guards).
  await expect.poll(() => page.locator("section.access__group > .access__group-title").allTextContents()).toEqual([
    "Acme › Site A › Lab",
    "Acme › Site B › Lab",
  ]);
  // Each machine shows its own group's PATH, so BOX-1 and BOX-2 (both "Lab") are told apart.
  await expect(page.getByTestId("machine-group-m-1")).toHaveText("Acme › Site A › Lab");
  await expect(page.getByTestId("machine-group-m-2")).toHaveText("Acme › Site B › Lab");
  expect(await optionTexts(page.getByTestId("machine-group-select-m-1"))).toEqual(expected);
  expect(await optionTexts(page.getByTestId("bulk-group-select"))).toEqual(["(choose a group)", ...expected]);

  await (await consoleTab(page, { name: "Install DeskRally" })).click();
  await expect(page.getByTestId("enroll-group")).toBeVisible();
  // Polled, like the Support picker below: the select is drawn before its groups load ("No machine groups —
  // create one first"), and a one-shot read raced that (flaky on 11-08).
  await expect.poll(() => optionTexts(page.getByTestId("enroll-group"))).toEqual(["Select a group…", ...expected]);

  await (await consoleTab(page, { name: "Support", exact: true })).click();
  await expect(page.getByTestId("attended-group")).toBeVisible();
  await expect.poll(() => optionTexts(page.getByTestId("attended-group"))).toEqual(["Select a group…", ...expected]);
});
