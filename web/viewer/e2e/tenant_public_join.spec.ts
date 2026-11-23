/**
 * "Public join page" section of the Appearance panel (docs/66 2j), mocked-API browser tests.
 *
 *   1. Owner: prefill (copied from the console appearance, labelled), edit, live preview with the REAL JoinBrand at phone and
 *      desktop widths and as the neutral default, submit -> status row; "no change" (200 created:false); the server's refusal
 *      text; the 20/hour budget (429) in plain words; the accent contrast readout.
 *   2. A draft is the starting point before the published revision; a kept logo is sent as keep_logo.
 *   3. A member sees it read-only (no submit, disabled inputs) with the status and the preview.
 *   4. The logo field is hidden when the server cannot convert logos; a picked image is downscaled to at most 512x256 PNG
 *      BEFORE it is uploaded.
 *
 * The API is mocked (every /cp/ call is routed, only the loopback origin is reachable); no control plane is started.
 * playwright.config.ts builds the viewer with VITE_DEFAULT_ORIGIN, which a tenant-branded preview needs (docs/66 2i).
 */

import { test, expect, type Page } from "@playwright/test";
import { consoleTab } from "./nav";
import { expectInertLink } from "./preview_inert";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

/** The join page the preview frame holds (an iframe; see JoinBrandFrame). */
const previewPage = (page: Page) => page.frameLocator('[data-testid="pub-preview"] iframe');

interface Rev {
  id: string;
  seq: number;
  product_name: string;
  accent_color: string;
  support_text: string;
  support_contact: { kind: string; value: string };
  logo_sha256: string;
  has_logo: boolean;
  normalized_hash: string;
  created_by: string;
  created_at: string;
}

const rev = (over: Partial<Rev> = {}): Rev => ({
  id: "rev-1",
  seq: 1,
  product_name: "Draft Co",
  accent_color: "#35654a",
  support_text: "Call us",
  support_contact: { kind: "phone", value: "15550100199" },
  logo_sha256: "",
  has_logo: false,
  normalized_hash: "h1",
  created_by: "u1",
  created_at: "2026-11-05T14:03:09Z",
  ...over,
});

interface Mock {
  owner: boolean;
  logoSupported: boolean;
  draft: Rev | null;
  published: Rev | null;
  assignment: { id: string; host: string; state: string } | null;
  live: boolean;
  draftIsPublished: boolean;
  /** Optional on the wire: when an operator approved the published revision. */
  publishedAt?: string;
  /** Optional on the wire: the last publication was withdrawn. */
  withdrawn?: { at: string; revision_id?: string };
  /** What the next POST answers. */
  post: { status: number; json: unknown } | null;
  posts: Record<string, unknown>[];
  /** GET .../revisions answers 500 from this point (set after the page has loaded). */
  refreshFails?: boolean;
}

const base = (over: Partial<Mock> = {}): Mock => ({
  owner: true,
  logoSupported: true,
  draft: null,
  published: null,
  assignment: { id: "a1", host: "acme.example.com", state: "pending" },
  live: false,
  draftIsPublished: false,
  post: null,
  posts: [],
  ...over,
});

async function mount(page: Page, m: Mock) {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  expect(LOOPBACK_HOSTS.has(baseUrl.hostname)).toBe(true);
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const p = url.pathname;
    if (url.origin !== baseUrl.origin) return route.abort();
    if (p === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (p === "/cp/me") {
      return route.fulfill({
        json: { email: "owner@example.com", user_id: "u1", capabilities: m.owner ? [{ capability: "manage_tenant", all_groups: true, group_ids: [] }] : [{ capability: "view_audit", all_groups: true, group_ids: [] }] },
      });
    }
    if (p === "/cp/tenant/branding" && method === "GET") {
      return route.fulfill({ json: { product_name: "Console Name", accent_color: "#1d4ed8", logo_data_uri: "" } });
    }
    if (p === "/cp/tenant/branding/revisions" && method === "GET") {
      if (m.refreshFails) return route.fulfill({ status: 500, json: { error: "boom" } });
      return route.fulfill({
        json: {
          state: { draft: m.draft, published: m.published, assignment: m.assignment, live: m.live, draft_is_published: m.draftIsPublished,
            ...(m.publishedAt ? { published_at: m.publishedAt } : {}), ...(m.withdrawn ? { withdrawn: m.withdrawn } : {}) },
          logo_upload_supported: m.logoSupported,
        },
      });
    }
    if (p === "/cp/tenant/branding/revisions" && method === "POST") {
      m.posts.push(route.request().postDataJSON() as Record<string, unknown>);
      const answer = m.post ?? { status: 201, json: { revision: rev(), created: true } };
      return route.fulfill({ status: answer.status, json: answer.json });
    }
    if (p.startsWith("/cp/")) return route.fulfill({ json: {} });
    return route.continue();
  });
  await page.goto(BASE);
  await (await consoleTab(page, { name: "Appearance" })).click();
  await expect(page.getByTestId("appearance")).toBeVisible({ timeout: 15_000 });
}

test("an Owner edits, previews with the real join page, submits, and sees the approval status", async ({ page }) => {
  const m = base();
  await mount(page, m);

  // Two separate things, visibly separate.
  await expect(page.getByTestId("appearance-console-note")).toContainText("console");
  await expect(page.getByTestId("public-join")).toContainText("only after your platform operator approves it");

  // Prefill: nothing drafted or published, so it is copied from the console appearance and says so.
  await expect(page.getByTestId("pub-prefill-note")).toHaveText("Copied from your console appearance; not submitted yet.");
  await expect(page.getByTestId("pub-name")).toHaveValue("Console Name");

  // The status row: the assigned hostname and its state, nothing submitted.
  await expect(page.getByTestId("pub-status-hostname")).toContainText("acme.example.com");
  await expect(page.getByTestId("pub-status-host-state")).toContainText("pending");
  await expect(page.getByTestId("pub-status-approval")).toHaveText("Nothing submitted yet");

  await page.getByTestId("pub-name").fill("Acme Remote IT");
  await page.getByTestId("pub-accent-text").fill("#1d4ed8");
  await page.getByTestId("pub-text").fill("Call us first.\nWe are open 9 to 5.");
  await expect(page.getByTestId("pub-text-counter")).toHaveText("34/280 characters · 2/4 lines");
  await page.getByTestId("pub-contact-kind").selectOption("url");
  await page.getByTestId("pub-contact-value").fill("https://Support.Example.com/help");
  await expect(page.getByTestId("pub-contrast")).toHaveAttribute("data-state", "ok");

  // The preview is the real JoinBrand with the DRAFT values, before anything is submitted.
  // The preview is the join page inside the shared iframe (the page's viewport media queries apply at the stated width).
  const preview = previewPage(page);
  const previewBox = page.getByTestId("pub-preview");
  await expect(preview.getByTestId("join-root")).toHaveAttribute("data-brand-state", "branded");
  await expect(preview.getByTestId("join-brand-name")).toHaveText("Acme Remote IT");
  await expect(preview.getByTestId("join-brand-text")).toContainText("We are open 9 to 5.");
  await expect(preview.getByTestId("join-brand-contact")).toContainText("https://support.example.com/help");
  await expect(preview.getByTestId("join-attribution")).toBeVisible();
  const sample = preview.getByTestId("pub-preview-sample-button");
  await expect(sample).toHaveCSS("background-color", "rgb(29, 78, 216)");

  // Phone and desktop widths.
  await page.getByTestId("pub-width-phone").check();
  await expect(previewBox).toHaveAttribute("data-width", "phone");
  expect((await page.locator('iframe[title="Join page as a guest sees it, phone width"]').boundingBox())!.width).toBe(390);
  await expect(preview.locator(".join__welcome")).toHaveCount(0);
  await page.getByTestId("pub-width-desktop").check();
  await expect(previewBox).toHaveAttribute("data-width", "desktop");
  expect((await page.locator('iframe[title="Join page as a guest sees it, desktop width"]').boundingBox())!.width).toBe(1100);
  // The guest page's top bar and welcome panel are there, and the links are inert text.
  await expect(preview.getByText("Technician sign in")).toBeVisible();
  await expect(preview.locator(".join__welcome")).toHaveCount(1);
  await expect(preview.locator("a[href='/console'], a[href='/downloads']")).toHaveCount(0);

  // Show as neutral default.
  await page.getByTestId("pub-neutral").check();
  await expect(preview.getByTestId("join-root")).toHaveAttribute("data-brand-state", "neutral");
  await expect(preview.getByTestId("join-brand-name")).not.toHaveText("Acme Remote IT");
  await expect(preview.getByTestId("join-attribution")).toHaveCount(0);
  await page.getByTestId("pub-neutral").uncheck();
  await expect(preview.getByTestId("join-root")).toHaveAttribute("data-brand-state", "branded");

  // The deployment's origin is set in this build, so the "neutral until" notice is absent.
  await expect(page.getByTestId("pub-origin-notice")).toHaveCount(0);

  // Submit: a 201 creates a revision; the status row then follows the server.
  m.post = { status: 201, json: { revision: rev({ product_name: "Acme Remote IT" }), created: true } };
  m.draft = rev({ product_name: "Acme Remote IT" });
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toContainText("Submitted");
  await expect(page.getByTestId("pub-status-approval")).toContainText("Nothing published");
  await expect(page.getByTestId("pub-status-approval")).toContainText("Draft waiting for approval");
  await expect(page.getByTestId("pub-status-approval")).toContainText("2026-11-05 14:03 UTC");
  await expect(page.getByTestId("pub-status-live")).toContainText("neutral");
  expect(m.posts).toHaveLength(1);
  expect(m.posts[0]).toMatchObject({
    product_name: "Acme Remote IT",
    accent_color: "#1d4ed8",
    support_text: "Call us first.\nWe are open 9 to 5.",
    support_contact: { kind: "url", value: "https://support.example.com/help" },
  });
  expect(m.posts[0]).not.toHaveProperty("logo_data_uri");

  // The same again: 200 created:false is reported as "no change".
  m.post = { status: 200, json: { revision: rev({ product_name: "Acme Remote IT" }), created: false } };
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toContainText("No change");
  expect(m.posts).toHaveLength(2);
});

test("the accent readout and the server's own refusal text", async ({ page }) => {
  const m = base({ draft: rev() });
  await mount(page, m);
  await expect(page.getByTestId("pub-prefill-note")).toHaveText("Showing your current draft.");

  // A colour too light for the white button label: the same sentence the server would answer with.
  await page.getByTestId("pub-accent-text").fill("#ffeecc");
  await expect(page.getByTestId("pub-contrast")).toHaveAttribute("data-state", "fail");
  await expect(page.getByTestId("pub-error-accent")).toHaveText("contrast 1.14:1 against the white button label, needs 4.5:1");
  await expect(page.getByTestId("pub-error-accent")).toHaveAttribute("data-from", "local");
  await page.getByTestId("pub-accent-clear").click();
  await expect(page.getByTestId("pub-error-accent")).toHaveCount(0);

  // The inline rules agree, but the server is the authority: its refusal is shown, labelled as the server's.
  m.post = { status: 400, json: { field: "product_name", error: "must be 3 to 100 characters (server wording)" } };
  await page.getByTestId("pub-submit").click();
  const serverErr = page.getByTestId("pub-error-productName");
  await expect(serverErr).toContainText("The server says: must be 3 to 100 characters (server wording)");
  await expect(serverErr).toHaveAttribute("data-from", "server");
  await page.getByTestId("pub-name").fill("Draft Co 2");
  await expect(page.getByTestId("pub-error-productName")).toHaveCount(0);

  // The 20/hour budget, in plain words.
  m.post = { status: 429, json: { error: "too many branding revisions; retry later" } };
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-error")).toContainText("20 per hour");
});

test("a published revision with a kept logo is the starting point and is sent as keep_logo", async ({ page }) => {
  const published = rev({ id: "rev-9", product_name: "Pub Co", has_logo: true, logo_sha256: "a".repeat(64) });
  const m = base({
    published,
    draft: published,
    draftIsPublished: true,
    live: true,
    assignment: { id: "a1", host: "acme.example.com", state: "active" },
  });
  await mount(page, m);
  await expect(page.getByTestId("pub-name")).toHaveValue("Pub Co");
  await expect(page.getByTestId("pub-status-approval")).toContainText("Published");
  await expect(page.getByTestId("pub-status-live")).toContainText("Yes");
  await expect(page.getByTestId("pub-status-live")).toHaveAttribute("data-live", "true");
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "kept");
  await expect(page.getByTestId("pub-preview-logo-note")).toBeVisible();

  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  expect(m.posts[0]).toMatchObject({ product_name: "Pub Co", keep_logo: true });
  expect(m.posts[0]).not.toHaveProperty("logo_data_uri");
});

test("a link in the Owner's preview goes nowhere", async ({ page }) => {
  await mount(page, base());
  await page.getByTestId("pub-contact-kind").selectOption("url");
  await page.getByTestId("pub-contact-value").fill("https://support.example.com/help");
  await expectInertLink(page, previewPage(page), '[data-testid="pub-preview"] iframe', "https://support.example.com/help");
  await expect(page.getByTestId("public-join")).toBeVisible();
});

test("a member sees the section read-only", async ({ page }) => {
  const m = base({ owner: false, draft: rev() });
  await mount(page, m);

  await expect(page.getByTestId("pub-readonly")).toBeVisible();
  await expect(page.getByTestId("pub-status")).toBeVisible();
  await expect(page.getByTestId("pub-name")).toHaveValue("Draft Co");
  for (const id of ["pub-name", "pub-accent", "pub-accent-text", "pub-text", "pub-contact-kind", "pub-contact-value", "pub-logo", "pub-accent-clear"]) {
    await expect(page.getByTestId(id)).toBeDisabled();
  }
  await expect(page.getByTestId("pub-submit")).toHaveCount(0);
  // The preview still works for them.
  await expect(previewPage(page).getByTestId("join-brand-name")).toHaveText("Draft Co");
  expect(m.posts).toHaveLength(0);
});

test("the logo field is hidden when the server cannot convert logos, yet the draft's logo is kept on submit", async ({ page }) => {
  const m = base({ logoSupported: false, draft: rev({ has_logo: true, logo_sha256: "b".repeat(64) }) });
  await mount(page, m);
  await expect(page.getByTestId("pub-name")).toBeVisible();
  await expect(page.getByTestId("pub-logo-field")).toHaveCount(0);
  await expect(page.getByTestId("pub-logo")).toHaveCount(0);
  await page.getByTestId("pub-name").fill("Draft Co 2");
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  expect(m.posts[0]).toMatchObject({ product_name: "Draft Co 2", keep_logo: true });
  expect(m.posts[0]).not.toHaveProperty("logo_data_uri");
});

test("a created revision is reported as submitted even when the status refresh fails", async ({ page }) => {
  const m = base({ draft: rev() });
  await mount(page, m);
  await page.getByTestId("pub-name").fill("Draft Co 2");
  m.refreshFails = true;
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toContainText("Submitted");
  await expect(page.getByTestId("pub-refresh-note")).toBeVisible();
  await expect(page.getByTestId("pub-error")).toHaveCount(0);
});

test("field errors are described by id, not folded into the control's label", async ({ page }) => {
  await mount(page, base({ draft: rev() }));
  await page.getByTestId("pub-name").fill("ab");
  const err = page.getByTestId("pub-error-productName");
  await expect(err).toBeVisible();
  await expect(page.getByTestId("pub-name")).toHaveAttribute("aria-describedby", /pub-err-productName/);
  expect(await err.evaluate((el) => el.closest("label") === null)).toBe(true);
  await page.getByTestId("pub-accent-text").fill("#ffeecc");
  expect(await page.getByTestId("pub-error-accent").evaluate((el) => el.closest("label") === null)).toBe(true);
});

test("a picked logo is downscaled to at most 512x256 PNG before it is uploaded", async ({ page }) => {
  const m = base({ draft: rev() });
  await mount(page, m);
  await expect(page.getByTestId("pub-logo-field")).toBeVisible();

  // A 1600x400 JPEG made in the page, so it is a real image far over the limit.
  const jpegB64 = await page.evaluate(() => {
    const c = document.createElement("canvas");
    c.width = 1600;
    c.height = 400;
    const g = c.getContext("2d")!;
    g.fillStyle = "#336699";
    g.fillRect(0, 0, 1600, 400);
    g.fillStyle = "#ffffff";
    g.fillRect(100, 100, 600, 200);
    return c.toDataURL("image/jpeg", 0.9).split(",")[1]!;
  });
  await page.getByTestId("pub-logo").setInputFiles({ name: "wide.jpg", mimeType: "image/jpeg", buffer: Buffer.from(jpegB64, "base64") });
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "new");
  await expect(previewPage(page).getByTestId("join-brand-logo")).toHaveAttribute("src", /^data:image\/png;base64,/);

  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  const uri = m.posts[0]!.logo_data_uri as string;
  expect(uri.startsWith("data:image/png;base64,")).toBe(true);
  expect(m.posts[0]).not.toHaveProperty("keep_logo");
  // 1600x400 fits 512 wide: 512x128.
  const size = await page.evaluate(
    (u) =>
      new Promise<{ w: number; h: number }>((resolve, reject) => {
        const i = new Image();
        i.onload = () => resolve({ w: i.naturalWidth, h: i.naturalHeight });
        i.onerror = () => reject(new Error("not an image"));
        i.src = u;
      }),
    uri,
  );
  expect(size).toEqual({ w: 512, h: 128 });
});

// ---- a logo still being prepared (docs/66 2j, review repair) ------------------------------------------------------
// Downscaling is asynchronous. These tests HOLD the image decode (the page's `onload` is parked until the test releases it)
// so the window between "picked" and "ready" is observable and the order of completion is chosen by the test.

async function holdLogoDecodes(page: Page) {
  await page.addInitScript(() => {
    const w = window as unknown as { __held: Array<() => void>; __holdLogo: boolean };
    w.__held = [];
    w.__holdLogo = true;
    const d = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "onload")!;
    Object.defineProperty(HTMLImageElement.prototype, "onload", {
      configurable: true,
      get() {
        return d.get!.call(this);
      },
      set(fn) {
        if (!w.__holdLogo || !fn) {
          d.set!.call(this, fn);
          return;
        }
        d.set!.call(this, function (this: unknown, ev: Event) {
          w.__held.push(() => fn.call(this, ev));
        });
      },
    });
  });
}

const heldCount = (page: Page) => page.evaluate(() => (window as unknown as { __held: unknown[] }).__held.length);
const release = (page: Page, i: number) => page.evaluate((n) => (window as unknown as { __held: Array<() => void> }).__held[n]!(), i);

/** A PNG of the given size made in the page (so it is a real image). */
async function pngOfSize(page: Page, w: number, h: number): Promise<Buffer> {
  const b64 = await page.evaluate(
    ([ww, hh]) => {
      const c = document.createElement("canvas");
      c.width = ww!;
      c.height = hh!;
      const g = c.getContext("2d")!;
      g.fillStyle = "#336699";
      g.fillRect(0, 0, ww!, hh!);
      return c.toDataURL("image/png").split(",")[1]!;
    },
    [w, h],
  );
  return Buffer.from(b64, "base64");
}

/** The pixel size of a PNG data URI, read from its IHDR (the page's own image decoding is parked in these tests). */
function pngSize(uri: string): { w: number; h: number } {
  const bytes = Buffer.from(uri.slice(uri.indexOf(",") + 1), "base64");
  return { w: bytes.readUInt32BE(16), h: bytes.readUInt32BE(20) };
}

test("Submit cannot send the previous logo while a picked one is still being prepared", async ({ page }) => {
  await holdLogoDecodes(page);
  const published = rev({ id: "rev-9", product_name: "Pub Co", has_logo: true, logo_sha256: "a".repeat(64) });
  const m = base({ published, draft: published, draftIsPublished: true, live: true, assignment: { id: "a1", host: "acme.example.com", state: "active" } });
  await mount(page, m);
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "kept");
  await expect(page.getByTestId("pub-submit")).toBeEnabled();

  const png = await pngOfSize(page, 300, 100);
  await page.getByTestId("pub-logo").setInputFiles({ name: "new.png", mimeType: "image/png", buffer: png });
  await expect.poll(() => heldCount(page)).toBe(1);
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-preparing", "true");
  await expect(page.getByTestId("pub-submit")).toBeDisabled();

  // Even a submit that bypasses the disabled button (Enter in a field) sends nothing: the stale keep_logo must not go out.
  await page.getByTestId("pub-form").evaluate((f) => (f as HTMLFormElement).requestSubmit());
  await expect(page.getByTestId("pub-error-logo")).toContainText("still being prepared");
  expect(m.posts).toHaveLength(0);

  await release(page, 0);
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "new");
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-preparing", "false");
  await expect(page.getByTestId("pub-submit")).toBeEnabled();
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  expect(m.posts).toHaveLength(1);
  expect(m.posts[0]).toHaveProperty("logo_data_uri");
  expect(m.posts[0]).not.toHaveProperty("keep_logo");
});

test("two rapid logo selections end with the second, even when the first finishes last", async ({ page }) => {
  await holdLogoDecodes(page);
  const m = base({ draft: rev() });
  await mount(page, m);
  const first = await pngOfSize(page, 200, 50);
  const second = await pngOfSize(page, 100, 100);
  await page.getByTestId("pub-logo").setInputFiles({ name: "first.png", mimeType: "image/png", buffer: first });
  await expect.poll(() => heldCount(page)).toBe(1);
  await page.getByTestId("pub-logo").setInputFiles({ name: "second.png", mimeType: "image/png", buffer: second });
  await expect.poll(() => heldCount(page)).toBe(2);

  await release(page, 1); // the second finishes first ...
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "new");
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-preparing", "false");
  await release(page, 0); // ... and the superseded first finishes last: it must be discarded
  await page.waitForTimeout(300);
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  expect(pngSize(m.posts[0]!.logo_data_uri as string)).toEqual({ w: 100, h: 100 });
});

test("removing the logo while a pick is being prepared drops the pick", async ({ page }) => {
  await holdLogoDecodes(page);
  const m = base({ draft: rev() });
  await mount(page, m);
  await page.getByTestId("pub-logo").setInputFiles({ name: "a.png", mimeType: "image/png", buffer: await pngOfSize(page, 64, 64) });
  await expect.poll(() => heldCount(page)).toBe(1);
  await page.getByTestId("pub-logo-clear").click();
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-preparing", "false");
  await release(page, 0);
  await page.waitForTimeout(300);
  await expect(page.getByTestId("pub-logo-state")).toHaveAttribute("data-state", "none");
  await page.getByTestId("pub-submit").click();
  await expect(page.getByTestId("pub-outcome")).toBeVisible();
  expect(m.posts[0]).not.toHaveProperty("logo_data_uri");
  expect(m.posts[0]).not.toHaveProperty("keep_logo");
});

test("the status row says when it was approved, and never claims never approved without proof", async ({ page }) => {
  const approved = "2026-11-07T08:30:00Z";
  const draft = rev({ id: "rev-2", created_at: "2026-11-06T09:00:00Z" });
  const assignment = { id: "a1", host: "acme.example.com", state: "active" };
  const row = page.getByTestId("pub-status-approval");

  // Published: the approval time, and a newer draft still waiting.
  const published = rev({ id: "rev-1", created_at: "2026-11-05T14:03:09Z" });
  await mount(page, base({ assignment, live: true, published, draft, publishedAt: approved }));
  await expect(row).toContainText("Published 2026-11-07 08:30 UTC");
  await expect(row).toContainText("newer draft (submitted 2026-11-06 09:00 UTC) is waiting for approval");
  await expect(row).not.toContainText("Withdrawn");
  await expect(row).not.toContainText("Nothing published");

  // Withdrawn: the withdrawal time and the neutral page.
  await page.unrouteAll({ behavior: "ignoreErrors" });
  await mount(page, base({ assignment, draft, withdrawn: { at: "2026-11-08T10:15:00Z", revision_id: "rev-1" } }));
  await expect(row).toContainText("Withdrawn 2026-11-08 10:15 UTC \u2014 guests see the neutral page");
  await expect(row).not.toContainText("Published");
  await expect(row).not.toContainText("Nothing published");
  await expect(page.getByTestId("pub-status-live")).toContainText("neutral");

  // No withdrawal recorded (an older server, an unknown backfilled history, or truly never approved): the row must not claim "never approved".
  await page.unrouteAll({ behavior: "ignoreErrors" });
  await mount(page, base({ assignment, draft }));
  await expect(row).toContainText("Nothing published");
  await expect(row).not.toContainText("Withdrawn");
  await expect(row).not.toContainText("Never approved");
  await expect(row).not.toContainText("earlier revision");
});
