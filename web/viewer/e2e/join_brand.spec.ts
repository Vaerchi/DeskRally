/**
 * The guest join page shows the brand its HOST publishes (docs/66 stage 2), driven through the real `/join` route
 * with the public branding route answered by Playwright. No control plane and no Go binary is involved, so every
 * kind of server trouble can be produced on demand; e2e/join_brand_host.spec.ts runs the same page against the real
 * control-plane handler with real host-keyed brands.
 *
 * What is held in place here (the viewer's half of the contract):
 *   - the page that renders while the lookup is pending is the NEUTRAL page, and the brand arrives in ONE step: no
 *     DOM snapshot anywhere mixes a brand with the neutral page ("a guest never sees a half-applied brand");
 *   - ANY failure (status, network, timeout, malformed or oversized or mistyped body, one bad field) leaves the
 *     neutral page, and there is no retry;
 *   - every tenant string is text, whatever it looks like; the only links are the validated contact kinds, and an
 *     email is never a link;
 *   - the logo loads from the published-hash route, shows nothing broken while it loads, and a logo that cannot be
 *     decoded (the server answers a stale hash with neutral JSON) falls back to the neutral mark;
 *   - the fixed safety lede is untouched by any accent, stays visible and unobscured, and nothing overflows a phone.
 *
 * Mutation evidence is recorded in docs/66 section 2i.
 */
import { test, expect, type Page, type Request, type Route } from "@playwright/test";

const JOIN = "/join#ABCD2345";
const HASH = "0123456789abcdef".repeat(4);

// A real 1x1 PNG (decodable, so the <img> reports a natural size).
const PNG = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M8AAAMBAQDJ/pLvAAAAAElFTkSuQmCC",
  "base64",
);

const NEUTRAL = { product_name: "", accent_color: "", logo_rev: "", support_text: "", support_contact: { kind: "", value: "" } };
const NEUTRAL_BYTES = JSON.stringify(NEUTRAL);

const BRAND = {
  product_name: "Acme IT",
  accent_color: "#1d4ed8",
  logo_rev: "",
  support_text: "Call us first.\nWe are open 9 to 5.",
  support_contact: { kind: "phone", value: "442079460958" },
};

const isBranding = (u: URL) => u.pathname === "/cp/public/branding";
const isLogo = (u: URL) => u.pathname === "/cp/public/branding/logo";

const root = (page: Page) => page.getByTestId("join-root");
const brandName = (page: Page) => page.getByTestId("join-brand-name");

/** Answers the branding route; swallows the error a fulfil gets when the page has already abandoned the request. */
async function answer(route: Route, response: Parameters<Route["fulfill"]>[0]) {
  try {
    await route.fulfill(response);
  } catch {
    /* the page abandoned this request (StrictMode's first effect, or a timeout) */
  }
}

async function serve(page: Page, body: unknown, status = 200) {
  await page.route(isBranding, (route) =>
    answer(route, { status, contentType: "application/json", body: typeof body === "string" ? body : JSON.stringify(body) }));
}

/** The neutral page, settled: the deployment's own name, nothing a brand adds, and the document's own title. */
async function expectNeutralPage(page: Page) {
  await expect(root(page)).toHaveAttribute("data-brand-state", "neutral");
  await expect(brandName(page)).toHaveText("DeskRally");
  await expect(page.getByTestId("join-brand-message")).toHaveCount(0);
  await expect(page.getByTestId("join-attribution")).toHaveCount(0);
  await expect(page.getByTestId("join-brand-logo")).toHaveCount(0);
  await expect(page).toHaveTitle("DeskRally");
  expect(await root(page).evaluate((el) => (el as HTMLElement).style.getPropertyValue("--join-accent"))).toBe("");
}

test.describe("the neutral skeleton and the one-step swap", () => {
  test("while the lookup is pending the page is the neutral page; the brand then arrives in ONE step", async ({ page }) => {
    // Record a snapshot of the brand-bearing DOM on every mutation: a half-applied brand would show up as a snapshot
    // that mixes the two (a tenant name beside the neutral state, an accent without the message, ...).
    await page.addInitScript(() => {
      const snaps: Array<Record<string, unknown>> = [];
      (window as unknown as { __snaps: unknown }).__snaps = snaps;
      new MutationObserver(() => {
        const r = document.querySelector('[data-testid="join-root"]') as HTMLElement | null;
        if (!r) return;
        snaps.push({
          state: r.getAttribute("data-brand-state"),
          name: document.querySelector('[data-testid="join-brand-name"]')?.textContent ?? null,
          accent: r.style.getPropertyValue("--join-accent"),
          message: !!document.querySelector('[data-testid="join-brand-message"]'),
          attribution: !!document.querySelector('[data-testid="join-attribution"]'),
          stepName: document.querySelector("#join-step1 bdi")?.textContent ?? null,
        });
      }).observe(document, { subtree: true, childList: true, attributes: true, characterData: true });
    });

    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    await page.route(isBranding, async (route) => {
      await gate;
      await answer(route, { status: 200, contentType: "application/json", body: JSON.stringify(BRAND) });
    });
    await page.goto(JOIN);

    // Pending: the neutral page, flagged as loading.
    await expect(root(page)).toHaveAttribute("data-brand-state", "loading");
    await expect(brandName(page)).toHaveText("DeskRally");
    await expect(page.getByTestId("join-brand-message")).toHaveCount(0);
    await expect(page.getByTestId("join-attribution")).toHaveCount(0);
    await expect(page.locator("#join-step1")).toContainText("Get the DeskRally support client");
    await page.waitForTimeout(300);
    await expect(root(page)).toHaveAttribute("data-brand-state", "loading");

    release();
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(brandName(page)).toHaveText("Acme IT");
    await expect(page.locator("#join-step1")).toContainText("Get the Acme IT support client");
    await expect(page.getByTestId("join-brand-text")).toHaveText("Call us first.\nWe are open 9 to 5.");
    await expect(page.getByTestId("join-attribution")).toContainText("Remote support software by DeskRally");
    await expect(page.getByTestId("join-attribution").locator("a")).toHaveAttribute("href", "https://default.example.test/docs");
    await expect(page).toHaveTitle("Acme IT");

    const snaps = (await page.evaluate(() => (window as unknown as { __snaps: unknown }).__snaps)) as Array<{
      state: string; name: string; accent: string; message: boolean; attribution: boolean; stepName: string;
    }>;
    expect(snaps.length).toBeGreaterThan(1);
    const kinds = new Set<string>();
    for (const s of snaps) {
      if (s.state === "branded") {
        kinds.add("branded");
        expect(s, "a branded snapshot is fully branded").toMatchObject({ name: "Acme IT", accent: "#1d4ed8", message: true, attribution: true, stepName: "Acme IT" });
      } else {
        kinds.add(s.state);
        expect(s, "a loading or neutral snapshot is fully neutral").toMatchObject({ name: "DeskRally", accent: "", message: false, attribution: false, stepName: "DeskRally" });
      }
    }
    expect(kinds.has("loading") && kinds.has("branded")).toBe(true);
  });

  test("a neutral answer settles to the neutral page without ever looking branded", async ({ page }) => {
    await serve(page, NEUTRAL_BYTES);
    await page.goto(JOIN);
    await expectNeutralPage(page);
  });

  test("the lookup asks once, with no cookies and no cache, and never again", async ({ page, context }) => {
    // The request must reach the NETWORK for the browser-managed headers (cookie, cache-control) to exist, so nothing
    // is routed here: the Vite dev proxy answers (a 500 when no control plane runs, which is neutral all the same).
    await context.addCookies([{ name: "session", value: "technician-secret", url: "http://127.0.0.1:5173" }]);
    const isLookup = (r: Request) => new URL(r.url()).pathname === "/cp/public/branding";
    const sent: Request[] = [];
    const answered: Request[] = [];
    page.on("request", (r) => { if (isLookup(r)) sent.push(r); });
    // `response` (headers received), not `requestfinished`: a non-200 answer is never read, so its body never "finishes".
    page.on("response", (r) => { if (isLookup(r.request())) answered.push(r.request()); });
    await page.goto(JOIN);
    await expectNeutralPage(page);
    await expect.poll(() => answered.length).toBeGreaterThanOrEqual(1);
    // React StrictMode runs the mount effect twice in development: the first lookup is abandoned by the cleanup.
    expect(sent.length).toBeLessThanOrEqual(2);
    for (const request of answered) {
      const headers = await request.allHeaders();
      expect(headers["cookie"], "the public lookup carries no cookie").toBeUndefined();
      expect(headers["cache-control"], "cache: no-store").toBe("no-cache");
      expect(headers["pragma"]).toBe("no-cache");
    }
    // And the browser really holds a cookie for this origin: it is the request that leaves it out, not the jar that is empty.
    expect((await context.cookies("http://127.0.0.1:5173")).map((c) => c.name)).toContain("session");
    const before = sent.length;
    await page.waitForTimeout(2000);
    expect(sent.length, "no retry loop").toBe(before);
  });
});

test.describe("any failure leaves the neutral page, with no retry", () => {
  const bad: Array<[string, (route: Route) => Promise<void>]> = [
    ["HTTP 500", (r) => answer(r, { status: 500, contentType: "application/json", body: JSON.stringify({ ...BRAND }) })],
    ["HTTP 429", (r) => answer(r, { status: 429, contentType: "application/json", headers: { "retry-after": "1" }, body: '{"error":"too many requests"}' })],
    ["HTTP 421 (an authority the edge refuses)", (r) => answer(r, { status: 421, contentType: "application/json", body: '{"error":"misdirected request"}' })],
    ["HTTP 401", (r) => answer(r, { status: 401, contentType: "application/json", body: '{"error":"unauthorized"}' })],
    ["HTTP 404", (r) => answer(r, { status: 404, body: "not found" })],
    ["a redirect", (r) => answer(r, { status: 302, headers: { location: "/elsewhere" }, body: "" })],
    ["a network error", (r) => r.abort("failed")],
    ["a connection reset", (r) => r.abort("connectionreset")],
    ["an empty 200", (r) => answer(r, { status: 200, body: "" })],
    ["a 200 that is not JSON", (r) => answer(r, { status: 200, contentType: "application/json", body: "this is not json" })],
    ["an HTML page where JSON was expected", (r) => answer(r, { status: 200, contentType: "text/html", body: "<!doctype html><title>x</title>" })],
    ["JSON null", (r) => answer(r, { status: 200, contentType: "application/json", body: "null" })],
    ["a JSON array", (r) => answer(r, { status: 200, contentType: "application/json", body: `[${JSON.stringify(BRAND)}]` })],
    ["a truncated object", (r) => answer(r, { status: 200, contentType: "application/json", body: '{"product_name":"Acme IT","accent_c' })],
    ["an empty object", (r) => answer(r, { status: 200, contentType: "application/json", body: "{}" })],
    ["a numeric name", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, product_name: 42 }) })],
    ["a missing contact object", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, support_contact: undefined }) })],
    ["an oversized body", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, padding: "x".repeat(20_000) }) })],
    ["one bad field (a bidi override in the name)", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, product_name: "Acme‮IT" }) })],
    ["one bad field (an accent that is a CSS injection)", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, accent_color: "#1d4ed8;background:url(//evil.example/x)" }) })],
    ["one bad field (a javascript: contact)", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, support_contact: { kind: "url", value: "javascript:alert(1)" } }) })],
    ["one bad field (a malformed logo hash)", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, logo_rev: "../../etc/passwd" }) })],
    ["a brand with no name", (r) => answer(r, { status: 200, contentType: "application/json", body: JSON.stringify({ ...BRAND, product_name: "" }) })],
  ];
  for (const [what, handler] of bad) {
    test(`${what}`, async ({ page }) => {
      let asked = 0;
      await page.route(isBranding, (route) => { asked++; return handler(route); });
      await page.goto(JOIN);
      await expectNeutralPage(page);
      const settledAt = asked;
      await page.waitForTimeout(1500);
      expect(asked, "no retry loop").toBe(settledAt);
      expect(asked, "one lookup per mount (two under development StrictMode)").toBeLessThanOrEqual(2);
      // The page is otherwise the normal join page.
      await expect(page.getByTestId("join-code")).toHaveAttribute("data-code", "ABCD2345");
    });
  }

  test("no answer at all: the neutral page for the whole wait, then settled neutral after 1.5 s, and it stays", async ({ page }) => {
    let firstAsk = 0;
    await page.route(isBranding, () => {
      if (!firstAsk) firstAsk = Date.now();
      return new Promise<void>(() => {}); // never answered
    });
    await page.goto(JOIN);
    await expect(root(page)).toHaveAttribute("data-brand-state", "loading");
    await expect(brandName(page)).toHaveText("DeskRally");
    await expect(root(page)).toHaveAttribute("data-brand-state", "neutral", { timeout: 5000 });
    const waited = Date.now() - firstAsk;
    expect(waited, "it waited about the documented 1.5 s, not less").toBeGreaterThanOrEqual(1400);
    expect(waited, "and did not wait much longer").toBeLessThan(4000);
    await expectNeutralPage(page);
    await page.waitForTimeout(700);
    await expectNeutralPage(page);
  });
});

test.describe("tenant strings are text", () => {
  const HOSTILE_NAME = "<img src=x onerror=window.__pwned=1>";
  const HOSTILE_TEXT = '"><script>window.__pwned=2</script>\n<b id="injected">bold</b> [link](javascript:window.__pwned=3) &lt;already&gt;';

  test("markup, script and link syntax in the name, the message and an email render as literal text", async ({ page }) => {
    await serve(page, {
      product_name: HOSTILE_NAME,
      accent_color: "#1d4ed8",
      logo_rev: "",
      support_text: HOSTILE_TEXT,
      support_contact: { kind: "email", value: "a'b&c=d?e@example.com" },
    });
    await page.goto(JOIN);
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(brandName(page)).toHaveText(HOSTILE_NAME);
    await expect(page.getByTestId("join-brand-text")).toHaveText(HOSTILE_TEXT);
    await expect(page.locator("#join-step1")).toContainText(`Get the ${HOSTILE_NAME} support client`);
    await expect(page).toHaveTitle(HOSTILE_NAME);

    expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
    await expect(page.locator("#injected")).toHaveCount(0);
    await expect(page.locator("main script")).toHaveCount(0);
    // No element was made from any of it: no image (the name looks like one), no link from the message or email.
    await expect(page.locator(".join__topbar img:not(.rally-mark), .join__main img:not(.rally-mark)")).toHaveCount(0);
    await expect(page.getByTestId("join-brand-message").locator("a")).toHaveCount(0);
    await expect(page.locator('a[href^="javascript"], a[href^="mailto"]')).toHaveCount(0);
    // The email is on screen as text, exactly.
    await expect(page.getByTestId("join-brand-contact")).toHaveText("Email a'b&c=d?e@example.com");
  });

  test("phone is a tel: link built from the digits", async ({ page }) => {
    await serve(page, BRAND);
    await page.goto(JOIN);
    const link = page.getByTestId("join-brand-contact").locator("a");
    await expect(link).toHaveAttribute("href", "tel:442079460958");
    await expect(link).toHaveText("442079460958");
    await expect(page.getByTestId("join-brand-contact")).toContainText("Phone");
  });

  test("email is text and never a link", async ({ page }) => {
    await serve(page, { ...BRAND, support_contact: { kind: "email", value: "help@example.com" } });
    await page.goto(JOIN);
    await expect(page.getByTestId("join-brand-contact")).toHaveText("Email help@example.com");
    await expect(page.getByTestId("join-brand-contact").locator("a")).toHaveCount(0);
    await expect(page.locator('a[href^="mailto"]')).toHaveCount(0);
  });

  test("website is an https link with the host emphasised, opened without an opener or referrer", async ({ page }) => {
    await serve(page, { ...BRAND, support_contact: { kind: "url", value: "https://help.example.com/support?x=1&y=2" } });
    await page.goto(JOIN);
    const link = page.getByTestId("join-brand-contact").locator("a");
    await expect(link).toHaveAttribute("href", "https://help.example.com/support?x=1&y=2");
    await expect(link).toHaveAttribute("target", "_blank");
    await expect(link).toHaveAttribute("rel", "noopener noreferrer nofollow");
    await expect(link).toHaveText("https://help.example.com/support?x=1&y=2");
    await expect(link.locator("strong")).toHaveText("help.example.com");
  });

  test("a message with no contact, and a contact with no message", async ({ page }) => {
    await serve(page, { ...BRAND, support_contact: { kind: "", value: "" } });
    await page.goto(JOIN);
    await expect(page.getByTestId("join-brand-text")).toBeVisible();
    await expect(page.getByTestId("join-brand-contact")).toHaveCount(0);
    await page.unroute(isBranding);
    await serve(page, { ...BRAND, support_text: "" });
    await page.reload(); // the URL is unchanged, so goto would be a same-document (fragment) navigation and ask nothing
    await expect(page.getByTestId("join-brand-contact")).toBeVisible();
    await expect(page.getByTestId("join-brand-text")).toHaveCount(0);
    await expect(page.getByTestId("join-brand-message")).toHaveAttribute("aria-label", "Support contact");
  });
});

test.describe("the logo", () => {
  const withLogo = { ...BRAND, logo_rev: HASH };

  test("loads from the published-hash route, shows nothing while it loads, then replaces the neutral mark", async ({ page }) => {
    await serve(page, withLogo);
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const logoUrls: string[] = [];
    await page.route(isLogo, async (route) => {
      logoUrls.push(route.request().url());
      await gate;
      await answer(route, { status: 200, contentType: "image/png", body: PNG });
    });
    await page.goto(JOIN);
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(brandName(page)).toHaveText("Acme IT");
    const logo = page.getByTestId("join-brand-logo");
    // Pending: the slot is reserved and the image is not shown (no broken-image box, no neutral flash).
    await expect(logo).toHaveAttribute("data-state", "loading");
    await expect(logo).toHaveCSS("visibility", "hidden");
    await expect(page.locator(".join__topbar .rally-mark")).toHaveCount(0);
    release();
    await expect(logo).toHaveAttribute("data-state", "ok");
    await expect(logo).toBeVisible();
    expect(await logo.evaluate((img) => (img as HTMLImageElement).naturalWidth)).toBe(1);
    expect(new URL(logoUrls[0]!).pathname + new URL(logoUrls[0]!).search).toBe(`/cp/public/branding/logo?rev=${HASH}`);
    // The URL is the page's own origin and the published hash, nothing from the response but the hash.
    expect(new URL(logoUrls[0]!).origin).toBe(new URL(page.url()).origin);
    await expect(page.locator(".join__topbar .rally-mark")).toHaveCount(0);
  });

  const failures: Array<[string, (route: Route) => Promise<void>]> = [
    // What the server really answers for a hash that is not the published one: 200 with the neutral JSON.
    ["the neutral JSON the server answers for a stale or unpublished hash", (r) => answer(r, { status: 200, contentType: "application/json", body: NEUTRAL_BYTES })],
    ["a 404", (r) => answer(r, { status: 404, body: "not found" })],
    ["a 500", (r) => answer(r, { status: 500, body: "boom" })],
    ["bytes that are not an image", (r) => answer(r, { status: 200, contentType: "image/png", body: "definitely not a png" })],
    ["an HTML page", (r) => answer(r, { status: 200, contentType: "text/html", body: "<!doctype html>" })],
    ["a network error", (r) => r.abort("failed")],
  ];
  for (const [what, handler] of failures) {
    test(`a logo that fails to load (${what}) falls back to the neutral mark; the name and message stay`, async ({ page }) => {
      await serve(page, withLogo);
      await page.route(isLogo, handler);
      await page.goto(JOIN);
      await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
      // The image is gone (not a broken-image box) and the neutral mark is in its place.
      await expect(page.getByTestId("join-brand-logo")).toHaveCount(0);
      await expect(page.locator(".join__topbar .rally-mark")).toHaveCount(1);
      await expect(page.locator(".join__topbar .rally-mark")).toBeVisible();
      await expect(brandName(page)).toHaveText("Acme IT");
      await expect(page.getByTestId("join-brand-message")).toBeVisible();
      await expect(page.getByTestId("join-attribution")).toBeVisible();
    });
  }

  test("a brand with no logo hash asks for no logo at all", async ({ page }) => {
    await serve(page, BRAND);
    let asked = 0;
    await page.route(isLogo, (route) => { asked++; return route.abort(); });
    await page.goto(JOIN);
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(page.locator(".join__topbar .rally-mark")).toHaveCount(1);
    await page.waitForTimeout(300);
    expect(asked).toBe(0);
  });
});

test.describe("the accent colours exactly two things", () => {
  test("the primary button fill and the contact link, and nothing else", async ({ page }) => {
    await serve(page, NEUTRAL_BYTES);
    await page.goto(JOIN);
    await expectNeutralPage(page);
    const join = page.getByRole("button", { name: "Continue", exact: true });
    await expect(join).toHaveCSS("background-color", "rgb(53, 101, 74)"); // the theme's forest
    const neutral = await page.evaluate(() => {
      const css = (sel: string) => { const cs = getComputedStyle(document.querySelector(sel)!); return `${cs.color}|${cs.backgroundColor}|${cs.borderLeftColor}`; };
      return { lede: css(".join__lede"), title: css(".join__title"), topbar: css(".join__topbar"), step: css(".join__stephead"), code: css("#support-session-code") };
    });

    await page.unroute(isBranding);
    await serve(page, BRAND);
    await page.reload(); // (same-document navigation otherwise)
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(join).toHaveCSS("background-color", "rgb(29, 78, 216)"); // #1d4ed8
    await expect(join).toHaveCSS("color", "rgb(255, 255, 255)"); // the label stays white
    await expect(page.getByTestId("join-brand-contact").locator("a")).toHaveCSS("color", "rgb(29, 78, 216)");
    const branded = await page.evaluate(() => {
      const css = (sel: string) => { const cs = getComputedStyle(document.querySelector(sel)!); return `${cs.color}|${cs.backgroundColor}|${cs.borderLeftColor}`; };
      return { lede: css(".join__lede"), title: css(".join__title"), topbar: css(".join__topbar"), step: css(".join__stephead"), code: css("#support-session-code") };
    });
    expect(branded).toEqual(neutral);
  });
});

function channel(v: string): number {
  const c = Number(v) / 255;
  return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
}
function luminance(rgb: string): number {
  const m = /rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)/.exec(rgb);
  if (!m) throw new Error(`not a colour: ${rgb}`);
  return 0.2126 * channel(m[1]!) + 0.7152 * channel(m[2]!) + 0.0722 * channel(m[3]!);
}
function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

/** The fixed safety copy as a guest sees it: its colours, its box, and whether anything is on top of it. */
async function measureFixedCopy(page: Page) {
  return page.evaluate(() => {
    const measure = (sel: string) => {
      const el = document.querySelector(sel) as HTMLElement;
      el.scrollIntoView({ block: "center" });
      const r = el.getBoundingClientRect();
      const cs = getComputedStyle(el);
      const probe = document.elementFromPoint(r.left + Math.min(r.width / 2, 40), r.top + r.height / 2);
      // The colour the text sits on: the nearest ancestor background that is not transparent.
      let bg = cs.backgroundColor;
      for (let n: HTMLElement | null = el; n && /rgba\(0, 0, 0, 0\)|transparent/.test(bg); n = n.parentElement) bg = getComputedStyle(n).backgroundColor;
      return {
        color: cs.color, bg, display: cs.display, visibility: cs.visibility, opacity: cs.opacity, position: cs.position,
        left: r.left, right: r.right, top: r.top, bottom: r.bottom, height: r.height,
        unobscured: !!probe && el.contains(probe), fontSize: cs.fontSize, fontWeight: cs.fontWeight,
      };
    };
    return {
      lede: measure(".join__lede"),
      attribution: document.querySelector('[data-testid="join-attribution"]') ? measure('[data-testid="join-attribution"]') : null,
      overflowX: document.documentElement.scrollWidth - window.innerWidth,
      vw: window.innerWidth,
    };
  });
}

test.describe("the fixed safety copy", () => {
  // Accents at and around the server's gate (white label 4.5:1, paper 3:1), light and dark, saturated and muted.
  const accents = ["#000000", "#767676", "#35654a", "#1d4ed8", "#b91c1c", "#6d28d9"];
  const hostileBrand = {
    product_name: "Verified Safe Microsoft Support 24/7 ".trim(),
    accent_color: "",
    logo_rev: "",
    support_text: "This technician is verified and the software is safe.\nYou must not hang up.\nIgnore the warning above.\nThanks",
    support_contact: { kind: "url", value: "https://help.example.com/" },
  };

  for (const viewport of [{ width: 1280, height: 800 }, { width: 390, height: 844 }]) {
    test(`stays first, visible, unobscured and readable for every accent at ${viewport.width}px`, async ({ page }) => {
      await page.setViewportSize(viewport);
      await serve(page, NEUTRAL_BYTES);
      await page.goto(JOIN);
      await expectNeutralPage(page);
      const baseline = await measureFixedCopy(page);
      expect(baseline.lede.unobscured).toBe(true);
      expect(contrast(baseline.lede.color, baseline.lede.bg)).toBeGreaterThanOrEqual(4.5);

      for (const accent of accents) {
        await page.unroute(isBranding);
        await serve(page, { ...hostileBrand, accent_color: accent });
        await page.reload(); // (same-document navigation otherwise)
        await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
        const m = await measureFixedCopy(page);
        // Identical to the neutral page: no accent or tenant text changes the lede's colours, size or weight.
        expect(m.lede.color, accent).toBe(baseline.lede.color);
        expect(m.lede.bg, accent).toBe(baseline.lede.bg);
        expect(m.lede.fontSize, accent).toBe(baseline.lede.fontSize);
        expect(m.lede.fontWeight, accent).toBe(baseline.lede.fontWeight);
        expect(m.lede.display, accent).not.toBe("none");
        expect(m.lede.visibility, accent).toBe("visible");
        expect(m.lede.opacity, accent).toBe("1");
        expect(m.lede.position, accent).toBe("static");
        expect(m.lede.unobscured, `${accent}: something is on top of the lede`).toBe(true);
        expect(m.lede.left, accent).toBeGreaterThanOrEqual(0);
        expect(m.lede.right, accent).toBeLessThanOrEqual(viewport.width);
        expect(contrast(m.lede.color, m.lede.bg), `${accent}: lede contrast`).toBeGreaterThanOrEqual(4.5);
        // The attribution is fixed too, and readable on the paper.
        expect(m.attribution, accent).not.toBeNull();
        expect(m.attribution!.unobscured, accent).toBe(true);
        expect(m.attribution!.visibility, accent).toBe("visible");
        expect(contrast(m.attribution!.color, m.attribution!.bg), `${accent}: attribution contrast`).toBeGreaterThanOrEqual(4.5);
        // The tenant's message sits BELOW the lede, never over it.
        const message = await page.getByTestId("join-brand-message").boundingBox();
        const ledeBox = await page.locator(".join__lede").boundingBox();
        expect(message!.y, accent).toBeGreaterThanOrEqual(ledeBox!.y + ledeBox!.height - 1);
        expect(m.overflowX, `${accent}: horizontal overflow`).toBeLessThanOrEqual(0);
      }
    });
  }

  test("the worst case of every tenant string at phone width: nothing overflows and the lede stays visible", async ({ page }) => {
    await page.setViewportSize({ width: 360, height: 800 });
    await serve(page, {
      product_name: "WWWW MMMM ".repeat(10).trim(), // the widest name the server accepts: 99 wide letters, no run of five
      accent_color: "#000000",
      logo_rev: "",
      support_text: `${"abcdefghijklmnopqrstuvwxyz0123456789".repeat(7).slice(0, 280)}`,
      support_contact: { kind: "url", value: `https://help.example.com/${"abcdefghij".repeat(17)}` },
    });
    await page.goto(JOIN);
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    const m = await measureFixedCopy(page);
    expect(m.overflowX, "no horizontal scroll").toBeLessThanOrEqual(0);
    expect(m.lede.unobscured).toBe(true);
    expect(m.lede.right).toBeLessThanOrEqual(360);
    // The name is one ellipsised line in the top bar, not a wall.
    const name = await brandName(page).boundingBox();
    expect(name!.height).toBeLessThan(40);
  });
});

test("a 100-character unbroken name (the server maximum) does not overflow the page at desktop width, and the attribution links the default host's /docs", async ({ page }) => {
  const LONG = "abcdefghij".repeat(10);
  await serve(page, { ...BRAND, product_name: LONG });
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto(JOIN);
  await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
  const m = await page.evaluate(() => {
    const vw = document.documentElement.clientWidth;
    const step = document.querySelector("#join-step1 bdi") as HTMLElement;
    const r = step.getBoundingClientRect();
    return { vw, scrollW: document.documentElement.scrollWidth, stepRight: r.right, stepText: step.textContent };
  });
  expect(m.stepText).toBe(LONG);
  expect(m.scrollW).toBeLessThanOrEqual(m.vw);
  expect(m.stepRight).toBeLessThanOrEqual(m.vw);
  // VITE_DEFAULT_ORIGIN is the lab value under the dev server (playwright.config.ts): the link is that origin + /docs,
  // never this page's own host.
  const attribution = page.getByTestId("join-attribution");
  await expect(attribution).toContainText("Remote support software by DeskRally");
  await expect(attribution.locator("a")).toHaveAttribute("href", "https://default.example.test/docs");
});
