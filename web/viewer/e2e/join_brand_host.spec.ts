/**
 * The guest join page against the REAL control-plane handler, with brands keyed by HOST (docs/66 stage 2).
 *
 * control-plane/cmd/cpthemefixture serves Server.Handler() over the real in-memory branding and hostname stores
 * (the public routes, the host policy, the edge authority gate and the 150 ms response schedule are the code
 * production runs). The browser reaches it through the Vite `/cp` proxy, which rewrites Host, so the authority a
 * guest "opened" is presented the way a real edge would deliver it, by a fixture-only header that the fixture's
 * edge stand-in turns into the Host (and the edge marker). It is never a query parameter, and no production code
 * knows the header (control-plane/fixture_isolation_test.go).
 *
 * Together with join_brand.spec.ts (the viewer against a scripted server) this proves the pair end to end: the
 * JSON the Go handler really emits is what the viewer's parser accepts, a tenant host shows its own approved brand,
 * the default host and every other state show the neutral page, and the logo route's real neutral answer is what
 * triggers the viewer's logo fallback.
 *
 * A prerequisite that is absent FAILS the run (it is never skipped): globalSetup builds the fixture before any
 * worker starts, exactly as it builds the control plane.
 */
import { test, expect, type Page } from "@playwright/test";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { stopProc } from "./devcp";
import { CP_BASE, CP_PORT } from "./ports";

const HERE = dirname(fileURLToPath(import.meta.url));
const FIXTURE_EXE = resolve(HERE, "..", "..", "..", "control-plane", "cpthemefixture.exe");
const FIXTURE_DIR = resolve(HERE, "..", "..", "..", "control-plane");

const JOIN = "/join#ABCD2345";
const HOST_HEADER = "x-fixture-host";
const NEUTRAL_BYTES = '{"product_name":"","accent_color":"","logo_rev":"","support_text":"","support_contact":{"kind":"","value":""}}';

let proc: ChildProcess | null = null;

test.beforeAll(async () => {
  test.setTimeout(60_000);
  // Assert, never build: a stale or missing fixture would be testing a different program.
  expect(existsSync(FIXTURE_EXE), `${FIXTURE_EXE} is missing: e2e/global-setup.ts builds it before any worker starts`).toBe(true);
  let output = "";
  proc = spawn(FIXTURE_EXE, [], { cwd: FIXTURE_DIR, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, CP_LISTEN: `127.0.0.1:${CP_PORT}` } });
  proc.stdout?.on("data", (d: Buffer) => { output += d.toString(); });
  proc.stderr?.on("data", (d: Buffer) => { output += d.toString(); });
  const deadline = Date.now() + 20_000;
  while (!output.includes("FIXTURE_READY")) {
    if (proc.exitCode !== null) throw new Error(`the theming fixture exited (${proc.exitCode}) before it was ready:\n${output}`);
    if (Date.now() > deadline) throw new Error(`the theming fixture was not ready in 20 s:\n${output}`);
    await new Promise((r) => setTimeout(r, 100));
  }
});

test.afterAll(async () => {
  await stopProc(proc);
});

interface Published { ok: boolean; host: string; logo_rev: string; assignment_state: string }

async function publish(host: string, brand: Record<string, unknown>): Promise<Published> {
  const res = await fetch(`${CP_BASE}/fixture/brand`, { method: "POST", body: JSON.stringify({ host, ...brand }) });
  const body = (await res.json()) as Published & { error?: string };
  expect(res.status, `publishing for ${host}: ${body.error ?? ""}`).toBe(200);
  return body;
}

/** Presents `host` as the authority the guest opened: every request this page makes carries it. */
async function openAs(page: Page, host: string | null, path = JOIN) {
  if (host) await page.setExtraHTTPHeaders({ [HOST_HEADER]: host });
  await page.goto(path);
}

const root = (page: Page) => page.getByTestId("join-root");
const brandName = (page: Page) => page.getByTestId("join-brand-name");

async function expectNeutral(page: Page) {
  await expect(root(page)).toHaveAttribute("data-brand-state", "neutral");
  await expect(brandName(page)).toHaveText("DeskRally");
  await expect(page.getByTestId("join-brand-message")).toHaveCount(0);
  await expect(page.getByTestId("join-attribution")).toHaveCount(0);
  await expect(page.getByTestId("join-brand-logo")).toHaveCount(0);
  await expect(page).toHaveTitle("DeskRally");
}

const ACME = {
  product_name: "Acme IT",
  accent_color: "#1d4ed8",
  support_text: "Call us first.\nWe are open 9 to 5.",
  support_contact: { kind: "phone", value: "(442) 079-460958" }, // the server stores digits only
};
const GLOBEX = {
  product_name: "Globex Support",
  accent_color: "#b91c1c",
  support_text: "Globex staff will never ask for your password.",
  support_contact: { kind: "url", value: "https://support.globex.example/help" },
};

test.describe("which brand a host shows", () => {
  test("the real server's neutral answer is exactly the bytes the viewer's fixtures use", async () => {
    const res = await fetch(`${CP_BASE}/public/branding`);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(NEUTRAL_BYTES);
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  test("the default host shows the neutral page", async ({ page }) => {
    await openAs(page, null);
    await expectNeutral(page);
    await expect(page.getByTestId("join-code")).toHaveAttribute("data-code", "ABCD2345");
  });

  test("a tenant host shows that tenant's approved brand, in one step", async ({ page }) => {
    await publish("tenant1.localhost", ACME);
    await openAs(page, "tenant1.localhost");
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(brandName(page)).toHaveText("Acme IT");
    await expect(page.locator("#join-step1")).toContainText("Get the Acme IT support client");
    await expect(page.getByTestId("join-brand-text")).toHaveText("Call us first.\nWe are open 9 to 5.");
    // The server stored the phone as digits; the viewer links exactly those digits.
    await expect(page.getByTestId("join-brand-contact").locator("a")).toHaveAttribute("href", "tel:442079460958");
    await expect(page.getByTestId("join-attribution")).toContainText("Remote support software by DeskRally");
    // The link is the default host's /docs, not the tenant host the page was served from.
    await expect(page.getByTestId("join-attribution").locator("a")).toHaveAttribute("href", "https://default.example.test/docs");
    await expect(page).toHaveTitle("Acme IT");
    await expect(page.getByRole("button", { name: "Continue", exact: true })).toHaveCSS("background-color", "rgb(29, 78, 216)");
    // The fixed lede is the same sentence it always is.
    await expect(page.locator(".join__lede")).toContainText("Do this only if YOU called your IT provider for help");
  });

  test("two tenant hosts show two different brands, and the default host shows neither", async ({ browser }) => {
    await publish("tenant1.localhost", ACME);
    await publish("tenant2.localhost", GLOBEX);
    const seen: Record<string, string> = {};
    for (const host of ["tenant1.localhost", "tenant2.localhost", null]) {
      const context = await browser.newContext();
      const page = await context.newPage();
      await openAs(page, host);
      await expect(root(page)).not.toHaveAttribute("data-brand-state", "loading");
      seen[host ?? "default"] = (await brandName(page).textContent()) ?? "";
      if (host === "tenant2.localhost") {
        await expect(page.getByTestId("join-brand-contact").locator("a")).toHaveAttribute("href", "https://support.globex.example/help");
        await expect(page.getByRole("button", { name: "Continue", exact: true })).toHaveCSS("background-color", "rgb(185, 28, 28)");
      }
      await context.close();
    }
    expect(seen).toEqual({ "tenant1.localhost": "Acme IT", "tenant2.localhost": "Globex Support", default: "DeskRally" });
  });

  const neutralHosts: Array<[string, string]> = [
    ["an assigned host that is still PENDING (a brand approved against it publishes nothing)", "pending.localhost"],
    ["a host the edge does not list (the gate answers 421)", "rogue.localhost"],
    ["a listed host with a port the edge refuses", "tenant1.localhost:8443"],
    ["an authority that is not a plain host name", "tenant1.localhost@evil.example"],
  ];
  for (const [what, host] of neutralHosts) {
    test(`${what} shows the neutral page`, async ({ page }) => {
      await publish("tenant1.localhost", ACME); // a brand exists on a DIFFERENT host: it must not leak
      await publish("pending.localhost", GLOBEX); // approved against the PENDING assignment: still not published
      await openAs(page, host);
      await expectNeutral(page);
    });
  }

  test("a withdrawn brand is neutral on the very next load (nothing is cached)", async ({ page }) => {
    await publish("tenant3.localhost", ACME);
    await openAs(page, "tenant3.localhost");
    await expect(brandName(page)).toHaveText("Acme IT");
    expect((await fetch(`${CP_BASE}/fixture/withdraw`, { method: "POST", body: JSON.stringify({ host: "tenant3.localhost" }) })).status).toBe(200);
    await page.reload();
    await expectNeutral(page);
    // And a re-approval shows on the next load too.
    await publish("tenant3.localhost", { ...ACME, product_name: "Acme Reborn" });
    await page.reload();
    await expect(brandName(page)).toHaveText("Acme Reborn");
  });

  test("a changed brand shows on the next load, never a cached one", async ({ page }) => {
    await publish("tenant4.localhost", { ...ACME, product_name: "First Name" });
    await openAs(page, "tenant4.localhost");
    await expect(brandName(page)).toHaveText("First Name");
    await publish("tenant4.localhost", { ...ACME, product_name: "Second Name" });
    await page.reload();
    await expect(brandName(page)).toHaveText("Second Name");
  });
});

test.describe("what the real server accepts, the viewer shows as text", () => {
  test("markup, script and link syntax pass the server's rules and render as literal text", async ({ page }) => {
    const name = "<img src=x onerror=window.__pwned=1>";
    const text = '"><script>window.__pwned=2</script>\n<b id="injected">bold</b> [link](javascript:window.__pwned=3)';
    await publish("tenant2.localhost", { product_name: name, accent_color: "", support_text: text, support_contact: { kind: "email", value: "a'b&c=d?e@example.com" } });
    await openAs(page, "tenant2.localhost");
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(brandName(page)).toHaveText(name);
    await expect(page.getByTestId("join-brand-text")).toHaveText(text);
    await expect(page).toHaveTitle(name);
    expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
    await expect(page.locator("#injected")).toHaveCount(0);
    await expect(page.locator("main script")).toHaveCount(0);
    await expect(page.locator(".join__topbar img:not(.rally-mark), .join__main img:not(.rally-mark)")).toHaveCount(0);
    await expect(page.locator('a[href^="javascript"], a[href^="mailto"]')).toHaveCount(0);
    await expect(page.getByTestId("join-brand-contact")).toHaveText("Email a'b&c=d?e@example.com");
  });

  test("what the server refuses never reaches a page (the fixture applies the real rules)", async () => {
    for (const bad of [
      { product_name: "Acme\u202EIT" },
      { product_name: "Acme IT", accent_color: "#ffff00" }, // too little contrast against the white label
      { product_name: "Acme IT", support_contact: { kind: "url", value: "http://insecure.example/" } },
      { product_name: "Acme IT", support_contact: { kind: "email", value: "not an address" } },
    ]) {
      const res = await fetch(`${CP_BASE}/fixture/brand`, { method: "POST", body: JSON.stringify({ host: "tenant1.localhost", ...bad }) });
      expect(res.status, JSON.stringify(bad)).toBe(400);
    }
  });
});

test.describe("the logo", () => {
  test("a published logo loads from its hash route on the tenant's own host", async ({ page }) => {
    const { logo_rev } = await publish("tenant1.localhost", { ...ACME, logo: "wide" });
    expect(logo_rev).toMatch(/^[0-9a-f]{64}$/);
    const requested: string[] = [];
    page.on("request", (r) => { if (new URL(r.url()).pathname === "/cp/public/branding/logo") requested.push(new URL(r.url()).search); });
    await openAs(page, "tenant1.localhost");
    const logo = page.getByTestId("join-brand-logo");
    await expect(logo).toHaveAttribute("data-state", "ok");
    await expect(logo).toBeVisible();
    expect(await logo.evaluate((img) => [(img as HTMLImageElement).naturalWidth, (img as HTMLImageElement).naturalHeight])).toEqual([160, 48]);
    expect(requested).toEqual([`?rev=${logo_rev}`]);
    await expect(page.locator(".join__topbar .rally-mark")).toHaveCount(0);
  });

  test("the real server answers a hash that is not the published one with neutral JSON, and the page falls back to the neutral mark", async ({ page }) => {
    const { logo_rev } = await publish("tenant1.localhost", { ...ACME, logo: "square" });
    // What the server really says to the wrong hash (200 and JSON, never a 404 and never the PNG):
    const wrong = await fetch(`${CP_BASE}/public/branding/logo?rev=${"0".repeat(64)}`, { headers: { [HOST_HEADER]: "tenant1.localhost" } });
    expect(wrong.status).toBe(200);
    expect(wrong.headers.get("content-type")).toBe("application/json");
    expect(await wrong.text()).toBe(NEUTRAL_BYTES);
    // ... and to the right hash on ANOTHER tenant's host:
    const foreign = await fetch(`${CP_BASE}/public/branding/logo?rev=${logo_rev}`, { headers: { [HOST_HEADER]: "tenant2.localhost" } });
    expect(foreign.headers.get("content-type")).toBe("application/json");

    // The page asks for a stale hash (the brand was re-approved between the two requests): the neutral JSON cannot
    // be decoded as an image, so the error event fires and the neutral mark takes the logo's place.
    await page.route((u) => u.pathname === "/cp/public/branding/logo", (route) => {
      const u = new URL(route.request().url());
      u.searchParams.set("rev", "0".repeat(64));
      return route.continue({ url: u.toString(), headers: { ...route.request().headers(), [HOST_HEADER]: "tenant1.localhost" } });
    });
    await openAs(page, "tenant1.localhost");
    await expect(root(page)).toHaveAttribute("data-brand-state", "branded");
    await expect(page.getByTestId("join-brand-logo")).toHaveCount(0);
    await expect(page.locator(".join__topbar .rally-mark")).toBeVisible();
    await expect(brandName(page)).toHaveText("Acme IT");
  });
});
