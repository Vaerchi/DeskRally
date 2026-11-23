/**
 * The mocked API the platform-operator specs share (docs/66 2k): an operator session with a fresh second factor,
 * the tenant listing, the step-up endpoint, and a hook for each spec's own routes. Loopback only; nothing leaves the
 * page (any other origin is aborted).
 */
import { expect, test, type Page, type Route } from "@playwright/test";

export const ACME = {
  id: "t-acme",
  slug: "acme",
  name: "Acme Corp",
  deployment_mode: "saas",
  created_at: "2026-10-12T00:00:00Z",
  user_count: 4,
  unleased_machines: false,
};

export interface PlatformMock {
  /** The /platform/me body: flipped to fresh by a successful step-up. */
  me: { operator: boolean; mfa_ok: boolean; mfa_fresh: boolean };
  stepUps: string[];
}

/** A route handler: return true when it answered the request. */
export type Handler = (url: URL, method: string, route: Route) => Promise<boolean> | boolean;

export async function mountPlatform(page: Page, handler: Handler, me: PlatformMock["me"] = { operator: true, mfa_ok: true, mfa_fresh: true }): Promise<PlatformMock> {
  const BASE = test.info().project.use.baseURL ?? "http://127.0.0.1:5173";
  const baseUrl = new URL(BASE);
  const mock: PlatformMock = { me: { ...me }, stepUps: [] };
  await page.route("**/*", async (route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    if (url.origin !== baseUrl.origin) return route.abort();
    if (url.pathname === "/cp/auth/session") return route.fulfill({ status: 204 });
    if (url.pathname === "/cp/platform/me") return route.fulfill({ json: mock.me });
    if (url.pathname === "/cp/platform/tenants" && method === "GET") return route.fulfill({ json: { tenants: [ACME] } });
    if (url.pathname === "/cp/auth/step-up" && method === "POST") {
      const code = (route.request().postDataJSON() as { code: string }).code;
      mock.stepUps.push(code);
      if (code === "123456") {
        mock.me = { operator: true, mfa_ok: true, mfa_fresh: true };
        return route.fulfill({ status: 204 });
      }
      return route.fulfill({ status: 403, json: { error: "invalid credentials" } });
    }
    if (url.pathname.startsWith("/cp/") && (await handler(url, method, route))) return;
    if (url.pathname.startsWith("/cp/")) return route.fulfill({ json: {} });
    return route.continue();
  });
  await page.goto(BASE);
  expect(new Set(["127.0.0.1", "localhost", "[::1]"]).has(baseUrl.hostname)).toBe(true);
  return mock;
}
