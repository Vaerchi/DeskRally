/**
 * M3 console wiring contract: the management panels compose `ConsoleApiClient` with the flows in
 * `lib/console_panels.ts` — SessionsPanel's End button runs `endSessionAndRefresh(api, id)` and
 * PlatformPanel's create form runs `submitCreateTenant(api, form)`. Components are `.tsx` and the vitest
 * env is `node`, so (following `v3_wiring.test.ts`) rather than render them we drive those exact
 * compositions through the REAL HTTP client against a fake fetch that simulates the control
 * plane's wire contract (`control-plane/http.go`): envelope shapes, `POST /sessions/{id}/end`,
 * 409 on a duplicate slug, and the CSRF echo on mutations.
 */

import { describe, it, expect } from "vitest";

import { ConsoleApiClient, CSRF_HEADER_NAME, type SessionRecord } from "./lib/console_api";
import { endSessionAndRefresh, sessionStatus, submitCreateTenant } from "./lib/console_panels";

/** A minimal in-memory control plane behind a fetch-shaped function. */
function fakeControlPlane() {
  const sessions = new Map<string, SessionRecord>();
  const tenantSlugs = new Set<string>();
  const csrfSeen: (string | undefined)[] = [];

  const addSession = (id: string, startedAt: string) => {
    sessions.set(id, {
      id,
      tenant_id: "t-1",
      machine_id: "pk-1",
      technician_id: "u-1",
      started_at: startedAt,
      consent_policy: "none",
      granted_caps: null,
      machine_group_id: "g-1",
      machine_device_id: "dev-1",
      machine_name: "M",
      machine_alias: "",
      note: "",
    });
  };

  const json = (body: unknown, status = 200) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const fetchImpl = (url: string, init?: RequestInit): Promise<Response> => {
    const method = init?.method ?? "GET";
    if (method === "POST") {
      csrfSeen.push((init?.headers as Record<string, string> | undefined)?.[CSRF_HEADER_NAME]);
    }

    const end = url.match(/^\/cp\/sessions\/([^/]+)\/end$/);
    if (end && method === "POST") {
      const rec = sessions.get(decodeURIComponent(end[1]));
      if (!rec) return Promise.resolve(json({ error: "unknown session" }, 404));
      if (!rec.ended_at) rec.ended_at = "2026-07-28T12:30:00Z"; // idempotent, like the Go store
      return Promise.resolve(json({ session: rec }));
    }
    if (url === "/cp/sessions" && method === "GET") {
      return Promise.resolve(json({ sessions: [...sessions.values()] }));
    }
    if (url === "/cp/platform/tenants" && method === "POST") {
      const body = JSON.parse(String(init?.body)) as { slug: string; name: string };
      if (tenantSlugs.has(body.slug)) {
        return Promise.resolve(json({ error: "tenant slug already in use" }, 409));
      }
      tenantSlugs.add(body.slug);
      return Promise.resolve(
        json(
          {
            tenant: {
              id: `t-${tenantSlugs.size}`,
              slug: body.slug,
              name: body.name,
              deployment_mode: "saas",
              created_at: "2026-07-28T12:00:00Z",
              disabled: false,
            },
          },
          201,
        ),
      );
    }
    return Promise.resolve(json({ error: "no route" }, 404));
  };

  return { fetchImpl, addSession, csrfSeen };
}

describe("M3 console wiring", () => {
  it("SessionsPanel's End flow: POST /sessions/{id}/end then a newest-first re-list", async () => {
    const cp = fakeControlPlane();
    cp.addSession("s-old", "2026-07-28T08:00:00Z");
    cp.addSession("s-new", "2026-07-28T11:00:00Z");
    const api = new ConsoleApiClient({ baseUrl: "/cp", fetch: cp.fetchImpl });

    const rows = await endSessionAndRefresh(api, "s-new");

    expect(rows.map((r) => r.id)).toEqual(["s-new", "s-old"]);
    expect(sessionStatus(rows[0])).toBe("ended");
    expect(sessionStatus(rows[1])).toBe("live");
  });

  it("End surfaces an unknown session as a typed not_found failure", async () => {
    const cp = fakeControlPlane();
    const api = new ConsoleApiClient({ baseUrl: "/cp", fetch: cp.fetchImpl });
    await expect(endSessionAndRefresh(api, "nope")).rejects.toMatchObject({
      name: "ConsoleApiError",
      kind: "not_found",
    });
  });

  it("PlatformPanel's create flow: create succeeds, then the same slug maps to slugTaken", async () => {
    const cp = fakeControlPlane();
    const api = new ConsoleApiClient({ baseUrl: "/cp", fetch: cp.fetchImpl });

    const first = await submitCreateTenant(api, { slug: "acme", name: "Acme", mode: "saas" });
    expect(first.ok).toBe(true);
    if (first.ok) expect(first.tenant.slug).toBe("acme");

    const dup = await submitCreateTenant(api, { slug: "acme", name: "Acme Again", mode: "saas" });
    expect(dup).toMatchObject({ ok: false, slugTaken: true });
  });

  it("mutations echo the rmt_csrf cookie end-to-end through the flows", async () => {
    const cp = fakeControlPlane();
    cp.addSession("s-1", "2026-07-28T10:00:00Z");
    const api = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: cp.fetchImpl,
      cookies: () => "rmt_csrf=tok-xyz",
    });

    await endSessionAndRefresh(api, "s-1");
    await submitCreateTenant(api, { slug: "acme", name: "Acme", mode: "saas" });

    // One POST per flow (the re-list GET carries no token by design).
    expect(cp.csrfSeen).toEqual(["tok-xyz", "tok-xyz"]);
  });
});
