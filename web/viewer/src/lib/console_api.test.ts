/**
 * Unit tests for the management-console API client (M3). A fake `fetch` records the request shape
 * (URL, method, credentials, headers, body) and returns canned responses, so we assert the exact
 * wire contract against `control-plane/http.go` without a running server — including the CSRF
 * double-submit hook (echo the `rmt_csrf` cookie as `X-CSRF-Token` on mutations only).
 */
import { describe, it, expect } from "vitest";
import {
  ConsoleApiClient,
  ConsoleApiError,
  CSRF_HEADER_NAME,
  isGroupSessionPolicyRow,
  csrfTokenFrom,
  ASSIGNABLE_ROLES,
  auditListPath,
  auditSummaryPath,
  sessionReportPath,
  errorKindFor,
  isHexColor,
  MACHINE_STATUSES,
  machinesListPath,
  type APIToken,
  type MachineProperty,
  type MgmtAuditEvent,
  type SessionRecord,
  type Tenant,
  type TenantWebhook,
} from "./console_api";

interface RecordedCall {
  url: string;
  init?: RequestInit;
}

/** A fake fetch that records calls and returns a canned Response per call. */
function fakeFetch(responder: (call: RecordedCall) => Response) {
  const calls: RecordedCall[] = [];
  const fn = (url: string, init?: RequestInit) => {
    const call = { url, init };
    calls.push(call);
    return Promise.resolve(responder(call));
  };
  return { fn, calls };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function headersOf(call: RecordedCall): Record<string, string> {
  return (call.init?.headers as Record<string, string> | undefined) ?? {};
}

const SESSION: SessionRecord = {
  id: "s-1",
  tenant_id: "t-1",
  machine_id: "pk-1",
  technician_id: "u-1",
  started_at: "2026-07-28T12:00:00Z",
  consent_policy: "none",
  granted_caps: ["system_info_read"],
  machine_group_id: "g-1",
  machine_device_id: "dev-1",
  machine_name: "LAB-VM",
  machine_alias: "",
  note: "",
};

const TENANT: Tenant = {
  id: "t-2",
  slug: "acme",
  name: "Acme Corp",
  deployment_mode: "saas",
  created_at: "2026-07-28T12:00:00Z",
  disabled: false,
};

describe("csrfTokenFrom", () => {
  it("extracts the rmt_csrf cookie from a document.cookie string", () => {
    expect(csrfTokenFrom("a=1; rmt_csrf=tok-123; b=2")).toBe("tok-123");
    expect(csrfTokenFrom("rmt_csrf=tok-123")).toBe("tok-123");
  });

  it("returns null when absent or empty and ignores prefix-named cookies", () => {
    expect(csrfTokenFrom("")).toBeNull();
    expect(csrfTokenFrom("a=1; b=2")).toBeNull();
    expect(csrfTokenFrom("rmt_csrf=")).toBeNull();
    expect(csrfTokenFrom("xrmt_csrf=nope")).toBeNull();
  });

  it("URI-decodes an encoded value", () => {
    expect(csrfTokenFrom("rmt_csrf=a%2Fb%3D")).toBe("a/b=");
  });

  it("returns the raw value unchanged when decodeURIComponent throws", () => {
    expect(csrfTokenFrom("rmt_csrf=%GG")).toBe("%GG");
  });
});

describe("errorKindFor", () => {
  it("maps the statuses handlers actually emit", () => {
    expect(errorKindFor(400)).toBe("bad_request");
    expect(errorKindFor(401)).toBe("unauthenticated");
    expect(errorKindFor(403)).toBe("forbidden");
    expect(errorKindFor(404)).toBe("not_found");
    expect(errorKindFor(409)).toBe("conflict");
    expect(errorKindFor(500)).toBe("server");
  });
});

describe("ConsoleApiClient reads", () => {
  it("listMachines GETs /machines with credentials and unwraps the envelope", async () => {
    const machines = [{ id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "M" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ machines }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.listMachines();

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/cp/machines");
    expect(calls[0].init?.method).toBe("GET");
    expect(calls[0].init?.credentials).toBe("include");
    expect(out).toEqual(machines);
  });

  it("listMachinesWithPresence keeps the presence_known flag and the enrichment fields", async () => {
    const machines = [
      {
        id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "M",
        os: "Windows 11 Pro", group_name: "Front Office", online: true,
        last_seen: "2026-08-01T10:00:00Z",
      },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ machines, presence_known: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.listMachinesWithPresence();

    expect(calls[0].url).toBe("/cp/machines");
    expect(out.presenceKnown).toBe(true);
    expect(out.machines).toEqual(machines);
  });

  it("listMachinesWithPresence reports presenceKnown=false when the server says so or omits it", async () => {
    const machines = [{ id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "M" }];
    for (const body of [{ machines, presence_known: false }, { machines }]) {
      const { fn } = fakeFetch(() => jsonResponse(body));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      const out = await client.listMachinesWithPresence();
      // An older control plane that omits the flag is read as UNKNOWN, not as "all offline".
      expect(out.presenceKnown).toBe(false);
      expect(out.machines[0].online).toBeUndefined();
    }
  });

  it("listMachinesWithPresence rejects with ConsoleApiError when the server returns no machines key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listMachinesWithPresence().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machines/i);
  });

  it("listSessions GETs /sessions and returns the rows", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ sessions: [SESSION] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listSessions()).toEqual([SESSION]);
    expect(calls[0].url).toBe("/cp/sessions");
  });

  it("listSessions appends the since/until window when given a filter", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ sessions: [] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.listSessions({ since: "2026-08-01T00:00:00Z", until: "2026-08-31T23:59:59Z" });
    expect(calls[0].url).toBe("/cp/sessions?since=2026-08-01T00%3A00%3A00Z&until=2026-08-31T23%3A59%3A59Z");
  });

  it("listLiveSessions returns only sessions whose ended_at is absent", async () => {
    // SESSION has no ended_at field — live. ENDED_SESSION has one — finished.
    const ended: SessionRecord = { ...SESSION, id: "s-2", ended_at: "2026-07-28T14:00:00Z" };
    const { fn } = fakeFetch(() => jsonResponse({ sessions: [SESSION, ended] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const live = await client.listLiveSessions();
    expect(live).toHaveLength(1);
    expect(live[0].id).toBe("s-1");
  });

  it("listLiveSessions treats a JSON null ended_at as live — Go nil-pointer serialization", async () => {
    // Go's encoding/json emits `"ended_at": null` for a nil *time.Time when omitempty is absent or
    // when a future struct-tag change drops it. `== null` in the filter handles both null and
    // undefined so we do not silently drop all badges in this case.
    const withNull = { ...SESSION, id: "s-3", ended_at: null } as unknown as SessionRecord;
    const { fn } = fakeFetch(() => jsonResponse({ sessions: [withNull] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const live = await client.listLiveSessions();
    expect(live).toHaveLength(1);
    expect(live[0].id).toBe("s-3");
  });

  it("listLiveSessions returns an empty list when all sessions have ended", async () => {
    const ended: SessionRecord = { ...SESSION, ended_at: "2026-07-28T14:00:00Z" };
    const { fn } = fakeFetch(() => jsonResponse({ sessions: [ended] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listLiveSessions()).toHaveLength(0);
  });

  it("sessionsByMachine GETs /reports/sessions-by-machine and unwraps sessions_by_machine", async () => {
    const rows = [
      { machine_id: "m-a", machine_name: "alpha", machine_group_id: "g-1", count: 3, total_seconds: 90 },
      { machine_id: "m-b", machine_name: "bravo", machine_group_id: "g-1", count: 1, total_seconds: 0 },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ sessions_by_machine: rows }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.sessionsByMachine()).toEqual(rows);
    expect(calls[0].url).toBe("/cp/reports/sessions-by-machine");
    expect(calls[0].init?.method).toBe("GET");
    expect(calls[0].init?.credentials).toBe("include");
  });

  it("sessionsByMachine appends the since/until window when given a filter", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ sessions_by_machine: [] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.sessionsByMachine({ since: "2026-08-01T00:00:00Z", until: "2026-08-31T23:59:59Z" });
    expect(calls[0].url).toBe(
      "/cp/reports/sessions-by-machine?since=2026-08-01T00%3A00%3A00Z&until=2026-08-31T23%3A59%3A59Z",
    );
  });

  it("sessionsByMachine rejects with ConsoleApiError when body has no sessions_by_machine key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.sessionsByMachine();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*sessions_by_machine/);
  });

  it("sessionsByTechnician GETs /reports/sessions-by-technician and unwraps sessions_by_technician", async () => {
    const rows = [
      { technician_id: "u-1", count: 5, total_seconds: 900 },
      { technician_id: "u-2", count: 1, total_seconds: 0 },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ sessions_by_technician: rows }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.sessionsByTechnician()).toEqual(rows);
    expect(calls[0].url).toBe("/cp/reports/sessions-by-technician");
    expect(calls[0].init?.method).toBe("GET");
    expect(calls[0].init?.credentials).toBe("include");
  });

  it("sessionsByTechnician rejects with ConsoleApiError when body has no sessions_by_technician key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.sessionsByTechnician();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*sessions_by_technician/);
  });

  it("listAudit omits the query without a limit and encodes one when given", async () => {
    const events: MgmtAuditEvent[] = [];
    const { fn, calls } = fakeFetch(() => jsonResponse({ events }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.listAudit();
    await client.listAudit(50);
    expect(calls[0].url).toBe("/cp/audit");
    expect(calls[1].url).toBe("/cp/audit?limit=50");
    expect(calls[1].init?.method).toBe("GET");
  });

  it("listTenants GETs /tenants", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ tenants: [TENANT] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listTenants()).toEqual([TENANT]);
    expect(calls[0].url).toBe("/cp/tenants");
  });

  it("platformWhoami grants nothing but explicit trues", async () => {
    for (const [body, want] of [
      [{ operator: true, mfa_ok: true, mfa_fresh: false }, { operator: true, mfa_ok: true, mfa_fresh: false }],
      [{}, { operator: false, mfa_ok: false, mfa_fresh: false }],
      [{ operator: "true", mfa_ok: 1, mfa_fresh: "yes" }, { operator: false, mfa_ok: false, mfa_fresh: false }],
    ] as const) {
      const { fn, calls } = fakeFetch(() => jsonResponse(body));
      expect(await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).platformWhoami()).toEqual(want);
      expect(calls[0].url).toBe("/cp/platform/me");
    }
  });

  it("listPlatformTenants GETs /platform/tenants and rejects a malformed body", async () => {
    const row = { ...TENANT, user_count: 3, unleased_machines: true };
    const { fn, calls } = fakeFetch(() => jsonResponse({ tenants: [row] }));
    expect(await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).listPlatformTenants()).toEqual([row]);
    expect(calls[0].url).toBe("/cp/platform/tenants");
    const bad = fakeFetch(() => jsonResponse({ tenants: {} }));
    const err = await new ConsoleApiClient({ baseUrl: "/cp", fetch: bad.fn }).listPlatformTenants().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
  });

  it("setTenantSuspended POSTs the typed slug and reason to suspend or resume", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ tenant: TENANT }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok" });
    await client.setTenantSuspended("t/1", true, "acme", "unpaid");
    await client.setTenantSuspended("t-2", false, "acme", "paid");
    expect(calls[0].url).toBe("/cp/platform/tenants/t%2F1/suspend");
    expect(calls[1].url).toBe("/cp/platform/tenants/t-2/resume");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ confirm_slug: "acme", reason: "unpaid" });
    expect((calls[0].init?.headers as Record<string, string>)["X-CSRF-Token"]).toBe("tok");
  });

  it("stepUp POSTs the code and maps a 409 to a conflict", async () => {
    const ok = fakeFetch(() => new Response(null, { status: 204 }));
    await new ConsoleApiClient({ baseUrl: "/cp", fetch: ok.fn }).stepUp("123456");
    expect(ok.calls[0].url).toBe("/cp/auth/step-up");
    expect(JSON.parse(ok.calls[0].init?.body as string)).toEqual({ code: "123456" });
    const gone = fakeFetch(() => jsonResponse({ error: "your session ended or your second factor changed; sign in again" }, 409));
    const err = (await new ConsoleApiClient({ baseUrl: "/cp", fetch: gone.fn }).stepUp("1").catch((e: unknown) => e)) as ConsoleApiError;
    expect(err.kind).toBe("conflict");
  });

  it("listTenants rejects with a server ConsoleApiError when tenants key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listTenants().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*tenants/);
  });

  it("GETs never send a CSRF header even when the cookie exists", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ machines: [] }));
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fn,
      cookies: () => "rmt_csrf=tok-123",
    });
    await client.listMachines();
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBeUndefined();
  });

  it("throws a typed server failure on a malformed (envelope-less) success body", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ nope: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listMachines().catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
  });
});

describe("ConsoleApiClient mutations", () => {
  it("startSession POSTs the DEVICE id as machine_id and unwraps the session", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: SESSION }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.startSession("dev-1");

    expect(calls[0].url).toBe("/cp/sessions");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.credentials).toBe("include");
    expect(headersOf(calls[0])["content-type"]).toBe("application/json");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ machine_id: "dev-1" });
    expect(out).toEqual(SESSION);
  });

  it("startSession rejects with ConsoleApiError(200) when the response envelope has session: null", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ session: null }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.startSession("dev-1").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).status).toBe(200);
    expect((err as ConsoleApiError).message).toContain('malformed response (no "session")');
  });

  it("endSession POSTs /sessions/{id}/end with no body and unwraps the session", async () => {
    const ended = { ...SESSION, ended_at: "2026-07-28T12:30:00Z" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: ended }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.endSession("s-1");

    expect(calls[0].url).toBe("/cp/sessions/s-1/end");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.keepalive).toBe(true);
    expect(calls[0].init?.body).toBeUndefined();
    expect(out).toEqual(ended);
  });

  it("ingestAudit passes keepalive through to fetch only when asked", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ accepted: 1, tail_seq: 0, tail_hash: "h" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.ingestAudit({ session_id: "s", events: [{}] }, { keepalive: true });
    await client.ingestAudit({ session_id: "s", events: [{}] });
    expect(calls[0].url).toBe("/cp/audit/ingest");
    expect(calls[0].init?.keepalive).toBe(true);
    expect(calls[1].init?.keepalive).toBeUndefined();
  });

  it("endSession URI-encodes a hostile session id into the path", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: SESSION }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.endSession("a/b?c");
    expect(calls[0].url).toBe("/cp/sessions/a%2Fb%3Fc/end");
  });

  it("endSession rejects with ConsoleApiError('server') when the response body has no session key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.endSession("s-1").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*session/i);
  });

  it("setSessionNote PATCHes /sessions/{id}/note with the note body and unwraps the session", async () => {
    const noted = { ...SESSION, note: "handoff to bob" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: noted }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.setSessionNote("s-1", "handoff to bob");

    expect(calls[0].url).toBe("/cp/sessions/s-1/note");
    expect(calls[0].init?.method).toBe("PATCH");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ note: "handoff to bob" });
    expect(out).toEqual(noted);
  });

  it("setSessionNote URI-encodes a hostile session id into the path", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: SESSION }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setSessionNote("a/b?c", "x");
    expect(calls[0].url).toBe("/cp/sessions/a%2Fb%3Fc/note");
  });

  it("setSessionNote rejects with ConsoleApiError('server') when the response body has no session key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.setSessionNote("s-1", "a note").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*session/i);
  });

  it("createTenant POSTs slug/name (+ deployment_mode only when given)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ tenant: TENANT }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.createTenant({ slug: "acme", name: "Acme Corp" });
    await client.createTenant({ slug: "acme2", name: "Acme 2", deploymentMode: "self_hosted" });

    expect(calls[0].url).toBe("/cp/platform/tenants");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ slug: "acme", name: "Acme Corp" });
    expect(JSON.parse(calls[1].init?.body as string)).toEqual({
      slug: "acme2",
      name: "Acme 2",
      deployment_mode: "self_hosted",
    });
  });

  it("createTenant rejects with ConsoleApiError(server) when response body has no tenant key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.createTenant({ slug: "x", name: "X" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*tenant/i);
  });

  it("mutations echo the rmt_csrf cookie as X-CSRF-Token when present", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: SESSION }, 201));
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fn,
      cookies: () => "other=1; rmt_csrf=tok-123",
    });
    await client.startSession("dev-1");
    await client.endSession("s-1");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-123");
    expect(headersOf(calls[1])[CSRF_HEADER_NAME]).toBe("tok-123");
  });

  it("mutations omit the CSRF header when no cookie exists (pre-CSRF control plane)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: SESSION }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "" });
    await client.startSession("dev-1");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBeUndefined();
  });
});

describe("ConsoleApiClient credential setup links (docs/01 §5)", () => {
  const TOKEN = {
    id: "ct-1",
    tenant_id: "t-1",
    user_id: "u-9",
    created_by: "u-1",
    created_at: "2026-08-16T12:00:00Z",
    expires_at: "2026-08-16T13:00:00Z",
    consumed: false,
    revoked: false,
  };

  it("issuePasswordReset POSTs the caller password (+ ttl only when given) and maps the response", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ token: "setup-secret", credential_token: TOKEN, first_provision: true }, 201),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.issuePasswordReset("u-9", "my-password");
    await client.issuePasswordReset("u-9", "my-password", 900);

    expect(calls[0].url).toBe("/cp/users/u-9/password-reset");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ password: "my-password" });
    // ttl_seconds appears ONLY when the caller passes one.
    expect(JSON.parse(calls[1].init?.body as string)).toEqual({ password: "my-password", ttl_seconds: 900 });
    expect(out).toEqual({ token: "setup-secret", credentialToken: TOKEN, firstProvision: true });
  });

  it("issuePasswordReset reports firstProvision=false when the server flag is not exactly true", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({ token: "s", credential_token: TOKEN, first_provision: false }, 201),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect((await client.issuePasswordReset("u-9", "pw")).firstProvision).toBe(false);
  });

  it("issuePasswordReset URI-encodes a hostile user id", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ token: "s", credential_token: TOKEN, first_provision: true }, 201),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.issuePasswordReset("a/b?c", "pw");
    expect(calls[0].url).toBe("/cp/users/a%2Fb%3Fc/password-reset");
  });

  it("issuePasswordReset throws a typed error when the response omits the token", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ credential_token: TOKEN, first_provision: true }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.issuePasswordReset("u-9", "pw")).rejects.toBeInstanceOf(ConsoleApiError);
  });

  it("issuePasswordReset throws ConsoleApiError matching /no.*credential_token/ when credential_token is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ token: "s", first_provision: true }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.issuePasswordReset("u-9", "pw");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).message).toMatch(/no.*credential_token/);
  });

  it("revokePasswordReset DELETEs the reset resource and returns the revoked count", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ revoked: 2 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const n = await client.revokePasswordReset("u-9");
    expect(calls[0].url).toBe("/cp/users/u-9/password-reset");
    expect(calls[0].init?.method).toBe("DELETE");
    expect(n).toBe(2);
  });

  it("redeemPasswordReset POSTs token + new_password to the PUBLIC endpoint and maps the result", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ changed: true, sessions_revoked: 3 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const out = await client.redeemPasswordReset("setup-secret", "new-strong-pw");
    expect(calls[0].url).toBe("/cp/auth/password/redeem");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      token: "setup-secret",
      new_password: "new-strong-pw",
    });
    expect(out).toEqual({ changed: true, sessions_revoked: 3 });
  });

  it("redeemPasswordReset surfaces the server's error message (a bad/spent token)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "invalid or expired credential token" }, 403));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.redeemPasswordReset("bad", "pw")).rejects.toThrow(/invalid or expired/);
  });

  it("redeemPasswordReset returns changed:false and sessions_revoked:0 when server returns { changed: 1 }", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ changed: 1 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const out = await client.redeemPasswordReset("tok", "pw");
    expect(out.changed).toBe(false);
    expect(out.sessions_revoked).toBe(0);
  });

  it("revokePasswordReset returns 0 when the server returns {} (revoked field absent)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const n = await client.revokePasswordReset("u-9");
    expect(n).toBe(0);
  });
});

describe("auditListPath (audit search)", () => {
  it("is bare /audit with no limit or filter", () => {
    expect(auditListPath()).toBe("/audit");
    expect(auditListPath(undefined, { action: "  ", targetKind: "" })).toBe("/audit"); // whitespace = none
  });

  it("adds limit alone", () => {
    expect(auditListPath(50)).toBe("/audit?limit=50");
  });

  it("adds action and target_kind (trimmed), omitting empty ones", () => {
    expect(auditListPath(undefined, { action: " machine.enroll " })).toBe("/audit?action=machine.enroll");
    expect(auditListPath(100, { action: "session.start", targetKind: "session" })).toBe(
      "/audit?limit=100&action=session.start&target_kind=session",
    );
    expect(auditListPath(undefined, { targetKind: "machine" })).toBe("/audit?target_kind=machine");
  });

  it("adds actor and the since/until time bounds (trimmed), omitting empty ones", () => {
    expect(auditListPath(undefined, { actor: " u-9 " })).toBe("/audit?actor=u-9");
    expect(auditListPath(undefined, { since: "2026-08-17T12:00:00Z" })).toBe(
      "/audit?since=2026-08-17T12%3A00%3A00Z",
    );
    expect(auditListPath(undefined, { until: "2026-08-17T13:00:00Z" })).toBe(
      "/audit?until=2026-08-17T13%3A00%3A00Z",
    );
    // All five filters together, in the fixed param order.
    expect(
      auditListPath(25, {
        action: "session.start",
        targetKind: "session",
        actor: "u-9",
        since: "2026-08-17T12:00:00Z",
        until: "2026-08-17T13:00:00Z",
      }),
    ).toBe(
      "/audit?limit=25&action=session.start&target_kind=session&actor=u-9&since=2026-08-17T12%3A00%3A00Z&until=2026-08-17T13%3A00%3A00Z",
    );
  });
});

describe("sessionReportPath (session reports since/until)", () => {
  it("omits the query when unbounded and encodes the since/until window otherwise", () => {
    expect(sessionReportPath("/reports/sessions-by-machine")).toBe("/reports/sessions-by-machine");
    expect(sessionReportPath("/reports/sessions-by-machine", { since: "  ", until: "" })).toBe(
      "/reports/sessions-by-machine",
    ); // whitespace = none
    expect(sessionReportPath("/reports/sessions-by-technician", { since: "2026-08-01T00:00:00Z" })).toBe(
      "/reports/sessions-by-technician?since=2026-08-01T00%3A00%3A00Z",
    );
    expect(
      sessionReportPath("/reports/sessions-by-machine", {
        since: "2026-08-01T00:00:00Z",
        until: "2026-08-31T23:59:59Z",
      }),
    ).toBe("/reports/sessions-by-machine?since=2026-08-01T00%3A00%3A00Z&until=2026-08-31T23%3A59%3A59Z");
  });
});

describe("auditSummaryPath (reports)", () => {
  it("omits the query when no filter and encodes the shared filter otherwise", () => {
    expect(auditSummaryPath()).toBe("/audit/summary");
    expect(auditSummaryPath({ since: "  ", until: "" })).toBe("/audit/summary"); // whitespace = none
    expect(auditSummaryPath({ actor: " u-9 " })).toBe("/audit/summary?actor=u-9");
    expect(
      auditSummaryPath({
        action: "machine.enroll",
        targetKind: "machine",
        since: "2026-08-17T12:00:00Z",
        until: "2026-08-17T13:00:00Z",
      }),
    ).toBe(
      "/audit/summary?action=machine.enroll&target_kind=machine&since=2026-08-17T12%3A00%3A00Z&until=2026-08-17T13%3A00%3A00Z",
    );
  });
});

describe("ConsoleApiClient.auditSummary", () => {
  it("GETs /audit/summary and unwraps the summary envelope", async () => {
    const summary = [
      { action: "machine.enroll", count: 3 },
      { action: "session.start", count: 1 },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ summary }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.auditSummary({ since: "2026-08-17T12:00:00Z" })).toEqual(summary);
    expect(calls[0].url).toBe("/cp/audit/summary?since=2026-08-17T12%3A00%3A00Z");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("rejects with a server ConsoleApiError when the response body has no summary key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.auditSummary().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*summary/);
  });
});

describe("ConsoleApiClient.listAudit filter", () => {
  it("GETs /audit with the limit + filter query", async () => {
    const events = [{ id: "e1", tenant_id: "t", action: "machine.enroll", occurred_at: "2026-01-01T00:00:00Z" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ events }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.listAudit(25, { action: "machine.enroll", targetKind: "machine" });
    expect(calls[0].url).toBe("/cp/audit?limit=25&action=machine.enroll&target_kind=machine");

    await client.listAudit(); // no limit, no filter
    expect(calls[1].url).toBe("/cp/audit");
  });

  it("rejects with a server ConsoleApiError when the response body has no events key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listAudit().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*events/);
  });
});

describe("machinesListPath (fleet property filter)", () => {
  it("omits the query entirely when there is no key", () => {
    expect(machinesListPath()).toBe("/machines");
    expect(machinesListPath({ propertyKey: "" })).toBe("/machines");
    expect(machinesListPath({ propertyKey: "   " })).toBe("/machines"); // whitespace-only = no filter
  });

  it("adds property_key alone (any value) and trims the key", () => {
    expect(machinesListPath({ propertyKey: " site " })).toBe("/machines?property_key=site");
    expect(machinesListPath({ propertyKey: "site", propertyValue: "" })).toBe("/machines?property_key=site");
  });

  it("adds property_value only when non-empty, and URI-encodes both segments", () => {
    expect(machinesListPath({ propertyKey: "site", propertyValue: "HQ" })).toBe(
      "/machines?property_key=site&property_value=HQ",
    );
    expect(machinesListPath({ propertyKey: "a b", propertyValue: "c&d" })).toBe(
      "/machines?property_key=a%20b&property_value=c%26d",
    );
  });
});

describe("ConsoleApiClient.listMachines filter", () => {
  it("GETs /machines with the property filter query", async () => {
    const machines = [{ id: "pk-1", tenant_id: "t-1", device_id: "dev-1", group_id: "g-1", name: "M" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ machines }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.listMachines({ propertyKey: "site", propertyValue: "HQ" });
    expect(calls[0].url).toBe("/cp/machines?property_key=site&property_value=HQ");
    expect(calls[0].init?.method).toBe("GET");

    await client.listMachines(); // unfiltered
    expect(calls[1].url).toBe("/cp/machines");
  });
});

describe("ConsoleApiClient machine properties", () => {
  it("listMachineProperties GETs /machines/{id}/properties and unwraps the envelope", async () => {
    const properties: MachineProperty[] = [{ key: "rack", value: "R7" }, { key: "site", value: "HQ" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ properties }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    expect(await client.listMachineProperties("pk-1")).toEqual(properties);
    expect(calls[0].url).toBe("/cp/machines/pk-1/properties");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listMachineProperties rejects with server ConsoleApiError when body has no properties key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    let err: unknown;
    try {
      await client.listMachineProperties("pk-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*properties/);
  });

  it("setMachineProperty PUTs {value}, echoes CSRF, and URI-encodes both path segments", async () => {
    const property: MachineProperty = { key: "a/b", value: "v" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ property }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    expect(await client.setMachineProperty("pk 1", "a/b", "v")).toEqual(property);
    // The machine PK and the free-text key both go in the PATH, so both are URI-encoded.
    expect(calls[0].url).toBe("/cp/machines/pk%201/properties/a%2Fb");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ value: "v" });
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("setMachineProperty rejects with a server ConsoleApiError when response body has no property key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.setMachineProperty("pk-1", "site", "hq").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*property/);
  });

  it("deleteMachineProperty DELETEs the path and echoes CSRF", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ deleted: true, key: "site" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    await client.deleteMachineProperty("pk-1", "site");
    expect(calls[0].url).toBe("/cp/machines/pk-1/properties/site");
    expect(calls[0].init?.method).toBe("DELETE");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("deleteMachineProperty maps a 404 to a not_found ConsoleApiError", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "unknown property" }, 404));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.deleteMachineProperty("pk-1", "gone").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("not_found");
  });
});

describe("ConsoleApiClient machine status (docs/01 §4)", () => {
  it("setMachineStatus POSTs /machines/{id}/status with {status} and returns the machine", async () => {
    const machine = { id: "pk 1", tenant_id: "t", device_id: "d", group_id: "g", name: "H", status: "quarantined" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.setMachineStatus("pk 1", "quarantined")).toEqual(machine);
    expect(calls[0].url).toBe("/cp/machines/pk%201/status"); // PK is URI-encoded
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ status: "quarantined" });
  });

  it("setMachineStatus rejects with server ConsoleApiError when response body has no machine key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.setMachineStatus("pk-1", "quarantined").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*machine/);
  });

  it("MACHINE_STATUSES mirrors the Go constants (active, quarantined, retired)", () => {
    expect([...MACHINE_STATUSES]).toEqual(["active", "quarantined", "retired"]);
  });

  it("setMachineGroup POSTs /machines/{id}/group with {group_id} and returns the machine", async () => {
    const machine = { id: "pk-1", tenant_id: "t", device_id: "d", group_id: "g-2", name: "H", status: "active" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.setMachineGroup("pk 1", "g-2")).toEqual(machine);
    expect(calls[0].url).toBe("/cp/machines/pk%201/group"); // PK is URI-encoded
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ group_id: "g-2" });
  });

  it("setMachineGroup rejects with server ConsoleApiError when response body has no machine key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.setMachineGroup("pk-1", "g-2").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*machine/);
  });

  it("setMachineAlias PATCHes /machines/{id}/alias with {alias} and returns the machine", async () => {
    const machine = { id: "pk-1", tenant_id: "t", device_id: "d", group_id: "g", name: "H", alias: "Reception PC" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.setMachineAlias("pk 1", "Reception PC")).toEqual(machine);
    expect(calls[0].url).toBe("/cp/machines/pk%201/alias"); // PK is URI-encoded
    expect(calls[0].init?.method).toBe("PATCH");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ alias: "Reception PC" });
  });

  it("setMachineAlias sends an empty alias to CLEAR it", async () => {
    const machine = { id: "pk-1", tenant_id: "t", device_id: "d", group_id: "g", name: "H" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setMachineAlias("pk-1", "");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ alias: "" });
  });

  it("setMachineAlias rejects with ConsoleApiError(server) when response body has no machine key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.setMachineAlias("pk-1", "Reception PC").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machine/);
  });

  it("setMachineNote PATCHes /machines/{id}/note with {note} (verbatim, multi-line) and returns the machine", async () => {
    const machine = { id: "pk-1", tenant_id: "t", device_id: "d", group_id: "g", name: "H", note: "line1\nline2" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.setMachineNote("pk 1", "line1\nline2")).toEqual(machine);
    expect(calls[0].url).toBe("/cp/machines/pk%201/note"); // PK is URI-encoded
    expect(calls[0].init?.method).toBe("PATCH");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ note: "line1\nline2" });
  });

  it("setMachineNote sends an empty note to CLEAR it", async () => {
    const machine = { id: "pk-1", tenant_id: "t", device_id: "d", group_id: "g", name: "H" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setMachineNote("pk-1", "");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ note: "" });
  });

  it("setMachineNote rejects with ConsoleApiError(server) when response body has no machine key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.setMachineNote("pk-1", "a note");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machine/);
  });

  it("bulkSetMachineStatus POSTs /machines/bulk-status with {machine_ids,status} and unwraps results", async () => {
    const results = [
      { machine_id: "m-1", ok: true },
      { machine_id: "m-2", ok: false, error: "denied" },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ results }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.bulkSetMachineStatus(["m-1", "m-2"], "quarantined")).toEqual(results);
    expect(calls[0].url).toBe("/cp/machines/bulk-status");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      machine_ids: ["m-1", "m-2"],
      status: "quarantined",
    });
  });

  it("bulkSetMachineGroup POSTs /machines/bulk-group with {machine_ids,group_id} and unwraps results", async () => {
    const results = [
      { machine_id: "m-1", ok: true },
      { machine_id: "m-2", ok: false, error: "denied" },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ results }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.bulkSetMachineGroup(["m-1", "m-2"], "g-9")).toEqual(results);
    expect(calls[0].url).toBe("/cp/machines/bulk-group");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      machine_ids: ["m-1", "m-2"],
      group_id: "g-9",
    });
  });

  it("bulkSetMachineGroup throws a typed server error when results is missing", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ nope: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.bulkSetMachineGroup(["m-1"], "g-9").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*results/);
  });

  it("bulkSetMachineStatus throws a typed server error when results is missing", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ nope: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.bulkSetMachineStatus(["m-1"], "active").catch((e) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
  });
});

describe("ConsoleApiClient tenant IP allow-list", () => {
  it("getTenantIPAllowlist GETs /tenant/ip-allowlist and returns cidrs + your_ip", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ cidrs: ["10.0.0.0/8", "192.0.2.0/24"], your_ip: "192.0.2.1" }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    expect(await client.getTenantIPAllowlist()).toEqual({
      cidrs: ["10.0.0.0/8", "192.0.2.0/24"],
      yourIp: "192.0.2.1",
    });
    expect(calls[0].url).toBe("/cp/tenant/ip-allowlist");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("addTenantIPAllowlistEntry POSTs {cidr} and echoes CSRF", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ cidr: "203.0.113.0/24" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    await client.addTenantIPAllowlistEntry("203.0.113.0/24");
    expect(calls[0].url).toBe("/cp/tenant/ip-allowlist");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ cidr: "203.0.113.0/24" });
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("addTenantIPAllowlistEntry surfaces the anti-lockout 400 as a ConsoleApiError", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "this would lock you out: your current IP 192.0.2.1 is not covered by the resulting allow-list" }, 400));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.addTenantIPAllowlistEntry("10.0.0.0/8").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.message).toContain("lock you out");
  });

  it("deleteTenantIPAllowlistEntry DELETEs with the CIDR as a URI-encoded ?cidr= query param", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ deleted: true, cidr: "10.0.0.0/8" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    await client.deleteTenantIPAllowlistEntry("10.0.0.0/8");
    // The '/' in the CIDR is why it rides a query param, not a path segment — and it is URI-encoded.
    expect(calls[0].url).toBe("/cp/tenant/ip-allowlist?cidr=10.0.0.0%2F8");
    expect(calls[0].init?.method).toBe("DELETE");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("getTenantIPAllowlist rejects with ConsoleApiError when cidrs key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.getTenantIPAllowlist()).rejects.toBeInstanceOf(ConsoleApiError);
    const err = await client.getTenantIPAllowlist().catch((e) => e) as ConsoleApiError;
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*cidrs/i);
  });

  it("getTenantIPAllowlist resolves with yourIp empty string when your_ip is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ cidrs: ["10.0.0.0/8"] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.getTenantIPAllowlist()).resolves.toEqual({
      cidrs: ["10.0.0.0/8"],
      yourIp: "",
    });
  });
});

describe("ConsoleApiClient dynamic groups", () => {
  it("listDynamicGroups GETs /dynamic-groups and unwraps the envelope", async () => {
    const groups = [{ id: "g1", name: "HQ", property_key: "site", property_value: "HQ" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ groups }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    expect(await client.listDynamicGroups()).toEqual(groups);
    expect(calls[0].url).toBe("/cp/dynamic-groups");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listDynamicGroups rejects with a server ConsoleApiError when response body has no groups key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const err = await client.listDynamicGroups().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*groups/);
  });

  it("createDynamicGroup POSTs {name, property_key, property_value}, plucks group, echoes CSRF", async () => {
    const group = { id: "g2", name: "Prod", property_key: "env", property_value: "prod" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ group }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    expect(await client.createDynamicGroup({ name: "Prod", propertyKey: "env", propertyValue: "prod" })).toEqual(group);
    expect(calls[0].url).toBe("/cp/dynamic-groups");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ name: "Prod", property_key: "env", property_value: "prod" });
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("createDynamicGroup maps a 409 name collision to a conflict ConsoleApiError", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "a dynamic group with that name already exists" }, 409));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createDynamicGroup({ name: "HQ", propertyKey: "site" }).catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("conflict");
  });

  it("createDynamicGroup rejects with a server ConsoleApiError when response body has no group key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createDynamicGroup({ name: "HQ", propertyKey: "site" }).catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*group/);
  });

  it("deleteDynamicGroup DELETEs the id path and echoes CSRF", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ deleted: true, id: "g1" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn, cookies: () => "rmt_csrf=tok-1" });

    await client.deleteDynamicGroup("g 1");
    expect(calls[0].url).toBe("/cp/dynamic-groups/g%201");
    expect(calls[0].init?.method).toBe("DELETE");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
  });

  it("resolveDynamicGroup GETs /dynamic-groups/{id}/machines and unwraps the members", async () => {
    const machines = [{ id: "m1", tenant_id: "t", device_id: "dev-1", group_id: "g", name: "M1" }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ group: { id: "g1" }, machines }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    expect(await client.resolveDynamicGroup("g1")).toEqual(machines);
    expect(calls[0].url).toBe("/cp/dynamic-groups/g1/machines");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("resolveDynamicGroup rejects with ConsoleApiError(server) when body has no machines key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const err = await client.resolveDynamicGroup("g1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machines/);
  });
});

describe("ConsoleApiClient machine groups (docs/01 §4)", () => {
  it("listMachineGroups GETs /machine-groups and unwraps the machine_groups envelope", async () => {
    const machine_groups = [
      { id: "g1", name: "Alpha" },
      { id: "g2", name: "Zeta" },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_groups }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listMachineGroups()).toEqual(machine_groups);
    expect(calls[0].url).toBe("/cp/machine-groups");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listMachineGroups rejects with ConsoleApiError(server) when body has no machine_groups key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listMachineGroups().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machine_groups/);
  });

  it("createMachineGroup POSTs {name}, plucks machine_group, and returns it", async () => {
    const machine_group = { id: "g9", name: "HQ" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_group }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.createMachineGroup({ name: "HQ" })).toEqual(machine_group);
    expect(calls[0].url).toBe("/cp/machine-groups");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ name: "HQ" });
  });

  it("createMachineGroup rejects with ConsoleApiError(server) when body has no machine_group key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.createMachineGroup({ name: "HQ" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machine_group/);
  });

  it("renameMachineGroup PATCHes {name} to /machine-groups/{id} and returns the group", async () => {
    const machine_group = { id: "g9", name: "New HQ" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_group }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.renameMachineGroup("g9", "New HQ")).toEqual(machine_group);
    expect(calls[0].url).toBe("/cp/machine-groups/g9");
    expect(calls[0].init?.method).toBe("PATCH");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ name: "New HQ" });
  });

  it("renameMachineGroup URI-encodes a hostile id", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_group: { id: "x", name: "n" } }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.renameMachineGroup("a/b?c", "n");
    expect(calls[0].url).toBe("/cp/machine-groups/a%2Fb%3Fc");
  });

  it("createMachineGroup sends parent_id ONLY for a subgroup (a top-level create is byte-identical to before)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_group: { id: "c1", name: "Lab", parent_id: "p1" } }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.createMachineGroup({ name: "Lab", parentId: "p1" });
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ name: "Lab", parent_id: "p1" });
    await client.createMachineGroup({ name: "Top", parentId: null });
    await client.createMachineGroup({ name: "Top2" });
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ name: "Top" });
    expect(JSON.parse(String(calls[2].init?.body))).toEqual({ name: "Top2" });
  });

  it("moveMachineGroup POSTs {parent_id} to /machine-groups/{id}/move; null = top level; the id is URI-encoded", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ machine_group: { id: "g9", name: "x", parent_id: "p1" } }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.moveMachineGroup("g9", "p1");
    await client.moveMachineGroup("g9", null);
    await client.moveMachineGroup("a/b?c", null);
    expect(calls[0].url).toBe("/cp/machine-groups/g9/move");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ parent_id: "p1" });
    // null must be SENT (JSON null), not omitted: omitting would read as "no change" to a strict server.
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ parent_id: null });
    expect(calls[2].url).toBe("/cp/machine-groups/a%2Fb%3Fc/move");
  });

  it("moveMachineGroup carries the server's 409 reason verbatim in the error message", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "would create a cycle" }, 409));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.moveMachineGroup("g9", "p1").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).status).toBe(409);
    expect((err as ConsoleApiError).message).toBe("could not move machine group: would create a cycle");
  });

  it("renameMachineGroup rejects with ConsoleApiError(server) when response body lacks machine_group", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.renameMachineGroup("g9", "New HQ");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*machine_group/);
  });

  it("deleteMachineGroup DELETEs /machine-groups/{id}", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ deleted: true, id: "g9" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.deleteMachineGroup("g9");
    expect(calls[0].url).toBe("/cp/machine-groups/g9");
    expect(calls[0].init?.method).toBe("DELETE");
  });

  it("deleteMachineGroup surfaces the server's 409 (group in use)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "group still has machines; move or remove them first" }, 409));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.deleteMachineGroup("g9")).rejects.toThrow(/still has machines/);
  });

  it("listGroupSessionPolicyView returns the server effective map, null from an older server, and fails on a malformed one", async () => {
    const policies = [{ group_id: "g1", max_concurrent_sessions: 3 }];
    const effective = { g1: { enforce_view_only: true, conflict: "x" } };
    const mk = (body: unknown) =>
      new ConsoleApiClient({ baseUrl: "/cp", fetch: fakeFetch(() => jsonResponse(body)).fn });
    expect(await mk({ policies, effective }).listGroupSessionPolicyView()).toEqual({ policies, effective });
    expect((await mk({ policies }).listGroupSessionPolicyView()).effective).toBeNull();
    await expect(mk({ policies, effective: { g1: { enforce_view_only: "yes" } } }).listGroupSessionPolicyView()).rejects.toThrow(/bad effective/);
    await expect(mk({ policies, effective: [] }).listGroupSessionPolicyView()).rejects.toThrow(/bad effective/);
    // The old call is unchanged.
    expect(await mk({ policies, effective }).listGroupSessionPolicies()).toEqual(policies);
  });

  it("listGroupSessionPolicies GETs /machine-groups/session-policies and unwraps the policies envelope", async () => {
    const policies = [{ group_id: "g1", max_concurrent_sessions: 3 }];
    const { fn, calls } = fakeFetch(() => jsonResponse({ policies }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listGroupSessionPolicies()).toEqual(policies);
    expect(calls[0].url).toBe("/cp/machine-groups/session-policies");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listGroupSessionPolicies rejects with a server ConsoleApiError when response body omits the policies key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.listGroupSessionPolicies();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*policies/);
  });

  it("listGroupSessionPolicies rejects a row with a wrong-typed setting instead of letting it seed a default", async () => {
    // Each of these would otherwise be drawn (and saved back by the full-overwrite PUT) as its zero value.
    const bad: unknown[] = [
      null,
      { max_concurrent_sessions: 1 },
      { group_id: "g1", enforce_view_only: "true" },
      { group_id: "g1", max_session_duration_seconds: null },
      { group_id: "g1", max_idle_seconds: -1 },
      { group_id: "g1", max_concurrent_sessions: 1.5 },
    ];
    for (const row of bad) {
      const { fn } = fakeFetch(() => jsonResponse({ policies: [{ group_id: "ok" }, row] }));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      const err = await client.listGroupSessionPolicies().then(() => null, (e: unknown) => e);
      expect(err, JSON.stringify(row)).toBeInstanceOf(ConsoleApiError);
      expect((err as ConsoleApiError).kind).toBe("server");
      expect((err as ConsoleApiError).message).toMatch(/bad policy row/);
    }
  });

  it("isGroupSessionPolicyRow accepts a full row and a row from a server that predates later settings", () => {
    expect(
      isGroupSessionPolicyRow({
        group_id: "g1",
        max_concurrent_sessions: 2,
        enforce_view_only: true,
        allow_backstage_under_view_only: false,
        prohibit_recording: false,
        require_recording: true,
        max_session_duration_seconds: 3600,
        max_idle_seconds: 0,
      }),
    ).toBe(true);
    expect(isGroupSessionPolicyRow({ group_id: "g1", max_concurrent_sessions: 3, enforce_view_only: false })).toBe(true);
  });

  it("connectAttendedSession carries the signed session_policy through to the caller", async () => {
    // The ATTENDED half of the same regression. An attended machine is ephemeral but NOT group-less —
    // redemption enrols it into the invite's group — so a per-group view-only mandate applies, and this
    // is the ONLY place the attended connect response is decoded. Deleting the pluck restores a complete
    // bypass of the mandate for guest-initiated sessions, silently.
    const { fn } = fakeFetch(() =>
      jsonResponse({
        session: { id: "att-1", group_id: "g-1", device_id: "d-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "att-1", ticket: {} },
        session_policy: { access: "view_only", signed: '{"claims":{},"sig":"ab"}' },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const connected = await client.connectAttendedSession("att-1");
    expect(connected.session_policy).toEqual({
      access: "view_only",
      signed: '{"claims":{},"sig":"ab"}',
    });
  });

  it("connectAttendedSession omits session_policy when the group enforces nothing", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({
        session: { id: "att-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "att-1", ticket: {} },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect((await client.connectAttendedSession("att-1")).session_policy).toBeUndefined();
  });

  it("connectAttendedSession REJECTS a malformed session_policy rather than dropping it", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({
        session: { id: "att-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "att-1", ticket: {} },
        session_policy: { access: "view_only" },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.connectAttendedSession("att-1")).rejects.toThrow(/session_policy/);
  });

  it("startBrokeredSession carries the signed session_policy through to the caller", async () => {
    // THE REGRESSION (loop 80, caught by the adversarial review). This method is the ONLY place the
    // start response is decoded, so a field it does not pluck does not exist for the rest of the app —
    // no matter how many types declare it. session_policy was declared everywhere and read nowhere, so
    // the viewer installed nothing and the entire per-group view-only feature was inert while the Go
    // tests, the unit tests and the e2e all passed.
    const { fn } = fakeFetch(() =>
      jsonResponse({
        session: { id: "s-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "s-1", ticket: {} },
        session_policy: { access: "view_only", signed: '{"claims":{},"sig":"ab"}' },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const started = await client.startBrokeredSession("d-1");
    expect(started.session_policy).toEqual({
      access: "view_only",
      signed: '{"claims":{},"sig":"ab"}',
    });
  });

  it("startBrokeredSession tolerates a response with no session_policy", async () => {
    // A control plane with no grant issuer wired mints none — that must stay a clean success, not an
    // error, or every dev/self-hosted deployment breaks.
    const { fn } = fakeFetch(() =>
      jsonResponse({
        session: { id: "s-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "s-1", ticket: {} },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const started = await client.startBrokeredSession("d-1");
    expect(started.session_policy).toBeUndefined();
    expect(started.session.id).toBe("s-1");
  });

  it("renewSessionPolicy POSTs the lease route and unwraps the lease (docs/25 F03)", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session_policy: {
          access: "control",
          signed: '{"claims":{},"sig":"ab"}',
          lease_ttl_ms: 30000,
          expires_at_ms: 1730000030000,
        },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const lease = await client.renewSessionPolicy("s-1");

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/cp/sessions/s-1/policy");
    expect(calls[0].init?.method).toBe("POST");
    expect(lease).toEqual({
      access: "control",
      signed: '{"claims":{},"sig":"ab"}',
      lease_ttl_ms: 30000,
      expires_at_ms: 1730000030000,
    });
  });

  it("renewSessionPolicy REJECTS a lease with no usable TTL rather than renewing blind", async () => {
    // `lease_ttl_ms` is what the renewal cadence is computed from. A missing or zero one would make
    // the console schedule its next renewal at 0 ms (a request storm) or never — and the session
    // would die at the agent's deadline either way. Loud beats silent.
    for (const bad of [
      { access: "control", signed: "{}" },
      { access: "control", signed: "{}", lease_ttl_ms: 0, expires_at_ms: 1 },
      { access: "control", signed: "", lease_ttl_ms: 30000, expires_at_ms: 1 },
    ]) {
      const { fn } = fakeFetch(() => jsonResponse({ session_policy: bad }));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.renewSessionPolicy("s-1")).rejects.toThrow(/session_policy/);
    }
  });

  it("renewSessionPolicy REJECTS when the response body omits session_policy entirely", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.renewSessionPolicy("s-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).message).toMatch(/session_policy/);
  });

  it("renewSessionPolicy surfaces a 409 as a CONFLICT — this is what an ended session looks like", async () => {
    // The console branches on this: a refusal is final (the session was ended centrally, the
    // principal disabled, the tenant suspended, the machine quarantined) and must stop the renewal
    // loop rather than retrying, so the kind has to be distinguishable from a network blip.
    const { fn } = fakeFetch(() => jsonResponse({ error: "session has ended" }, 409));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.renewSessionPolicy("s-1")).rejects.toMatchObject({ kind: "conflict" });
  });

  it("renewSessionPolicy URL-encodes the session id", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session_policy: { access: "control", signed: "{}", lease_ttl_ms: 30000, expires_at_ms: 1 },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.renewSessionPolicy("a/b?c");
    expect(calls[0].url).toBe("/cp/sessions/a%2Fb%3Fc/policy");
  });

  it("mintSessionElevation POSTs the session-scoped route and unwraps the grant", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        elevation: {
          elevation_id: "44444444-4444-4444-4444-444444444444",
          token: "linked_elevated",
          expires_at_ms: 1730000120000,
          signed: '{"claims":{},"sig":"ab"}',
        },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const grant = await client.mintSessionElevation("s-1");

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/cp/sessions/s-1/elevation");
    expect(calls[0].init?.method).toBe("POST");
    expect(grant).toEqual({
      elevation_id: "44444444-4444-4444-4444-444444444444",
      token: "linked_elevated",
      expires_at_ms: 1730000120000,
      signed: '{"claims":{},"sig":"ab"}',
    });
  });

  it("mintSessionElevation URL-encodes the session id", async () => {
    // The id goes in the PATH. An unencoded one would silently address a different route.
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        elevation: { elevation_id: "e", token: "linked_elevated", expires_at_ms: 1, signed: "{}" },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.mintSessionElevation("a/b?c");
    expect(calls[0].url).toBe("/cp/sessions/a%2Fb%3Fc/elevation");
  });

  it("mintSessionElevation REJECTS a partially-decoded grant rather than forwarding it", async () => {
    // A half-read grant is worse than none: the caller would forward a blob the agent refuses, having
    // already spent a `session.elevation_minted` audit event, and the technician would see an
    // unexplained agent-side refusal. Loud and local is the only safe option — the same rule
    // `parseSessionAccessPolicy` follows.
    for (const bad of [
      undefined,
      {},
      { token: "linked_elevated", expires_at_ms: 1, signed: "{}" }, // no elevation_id
      { elevation_id: "e", expires_at_ms: 1, signed: "{}" }, // no token
      { elevation_id: "e", token: "linked_elevated", signed: "{}" }, // no expiry
      { elevation_id: "e", token: "linked_elevated", expires_at_ms: 1 }, // no blob
      { elevation_id: "e", token: "linked_elevated", expires_at_ms: 1, signed: "" }, // empty blob
      { elevation_id: "e", token: "linked_elevated", expires_at_ms: "soon", signed: "{}" },
    ]) {
      const { fn } = fakeFetch(() => jsonResponse(bad === undefined ? {} : { elevation: bad }));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.mintSessionElevation("s-1")).rejects.toThrow(/elevation/);
    }
    // …and the well-formed shape DOES resolve, so the rejections above are not the method simply
    // refusing everything.
    const { fn } = fakeFetch(() =>
      jsonResponse({
        elevation: { elevation_id: "e", token: "linked_elevated", expires_at_ms: 1, signed: "{}" },
      }),
    );
    const ok = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(ok.mintSessionElevation("s-1")).resolves.toMatchObject({ token: "linked_elevated" });
  });

  it("startBrokeredSession REJECTS a malformed session_policy rather than dropping it", async () => {
    // Silently ignoring a malformed policy is the same failure as never reading one: the session would
    // run unrestricted while the console believed a mandate was in force. Loud is the only safe option.
    for (const bad of [
      { access: "view_only" },
      { signed: '{"sig":"ab"}' },
      { access: 5, signed: '{"sig":"ab"}' },
      { access: "view_only", signed: "" },
    ]) {
      const { fn } = fakeFetch(() =>
        jsonResponse({ session: { id: "s-1" }, session_policy: bad }),
      );
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.startBrokeredSession("d-1")).rejects.toThrow(/session_policy/);
    }
  });

  it("startBrokeredSession REJECTS a non-object signaling field rather than forwarding it", async () => {
    // The guard at console_api.ts:1222 fires when signaling is present but not an object (e.g. a
    // number). Without it a mutant replacing `typeof signaling !== 'object'` with `false` would cast
    // 42 as SessionSignaling and forward it silently to every signaling caller.
    const { fn } = fakeFetch(() =>
      jsonResponse({ session: { id: "s-1" }, signaling: 42 }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const p = client.startBrokeredSession("d-1");
    await expect(p).rejects.toBeInstanceOf(ConsoleApiError);
    await expect(p).rejects.toThrow(/bad.*signaling/i);
  });

  it("startBrokeredSession REJECTS a 200 body with no session key", async () => {
    // pluck<SessionRecord>(body, 'session', 'start session') throws ConsoleApiError(kind='server')
    // when the key is absent. A mutant replacing that call with `body as SessionRecord` would resolve
    // with {} instead of throwing, silently forwarding an empty object to all callers.
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.startBrokeredSession("d-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*session/);
  });

  it("setGroupSessionPolicy PUTs ALL SIX policy fields to /machine-groups/{id}/session-policy", async () => {
    const cap = {
      group_id: "g9",
      max_concurrent_sessions: 4,
      enforce_view_only: true,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    };
    const { fn, calls } = fakeFetch(() => jsonResponse(cap));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(
      await client.setGroupSessionPolicy("g9", {
        max_concurrent_sessions: 4,
        enforce_view_only: true,
        allow_backstage_under_view_only: false,
        prohibit_recording: false,
        require_recording: false,
        max_session_duration_seconds: 0,
        max_idle_seconds: 0,
      }),
    ).toEqual(cap);
    expect(calls[0].url).toBe("/cp/machine-groups/g9/session-policy");
    expect(calls[0].init?.method).toBe("PUT");
    // EVERY field must be on the wire, asserted with toEqual so an EXTRA or a MISSING key both fail. The
    // PUT is a full overwrite: an omitted enforce_view_only decodes to false server-side and would silently
    // clear the group's view-only mandate, and an omitted prohibit_recording would silently lift a recording
    // ban somebody deliberately set.
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      max_concurrent_sessions: 4,
      enforce_view_only: true,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
  });

  it("setGroupSessionPolicy sends each false explicitly, not as an omission", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        group_id: "g9",
        max_concurrent_sessions: 0,
        enforce_view_only: false,
        allow_backstage_under_view_only: false,
        prohibit_recording: false,
        require_recording: false,
        max_session_duration_seconds: 0,
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setGroupSessionPolicy("g9", {
      max_concurrent_sessions: 0,
      enforce_view_only: false,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
    const body = JSON.parse(String(calls[0].init?.body));
    // toHaveProperty, not a truthiness check: a KEY THAT IS ABSENT and a key whose value is false are the
    // same thing to the server (both decode to false), but they are not the same thing to this test — only
    // the explicit form proves the console is stating its intent rather than relying on the zero value.
    expect(body).toHaveProperty("enforce_view_only", false);
    expect(body).toHaveProperty("allow_backstage_under_view_only", false);
    expect(body).toHaveProperty("prohibit_recording", false);
    expect(body).toHaveProperty("require_recording", false);
  });

  it("setGroupSessionPolicy sends the backstage opt-out as true when it is set", async () => {
    // The opposite direction, because a client that hardcoded `false` for this field would pass every
    // assertion above. This is the value that RE-OPENS backstage on a view-only group, so it must reach
    // the wire exactly as the operator ticked it.
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        group_id: "g9",
        max_concurrent_sessions: 0,
        enforce_view_only: true,
        allow_backstage_under_view_only: true,
        prohibit_recording: false,
        require_recording: false,
        max_session_duration_seconds: 0,
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setGroupSessionPolicy("g9", {
      max_concurrent_sessions: 0,
      enforce_view_only: true,
      allow_backstage_under_view_only: true,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
    expect(JSON.parse(String(calls[0].init?.body))).toHaveProperty(
      "allow_backstage_under_view_only",
      true,
    );
  });

  it("setGroupSessionPolicy sends prohibit_recording as true when the ban is set", async () => {
    // The opposite direction for the recording ban: a client that hardcoded `false` would pass every
    // false-assertion above. `true` is the value that BANS recording for the group; it must reach the
    // wire exactly as the admin ticked it.
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        group_id: "g9",
        max_concurrent_sessions: 0,
        enforce_view_only: false,
        allow_backstage_under_view_only: false,
        prohibit_recording: true,
        require_recording: false,
        max_session_duration_seconds: 0,
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setGroupSessionPolicy("g9", {
      max_concurrent_sessions: 0,
      enforce_view_only: false,
      allow_backstage_under_view_only: false,
      prohibit_recording: true,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
    expect(JSON.parse(String(calls[0].init?.body))).toHaveProperty("prohibit_recording", true);
  });

  it("setGroupSessionPolicy sends require_recording as true when mandatory capture is set", async () => {
    // The positive direction for the recording mandate: a client that hardcoded `false` would pass every
    // false-assertion above. `true` is the value that REQUIRES recording for the group; it must reach the
    // wire exactly as the admin ticked it.
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        group_id: "g9",
        max_concurrent_sessions: 0,
        enforce_view_only: false,
        allow_backstage_under_view_only: false,
        prohibit_recording: false,
        require_recording: true,
        max_session_duration_seconds: 0,
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setGroupSessionPolicy("g9", {
      max_concurrent_sessions: 0,
      enforce_view_only: false,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: true,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
    expect(JSON.parse(String(calls[0].init?.body))).toHaveProperty("require_recording", true);
  });

  it("setGroupSessionPolicy URI-encodes a hostile id", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        group_id: "x",
        max_concurrent_sessions: 0,
        enforce_view_only: false,
        allow_backstage_under_view_only: false,
        prohibit_recording: false,
        require_recording: false,
        max_session_duration_seconds: 0,
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setGroupSessionPolicy("a/b?c", {
      max_concurrent_sessions: 0,
      enforce_view_only: false,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: false,
      max_session_duration_seconds: 0,
      max_idle_seconds: 0,
    });
    expect(calls[0].url).toBe("/cp/machine-groups/a%2Fb%3Fc/session-policy");
  });
});

describe("ConsoleApiClient error mapping", () => {
  it("maps a 401 to kind unauthenticated with the body's error message", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "authentication required" }, 401));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.listSessions().catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.status).toBe(401);
    expect(err.kind).toBe("unauthenticated");
    expect(err.message).toMatch(/authentication required/);
  });

  it("maps a 403 capability denial to kind forbidden", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "capability denied" }, 403));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.startSession("dev-1").catch((e) => e)) as ConsoleApiError;
    expect(err.status).toBe(403);
    expect(err.kind).toBe("forbidden");
  });

  it("maps a 404 unknown machine to kind not_found", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "unknown machine" }, 404));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.startSession("nope").catch((e) => e)) as ConsoleApiError;
    expect(err.kind).toBe("not_found");
    expect(err.message).toMatch(/unknown machine/);
  });

  it("maps a duplicate-slug 409 to kind conflict (http.go handleCreateTenant)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "tenant slug already in use" }, 409));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client
      .createTenant({ slug: "acme", name: "Acme" })
      .catch((e) => e)) as ConsoleApiError;
    expect(err.status).toBe(409);
    expect(err.kind).toBe("conflict");
    expect(err.message).toMatch(/slug already in use/);
  });

  it("falls back to the status text on a non-JSON error body", async () => {
    const { fn } = fakeFetch(
      () => new Response("boom", { status: 500, statusText: "Internal Server Error" }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.listAudit().catch((e) => e)) as ConsoleApiError;
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/Internal Server Error/);
  });

  it("rejects with ConsoleApiError(200) when a 200 response body is not valid JSON", async () => {
    const { fn } = fakeFetch(() => new Response("not-json", { status: 200 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.listMachines().catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.status).toBe(200);
    expect(err.message).toMatch(/malformed response body/);
  });

  it("normalizes a trailing slash in the base URL", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ machines: [] }));
    const client = new ConsoleApiClient({ baseUrl: "http://127.0.0.1:8081/", fetch: fn });
    await client.listMachines();
    expect(calls[0].url).toBe("http://127.0.0.1:8081/machines");
  });
});

describe("ConsoleApiClient attended sessions (docs/12 §9)", () => {
  const ATTENDED = {
    id: "as-1",
    tenant_id: "t-1",
    group_id: "g-1",
    technician_id: "u-1",
    state: "pending",
    created_at: "2026-07-30T12:00:00Z",
    expires_at: "2026-07-30T12:10:00Z",
  };

  it("createAttendedSession POSTs group_id + reason and returns the one-time code envelope", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse(
        { session: ATTENDED, code: "ABCD-EFGH-JKMN", join_code: "ABCDEFGHJKMN", join_url: "/join#ABCDEFGHJKMN" },
        201,
      ),
    );
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fn,
      cookies: () => "rmt_csrf=tok-1",
    });

    const out = await client.createAttendedSession("g-1", "printer support");

    expect(calls[0].url).toBe("/cp/attended-sessions");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.credentials).toBe("include");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      group_id: "g-1",
      reason: "printer support",
    });
    // Mutation → the CSRF cookie is echoed as the header.
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
    expect(out.join_code).toBe("ABCDEFGHJKMN");
    expect(out.join_url).toBe("/join#ABCDEFGHJKMN");
    expect(out.session).toEqual(ATTENDED);
  });

  it("createAttendedSession rejects a response without the code fields", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ session: ATTENDED }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createAttendedSession("g-1").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
  });

  it("createAttendedSession rejects a 201 whose body has no session key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createAttendedSession("g-1").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*session/);
    expect(err.message).toContain('malformed response (no "session")');
  });

  it("createAttendedSession rejects a 201 with code and join_url but no join_code", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({ session: ATTENDED, code: "ABCD-EFGH-JKMN", join_url: "/join#X" }, 201),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createAttendedSession("g-1").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*code/);
  });

  it("createAttendedSession rejects a 201 with code and join_code but no join_url", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse(
        { session: ATTENDED, code: "ABCD-EFGH-JKMN", join_code: "WXYZ-1234" },
        201,
      ),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.createAttendedSession("g-1").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*code/);
  });

  it("getAttendedSession GETs the id (URL-encoded) and unwraps the session", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ session: ATTENDED }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.getAttendedSession("as 1")).toEqual(ATTENDED);
    expect(calls[0].url).toBe("/cp/attended-sessions/as%201");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("getAttendedSession rejects with ConsoleApiError(server) when body has no session key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.getAttendedSession("as-1").catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.kind).toBe("server");
    expect(err.message).toMatch(/no.*session/);
  });

  it("connectAttendedSession POSTs the consent gate and returns session + signaling", async () => {
    const signaling = {
      url: "ws://127.0.0.1:8080/ws",
      device_id: "dev-eph",
      session_id: "as-1",
      ticket: { claims: { v: 1 }, sig: "aa" },
    };
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ session: { ...ATTENDED, state: "active" }, signaling }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.connectAttendedSession("as-1");

    expect(calls[0].url).toBe("/cp/attended-sessions/as-1/connect");
    expect(calls[0].init?.method).toBe("POST");
    expect(out.session.state).toBe("active");
    expect(out.signaling).toEqual(signaling);
  });

  it("connectAttendedSession surfaces the pre-consent 409 as kind conflict", async () => {
    const { fn } = fakeFetch(() =>
      jsonResponse({ error: "attended session is awaiting consent" }, 409),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = (await client.connectAttendedSession("as-1").catch((e) => e)) as ConsoleApiError;
    expect(err.kind).toBe("conflict");
    expect(err.message).toMatch(/awaiting consent/);
  });

  it("promoteAttendedSession and endAttendedSession hit their routes", async () => {
    const { fn, calls } = fakeFetch((call) =>
      call.url.endsWith("/promote")
        ? jsonResponse({ promoted: true })
        : jsonResponse({ session: { ...ATTENDED, state: "ended" } }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.promoteAttendedSession("as-1");
    const ended = await client.endAttendedSession("as-1");

    expect(calls[0].url).toBe("/cp/attended-sessions/as-1/promote");
    expect(calls[1].url).toBe("/cp/attended-sessions/as-1/end");
    expect(ended.state).toBe("ended");
  });

  it("endAttendedSession rejects with ConsoleApiError when session key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.endAttendedSession("as-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*session/);
  });

  it("connectAttendedSession rejects with ConsoleApiError when session key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.connectAttendedSession("as-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*session/);
    expect((err as ConsoleApiError).message).toContain('malformed response (no "session")');
  });

  it("connectAttendedSession rejects with ConsoleApiError when signaling key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ session: { id: "att-1" } }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.connectAttendedSession("att-1");
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).message).toMatch(/no.*signaling/);
  });
});

describe("ConsoleApiClient API tokens (docs/01 §8)", () => {
  const TOKEN: APIToken = {
    id: "at-1",
    name: "ci-bot",
    capabilities: ["view_machines", "view_audit"],
    created_at: "2026-08-17T12:00:00Z",
    expires_at: null,
    revoked_at: null,
  };

  it("listAPITokens reads the api_tokens envelope from GET /api-tokens", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ api_tokens: [TOKEN] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const tokens = await client.listAPITokens();

    expect(calls[0].url).toBe("/cp/api-tokens");
    expect(calls[0].init?.method).toBe("GET");
    expect(tokens).toEqual([TOKEN]);
  });

  it("listAPITokens rejects with ConsoleApiError when the server returns no api_tokens key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listAPITokens().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*api_tokens/i);
  });

  it("createAPIToken POSTs the body and returns the one-time secret plus metadata", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ token: "rmt_api_the-secret", api_token: TOKEN }, 201),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const created = await client.createAPIToken({
      name: "ci-bot",
      capabilities: ["view_machines", "view_audit"],
      expiresInDays: 90,
    });

    expect(calls[0].url).toBe("/cp/api-tokens");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      name: "ci-bot",
      capabilities: ["view_machines", "view_audit"],
      expires_in_days: 90,
    });
    expect(created.token).toBe("rmt_api_the-secret");
    expect(created.apiToken).toEqual(TOKEN);
  });

  it("createAPIToken throws when the response omits the secret", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ api_token: TOKEN }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await expect(client.createAPIToken({ name: "x", capabilities: ["view_machines"] })).rejects.toBeInstanceOf(
      ConsoleApiError,
    );
  });

  it("createAPIToken rejects with a server ConsoleApiError when api_token key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ token: "rmt_api_s" }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    let err: unknown;
    try {
      await client.createAPIToken({ name: "x", capabilities: ["view_machines"] });
    } catch (e) {
      err = e;
    }

    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*api_token/);
  });

  it("revokeAPIToken DELETEs /api-tokens/{id}", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ revoked: true, id: "at-1" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.revokeAPIToken("at-1");

    expect(calls[0].url).toBe("/cp/api-tokens/at-1");
    expect(calls[0].init?.method).toBe("DELETE");
  });
});

describe("ConsoleApiClient enrollment tokens (docs/01 §4/§6)", () => {
  it("listEnrollmentTokens reads the enrollment_tokens envelope from GET /enrollment-tokens", async () => {
    const enrollment_tokens = [
      { id: "et-1", tenant_id: "t", group_id: "g1", created_at: "2026-01-01T00:00:00Z", expires_at: "2026-02-01T00:00:00Z", max_uses: 1, uses: 0, revoked: false },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ enrollment_tokens }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listEnrollmentTokens()).toEqual(enrollment_tokens);
    expect(calls[0].url).toBe("/cp/enrollment-tokens");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listEnrollmentTokens rejects with a server ConsoleApiError when the response body has no enrollment_tokens key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.listEnrollmentTokens().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*enrollment_tokens/);
  });

  it("createEnrollmentToken POSTs group_id/ttl_seconds/max_uses and returns the one-time secret", async () => {
    const enrollment_token = { id: "et-2", tenant_id: "t", group_id: "g1", created_at: "x", expires_at: "y", max_uses: 5, uses: 0, revoked: false };
    const { fn, calls } = fakeFetch(() => jsonResponse({ enrollment_token, token: "rmt_enroll_SECRET" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const created = await client.createEnrollmentToken({ groupId: "g1", ttlSeconds: 604800, maxUses: 5 });
    expect(created.token).toBe("rmt_enroll_SECRET");
    expect(created.enrollmentToken).toEqual(enrollment_token);
    expect(calls[0].url).toBe("/cp/enrollment-tokens");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ group_id: "g1", ttl_seconds: 604800, max_uses: 5 });
  });

  it("createEnrollmentToken omits ttl_seconds/max_uses when not given (server defaults)", async () => {
    const enrollment_token = { id: "et-3", tenant_id: "t", group_id: "g1", created_at: "x", expires_at: "y", max_uses: 1, uses: 0, revoked: false };
    const { fn, calls } = fakeFetch(() => jsonResponse({ enrollment_token, token: "s" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.createEnrollmentToken({ groupId: "g1" });
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ group_id: "g1" });
  });

  it("createEnrollmentToken throws when the response omits the secret", async () => {
    const enrollment_token = { id: "et-4", group_id: "g1" };
    const { fn } = fakeFetch(() => jsonResponse({ enrollment_token }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.createEnrollmentToken({ groupId: "g1" })).rejects.toBeInstanceOf(ConsoleApiError);
  });

  it("createEnrollmentToken rejects with server ConsoleApiError when enrollment_token key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ token: "rmt_enroll_SECRET" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.createEnrollmentToken({ groupId: "g-1" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*enrollment_token/);
  });

  it("revokeEnrollmentToken POSTs /enrollment-tokens/{id}/revoke", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ revoked: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.revokeEnrollmentToken("et 1");
    expect(calls[0].url).toBe("/cp/enrollment-tokens/et%201/revoke");
    expect(calls[0].init?.method).toBe("POST");
  });
});

describe("isHexColor", () => {
  it("accepts #rrggbb and rejects everything else (mirrors Go IsHexColor)", () => {
    expect(isHexColor("#ff0000")).toBe(true);
    expect(isHexColor("#ABCDEF")).toBe(true);
    for (const bad of ["", "red", "#fff", "#fffffff", "ff0000", "#gg0000"]) {
      expect(isHexColor(bad)).toBe(false);
    }
  });
});

describe("ConsoleApiClient branding (docs/01 §9)", () => {
  it("getTenantBranding GETs /tenant/branding and defaults missing fields", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ product_name: "Acme", accent_color: "#ff0000" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const b = await client.getTenantBranding();
    expect(calls[0].url).toBe("/cp/tenant/branding");
    expect(calls[0].init?.method).toBe("GET");
    expect(b).toEqual({ product_name: "Acme", accent_color: "#ff0000", logo_data_uri: "" });

    // A response missing fields yields empty strings (the defaults), never undefined.
    const { fn: fn2 } = fakeFetch(() => jsonResponse({}));
    const client2 = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn2 });
    expect(await client2.getTenantBranding()).toEqual({ product_name: "", accent_color: "", logo_data_uri: "" });
  });

  it("setTenantBranding PUTs the body (incl. logo) and returns the echoed value", async () => {
    const logo = "data:image/png;base64,iVBORw0KGgo=";
    const { fn, calls } = fakeFetch(() => jsonResponse({ product_name: "Acme", accent_color: "#3b82f6", logo_data_uri: logo }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const out = await client.setTenantBranding({ product_name: "Acme", accent_color: "#3b82f6", logo_data_uri: logo });
    expect(calls[0].url).toBe("/cp/tenant/branding");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      product_name: "Acme",
      accent_color: "#3b82f6",
      logo_data_uri: logo,
    });
    expect(out).toEqual({ product_name: "Acme", accent_color: "#3b82f6", logo_data_uri: logo });
  });
});

describe("ConsoleApiClient session policy (docs/01 §5 seat metering)", () => {
  it("getSessionPolicy GETs /tenant/session-policy and parses both fields", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ max_concurrent_sessions: 5, max_session_seconds: 3600 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const p = await client.getSessionPolicy();
    expect(calls[0].url).toBe("/cp/tenant/session-policy");
    expect(calls[0].init?.method).toBe("GET");
    expect(p).toEqual({ max_concurrent_sessions: 5, max_session_seconds: 3600 });
  });

  const badSessionPolicyBodies: Array<[string, unknown]> = [
    ["null body", null],
    ["array body", []],
    ["missing max_session_seconds", { max_concurrent_sessions: 3 }],
    ["missing max_concurrent_sessions", { max_session_seconds: 60 }],
    ["string field", { max_concurrent_sessions: "5", max_session_seconds: 60 }],
    ["NaN-like string field", { max_concurrent_sessions: 5, max_session_seconds: "NaN" }],
    ["null field", { max_concurrent_sessions: null, max_session_seconds: 60 }],
    ["negative field", { max_concurrent_sessions: -3, max_session_seconds: 60 }],
    ["negative seconds", { max_concurrent_sessions: 3, max_session_seconds: -1 }],
  ];

  for (const [label, body] of badSessionPolicyBodies) {
    it(`getSessionPolicy REJECTS a malformed ok response: ${label}`, async () => {
      const { fn } = fakeFetch(() => jsonResponse(body));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.getSessionPolicy()).rejects.toMatchObject({ kind: "server" });
    });

    it(`setSessionPolicy REJECTS a malformed ok response: ${label}`, async () => {
      const { fn } = fakeFetch(() => jsonResponse(body));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(
        client.setSessionPolicy({ max_concurrent_sessions: 3, max_session_seconds: 7200 }),
      ).rejects.toMatchObject({ kind: "server" });
    });
  }

  it("getSessionPolicy accepts an explicit zero (unlimited) as a real value", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ max_concurrent_sessions: 0, max_session_seconds: 0 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.getSessionPolicy()).toEqual({ max_concurrent_sessions: 0, max_session_seconds: 0 });
  });

  it("setSessionPolicy PUTs both fields and returns the echoed value", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ max_concurrent_sessions: 3, max_session_seconds: 7200 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const out = await client.setSessionPolicy({ max_concurrent_sessions: 3, max_session_seconds: 7200 });
    expect(calls[0].url).toBe("/cp/tenant/session-policy");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ max_concurrent_sessions: 3, max_session_seconds: 7200 });
    expect(out).toEqual({ max_concurrent_sessions: 3, max_session_seconds: 7200 });
  });
});

describe("ConsoleApiClient tenant security policy (docs/01 §10 2FA enforcement)", () => {
  it("getTenantSecurityPolicy GETs /tenant/security-policy and parses require_2fa", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ require_2fa: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const p = await client.getTenantSecurityPolicy();
    expect(calls[0].url).toBe("/cp/tenant/security-policy");
    expect(calls[0].init?.method).toBe("GET");
    expect(p).toEqual({ require_2fa: true });
  });

  const badSecurityPolicyBodies: Array<[string, unknown]> = [
    ["null body", null],
    ["array body", []],
    ["missing require_2fa", { other: true }],
    ["numeric require_2fa", { require_2fa: 1 }],
    ["string require_2fa", { require_2fa: "true" }],
    ["null require_2fa", { require_2fa: null }],
  ];

  for (const [label, body] of badSecurityPolicyBodies) {
    it(`getTenantSecurityPolicy REJECTS a malformed ok response: ${label}`, async () => {
      const { fn } = fakeFetch(() => jsonResponse(body));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.getTenantSecurityPolicy()).rejects.toMatchObject({ kind: "server" });
    });

    it(`setTenantSecurityPolicy REJECTS a malformed ok response: ${label}`, async () => {
      const { fn } = fakeFetch(() => jsonResponse(body));
      const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
      await expect(client.setTenantSecurityPolicy({ require_2fa: true })).rejects.toMatchObject({
        kind: "server",
      });
    });
  }

  it("setTenantSecurityPolicy PUTs require_2fa and returns the echoed value", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ require_2fa: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const out = await client.setTenantSecurityPolicy({ require_2fa: true });
    expect(calls[0].url).toBe("/cp/tenant/security-policy");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ require_2fa: true });
    expect(out).toEqual({ require_2fa: true });
  });

  it("setTenantSecurityPolicy false round-trips correctly", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ require_2fa: false }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.setTenantSecurityPolicy({ require_2fa: false })).toEqual({ require_2fa: false });
  });

  it("getPublishedAgentVersion returns version and configured=true when server reports them", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ configured: true, version: "0.0.1+abc1234" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const info = await client.getPublishedAgentVersion();
    expect(calls[0].url).toBe("/cp/agent-version");
    expect(calls[0].init?.method).toBe("GET");
    expect(info).toEqual({ configured: true, version: "0.0.1+abc1234" });
  });

  it("getPublishedAgentVersion returns configured=false and no version when server is unconfigured", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ configured: false }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const info = await client.getPublishedAgentVersion();
    expect(info.configured).toBe(false);
    expect(info.version).toBeUndefined();
  });

  it("getPublishedAgentVersion treats non-string version as absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ configured: true, version: 42 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const info = await client.getPublishedAgentVersion();
    expect(info.configured).toBe(true);
    expect(info.version).toBeUndefined();
  });
});

describe("ConsoleApiClient user management (docs/01 §5)", () => {
  it("listUsers GETs /users and unwraps the envelope", async () => {
    const users = [
      { id: "u1", email: "a@x.test", display_name: "Ay", disabled: false },
      { id: "u2", email: "b@x.test", display_name: "Bee", disabled: true },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ users }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listUsers()).toEqual(users);
    expect(calls[0].url).toBe("/cp/users");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listRoles GETs /roles and unwraps the role catalog", async () => {
    const roles = [
      { role: "owner", capabilities: ["manage_tenant", "view_machines"] },
      { role: "readonly", capabilities: ["view_machines"] },
    ];
    const { fn, calls } = fakeFetch(() => jsonResponse({ roles }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listRoles()).toEqual(roles);
    expect(calls[0].url).toBe("/cp/roles");
    expect(calls[0].init?.method).toBe("GET");
  });

  it("listRoles rejects with a server ConsoleApiError when response body has no roles key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.listRoles();
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*roles/);
  });

  it("setUserDisabled POSTs the disable/enable route by the flag", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ id: "u1", disabled: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setUserDisabled("u1", true);
    await client.setUserDisabled("u2", false);
    expect(calls[0].url).toBe("/cp/users/u1/disable");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[1].url).toBe("/cp/users/u2/enable");
  });

  it("signOutUser POSTs /users/{id}/sign-out and returns the revoked count", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ revoked: 3 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.signOutUser("u 1")).toBe(3);
    expect(calls[0].url).toBe("/cp/users/u%201/sign-out"); // id is URI-encoded
    expect(calls[0].init?.method).toBe("POST");
  });

  it("signOutUser tolerates a response with no revoked count (→ 0)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.signOutUser("u1")).toBe(0);
  });

  it("clearUserLockout DELETEs /users/{id}/lockout and resolves on 204", async () => {
    const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.clearUserLockout("u 1")).resolves.toBeUndefined();
    expect(calls[0].url).toBe("/cp/users/u%201/lockout"); // id is URI-encoded
    expect(calls[0].init?.method).toBe("DELETE");
  });

  it("listUsers rejects with a server ConsoleApiError when the 200 body has no users key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try { await client.listUsers(); } catch (e) { err = e; }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*users/);
  });

  it("listUsers carries each user's roles through the envelope", async () => {
    const users = [
      { id: "u1", email: "a@x.test", display_name: "Ay", disabled: false, roles: ["owner"] },
      { id: "u2", email: "b@x.test", display_name: "Bee", disabled: false, roles: [] },
    ];
    const { fn } = fakeFetch(() => jsonResponse({ users }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.listUsers()).toEqual(users);
  });

  it("setUserRole POSTs /users/{id}/role with the role in the body", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ id: "u1", role: "admin" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setUserRole("u1", "admin");
    expect(calls[0].url).toBe("/cp/users/u1/role");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ role: "admin" });
  });

  it("setUserRole sends expires_at only when given (docs/56: omitted preserves, null clears)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ id: "u1", role: "admin" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.setUserRole("u1", "admin", {});
    await client.setUserRole("u1", "admin", { expiresAt: null });
    await client.setUserRole("u1", "admin", { expiresAt: "2026-11-05T17:00:00Z" });
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ role: "admin" });
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ role: "admin", expires_at: null });
    expect(JSON.parse(String(calls[2].init?.body))).toEqual({ role: "admin", expires_at: "2026-11-05T17:00:00Z" });
  });

  it("setUserRole sends access_window and scope only when given (docs/57)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const w = { days: ["mon"], start: "08:00", end: "24:00", time_zone: "UTC" };
    await client.setUserRole("u1", "admin", { accessWindow: w });
    await client.setUserRole("u1", "admin", { accessWindow: null });
    await client.setUserRole("u1", "admin", { accessWindow: w, expiresAt: null, scopedGroupIds: [] });
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ role: "admin", access_window: w });
    expect(JSON.parse(String(calls[1].init?.body))).toEqual({ role: "admin", access_window: null });
    expect(JSON.parse(String(calls[2].init?.body))).toEqual({ role: "admin", access_window: w, expires_at: null, scoped_group_ids: [] });
  });

  it("createUser sends the window with the invite (docs/57)", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ user: { id: "u" } }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const w = { days: ["sat", "sun"], start: "22:00", end: "06:00", time_zone: "Europe/London" };
    await client.createUser({ email: "n@x.test", displayName: "", role: "technician", accessWindow: w });
    await client.createUser({ email: "m@x.test", displayName: "", role: "technician", accessWindow: null });
    expect(JSON.parse(String(calls[0].init?.body)).access_window).toEqual(w);
    expect("access_window" in JSON.parse(String(calls[1].init?.body))).toBe(false);
  });

  it("me() reads the access fields, and an older server reads as not expired (docs/56)", async () => {
    const replies = [
      { email: "a@x.test", access_expired: true, access_expires_at: "2026-11-05T17:00:00Z" },
      { email: "a@x.test" },
    ];
    let i = 0;
    const { fn } = fakeFetch(() => jsonResponse(replies[i++]));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.me()).toEqual({ email: "a@x.test", userId: null, capabilities: [], accessExpired: true, accessExpiresAt: "2026-11-05T17:00:00Z", accessWindow: null, accessWindowVaries: false, accessOutsideWindow: false });
    expect(await client.me()).toEqual({ email: "a@x.test", userId: null, capabilities: [], accessExpired: false, accessExpiresAt: null, accessWindow: null, accessWindowVaries: false, accessOutsideWindow: false });
  });

  it("me() reads user_id and the capability list (docs/65), dropping malformed entries", async () => {
    const { fn } = fakeFetch(() => jsonResponse({
      email: "a@x.test", user_id: "u-1",
      capabilities: [{ capability: "remove_agent", all_groups: false, group_ids: ["g1"] }, { capability: 5 }, "x"],
    }));
    const me = await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).me();
    expect(me.userId).toBe("u-1");
    expect(me.capabilities).toEqual([{ capability: "remove_agent", all_groups: false, group_ids: ["g1"] }]);
  });

  it("listActiveDirectives GETs /directives?state=active and follows next_before until it stops", async () => {
    const replies = [
      { directives: [{ id: "d1" }], next_before: "2026-10-31T10:00:00.123456Z", next_before_id: "0000-id1" },
      { directives: [{ id: "d2" }] },
    ];
    let i = 0;
    const { fn, calls } = fakeFetch(() => jsonResponse(replies[i++]));
    const res = await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).listActiveDirectives();
    expect(res.rows.map((r) => r.id)).toEqual(["d1", "d2"]);
    expect(res.hasMore).toBe(false);
    expect(calls.map((c) => String(c.url))).toEqual([
      "/cp/directives?state=active",
      "/cp/directives?state=active&before=2026-10-31T10%3A00%3A00.123456Z&before_id=0000-id1",
    ]);
  });

  it("forgetMachine POSTs the typed name to /machines/{id}/forget and reads the outcome (docs/65 sec. 8)", async () => {
    const replies = [
      { outcome: "forgotten", machine: { id: "m 1", name: "PC", status: "removed" }, closed_directives: [{ id: "d1", state: "forgotten" }] },
      { outcome: "already_removed", machine: { id: "m 1", name: "PC", status: "removed" }, closed_directives: [] },
    ];
    let i = 0;
    const { fn, calls } = fakeFetch(() => jsonResponse(replies[i++]));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const first = await client.forgetMachine("m 1", "PC");
    expect(first.outcome).toBe("forgotten");
    expect(first.machine.status).toBe("removed");
    expect(first.closed_directives.map((d) => d.id)).toEqual(["d1"]);
    expect((await client.forgetMachine("m 1", "PC")).outcome).toBe("already_removed");
    expect(calls.map((c) => [String(c.url), c.init?.method])).toEqual([["/cp/machines/m%201/forget", "POST"], ["/cp/machines/m%201/forget", "POST"]]);
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ confirm: "PC" });
  });

  it("forgetMachine refuses a malformed answer (no outcome, an unknown outcome, no machine) and carries the server's refusal code", async () => {
    for (const body of [{}, { outcome: "maybe", machine: { id: "m" } }, { outcome: "forgotten" }]) {
      const { fn } = fakeFetch(() => jsonResponse(body));
      await expect(new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).forgetMachine("m", "PC")).rejects.toMatchObject({ status: 200, kind: "server" });
    }
    const { fn } = fakeFetch(() => jsonResponse({ error: "a recent second-factor verification is required", code: "step_up_required" }, 403));
    await expect(new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).forgetMachine("m", "PC")).rejects.toMatchObject({ status: 403, code: "step_up_required" });
  });

  it("listActiveDirectives reports hasMore instead of truncating silently when the page budget runs out", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ directives: [{ id: "d" }], next_before: "2026-10-31T10:00:00Z", next_before_id: "x" }));
    const res = await new ConsoleApiClient({ baseUrl: "/cp", fetch: fn }).listActiveDirectives({ maxPages: 2 });
    expect(res.rows).toHaveLength(2);
    expect(res.hasMore).toBe(true);
  });

  it("me() reads the window fields and ignores a malformed window (docs/57)", async () => {
    const w = { days: ["mon", "fri"], start: "08:00", end: "18:00", time_zone: "Europe/London" };
    const replies = [
      { email: "a@x.test", access_window: w, access_outside_window: true },
      { email: "a@x.test", access_window: null, access_window_varies: true, access_outside_window: true },
      { email: "a@x.test", access_window: { days: "mon", start: 8 } },
    ];
    let i = 0;
    const { fn } = fakeFetch(() => jsonResponse(replies[i++]));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.me()).toMatchObject({ accessWindow: w, accessWindowVaries: false, accessOutsideWindow: true });
    expect(await client.me()).toMatchObject({ accessWindow: null, accessWindowVaries: true, accessOutsideWindow: true });
    expect(await client.me()).toMatchObject({ accessWindow: null, accessOutsideWindow: false });
  });

  it("ASSIGNABLE_ROLES mirrors the Go preset order (owner…auditor)", () => {
    expect([...ASSIGNABLE_ROLES]).toEqual(["owner", "admin", "technician", "readonly", "auditor"]);
  });

  it("createUser POSTs /users with email/display_name/role and returns the created user", async () => {
    const created = { id: "u9", email: "n@x.test", display_name: "N", disabled: false, roles: ["technician"] };
    const { fn, calls } = fakeFetch(() => jsonResponse({ user: created }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.createUser({ email: "n@x.test", displayName: "N", role: "technician" })).toEqual(created);
    expect(calls[0].url).toBe("/cp/users");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      email: "n@x.test",
      display_name: "N",
      role: "technician",
    });
  });

  it("createUser sends scoped_group_ids only when groups are chosen (docs/55)", async () => {
    const created = { id: "u9", email: "n@x.test", display_name: "N", disabled: false, roles: ["technician"], scoped_group_ids: ["gA"] };
    // Non-empty scope → sent.
    const withScope = fakeFetch(() => jsonResponse({ user: created }));
    await new ConsoleApiClient({ baseUrl: "/cp", fetch: withScope.fn }).createUser({
      email: "n@x.test", displayName: "N", role: "technician", scopedGroupIds: ["gA", "gB"],
    });
    expect(JSON.parse(String(withScope.calls[0].init?.body))).toEqual({
      email: "n@x.test", display_name: "N", role: "technician", scoped_group_ids: ["gA", "gB"],
    });
    // Empty scope → omitted (never an explicit [] that could read as a deliberate tenant-wide widen).
    const empty = fakeFetch(() => jsonResponse({ user: created }));
    await new ConsoleApiClient({ baseUrl: "/cp", fetch: empty.fn }).createUser({
      email: "n@x.test", displayName: "N", role: "technician", scopedGroupIds: [],
    });
    expect(JSON.parse(String(empty.calls[0].init?.body))).not.toHaveProperty("scoped_group_ids");
  });

  it("createUser rejects with ConsoleApiError(server) when response body has no user key", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    let err: unknown;
    try {
      await client.createUser({ email: "n@x.test", displayName: "N", role: "technician" });
    } catch (e) {
      err = e;
    }
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*user/i);
  });
});


it("prefers host-prefixed CSRF cookies over a tossed legacy cookie", () => {
  expect(csrfTokenFrom("rmt_csrf=attacker; __Host-rmt_csrf=legitimate")).toBe("legitimate");
});

describe("ConsoleApiClient AbortSignal threading", () => {
  it("renewSessionPolicy threads the AbortSignal through to the fetch call", async () => {
    const controller = new AbortController();
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session_policy: { access: "control", signed: "{}", lease_ttl_ms: 30_000, expires_at_ms: 1 },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.renewSessionPolicy("s-1", controller.signal);

    expect(calls[0].init?.signal).toBe(controller.signal);
  });

  it("renewSessionPolicy with no signal leaves signal undefined on the fetch init", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session_policy: { access: "control", signed: "{}", lease_ttl_ms: 30_000, expires_at_ms: 1 },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.renewSessionPolicy("s-1");

    // No signal in init: existing callers that don't pass one must not receive an unexpected field.
    expect(calls[0].init?.signal).toBeUndefined();
  });

  it("startBrokeredSession threads the AbortSignal through to the fetch call", async () => {
    const controller = new AbortController();
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session: { id: "s-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "s-1", ticket: {} },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.startBrokeredSession("d-1", controller.signal);

    expect(calls[0].init?.signal).toBe(controller.signal);
  });

  it("startBrokeredSession with no signal leaves signal undefined on the fetch init", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({
        session: { id: "s-1" },
        signaling: { url: "ws://x/ws", device_id: "d-1", session_id: "s-1", ticket: {} },
      }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.startBrokeredSession("d-1");

    expect(calls[0].init?.signal).toBeUndefined();
  });
});

describe("ConsoleApiClient downloadManagedInstaller", () => {
  it("happy-path — POSTs to /cp/managed-installer, sends CSRF header, resolves to application/zip Blob", async () => {
    const { fn, calls } = fakeFetch(() =>
      new Response(new Uint8Array([1, 2, 3]), {
        status: 200,
        headers: { "content-type": "application/zip" },
      })
    );
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fn,
      cookies: () => "rmt_csrf=tok-123",
    });
    const blob = await client.downloadManagedInstaller("grp-1", new AbortController().signal);
    expect(blob.type).toBe("application/zip");
    expect(calls[0].url).toBe("/cp/managed-installer");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.credentials).toBe("include");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-123");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ group_id: "grp-1" });
  });

  it("non-OK (403) rejects with ConsoleApiError matching /download installer/", async () => {
    const { fn } = fakeFetch(() =>
      new Response(JSON.stringify({ error: "forbidden" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      })
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(
      client.downloadManagedInstaller("grp-1", new AbortController().signal)
    ).rejects.toBeInstanceOf(ConsoleApiError);
    await expect(
      client.downloadManagedInstaller("grp-1", new AbortController().signal)
    ).rejects.toMatchObject({ message: expect.stringMatching(/download installer/) });
  });

  it("200 with content-type: text/html rejects with 'The server did not return an installer bundle.'", async () => {
    const { fn } = fakeFetch(() =>
      new Response("<html>error</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      })
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(
      client.downloadManagedInstaller("grp-1", new AbortController().signal)
    ).rejects.toThrow("The server did not return an installer bundle.");
  });

  it("200 with application/zip and zero-byte body rejects with 'The installer bundle was empty.'", async () => {
    const { fn } = fakeFetch(() =>
      new Response(new Uint8Array(0), {
        status: 200,
        headers: { "content-type": "application/zip" },
      })
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(
      client.downloadManagedInstaller("grp-1", new AbortController().signal)
    ).rejects.toThrow("The installer bundle was empty.");
  });
});

describe("ConsoleApiClient ingestAudit", () => {
  it("happy path — POSTs to /cp/audit/ingest with CSRF header and body, resolves to full result", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ accepted: 3, tail_seq: 2, tail_hash: "deadbeef" })
    );
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      fetch: fn,
      cookies: () => "rmt_csrf=tok-1",
    });
    const result = await client.ingestAudit({ session_id: "sid-1", events: [{ seq: 0 }] });
    expect(result).toEqual({ accepted: 3, tail_seq: 2, tail_hash: "deadbeef" });
    expect(calls[0].url).toBe("/cp/audit/ingest");
    expect(calls[0].init?.method).toBe("POST");
    expect(headersOf(calls[0])[CSRF_HEADER_NAME]).toBe("tok-1");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({
      session_id: "sid-1",
      events: [{ seq: 0 }],
    });
  });

  it("fallback defaults — server returns {} (all fields absent) resolves to { accepted: 0, tail_seq: 0, tail_hash: '' }", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const result = await client.ingestAudit({ session_id: "sid-1", events: [] });
    expect(result).toEqual({ accepted: 0, tail_seq: 0, tail_hash: "" });
  });
});

describe("ConsoleApiClient.managedInstallerAvailable", () => {
  it("happy-path — GETs /managed-installer with credentials: 'include', resolves to true when server returns { available: true }", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ available: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const result = await client.managedInstallerAvailable();
    expect(result).toBe(true);
    expect(calls[0].url).toBe("/cp/managed-installer");
    expect(calls[0].init?.method).toBe("GET");
    expect(calls[0].init?.credentials).toBe("include");
  });

  it("strict === true type guard — server returns { available: 1 } (truthy number), resolves to false", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ available: 1 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.managedInstallerAvailable()).toBe(false);
  });

  it("absent field — server returns {}, resolves to false", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.managedInstallerAvailable()).toBe(false);
  });
});

describe("ConsoleApiClient webhooks (docs/01 §8, migration 0047)", () => {
  const WH: TenantWebhook = {
    id: "wh-1",
    url: "https://example.com/hook",
    events: ["session.start"],
    created_at: "2026-09-27T00:00:00Z",
  };

  it("listWebhooks GETs /tenant/webhooks and reads the webhooks envelope", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ webhooks: [WH] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const list = await client.listWebhooks();

    expect(calls[0].url).toBe("/cp/tenant/webhooks");
    expect(calls[0].init?.method).toBe("GET");
    expect(list).toEqual([WH]);
  });

  it("listWebhooks rejects with ConsoleApiError when the webhooks envelope is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const err = await client.listWebhooks().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
    expect((err as ConsoleApiError).message).toMatch(/no.*webhooks/i);
  });

  it("createWebhook POSTs url+events and returns the one-time secret embedded in the webhook object", async () => {
    const created = { ...WH, secret: "cafebabe0011" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ webhook: created }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const result = await client.createWebhook({ url: WH.url, events: ["session.start"] });

    expect(calls[0].url).toBe("/cp/tenant/webhooks");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      url: WH.url,
      events: ["session.start"],
    });
    expect(result.id).toBe(WH.id);
    expect(result.secret).toBe("cafebabe0011");
  });

  it("createWebhook defaults events to [] when omitted", async () => {
    const created = { ...WH, events: [], secret: "aabbccdd" };
    const { fn, calls } = fakeFetch(() => jsonResponse({ webhook: created }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.createWebhook({ url: WH.url });

    expect(JSON.parse(calls[0].init?.body as string)).toMatchObject({ events: [] });
  });

  it("createWebhook throws ConsoleApiError when the response omits the secret field", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ webhook: WH }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await expect(client.createWebhook({ url: WH.url })).rejects.toBeInstanceOf(ConsoleApiError);
  });

  it("createWebhook throws ConsoleApiError when the webhook envelope key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ secret: "abc" }, 201));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const err = await client.createWebhook({ url: WH.url }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect((err as ConsoleApiError).kind).toBe("server");
  });

  it("deleteWebhook DELETEs /tenant/webhooks/{id} (204 No Content)", async () => {
    const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.deleteWebhook("wh-1");

    expect(calls[0].url).toBe("/cp/tenant/webhooks/wh-1");
    expect(calls[0].init?.method).toBe("DELETE");
  });

  it("deleteWebhook URL-encodes the id", async () => {
    const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.deleteWebhook("wh/special id");

    expect(calls[0].url).toBe("/cp/tenant/webhooks/wh%2Fspecial%20id");
  });

  it("listWebhookDeliveries GETs /tenant/webhooks/{id}/deliveries and returns the array", async () => {
    const rec = {
      webhook_id: "wh-1",
      event: "session.start",
      attempted_at: "2026-09-27T12:00:00Z",
      attempt: 1,
      success: true,
      status_code: 200,
      duration_ms: 143,
      error: "",
    };
    const { fn, calls } = fakeFetch(() => jsonResponse({ deliveries: [rec] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const list = await client.listWebhookDeliveries("wh-1");

    expect(calls[0].url).toBe("/cp/tenant/webhooks/wh-1/deliveries");
    expect(calls[0].init?.method ?? "GET").toBe("GET");
    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({ success: true, event: "session.start", status_code: 200 });
  });

  it("listWebhookDeliveries URL-encodes the webhook id", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ deliveries: [] }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    await client.listWebhookDeliveries("wh/special id");

    expect(calls[0].url).toBe("/cp/tenant/webhooks/wh%2Fspecial%20id/deliveries");
  });

  it("listWebhookDeliveries returns empty array when deliveries key is absent", async () => {
    const { fn } = fakeFetch(() => jsonResponse({}));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });

    const list = await client.listWebhookDeliveries("wh-1");

    expect(list).toEqual([]);
  });
});

describe("ConsoleApiClient credential self-service (docs/01 §10 password + TOTP)", () => {
  it("changes the login email and returns the address confirmed by the server", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ changed: true, email: "new@example.test" }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    expect(await client.changeEmail("current-password", "new@example.test")).toBe("new@example.test");
    expect(calls[0].url).toBe("/cp/me/email");
    expect(calls[0].init?.method).toBe("POST");
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({ current_password: "current-password", new_email: "new@example.test" });
  });

  it.each([{}, { changed: false, email: "new@example.test" }, { changed: true }, null])("refuses to confirm an incomplete email-change response: %j", async (body) => {
    const { fn } = fakeFetch(() => jsonResponse(body));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.changeEmail("password", "new@example.test")).rejects.toThrow("Could not confirm");
  });

  it("changePassword POSTs to /me/password with current and new passwords", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ changed: true, sessions_revoked: 1 }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.changePassword("old-pw", "New-pw-42!");
    expect(calls[0].url).toBe("/cp/me/password");
    expect(calls[0].init?.method).toBe("POST");
    const body = JSON.parse(calls[0].init?.body as string);
    expect(body).toEqual({ current_password: "old-pw", new_password: "New-pw-42!" });
  });

  it("changePassword rejects and propagates an error on 401", async () => {
    const { fn } = fakeFetch(
      () => new Response(JSON.stringify({ error: "invalid credentials" }), { status: 401 }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.changePassword("wrong", "new")).rejects.toThrow();
  });

  it("enrollTotp POSTs to /auth/totp/enroll with password and returns secret + uri", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ secret: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/test:user%40example.com?secret=JBSWY3DPEHPK3PXP" }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    const result = await client.enrollTotp({ password: "my-password" });
    expect(calls[0].url).toBe("/cp/auth/totp/enroll");
    expect(calls[0].init?.method).toBe("POST");
    const body = JSON.parse(calls[0].init?.body as string);
    expect(body).toEqual({ password: "my-password" });
    expect(result.secret).toBe("JBSWY3DPEHPK3PXP");
    expect(result.otpauth_uri).toContain("otpauth://totp/");
  });

  it("enrollTotp POSTs with TOTP code for re-enrollment", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ secret: "NEWSECRET123", otpauth_uri: "otpauth://totp/test:u?secret=NEWSECRET123" }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.enrollTotp({ code: "123456" });
    const body = JSON.parse(calls[0].init?.body as string);
    expect(body).toEqual({ code: "123456" });
  });

  it("confirmTotp POSTs to /auth/totp/confirm with the code", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ confirmed: true }));
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await client.confirmTotp("654321");
    expect(calls[0].url).toBe("/cp/auth/totp/confirm");
    expect(calls[0].init?.method).toBe("POST");
    const body = JSON.parse(calls[0].init?.body as string);
    expect(body).toEqual({ code: "654321" });
  });

  it("confirmTotp rejects and propagates an error on 401 wrong code", async () => {
    const { fn } = fakeFetch(
      () => new Response(JSON.stringify({ error: "invalid code" }), { status: 401 }),
    );
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.confirmTotp("000000")).rejects.toThrow();
  });
});


describe("shared attended session listing", () => {
  it("uses authenticated GET with pagination and decodes the page", async () => {
    const {fn,calls}=fakeFetch(()=>jsonResponse({sessions:[],has_more:true}));
    const client=new ConsoleApiClient({baseUrl:"/cp",fetch:fn});
    expect(await client.listAttendedSessions(50)).toEqual({sessions:[],has_more:true});
    expect(calls[0].url).toBe("/cp/attended-sessions?limit=50&offset=50");
    expect(calls[0].init?.credentials).toBe("include");
    expect(calls[0].init?.method).toBe("GET");
  });
  it.each([{sessions:null,has_more:false},{sessions:[],has_more:"yes"},{}])("rejects malformed pages %j",async body=>{
    const {fn}=fakeFetch(()=>jsonResponse(body));
    await expect(new ConsoleApiClient({fetch:fn}).listAttendedSessions()).rejects.toBeInstanceOf(ConsoleApiError);
  });
});
