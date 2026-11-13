/**
 * Unit tests for the control-plane client (V4). A fake `fetch` records the request shape (URL,
 * method, credentials, headers, body) and returns canned responses, so we assert the exact wire
 * contract against `control-plane/http.go` + `grant.go` without a running server.
 */
import { describe, it, expect } from "vitest";
import { ControlPlaneClient, ControlPlaneError } from "./controlplane";
import { CSRF_HEADER_NAME } from "./console_api";

interface RecordedCall {
  url: string;
  init?: RequestInit;
}

/** A fake fetch that records calls and returns a queued Response. */
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

const SIGNED_GRANT = {
  claims: {
    grant: {
      technician_id: "00000000-0000-0000-0000-000000000000",
      session_id: "11111111-1111-4111-8111-111111111111",
      machine_id: "22222222-2222-4222-8222-222222222222",
      capabilities: ["system_info_read", "process_list"],
    },
    issued_at_ms: 1730000000000,
    expires_at_ms: 1730000300000,
  },
  sig: "deadbeef",
};

describe("ControlPlaneClient", () => {
  it("mintGrant POSTs machine_id and returns the raw SignedGrant JSON text", async () => {
    const grantText = JSON.stringify(SIGNED_GRANT);
    const { fn, calls } = fakeFetch(() => new Response(grantText, { status: 200 }));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });

    const out = await client.mintGrant("22222222-2222-4222-8222-222222222222");

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/cp/grant/mint");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.credentials).toBe("include");
    expect((calls[0].init?.headers as Record<string, string>)["content-type"]).toBe(
      "application/json",
    );
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      machine_id: "22222222-2222-4222-8222-222222222222",
    });
    // Returned verbatim so the exact signed bytes reach the agent unchanged.
    expect(out).toBe(grantText);
  });

  it("mintGrant includes optional machine_group_id + session_id when provided", async () => {
    const { fn, calls } = fakeFetch(() => new Response("{}", { status: 200 }));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await client.mintGrant("m-1", { machineGroupId: "g-1", sessionId: "s-1" });
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      machine_id: "m-1",
      machine_group_id: "g-1",
      session_id: "s-1",
    });
  });

  it("mintGrant throws a ControlPlaneError carrying the status + body error on 401", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "unauthorized" }, 401));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.mintGrant("m-1")).rejects.toMatchObject({
      name: "ControlPlaneError",
      status: 401,
    });
    // And the message surfaces the server's reason.
    await expect(client.mintGrant("m-1")).rejects.toThrow(/unauthorized/);
  });

  it("mintGrant surfaces a 403 (technician lacks backstage authorization)", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "capability denied" }, 403));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.mintGrant("m-1").catch((e) => e);
    expect(err).toBeInstanceOf(ControlPlaneError);
    expect((err as ControlPlaneError).status).toBe(403);
  });

  it("getIssuerPubkey GETs /grant/pubkey and returns the hex key", async () => {
    const { fn, calls } = fakeFetch(() =>
      jsonResponse({ grant_issuer_pubkey: "abc123" }),
    );
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    const key = await client.getIssuerPubkey();
    expect(calls[0].url).toBe("/cp/grant/pubkey");
    expect(calls[0].init?.method).toBe("GET");
    expect(calls[0].init?.credentials).toBe("include");
    expect(key).toBe("abc123");
  });

  it("getIssuerPubkey throws a ControlPlaneError carrying the server error on non-OK", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "service unavailable" }, 503));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.getIssuerPubkey().catch((e) => e);
    expect(err).toBeInstanceOf(ControlPlaneError);
    expect((err as ControlPlaneError).status).toBe(503);
    expect((err as ControlPlaneError).message).toMatch(/service unavailable/);
  });

  it("login POSTs credentials (with optional totp) to /auth/login", async () => {
    const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await client.login("acme", "alice@acme.test", "pw", "123456");
    expect(calls[0].url).toBe("/cp/auth/login");
    expect(calls[0].init?.method).toBe("POST");
    expect(calls[0].init?.credentials).toBe("include");
    // These key names are the Go `loginRequest` json tags. `toEqual` (not `toMatchObject`) so an
    // EXTRA key fails too: this test previously pinned `{username, password, totp}`, none of which
    // the server decodes, and pinning the wrong shape is how the bug survived.
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      tenant: "acme",
      email: "alice@acme.test",
      password: "pw",
      totp_code: "123456",
    });
  });

  it("remembered login explicitly opts in and still sends password and TOTP", async () => {
    const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await client.login("loam", "owner@example.test", "pw", "123456", true);
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      tenant: "loam", email: "owner@example.test", password: "pw",
      totp_code: "123456", remember_device: true,
    });
  });

  it("login omits totp when not supplied and throws on bad credentials", async () => {
    const { fn, calls } = fakeFetch(() => jsonResponse({ error: "invalid credentials" }, 401));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.login("acme", "alice@acme.test", "wrong")).rejects.toMatchObject({ status: 401 });
    expect(JSON.parse(calls[0].init?.body as string)).toEqual({
      tenant: "acme",
      email: "alice@acme.test",
      password: "wrong",
    });
  });

  it("normalizes a trailing slash in the base URL", async () => {
    const { fn, calls } = fakeFetch(() => new Response("{}", { status: 200 }));
    const client = new ControlPlaneClient({ baseUrl: "http://127.0.0.1:8081/", fetch: fn });
    await client.mintGrant("m-1");
    expect(calls[0].url).toBe("http://127.0.0.1:8081/grant/mint");
  });

  it("logout POSTs to /auth/logout with credentials and the CSRF header", async () => {
    // mutatingHeaders() reads document.cookie; inject a fake document so the node test env
    // exercises the same CSRF-token path a browser would.
    const g = globalThis as Record<string, unknown>;
    const savedDocument = g.document;
    g.document = { cookie: "rmt_csrf=csrf-tok" };
    try {
      const { fn, calls } = fakeFetch(() => new Response(null, { status: 204 }));
      const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
      await client.logout();
      expect(calls).toHaveLength(1);
      expect(calls[0].url).toBe("/cp/auth/logout");
      expect(calls[0].init?.method).toBe("POST");
      expect(calls[0].init?.credentials).toBe("include");
      expect((calls[0].init?.headers as Record<string, string>)[CSRF_HEADER_NAME]).toBe("csrf-tok");
    } finally {
      g.document = savedDocument;
    }
  });

  it("logout throws a ControlPlaneError carrying the status and server reason on non-OK", async () => {
    const { fn } = fakeFetch(() => jsonResponse({ error: "session expired" }, 401));
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    await expect(client.logout()).rejects.toMatchObject({
      name: "ControlPlaneError",
      status: 401,
    });
    await expect(client.logout()).rejects.toThrow(/session expired/);
  });

  it("toError falls back to res.statusText when the error body is not JSON", async () => {
    // Every other error-path stub returns jsonResponse(), so the catch {} inside toError() was
    // never reached. This test returns a plain-text body to force that branch.
    const { fn } = fakeFetch(
      () => new Response("Service Unavailable", { status: 503, statusText: "Service Unavailable" }),
    );
    const client = new ControlPlaneClient({ baseUrl: "/cp", fetch: fn });
    const err = await client.logout().catch((e) => e);
    expect(err).toBeInstanceOf(ControlPlaneError);
    expect((err as ControlPlaneError).status).toBe(503);
    expect((err as ControlPlaneError).message).toMatch(/Service Unavailable/);
  });
});
