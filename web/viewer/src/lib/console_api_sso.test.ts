import { describe, expect, it } from "vitest";
import { ConsoleApiClient, ConsoleApiError, CSRF_HEADER_NAME } from "./console_api";

const settings = {
  profile: "entra", entra_tenant_id: "tenant", client_id: "client", enabled: true,
  trust_entra_mfa: false, has_secret: true, version: 1, last_test: null,
  redirect_uri: "https://acme.example/cp/auth/oidc/callback",
};
const completed = {
  user_id: "user", tenant_id: "tenant", expires_at: "2026-10-17T12:00:00Z",
  csrf_token: "new-csrf", return_path: "/console?area=enrollment",
};

function fixture(responses: Response[], cookies: () => string = () => "rmt_csrf=old-csrf") {
  const calls: { url: string; init: RequestInit }[] = [];
  const api = new ConsoleApiClient({ baseUrl: "/cp/", cookies, fetch: async (url, init) => {
    calls.push({ url, init: init ?? {} });
    const response = responses.shift();
    if (!response) throw new Error("Unexpected request");
    return response;
  } });
  return { api, calls };
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json" },
});

describe("ConsoleApiClient SSO", () => {
  it("encodes the public discovery tenant and preserves provider labels", async () => {
    const info = { providers: [{ id: "entra", label: "Microsoft" }] };
    const { api, calls } = fixture([json(info)]);
    expect(await api.ssoInfo("a&b")).toEqual(info);
    expect(calls[0].url).toBe("/cp/auth/sso-info?tenant=a%26b");
    expect(calls[0].init.method).toBe("GET");
    expect(calls[0].init.credentials).toBe("include");
    expect(new Headers(calls[0].init.headers).has(CSRF_HEADER_NAME)).toBe(false);
  });

  it("gets and saves flat settings, omitting blank secrets and unrelated fields", async () => {
    const { api, calls } = fixture([json({ ...settings, client_secret: "never expose" }), json(settings), json(settings)]);
    expect(await api.getSSO()).toEqual(settings);
    const input = { entra_tenant_id: "tenant", client_id: "client", enabled: true, trust_entra_mfa: false };
    await api.putSSO({ ...input, client_secret: "" });
    await api.putSSO({ ...input, client_secret: "replacement" });
    expect(calls.map(c => [c.url, c.init.method])).toEqual([
      ["/cp/tenant/sso", "GET"], ["/cp/tenant/sso", "PUT"], ["/cp/tenant/sso", "PUT"],
    ]);
    expect(JSON.parse(String(calls[1].init.body))).toEqual(input);
    expect(JSON.parse(String(calls[2].init.body))).toEqual({ ...input, client_secret: "replacement" });
    expect(new Headers(calls[1].init.headers).get(CSRF_HEADER_NAME)).toBe("old-csrf");
  });

  it("starts link/test and accepts unlink's 204 without a JSON body", async () => {
    const url = "https://login.microsoftonline.com/authorize";
    const { api, calls } = fixture([json({ url }), json({ url }), new Response(null, { status: 204 })]);
    expect(await api.startSSOLink()).toEqual({ url });
    expect(await api.startSSOTest()).toEqual({ url });
    await api.unlinkSSO();
    expect(calls.map(c => c.url)).toEqual([
      "/cp/auth/oidc/link/start", "/cp/auth/oidc/test/start", "/cp/auth/oidc/unlink",
    ]);
    for (const { init } of calls) {
      expect(init.method).toBe("POST");
      expect(init.credentials).toBe("include");
      expect(init.body).toBeUndefined();
      expect(new Headers(init.headers).get(CSRF_HEADER_NAME)).toBe("old-csrf");
    }
  });

  it("posts public TOTP fields and adopts CSRF until the cookie rotates", async () => {
    let cookie = "rmt_csrf=old-csrf";
    const { api, calls } = fixture([
      json(completed), new Response(null, { status: 204 }), new Response(null, { status: 204 }),
    ], () => cookie);
    expect(await api.completeSSOTotp("pending", "123456")).toEqual(completed);
    expect(calls[0].url).toBe("/cp/auth/oidc/totp");
    expect(calls[0].init.method).toBe("POST");
    expect(calls[0].init.credentials).toBe("include");
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ pending_id: "pending", totp_code: "123456" });
    expect(new Headers(calls[0].init.headers).has(CSRF_HEADER_NAME)).toBe(false);
    await api.unlinkSSO();
    expect(new Headers(calls[1].init.headers).get(CSRF_HEADER_NAME)).toBe("new-csrf");
    cookie = "rmt_csrf=rotated";
    await api.unlinkSSO();
    expect(new Headers(calls[2].init.headers).get(CSRF_HEADER_NAME)).toBe("rotated");
  });

  it("preserves JSON and HTML failures as typed API errors", async () => {
    const { api } = fixture([json({ error: "fresh step-up required" }, 403),
      new Response("<html>Sign-in unsuccessful</html>", { status: 401 })]);
    await expect(api.startSSOLink()).rejects.toMatchObject({
      status: 403, kind: "forbidden", message: "could not start SSO link: fresh step-up required",
    });
    await expect(api.completeSSOTotp("pending", "bad")).rejects.toMatchObject({ status: 401, kind: "unauthenticated" });
  });

  it("rejects malformed successful responses", async () => {
    const { api } = fixture([json({ providers: [{}] }), json({}), json({ url: "" }),
      json({ ...completed, csrf_token: null })]);
    await expect(api.ssoInfo("acme")).rejects.toBeInstanceOf(ConsoleApiError);
    await expect(api.getSSO()).rejects.toBeInstanceOf(ConsoleApiError);
    await expect(api.startSSOTest()).rejects.toBeInstanceOf(ConsoleApiError);
    await expect(api.completeSSOTotp("pending", "123456")).rejects.toBeInstanceOf(ConsoleApiError);
  });

  it("reads step-up freshness strictly: only fresh === true skips the code", async () => {
    const { api, calls } = fixture([json({ fresh: true }), json({ fresh: "true" }), json({})]);
    expect(await api.ssoStepUpFresh()).toBe(true);
    expect(await api.ssoStepUpFresh()).toBe(false);
    expect(await api.ssoStepUpFresh()).toBe(false);
    expect(calls[0].url).toBe("/cp/auth/oidc/step-up-status");
    expect(calls[0].init.method).toBe("GET");
  });

  it("reads the signed-in user's email and refuses a malformed answer", async () => {
    const { api, calls } = fixture([json({ email: "ed@example.com" }), json({ email: 7 })]);
    expect(await api.me()).toEqual({ email: "ed@example.com", userId: null, capabilities: [], accessExpired: false, accessExpiresAt: null, accessWindow: null, accessWindowVaries: false, accessOutsideWindow: false });
    expect(calls[0].url).toBe("/cp/me");
    await expect(api.me()).rejects.toBeInstanceOf(ConsoleApiError);
  });
});
