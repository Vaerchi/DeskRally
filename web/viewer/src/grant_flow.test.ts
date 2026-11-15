/**
 * V4 secure-mode grant-flow wiring: the console's "Get access" path + the prod login gate.
 *
 * `App.tsx`'s `handleFetchGrant` mints a grant from the control plane and installs it over the
 * Control channel; on a 401 it shows the login form. App is `.tsx` and the vitest env is `node`, so
 * (following `v3_wiring.test.ts`) rather than render App we exercise the exact logic against the
 * REAL `ControlPlaneClient` (fake fetch) + REAL `ControlClient` (capturing send) — proving the
 * minted `SignedGrant` JSON flows verbatim into a real `InstallGrant` control frame the agent
 * decodes. Plus a structural render of the `LoginForm`.
 */
import { describe, it, expect } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";

import { ControlClient, ControlPlaneClient, ControlPlaneError, decodeControl } from "./lib";
import { LoginForm } from "./components/LoginForm";

const DEVICE = "22222222-2222-4222-8222-222222222222";
const SIGNED_GRANT_JSON = JSON.stringify({
  claims: {
    grant: { technician_id: "0", session_id: "0", machine_id: DEVICE, capabilities: [] },
    issued_at_ms: 1,
    expires_at_ms: 2,
  },
  sig: "abcd",
});

/** Mirror of App.tsx `handleFetchGrant`: mint → install; on 401 flag login-required, then rethrow. */
function makeFetchGrant(
  controlPlane: ControlPlaneClient,
  control: ControlClient,
  deviceId: string,
  onLoginRequired: () => void,
) {
  return async () => {
    try {
      const signedGrant = await controlPlane.mintGrant(deviceId);
      control.installGrant(signedGrant);
    } catch (e) {
      if (e instanceof ControlPlaneError && e.status === 401) onLoginRequired();
      throw e;
    }
  };
}

describe("V4 grant-fetch wiring (mint → install over the Control channel)", () => {
  it("mints for the connected device and frames a real InstallGrant carrying the SignedGrant JSON", async () => {
    const fetchCalls: { url: string; body: unknown }[] = [];
    const cp = new ControlPlaneClient({
      baseUrl: "/cp",
      fetch: (url, init) => {
        fetchCalls.push({ url, body: init?.body });
        return Promise.resolve(new Response(SIGNED_GRANT_JSON, { status: 200 }));
      },
    });
    const controlFrames: Uint8Array[] = [];
    const control = new ControlClient((payload) => controlFrames.push(payload));

    let loginRequired = false;
    await makeFetchGrant(cp, control, DEVICE, () => (loginRequired = true))();

    // Minted for the connected device.
    expect(fetchCalls[0].url).toBe("/cp/grant/mint");
    expect(JSON.parse(fetchCalls[0].body as string)).toEqual({ machine_id: DEVICE });

    // Installed as a real Control-channel InstallGrant carrying the exact SignedGrant JSON.
    expect(controlFrames).toHaveLength(1);
    const msg = decodeControl(controlFrames[0]);
    expect(msg.t).toBe("InstallGrant");
    if (msg.t !== "InstallGrant") throw new Error("expected InstallGrant");
    expect(msg.c.signed_grant).toBe(SIGNED_GRANT_JSON);
    expect(loginRequired).toBe(false);
  });

  it("a 401 from mint flags login-required and rethrows (no InstallGrant framed)", async () => {
    const cp = new ControlPlaneClient({
      baseUrl: "/cp",
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }),
        ),
    });
    const controlFrames: Uint8Array[] = [];
    const control = new ControlClient((payload) => controlFrames.push(payload));

    let loginRequired = false;
    const run = makeFetchGrant(cp, control, DEVICE, () => (loginRequired = true));
    await expect(run()).rejects.toMatchObject({ status: 401 });
    expect(loginRequired).toBe(true);
    expect(controlFrames).toHaveLength(0);
  });

  it("a 403 from mint surfaces the error without flagging login-required", async () => {
    const cp = new ControlPlaneClient({
      baseUrl: "/cp",
      fetch: () =>
        Promise.resolve(
          new Response(JSON.stringify({ error: "capability denied" }), { status: 403 }),
        ),
    });
    const control = new ControlClient(() => {});
    let loginRequired = false;
    const run = makeFetchGrant(cp, control, DEVICE, () => (loginRequired = true));
    await expect(run()).rejects.toThrow(/capability denied/);
    expect(loginRequired).toBe(false);
  });

  it("after login, a retry mints again with the (now-cookied) request", async () => {
    let mints = 0;
    let status = 401;
    const cp = new ControlPlaneClient({
      baseUrl: "/cp",
      fetch: (url) => {
        if (url.endsWith("/auth/login")) return Promise.resolve(new Response(null, { status: 204 }));
        mints += 1;
        const s = status;
        status = 200; // the post-login retry succeeds
        return Promise.resolve(
          s === 200
            ? new Response(SIGNED_GRANT_JSON, { status: 200 })
            : new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 }),
        );
      },
    });
    const control = new ControlClient(() => {});
    let loginRequired = false;
    const fetchGrant = makeFetchGrant(cp, control, DEVICE, () => (loginRequired = true));

    await expect(fetchGrant()).rejects.toMatchObject({ status: 401 });
    expect(loginRequired).toBe(true);

    // Mirror App.handleLoginSuccess: login, then retry the mint.
    await cp.login("acme", "alice@acme.test", "pw");
    await fetchGrant();
    expect(mints).toBe(2); // first (401) + post-login retry (200)
  });
});

describe("V4 LoginForm", () => {
  it("renders the credential fields (structural build check)", () => {
    const html = renderToStaticMarkup(
      createElement(LoginForm, { onLogin: async () => {}, hostname: "localhost" }),
    );
    expect(html).toContain('data-testid="cp-login"');
    // TENANT is required by the server and was absent from this form entirely, which is why a
    // Postgres-backed console could not log in. Its presence is the regression guard.
    expect(html).toContain('data-testid="cp-login-tenant"');
    expect(html).toContain('data-testid="cp-login-email"');
    expect(html).toContain('data-testid="cp-login-password"');
    expect(html).toContain('data-testid="cp-login-totp"');
    expect(html).toContain('data-testid="cp-login-submit"');
  });

  it("prefills the tenant from the hostname, and leaves it empty when it cannot be derived", () => {
    const withSub = renderToStaticMarkup(
      createElement(LoginForm, { onLogin: async () => {}, hostname: "main.deskrally.com" }),
    );
    expect(withSub).toContain(`value="main"`);

    // Negative control: on localhost nothing is derivable, so the field must start EMPTY rather
    // than prefilling a guess the operator would have to notice and clear.
    const dev = renderToStaticMarkup(
      createElement(LoginForm, { onLogin: async () => {}, hostname: "localhost" }),
    );
    expect(dev).not.toContain('value="localhost"');
  });

});
