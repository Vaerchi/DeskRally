import { describe, expect, it, vi } from "vitest";
import { AuthSession } from "./auth_session";

describe("AuthSession", () => {
  it("expires once for concurrent protected 401s and invalidates pending work", async () => {
    const expired = vi.fn();
    const session = new AuthSession(expired, async () => new Response(null, { status: 401 }));
    const epoch = session.epoch;
    await Promise.all([session.fetch("/cp/machines"), session.fetch("/cp/auth/session")]);
    expect(expired).toHaveBeenCalledTimes(1);
    expect(session.isCurrent(epoch)).toBe(false);
  });

  it.each(["/auth/login", "/auth/logout", "/auth/password/redeem", "/grant/pubkey"])("keeps %s failures local", async (path) => {
    const expired = vi.fn();
    const session = new AuthSession(expired, async () => new Response(null, { status: 401 }));
    expect((await session.fetch(`/cp${path}`)).status).toBe(401);
    expect(expired).not.toHaveBeenCalled();
  });

  it.each([403, 404, 500, 503])("does not interpret HTTP %i as expiry", async (status) => {
    const expired = vi.fn();
    const session = new AuthSession(expired, async () => new Response(null, { status }));
    await session.fetch("/cp/auth/session");
    expect(expired).not.toHaveBeenCalled();
  });

  it("does not interpret an offline connection as expiry", async () => {
    const expired = vi.fn();
    const session = new AuthSession(expired, async () => { throw new TypeError("offline"); });
    await expect(session.fetch("/cp/auth/session")).rejects.toThrow("offline");
    expect(expired).not.toHaveBeenCalled();
  });

  it("fires onExpired exactly once when expire() is called twice consecutively", () => {
    const expired = vi.fn();
    const session = new AuthSession(expired);
    session.expire();
    session.expire();
    expect(expired).toHaveBeenCalledTimes(1);
  });

  it("ignores a prior login's delayed 401, but detects the new login's expiry", async () => {
    let reply!: (response: Response) => void;
    const expired = vi.fn();
    const fetch = vi.fn().mockImplementationOnce(() => new Promise<Response>((resolve) => { reply = resolve; }))
      .mockResolvedValue(new Response(null, { status: 401 }));
    const session = new AuthSession(expired, fetch);
    const old = session.fetch("/cp/machines");
    session.expire();
    session.signedIn();
    const epoch = session.epoch;
    reply(new Response(null, { status: 401 }));
    await old;
    expect(expired).toHaveBeenCalledTimes(1);
    expect(session.isCurrent(epoch)).toBe(true);
    await session.fetch("/cp/auth/session");
    expect(expired).toHaveBeenCalledTimes(2);
  });
});
