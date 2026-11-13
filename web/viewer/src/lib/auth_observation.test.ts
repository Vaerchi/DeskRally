import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AUTH_CHECK_TIMEOUT_MS, boundedAuthCheck } from "./auth_observation";
import { AuthSession } from "./auth_session";

describe("boundedAuthCheck", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("returns the response when the fetch completes before the timeout", async () => {
    const ok = new Response(null, { status: 200 });
    const fetchImpl = vi.fn().mockResolvedValue(ok);
    const ctrl = new AbortController();
    const result = await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(result).toBe(ok);
    expect(fetchImpl).toHaveBeenCalledOnce();
  });

  it("passes credentials and no-store cache to the underlying fetch", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const ctrl = new AbortController();
    await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(fetchImpl).toHaveBeenCalledWith("/auth/session", expect.objectContaining({
      credentials: "include",
      cache: "no-store",
    }));
  });

  it("returns null when the request hangs past the timeout, so pending resets for the next check", async () => {
    const fetchImpl = vi.fn().mockImplementation((_url: string, { signal }: RequestInit) =>
      new Promise<Response>((_res, rej) => {
        signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
      }),
    );
    const ctrl = new AbortController();
    const promise = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    await vi.advanceTimersByTimeAsync(AUTH_CHECK_TIMEOUT_MS + 1);
    expect(await promise).toBeNull();
  });

  it("second check succeeds when run after the first times out", async () => {
    let firstAbort!: () => void;
    const fetchImpl = vi.fn()
      .mockImplementationOnce((_url: string, { signal }: RequestInit) =>
        new Promise<Response>((_res, rej) => {
          firstAbort = () => rej(new DOMException("aborted", "AbortError"));
          signal?.addEventListener("abort", firstAbort);
        }),
      )
      .mockResolvedValue(new Response(null, { status: 200 }));

    const ctrl = new AbortController();

    const first = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    await vi.advanceTimersByTimeAsync(AUTH_CHECK_TIMEOUT_MS + 1);
    expect(await first).toBeNull();

    // Simulate the next scheduled check — must be able to start a new request.
    const second = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(await second).toBeInstanceOf(Response);
    expect((await second)?.status).toBe(200);
  });

  it("returns null when the cleanup signal fires before the timeout", async () => {
    const fetchImpl = vi.fn().mockImplementation((_url: string, { signal }: RequestInit) =>
      new Promise<Response>((_res, rej) => {
        signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
      }),
    );
    const ctrl = new AbortController();
    const promise = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    ctrl.abort();
    expect(await promise).toBeNull();
  });

  it("returns null on a network error without treating it as expiry", async () => {
    const fetchImpl = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    const ctrl = new AbortController();
    const result = await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(result).toBeNull();
  });

  it("passes a 401 response through so the caller's AuthSession can handle expiry", async () => {
    const unauthorized = new Response(null, { status: 401 });
    const fetchImpl = vi.fn().mockResolvedValue(unauthorized);
    const ctrl = new AbortController();
    const result = await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(result).toBe(unauthorized);
  });

  it("leaves no pending timers after the fetch resolves", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const ctrl = new AbortController();
    await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("leaves no pending timers after cleanup-signal abort", async () => {
    const fetchImpl = vi.fn().mockImplementation((_url: string, { signal }: RequestInit) =>
      new Promise<Response>((_res, rej) => {
        signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
      }),
    );
    const ctrl = new AbortController();
    const promise = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    ctrl.abort();
    await promise;
    expect(vi.getTimerCount()).toBe(0);
  });

  it("returns null immediately without issuing a fetch when cleanupSignal is already aborted", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(new Response(null, { status: 200 }));
    const ctrl = new AbortController();
    ctrl.abort();
    const result = await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, fetchImpl);
    expect(result).toBeNull();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe("boundedAuthCheck expiry integration (AuthSession)", () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it("a timed-out check does not expire the session", async () => {
    const onExpired = vi.fn();
    const inner = vi.fn().mockImplementation((_url: string, init: RequestInit) =>
      new Promise<Response>((_res, rej) => {
        init.signal?.addEventListener("abort", () => rej(new DOMException("aborted", "AbortError")));
      }),
    );
    const session = new AuthSession(onExpired, inner);
    const ctrl = new AbortController();
    const promise = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, session.fetch);
    await vi.advanceTimersByTimeAsync(AUTH_CHECK_TIMEOUT_MS + 1);
    expect(await promise).toBeNull();
    expect(onExpired).not.toHaveBeenCalled();
  });

  it("a network error does not expire the session", async () => {
    const onExpired = vi.fn();
    const inner = vi.fn().mockRejectedValue(new TypeError("Failed to fetch"));
    const session = new AuthSession(onExpired, inner);
    const ctrl = new AbortController();
    const result = await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, session.fetch);
    expect(result).toBeNull();
    expect(onExpired).not.toHaveBeenCalled();
  });

  it("a 401 response expires the session", async () => {
    const onExpired = vi.fn();
    const inner = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
    const session = new AuthSession(onExpired, inner);
    const ctrl = new AbortController();
    await boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, session.fetch);
    expect(onExpired).toHaveBeenCalledOnce();
  });

  it("a 401 from an old epoch does not expire a newer login", async () => {
    const onExpired = vi.fn();
    let resolveOldFetch!: (r: Response) => void;
    const inner = vi.fn()
      .mockImplementationOnce(() => new Promise<Response>((res) => { resolveOldFetch = res; }))
      .mockResolvedValue(new Response(null, { status: 200 }));
    const session = new AuthSession(onExpired, inner);
    const ctrl = new AbortController();

    // Capture epoch 0 inside session.fetch before signedIn() advances it.
    const oldPromise = boundedAuthCheck("/auth/session", ctrl.signal, AUTH_CHECK_TIMEOUT_MS, session.fetch);

    // A re-login advances the generation; the old fetch now carries a stale epoch.
    session.signedIn();

    // The stale 401 arrives — session.isCurrent(0) is false, so expire() must not fire.
    resolveOldFetch(new Response(null, { status: 401 }));
    await oldPromise;

    expect(onExpired).not.toHaveBeenCalled();
  });
});
