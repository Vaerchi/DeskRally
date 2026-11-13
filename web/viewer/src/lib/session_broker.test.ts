import { describe, expect, it, vi } from "vitest";

import type { ConsoleApi, SessionSignaling, StartedSession } from "./console_api";
import { ConsoleApiError } from "./console_api";
import { acquireBrokeredSession, releaseBrokeredSession } from "./session_broker";

// Minimal SessionRecord stub — only the field acquireBrokeredSession reads (session.id).
const STUB_SESSION = {
  id: "sess-abc",
  tenant_id: "t1",
  machine_id: "m1",
  technician_id: "u1",
  started_at: "2026-01-01T00:00:00Z",
  ended_at: undefined,
  consent_policy: "none",
  granted_caps: null,
  machine_group_id: "g1",
  machine_device_id: "dev-1",
  machine_name: "host",
  machine_alias: "",
  note: "",
};

const STUB_SIGNALING: SessionSignaling = {
  url: "wss://signaling.example/",
  device_id: "dev-1",
  session_id: "sess-abc",
  ticket: { payload: "tok", signature: "sig" } as unknown as SessionSignaling["ticket"],
};

// --- acquireBrokeredSession --------------------------------------------------

describe("acquireBrokeredSession", () => {
  it("resolves BrokeredSession when startBrokeredSession returns a signaling envelope", async () => {
    const started: StartedSession = {
      session: STUB_SESSION,
      signaling: STUB_SIGNALING,
      session_policy: { access: "control", signed: "signed-blob" },
    };
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockResolvedValue(started),
    };

    const result = await acquireBrokeredSession(api, "dev-1");

    expect(result).not.toBeNull();
    expect(result?.sessionId).toBe("sess-abc");
    expect(result?.signaling).toStrictEqual(STUB_SIGNALING);
    expect(result?.sessionPolicy).toStrictEqual({ access: "control", signed: "signed-blob" });
  });

  it("returns null in dev mode when startBrokeredSession resolves with no signaling (no-issuer path)", async () => {
    const started: StartedSession = { session: STUB_SESSION };
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockResolvedValue(started),
    };

    const result = await acquireBrokeredSession(api, "dev-1", true);

    expect(result).toBeNull();
  });

  it("throws in production mode when CP returns success with no signaling envelope", async () => {
    const started: StartedSession = { session: STUB_SESSION };
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockResolvedValue(started),
    };

    await expect(acquireBrokeredSession(api, "dev-1", false)).rejects.toThrow();
  });

  it("returns null in dev mode when startBrokeredSession throws a network error (CP unreachable)", async () => {
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockRejectedValue(new Error("network failure")),
    };

    const result = await acquireBrokeredSession(api, "dev-1", true);

    expect(result).toBeNull();
  });

  it("throws a network error in production mode so the caller surfaces CP unavailability", async () => {
    const networkErr = new Error("network failure");
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockRejectedValue(networkErr),
    };

    await expect(acquireBrokeredSession(api, "dev-1", false)).rejects.toThrow(networkErr);
  });

  it("returns null when 5xx in dev mode (local stack with -insecure-no-ticket-verification)", async () => {
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockRejectedValue(new ConsoleApiError(503, "service unavailable")),
    };

    const result = await acquireBrokeredSession(api, "dev-1", true);

    expect(result).toBeNull();
  });

  it("re-throws 5xx from CP in production mode so the caller surfaces a clear error", async () => {
    const serverErr = new ConsoleApiError(503, "service unavailable");
    const api: Pick<ConsoleApi, "startBrokeredSession"> = {
      startBrokeredSession: vi.fn().mockRejectedValue(serverErr),
    };

    await expect(acquireBrokeredSession(api, "dev-1", false)).rejects.toThrow(serverErr);
  });
});

// --- releaseBrokeredSession --------------------------------------------------

describe("releaseBrokeredSession", () => {
  it("is a no-op when sessionId is null — endSession is never called", () => {
    const api: Pick<ConsoleApi, "endSession"> = {
      endSession: vi.fn(),
    };

    releaseBrokeredSession(api, null);

    expect(api.endSession).not.toHaveBeenCalled();
  });

  it("is a no-op when sessionId is undefined — endSession is never called", () => {
    const api: Pick<ConsoleApi, "endSession"> = {
      endSession: vi.fn(),
    };

    releaseBrokeredSession(api, undefined);

    expect(api.endSession).not.toHaveBeenCalled();
  });

  it("calls endSession with the id and swallows a rejection — does not throw", async () => {
    // session_broker.ts:58 — `void api.endSession(sessionId).catch(() => {})`
    const api: Pick<ConsoleApi, "endSession"> = {
      endSession: vi.fn().mockRejectedValue(new Error("server gone")),
    };

    // releaseBrokeredSession is synchronous (fire-and-forget); no throw at the call site.
    expect(() => releaseBrokeredSession(api, "sess-abc")).not.toThrow();
    expect(api.endSession).toHaveBeenCalledWith("sess-abc");

    // Let the microtask queue drain so the swallowed rejection is fully handled before the
    // test exits — avoids an unhandled-rejection warning from the runtime.
    await Promise.resolve();
  });
});
