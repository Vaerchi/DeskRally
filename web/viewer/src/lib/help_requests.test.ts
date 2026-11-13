import { describe, expect, it, vi } from "vitest";
import { ConsoleApiError, type HelpRequest, type StartedSession } from "./console_api";
import {
  AcceptKeys,
  HelpAcceptController,
  type HelpAcceptState,
  classifyAcceptFailure,
  HELP_NOTE_LABEL,
  HELP_NOTE_MAX,
  HelpRequestPoller,
  acceptedHelpSession,
  displayNote,
  helpBadge,
  helpBellView,
  helpRowView,
} from "./help_requests";

function req(id: string, extra: Partial<HelpRequest> = {}): HelpRequest {
  return {
    id, machine_id: `m-${id}`, machine_name: "FRONT-DESK", group_id: "g1", note: "printer is jammed",
    note_source: "guest_machine", requested_from: "machine", status: "open",
    created_at: "2026-10-31T10:00:00Z", expires_at: "2026-10-31T10:30:00Z", can_accept: true, ...extra,
  };
}

describe("helpBadge", () => {
  it("hides at zero, counts, and caps at 99+", () => {
    expect(helpBadge(0)).toBeNull();
    expect(helpBadge(-1)).toBeNull();
    expect(helpBadge(3)).toBe("3");
    expect(helpBadge(99)).toBe("99");
    expect(helpBadge(100)).toBe("99+");
  });
});

describe("displayNote", () => {
  it("is plain text: markup is kept inert as text, never interpreted", () => {
    expect(displayNote("<img src=x onerror=alert(1)> **bold**")).toBe("<img src=x onerror=alert(1)> **bold**");
  });
  it("drops control and bidirectional-format characters and flattens whitespace controls", () => {
    expect(displayNote("a\u0007b\u202Ec\u200Bd\nline2\tx")).toBe("abcd line2 x");
    expect(displayNote("\u0000\u001f\u007f\u0085")).toBe("");
  });
  it("is bounded to the server cap, by characters", () => {
    expect(Array.from(displayNote("é".repeat(500))).length).toBe(HELP_NOTE_MAX);
    expect(displayNote(42)).toBe("");
    expect(displayNote(undefined)).toBe("");
  });
});

describe("helpRowView", () => {
  it("labels the note as the guest machine's and prefers the alias as the title", () => {
    const v = helpRowView(req("a", { machine_alias: "Reception PC" }));
    expect(v.title).toBe("Reception PC");
    expect(v.subtitle).toBe("FRONT-DESK");
    expect(v.noteLabel).toBe(HELP_NOTE_LABEL);
    expect(HELP_NOTE_LABEL).toBe("From the guest's machine");
    expect(v.note).toBe("printer is jammed");
  });
  it("offers Accept only for an open, acceptable machine that is not known to be offline", () => {
    expect(helpRowView(req("a")).canAccept).toBe(true);
    expect(helpRowView(req("a", { online: true })).canAccept).toBe(true);
    const off = helpRowView(req("a", { online: false }));
    expect(off.canAccept).toBe(false);
    expect(off.offline).toBe(true);
    // Presence unknown (absent) is not "offline".
    expect(helpRowView(req("a")).offline).toBe(false);
    expect(helpRowView(req("a", { can_accept: false })).canAccept).toBe(false);
    expect(helpRowView(req("a", { status: "accepted" })).canAccept).toBe(false);
  });
  it("falls back to the machine id when the name is blank", () => {
    expect(helpRowView(req("a", { machine_name: "  " })).title).toBe("m-a");
  });
});

describe("helpBellView", () => {
  it("counts and lists only OPEN requests", () => {
    const v = helpBellView([req("a"), req("b", { status: "cancelled" }), req("c")]);
    expect(v.badge).toBe("2");
    expect(v.label).toBe("Help requests, 2 waiting");
    expect(v.rows.map((r) => r.id)).toEqual(["a", "c"]);
    expect(v.empty).toBe(false);
  });
  it("is empty and unbadged with nothing open", () => {
    const v = helpBellView([]);
    expect(v.badge).toBeNull();
    expect(v.label).toBe("Help requests");
    expect(v.empty).toBe(true);
  });
});

const started = (extra: Partial<StartedSession> = {}): StartedSession => ({
  session: { id: "s9" } as StartedSession["session"],
  signaling: { url: "wss://sig.example/ws", device_id: "dev-1", session_id: "s9", ticket: {} } as unknown as StartedSession["signaling"],
  ...extra,
});

describe("acceptedHelpSession", () => {
  it("maps the accept response to an OWNED brokered session for the machine's device", () => {
    const got = acceptedHelpSession(started());
    expect(got.deviceId).toBe("dev-1");
    expect(got.signalingUrl).toBe("wss://sig.example/ws");
    expect(got.brokered.sessionId).toBe("s9");
    expect(got.brokered.owned).toBe(true);
    expect(got.brokered.sessionPolicy).toBeUndefined();
  });
  it("carries the signed session policy through", () => {
    const policy = { access: "view_only", signed: "x" } as unknown as StartedSession["session_policy"];
    expect(acceptedHelpSession(started({ session_policy: policy })).brokered.sessionPolicy).toBe(policy);
  });
  it("refuses a response without signaling instead of looking connected", () => {
    expect(() => acceptedHelpSession({ session: { id: "s9" } } as StartedSession)).toThrow(/no signaling/);
  });
});

describe("AcceptKeys", () => {
  it("returns the SAME key for the same request (a retry hits the server's idempotency), distinct across requests", () => {
    let n = 0;
    const keys = new AcceptKeys(() => `k${++n}`);
    expect(keys.forRequest("a")).toBe("k1");
    expect(keys.forRequest("a")).toBe("k1");
    expect(keys.forRequest("b")).toBe("k2");
  });
  it("stays bounded", () => {
    let n = 0;
    const keys = new AcceptKeys(() => `k${++n}`);
    for (let i = 0; i < 300; i++) keys.forRequest(`r${i}`);
    expect(keys.forRequest("r0")).not.toBe("k1"); // evicted, so it gets a fresh key
  });
});

describe("HelpRequestPoller", () => {
  it("publishes only open requests, polls on the interval and stops on stop()", async () => {
    vi.useFakeTimers();
    try {
      const list = vi.fn().mockResolvedValue([req("a"), req("b", { status: "expired" })]);
      const seen: string[][] = [];
      const poller = new HelpRequestPoller({ listHelpRequests: list }, (r) => seen.push(r.map((x) => x.id)), 15_000);
      poller.start();
      await vi.advanceTimersByTimeAsync(0);
      expect(seen).toEqual([["a"]]);
      await vi.advanceTimersByTimeAsync(15_000);
      expect(list).toHaveBeenCalledTimes(2);
      poller.stop();
      await vi.advanceTimersByTimeAsync(60_000);
      expect(list).toHaveBeenCalledTimes(2);
    } finally {
      vi.useRealTimers();
    }
  });
  it("keeps the last list through a transient failure and retries", async () => {
    vi.useFakeTimers();
    try {
      const list = vi.fn().mockResolvedValueOnce([req("a")]).mockRejectedValueOnce(new ConsoleApiError(503, "x")).mockResolvedValue([req("a"), req("c")]);
      const seen: string[][] = [];
      const poller = new HelpRequestPoller({ listHelpRequests: list }, (r) => seen.push(r.map((x) => x.id)), 1_000);
      poller.start();
      await vi.advanceTimersByTimeAsync(0);
      await vi.advanceTimersByTimeAsync(1_000);
      await vi.advanceTimersByTimeAsync(1_000);
      expect(seen).toEqual([["a"], ["a", "c"]]);
      poller.stop();
    } finally {
      vi.useRealTimers();
    }
  });
  it("stops quietly on 404 / 401 / 403 (no route, or a role that cannot start sessions)", async () => {
    for (const status of [404, 401, 403]) {
      vi.useFakeTimers();
      try {
        const list = vi.fn().mockRejectedValue(new ConsoleApiError(status, "no"));
        const seen: string[][] = [];
        const poller = new HelpRequestPoller({ listHelpRequests: list }, (r) => seen.push(r.map((x) => x.id)), 1_000);
        poller.start();
        await vi.advanceTimersByTimeAsync(10_000);
        expect(list, `status ${status}`).toHaveBeenCalledTimes(1);
        expect(seen).toEqual([[]]);
      } finally {
        vi.useRealTimers();
      }
    }
  });
  it("drops a late answer from a superseded poll", async () => {
    let release!: (rows: HelpRequest[]) => void;
    const list = vi.fn().mockImplementation(() => new Promise<HelpRequest[]>((r) => { release = r; }));
    const seen: string[][] = [];
    const poller = new HelpRequestPoller({ listHelpRequests: list }, (r) => seen.push(r.map((x) => x.id)));
    poller.start();
    poller.stop();
    release([req("late")]);
    await Promise.resolve();
    expect(seen).toEqual([]);
  });
});

describe("classifyAcceptFailure", () => {
  it("treats an unknown or transient outcome as RETRYABLE and a definite refusal as TERMINAL", () => {
    expect(classifyAcceptFailure(new TypeError("Failed to fetch"))).toBe("retryable"); // lost response
    expect(classifyAcceptFailure(new ConsoleApiError(200, "malformed body", "server"))).toBe("retryable"); // 2xx, unreadable
    for (const s of [408, 425, 429, 500, 502, 503, 504]) expect(classifyAcceptFailure(new ConsoleApiError(s, "x"))).toBe("retryable");
    for (const s of [400, 401, 403, 404, 409, 422]) expect(classifyAcceptFailure(new ConsoleApiError(s, "x"))).toBe("terminal");
  });
});

describe("helpBellView with an unresolved accept", () => {
  it("counts it in the badge even though the queue no longer lists the request", () => {
    expect(helpBellView([], 1).badge).toBe("1");
    expect(helpBellView([req("a")], 1).badge).toBe("2");
    expect(helpBellView([], 0).badge).toBeNull();
    expect(helpBellView([], 1).label).toBe("Help requests, 1 waiting");
  });
});

describe("HelpAcceptController (a lost accept response)", () => {
  const harness = () => {
    const states: HelpAcceptState[] = [];
    const calls: Array<{ id: string; op: string | undefined }> = [];
    const results: Array<() => Promise<StartedSession>> = [];
    const api = {
      acceptHelpRequest: vi.fn((id: string, op?: string) => {
        calls.push({ id, op });
        const next = results.shift();
        if (!next) throw new Error("no scripted result");
        return next();
      }),
    };
    let n = 0;
    const controller = new HelpAcceptController(api, new AcceptKeys(() => `key${++n}`), (s) => states.push(s));
    return { controller, calls, results, states, api };
  };

  it("keeps the attempt after a lost response and Retry resends the SAME request id and op_id until it connects", async () => {
    const h = harness();
    h.results.push(() => Promise.reject(new TypeError("Failed to fetch")), () => Promise.resolve(started()));
    const r = req("a");
    expect(await h.controller.attempt(r)).toBeNull();
    // the queue (refreshed) no longer lists "a", but the unresolved attempt does not depend on it
    const u = h.controller.snapshot().unresolved;
    expect(u?.request.id).toBe("a");
    expect(u?.opId).toBe("key1");
    expect(u?.attempts).toBe(1);
    expect(h.controller.snapshot().error).toBeNull();

    const session = await h.controller.retry();
    expect(session?.brokered.sessionId).toBe("s9");
    expect(h.calls).toEqual([{ id: "a", op: "key1" }, { id: "a", op: "key1" }]);
    expect(h.controller.snapshot()).toEqual({ accepting: null, error: null, unresolved: null });
  });

  it("stays unresolved across repeated transient failures, counting attempts, and shows 'Retrying…' meanwhile", async () => {
    const h = harness();
    h.results.push(
      () => Promise.reject(new ConsoleApiError(503, "still being prepared")),
      () => Promise.reject(new ConsoleApiError(503, "still being prepared")),
    );
    await h.controller.attempt(req("a"));
    await h.controller.retry();
    expect(h.controller.snapshot().unresolved?.attempts).toBe(2);
    expect(h.states.some((s) => s.accepting?.status === "Retrying…")).toBe(true);
    expect(h.calls.every((c) => c.op === "key1")).toBe(true);
  });

  it("a TERMINAL answer to the retry ends the unresolved state and is shown verbatim", async () => {
    const h = harness();
    h.results.push(
      () => Promise.reject(new TypeError("Failed to fetch")),
      () => Promise.reject(new ConsoleApiError(409, "help request is expired")),
    );
    await h.controller.attempt(req("a"));
    expect(await h.controller.retry()).toBeNull();
    expect(h.controller.snapshot().unresolved).toBeNull();
    expect(h.controller.snapshot().error).toEqual({ id: "a", message: "help request is expired" });
    expect(await h.controller.retry()).toBeNull(); // nothing left to retry
    expect(h.calls).toHaveLength(2);
  });

  it("a terminal failure on the first try never offers a retry", async () => {
    const h = harness();
    h.results.push(() => Promise.reject(new ConsoleApiError(404, "unknown help request")));
    await h.controller.attempt(req("a"));
    expect(h.controller.snapshot().unresolved).toBeNull();
    expect(h.controller.snapshot().error?.message).toBe("unknown help request");
  });

  it("refuses an attempt on ANOTHER request while one is unresolved, and the Retry for the first remains", async () => {
    const h = harness();
    h.results.push(() => Promise.reject(new TypeError("Failed to fetch")), () => Promise.resolve(started()));
    await h.controller.attempt(req("a", { machine_alias: "Reception PC" }));
    expect(h.controller.snapshot().unresolved?.request.id).toBe("a");

    expect(await h.controller.attempt(req("b"))).toBeNull();
    expect(h.calls).toHaveLength(1); // nothing was sent for b
    const s = h.controller.snapshot();
    expect(s.unresolved?.request.id).toBe("a"); // A's Retry state survived
    expect(s.unresolved?.opId).toBe("key1");
    expect(s.error?.id).toBe("b");
    expect(s.error?.message).toContain("Reception PC");
    expect(s.error?.message).toContain("Retry");

    const session = await h.controller.retry(); // A still retries with its own id + key
    expect(session?.brokered.sessionId).toBe("s9");
    expect(h.calls[1]).toEqual({ id: "a", op: "key1" });
    // once A is resolved, B may be accepted
    h.results.push(() => Promise.resolve(started()));
    expect(await h.controller.attempt(req("b"))).not.toBeNull();
    expect(h.calls[2].id).toBe("b");
  });

  it("an auth change (reset) makes an in-flight attempt inert: no state, no session; the retry is gone", async () => {
    const h = harness();
    let finish!: (s: StartedSession) => void;
    h.results.push(() => new Promise<StartedSession>((res) => { finish = res; }));
    const pending = h.controller.attempt(req("a"));
    h.controller.reset(); // signed out / switched tenant while the request was in flight
    finish(started());
    expect(await pending).toBeNull();
    expect(h.controller.snapshot()).toEqual({ accepting: null, error: null, unresolved: null });

    // an unresolved accept does not survive a reset either
    h.results.push(() => Promise.reject(new TypeError("Failed to fetch")));
    await h.controller.attempt(req("b"));
    expect(h.controller.snapshot().unresolved).not.toBeNull();
    h.controller.reset();
    expect(h.controller.snapshot().unresolved).toBeNull();
    expect(await h.controller.retry()).toBeNull();
  });
});
