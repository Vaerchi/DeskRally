/**
 * Session-lease renewal (docs/25 F03) — the console half of "a central End session actually ends
 * unattended remote access".
 *
 * The loop is driven with an INJECTED scheduler rather than real timers, so every test asserts what
 * was scheduled and when, and a whole session's worth of renewals runs in microseconds.
 *
 * The negative control is as important as everything else here: a renewer that stopped after one
 * lease would end every session about thirty seconds in, and every "it refuses after End" test would
 * still pass.
 */

import { describe, expect, it, vi } from "vitest";

import {
  MAX_RENEW_INTERVAL_MS,
  MIN_RENEW_INTERVAL_MS,
  RENEW_ATTEMPT_TIMEOUT_MS,
  TRANSPORT_DISCONNECT_GRACE_MS,
  SessionLeaseRenewer,
  isRefusal,
  renewIntervalMs,
} from "./session_lease";
import type { SessionLease } from "./console_api";

/** A scheduler whose queue the test drives by hand. */
class FakeClock {
  private next = 1;
  readonly pending = new Map<number, { fn: () => void; ms: number }>();

  setTimer = (fn: () => void, ms: number): number => {
    const id = this.next++;
    this.pending.set(id, { fn, ms });
    return id;
  };

  clearTimer = (id: number): void => {
    this.pending.delete(id);
  };

  /** The delay of the single pending timer (asserting there is exactly one). */
  onlyDelay(): number {
    expect(this.pending.size).toBe(1);
    return [...this.pending.values()][0].ms;
  }

  /** Fire the single pending timer. */
  fire(): void {
    expect(this.pending.size).toBe(1);
    const [id, entry] = [...this.pending.entries()][0];
    this.pending.delete(id);
    entry.fn();
  }

  /** Fire the timer with the given delay (asserting exactly one with that delay exists). */
  fireWithDelay(ms: number): void {
    const matches = [...this.pending.entries()].filter(([, e]) => e.ms === ms);
    expect(matches.length).toBe(1);
    const [id, entry] = matches[0];
    this.pending.delete(id);
    entry.fn();
  }
}

/** Let the renewer's promise chain settle. */
const flush = () => new Promise((r) => setTimeout(r, 0));

function lease(overrides: Partial<SessionLease> = {}): SessionLease {
  return {
    access: "control",
    signed: '{"claims":{},"sig":"ab"}',
    lease_ttl_ms: 30_000,
    expires_at_ms: 1_730_000_030_000,
    ...overrides,
  };
}

/** An error shaped like `ConsoleApiError` — the console branches on `status`. */
function httpError(status: number, message = "nope"): Error & { status: number } {
  return Object.assign(new Error(message), { status });
}

describe("renewIntervalMs", () => {
  it("renews at a THIRD of the lease, so three attempts fit inside one", () => {
    expect(renewIntervalMs(30_000)).toBe(10_000);
    expect(renewIntervalMs(12_000)).toBe(4_000);
  });

  it("clamps both ends, so no TTL can produce a request storm or a lapse", () => {
    expect(renewIntervalMs(300)).toBe(MIN_RENEW_INTERVAL_MS);
    expect(renewIntervalMs(10 * 60_000)).toBe(MAX_RENEW_INTERVAL_MS);
  });

  it("treats a nonsense TTL as the minimum rather than as never", () => {
    // `Math.floor(NaN / 3)` is NaN, and `setTimeout(fn, NaN)` fires immediately in some runtimes and
    // never in others. Neither is an acceptable answer for the thing keeping a session alive.
    for (const bad of [0, -1, NaN, Infinity]) {
      expect(renewIntervalMs(bad)).toBe(MIN_RENEW_INTERVAL_MS);
    }
  });
});

describe("isRefusal", () => {
  it("treats the whole 4xx family as final", () => {
    // Keyed on the family, not a list: a future refusal reason must be final BY DEFAULT rather than
    // retried forever against a control plane that has already said no.
    for (const s of [400, 401, 403, 404, 409, 418, 429]) {
      expect(isRefusal(httpError(s))).toBe(true);
    }
  });

  it("does not treat transport trouble or a server fault as final", () => {
    expect(isRefusal(new Error("Failed to fetch"))).toBe(false);
    expect(isRefusal(httpError(500))).toBe(false);
    expect(isRefusal(httpError(503))).toBe(false);
    expect(isRefusal(null)).toBe(false);
  });
});

describe("SessionLeaseRenewer", () => {
  function build(
    renew: (id: string, signal?: AbortSignal) => Promise<SessionLease>,
    opts?: { disconnectGraceMs?: number },
  ) {
    const clock = new FakeClock();
    const installed: string[] = [];
    const refusals: string[] = [];
    const renewer = new SessionLeaseRenewer({
      renew,
      install: (s) => installed.push(s),
      onRefused: (m) => refusals.push(m),
      setTimer: clock.setTimer,
      clearTimer: clock.clearTimer,
      ...opts,
    });
    return { clock, installed, refusals, renewer };
  }

  it("renews IMMEDIATELY on start and installs the signed blob verbatim", async () => {
    // Immediately, not after one interval: the agent's grace window for the first lease is the
    // tightest deadline in the scheme, and waiting ten seconds to start would spend most of it.
    const { clock, installed, renewer } = build(async () => lease());
    renewer.start("s-1");
    await flush();
    expect(installed).toEqual(['{"claims":{},"sig":"ab"}']);
    expect(clock.onlyDelay()).toBe(10_000);
  });

  it("passes the session id and an AbortSignal through to the control plane", async () => {
    const renew = vi.fn(async () => lease());
    const { renewer } = build(renew);
    renewer.start("s-42");
    await flush();
    expect(renew).toHaveBeenCalledWith("s-42", expect.any(AbortSignal));
  });

  /** THE NEGATIVE CONTROL. A renewed session runs indefinitely. */
  it("keeps renewing for as long as the control plane keeps saying yes", async () => {
    const { clock, installed, refusals, renewer } = build(async () => lease());
    renewer.start("s-1");
    await flush();
    // Forty renewals at a third of a thirty-second lease is twenty minutes of session — forty times
    // the life of any single lease. Without this test, a renewer that stopped after the first would
    // pass every other test in this file and take every session offline half a minute in.
    for (let i = 0; i < 40; i++) {
      expect(clock.onlyDelay()).toBe(10_000);
      clock.fire();
      await flush();
    }
    expect(installed).toHaveLength(41);
    expect(refusals).toEqual([]);
    expect(renewer.current).toBe("s-1");
  });

  it("follows the control plane's TTL rather than a hardcoded cadence", async () => {
    // If an operator shortens or lengthens the lease TTL, the console must follow without a redeploy
    // — otherwise a shortened TTL silently starts killing sessions.
    let ttl = 30_000;
    const { clock, renewer } = build(async () => lease({ lease_ttl_ms: ttl }));
    renewer.start("s-1");
    await flush();
    expect(clock.onlyDelay()).toBe(10_000);
    ttl = 9_000;
    clock.fire();
    await flush();
    expect(clock.onlyDelay()).toBe(3_000);
  });

  it("STOPS DEAD on a refusal and reports it once — this is End session arriving", async () => {
    let calls = 0;
    const { clock, installed, refusals, renewer } = build(async () => {
      calls++;
      if (calls === 1) return lease();
      throw httpError(409, "session has ended");
    });
    renewer.start("s-1");
    await flush();
    clock.fire();
    await flush();

    expect(installed).toHaveLength(1); // the refused renewal installed nothing
    expect(refusals).toEqual(["session has ended"]);
    // Nothing scheduled: retrying would spam the control plane while the agent runs its last lease
    // down, and could never succeed.
    expect(clock.pending.size).toBe(0);
    expect(renewer.current).toBeNull();
  });

  it("RETRIES transport trouble, because a network blip is not a revocation", async () => {
    let calls = 0;
    const { clock, installed, refusals, renewer } = build(async () => {
      calls++;
      if (calls === 1) throw new Error("Failed to fetch");
      return lease();
    });
    renewer.start("s-1");
    await flush();
    expect(installed).toEqual([]);
    expect(refusals).toEqual([]);
    expect(clock.onlyDelay()).toBe(MIN_RENEW_INTERVAL_MS);
    clock.fire();
    await flush();
    expect(installed).toHaveLength(1);
    // Retrying cannot extend a revoked session: every lease is short and signed, so a console that
    // keeps trying can only ever recover a session the control plane still authorizes.
    expect(clock.onlyDelay()).toBe(10_000);
  });

  it("a renewal that lands AFTER stop() installs nothing", async () => {
    // The dangerous case, and the reason `stop` clears the session id and not only the timer: a
    // policy is bound to a session id, and installing one for a session the agent is no longer
    // serving is rejected TERMINALLY (`WrongSession`) — costing the operator the session they have
    // just opened, on the next machine, for no reason they could ever diagnose.
    let release!: (l: SessionLease) => void;
    const { clock, installed, renewer } = build(
      () => new Promise<SessionLease>((r) => (release = r)),
    );
    renewer.start("s-1");
    await flush();
    renewer.stop();
    release(lease());
    await flush();
    expect(installed).toEqual([]);
    expect(clock.pending.size).toBe(0);
  });

  it("re-announcement does not reset the cadence", async () => {
    // The agent re-announces every couple of seconds until a lease verifies, so `start` is called
    // repeatedly for the same session. Restarting each time would issue a renewal per announcement.
    const renew = vi.fn(async () => lease());
    const { renewer } = build(renew);
    renewer.start("s-1");
    await flush();
    renewer.start("s-1");
    renewer.start("s-1");
    await flush();
    expect(renew).toHaveBeenCalledTimes(1);
  });

  it("switching sessions abandons the old one's schedule", async () => {
    const renew = vi.fn(async () => lease());
    const { clock, renewer } = build(renew);
    renewer.start("s-1");
    await flush();
    renewer.start("s-2");
    await flush();
    expect(renewer.current).toBe("s-2");
    expect(renew).toHaveBeenLastCalledWith("s-2", expect.any(AbortSignal));
    // Exactly one timer, belonging to s-2: the old session's must have been cleared, not leaked.
    expect(clock.pending.size).toBe(1);
  });

  it("stop() is safe when nothing is running", () => {
    const { renewer } = build(async () => lease());
    expect(() => {
      renewer.stop();
      renewer.stop();
    }).not.toThrow();
    expect(renewer.current).toBeNull();
  });

  it("TRANSPORT_DISCONNECT_GRACE_MS is exported and matches the documented 60 s", () => {
    // The constant is a contract: callers (App.tsx) can reason about the bound.
    expect(TRANSPORT_DISCONNECT_GRACE_MS).toBe(60_000);
  });

  it("transport reconnect before grace cancels the disconnect timer — session continues", async () => {
    // ICE recovery and brief network glitches are expected; 60 s gives time to reconnect.
    const { clock, refusals, renewer } = build(async () => lease(), { disconnectGraceMs: 5_000 });
    renewer.start("s-1");
    await flush();
    // One renewal timer pending.
    expect(clock.pending.size).toBe(1);

    renewer.notifyTransportDisconnected();
    // Now there are two timers: the renewal timer (10_000) and the grace timer (5_000).
    expect(clock.pending.size).toBe(2);

    renewer.notifyTransportConnected();
    // Grace timer cancelled — only the renewal timer remains.
    expect(clock.pending.size).toBe(1);
    expect(clock.onlyDelay()).toBe(10_000);

    // Session still runs normally.
    clock.fire();
    await flush();
    expect(refusals).toEqual([]);
    expect(renewer.current).toBe("s-1");
  });

  it("prolonged disconnect ends the session via onRefused", async () => {
    // After the grace period, the renewer invokes onRefused — the same terminal path as a
    // control-plane refusal, so the viewer can tear the session down consistently.
    const { clock, installed, refusals, renewer } = build(
      async () => lease(),
      { disconnectGraceMs: 5_000 },
    );
    renewer.start("s-1");
    await flush();
    expect(installed).toHaveLength(1); // initial renewal succeeded

    renewer.notifyTransportDisconnected();
    expect(clock.pending.size).toBe(2); // renewal timer + grace timer

    // Fire the grace timer (delay 5_000); the renewal timer (10_000) is still pending.
    clock.fireWithDelay(5_000);
    await flush();

    expect(refusals).toEqual(["transport disconnected"]);
    expect(renewer.current).toBeNull();
    // Both timers must have been cleared: the grace timer fired and stop() cleared the renewal timer.
    expect(clock.pending.size).toBe(0);
  });

  it("session replacement cancels the disconnect grace timer", async () => {
    // start(newId) calls stop() which must clear the disconnect timer, not leave it racing.
    const { clock, refusals, renewer } = build(async () => lease(), { disconnectGraceMs: 5_000 });
    renewer.start("s-1");
    await flush();

    renewer.notifyTransportDisconnected();
    expect(clock.pending.size).toBe(2);

    // Switch to a new session — stop() clears both timers.
    renewer.start("s-2");
    await flush();

    expect(renewer.current).toBe("s-2");
    // Only s-2's renewal timer; s-1's renewal and grace timers are gone.
    expect(clock.pending.size).toBe(1);
    expect(refusals).toEqual([]);
  });

  it("idle but CONNECTED session keeps renewing without triggering disconnect", async () => {
    // Idle view-only sessions (no user input, transport connected) must NOT be affected.
    // The disconnect grace is only triggered by an explicit notifyTransportDisconnected() call.
    const { clock, refusals, renewer } = build(async () => lease());
    renewer.start("s-1");
    await flush();

    for (let i = 0; i < 5; i++) {
      expect(clock.onlyDelay()).toBe(10_000); // only the renewal timer — no grace timer
      clock.fire();
      await flush();
    }
    expect(refusals).toEqual([]);
    expect(renewer.current).toBe("s-1");
    expect(clock.pending.size).toBe(1); // next renewal scheduled, nothing else
  });

  it("second notifyTransportDisconnected() while grace timer is running is a no-op", async () => {
    // Mutation target: removing `this.disconnectTimer !== null` from the guard at session_lease.ts:168
    // would allow a second call to arm a second grace timer, growing pending.size from 2 to 3.
    const { clock, renewer } = build(async () => lease(), { disconnectGraceMs: 5_000 });
    renewer.start("s-1");
    await flush();
    expect(clock.pending.size).toBe(1); // only the renewal timer

    renewer.notifyTransportDisconnected();
    expect(clock.pending.size).toBe(2); // renewal timer + grace timer

    // Second call must be a no-op — the guard short-circuits on disconnectTimer !== null.
    renewer.notifyTransportDisconnected();
    expect(clock.pending.size).toBe(2); // still 2, not 3
  });

  it("an obsolete disconnect callback cannot end a recovered or replacement session", async () => {
    const { clock, refusals, renewer } = build(async () => lease(), { disconnectGraceMs: 5_000 });
    renewer.start("s-1");
    await flush();
    renewer.notifyTransportDisconnected();
    const obsolete = [...clock.pending.values()].find((timer) => timer.ms === 5_000)!.fn;
    renewer.notifyTransportConnected();
    obsolete();
    expect(renewer.current).toBe("s-1");
    renewer.start("s-2");
    await flush();
    obsolete();
    expect(renewer.current).toBe("s-2");
    expect(refusals).toEqual([]);
    expect(clock.pending.size).toBe(1);
    renewer.stop();
    obsolete();
    expect(clock.pending.size).toBe(0);
    expect(refusals).toEqual([]);
  });

  it("RENEW_ATTEMPT_TIMEOUT_MS is exported and matches the documented 8 s", () => {
    expect(RENEW_ATTEMPT_TIMEOUT_MS).toBe(8_000);
  });

  it("a hung renewal times out after RENEW_ATTEMPT_TIMEOUT_MS and retries at the minimum interval", async () => {
    // The control plane stalls on the first attempt (simulating a hung upstream). The per-attempt
    // timeout must fire and schedule a retry — the session must not be held alive by a request that
    // will never complete.
    let calls = 0;
    const { clock, installed, refusals, renewer } = build(async () => {
      calls++;
      if (calls === 1) return new Promise<SessionLease>(() => {}); // hangs forever
      return lease();
    });

    renewer.start("s-1");
    await flush();
    // Only the per-attempt timeout timer is pending: the renewal schedule hasn't run yet.
    expect(clock.onlyDelay()).toBe(RENEW_ATTEMPT_TIMEOUT_MS);
    expect(installed).toHaveLength(0);

    // Fire the timeout — the race loses, the hung promise is abandoned.
    clock.fireWithDelay(RENEW_ATTEMPT_TIMEOUT_MS);
    await flush();

    // The timeout is a non-refusal error → retry scheduled at the minimum interval.
    expect(installed).toHaveLength(0);
    expect(refusals).toHaveLength(0);
    expect(clock.onlyDelay()).toBe(MIN_RENEW_INTERVAL_MS);

    // Fire the retry — the second call returns a real lease.
    clock.fire();
    await flush();
    expect(installed).toHaveLength(1);
    expect(refusals).toHaveLength(0);
    expect(renewer.current).toBe("s-1");
  });

  it("stop() aborts the AbortSignal passed to an in-flight renewal", async () => {
    // The renewer must cancel the live fetch when the session is stopped, so the request does not
    // keep consuming server resources after the console has moved on.
    let capturedSignal: AbortSignal | undefined;
    const { renewer } = build((_id, signal) => {
      capturedSignal = signal;
      return new Promise<SessionLease>(() => {}); // hangs
    });

    renewer.start("s-1");
    await flush();
    expect(capturedSignal).toBeInstanceOf(AbortSignal);
    expect(capturedSignal!.aborted).toBe(false);

    renewer.stop();
    expect(capturedSignal!.aborted).toBe(true);
    expect(renewer.current).toBeNull();
  });

  it("session switch aborts the old session's in-flight renewal before starting the new one", async () => {
    // start(newId) calls stop() which must abort the old controller — the old fetch must not
    // keep consuming a slot on the control plane while the new session's renewal begins.
    let s1Signal: AbortSignal | undefined;
    let s2Signal: AbortSignal | undefined;
    const { renewer } = build(async (id, signal) => {
      if (id === "s-1") { s1Signal = signal; return new Promise<SessionLease>(() => {}); }
      s2Signal = signal;
      return new Promise<SessionLease>(() => {});
    });

    renewer.start("s-1");
    await flush();
    expect(s1Signal?.aborted).toBe(false);

    renewer.start("s-2");
    // s-1's signal is aborted synchronously when stop() runs inside start().
    expect(s1Signal?.aborted).toBe(true);
    await flush();

    expect(s2Signal?.aborted).toBe(false); // s-2's request is still live
    expect(renewer.current).toBe("s-2");
  });

  it("a timed-out attempt that later resolves cannot install a stale lease or schedule a renewal", async () => {
    // The race abandons the hung promise, but the promise keeps running (no cancellation obligation
    // on the renew implementation). When it eventually resolves, the session-id guard must stop it
    // from installing or scheduling, just as it stops a late post-stop response.
    let deliverStale!: (l: SessionLease) => void;
    let calls = 0;
    const { clock, installed, renewer } = build(async (_id) => {
      calls++;
      if (calls === 1) return new Promise<SessionLease>((r) => (deliverStale = r));
      return lease(); // second call succeeds immediately
    });

    renewer.start("s-1");
    await flush();

    // Fire the per-attempt timeout — race rejects, retry scheduled.
    clock.fireWithDelay(RENEW_ATTEMPT_TIMEOUT_MS);
    await flush();
    expect(clock.onlyDelay()).toBe(MIN_RENEW_INTERVAL_MS);

    // Fire the retry — second call succeeds, normal schedule resumes.
    clock.fire();
    await flush();
    expect(installed).toHaveLength(1);
    const sizeAfterGoodRenewal = clock.pending.size; // 1: the renewal timer

    // NOW the stale first promise resolves. The session-id and abort guard must block it.
    deliverStale(lease({ signed: '{"claims":{},"sig":"STALE"}' }));
    await flush();

    // Nothing extra installed, nothing extra scheduled.
    expect(installed).toHaveLength(1);
    expect(clock.pending.size).toBe(sizeAfterGoodRenewal);
  });

  it("a 4xx refusal is still treated as final even with the timeout machinery in place", async () => {
    // The timeout adds a new error path; it must not inadvertently shadow the 4xx branch and turn
    // an administrator's End session into a retry loop.
    let calls = 0;
    const { clock, installed, refusals, renewer } = build(async () => {
      calls++;
      if (calls === 1) return lease();
      throw httpError(409, "session has ended");
    });

    renewer.start("s-1");
    await flush();
    clock.fire(); // fire renewal timer → second call throws 409
    await flush();

    expect(installed).toHaveLength(1);
    expect(refusals).toEqual(["session has ended"]);
    expect(clock.pending.size).toBe(0);
    expect(renewer.current).toBeNull();
  });
  it("stop and restart of the SAME session ignores the old completion", async () => {
    let stale!: (value: SessionLease) => void;
    let calls=0;
    const {renewer, installed, clock}=build(() => ++calls === 1
      ? new Promise<SessionLease>(resolve => {stale=resolve;})
      : Promise.resolve(lease({signed:"fresh"})));
    renewer.start("s-1");renewer.stop();renewer.start("s-1");await flush();
    stale(lease({signed:"old"}));await flush();
    expect(installed).toEqual(["fresh"]);expect(clock.pending.size).toBe(1);
  });

});
