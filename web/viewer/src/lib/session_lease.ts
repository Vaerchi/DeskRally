/**
 * The console half of the SESSION LEASE (docs/25 F03) — keeping a live unattended session
 * authorized, and stopping the moment the control plane says no.
 *
 * # Why this exists as a module and not as a closure in App.tsx
 *
 * It started as a closure in `App.tsx`, where nothing could reach it: the loop needs a live
 * transport, a live control client and real timers. That is the exact shape this project has shipped
 * an inert feature in before — loop 80's session policy was declared in every type and read nowhere,
 * and every test passed while the whole feature did nothing. As a small class with injected timers
 * it is a truth table, and the behaviours that matter (renew on a fraction of the lease, stop dead
 * on a refusal, never install a lease for a session we have left) each get a test.
 *
 * # What it is for
 *
 * `POST /sessions/{id}/end` cannot reach a running agent — there is no authenticated control-plane →
 * agent channel — so an administrator ending an unattended session used to change a database row and
 * nothing else. Instead the agent demands a freshly-signed policy every so often and ends the session
 * when one stops arriving; this class is what keeps them arriving while the session is legitimate.
 *
 * **If this stops renewing, the session ends.** That is the mechanism, not a bug in it.
 */

import type { SessionLease } from "./console_api";

/** Never renew more often than this, whatever TTL the control plane reports. A misconfigured or
 *  future-tiny TTL must not turn a console into a request storm against the control plane. */
export const MIN_RENEW_INTERVAL_MS = 2_000;
/** Abandon a single renewal attempt after this long. The lease is 30 s; 8 s gives three attempts
 *  within one lease and a 2 s margin per attempt before the next window. A hung server-side request
 *  must not silently consume the entire renewal window. */
export const RENEW_ATTEMPT_TIMEOUT_MS = 8_000;
/** Never wait longer than this between renewals, whatever TTL is reported. Bounds how stale the
 *  console's picture of "am I still authorized?" can get if a future TTL is raised a long way. */
export const MAX_RENEW_INTERVAL_MS = 15_000;
/** How long after a transport disconnect to wait before invoking `onRefused` and tearing down the
 *  session. Long enough for WebRTC ICE to restart (~30 s in poor conditions); short enough that a
 *  zombie viewer that lost transport connectivity does not keep a session's lease alive indefinitely.
 *  A connected-but-idle session is not affected — this only fires when the transport is actually
 *  DISCONNECTED. */
export const TRANSPORT_DISCONNECT_GRACE_MS = 60_000;

/**
 * How long to wait before the next renewal, given the lease duration the control plane reported.
 *
 * A THIRD of the lease, so three renewals fit inside one lease and a single dropped request never
 * costs anyone their session.
 *
 * Computed from the reported DURATION, never from `expires_at_ms - Date.now()`: the browser's clock
 * and the control plane's are not the same clock, and a skewed browser would otherwise renew far too
 * late (losing the session) or far too often.
 */
export function renewIntervalMs(leaseTtlMs: number): number {
  if (!Number.isFinite(leaseTtlMs) || leaseTtlMs <= 0) return MIN_RENEW_INTERVAL_MS;
  return Math.min(MAX_RENEW_INTERVAL_MS, Math.max(MIN_RENEW_INTERVAL_MS, Math.floor(leaseTtlMs / 3)));
}

/**
 * Is this failure a REFUSAL — the control plane declining to re-authorize — rather than transport
 * trouble?
 *
 * The distinction decides whether to keep trying. A refusal is what an administrator's "End session"
 * looks like from here (and equally a disabled principal, a suspended tenant, a quarantined
 * machine): final, and retrying would only spam the control plane while the agent runs its last
 * lease down. Anything else is a network blip, where retrying can only ever recover a session that
 * is still legitimate — it can never extend one the control plane has stopped authorizing, because
 * every lease is signed and short.
 *
 * Keyed on the 4xx family rather than on a list of specific statuses, so a future refusal reason
 * (say a 402 for a lapsed subscription) is treated as final by default rather than retried forever.
 */
export function isRefusal(err: unknown): boolean {
  const e = err as { status?: unknown } | null;
  return typeof e?.status === "number" && e.status >= 400 && e.status < 500;
}

/** Everything the renewer needs from the outside world. Injected so the whole loop is testable. */
export interface SessionLeaseRenewerOptions {
  /** Ask the control plane for the next lease. Normally `ConsoleApiClient.renewSessionPolicy`.
   *  The signal is aborted when `stop()` is called or the session switches — pass it to fetch so
   *  the underlying request is cancelled rather than silently consuming the renewal window. */
  renew: (sessionId: string, signal?: AbortSignal) => Promise<SessionLease>;
  /** Hand the signed blob to the agent VERBATIM (`Control::InstallSessionPolicy`). */
  install: (signedPolicy: string) => void;
  /** Called once when the control plane REFUSES, or when the transport has been disconnected for
   *  longer than disconnectGraceMs. In both cases the session is about to end and the technician
   *  needs to be told why. */
  onRefused: (message: string) => void;
  /** Injected timers (tests supply fakes). Defaults to the globals. */
  setTimer?: (fn: () => void, ms: number) => number;
  clearTimer?: (handle: number) => void;
  /** How long after a transport disconnect to wait before invoking `onRefused` and ending the
   *  session. Defaults to TRANSPORT_DISCONNECT_GRACE_MS (60 s). Inject a shorter value in tests. */
  disconnectGraceMs?: number;
}

/**
 * Keeps one session's lease renewed.
 *
 * One instance per console; `start` switches it to a new session and `stop` ends it. Both are
 * idempotent, because the agent re-announces `SessionLeaseRequired` every couple of seconds until a
 * lease verifies and `start` is called on each one.
 */
export class SessionLeaseRenewer {
  private readonly opts: SessionLeaseRenewerOptions;
  private readonly setTimer: (fn: () => void, ms: number) => number;
  private readonly clearTimer: (handle: number) => void;
  private readonly disconnectGraceMs: number;
  private timer: number | null = null;
  /** Fired disconnectGraceMs after notifyTransportDisconnected(); cleared by notifyTransportConnected(),
   *  stop(), or start(). If it fires, the session is torn down via onRefused. */
  private disconnectTimer: number | null = null;
  /** AbortController for the currently in-flight renewal request; aborted by stop(). */
  private currentAbort: AbortController | null = null;
  private disconnectEpoch = 0;
  /** The session renewals are keyed on, or null when not renewing. THE LOAD-BEARING FIELD: an
   *  in-flight renewal's continuation checks it before installing anything, so a response that
   *  arrives after `stop` cannot install a policy bound to a session this agent is no longer
   *  serving — which the agent rejects TERMINALLY (`WrongSession`), costing the operator the session
   *  they have just opened. */
  private sessionId: string | null = null;

  constructor(opts: SessionLeaseRenewerOptions) {
    this.opts = opts;
    this.setTimer =
      opts.setTimer ?? ((fn, ms) => setTimeout(fn, ms) as unknown as number);
    this.clearTimer = opts.clearTimer ?? ((h) => clearTimeout(h as unknown as ReturnType<typeof setTimeout>));
    this.disconnectGraceMs = opts.disconnectGraceMs ?? TRANSPORT_DISCONNECT_GRACE_MS;
  }

  /** Which session is being renewed, or null. */
  get current(): string | null {
    return this.sessionId;
  }

  /**
   * Begin (or continue) renewing `sessionId`. Renews immediately, then on a fraction of each lease.
   *
   * Calling it again for the SAME session is a no-op: the agent re-announces until a lease verifies,
   * and restarting on every announcement would reset the cadence and hammer the control plane.
   */
  start(sessionId: string): void {
    if (this.sessionId === sessionId) return;
    this.stop();
    this.sessionId = sessionId;
    void this.tick(sessionId);
  }

  /** Stop renewing. Safe to call when not running, and safe to call with a request in flight. */
  stop(): void {
    this.disconnectEpoch++;
    if (this.currentAbort !== null) {
      this.currentAbort.abort();
      this.currentAbort = null;
    }
    if (this.disconnectTimer !== null) {
      this.clearTimer(this.disconnectTimer);
      this.disconnectTimer = null;
    }
    if (this.timer !== null) {
      this.clearTimer(this.timer);
      this.timer = null;
    }
    this.sessionId = null;
  }

  /**
   * Notify that the WebRTC transport has disconnected. Starts a grace timer; if the transport
   * does not reconnect within disconnectGraceMs, `onRefused` is invoked and the session is torn
   * down — the same path as a control-plane refusal.
   *
   * A no-op when not currently renewing or when a grace timer is already running. Call
   * `notifyTransportConnected` to cancel before the timer fires.
   *
   * WHY: zombie viewers that lost transport connectivity would otherwise keep renewing
   * (renewals succeed at the control plane) indefinitely. The transport disconnect is the only
   * client-observable signal that the session is no longer live.
   */
  notifyTransportDisconnected(): void {
    if (this.sessionId === null || this.disconnectTimer !== null) return;
    const sessionId = this.sessionId;
    const epoch = ++this.disconnectEpoch;
    this.disconnectTimer = this.setTimer(() => {
      if (this.disconnectEpoch !== epoch || this.sessionId !== sessionId) return;
      this.disconnectTimer = null;
      this.stop();
      this.opts.onRefused("transport disconnected");
    }, this.disconnectGraceMs);
  }

  /**
   * Notify that the WebRTC transport has reconnected. Cancels any running disconnect grace timer,
   * preserving the session. A no-op when no grace timer is running.
   */
  notifyTransportConnected(): void {
    this.disconnectEpoch++;
    if (this.disconnectTimer !== null) {
      this.clearTimer(this.disconnectTimer);
      this.disconnectTimer = null;
    }
  }

  private async tick(sessionId: string): Promise<void> {
    if (this.sessionId !== sessionId) return;

    const abort = new AbortController();
    this.currentAbort = abort;
    let timeoutHandle: number | null = null;

    try {
      // Race the renew call against a per-attempt timeout. The timeout uses the injected
      // scheduler so fake clocks can drive it in tests without real wall-clock waits.
      // isRefusal checks HTTP status, not message text, so the timeout error is always
      // treated as a network blip rather than a revocation — correct and retried.
      const timeoutPromise = new Promise<never>((_, reject) => {
        timeoutHandle = this.setTimer(
          () => reject(new Error("renew timed out")),
          RENEW_ATTEMPT_TIMEOUT_MS,
        );
      });

      const lease = await Promise.race([
        this.opts.renew(sessionId, abort.signal),
        timeoutPromise,
      ]);

      // Re-checked AFTER the await: teardown may have run while this was in flight.
      if (this.sessionId !== sessionId || this.currentAbort !== abort) return;
      this.opts.install(lease.signed);
      this.schedule(sessionId, renewIntervalMs(lease.lease_ttl_ms));
    } catch (err) {
      if (this.sessionId !== sessionId || this.currentAbort !== abort) return;
      if (isRefusal(err)) {
        const message = (err as { message?: string })?.message ?? "renewal refused";
        this.stop();
        this.opts.onRefused(message);
        return;
      }
      // Network error, timeout, or abort: retry at minimum interval. The disconnect grace
      // timer (if running) provides the hard outer bound for persistent connectivity loss.
      this.schedule(sessionId, MIN_RENEW_INTERVAL_MS);
    } finally {
      if (timeoutHandle !== null) this.clearTimer(timeoutHandle);
      // Cancel any still-in-flight request and release the reference.
      abort.abort();
      if (this.currentAbort === abort) this.currentAbort = null;
    }
  }

  private schedule(sessionId: string, ms: number): void {
    this.timer = this.setTimer(() => {
      this.timer = null;
      void this.tick(sessionId);
    }, ms);
  }
}
