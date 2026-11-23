import type { LayoutReconnectBudget } from "./layout_reconnect";

/** A retry loop for a user-owned connection, never an authorization override. */
export interface RecoveryNotice { message: string; retrying: boolean; }
export class RecoveryRefused extends Error {}
/**
 * How long automatic recovery may keep trying after the FIRST loss before it hands back to the
 * technician. Without a bound, a forgotten window kept retrying every 30 s for as long as it was
 * open, and each retry may start a FRESH session: on 2026-10-21 a window whose session had died ten
 * minutes earlier opened a new session 10 s after the guest pressed End on a different one. Past
 * this window, reconnecting is a deliberate act (Reconnect), never a timer.
 */
export const RECOVERY_WINDOW_MS = 120000;
/**
 * How long a connection must stay up before it counts as RECOVERED, ending the outage (backoff and
 * {@link RECOVERY_WINDOW_MS} start over). Reaching "connected" is not enough: on 2026-11-09 a machine
 * whose agent connected but sent no video looped for minutes, because every attempt reached
 * "connected", reset the budget, then failed the 20 s video-stall check ({@link MediaProgress}) and
 * reconnected 2 s later: a fresh session every ~33 s, forever. This outlasts that check (and its poll)
 * with room to spare, and Chrome's ~30 s ICE consent timeout.
 */
export const RECOVERED_AFTER_MS = 60000;
export class SessionRecovery {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private epoch = 0;
  private attempt = 0;
  private running = false;
  private backgroundAttempt = false;
  private refused = false;
  /** A loss reported while a retry was still in flight; acted on when that retry settles. */
  private lostDuringRetry: string | undefined;
  /** When the current outage began (first loss since the last connect); bounds the retry loop. */
  private lostSince: number | undefined;
  /** When the current connection came up; the outage ends only once it has lasted RECOVERED_AFTER_MS. */
  private connectedAt: number | undefined;
  enabled = false;
  /**
   * `stopped` runs once each time recovery stops FOR GOOD (refused, or past its window), never on a deliberate
   * cancel. While recovery runs it keeps the session record (a retry must check the original is still authorized),
   * so this is where the caller lets go of it. Without that, the record of the last retry outlived the page's
   * sign-in and leaked (production 2026-11-09, session 4c1f4541: its /end came 2 h later and got a 401).
   */
  constructor(private readonly retry: (isCurrent: () => boolean) => Promise<void>,
    private readonly notify: (notice: RecoveryNotice | null) => void,
    private readonly stopped?: () => void,
    private readonly deferRetry?: () => boolean) {}
  cancel(): void {
    this.epoch++; this.refused=false; this.enabled = false; this.attempt = 0; this.running = false; this.lostDuringRetry = undefined; this.lostSince = undefined; this.connectedAt = undefined;
    this.backgroundAttempt = false;
    clearTimeout(this.timer); this.timer = undefined; this.notify(null);
  }
  /** Stops any pending retry. The outage (backoff, window) ends only if this connection then lasts. */
  connected(): void {
    if(this.refused || this.backgroundAttempt) return;
    this.epoch++; this.running = false; this.lostDuringRetry = undefined; this.connectedAt = Date.now();
    clearTimeout(this.timer); this.timer = undefined; this.notify(null);
  }
  refuse(message: string): void {
    const wasRefused = this.refused;
    this.cancel(); this.refused=true; this.notify({message, retrying:false});
    if (!wasRefused) this.stopped?.();
  }
  lost(message = "Connection lost"): void {
    if(this.refused) return;
    if (this.connectedAt !== undefined) {
      // A connection that lasted was a recovery: this loss starts a new outage. One that did not is
      // the same outage continuing (connects, then fails at once), and keeps its backoff and window.
      if (Date.now() - this.connectedAt >= RECOVERED_AFTER_MS) { this.attempt = 0; this.lostSince = undefined; }
      this.connectedAt = undefined;
    }
    if (!this.enabled) { this.notify({message, retrying:false}); return; }
    // A retry is still settling (its connect can be rejected before handleConnect returns): keep
    // the loss and schedule the next attempt when it settles, or the view waits forever.
    if (this.running) { this.lostDuringRetry = message; return; }
    if (this.timer !== undefined) return;
    this.lostSince ??= Date.now();
    if (this.expired()) return;
    const delay = Math.min(30000, 2000 * 2 ** Math.min(this.attempt++,4));
    this.notify({message:`${message}. Reconnecting in ${delay / 1000}s…`,retrying:true});
    const run = () => {
      this.timer = undefined;
      if (!this.enabled) return;
      if (this.deferRetry?.()) {
        this.timer = setTimeout(run, 2000);
        return;
      }
      if (!this.expired()) this.startRetry();
    };
    this.timer = setTimeout(run, delay);
  }

  connectionStarting(): void {
    this.backgroundAttempt = false;
  }

  afterBackground(budget: LayoutReconnectBudget, isCurrent: () => boolean): void {
    if (this.refused || this.running || !isCurrent()) return;
    clearTimeout(this.timer);
    this.backgroundAttempt = true;
    this.notify({ message: "Reconnecting after the app was in the background…", retrying: true });
    this.timer = setTimeout(() => {
      this.timer = undefined;
      if (!isCurrent()) {
        this.backgroundAttempt = false;
        this.notify(this.lostSince === undefined ? null : {
          message: "Connection unavailable. Reconnect to start a new session.", retrying: false,
        });
        return;
      }
      if (!budget.take(Date.now())) {
        this.refuse("Connection unavailable. Reconnect to start a new session.");
        return;
      }
      this.startRetry(isCurrent);
    }, 1000);
  }

  private startRetry(backgroundIsCurrent?: () => boolean): void {
    const epoch = this.epoch;
    this.running = true;
    if (!backgroundIsCurrent) this.notify({ message: "Reconnecting…", retrying: true });
    // Capture the connection guard until retry hands off to a new generation.
    void this.retry(() => epoch === this.epoch &&
      (backgroundIsCurrent ? backgroundIsCurrent() : this.enabled)).catch(error => {
      if (epoch !== this.epoch || (this.backgroundAttempt && !backgroundIsCurrent?.())) return;
      this.running = false;
      this.backgroundAttempt = false;
      if (error instanceof RecoveryRefused) this.refuse(error.message);
      else this.lost("Connection unavailable");
    }).finally(() => {
      if (epoch !== this.epoch) return;
      const wasBackground = this.backgroundAttempt;
      this.backgroundAttempt = false;
      this.running = false;
      const pending = this.lostDuringRetry;
      this.lostDuringRetry = undefined;
      if (pending !== undefined) this.lost(pending);
      else if (wasBackground) this.notify(null);
    });
  }
  /** Past the window: stop for good (until a deliberate reconnect) and say so. */
  private expired(): boolean {
    if (this.lostSince === undefined || Date.now() - this.lostSince < RECOVERY_WINDOW_MS) return false;
    this.refuse("Automatic reconnect stopped after 2 minutes. Reconnect to start a new session.");
    return true;
  }
}

/** A late result must never revive a cancelled attempt. Optional cleanup releases late sessions. */
export async function withDeadline<T>(promise: Promise<T>, ms: number, late?: (value:T)=>void): Promise<T> {
  let timedOut=false;
  let timer:ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise.then(value => {if(timedOut) late?.(value);return value;}),
      new Promise<never>((_,reject)=> {timer=setTimeout(()=> {timedOut=true;reject(new Error("Connection request timed out"));},ms);})]);
  } finally {clearTimeout(timer);}
}

/** Count decoded frames, not changes to pixel content: a quiet desktop still delivers frames. */
export class MediaProgress {
  private frames: number | undefined;
  private changedAt: number;
  constructor(now:number) {this.changedAt=now;}
  /**
   * `expectFrames` false: the agent owes no frames right now. In background mode (every window showing
   * the session hidden) it sends only real changes, with no keep-alive, so an idle or powered-off screen
   * sends nothing at all; counting that as a stall ended every hidden session after 20 s and reconnected
   * it into the same state, every ~33 s (2026-11-09 no-video loop). The clock restarts instead, so the
   * 20 s only ever counts time in which frames were owed.
   */
  stalled(report:RTCStatsReport,now:number,expectFrames=true):boolean {
    let frames:number|undefined;
    report.forEach(stat=> {
      if(stat.type === "inbound-rtp" && (stat.kind === "video" || stat.mediaType === "video") && typeof stat.framesDecoded === "number")
        frames=(frames ?? 0)+stat.framesDecoded;
    });
    // Older engines without a decoded-frame counter cannot support this detector.
    if(frames === undefined) return false;
    if(!expectFrames || this.frames !== frames) {this.frames=frames;this.changedAt=now;return false;}
    return now-this.changedAt >= 20000;
  }
}
