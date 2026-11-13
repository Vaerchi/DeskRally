/**
 * Session transfer / escalation, console side (docs/51; §7-§9 supersede §3-§5).
 *
 * The hand-off is two sessions, never one mutated session: the sender's S1 ends and the acceptor gets a
 * fresh S2 on the same machine. The server sequences it:
 *
 *   offer (pending) -> accept (releasing: S1's renewals now refuse 409 "session transferred", so the
 *   sender's viewer closes and the agent reports S1 gone) -> the agent's end report or the acceptor's
 *   status poll FINALIZES (accepted: S2 exists) -> the acceptor fetches S2's ticket and connects.
 *
 * Everything here is pure orchestration over the API seam, so it is unit-tested without a browser.
 */
import type { ConsoleApi, SessionTransfer, StartedSession } from "./console_api";
import type { BrokeredSession } from "./session_broker";

/** Receiver poll cadence for new offers (docs/51 §5: matches the 10 s lease cadence; no push channel). */
export const INCOMING_POLL_MS = 10_000;
/** How often the acceptor re-reads a releasing offer; each read can finalize it. */
export const ACCEPT_POLL_MS = 2_000;
/** The server fails a releasing offer after 60 s without the agent's end report; wait a little past it. */
export const ACCEPT_TIMEOUT_MS = 75_000;

type TransferApi = Pick<ConsoleApi, "acceptSessionTransfer" | "getSessionTransfer" | "sessionTransferTicket">;

export interface TransferredSession {
  /** The machine's DEVICE id, from the signaling envelope (what the connect path dials). */
  deviceId: string;
  signalingUrl: string;
  brokered: BrokeredSession;
  transfer: SessionTransfer;
}

/** Why a transfer did not hand over, worded for the acceptor. */
export function transferFailureMessage(t: SessionTransfer): string {
  switch (t.state) {
    case "failed":
      return `The hand-off did not complete: ${t.failure_reason || "unknown reason"}`;
    case "cancelled":
      return "The sender cancelled this hand-off.";
    case "expired":
      return "This hand-off expired before it was accepted.";
    case "superseded":
      return "The sender replaced this hand-off with a newer one.";
    default:
      return `The hand-off is ${t.state}.`;
  }
}

/** Turn S2's ticket response into what the connect path takes. Throws when signaling is missing. */
export function transferredSession(t: SessionTransfer, started: StartedSession): TransferredSession {
  if (!started.signaling) throw new Error("The control plane returned no signaling for the transferred session.");
  return {
    deviceId: started.signaling.device_id,
    signalingUrl: started.signaling.url,
    transfer: t,
    brokered: {
      sessionId: started.session.id,
      signaling: started.signaling,
      ...(started.session_policy ? { sessionPolicy: started.session_policy } : {}),
      owned: true,
    },
  };
}

/**
 * Accept `transferId` and wait until the hand-off completes, then fetch S2's ticket.
 *
 * `onState` reports progress ("releasing" while the sender's session closes). Resolves the session to
 * connect to; rejects with a readable message when the offer fails, is withdrawn, or the agent never
 * confirms (the server's own 60 s limit, plus margin). `signal` stops waiting; it does not undo the accept.
 */
export async function acceptAndWait(
  api: TransferApi,
  transferId: string,
  opts: {
    onState?: (t: SessionTransfer) => void;
    signal?: AbortSignal;
    pollMs?: number;
    timeoutMs?: number;
    sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
    now?: () => number;
  } = {},
): Promise<TransferredSession> {
  const pollMs = opts.pollMs ?? ACCEPT_POLL_MS;
  const timeoutMs = opts.timeoutMs ?? ACCEPT_TIMEOUT_MS;
  const sleep = opts.sleep ?? defaultSleep;
  const now = opts.now ?? (() => Date.now());
  const deadline = now() + timeoutMs;

  let t = await api.acceptSessionTransfer(transferId);
  for (;;) {
    opts.onState?.(t);
    if (t.state === "accepted") break;
    if (t.state !== "releasing" && t.state !== "pending") throw new Error(transferFailureMessage(t));
    if (now() >= deadline) throw new Error("The machine did not confirm the previous session closed. Try connecting normally.");
    await sleep(pollMs, opts.signal);
    if (opts.signal?.aborted) throw new Error("Stopped waiting for the hand-off.");
    t = await api.getSessionTransfer(transferId);
  }
  return transferredSession(t, await api.sessionTransferTicket(transferId));
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => { clearTimeout(timer); resolve(); }, { once: true });
  });
}

/**
 * The 409 a sender's lease renewal gets once their session was handed over. The server words it
 * "session transferred", or "session handed off; the transfer did not complete" when the hand-off failed
 * after the session was released (S1 never renews again either way, docs/51 §8.4).
 */
export function senderTransferredMessage(refusal: string, recipient?: string): string | null {
  if (/session handed off; the transfer did not complete/.test(refusal)) {
    return "You handed this session off, but the hand-off did not complete. Reconnect if you still need the machine.";
  }
  if (/session transferred/.test(refusal)) {
    return recipient ? `Session transferred to ${recipient}.` : "Session transferred.";
  }
  return null;
}

/** Polls the caller's incoming offers. Failures are silent (the next tick retries). */
export class IncomingTransferPoller {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private epoch = 0;

  constructor(
    private readonly api: Pick<ConsoleApi, "listIncomingTransfers">,
    private readonly onChange: (offers: SessionTransfer[]) => void,
    private readonly intervalMs = INCOMING_POLL_MS,
  ) {}

  start(): void {
    if (this.running) return;
    this.running = true;
    void this.tick(++this.epoch);
  }

  stop(): void {
    this.running = false;
    this.epoch++;
    clearTimeout(this.timer);
    this.timer = undefined;
  }

  /** Poll now (after an accept or dismiss), without waiting for the next tick. */
  refresh(): void {
    if (!this.running) return;
    clearTimeout(this.timer);
    void this.tick(++this.epoch);
  }

  private async tick(epoch: number): Promise<void> {
    try {
      const offers = await this.api.listIncomingTransfers();
      if (epoch !== this.epoch || !this.running) return;
      this.onChange(offers.filter((t) => t.state === "pending"));
    } catch {
      /* retried on the next tick */
    }
    if (epoch !== this.epoch || !this.running) return;
    this.timer = setTimeout(() => void this.tick(epoch), this.intervalMs);
  }
}
