/**
 * docs/73 §2.2: "request input control", as the viewer models it, for both ends.
 *
 * Requester (B): asks the technician who owns input for it. The agent decides; the viewer only reports. It
 * mints a fresh `client_request_id`, re-sends the SAME id with `retry: true` when no reply comes (§2.2.2:
 * after 3 s, at most 3 times, then "could not confirm"), and treats a terminal `Result` as STICKY per id.
 *
 * Holder (A): is shown a NON-MODAL prompt, tells the agent it was rendered, answers, drops it when the agent
 * withdraws it, and drops it locally at `expires_in_ms` + 5 s. It remembers the last 32 ids it has seen
 * closed for 5 minutes so a delayed `InputControlRequested` for one of them never shows.
 *
 * Nothing here is bound to React or to a transport: `InputRequestController` takes a sender getter and an
 * injectable clock, and the components subscribe to it. Nothing is announced or shown unless the agent said
 * `InputRequestAvailable { available: true }`, which an old agent (or a bulk run, which never announces)
 * never does.
 */
import type { InputRequestAgentMessage, InputRequestOutcome, InputRequestState } from "./control";
import type { InputHandoffModel } from "./input_handoff";
import type { SessionParticipantEntry } from "./protocol";

/** §2.2.2: re-send after this long without a reply. */
export const REQUEST_RETRY_MS = 3_000;
/** §2.2.2: at most this many re-sends before "could not confirm". */
export const REQUEST_MAX_RETRIES = 3;
/** §2.2.2: a holder drops a prompt locally this long after `expires_in_ms`. */
export const PROMPT_GRACE_MS = 5_000;
/** §2.2.2: the holder keeps the last 32 closed ids, for 5 minutes. */
export const CLOSED_IDS_KEPT = 32;
export const CLOSED_IDS_TTL_MS = 5 * 60_000;

export const GENERIC_HOLDER_LABEL = "Another technician";

/** The calls the controller makes; `ControlClient` implements all of them. */
export interface InputRequestSender {
  requestInputControl(clientRequestId: string, retry?: boolean): void;
  withdrawInputControlRequest(clientRequestId: string): void;
  inputControlPromptShown(requestId: string): void;
  answerInputControlRequest(requestId: string, accept: boolean): void;
}

/** What B's request is doing. Everything but `pending`-like phases is final for that id. */
export type RequestPhase =
  | "sending" // sent, no reply yet
  | InputRequestState // the agent's current state
  | "unconfirmed" // no reply after the last re-send
  | "done"; // a terminal Result is in: `outcome`

export interface RequestView {
  clientRequestId: string;
  phase: RequestPhase;
  /** Set when `phase === "done"`. */
  outcome: InputRequestOutcome | null;
}

export interface HolderPrompt {
  requestId: string;
  /** The requester's signaling session id. TEXT only, and only ever used to look a name up. */
  fromSession: string;
}

export interface InputRequestSnapshot {
  /** The agent's affirmative `InputRequestAvailable`; false until then. */
  available: boolean;
  request: RequestView | null;
  prompts: readonly HolderPrompt[];
}

export const NO_INPUT_REQUEST: InputRequestSnapshot = { available: false, request: null, prompts: [] };

/** One short plain sentence for every outcome and refusal in §2.2. */
export const OUTCOME_TEXT: Readonly<Record<InputRequestOutcome, string>> = {
  granted: "The other technician handed you input control",
  declined: "The other technician declined",
  expired: "The other technician did not answer in time",
  undelivered: "The request did not reach the other technician",
  cancelled: "The request was cancelled",
  replaced: "The request was replaced by a newer one",
  holder_changed: "Input control changed hands before the request was answered",
  already_satisfied: "You already have input control",
  failed: "The hand-over did not complete, try again",
  ineligible: "You cannot request input control right now",
  no_holder: "Nobody has input control right now",
  busy: "Input is recovering, try again shortly",
  rate_limited: "Too many requests, try again in a minute",
  capacity: "Another session of yours already has a request open",
  unsupported_holder: "The other technician's console cannot receive requests",
  unknown: "The agent has no record of that request, so the result is unknown",
  requester_left: "The request ended",
};

export const WAITING_TEXT = "Waiting for the other technician…";
export const HANDING_OVER_TEXT = "Handing over…";
export const UNCONFIRMED_TEXT = "Could not confirm the request, you can send a new one";

/** The line B sees for a request, or null when there is none. */
export function requestStatusText(r: RequestView | null): string | null {
  if (!r) return null;
  switch (r.phase) {
    case "sending":
    case "pending_delivery":
    case "shown":
      return WAITING_TEXT;
    case "accepted_in_flight":
      return HANDING_OVER_TEXT;
    case "unconfirmed":
      return UNCONFIRMED_TEXT;
    case "done":
      return OUTCOME_TEXT[r.outcome ?? "unknown"];
  }
}

export interface InputRequestView {
  /** Render the Session-menu item at all. */
  show: boolean;
  /** The "Request input control" button. */
  canRequest: boolean;
  /** The Withdraw button (only while the holder has not accepted). */
  canWithdraw: boolean;
  status: string | null;
}

/**
 * The view rules (§2.2): the action is offered only on the agent's affirmative `InputRequestAvailable` and
 * only while the docs/61 snapshot says input is OWNED BY ANOTHER session; never to an observer or view-only
 * session, and not before our own id is known. A request in flight, or its sticky outcome, keeps the item
 * (and its status line) up even after the snapshot changes: a `granted` makes us the owner, which must not
 * hide the answer.
 */
export function inputRequestView(
  snap: InputRequestSnapshot,
  handoff: InputHandoffModel,
  observing: boolean,
  ownSessionId: string | null,
): InputRequestView {
  const hidden: InputRequestView = { show: false, canRequest: false, canWithdraw: false, status: null };
  if (!snap.available || observing || ownSessionId === null) return hidden;
  const ownedByOther = handoff.mode === "owned" && handoff.ownerSession !== null && handoff.ownerSession !== ownSessionId;
  const r = snap.request;
  const live = r !== null && r.phase !== "done" && r.phase !== "unconfirmed";
  if (!ownedByOther && r === null) return hidden;
  return {
    show: true,
    canRequest: ownedByOther && !live,
    canWithdraw: r !== null && (r.phase === "sending" || r.phase === "pending_delivery" || r.phase === "shown"),
    status: requestStatusText(r),
  };
}

/** The holder prompt's text: a known participant's display name, else the generic label. Plain text. */
export function holderPromptLabel(fromSession: string, participants: readonly SessionParticipantEntry[]): string {
  const name = participants.find((p) => p.session_id === fromSession)?.display_name;
  return name ? name : GENERIC_HOLDER_LABEL;
}

type Timer = ReturnType<typeof setTimeout>;

export interface ControllerDeps {
  now?: () => number;
  newId?: () => string;
}

/** Both ends' state machine. Holds no React; `getSnapshot` is referentially stable between changes. */
export class InputRequestController {
  private snap: InputRequestSnapshot = NO_INPUT_REQUEST;
  private readonly listeners = new Set<() => void>();
  private retryTimer: Timer | null = null;
  private retries = 0;
  private readonly promptTimers = new Map<string, Timer>();
  private readonly shown = new Set<string>();
  /** request id -> when it was seen closed (withdrawn, answered or expired). Insertion-ordered. */
  private readonly closed = new Map<string, number>();
  private readonly now: () => number;
  private readonly newId: () => string;

  constructor(private readonly sender: () => InputRequestSender | null, deps: ControllerDeps = {}) {
    this.now = deps.now ?? (() => Date.now());
    this.newId = deps.newId ?? (() => crypto.randomUUID().toLowerCase());
  }

  readonly subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => { this.listeners.delete(fn); };
  };

  readonly getSnapshot = (): InputRequestSnapshot => this.snap;

  private set(next: Partial<InputRequestSnapshot>): void {
    this.snap = { ...this.snap, ...next };
    for (const fn of [...this.listeners]) fn();
  }

  /** The session ended or a new one began: nothing carries over (§2.2.2: no resume across a reconnect). */
  reset(): void {
    this.clearRetry();
    for (const t of this.promptTimers.values()) clearTimeout(t);
    this.promptTimers.clear();
    this.shown.clear();
    this.closed.clear();
    if (this.snap !== NO_INPUT_REQUEST) this.set({ ...NO_INPUT_REQUEST });
  }

  dispose(): void {
    this.reset();
    this.listeners.clear();
  }

  private send(fn: (s: InputRequestSender) => void): void {
    try {
      const s = this.sender();
      if (s) fn(s);
    } catch {
      // The transport went away: the retry timer or the session teardown settles it.
    }
  }

  private clearRetry(): void {
    if (this.retryTimer !== null) clearTimeout(this.retryTimer);
    this.retryTimer = null;
  }

  private armRetry(id: string): void {
    this.clearRetry();
    this.retryTimer = setTimeout(() => {
      this.retryTimer = null;
      const r = this.snap.request;
      if (!r || r.clientRequestId !== id || r.phase !== "sending") return;
      if (this.retries >= REQUEST_MAX_RETRIES) {
        this.set({ request: { ...r, phase: "unconfirmed" } });
        return;
      }
      this.retries += 1;
      this.send((s) => s.requestInputControl(id, true));
      this.armRetry(id);
    }, REQUEST_RETRY_MS);
  }

  // ---- requester (B) -------------------------------------------------------------------------------

  /** Ask for control with a fresh id. A request already in flight is left alone. */
  request(): void {
    const r = this.snap.request;
    if (!this.snap.available) return;
    if (r && r.phase !== "done" && r.phase !== "unconfirmed") return;
    const id = this.newId();
    this.retries = 0;
    this.set({ request: { clientRequestId: id, phase: "sending", outcome: null } });
    this.send((s) => s.requestInputControl(id, false));
    this.armRetry(id);
  }

  /** Withdraw while the holder has not accepted. The reply (a `cancelled` Result) is the only answer. */
  withdraw(): void {
    const r = this.snap.request;
    if (!r || (r.phase !== "sending" && r.phase !== "pending_delivery" && r.phase !== "shown")) return;
    this.send((s) => s.withdrawInputControlRequest(r.clientRequestId));
  }

  // ---- holder (A) ----------------------------------------------------------------------------------

  /** The prompt for `requestId` is on screen: tell the agent, once. */
  promptRendered(requestId: string): void {
    if (this.shown.has(requestId) || !this.snap.prompts.some((p) => p.requestId === requestId)) return;
    this.shown.add(requestId);
    this.send((s) => s.inputControlPromptShown(requestId));
  }

  /** Allow or Decline. The prompt goes at once (buttons cannot be double-clicked); the agent's Withdrawn confirms. */
  answer(requestId: string, accept: boolean): void {
    if (!this.snap.prompts.some((p) => p.requestId === requestId)) return;
    this.send((s) => s.answerInputControlRequest(requestId, accept));
    this.closePrompt(requestId);
  }

  private pruneClosed(): void {
    const cutoff = this.now() - CLOSED_IDS_TTL_MS;
    for (const [id, at] of this.closed) if (at < cutoff) this.closed.delete(id);
    while (this.closed.size > CLOSED_IDS_KEPT) {
      const oldest = this.closed.keys().next().value;
      if (oldest === undefined) break;
      this.closed.delete(oldest);
    }
  }

  private markClosed(requestId: string): void {
    this.closed.delete(requestId);
    this.closed.set(requestId, this.now());
    this.pruneClosed();
  }

  private closePrompt(requestId: string): void {
    this.markClosed(requestId);
    const t = this.promptTimers.get(requestId);
    if (t !== undefined) clearTimeout(t);
    this.promptTimers.delete(requestId);
    this.shown.delete(requestId);
    if (this.snap.prompts.some((p) => p.requestId === requestId)) {
      this.set({ prompts: this.snap.prompts.filter((p) => p.requestId !== requestId) });
    }
  }

  // ---- the agent's messages ------------------------------------------------------------------------

  handleMessage(msg: InputRequestAgentMessage): void {
    switch (msg.t) {
      case "InputRequestAvailable":
        if (this.snap.available !== msg.c.available) this.set({ available: msg.c.available });
        return;
      case "InputControlRequestPending": {
        const r = this.snap.request;
        // Sticky: a Pending never overwrites a terminal result, and a stale id is not ours.
        if (!r || r.clientRequestId !== msg.c.client_request_id || r.phase === "done") return;
        this.clearRetry();
        this.set({ request: { ...r, phase: msg.c.state } });
        return;
      }
      case "InputControlRequestResult": {
        const r = this.snap.request;
        if (!r || r.clientRequestId !== msg.c.client_request_id || r.phase === "done") return;
        this.clearRetry();
        this.set({ request: { ...r, phase: "done", outcome: msg.c.outcome } });
        return;
      }
      case "InputControlRequested": {
        const { request_id: id, from_session: from, expires_in_ms: ms } = msg.c;
        this.pruneClosed();
        if (this.closed.has(id) || this.snap.prompts.some((p) => p.requestId === id)) return;
        this.promptTimers.set(id, setTimeout(() => this.closePrompt(id), ms + PROMPT_GRACE_MS));
        this.set({ prompts: [...this.snap.prompts, { requestId: id, fromSession: from }] });
        return;
      }
      case "InputControlRequestWithdrawn":
        // Also recorded for an id never shown (a delayed Requested must not appear after this).
        this.closePrompt(msg.c.request_id);
        return;
    }
  }
}
