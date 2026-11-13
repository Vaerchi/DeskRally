/**
 * Guest help requests, console side (docs/64, H-C1..H-C7).
 *
 * An ENROLLED machine asks for a technician; the control plane queues the request, scoped to the groups
 * the signed-in user may start sessions in. Accepting creates the session on the SERVER (bound to this
 * one request, through the same admission as `POST /sessions`) and answers with that session's ticket;
 * the console then connects to THAT session exactly like a transferred one (an owned, ordinary session).
 *
 * Everything here is pure orchestration over the API seam, so it is unit-tested without a browser. The
 * note is the guest machine's own text: it is rendered as plain React text under the label
 * {@link HELP_NOTE_LABEL}, and {@link displayNote} is the client's second line of defence behind the
 * server's normalisation.
 */
import type { ConsoleApi, HelpRequest, StartedSession } from "./console_api";
import type { BrokeredSession } from "./session_broker";

/** How often the open list is re-read (no push channel exists; the audit bell polls at 20 s). */
export const HELP_POLL_MS = 15_000;
/** The label every note appears under: the text is the guest machine's, not the technician's or the server's. */
export const HELP_NOTE_LABEL = "From the guest's machine";
/** The longest note shown (the server caps at 200 characters; this is a defensive bound). */
export const HELP_NOTE_MAX = 200;

/** The badge text: null when nothing is waiting, the count up to 99, then "99+". */
export function helpBadge(count: number): string | null {
  if (count <= 0) return null;
  return count > 99 ? "99+" : String(count);
}

/** C0/C1 controls and the Unicode format characters (soft hyphen, zero-width, bidi marks and overrides, BOM). */
function droppable(cp: number): boolean {
  return cp <= 0x1f || (cp >= 0x7f && cp <= 0x9f) || cp === 0xad || cp === 0x61c || cp === 0x180e ||
    (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x2028 && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x206f) || cp === 0xfeff;
}

/**
 * The note as plain display text: control and bidirectional-format characters dropped (whitespace controls
 * become spaces), trimmed, capped. The result is only ever placed in a React text node.
 */
export function displayNote(note: unknown): string {
  if (typeof note !== "string") return "";
  let out = "";
  for (const ch of note) {
    if (ch === "\n" || ch === "\r" || ch === "\t") {
      out += " ";
      continue;
    }
    // C0/C1 controls, then the Unicode format characters (zero-width and bidi overrides among them).
    if (droppable(ch.codePointAt(0) ?? 0)) continue;
    out += ch;
  }
  return Array.from(out.trim()).slice(0, HELP_NOTE_MAX).join("").trim();
}

export interface HelpRequestRowView {
  id: string;
  /** The machine's alias when set, else its name. */
  title: string;
  /** The machine's own name, shown beside an alias. */
  subtitle: string;
  note: string;
  noteLabel: string;
  /** True only for an open request on a machine not known to be offline. */
  canAccept: boolean;
  /** Presence says the machine is offline: shown as such, with NO accept button. */
  offline: boolean;
  createdAt: string;
  expiresAt: string;
}

export function helpRowView(r: HelpRequest): HelpRequestRowView {
  const alias = (r.machine_alias ?? "").trim();
  const name = (r.machine_name ?? "").trim() || r.machine_id;
  const offline = r.online === false;
  return {
    id: r.id,
    title: alias || name,
    subtitle: alias && alias !== name ? name : "",
    note: displayNote(r.note),
    noteLabel: HELP_NOTE_LABEL,
    canAccept: r.status === "open" && r.can_accept === true && !offline,
    offline,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  };
}

export interface HelpBellView {
  badge: string | null;
  label: string;
  empty: boolean;
  rows: HelpRequestRowView[];
}

/**
 * Pure view model for the "Help requests" control: only OPEN requests list. `unresolved` is the number of
 * accepts whose outcome is unknown (0 or 1): they are not in the queue any more but still need the
 * technician, so they count in the badge.
 */
export function helpBellView(requests: readonly HelpRequest[], unresolved = 0): HelpBellView {
  const open = requests.filter((r) => r.status === "open");
  const waiting = open.length + unresolved;
  const badge = helpBadge(waiting);
  return {
    badge,
    label: waiting === 0 ? "Help requests" : `Help requests, ${waiting} waiting`,
    empty: open.length === 0,
    rows: open.map(helpRowView),
  };
}

export interface AcceptedHelpSession {
  /** The machine's DEVICE id, from the signaling envelope (what the connect path dials). */
  deviceId: string;
  signalingUrl: string;
  brokered: BrokeredSession;
}

/**
 * Turn the accept response (POST /sessions' own shape) into what the connect path takes. The session is
 * OWNED, like any ordinary one: renewed, recovered and ended on teardown. Throws when signaling is
 * missing, because a session the console cannot dial must not look connected.
 */
export function acceptedHelpSession(started: StartedSession): AcceptedHelpSession {
  if (!started.signaling) throw new Error("The control plane returned no signaling for the accepted help request.");
  return {
    deviceId: started.signaling.device_id,
    signalingUrl: started.signaling.url,
    brokered: {
      sessionId: started.session.id,
      signaling: started.signaling,
      ...(started.session_policy ? { sessionPolicy: started.session_policy } : {}),
      owned: true,
    },
  };
}

/**
 * One idempotency key per request id for the life of the console, so a retry after a lost response
 * (the server committed the accept, the answer never arrived) returns the SAME session instead of a
 * "request is accepted" conflict.
 */
export class AcceptKeys {
  private readonly keys = new Map<string, string>();
  constructor(private readonly make: () => string = defaultKey) {}
  forRequest(id: string): string {
    let k = this.keys.get(id);
    if (!k) {
      k = this.make();
      this.keys.set(id, k);
      if (this.keys.size > 200) this.keys.delete(this.keys.keys().next().value as string);
    }
    return k;
  }
}

function defaultKey(): string {
  try {
    return `acc-${crypto.randomUUID()}`;
  } catch {
    return `acc-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }
}

/** The 4xx statuses that mean "this deployment has no help requests for you": stop polling quietly. */
function absent(error: unknown): boolean {
  const status = (error as { status?: number } | null)?.status;
  return status === 404 || status === 401 || status === 403;
}

/**
 * Polls the open list. Best-effort like the audit bell: a failed poll keeps the last list and retries; a
 * 404 / 401 / 403 (an older control plane without the route, or a role that cannot start sessions) stops
 * polling and shows nothing, instead of asking every few seconds forever.
 */
export class HelpRequestPoller {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private epoch = 0;

  constructor(
    private readonly api: Pick<ConsoleApi, "listHelpRequests">,
    private readonly onChange: (requests: HelpRequest[]) => void,
    private readonly intervalMs = HELP_POLL_MS,
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

  /** Poll now (after an accept attempt), without waiting for the next tick. */
  refresh(): void {
    if (!this.running) return;
    clearTimeout(this.timer);
    void this.tick(++this.epoch);
  }

  private async tick(epoch: number): Promise<void> {
    try {
      const rows = await this.api.listHelpRequests();
      if (epoch !== this.epoch || !this.running) return;
      this.onChange(rows.filter((r) => r.status === "open"));
    } catch (error) {
      if (epoch !== this.epoch || !this.running) return;
      if (absent(error)) {
        this.onChange([]);
        this.running = false;
        return;
      }
      /* retried on the next tick */
    }
    if (epoch !== this.epoch || !this.running) return;
    this.timer = setTimeout(() => void this.tick(epoch), this.intervalMs);
  }
}

// ---------------------------------------------------------------------------------------------------------
// Accepting with a lost response (review r2 #7)
// ---------------------------------------------------------------------------------------------------------

/** Whether a failed accept may still have committed on the server (so the SAME attempt can be retried). */
export type AcceptFailure = "retryable" | "terminal";

/**
 * A failed accept is RETRYABLE when the outcome is unknown or transient: no HTTP status at all (network
 * failure, abort), a 2xx whose body could not be read (the server committed and the answer was lost or
 * mangled), 408/425/429 and any 5xx (the control plane answers 503 while the original is still issuing the
 * session). Every other 4xx is a TERMINAL answer (taken by someone else, expired, offline, out of scope...):
 * retrying cannot change it.
 */
export function classifyAcceptFailure(error: unknown): AcceptFailure {
  const status = (error as { status?: unknown } | null)?.status;
  if (typeof status !== "number") return "retryable";
  if (status < 400) return "retryable";
  if (status === 408 || status === 425 || status === 429 || status >= 500) return "retryable";
  return "terminal";
}

/** An accept whose outcome is not confirmed. Kept independently of the open queue, which stops listing the
 *  request the moment the server has accepted it. */
export interface UnresolvedAccept {
  request: HelpRequest;
  opId: string;
  message: string;
  attempts: number;
}

export interface HelpAcceptState {
  /** The request being accepted right now. */
  accepting: { id: string; status: string } | null;
  /** A TERMINAL failure, verbatim from the server. */
  error: { id: string; message: string } | null;
  /** An accept that may have committed: shown with Retry (same request id + op_id) until resolved. */
  unresolved: UnresolvedAccept | null;
}

/** Why Accept is refused on a request while another accept is unresolved. */
export function blockedByUnresolvedMessage(u: UnresolvedAccept): string {
  const name = u.request.machine_alias || u.request.machine_name;
  return `Finish the pending accept for ${name} first: use its Retry. It may already have connected.`;
}

const IDLE: HelpAcceptState = { accepting: null, error: null, unresolved: null };

/**
 * Runs accepts and remembers the one whose outcome is unknown. A retry reuses the request id AND the
 * idempotency key, so the server answers with the SAME session if the first attempt had committed. Every
 * attempt is bound to the sign-in it started under: after {@link reset} (sign-out, tenant switch) a late
 * response changes no state and connects nothing.
 */
export class HelpAcceptController {
  private state: HelpAcceptState = IDLE;
  private generation = 0;
  constructor(
    private readonly api: Pick<ConsoleApi, "acceptHelpRequest">,
    private readonly keys: AcceptKeys,
    private readonly onChange: (state: HelpAcceptState) => void,
  ) {}

  snapshot(): HelpAcceptState {
    return this.state;
  }

  private set(next: HelpAcceptState): void {
    this.state = next;
    this.onChange(next);
  }

  /** Forget everything (auth changed): in-flight attempts become inert. */
  reset(): void {
    this.generation++;
    this.set(IDLE);
  }

  /**
   * One attempt for `request` (a first accept or a Retry: both send the same id + key). Resolves to the
   * session to connect to, or null (refused, unresolved, or superseded by {@link reset}).
   */
  async attempt(request: HelpRequest): Promise<AcceptedHelpSession | null> {
    const gen = this.generation;
    const pending = this.state.unresolved;
    if (pending && pending.request.id !== request.id) {
      // Another accept may have committed and left the queue: its Retry is the only way back to that session,
      // so no OTHER accept may start (and drop it) until it resolves.
      this.set({ ...this.state, error: { id: request.id, message: blockedByUnresolvedMessage(pending) } });
      return null;
    }
    const opId = this.keys.forRequest(request.id);
    const prior = pending;
    this.set({ accepting: { id: request.id, status: prior ? "Retrying…" : "Accepting…" }, error: null, unresolved: prior });
    try {
      const started = await this.api.acceptHelpRequest(request.id, opId);
      if (gen !== this.generation) return null;
      const session = acceptedHelpSession(started);
      this.set(IDLE);
      return session;
    } catch (failure) {
      if (gen !== this.generation) return null;
      const message = failure instanceof Error ? failure.message : String(failure);
      if (classifyAcceptFailure(failure) === "retryable") {
        this.set({ accepting: null, error: null, unresolved: { request, opId, message, attempts: (prior?.attempts ?? 0) + 1 } });
      } else {
        this.set({ accepting: null, error: { id: request.id, message }, unresolved: null });
      }
      return null;
    }
  }

  /** Retry the unresolved accept with its retained request id and key. */
  retry(): Promise<AcceptedHelpSession | null> {
    const u = this.state.unresolved;
    return u ? this.attempt(u.request) : Promise.resolve(null);
  }

  clearError(): void {
    if (this.state.error) this.set({ ...this.state, error: null });
  }
}
