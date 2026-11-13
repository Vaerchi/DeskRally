/**
 * Backstage client: the typed browser side of the agent's structured tool API.
 *
 * The agent exposes a single endpoint, `POST /backstage/exec`, whose body is one JSON `Request`
 * (adjacently tagged `{"type": ..., "data": ...}`) and whose reply is an `Envelope`
 * `{ ok, response?, error?, audit? }`. Actions that can change the machine may come back with
 * `error.kind === "needs_confirmation"`; the operator re-types the machine name and the same
 * request is retried with `?confirm=1`.
 *
 * The client takes an **injectable transport** (`(path, body) => Promise<string>`) so it is fully
 * testable without a live agent — the default transport is a thin `fetch` wrapper. This module is
 * transport-agnostic about *how* bytes move: it only knows the endpoint path and the JSON shapes,
 * which mirror the Rust dispatcher (docs/05-backstage-implementation.md) exactly.
 */

import type {
  DirListing,
  EventLogRow,
  ProcessRow,
  ServiceRow,
  SystemInfo,
} from "./panels";

// ---------------------------------------------------------------------------
// Request — adjacently tagged discriminated union (mirror of the Rust `Request` enum)
// ---------------------------------------------------------------------------

/** Verb for a service-control action. */
export type ServiceVerb = "start" | "stop" | "restart";

export interface ReadEventLogArgs {
  channel: string;
  max: number;
}
export interface BrowseDirectoryArgs {
  /** Empty string = the top level (drive roots). */
  path: string;
}
export interface KillProcessArgs {
  pid: number;
  image: string;
  owner: string;
}
export interface ControlServiceArgs {
  service: string;
  verb: ServiceVerb;
}
export interface ReadRegistryArgs {
  path: string;
  value_name: string;
}
export interface WriteRegistryArgs {
  path: string;
  value_name: string;
  new_value: string;
}

/**
 * A backstage tool request. Unit variants carry no `data`; the rest nest their args under `data`,
 * matching serde's adjacently-tagged representation on the wire.
 */
export type Request =
  | { type: "ListProcesses" }
  | { type: "ListServices" }
  | { type: "GetSystemInfo" }
  | { type: "ReadEventLog"; data: ReadEventLogArgs }
  | { type: "BrowseDirectory"; data: BrowseDirectoryArgs }
  | { type: "KillProcess"; data: KillProcessArgs }
  | { type: "ControlService"; data: ControlServiceArgs }
  | { type: "ReadRegistry"; data: ReadRegistryArgs }
  | { type: "WriteRegistry"; data: WriteRegistryArgs }
  // docs/58 file management (admin tier; sent only to an agent that advertised `file_manage`).
  | { type: "CreateDirectory"; data: { path: string } }
  | { type: "RenamePath"; data: { from: string; to: string } }
  | { type: "DeletePath"; data: { path: string } }
  // docs/58 §12 (agent advertised `file_place`): place / discard a completed upload by transfer id.
  | { type: "PlaceUpload"; data: { transfer_id: string; dest_dir: string } }
  | { type: "DiscardUpload"; data: { transfer_id: string } };

/** Discriminator strings for requests. */
export type RequestType = Request["type"];

// ---------------------------------------------------------------------------
// Response + Envelope (mirror of the Rust response enum and reply envelope)
// ---------------------------------------------------------------------------

/**
 * A successful tool response. `Ack` carries no `data` (it acknowledges a mutating action);
 * `RegistryValue` carries a bare string or null.
 */
export type Response =
  | { type: "ProcessList"; data: ProcessRow[] }
  | { type: "ServiceList"; data: ServiceRow[] }
  | { type: "SystemInfo"; data: SystemInfo }
  | { type: "EventLog"; data: EventLogRow[] }
  | { type: "DirectoryListing"; data: DirListing }
  | { type: "RegistryValue"; data: string | null }
  | { type: "Ack" };

export type ResponseType = Response["type"];

/** Failure classes the dispatcher returns. */
export type ErrorKind = "denied" | "needs_confirmation" | "refused" | "exec_failed";

export interface BackstageError {
  kind: ErrorKind;
  message: string;
  /** docs/58 §3: on `needs_confirmation`, the token a confirmed retry must echo. Absent from an
   *  agent too old to accept a confirmation over the session channel. */
  confirm_token?: string;
}

/**
 * Tamper-evident audit record attached to every dispatched request (present even on denials).
 * Mirrors the agent's `audit.rs` event; the SHA-256 `hash` chains events. Only `hash` and
 * `outcome` are relied on by the UI — the rest are surfaced when present.
 */
export interface AuditEvent {
  /** SHA-256 hash of this event over its canonical preimage (hex). */
  hash: string;
  /**
   * Dispatch outcome. The live agent serializes the Rust `Outcome` enum as an object (e.g.
   * `{ "result": "ok" }` / `{ "result": "denied", "reason": … }`); older/mock sources use a bare
   * string (e.g. "authorized"). Render via {@link auditOutcomeLabel}, which accepts either.
   */
  outcome: string | { result?: string; reason?: string; [k: string]: unknown };
  /** Hash of the previous event in the chain, when present. */
  prev_hash?: string | null;
  /** Monotonic sequence number in the chain. */
  seq?: number;
  /** RFC3339 timestamp of the event. */
  time?: string;
  /** Unix-ms timestamp the live agent stamps (`occurred_at_unix_ms`). */
  occurred_at_unix_ms?: number;
  /**
   * The action/tool that was dispatched. The live agent serializes the Rust `Action` enum as an
   * object (e.g. `{ "kind": "consent_signal", … }`); mocks use a bare string. Render via
   * {@link auditActionLabel}.
   */
  action?: string | { kind?: string; [k: string]: unknown };
  /** The token identity the operation ran under, when recorded. */
  actor?: string;
}

/** A short, safe display string for an {@link AuditEvent} outcome (string form or Rust-enum object). */
export function auditOutcomeLabel(audit: AuditEvent): string {
  const o = audit.outcome;
  if (typeof o === "string") return o;
  if (o && typeof o === "object") return o.result ?? "unknown";
  return "unknown";
}

/** A short display string for an {@link AuditEvent} action (string form or Rust-enum object), or "". */
export function auditActionLabel(audit: AuditEvent): string {
  const a = audit.action;
  if (typeof a === "string") return a;
  if (a && typeof a === "object") return a.kind ?? "";
  return "";
}

/** The reply envelope: exactly one of `response` (ok) or `error` (failure), plus optional audit. */
export interface Envelope {
  ok: boolean;
  response?: Response;
  error?: BackstageError;
  audit?: AuditEvent;
}

// ---------------------------------------------------------------------------
// Transport seam
// ---------------------------------------------------------------------------

/** The one thing the client needs from the outside world: send a JSON body to a path, get text. */
export type BackstageTransport = (path: string, body: string) => Promise<string>;

/** The endpoint the agent serves the tool API on. */
export const BACKSTAGE_EXEC_PATH = "/backstage/exec";

/**
 * Default `fetch`-based transport. `baseUrl` is prefixed to the path (empty = same origin as the
 * console). POSTs `application/json` and returns the raw response text for the client to parse.
 */
export function fetchTransport(baseUrl = ""): BackstageTransport {
  return async (path, body) => {
    const res = await fetch(baseUrl + path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    return res.text();
  };
}

/** Parse an envelope, checking fields the UI relies on before returning typed data. */
export function parseEnvelope(text: string): Envelope {
  const value: unknown = JSON.parse(text);
  const isObject = (v: unknown): v is Record<string, unknown> =>
    typeof v === "object" && v !== null && !Array.isArray(v);
  const malformed = (field: string): never => {
    throw new Error(`malformed Under the Hood reply: invalid '${field}'`);
  };
  if (!isObject(value) || typeof value.ok !== "boolean") {
    throw new Error("malformed Under the Hood reply: missing 'ok' flag");
  }
  // Nested fields come from the agent too; a top-level flag cannot make them safe to render.
  if ("error" in value) {
    const error = value.error;
    if (!isObject(error)) malformed("error");
    else {
      if (typeof error.kind !== "string") malformed("error.kind");
      if (typeof error.message !== "string") malformed("error.message");
      if ("confirm_token" in error && typeof error.confirm_token !== "string") malformed("error.confirm_token");
    }
  }
  if ("audit" in value) {
    const audit = value.audit;
    if (!isObject(audit)) malformed("audit");
    else {
      if (typeof audit.hash !== "string") malformed("audit.hash");
      for (const field of ["time", "actor"] as const) {
        if (field in audit && typeof audit[field] !== "string") malformed(`audit.${field}`);
      }
      if ("prev_hash" in audit && audit.prev_hash !== null && typeof audit.prev_hash !== "string") {
        malformed("audit.prev_hash");
      }
      const outcome = audit.outcome;
      if (typeof outcome !== "string") {
        if (!isObject(outcome)) malformed("audit.outcome");
        else {
          for (const field of ["result", "reason"] as const) {
            if (field in outcome && typeof outcome[field] !== "string") malformed(`audit.outcome.${field}`);
          }
        }
      }
      if ("action" in audit && typeof audit.action !== "string") {
        const action = audit.action;
        if (!isObject(action)) malformed("audit.action");
        else if ("kind" in action && typeof action.kind !== "string") malformed("audit.action.kind");
      }
    }
  }
  return value as unknown as Envelope;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/** Options for a single `exec`. */
export interface ExecOptions {
  /** Send `?confirm=1` — the retry after the operator confirmed a dangerous action. */
  confirm?: boolean;
  /** docs/58 §3: the agent's `confirm_token`, echoed as the request's top-level `confirm`. */
  confirmToken?: string;
}

/** Shown when an agent asks for confirmation but cannot accept one over the session channel. */
export const AGENT_TOO_OLD_TO_CONFIRM =
  "This agent cannot accept confirmations from here. Update the agent on this machine to 1.3.17 or later.";

/**
 * Typed backstage client. Construct with a transport (default: `fetchTransport()` at
 * `/backstage/exec`). Every method returns the full `Envelope` so callers can surface the audit
 * record and branch on `error.kind` (notably `needs_confirmation`).
 */
export class BackstageClient {
  private readonly transport: BackstageTransport;
  /**
   * docs/58 §2-3: whether a confirmed retry may be sent. A session client starts WITHOUT it and
   * gains it only when the session's agent advertises `confirm` ({@link allowConfirmation}); a new
   * session builds a new client, so the permission never outlives the session. The dev HTTP seam
   * (no session) confirms with `?confirm=1` as it always has.
   */
  private confirmAllowed: boolean;

  constructor(transport: BackstageTransport = fetchTransport(), opts: { sessionChannel?: boolean } = {}) {
    this.transport = transport;
    this.confirmAllowed = !opts.sessionChannel;
  }

  /** The session's agent advertised `confirm` (docs/58 §2). */
  allowConfirmation(): void {
    this.confirmAllowed = true;
  }

  /** Send one request; returns the decoded envelope. Set `opts.confirm` to add `?confirm=1`. */
  async exec(request: Request, opts: ExecOptions = {}): Promise<Envelope> {
    const path = opts.confirm ? `${BACKSTAGE_EXEC_PATH}?confirm=1` : BACKSTAGE_EXEC_PATH;
    const body = opts.confirmToken ? { ...request, confirm: opts.confirmToken } : request;
    const text = await this.transport(path, JSON.stringify(body));
    return parseEnvelope(text);
  }

  /**
   * Send a (typically mutating) request and, if the agent replies `needs_confirmation`, ask the
   * caller-supplied `confirm` callback (which prompts the operator to re-type the machine name).
   * If it resolves true, retry once with `?confirm=1`; otherwise return the original
   * `needs_confirmation` envelope untouched.
   */
  async execConfirmable(
    request: Request,
    confirm: (pending: Envelope) => Promise<boolean>,
  ): Promise<Envelope> {
    const first = await this.exec(request);
    if (first.ok || first.error?.kind !== "needs_confirmation") return first;
    const token = first.error.confirm_token;
    // docs/58 §3: without the advertised `confirm` feature, or without a token, the agent cannot be
    // told the operator confirmed (an agent older than 1.3.17 dispatches every session frame
    // unconfirmed); say so instead of a dialog that could only ever loop. A token alone is not
    // enough: the session's agent must have advertised the feature.
    if (!token || !this.confirmAllowed) {
      return { ...first, error: { kind: "needs_confirmation", message: AGENT_TOO_OLD_TO_CONFIRM } };
    }
    const proceed = await confirm(first);
    if (!proceed) return first;
    // One retry. If the target changed meanwhile the agent answers needs_confirmation again with a
    // new token; that reply is returned as is, for the operator to look at, never retried blindly.
    return this.exec(request, { confirm: true, confirmToken: token });
  }

  // --- Read-only tools -----------------------------------------------------

  listProcesses(): Promise<Envelope> {
    return this.exec({ type: "ListProcesses" });
  }
  listServices(): Promise<Envelope> {
    return this.exec({ type: "ListServices" });
  }
  getSystemInfo(): Promise<Envelope> {
    return this.exec({ type: "GetSystemInfo" });
  }
  readEventLog(channel: string, max: number): Promise<Envelope> {
    return this.exec({ type: "ReadEventLog", data: { channel, max } });
  }
  browseDirectory(path: string): Promise<Envelope> {
    return this.exec({ type: "BrowseDirectory", data: { path } });
  }
  readRegistry(args: ReadRegistryArgs): Promise<Envelope> {
    return this.exec({ type: "ReadRegistry", data: args });
  }

  // --- Mutating tools (route through execConfirmable for the confirm flow) --

  killProcess(args: KillProcessArgs, confirm: () => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "KillProcess", data: args }, confirm);
  }
  controlService(args: ControlServiceArgs, confirm: () => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "ControlService", data: args }, confirm);
  }
  writeRegistry(args: WriteRegistryArgs, confirm: () => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "WriteRegistry", data: args }, confirm);
  }

  // --- docs/58 file management ---------------------------------------------

  createDirectory(path: string, confirm: (pending: Envelope) => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "CreateDirectory", data: { path } }, confirm);
  }
  renamePath(from: string, to: string, confirm: (pending: Envelope) => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "RenamePath", data: { from, to } }, confirm);
  }
  deletePath(path: string, confirm: (pending: Envelope) => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "DeletePath", data: { path } }, confirm);
  }
  placeUpload(transferId: string, destDir: string, confirm: (pending: Envelope) => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "PlaceUpload", data: { transfer_id: transferId, dest_dir: destDir } }, confirm);
  }
  discardUpload(transferId: string, confirm: (pending: Envelope) => Promise<boolean>): Promise<Envelope> {
    return this.execConfirmable({ type: "DiscardUpload", data: { transfer_id: transferId } }, confirm);
  }
}
