import type { ConsoleApi } from "./console_api";
import type { AuthSession } from "./auth_session";
import { ControlClient } from "./control";
import type { CommandResult, CommandShell } from "./control";
import { ChannelId, asDeviceId } from "./protocol";
import { SignalingClient, WebRTCTransport } from "./transport";
import type { Transport, TransportEvents, WebRTCTransportConfig } from "./transport";
import { acquireBrokeredSession, releaseBrokeredSession } from "./session_broker";
import { SessionLeaseRenewer } from "./session_lease";
import { auditSessionIdFor, makeAuditForwarder } from "./session_audit";
import type { AuditEvent, AuditForwarder } from "./audit_forward";
import { iceServersFor } from "./ice_servers";
import { runToolboxScript } from "./toolbox_run";
import { runAdhocCommand } from "./adhoc_run";
import { composeRunLine, type BulkTask } from "./bulk_run";
import { ChannelBackstageTransport } from "../backstage/channel";
import { FileTransferClient } from "./file_transfer";

export type RunOutcome =
  | { kind: "done"; exitCode: number; stdout: string; stderr: string; agentTruncated: boolean; consoleTruncated: boolean }
  | { kind: "not_run"; reason: string }
  | { kind: "unknown"; reason: string };

export type CorePhase = "acquire" | "signaling" | "channel" | "policy" | "authorization" | "result" | "closed";

export class CoreError extends Error {
  constructor(readonly phase: CorePhase, message: string) {
    super(message);
    this.name = "CoreError";
  }
}

type CoreApi = Pick<ConsoleApi, "startBrokeredSession" | "endSession" | "setSessionNote" | "requestToolboxRun" | "requestCommandRun" | "renewSessionPolicy" | "ingestAudit">;
type ControlHandlers = NonNullable<ConstructorParameters<typeof ControlClient>[1]>;
type CoreControl = Pick<ControlClient, "installSessionPolicy" | "runCommand" | "handleMessage">;
type CoreSignaling = Pick<SignalingClient, "open" | "send" | "close">;

export interface BrokeredSessionCoreDeps {
  api: CoreApi;
  authSession: Pick<AuthSession, "epoch" | "isCurrent">;
  signal?: AbortSignal;
  makeSignaling?: (url: string) => CoreSignaling;
  makeTransport?: (config: WebRTCTransportConfig, events: TransportEvents) => Transport;
  /** The default binds the send callback to this instance's Control channel. */
  makeControl?: (handlers: ControlHandlers) => CoreControl;
  now?: () => number;
  setTimer?: (fn: () => void, ms: number) => number;
  clearTimer?: (handle: number) => void;
  /** Audit delivery failures must be surfaced by the caller, including after a result settles. */
  onAuditError?: (error: Error) => void;
}

/** Keep valid UTF-8 heads without splitting a code point or retaining the discarded tail. */
function outputHead(value: string, budget: number): { text: string; bytes: number; truncated: boolean } {
  let text = "";
  let bytes = 0;
  for (const char of value) {
    const point = char.codePointAt(0)!;
    const size = point <= 0x7f ? 1 : point <= 0x7ff ? 2 : point <= 0xffff ? 3 : 4;
    if (bytes + size > budget) return { text, bytes, truncated: true };
    text += char;
    bytes += size;
  }
  return { text, bytes, truncated: false };
}

export class BrokeredSessionCore {
  private id = "";
  get sessionId(): string { return this.id; }
  private readonly epoch: number;
  private readonly now: () => number;
  private readonly setTimer: (fn: () => void, ms: number) => number;
  private readonly clearTimer: (handle: number) => void;
  private readonly abort = new AbortController();
  private readonly signals: AbortSignal[];
  private readonly ownedRecords = new Set<string>();
  private readonly releasedRecords = new Set<string>();
  private readonly timers = new Set<number>();
  private closed = false;
  private ready = false;
  private used = false;
  private dispatched = false;
  private phase: CorePhase = "acquire";
  private failure: CoreError | null = null;
  private readonly stopped: Promise<CoreError>;
  private stop!: (error: CoreError) => void;
  private closing: Promise<void> | null = null;
  private signaling?: CoreSignaling;
  private transport?: Transport;
  private control?: CoreControl;
  private renewer?: SessionLeaseRenewer;
  private audit: AuditForwarder | null = null;
  private backstage?: ChannelBackstageTransport;
  private files?: FileTransferClient;
  private policyPending = false;
  // Runs waiting for a RENEWAL installation to be acknowledged (Codex impl review p1): a renewed policy
  // may turn the session view-only or recording-required, so nothing is dispatched while one is in
  // flight. Settled by onSessionPolicyInstalled; a wait is bounded by the caller.
  private policyWaiters: Array<() => void> = [];
  private policyRequired = false;
  private policyApplied = false;
  private policySigned = "";
  private refusal: string | null = null;
  // The agent-advertised transfer folder (control TransferDir), for push-and-run (docs/60 2a).
  private transferDir?: string;
  // Prefixed onto the eventual outcome when a run follows an upload, so the uploaded-as fact
  // survives every later classification, including the conservative catch paths (review r1 M2).
  private resultNote = "";
  private channelOpen = false;
  private channelResolve!: () => void;
  private policyResolve!: () => void;
  private readonly channelReady = new Promise<void>((resolve) => { this.channelResolve = resolve; });
  private readonly policyReady = new Promise<void>((resolve) => { this.policyResolve = resolve; });
  private settleRun?: (outcome: RunOutcome) => void;

  private constructor(private readonly deps: BrokeredSessionCoreDeps, signal?: AbortSignal) {
    this.epoch = deps.authSession.epoch;
    this.now = deps.now ?? Date.now;
    this.setTimer = deps.setTimer ?? ((fn, ms) => setTimeout(fn, ms) as unknown as number);
    this.clearTimer = deps.clearTimer ?? ((handle) => clearTimeout(handle));
    this.stopped = new Promise((resolve) => { this.stop = resolve; });
    this.signals = [...new Set([deps.signal, signal].filter((value): value is AbortSignal => !!value))];
  }

  /** Caller supplies only device ids from non-ephemeral machines in the console machine list. */
  static async open(device: string, deps: BrokeredSessionCoreDeps, opts: { note?: string; signal?: AbortSignal } = {}): Promise<BrokeredSessionCore> {
    const core = new BrokeredSessionCore(deps, opts.signal);
    try {
      core.signals.forEach((signal) => signal.addEventListener("abort", core.onAbort));
      if (core.signals.some((signal) => signal.aborted)) throw new CoreError("acquire", "Cancelled");
      core.check();
      core.pollAuth();
      await core.establish(device, opts.note);
      core.check();
      core.ready = true;
      return core;
    } catch (error) {
      const typed = core.failure ?? (error instanceof CoreError ? error : new CoreError(core.phase, core.message(error)));
      core.fail(typed);
      await core.close();
      throw typed;
    }
  }

  private message(error: unknown): string { return error instanceof Error ? error.message : String(error); }

  private check(): void {
    if (this.closed) throw this.failure ?? new CoreError("closed", "Session closed");
    if (!this.deps.authSession.isCurrent(this.epoch)) {
      const error = new CoreError(this.phase, "Authentication changed");
      this.fail(error);
      throw error;
    }
  }

  private readonly onAbort = (): void => {
    // Cancellation cannot recall a command already handed to the transport.
    if (!this.dispatched) this.fail(new CoreError(this.phase, "Cancelled"));
  };

  private schedule(fn: () => void, ms: number): number {
    const handle = this.setTimer(() => { this.timers.delete(handle); fn(); }, ms);
    this.timers.add(handle);
    return handle;
  }

  private unschedule(handle: number): void {
    this.clearTimer(handle);
    this.timers.delete(handle);
  }

  private pollAuth(): void {
    this.schedule(() => {
      if (this.closed) return;
      try { this.check(); this.pollAuth(); } catch { /* check initiates teardown */ }
    }, 1000);
  }

  private async wait<T>(promise: Promise<T>, phase: CorePhase, ms: number): Promise<T> {
    this.phase = phase;
    this.check();
    const deadline = this.now() + ms;
    let handle: number | undefined;
    const timeout = new Promise<never>((_, reject) => {
      const wake = () => {
        const remaining = deadline - this.now();
        if (remaining > 0) { handle = this.schedule(wake, remaining); return; }
        const error = new CoreError(phase, `${phase} timed out`);
        this.fail(error);
        reject(error);
      };
      handle = this.schedule(wake, ms);
    });
    try {
      const value = await Promise.race([promise, timeout, this.stopped.then((error) => { throw error; })]);
      this.check();
      return value;
    } finally {
      if (handle !== undefined) this.unschedule(handle);
    }
  }

  private release(id: string): void {
    if (this.releasedRecords.has(id)) return;
    this.releasedRecords.add(id);
    // This existing primitive starts the keepalive end call and absorbs network failures.
    try { releaseBrokeredSession(this.deps.api, id); } catch { /* best effort */ }
  }

  private async establish(device: string, note?: string): Promise<void> {
    // Own the raw start response, including records whose missing envelope makes acquisition null.
    const brokered = await this.wait(acquireBrokeredSession({
      startBrokeredSession: async (target) => {
        this.check();
        const started = await this.deps.api.startBrokeredSession(target, this.abort.signal);
        this.ownedRecords.add(started.session.id);
        if (this.closed || !this.deps.authSession.isCurrent(this.epoch)) this.release(started.session.id);
        return started;
      },
    }, device), "acquire", 15000);
    if (!brokered) throw new CoreError("acquire", "A brokered session is required; nothing ran");
    this.id = brokered.sessionId;
    this.policyRequired = !!brokered.sessionPolicy;
    this.policySigned = brokered.sessionPolicy?.signed ?? "";
    // The unchanged factory reads only ingestAudit; preserve its first-event chain adoption.
    this.audit = makeAuditForwarder(this.deps.api as ConsoleApi, auditSessionIdFor(brokered), (error) => this.auditError(error));
    this.flushPeriodically();
    if (note !== undefined) {
      // Descriptive only (design v2, Q2): the run's authority and audit never depend on it, so a
      // refused or failed note (no note capability, a transient error) must not fail the row. The WAIT
      // is bounded; the request itself is not cancelled, so a slow note may still land later. That is
      // harmless: it only annotates this session's own record.
      // Its own bound, NOT this.wait(): a wait() timeout fails the whole core.
      let handle: number | undefined;
      try {
        await Promise.race([
          this.deps.api.setSessionNote(this.id, note),
          new Promise<never>((_, reject) => { handle = this.schedule(() => reject(new Error("session note timed out")), 15000); }),
        ]);
      } catch (error) {
        console.warn("Bulk session note could not be set; continuing.", error);
      } finally {
        if (handle !== undefined) this.unschedule(handle);
      }
      this.check();
    }
    this.check();
    this.signaling = this.deps.makeSignaling?.(brokered.signaling.url) ?? new SignalingClient(brokered.signaling.url);
    await this.wait(this.signaling.open(), "signaling", 20000);
    this.signaling.send({
      type: "register_agent", device: asDeviceId(crypto.randomUUID()),
      pubkey: "ed25519:browser-controller", nat: "unknown", enrollment_token: null,
    });
    this.check();
    this.renewer = new SessionLeaseRenewer({
      renew: (id, signal) => { this.check(); return this.deps.api.renewSessionPolicy(id, signal); },
      install: (signed) => {
        this.check();
        this.policyPending = true;
        this.control!.installSessionPolicy(signed);
      },
      onRefused: (message) => { if (!this.closed) this.fail(new CoreError("policy", message)); },
      setTimer: this.setTimer, clearTimer: this.clearTimer,
    });
    const handlers: ControlHandlers = {
      onSessionPolicyInstalled: (_access, viewOnly, _allowRecording, requireRecording) => {
        if (!this.live()) return;
        // Unsolicited acknowledgements cannot satisfy the initial installation gate.
        if (!this.policyPending) return;
        this.policyPending = false;
        this.policyApplied = true;
        this.policyResolve();
        for (const settle of this.policyWaiters.splice(0)) settle();
        if (viewOnly || requireRecording) {
          this.refusal = "Needs an interactive session: " + (viewOnly ? "effective policy is view-only" : "recording is required");
          if (this.dispatched) this.fail(new CoreError("policy", this.refusal));
          else if (this.used) this.finish({ kind: "not_run", reason: this.refusal });
        }
      },
      onSessionLeaseRequired: () => { if (this.live()) this.renewer!.start(this.id); },
      onCommandResult: (result) => { if (this.live() && this.dispatched) this.result(result); },
      onError: (message) => this.agentError(message),
      onElevationDenied: (reason) => this.agentError(reason),
      onSessionEnding: () => { if (this.live()) this.fail(new CoreError(this.phase, "Remote session ending")); },
      onSessionEndedByGuest: () => { if (this.live()) this.fail(new CoreError(this.phase, "Guest ended the session")); },
      onViewOnlyApplied: (enabled) => {
        if (!enabled || !this.live()) return;
        this.refusal = "Needs an interactive session: effective policy is view-only";
        if (this.dispatched) this.fail(new CoreError("policy", this.refusal));
        else if (this.used) this.finish({ kind: "not_run", reason: this.refusal });
      },
      onTransferDir: (path) => { if (this.live()) this.transferDir = path; },
      onRecordingStarted: (_at, audit) => this.enqueueAudit(audit),
      onRecordingStopped: (_result, audit) => this.enqueueAudit(audit),
      onDirectoryListing: (listing) => this.enqueueAudit(listing.audit),
      onDirectoryListingRefused: (refusal) => this.enqueueAudit(refusal.audit),
      onUnknown: (error) => { if (this.live()) this.fail(new CoreError(this.phase, `Undecodable control message: ${error.message}`)); },
    };
    this.control = this.deps.makeControl?.(handlers) ?? new ControlClient((payload) => {
      this.check();
      if (!this.transport) throw new Error("Transport unavailable");
      this.transport.send(ChannelId.Control, payload);
    }, handlers);
    // Backstage stays a receive-only tap (never initiates a request or reply). The file-transfer client
    // may SEND, but only for an UPLOAD (push) this core initiates: with no onDownload handler and no
    // download Request ever made, the only outbound frames are an upload's Offer/Chunk/Done and a safe
    // refusal Error — never a download accept — so an unsolicited inbound Offer is still never admitted.
    this.backstage = new ChannelBackstageTransport(() => {}, (env) => {
      if (!this.closed) this.audit?.enqueueEnvelope(env as { ok: boolean; audit?: AuditEvent | null });
    });
    this.files = new FileTransferClient(
      (payload) => { if (!this.closed) this.transport?.send(ChannelId.FileTransfer, payload); },
      () => {},
      (event) => this.enqueueAudit(event),
    );
    const events: TransportEvents = {
      onChannelOpen: () => {
        if (!this.live() || this.channelOpen) return;
        this.channelOpen = true;
        this.channelResolve();
        if (this.policyRequired) {
          this.policyPending = true;
          try { this.control!.installSessionPolicy(this.policySigned); }
          catch (error) { this.fail(new CoreError("policy", this.message(error))); }
        }
      },
      onStateChange: (state) => {
        if (!this.closed && (state === "failed" || state === "disconnected")) this.fail(new CoreError(this.phase, `Transport ${state}`));
      },
      onError: (error) => { if (!this.closed) this.fail(new CoreError(this.phase, error.message)); },
      onMessage: (channel, payload) => {
        if (!this.live()) return;
        if (channel === ChannelId.Control) this.control!.handleMessage(payload);
        else if (channel === ChannelId.Backstage) this.backstage!.handleMessage(payload);
        else if (channel === ChannelId.FileTransfer) this.files!.handleMessage(payload);
      },
    };
    this.check();
    const config = { signaling: this.signaling as SignalingClient, iceServers: iceServersFor(brokered.signaling.url) };
    this.transport = this.deps.makeTransport?.(config, events) ?? new WebRTCTransport(config, events);
    // WebRTCTransport retains connectImpl's audio/video transceivers, with no media sink here.
    await this.wait((async () => {
      await this.transport!.connect(asDeviceId(device), brokered.signaling.ticket);
      this.check();
      await this.channelReady;
    })(), "channel", 20000);
    if (this.policyRequired && !this.policyApplied) await this.wait(this.policyReady, "policy", 10000);
  }

  private live(): boolean {
    if (this.closed) return false;
    try { this.check(); return true; } catch { return false; }
  }

  private enqueueAudit(event: unknown): void {
    if (!this.closed && event != null) this.audit?.enqueue(event as AuditEvent);
  }

  private auditError(error: Error): void {
    try {
      if (this.deps.onAuditError) this.deps.onAuditError(error);
      else console.error("Bulk session audit forwarding failed; the audit trail may be incomplete.", error);
    } catch { /* reporting must not prevent record release */ }
  }

  private flushPeriodically(): void {
    if (this.closed || !this.audit) return;
    this.schedule(() => {
      if (this.closed) return;
      void Promise.resolve().then(() => this.audit!.flush()).catch((error) => this.auditError(new Error(this.message(error))));
      this.flushPeriodically();
    }, 5000);
  }

  private agentError(message: string): void {
    if (!this.live()) return;
    // Neither Error nor ElevationDenied carries a run identifier; after dispatch neither proves non-execution.
    this.fail(new CoreError(this.policyPending ? "policy" : this.phase, message));
  }

  private finish(outcome: RunOutcome): void { this.settleRun?.(outcome); }

  private result(result: CommandResult): void {
    const stdout = outputHead(this.resultNote + result.stdout, 64 * 1024);
    const stderr = outputHead(result.stderr, 64 * 1024 - stdout.bytes);
    this.finish({ kind: "done", exitCode: result.exit_code, stdout: stdout.text, stderr: stderr.text,
      agentTruncated: result.truncated, consoleTruncated: stdout.truncated || stderr.truncated });
  }

  async run(task: BulkTask, isCancelled: () => boolean): Promise<RunOutcome> {
    if (this.used) throw new CoreError("authorization", "Only one run is permitted per core lifetime");
    this.used = true;
    let settled = false;
    const outcome = new Promise<RunOutcome>((resolve) => {
      this.settleRun = (value) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };
    });
    // The waiter exists before authorization and before any potentially reentrant send.
    const current = () => !settled && !this.closed && this.deps.authSession.isCurrent(this.epoch)
      && !this.signals.some((signal) => signal.aborted) && !isCancelled() && !this.refusal
      // A renewal installation whose acknowledgement has not arrived: its effective policy is unknown.
      && !this.policyPending;
    try {
      this.check();
      if (!this.ready) throw new CoreError("authorization", "Session is not ready");
      // Wait (bounded) for an in-flight renewal to be acknowledged BEFORE asking for authorization, so
      // the common case dispatches; the residual race (a renewal starting during authorization) is
      // caught by `current()` at the dispatch boundary and settles not_run, never a blind dispatch.
      if (this.policyPending) {
        await this.wait(new Promise<void>((settle) => this.policyWaiters.push(settle)), "policy", 10000);
      }
      // Command dispatch shared by the toolbox, ad-hoc and run-after-upload paths: authorize at the
      // control plane, then send an ordinary RunCommand. The dispatch guard and conservative
      // classification are shared.
      const authDeps = {
        api: this.deps.api,
        currentSessionId: () => current() ? this.id : null,
        isCurrent: current,
        sendRunCommand: (command: string, shell: CommandShell, asUser: boolean) => {
          // No await may intervene between this guard and the synchronous dispatch boundary.
          this.check();
          if (!current()) throw new CoreError("authorization", this.refusal ?? "Cancelled before dispatch");
          this.dispatched = true;
          // A throwing send may already have handed bytes to the transport: classify conservatively.
          this.control!.runCommand(command, shell, asUser);
        },
      };
      if (!current()) {
        this.finish({ kind: "not_run", reason: this.refusal ?? "Cancelled before dispatch" });
      } else if (task.kind === "upload") {
        // A file push: no control-plane grant (the agent's session dispatcher gates + audits the
        // transfer, ADR-008). Once bytes are handed to the client they cannot be recalled, so mark
        // dispatched before the await and classify a later failure conservatively.
        this.check();
        this.dispatched = true;
        const ack = await this.wait(this.files!.upload(task.name, task.bytes), "result", 5 * 60 * 1000);
        if (!ack.ok) {
          this.finish({ kind: "not_run", reason: ack.message });
        } else if (!task.run) {
          this.finish({ kind: "done", exitCode: 0, stdout: ack.message, stderr: "", agentTruncated: false, consoleTruncated: false });
        } else {
          // Push-and-run (docs/60 2a): the file landed; run it through the SAME audited command-run
          // grant as an ad-hoc command, as POWERSHELL source built by composeRunLine (never cmd: see
          // its comment). Every outcome from here carries the uploaded-as fact. Cancellation is
          // checked BEFORE the grant (review r1 M3) and again inside the dispatch guard; a cancel
          // here leaves the landed file on the machine, which the dialog states.
          const landed = ack.message;
          this.resultNote = `uploaded as ${landed}; `;
          const composed = composeRunLine(this.transferDir, landed, task.run.args);
          if (!composed.ok) {
            this.finish({ kind: "not_run", reason: this.resultNote + "run not started: " + composed.reason });
          } else if (!current()) {
            this.finish({ kind: "not_run", reason: this.resultNote + "run not started: " + (this.refusal ?? "cancelled") });
          } else {
            const grant = await this.wait(
              runAdhocCommand({ shell: "powershell", runAs: task.run.runAs, body: composed.line }, authDeps),
              "authorization", 15000);
            if (!grant.sent) {
              this.finish({ kind: "not_run", reason: this.resultNote + "run not started: " + (this.refusal ?? (grant.stale ? "cancelled or session changed" : grant.error)) });
            }
            if (grant.sent && !settled) await this.wait(outcome, "result", 5 * 60 * 1000);
          }
        }
      } else {
        const grant = await this.wait(
          task.kind === "toolbox"
            ? runToolboxScript(task.item, authDeps)
            : runAdhocCommand({ shell: task.shell, runAs: task.runAs, body: task.body }, authDeps),
          "authorization", 15000);
        if (!grant.sent) this.finish({ kind: "not_run", reason: this.refusal ?? (grant.stale ? "Cancelled or session changed before dispatch" : grant.error) });
        if (this.dispatched && !settled) await this.wait(outcome, "result", 5 * 60 * 1000);
      }
    } catch (error) {
      const reason = this.resultNote + this.message(error);
      this.finish({ kind: this.dispatched ? "unknown" : "not_run", reason });
      this.fail(error instanceof CoreError ? error : new CoreError(this.phase, reason));
    }
    return outcome;
  }

  private fail(error: CoreError): void {
    if (this.closed) return;
    this.failure = error;
    void this.close();
  }

  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    const error = this.failure ?? new CoreError("closed", "Session closed");
    this.stop(error);
    this.finish({ kind: this.dispatched ? "unknown" : "not_run", reason: error.message });
    // Assign before invoking resource methods: close callbacks may synchronously reenter close().
    this.closing = Promise.resolve().then(async () => {
      const safely = (fn: () => void) => { try { fn(); } catch { /* continue ordered teardown */ } };
      this.signals.forEach((signal) => signal.removeEventListener("abort", this.onAbort));
      for (const timer of this.timers) safely(() => this.clearTimer(timer));
      this.timers.clear();
      safely(() => this.renewer?.stop());
      safely(() => this.abort.abort());
      safely(() => this.transport?.close());
      safely(() => this.signaling?.close());
      safely(() => this.backstage?.close());
      safely(() => this.files?.dispose());
      let timer: number | undefined;
      try {
        if (this.audit) {
          await Promise.race([
            Promise.resolve().then(() => this.audit!.flush({ keepaliveFirstBatch: true })),
            new Promise<never>((_, reject) => {
              timer = this.setTimer(() => reject(new Error("Audit cleanup timed out; the audit trail may be incomplete")), 5000);
            }),
          ]);
        }
      } catch (failure) {
        this.auditError(new Error(this.message(failure)));
      } finally {
        if (timer !== undefined) safely(() => this.clearTimer(timer!));
        for (const id of this.ownedRecords) this.release(id);
      }
    });
    return this.closing;
  }
}
