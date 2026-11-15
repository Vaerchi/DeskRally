import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { BrokeredSessionCore, CoreError } from "./brokered_session_core";
import type { BrokeredSessionCoreDeps } from "./brokered_session_core";
import type { StartedSession, ToolboxItem, ToolboxRunGrant } from "./console_api";
import type { BulkTask } from "./bulk_run";
import type { ControlClient, CommandResult } from "./control";
import type { AuditEvent } from "./audit_forward";
import type { TransportEvents } from "./transport";
import { ChannelId } from "./protocol";

type Handlers = NonNullable<ConstructorParameters<typeof ControlClient>[1]>;

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

// Drain only promise continuations: advancing the clock here could hide a missing readiness gate.
async function drain() {
  for (let i = 0; i < 30; i++) await Promise.resolve();
}

const ITEM: ToolboxItem = {
  id: "tool-1", name: "Inventory", description: "", scope: "shared",
  shell: "powershell", run_as: "system", body: "untrusted cached body",
  body_sha256: "hash", version: 7, updated_at: "2026-01-01T00:00:00Z", mine: false,
};
const GRANT: ToolboxRunGrant = {
  request_id: "request-1", command: "authorized command", shell: "cmd", run_as: "user",
};
// The bulk task the core runs in most tests: a saved toolbox item.
const TOOLBOX_TASK: BulkTask = { kind: "toolbox", item: ITEM };
const RESULT: CommandResult = {
  exit_code: 13, stdout: "out", stderr: "err", truncated: false, timed_out: false,
};
const SIGNED = ' {"payload":"opaque signed policy","signature":"preserve whitespace"} ';
const EVENT: AuditEvent = {
  id: "event-1", seq: 0, session_id: "agent-chain", technician_id: "tech-1",
  machine_id: "machine-1", occurred_at_unix_ms: 123,
  action: { kind: "test" }, outcome: { result: "ok" }, prev_hash: "", hash: "hash-0",
  agent_pubkey: "key", agent_signature: "signature",
};

function fixture(policy = true) {
  const order: string[] = [];
  const started: StartedSession = {
    // Session metadata is irrelevant to the core; ownership keys exclusively on this id.
    session: { id: "session-1" } as StartedSession["session"],
    signaling: {
      url: "wss://broker.example/", device_id: "device-1", session_id: "session-1",
      ticket: { payload: "ticket", signature: "signature" } as unknown as NonNullable<StartedSession["signaling"]>["ticket"],
    },
    ...(policy ? { session_policy: { access: "control", signed: SIGNED } } : {}),
  };
  let handlers!: Handlers;
  let events!: TransportEvents;
  let authenticated = true;
  const api = {
    startBrokeredSession: vi.fn<BrokeredSessionCoreDeps["api"]["startBrokeredSession"]>().mockResolvedValue(started),
    endSession: vi.fn<BrokeredSessionCoreDeps["api"]["endSession"]>().mockImplementation(async () => {
      order.push("release"); return started.session;
    }),
    setSessionNote: vi.fn<BrokeredSessionCoreDeps["api"]["setSessionNote"]>().mockResolvedValue(started.session),
    requestToolboxRun: vi.fn<BrokeredSessionCoreDeps["api"]["requestToolboxRun"]>().mockResolvedValue(GRANT),
    requestCommandRun: vi.fn<BrokeredSessionCoreDeps["api"]["requestCommandRun"]>().mockResolvedValue(GRANT),
    renewSessionPolicy: vi.fn<BrokeredSessionCoreDeps["api"]["renewSessionPolicy"]>().mockResolvedValue({
      access: "control", signed: "renewed verbatim", lease_ttl_ms: 30000, expires_at_ms: 30000,
    }),
    ingestAudit: vi.fn<BrokeredSessionCoreDeps["api"]["ingestAudit"]>().mockImplementation(async (body) => {
      order.push("flush");
      return { accepted: body.events.length, tail_seq: body.events.length - 1, tail_hash: "tail" };
    }),
  };
  const signaling = {
    open: vi.fn(async () => {}), send: vi.fn(),
    close: vi.fn(() => { order.push("signaling"); }),
  };
  const control = {
    installSessionPolicy: vi.fn<(signed: string) => void>(),
    runCommand: vi.fn<ControlClient["runCommand"]>(), handleMessage: vi.fn(),
  };
  const transport = {
    kind: "webrtc" as const, state: "idle" as const,
    connect: vi.fn(async () => {}), send: vi.fn(), sendFrame: vi.fn(),
    close: vi.fn(() => { order.push("transport"); events.onStateChange?.("disconnected"); }),
  };
  const deps: BrokeredSessionCoreDeps = {
    api, authSession: { epoch: 4, isCurrent: (epoch) => authenticated && epoch === 4 },
    makeSignaling: vi.fn(() => signaling),
    makeControl: (value) => { handlers = value; return control; },
    makeTransport: vi.fn((_config, value) => { events = value; return transport; }),
    now: () => Date.now(),
    setTimer: (fn, ms) => setTimeout(fn, ms) as unknown as number,
    clearTimer: (handle) => clearTimeout(handle), onAuditError: vi.fn(),
  };
  const cores: BrokeredSessionCore[] = [];
  const open = (opts?: Parameters<typeof BrokeredSessionCore.open>[2]) => {
    const promise = BrokeredSessionCore.open("device-1", deps, opts);
    // Observe rejection immediately, including tests which deliberately hold a phase open.
    void promise.then((core) => { cores.push(core); }, () => {});
    return promise;
  };
  const ack = (viewOnly = false, requireRecording = false, allowRecording = true) => {
    handlers.onSessionPolicyInstalled?.("control", viewOnly, allowRecording, requireRecording, 0);
  };
  const ready = async () => {
    const promise = open();
    await drain();
    events.onChannelOpen?.();
    if (policy) ack();
    return await promise;
  };
  return {
    api, deps, started, signaling, control, transport, order, cores, open, ready, ack,
    get handlers() { return handlers; }, get events() { return events; },
    logout: () => { authenticated = false; },
  };
}

type Fixture = ReturnType<typeof fixture>;
let fixtures: Fixture[];
function setup(policy = true) {
  const value = fixture(policy);
  fixtures.push(value);
  return value;
}

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(0); fixtures = []; });
afterEach(async () => {
  const closing = fixtures.flatMap((f) => f.cores.map((core) => core.close()));
  await drain();
  await vi.advanceTimersByTimeAsync(5000);
  await Promise.all(closing);
  vi.useRealTimers();
});

describe("BrokeredSessionCore readiness and ownership", () => {
  it("uses broker coordinates and ticket, installs policy verbatim only after channel open, and waits for its acknowledgement", async () => {
    const f = setup();
    const opening = f.open({ note: "Bulk run b: Inventory v7" });
    const resolved = vi.fn();
    void opening.then(resolved);
    await drain();
    expect(f.deps.makeSignaling).toHaveBeenCalledWith("wss://broker.example/");
    expect(f.api.setSessionNote).toHaveBeenCalledWith("session-1", "Bulk run b: Inventory v7");
    expect(f.signaling.send).toHaveBeenCalledWith(expect.objectContaining({
      type: "register_agent", pubkey: "ed25519:browser-controller", nat: "unknown", enrollment_token: null,
    }));
    expect(f.transport.connect).toHaveBeenCalledWith("device-1", f.started.signaling!.ticket);
    expect(f.deps.makeTransport).toHaveBeenCalledWith(expect.objectContaining({ iceServers: [] }), expect.any(Object));
    f.events.onStateChange?.("connected");
    f.ack(); // An unsolicited acknowledgement cannot satisfy installation readiness.
    await drain();
    expect(resolved).not.toHaveBeenCalled();
    expect(f.control.installSessionPolicy).not.toHaveBeenCalled();
    f.events.onChannelOpen?.();
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenCalledExactlyOnceWith(SIGNED);
    expect(resolved).not.toHaveBeenCalled();
    f.ack();
    const core = await opening;
    expect(core.sessionId).toBe("session-1");
    expect(resolved).toHaveBeenCalledOnce();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("a refused or hung session note never fails the open (the note is descriptive only)", async () => {
    for (const mode of ["reject", "hang"] as const) {
      const f = setup();
      f.api.setSessionNote.mockImplementation(() =>
        mode === "reject" ? Promise.reject(new Error("forbidden")) : new Promise(() => {}));
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const opening = f.open({ note: "Bulk run b: Inventory v7" });
      await drain();
      if (mode === "hang") await vi.advanceTimersByTimeAsync(15000);
      f.events.onStateChange?.("connected");
      f.events.onChannelOpen?.();
      await drain();
      f.ack();
      const core = await opening;
      expect(core.sessionId).toBe("session-1");
      expect(warn).toHaveBeenCalled();
      warn.mockRestore();
    }
  });

  it("requires channel open even without a minted policy", async () => {
    const f = setup(false);
    const opening = f.open();
    const resolved = vi.fn();
    void opening.then(resolved);
    await drain();
    f.events.onStateChange?.("connected");
    await drain();
    expect(resolved).not.toHaveBeenCalled();
    f.events.onChannelOpen?.();
    await opening;
    expect(f.control.installSessionPolicy).not.toHaveBeenCalled();
  });

  it.each([[true, false], [false, true]])("refuses effective viewOnly=%s requireRecording=%s without authorization or dispatch", async (viewOnly, requireRecording) => {
    const f = setup();
    const opening = f.open();
    await drain();
    f.events.onChannelOpen?.();
    f.ack(viewOnly, requireRecording);
    const core = await opening;
    expect(await core.run(TOOLBOX_TASK, () => false)).toEqual({ kind: "not_run", reason: expect.stringMatching(/interactive session/i) });
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("allows execution when recording is forbidden but not required", async () => {
    const f = setup();
    const opening = f.open();
    await drain(); f.events.onChannelOpen?.(); f.ack(false, false, false);
    const core = await opening;
    f.control.runCommand.mockImplementation(() => f.handlers.onCommandResult?.(RESULT));
    expect(await core.run(TOOLBOX_TASK, () => false)).toMatchObject({ kind: "done", exitCode: 13 });
  });

  it("releases a late record after the acquisition deadline and never creates signaling", async () => {
    const f = setup();
    const start = deferred<StartedSession>();
    f.api.startBrokeredSession.mockReturnValue(start.promise);
    const opening = f.open();
    const rejected = expect(opening).rejects.toMatchObject({ name: "CoreError", phase: "acquire" });
    await vi.advanceTimersByTimeAsync(15000);
    await rejected;
    expect(f.api.endSession).not.toHaveBeenCalled();
    expect(f.api.startBrokeredSession.mock.calls[0][1]?.aborted).toBe(true);
    start.resolve(f.started);
    await drain();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.deps.makeSignaling).not.toHaveBeenCalled();
  });

  it("releases a created record when acquisition has no signaling envelope", async () => {
    const f = setup();
    f.api.startBrokeredSession.mockResolvedValue({ session: f.started.session });
    await expect(f.open()).rejects.toBeInstanceOf(CoreError);
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.deps.makeSignaling).not.toHaveBeenCalled();
  });

  it("aborts acquisition and releases its eventual record", async () => {
    const f = setup();
    const start = deferred<StartedSession>();
    f.api.startBrokeredSession.mockReturnValue(start.promise);
    const abort = new AbortController();
    const opening = f.open({ signal: abort.signal });
    const rejected = expect(opening).rejects.toMatchObject({ phase: "acquire", message: "Cancelled" });
    abort.abort();
    await rejected;
    expect(f.api.startBrokeredSession.mock.calls[0][1]?.aborted).toBe(true);
    start.resolve(f.started);
    await drain();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.deps.makeSignaling).not.toHaveBeenCalled();
  });

  it.each(["signaling", "channel", "policy"] as const)("bounds the %s phase and releases the record", async (phase) => {
    const f = setup();
    if (phase === "signaling") f.signaling.open.mockReturnValue(new Promise<void>(() => {}));
    const opening = f.open();
    const rejected = expect(opening).rejects.toMatchObject({ name: "CoreError", phase });
    await drain();
    if (phase === "policy") { f.events.onChannelOpen?.(); await drain(); }
    await vi.advanceTimersByTimeAsync(phase === "policy" ? 10000 : 20000);
    await rejected;
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.signaling.close).toHaveBeenCalledOnce();
  });

  it("rejects a policy installation error before readiness", async () => {
    const f = setup();
    const opening = f.open();
    const rejected = expect(opening).rejects.toMatchObject({ phase: "policy", message: "policy floor refused" });
    await drain(); f.events.onChannelOpen?.();
    f.handlers.onError?.("policy floor refused");
    await rejected;
    expect(f.control.runCommand).not.toHaveBeenCalled();
    expect(f.api.endSession).toHaveBeenCalledOnce();
  });
});

describe("BrokeredSessionCore dispatch boundary and outcomes", () => {
  it("authorizes the held session and version, arms the waiter before synchronous dispatch, and settles once", async () => {
    const f = setup();
    const core = await f.ready();
    f.control.runCommand.mockImplementation(() => {
      f.handlers.onCommandResult?.(RESULT);
      f.handlers.onCommandResult?.({ ...RESULT, exit_code: 99 });
    });
    expect(await core.run(TOOLBOX_TASK, () => false)).toEqual({
      kind: "done", exitCode: 13, stdout: "out", stderr: "err", agentTruncated: false, consoleTruncated: false,
    });
    expect(f.api.requestToolboxRun).toHaveBeenCalledExactlyOnceWith("tool-1", "session-1", 7);
    expect(f.control.runCommand).toHaveBeenCalledExactlyOnceWith("authorized command", "Cmd", true);
    await expect(core.run(TOOLBOX_TASK, () => false)).rejects.toMatchObject({ phase: "authorization" });
    expect(f.control.runCommand).toHaveBeenCalledOnce();
  });

  it("does not authorize or dispatch an already cancelled run", async () => {
    const f = setup(); const core = await f.ready();
    expect(await core.run(TOOLBOX_TASK, () => true)).toMatchObject({ kind: "not_run" });
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("an ad-hoc task authorizes via the command-run grant and dispatches the returned command", async () => {
    const f = setup();
    const core = await f.ready();
    f.control.runCommand.mockImplementation(() => f.handlers.onCommandResult?.(RESULT));
    const task: BulkTask = { kind: "adhoc", name: "a command", shell: "cmd", runAs: "user", body: "ipconfig /all" };
    expect(await core.run(task, () => false)).toMatchObject({ kind: "done", exitCode: 13 });
    // The ad-hoc path uses the command-run grant (not the toolbox one) with the session id and the
    // composed shell/run_as/body, then sends exactly the authoritative command the grant returned.
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.api.requestCommandRun).toHaveBeenCalledExactlyOnceWith("session-1", "cmd", "user", "ipconfig /all");
    expect(f.control.runCommand).toHaveBeenCalledExactlyOnceWith("authorized command", "Cmd", true);
  });

  it("does not dispatch when cancellation occurs during authorization", async () => {
    const f = setup(); const core = await f.ready();
    const grant = deferred<ToolboxRunGrant>();
    f.api.requestToolboxRun.mockReturnValue(grant.promise);
    let cancelled = false;
    const running = core.run(TOOLBOX_TASK, () => cancelled);
    cancelled = true;
    grant.resolve(GRANT);
    expect(await running).toMatchObject({ kind: "not_run" });
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("checks cancellation again immediately before the synchronous send", async () => {
    const f = setup(); const core = await f.ready();
    let checks = 0;
    // runToolboxScript checks isCurrent, then currentSessionId; the next check is the send guard.
    const running = core.run(TOOLBOX_TASK, () => ++checks >= 5);
    expect(await running).toMatchObject({ kind: "not_run" });
    expect(f.api.requestToolboxRun).toHaveBeenCalledOnce();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it.each(["close", "logout"] as const)("ignores authorization completing after %s", async (boundary) => {
    const f = setup(); const core = await f.ready();
    const grant = deferred<ToolboxRunGrant>();
    f.api.requestToolboxRun.mockReturnValue(grant.promise);
    const running = core.run(TOOLBOX_TASK, () => false);
    if (boundary === "close") await core.close(); else f.logout();
    grant.resolve(GRANT);
    expect(await running).toMatchObject({ kind: "not_run" });
    await core.close();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
  });

  it("does not dispatch a grant arriving after the authorization deadline", async () => {
    const f = setup(); const core = await f.ready();
    const grant = deferred<ToolboxRunGrant>(); f.api.requestToolboxRun.mockReturnValue(grant.promise);
    const running = core.run(TOOLBOX_TASK, () => false);
    await vi.advanceTimersByTimeAsync(15000);
    expect(await running).toMatchObject({ kind: "not_run", reason: expect.stringContaining("authorization") });
    grant.resolve(GRANT); await drain(); await core.close();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    expect(f.api.endSession).toHaveBeenCalledOnce();
  });

  it("classifies authorization refusal as not_run", async () => {
    const f = setup(); const core = await f.ready();
    f.api.requestToolboxRun.mockRejectedValue(new Error("version changed"));
    expect(await core.run(TOOLBOX_TASK, () => false)).toEqual({ kind: "not_run", reason: "version changed" });
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it.each(["disconnect", "error", "elevation", "session ended", "send throws"])("returns unknown after dispatch on %s", async (trigger) => {
    const f = setup(); const core = await f.ready();
    if (trigger === "send throws") f.control.runCommand.mockImplementation(() => { throw new Error("send uncertain"); });
    const running = core.run(TOOLBOX_TASK, () => false);
    await drain();
    expect(f.control.runCommand).toHaveBeenCalledOnce();
    if (trigger === "disconnect") f.events.onStateChange?.("disconnected");
    if (trigger === "error") f.handlers.onError?.("unrelated agent error");
    if (trigger === "elevation") f.handlers.onElevationDenied?.("unattributed refusal");
    if (trigger === "session ended") f.handlers.onError?.("session ended: lease expired");
    expect(await running).toMatchObject({ kind: "unknown", reason: expect.any(String) });
    f.handlers.onCommandResult?.(RESULT);
    await core.close();
    expect(await running).toMatchObject({ kind: "unknown" });
    expect(f.api.endSession).toHaveBeenCalledOnce();
  });

  it("returns unknown on the result deadline and ignores a late result", async () => {
    const f = setup(); const core = await f.ready();
    const running = core.run(TOOLBOX_TASK, () => false);
    await drain();
    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);
    expect(await running).toMatchObject({ kind: "unknown", reason: expect.stringContaining("result") });
    f.handlers.onCommandResult?.(RESULT);
    await core.close();
    expect(await running).toMatchObject({ kind: "unknown" });
    expect(f.api.endSession).toHaveBeenCalledOnce();
  });

  it("keeps dispatched work alive when its cancellation signal is aborted", async () => {
    const f = setup(); const abort = new AbortController(); f.deps.signal = abort.signal;
    const core = await f.ready();
    let cancelled = false;
    const running = core.run(TOOLBOX_TASK, () => cancelled);
    await drain();
    cancelled = true; abort.abort(); await drain();
    expect(f.transport.close).not.toHaveBeenCalled();
    f.handlers.onCommandResult?.(RESULT);
    expect(await running).toMatchObject({ kind: "done", exitCode: 13 });
  });

  it("retains UTF-8 heads within a shared 64 KiB row budget and preserves both truncation flags", async () => {
    const f = setup(); const core = await f.ready();
    const stdout = "a".repeat(65533) + "🙂tail";
    f.control.runCommand.mockImplementation(() => f.handlers.onCommandResult?.({
      ...RESULT, stdout, stderr: "éé", truncated: true,
    }));
    const result = await core.run(TOOLBOX_TASK, () => false);
    expect(result).toEqual({
      kind: "done", exitCode: 13, stdout: "a".repeat(65533), stderr: "é",
      agentTruncated: true, consoleTruncated: true,
    });
    if (result.kind !== "done") throw new Error("Expected captured output");
    expect(new TextEncoder().encode(result.stdout + result.stderr).length).toBe(65535);
  });

  it("does not mark an exact 64 KiB head as console-truncated", async () => {
    const f = setup(); const core = await f.ready();
    f.control.runCommand.mockImplementation(() => f.handlers.onCommandResult?.({
      ...RESULT, stdout: "é".repeat(32768), stderr: "", truncated: true,
    }));
    expect(await core.run(TOOLBOX_TASK, () => false)).toMatchObject({ kind: "done", agentTruncated: true, consoleTruncated: false });
  });

  it("waits for an executable renewal acknowledgement before authorization and dispatch", async () => {
    const f = setup(); const core = await f.ready();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenCalledTimes(2);
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    const settled = vi.fn();
    const running = core.run(TOOLBOX_TASK, () => false);
    void running.then(settled);
    await drain();
    expect(settled).not.toHaveBeenCalled();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    f.ack();
    await drain();
    expect(f.api.requestToolboxRun).toHaveBeenCalledExactlyOnceWith("tool-1", "session-1", 7);
    expect(f.control.runCommand).toHaveBeenCalledExactlyOnceWith("authorized command", "Cmd", true);
    expect(settled).not.toHaveBeenCalled();
    f.handlers.onCommandResult?.(RESULT);
    expect(await running).toEqual({
      kind: "done", exitCode: 13, stdout: "out", stderr: "err", agentTruncated: false, consoleTruncated: false,
    });
  });

  it.each([[true, false], [false, true]])("refuses a pending renewal acknowledged with viewOnly=%s requireRecording=%s", async (viewOnly, requireRecording) => {
    const f = setup(); const core = await f.ready();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    const running = core.run(TOOLBOX_TASK, () => false);
    await drain();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    f.ack(viewOnly, requireRecording);
    expect(await running).toEqual({
      kind: "not_run", reason: expect.stringMatching(viewOnly ? /view-only/i : /recording is required/i),
    });
    await drain();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("bounds a pending renewal acknowledgement at ten seconds and releases the record", async () => {
    const f = setup(); const core = await f.ready();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    const settled = vi.fn();
    const running = core.run(TOOLBOX_TASK, () => false);
    void running.then(settled);
    await vi.advanceTimersByTimeAsync(9999);
    expect(settled).not.toHaveBeenCalled();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(await running).toEqual({ kind: "not_run", reason: expect.stringMatching(/policy.*timed out/i) });
    await core.close();
    f.ack();
    await drain();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
  });

  it("does not dispatch when renewal installation starts during authorization and its acknowledgement is still pending", async () => {
    const f = setup(); const core = await f.ready();
    const grant = deferred<ToolboxRunGrant>();
    f.api.requestToolboxRun.mockReturnValue(grant.promise);
    const running = core.run(TOOLBOX_TASK, () => false);
    await drain();
    expect(f.api.requestToolboxRun).toHaveBeenCalledOnce();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenCalledTimes(2);
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    grant.resolve(GRANT);
    expect(await running).toMatchObject({ kind: "not_run" });
    expect(f.control.runCommand).not.toHaveBeenCalled();
    f.ack();
    await drain();
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it.each(["cancel", "close"] as const)("does not dispatch after %s while waiting for a renewal acknowledgement", async (boundary) => {
    const f = setup();
    const abort = new AbortController();
    f.deps.signal = abort.signal;
    const core = await f.ready();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    const settled = vi.fn();
    const running = core.run(TOOLBOX_TASK, () => false);
    void running.then(settled);
    await drain();
    expect(settled).not.toHaveBeenCalled();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    if (boundary === "cancel") abort.abort(); else await core.close();
    expect(await running).toEqual({
      kind: "not_run", reason: boundary === "cancel" ? "Cancelled" : "Session closed",
    });
    await core.close();
    f.ack();
    await drain();
    expect(f.api.requestToolboxRun).not.toHaveBeenCalled();
    expect(f.control.runCommand).not.toHaveBeenCalled();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
  });
});

describe("BrokeredSessionCore teardown and audit", () => {
  it("renews only on the agent request, forwards renewal verbatim, and tears down on refusal", async () => {
    const f = setup(); const core = await f.ready();
    expect(f.api.renewSessionPolicy).not.toHaveBeenCalled();
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    expect(f.api.renewSessionPolicy).toHaveBeenCalledOnce();
    expect(f.api.renewSessionPolicy.mock.calls[0][0]).toBe("session-1");
    expect(f.control.installSessionPolicy).toHaveBeenLastCalledWith("renewed verbatim");
    f.ack();
    f.api.renewSessionPolicy.mockRejectedValue({ status: 403, message: "revoked" });
    await vi.advanceTimersByTimeAsync(10000);
    await core.close();
    expect(f.transport.close).toHaveBeenCalledOnce();
    expect(f.signaling.close).toHaveBeenCalledOnce();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    const calls = f.api.renewSessionPolicy.mock.calls.length;
    f.handlers.onSessionLeaseRequired?.(30000);
    await vi.advanceTimersByTimeAsync(30000);
    expect(f.api.renewSessionPolicy).toHaveBeenCalledTimes(calls);
  });

  it("refuses a stricter effective renewal policy before dispatch", async () => {
    const f = setup(); const core = await f.ready();
    f.handlers.onSessionLeaseRequired?.(30000); await drain();
    f.ack(false, true);
    expect(await core.run(TOOLBOX_TASK, () => false)).toMatchObject({ kind: "not_run" });
    expect(f.control.runCommand).not.toHaveBeenCalled();
  });

  it("tears down immediately on transport failed", async () => {
    const f = setup(); const core = await f.ready();
    f.events.onStateChange?.("failed");
    await drain();
    expect(f.transport.close).toHaveBeenCalledOnce();
    expect(f.signaling.close).toHaveBeenCalledOnce();
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(await core.run(TOOLBOX_TASK, () => false)).toMatchObject({ kind: "not_run" });
  });

  it("polls logout while idle and clears all lifecycle timers on close", async () => {
    const f = setup(); await f.ready();
    f.logout();
    await vi.advanceTimersByTimeAsync(1000);
    expect(f.transport.close).toHaveBeenCalledOnce();
    expect(f.api.endSession).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("stops an in-flight renewal and suppresses its late install", async () => {
    const f = setup(); const core = await f.ready();
    const lease = deferred<Awaited<ReturnType<BrokeredSessionCoreDeps["api"]["renewSessionPolicy"]>>>();
    f.api.renewSessionPolicy.mockReturnValue(lease.promise);
    f.handlers.onSessionLeaseRequired?.(30000);
    await drain();
    const signal = f.api.renewSessionPolicy.mock.calls[0][1];
    await core.close();
    expect(signal?.aborted).toBe(true);
    lease.resolve({ access: "control", signed: "late", lease_ttl_ms: 30000, expires_at_ms: 30000 });
    await drain();
    expect(f.control.installSessionPolicy).toHaveBeenCalledExactlyOnceWith(SIGNED);
  });

  it("adopts the first agent audit chain, forwards unsolicited events unchanged, and periodically flushes without sending requests", async () => {
    const f = setup(); const core = await f.ready();
    const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    f.events.onMessage?.(ChannelId.Backstage, bytes({ ok: true, audit: EVENT }));
    const second = { ...EVENT, id: "event-2", seq: 1, prev_hash: EVENT.hash, hash: "hash-1" };
    f.events.onMessage?.(ChannelId.FileTransfer, bytes({ t: "Audit", c: { event: second } }));
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.api.ingestAudit).toHaveBeenCalledExactlyOnceWith({ session_id: "agent-chain", events: [EVENT, second] }, undefined);
    expect(f.transport.send).not.toHaveBeenCalled();
    const third = { ...EVENT, id: "event-3", seq: 2, prev_hash: second.hash, hash: "hash-2" };
    f.handlers.onRecordingStarted?.(123, third as unknown as Record<string, unknown>);
    await core.close();
    expect(f.api.ingestAudit).toHaveBeenLastCalledWith({ session_id: "agent-chain", events: [third] }, { keepalive: true });
    expect(f.order).toEqual(["flush", "transport", "signaling", "flush", "release"]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(["throws", "rejects", "hangs"] as const)("close is idempotent and releases the record when audit delivery %s", async (failure) => {
    const f = setup(); const core = await f.ready();
    f.handlers.onRecordingStarted?.(123, EVENT as unknown as Record<string, unknown>);
    if (failure === "throws") f.api.ingestAudit.mockImplementation(() => { throw new Error("audit throw"); });
    if (failure === "rejects") f.api.ingestAudit.mockRejectedValue(new Error("audit rejected"));
    if (failure === "hangs") f.api.ingestAudit.mockReturnValue(new Promise(() => {}));
    const first = core.close();
    expect(core.close()).toBe(first);
    await drain();
    expect(f.transport.close).toHaveBeenCalledOnce();
    expect(f.signaling.close).toHaveBeenCalledOnce();
    if (failure === "hangs") {
      expect(f.api.endSession).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(4999);
      expect(f.api.endSession).not.toHaveBeenCalled();
      await vi.advanceTimersByTimeAsync(1);
    }
    await first;
    await core.close();
    expect(f.deps.onAuditError).toHaveBeenCalledWith(expect.any(Error));
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.order).toEqual(["transport", "signaling", "release"]);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("surfaces periodic audit failures and still releases on close", async () => {
    const f = setup(); const core = await f.ready();
    f.handlers.onRecordingStarted?.(123, EVENT as unknown as Record<string, unknown>);
    f.api.ingestAudit.mockRejectedValue(new Error("audit unavailable"));
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.deps.onAuditError).toHaveBeenCalledWith(expect.objectContaining({ message: "audit unavailable" }));
    await core.close();
    expect(f.api.endSession).toHaveBeenCalledOnce();
  });

  it("bounds close while a periodic audit flush is pending without duplicating pre-close events", async () => {
    const f = setup(); const core = await f.ready();
    const delivery = deferred<Awaited<ReturnType<BrokeredSessionCoreDeps["api"]["ingestAudit"]>>>();
    f.api.ingestAudit.mockReturnValueOnce(delivery.promise);
    f.handlers.onRecordingStarted?.(123, EVENT as unknown as Record<string, unknown>);
    await vi.advanceTimersByTimeAsync(5000);
    expect(f.api.ingestAudit).toHaveBeenCalledExactlyOnceWith({ session_id: "agent-chain", events: [EVENT] }, undefined);
    const second = { ...EVENT, id: "event-2", seq: 1, prev_hash: EVENT.hash, hash: "hash-1" };
    f.handlers.onRecordingStarted?.(124, second as unknown as Record<string, unknown>);
    const closed = vi.fn();
    const closing = core.close();
    void closing.then(closed);
    await drain();
    expect(f.api.ingestAudit).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(4999);
    expect(closed).not.toHaveBeenCalled();
    expect(f.api.endSession).not.toHaveBeenCalled();
    expect(f.api.ingestAudit).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(1);
    await closing;
    expect(closed).toHaveBeenCalledOnce();
    expect(f.deps.onAuditError).toHaveBeenCalledWith(expect.objectContaining({ message: expect.stringMatching(/audit cleanup timed out/i) }));
    expect(f.api.endSession).toHaveBeenCalledExactlyOnceWith("session-1");
    expect(f.api.ingestAudit).toHaveBeenCalledOnce();
    delivery.resolve({ accepted: 1, tail_seq: 0, tail_hash: EVENT.hash });
    await drain();
    expect(f.api.ingestAudit).toHaveBeenCalledTimes(2);
    expect(f.api.ingestAudit).toHaveBeenNthCalledWith(2, { session_id: "agent-chain", events: [second] }, undefined);
    expect(f.api.ingestAudit.mock.calls.flatMap(([body]) => body.events)).toEqual([EVENT, second]);
    await core.close();
    await vi.advanceTimersByTimeAsync(10000);
    expect(f.api.ingestAudit).toHaveBeenCalledTimes(2);
    expect(f.api.endSession).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
  });
});
