import type { ToolboxItem, ToolboxRunAs, ToolboxShell } from "./console_api";
import type { RunOutcome } from "./brokered_session_core";
import type { BulkRow, BulkRowState } from "./bulk_types";

export type { BulkRow, BulkRowOutcome, BulkRowState } from "./bulk_types";

/**
 * What a bulk run executes on each machine: either a saved toolbox item (authorized + audited by item
 * identity) or an ad-hoc command the operator typed (authorized + audited by the command-run grant).
 * Both run as an ordinary RunCommand on the agent; only the control-plane authorization differs.
 */
export type BulkTask =
  | { kind: "toolbox"; item: ToolboxItem }
  | { kind: "adhoc"; name: string; shell: ToolboxShell; runAs: ToolboxRunAs; body: string }
  | {
      kind: "upload";
      name: string;
      bytes: Uint8Array;
      /** Push-and-run (docs/60 §2a): after the file lands, run it via the audited command-run grant. */
      run?: { args: string; runAs: ToolboxRunAs };
    };

// ---------------------------------------------------------------------------------------------
// Push-and-run command composition (docs/60 §2a, review r1). PURE so the refusal rules are
// unit-tested. The run step deliberately avoids cmd.exe — `%VAR%` expands even inside cmd double
// quotes, and `cmd /C` quote-stripping mishandles a leading quoted path containing parentheses, which
// the agent's own " (2)" dedup suffix produces. Instead the body is POWERSHELL source,
//   & '<dir>\<landed>' <args>; exit $LASTEXITCODE
// submitted to the command-run grant with shell=powershell: the grant wraps it in the base64
// scriptblock transform toolbox scripts already use, so no quoting hazard ever meets a parser. The
// path is a single-quoted PS literal, and anything the literal cannot hold VERBATIM is REFUSED, never
// escaped: the refusal names the reason and the upload itself still stands. The landed name and the
// directory come from the AGENT (its ack / its advertised TransferDir) and execute on that same agent
// — not a privilege boundary, but the line is CENTRALLY AUDITED, so it must read unambiguously.
// ---------------------------------------------------------------------------------------------

/** Allowed in the directory segments and the landed filename: conservative literal-safe characters.
 *  Excluded on purpose: both quote kinds, backtick, $, %, !, &, |, <, >, ^, ;, path separators and
 *  `:` (segments only ever name ONE component), and all control characters. The agent's " (N)"
 *  dedup suffix stays representable. */
const RUN_SEGMENT_RE = /^[A-Za-z0-9 ._()\-\[\]{}+,=@~#]+$/;

/** A segment that is only dots/spaces (".", "..", ". .") can alias another path component. */
const DOT_ONLY_RE = /^[. ]+$/;

function runSegmentOK(seg: string): boolean {
  return seg !== "" && RUN_SEGMENT_RE.test(seg) && !DOT_ONLY_RE.test(seg);
}

export function composeRunLine(
  transferDir: string | undefined,
  landed: string,
  args: string,
): { ok: true; line: string } | { ok: false; reason: string } {
  if (!transferDir) return { ok: false, reason: "the agent did not advertise a transfer folder" };
  const dirOk = /^[A-Za-z]:\\/.test(transferDir)
    && !transferDir.endsWith("\\")
    && transferDir.slice(3).split("\\").every(runSegmentOK);
  if (!dirOk) return { ok: false, reason: "the advertised transfer folder cannot be written as a safe literal path" };
  if (!runSegmentOK(landed)) {
    return { ok: false, reason: "the landed filename cannot be written as a safe literal path (rename the file simply and retry)" };
  }
  // Args are RAW POWERSHELL ARGUMENT SYNTAX — the operator's own text, centrally audited verbatim,
  // the same trust as an ad-hoc command. Only characters that would break the one-line audited form
  // are refused.
  if (/[\r\n\u0000]/.test(args)) return { ok: false, reason: "arguments must be a single line" };
  const trimmed = args.trim();
  const line = `& '${transferDir}\\${landed}'` + (trimmed !== "" ? " " + trimmed : "") + "; exit $LASTEXITCODE";
  return { ok: true, line };
}

/** Structural seam: importing this scheduler never loads the transport implementation. */
export interface BulkCore {
  run(task: BulkTask, isCancelled: () => boolean): Promise<RunOutcome>;
  close(): Promise<void>;
}

export type OpenBulkCore = (device: string, signal: AbortSignal) => Promise<BulkCore>;

export interface BulkRunOptions {
  onChange?: (rows: readonly BulkRow[]) => void;
  /** UTF-8 bytes retained across all rows; defaults to 2 MiB. */
  aggregateBudgetBytes?: number;
}

export interface BulkRun {
  /** Detached snapshots: callers cannot mutate scheduler state. */
  readonly rows: readonly BulkRow[];
  /** Resolves only after every opened core's close() has settled. */
  readonly done: Promise<readonly BulkRow[]>;
  cancel(): void;
}

function head(value: string, budget: number): { text: string; bytes: number; truncated: boolean } {
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

/**
 * FIFO, at most three live sessions, and no retries. The caller supplies only eligible
 * unattended device ids from the console machine list; display labels can be joined by id.
 * "running" includes authorization: only the core knows the synchronous dispatch boundary.
 */
export function runBulk(
  devices: readonly string[],
  task: BulkTask,
  openCore: OpenBulkCore,
  opts: BulkRunOptions = {},
): BulkRun {
  const unique = [...new Set(devices)];
  if (unique.length > 25) throw new Error("Bulk runs support at most 25 unique devices");
  const budget = opts.aggregateBudgetBytes ?? 2 * 1024 * 1024;
  if (!Number.isSafeInteger(budget) || budget < 0) throw new Error("Invalid aggregate output budget");
  // The selected task must not change underneath queued rows (a toolbox item's version in particular).
  const selected: BulkTask = task.kind === "toolbox" ? { kind: "toolbox", item: { ...task.item } } : { ...task };
  const rows: BulkRow[] = unique.map((deviceId) => ({ deviceId, machineName: deviceId, state: "queued" }));
  const aborts = new Set<AbortController>();
  let cancelled = false;
  let next = 0;
  let retained = 0;
  const snapshot = (): BulkRow[] => rows.map((row) => ({
    ...row, ...(row.outcome ? { outcome: { ...row.outcome } } : {}),
  }));
  const notify = (): void => {
    // An observer must never strand a session or stop the remaining queue.
    try { opts.onChange?.(snapshot()); } catch { /* consumer failure */ }
  };
  const terminal = (state: BulkRowState): boolean => state !== "queued" && state !== "connecting" && state !== "running";
  const settle = (row: BulkRow, state: BulkRowState, outcome: BulkRow["outcome"]): void => {
    if (terminal(row.state)) return;
    row.state = state;
    row.outcome = outcome;
    notify();
  };
  const message = (error: unknown): string => error instanceof Error ? error.message : String(error);

  const worker = async (): Promise<void> => {
    while (next < rows.length) {
      const row = rows[next++];
      if (terminal(row.state)) continue;
      if (cancelled) {
        settle(row, "cancelled", { reason: "Cancelled before dispatch" });
        continue;
      }
      const abort = new AbortController();
      aborts.add(abort);
      let core: BulkCore | undefined;
      let runStarted = false;
      row.state = "connecting";
      notify();
      try {
        if (cancelled) {
          settle(row, "cancelled", { reason: "Cancelled before dispatch" });
          continue;
        }
        core = await openCore(row.deviceId, abort.signal);
        // Also handles factories that resolve successfully after ignoring an abort.
        if (cancelled) {
          settle(row, "cancelled", { reason: "Cancelled before dispatch" });
          continue;
        }
        row.state = "running";
        notify();
        if (cancelled) {
          settle(row, "cancelled", { reason: "Cancelled before dispatch" });
          continue;
        }
        runStarted = true;
        const result = await core.run(selected, () => cancelled);
        if (result.kind === "done") {
          const limit = Math.min(64 * 1024, budget - retained);
          const stdout = head(result.stdout, limit);
          const stderr = head(result.stderr, limit - stdout.bytes);
          retained += stdout.bytes + stderr.bytes;
          settle(row, "done", {
            exitCode: result.exitCode,
            outputHead: stdout.text + stderr.text,
            agentTruncated: result.agentTruncated,
            consoleTruncated: result.consoleTruncated || stdout.truncated || stderr.truncated,
          });
        } else {
          settle(row, result.kind === "unknown" ? "unknown" : cancelled ? "cancelled" : "failed", { reason: result.reason });
        }
      } catch (error) {
        // An unexpected run rejection provides no proof that dispatch did not occur.
        settle(row, runStarted ? "unknown" : cancelled ? "cancelled" : "failed", { reason: message(error) });
      } finally {
        // Keep the concurrency slot through cleanup, including cancelled late opens.
        if (core) {
          try { await core.close(); } catch { /* cleanup failure cannot erase a command outcome */ }
        }
        aborts.delete(abort);
      }
    }
  };

  const handle: BulkRun = {
    get rows() { return snapshot(); },
    // Start on a microtask so onChange can safely refer to the returned handle.
    done: Promise.resolve().then(async () => {
      notify();
      await Promise.all(Array.from({ length: Math.min(3, rows.length) }, () => worker()));
      return snapshot();
    }),
    cancel() {
      if (cancelled) return;
      cancelled = true;
      for (const row of rows) {
        if (row.state === "queued") {
          row.state = "cancelled";
          row.outcome = { reason: "Cancelled before dispatch" };
        }
      }
      // The core ignores abort after dispatch, but closes acquisition/authorization promptly.
      // Never call close() here: doing so would abandon an already-dispatched result.
      for (const abort of aborts) abort.abort();
      notify();
    },
  };
  return handle;
}
