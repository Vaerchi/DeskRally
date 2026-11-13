import { useEffect, useId, useRef, useState } from "react";
import type { ConsoleApi, MachineRecord, ToolboxRunAs, ToolboxShell } from "../lib/console_api";
import { runBulk, type BulkRow, type BulkRun, type BulkTask, type OpenBulkCore } from "../lib/bulk_run";
import { buildActiveSessionMap } from "../lib/console_panels";
import { bulkResultsToCsv } from "../lib/report_csv";

interface BulkRunDialogProps {
  api: ConsoleApi;
  /** A saved task to run (a toolbox item). When absent and `compose` is set, start in the ad-hoc
   *  compose step to build a command. */
  task?: BulkTask;
  /** Start in the ad-hoc compose step (ignored when `task` is given). */
  compose?: boolean;
  /** Builds the per-device core factory for a run, given a short label for the session note and a
   *  fresh bulk id. The dialog calls it at start() so an ad-hoc label reflects the composed command. */
  openBulkCore: (label: string, bulkId: string) => OpenBulkCore;
  onClose: () => void;
}

type PickerMachine = MachineRecord & { ephemeral?: boolean };
const eligible = (machine: PickerMachine) => machine.online === true && machine.ephemeral !== true
  && machine.status !== "quarantined" && machine.status !== "retired";

function preview(text: string): string {
  let result = "";
  let bytes = 0;
  for (const char of text) {
    const size = new TextEncoder().encode(char).length;
    if (bytes + size > 4096) break;
    bytes += size;
    result += char;
  }
  return result;
}

export function BulkRunDialog({ api, task, compose, openBulkCore, onClose }: BulkRunDialogProps) {
  const titleId = useId();
  const root = useRef<HTMLDivElement>(null);
  const mounted = useRef(false);
  const handle = useRef<BulkRun | null>(null);
  const urls = useRef(new Set<string>());
  const [machines, setMachines] = useState<PickerMachine[]>([]);
  const [inSession, setInSession] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [sessionWarning, setSessionWarning] = useState(false);
  // Ad-hoc compose state (unused when a saved task is passed).
  const [cmdBody, setCmdBody] = useState("");
  const [cmdShell, setCmdShell] = useState<ToolboxShell>("powershell");
  const [cmdRunAs, setCmdRunAs] = useState<ToolboxRunAs>("system");
  const [composed, setComposed] = useState<BulkTask | null>(null);
  // Push-and-run (docs/60 2a): optionally run the uploaded file after it lands.
  const [runAfter, setRunAfter] = useState(false);
  const [runArgs, setRunArgs] = useState("");
  const [runAsAfter, setRunAsAfter] = useState<ToolboxRunAs>("system");
  const [step, setStep] = useState<"compose" | "picker" | "confirm" | "results">(task ? "picker" : compose ? "compose" : "picker");
  // The task actually being run: the saved one, or the ad-hoc one once composed.
  const activeTask: BulkTask | null = task ?? composed;
  const isUpload = activeTask?.kind === "upload";
  const taskName = activeTask ? (activeTask.kind === "toolbox" ? activeTask.item.name : activeTask.name) : "a command";
  const uploadBytes = activeTask?.kind === "upload" ? activeTask.bytes.length : 0;
  // A command summary for the confirm step (null for an upload, which has no shell/run_as/body).
  const cmdSummary = activeTask && activeTask.kind !== "upload"
    ? {
        shell: activeTask.kind === "toolbox" ? activeTask.item.shell : activeTask.shell,
        runAs: activeTask.kind === "toolbox" ? activeTask.item.run_as : activeTask.runAs,
        body: activeTask.kind === "toolbox" ? activeTask.item.body : activeTask.body,
      }
    : null;
  // Cheap client pre-flight so an obviously-malformed command does not open 25 sessions just to be
  // refused 25 times; the control plane remains the authority on the length caps.
  const cmdProblem = cmdBody.trim() === "" ? "Enter a command."
    : cmdShell === "cmd" && /[\r\n]/.test(cmdBody) ? "A cmd command is a single line."
    : null;
  const [rows, setRows] = useState<readonly BulkRow[]>([]);
  const [settled, setSettled] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const closing = useRef(false);
  const closeRef = useRef(onClose);
  closeRef.current = onClose;

  useEffect(() => {
    mounted.current = true;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    root.current?.focus();
    return () => {
      mounted.current = false;
      handle.current?.cancel();
      handle.current = null;
      for (const url of urls.current) URL.revokeObjectURL(url);
      urls.current.clear();
      previous?.focus();
    };
  }, []);

  useEffect(() => {
    let current = true;
    void Promise.all([
      api.listMachines(),
      api.listLiveSessions().catch(() => {
        if (current) setSessionWarning(true);
        return [];
      }),
    ]).then(([listing, sessions]) => {
      if (!current) return;
      const unique = [...new Map(listing.map(machine => [machine.device_id, machine])).values()];
      const active = buildActiveSessionMap(sessions);
      setMachines(unique);
      setInSession(new Set(unique.filter(machine => active.has(machine.device_id)).map(machine => machine.device_id)));
      setSelected(new Set(unique.filter(machine => eligible(machine) && !active.has(machine.device_id)).slice(0, 25).map(machine => machine.device_id)));
    }).catch(failure => {
      if (current) setError(failure instanceof Error ? failure.message : String(failure));
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [api]);

  const requestClose = () => {
    if (handle.current && !settled) setConfirmClose(true);
    else closeRef.current();
  };

  const download = (text: string, filename: string, type: string) => {
    const url = URL.createObjectURL(new Blob([text], { type }));
    urls.current.add(url);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    try { anchor.click(); }
    finally {
      anchor.remove();
      setTimeout(() => {
        URL.revokeObjectURL(url);
        urls.current.delete(url);
      }, 0);
    }
  };

  const start = () => {
    let t = task ?? composed;
    if (handle.current || !t || selected.size === 0 || selected.size > 25) return;
    if (t.kind === "upload" && runAfter) {
      t = { ...t, run: { args: runArgs, runAs: runAsAfter } };
    }
    const label = t.kind === "toolbox" ? `${t.item.name} v${t.item.version}`
      : t.kind === "upload" ? (t.run ? `file+run: ${t.name}` : `file: ${t.name}`)
      : `ad-hoc ${t.shell} command`;
    const openCore = openBulkCore(label, crypto.randomUUID());
    const snapshot = new Map(machines.map(machine => [machine.device_id, { name: machine.name, alias: machine.alias }]));
    const labels = (values: readonly BulkRow[]) => values.map(row => ({
      ...row, machineName: snapshot.get(row.deviceId)?.name ?? row.deviceId,
      alias: snapshot.get(row.deviceId)?.alias,
    }));
    try {
      const run = runBulk([...selected], t, openCore, {
        onChange: values => { if (mounted.current) setRows(labels(values)); },
      });
      handle.current = run;
      setRows(labels(run.rows));
      setStep("results");
      void run.done.then(() => {
        handle.current = null;
        if (!mounted.current) return;
        setSettled(true);
        if (closing.current) closeRef.current();
      });
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    }
  };

  const cancel = () => {
    handle.current?.cancel();
    setCancelled(true);
  };
  const filtered = machines.filter(machine => `${machine.name} ${machine.alias ?? ""} ${machine.device_id}`.toLowerCase().includes(query.trim().toLowerCase()));
  const counts = rows.reduce<Record<string, number>>((result, row) => {
    result[row.state] = (result[row.state] ?? 0) + 1;
    return result;
  }, {});

  return (
    <div className="backstage__confirm-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId}
      data-testid="bulk-dialog" tabIndex={-1} ref={root} onKeyDown={event => {
        if (event.key === "Escape") {
          event.preventDefault();
          event.stopPropagation();
          requestClose();
        }
        if (event.key === "Tab") {
          const controls = [...(root.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), [tabindex="0"]') ?? [])];
          const first = controls[0];
          const last = controls[controls.length - 1];
          if (!first) { event.preventDefault(); return; }
          if (event.shiftKey && (document.activeElement === first || document.activeElement === root.current)) {
            event.preventDefault(); last.focus();
          } else if (!event.shiftKey && (document.activeElement === last || document.activeElement === root.current)) {
            event.preventDefault(); first.focus();
          }
        }
      }}>
      <div className="backstage__confirm" style={{ width: "min(1100px, 95vw)", maxWidth: "95vw", maxHeight: "90vh", overflow: "auto" }}>
        <h2 id={titleId}>{isUpload ? `Send ${taskName} to machines` : `Run ${taskName} on machines`}</h2>
        <button className="panel__action" data-testid="bulk-close" onClick={requestClose}>Close</button>
        {error && <p role="alert" className="panel__toolbar-error">{error}</p>}
        {step === "compose" && <>
          <p className="panel__hint">Type a command to run on the machines you pick next. It is authorized and audited per machine, exactly like a saved toolbox script. The server enforces the length limits.</p>
          <label style={{ display: "block" }}>Shell{" "}
            <select data-testid="bulk-cmd-shell" value={cmdShell} onChange={event => setCmdShell(event.target.value as ToolboxShell)}>
              <option value="powershell">PowerShell</option>
              <option value="cmd">Command Prompt (cmd)</option>
            </select>
          </label>
          <label style={{ display: "block" }}>Run as{" "}
            <select data-testid="bulk-cmd-runas" value={cmdRunAs} onChange={event => setCmdRunAs(event.target.value as ToolboxRunAs)}>
              <option value="system">SYSTEM</option>
              <option value="user">signed-in user</option>
            </select>
          </label>
          <textarea data-testid="bulk-cmd-body" aria-label="Command" className="panel__code"
            style={{ width: "100%", minHeight: "8rem", whiteSpace: "pre", overflowWrap: "normal", overflow: "auto" }}
            value={cmdBody} onChange={event => setCmdBody(event.target.value)} />
          {cmdProblem && <p role="status" className="panel__hint">{cmdProblem}</p>}
          <button className="panel__action" data-testid="bulk-cmd-next" disabled={!!cmdProblem} onClick={() => {
            setComposed({ kind: "adhoc", name: "a command", shell: cmdShell, runAs: cmdRunAs, body: cmdBody });
            setStep("picker");
          }}>Pick machines</button>
        </>}
        {step === "picker" && <>
          <p className="panel__hint">Select up to 25 online unattended machines. Machines in session start unselected; you may include them explicitly. Session availability is advisory.</p>
          {sessionWarning && <p role="status">Session listing unavailable; existing sessions could not be marked.</p>}
          <input className="panel__search" type="search" aria-label="Search machines" value={query} onChange={event => setQuery(event.target.value)} />
          {loading && <p role="status">Loading…</p>}
          <div style={{ maxHeight: "45vh", overflow: "auto" }}>
            {filtered.map(machine => <label key={machine.device_id} style={{ display: "block" }}>
              <input type="checkbox" data-testid={`bulk-machine-${machine.device_id}`} checked={selected.has(machine.device_id)}
                disabled={!eligible(machine) || (!selected.has(machine.device_id) && selected.size >= 25)}
                onChange={event => {
                  const checked = event.target.checked;
                  setSelected(previous => {
                    const next = new Set(previous);
                    if (!checked) next.delete(machine.device_id);
                    else if (eligible(machine) && next.size < 25) next.add(machine.device_id);
                    return next;
                  });
                }} />
              {machine.alias || machine.name} ({machine.device_id})
              {inSession.has(machine.device_id) && " — in session"}
              {!eligible(machine) && " — unavailable (requires online unattended, active machine)"}
            </label>)}
          </div>
          <p>{selected.size} / 25 selected</p>
          {composed && !task && <button className="panel__action" data-testid="bulk-cmd-back" onClick={() => setStep("compose")}>Back to command</button>}
          <button className="panel__action" data-testid="bulk-confirm" disabled={loading || !!error || selected.size === 0} onClick={() => setStep("confirm")}>Continue</button>
        </>}
        {step === "confirm" && <>
          {isUpload
            ? <>
                <p>Send {taskName} ({uploadBytes.toLocaleString()} bytes) to {selected.size} machines. It lands in each machine's transfer folder; an existing file is never replaced.</p>
                <label style={{ display: "block" }}>
                  <input type="checkbox" data-testid="bulk-run-after" checked={runAfter}
                    onChange={event => { setRunAfter(event.target.checked); }} />
                  {" "}Run it after it lands
                </label>
                {runAfter && <>
                  <label style={{ display: "block" }}>Arguments (PowerShell syntax, audited verbatim){" "}
                    <input data-testid="bulk-run-args" value={runArgs} onChange={event => setRunArgs(event.target.value)} placeholder="/S" />
                  </label>
                  <label style={{ display: "block" }}>Run as{" "}
                    <select data-testid="bulk-run-runas" value={runAsAfter} onChange={event => setRunAsAfter(event.target.value as ToolboxRunAs)}>
                      <option value="system">SYSTEM</option>
                      <option value="user">signed-in user</option>
                    </select>
                  </label>
                  <p className="panel__hint">Each machine runs {"& '<transfer folder>\\<landed name>'"} with your arguments; the exact line is authorized and audited per machine before it runs. Cancelling after a file lands leaves that file on the machine.</p>
                </>}
              </>
            : <>
                <p>Run {taskName} ({cmdSummary?.shell}, as {cmdSummary?.runAs === "system" ? "SYSTEM" : "signed-in user"}) on {selected.size} machines</p>
                <pre className="panel__code" tabIndex={0} style={{ maxHeight: "35vh", overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{cmdSummary?.body}</pre>
              </>}
          <button className="panel__action" onClick={() => setStep("picker")}>Back</button>
          <button className="panel__action" data-testid="bulk-run" onClick={start}>Run</button>
        </>}
        {step === "results" && <>
          <p role="status" aria-live="polite">{Object.entries(counts).map(([state, count]) => `${count} ${state}`).join("; ")}{!settled && " — cleanup remains active"}</p>
          <p className="panel__hint">Cancel stops queued and undispatched work. Commands already sent keep running; their results and session cleanup are awaited.</p>
          <button className="panel__action" data-testid="bulk-cancel" disabled={settled || cancelled} onClick={cancel}>{cancelled ? "Cancellation requested" : "Cancel"}</button>
          <button className="panel__action" data-testid="bulk-export-csv" onClick={() => download(bulkResultsToCsv(rows), "bulk-results.csv", "text/csv;charset=utf-8")}>Export CSV</button>
          <div style={{ overflow: "auto" }}>
            <table className="panel__table">
              <thead><tr><th>Machine</th><th>State</th><th>Exit code / reason</th><th>Output head</th><th>Download</th></tr></thead>
              <tbody>{rows.map(row => <tr key={row.deviceId} data-testid={`bulk-row-${row.deviceId}`} data-state={row.state}>
                <td>{row.alias || row.machineName}<br /><span className="panel__mono">{row.deviceId}</span></td>
                <td>{row.state}{row.state === "unknown" && " (sent; result not received)"}</td>
                <td>{row.outcome?.exitCode ?? row.outcome?.reason ?? ""}</td>
                <td>
                  {row.outcome?.agentTruncated && <span className="panel__hint">Agent truncated </span>}
                  {row.outcome?.consoleTruncated && <span className="panel__hint">Console truncated </span>}
                  {(row.outcome?.outputHead?.length ?? 0) > preview(row.outcome?.outputHead ?? "").length && <span className="panel__hint">Preview limited to 4 KiB </span>}
                  <pre tabIndex={0} style={{ maxWidth: "40vw", maxHeight: "16rem", overflow: "auto", whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{preview(row.outcome?.outputHead ?? "")}</pre>
                </td>
                <td>{row.outcome?.outputHead !== undefined && <button className="panel__action" onClick={() => download(row.outcome!.outputHead!, `bulk-output-${encodeURIComponent(row.deviceId)}.txt`, "text/plain;charset=utf-8")}>Download output</button>}</td>
              </tr>)}</tbody>
            </table>
          </div>
          <p className="panel__hint">Downloads contain retained output: at most 64 KiB per machine and 2 MiB across the run. Truncation badges apply to downloads too.</p>
        </>}
        {confirmClose && <div role="group" aria-label="Cancel before closing">
          <p>Cancel remaining work and close after results and cleanup finish? Commands already sent keep running.</p>
          <button className="panel__action" onClick={() => {
            closing.current = true;
            setConfirmClose(false);
            cancel();
            if (!handle.current) closeRef.current();
          }}>Cancel work and close when finished</button>
          <button className="panel__action" onClick={() => setConfirmClose(false)}>Keep open</button>
        </div>}
      </div>
    </div>
  );
}
