// Under the Hood -> Command prompt (docs/76): an interactive PowerShell running as SYSTEM on the remote machine,
// over the session's own `shell` data channel. The agent enforces everything (grant, its confirmation token, the
// gate, expiry, attended/observer refusals); this panel adds a typed machine-name confirmation and says plainly what
// it is. Leaving the tab closes the channel, and the agent then kills the shell's whole process tree.
import { useEffect, useRef, useState } from "react";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { ShellClient, type ShellState } from "../lib/shell_client";

export interface TerminalPanelProps {
  machineName: string;
  /** Opens the session's `shell` data channel; null when there is no live connection. */
  openChannel: () => RTCDataChannel | null;
}

export function TerminalPanel({ machineName, openChannel }: TerminalPanelProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const clientRef = useRef<ShellClient | null>(null);
  const [state, setState] = useState<ShellState | null>(null);
  const [typed, setTyped] = useState("");
  const [noChannel, setNoChannel] = useState(false);

  // One terminal for the panel's life.
  useEffect(() => {
    const term = new Terminal({ convertEol: false, cursorBlink: true, scrollback: 5000, fontSize: 13 });
    const fit = new FitAddon();
    term.loadAddon(fit);
    termRef.current = term;
    fitRef.current = fit;
    if (hostRef.current) term.open(hostRef.current);
    const sub = term.onData((d) => clientRef.current?.input(d));
    const ro = new ResizeObserver(() => {
      try {
        fit.fit();
      } catch {
        // not laid out yet
      }
      clientRef.current?.resize(term.cols, term.rows);
    });
    if (hostRef.current) ro.observe(hostRef.current);
    return () => {
      ro.disconnect();
      sub.dispose();
      clientRef.current?.dispose();
      clientRef.current = null;
      term.dispose();
    };
  }, []);

  const confirmed = typed.trim().toLowerCase() === machineName.trim().toLowerCase() && machineName.trim() !== "";
  const open = state?.kind === "open";
  const busy = state?.kind === "opening" || state?.kind === "connecting";

  const start = () => {
    const term = termRef.current;
    if (!term || !confirmed) return;
    if (!clientRef.current || clientRef.current.current.kind === "disconnected") {
      const dc = openChannel();
      if (!dc) {
        setNoChannel(true);
        return;
      }
      setNoChannel(false);
      clientRef.current = new ShellClient(dc, {
        onState: (s) => {
          setState(s);
          if (s.kind === "open") {
            term.reset();
            term.focus();
          }
        },
        onOutput: (bytes) => term.write(bytes),
      });
    }
    try {
      fitRef.current?.fit();
    } catch {
      // keep the default size
    }
    clientRef.current.open(term.cols || 100, term.rows || 30);
    setTyped("");
  };

  return (
    <div className="terminal" data-testid="uth-terminal">
      {!open && (
        <div className="terminal__gate" data-testid="uth-terminal-gate">
          <p>
            <strong>Command prompt as SYSTEM.</strong> PowerShell runs on <strong>{machineName}</strong> with full system
            rights, out of the user&apos;s sight. The machine&apos;s indicator says a command prompt is open, and opening and
            closing it are recorded in the audit trail. Closing it stops everything it started, but not changes it made
            (services, scheduled tasks). Not available in attended sessions.
          </p>
          <label>
            Type the machine name to confirm{" "}
            <input value={typed} onChange={(e) => setTyped(e.target.value)} data-testid="uth-terminal-confirm"
              placeholder={machineName} autoComplete="off" />
          </label>{" "}
          <button type="button" className="panel__action" disabled={!confirmed || busy} onClick={start}
            data-testid="uth-terminal-open">
            {busy ? "Opening…" : "Open command prompt"}
          </button>
          {noChannel && <p className="panel__hint" role="alert">The session is not connected.</p>}
          {state?.kind === "refused" && (
            <p className="panel__hint" role="alert" data-testid="uth-terminal-refused">Refused: {state.reason}</p>
          )}
          {state?.kind === "closed" && (
            <p className="panel__hint" role="status" data-testid="uth-terminal-closed">
              The command prompt closed: {state.reason}
              {state.exitCode !== null ? ` (exit code ${state.exitCode})` : ""}.
            </p>
          )}
          {state?.kind === "disconnected" && (
            <p className="panel__hint" role="status">The command prompt channel closed.</p>
          )}
        </div>
      )}
      {open && (
        <div className="terminal__bar">
          <span>PowerShell as SYSTEM on {machineName}</span>{" "}
          <button type="button" className="panel__action" onClick={() => clientRef.current?.close()}
            data-testid="uth-terminal-close">
            Close command prompt
          </button>
        </div>
      )}
      <div ref={hostRef} className="terminal__screen" data-testid="uth-terminal-screen"
        style={{ display: open ? "block" : "none", height: "60vh" }} />
    </div>
  );
}
