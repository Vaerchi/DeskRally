/**
 * "Transfer…" — the sender's half of a session hand-off (docs/51 §5).
 *
 * Lists the colleagues the server says may take this machine (GET /sessions/{id}/transfer-candidates,
 * the same rule the offer's 422 applies), plus "Anyone in <group>" for an escalation. The offer itself
 * is authorized server-side; this dialog only collects the choice.
 */
import { useEffect, useId, useRef, useState } from "react";
import type { ConsoleApi, SessionTransfer, TransferCandidates } from "../lib/console_api";

const ANYONE = "";
const MAX_NOTE = 500;

export interface TransferDialogProps {
  api: Pick<ConsoleApi, "sessionTransferCandidates" | "offerSessionTransfer">;
  sessionId: string;
  machineName: string;
  onOffered: (transfer: SessionTransfer) => void;
  onClose: () => void;
}

export function TransferDialog({ api, sessionId, machineName, onOffered, onClose }: TransferDialogProps) {
  const titleId = useId();
  const root = useRef<HTMLDivElement>(null);
  const [options, setOptions] = useState<TransferCandidates | null>(null);
  const [choice, setChoice] = useState<string | null>(null);
  const [note, setNote] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);

  useEffect(() => {
    let live = true;
    api.sessionTransferCandidates(sessionId).then(
      (got) => { if (live) setOptions(got); },
      (failure: unknown) => { if (live) setError(failure instanceof Error ? failure.message : String(failure)); },
    );
    root.current?.focus();
    return () => { live = false; };
  }, [api, sessionId]);

  const groupLabel = options?.group.id ? (options.group.name || "this machine's group") : null;
  const send = async () => {
    if (choice === null) return;
    setSending(true);
    setError(null);
    try {
      const t = await api.offerSessionTransfer(sessionId, {
        ...(choice === ANYONE ? {} : { toUserId: choice }),
        note: note.trim(),
      });
      onOffered(t);
      onClose();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
      setSending(false);
    }
  };

  return (
    <div className="backstage__confirm-backdrop" role="dialog" aria-modal="true" aria-labelledby={titleId}
      data-testid="transfer-dialog" tabIndex={-1} ref={root}
      onKeyDown={(event) => {
        // Keys typed here are for this dialog, never the remote machine.
        event.stopPropagation();
        if (event.key === "Escape") { event.preventDefault(); onClose(); }
      }}>
      <div className="backstage__confirm" style={{ width: "min(520px, 95vw)", maxHeight: "90vh", overflow: "auto" }}>
        <h2 id={titleId}>Transfer {machineName}</h2>
        <p className="panel__hint">Your session ends when the colleague accepts. They get their own new session on this machine.</p>
        {error && <p role="alert" className="panel__toolbar-error" data-testid="transfer-error">{error}</p>}
        {!options && !error && <p role="status">Loading colleagues…</p>}
        {options && <fieldset style={{ border: 0, padding: 0 }}>
          <legend className="panel__hint">Hand to</legend>
          {options.candidates.map((c) => (
            <label key={c.id} style={{ display: "block" }}>
              <input type="radio" name="transfer-to" value={c.id} checked={choice === c.id}
                data-testid={`transfer-to-${c.id}`} onChange={() => setChoice(c.id)} />
              {" "}{c.display_name || c.email}{c.display_name && <span className="panel__hint"> ({c.email})</span>}
            </label>
          ))}
          {groupLabel && <label style={{ display: "block" }}>
            <input type="radio" name="transfer-to" value={ANYONE} checked={choice === ANYONE}
              data-testid="transfer-to-group" onChange={() => setChoice(ANYONE)} />
            {" "}Anyone in {groupLabel}
          </label>}
          {options.candidates.length === 0 && !groupLabel &&
            <p className="panel__hint" data-testid="transfer-none">No colleague may take sessions on this machine.</p>}
        </fieldset>}
        <label style={{ display: "block", marginTop: 8 }}>
          Note (optional)
          <textarea className="backstage__confirm-input" data-testid="transfer-note" value={note} maxLength={MAX_NOTE} rows={3}
            style={{ width: "100%", boxSizing: "border-box" }} onChange={(e) => setNote(e.target.value)} />
        </label>
        <div className="backstage__confirm-actions">
          <button className="panel__action" onClick={onClose} data-testid="transfer-cancel">Cancel</button>
          <button className="panel__action" data-testid="transfer-send" disabled={choice === null || sending} onClick={() => void send()}>
            {sending ? "Sending…" : "Send"}
          </button>
        </div>
      </div>
    </div>
  );
}
