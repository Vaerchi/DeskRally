/**
 * Incoming session hand-offs, the receiver's half (docs/51 §5): "Alice wants to hand you <machine>".
 *
 * Offers come from the 10 s poll in App (lib/session_transfer IncomingTransferPoller). Dismiss only hides
 * an offer here; it does not decline it on the server (another colleague may still take a group offer).
 */
import type { SessionTransfer } from "../lib/console_api";

export interface IncomingTransfersProps {
  offers: SessionTransfer[];
  /** The offer being accepted, and what is happening to it. */
  accepting: { id: string; status: string } | null;
  error: string | null;
  onAccept: (offer: SessionTransfer) => void;
  onDismiss: (offer: SessionTransfer) => void;
  onClearError: () => void;
}

export function IncomingTransfers({ offers, accepting, error, onAccept, onDismiss, onClearError }: IncomingTransfersProps) {
  if (offers.length === 0 && !accepting && !error) return null;
  return (
    <section className="panel" aria-label="Incoming session hand-offs" data-testid="incoming-transfers"
      style={{ margin: "8px 0", padding: 8 }}>
      {error && <p role="alert" className="panel__toolbar-error" data-testid="incoming-transfer-error">
        {error} <button className="panel__action" onClick={onClearError}>OK</button>
      </p>}
      {accepting && <p role="status" aria-live="polite" data-testid="incoming-transfer-status">{accepting.status}</p>}
      {offers.map((t) => (
        <div key={t.id} data-testid={`incoming-transfer-${t.id}`} style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <span>
            <strong>{t.from_name || "A colleague"}</strong> wants to hand {t.to_user_id ? "you" : "your group"}{" "}
            <strong>{t.machine_name || "a machine"}</strong>
            {t.note && <span className="panel__hint"> · “{t.note}”</span>}
          </span>
          <button className="panel__action" data-testid={`incoming-transfer-accept-${t.id}`}
            disabled={accepting !== null} onClick={() => onAccept(t)}>Accept</button>
          <button className="panel__action" data-testid={`incoming-transfer-dismiss-${t.id}`}
            disabled={accepting?.id === t.id} onClick={() => onDismiss(t)}>Dismiss</button>
        </div>
      ))}
    </section>
  );
}
