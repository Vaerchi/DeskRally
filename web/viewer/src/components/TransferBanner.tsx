import type { SessionTransfer } from "../lib/console_api";

/** The sender's status line for an outgoing session hand-off (docs/51). Moved out of App.tsx unchanged. */
export function TransferBanner({ transfer, onCancel, onDismiss }: {
  transfer: SessionTransfer;
  onCancel: () => void;
  onDismiss: () => void;
}) {
  return (
    <p role="status" className="panel__hint" data-testid="transfer-banner">
      {transfer.state === "pending" && <>
        Waiting for {transfer.to_name || "anyone in the group"} to accept{" "}
        <button type="button" className="panel__action" data-testid="transfer-banner-cancel"
          onClick={onCancel}>Cancel hand-off</button>
      </>}
      {transfer.state === "releasing" &&
        `${transfer.accepted_by_name || "Your colleague"} accepted · handing the session over…`}
      {transfer.state !== "pending" && transfer.state !== "releasing" && <>
        {transfer.state === "expired" ? "Nobody accepted the hand-off in time."
          : transfer.state === "failed" ? `The hand-off did not complete: ${transfer.failure_reason ?? ""}`
          : `The hand-off is ${transfer.state}.`}{" "}
        <button type="button" className="panel__action" onClick={onDismiss}>OK</button>
      </>}
    </p>
  );
}
