/**
 * F06 explicit-approval prompt for unsolicited inbound downloads.
 *
 * Renders one row per pending (verified, held-for-approval) download. Save/Dismiss buttons call
 * `client.approveDownload(id)` / `client.dismissDownload(id)`. The BYTES live inside the client
 * under an active F07 lease — this component only sees bounded metadata (id, sanitized name,
 * size). A click after the underlying `FileTransferClient` was disposed or replaced silently
 * no-ops on the stale client; the current-client ref is captured per render.
 */

import type { FileTransferClient, PendingDownloadMeta } from "../lib/file_transfer";

export interface IncomingDownloadPromptProps {
  /** Live file-transfer client. Absent ⇒ nothing rendered. */
  client?: FileTransferClient;
  /** Snapshot the client emits via `onPendingDownloadsChanged`. Metadata only, never bytes. */
  pending: readonly PendingDownloadMeta[];
}

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

export function IncomingDownloadPrompt({ client, pending }: IncomingDownloadPromptProps) {
  if (!client || pending.length === 0) return null;
  return (
    <section
      className="incoming-download-prompt"
      role="region"
      aria-label="Incoming download"
      data-testid="incoming-download-prompt"
    >
      <p className="incoming-download-prompt__hint">
        The remote machine sent a file. Review the file name before saving. Files are held temporarily.
      </p>
      <ul className="incoming-download-prompt__list">
        {pending.map((p) => (
          <li className="incoming-download-prompt__row" key={p.id} data-testid="incoming-download-row">
            {/* Isolate the peer-controlled name in a bdi so bidi runs cannot spoof surrounding UI.
                The client already stripped control/format chars; this is defence in depth. */}
            <bdi className="incoming-download-prompt__name" data-testid="incoming-download-name">
              {p.name}
            </bdi>
            <span className="incoming-download-prompt__size">{humanSize(p.size)}</span>
            <button
              type="button"
              onClick={() => client.approveDownload(p.id)}
              data-testid="incoming-download-save"
            >
              Save
            </button>
            <button
              type="button"
              onClick={() => client.dismissDownload(p.id)}
              data-testid="incoming-download-dismiss"
            >
              Dismiss
            </button>
          </li>
        ))}
      </ul>
    </section>
  );
}
