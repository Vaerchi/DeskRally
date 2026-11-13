/**
 * File-transfer console (Milestone V3).
 *
 * A tab in the session UI that drives the `FileTransferClient` (M8) over the live session's
 * `ChannelId.FileTransfer`:
 *
 *  - **Upload:** a file picker + a drag-and-drop zone. Each selected file's bytes are read
 *    (`File.arrayBuffer`) and handed to `client.upload(name, bytes)`, which emits `Offer`→`Chunk`s→
 *    `Done` and resolves with the agent's `Ack`. The panel shows a per-file status row (uploading →
 *    committed / failed) driven by that resolved Ack — the M8 client reports completion, not
 *    per-chunk progress, so the in-flight state is shown indeterminate.
 *  - **Download:** a path input → `client.request(path)`. The reassembled bytes arrive via the
 *    client's `onDownload` callback (wired in `App.tsx`), which the app feeds back here as the
 *    `download` prop; an effect then triggers a real browser save (Blob + `<a download>`), keyed on
 *    the download's `seq` so the same file can be re-fetched.
 *
 * The `client` is injectable so this mounts against a live agent in production and a fake channel in
 * tests. All wire framing lives in `file_transfer.ts`; this file is only UI + lifecycle.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import type { FileTransferClient } from "../lib";

/** A completed inbound download handed down from `App` (the client's `onDownload` payload + a seq). */
export interface CompletedDownload {
  name: string;
  bytes: Uint8Array;
  sha256: string;
  verified: boolean;
  /** Monotonic id bumped by `App` per completion, so the save effect fires once per new download. */
  seq: number;
}

export interface FileTransferPanelProps {
  /** Live client over `ChannelId.FileTransfer`. Absent ⇒ controls are disabled (no session). */
  client?: FileTransferClient;
  /** The most recently completed inbound download (from the client's `onDownload`), or null. */
  download?: CompletedDownload | null;
}

type UploadPhase = "uploading" | "ok" | "error";

interface UploadRow {
  id: number;
  name: string;
  size: number;
  phase: UploadPhase;
  message: string;
}

/**
 * Trigger a browser "Save as" for `bytes` under `name` via an object-URL anchor. Kept in this module
 * (the file-transfer UI owns the DOM download gesture) and exported so it is unit-testable.
 */
export function saveBytesAsFile(name: string, bytes: Uint8Array): void {
  // Copy into a fresh ArrayBuffer-backed array so the BlobPart type is unambiguous under strict DOM
  // typings (a view over a SharedArrayBuffer is not a valid BlobPart).
  const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Revoke on the next tick so the click has a chance to start the download first.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

export function FileTransferPanel({ client, download }: FileTransferPanelProps) {
  const [rows, setRows] = useState<UploadRow[]>([]);
  const [dragOver, setDragOver] = useState(false);
  const [path, setPath] = useState("");
  const [downloadStatus, setDownloadStatus] = useState<string>("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  const rowSeq = useRef(0);
  const lastStatusSeq = useRef<number>(-1);

  const uploadFiles = useCallback(
    async (files: FileList | File[]) => {
      if (!client) return;
      for (const file of Array.from(files)) {
        const id = ++rowSeq.current;
        setRows((prev) => [
          { id, name: file.name, size: file.size, phase: "uploading", message: "Uploading…" },
          ...prev,
        ]);
        try {
          const bytes = new Uint8Array(await file.arrayBuffer());
          const ack = await client.upload(file.name, bytes);
          setRows((prev) =>
            prev.map((r) =>
              r.id === id
                ? {
                    ...r,
                    phase: ack.ok ? "ok" : "error",
                    message: ack.ok ? "Committed on agent" : ack.message || "Rejected by agent",
                  }
                : r,
            ),
          );
        } catch (e) {
          setRows((prev) =>
            prev.map((r) =>
              r.id === id
                ? { ...r, phase: "error", message: e instanceof Error ? e.message : String(e) }
                : r,
            ),
          );
        }
      }
    },
    [client],
  );

  const onPick = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      if (e.target.files && e.target.files.length > 0) void uploadFiles(e.target.files);
      e.target.value = ""; // allow re-picking the same file
    },
    [uploadFiles],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (e.dataTransfer?.files && e.dataTransfer.files.length > 0) {
        void uploadFiles(e.dataTransfer.files);
      }
    },
    [uploadFiles],
  );

  const onRequest = useCallback(() => {
    const p = path.trim();
    if (!client || p === "") return;
    // `client.request` mints a UUID, INSERTS the pending-request entry BEFORE it frames the wire
    // message, and can fail synchronously (limit, disposed, invalid path, id collision, send throw).
    // We surface its own error message here — never claim a fake success to the UI.
    try {
      client.request(p);
      setDownloadStatus(`Requested "${p}" — waiting for the agent…`);
    } catch (e) {
      setDownloadStatus(`Request failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [client, path]);

  // When App feeds a freshly completed download, surface its status (keyed on seq).
  // saveBytesAsFile is now called in App.tsx onDownload, independent of which tab is active.
  useEffect(() => {
    if (!download || download.seq === lastStatusSeq.current) return;
    lastStatusSeq.current = download.seq;
    // saveBytesAsFile is now called in App.tsx onDownload (independent of which tab is active).
    setDownloadStatus(
      `Downloaded "${download.name}" (${humanSize(download.bytes.length)}) — ${
        download.verified ? "sha256 verified ✓" : "WARNING: checksum/size mismatch"
      }`,
    );
  }, [download]);

  const disabled = !client;

  return (
    <div className="filepanel" data-testid="file-transfer-panel">
      <section className="filepanel__section">
        <h3 className="filepanel__title">Upload to agent</h3>
        <div
          className="filepanel__drop"
          data-over={dragOver}
          data-testid="ft-dropzone"
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
        >
          <p className="filepanel__drophint">Drag files here, or</p>
          <button
            type="button"
            disabled={disabled}
            onClick={() => fileInputRef.current?.click()}
            data-testid="ft-pick"
          >
            Choose file…
          </button>
          <input
            ref={fileInputRef}
            type="file"
            multiple
            hidden
            onChange={onPick}
            data-testid="ft-file-input"
          />
        </div>

        {rows.length > 0 && (
          <ul className="filepanel__list" data-testid="ft-upload-list">
            {rows.map((r) => (
              <li className="filepanel__row" data-phase={r.phase} key={r.id}>
                <span className="filepanel__name">{r.name}</span>
                <span className="filepanel__size">{humanSize(r.size)}</span>
                <span className="filepanel__phase" data-testid="ft-upload-status">
                  {r.phase === "uploading" && <span className="filepanel__spinner" aria-hidden />}
                  {r.message}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="filepanel__section">
        <h3 className="filepanel__title">Download from agent</h3>
        <div className="filepanel__downloadrow">
          <input
            type="text"
            className="filepanel__pathinput"
            placeholder="file name in the agent's transfer folder"
            value={path}
            disabled={disabled}
            onChange={(e) => setPath(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onRequest();
            }}
            data-testid="ft-download-path"
          />
          <button
            type="button"
            disabled={disabled || path.trim() === ""}
            onClick={onRequest}
            data-testid="ft-download-btn"
          >
            Download
          </button>
        </div>
        {downloadStatus && (
          <p className="filepanel__dlstatus" data-testid="ft-download-status">
            {downloadStatus}
          </p>
        )}
      </section>
    </div>
  );
}
