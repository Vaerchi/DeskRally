/**
 * Remote file browser (docs/01 §3 "File Manager — browse remote filesystem"). A session-scoped,
 * READ-ONLY view: it sends `ListDirectory` over the live control channel and renders the agent's
 * `DirectoryListing`. Presentational — App owns the request/response state (the listing, a loading
 * flag, an error) and passes a stable `onNavigate`; this component only decides which path a click
 * asks for, via the pure `filepath` helpers.
 *
 * The one write it offers is UPLOAD, and only while the browser is AT the agent's transfer root: the
 * existing `Offer` lands every upload in that root under its base name, so offering it anywhere else
 * would put the file somewhere other than the folder the operator is looking at.
 */

import { useCallback, useEffect, useRef, type ChangeEvent, type DragEvent } from "react";
import type { DirectoryListing } from "../lib/control";
import { childPath, parentPath, locationLabel, formatSize, formatModified, pathRelativeTo, isSamePath } from "../lib/filepath";

/** Whether a drag carries files from the operator's machine (as opposed to text or a link). */
function isFileDrag(e: DragEvent<HTMLElement>): boolean {
  return Array.from(e.dataTransfer?.types ?? []).includes("Files");
}

/** One upload started from the file browser, as App reports it back for display. */
export interface BrowseUploadRow {
  id: number;
  name: string;
  phase: "uploading" | "ok" | "error";
  message: string;
}

export interface FileManagerPanelProps {
  /** The most recent listing from the agent, or undefined before the first reply. */
  listing?: DirectoryListing;
  /** A `ListDirectory` is in flight (show a spinner rather than a stale-looking empty list). */
  loading: boolean;
  /** The agent refused the last navigation (e.g. a denied/absent path). */
  error?: string;
  /** Ask the agent to list `path` (empty = the drive roots). MUST be stable across renders. */
  onNavigate: (path: string) => void;
  /**
   * Called with the absolute remote path when the operator clicks a file's download button.
   * When absent, no download buttons are shown. Authorization is enforced by the agent
   * (`Capability::FileDownload`); the agent will refuse any request the session is not
   * permitted to make. The viewer does not duplicate that check.
   */
  onDownloadFile?: (absolutePath: string) => void;
  /**
   * The agent's configured transfer directory (agent `config.json` `transfer_dir`), advertised
   * via the `TransferDir` control message. When `undefined` (older agent that has not sent this
   * message), the "Go to Transfers" shortcut is disabled and download affordances are suppressed —
   * we cannot safely infer a root that may differ from any default.
   */
  transferDirPath?: string;
  /**
   * Relative paths (relative to `transferDirPath`) of files whose browse-download completed this
   * session. When a file row is inside the transfer directory AND its relative path appears here,
   * a "✓ saved" indicator is shown alongside (or instead of) the download button. The indicator
   * is shown even when `onDownloadFile` is absent (e.g. grant revoked after download), because
   * the completed fact is still accurate.
   *
   * Callers must pass forward-slash-separated paths relative to the transfer root, matching the
   * output of `pathRelativeTo(transferDirPath, absolutePath)`.
   */
  completedFiles?: ReadonlySet<string>;
  /**
   * Upload the chosen/dropped files into the transfer root. Offered (button + drop target) only while
   * the browser is AT `transferDirPath`. Absent ⇒ no upload affordance. As with downloads, the agent
   * enforces `Capability::FileUpload`; App only omits this when the session is known to lack it.
   */
  onUploadFiles?: (files: File[]) => void;
  /** Uploads started from this browser this session, newest first, for the status list. */
  uploads?: readonly BrowseUploadRow[];
  /**
   * Fetch and install a signed backstage grant (the same action as Under the Hood's "Get access"). When given and
   * the agent refused the listing because no grant is installed, the refusal offers it right here. Before, the
   * panel showed "no backstage grant is installed for this session" with no way forward unless the technician knew
   * to open Under the Hood first (server-install acceptance, 2026-11-10). Failures are App's to report.
   */
  onGetAccess?: () => void;
  /** The agent acknowledged an installed grant. After "Get access" here, the panel re-lists its folder on this. */
  grantInstalled?: boolean;
}

/** The agent's secure-mode refusal: no grant installed yet (rmt_agent_windows::host, "no backstage grant is installed"). */
export function isNoGrantRefusal(error: string | undefined): boolean {
  return !!error && /no backstage grant is installed/i.test(error);
}

export function FileManagerPanel({ listing, loading, error, onNavigate, onDownloadFile, transferDirPath, completedFiles, onUploadFiles, uploads, onGetAccess, grantInstalled }: FileManagerPanelProps) {
  const tdir = transferDirPath;
  const uploadInputRef = useRef<HTMLInputElement>(null);
  // Set by this panel's "Get access"; the grant's acknowledgement then re-lists the folder that was refused.
  const relistOnGrant = useRef(false);
  // Load the drive roots once when the browser opens. The control client buffers the request until
  // the channel is ready, so an early call is safe.
  useEffect(() => {
    onNavigate("");
  }, [onNavigate]);

  // The listing echoes the path it is for; before the first reply we are conceptually at the roots.
  const current = listing?.path ?? "";
  const atRoots = current === "";
  useEffect(() => {
    if (grantInstalled && relistOnGrant.current) {
      relistOnGrant.current = false;
      onNavigate(current);
    }
  }, [grantInstalled, current, onNavigate]);
  // Upload is offered only AT the transfer root (see the module comment), and only for a listing the
  // agent actually returned for it — `current` is the echoed path, never the one merely requested.
  const canUpload = onUploadFiles !== undefined && tdir !== undefined && isSamePath(current, tdir);

  const onPicked = useCallback(
    (e: ChangeEvent<HTMLInputElement>) => {
      const files = e.target.files ? Array.from(e.target.files) : [];
      e.target.value = ""; // picking the same file again must fire `change` again
      if (files.length > 0 && onUploadFiles) onUploadFiles(files);
    },
    [onUploadFiles],
  );
  const onDragOver = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      // A FILE drag is always consumed here, even where upload is not offered: the browser's default
      // for a dropped file is to navigate the tab to it, which would tear down the live session.
      if (!isFileDrag(e)) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = canUpload ? "copy" : "none";
    },
    [canUpload],
  );
  const onDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      if (!isFileDrag(e)) return;
      e.preventDefault(); // see onDragOver: never let a dropped file navigate the tab
      if (!canUpload || !onUploadFiles) return;
      const files = Array.from(e.dataTransfer.files);
      if (files.length > 0) onUploadFiles(files);
    },
    [canUpload, onUploadFiles],
  );

  return (
    <div className="viewer__files" data-testid="file-manager" onDragOver={onDragOver} onDrop={onDrop}>
      <div className="viewer__files-bar">
        <button
          type="button"
          className="viewer__zoombtn"
          data-testid="file-up"
          disabled={atRoots || loading}
          onClick={() => onNavigate(parentPath(current))}
          title="Up one folder"
        >
          ⭡ Up
        </button>
        <button
          type="button"
          className="viewer__zoombtn"
          data-testid="file-refresh"
          disabled={loading}
          onClick={() => onNavigate(current)}
          title="Refresh this folder"
        >
          ⟳ Refresh
        </button>
        <button
          type="button"
          className="viewer__zoombtn"
          data-testid="file-goto-transfers"
          disabled={loading || tdir === undefined || current === tdir}
          onClick={() => tdir !== undefined && onNavigate(tdir)}
          title={tdir === undefined ? "Transfer root unknown — connect to a newer agent" : `Go to transfer folder (${tdir})`}
        >
          ⤓ Transfers
        </button>
        {canUpload && (
          <>
            <button
              type="button"
              className="viewer__zoombtn"
              data-testid="file-upload"
              disabled={loading}
              onClick={() => uploadInputRef.current?.click()}
              title="Upload files into this folder (or drop them here)"
            >
              ⬆ Upload here
            </button>
            <input
              ref={uploadInputRef}
              type="file"
              multiple
              hidden
              data-testid="file-upload-input"
              onChange={onPicked}
            />
          </>
        )}
        <span className="viewer__files-loc" data-testid="file-loc">
          {locationLabel(current)}
        </span>
        {loading && (
          <span className="viewer__files-loading" data-testid="file-loading">
            Loading…
          </span>
        )}
      </div>

      {error && (
        <div className="viewer__files-error" role="alert" data-testid="file-error">
          {error}
          {onGetAccess && isNoGrantRefusal(error) && (
            <>
              {" "}
              <button
                type="button"
                className="viewer__zoombtn"
                data-testid="file-get-access"
                onClick={() => {
                  relistOnGrant.current = true;
                  onGetAccess();
                }}
              >
                Get access
              </button>
            </>
          )}
        </div>
      )}

      {uploads && uploads.length > 0 && (
        <ul className="viewer__files-uploads" data-testid="file-uploads">
          {uploads.map((u) => (
            <li key={u.id} data-testid={`file-upload-row-${u.id}`} data-phase={u.phase}>
              ⬆ {u.name} — {u.message}
            </li>
          ))}
        </ul>
      )}

      <ul className="viewer__files-list">
        {listing && listing.entries.length === 0 && !loading && (
          <li className="viewer__files-empty" data-testid="files-empty">
            {atRoots ? "No drives." : "This folder is empty."}
          </li>
        )}
        {listing?.entries.map((e) =>
          e.is_dir ? (
            <li key={e.name}>
              <button
                type="button"
                className="viewer__files-entry viewer__files-entry--dir"
                data-testid={`file-entry-${e.name}`}
                disabled={loading}
                onClick={() => onNavigate(childPath(current, e.name))}
              >
                📁 {e.name}
              </button>
            </li>
          ) : (
            <li key={e.name} className="viewer__files-entry" data-testid={`file-row-${e.name}`}>
              📄 {e.name} <span className="viewer__files-size">{formatSize(e.size)}</span>
              {e.modified_unix > 0 && (
                <span className="viewer__files-modified" data-testid={`file-modified-${e.name}`}>
                  {formatModified(e.modified_unix)}
                </span>
              )}
              {tdir !== undefined && pathRelativeTo(tdir, childPath(current, e.name)) !== null && (
                <>
                  {onDownloadFile && (
                    <button
                      type="button"
                      className="viewer__files-download"
                      data-testid={`file-download-${e.name}`}
                      title={`Download ${e.name}`}
                      onClick={() => onDownloadFile(childPath(current, e.name))}
                    >
                      ⬇
                    </button>
                  )}
                  {tdir !== undefined && completedFiles?.has(pathRelativeTo(tdir, childPath(current, e.name)) ?? "") && (
                    <span
                      className="viewer__files-saved"
                      data-testid={`file-saved-${e.name}`}
                      title="Downloaded this session"
                    >
                      ✓ saved
                    </span>
                  )}
                </>
              )}
            </li>
          ),
        )}
      </ul>

      {listing?.truncated && (
        <div className="viewer__files-truncated" data-testid="file-truncated">
          Showing the first {listing.entries.length} entries; this folder has more.
        </div>
      )}
    </div>
  );
}
