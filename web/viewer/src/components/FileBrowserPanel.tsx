/**
 * Backstage file browser panel: a read-only directory listing rendered natively in the
 * technician's browser (docs/04-backstage.md Part 1). Directories sort first, sizes are humanized
 * (dirs show "—"), and a breadcrumb is derived from the listing's path.
 *
 * Presentational only: the `DirListing` comes in as a prop from a typed source — this component
 * does not fetch. Navigation is surfaced as an optional `onNavigate(path)` callback (breadcrumb
 * hops and directory rows); when omitted the panel is a static view.
 *
 * docs/58: with `manage` set (the grant holds `file_delete` AND the agent advertised `file_manage`),
 * the panel offers New folder, Rename and Delete. Never in the drive list. The panel only collects
 * names; the container sends the requests, runs the confirmation, and refreshes.
 */

import { type FormEvent, useMemo, useState } from "react";
import {
  breadcrumbSegments,
  formatBytes,
  formatTimestamp,
  sortFileEntries,
  DASH,
  type DirListing,
} from "../backstage/panels";

/** docs/58 file management, as names within the listed folder. */
export interface FileManageActions {
  onNewFolder: (name: string) => void;
  onRename: (entryName: string, newName: string) => void;
  onDelete: (entryName: string) => void;
  /** A change is in flight: controls are disabled until it settles. */
  busy?: boolean;
  /** docs/58 §12: upload files and place them in THIS folder (the agent advertised `file_place`). */
  onUploadHere?: (files: File[]) => void;
}

export interface FileBrowserPanelProps {
  listing: DirListing;
  /** Invoked when the technician clicks a breadcrumb hop or a directory row. */
  onNavigate?: (path: string) => void;
  /** docs/58: file management controls; omitted = read-only browser. */
  manage?: FileManageActions;
}

/** The expectation docs/58 §1 writes down, shown wherever Under the Hood can change files. */
export const SILENT_OPERATIONS_NOTE =
  "The person at this PC sees that a technician is connected, but no prompt for each action here. Each action is recorded in this session's audit trail.";

export function FileBrowserPanel({ listing, onNavigate, manage }: FileBrowserPanelProps) {
  const crumbs = useMemo(() => breadcrumbSegments(listing.path), [listing.path]);
  const entries = useMemo(() => sortFileEntries(listing.entries), [listing.entries]);
  // Management never applies to the drive list (there is no folder to act in).
  const actions = listing.path === "" ? undefined : manage;
  const [newFolder, setNewFolder] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ from: string; to: string } | null>(null);

  const submitNewFolder = (e: FormEvent) => {
    e.preventDefault();
    const name = (newFolder ?? "").trim();
    if (!actions || name === "") return;
    actions.onNewFolder(name);
    setNewFolder(null);
  };
  const submitRename = (e: FormEvent) => {
    e.preventDefault();
    if (!actions || !renaming) return;
    const to = renaming.to.trim();
    if (to === "" || to === renaming.from) {
      setRenaming(null);
      return;
    }
    actions.onRename(renaming.from, to);
    setRenaming(null);
  };

  return (
    <div className="panel panel--files">
      {actions && (
        <div className="panel__toolbar" data-testid="files-manage">
          {newFolder === null ? (
            <button
              type="button"
              className="panel__action"
              disabled={actions.busy}
              onClick={() => setNewFolder("")}
              data-testid="files-new-folder"
            >
              New folder
            </button>
          ) : (
            <form className="panel__inline-form" onSubmit={submitNewFolder}>
              <input
                className="panel__input"
                autoFocus
                aria-label="New folder name"
                value={newFolder}
                onChange={(e) => setNewFolder(e.target.value)}
                data-testid="files-new-folder-name"
              />
              <button type="submit" className="panel__action" disabled={actions.busy || newFolder.trim() === ""} data-testid="files-new-folder-create">
                Create
              </button>
              <button type="button" className="panel__action" onClick={() => setNewFolder(null)}>
                Cancel
              </button>
            </form>
          )}
          {actions.onUploadHere && (
            <label className="panel__action" data-testid="files-upload-here">
              Upload here
              <input
                type="file"
                multiple
                hidden
                disabled={actions.busy}
                data-testid="files-upload-here-input"
                onChange={(e) => {
                  const files = Array.from(e.target.files ?? []);
                  e.target.value = "";
                  if (files.length > 0) actions.onUploadHere?.(files);
                }}
              />
            </label>
          )}
          <span className="panel__note" data-testid="files-silent-note">
            {SILENT_OPERATIONS_NOTE}
          </span>
        </div>
      )}
      <nav className="panel__breadcrumb" aria-label="path">
        <button
          className="panel__crumb"
          disabled={!onNavigate || listing.path === ""}
          onClick={() => onNavigate?.("")}
        >
          Drives
        </button>
        {crumbs.map((c) => (
          <span key={c.path} className="panel__crumb-wrap">
            <span className="panel__crumb-sep">/</span>
            <button
              className="panel__crumb"
              disabled={!onNavigate}
              onClick={() => onNavigate?.(c.path)}
            >
              {c.label}
            </button>
          </span>
        ))}
      </nav>

      <table className="panel__table">
        <thead>
          <tr>
            <th>Name</th>
            <th className="panel__col--num">Size</th>
            <th>Modified</th>
            {actions && <th className="panel__col--action">Actions</th>}
          </tr>
        </thead>
        <tbody>
          {entries.length === 0 && (
            <tr>
              <td className="panel__empty" colSpan={actions ? 4 : 3}>
                Empty directory.
              </td>
            </tr>
          )}
          {entries.map((e) => {
            const navigable = e.is_dir && !!onNavigate;
            return (
              <tr key={e.name} data-dir={e.is_dir}>
                <td className="panel__name">
                  {navigable ? (
                    <button
                      className="panel__filelink"
                      onClick={() => onNavigate?.(joinPath(listing.path, e.name))}
                    >
                      <FileIcon entry={e} />
                      {e.name}
                    </button>
                  ) : (
                    <span className="panel__filelabel">
                      <FileIcon entry={e} />
                      {e.name}
                    </span>
                  )}
                </td>
                <td className="panel__col--num">{e.is_dir ? DASH : formatBytes(e.size_bytes)}</td>
                <td>{formatTimestamp(e.modified_unix_ms)}</td>
                {actions && (
                  <td className="panel__col--action">
                    {renaming?.from === e.name ? (
                      <form className="panel__inline-form" onSubmit={submitRename}>
                        <input
                          className="panel__input"
                          autoFocus
                          aria-label={`New name for ${e.name}`}
                          value={renaming.to}
                          onChange={(ev) => setRenaming({ from: e.name, to: ev.target.value })}
                          data-testid={`files-rename-name-${e.name}`}
                        />
                        <button type="submit" className="panel__action" disabled={actions.busy} data-testid={`files-rename-save-${e.name}`}>
                          Rename
                        </button>
                        <button type="button" className="panel__action" onClick={() => setRenaming(null)}>
                          Cancel
                        </button>
                      </form>
                    ) : (
                      <>
                        <button
                          type="button"
                          className="panel__action"
                          disabled={actions.busy}
                          onClick={() => setRenaming({ from: e.name, to: e.name })}
                          aria-label={`Rename ${e.name}`}
                          data-testid={`files-rename-${e.name}`}
                        >
                          Rename
                        </button>{" "}
                        <button
                          type="button"
                          className="panel__action panel__action--danger"
                          disabled={actions.busy}
                          onClick={() => actions.onDelete(e.name)}
                          aria-label={`Delete ${e.name}`}
                          data-testid={`files-delete-${e.name}`}
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function FileIcon({ entry }: { entry: { is_dir: boolean; is_symlink: boolean } }) {
  const glyph = entry.is_dir ? "📁" : "📄";
  return (
    <span className="panel__fileicon" aria-hidden>
      {glyph}
      {entry.is_symlink && <span className="panel__symlink" title="symlink / reparse point">↩</span>}
    </span>
  );
}

/**
 * Join a directory entry onto the current path, preserving the path's separator style. An empty
 * base (the drive list) means the entry name is already an absolute drive root (e.g. "C:\\").
 */
export function joinPath(base: string, name: string): string {
  if (base === "") return name;
  const sep = base.includes("\\") || /^[A-Za-z]:/.test(base) ? "\\" : "/";
  return base.endsWith(sep) ? base + name : base + sep + name;
}
