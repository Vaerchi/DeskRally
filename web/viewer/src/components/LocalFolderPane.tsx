// docs/77 two-pane explorer, left pane: a folder on the technician's computer. Chrome / Edge open a real folder
// (File System Access API) the technician can move around in (never above the folder they picked) and select files
// from to Send. Other browsers get a file picker. The picked folder is also where Get writes (reported upward).
import { useCallback, useEffect, useRef, useState } from "react";
import {
  listLocal,
  LocalFolderNav,
  pickLocalFolder,
  supportsFolderAccess,
  type LocalDirHandle,
  type LocalEntry,
} from "../lib/local_folder";
import { formatSize } from "../lib/filepath";

export interface LocalFolderPaneProps {
  /** Send the chosen files to the remote folder on screen. Absent: no Send (no permission, or an observer). */
  onSend?: (files: File[]) => void;
  /** docs/77 phase 2: send this whole local folder to the remote folder on screen. Absent: no folder Send. */
  onSendFolder?: (dir: LocalDirHandle) => void;
  /** The folder on screen (where Get writes), or null when none is open. */
  onFolderChange?: (dir: LocalDirHandle | null) => void;
  /** Bump to re-list the folder (after a Get wrote into it). */
  refreshKey?: number;
  /** For tests: whether folder access exists, and the picker. */
  folderAccess?: boolean;
  pick?: () => Promise<LocalDirHandle>;
}

export function LocalFolderPane({ onSend, onSendFolder, onFolderChange, refreshKey = 0, folderAccess, pick }: LocalFolderPaneProps) {
  const supported = folderAccess ?? supportsFolderAccess();
  const navRef = useRef<LocalFolderNav | null>(null);
  const [label, setLabel] = useState<string | null>(null);
  const [atRoot, setAtRoot] = useState(true);
  const [entries, setEntries] = useState<LocalEntry[]>([]);
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [error, setError] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const relist = useCallback(async () => {
    const nav = navRef.current;
    if (!nav) return;
    try {
      setEntries(await listLocal(nav.current));
      setError(null);
    } catch (e) {
      setEntries([]);
      setError(e instanceof Error ? e.message : String(e));
    }
    setLabel(nav.label);
    setAtRoot(nav.atRoot);
    setSelected(new Set());
    onFolderChange?.(nav.current);
  }, [onFolderChange]);

  useEffect(() => {
    void relist();
  }, [refreshKey, relist]);

  const choose = async () => {
    try {
      const root = await (pick ?? (() => pickLocalFolder()))();
      navRef.current = new LocalFolderNav(root);
      await relist();
    } catch (e) {
      if (e instanceof DOMException && e.name === "AbortError") return; // the technician cancelled
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const enter = async (name: string) => {
    try {
      await navRef.current?.enter(name);
      await relist();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  };

  const up = () => {
    navRef.current?.up();
    void relist();
  };

  const toggle = (name: string) =>
    setSelected((s) => {
      const next = new Set(s);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const send = async () => {
    const nav = navRef.current;
    if (!nav || !onSend) return;
    const files: File[] = [];
    for (const name of selected) {
      const h = await nav.current.getFileHandle(name);
      files.push(await h.getFile());
    }
    if (files.length > 0) onSend(files);
    setSelected(new Set());
  };

  if (!supported) {
    return (
      <section className="explorer__pane" data-testid="local-pane" aria-label="This computer">
        <h4 className="explorer__title">This computer</h4>
        <p className="panel__hint">
          This browser cannot open a folder on your computer (Chrome and Edge can). Send picks files here, and Get
          saves through the browser&apos;s download.
        </p>
        {onSend && (
          <>
            <button type="button" className="panel__action" onClick={() => fileInput.current?.click()}
              data-testid="local-pick-files">
              Choose files to send…
            </button>
            <input ref={fileInput} type="file" multiple hidden data-testid="local-file-input"
              onChange={(e) => {
                const files = Array.from(e.target.files ?? []);
                e.target.value = "";
                if (files.length > 0) onSend(files);
              }} />
          </>
        )}
      </section>
    );
  }

  return (
    <section className="explorer__pane" data-testid="local-pane" aria-label="This computer">
      <h4 className="explorer__title">This computer</h4>
      <div className="explorer__bar">
        <button type="button" className="panel__action" onClick={() => void choose()} data-testid="local-choose">
          {label === null ? "Choose a folder…" : "Change folder…"}
        </button>
        {label !== null && (
          <>
            <button type="button" className="panel__action" onClick={up} disabled={atRoot} data-testid="local-up">
              ↑ Up
            </button>
            <span className="explorer__loc" data-testid="local-loc">{label}</span>
          </>
        )}
      </div>
      {error && <p className="panel__hint" role="alert">{error}</p>}
      {label !== null && (
        <>
          <table className="panel__table">
            <tbody>
              {entries.length === 0 && (
                <tr><td className="panel__empty" colSpan={3}>This folder is empty.</td></tr>
              )}
              {entries.map((e) => (
                <tr key={e.name}>
                  <td>
                    {!e.isDir && (
                      <input type="checkbox" aria-label={`Select ${e.name}`} checked={selected.has(e.name)}
                        onChange={() => toggle(e.name)} data-testid={`local-select-${e.name}`} />
                    )}
                  </td>
                  <td>
                    {e.isDir ? (
                      <>
                        <button type="button" className="panel__filelink" onClick={() => void enter(e.name)}>
                          📁 {e.name}
                        </button>
                        {onSendFolder && (
                          <>
                            {" "}
                            <button type="button" className="panel__action" data-testid={`local-send-folder-${e.name}`}
                              aria-label={`Send folder ${e.name}`}
                              onClick={() => {
                                const nav = navRef.current;
                                if (nav) void nav.current.getDirectoryHandle(e.name).then(onSendFolder, (err: unknown) =>
                                  setError(err instanceof Error ? err.message : String(err)));
                              }}>
                              Send folder →
                            </button>
                          </>
                        )}
                      </>
                    ) : (
                      e.name
                    )}
                  </td>
                  <td className="panel__col--num">{e.size === null ? "" : formatSize(e.size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {onSend && (
            <button type="button" className="panel__action" disabled={selected.size === 0} onClick={() => void send()}
              data-testid="local-send">
              Send {selected.size > 0 ? `${selected.size} ` : ""}→
            </button>
          )}
        </>
      )}
    </section>
  );
}
