/**
 * Pure path helpers for the remote file browser (docs/01 §3). The agent speaks Windows paths, so
 * these join/split on backslashes and treat an empty path as "the drive roots" — where each entry's
 * `name` is itself a full `X:\` root path. Pure + unit-tested so the browser's navigation can never
 * desync from what the agent will accept as a `ListDirectory` path (a wrong join would send the agent
 * a path it cannot read and turn every click into an error).
 */

/**
 * The agent's default transfer folder (configured as `transfer_dir` in `config.json`).
 * Files inside this directory can be downloaded via the existing `FileTransferClient.request()`
 * protocol without an agent upgrade; files elsewhere on the filesystem require a future agent
 * extension. Used by the file browser to decide whether to offer one-click download buttons.
 */
export const DEFAULT_TRANSFER_DIR = "C:\\rmt-agent\\transfers";

/**
 * Whether `a` and `b` name the same remote folder, compared the way Windows does for a path the agent
 * echoed: case-insensitively, with either separator, and ignoring trailing separators. Used to decide
 * whether the file browser is AT the transfer root, where an upload lands.
 */
export function isSamePath(a: string, b: string): boolean {
  const norm = (p: string) => p.replace(/\\/g, "/").replace(/\/+$/, "").toLowerCase();
  return a !== "" && b !== "" && norm(a) === norm(b);
}

/**
 * Returns the forward-slash relative path from `root` to `full`, or `null` if `full` is not
 * strictly inside `root`. Comparison is case-insensitive (Windows semantics). The returned path
 * uses forward slashes, which the agent's `resolve_download_path` accepts on Windows.
 *
 * Examples:
 *   pathRelativeTo("C:\\rmt-agent\\transfers", "C:\\rmt-agent\\transfers\\report.pdf") → "report.pdf"
 *   pathRelativeTo("C:\\rmt-agent\\transfers", "C:\\rmt-agent\\transfers\\sub\\f.txt") → "sub/f.txt"
 *   pathRelativeTo("C:\\rmt-agent\\transfers", "C:\\Users\\Ed\\file.txt") → null
 */
export function pathRelativeTo(root: string, full: string): string | null {
  const r = root.replace(/[\\/]+$/, "").replace(/\\/g, "/");
  const f = full.replace(/\\/g, "/");
  if (!f.toLowerCase().startsWith(r.toLowerCase() + "/")) return null;
  return f.slice(r.length + 1);
}

/**
 * The path to navigate to when opening `entryName` inside `current`. At the drive roots
 * (`current === ""`), an entry's name is already a full root path (`"C:\\"`), so it is used as-is;
 * otherwise the name is joined onto `current` with exactly one backslash.
 */
export function childPath(current: string, entryName: string): string {
  if (current === "") return entryName; // roots: the entry name is a full "X:\" path
  return current.endsWith("\\") ? `${current}${entryName}` : `${current}\\${entryName}`;
}

/**
 * The parent of `current`, or `""` (the drive roots) when `current` is a drive root or already the
 * roots. A drive root like `"C:\\"` goes up to the roots list; `"C:\\Users\\Public"` goes to
 * `"C:\\Users"`; and `"C:\\Users"` goes to `"C:\\"` (a bare `"C:"` is normalized back to `"C:\\"`).
 */
export function parentPath(current: string): string {
  if (current === "") return ""; // already at the roots
  const trimmed = current.replace(/\\+$/, ""); // drop any trailing backslashes
  if (/^[A-Za-z]:$/.test(trimmed)) return ""; // a drive root ("C:\") → the roots list
  const idx = trimmed.lastIndexOf("\\");
  if (idx < 0) return "";
  const parent = trimmed.slice(0, idx);
  if (/^[A-Za-z]:$/.test(parent)) return `${parent}\\`; // "C:\Users" → parent "C:" → "C:\"
  return parent;
}

/** A short human label for the current location: `"This PC"` at the roots, else the path itself. */
export function locationLabel(path: string): string {
  return path === "" ? "This PC" : path;
}

/**
 * Whether a `DirectoryListing` reply should be adopted, given the path the browser is currently
 * waiting on (`null` = not waiting on any specific one). A reply is adopted when it is FOR the
 * path we last asked for, or when we are not waiting for a specific path (a late reply after a
 * timeout still recovers the panel). A reply for a DIFFERENT path than the pending one is a stale
 * out-of-order answer to a superseded navigation and is dropped, so the panel never flips to a
 * folder the operator has already navigated away from.
 */
export function shouldAdoptListing(pendingPath: string | null, replyPath: string): boolean {
  return pendingPath === null || pendingPath === replyPath;
}

/** A compact human file size (`"512 B"`, `"1.5 KB"`, `"3.0 MB"`). Binary units (1024). */
export function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

/**
 * A compact human modification timestamp for a `DirEntry.modified_unix` value.
 *
 * Returns `""` when `unixSeconds` is `0` (the agent's sentinel for "unavailable") so callers can
 * skip rendering it. Otherwise returns a `"YYYY-MM-DD HH:MM"` string in the browser's LOCAL time
 * (the technician's own timezone), which is the correct reference for when to act on a file.
 */
export function formatModified(unixSeconds: number): string {
  if (unixSeconds <= 0) return "";
  const d = new Date(unixSeconds * 1000);
  const year = d.getFullYear();
  const month = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  const hour = String(d.getHours()).padStart(2, "0");
  const min = String(d.getMinutes()).padStart(2, "0");
  return `${year}-${month}-${day} ${hour}:${min}`;
}
