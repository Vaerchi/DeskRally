// docs/77 two-pane explorer, the technician's side: a folder picked with the File System Access API (Chrome / Edge),
// listed and navigated WITHIN that folder (the API grants nothing above it), and written into for "Get". The handle
// never leaves the page and is not persisted: each session asks again.
//
// The handle types are the small subset this module uses, so tests can drive a fake tree.

export interface LocalFileHandle {
  readonly kind: "file";
  readonly name: string;
  getFile(): Promise<File>;
  createWritable(): Promise<LocalWritable>;
}

export interface LocalWritable {
  write(data: Blob | BufferSource): Promise<void>;
  close(): Promise<void>;
  abort?(): Promise<void>;
}

export interface LocalDirHandle {
  readonly kind: "directory";
  readonly name: string;
  entries(): AsyncIterable<[string, LocalDirHandle | LocalFileHandle]>;
  getDirectoryHandle(name: string, opts?: { create?: boolean }): Promise<LocalDirHandle>;
  getFileHandle(name: string, opts?: { create?: boolean }): Promise<LocalFileHandle>;
  /** Removes an entry (a streamed Get that failed removes the empty file it created). */
  removeEntry?(name: string): Promise<void>;
}

export interface LocalEntry {
  name: string;
  isDir: boolean;
  /** Bytes, for files; null for folders. */
  size: number | null;
  /** Last modified (ms since epoch), for files; null for folders. */
  modified: number | null;
}

type PickerWindow = { showDirectoryPicker?: (opts?: { mode?: "read" | "readwrite"; id?: string }) => Promise<LocalDirHandle> };

/** Whether this browser can open a local folder (Chrome / Edge yes; Firefox / Safari no). */
export function supportsFolderAccess(win: unknown = globalThis): boolean {
  return typeof (win as PickerWindow).showDirectoryPicker === "function";
}

/** Ask the technician for a folder (read + write). Rejects with AbortError when they cancel. */
export async function pickLocalFolder(win: unknown = globalThis): Promise<LocalDirHandle> {
  const w = win as PickerWindow;
  if (typeof w.showDirectoryPicker !== "function") throw new Error("this browser cannot open a local folder");
  return w.showDirectoryPicker({ mode: "readwrite", id: "deskrally-explorer" });
}

// Windows reserved device names: a file called "CON.txt" cannot be created there.
const RESERVED = /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$/i;

/**
 * Why `name` is not a safe single file name for the local folder, or null when it is. Names come from the REMOTE
 * machine and are untrusted: anything that could leave the folder or that Windows refuses is rejected, never "cleaned"
 * (a cleaned name can collide with, and overwrite, a different file).
 */
export function unsafeLocalName(name: string): string | null {
  if (name.length === 0) return "empty name";
  if (name.length > 255) return "name longer than 255 characters";
  if (name === "." || name === "..") return "not a file name";
  if (/[\\/]/.test(name)) return "contains a path separator";
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f<>:"|?*]/.test(name)) return "contains a character Windows does not allow";
  if (/[. ]$/.test(name)) return "ends with a dot or a space";
  if (RESERVED.test(name)) return "is a reserved Windows device name";
  return null;
}

/** `report.pdf` -> `report (2).pdf`, the first free one; a name without an extension gets the suffix at the end. */
export function keepBothName(name: string, taken: ReadonlySet<string>): string {
  const lowerTaken = new Set([...taken].map((n) => n.toLowerCase()));
  const dot = name.lastIndexOf(".");
  const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ""];
  for (let i = 2; i < 10_000; i++) {
    const candidate = `${stem} (${i})${ext}`;
    if (!lowerTaken.has(candidate.toLowerCase())) return candidate;
  }
  throw new Error("no free name");
}

export type ConflictPolicy = "replace" | "keep-both" | "skip";

export type WriteResult = { kind: "written"; name: string } | { kind: "skipped"; name: string };

/** The folder's entries: folders first, then by name (case-insensitive). */
export async function listLocal(dir: LocalDirHandle): Promise<LocalEntry[]> {
  const out: LocalEntry[] = [];
  for await (const [name, h] of dir.entries()) {
    if (h.kind === "directory") {
      out.push({ name, isDir: true, size: null, modified: null });
    } else {
      try {
        const f = await h.getFile();
        out.push({ name, isDir: false, size: f.size, modified: f.lastModified });
      } catch {
        out.push({ name, isDir: false, size: null, modified: null });
      }
    }
  }
  return out.sort((a, b) =>
    a.isDir !== b.isDir ? (a.isDir ? -1 : 1) : a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
  );
}

async function exists(dir: LocalDirHandle, name: string): Promise<boolean> {
  try {
    await dir.getFileHandle(name);
    return true;
  } catch {
    return false;
  }
}

/**
 * Write `data` as `name` in `dir`. The name is checked first (refused, never cleaned). An existing file is replaced,
 * kept alongside (`name (2).ext`) or skipped, per `policy`. A failed write is aborted so no half file is left behind.
 */
/**
 * Open `name` in `dir` for writing under `policy` (the name checked first; an existing file replaced, kept alongside, or
 * skipped). Returns null when skipped. The caller writes and closes, or aborts so no half file is left behind
 * (docs/77 phase 3 streams into it).
 */
export async function openLocalWritable(
  dir: LocalDirHandle,
  name: string,
  policy: ConflictPolicy,
): Promise<{ name: string; writable: LocalWritable } | null> {
  const bad = unsafeLocalName(name);
  if (bad) throw new Error(`"${name}" cannot be saved here: ${bad}`);
  let target = name;
  if (await exists(dir, name)) {
    if (policy === "skip") return null;
    if (policy === "keep-both") {
      const taken = new Set((await listLocal(dir)).map((e) => e.name));
      target = keepBothName(name, taken);
    }
  }
  const handle = await dir.getFileHandle(target, { create: true });
  return { name: target, writable: await handle.createWritable() };
}

export async function writeLocalFile(
  dir: LocalDirHandle,
  name: string,
  data: Blob | BufferSource,
  policy: ConflictPolicy,
): Promise<WriteResult> {
  const opened = await openLocalWritable(dir, name, policy);
  if (!opened) return { kind: "skipped", name };
  const target = opened.name;
  const w = opened.writable;
  try {
    await w.write(data);
    await w.close();
  } catch (e) {
    await w.abort?.().catch(() => undefined);
    throw e;
  }
  return { kind: "written", name: target };
}

/** Where the local pane is: the picked folder plus the subfolders entered, never above the picked folder. */
export class LocalFolderNav {
  private stack: LocalDirHandle[];

  constructor(root: LocalDirHandle) {
    this.stack = [root];
  }

  get current(): LocalDirHandle {
    return this.stack[this.stack.length - 1];
  }

  get atRoot(): boolean {
    return this.stack.length === 1;
  }

  /** `Chosen\sub\deeper`, for display. */
  get label(): string {
    return this.stack.map((d) => d.name).join("\\");
  }

  async enter(name: string): Promise<void> {
    this.stack.push(await this.current.getDirectoryHandle(name));
  }

  up(): void {
    if (!this.atRoot) this.stack.pop();
  }
}
