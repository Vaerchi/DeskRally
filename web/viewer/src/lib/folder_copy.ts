// docs/77 phase 2: copy a whole remote folder. The tree is listed first (one BrowseDirectory per folder) so the
// technician sees how much will be copied before anything moves; files are then copied one at a time through the
// same Get path as a single file. Pure apart from the injected lister, so it is unit-tested with a fake tree.

export interface RemoteEntryLike {
  name: string;
  is_dir: boolean;
  size_bytes: number | null;
}

export interface PlannedFile {
  /** Path segments below the copied folder, the last being the file name. */
  rel: string[];
  /** The remote absolute path. */
  path: string;
  size: number;
}

export interface SkippedEntry {
  path: string;
  reason: string;
}

export interface CopyPlan {
  files: PlannedFile[];
  /** Every folder below the root (relative segments), parents before children, so they can be created in order. */
  dirs: string[][];
  skipped: SkippedEntry[];
  totalBytes: number;
  /** The walk stopped early (too many entries); `files` is what was found before it stopped. */
  truncated: boolean;
}

/** The agent's per-file download limit when it copies (agent fs_manage MAX_STAGE_BYTES). */
export const MAX_FILE_BYTES = 64 * 1024 * 1024;
/** docs/77 phase 3b: the limit when the console streams (the agent leases instead of copying; MAX_LEASE_BYTES). */
export const MAX_STREAM_FILE_BYTES = 4 * 1024 * 1024 * 1024;
/** Above either of these the technician confirms the copy. */
export const CONFIRM_FILES = 500;
export const CONFIRM_BYTES = 1024 * 1024 * 1024;
/** Hard stops for the walk itself. */
export const MAX_ENTRIES = 5000;
export const MAX_DEPTH = 32;

export function joinRemote(dir: string, name: string): string {
  return dir.endsWith("\\") ? `${dir}${name}` : `${dir}\\${name}`;
}

/**
 * List `root` recursively with `list` (one call per folder, breadth-first). Folders that cannot be listed are
 * recorded as skipped and the walk continues; files over the per-file limit are skipped with the reason.
 */
export async function planRemoteCopy(
  root: string,
  list: (path: string) => Promise<RemoteEntryLike[]>,
  maxFileBytes: number = MAX_FILE_BYTES,
): Promise<CopyPlan> {
  const plan: CopyPlan = { files: [], dirs: [], skipped: [], totalBytes: 0, truncated: false };
  const queue: { path: string; rel: string[] }[] = [{ path: root, rel: [] }];
  let seen = 0;
  while (queue.length > 0) {
    const { path, rel } = queue.shift()!;
    let entries: RemoteEntryLike[];
    try {
      entries = await list(path);
    } catch (e) {
      plan.skipped.push({ path, reason: e instanceof Error ? e.message : String(e) });
      continue;
    }
    for (const e of entries) {
      if (++seen > MAX_ENTRIES) {
        plan.truncated = true;
        return plan;
      }
      const childPath = joinRemote(path, e.name);
      const childRel = [...rel, e.name];
      if (e.is_dir) {
        if (childRel.length > MAX_DEPTH) {
          plan.skipped.push({ path: childPath, reason: `deeper than ${MAX_DEPTH} folders` });
          continue;
        }
        plan.dirs.push(childRel);
        queue.push({ path: childPath, rel: childRel });
      } else {
        const size = e.size_bytes ?? 0;
        if (size > maxFileBytes) {
          plan.skipped.push({ path: childPath, reason: maxFileBytes === MAX_FILE_BYTES ? "over 64 MiB" : "over 4 GiB" });
          continue;
        }
        plan.files.push({ rel: childRel, path: childPath, size });
        plan.totalBytes += size;
      }
    }
  }
  return plan;
}

/** What the summary and the confirmation read: counts and totals only (a remote or a local plan). */
type PlanSummary = Pick<CopyPlan, "dirs" | "skipped" | "totalBytes" | "truncated"> & { files: readonly unknown[] };

export function needsConfirmation(plan: PlanSummary): boolean {
  return plan.files.length > CONFIRM_FILES || plan.totalBytes > CONFIRM_BYTES;
}

export function describePlan(plan: PlanSummary): string {
  const mb = (plan.totalBytes / (1024 * 1024)).toFixed(1);
  const parts = [`${plan.files.length} file${plan.files.length === 1 ? "" : "s"} (${mb} MB) in ${plan.dirs.length + 1} folder${plan.dirs.length === 0 ? "" : "s"}`];
  if (plan.skipped.length > 0) parts.push(`${plan.skipped.length} skipped`);
  if (plan.truncated) parts.push(`stopped listing at ${MAX_ENTRIES} entries`);
  return parts.join("; ");
}

// ---------------------------------------------------------------------------
// Send folder: the technician's folder -> the remote folder on screen.
// ---------------------------------------------------------------------------

/** The agent's upload limit (file_transfer.ts DEFAULT_MAX_FILE_BYTES). */
export const MAX_UPLOAD_BYTES = 128 * 1024 * 1024;

export interface LocalDirLike {
  readonly kind: "directory";
  readonly name: string;
  entries(): AsyncIterable<[string, LocalDirLike | LocalFileLike]>;
}
export interface LocalFileLike {
  readonly kind: "file";
  readonly name: string;
  getFile(): Promise<File>;
}

export interface PlannedUpload {
  rel: string[];
  file: File;
}

export interface UploadPlan {
  files: PlannedUpload[];
  dirs: string[][];
  skipped: SkippedEntry[];
  totalBytes: number;
  truncated: boolean;
}

/** Walk a local folder breadth-first with the same limits as the remote walk (5000 entries, depth 32). */
export async function planLocalCopy(root: LocalDirLike): Promise<UploadPlan> {
  const plan: UploadPlan = { files: [], dirs: [], skipped: [], totalBytes: 0, truncated: false };
  const queue: { dir: LocalDirLike; rel: string[] }[] = [{ dir: root, rel: [] }];
  let seen = 0;
  while (queue.length > 0) {
    const { dir, rel } = queue.shift()!;
    try {
      for await (const [name, h] of dir.entries()) {
        if (++seen > MAX_ENTRIES) {
          plan.truncated = true;
          return plan;
        }
        const childRel = [...rel, name];
        const shown = childRel.join("\\");
        if (h.kind === "directory") {
          if (childRel.length > MAX_DEPTH) {
            plan.skipped.push({ path: shown, reason: `deeper than ${MAX_DEPTH} folders` });
            continue;
          }
          plan.dirs.push(childRel);
          queue.push({ dir: h, rel: childRel });
        } else {
          let file: File;
          try {
            file = await h.getFile();
          } catch (e) {
            plan.skipped.push({ path: shown, reason: e instanceof Error ? e.message : String(e) });
            continue;
          }
          if (file.size > MAX_UPLOAD_BYTES) {
            plan.skipped.push({ path: shown, reason: "over 128 MiB" });
            continue;
          }
          plan.files.push({ rel: childRel, file });
          plan.totalBytes += file.size;
        }
      }
    } catch (e) {
      plan.skipped.push({ path: rel.join("\\") || dir.name, reason: e instanceof Error ? e.message : String(e) });
    }
  }
  return plan;
}