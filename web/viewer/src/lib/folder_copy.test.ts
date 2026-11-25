import { describe, expect, it } from "vitest";
import { describePlan, MAX_FILE_BYTES, MAX_UPLOAD_BYTES, needsConfirmation, planLocalCopy, planRemoteCopy, type LocalDirLike, type LocalFileLike, type RemoteEntryLike } from "./folder_copy";

const tree: Record<string, RemoteEntryLike[] | Error> = {
  "C:\\logs": [
    { name: "a.log", is_dir: false, size_bytes: 10 },
    { name: "sub", is_dir: true, size_bytes: null },
    { name: "huge.bin", is_dir: false, size_bytes: MAX_FILE_BYTES + 1 },
    { name: "locked", is_dir: true, size_bytes: null },
  ],
  "C:\\logs\\sub": [
    { name: "b.log", is_dir: false, size_bytes: 20 },
    { name: "deeper", is_dir: true, size_bytes: null },
  ],
  "C:\\logs\\sub\\deeper": [{ name: "c.log", is_dir: false, size_bytes: 30 }],
  "C:\\logs\\locked": new Error("access is denied"),
};

const lister = async (p: string) => {
  const v = tree[p];
  if (v instanceof Error) throw v;
  if (!v) throw new Error(`no such folder ${p}`);
  return v;
};

describe("planRemoteCopy (docs/77 phase 2)", () => {
  it("lists the whole tree, folders parents-first, and totals the files it will copy", async () => {
    const plan = await planRemoteCopy("C:\\logs", lister);
    expect(plan.files.map((f) => f.rel.join("/"))).toEqual(["a.log", "sub/b.log", "sub/deeper/c.log"]);
    expect(plan.files[2].path).toBe("C:\\logs\\sub\\deeper\\c.log");
    expect(plan.dirs.map((d) => d.join("/"))).toEqual(["sub", "locked", "sub/deeper"]);
    expect(plan.totalBytes).toBe(60);
    expect(plan.truncated).toBe(false);
  });

  it("skips (and says why) files over the limit and folders that cannot be listed", async () => {
    const plan = await planRemoteCopy("C:\\logs", lister);
    expect(plan.skipped).toEqual([
      { path: "C:\\logs\\huge.bin", reason: "over 64 MiB" },
      { path: "C:\\logs\\locked", reason: "access is denied" },
    ]);
    expect(describePlan(plan)).toBe("3 files (0.0 MB) in 4 folders; 2 skipped");
  });

  it("asks before large copies", () => {
    const base = { dirs: [], skipped: [], truncated: false };
    expect(needsConfirmation({ ...base, files: [], totalBytes: 0 })).toBe(false);
    expect(needsConfirmation({ ...base, files: Array(501).fill({ rel: ["x"], path: "x", size: 1 }), totalBytes: 501 })).toBe(true);
    expect(needsConfirmation({ ...base, files: [], totalBytes: 2 * 1024 * 1024 * 1024 })).toBe(true);
  });

  it("works from a drive root without doubling the separator", async () => {
    const plan = await planRemoteCopy("D:\\", async (p) => (p === "D:\\" ? [{ name: "x.txt", is_dir: false, size_bytes: 1 }] : []));
    expect(plan.files[0].path).toBe("D:\\x.txt");
  });
});

function localDir(name: string, children: Record<string, string | number | Record<string, unknown>>): LocalDirLike {
  return {
    kind: "directory",
    name,
    async *entries() {
      for (const [n, v] of Object.entries(children)) {
        if (typeof v === "object") yield [n, localDir(n, v as Record<string, string | number | Record<string, unknown>>)];
        else {
          const f: LocalFileLike = {
            kind: "file",
            name: n,
            getFile: async () =>
              typeof v === "number"
                ? ({ name: n, size: v } as unknown as File) // size only: never read
                : new File([v], n),
          };
          yield [n, f];
        }
      }
    },
  };
}

describe("planLocalCopy (docs/77 phase 2, Send folder)", () => {
  it("lists the local tree with sizes and skips what the agent would refuse", async () => {
    const plan = await planLocalCopy(
      localDir("Picked", { "a.txt": "alpha", sub: { "b.txt": "bravo", deep: { "c.txt": "c" } }, "big.iso": MAX_UPLOAD_BYTES + 1 }),
    );
    expect(plan.files.map((f) => f.rel.join("/"))).toEqual(["a.txt", "sub/b.txt", "sub/deep/c.txt"]);
    expect(plan.dirs.map((d) => d.join("/"))).toEqual(["sub", "sub/deep"]);
    expect(plan.totalBytes).toBe(11);
    expect(plan.skipped).toEqual([{ path: "big.iso", reason: "over 128 MiB" }]);
  });
});