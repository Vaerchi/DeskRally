import { describe, expect, it } from "vitest";
import {
  keepBothName,
  listLocal,
  LocalFolderNav,
  supportsFolderAccess,
  unsafeLocalName,
  writeLocalFile,
  type LocalDirHandle,
  type LocalFileHandle,
  type LocalWritable,
} from "./local_folder";

/** An in-memory folder tree with the handle subset local_folder uses. */
class FakeDir implements LocalDirHandle {
  readonly kind = "directory" as const;
  dirs = new Map<string, FakeDir>();
  files = new Map<string, Uint8Array>();
  failWrites = false;
  constructor(readonly name: string) {}
  async *entries(): AsyncIterable<[string, LocalDirHandle | LocalFileHandle]> {
    for (const [n, d] of this.dirs) yield [n, d];
    for (const n of this.files.keys()) yield [n, this.fileHandle(n)];
  }
  async getDirectoryHandle(name: string): Promise<LocalDirHandle> {
    const d = this.dirs.get(name);
    if (!d) throw new DOMException("not found", "NotFoundError");
    return d;
  }
  async getFileHandle(name: string, opts?: { create?: boolean }): Promise<LocalFileHandle> {
    if (!this.files.has(name)) {
      if (!opts?.create) throw new DOMException("not found", "NotFoundError");
      this.files.set(name, new Uint8Array());
    }
    return this.fileHandle(name);
  }
  private fileHandle(name: string): LocalFileHandle {
    const dir = this;
    return {
      kind: "file",
      name,
      async getFile() {
        return new File([new Uint8Array(dir.files.get(name) ?? new Uint8Array())], name, { lastModified: 1000 });
      },
      async createWritable(): Promise<LocalWritable> {
        let buf = new Uint8Array();
        let aborted = false;
        return {
          async write(data) {
            if (dir.failWrites) throw new Error("disk full");
            buf = new Uint8Array(data instanceof Blob ? await data.arrayBuffer() : (data as ArrayBuffer));
          },
          async close() {
            if (!aborted) dir.files.set(name, buf);
          },
          async abort() {
            aborted = true;
          },
        };
      },
    };
  }
}

const bytes = (s: string) => new TextEncoder().encode(s);

describe("local folder (docs/77)", () => {
  it("detects folder access by the picker's presence", () => {
    expect(supportsFolderAccess({ showDirectoryPicker: () => undefined })).toBe(true);
    expect(supportsFolderAccess({})).toBe(false);
  });

  it("refuses remote names that could escape the folder or that Windows rejects", () => {
    for (const bad of ["", ".", "..", "a/b", "a\\b", "..\\x", "CON", "nul.txt", "lpt1", "x.", "x ", "a:b", "q?"]) {
      expect(unsafeLocalName(bad), bad).not.toBeNull();
    }
    for (const ok of ["report.pdf", "a b.txt", ".gitignore", "con-notes.txt", "résumé.docx"]) {
      expect(unsafeLocalName(ok), ok).toBeNull();
    }
  });

  it("keep-both picks the first free numbered name, case-insensitively", () => {
    expect(keepBothName("report.pdf", new Set(["report.pdf"]))).toBe("report (2).pdf");
    expect(keepBothName("report.pdf", new Set(["report.pdf", "REPORT (2).PDF"]))).toBe("report (3).pdf");
    expect(keepBothName("Makefile", new Set(["Makefile"]))).toBe("Makefile (2)");
    expect(keepBothName(".env", new Set([".env"]))).toBe(".env (2)");
  });

  it("lists folders first, then files by name, with sizes", async () => {
    const root = new FakeDir("Root");
    root.files.set("b.txt", bytes("bb"));
    root.files.set("A.txt", bytes("a"));
    root.dirs.set("zeta", new FakeDir("zeta"));
    expect(await listLocal(root)).toEqual([
      { name: "zeta", isDir: true, size: null, modified: null },
      { name: "A.txt", isDir: false, size: 1, modified: 1000 },
      { name: "b.txt", isDir: false, size: 2, modified: 1000 },
    ]);
  });

  it("writes, then on a conflict replaces, keeps both or skips", async () => {
    const root = new FakeDir("Root");
    expect(await writeLocalFile(root, "r.txt", bytes("one"), "replace")).toEqual({ kind: "written", name: "r.txt" });
    expect(await writeLocalFile(root, "r.txt", bytes("two"), "skip")).toEqual({ kind: "skipped", name: "r.txt" });
    expect(new TextDecoder().decode(root.files.get("r.txt"))).toBe("one");
    expect(await writeLocalFile(root, "r.txt", bytes("three"), "keep-both")).toEqual({ kind: "written", name: "r (2).txt" });
    expect(await writeLocalFile(root, "r.txt", bytes("four"), "replace")).toEqual({ kind: "written", name: "r.txt" });
    expect(new TextDecoder().decode(root.files.get("r.txt"))).toBe("four");
  });

  it("refuses an unsafe name before touching the folder, and aborts a failed write", async () => {
    const root = new FakeDir("Root");
    await expect(writeLocalFile(root, "..\\evil.exe", bytes("x"), "replace")).rejects.toThrow(/cannot be saved/);
    expect(root.files.size).toBe(0);
    root.failWrites = true;
    await expect(writeLocalFile(root, "a.txt", bytes("x"), "replace")).rejects.toThrow(/disk full/);
    expect(root.files.get("a.txt")?.length).toBe(0); // created empty by getFileHandle, never given the partial bytes
  });

  it("navigates within the picked folder and never above it", async () => {
    const root = new FakeDir("Root");
    const sub = new FakeDir("sub");
    root.dirs.set("sub", sub);
    const nav = new LocalFolderNav(root);
    expect(nav.atRoot).toBe(true);
    await nav.enter("sub");
    expect(nav.label).toBe("Root\\sub");
    expect(nav.current).toBe(sub);
    nav.up();
    nav.up();
    expect(nav.atRoot).toBe(true);
    expect(nav.label).toBe("Root");
  });
});
