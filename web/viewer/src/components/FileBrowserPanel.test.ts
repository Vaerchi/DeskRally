import { describe, expect, it } from "vitest";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { FileBrowserPanel, SILENT_OPERATIONS_NOTE, joinPath, type FileManageActions } from "./FileBrowserPanel";
import { dequeueConfirm, describePendingFileOp, placeableDestination } from "./BackstagePanels";

const LISTING = {
  path: "D:\\work",
  entries: [
    { name: "old.txt", is_dir: false, is_symlink: false, size_bytes: 3, modified_unix_ms: 0 },
    { name: "sub", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: 0 },
  ],
};
const MANAGE: FileManageActions = { onNewFolder: () => {}, onRename: () => {}, onDelete: () => {} };

describe("FileBrowserPanel file management (docs/58)", () => {
  it("is read-only without `manage`", () => {
    const html = renderToStaticMarkup(createElement(FileBrowserPanel, { listing: LISTING }));
    expect(html).not.toContain("files-new-folder");
    expect(html).not.toContain("files-delete-");
  });

  it("offers New folder, Rename and Delete per row, with the silent-operations note", () => {
    const html = renderToStaticMarkup(createElement(FileBrowserPanel, { listing: LISTING, manage: MANAGE }));
    expect(html).toContain('data-testid="files-new-folder"');
    expect(html).toContain('data-testid="files-rename-old.txt"');
    expect(html).toContain('data-testid="files-delete-sub"');
    expect(html).toContain(SILENT_OPERATIONS_NOTE.slice(0, 40));
  });

  it("never offers management in the drive list", () => {
    const drives = { path: "", entries: [{ name: "C:\\", is_dir: true, is_symlink: false, size_bytes: null, modified_unix_ms: null }] };
    const html = renderToStaticMarkup(createElement(FileBrowserPanel, { listing: drives, manage: MANAGE }));
    expect(html).not.toContain("files-new-folder");
    expect(html).not.toContain("files-delete-");
  });

  it("joins names onto the listed folder", () => {
    expect(joinPath("D:\\work", "a")).toBe("D:\\work\\a");
    expect(joinPath("D:\\", "a")).toBe("D:\\a");
  });
});

describe("describePendingFileOp", () => {
  it("shows the RESOLVED path the agent reported and its reason", () => {
    const pending = {
      ok: false,
      error: { kind: "needs_confirmation" as const, message: "action requires confirmation: deleting cannot be undone", confirm_token: "t" },
      audit: { hash: "h", outcome: "denied", action: { kind: "file_delete", path: "D:\\Work\\OLD.TXT" } },
    };
    expect(describePendingFileOp(pending as never, "fallback")).toBe("D:\\Work\\OLD.TXT (deleting cannot be undone)");
  });
  it("shows both ends of a rename, and falls back to the typed target", () => {
    const rename = { ok: false, error: { kind: "needs_confirmation" as const, message: "x" }, audit: { hash: "h", outcome: "denied", action: { kind: "file_rename", from: "a", to: "b" } } };
    expect(describePendingFileOp(rename as never, "f")).toBe("a → b (x)");
    expect(describePendingFileOp({ ok: false } as never, "typed")).toBe("typed");
  });
});

describe("Upload here (docs/58 §12)", () => {
  it("is offered only when the container gives onUploadHere", () => {
    const without = renderToStaticMarkup(createElement(FileBrowserPanel, { listing: LISTING, manage: MANAGE }));
    expect(without).not.toContain("files-upload-here");
    const withIt = renderToStaticMarkup(
      createElement(FileBrowserPanel, { listing: LISTING, manage: { ...MANAGE, onUploadHere: () => {} } }),
    );
    expect(withIt).toContain('data-testid="files-upload-here"');
  });

  it("refuses a destination off drive C: before anything is uploaded", () => {
    const BS = String.fromCharCode(92); // a backslash, never typed as an escape
    expect(placeableDestination(`C:${BS}Users${BS}x`)).toBeNull();
    expect(placeableDestination(`c:${BS}`)).toBeNull();
    expect(placeableDestination(`D:${BS}work`)).toMatch(/drive C:/);
    expect(placeableDestination("")).toMatch(/drive C:/);
  });
});

describe("dequeueConfirm (concurrent confirmations, Codex phase B review)", () => {
  it("answers each pending confirmation in turn, so none is lost", () => {
    const a = { description: "place a" };
    const b = { description: "place b" };
    const c = { description: "place c" };
    let q = [a, b, c];
    q = dequeueConfirm(q, a);
    expect(q).toEqual([b, c]);
    q = dequeueConfirm(q, b);
    expect(q).toEqual([c]);
    q = dequeueConfirm(q, c);
    expect(q).toEqual([]);
  });

  it("ignores a stale second answer for one already removed", () => {
    const a = { description: "a" };
    const b = { description: "b" };
    expect(dequeueConfirm([b], a)).toEqual([b]);
  });
});
