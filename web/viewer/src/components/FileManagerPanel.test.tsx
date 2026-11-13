/**
 * `FileManagerPanel` — behavioral tests for the browse-to-download integration.
 *
 * Pattern: invoke the component as a pure function, walk the React element tree, and assert on
 * what the operator would see and which callbacks fire. No DOM / jsdom needed — matches the style
 * of IncomingDownloadPrompt.test.tsx and the rest of this repo's vitest suite.
 */

import { describe, expect, it, vi } from "vitest";
import type { ReactElement } from "react";

// FileManagerPanel uses useEffect to request the drive roots on mount. When invoked as a plain
// function (no reconciler) that call throws. Mock it to a no-op so the element tree is testable.
vi.mock("react", async () => {
  const actual = await vi.importActual<typeof import("react")>("react");
  // useRef/useCallback likewise need a reconciler; as plain functions they are a box and the identity.
  return { ...actual, useEffect: () => {}, useRef: (v: unknown) => ({ current: v }), useCallback: (f: unknown) => f };
});

import { FileManagerPanel, isNoGrantRefusal } from "./FileManagerPanel";
import type { DirectoryListing, DirEntry } from "../lib/control";

// ---------- tree walker (identical pattern to IncomingDownloadPrompt.test.tsx) -----------------

type Node = ReactElement<{
  children?: unknown;
  onClick?: () => void;
  "data-testid"?: string;
  disabled?: boolean;
  title?: string;
  onChange?: (e: unknown) => void;
  onDrop?: (e: unknown) => void;
  onDragOver?: (e: unknown) => void;
}>;

function walk(node: unknown, out: Node[] = []): Node[] {
  if (Array.isArray(node)) {
    for (const child of node) walk(child, out);
    return out;
  }
  if (node && typeof node === "object" && "props" in node) {
    const n = node as Node;
    out.push(n);
    walk((n.props as { children?: unknown }).children, out);
  }
  return out;
}

const findAll = (root: unknown, testid: string) =>
  walk(root).filter((n) => n.props?.["data-testid"] === testid);

// ---------- fixtures --------------------------------------------------------------------------

const TRANSFER_DIR = "C:\\rmt-agent\\transfers";

function makeListing(path: string, entries: DirEntry[]): DirectoryListing {
  return { path, entries, truncated: false, audit: null };
}

const fileEntry = (name: string, size = 1024): DirEntry => ({
  name,
  is_dir: false,
  size,
  modified_unix: 0,
});

const dirEntry = (name: string): DirEntry => ({
  name,
  is_dir: true,
  size: 0,
  modified_unix: 0,
});

// ---------- tests --------------------------------------------------------------------------

describe("FileManagerPanel — download buttons absent without onDownloadFile", () => {
  it("shows no download buttons when onDownloadFile is not provided", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      // onDownloadFile intentionally absent
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-download-report.pdf")).toHaveLength(0);
  });
});

describe("FileManagerPanel — download buttons inside transfer directory", () => {
  it("renders a download button for a file in the transfer directory root", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    const btns = findAll(tree, "file-download-report.pdf");
    expect(btns).toHaveLength(1);
  });

  it("calls onDownloadFile with the absolute path on click", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    findAll(tree, "file-download-report.pdf")[0].props.onClick!();
    expect(onDownloadFile).toHaveBeenCalledTimes(1);
    expect(onDownloadFile).toHaveBeenCalledWith(`${TRANSFER_DIR}\\report.pdf`);
  });

  it("renders download buttons for files in a subdirectory of the transfer directory", () => {
    const onDownloadFile = vi.fn();
    const subdir = `${TRANSFER_DIR}\\incoming`;
    const tree = FileManagerPanel({
      listing: makeListing(subdir, [fileEntry("data.zip")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-download-data.zip")).toHaveLength(1);
    findAll(tree, "file-download-data.zip")[0].props.onClick!();
    expect(onDownloadFile).toHaveBeenCalledWith(`${subdir}\\data.zip`);
  });

  it("renders multiple download buttons — one per downloadable file", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("a.txt"), fileEntry("b.zip")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-download-a.txt")).toHaveLength(1);
    expect(findAll(tree, "file-download-b.zip")).toHaveLength(1);
  });
});

describe("FileManagerPanel — download buttons absent outside transfer directory", () => {
  it("does not show download buttons for files outside the transfer directory", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Users\\Ed\\Documents", [fileEntry("private.docx")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-download-private.docx")).toHaveLength(0);
  });

  it("does not show download buttons at the drive roots (empty path)", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing("", [fileEntry("C:\\")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    // Drive root entries are actually dirs rendered as folder buttons, not file rows, but even as
    // files they are outside the transfer dir so no download button should appear.
    expect(findAll(tree, "file-download-C:\\")).toHaveLength(0);
  });
});

describe("FileManagerPanel — directory entries never get download buttons", () => {
  it("does not render a download button for a directory entry, even in the transfer dir", () => {
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [dirEntry("subdir")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-download-subdir")).toHaveLength(0);
  });
});

describe("FileManagerPanel — suppresses download affordances when transferDirPath is undefined", () => {
  it("shows no download buttons when transferDirPath is not provided (no safe root known)", () => {
    // When the agent has not sent a TransferDir message we cannot safely infer a root — suppress
    // download affordances entirely rather than guessing and silently requesting the wrong file.
    const onDownloadFile = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing("C:\\rmt-agent\\transfers", [fileEntry("test.txt")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile,
      // transferDirPath intentionally absent
    });
    expect(findAll(tree, "file-download-test.txt")).toHaveLength(0);
  });
});

describe("FileManagerPanel — 'Go to Transfers' toolbar button", () => {
  it("renders the Transfers button", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\", []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-goto-transfers")).toHaveLength(1);
  });

  it("renders the Transfers button and keeps it enabled before any listing arrives", () => {
    const tree = FileManagerPanel({
      listing: undefined,
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    const btn = findAll(tree, "file-goto-transfers")[0];
    expect(btn).toBeDefined();
    expect(btn.props.disabled).toBe(false);
  });

  it("calls onNavigate with the transfer dir path when clicked", () => {
    const onNavigate = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing("C:\\", []),
      loading: false,
      onNavigate,
      transferDirPath: TRANSFER_DIR,
    });
    findAll(tree, "file-goto-transfers")[0].props.onClick!();
    expect(onNavigate).toHaveBeenCalledWith(TRANSFER_DIR);
  });

  it("is disabled when already at the transfer directory", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    const btn = findAll(tree, "file-goto-transfers")[0];
    expect(btn.props.disabled).toBe(true);
  });

  it("is not disabled when at a directory other than the transfer dir", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Users\\Ed", []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    const btn = findAll(tree, "file-goto-transfers")[0];
    expect(btn.props.disabled).toBe(false);
  });

  it("is disabled when loading, regardless of current path", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Users\\Ed", []),
      loading: true,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    const btn = findAll(tree, "file-goto-transfers")[0];
    expect(btn.props.disabled).toBe(true);
  });

  it("is disabled with an upgrade hint when transferDirPath is undefined", () => {
    const onNavigate = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing("C:\\", []),
      loading: false,
      onNavigate,
      // transferDirPath intentionally absent — older agent has not sent TransferDir
    });
    const btn = findAll(tree, "file-goto-transfers")[0];
    expect(btn.props.disabled).toBe(true);
    expect(btn.props.title).toMatch(/unknown/i);
    // onClick is guarded; even if invoked directly it must not navigate anywhere.
    btn.props.onClick!();
    expect(onNavigate).not.toHaveBeenCalled();
  });
});

describe("FileManagerPanel — completedFiles indicator", () => {
  it("shows no saved indicator when completedFiles is absent", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      // completedFiles intentionally absent
    });
    expect(findAll(tree, "file-saved-report.pdf")).toHaveLength(0);
  });

  it("shows no saved indicator when completedFiles is an empty set", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      completedFiles: new Set(),
    });
    expect(findAll(tree, "file-saved-report.pdf")).toHaveLength(0);
  });

  it("shows the saved indicator when the file rel path is in completedFiles", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      completedFiles: new Set(["report.pdf"]),
    });
    expect(findAll(tree, "file-saved-report.pdf")).toHaveLength(1);
  });

  it("shows the saved indicator even when onDownloadFile is absent (grant revoked after download)", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      // onDownloadFile intentionally absent — simulates revoked capability
      transferDirPath: TRANSFER_DIR,
      completedFiles: new Set(["report.pdf"]),
    });
    // download button absent
    expect(findAll(tree, "file-download-report.pdf")).toHaveLength(0);
    // saved indicator still present
    expect(findAll(tree, "file-saved-report.pdf")).toHaveLength(1);
  });

  it("shows saved indicator for the matching file only", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [fileEntry("done.zip"), fileEntry("pending.txt")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      completedFiles: new Set(["done.zip"]),
    });
    expect(findAll(tree, "file-saved-done.zip")).toHaveLength(1);
    expect(findAll(tree, "file-saved-pending.txt")).toHaveLength(0);
  });

  it("does not show saved indicator for files outside the transfer directory", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Users\\Ed\\Documents", [fileEntry("report.pdf")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      completedFiles: new Set(["report.pdf"]),
    });
    // File is outside the transfer dir — no download button and no indicator
    expect(findAll(tree, "file-saved-report.pdf")).toHaveLength(0);
  });

  it("shows saved indicator for files in a subdirectory of the transfer directory", () => {
    const subdir = `${TRANSFER_DIR}\\incoming`;
    const tree = FileManagerPanel({
      listing: makeListing(subdir, [fileEntry("data.zip")]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      // rel path from transfer root: "incoming/data.zip" (not just the basename)
      completedFiles: new Set(["incoming/data.zip"]),
    });
    expect(findAll(tree, "file-saved-data.zip")).toHaveLength(1);
  });
});

describe("FileManagerPanel — modification date display", () => {
  it("shows the modification date span when modified_unix is non-zero", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Documents", [
        { name: "report.pdf", is_dir: false, size: 4096, modified_unix: 1700000000 },
      ]),
      loading: false,
      onNavigate: vi.fn(),
    });
    expect(findAll(tree, "file-modified-report.pdf")).toHaveLength(1);
  });

  it("does not show the modification date span when modified_unix is 0 (unavailable)", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Documents", [fileEntry("unknown.txt")]), // fixture uses modified_unix: 0
      loading: false,
      onNavigate: vi.fn(),
    });
    expect(findAll(tree, "file-modified-unknown.txt")).toHaveLength(0);
  });

  it("shows the modification date span for the minimum valid value (modified_unix: 1)", () => {
    // Guards the boundary: the render guard is `> 0`, so 1 must show a span.
    // A mutation changing `> 0` to `> 1` would fail this test.
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Documents", [
        { name: "oldest.txt", is_dir: false, size: 0, modified_unix: 1 },
      ]),
      loading: false,
      onNavigate: vi.fn(),
    });
    expect(findAll(tree, "file-modified-oldest.txt")).toHaveLength(1);
  });

  it("shows a date span for every file with a non-zero timestamp", () => {
    const tree = FileManagerPanel({
      listing: makeListing("C:\\Documents", [
        { name: "a.pdf", is_dir: false, size: 100, modified_unix: 1700000000 },
        { name: "b.pdf", is_dir: false, size: 200, modified_unix: 1700000060 },
        { name: "c.pdf", is_dir: false, size: 300, modified_unix: 0 }, // unavailable
      ]),
      loading: false,
      onNavigate: vi.fn(),
    });
    expect(findAll(tree, "file-modified-a.pdf")).toHaveLength(1);
    expect(findAll(tree, "file-modified-b.pdf")).toHaveLength(1);
    expect(findAll(tree, "file-modified-c.pdf")).toHaveLength(0);
  });

  it("does not show modification dates for directory entries", () => {
    // Directories are navigable buttons, not metadata rows — we don't add dates to them.
    const tree = FileManagerPanel({
      listing: makeListing("C:\\", [
        { name: "Users", is_dir: true, size: 0, modified_unix: 1700000000 },
      ]),
      loading: false,
      onNavigate: vi.fn(),
    });
    expect(findAll(tree, "file-modified-Users")).toHaveLength(0);
  });

  it("shows modification date alongside size and download button for transferable files", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, [
        { name: "data.zip", is_dir: false, size: 8192, modified_unix: 1700000000 },
      ]),
      loading: false,
      onNavigate: vi.fn(),
      onDownloadFile: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    // All three metadata elements present together
    expect(findAll(tree, "file-row-data.zip")).toHaveLength(1);
    expect(findAll(tree, "file-modified-data.zip")).toHaveLength(1);
    expect(findAll(tree, "file-download-data.zip")).toHaveLength(1);
  });
});

describe("FileManagerPanel — upload into the transfer root", () => {
  const files = [new File(["a"], "a.txt"), new File(["bb"], "b.txt")];

  it("offers Upload here only when AT the transfer root (case/trailing-slash insensitive)", () => {
    const at = FileManagerPanel({
      listing: makeListing("c:\\RMT-AGENT\\transfers\\\\", []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      onUploadFiles: vi.fn(),
    });
    expect(findAll(at, "file-upload")).toHaveLength(1);
    expect(findAll(at, "file-upload-input")).toHaveLength(1);
  });

  it("does not offer upload in a subfolder of the root, elsewhere, at the drive roots, or with an unknown root", () => {
    for (const [path, tdir] of [
      [`${TRANSFER_DIR}\\sub`, TRANSFER_DIR],
      ["C:\\Users", TRANSFER_DIR],
      ["", TRANSFER_DIR],
      [TRANSFER_DIR, undefined],
    ] as const) {
      const tree = FileManagerPanel({
        listing: makeListing(path, []),
        loading: false,
        onNavigate: vi.fn(),
        transferDirPath: tdir,
        onUploadFiles: vi.fn(),
      });
      expect(findAll(tree, "file-upload"), `path=${path} tdir=${tdir}`).toHaveLength(0);
    }
  });

  it("does not offer upload without onUploadFiles (capability gate closed)", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
    });
    expect(findAll(tree, "file-upload")).toHaveLength(0);
  });

  it("hands picked files to onUploadFiles and clears the picker so the same file can be picked again", () => {
    const onUploadFiles = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      onUploadFiles,
    });
    const target = { files: files, value: "C:\\fakepath\\a.txt" };
    findAll(tree, "file-upload-input")[0].props.onChange!({ target });
    expect(onUploadFiles).toHaveBeenCalledWith(files);
    expect(target.value).toBe("");
  });

  const drop = (path: string, types: string[] = ["Files"], withUpload = true) => {
    const onUploadFiles = vi.fn();
    const tree = FileManagerPanel({
      listing: makeListing(path, []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      onUploadFiles: withUpload ? onUploadFiles : undefined,
    });
    const root = findAll(tree, "file-manager")[0];
    const ev = { preventDefault: vi.fn(), dataTransfer: { files, types, dropEffect: "unset" } };
    root.props.onDragOver!(ev);
    const effectOnDragOver = ev.dataTransfer.dropEffect;
    root.props.onDrop!(ev);
    return { onUploadFiles, ev, effectOnDragOver };
  };

  it("uploads a file drop at the root", () => {
    const atRoot = drop(TRANSFER_DIR);
    expect(atRoot.onUploadFiles).toHaveBeenCalledWith(files);
    expect(atRoot.ev.preventDefault).toHaveBeenCalledTimes(2);
    expect(atRoot.effectOnDragOver).toBe("copy");
  });

  it("CONSUMES a file drop where upload is not offered, so the browser never navigates the tab to the file", () => {
    for (const d of [drop("C:\\Users"), drop(TRANSFER_DIR, ["Files"], false)]) {
      expect(d.onUploadFiles).not.toHaveBeenCalled();
      expect(d.ev.preventDefault).toHaveBeenCalledTimes(2); // dragover AND drop: no default navigation
      expect(d.effectOnDragOver).toBe("none");
    }
  });

  it("leaves non-file drags (text, links) alone", () => {
    const text = drop(TRANSFER_DIR, ["text/plain"]);
    expect(text.onUploadFiles).not.toHaveBeenCalled();
    expect(text.ev.preventDefault).not.toHaveBeenCalled();
    expect(text.effectOnDragOver).toBe("unset");
  });

  it("lists upload rows with their phase", () => {
    const tree = FileManagerPanel({
      listing: makeListing(TRANSFER_DIR, []),
      loading: false,
      onNavigate: vi.fn(),
      transferDirPath: TRANSFER_DIR,
      uploads: [
        { id: 2, name: "b.txt", phase: "error", message: "Rejected" },
        { id: 1, name: "a.txt", phase: "ok", message: "Uploaded" },
      ],
    });
    const rows = findAll(tree, "file-upload-row-2");
    expect(rows).toHaveLength(1);
    expect((rows[0].props as { "data-phase"?: string })["data-phase"]).toBe("error");
    expect(findAll(tree, "file-upload-row-1")).toHaveLength(1);
  });
});

describe("FileManagerPanel: Get access on a secure-mode refusal (2026-11-10)", () => {
  const NO_GRANT = "no backstage grant is installed for this session";
  const base = { loading: false, onNavigate: () => {}, listing: makeListing("", []) };

  it("offers Get access on the agent's no-grant refusal and calls it", () => {
    const onGetAccess = vi.fn();
    const tree = FileManagerPanel({ ...base, error: NO_GRANT, onGetAccess });
    const btn = findAll(tree, "file-get-access");
    expect(btn).toHaveLength(1);
    btn[0].props.onClick!();
    expect(onGetAccess).toHaveBeenCalledTimes(1);
  });

  it("offers nothing for any other refusal, or when the console cannot fetch a grant", () => {
    expect(findAll(FileManagerPanel({ ...base, error: "access denied: C:\\secret", onGetAccess: vi.fn() }), "file-get-access")).toHaveLength(0);
    expect(findAll(FileManagerPanel({ ...base, error: NO_GRANT }), "file-get-access")).toHaveLength(0);
    expect(findAll(FileManagerPanel({ ...base, onGetAccess: vi.fn() }), "file-get-access")).toHaveLength(0);
  });

  it("recognises exactly the agent's wording", () => {
    expect(isNoGrantRefusal(NO_GRANT)).toBe(true);
    expect(isNoGrantRefusal(undefined)).toBe(false);
    expect(isNoGrantRefusal("grant expired")).toBe(false);
  });
});
