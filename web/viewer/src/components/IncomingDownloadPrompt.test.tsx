/**
 * `IncomingDownloadPrompt` tests. This repo's `vitest` runs in Node without a DOM (no
 * jsdom/@testing-library available), so tests invoke the component as a pure function and inspect
 * the returned React element tree — enough to assert what the operator sees + the round-trip that
 * Save/Dismiss buttons make into the current `FileTransferClient`.
 */

import { describe, expect, it, vi } from "vitest";
import { IncomingDownloadPrompt } from "./IncomingDownloadPrompt";
import type { FileTransferClient, PendingDownloadMeta } from "../lib/file_transfer";
import type { ReactElement } from "react";

type Node = ReactElement<{ children?: unknown; onClick?: () => void; "data-testid"?: string }>;

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

function fakeClient(): FileTransferClient {
  return {
    approveDownload: vi.fn(),
    dismissDownload: vi.fn(),
  } as unknown as FileTransferClient;
}

const meta = (over: Partial<PendingDownloadMeta> = {}): PendingDownloadMeta => ({
  id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  name: "invoice.pdf",
  size: 4096,
  ...over,
});

describe("IncomingDownloadPrompt", () => {
  it("renders nothing when no client is present", () => {
    expect(IncomingDownloadPrompt({ client: undefined, pending: [meta()] })).toBeNull();
  });

  it("renders nothing when the pending list is empty", () => {
    expect(IncomingDownloadPrompt({ client: fakeClient(), pending: [] })).toBeNull();
  });

  it("Save button calls approveDownload once for the row's id", () => {
    const client = fakeClient();
    const tree = IncomingDownloadPrompt({ client, pending: [meta({ id: "id-1" }), meta({ id: "id-2" })] });
    const saves = findAll(tree, "incoming-download-save");
    expect(saves).toHaveLength(2);
    saves[0].props.onClick!();
    expect(client.approveDownload).toHaveBeenCalledTimes(1);
    expect(client.approveDownload).toHaveBeenCalledWith("id-1");
  });

  it("Dismiss button calls dismissDownload for the row's id", () => {
    const client = fakeClient();
    const tree = IncomingDownloadPrompt({ client, pending: [meta({ id: "id-x" })] });
    findAll(tree, "incoming-download-dismiss")[0].props.onClick!();
    expect(client.dismissDownload).toHaveBeenCalledWith("id-x");
  });

  it("displays the sanitized name inside an isolating bdi", () => {
    const tree = IncomingDownloadPrompt({
      client: fakeClient(),
      pending: [meta({ name: "invoice.pdf" })],
    });
    const names = findAll(tree, "incoming-download-name");
    expect(names).toHaveLength(1);
    expect((names[0] as unknown as { type: unknown }).type).toBe("bdi");
    expect(names[0].props.children).toBe("invoice.pdf");
  });
});
