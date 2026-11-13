import { expect, it, vi } from "vitest";
import { FileTransferClient, encodeMessage } from "./file_transfer";

const id = "11111111-2222-3333-4444-555555555555";

it.each([true, false])("cleans rejected peer names before the error observer (approval observer=%s)", observesApproval => {
  const onDownloadError = vi.fn();
  const client = new FileTransferClient(() => {}, () => {}, () => {}, {
    onDownloadError,
    ...(observesApproval ? { onPendingDownloadsChanged: () => {} } : {}),
  });
  try {
    client.handleMessage(encodeMessage({ t: "Offer", c: {
      id, name: "report\u202Egnp.exe\u202C\n\u2066確認\u2069-👩‍💻.txt",
      size: -1, sha256: "0".repeat(64),
    } }));
    expect(onDownloadError).toHaveBeenCalledExactlyOnceWith({
      id, name: "reportgnp.exe確認-👩‍💻.txt",
      reason: observesApproval ? "invalid offer size" : "unsolicited download refused",
    });
  } finally { client.dispose(); }
});

it("cleans a retained offer name when incomplete completion aborts the transfer", () => {
  const onDownloadError = vi.fn();
  const client = new FileTransferClient(() => {}, () => {}, () => {}, {
    onDownloadError, onPendingDownloadsChanged: () => {},
  });
  try {
    client.handleMessage(encodeMessage({ t: "Offer", c: {
      id, name: "safe\u202Egnp.exe\u202C", size: 1, sha256: "0".repeat(64),
    } }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    expect(onDownloadError).toHaveBeenCalledExactlyOnceWith({
      id, name: "safegnp.exe", reason: "declared size not met",
    });
  } finally { client.dispose(); }
});
