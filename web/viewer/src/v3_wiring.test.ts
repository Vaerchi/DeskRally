/**
 * V3 App wiring contract: file-transfer + clipboard over the live session.
 *
 * `App.tsx` extends its single `onMessage(channel, payload)` router to feed `ChannelId.FileTransfer`
 * frames to a `FileTransferClient` and `ChannelId.Clipboard` frames to a `ClipboardClient`, alongside
 * the existing Control/Backstage routing — with no channel consuming another's frames. It also builds
 * those clients so `send` frames onto the transport. App is `.tsx` and the vitest env is `node`, so
 * (following `backstage/app_routing.test.ts`) rather than render the component we exercise the exact
 * routing + client usage the panels rely on:
 *
 *  - the **FileTransferPanel** uploads a file exactly as `client.upload(name, bytes)` — asserted here
 *    to emit the agent-visible `Offer`→`Chunk`s→`Done` frames and resolve on the agent's `Ack`, and
 *    to emit a `Request` frame for a download whose reassembled bytes reach `onDownload`;
 *  - the **ClipboardControl** pushes via `client.sendText()` — asserted to frame the local clipboard
 *    text out, and inbound clipboard frames to apply to the local clipboard through the router.
 */

import { describe, it, expect } from "vitest";

import { ChannelId } from "./lib";
import {
  FileTransferClient,
  decodeMessage as decodeFt,
  encodeMessage as encodeFt,
  chunkFile,
  sha256Hex,
  type Message as FtMessage,
} from "./lib/file_transfer";
import {
  ClipboardClient,
  decodeMessage as decodeClip,
  encodeMessage as encodeClip,
  text as clipText,
  type ClipboardApi,
  type ClipboardMessage,
} from "./lib/clipboard";

/** An in-memory fake `navigator.clipboard` (mirrors the one in clipboard.test.ts). */
class FakeClipboard implements ClipboardApi {
  value = "";
  readonly writes: string[] = [];
  async readText(): Promise<string> {
    return this.value;
  }
  async writeText(t: string): Promise<void> {
    this.value = t;
    this.writes.push(t);
  }
}

interface CompletedDownload {
  name: string;
  bytes: Uint8Array;
  verified: boolean;
  seq: number;
}

/** Build the two V3 clients + the App-shaped router exactly as `App.tsx` composes them. */
function wire() {
  const ftSent: Uint8Array[] = [];
  const clipSent: Uint8Array[] = [];
  const downloads: CompletedDownload[] = [];
  let downloadSeq = 0;

  const fileTransfer = new FileTransferClient(
    (payload) => ftSent.push(payload),
    (file) => downloads.push({ name: file.name, bytes: file.bytes, verified: file.verified, seq: ++downloadSeq }),
  );
  const fakeClipboard = new FakeClipboard();
  const clipboard = new ClipboardClient((payload) => clipSent.push(payload), fakeClipboard);

  // Byte-for-byte the routing in App.tsx's `onMessage`.
  const route = (channel: ChannelId, payload: Uint8Array) => {
    if (channel === ChannelId.FileTransfer) fileTransfer.handleMessage(payload);
    else if (channel === ChannelId.Clipboard) void clipboard.handleMessage(payload);
  };

  return { route, fileTransfer, clipboard, fakeClipboard, ftSent, clipSent, downloads };
}

describe("V3 file-transfer wiring (panel upload/download over a fake channel)", () => {
  it("upload emits Offer→Chunks→Done with the file's size + sha and resolves on the agent Ack", async () => {
    const { fileTransfer, ftSent } = wire();
    const bytes = new Uint8Array(100_000).map((_, i) => (i * 13) % 256);
    const expectedSha = await sha256Hex(bytes);

    // The panel reads File.arrayBuffer() then calls upload(name, bytes) — replicate that exactly.
    const ackPromise = fileTransfer.upload("report.bin", bytes);
    // upload awaits the async SHA-256 before emitting Offer→Chunks→Done; poll for Done rather than a
    // fixed delay (flakes under load).
    for (let i = 0; i < 200 && !ftSent.some((p) => decodeFt(p).t === "Done"); i++) await new Promise((r) => setTimeout(r, 5));

    const msgs = ftSent.map((p) => decodeFt(p));
    expect(msgs[0].t).toBe("Offer");
    expect(msgs[msgs.length - 1].t).toBe("Done");
    const offer = msgs[0];
    if (offer.t !== "Offer") throw new Error("first frame must be an Offer");
    expect(offer.c.name).toBe("report.bin");
    expect(offer.c.size).toBe(bytes.length);
    expect(offer.c.sha256).toBe(expectedSha);

    // Chunks are in-order, gap-free, and reassemble to the original bytes.
    const chunks = msgs.flatMap((m) => (m.t === "Chunk" ? [m.c] : []));
    expect(chunks.map((c) => c.seq)).toEqual(chunks.map((_, i) => i));
    const total = chunks.reduce((n, c) => n + c.data.length, 0);
    expect(total).toBe(bytes.length);

    // Agent commits → Ack{ok:true} resolves the upload the panel awaits.
    const ftAck: FtMessage = { t: "Ack", c: { id: offer.c.id, ok: true, message: "" } };
    fileTransfer.handleMessage(encodeFt(ftAck));
    await expect(ackPromise).resolves.toEqual({ ok: true, message: "" });
  });

  it("a rejected upload surfaces the agent's Ack{ok:false} message", async () => {
    const { fileTransfer, ftSent } = wire();
    const ackPromise = fileTransfer.upload("x.bin", new Uint8Array([1, 2, 3]));
    for (let i = 0; i < 200 && ftSent.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    const offer = decodeFt(ftSent[0]);
    if (offer.t !== "Offer") throw new Error("expected Offer");
    fileTransfer.handleMessage(
      encodeFt({ t: "Ack", c: { id: offer.c.id, ok: false, message: "sha256 mismatch" } }),
    );
    await expect(ackPromise).resolves.toEqual({ ok: false, message: "sha256 mismatch" });
  });

  it("download: request(path) frames a Request, and the reassembled bytes reach onDownload (verified)", async () => {
    const { fileTransfer, route, ftSent, downloads } = wire();

    fileTransfer.request("logs/agent.txt");
    const req = decodeFt(ftSent[0]);
    expect(req.t).toBe("Request");
    if (req.t !== "Request") throw new Error("expected Request");
    expect(req.c.path).toBe("logs/agent.txt");

    // Agent replies Offer→Chunks→Done on ChannelId.FileTransfer; drive it through the App router.
    const data = new Uint8Array(60_000).map((_, i) => (i * 5) % 256);
    const sha = await sha256Hex(data);
    const id = req.c.id;
    route(ChannelId.FileTransfer, encodeFt({ t: "Offer", c: { id, name: "agent.txt", size: data.length, sha256: sha } }));
    for (const c of chunkFile(id, data)) route(ChannelId.FileTransfer, encodeFt({ t: "Chunk", c }));
    route(ChannelId.FileTransfer, encodeFt({ t: "Done", c: { id } }));
    // finishDownload's SHA-256 is async + fire-and-forget; poll rather than bet on one macrotask
    // (a fixed setTimeout(0) flakes under load — see file_transfer.test.ts).
    for (let i = 0; i < 200 && downloads.length === 0; i++) await new Promise((r) => setTimeout(r, 5));

    expect(downloads).toHaveLength(1);
    expect(downloads[0].name).toBe("agent.txt");
    expect(downloads[0].bytes).toEqual(data);
    expect(downloads[0].verified).toBe(true);
    expect(downloads[0].seq).toBe(1); // App bumps the seq so the panel saves each once
  });
});

describe("V3 clipboard wiring (control push + inbound apply over the router)", () => {
  it("sendText() frames the local clipboard out on ChannelId.Clipboard", async () => {
    const { clipboard, fakeClipboard, clipSent } = wire();
    fakeClipboard.value = "console → agent secret";

    const sent = await clipboard.sendText();
    expect(sent).toBe("console → agent secret");
    expect(clipSent).toHaveLength(1);
    expect(decodeClip(clipSent[0])).toEqual<ClipboardMessage>({ t: "Text", c: "console → agent secret" });
  });

  it("inbound clipboard frames leave the local clipboard alone before consent", async () => {
    const { route, fakeClipboard } = wire();
    fakeClipboard.value = "operator value";
    route(ChannelId.Clipboard, encodeClip(clipText("unsolicited value")));
    await Promise.resolve();
    expect(fakeClipboard.value).toBe("operator value");
    expect(fakeClipboard.writes).toEqual([]);
  });

  it("inbound ChannelId.Clipboard frames apply text after explicit consent", async () => {
    const { route, fakeClipboard, clipboard } = wire();
    clipboard.setReceiveEnabled(true);
    route(ChannelId.Clipboard, encodeClip(clipText("from the agent 🦀")));
    await new Promise((r) => setTimeout(r, 0)); // handleMessage is async (writeText)
    expect(fakeClipboard.value).toBe("from the agent 🦀");
    expect(fakeClipboard.writes).toEqual(["from the agent 🦀"]);
  });

  it("does not bounce the agent's own text back (echo suppression across the router)", async () => {
    const { route, clipboard, clipSent } = wire();
    clipboard.setReceiveEnabled(true);
    route(ChannelId.Clipboard, encodeClip(clipText("agent value")));
    await new Promise((r) => setTimeout(r, 0));
    // An opportunistic push after applying inbound text must not re-send the same value.
    expect(await clipboard.sendText()).toBeNull();
    expect(clipSent).toEqual([]);
  });
});
