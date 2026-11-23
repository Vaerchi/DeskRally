/**
 * File-transfer codec + client tests — pins `encodeMessage` to the exact canonical JSON the Rust
 * `crates/agent-core/src/file_transfer.rs` unit tests assert (byte-for-byte the same literals), plus
 * a binary chunk round-trip with real bytes and a minimal upload/download client exercise.
 */

import { describe, it, expect } from "vitest";
import {
  encodeMessage,
  decodeMessage,
  chunkFile,
  uuidToBytes,
  bytesToUuid,
  CHUNK_TAG,
  CONTROL_TAG,
  MAX_CHUNK_DATA,
  FileTransferClient,
  type Message,
} from "./file_transfer";

const ID = "550e8400-e29b-41d4-a716-446655440000";
const dec = (u: Uint8Array) => new TextDecoder().decode(u);

describe("file-transfer control codec (wire-compat with Rust file_transfer.rs)", () => {
  it("Audit → adjacently-tagged JSON (byte-identical to the Rust audit_round_trips test)", () => {
    const msg: Message = {
      t: "Audit",
      c: { id: ID, event: { action: { direction: "input", kind: "file_transfer" }, hash: "abc", seq: 3 } },
    };
    const bytes = encodeMessage(msg);
    expect(bytes[0]).toBe(CONTROL_TAG);
    expect(dec(bytes)).toBe(
      `{"t":"Audit","c":{"id":"${ID}","event":{"action":{"direction":"input","kind":"file_transfer"},"hash":"abc","seq":3}}}`,
    );
    expect(decodeMessage(bytes)).toEqual(msg);
  });

  it("Offer → adjacently-tagged JSON", () => {
    const msg: Message = { t: "Offer", c: { id: ID, name: "a.bin", size: 1048576, sha256: "deadbeef" } };
    const bytes = encodeMessage(msg);
    expect(bytes[0]).toBe(CONTROL_TAG); // '{'
    expect(dec(bytes)).toBe(
      `{"t":"Offer","c":{"id":"${ID}","name":"a.bin","size":1048576,"sha256":"deadbeef"}}`,
    );
    expect(decodeMessage(bytes)).toEqual(msg);
  });

  it("Done → id only", () => {
    const bytes = encodeMessage({ t: "Done", c: { id: ID } });
    expect(dec(bytes)).toBe(`{"t":"Done","c":{"id":"${ID}"}}`);
  });

  it("Ack → ok + message (both success and failure)", () => {
    expect(dec(encodeMessage({ t: "Ack", c: { id: ID, ok: true, message: "" } }))).toBe(
      `{"t":"Ack","c":{"id":"${ID}","ok":true,"message":""}}`,
    );
    expect(
      dec(encodeMessage({ t: "Ack", c: { id: ID, ok: false, message: "sha256 mismatch" } })),
    ).toBe(`{"t":"Ack","c":{"id":"${ID}","ok":false,"message":"sha256 mismatch"}}`);
  });

  it("Request → path (mirrors download request)", () => {
    expect(dec(encodeMessage({ t: "Request", c: { id: ID, path: "sub/a.bin" } }))).toBe(
      `{"t":"Request","c":{"id":"${ID}","path":"sub/a.bin"}}`,
    );
  });

  it("Error → message", () => {
    expect(dec(encodeMessage({ t: "Error", c: { id: ID, message: "not found" } }))).toBe(
      `{"t":"Error","c":{"id":"${ID}","message":"not found"}}`,
    );
  });
});

describe("file-transfer binary chunk codec", () => {
  it("round-trips a chunk with real bytes (incl. an 0x7B byte in the data)", () => {
    // A 0x7B byte inside the data must not confuse dispatch (which keys on the FIRST byte = 0x01).
    const data = new Uint8Array([0x7b, 0x00, 0xff, 0x10, 0x7b, 0x42, 0x99]);
    const bytes = encodeMessage({ t: "Chunk", c: { id: ID, seq: 258, data } });
    expect(bytes[0]).toBe(CHUNK_TAG); // 0x01
    expect(bytes.slice(1, 17)).toEqual(uuidToBytes(ID));
    // seq 258 big-endian = 00 00 01 02
    expect(Array.from(bytes.slice(17, 21))).toEqual([0x00, 0x00, 0x01, 0x02]);
    expect(bytes.slice(21)).toEqual(data);
    const back = decodeMessage(bytes);
    expect(back).toEqual({ t: "Chunk", c: { id: ID, seq: 258, data } });
  });

  it("uuid <-> bytes is a faithful round-trip", () => {
    expect(bytesToUuid(uuidToBytes(ID))).toBe(ID);
  });

  it("decode rejects garbage tags and truncated chunks", () => {
    expect(() => decodeMessage(new Uint8Array(0))).toThrow();
    expect(() => decodeMessage(new Uint8Array([0x02, 1, 2]))).toThrow();
    expect(() => decodeMessage(new Uint8Array([CHUNK_TAG, 1, 2, 3]))).toThrow();
  });
});

describe("chunkFile", () => {
  it("splits into ≤48KiB ordered chunks and reassembles", () => {
    const data = new Uint8Array(MAX_CHUNK_DATA * 2 + 123).map((_, i) => i % 251);
    const chunks = chunkFile(ID, data);
    expect(chunks.length).toBe(3);
    expect(chunks.map((c) => c.seq)).toEqual([0, 1, 2]);
    const back = new Uint8Array(data.length);
    let off = 0;
    for (const c of chunks) {
      expect(c.data.length).toBeLessThanOrEqual(MAX_CHUNK_DATA);
      back.set(c.data, off);
      off += c.data.length;
    }
    expect(back).toEqual(data);
    expect(chunkFile(ID, new Uint8Array(0)).length).toBe(0); // empty file → no chunks
  });
});

describe("FileTransferClient", () => {
  it("upload emits Offer→Chunks→Done and resolves on Ack", async () => {
    const sent: Message[] = [];
    const client = new FileTransferClient((payload) => sent.push(decodeMessage(payload)));
    const data = new Uint8Array(MAX_CHUNK_DATA + 10).map((_, i) => i % 256);

    const ackPromise = client.upload("blob.bin", data);
    // upload() awaits the async SHA-256 digest before emitting frames; poll for Done rather than a
    // fixed delay (flakes under load).
    for (let i = 0; i < 200 && !sent.some((m) => m.t === "Done"); i++) await new Promise((r) => setTimeout(r, 5));

    // Offer first, Done last, chunks in between (2 chunks for size > MAX_CHUNK_DATA).
    expect(sent[0].t).toBe("Offer");
    expect(sent[sent.length - 1].t).toBe("Done");
    const chunks = sent.filter((m) => m.t === "Chunk");
    expect(chunks.length).toBe(2);
    const offer = sent[0];
    expect(offer.t === "Offer" && offer.c.size).toBe(data.length);
    const id = offer.t === "Offer" ? offer.c.id : "";

    // Feed back an Ack to resolve the upload.
    client.handleMessage(encodeMessage({ t: "Ack", c: { id, ok: true, message: "" } }));
    await expect(ackPromise).resolves.toEqual({ ok: true, message: "" });
  });

  it("an upload the agent answers with an Error (no Ack) settles as failed, without echoing the peer's text", async () => {
    const sent: Message[] = [];
    const client = new FileTransferClient((payload) => sent.push(decodeMessage(payload)));
    const ackPromise = client.upload("big.bin", new Uint8Array([1, 2, 3]));
    for (let i = 0; i < 200 && !sent.some((m) => m.t === "Done"); i++) await new Promise((r) => setTimeout(r, 5));
    const offer = sent[0];
    const id = offer.t === "Offer" ? offer.c.id : "";

    // The agent refuses at Offer time (limit, disk, .part creation) with an Error, never an Ack.
    client.handleMessage(encodeMessage({ t: "Error", c: { id, message: "<b>peer-controlled text</b>" } }));
    const res = await ackPromise;
    expect(res.ok).toBe(false);
    expect(res.message).not.toContain("peer-controlled");

    // A late Ack for the same id changes nothing (the promise already settled; no throw).
    client.handleMessage(encodeMessage({ t: "Ack", c: { id, ok: true, message: "" } }));
  });

  it("an Error for some OTHER id leaves a pending upload pending", async () => {
    const sent: Message[] = [];
    const client = new FileTransferClient((payload) => sent.push(decodeMessage(payload)));
    let settled = false;
    void client.upload("a.bin", new Uint8Array([1])).then(() => (settled = true));
    for (let i = 0; i < 200 && !sent.some((m) => m.t === "Done"); i++) await new Promise((r) => setTimeout(r, 5));
    client.handleMessage(encodeMessage({ t: "Error", c: { id: "00000000-0000-4000-8000-000000000001", message: "x" } }));
    await new Promise((r) => setTimeout(r, 10));
    expect(settled).toBe(false);
    client.dispose();
  });

  it("hands an inbound Audit record to onAudit without disturbing an in-flight download (ADR-008)", async () => {
    const data = new Uint8Array(64).map((_, i) => i);
    const { sha256Hex } = await import("./file_transfer");
    const sha = await sha256Hex(data);
    const id = "11111111-2222-3333-4444-555555555555";

    const audits: unknown[] = [];
    let got: { name: string; bytes: Uint8Array; verified: boolean } | undefined;
    const client = new FileTransferClient(
      () => {},
      (file) => {
        got = file;
      },
      (event) => {
        audits.push(event);
      },
    );

    // F06 explicit-approval contract: only offers matching an outstanding request() are delivered
    // without operator approval. Mint a request and reuse its id as the peer would echo it back.
    void id; // legacy fixture id — the client mints its own now
    const reqId = client.request("dl.bin");
    client.handleMessage(encodeMessage({ t: "Offer", c: { id: reqId, name: "dl.bin", size: data.length, sha256: sha } }));
    for (const c of chunkFile(reqId, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id: reqId } }));
    // The agent sends the Audit AFTER the terminal Done — it must be informational only.
    const event = { seq: 7, hash: "f".repeat(64), action: { kind: "file_transfer", direction: "output" } };
    client.handleMessage(encodeMessage({ t: "Audit", c: { id: reqId, event } }));

    for (let i = 0; i < 200 && got === undefined; i++) await new Promise((r) => setTimeout(r, 5));

    // The download still completed and verified — the trailing Audit did not abort it.
    expect(got).toBeDefined();
    expect(got!.verified).toBe(true);
    // And the event reached the forwarder hook verbatim (opaque pass-through, no reshaping: the
    // control plane re-hashes the canonical form, so any mutation here would break verification).
    expect(audits).toEqual([event]);
  });

  it("reassembles an inbound download (Offer→Chunks→Done) and verifies sha256", async () => {
    const data = new Uint8Array(MAX_CHUNK_DATA + 500).map((_, i) => (i * 7) % 256);
    // Precompute the offer the way the agent would.
    const { sha256Hex } = await import("./file_transfer");
    const sha = await sha256Hex(data);
    let got: { id: string; name: string; bytes: Uint8Array; sha256: string; verified: boolean } | undefined;
    const client = new FileTransferClient(
      () => {},
      (file) => {
        got = file;
      },
    );

    const id = client.request("dl.bin");
    client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "dl.bin", size: data.length, sha256: sha } }));
    for (const c of chunkFile(id, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    // finishDownload's SHA-256 (crypto.subtle.digest) is async and fire-and-forget from
    // handleMessage; poll for the callback rather than betting on a single macrotask, which is
    // not enough under load (a fixed setTimeout(0) flakes when the machine is busy).
    for (let i = 0; i < 200 && got === undefined; i++) await new Promise((r) => setTimeout(r, 5));

    expect(got).toBeDefined();
    expect(got!.id).toBe(id); // UUID from request() must arrive in onDownload for badge correlation
    expect(got!.name).toBe("dl.bin");
    expect(got!.bytes).toEqual(data);
    expect(got!.verified).toBe(true);
    expect(got!.sha256).toBe(sha);
  });
});

describe("a request the agent never fulfils is reported, never left waiting", () => {
  type Err = { id?: string; name?: string; reason: string };

  it("an Error before any Offer reports the requested name with our own reason", () => {
    const errors: Err[] = [];
    const client = new FileTransferClient(() => {}, () => {}, () => {}, { onDownloadError: (e) => errors.push(e) });
    const id = client.request("reports\\q3.pdf");
    client.handleMessage(encodeMessage({ t: "Error", c: { id, message: "<b>file download not permitted</b>" } }));
    expect(errors).toHaveLength(1);
    expect(errors[0].id).toBe(id);
    expect(errors[0].name).toBe("q3.pdf");
    expect(errors[0].reason).toMatch(/refused/);
    expect(errors[0].reason).not.toContain("<b>");
    // The request is gone: a late Offer for it is no longer "requested", and a repeat Error reports nothing new.
    client.handleMessage(encodeMessage({ t: "Error", c: { id, message: "again" } }));
    expect(errors).toHaveLength(1);
    client.dispose();
  });

  it("an Error for an id nobody requested reports nothing", () => {
    const errors: Err[] = [];
    const client = new FileTransferClient(() => {}, () => {}, () => {}, { onDownloadError: (e) => errors.push(e) });
    client.handleMessage(encodeMessage({ t: "Error", c: { id: "00000000-0000-4000-8000-000000000009", message: "x" } }));
    expect(errors).toHaveLength(0);
    client.dispose();
  });

  it("a request with no reply by its deadline is reported once", async () => {
    let now = 0;
    const errors: Err[] = [];
    const client = new FileTransferClient(() => {}, () => {}, () => {}, {
      onDownloadError: (e) => errors.push(e), clock: () => now, requestDeadlineMs: 20,
    });
    const id = client.request("big.iso");
    now = 25;
    for (let i = 0; i < 100 && errors.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    expect(errors).toEqual([{ id, name: "big.iso", reason: "the remote machine did not answer in time" }]);
    client.dispose();
  });

  it("a request answered with an Offer is never reported as timed out after it completes", async () => {
    const { sha256Hex } = await import("./file_transfer");
    const data = new Uint8Array([1, 2, 3, 4]);
    const sha = await sha256Hex(data);
    let now = 0;
    const errors: Err[] = [];
    let got = false;
    const client = new FileTransferClient(() => {}, () => { got = true; }, () => {}, {
      onDownloadError: (e) => errors.push(e), clock: () => now, requestDeadlineMs: 50,
    });
    const id = client.request("dl.bin");
    client.handleMessage(encodeMessage({ t: "Offer", c: { id, name: "dl.bin", size: data.length, sha256: sha } }));
    for (const c of chunkFile(id, data)) client.handleMessage(encodeMessage({ t: "Chunk", c }));
    client.handleMessage(encodeMessage({ t: "Done", c: { id } }));
    for (let i = 0; i < 200 && !got; i++) await new Promise((r) => setTimeout(r, 5));
    expect(got).toBe(true);
    now = 1_000;
    await new Promise((r) => setTimeout(r, 80));
    expect(errors).toEqual([]);
    client.dispose();
  });
});
