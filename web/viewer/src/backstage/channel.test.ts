/**
 * Backstage-over-data-channel adapter tests: request encoding to bytes, envelope decoding from
 * bytes, and that ChannelBackstageTransport drives an unchanged BackstageClient over a raw
 * send/receive channel with FIFO reply correlation.
 */

import { describe, it, expect, vi } from "vitest";

import { BackstageClient, type Envelope } from "./client";
import {
  ChannelBackstageTransport,
  decodeBackstageEnvelope,
  encodeBackstageRequest,
} from "./channel";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

const AUDIT = { hash: "a773d18032be8d72", outcome: "authorized", action: "GetSystemInfo" };

describe("backstage request/envelope codec", () => {
  it("encodes a unit-variant request as adjacently-tagged JSON bytes", () => {
    const bytes = encodeBackstageRequest({ type: "GetSystemInfo" });
    expect(JSON.parse(decoder.decode(bytes))).toEqual({ type: "GetSystemInfo" });
  });

  it("encodes a request that nests args under `data`", () => {
    const bytes = encodeBackstageRequest({
      type: "BrowseDirectory",
      data: { path: "C:\\" },
    });
    expect(JSON.parse(decoder.decode(bytes))).toEqual({
      type: "BrowseDirectory",
      data: { path: "C:\\" },
    });
  });

  it("decodes an envelope frame payload", () => {
    const env: Envelope = { ok: true, response: { type: "Ack" }, audit: AUDIT };
    const decoded = decodeBackstageEnvelope(encoder.encode(JSON.stringify(env)));
    expect(decoded.ok).toBe(true);
    expect(decoded.response).toEqual({ type: "Ack" });
    expect(decoded.audit?.hash).toBe(AUDIT.hash);
  });
});

describe("ChannelBackstageTransport driving a BackstageClient", () => {
  it("sends the request bytes and resolves the envelope from the next inbound frame", async () => {
    const sent: Uint8Array[] = [];
    const cbt = new ChannelBackstageTransport((payload) => sent.push(payload));
    const client = new BackstageClient(cbt.asBackstageTransport());

    const envelope: Envelope = {
      ok: true,
      response: { type: "SystemInfo", data: { hostname: "H" } as never },
      audit: AUDIT,
    };

    const pending = client.getSystemInfo();
    // The client should have sent exactly the request bytes on the channel.
    expect(sent).toHaveLength(1);
    expect(JSON.parse(decoder.decode(sent[0]))).toEqual({ type: "GetSystemInfo" });

    // Deliver the agent's reply frame; the pending exec resolves with the parsed envelope.
    cbt.handleMessage(encoder.encode(JSON.stringify(envelope)));
    const result = await pending;
    expect(result.ok).toBe(true);
    expect(result.response?.type).toBe("SystemInfo");
    expect(result.audit?.hash).toBe(AUDIT.hash);
  });

  it("correlates concurrent requests to replies in FIFO order", async () => {
    const cbt = new ChannelBackstageTransport(() => {});
    const client = new BackstageClient(cbt.asBackstageTransport());

    const first = client.listProcesses();
    const second = client.listServices();

    cbt.handleMessage(
      encoder.encode(JSON.stringify({ ok: true, response: { type: "ProcessList", data: [] } })),
    );
    cbt.handleMessage(
      encoder.encode(JSON.stringify({ ok: true, response: { type: "ServiceList", data: [] } })),
    );

    expect((await first).response?.type).toBe("ProcessList");
    expect((await second).response?.type).toBe("ServiceList");
  });

  it("close() rejects in-flight requests and refuses further sends (session teardown)", async () => {
    const cbt = new ChannelBackstageTransport(() => {});
    const client = new BackstageClient(cbt.asBackstageTransport());

    const inFlight = client.getSystemInfo();
    cbt.close();
    await expect(inFlight).rejects.toThrow(/closed/);

    // A request issued after teardown fails fast rather than hanging forever.
    await expect(client.listProcesses()).rejects.toThrow(/closed/);
  });
});

// docs/58 §2: correlation is by order, so a missed reply or a failed send must close the transport
// for good; a late reply must never answer a newer request.
describe("ChannelBackstageTransport closes on a missed reply or a failed send", () => {
  const ok = (n: number) => encoder.encode(JSON.stringify({ ok: true, response: { type: "Ack" }, audit: { hash: `h${n}`, outcome: "ok" } }));

  it("an overdue reply closes the transport; the late reply then answers nothing", async () => {
    vi.useFakeTimers();
    try {
      const sent: Uint8Array[] = [];
      const ch = new ChannelBackstageTransport((p) => sent.push(p), undefined, 1000);
      const client = new BackstageClient(ch.asBackstageTransport());
      const first = client.exec({ type: "GetSystemInfo" });
      vi.advanceTimersByTime(1001);
      await expect(first).rejects.toThrow(/stopped responding/);
      // A new request after the close is refused at once, with the same reason.
      await expect(client.exec({ type: "ListProcesses" })).rejects.toThrow(/stopped responding/);
      // The overdue reply finally arrives: it must not resolve anything.
      ch.handleMessage(ok(1));
      expect(sent).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("a reply in time re-arms the timer for the next request, not the first one's clock", async () => {
    vi.useFakeTimers();
    try {
      const ch = new ChannelBackstageTransport(() => {}, undefined, 1000);
      const client = new BackstageClient(ch.asBackstageTransport());
      const a = client.exec({ type: "GetSystemInfo" });
      vi.advanceTimersByTime(900);
      const b = client.exec({ type: "ListProcesses" });
      ch.handleMessage(ok(1));
      await expect(a).resolves.toMatchObject({ ok: true });
      vi.advanceTimersByTime(900); // 1800 ms after a, 900 after b's clock started
      ch.handleMessage(ok(2));
      await expect(b).resolves.toMatchObject({ ok: true });
    } finally {
      vi.useRealTimers();
    }
  });

  it("a send that throws closes the transport and rejects the request it could not send", async () => {
    let fail = false;
    const ch = new ChannelBackstageTransport(() => {
      if (fail) throw new Error("data channel is closed");
    });
    const client = new BackstageClient(ch.asBackstageTransport());
    const a = client.exec({ type: "GetSystemInfo" });
    fail = true;
    const b = client.exec({ type: "ListProcesses" });
    await expect(a).rejects.toThrow(/could not send/);
    await expect(b).rejects.toThrow(/could not send/);
    // Even if the agent answers the first request afterwards, nothing is left to answer.
    ch.handleMessage(ok(1));
    await expect(client.exec({ type: "GetSystemInfo" })).rejects.toThrow(/could not send/);
  });
});
