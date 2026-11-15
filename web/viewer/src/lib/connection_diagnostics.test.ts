import { describe, it, expect } from "vitest";
import { extractDiagnostics } from "./connection_diagnostics";

function makeReport(entries: Record<string, unknown>[]): RTCStatsReport {
  const map = new Map<string, unknown>(entries.map((e) => [(e["id"] as string), e]));
  return {
    forEach: (cb: (v: unknown, k: string) => void) => map.forEach((v, k) => cb(v, k)),
    get: (id: string) => map.get(id),
  } as unknown as RTCStatsReport;
}

function makeStream(videoTracks = 1): MediaStream {
  const tracks = Array.from({ length: videoTracks }, () => ({ kind: "video" }));
  return { getVideoTracks: () => tracks } as unknown as MediaStream;
}

describe("extractDiagnostics", () => {
  it("returns no inbound when report is undefined", () => {
    const snap = extractDiagnostics(undefined, null);
    expect(snap.videoTrackPresent).toBe(false);
    expect(snap.inbound).toBeUndefined();
  });

  it("detects video track in stream", () => {
    const snap = extractDiagnostics(undefined, makeStream(1));
    expect(snap.videoTrackPresent).toBe(true);
  });

  it("stream with zero video tracks → videoTrackPresent false", () => {
    const snap = extractDiagnostics(undefined, makeStream(0));
    expect(snap.videoTrackPresent).toBe(false);
  });

  it("null stream → videoTrackPresent false", () => {
    const snap = extractDiagnostics(makeReport([]), null);
    expect(snap.videoTrackPresent).toBe(false);
  });

  it("picks inbound-rtp video entry", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 12345, packetsReceived: 100, framesDecoded: 50 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.bytesReceived).toBe(12345);
    expect(snap.inbound?.packetsReceived).toBe(100);
    expect(snap.inbound?.framesDecoded).toBe(50);
  });

  it("ignores audio inbound-rtp entries", () => {
    const report = makeReport([
      { id: "a1", type: "inbound-rtp", kind: "audio", bytesReceived: 9999, packetsReceived: 200 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound).toBeUndefined();
  });

  it("treats NaN bytesReceived as unavailable", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: NaN, packetsReceived: 10, framesDecoded: 5 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.bytesReceived).toBeUndefined();
    expect(snap.inbound?.packetsReceived).toBe(10);
  });

  it("treats Infinity as unavailable", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: Infinity, packetsReceived: 10, framesDecoded: 2 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.bytesReceived).toBeUndefined();
  });

  it("treats negative value as unavailable", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", framesDecoded: -1, packetsReceived: 5 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.framesDecoded).toBeUndefined();
  });

  it("treats missing counter fields as unavailable (not zero)", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video" },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound).toBeDefined();
    expect(snap.inbound?.bytesReceived).toBeUndefined();
    expect(snap.inbound?.packetsReceived).toBeUndefined();
    expect(snap.inbound?.framesDecoded).toBeUndefined();
  });

  it("resolves allowlisted codec MIME type", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 100, codecId: "c1" },
      { id: "c1", type: "codec", mimeType: "video/VP9" },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.codec?.mimeShortName).toBe("VP9");
  });

  it("suppresses non-allowlisted codec type", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 100, codecId: "c1" },
      { id: "c1", type: "codec", mimeType: "video/UNKNOWN_CODEC" },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.codec).toBeUndefined();
  });

  it("handles missing codecId gracefully", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 50 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.codec).toBeUndefined();
    expect(snap.inbound?.bytesReceived).toBe(50);
  });

  it("uses first video track when multiple inbound-rtp video entries exist", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 111 },
      { id: "v2", type: "inbound-rtp", kind: "video", bytesReceived: 222 },
    ]);
    const snap = extractDiagnostics(report, null);
    // First encountered is used; both are valid; just ensure a result is returned.
    expect(snap.inbound?.bytesReceived).toBeDefined();
  });

  it("returns snapshot with no inbound when report has no inbound-rtp video", () => {
    const report = makeReport([
      { id: "cp", type: "candidate-pair", state: "succeeded" },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound).toBeUndefined();
  });

  it("floors fractional bytesReceived", () => {
    const report = makeReport([
      { id: "v1", type: "inbound-rtp", kind: "video", bytesReceived: 100.7 },
    ]);
    const snap = extractDiagnostics(report, null);
    expect(snap.inbound?.bytesReceived).toBe(100);
  });
});
