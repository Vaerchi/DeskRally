/**
 * docs/63 R3: the recordings model (status, provenance, flags, rows, errors), the playlist parser, the policy form,
 * and the API client's policy PUT (every field, always). Wire shapes follow control-plane/http_recording_*.go.
 */
import { describe, expect, it } from "vitest";
import { ConsoleApiClient, ConsoleApiError } from "./console_api";
import {
  PROVENANCE_CAVEAT,
  PROVENANCE_MATCHES,
  PROVENANCE_NO_STOP,
  canDownloadEvidence,
  canPlay,
  downloadUrl,
  formatBytes,
  parsePolicyForm,
  parseRecordingPage,
  parseRecordingPlaylist,
  policyToForm,
  provenanceView,
  recordingErrorMessage,
  recordingFlags,
  recordingRows,
  recordingStatus,
  segmentStreamUrl,
  turnsStorageOn,
  type PolicyForm,
  type RecordingListItem,
} from "./recordings";

const ID = "11111111-2222-3333-4444-555555555555";
const item = (over: Partial<RecordingListItem> = {}): RecordingListItem => ({
  id: ID, session_id: "s-1", machine_id: "m-1", state: "playback_ready", playable: true,
  provenance: "matches_session_audit", provenance_label: "x", segment_count: 2, declared_bytes: 5 * 1024 * 1024,
  truncated: null, dropped_frames: null, playback_error: "", evidence_complete_at: "2026-10-31T10:00:00Z",
  expires_at: "2026-11-30T10:00:00Z", machine_name: "", machine_alias: "", technician_id: "", technician_name: "",
  session_started_at: "", session_ended_at: "", ...over,
});

describe("recordingStatus", () => {
  it("words each server state, and an expired or deleted recording is EXPIRED, never missing", () => {
    expect(recordingStatus("uploading").label).toBe("Uploading");
    expect(recordingStatus("evidence_complete").label).toBe("Evidence complete");
    expect(recordingStatus("playback_ready").label).toBe("Playback ready");
    expect(recordingStatus("playback_failed").label).toBe("Playback failed");
    expect(recordingStatus("expired").label).toBe("Expired");
    expect(recordingStatus("deleted").label).toBe("Expired");
    expect(recordingStatus("lost").label).toBe("Lost");
    // "missing" is reserved for the restore state: a recording past its retention is expired, never missing.
    for (const s of ["expired", "deleted", "uploading", "evidence_complete", "playback_ready", "playback_failed"]) {
      expect(recordingStatus(s).label.toLowerCase()).not.toContain("missing");
      expect(recordingStatus(s).detail.toLowerCase()).not.toContain("missing");
    }
  });
  it("a lost recording says the file is missing after a restore, and offers neither play nor download", () => {
    const st = recordingStatus("lost");
    expect(st).toMatchObject({ label: "Lost", tone: "bad" });
    expect(st.detail).toBe("The file is missing after a restore, so it cannot be played or downloaded.");
    expect(canPlay({ state: "lost", playable: true })).toBe(false); // even if a server said playable
    expect(canDownloadEvidence("lost")).toBe(false);
    const [row] = recordingRows([item({ state: "lost", playable: false })]);
    expect(row.status.label).toBe("Lost");
    expect(row.canPlay).toBe(false);
    expect(row.canDownload).toBe(false);
  });
  it("an unknown state is shown as itself, neutral", () => {
    expect(recordingStatus("quarantined")).toMatchObject({ label: "quarantined", tone: "neutral" });
  });
});

describe("provenanceView (C4)", () => {
  it("uses the two exact C4 labels, from the machine code", () => {
    expect(provenanceView("matches_session_audit").label).toBe("Agent-signed; matches session audit");
    expect(provenanceView("no_matching_stop_event").label).toBe("Agent-signed; no matching stop event");
    expect(PROVENANCE_MATCHES).toBe("Agent-signed; matches session audit");
    expect(PROVENANCE_NO_STOP).toBe("Agent-signed; no matching stop event");
  });
  it("both tooltips say neither is independent capture verification; no label says verified", () => {
    for (const c of ["matches_session_audit", "no_matching_stop_event", "something_new", ""]) {
      const v = provenanceView(c);
      expect(v.tooltip).toContain("independent capture verification");
      expect(v.label.toLowerCase()).not.toMatch(/verified/);
    }
    expect(PROVENANCE_CAVEAT).toContain("whoever controls the endpoint's agent key can fabricate either");
  });
  it("an unrecognised code never borrows a stronger claim", () => {
    const v = provenanceView("signed_and_verified");
    expect(v.known).toBe(false);
    expect(v.label).toBe("Provenance not stated");
  });
  it("a row takes its label from the CODE, not the server's free text", () => {
    const rows = recordingRows([item({ provenance: "no_matching_stop_event", provenance_label: "Verified!" })]);
    expect(rows[0].provenance.label).toBe(PROVENANCE_NO_STOP);
  });
});

describe("flags, playability, download", () => {
  it("truncation and dropped frames are flagged; a clean recording has none", () => {
    expect(recordingFlags({ truncated: null, dropped_frames: null })).toEqual([]);
    expect(recordingFlags({ truncated: null, dropped_frames: 0 })).toEqual([]);
    expect(recordingFlags({ truncated: "queue_full", dropped_frames: 117 })).toEqual(["Truncated (queue_full)", "117 frames dropped"]);
    expect(recordingFlags({ truncated: null, dropped_frames: 1 })).toEqual(["1 frame dropped"]);
  });
  it("only a ready recording plays; the evidence ZIP exists only while the evidence does", () => {
    expect(canPlay({ state: "playback_ready", playable: true })).toBe(true);
    expect(canPlay({ state: "playback_ready", playable: false })).toBe(false);
    expect(canPlay({ state: "evidence_complete", playable: true })).toBe(false);
    expect(canPlay({ state: "expired", playable: true })).toBe(false);
    expect(["evidence_complete", "playback_ready", "playback_failed"].every(canDownloadEvidence)).toBe(true);
    expect(["uploading", "expired", "deleted", "lost"].some(canDownloadEvidence)).toBe(false);
  });
  it("formats sizes", () => {
    expect(formatBytes(512)).toBe("512 B");
    expect(formatBytes(5 * 1024 * 1024)).toBe("5.0 MiB");
    expect(formatBytes(-1)).toBe("—");
  });
});

describe("recordingRows", () => {
  it("shows what the SERVER joined, and falls back to ids (never blank) only when a value is absent", () => {
    const [a] = recordingRows([item({
      machine_name: "HOST-1", machine_alias: "Front desk", technician_id: "u-1", technician_name: "Tess Tech",
      session_started_at: "2026-10-31T09:00:00Z", session_ended_at: "2026-10-31T09:30:00Z",
    })]);
    expect(a.machine).toBe("Front desk");
    expect(a.technician).toBe("Tess Tech");
    expect(a.started).toBe("2026-10-31T09:00:00Z");
    expect(a.ended).toBe("2026-10-31T09:30:00Z");
    expect(a.size).toBe("5.0 MiB");
    const [b] = recordingRows([item({ machine_name: "HOST-1", technician_id: "u-1" })]);
    expect(b.machine).toBe("HOST-1");
    expect(b.technician).toBe("u-1");
    const [c] = recordingRows([item({ machine_id: "m-9" })]);
    expect(c.machine).toBe("m-9");
    expect(c.technician).toBe("—");
    expect(c.started).toBe("");
  });
  it("parses the joined fields from the wire, absent ones as empty", () => {
    const page = parseRecordingPage({ recordings: [{ ...item(), machine_name: "H", technician_name: "T", session_started_at: "2026-10-31T09:00:00Z" }, { ...item({ id: "x" }) }] })!;
    expect(page.recordings[0]).toMatchObject({ machine_name: "H", technician_name: "T", session_started_at: "2026-10-31T09:00:00Z", session_ended_at: "" });
    expect(page.recordings[1].machine_name).toBe("");
  });
});

describe("recordingErrorMessage", () => {
  it("states expiry as expiry and names each refusal", () => {
    expect(recordingErrorMessage(410, "expired")).toContain("expired");
    expect(recordingErrorMessage(410, "deleted").toLowerCase()).not.toContain("missing");
    expect(recordingErrorMessage(410, "lost")).toContain("missing after a restore");
    expect(recordingErrorMessage(410, "lost")).not.toContain("expired");
    expect(recordingErrorMessage(403, "")).toContain("permission");
    expect(recordingErrorMessage(503, "audit_unavailable")).toContain("audit log is unavailable");
    expect(recordingErrorMessage(409, "playback_pending")).toContain("still being prepared");
    expect(recordingErrorMessage(409, "playback_failed")).toContain("download");
    expect(recordingErrorMessage(404, "not_found")).toContain("not found");
    expect(recordingErrorMessage(500, "internal")).toContain("500");
  });
});

describe("playlist and URLs", () => {
  const body = {
    recording_id: ID, mime: 'video/webm; codecs="vp8"', total_duration_ms: 9000, provenance: "matches_session_audit",
    provenance_label: "x", provenance_note: "n", truncated: null, dropped_frames: 0,
    segments: [
      { index: 0, url: "segments/0/stream", start_ms: 0, duration_ms: 4000, width: 800, height: 600, bytes: 100 },
      { index: 1, url: "segments/1/stream", start_ms: 5000, duration_ms: 4000, width: 1024, height: 768, bytes: 100 },
    ],
  };
  it("parses the playlist and builds same-origin stream URLs", () => {
    const p = parseRecordingPlaylist(body)!;
    expect(p.segments).toHaveLength(2);
    expect(segmentStreamUrl("/cp/", ID, p.segments[1])).toBe(`/cp/recordings/${ID}/segments/1/stream`);
    expect(downloadUrl("/cp", ID)).toBe(`/cp/recordings/${ID}/download`);
  });
  it("refuses a playlist whose URL is anything but segments/N/stream (never fetched)", () => {
    for (const url of ["https://evil.test/x", "../x", "segments/1/stream?x=1", "/segments/1/stream", "segments/a/stream"]) {
      expect(parseRecordingPlaylist({ ...body, segments: [{ ...body.segments[0], url }] })).toBeNull();
    }
    expect(parseRecordingPlaylist({ ...body, segments: [] })).toBeNull();
    expect(segmentStreamUrl("/cp", "../x", { url: "segments/0/stream" })).toBeNull();
  });
  it("parses a list page and rejects a malformed row", () => {
    expect(parseRecordingPage({ recordings: [item()], next_cursor: "abc" })?.next_cursor).toBe("abc");
    expect(parseRecordingPage({ recordings: [{ nope: 1 }] })).toBeNull();
    expect(parseRecordingPage({})).toBeNull();
  });
});

describe("policy form", () => {
  const cur = { retention_days: 0, max_recording_bytes: 1024 ** 3, quota_bytes: 20 * 1024 ** 3 };
  const base = (over: Partial<PolicyForm> = {}): PolicyForm => ({ ...policyToForm(cur), ...over });

  it("the stored default reads as OFF with the stored caps", () => {
    expect(policyToForm(cur)).toEqual({ retention: "off", customDays: "", maxMiB: "1024", quotaGiB: "20" });
    expect(policyToForm({ ...cur, retention_days: 90 }).retention).toBe("90");
    expect(policyToForm({ ...cur, retention_days: 45 })).toMatchObject({ retention: "custom", customDays: "45" });
  });
  it("EVERY field is always in the body, with exactly these keys", () => {
    const r = parsePolicyForm(base({ retention: "30" }), cur);
    expect(r).toEqual({ ok: true, body: { retention_days: 30, max_recording_bytes: 1024 ** 3, quota_bytes: 20 * 1024 ** 3 } });
    const off = parsePolicyForm(base(), cur);
    expect(off.ok && Object.keys(off.body).sort()).toEqual(["max_recording_bytes", "quota_bytes", "retention_days"]);
    expect(off.ok && off.body.retention_days).toBe(0);
  });
  it("converts edited sizes and keeps an untouched, non-round stored size exact", () => {
    const r = parsePolicyForm(base({ retention: "90", maxMiB: "512", quotaGiB: "5" }), cur);
    expect(r).toEqual({ ok: true, body: { retention_days: 90, max_recording_bytes: 512 * 1024 ** 2, quota_bytes: 5 * 1024 ** 3 } });
    const odd = { retention_days: 30, max_recording_bytes: 123456789, quota_bytes: 7_654_321_000 };
    const kept = parsePolicyForm(policyToForm(odd), odd);
    expect(kept).toEqual({ ok: true, body: odd });
  });
  it("validates retention, sizes and the quota/size relation", () => {
    expect(parsePolicyForm(base({ retention: "custom", customDays: "" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "custom", customDays: "366" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "custom", customDays: "0" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "custom", customDays: "1.5" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "custom", customDays: "365" }), cur).ok).toBe(true);
    expect(parsePolicyForm(base({ retention: "30", maxMiB: "1025" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "30", maxMiB: "0" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "30", maxMiB: "abc" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "30", quotaGiB: "-1" }), cur).ok).toBe(false);
    const zeroQuota = parsePolicyForm(base({ retention: "30", quotaGiB: "0" }), cur);
    expect(zeroQuota.ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "30", maxMiB: "1024", quotaGiB: "0.5" }), cur).ok).toBe(false);
    expect(parsePolicyForm(base({ retention: "bogus" }), cur).ok).toBe(false);
  });
  it("only a change from off to a positive retention needs the storage-on confirmation", () => {
    const on = { retention_days: 30, max_recording_bytes: 1, quota_bytes: 1 };
    expect(turnsStorageOn({ retention_days: 0 }, on)).toBe(true);
    expect(turnsStorageOn({ retention_days: 30 }, { ...on, retention_days: 90 })).toBe(false);
    expect(turnsStorageOn({ retention_days: 30 }, { ...on, retention_days: 0 })).toBe(false);
    expect(turnsStorageOn({ retention_days: 0 }, { ...on, retention_days: 0 })).toBe(false);
  });
});

describe("ConsoleApiClient recordings", () => {
  const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { "content-type": "application/json" } });
  it("PUT /tenant/recording-policy sends exactly the three fields, nothing extra", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const client = new ConsoleApiClient({
      baseUrl: "/cp",
      cookies: () => "rmt_csrf=tok",
      fetch: ((url: string, init?: RequestInit) => {
        calls.push({ url, init });
        return Promise.resolve(json({ retention_days: 30, max_recording_bytes: 1, quota_bytes: 2, enabled: true, storage_available: true }));
      }) as never,
    });
    const out = await client.setRecordingPolicy({
      retention_days: 30, max_recording_bytes: 1, quota_bytes: 2, enabled: true, storage_available: true,
    } as never);
    expect(out.enabled).toBe(true);
    expect(calls[0].url).toBe("/cp/tenant/recording-policy");
    expect(calls[0].init?.method).toBe("PUT");
    expect(JSON.parse(String(calls[0].init?.body))).toEqual({ retention_days: 30, max_recording_bytes: 1, quota_bytes: 2 });
  });
  it("a refusal carries the server's error code and status", async () => {
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: (() => Promise.resolve(json({ error: "playback_pending" }, 409))) as never });
    const err = (await client.getRecordingPlaylist(ID).catch((e) => e)) as ConsoleApiError;
    expect(err).toBeInstanceOf(ConsoleApiError);
    expect(err.status).toBe(409);
    expect(err.code).toBe("playback_pending");
  });
  it("lists with the filters as query parameters", async () => {
    const urls: string[] = [];
    const client = new ConsoleApiClient({ baseUrl: "/cp", fetch: ((u: string) => { urls.push(u); return Promise.resolve(json({ recordings: [], next_cursor: "" })); }) as never });
    await client.listRecordings({ limit: 50, cursor: "c1", sessionId: "s" });
    expect(urls[0]).toBe("/cp/recordings?limit=50&cursor=c1&session_id=s");
  });
});
