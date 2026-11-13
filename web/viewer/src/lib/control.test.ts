/**
 * Control codec + client tests — pins `encodeControl` to the exact canonical JSON the Rust
 * `crates/agent-core/src/control.rs` unit tests assert (byte-for-byte the same literals), plus a
 * minimal client exercise (request list, handle inbound MonitorList, surface Error).
 */

import { describe, it, expect, vi } from "vitest";
import {
  encodeControl,
  decodeControl,
  requestMonitors,
  requestQuality,
  selectMonitor,
  selectAllMonitors,
  setQuality,
  COMPOSITE_MONITOR_ID,
  installGrant,
  installSessionPolicy,
  isScreenshotName,
  listDirectory,
  recordingSummary,
  startRecording,
  stopRecording,
  ControlClient,
  type ControlMessage,
  type MonitorDesc,
  type QualitySettings,
  type CommandResult,
  type DirectoryListing,
  type RecordingResult,
} from "./control";

const dec = (u: Uint8Array) => new TextDecoder().decode(u);

describe("control codec (wire-compat with Rust control.rs)", () => {
  it("RequestMonitors → bare tag (no content)", () => {
    const bytes = encodeControl({ t: "RequestMonitors" });
    expect(dec(bytes)).toBe(`{"t":"RequestMonitors"}`);
    expect(decodeControl(bytes)).toEqual({ t: "RequestMonitors" });
  });

  it("MonitorList → adjacently-tagged JSON with serde field order", () => {
    const monitors: MonitorDesc[] = [
      { id: 0, width: 1920, height: 1080, primary: true },
      { id: 1, width: 1280, height: 1024, primary: false },
    ];
    const bytes = encodeControl({ t: "MonitorList", c: { monitors } });
    expect(dec(bytes)).toBe(
      `{"t":"MonitorList","c":{"monitors":[{"id":0,"width":1920,"height":1080,"primary":true},{"id":1,"width":1280,"height":1024,"primary":false}]}}`,
    );
    expect(decodeControl(bytes)).toEqual({ t: "MonitorList", c: { monitors } });
  });

  it("empty MonitorList round-trips", () => {
    const bytes = encodeControl({ t: "MonitorList", c: { monitors: [] } });
    expect(dec(bytes)).toBe(`{"t":"MonitorList","c":{"monitors":[]}}`);
    expect(decodeControl(bytes)).toEqual({ t: "MonitorList", c: { monitors: [] } });
  });

  it("SelectMonitor → adjacently-tagged JSON", () => {
    const bytes = encodeControl(selectMonitor(2));
    expect(dec(bytes)).toBe(`{"t":"SelectMonitor","c":{"id":2}}`);
    expect(decodeControl(bytes)).toEqual({ t: "SelectMonitor", c: { id: 2 } });
  });

  it("SelectMonitor(view-all) → same u32 wire shape as Rust COMPOSITE_MONITOR_ID", () => {
    const bytes = encodeControl(selectAllMonitors());
    // Byte-identical to the Rust `select_composite_monitor_round_trips` literal (u32::MAX).
    expect(dec(bytes)).toBe(`{"t":"SelectMonitor","c":{"id":4294967295}}`);
    expect(COMPOSITE_MONITOR_ID).toBe(4294967295);
    expect(decodeControl(bytes)).toEqual({ t: "SelectMonitor", c: { id: COMPOSITE_MONITOR_ID } });
  });

  it("Error → adjacently-tagged JSON", () => {
    const bytes = encodeControl({ t: "Error", c: { message: "unknown monitor id 7" } });
    expect(dec(bytes)).toBe(`{"t":"Error","c":{"message":"unknown monitor id 7"}}`);
    expect(decodeControl(bytes)).toEqual({ t: "Error", c: { message: "unknown monitor id 7" } });
  });

  it("requestMonitors() constructor matches the tag", () => {
    expect(requestMonitors()).toEqual({ t: "RequestMonitors" });
  });

  it("InstallGrant → adjacently-tagged JSON carrying the opaque signed-grant string (H1)", () => {
    // The signed grant is an opaque JSON string; the codec neither parses nor validates it, but the
    // inner quotes must round-trip through JSON escaping. This literal mirrors the Rust unit test.
    const signed = `{"claims":{},"sig":"ab"}`;
    const bytes = encodeControl({ t: "InstallGrant", c: { signed_grant: signed } });
    expect(dec(bytes)).toBe(`{"t":"InstallGrant","c":{"signed_grant":"{\\"claims\\":{},\\"sig\\":\\"ab\\"}"}}`);
    expect(decodeControl(bytes)).toEqual({ t: "InstallGrant", c: { signed_grant: signed } });
  });

  it("installGrant() constructor wraps the signed-grant string", () => {
    expect(installGrant(`{"sig":"x"}`)).toEqual({ t: "InstallGrant", c: { signed_grant: `{"sig":"x"}` } });
  });

  it("GrantInstalled → bare tag (no content) (H1)", () => {
    const bytes = encodeControl({ t: "GrantInstalled" });
    expect(dec(bytes)).toBe(`{"t":"GrantInstalled"}`);
    expect(decodeControl(bytes)).toEqual({ t: "GrantInstalled" });
  });

  it("RequestBackstageFeatures → bare tag; BackstageFeatures carries the list (docs/58, Rust pins the same bytes)", () => {
    const ask = encodeControl({ t: "RequestBackstageFeatures" });
    expect(dec(ask)).toBe(`{"t":"RequestBackstageFeatures"}`);
    expect(decodeControl(ask)).toEqual({ t: "RequestBackstageFeatures" });
    const answer = encodeControl({ t: "BackstageFeatures", c: { features: ["confirm", "file_manage"] } });
    expect(dec(answer)).toBe(`{"t":"BackstageFeatures","c":{"features":["confirm","file_manage"]}}`);
    expect(decodeControl(answer)).toEqual({ t: "BackstageFeatures", c: { features: ["confirm", "file_manage"] } });
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"BackstageFeatures","c":{"features":[1]}}`))).toThrow();
  });

  it("InstallSessionPolicy → adjacently-tagged JSON carrying the opaque signed policy (loops 79/80)", () => {
    // Like InstallGrant, the signed policy is an OPAQUE string forwarded verbatim: the signature covers
    // the claims, and the agent re-derives the canonical preimage from exactly these bytes, so the codec
    // must neither parse nor re-serialize it. Mirrors the Rust unit test.
    const signed = `{"claims":{},"sig":"ab"}`;
    const bytes = encodeControl({ t: "InstallSessionPolicy", c: { signed_policy: signed } });
    expect(dec(bytes)).toBe(
      `{"t":"InstallSessionPolicy","c":{"signed_policy":"{\\"claims\\":{},\\"sig\\":\\"ab\\"}"}}`,
    );
    expect(decodeControl(bytes)).toEqual({ t: "InstallSessionPolicy", c: { signed_policy: signed } });
  });

  it("installSessionPolicy() constructor wraps the signed-policy string", () => {
    expect(installSessionPolicy(`{"sig":"x"}`)).toEqual({
      t: "InstallSessionPolicy",
      c: { signed_policy: `{"sig":"x"}` },
    });
  });

  it("SessionPolicyInstalled carries the level AND the effective view-only state (loops 79/80)", () => {
    const bytes = encodeControl({
      t: "SessionPolicyInstalled",
      c: { access: "view_only", view_only: true, allow_recording: true, require_recording: false, max_session_duration_seconds: 0 },
    });
    expect(dec(bytes)).toBe(
      `{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":false,"max_session_duration_seconds":0}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      c: { access: "view_only", view_only: true, allow_recording: true, require_recording: false, max_session_duration_seconds: 0 },
    });
  });

  it("SessionPolicyInstalled keeps access and view_only INDEPENDENT", () => {
    // A "control" policy can still leave the session view-only — the agent applies a policy as a one-way
    // ratchet, so a stricter policy already in force (or the technician's own toggle) wins. Collapsing
    // these into one field would lose exactly that case.
    const bytes = encodeControl({
      t: "SessionPolicyInstalled",
      c: { access: "control", view_only: true, allow_recording: false, require_recording: false, max_session_duration_seconds: 0 },
    });
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      c: { access: "control", view_only: true, allow_recording: false, require_recording: false, max_session_duration_seconds: 0 },
    });
  });

  it("SessionPolicyInstalled require_recording=true round-trips", () => {
    // Pins that the mandatory-recording byte is present in the wire encoding and decoded correctly.
    // A viewer that receives this must auto-start recording; the agent will refuse StopRecording.
    const bytes = encodeControl({
      t: "SessionPolicyInstalled",
      c: { access: "view_only", view_only: true, allow_recording: true, require_recording: true, max_session_duration_seconds: 0 },
    });
    expect(dec(bytes)).toBe(
      `{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":true,"max_session_duration_seconds":0}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      c: { access: "view_only", view_only: true, allow_recording: true, require_recording: true, max_session_duration_seconds: 0 },
    });
  });

  it("SessionPolicyInstalled decodes an UNFAMILIAR access level rather than failing", () => {
    // `access` is a plain string on purpose: a future third level must render on an older console
    // instead of making the whole message undecodable. Pinned because switching it to a union would
    // look like a tidy-up and would silently break forward compatibility.
    const bytes = new TextEncoder().encode(
      `{"t":"SessionPolicyInstalled","c":{"access":"future_level","view_only":false}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      // allow_recording absent from old-agent wire bytes → defaults to true (permissive baseline).
      // require_recording absent from old-agent wire bytes → defaults to false (optional baseline).
      // max_session_duration_seconds absent from old-agent wire bytes → defaults to 0 (no limit).
      c: { access: "future_level", view_only: false, allow_recording: true, require_recording: false, max_session_duration_seconds: 0 },
    });
  });

  it("SessionPolicyInstalled allow_recording absent in old-agent messages defaults to true", () => {
    // Backward-compatibility: a message from an agent that predates loop 93 has no allow_recording
    // field. The decoder must supply true (allow), not false (ban). The ban is the restriction.
    const bytes = new TextEncoder().encode(
      `{"t":"SessionPolicyInstalled","c":{"access":"control","view_only":false}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      c: { access: "control", view_only: false, allow_recording: true, require_recording: false, max_session_duration_seconds: 0 },
    });
  });

  it("SessionPolicyInstalled require_recording absent in old-agent messages defaults to false", () => {
    // Backward-compatibility: a message from an agent that predates 0044 has no require_recording
    // field. The decoder must supply false (optional), not true (mandatory). Mandatory is the restriction.
    const bytes = new TextEncoder().encode(
      `{"t":"SessionPolicyInstalled","c":{"access":"control","view_only":false,"allow_recording":true}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SessionPolicyInstalled",
      c: { access: "control", view_only: false, allow_recording: true, require_recording: false, max_session_duration_seconds: 0 },
    });
  });

  it("SessionLeaseRequired round-trips byte-for-byte with the Rust encoder (docs/25 F03)", () => {
    // The SAME literal `crates/agent-core/src/control.rs`'s `session_lease_required_round_trips`
    // asserts. If these two ever disagree, a console silently stops renewing and every leased
    // session on the fleet dies at its grace deadline for a reason nobody can see.
    const bytes = encodeControl({ t: "SessionLeaseRequired", c: { renew_within_ms: 15000 } });
    expect(dec(bytes)).toBe(`{"t":"SessionLeaseRequired","c":{"renew_within_ms":15000}}`);
    expect(decodeControl(bytes)).toEqual({
      t: "SessionLeaseRequired",
      c: { renew_within_ms: 15000 },
    });
  });

  it("SessionLeaseRequired reaches its handler, because ignoring it ends the session", () => {
    // The whole renewal loop hangs off this callback. A message that decodes but is never dispatched
    // is the "feature inert at its untested layer" shape: every unit test green, every session dead
    // thirty seconds in.
    const seen: number[] = [];
    const client = new ControlClient(
      () => {},
      { onSessionLeaseRequired: (ms) => seen.push(ms) },
    );
    client.handleMessage(
      new TextEncoder().encode(`{"t":"SessionLeaseRequired","c":{"renew_within_ms":9000}}`),
    );
    expect(seen).toEqual([9000]);
  });

  it("docs/61 input-handoff messages reach their handlers, and handInputControl sends the pinned bytes", () => {
    // Decode-but-never-dispatched would leave the hand-off UI inert while every codec test stays green.
    const avail: boolean[] = [];
    const changes: Array<[string | null, string]> = [];
    const sent: Uint8Array[] = [];
    const client = new ControlClient((p) => sent.push(p), {
      onInputHandoffAvailable: (a) => avail.push(a),
      onInputControlChanged: (owner, mode) => changes.push([owner, mode]),
    });
    client.handleMessage(new TextEncoder().encode(`{"t":"InputHandoffAvailable","c":{"available":true}}`));
    client.handleMessage(
      new TextEncoder().encode(`{"t":"InputControlChanged","c":{"owner_session":"sig-b","owner_name":null,"mode":"owned"}}`),
    );
    client.handleMessage(new TextEncoder().encode(`{"t":"InputControlChanged","c":{"mode":"blocked"}}`));
    expect(avail).toEqual([true]);
    expect(changes).toEqual([["sig-b", "owned"], [null, "blocked"]]);
    client.handInputControl("11111111-2222-3333-4444-555555555555");
    expect(sent.map((b) => new TextDecoder().decode(b))).toEqual([
      `{"t":"HandInputControl","c":{"to_session":"11111111-2222-3333-4444-555555555555"}}`,
    ]);
  });

  it("decode rejects a SessionLeaseRequired with no deadline", () => {
    const enc = (t: string) => new TextEncoder().encode(t);
    expect(() => decodeControl(enc(`{"t":"SessionLeaseRequired","c":{}}`))).toThrow();
    // A STRING deadline must not sneak through: the console divides it, and "15000"/3 is NaN, which
    // would schedule a renewal that never fires.
    expect(() =>
      decodeControl(enc(`{"t":"SessionLeaseRequired","c":{"renew_within_ms":"15000"}}`)),
    ).toThrow();
  });

  it("decode rejects a malformed InstallSessionPolicy / SessionPolicyInstalled", () => {
    const enc = (t: string) => new TextEncoder().encode(t);
    expect(() => decodeControl(enc(`{"t":"InstallSessionPolicy","c":{}}`))).toThrow();
    expect(() =>
      decodeControl(enc(`{"t":"SessionPolicyInstalled","c":{"access":"control"}}`)),
    ).toThrow();
    // view_only must be a BOOLEAN — a truthy string must not sneak through as "yes it is view-only".
    expect(() =>
      decodeControl(enc(`{"t":"SessionPolicyInstalled","c":{"access":"control","view_only":"true"}}`)),
    ).toThrow();
  });

  it("decode rejects garbage and unknown variants", () => {
    expect(() => decodeControl(new Uint8Array(0))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode("not json"))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"Nope"}`))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SelectMonitor","c":{}}`))).toThrow();
    expect(() =>
      decodeControl(new TextEncoder().encode(`{"t":"MonitorList","c":{"monitors":[{"id":0}]}}`)),
    ).toThrow();
  });

  it("docs/61 input-handoff messages pin the same bytes as Rust control.rs", () => {
    const avail: ControlMessage = { t: "InputHandoffAvailable", c: { available: true } };
    expect(dec(encodeControl(avail))).toBe(`{"t":"InputHandoffAvailable","c":{"available":true}}`);
    expect(decodeControl(encodeControl(avail))).toEqual(avail);

    const hand: ControlMessage = { t: "HandInputControl", c: { to_session: "11111111-2222-3333-4444-555555555555" } };
    expect(dec(encodeControl(hand))).toBe(`{"t":"HandInputControl","c":{"to_session":"11111111-2222-3333-4444-555555555555"}}`);
    expect(decodeControl(encodeControl(hand))).toEqual(hand);

    const owned: ControlMessage = {
      t: "InputControlChanged",
      c: { owner_session: "11111111-2222-3333-4444-555555555555", owner_name: "Jordan", mode: "owned" },
    };
    expect(dec(encodeControl(owned))).toBe(
      `{"t":"InputControlChanged","c":{"owner_session":"11111111-2222-3333-4444-555555555555","owner_name":"Jordan","mode":"owned"}}`,
    );
    expect(decodeControl(encodeControl(owned))).toEqual(owned);

    const shared: ControlMessage = { t: "InputControlChanged", c: { owner_session: null, owner_name: null, mode: "shared" } };
    expect(dec(encodeControl(shared))).toBe(`{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"shared"}}`);
    expect(decodeControl(encodeControl(shared))).toEqual(shared);

    const blocked: ControlMessage = { t: "InputControlChanged", c: { owner_session: null, owner_name: null, mode: "blocked" } };
    expect(dec(encodeControl(blocked))).toBe(`{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"blocked"}}`);
    expect(decodeControl(encodeControl(blocked))).toEqual(blocked);

    // A terser agent may omit the owner fields on a Shared/Blocked snapshot.
    expect(decodeControl(new TextEncoder().encode(`{"t":"InputControlChanged","c":{"mode":"shared"}}`))).toEqual(shared);
    // A bad mode or wrong-typed owner is rejected.
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"InputControlChanged","c":{"mode":"nope"}}`))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"HandInputControl","c":{}}`))).toThrow();
  });
});

/**
 * M11 quality control — the cross-language golden vectors.
 *
 * Every literal below is byte-for-byte the string the Rust unit tests in
 * `crates/agent-core/src/control.rs` assert (module `tests`, the `--- M11 quality control ---`
 * block); that file names this one in return. They are duplicated deliberately rather than generated:
 * reordering a serde struct field changes the bytes silently, and two independently-written literals
 * are the only thing that catches it before a mixed-version fleet does.
 */
describe("control codec: M11 quality (wire-compat with Rust control.rs)", () => {
  const DEFAULTS: QualitySettings = {
    scale_div: 1,
    fps: 30,
    color: "Full",
    max_bitrate_bps: 3000000,
    adaptive: true,
  };

  it("RequestQuality → bare tag (no content)", () => {
    const bytes = encodeControl({ t: "RequestQuality" });
    expect(dec(bytes)).toBe(`{"t":"RequestQuality"}`);
    expect(decodeControl(bytes)).toEqual({ t: "RequestQuality" });
  });

  it("SetQuality at the defaults → nested settings in serde field order", () => {
    const bytes = encodeControl({ t: "SetQuality", c: { quality: DEFAULTS } });
    expect(dec(bytes)).toBe(
      `{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true}}}`,
    );
    expect(decodeControl(bytes)).toEqual({ t: "SetQuality", c: { quality: DEFAULTS } });
  });

  it("SetQuality at the slow-link end → colour is a bare string, not an object", () => {
    // ColorMode is a unit-only enum in Rust, so serde emits `"Gray"` and not `{"Gray":null}`.
    const quality: QualitySettings = {
      scale_div: 2,
      fps: 5,
      color: "Gray",
      max_bitrate_bps: 400000,
      adaptive: false,
    };
    const bytes = encodeControl({ t: "SetQuality", c: { quality } });
    expect(dec(bytes)).toBe(
      `{"t":"SetQuality","c":{"quality":{"scale_div":2,"fps":5,"color":"Gray","max_bitrate_bps":400000,"adaptive":false}}}`,
    );
    expect(decodeControl(bytes)).toEqual({ t: "SetQuality", c: { quality } });
  });

  it("QualityApplied (policy-capped floor) → settings, then encoder bitrate, then the cap flag", () => {
    const msg: ControlMessage = {
      t: "QualityApplied",
      c: {
        quality: {
          scale_div: 4,
          fps: 1,
          color: "Gray",
          max_bitrate_bps: 100000,
          adaptive: true,
        },
        encoder_bitrate_bps: 100000,
        capped_by_policy: true,
      },
    };
    const bytes = encodeControl(msg);
    expect(dec(bytes)).toBe(
      `{"t":"QualityApplied","c":{"quality":{"scale_div":4,"fps":1,"color":"Gray","max_bitrate_bps":100000,"adaptive":true},"encoder_bitrate_bps":100000,"capped_by_policy":true}}`,
    );
    expect(decodeControl(bytes)).toEqual(msg);
  });

  it("QualityApplied (uncapped defaults) round-trips", () => {
    const msg: ControlMessage = {
      t: "QualityApplied",
      c: { quality: DEFAULTS, encoder_bitrate_bps: 3000000, capped_by_policy: false },
    };
    const bytes = encodeControl(msg);
    expect(dec(bytes)).toBe(
      `{"t":"QualityApplied","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true},"encoder_bitrate_bps":3000000,"capped_by_policy":false}}`,
    );
    expect(decodeControl(bytes)).toEqual(msg);
  });

  it("QualityStats → nine fields in serde order, with the rate pair LAST", () => {
    // `fps_x100` and `dropped_frames_total` were appended to the Rust struct variant, so serde emits them
    // after `feedback_reports` — the position is the whole point of a golden vector, because a
    // reorder changes the bytes and nothing else in either language would notice.
    // Wire key is "dropped_frames" (the internal TS/Rust field name is dropped_frames_total).
    const msg: ControlMessage = {
      t: "QualityStats",
      c: {
        encoder_bitrate_bps: 742000,
        measured_bitrate_bps: 731520,
        fraction_lost_256: 13,
        rtt_ms: 24,
        width: 960,
        height: 540,
        feedback_reports: 42,
        fps_x100: 1437,
        dropped_frames_total: 118,
      },
    };
    const bytes = encodeControl(msg);
    expect(dec(bytes)).toBe(
      `{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}`,
    );
    expect(decodeControl(bytes)).toEqual(msg);
  });

  it("QualityStats carries 0 for a not-yet-measurable frame rate, not an omitted field", () => {
    // The agent documents `fps_x100: 0` as "not yet measurable" (a window too short to divide by),
    // which is a different statement from "zero frames were encoded". It must survive the wire as a
    // present zero so the readout can print an em dash for it rather than a confident "0.0 fps".
    const msg: ControlMessage = {
      t: "QualityStats",
      c: {
        encoder_bitrate_bps: 3000000,
        measured_bitrate_bps: 0,
        fraction_lost_256: 0,
        rtt_ms: 0,
        width: 1920,
        height: 1080,
        feedback_reports: 0,
        fps_x100: 0,
        dropped_frames_total: 0,
      },
    };
    const bytes = encodeControl(msg);
    expect(dec(bytes)).toContain(`"fps_x100":0,"dropped_frames":0`);
    expect(decodeControl(bytes)).toEqual(msg);
  });

  it("requestQuality() / setQuality() constructors match the tags", () => {
    expect(requestQuality()).toEqual({ t: "RequestQuality" });
    expect(setQuality(DEFAULTS)).toEqual({ t: "SetQuality", c: { quality: DEFAULTS } });
  });

  it("decode REJECTS an unknown ColorMode rather than defaulting it", () => {
    // Mirrors Rust's `the_schema_owns_the_quality_constraint`. A tolerant decode here would mean an
    // unparseable colour arrives as "Full" and the operator's greyscale selection quietly does
    // nothing — on exactly the link that was chosen because it cannot afford chroma.
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          `{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Sepia","max_bitrate_bps":3000000,"adaptive":true}}}`,
        ),
      ),
    ).toThrow();
  });

  it("decode REJECTS a missing field (no absent-means-default rule on this wire)", () => {
    // `adaptive` omitted. Accepting this is the shape that shipped the Option whose None granted all
    // 19 backstage capabilities; there is no partial update here, so absence is malformed.
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          `{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000}}}`,
        ),
      ),
    ).toThrow();
    // …and the whole `quality` object missing, and a QualityStats missing one of its nine.
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SetQuality","c":{}}`))).toThrow();
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          `{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":1,"rtt_ms":1,"width":1,"height":1,"fps_x100":0,"dropped_frames":0}}`,
        ),
      ),
    ).toThrow();
    // Both new fields are REQUIRED — the same rule as the other seven, and mirroring the Rust
    // `quality_stats_requires_the_rate_fields`. A tolerated absence would read as "not yet
    // measurable" forever, so a stalled stream and an agent that predates the field would be
    // indistinguishable on the operator's readout.
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          // Wire key is "dropped_frames"; fps_x100 is the missing field here.
          `{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"dropped_frames":0}}`,
        ),
      ),
    ).toThrow();
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          `{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"fps_x100":0}}`,
        ),
      ),
    ).toThrow();
    expect(() =>
      decodeControl(
        new TextEncoder().encode(
          `{"t":"QualityApplied","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true},"encoder_bitrate_bps":3000000}}`,
        ),
      ),
    ).toThrow();
  });

  it("decode ACCEPTS out-of-range values — range is the clamp's job, not the codec's", () => {
    // Mirrors the Rust assertion of the same name: a hostile controller gets a working session at
    // legal values (the agent clamps) rather than a dropped frame.
    const bytes = new TextEncoder().encode(
      `{"t":"SetQuality","c":{"quality":{"scale_div":0,"fps":0,"color":"Full","max_bitrate_bps":0,"adaptive":true}}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "SetQuality",
      c: { quality: { scale_div: 0, fps: 0, color: "Full", max_bitrate_bps: 0, adaptive: true } },
    });
  });
});

describe("control codec: input block (wire-compat with Rust control.rs)", () => {
  it("SetInputBlocked → adjacently-tagged JSON, both states (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "SetInputBlocked", c: { blocked: true } }))).toBe(
      `{"t":"SetInputBlocked","c":{"blocked":true}}`,
    );
    expect(dec(encodeControl({ t: "SetInputBlocked", c: { blocked: false } }))).toBe(
      `{"t":"SetInputBlocked","c":{"blocked":false}}`,
    );
    expect(decodeControl(encodeControl({ t: "SetInputBlocked", c: { blocked: true } }))).toEqual({
      t: "SetInputBlocked",
      c: { blocked: true },
    });
  });

  it("InputBlockApplied → adjacently-tagged JSON, both states", () => {
    expect(dec(encodeControl({ t: "InputBlockApplied", c: { blocked: true } }))).toBe(
      `{"t":"InputBlockApplied","c":{"blocked":true}}`,
    );
    expect(decodeControl(encodeControl({ t: "InputBlockApplied", c: { blocked: false } }))).toEqual({
      t: "InputBlockApplied",
      c: { blocked: false },
    });
  });

  it("decode REJECTS a missing `blocked` field (no absent-means-default on this wire)", () => {
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SetInputBlocked","c":{}}`))).toThrow();
  });
});

describe("control codec: monitor blank (wire-compat with Rust control.rs)", () => {
  it("SetMonitorBlanked → adjacently-tagged JSON, both states (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "SetMonitorBlanked", c: { blanked: true } }))).toBe(
      `{"t":"SetMonitorBlanked","c":{"blanked":true}}`,
    );
    expect(dec(encodeControl({ t: "SetMonitorBlanked", c: { blanked: false } }))).toBe(
      `{"t":"SetMonitorBlanked","c":{"blanked":false}}`,
    );
    expect(decodeControl(encodeControl({ t: "SetMonitorBlanked", c: { blanked: true } }))).toEqual({
      t: "SetMonitorBlanked",
      c: { blanked: true },
    });
  });

  it("MonitorBlankedApplied → adjacently-tagged JSON, both states", () => {
    expect(dec(encodeControl({ t: "MonitorBlankedApplied", c: { blanked: true } }))).toBe(
      `{"t":"MonitorBlankedApplied","c":{"blanked":true}}`,
    );
    expect(
      decodeControl(encodeControl({ t: "MonitorBlankedApplied", c: { blanked: false } })),
    ).toEqual({ t: "MonitorBlankedApplied", c: { blanked: false } });
  });

  it("decode REJECTS a missing `blanked` field (no absent-means-default on this wire)", () => {
    expect(() =>
      decodeControl(new TextEncoder().encode(`{"t":"SetMonitorBlanked","c":{}}`)),
    ).toThrow();
  });
});

describe("control codec: view-only (wire-compat with Rust control.rs)", () => {
  it("SetViewOnly/ViewOnlyApplied → adjacently-tagged JSON, both states (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "SetViewOnly", c: { enabled: true } }))).toBe(
      `{"t":"SetViewOnly","c":{"enabled":true}}`,
    );
    expect(dec(encodeControl({ t: "SetViewOnly", c: { enabled: false } }))).toBe(
      `{"t":"SetViewOnly","c":{"enabled":false}}`,
    );
    expect(dec(encodeControl({ t: "ViewOnlyApplied", c: { enabled: true } }))).toBe(
      `{"t":"ViewOnlyApplied","c":{"enabled":true}}`,
    );
    expect(decodeControl(encodeControl({ t: "SetViewOnly", c: { enabled: true } }))).toEqual({
      t: "SetViewOnly",
      c: { enabled: true },
    });
  });

  it("decode REJECTS a missing `enabled` field", () => {
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SetViewOnly","c":{}}`))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"ViewOnlyApplied","c":{}}`))).toThrow();
  });

  it("setViewOnly(enabled) frames a SetViewOnly, and handleMessage routes ViewOnlyApplied", () => {
    const sent: ControlMessage[] = [];
    const applied: boolean[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onViewOnlyApplied: (e) => applied.push(e),
    });
    client.setViewOnly(true);
    expect(sent).toEqual([{ t: "SetViewOnly", c: { enabled: true } }]);
    client.handleMessage(encodeControl({ t: "ViewOnlyApplied", c: { enabled: true } }));
    expect(applied).toEqual([true]);
  });
});

describe("control codec: reboot guest (wire-compat with Rust control.rs)", () => {
  it("RebootGuest → adjacently-tagged JSON, both modes (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "RebootGuest", c: { safe_mode: true } }))).toBe(
      `{"t":"RebootGuest","c":{"safe_mode":true}}`,
    );
    expect(dec(encodeControl({ t: "RebootGuest", c: { safe_mode: false } }))).toBe(
      `{"t":"RebootGuest","c":{"safe_mode":false}}`,
    );
    expect(decodeControl(encodeControl({ t: "RebootGuest", c: { safe_mode: true } }))).toEqual({
      t: "RebootGuest",
      c: { safe_mode: true },
    });
  });

  it("RebootScheduled → adjacently-tagged JSON, both modes", () => {
    expect(dec(encodeControl({ t: "RebootScheduled", c: { safe_mode: true } }))).toBe(
      `{"t":"RebootScheduled","c":{"safe_mode":true}}`,
    );
    expect(decodeControl(encodeControl({ t: "RebootScheduled", c: { safe_mode: false } }))).toEqual({
      t: "RebootScheduled",
      c: { safe_mode: false },
    });
  });

  it("decode REJECTS a missing `safe_mode` field (no absent-means-default on this wire)", () => {
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"RebootGuest","c":{}}`))).toThrow();
  });

  it("LockWorkstation / WorkstationLocked → bare tags (mirror Rust literals)", () => {
    expect(dec(encodeControl({ t: "LockWorkstation" }))).toBe(`{"t":"LockWorkstation"}`);
    expect(dec(encodeControl({ t: "WorkstationLocked" }))).toBe(`{"t":"WorkstationLocked"}`);
    expect(decodeControl(encodeControl({ t: "LockWorkstation" }))).toEqual({ t: "LockWorkstation" });
    expect(decodeControl(encodeControl({ t: "WorkstationLocked" }))).toEqual({ t: "WorkstationLocked" });
  });

  it("LogOffGuest / LogOffScheduled → bare tags (mirror Rust literals)", () => {
    // Cross-language contract: agent-core `control.rs::log_off_round_trips_as_bare_tags` pins the SAME
    // strings. Both are content-free, so they serialize as just `{"t":…}` (like the lock pair).
    expect(dec(encodeControl({ t: "LogOffGuest" }))).toBe(`{"t":"LogOffGuest"}`);
    expect(dec(encodeControl({ t: "LogOffScheduled" }))).toBe(`{"t":"LogOffScheduled"}`);
    expect(decodeControl(encodeControl({ t: "LogOffGuest" }))).toEqual({ t: "LogOffGuest" });
    expect(decodeControl(encodeControl({ t: "LogOffScheduled" }))).toEqual({ t: "LogOffScheduled" });
  });

  it("ShutDownGuest / ShutDownScheduled → bare tags (mirror Rust literals)", () => {
    // Cross-language contract: agent-core `control.rs::shut_down_round_trips_as_bare_tags` pins the SAME
    // strings. Both are content-free, so they serialize as just `{"t":…}` (like the lock/logoff pairs).
    expect(dec(encodeControl({ t: "ShutDownGuest" }))).toBe(`{"t":"ShutDownGuest"}`);
    expect(dec(encodeControl({ t: "ShutDownScheduled" }))).toBe(`{"t":"ShutDownScheduled"}`);
    expect(decodeControl(encodeControl({ t: "ShutDownGuest" }))).toEqual({ t: "ShutDownGuest" });
    expect(decodeControl(encodeControl({ t: "ShutDownScheduled" }))).toEqual({ t: "ShutDownScheduled" });
  });
});

describe("control codec: system tool launchers (wire-compat with Rust control.rs)", () => {
  it("LaunchTool → adjacently-tagged JSON (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "LaunchTool", c: { tool: "task_manager" } }))).toBe(
      `{"t":"LaunchTool","c":{"tool":"task_manager"}}`,
    );
    expect(dec(encodeControl({ t: "LaunchTool", c: { tool: "registry_editor" } }))).toBe(
      `{"t":"LaunchTool","c":{"tool":"registry_editor"}}`,
    );
    expect(decodeControl(encodeControl({ t: "LaunchTool", c: { tool: "services" } }))).toEqual({
      t: "LaunchTool",
      c: { tool: "services" },
    });
  });

  it("ToolLaunched → adjacently-tagged JSON", () => {
    expect(dec(encodeControl({ t: "ToolLaunched", c: { tool: "device_manager" } }))).toBe(
      `{"t":"ToolLaunched","c":{"tool":"device_manager"}}`,
    );
  });

  it("decode REJECTS a missing `tool` field", () => {
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"LaunchTool","c":{}}`))).toThrow();
  });
});

describe("control codec: one-line command bar (wire-compat with Rust control.rs)", () => {
  it("RunCommand → adjacently-tagged JSON, both shells + contexts (mirrors Rust literals)", () => {
    // A unit-only CommandShell serializes as a BARE STRING; field order is command, shell, as_user.
    expect(
      dec(encodeControl({ t: "RunCommand", c: { command: "whoami", shell: "Cmd", as_user: false } })),
    ).toBe(`{"t":"RunCommand","c":{"command":"whoami","shell":"Cmd","as_user":false}}`);
    expect(
      dec(encodeControl({ t: "RunCommand", c: { command: "Get-Date", shell: "PowerShell", as_user: true } })),
    ).toBe(`{"t":"RunCommand","c":{"command":"Get-Date","shell":"PowerShell","as_user":true}}`);
    expect(
      decodeControl(encodeControl({ t: "RunCommand", c: { command: "dir", shell: "Cmd", as_user: false } })),
    ).toEqual({ t: "RunCommand", c: { command: "dir", shell: "Cmd", as_user: false } });
  });

  it("CommandResult → adjacently-tagged JSON (mirrors Rust literals), incl. a killed/truncated one", () => {
    expect(
      dec(
        encodeControl({
          t: "CommandResult",
          c: { exit_code: 0, stdout: "nt authority\\system\r\n", stderr: "", truncated: false, timed_out: false },
        }),
      ),
    ).toBe(
      `{"t":"CommandResult","c":{"exit_code":0,"stdout":"nt authority\\\\system\\r\\n","stderr":"","truncated":false,"timed_out":false}}`,
    );
    // A killed-on-timeout result carries the kill code (-1) and both flags — a negative number
    // round-trips as a signed integer.
    expect(
      decodeControl(
        encodeControl({
          t: "CommandResult",
          c: { exit_code: -1, stdout: "partial", stderr: "boom", truncated: true, timed_out: true },
        }),
      ),
    ).toEqual({
      t: "CommandResult",
      c: { exit_code: -1, stdout: "partial", stderr: "boom", truncated: true, timed_out: true },
    });
  });

  it("decode REJECTS a missing field or an unknown shell (no absent-means-default on this wire)", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(() => decodeControl(enc(`{"t":"RunCommand","c":{"command":"x","as_user":false}}`))).toThrow();
    expect(() => decodeControl(enc(`{"t":"RunCommand","c":{"shell":"Cmd","as_user":false}}`))).toThrow();
    expect(() => decodeControl(enc(`{"t":"RunCommand","c":{"command":"x","shell":"Cmd"}}`))).toThrow();
    expect(() => decodeControl(enc(`{"t":"RunCommand","c":{"command":"x","shell":"Bash","as_user":false}}`))).toThrow();
    // CommandResult: a missing exit_code must not be read as 0 (a command that never ran ≠ exit 0).
    expect(() =>
      decodeControl(enc(`{"t":"CommandResult","c":{"stdout":"","stderr":"","truncated":false,"timed_out":false}}`)),
    ).toThrow();
  });
});

describe("control codec: elevated run (wire-compat with Rust control.rs)", () => {
  // These literals are the CROSS-LANGUAGE CONTRACT. The same strings are hardcoded in
  // crates/agent-core/src/control.rs's `elevated_run_round_trips` / `elevation_denied_round_trips`.
  // Nothing mechanical keeps the two files in step, so a change here needs the same change there.
  it("ElevatedRun → adjacently-tagged JSON, both shells (mirrors Rust literals)", () => {
    // Field order is declaration order: signed_elevation, command, shell. The grant rides as an
    // OPAQUE JSON string — this codec neither parses nor validates it, exactly like InstallGrant.
    expect(
      dec(
        encodeControl({
          t: "ElevatedRun",
          c: { signed_elevation: `{"claims":{},"sig":"ab"}`, command: "whoami /groups", shell: "Cmd" },
        }),
      ),
    ).toBe(
      `{"t":"ElevatedRun","c":{"signed_elevation":"{\\"claims\\":{},\\"sig\\":\\"ab\\"}","command":"whoami /groups","shell":"Cmd"}}`,
    );
    expect(
      dec(
        encodeControl({
          t: "ElevatedRun",
          c: { signed_elevation: "{}", command: "Get-Date", shell: "PowerShell" },
        }),
      ),
    ).toBe(`{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"Get-Date","shell":"PowerShell"}}`);
  });

  it("ElevationDenied → adjacently-tagged JSON (mirrors Rust literals)", () => {
    expect(
      dec(
        encodeControl({
          t: "ElevationDenied",
          c: { reason: "elevation grant is for a different session" },
        }),
      ),
    ).toBe(`{"t":"ElevationDenied","c":{"reason":"elevation grant is for a different session"}}`);
  });

  it("decode REJECTS a missing field or an unknown shell", () => {
    const enc = (x: string) => new TextEncoder().encode(x);
    // A missing `signed_elevation` decoding as "" would forward an UNAUTHORIZED elevated run and
    // lean entirely on the agent's verifier to catch it. It must not decode at all.
    expect(() => decodeControl(enc(`{"t":"ElevatedRun","c":{"command":"x","shell":"Cmd"}}`))).toThrow();
    expect(() =>
      decodeControl(enc(`{"t":"ElevatedRun","c":{"signed_elevation":"{}","shell":"Cmd"}}`)),
    ).toThrow();
    expect(() =>
      decodeControl(enc(`{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x"}}`)),
    ).toThrow();
    expect(() =>
      decodeControl(enc(`{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Bash"}}`)),
    ).toThrow();
    expect(() => decodeControl(enc(`{"t":"ElevationDenied","c":{}}`))).toThrow();
    // …and the full shapes DO decode, so the throws above are not the variant being unknown.
    expect(
      decodeControl(enc(`{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Cmd"}}`)),
    ).toEqual({ t: "ElevatedRun", c: { signed_elevation: "{}", command: "x", shell: "Cmd" } });
    expect(decodeControl(enc(`{"t":"ElevationDenied","c":{"reason":"nope"}}`))).toEqual({
      t: "ElevationDenied",
      c: { reason: "nope" },
    });
  });
});

describe("control codec: screenshot (wire-compat with Rust control.rs)", () => {
  it("RequestScreenshot → a bare tag (unit variant, mirrors the Rust literal)", () => {
    expect(dec(encodeControl({ t: "RequestScreenshot" }))).toBe(`{"t":"RequestScreenshot"}`);
    expect(decodeControl(encodeControl({ t: "RequestScreenshot" }))).toEqual({ t: "RequestScreenshot" });
  });

  it("ListDirectory → adjacently-tagged JSON (mirrors the Rust literal; escaped backslash)", () => {
    // A drive path: the single backslash becomes `\\` in JSON — the same bytes as the Rust literal.
    expect(dec(encodeControl({ t: "ListDirectory", c: { path: "C:\\" } }))).toBe(
      `{"t":"ListDirectory","c":{"path":"C:\\\\"}}`,
    );
    expect(dec(encodeControl(listDirectory("")))).toBe(`{"t":"ListDirectory","c":{"path":""}}`);
    expect(decodeControl(encodeControl(listDirectory("C:\\Users")))).toEqual({
      t: "ListDirectory",
      c: { path: "C:\\Users" },
    });
  });

  it("DirectoryListing → adjacently-tagged JSON, serde field order (mirrors the Rust literal)", () => {
    const entries = [
      { name: "Windows", is_dir: true, size: 0, modified_unix: 1700000000 },
      { name: "readme.txt", is_dir: false, size: 42, modified_unix: 1700000001 },
    ];
    const bytes = encodeControl({
      t: "DirectoryListing",
      c: { path: "C:\\", entries, truncated: false, audit: null },
    });
    expect(dec(bytes)).toBe(
      `{"t":"DirectoryListing","c":{"path":"C:\\\\","entries":[{"name":"Windows","is_dir":true,"size":0,"modified_unix":1700000000},{"name":"readme.txt","is_dir":false,"size":42,"modified_unix":1700000001}],"truncated":false,"audit":null}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "DirectoryListing",
      c: { path: "C:\\", entries, truncated: false, audit: null },
    });
    // Empty + truncated round-trips too.
    expect(
      dec(
        encodeControl({
          t: "DirectoryListing",
          c: { path: "", entries: [], truncated: true, audit: null },
        }),
      ),
    ).toBe(`{"t":"DirectoryListing","c":{"path":"","entries":[],"truncated":true,"audit":null}}`);
  });

  // docs/25 F04. The refusal is its own message because it is its own event — and because it has to
  // carry an audit record, which `Error` has nowhere to put.
  it("DirectoryListingRefused → adjacently-tagged JSON, serde field order (mirrors the Rust literal)", () => {
    const bytes = encodeControl({
      t: "DirectoryListingRefused",
      c: { path: "\\\\attacker\\share", reason: "network (UNC) paths are not browsable", audit: null },
    });
    expect(dec(bytes)).toBe(
      `{"t":"DirectoryListingRefused","c":{"path":"\\\\\\\\attacker\\\\share","reason":"network (UNC) paths are not browsable","audit":null}}`,
    );
    expect(decodeControl(bytes)).toEqual({
      t: "DirectoryListingRefused",
      c: { path: "\\\\attacker\\share", reason: "network (UNC) paths are not browsable", audit: null },
    });
    // `reason` is required; `audit` is the one lenient field, for the same reason it is lenient on a
    // recording ack — an agent predating F04 sends no key, and refusing the message would break the
    // browser to protect a record that agent never sealed.
    const enc = (x: string) => new TextEncoder().encode(x);
    expect(() => decodeControl(enc(`{"t":"DirectoryListingRefused","c":{"path":"C:"}}`))).toThrow();
    expect(decodeControl(enc(`{"t":"DirectoryListingRefused","c":{"path":"","reason":"no"}}`))).toEqual({
      t: "DirectoryListingRefused",
      c: { path: "", reason: "no", audit: null },
    });
  });

  // The sealed event must survive the codec BYTE FOR BYTE: `/audit/ingest` recomputes the canonical
  // preimage and reads any field-level difference as the agent forging its own trail.
  it("a sealed audit event rides a directory reply unmodified", () => {
    const audit = {
      seq: 3,
      action: { kind: "file_browse", path: "C:\Users" },
      outcome: { result: "ok" },
      hash: "b8f1",
    };
    const listing = decodeControl(
      encodeControl({ t: "DirectoryListing", c: { path: "C:\Users", entries: [], truncated: false, audit } }),
    );
    expect(listing).toEqual({
      t: "DirectoryListing",
      c: { path: "C:\Users", entries: [], truncated: false, audit },
    });
    const refusal = decodeControl(
      encodeControl({ t: "DirectoryListingRefused", c: { path: "C:\Users", reason: "nope", audit } }),
    );
    expect(refusal).toEqual({
      t: "DirectoryListingRefused",
      c: { path: "C:\Users", reason: "nope", audit },
    });
  });

  it("ListDirectory/DirectoryListing reject missing fields (strict, mirrors Rust)", () => {
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(() => decodeControl(enc(`{"t":"ListDirectory","c":{}}`))).toThrow();
    expect(() => decodeControl(enc(`{"t":"DirectoryListing","c":{"path":"x","entries":[]}}`))).toThrow();
    expect(() =>
      decodeControl(enc(`{"t":"DirectoryListing","c":{"path":"x","truncated":false}}`)),
    ).toThrow();
    // A DirEntry missing modified_unix is rejected, not rendered with an undefined cell.
    expect(() =>
      decodeControl(
        enc(`{"t":"DirectoryListing","c":{"path":"x","entries":[{"name":"y","is_dir":true,"size":0}],"truncated":false}}`),
      ),
    ).toThrow();
  });

  it("EndSession/SessionEnding → adjacently-tagged JSON, both modes (mirrors Rust literals)", () => {
    expect(dec(encodeControl({ t: "EndSession", c: { uninstall: false } }))).toBe(
      `{"t":"EndSession","c":{"uninstall":false}}`,
    );
    expect(dec(encodeControl({ t: "EndSession", c: { uninstall: true } }))).toBe(
      `{"t":"EndSession","c":{"uninstall":true}}`,
    );
    expect(dec(encodeControl({ t: "SessionEnding", c: { uninstall: true } }))).toBe(
      `{"t":"SessionEnding","c":{"uninstall":true}}`,
    );
    expect(decodeControl(encodeControl({ t: "EndSession", c: { uninstall: true } }))).toEqual({
      t: "EndSession",
      c: { uninstall: true },
    });
    // No absent-means-default: a missing `uninstall` is rejected, not read as false.
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"EndSession","c":{}}`))).toThrow();
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SessionEnding","c":{}}`))).toThrow();
  });

  it("SessionEndedByGuest → bare tag (mirrors Rust literal)", () => {
    expect(dec(encodeControl({ t: "SessionEndedByGuest" }))).toBe(
      `{"t":"SessionEndedByGuest"}`,
    );
    expect(decodeControl(new TextEncoder().encode(`{"t":"SessionEndedByGuest"}`))).toEqual({
      t: "SessionEndedByGuest",
    });
  });

  it("TransferDir → adjacently-tagged JSON (mirrors Rust literal)", () => {
    // The canonical wire shape, byte-for-byte equal to the Rust round_trip assertion in control.rs.
    const msg = { t: "TransferDir" as const, c: { path: "C:\\rmt-agent\\transfers" } };
    expect(dec(encodeControl(msg))).toBe(
      `{"t":"TransferDir","c":{"path":"C:\\\\rmt-agent\\\\transfers"}}`,
    );
    expect(decodeControl(encodeControl(msg))).toEqual(msg);
  });

  it("TransferDir rejects a missing or non-string path", () => {
    // An absent `path` must be rejected — a viewer that falls back silently could show download
    // buttons for files the agent will refuse (wrong root).
    expect(() =>
      decodeControl(new TextEncoder().encode(`{"t":"TransferDir","c":{}}`)),
    ).toThrow("malformed TransferDir");
    expect(() =>
      decodeControl(new TextEncoder().encode(`{"t":"TransferDir","c":{"path":null}}`)),
    ).toThrow("malformed TransferDir");
  });

  it("isScreenshotName matches the agent's `screenshot-<ts>.png` convention, and nothing else", () => {
    // The convention that lets App tell an agent-pushed screenshot from an ordinary download. Both the
    // prefix AND the .png suffix are required — a `screenshot-notes.txt` or a `photo-1.png` is NOT one.
    expect(isScreenshotName("screenshot-1700000000000.png")).toBe(true);
    expect(isScreenshotName("screenshot-.png")).toBe(true);
    expect(isScreenshotName("screenshot-1.txt")).toBe(false);
    expect(isScreenshotName("photo-1.png")).toBe(false);
    expect(isScreenshotName("report.png")).toBe(false);
    expect(isScreenshotName("")).toBe(false);
  });
});

describe("control codec: session recording (wire-compat with Rust control.rs)", () => {
  it("StartRecording / StopRecording → bare tags (unit variants, mirror the Rust literals)", () => {
    expect(dec(encodeControl({ t: "StartRecording" }))).toBe(`{"t":"StartRecording"}`);
    expect(dec(encodeControl({ t: "StopRecording" }))).toBe(`{"t":"StopRecording"}`);
    expect(dec(encodeControl(startRecording()))).toBe(`{"t":"StartRecording"}`);
    expect(dec(encodeControl(stopRecording()))).toBe(`{"t":"StopRecording"}`);
    expect(decodeControl(encodeControl(startRecording()))).toEqual({ t: "StartRecording" });
    expect(decodeControl(encodeControl(stopRecording()))).toEqual({ t: "StopRecording" });
  });

  it("RecordingStarted → adjacently-tagged JSON (mirrors the Rust literal)", () => {
    const msg: ControlMessage = {
      t: "RecordingStarted",
      c: { started_at_unix_ms: 1764000000123, audit: null },
    };
    expect(dec(encodeControl(msg))).toBe(
      `{"t":"RecordingStarted","c":{"started_at_unix_ms":1764000000123,"audit":null}}`,
    );
    expect(decodeControl(encodeControl(msg))).toEqual(msg);
  });

  it("RecordingStopped → serde field order, with `truncated` null for a clean run", () => {
    // Wire key is "dropped_frames" (not "dropped_frames_total" — the internal TS field name).
    const msg: ControlMessage = {
      t: "RecordingStopped",
      c: {
        segments: 2,
        frames: 913,
        payload_bytes: 4211337,
        truncated: null,
        dropped_frames_total: 0,
        directory: "C:\\rmt-agent\\recordings",
        audit: null,
      },
    };
    expect(dec(encodeControl(msg))).toBe(
      `{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":0,"directory":"C:\\\\rmt-agent\\\\recordings","audit":null}}`,
    );
    expect(decodeControl(encodeControl(msg))).toEqual(msg);

    const cut: ControlMessage = {
      t: "RecordingStopped",
      c: {
        segments: 1,
        frames: 12,
        payload_bytes: 900,
        truncated: "queue_full",
        dropped_frames_total: 47,
        directory: "",
        audit: null,
      },
    };
    expect(dec(encodeControl(cut))).toBe(
      `{"t":"RecordingStopped","c":{"segments":1,"frames":12,"payload_bytes":900,"truncated":"queue_full","dropped_frames":47,"directory":"","audit":null}}`,
    );
    expect(decodeControl(encodeControl(cut))).toEqual(cut);
  });

  it("a RecordingStopped with `truncated` ABSENT is rejected, not read as complete", () => {
    // The mirror of the Rust test of the same name, and the reason `truncated` carries a
    // `deserialize_with` over there: serde's default for a missing `Option` is `None`, which here
    // would silently turn a recording that stopped early into one that finished. A truncated file
    // ends exactly like a complete one, so this key is the ONLY thing that distinguishes them.
    // Wire key is "dropped_frames".
    const enc = (s: string) => new TextEncoder().encode(s);
    expect(() =>
      decodeControl(
        enc(
          `{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"dropped_frames":0,"directory":"","audit":null}}`,
        ),
      ),
    ).toThrow();
    // …and the explicit null IS accepted, so the assertion above is about ABSENCE and not about
    // null. Without this pair, a decoder that rejected both would pass the negative case while
    // making every clean recording undecodable.
    expect(() =>
      decodeControl(
        enc(
          `{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"truncated":null,"dropped_frames":0,"directory":"","audit":null}}`,
        ),
      ),
    ).not.toThrow();
    expect(() => decodeControl(enc(`{"t":"RecordingStarted","c":{}}`))).toThrow();
  });

  it("mixed-version wire compatibility: 'dropped_frames' key accepted, 'dropped_frames_total' rejected", () => {
    // Documents the deployed-wire constraint for mixed-version deployments.
    // Old agents (pre-rename commit) emit "dropped_frames"; new viewers must accept it.
    // The rejected-rename format "dropped_frames_total" must not silently pass.
    const enc = (s: string) => new TextEncoder().encode(s);
    // Old-agent QualityStats (wire key "dropped_frames") accepted and value mapped correctly.
    const qs = decodeControl(
      enc(
        `{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}`,
      ),
    );
    expect(qs).toMatchObject({ t: "QualityStats", c: { dropped_frames_total: 118 } });
    // Old-agent RecordingStopped (wire key "dropped_frames") accepted and value mapped correctly.
    const rs = decodeControl(
      enc(
        `{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":47,"directory":"","audit":null}}`,
      ),
    );
    expect(rs).toMatchObject({ t: "RecordingStopped", c: { dropped_frames_total: 47 } });
    // Rejected-rename format "dropped_frames_total" must be rejected (not silently aliased).
    expect(() =>
      decodeControl(
        enc(
          `{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames_total":118}}`,
        ),
      ),
    ).toThrow("malformed QualityStats");
    expect(() =>
      decodeControl(
        enc(
          `{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames_total":0,"directory":"","audit":null}}`,
        ),
      ),
    ).toThrow("malformed RecordingStopped");
  });
});

describe("recordingSummary", () => {
  const base: RecordingResult = {
    segments: 1,
    frames: 43,
    payload_bytes: 12345,
    truncated: null,
    dropped_frames_total: 0,
    directory: "C:\\rmt-agent\\recordings",
  };

  it("a clean recording reads as a count and a place to find it", () => {
    expect(recordingSummary(base)).toBe(
      "Recorded 43 frames → C:\\rmt-agent\\recordings (on the guest)",
    );
  });

  it("a TRUNCATED recording says so FIRST, and names the reason", () => {
    // The branch an e2e cannot stage: a truncation needs a full queue, an exhausted disk or a blown
    // size budget. It is also the branch that matters — a recording reported as "Recorded 43 frames"
    // when it stopped early is a file the operator hands over believing it is complete.
    const cut = recordingSummary({ ...base, truncated: "queue_full", dropped_frames_total: 117 });
    expect(cut).toContain("TRUNCATED");
    expect(cut).toContain("queue_full");
    expect(cut).toContain("117 frames lost");
    expect(cut.indexOf("TRUNCATED")).toBeLessThan(cut.indexOf("43 frames"));
    // …and the clean case must NOT say any of it, or the warning is noise.
    expect(recordingSummary(base)).not.toContain("TRUNCATED");
    expect(recordingSummary(base)).not.toContain("lost");
  });

  it("each truncation reason is carried through verbatim", () => {
    // The four the agent can produce (`recording::TruncationReason::as_str`). A summary that
    // collapsed them to "truncated" would lose the difference between "this machine is out of disk"
    // and "this recording hit its size cap", which are different things to do next.
    for (const reason of ["queue_full", "size_limit", "disk_low", "io_error"]) {
      expect(recordingSummary({ ...base, truncated: reason })).toContain(reason);
    }
  });
});

describe("ControlClient", () => {
  it("requestList() frames a RequestMonitors message", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.requestList();
    expect(sent).toEqual([{ t: "RequestMonitors" }]);
  });

  it("select(id) frames a SelectMonitor message", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.select(1);
    expect(sent).toEqual([{ t: "SelectMonitor", c: { id: 1 } }]);
  });

  it("selectAll() frames a SelectMonitor with the reserved view-all id", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.selectAll();
    expect(sent).toEqual([{ t: "SelectMonitor", c: { id: COMPOSITE_MONITOR_ID } }]);
  });

  it("handleMessage() records an inbound MonitorList and fires onMonitors", () => {
    const monitors: MonitorDesc[] = [
      { id: 0, width: 800, height: 600, primary: true },
      { id: 1, width: 640, height: 480, primary: false },
    ];
    let notified: MonitorDesc[] | null = null;
    const client = new ControlClient(() => {}, { onMonitors: (m) => (notified = m) });

    expect(client.monitors).toEqual([]);
    client.handleMessage(encodeControl({ t: "MonitorList", c: { monitors } }));
    expect(client.monitors).toEqual(monitors);
    expect(notified).toEqual(monitors);
  });

  it("handleMessage() surfaces an inbound Error via onError", () => {
    let err: string | null = null;
    const client = new ControlClient(() => {}, { onError: (m) => (err = m) });
    client.handleMessage(encodeControl({ t: "Error", c: { message: "unknown monitor id 99" } }));
    expect(err).toBe("unknown monitor id 99");
  });

  it("installGrant() frames an InstallGrant message (H1)", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.installGrant(`{"sig":"x"}`);
    expect(sent).toEqual([{ t: "InstallGrant", c: { signed_grant: `{"sig":"x"}` } }]);
  });

  it("handleMessage() fires onGrantInstalled for a GrantInstalled ack (H1)", () => {
    let acked = false;
    const client = new ControlClient(() => {}, { onGrantInstalled: () => (acked = true) });
    client.handleMessage(encodeControl({ t: "GrantInstalled" }));
    expect(acked).toBe(true);
  });

  it("requestBackstageFeatures() asks, and onBackstageFeatures hears the answer (docs/58)", () => {
    const sent: ControlMessage[] = [];
    let heard: string[] | null = null;
    const client = new ControlClient((p) => sent.push(decodeControl(p)), { onBackstageFeatures: (f) => (heard = f) });
    client.requestBackstageFeatures();
    expect(sent).toEqual([{ t: "RequestBackstageFeatures" }]);
    client.handleMessage(encodeControl({ t: "BackstageFeatures", c: { features: ["file_manage"] } }));
    expect(heard).toEqual(["file_manage"]);
  });

  it("requestQuality() frames a RequestQuality message (M11)", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.requestQuality();
    expect(sent).toEqual([{ t: "RequestQuality" }]);
  });

  it("setQuality(q) frames a SetQuality message carrying all five fields (M11)", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    const q: QualitySettings = {
      scale_div: 2,
      fps: 15,
      color: "Gray",
      max_bitrate_bps: 1000000,
      adaptive: false,
    };
    client.setQuality(q);
    expect(sent).toEqual([{ t: "SetQuality", c: { quality: q } }]);
  });

  it("handleMessage() surfaces QualityApplied and QualityStats (M11)", () => {
    const applied: { quality: QualitySettings; encoder_bitrate_bps: number; capped_by_policy: boolean }[] =
      [];
    const stats: number[] = [];
    const rates: number[] = [];
    const client = new ControlClient(() => {}, {
      onQualityApplied: (a) => applied.push(a),
      onQualityStats: (s) => {
        stats.push(s.measured_bitrate_bps);
        rates.push(s.fps_x100);
      },
    });

    client.handleMessage(
      encodeControl({
        t: "QualityApplied",
        c: {
          quality: { scale_div: 2, fps: 15, color: "Gray", max_bitrate_bps: 1000000, adaptive: true },
          encoder_bitrate_bps: 1000000,
          capped_by_policy: true,
        },
      }),
    );
    client.handleMessage(
      encodeControl({
        t: "QualityStats",
        c: {
          encoder_bitrate_bps: 742000,
          measured_bitrate_bps: 731520,
          fraction_lost_256: 13,
          rtt_ms: 24,
          width: 960,
          height: 540,
          feedback_reports: 42,
          fps_x100: 1437,
          dropped_frames_total: 118,
        },
      }),
    );

    expect(applied).toHaveLength(1);
    expect(applied[0].quality.color).toBe("Gray");
    // The flag exists so the operator can tell "I asked for too much" from "this machine is capped".
    expect(applied[0].capped_by_policy).toBe(true);
    expect(stats).toEqual([731520]);
    // The achieved rate has to survive the CLIENT too, not just the codec: the readout is fed from
    // this callback, and a client that dropped the field would leave the operator with the same
    // blind spot the field was added to close.
    expect(rates).toEqual([1437]);
  });

  it("setInputBlocked(b) frames a SetInputBlocked, and handleMessage routes InputBlockApplied", () => {
    const sent: ControlMessage[] = [];
    const applied: boolean[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onInputBlockApplied: (b) => applied.push(b),
    });
    client.setInputBlocked(true);
    expect(sent).toEqual([{ t: "SetInputBlocked", c: { blocked: true } }]);
    // The agent's ack — the state ACTUALLY in force — is what the UI must reflect, so the client
    // routes it to onInputBlockApplied. Here the agent reports it could not arm the block (false)
    // despite the request being true.
    client.handleMessage(encodeControl({ t: "InputBlockApplied", c: { blocked: false } }));
    expect(applied).toEqual([false]);
  });

  it("setMonitorBlanked(b) frames a SetMonitorBlanked, handleMessage routes MonitorBlankedApplied", () => {
    const sent: ControlMessage[] = [];
    const applied: boolean[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onMonitorBlankedApplied: (b) => applied.push(b),
    });
    client.setMonitorBlanked(true);
    expect(sent).toEqual([{ t: "SetMonitorBlanked", c: { blanked: true } }]);
    // The agent's ack — the state ACTUALLY in force — is what the UI must reflect. Here the
    // agent reports window creation failed (false) despite the request being true.
    client.handleMessage(encodeControl({ t: "MonitorBlankedApplied", c: { blanked: false } }));
    expect(applied).toEqual([false]);
  });

  it("reboot(safeMode) frames a RebootGuest, and handleMessage routes RebootScheduled", () => {
    const sent: ControlMessage[] = [];
    const scheduled: boolean[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onRebootScheduled: (s) => scheduled.push(s),
    });
    client.reboot(true);
    expect(sent).toEqual([{ t: "RebootGuest", c: { safe_mode: true } }]);
    // The agent's ack confirms the mode it actually scheduled; the UI reflects that, not the request.
    client.handleMessage(encodeControl({ t: "RebootScheduled", c: { safe_mode: true } }));
    expect(scheduled).toEqual([true]);
  });

  it("launchTool(key) frames a LaunchTool, and handleMessage routes ToolLaunched", () => {
    const sent: ControlMessage[] = [];
    const launched: string[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onToolLaunched: (tool) => launched.push(tool),
    });
    client.launchTool("event_viewer");
    expect(sent).toEqual([{ t: "LaunchTool", c: { tool: "event_viewer" } }]);
    client.handleMessage(encodeControl({ t: "ToolLaunched", c: { tool: "event_viewer" } }));
    expect(launched).toEqual(["event_viewer"]);
  });

  it("runCommand(...) frames a RunCommand, and handleMessage routes CommandResult", () => {
    const sent: ControlMessage[] = [];
    const results: CommandResult[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onCommandResult: (r) => results.push(r),
    });
    client.runCommand("whoami", "Cmd", false);
    expect(sent).toEqual([{ t: "RunCommand", c: { command: "whoami", shell: "Cmd", as_user: false } }]);
    client.handleMessage(
      encodeControl({
        t: "CommandResult",
        c: { exit_code: 0, stdout: "nt authority\\system", stderr: "", truncated: false, timed_out: false },
      }),
    );
    expect(results).toEqual([
      { exit_code: 0, stdout: "nt authority\\system", stderr: "", truncated: false, timed_out: false },
    ]);
  });

  it("elevatedRun(...) frames an ElevatedRun, and handleMessage routes both verdicts", () => {
    const sent: ControlMessage[] = [];
    const results: CommandResult[] = [];
    const denials: string[] = [];
    const errors: string[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onCommandResult: (r) => results.push(r),
      onElevationDenied: (reason) => denials.push(reason),
      onError: (m) => errors.push(m),
    });
    client.elevatedRun(`{"claims":{},"sig":"ab"}`, "whoami /groups", "Cmd");
    expect(sent).toEqual([
      {
        t: "ElevatedRun",
        c: { signed_elevation: `{"claims":{},"sig":"ab"}`, command: "whoami /groups", shell: "Cmd" },
      },
    ]);
    // SUCCESS comes back as the ordinary CommandResult — the viewer renders it with the same code.
    client.handleMessage(
      encodeControl({
        t: "CommandResult",
        c: { exit_code: 0, stdout: "High Mandatory Level", stderr: "", truncated: false, timed_out: false },
      }),
    );
    expect(results).toHaveLength(1);
    // A REFUSAL routes to its OWN callback and NOT to onError. That separation is the whole reason
    // ElevationDenied exists: "the command failed" and "nothing ran, elevation was declined" must be
    // distinguishable, or a viewer cannot say whether a privileged action happened.
    client.handleMessage(
      encodeControl({ t: "ElevationDenied", c: { reason: "elevation grant has already been used" } }),
    );
    expect(denials).toEqual(["elevation grant has already been used"]);
    expect(errors).toEqual([]);
  });

  it("requestScreenshot() frames a RequestScreenshot", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.requestScreenshot();
    expect(sent).toEqual([{ t: "RequestScreenshot" }]);
  });

  /**
   * Loop 91: the SEALED audit event survives decode and reaches BOTH recording handlers.
   *
   * Three mutations of this path were unkillable before this test existed — `decodeSealedAudit`
   * returning null for a real object, and either handler being handed `null` instead of the event.
   * That is the shape this project keeps getting bitten by: a feature that is complete everywhere
   * except the layer that actually delivers it, with every unit below it green.
   *
   * The event is compared by deep equality against the object that went in, because the console
   * re-posts it VERBATIM and the control plane re-hashes its canonical preimage — a single key
   * added, dropped or re-typed anywhere on this path presents as the agent having forged its own
   * audit trail, and wedges the rest of the session's chain.
   */
  it("carries the sealed audit event through decode and into both recording handlers", () => {
    const started: unknown[] = [];
    const stopped: unknown[] = [];
    const client = new ControlClient(() => {}, {
      onRecordingStarted: (_at, audit) => started.push(audit),
      onRecordingStopped: (_r, audit) => stopped.push(audit),
    });

    const startEvent = {
      id: "44444444-4444-4444-4444-444444444444",
      seq: 0,
      session_id: "11111111-1111-4111-8111-111111111111",
      technician_id: "22222222-2222-4222-8222-222222222222",
      machine_id: "33333333-3333-4333-8333-333333333333",
      occurred_at_unix_ms: 1730000000000,
      action: { kind: "recording_started", started_at_unix_ms: 1730000000000, directory: "D:/rec" },
      outcome: { result: "ok" },
      prev_hash: "",
      hash: "a".repeat(64),
    };
    client.handleMessage(
      encodeControl({
        t: "RecordingStarted",
        c: { started_at_unix_ms: 1730000000000, audit: startEvent },
      }),
    );
    expect(started).toEqual([startEvent]);

    const stopEvent = {
      ...startEvent,
      seq: 1,
      prev_hash: "a".repeat(64),
      hash: "b".repeat(64),
      action: {
        kind: "recording_stopped",
        frames: 913,
        payload_bytes: 4211337,
        truncated: null,
        dropped_frames: 0, // audit canonical key (agent/backstage/audit.rs) — same string as the control-channel wire key "dropped_frames" but a different schema
        // The list is the audit-valuable part: it is what ties the record to the file somebody
        // later hands over, and it exists ONLY here — nothing in the UI would show it missing.
        segment_sha256: ["c".repeat(64), "d".repeat(64)],
        directory: "D:/rec",
      },
    };
    client.handleMessage(
      encodeControl({
        t: "RecordingStopped",
        c: {
          segments: 2,
          frames: 913,
          payload_bytes: 4211337,
          truncated: null,
          dropped_frames_total: 0,
          directory: "D:/rec",
          audit: stopEvent,
        },
      }),
    );
    expect(stopped).toEqual([stopEvent]);
    // Nested arrays and nulls survive: a decoder that rebuilt the object field-by-field would be
    // the natural way to lose exactly these.
    expect((stopped[0] as typeof stopEvent).action.segment_sha256).toEqual([
      "c".repeat(64),
      "d".repeat(64),
    ]);
    expect((stopped[0] as typeof stopEvent).action.truncated).toBeNull();
  });

  /**
   * An ack from an agent that sealed NOTHING decodes as `null`, not as a throw.
   *
   * The asymmetry with `truncated` two tests up is deliberate. A missing `truncated` would silently
   * turn a truncated recording into a clean one, so it is rejected; a missing `audit` can only make
   * the trail thinner, never make a false statement — and the message itself is the operator's
   * confirmation that a video of somebody's screen is being written, so throwing it away over an
   * audit key the agent may legitimately omit would break the feature to protect the trail.
   */
  it("decodes a recording ack with no audit key, and one with a non-object audit, as no event", () => {
    const started: unknown[] = [];
    const client = new ControlClient(() => {}, {
      onRecordingStarted: (_at, audit) => started.push(audit),
    });

    // Absent key (an older agent, or one with no vouched-for session).
    client.handleMessage(
      new TextEncoder().encode(`{"t":"RecordingStarted","c":{"started_at_unix_ms":7}}`),
    );
    // Explicit null (the shape this agent actually sends on the dev path).
    client.handleMessage(
      new TextEncoder().encode(`{"t":"RecordingStarted","c":{"started_at_unix_ms":7,"audit":null}}`),
    );
    // Junk that is not an object: read as "no event" rather than passed on to be posted.
    client.handleMessage(
      new TextEncoder().encode(`{"t":"RecordingStarted","c":{"started_at_unix_ms":7,"audit":[1,2]}}`),
    );
    expect(started).toEqual([null, null, null]);
  });
  it("startRecording()/stopRecording() frame the asks, and the acks route to their handlers", () => {
    const sent: ControlMessage[] = [];
    const started: number[] = [];
    const stopped: RecordingResult[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onRecordingStarted: (at) => started.push(at),
      onRecordingStopped: (r) => stopped.push(r),
    });
    client.startRecording();
    client.stopRecording();
    expect(sent).toEqual([{ t: "StartRecording" }, { t: "StopRecording" }]);

    client.handleMessage(
      encodeControl({ t: "RecordingStarted", c: { started_at_unix_ms: 1764000000123, audit: null } }),
    );
    expect(started).toEqual([1764000000123]);

    const result: RecordingResult = {
      segments: 1,
      frames: 900,
      payload_bytes: 123456,
      truncated: null,
      dropped_frames_total: 0,
      directory: "C:\\rmt-agent\\recordings",
    };
    client.handleMessage(encodeControl({ t: "RecordingStopped", c: { ...result, audit: null } }));
    expect(stopped).toEqual([{ ...result, audit: null }]);
    // `truncated` survives the round trip through the client, not just the codec — this is the
    // field the operator's "was my recording complete?" answer is built from.
    client.handleMessage(
      encodeControl({ t: "RecordingStopped", c: { ...result, truncated: "disk_low", audit: null } }),
    );
    expect(stopped[1]?.truncated).toBe("disk_low");
  });

  it("listDirectory(path) frames a ListDirectory, and handleMessage routes DirectoryListing", () => {
    const sent: ControlMessage[] = [];
    const listings: DirectoryListing[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onDirectoryListing: (l) => listings.push(l),
    });
    client.listDirectory("C:\\");
    expect(sent).toEqual([{ t: "ListDirectory", c: { path: "C:\\" } }]);
    const entries = [{ name: "Users", is_dir: true, size: 0, modified_unix: 1700000000 }];
    client.handleMessage(
      encodeControl({
        t: "DirectoryListing",
        c: { path: "C:\\", entries, truncated: false, audit: null },
      }),
    );
    expect(listings).toEqual([{ path: "C:\\", entries, truncated: false, audit: null }]);
  });

  // docs/25 F04: a refusal must reach its OWN handler. Routing it to `onError` would have been the
  // cheap option and it loses the audit event — the one thing the message exists to deliver.
  it("handleMessage routes DirectoryListingRefused to its own handler, not onError", () => {
    const refusals: { path: string; reason: string; audit: unknown }[] = [];
    const errors: string[] = [];
    const client = new ControlClient(() => {}, {
      onDirectoryListingRefused: (r) => refusals.push(r),
      onError: (m) => errors.push(m),
    });
    const audit = { seq: 0, action: { kind: "file_browse", path: "C:\\" }, outcome: { result: "denied" } };
    client.handleMessage(
      encodeControl({
        t: "DirectoryListingRefused",
        c: { path: "C:\\", reason: "no backstage grant is installed for this session", audit },
      }),
    );
    expect(refusals).toEqual([
      { path: "C:\\", reason: "no backstage grant is installed for this session", audit },
    ]);
    expect(errors).toEqual([]);
  });

  it("endSession(uninstall) frames an EndSession, and handleMessage routes SessionEnding", () => {
    const sent: ControlMessage[] = [];
    const ended: boolean[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)), {
      onSessionEnding: (u) => ended.push(u),
    });
    client.endSession(true);
    expect(sent).toEqual([{ t: "EndSession", c: { uninstall: true } }]);
    client.handleMessage(encodeControl({ t: "SessionEnding", c: { uninstall: true } }));
    expect(ended).toEqual([true]);
  });

  it("handleMessage routes SessionEndedByGuest to onSessionEndedByGuest", () => {
    let ended = 0;
    const client = new ControlClient(() => {}, {
      onSessionEndedByGuest: () => { ended++; },
    });
    client.handleMessage(new TextEncoder().encode(`{"t":"SessionEndedByGuest"}`));
    expect(ended).toBe(1);
  });

  it("handleMessage routes TransferDir to onTransferDir with the advertised path", () => {
    const paths: string[] = [];
    const client = new ControlClient(() => {}, {
      onTransferDir: (p) => paths.push(p),
    });
    client.handleMessage(encodeControl({ t: "TransferDir", c: { path: "D:\\rmt\\transfers" } }));
    expect(paths).toEqual(["D:\\rmt\\transfers"]);
    // A second advertisement overwrites the first (agent reconnect or config reload).
    client.handleMessage(encodeControl({ t: "TransferDir", c: { path: "C:\\rmt-agent\\transfers" } }));
    expect(paths).toEqual(["D:\\rmt\\transfers", "C:\\rmt-agent\\transfers"]);
  });

  /**
   * The tolerance contract. `handleMessage` is called with no try/catch from `App.tsx`, inside
   * `transport.ts`'s `for (const f of frames)` loop over the frames coalesced into one SCTP message.
   * A throw escaping it therefore abandons the loop and takes the INNOCENT SIBLING frames with it —
   * which is why the codec stays strict and the client became tolerant.
   */
  it("handleMessage() does NOT throw on an unknown variant — it routes to onUnknown", () => {
    const errs: string[] = [];
    const client = new ControlClient(() => {}, { onUnknown: (e) => errs.push(e.message) });
    expect(() =>
      client.handleMessage(new TextEncoder().encode(`{"t":"FromANewerAgent","c":{"x":1}}`)),
    ).not.toThrow();
    expect(errs).toHaveLength(1);
    expect(errs[0]).toMatch(/unknown control variant/);
  });

  it("a VALID message handled AFTER an undecodable one still works (the sibling-frame case)", () => {
    // This is the regression the tolerance exists for: the second frame here stands for a MonitorList
    // that arrived in the same SCTP message as something we could not parse. If the throw escaped, the
    // caller's frame loop would never reach it and the picker would stay empty for the whole session.
    const monitors: MonitorDesc[] = [{ id: 0, width: 800, height: 600, primary: true }];
    let notified: MonitorDesc[] | null = null;
    const errs: Error[] = [];
    const client = new ControlClient(() => {}, {
      onMonitors: (m) => (notified = m),
      onUnknown: (e) => errs.push(e),
    });

    for (const payload of [
      new TextEncoder().encode(`{"t":"FromANewerAgent"}`),
      encodeControl({ t: "MonitorList", c: { monitors } }),
    ]) {
      client.handleMessage(payload);
    }

    expect(errs).toHaveLength(1);
    expect(notified).toEqual(monitors);
    expect(client.monitors).toEqual(monitors);
  });

  it("malformed content also reaches onUnknown, not the caller", () => {
    // Not just an unknown TAG: a known variant with a bad shape (a Sepia colour) must be absorbed
    // the same way, because it reaches the caller through the identical code path.
    const errs: Error[] = [];
    const client = new ControlClient(() => {}, { onUnknown: (e) => errs.push(e) });
    expect(() =>
      client.handleMessage(
        new TextEncoder().encode(
          `{"t":"QualityApplied","c":{"quality":{"scale_div":1,"fps":30,"color":"Sepia","max_bitrate_bps":3000000,"adaptive":true},"encoder_bitrate_bps":1,"capped_by_policy":false}}`,
        ),
      ),
    ).not.toThrow();
    expect(errs).toHaveLength(1);
  });

  it("without an onUnknown handler the default is console.debug — never a throw", () => {
    // A mixed-version fleet makes this an EXPECTED condition, not a fault: warn-level noise here
    // would train the operator to ignore the console. Assert the default is wired, not just silent.
    const debug = vi.spyOn(console, "debug").mockImplementation(() => {});
    try {
      const client = new ControlClient(() => {});
      expect(() => client.handleMessage(new TextEncoder().encode(`{"t":"Nope"}`))).not.toThrow();
      expect(debug).toHaveBeenCalledTimes(1);
    } finally {
      debug.mockRestore();
    }
  });
});
