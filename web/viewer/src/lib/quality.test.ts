/**
 * Quality preset / clamp / readout tests.
 *
 * The clamp table below is deliberately the SAME table as the Rust `clamped_saturates_at_both_extremes`
 * in `crates/agent-core/src/quality.rs` (0 and the u32::MAX equivalents at both extremes), because the
 * two clamps are a mirrored pair: if they ever disagree, the operator's control shows one value and
 * the agent encodes another, and nothing else in the system would notice.
 */

import { describe, it, expect } from "vitest";
import {
  BITRATE_CHOICES_KBPS,
  DEFAULT_QUALITY,
  FPS_CHOICES,
  FPS_DIVERGENCE_RATIO,
  HIGH_LOSS_256,
  LOW_LOSS_256,
  MAX_FPS,
  MAX_MAX_BITRATE_BPS,
  MAX_SCALE_DIV,
  MIN_FPS,
  MIN_MAX_BITRATE_BPS,
  MIN_SCALE_DIV,
  QUALITY_PRESETS,
  bitrateChoicesKbps,
  clampQuality,
  effectiveQuality,
  formatQualityReadout,
  fpsDiverges,
  initialQualityIntent,
  presetIdFor,
  qualityFromPreset,
  qualityIntentReducer,
  qualityTone,
  type QualityIntent,
  type QualityIntentAction,
} from "./quality";
import type { QualitySettings, QualityStats } from "./control";

/** The largest u32, i.e. the value Rust's `clamped_saturates_at_both_extremes` drives the top with. */
const U32_MAX = 4294967295;

const stats = (over: Partial<QualityStats> = {}): QualityStats => ({
  encoder_bitrate_bps: 742000,
  measured_bitrate_bps: 731520,
  fraction_lost_256: 13,
  rtt_ms: 24,
  width: 960,
  height: 540,
  feedback_reports: 42,
  // 29.8 fps achieved with nothing dropped: a healthy 30 fps session, so the baseline sample carries
  // no warning and no drop count and the divergence branch has to be asked for explicitly.
  fps_x100: 2980,
  dropped_frames_total: 0,
  ...over,
});

describe("quality presets", () => {
  it("round-trips through presetIdFor ∘ qualityFromPreset for every preset", () => {
    // Also proves the four are mutually distinct: if two presets had identical settings, one of them
    // could never round-trip (presetIdFor returns the first match).
    for (const p of QUALITY_PRESETS) {
      expect(presetIdFor(qualityFromPreset(p.id))).toBe(p.id);
    }
    expect(QUALITY_PRESETS).toHaveLength(4);
  });

  it("Balanced IS the shipped default, field by field", () => {
    // Not a struct-equality shortcut against DEFAULT_QUALITY alone: the point is that a fresh session
    // (which the agent starts at its own DEFAULT) opens showing "Balanced" rather than "Custom".
    const balanced = qualityFromPreset("balanced");
    expect(balanced.scale_div).toBe(1);
    expect(balanced.fps).toBe(30);
    expect(balanced.color).toBe("Full");
    expect(balanced.max_bitrate_bps).toBe(3_000_000);
    expect(balanced.adaptive).toBe(true);
    expect(presetIdFor(DEFAULT_QUALITY)).toBe("balanced");
  });

  it("keeps full resolution in the Text preset and pays with fps + colour instead", () => {
    // The deliberate choice documented in quality.ts: on a support session unreadable text is worse
    // than choppy motion, so the slow-link preset does NOT downscale.
    const text = qualityFromPreset("text");
    expect(text.scale_div).toBe(1);
    expect(text.fps).toBe(5);
    expect(text.color).toBe("Gray");
    expect(text.max_bitrate_bps).toBe(400_000);
  });

  it("returns 'custom' for settings matching no preset", () => {
    expect(presetIdFor({ ...DEFAULT_QUALITY, max_bitrate_bps: 1_234_000 })).toBe("custom");
    // A single differing field is enough — including the non-numeric ones, which a laxer comparison
    // would skip and then mislabel as a preset the operator never chose.
    expect(presetIdFor({ ...DEFAULT_QUALITY, adaptive: false })).toBe("custom");
    expect(presetIdFor({ ...DEFAULT_QUALITY, color: "Gray" })).toBe("custom");
    expect(presetIdFor({ ...DEFAULT_QUALITY, fps: 29 })).toBe("custom");
    expect(presetIdFor({ ...DEFAULT_QUALITY, scale_div: 3 })).toBe("custom");
  });

  it("every preset survives its own clamp", () => {
    // The shipped-constant net: a preset outside the clamp would be silently rewritten by the agent,
    // so the picker would show one thing and the encoder do another.
    for (const p of QUALITY_PRESETS) {
      expect(clampQuality(p.settings)).toEqual(p.settings);
    }
    expect(clampQuality(DEFAULT_QUALITY)).toEqual(DEFAULT_QUALITY);
  });

  it("every preset's values appear on the advanced panel's ladders", () => {
    // Otherwise a `<select>` whose value is off-ladder renders blank in React, and picking a preset
    // would leave the advanced panel showing nothing for that field.
    for (const p of QUALITY_PRESETS) {
      expect(FPS_CHOICES).toContain(p.settings.fps);
      expect(BITRATE_CHOICES_KBPS).toContain(p.settings.max_bitrate_bps / 1000);
      expect(p.settings.scale_div).toBeGreaterThanOrEqual(MIN_SCALE_DIV);
      expect(p.settings.scale_div).toBeLessThanOrEqual(MAX_SCALE_DIV);
    }
  });
});

describe("clampQuality (mirror of Rust QualitySettings::clamped)", () => {
  it("saturates at both extremes — the same table as the Rust test", () => {
    const zeroed = clampQuality({
      scale_div: 0,
      fps: 0,
      color: "Gray",
      max_bitrate_bps: 0,
      adaptive: false,
    });
    expect(zeroed.scale_div).toBe(MIN_SCALE_DIV);
    expect(zeroed.fps).toBe(MIN_FPS);
    expect(zeroed.max_bitrate_bps).toBe(MIN_MAX_BITRATE_BPS);
    // Non-numeric fields pass through untouched.
    expect(zeroed.color).toBe("Gray");
    expect(zeroed.adaptive).toBe(false);

    const maxed = clampQuality({
      scale_div: U32_MAX,
      fps: U32_MAX,
      color: "Full",
      max_bitrate_bps: U32_MAX,
      adaptive: true,
    });
    expect(maxed.scale_div).toBe(MAX_SCALE_DIV);
    expect(maxed.fps).toBe(MAX_FPS);
    expect(maxed.max_bitrate_bps).toBe(MAX_MAX_BITRATE_BPS);
    expect(maxed.color).toBe("Full");
    expect(maxed.adaptive).toBe(true);
  });

  it("saturates, never wraps", () => {
    // The distinction the Rust doc calls out: a modular reduction of a huge fps would land INSIDE the
    // legal range and look fine, so assert the bound itself rather than just "legal".
    expect(clampQuality({ ...DEFAULT_QUALITY, fps: 61 }).fps).toBe(MAX_FPS);
    expect(clampQuality({ ...DEFAULT_QUALITY, fps: 1_000_000 }).fps).toBe(MAX_FPS);
    expect(clampQuality({ ...DEFAULT_QUALITY, scale_div: 99 }).scale_div).toBe(MAX_SCALE_DIV);
    expect(clampQuality({ ...DEFAULT_QUALITY, max_bitrate_bps: 1 }).max_bitrate_bps).toBe(
      MIN_MAX_BITRATE_BPS,
    );
  });

  it("leaves legal values alone and is idempotent", () => {
    const legal: QualitySettings = {
      scale_div: 2,
      fps: 15,
      color: "Gray",
      max_bitrate_bps: 1_000_000,
      adaptive: true,
    };
    expect(clampQuality(legal)).toEqual(legal);
    expect(clampQuality(clampQuality(legal))).toEqual(clampQuality(legal));

    const wild: QualitySettings = {
      scale_div: 99,
      fps: 0,
      color: "Full",
      max_bitrate_bps: 1,
      adaptive: false,
    };
    expect(clampQuality(clampQuality(wild))).toEqual(clampQuality(wild));
  });

  it("coerces values a browser can produce but a u32 cannot represent", () => {
    // NaN and 1.5 have no Rust counterpart — and both would fail SILENTLY on the wire, because
    // JSON.stringify(NaN) is `null` and 1.5 is not a u32, so serde would reject the whole message and
    // the operator's setting would simply never be applied.
    const fractional = clampQuality({ ...DEFAULT_QUALITY, scale_div: 2.7, fps: 15.9 });
    expect(fractional.scale_div).toBe(2);
    expect(fractional.fps).toBe(15);
    expect(Number.isInteger(fractional.max_bitrate_bps)).toBe(true);

    // NaN has no ordering, so it would poison both comparisons and pass straight through a naive
    // clamp — it takes the field's shipped default instead.
    const nan = clampQuality({ ...DEFAULT_QUALITY, fps: NaN, max_bitrate_bps: NaN });
    expect(nan.fps).toBe(DEFAULT_QUALITY.fps);
    expect(nan.max_bitrate_bps).toBe(DEFAULT_QUALITY.max_bitrate_bps);

    // ±Infinity is NOT the same case: it means "arbitrarily large/small" and saturates to the bound,
    // which is the u32::MAX / 0 row of the Rust table by another spelling.
    expect(clampQuality({ ...DEFAULT_QUALITY, scale_div: Infinity }).scale_div).toBe(MAX_SCALE_DIV);
    expect(clampQuality({ ...DEFAULT_QUALITY, fps: -Infinity }).fps).toBe(MIN_FPS);

    // Idempotent from these inputs too — the fallback and the saturated bound are both in range.
    const coerced = clampQuality({ ...DEFAULT_QUALITY, fps: NaN, scale_div: Infinity });
    expect(clampQuality(coerced)).toEqual(coerced);
  });
});

describe("quality readout", () => {
  // PREMISE NOTE. These three expectations changed shape when `fps_x100`/`dropped_frames` landed:
  // they previously pinned a readout with NO frame-rate term at all, which was the gap — an operator
  // who commanded 30 fps and got 14 was never told. The strings below are the same assertions under
  // the new premise (a rate term always present), not relaxed ones.
  it("formats the live sample", () => {
    // 731520 bps → 732 kbps; 13/256 → 5.1 % loss; 2980 → 29.8 fps.
    expect(formatQualityReadout(stats())).toBe("960×540 · 29.8 fps · 732 kbps · 5.1% loss · rtt 24 ms");
  });

  it("says so instead of printing a confident zero when nothing has been measured", () => {
    expect(formatQualityReadout(null)).toBe("no stats yet");
    expect(formatQualityReadout(undefined)).toBe("no stats yet");
    // feedback_reports === 0 means no RTCP report block has been CONSUMED, so fraction_lost and rtt
    // are initial values rather than measurements — printing "0.0% loss · rtt 0 ms" would be stating
    // a fact nothing in the system has established.
    expect(formatQualityReadout(stats({ feedback_reports: 0, fraction_lost_256: 0, rtt_ms: 0 }))).toBe(
      "960×540 · 29.8 fps · 732 kbps · awaiting feedback",
    );
    // Feedback flowing but RTT not yet derivable (the agent documents 0 as "not yet measurable").
    expect(formatQualityReadout(stats({ rtt_ms: 0 }))).toBe(
      "960×540 · 29.8 fps · 732 kbps · 5.1% loss · rtt —",
    );
    // fps_x100 === 0 is the SAME kind of statement — a window too short to divide by, not a stalled
    // encoder — so it takes an em dash rather than reading "0.0 fps".
    expect(formatQualityReadout(stats({ fps_x100: 0 }), 30)).toBe(
      "960×540 · —/30 fps · 732 kbps · 5.1% loss · rtt 24 ms",
    );
  });

  it("reports the encoded size, which is not the desktop size", () => {
    // width/height are post-scale, post-even-crop: this is what the encoder produced, and it is the
    // only place the operator sees the effect of scale_div land.
    expect(formatQualityReadout(stats({ width: 480, height: 270 }))).toContain("480×270");
  });

  it("prints achieved BESIDE commanded, so the gap is legible without arithmetic", () => {
    expect(formatQualityReadout(stats(), 30)).toContain("29.8/30 fps");
    // A healthy session must NOT be flagged — 29.8 of 30 is the pacing loop's own jitter.
    expect(formatQualityReadout(stats(), 30)).not.toContain("⚠");
  });

  it("flags a materially low achieved rate — the 30-commanded / 14-achieved case", () => {
    // The exact divergence the field was added for: the lab VM captures ~14 fps when commanded 30.
    // Without the flag the operator sees a control reading 30 and a picture that feels wrong, with
    // nothing in the UI connecting the two.
    const out = formatQualityReadout(stats({ fps_x100: 1437, dropped_frames_total: 118 }), 30);
    expect(out).toContain("14.4/30 fps ⚠");
    // …and the REASON alongside it: capture outran encode and the queue kept the newest frame.
    expect(out).toContain("(118 dropped total)");
  });

  it("separates the two shortfall causes: dropped frames vs a capturer that cannot keep up", () => {
    // Diverging with drops → the encoder queue is shedding. Diverging with none → the capture side
    // never produced the frames. Same symptom, different fault, and the count is what tells them
    // apart, so it must not be folded into the warning.
    expect(formatQualityReadout(stats({ fps_x100: 1400, dropped_frames_total: 0 }), 30)).toContain(
      "14.0/30 fps ⚠",
    );
    expect(formatQualityReadout(stats({ fps_x100: 1400, dropped_frames_total: 0 }), 30)).not.toContain(
      "dropped",
    );
    // Drops that the stream RECOVERED from are still shown: the counter is session-total, and frames
    // the encoder threw away are never routine even once the rate is back at target.
    expect(formatQualityReadout(stats({ fps_x100: 2980, dropped_frames_total: 3 }), 30)).toContain(
      "29.8/30 fps (3 dropped total)",
    );
    expect(formatQualityReadout(stats({ fps_x100: 2980, dropped_frames_total: 3 }), 30)).not.toContain("⚠");
  });

  it("shows the frame rate even while feedback is still absent", () => {
    // The rate is an ENCODER-side fact and owes nothing to RTCP. Hiding it behind "awaiting feedback"
    // would withhold it for the first second of every session — and forever on a link whose feedback
    // never arrives, which is exactly where the operator most needs it.
    const out = formatQualityReadout(stats({ feedback_reports: 0, fps_x100: 1437, dropped_frames_total: 9 }), 30);
    expect(out).toContain("14.4/30 fps ⚠");
    expect(out).toContain("(9 dropped total)");
    expect(out).toContain("awaiting feedback");
  });
});

describe("fpsDiverges", () => {
  it("switches at exactly FPS_DIVERGENCE_RATIO of the commanded rate", () => {
    expect(FPS_DIVERGENCE_RATIO).toBe(0.85);
    // 30 fps commanded → the boundary is 25.5 fps. Assert the bound itself, not merely "low values
    // flag": a threshold that had drifted to, say, 0.5 would still pass a coarse high/low pair.
    expect(fpsDiverges(2550, 30)).toBe(false); // exactly at the ratio is still acceptable
    expect(fpsDiverges(2549, 30)).toBe(true);
    expect(fpsDiverges(3000, 30)).toBe(false);
    // The ratio is RELATIVE, so the Text preset's 5 fps gets a proportionally tighter absolute band
    // (boundary 4.25 fps) rather than the 4.5-fps slack a fixed offset tuned for 30 fps would give it.
    expect(fpsDiverges(430, 5)).toBe(false);
    expect(fpsDiverges(420, 5)).toBe(true);
  });

  it("treats 'not yet measurable' as neither good nor bad", () => {
    // 0 means the agent's window was too short to divide by. Flagging it would put a warning on the
    // first second of every session, which is the alarm-fatigue failure qualityTone avoids too.
    expect(fpsDiverges(0, 30)).toBe(false);
    // No commanded rate to compare against ⇒ nothing to diverge from.
    expect(fpsDiverges(1000)).toBe(false);
    expect(fpsDiverges(1000, 0)).toBe(false);
  });
});

describe("qualityTone", () => {
  it("switches at exactly the rate controller's LOW/HIGH loss thresholds", () => {
    // Same constants as crates/transport-webrtc/src/video/rate.rs, so the colour changes at the same
    // points the encoder changes behaviour: <=5 it ramps up, <=26 is the dead band, above it backs off.
    expect(LOW_LOSS_256).toBe(5);
    expect(HIGH_LOSS_256).toBe(26);

    expect(qualityTone(stats({ fraction_lost_256: 0 }))).toBe("good");
    expect(qualityTone(stats({ fraction_lost_256: LOW_LOSS_256 }))).toBe("good"); // 5 is still clean
    expect(qualityTone(stats({ fraction_lost_256: LOW_LOSS_256 + 1 }))).toBe("degraded"); // 6
    expect(qualityTone(stats({ fraction_lost_256: HIGH_LOSS_256 }))).toBe("degraded"); // 26 = dead band
    expect(qualityTone(stats({ fraction_lost_256: HIGH_LOSS_256 + 1 }))).toBe("poor"); // 27 backs off
    expect(qualityTone(stats({ fraction_lost_256: 255 }))).toBe("poor");
  });

  it("does not raise an alarm before anything has been measured", () => {
    // An amber indicator for the first second of every session teaches operators to ignore it; the
    // READOUT is where "awaiting feedback" is stated, in words that cannot be misread as a link fault.
    expect(qualityTone(null)).toBe("good");
    expect(qualityTone(undefined)).toBe("good");
    expect(qualityTone(stats({ feedback_reports: 0, fraction_lost_256: 200 }))).toBe("good");
  });
});

/**
 * The read-modify-write regression (loop-15 review finding).
 *
 * The advanced panel builds every message from ALL five fields — the wire has no partial update — so
 * what it reads from decides whether two quick edits compose or clobber each other. These drive the
 * reducer through the exact message order a high-RTT session produces.
 */
describe("qualityIntentReducer", () => {
  /** What the panel does per knob: read-modify-write against whatever it is currently displaying. */
  const edit = (intent: QualityIntent, patch: Partial<QualitySettings>): QualitySettings => ({
    ...effectiveQuality(intent),
    ...patch,
  });

  const run = (start: QualityIntent, actions: QualityIntentAction[]): QualityIntent =>
    actions.reduce(qualityIntentReducer, start);

  it("starts on the shipped default with nothing pending", () => {
    const init = initialQualityIntent();
    expect(init.acknowledged).toEqual(DEFAULT_QUALITY);
    expect(init.pending).toBeNull();
    expect(init.outstanding).toBe(0);
    expect(effectiveQuality(init)).toEqual(DEFAULT_QUALITY);
  });

  it("composes two edits made before EITHER ack lands — the bug this reducer exists for", () => {
    // Connect-time probe, answered before the operator touches anything.
    let intent = run(initialQualityIntent(), [
      { type: "requested" },
      { type: "applied", quality: DEFAULT_QUALITY },
    ]);

    // Edit 1: frame rate. The message goes out carrying 15 fps and everything else unchanged.
    const first = edit(intent, { fps: 15 });
    expect(first.fps).toBe(15);
    intent = qualityIntentReducer(intent, { type: "asked", quality: first });

    // Edit 2: colour, made BEFORE the fps reply arrives (the whole scenario).
    const second = edit(intent, { color: "Gray" });
    // THE ASSERTION. Read against `acknowledged` this carried fps 30 — the operator's first edit
    // silently undone by their second, with the agent faithfully applying what it was told.
    expect(second.fps).toBe(15);
    expect(second.color).toBe("Gray");
    intent = qualityIntentReducer(intent, { type: "asked", quality: second });
    expect(intent.outstanding).toBe(2);

    // First reply arrives: still one outstanding, so the display must NOT snap back to it.
    intent = qualityIntentReducer(intent, { type: "applied", quality: first });
    expect(effectiveQuality(intent).color).toBe("Gray");
    expect(intent.pending).not.toBeNull();

    // Second reply: everything is acknowledged, so the agent's value takes over again.
    intent = qualityIntentReducer(intent, { type: "applied", quality: second });
    expect(intent.pending).toBeNull();
    expect(intent.outstanding).toBe(0);
    expect(effectiveQuality(intent)).toEqual(second);
  });

  it("lets the AGENT's value win once everything is acknowledged (the snap-back is deliberate)", () => {
    // The operator asks for 60 fps; the machine's QualityPolicy caps it to 10. The panel shows 60
    // while the ask is in flight and 10 afterwards — showing 60 forever would be a UI that lies
    // about what the encoder is doing, which is what the acknowledged-only design got right.
    const asked: QualitySettings = { ...DEFAULT_QUALITY, fps: 60 };
    const capped: QualitySettings = { ...DEFAULT_QUALITY, fps: 10 };
    let intent = qualityIntentReducer(initialQualityIntent(), { type: "asked", quality: asked });
    expect(effectiveQuality(intent).fps).toBe(60);
    intent = qualityIntentReducer(intent, { type: "applied", quality: capped });
    expect(effectiveQuality(intent).fps).toBe(10);
    expect(intent.pending).toBeNull();
  });

  it("counts the connect-time RequestQuality, whose reply is a QualityApplied too", () => {
    // Ordered channel: the probe is sent first, so its reply arrives first. If it were not counted,
    // that reply would be consumed as the answer to the operator's edit and the panel would snap
    // back to the pre-edit settings for as long as the real reply took to arrive.
    let intent = qualityIntentReducer(initialQualityIntent(), { type: "requested" });
    const asked: QualitySettings = { ...DEFAULT_QUALITY, fps: 15 };
    intent = qualityIntentReducer(intent, { type: "asked", quality: asked });
    expect(intent.outstanding).toBe(2);
    // The probe's reply reports the agent's starting settings, NOT the operator's edit.
    intent = qualityIntentReducer(intent, { type: "applied", quality: DEFAULT_QUALITY });
    expect(effectiveQuality(intent).fps).toBe(15);
    intent = qualityIntentReducer(intent, { type: "applied", quality: asked });
    expect(effectiveQuality(intent).fps).toBe(15);
    expect(intent.pending).toBeNull();
  });

  it("saturates the counter at zero, so an unmatched reply cannot wedge the panel permanently", () => {
    // An extra/unsolicited QualityApplied with nothing outstanding. Allowed to go negative, the very
    // next edit would leave `outstanding` at 0-after-increment mismatched forever: `pending` would
    // never clear again and the panel would display the operator's ask for the rest of the session,
    // discarding every clamp and policy cap the agent reported. Worse than the bug being fixed.
    let intent = qualityIntentReducer(initialQualityIntent(), {
      type: "applied",
      quality: DEFAULT_QUALITY,
    });
    expect(intent.outstanding).toBe(0);
    intent = qualityIntentReducer(intent, { type: "applied", quality: DEFAULT_QUALITY });
    expect(intent.outstanding).toBe(0);

    // Now prove the books still balance: one ask, one ack, pending clears.
    const asked: QualitySettings = { ...DEFAULT_QUALITY, color: "Gray" };
    intent = qualityIntentReducer(intent, { type: "asked", quality: asked });
    const capped: QualitySettings = { ...DEFAULT_QUALITY, color: "Full" };
    intent = qualityIntentReducer(intent, { type: "applied", quality: capped });
    expect(intent.pending).toBeNull();
    expect(effectiveQuality(intent)).toEqual(capped);
  });

  it("resets on disconnect — quality belongs to the AGENT, not to the console", () => {
    const busy = run(initialQualityIntent(), [
      { type: "requested" },
      { type: "asked", quality: { ...DEFAULT_QUALITY, fps: 5 } },
    ]);
    expect(busy.outstanding).toBe(2);
    expect(qualityIntentReducer(busy, { type: "reset" })).toEqual(initialQualityIntent());
  });

  it("never mutates the state it is handed", () => {
    // The app holds this in a React reducer, which compares by identity: a mutated-in-place state
    // would stop re-rendering the panel at exactly the moment an ack changed something.
    const before = initialQualityIntent();
    const snapshot = JSON.parse(JSON.stringify(before)) as QualityIntent;
    qualityIntentReducer(before, { type: "asked", quality: { ...DEFAULT_QUALITY, fps: 1 } });
    qualityIntentReducer(before, { type: "applied", quality: { ...DEFAULT_QUALITY, fps: 1 } });
    expect(before).toEqual(snapshot);
  });
});

describe("bitrateChoicesKbps", () => {
  it("returns the ladder unchanged for a value already on it", () => {
    expect(bitrateChoicesKbps(3_000_000)).toEqual([...BITRATE_CHOICES_KBPS]);
  });

  it("folds an off-ladder value in, sorted — the policy-capped case", () => {
    // The agent's machine policy can cap the ceiling to any value (that is what capped_by_policy
    // reports). A <select> whose value matches no <option> renders BLANK, so without this the one
    // case where the operator most needs to read the bitrate is the case that shows nothing.
    const opts = bitrateChoicesKbps(1_500_000);
    expect(opts).toContain(1500);
    expect(opts).toEqual([...opts].sort((a, b) => a - b));
    expect(opts).toHaveLength(BITRATE_CHOICES_KBPS.length + 1);
  });

  it("spans the clamp exactly, so no legal ceiling is unreachable from the ladder", () => {
    expect(BITRATE_CHOICES_KBPS[0] * 1000).toBe(MIN_MAX_BITRATE_BPS);
    expect(BITRATE_CHOICES_KBPS[BITRATE_CHOICES_KBPS.length - 1] * 1000).toBe(MAX_MAX_BITRATE_BPS);
  });
});
