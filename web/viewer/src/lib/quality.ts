/**
 * Operator-facing quality logic (M11): the presets the picker offers, the clamp that mirrors the
 * agent's, and the formatting of the live telemetry readout.
 *
 * Pure — no React, no DOM — so every rule here is unit-testable without rendering, matching the way
 * `Viewer.tsx` keeps its picker logic in exported helpers. The wire types themselves live in
 * `control.ts` next to the codec that pins their bytes.
 */

import type { ColorMode, QualitySettings, QualityStats } from "./control";

// --- bounds (mirror of crates/agent-core/src/quality.rs) -----------------------------------------

/** Smallest accepted `scale_div`. */
export const MIN_SCALE_DIV = 1;
/** Largest accepted `scale_div`. 4 is where a 1080p desktop becomes 480×270 — past legibility. */
export const MAX_SCALE_DIV = 4;
/** Smallest accepted `fps`. Never 0: on the agent, `Duration::from_secs(1) / 0` panics. */
export const MIN_FPS = 1;
/** Largest accepted `fps`. */
export const MAX_FPS = 60;
/** Smallest accepted `max_bitrate_bps`. Below this the VP8 encoder fails to construct at all. */
export const MIN_MAX_BITRATE_BPS = 100_000;
/** Largest accepted `max_bitrate_bps` — the wire-level bound on a customer's uplink. */
export const MAX_MAX_BITRATE_BPS = 20_000_000;

/**
 * Exactly the behaviour this project shipped before M11: full resolution, 30 fps, full colour, the
 * 3 Mbps encoder default, adaptive on. Mirror of the Rust `QualitySettings::DEFAULT`.
 *
 * `adaptive: true` is not a behaviour change — the rate controller starts at the ceiling and a link
 * with no loss gives it nothing to do.
 */
export const DEFAULT_QUALITY: QualitySettings = {
  scale_div: 1,
  fps: 30,
  color: "Full",
  max_bitrate_bps: 3_000_000,
  adaptive: true,
};

// --- presets ------------------------------------------------------------------------------------

/** Identifier of a named preset, or `"custom"` for settings matching none of them. */
export type QualityPresetId = "best" | "balanced" | "low" | "text";

/** A named point in the quality space, as offered by the picker. */
export interface QualityPreset {
  id: QualityPresetId;
  label: string;
  settings: QualitySettings;
}

/**
 * The four presets, ordered best → cheapest. This is the whole quality UI for most sessions; the
 * advanced panel exists for the rest.
 */
export const QUALITY_PRESETS: readonly QualityPreset[] = [
  {
    id: "best",
    label: "Best (LAN)",
    settings: { scale_div: 1, fps: 30, color: "Full", max_bitrate_bps: 8_000_000, adaptive: true },
  },
  {
    id: "balanced",
    // Byte-identical to DEFAULT_QUALITY, deliberately: the preset the session starts on must be the
    // one the agent already applied, or the picker would open showing "Custom" on a fresh connect.
    label: "Balanced",
    settings: { scale_div: 1, fps: 30, color: "Full", max_bitrate_bps: 3_000_000, adaptive: true },
  },
  {
    id: "low",
    label: "Low bandwidth",
    settings: { scale_div: 2, fps: 15, color: "Full", max_bitrate_bps: 1_000_000, adaptive: true },
  },
  {
    id: "text",
    label: "Text (slow link)",
    // NOTE the deliberate `scale_div: 1`. The cheapest-looking move here would be to downscale, but on
    // a support session unreadable text is worse than choppy motion: the operator is reading a dialog,
    // an error code, a registry path — not watching video. So this preset spends its budget on
    // RESOLUTION and pays with frame rate (5 fps) and colour (grey, which makes both chroma planes
    // constant and costs essentially nothing to code). This is libwebrtc's MAINTAIN_RESOLUTION
    // degradation preference for screencast, expressed as a UI choice rather than an encoder hint.
    settings: { scale_div: 1, fps: 5, color: "Gray", max_bitrate_bps: 400_000, adaptive: true },
  },
];

/** The settings behind a named preset. */
export function qualityFromPreset(id: QualityPresetId): QualitySettings {
  const preset = QUALITY_PRESETS.find((p) => p.id === id);
  // Unreachable through the type, but a bad id must not hand a caller `undefined` to send on the wire.
  return { ...(preset?.settings ?? DEFAULT_QUALITY) };
}

/**
 * Which preset `q` is, or `"custom"` when it matches none.
 *
 * Field-by-field equality across ALL five fields, so a value differing only in `adaptive` is honestly
 * reported as custom rather than mislabelled with a preset the operator did not choose.
 */
export function presetIdFor(q: QualitySettings): QualityPresetId | "custom" {
  const match = QUALITY_PRESETS.find(
    (p) =>
      p.settings.scale_div === q.scale_div &&
      p.settings.fps === q.fps &&
      p.settings.color === q.color &&
      p.settings.max_bitrate_bps === q.max_bitrate_bps &&
      p.settings.adaptive === q.adaptive,
  );
  return match?.id ?? "custom";
}

// --- clamp --------------------------------------------------------------------------------------

/**
 * Coerce one numeric field into range: NaN → `fallback`, fractional → truncated, then clamped.
 *
 * The trunc and the NaN guard have no counterpart in Rust because `u32` cannot represent either — but
 * a browser can produce both, and both would fail SILENTLY rather than loudly: `JSON.stringify(NaN)`
 * is `null` and `1.5` is not a `u32`, so serde would reject the whole message and the agent would
 * simply never apply the operator's setting. Falling back to the field's shipped default (not the
 * minimum) keeps a UI bug from also crushing the session to 100 kbps at 1 fps.
 *
 * `±Infinity` is deliberately NOT sent to the fallback: it means "arbitrarily large/small", which
 * saturates through `Math.min`/`Math.max` to exactly the bound the Rust test's `u32::MAX` row expects.
 * Only NaN — the value with no ordering at all, and which would poison both comparisons — is special.
 */
function clampInt(v: number, min: number, max: number, fallback: number): number {
  if (Number.isNaN(v)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(v)));
}

/**
 * Clamp every field into range — **never reject**. Mirror of `QualitySettings::clamped` in
 * `crates/agent-core/src/quality.rs`; same bounds, saturating (not modular), and idempotent.
 *
 * The agent clamps again on receipt and ITS clamp is the authoritative one — this copy is not a trust
 * boundary. It exists so the value the operator sees selected is the value that will be in force,
 * instead of the UI showing an ask the agent silently reduced.
 */
export function clampQuality(q: QualitySettings): QualitySettings {
  return {
    scale_div: clampInt(q.scale_div, MIN_SCALE_DIV, MAX_SCALE_DIV, DEFAULT_QUALITY.scale_div),
    fps: clampInt(q.fps, MIN_FPS, MAX_FPS, DEFAULT_QUALITY.fps),
    // Non-numeric fields pass through untouched, exactly as in Rust.
    color: q.color,
    max_bitrate_bps: clampInt(
      q.max_bitrate_bps,
      MIN_MAX_BITRATE_BPS,
      MAX_MAX_BITRATE_BPS,
      DEFAULT_QUALITY.max_bitrate_bps,
    ),
    adaptive: q.adaptive,
  };
}

// --- telemetry readout --------------------------------------------------------------------------

/**
 * Loss thresholds in RFC 3550 1/256 units, mirroring `LOW_LOSS_256` / `HIGH_LOSS_256` in
 * `crates/transport-webrtc/src/video/rate.rs` (themselves libwebrtc's `kDefaultLowLossThreshold` /
 * `kDefaultHighLossThreshold`, 2 % and 10 %).
 *
 * The readout uses the SAME numbers as the controller so the colour the operator sees means something
 * specific: "good" is the band where the rate controller is ramping UP, "degraded" is its dead band,
 * and "poor" is where it is backing OFF. A readout with its own private thresholds would show green
 * while the encoder was cutting bitrate.
 */
export const LOW_LOSS_256 = 5;
/** Above this the rate controller backs off; at exactly this value it is still in the dead band. */
export const HIGH_LOSS_256 = 26;

/** Severity of the current link, for the readout's `data-tone`. */
export type QualityTone = "good" | "degraded" | "poor";

/**
 * Map the newest telemetry to a tone. Boundaries follow the Rust controller exactly: `<= LOW_LOSS_256`
 * is clean (it ramps up), `<= HIGH_LOSS_256` is the dead band, above it is congested.
 *
 * No stats — or stats with no feedback yet — reports `"good"` rather than a warning colour. That is a
 * choice about alarm fatigue, not a claim: a viewer that shows amber for the first second of every
 * session teaches the operator to ignore the indicator. The *words* never lie about it —
 * {@link formatQualityReadout} says "awaiting feedback" for exactly this case.
 */
export function qualityTone(stats: QualityStats | null | undefined): QualityTone {
  if (!stats || stats.feedback_reports === 0) return "good";
  if (stats.fraction_lost_256 <= LOW_LOSS_256) return "good";
  if (stats.fraction_lost_256 <= HIGH_LOSS_256) return "degraded";
  return "poor";
}

/**
 * How far the achieved frame rate may fall below the commanded one before the readout flags it.
 *
 * Not a tight bound, on purpose. A capture loop paced at N fps measures a little under N as a matter
 * of course — the pacing sleep quantises, and the agent's measurement window closes mid-frame — so a
 * threshold near 1.0 would put a warning on every healthy session and teach the operator to ignore
 * it (the same alarm-fatigue argument {@link qualityTone} makes about colour). 15 % is wide enough to
 * swallow that jitter and far narrower than the divergence that actually matters: the lab VM
 * captures ~14 fps when commanded 30, which is 0.47.
 */
export const FPS_DIVERGENCE_RATIO = 0.85;

/**
 * Whether the achieved rate is materially below the commanded one (see {@link FPS_DIVERGENCE_RATIO}).
 *
 * `fpsX100 === 0` is NOT divergence: the agent documents it as "not yet measurable", so treating it
 * as a shortfall would flag the first second of every session as a fault. With no commanded rate to
 * compare against there is likewise nothing to diverge FROM.
 */
export function fpsDiverges(fpsX100: number, commandedFps?: number): boolean {
  if (fpsX100 <= 0 || !commandedFps || commandedFps <= 0) return false;
  return fpsX100 < commandedFps * 100 * FPS_DIVERGENCE_RATIO;
}

/**
 * One-line live readout: what is actually being encoded, and what the link is doing about it.
 *
 * `commandedFps` is the frame rate currently in force (the agent's applied `quality.fps`), and the
 * readout prints the ACHIEVED rate beside it. Without the pair there is no readout of the gap at
 * all: an operator who sets 30 fps and gets 14 sees a control saying 30 and a picture that feels
 * wrong, with nothing in the UI connecting the two. `dropped_frames_total` rides alongside because it is
 * the *cause* — capture outrunning encode, the newest frame winning — and a shortfall with no drops
 * is a different fault (a capturer that cannot sustain the rate) than one with them.
 *
 * Guards the "measured nothing" cases explicitly, because each would otherwise render as a confident
 * zero:
 *
 * * `feedback_reports === 0` — no RTCP report block has been consumed, so `fraction_lost_256` and
 *   `rtt_ms` are not measurements at all, they are initial values. Printing "0.0% loss · rtt 0 ms"
 *   would be stating a fact nothing in the system has established.
 * * `rtt_ms === 0` with feedback flowing — the agent documents 0 as "not yet measurable" (it needs an
 *   LSR/DLSR pair), so it prints as an em dash.
 * * `fps_x100 === 0` — likewise "not yet measurable" (a window too short to divide by), so it gets
 *   the same em dash rather than "0.0 fps", which would read as a stalled stream.
 *
 * Note the frame-rate term is emitted in BOTH branches. It is an encoder-side fact that owes nothing
 * to RTCP, so hiding it behind "awaiting feedback" would withhold it for the first second of every
 * session — and forever on a link whose feedback never arrives, which is exactly a session where the
 * operator most needs to know what is actually being encoded.
 */
export function formatQualityReadout(
  stats: QualityStats | null | undefined,
  commandedFps?: number,
): string {
  if (!stats) return "no stats yet";
  const kbps = Math.round(stats.measured_bitrate_bps / 1000);
  const size = `${stats.width}×${stats.height}`;
  // One decimal on the achieved rate, matching the loss percentage: the gap worth seeing (28 vs 30)
  // is a few percent wide, and integers would round it away.
  const achieved = stats.fps_x100 > 0 ? (stats.fps_x100 / 100).toFixed(1) : "—";
  let fps = commandedFps ? `${achieved}/${commandedFps} fps` : `${achieved} fps`;
  if (fpsDiverges(stats.fps_x100, commandedFps)) fps += " ⚠";
  // Session-total, so it is shown whenever it is nonzero rather than only while diverging: frames
  // the encoder threw away are never routine, and the count is what distinguishes "the queue is
  // shedding" from "the capturer is slow" when the rate has already recovered.
  if (stats.dropped_frames_total > 0) fps += ` (${stats.dropped_frames_total} dropped total)`;
  if (stats.feedback_reports === 0) return `${size} · ${fps} · ${kbps} kbps · awaiting feedback`;
  // One decimal, not a whole percent: the interesting band is 2 %–10 % wide (see LOW/HIGH_LOSS_256),
  // and rounding to integers would collapse a third of it.
  const lossPct = ((stats.fraction_lost_256 * 100) / 256).toFixed(1);
  const rtt = stats.rtt_ms > 0 ? `rtt ${stats.rtt_ms} ms` : "rtt —";
  return `${size} · ${fps} · ${kbps} kbps · ${lossPct}% loss · ${rtt}`;
}

// --- advanced-panel choice ladders --------------------------------------------------------------

/** `scale_div` choices with operator-facing labels (a divisor reads as nothing; a percentage reads). */
export const SCALE_CHOICES: readonly { value: number; label: string }[] = [
  { value: 1, label: "100% (native)" },
  { value: 2, label: "50%" },
  { value: 3, label: "33%" },
  { value: 4, label: "25%" },
];

/** Frame-rate ladder. Contains every preset's `fps` plus both clamp bounds, so no preset renders blank. */
export const FPS_CHOICES: readonly number[] = [1, 5, 10, 15, 24, 30, 60];

/** Colour choices, labelled for an operator rather than for the codec. */
export const COLOR_CHOICES: readonly { value: ColorMode; label: string }[] = [
  { value: "Full", label: "Full colour" },
  { value: "Gray", label: "Greyscale" },
];

/**
 * Bitrate-ceiling ladder in kbps. Spans the clamp exactly (100 kbps … 20 Mbps) and contains every
 * preset's value.
 */
export const BITRATE_CHOICES_KBPS: readonly number[] = [
  100, 400, 1_000, 2_000, 3_000, 5_000, 8_000, 12_000, 20_000,
];

/**
 * The bitrate ladder with `currentBps` folded in when it is not already on it.
 *
 * Needed because the value in force is not always one WE chose: the agent's machine policy can cap the
 * ceiling to an arbitrary number (that is what `capped_by_policy` reports). A `<select>` whose `value`
 * matches no `<option>` renders BLANK in React — so without this the one case where the operator most
 * needs to see the bitrate is the case where the control shows nothing at all.
 */
export function bitrateChoicesKbps(currentBps: number): number[] {
  const current = Math.round(currentBps / 1000);
  const all = BITRATE_CHOICES_KBPS.includes(current)
    ? [...BITRATE_CHOICES_KBPS]
    : [...BITRATE_CHOICES_KBPS, current];
  return all.sort((a, b) => a - b);
}

// --- operator intent vs. what the agent acknowledged ---------------------------------------------

/**
 * The console's two views of the quality settings: what the agent last said is IN FORCE, and what
 * the operator has asked for but not yet been answered about.
 *
 * WHY BOTH. There is no partial update on this wire (see `control.ts`), so every advanced-panel knob
 * is a read-modify-write of all five fields. Reading only the acknowledged value meant two quick
 * edits on a high-RTT link reverted each other: change fps, then change colour before the fps
 * `QualityApplied` has come back, and the second message is built from the pre-fps settings — the
 * operator watches their first edit undo itself and has no way to tell that from the agent refusing
 * it. Reading `pending ?? acknowledged` composes the edits instead.
 *
 * WHY IT IS SOUND, from two facts about `crates/agent-windows/src/host.rs`: every `SetQuality` is
 * answered with exactly one `QualityApplied` — including the deduplicated "repeats the settings in
 * force" case, where the reply is sent even though the encoder is not re-touched — and the control
 * channel is ordered, so replies arrive in the order the asks were sent. So counting outstanding
 * replies is a faithful model of the agent's state, not a guess about timing.
 */
export interface QualityIntent {
  /** The settings the agent's last `QualityApplied` reported are in force. Authoritative. */
  acknowledged: QualitySettings;
  /** The operator's not-yet-answered ask, or `null` when everything has been acknowledged. */
  pending: QualitySettings | null;
  /**
   * Quality messages sent whose `QualityApplied` has not arrived yet. **Saturates at 0** — see
   * {@link qualityIntentReducer} for why that is load-bearing rather than defensive.
   */
  outstanding: number;
}

/** The console's starting view: the shipped default, nothing asked, nothing outstanding. */
export function initialQualityIntent(): QualityIntent {
  return { acknowledged: DEFAULT_QUALITY, pending: null, outstanding: 0 };
}

/**
 * What the quality controls should DISPLAY, and what a read-modify-write must be built from: the
 * operator's own pending ask while one is in flight, otherwise the agent's acknowledged truth.
 */
export function effectiveQuality(intent: QualityIntent): QualitySettings {
  return intent.pending ?? intent.acknowledged;
}

/**
 * One transition of the console's quality state.
 *
 * * `requested` — a `RequestQuality` went out. It carries no settings, but it IS answered with a
 *   `QualityApplied`, so it must be counted or its reply would be mistaken for the answer to a
 *   later `SetQuality`.
 * * `asked` — a `SetQuality` went out carrying `quality`.
 * * `applied` — a `QualityApplied` came back carrying what the agent actually put in force.
 * * `reset` — the session ended; quality is a property of the AGENT, so nothing carries over.
 */
export type QualityIntentAction =
  | { type: "requested" }
  | { type: "asked"; quality: QualitySettings }
  | { type: "applied"; quality: QualitySettings }
  | { type: "reset" };

/**
 * The pure state transition. Lives here rather than inline in `App.tsx` so it is testable: vitest's
 * `include` glob covers only `.ts`, so logic inside a component render body is invisible to it.
 *
 * SATURATION AT ZERO IS THE SUBTLE PART. `QualityApplied` answers `RequestQuality` as well as
 * `SetQuality`, and the app fires a `RequestQuality` at connect (it is what arms telemetry and
 * probes for M11 support). Counting only `SetQuality` would therefore let an unmatched reply drive
 * the counter negative — and a negative counter never returns to 0 on the next ask/ack pair, so
 * `pending` would never clear again and the panel would show the operator's ask forever, silently
 * discarding the agent's clamp and policy cap. That is a WORSE failure than the bug being fixed
 * here, because the displayed value would then never be true. Counting `requested` keeps the books
 * straight in the ordinary case; `Math.max(0, …)` keeps them non-negative in every other.
 *
 * Clearing `pending` only when the last reply lands is what preserves the deliberate snap-back: the
 * agent's applied value — clamped, policy-capped, possibly not what was asked for — wins as soon as
 * the console is no longer waiting on anything.
 */
export function qualityIntentReducer(
  state: QualityIntent,
  action: QualityIntentAction,
): QualityIntent {
  switch (action.type) {
    case "requested":
      return { ...state, outstanding: state.outstanding + 1 };
    case "asked":
      return { ...state, pending: action.quality, outstanding: state.outstanding + 1 };
    case "applied": {
      const outstanding = Math.max(0, state.outstanding - 1);
      return {
        acknowledged: action.quality,
        pending: outstanding === 0 ? null : state.pending,
        outstanding,
      };
    }
    case "reset":
      return initialQualityIntent();
  }
}
