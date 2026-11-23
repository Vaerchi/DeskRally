/**
 * Pure-logic tests for the Viewer's monitor picker: the option list (incl. the "View all" composite
 * entry) and the selection-validity rule, plus the M11 quality picker's options and enabled state.
 * Rendering is not exercised (the project has no component test harness); the live Viewer is covered
 * by the Playwright console/multimonitor e2e.
 */

import { describe, it, expect } from "vitest";
import viewerSource from "./Viewer.tsx?raw";
import {
  viewerMonitorOptions,
  viewerQualityOptions,
  isValidMonitorSelection,
  defaultMonitorSelection,
  audioToggleTitle,
  controlReasons,
  qualityControlState,
  sessionPolicyBanner,
  videoTransform,
  machineDisplayLabel,
  machineDisplayTitle,
  preferredViewForMonitorSwitch,
  type MonitorInfo,
} from "./Viewer";
import { IDENTITY_VIEW, MIN_ZOOM, actualZoom } from "../lib/viewport";
import { COMPOSITE_MONITOR_ID } from "../lib/control";
import { DEFAULT_QUALITY, QUALITY_PRESETS, qualityFromPreset } from "../lib/quality";

const two: MonitorInfo[] = [
  { id: 0, label: "Display 1", width: 1920, height: 1080, primary: true },
  { id: 1, label: "Display 2", width: 1280, height: 1024 },
];
const one: MonitorInfo[] = [{ id: 0, label: "Display 1", width: 1920, height: 1080, primary: true }];

describe("viewer monitor picker options", () => {
  it("appends a 'View all' composite option only when more than one monitor is advertised", () => {
    const opts = viewerMonitorOptions(two);
    expect(opts).toHaveLength(3);
    expect(opts[2]).toEqual({ value: COMPOSITE_MONITOR_ID, label: "View all (composite)" });
    // Per-monitor labels carry size + a primary star.
    expect(opts[0].label).toBe("Display 1 (1920×1080) ★");
    expect(opts[1].label).toBe("Display 2 (1280×1024)");
  });

  it("omits the composite option for a single monitor", () => {
    const opts = viewerMonitorOptions(one);
    expect(opts).toHaveLength(1);
    expect(opts.some((o) => o.value === COMPOSITE_MONITOR_ID)).toBe(false);
  });

  it("treats the composite id as a valid selection only with more than one monitor", () => {
    expect(isValidMonitorSelection(COMPOSITE_MONITOR_ID, two)).toBe(true);
    expect(isValidMonitorSelection(COMPOSITE_MONITOR_ID, one)).toBe(false);
    expect(isValidMonitorSelection(1, two)).toBe(true);
    expect(isValidMonitorSelection(9, two)).toBe(false);
  });
});

describe("viewer default monitor selection", () => {
  it("opens on the PRIMARY even when it is not the first monitor", () => {
    // The case that makes this more than `monitors[0]`: monitor ids are positional (left to right
    // across the virtual desktop), so a screen placed LEFT of the main one takes id 0. Opening the
    // session there would put the technician on the wrong display and label it "Display 1".
    const leftOfPrimary: MonitorInfo[] = [
      { id: 0, label: "Display 1", width: 1280, height: 1024 },
      { id: 1, label: "Display 2", width: 1920, height: 1080, primary: true },
      { id: 2, label: "Display 3", width: 2560, height: 1440 },
    ];
    expect(defaultMonitorSelection(leftOfPrimary)).toBe(1);
  });

  it("opens on the first monitor when the agent flagged no primary", () => {
    const noPrimary: MonitorInfo[] = [
      { id: 0, label: "Display 1", width: 1280, height: 1024 },
      { id: 1, label: "Display 2", width: 1920, height: 1080 },
    ];
    expect(defaultMonitorSelection(noPrimary)).toBe(0);
  });

  it("is 0 for an empty list rather than undefined", () => {
    // Reached before the agent's MonitorList arrives; must be a usable id, not NaN/undefined.
    expect(defaultMonitorSelection([])).toBe(0);
  });

  it("is unchanged for the ordinary single-monitor and primary-first cases", () => {
    expect(defaultMonitorSelection(one)).toBe(0);
    expect(defaultMonitorSelection(two)).toBe(0);
  });
});

describe("viewer quality picker options (M11)", () => {
  it("lists the presets and no 'Custom' entry when the settings ARE a preset", () => {
    const opts = viewerQualityOptions(DEFAULT_QUALITY);
    expect(opts).toHaveLength(QUALITY_PRESETS.length);
    expect(opts.map((o) => o.value)).toEqual(QUALITY_PRESETS.map((p) => p.id));
    expect(opts.some((o) => o.value === "custom")).toBe(false);
    // Every preset must be reachable from a picker opened on any other preset.
    for (const p of QUALITY_PRESETS) {
      expect(viewerQualityOptions(qualityFromPreset(p.id)).map((o) => o.value)).toContain(p.id);
    }
  });

  it("appends 'Custom' when the settings in force match no preset", () => {
    // The policy-capped / advanced-tweaked case. Without the entry, the <select> value would match no
    // <option> and React renders it blank — the operator would see an empty control, not a custom one.
    const opts = viewerQualityOptions({ ...DEFAULT_QUALITY, max_bitrate_bps: 1_500_000 });
    expect(opts).toHaveLength(QUALITY_PRESETS.length + 1);
    expect(opts[opts.length - 1]).toEqual({ value: "custom", label: "Custom" });
  });
});

describe("viewer quality controls enabled state (M11)", () => {
  it("disables ONLY on a proven-unsupported agent, and explains why in the title", () => {
    const off = qualityControlState(false);
    expect(off.disabled).toBe(true);
    // A greyed-out control with no explanation is the worst outcome for an operator: they cannot tell
    // "broken" from "not supported here". Assert the reason is actually carried, not just some text.
    expect(off.title).toMatch(/does not support quality/i);
  });

  it("stays enabled while support is still unknown", () => {
    // `undefined` = the probe has not timed out yet (or there is no probe at all, as in preview mode).
    // Dead controls for the first seconds of every session is a worse trade than an old agent
    // ignoring one SetQuality it cannot decode.
    expect(qualityControlState(undefined).disabled).toBe(false);
    expect(qualityControlState(true).disabled).toBe(false);
    expect(qualityControlState(true).title).toMatch(/quality/i);
  });
});

describe("viewer video transform", () => {
  it("renders the identity view as an origin-anchored, unscaled transform", () => {
    // The CSS must invert to the same math lib/viewport uses for the pointer mapping, so the string
    // shape (translate then scale, px units) is load-bearing, not cosmetic.
    expect(videoTransform(IDENTITY_VIEW)).toBe("translate(0px, 0px) scale(1)");
  });

  it("carries the pan (px) and zoom through verbatim", () => {
    expect(videoTransform({ zoom: 2, panX: -120.5, panY: 40 })).toBe(
      "translate(-120.5px, 40px) scale(2)",
    );
  });
});

describe("session policy banner", () => {
  it("says nothing when there is no policy at all", () => {
    expect(sessionPolicyBanner(undefined)).toBeNull();
  });

  it("says nothing about a policy the agent VERIFIED, at either level", () => {
    // A verified view_only policy: the button already reads "🔒 View only (policy)" and its title
    // explains the mandate, so a banner would be noise.
    expect(sessionPolicyBanner({ enforced: true, applied: true, note: "policy: view_only" })).toBeNull();
    // A verified `control` policy (loop 83's discharge) reports enforced:false — and is also nothing to
    // report. This is the case that makes `applied` necessary: without it, "enforced:false with a note"
    // could not be told apart from a refusal.
    expect(sessionPolicyBanner({ enforced: false, applied: true, note: "policy: control" })).toBeNull();
  });

  it("surfaces a REFUSED policy, with the agent's reason and the real consequence", () => {
    const text = sessionPolicyBanner({
      enforced: false,
      applied: false,
      note: "session policy rejected (bad signature)",
    });
    // The reason, because "policy failed" alone leaves the operator nothing to act on.
    expect(text).toContain("bad signature");
    // And the consequence, which is TERMINAL: reject_unverified raises a floor no later policy can
    // release, so telling them to retry the install would be telling them to do something futile.
    expect(text).toContain("stays view-only");
    expect(text).toContain("start a new one");
  });

  it("still reports a refusal that arrived with no reason attached", () => {
    // Fail loud even when the agent said nothing useful: silence here is what the bug WAS.
    const text = sessionPolicyBanner({ enforced: false, applied: false });
    expect(text).not.toBeNull();
    expect(text).toContain("could not be applied");
    // No stray punctuation from an empty reason.
    expect(text).not.toContain(": .");
  });

  it("treats a whitespace-only reason as no reason", () => {
    expect(sessionPolicyBanner({ enforced: false, applied: false, note: "   " })).toBe(
      sessionPolicyBanner({ enforced: false, applied: false }),
    );
  });
});

describe("viewer audio toggle tooltip", () => {
  it("distinguishes UNAVAILABLE from merely off", () => {
    // The distinction the control exists to make. Both states render as "Sound off", and an
    // operator who cannot tell "this machine sends no audio" from "you have not asked to hear it"
    // reports a working feature as broken.
    const unavailable = audioToggleTitle(false, false);
    const off = audioToggleTitle(true, false);
    expect(unavailable).not.toBe(off);
    expect(unavailable).toMatch(/not sending audio/i);
    expect(off).toMatch(/hear/i);
  });

  it("says how to turn it OFF once it is on", () => {
    expect(audioToggleTitle(true, true)).toMatch(/mute/i);
  });

  it("reports unavailable even if the on-flag is somehow set", () => {
    // Defensive: availability wins. A stale `on` from a previous session must never produce a
    // tooltip claiming audio is playing when the agent is sending none.
    expect(audioToggleTitle(false, true)).toMatch(/not sending audio/i);
  });
});

describe("machineDisplayLabel / machineDisplayTitle", () => {
  it("shows the alias when set (alias is primary label)", () => {
    expect(machineDisplayLabel("DESKTOP-ABC123", "the operator's Workstation")).toBe("the operator's Workstation");
  });

  it("shows the hostname when no alias is present", () => {
    expect(machineDisplayLabel("DESKTOP-ABC123")).toBe("DESKTOP-ABC123");
    expect(machineDisplayLabel("DESKTOP-ABC123", undefined)).toBe("DESKTOP-ABC123");
  });

  it("alias label and no-alias label differ", () => {
    // Mutation guard: if machineDisplayLabel returned machineName unconditionally, this would fail.
    expect(machineDisplayLabel("DESKTOP-ABC123", "the operator's Workstation")).not.toBe(
      machineDisplayLabel("DESKTOP-ABC123"),
    );
  });

  it("returns the hostname as tooltip only when alias is shown (hostname becomes secondary)", () => {
    // When alias present: tooltip carries the hostname so the operator can still see it.
    expect(machineDisplayTitle("DESKTOP-ABC123", "the operator's Workstation")).toBe("DESKTOP-ABC123");
  });

  it("returns undefined tooltip when no alias (hostname is already the primary label)", () => {
    // No tooltip when the label IS the hostname; a tooltip saying the same thing would be noise.
    expect(machineDisplayTitle("DESKTOP-ABC123")).toBeUndefined();
    expect(machineDisplayTitle("DESKTOP-ABC123", undefined)).toBeUndefined();
  });

  it("tooltip and no-alias-tooltip differ", () => {
    // Mutation guard: if machineDisplayTitle returned machineName unconditionally, this would fail.
    expect(machineDisplayTitle("DESKTOP-ABC123", "the operator's Workstation")).not.toEqual(
      machineDisplayTitle("DESKTOP-ABC123"),
    );
  });
});

describe("preferredViewForMonitorSwitch — scale preference across monitor changes", () => {
  // 1920×1080 content in a 1000×600 surface: content is larger, so actualZoom > MIN_ZOOM.
  const largerContent = { surfaceW: 1000, surfaceH: 600, contentW: 1920, contentH: 1080 };
  // 640×360 content in a 1920×1080 surface: content is smaller, so actualZoom clamps to MIN_ZOOM.
  const smallerContent = { surfaceW: 1920, surfaceH: 1080, contentW: 640, contentH: 360 };

  it("'fit' preference always returns IDENTITY_VIEW regardless of content size", () => {
    expect(preferredViewForMonitorSwitch("fit", largerContent)).toEqual(IDENTITY_VIEW);
    expect(preferredViewForMonitorSwitch("fit", smallerContent)).toEqual(IDENTITY_VIEW);
  });

  it("'actual' preference zooms to native pixels when content exceeds the surface", () => {
    const v = preferredViewForMonitorSwitch("actual", largerContent);
    expect(v.zoom).toBeGreaterThan(MIN_ZOOM);
    expect(v.zoom).toBeCloseTo(actualZoom(largerContent), 8);
  });

  it("'actual' preference keeps IDENTITY_VIEW when content is smaller than the surface", () => {
    // When the monitor is lower-resolution than the viewer window, native pixels is already
    // visible at the fit zoom — zooming "to 1:1" would add black bars, which clampZoom disallows
    // (MIN_ZOOM is the floor). The result must be the fit, not a sub-fit scale.
    expect(preferredViewForMonitorSwitch("actual", smallerContent)).toEqual(IDENTITY_VIEW);
  });

  it("'actual' and 'fit' produce different views for a monitor larger than the surface", () => {
    // Mutation guard: if the function ignored `pref`, both branches would return the same thing.
    const fit = preferredViewForMonitorSwitch("fit", largerContent);
    const actual = preferredViewForMonitorSwitch("actual", largerContent);
    expect(actual).not.toEqual(fit);
  });

  it("'actual' centres the zoomed view — pan is non-zero when content overflows the surface", () => {
    // 1920-wide content at 1:1 in a 1000-wide surface overflows by 920px; centering scrolls
    // the left edge off-screen (panX < 0). A mutation that zeroed the pan and only set the zoom
    // would pass the zoom-only assertions above but fail here.
    const v = preferredViewForMonitorSwitch("actual", largerContent);
    expect(v.panX).toBeLessThan(0);
  });
});

describe("trackpad overlay declaration order", () => {
  it("padOverlay is declared before every use (reading a const early is a ReferenceError)", () => {
    const src = viewerSource;
    // Needles are split so this test cannot match its own text.
    const decl = src.indexOf("const " + "padOverlay =");
    const first = src.indexOf("pad" + "Overlay", decl + 10);
    const uses = [...src.matchAll(/overlay=\{pad(Overlay)\}/g)].map((m) => m.index ?? -1);
    expect(decl).toBeGreaterThan(0);
    expect(first).toBeGreaterThan(decl);
    expect(uses.length).toBe(2);
    for (const u of uses) expect(u).toBeGreaterThan(decl);
    // And it sits above the pop-out render effect that reads it.
    expect(src.indexOf("overlay=" + "{padOverlay}")).toBeGreaterThan(decl);
  });
});

describe("controlReasons (menu redesign wave 7c: why a control is unavailable, on screen)", () => {
  const all = {
    audioAvailable: true, qualityDisabled: false, pannable: true, viewOnlyEnforced: false,
    typingEnabled: true, viewOnly: false, panning: false, recordingLocked: false,
  };

  it("says nothing when every control is available", () => {
    expect(Object.values(controlReasons(all)).every((r) => r === null)).toBe(true);
  });

  it("gives each unavailable control its own reason", () => {
    expect(controlReasons({ ...all, audioAvailable: false }).audio).toMatch(/not sending sound/);
    expect(controlReasons({ ...all, qualityDisabled: true }).quality).toMatch(/Update the agent/);
    expect(controlReasons({ ...all, pannable: false }).pan).toMatch(/^Zoom in first/);
    expect(controlReasons({ ...all, viewOnlyEnforced: true }).viewOnly).toMatch(/requires view only/);
    expect(controlReasons({ ...all, recordingLocked: true }).record).toMatch(/cannot be stopped/);
    // Only the control that is unavailable gets a reason.
    const one = controlReasons({ ...all, pannable: false });
    expect(Object.entries(one).filter(([, r]) => r !== null).map(([k]) => k)).toEqual(["pan"]);
  });

  it("names the right obstacle to typing, view only before Pan before Capture input", () => {
    const off = { ...all, typingEnabled: false };
    expect(controlReasons({ ...off, viewOnly: true, panning: true }).typing).toBe("This session is view only.");
    expect(controlReasons({ ...off, panning: true }).typing).toBe("Turn off Pan to type.");
    expect(controlReasons(off).typing).toBe("Turn on Capture input to type.");
  });
});
