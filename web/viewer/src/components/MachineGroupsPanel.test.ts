/**
 * MachineGroupsPanel view-model tests — the per-group session-cap column (docs/01 §5, loop 78).
 *
 * The property under test throughout is that a cap is TRI-STATE and stays that way: capped at N,
 * uncapped (0 = unlimited), and UNKNOWN are three distinct answers, and "the caps request failed"
 * must never be rendered as "no group is capped". Exactly the discipline AccessPanel's tests pin for
 * presence, and for the same reason — except here the stakes are higher, because the fabricated
 * value (0) is itself writable and clears the group's real cap server-side.
 *
 * This file exists because the retroactive adversarial review of loop 78 found the panel had NO unit
 * test, which is how the defect below shipped in the first place.
 */

import { describe, it, expect } from "vitest";
import {
  allowBackstageDraftsFor,
  describeSeconds,
  policyDraftDirty,
  policyDraftFromRead,
  recordingChoice,
  recordingFlags,
  capDraftsFor,
  capSubmitRefusal,
  GROUP_POLICY_LIMITS,
  groupPolicySubmission,
  type GroupPolicyDraft,
  maxDurationDraftsFor,
  maxIdleDraftsFor,
  prohibitRecordingDraftsFor,
  requireRecordingDraftsFor,
  viewOnlyDraftsFor,
} from "./MachineGroupsPanel";
import type { GroupSessionCap, MachineGroup } from "../lib/console_api";

const GROUPS: readonly MachineGroup[] = [
  { id: "g-1", tenant_id: "t-1", name: "Front Office" },
  { id: "g-2", tenant_id: "t-1", name: "Warehouse" },
] as unknown as readonly MachineGroup[];

const CAPPED: readonly GroupSessionCap[] = [
  { group_id: "g-2", max_concurrent_sessions: 3, enforce_view_only: true, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
];

describe("capDraftsFor", () => {
  it("seeds a capped group with its cap and an uncapped one with 0", () => {
    expect(capDraftsFor(GROUPS, CAPPED)).toEqual({ "g-1": "0", "g-2": "3" });
  });

  it("returns NO drafts when the caps could not be read, rather than defaulting them to 0", () => {
    // THE REGRESSION. A failed caps load previously produced { "g-1": "0", "g-2": "0" } — visually
    // identical to a fleet where nothing is capped, under a header that reads "0 = unlimited". The
    // absence of a draft is what lets the column render "unknown" instead.
    expect(capDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    // An EMPTY list is a real answer: the server says no group is capped, so 0 is correct and
    // editable. `null` is the absence of an answer. Collapsing the two is precisely the bug.
    expect(capDraftsFor(GROUPS, [])).toEqual({ "g-1": "0", "g-2": "0" });
    expect(capDraftsFor(GROUPS, [])).not.toEqual(capDraftsFor(GROUPS, null));
  });

  it("ignores a policy for a group that is not listed", () => {
    // A cap for an out-of-scope or just-deleted group must not invent a row.
    const stale: readonly GroupSessionCap[] = [
      { group_id: "g-gone", max_concurrent_sessions: 9, enforce_view_only: true, allow_backstage_under_view_only: true, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(capDraftsFor(GROUPS, stale)).toEqual({ "g-1": "0", "g-2": "0" });
  });

  it("has no drafts when there are no groups", () => {
    expect(capDraftsFor([], CAPPED)).toEqual({});
  });
});

describe("capSubmitRefusal", () => {
  it("allows a whole number ≥ 0", () => {
    expect(capSubmitRefusal(null, "0")).toBeNull();
    expect(capSubmitRefusal(null, "3")).toBeNull();
    expect(capSubmitRefusal(null, " 12 ")).toBeNull();
  });

  it("refuses anything that is not a whole number ≥ 0", () => {
    for (const bad of ["", "   ", "abc", "-1", "1.5", "1e3x", "NaN"]) {
      expect(capSubmitRefusal(null, bad), `input ${JSON.stringify(bad)}`).not.toBeNull();
    }
  });

  it("refuses EVERY value while the caps are unknown, including a well-formed one", () => {
    // The point of the guard: you may not write a cap you never read back. A value-only check would
    // happily submit "0" here and delete the group's real cap.
    expect(capSubmitRefusal("boom", "0")).not.toBeNull();
    expect(capSubmitRefusal("boom", "3")).not.toBeNull();
    expect(capSubmitRefusal("boom", "")).not.toBeNull();
  });

  it("reports the load failure, not the format, when the caps are unknown", () => {
    // Distinct messages matter: "must be a whole number" for an unread cap sends the operator off to
    // fix an input that is already valid.
    expect(capSubmitRefusal("boom", "3")).toMatch(/could not be loaded/i);
    expect(capSubmitRefusal(null, "-1")).toMatch(/whole number/i);
  });

  it("refuses a cap above the server's MaxSessionLimit, and accepts the limit itself", () => {
    expect(capSubmitRefusal(null, "100000")).toBeNull();
    expect(capSubmitRefusal(null, "100001")).toMatch(/0 to 100000/);
  });
});

describe("groupPolicySubmission", () => {
  // Every case mirrors a 400 branch of handleSetGroupSessionPolicy / NormalizeGroupSessionPolicy
  // (control-plane/http_group_session_policy.go, group_session_policy.go), or the unread-policy rule.
  const VALID: GroupPolicyDraft = {
    cap: "2",
    enforceViewOnly: true,
    allowBackstageUnderViewOnly: false,
    prohibitRecording: true,
    requireRecording: false,
    maxDuration: "3600",
    maxIdle: "300",
  };

  it("pins the limits to the server constants", () => {
    // MaxSessionLimit, MaxGroupSessionDurationSeconds, MaxGroupIdleSeconds.
    expect(GROUP_POLICY_LIMITS).toEqual({ maxConcurrentSessions: 100000, maxSessionDurationSeconds: 86400, maxIdleSeconds: 3600 });
  });

  it("builds the full PUT body from a valid draft, with every field carried through", () => {
    // An asymmetric draft: each boolean differs from its neighbour and each number is distinct, so a body
    // wired to the wrong draft field cannot pass.
    expect(groupPolicySubmission("loaded", VALID)).toEqual({
      refusal: null,
      body: {
        max_concurrent_sessions: 2,
        enforce_view_only: true,
        allow_backstage_under_view_only: false,
        prohibit_recording: true,
        require_recording: false,
        max_session_duration_seconds: 3600,
        max_idle_seconds: 300,
      },
    });
  });

  it("refuses a session cap with no max duration, naming the fix (THE regression: was an opaque server 400)", () => {
    const r = groupPolicySubmission("loaded", { ...VALID, cap: "2", maxDuration: "0" });
    expect(r.body).toBeNull();
    expect(r.refusal).toMatch(/max sessions limit also needs a max session duration/);
    expect(r.refusal).toMatch(/set max sessions to 0/);
  });

  it("allows a 0 duration when the cap is 0 (unlimited), and a duration without a cap", () => {
    expect(groupPolicySubmission("loaded", { ...VALID, cap: "0", maxDuration: "0" }).refusal).toBeNull();
    expect(groupPolicySubmission("loaded", { ...VALID, cap: "0", maxDuration: "60" }).refusal).toBeNull();
  });

  it("refuses an out-of-range or malformed duration instead of coercing it to 0 (= unlimited)", () => {
    // The old submit path turned each of these into 0 and sent it, so a typo quietly removed the limit.
    for (const bad of ["-1", "1.5", "", "  ", "abc", "86401"]) {
      const r = groupPolicySubmission("loaded", { ...VALID, cap: "0", maxDuration: bad });
      expect(r.body, `duration ${JSON.stringify(bad)}`).toBeNull();
      expect(r.refusal).toMatch(/max session duration must be a whole number of seconds from 0 to 86400/);
    }
    expect(groupPolicySubmission("loaded", { ...VALID, maxDuration: "86400" }).refusal).toBeNull();
  });

  it("refuses an out-of-range or malformed idle limit instead of coercing it", () => {
    for (const bad of ["-5", "2.5", "", "3601"]) {
      const r = groupPolicySubmission("loaded", { ...VALID, maxIdle: bad });
      expect(r.body, `idle ${JSON.stringify(bad)}`).toBeNull();
      expect(r.refusal).toMatch(/max idle must be a whole number of seconds from 0 to 3600/);
    }
    expect(groupPolicySubmission("loaded", { ...VALID, maxIdle: "3600" }).refusal).toBeNull();
  });

  it("refuses Block recording together with Require recording", () => {
    const r = groupPolicySubmission("loaded", { ...VALID, prohibitRecording: true, requireRecording: true });
    expect(r.body).toBeNull();
    expect(r.refusal).toMatch(/both blocked and required/);
  });

  it("refuses an out-of-range cap", () => {
    expect(groupPolicySubmission("loaded", { ...VALID, cap: "100001" }).refusal).toMatch(/max sessions must be/);
  });

  it("refuses EVERYTHING while policies are loading or failed, even a valid draft", () => {
    // A draft left over from an earlier read must not be written while the current read is outstanding.
    expect(groupPolicySubmission("loading", VALID).refusal).toMatch(/still loading/);
    expect(groupPolicySubmission("failed", VALID).refusal).toMatch(/could not be loaded/);
  });

  it("refuses a group whose drafts were never seeded, rather than writing zero values over its policy", () => {
    // The old handler filled each unseeded field with `?? false` / `?? "0"` — the server's zero values,
    // which a full-overwrite PUT would write over a real mandate.
    for (const k of Object.keys(VALID) as (keyof GroupPolicyDraft)[]) {
      const r = groupPolicySubmission("loaded", { ...VALID, [k]: undefined });
      expect(r.body, `unseeded ${k}`).toBeNull();
      expect(r.refusal).toMatch(/has not been loaded/);
    }
  });
});

describe("viewOnlyDraftsFor", () => {
  it("seeds each group's mandate from the policies", () => {
    expect(viewOnlyDraftsFor(GROUPS, CAPPED)).toEqual({ "g-1": false, "g-2": true });
  });

  it("returns NO entries when the policies could not be read", () => {
    // Same tri-state discipline as the cap, in the opposite direction: an unread mandate rendered as an
    // unchecked box reads as "this group is NOT view-only", and submitting that false would REMOVE a real
    // mandate and hand control of those machines back to every technician.
    expect(viewOnlyDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    expect(viewOnlyDraftsFor(GROUPS, [])).toEqual({ "g-1": false, "g-2": false });
    expect(viewOnlyDraftsFor(GROUPS, [])).not.toEqual(viewOnlyDraftsFor(GROUPS, null));
  });

  it("is independent of the cap: a group can be view-only with no cap", () => {
    // The two settings share a row but not a meaning — the whole reason the store's delete test is
    // IsDefault() rather than cap === 0.
    const uncappedButLocked: readonly GroupSessionCap[] = [
      { group_id: "g-1", max_concurrent_sessions: 0, enforce_view_only: true, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(capDraftsFor(GROUPS, uncappedButLocked)["g-1"]).toBe("0");
    expect(viewOnlyDraftsFor(GROUPS, uncappedButLocked)["g-1"]).toBe(true);
  });
});

describe("allowBackstageDraftsFor", () => {
  // The backstage opt-out (migration 0040): checked means a view-only group may STILL be issued backstage
  // grants — the remote shell and tool panels — for deliberate unattended maintenance. Unchecked, the
  // default, is what makes "View only" mean watch-only full stop.
  const OPTED_OUT: readonly GroupSessionCap[] = [
    { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: true, allow_backstage_under_view_only: true, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
  ];

  it("seeds each group's opt-out from the policies", () => {
    expect(allowBackstageDraftsFor(GROUPS, OPTED_OUT)).toEqual({ "g-1": false, "g-2": true });
  });

  it("returns NO entries when the policies could not be read", () => {
    // THE MIRRORED HAZARD, and the reason this is asserted rather than left to inherit the branch. For the
    // cap and the mandate a fabricated value looks UNPROTECTED and invites an admin to submit it. Here it
    // looks PROTECTED — "backstage is refused on this group" — and the danger is the belief, not the write:
    // an admin who reads that concludes the group is watch-only full stop and stops looking, while the
    // opt-out may in fact be set and technicians may in fact be running SYSTEM shells there. An unread
    // security setting renders as unread whichever way its zero value points.
    expect(allowBackstageDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    expect(allowBackstageDraftsFor(GROUPS, [])).toEqual({ "g-1": false, "g-2": false });
    expect(allowBackstageDraftsFor(GROUPS, [])).not.toEqual(allowBackstageDraftsFor(GROUPS, null));
  });

  it("reads its OWN field, not the view-only mandate", () => {
    // An asymmetric fixture: the two flags disagree on every row, so a seeder wired to the wrong field
    // (they have the same type and sit next to each other) produces the exact inverse and cannot pass.
    const mixed: readonly GroupSessionCap[] = [
      { group_id: "g-1", max_concurrent_sessions: 0, enforce_view_only: true, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
      { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: true, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(allowBackstageDraftsFor(GROUPS, mixed)).toEqual({ "g-1": false, "g-2": true });
    expect(viewOnlyDraftsFor(GROUPS, mixed)).toEqual({ "g-1": true, "g-2": false });
  });

  it("defaults a group with no policy row to the PROTECTED value", () => {
    // A group the server never returned has no row, which server-side means every setting is default -
    // and the default for this one is false = backstage refused. Seeding true here would draw an opt-out
    // nobody set, and the console would then SUBMIT it on the next save, because the PUT is a full
    // overwrite: a rendering bug that writes itself into the database.
    expect(allowBackstageDraftsFor(GROUPS, OPTED_OUT)["g-1"]).toBe(false);
  });

  it("ignores a policy for a group that is not listed", () => {
    const stale: readonly GroupSessionCap[] = [
      { group_id: "g-gone", max_concurrent_sessions: 0, enforce_view_only: true, allow_backstage_under_view_only: true, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(allowBackstageDraftsFor(GROUPS, stale)).toEqual({ "g-1": false, "g-2": false });
  });

  it("has no drafts when there are no groups", () => {
    expect(allowBackstageDraftsFor([], OPTED_OUT)).toEqual({});
  });
});

describe("prohibitRecordingDraftsFor", () => {
  // The recording ban (migration 0043): checked means sessions on machines in this group cannot record.
  // Unchecked, the default, means recording is permitted. Zero-value (false) is PERMISSIVE — opposite
  // hazard direction from the backstage opt-out but same discipline: render as unknown when unread.
  const BANNED: readonly GroupSessionCap[] = [
    { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: true, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
  ];

  it("seeds each group's ban from the policies", () => {
    expect(prohibitRecordingDraftsFor(GROUPS, BANNED)).toEqual({ "g-1": false, "g-2": true });
  });

  it("returns NO entries when the policies could not be read", () => {
    // Same discipline as the mandate: false = "recording is allowed" looks PERMISSIVE and safe, but an admin
    // who believes that stops looking — while the ban may in fact be set. An unread setting must render as
    // unread whichever direction its zero value points.
    expect(prohibitRecordingDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    expect(prohibitRecordingDraftsFor(GROUPS, [])).toEqual({ "g-1": false, "g-2": false });
    expect(prohibitRecordingDraftsFor(GROUPS, [])).not.toEqual(prohibitRecordingDraftsFor(GROUPS, null));
  });

  it("reads its OWN field, not enforce_view_only or allow_backstage_under_view_only", () => {
    // An asymmetric fixture: prohibit_recording disagrees with both other booleans on every row.
    // A seeder wired to any wrong field produces the exact inverse and cannot pass.
    const mixed: readonly GroupSessionCap[] = [
      { group_id: "g-1", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: true, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
      { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: true,  allow_backstage_under_view_only: true,  prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(prohibitRecordingDraftsFor(GROUPS, mixed)).toEqual({ "g-1": true, "g-2": false });
    expect(viewOnlyDraftsFor(GROUPS, mixed)).toEqual({ "g-1": false, "g-2": true });
    expect(allowBackstageDraftsFor(GROUPS, mixed)).toEqual({ "g-1": false, "g-2": true });
  });

  it("defaults a group with no policy row to false (recording permitted)", () => {
    // A missing row means the server's zero value: false = recording allowed. Seeding true here would draw
    // a ban nobody set and submit it on the next save — a rendering bug that writes itself into the database.
    expect(prohibitRecordingDraftsFor(GROUPS, BANNED)["g-1"]).toBe(false);
  });

  it("ignores a policy for a group that is not listed", () => {
    const stale: readonly GroupSessionCap[] = [
      { group_id: "g-gone", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: true, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(prohibitRecordingDraftsFor(GROUPS, stale)).toEqual({ "g-1": false, "g-2": false });
  });

  it("has no drafts when there are no groups", () => {
    expect(prohibitRecordingDraftsFor([], BANNED)).toEqual({});
  });
});

describe("requireRecordingDraftsFor", () => {
  const REQUIRED: readonly GroupSessionCap[] = [
    { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: true, max_session_duration_seconds: 0, max_idle_seconds: 0 },
  ];

  it("seeds each group's mandate from the policies", () => {
    expect(requireRecordingDraftsFor(GROUPS, REQUIRED)).toEqual({ "g-1": false, "g-2": true });
  });

  it("returns NO entries when the policies could not be read", () => {
    expect(requireRecordingDraftsFor(GROUPS, null)).toEqual({});
  });

  it("defaults a group with no policy row to false (recording optional)", () => {
    expect(requireRecordingDraftsFor(GROUPS, REQUIRED)["g-1"]).toBe(false);
  });
});

describe("maxDurationDraftsFor", () => {
  const TIMED: readonly GroupSessionCap[] = [
    { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 3600, max_idle_seconds: 0 },
  ];

  it("seeds each group's duration from the policies (seconds as string)", () => {
    expect(maxDurationDraftsFor(GROUPS, TIMED)).toEqual({ "g-1": "0", "g-2": "3600" });
  });

  it("returns NO entries when the policies could not be read", () => {
    expect(maxDurationDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    expect(maxDurationDraftsFor(GROUPS, [])).toEqual({ "g-1": "0", "g-2": "0" });
    expect(maxDurationDraftsFor(GROUPS, [])).not.toEqual(maxDurationDraftsFor(GROUPS, null));
  });

  it("defaults a group with no policy row to '0' (unlimited)", () => {
    expect(maxDurationDraftsFor(GROUPS, TIMED)["g-1"]).toBe("0");
  });

  it("reads its OWN field, not max_concurrent_sessions", () => {
    const mixed: readonly GroupSessionCap[] = [
      { group_id: "g-1", max_concurrent_sessions: 5, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 1800, max_idle_seconds: 0 },
      { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(maxDurationDraftsFor(GROUPS, mixed)).toEqual({ "g-1": "1800", "g-2": "0" });
  });

  it("ignores a policy for a group that is not listed", () => {
    const stale: readonly GroupSessionCap[] = [
      { group_id: "g-gone", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 7200, max_idle_seconds: 0 },
    ];
    expect(maxDurationDraftsFor(GROUPS, stale)).toEqual({ "g-1": "0", "g-2": "0" });
  });

  it("has no drafts when there are no groups", () => {
    expect(maxDurationDraftsFor([], TIMED)).toEqual({});
  });
});

describe("maxIdleDraftsFor", () => {
  const IDLE: readonly GroupSessionCap[] = [
    { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 300 },
  ];

  it("seeds each group's idle limit from the policies (seconds as string)", () => {
    expect(maxIdleDraftsFor(GROUPS, IDLE)).toEqual({ "g-1": "0", "g-2": "300" });
  });

  it("returns NO entries when the policies could not be read", () => {
    expect(maxIdleDraftsFor(GROUPS, null)).toEqual({});
  });

  it("distinguishes an empty policy list from a failed load", () => {
    expect(maxIdleDraftsFor(GROUPS, [])).toEqual({ "g-1": "0", "g-2": "0" });
    expect(maxIdleDraftsFor(GROUPS, [])).not.toEqual(maxIdleDraftsFor(GROUPS, null));
  });

  it("defaults a group with no policy row to '0' (unlimited)", () => {
    expect(maxIdleDraftsFor(GROUPS, IDLE)["g-1"]).toBe("0");
  });

  it("reads max_idle_seconds, not max_session_duration_seconds", () => {
    const mixed: readonly GroupSessionCap[] = [
      { group_id: "g-1", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 3600, max_idle_seconds: 600 },
      { group_id: "g-2", max_concurrent_sessions: 0, enforce_view_only: false, allow_backstage_under_view_only: false, prohibit_recording: false, require_recording: false, max_session_duration_seconds: 0, max_idle_seconds: 0 },
    ];
    expect(maxIdleDraftsFor(GROUPS, mixed)).toEqual({ "g-1": "600", "g-2": "0" });
  });

  it("has no drafts when there are no groups", () => {
    expect(maxIdleDraftsFor([], IDLE)).toEqual({});
  });
});

describe("the policy editor (menu redesign wave 6)", () => {
  const read = [
    {
      group_id: "g1",
      max_concurrent_sessions: 3,
      enforce_view_only: true,
      allow_backstage_under_view_only: false,
      prohibit_recording: false,
      require_recording: true,
      max_session_duration_seconds: 3600,
      max_idle_seconds: 300,
    },
  ];

  it("recording is one choice: allowed, blocked or required, and a stored conflict is shown as one", () => {
    expect(recordingChoice(false, false)).toBe("allowed");
    expect(recordingChoice(true, false)).toBe("blocked");
    expect(recordingChoice(false, true)).toBe("required");
    expect(recordingChoice(true, true)).toBe("conflict");
    expect(recordingFlags("allowed")).toEqual({ prohibit: false, require: false });
    expect(recordingFlags("blocked")).toEqual({ prohibit: true, require: false });
    expect(recordingFlags("required")).toEqual({ prohibit: false, require: true });
  });

  it("a stored conflict cannot be saved until another choice is made", () => {
    const d = { ...policyDraftFromRead("g1", read)!, prohibitRecording: true, requireRecording: true };
    expect(groupPolicySubmission("loaded", d).refusal).toMatch(/both blocked and required/);
  });

  it("reads a group's saved policy back as a draft, with defaults for a group that has none", () => {
    expect(policyDraftFromRead("g1", read)).toEqual({
      cap: "3",
      enforceViewOnly: true,
      allowBackstageUnderViewOnly: false,
      prohibitRecording: false,
      requireRecording: true,
      maxDuration: "3600",
      maxIdle: "300",
    });
    expect(policyDraftFromRead("other", read)).toEqual({
      cap: "0",
      enforceViewOnly: false,
      allowBackstageUnderViewOnly: false,
      prohibitRecording: false,
      requireRecording: false,
      maxDuration: "0",
      maxIdle: "0",
    });
    expect(policyDraftFromRead("g1", null)).toBeNull();
  });

  it("Save policy is offered only when something changed, field by field", () => {
    const saved = policyDraftFromRead("g1", read)!;
    expect(policyDraftDirty(saved, { ...saved })).toBe(false);
    for (const [k, v] of Object.entries({
      cap: "4",
      enforceViewOnly: false,
      allowBackstageUnderViewOnly: true,
      prohibitRecording: true,
      requireRecording: false,
      maxDuration: "60",
      maxIdle: "0",
    })) {
      expect(policyDraftDirty(saved, { ...saved, [k]: v }), k).toBe(true);
    }
    // Nothing is dirty against a policy that was never read.
    expect(policyDraftDirty(null, { ...saved, cap: "9" })).toBe(false);
  });

  it("says a number of seconds in words", () => {
    expect(describeSeconds("0")).toBe("unlimited");
    expect(describeSeconds("3600")).toBe("1 h");
    expect(describeSeconds("5400")).toBe("1 h 30 min");
    expect(describeSeconds("86400")).toBe("24 h");
    expect(describeSeconds("90")).toBe("1 min 30 s");
    expect(describeSeconds("")).toBe("");
    expect(describeSeconds("1.5")).toBe("");
    expect(describeSeconds("-3")).toBe("");
    expect(describeSeconds(undefined)).toBe("");
  });
});
