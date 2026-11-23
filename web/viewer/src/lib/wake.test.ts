import { describe, expect, it } from "vitest";
import { wakeMenuState, wakeResultMessage } from "./wake";

const ready = { online: false, group_id: "g1", wake: "ready" } as const;
const scoped = [{ capability: "wake_machine", all_groups: false, group_ids: ["g1"] }];
const tenantWide = [{ capability: "wake_machine", all_groups: true, group_ids: [] }];
const hidden = { visible: false, enabled: false };
const noLanFacts = "This machine hasn't reported a wired network yet";
const noRelay = "No online machine you manage is on its network";

describe("wakeMenuState", () => {
  it("offers Wake for a ready offline machine with a matching group or tenant-wide capability", () => {
    expect(wakeMenuState(ready, scoped, true)).toEqual({ visible: true, enabled: true });
    expect(wakeMenuState(ready, tenantWide, true)).toEqual({ visible: true, enabled: true });
  });

  it("hides Wake when the machine is online or its presence is unknown", () => {
    expect(wakeMenuState({ ...ready, online: true }, scoped, true)).toEqual(hidden);
    expect(wakeMenuState({ group_id: "g1", wake: "ready" }, scoped, true)).toEqual(hidden);
    expect(wakeMenuState(ready, scoped, false)).toEqual(hidden);
  });

  it("hides Wake without the capability, group access, or readiness hint", () => {
    expect(wakeMenuState(ready, [], true)).toEqual(hidden);
    expect(wakeMenuState({ ...ready, group_id: "g2" }, scoped, true)).toEqual(hidden);
    expect(wakeMenuState({ online: false, group_id: "g1" }, scoped, true)).toEqual(hidden);
  });

  it("shows why an offline machine is ineligible", () => {
    expect(wakeMenuState({ ...ready, wake: "no_lan_facts" }, scoped, true))
      .toEqual({ visible: true, enabled: false, reason: noLanFacts });
    expect(wakeMenuState({ ...ready, wake: "no_relay" }, scoped, true))
      .toEqual({ visible: true, enabled: false, reason: noRelay });
  });
});

describe("wakeResultMessage", () => {
  const cases: [string | number | undefined, string][] = [
    ["requested", "Wake requested. It only works if Wake-on-LAN is turned on for this machine."],
    ["uncertain", "Wake requested. It only works if Wake-on-LAN is turned on for this machine. The request may not have reached the relay."],
    ["machine_online", "This machine is already online."],
    ["no_lan_facts", noLanFacts],
    ["no_relay", noRelay],
    ["unavailable", "No relay could be reached right now. Try again shortly."],
    ["changed", "Something changed while sending the request. Try again."],
    ["presence_unknown", "Machine status is unknown right now. Try again shortly."],
    ["audit_unavailable", "Wake is unavailable: auditing is not configured."],
    [429, "Wake was requested very recently. Wait a moment and try again."],
    [404, "Wake-on-LAN is not enabled on this server."],
    ["internal_error", "Could not request wake. Try again shortly."],
    [undefined, "Could not request wake. Try again shortly."],
  ];

  it.each(cases)("describes %s without implying delivery or a power change", (outcome, expected) => {
    const message = wakeResultMessage(outcome);
    expect(message).toBe(expected);
    expect(message).not.toMatch(/woke| sent/i);
  });
});
