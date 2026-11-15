import { describe, expect, it } from "vitest";
import {
  NO_ADMIN_RIGHTS,
  adminRightsAdvertised,
  adminRightsRequested,
  adminRightsResult,
  adminRightsView,
} from "./admin_rights";
import { ControlClient, decodeControl, encodeControl, type AdminRightsState } from "./control";

describe("admin-rights control messages (docs/53)", () => {
  it("round-trip with the agent's exact shapes", () => {
    const req = new TextDecoder().decode(encodeControl({ t: "RequestAdminRights" }));
    expect(req).toBe('{"t":"RequestAdminRights"}');
    // The agent's pinned JSON (crates/agent-core control.rs tests).
    const avail = new TextEncoder().encode('{"t":"AdminRightsAvailable","c":{"available":false,"reason":"the signed-in user is not an administrator"}}');
    expect(decodeControl(avail)).toEqual({ t: "AdminRightsAvailable", c: { available: false, reason: "the signed-in user is not an administrator" } });
    const res = new TextEncoder().encode('{"t":"AdminRightsResult","c":{"state":"granted","reason":null}}');
    expect(decodeControl(res)).toEqual({ t: "AdminRightsResult", c: { state: "granted", reason: null } });
    // An absent reason decodes as null.
    expect(decodeControl(new TextEncoder().encode('{"t":"AdminRightsResult","c":{"state":"declined"}}'))).toEqual({
      t: "AdminRightsResult",
      c: { state: "declined", reason: null },
    });
  });

  it("are decoded strictly", () => {
    const bad = [
      '{"t":"AdminRightsAvailable","c":{}}',
      '{"t":"AdminRightsAvailable","c":{"available":"yes"}}',
      '{"t":"AdminRightsAvailable","c":{"available":true,"reason":5}}',
      '{"t":"AdminRightsResult","c":{"state":"approved"}}',
      '{"t":"AdminRightsResult","c":{"state":"granted","reason":{}}}',
    ];
    for (const b of bad) expect(() => decodeControl(new TextEncoder().encode(b)), b).toThrow();
  });

  it("reach their handlers, and requestAdminRights sends the request", () => {
    const sent: string[] = [];
    const seen: unknown[] = [];
    const client = new ControlClient((bytes) => sent.push(new TextDecoder().decode(bytes)), {
      onAdminRightsAvailable: (a, r) => seen.push(["available", a, r]),
      onAdminRightsResult: (s, r) => seen.push(["result", s, r]),
    });
    client.handleMessage(encodeControl({ t: "AdminRightsAvailable", c: { available: true, reason: null } }));
    client.handleMessage(encodeControl({ t: "AdminRightsResult", c: { state: "pending", reason: null } }));
    expect(seen).toEqual([["available", true, null], ["result", "pending", null]]);
    client.requestAdminRights();
    expect(sent).toEqual(['{"t":"RequestAdminRights"}']);
  });
});

describe("adminRightsView (docs/53 §5)", () => {
  const advertised = (available: boolean, reason: string | null = null) => adminRightsAdvertised(NO_ADMIN_RIGHTS, available, reason);

  it("shows nothing until the agent advertises, and never to an observer", () => {
    expect(adminRightsView(NO_ADMIN_RIGHTS, false).show).toBe(false);
    expect(adminRightsView(advertised(true), true).show).toBe(false);
    expect(adminRightsView(advertised(true), false)).toMatchObject({ show: true, canRequest: true, status: null, hint: null });
  });

  it("shows why not when the agent cannot", () => {
    const v = adminRightsView(advertised(false, "the signed-in user is not an administrator"), false);
    expect(v).toMatchObject({ show: true, canRequest: false, disabledReason: "the signed-in user is not an administrator" });
  });

  it("blocks a second request while one waits or a grant lives, with the standing hint", () => {
    const pending = adminRightsRequested(advertised(true));
    expect(adminRightsView(pending, false)).toMatchObject({ canRequest: false, status: "Waiting for the guest to approve…" });
    expect(adminRightsView(pending, false).hint).toContain("only on the guest's screen");
    const granted = adminRightsResult(pending, "granted", null);
    expect(adminRightsView(granted, false)).toMatchObject({ canRequest: false, status: "Admin rights granted" });
    expect(adminRightsView(granted, false).hint).not.toBeNull();
  });

  it("allows asking again after an end, a decline or an unavailable answer", () => {
    const base = adminRightsRequested(advertised(true));
    const cases: [AdminRightsState, string | null, string][] = [
      ["ended", null, "Admin rights ended"],
      ["declined", null, "The guest declined"],
      ["unavailable", "the guest's session window is not showing", "Admin rights unavailable: the guest's session window is not showing"],
      ["unavailable", "expired", "Request expired; if Windows is still asking, the guest can click No."],
    ];
    for (const [state, reason, text] of cases) {
      const v = adminRightsView(adminRightsResult(base, state, reason), false);
      expect(v, state).toMatchObject({ canRequest: true, status: text, hint: null });
    }
  });
});
