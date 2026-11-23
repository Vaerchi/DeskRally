import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { ControlClient, decodeControl, encodeControl } from "../lib/control";
import { KEEP_AWAKE_OFF, KeepAwakeBadge, KeepAwakeControl, keepAwakeReducer } from "./KeepAwakeControl";

describe("Keep awake wire messages", () => {
  it.each(["SetKeepAwake", "KeepAwakeState"] as const)("round-trips %s with a boolean", (t) => {
    for (const on of [true, false]) {
      const msg = { t, c: { on } };
      const wire = encodeControl(msg);
      expect(new TextDecoder().decode(wire)).toBe(`{"t":"${t}","c":{"on":${on}}}`);
      expect(decodeControl(wire)).toEqual(msg);
    }
    for (const c of [{}, { on: "true" }]) {
      expect(() => decodeControl(new TextEncoder().encode(JSON.stringify({ t, c })))).toThrow();
    }
  });
});

describe("Keep awake session controls", () => {
  const controlMarkup = (model = KEEP_AWAKE_OFF, advertised = true, observing = false, viewOnly = false) =>
    renderToStaticMarkup(<KeepAwakeControl model={model} advertised={advertised} observing={observing}
      viewOnly={viewOnly} onRequest={() => {}} />);
  const badgeMarkup = (model = KEEP_AWAKE_OFF) => renderToStaticMarkup(<KeepAwakeBadge model={model} />);

  it("offers the toggle in the Session section only for advertised, controllable sessions", () => {
    expect(controlMarkup()).toContain("keep-awake-toggle");
    expect(controlMarkup()).toContain(">Session<");
    expect(controlMarkup(KEEP_AWAKE_OFF, false)).toBe("");
    expect(controlMarkup(KEEP_AWAKE_OFF, true, true)).toBe("");
    expect(controlMarkup(KEEP_AWAKE_OFF, true, false, true)).toBe("");
  });

  it("waits for the agent, shows a badge outside the menu, and clears state on reset", () => {
    let model = KEEP_AWAKE_OFF;
    const sent: Uint8Array[] = [];
    const client = new ControlClient((payload) => sent.push(payload), {
      onKeepAwakeState: (on) => { model = keepAwakeReducer(model, { type: "confirmed", on }); },
    });
    const receive = (on: boolean) => client.handleMessage(encodeControl({ t: "KeepAwakeState", c: { on } }));

    model = keepAwakeReducer(model, { type: "requested" });
    client.setKeepAwake(true);
    expect(sent.map(decodeControl)).toEqual([{ t: "SetKeepAwake", c: { on: true } }]);
    expect(controlMarkup(model)).toContain('aria-pressed="false"');
    expect(controlMarkup(model)).toContain('disabled=""');
    expect(badgeMarkup(model)).toBe("");

    receive(true);
    expect(controlMarkup(model)).toContain('aria-pressed="true"');
    expect(controlMarkup(model)).not.toContain("disabled");
    expect(badgeMarkup(model)).toContain('data-testid="keep-awake-badge">Awake');

    model = keepAwakeReducer(model, { type: "requested" });
    expect(controlMarkup(model)).toContain('aria-pressed="true"');
    expect(badgeMarkup(model)).toContain("Awake");
    receive(false);
    expect(badgeMarkup(model)).toBe("");

    receive(true);
    model = keepAwakeReducer(model, { type: "requested" });
    model = keepAwakeReducer(model, { type: "reset" });
    expect(controlMarkup(model)).toContain('aria-pressed="false"');
    expect(controlMarkup(model)).not.toContain("disabled");
    expect(badgeMarkup(model)).toBe("");
  });
});
