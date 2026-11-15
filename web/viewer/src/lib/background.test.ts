import { describe, expect, it } from "vitest";

import { BackgroundTracker, watchVisibility, type VisibilityDocument } from "./background";
import { ControlClient, decodeControl, encodeControl, setBackground, type ControlMessage } from "./control";

describe("BackgroundTracker", () => {
  it("is in the background only when every window showing the session is hidden", () => {
    const t = new BackgroundTracker();
    const main = {};
    const monitor2 = {};
    expect(t.update(main, false)).toBeUndefined(); // visible: no change from the initial state
    expect(t.update(monitor2, true)).toBeUndefined(); // one of two hidden: still in front
    expect(t.update(main, true)).toBe(true); // both hidden: background
    expect(t.update(main, true)).toBeUndefined(); // repeats are not transitions
    expect(t.update(monitor2, false)).toBe(false); // any window shown: back at once
    expect(t.background).toBe(false);
  });

  it("forgets an unmounted window", () => {
    const t = new BackgroundTracker();
    const main = {};
    const popout = {};
    expect(t.update(main, true)).toBe(true); // the only window, hidden
    expect(t.update(popout, false)).toBe(false); // a visible pop-out opens
    expect(t.update(popout, null)).toBe(true); // the visible pop-out closed; the hidden main remains
    expect(t.update(main, null)).toBeUndefined(); // nothing mounted: still background
  });

  it("is in the background with no window at all (another console tab), and back when one mounts", () => {
    const t = new BackgroundTracker();
    const main = {};
    expect(t.background).toBe(false); // a new session starts in front, before any window reports
    expect(t.update(main, false)).toBeUndefined(); // the desktop mounts, visible
    expect(t.update(main, null)).toBe(true); // switched to Files/Chat: the desktop unmounted
    expect(t.background).toBe(true);
    const again = {};
    expect(t.update(again, false)).toBe(false); // back on the Screen tab: a new, visible window
  });
});

describe("watchVisibility", () => {
  function fakeDoc(state: DocumentVisibilityState) {
    const listeners = new Set<() => void>();
    const doc = {
      visibilityState: state,
      addEventListener: (type: string, fn: () => void) => type === "visibilitychange" && listeners.add(fn),
      removeEventListener: (type: string, fn: () => void) => type === "visibilitychange" && listeners.delete(fn),
    };
    const set = (s: DocumentVisibilityState) => {
      doc.visibilityState = s;
      listeners.forEach((fn) => fn());
    };
    return { doc: doc as unknown as VisibilityDocument, set, listeners };
  }

  it("reports now, on every change, and nothing after unsubscribing", () => {
    const { doc, set, listeners } = fakeDoc("visible");
    const seen: boolean[] = [];
    const stop = watchVisibility(doc, (h) => seen.push(h));
    set("hidden");
    set("visible");
    stop();
    set("hidden");
    expect(seen).toEqual([false, true, false]);
    expect(listeners.size).toBe(0);
  });
});

describe("SetBackground on the wire", () => {
  it("matches the agent's pinned form and decodes back", () => {
    const bytes = encodeControl(setBackground(true));
    expect(new TextDecoder().decode(bytes)).toBe(`{"t":"SetBackground","c":{"background":true}}`);
    expect(decodeControl(bytes)).toEqual({ t: "SetBackground", c: { background: true } });
    expect(() => decodeControl(new TextEncoder().encode(`{"t":"SetBackground","c":{}}`))).toThrow();
  });

  it("ControlClient.setBackground frames it", () => {
    const sent: ControlMessage[] = [];
    const client = new ControlClient((p) => sent.push(decodeControl(p)));
    client.setBackground(false);
    expect(sent).toEqual([{ t: "SetBackground", c: { background: false } }]);
  });
});
