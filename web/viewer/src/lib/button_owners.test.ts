import { describe, expect, it } from "vitest";
import {
  NO_OWNERS,
  acquire,
  clickAllowed,
  isDown,
  owns,
  release,
  releaseAll,
  type Owner,
  type Owners,
} from "./button_owners";
import { createPadSender } from "./pad_sender";

/** Apply a script of [op, owner] on button 0, returning the wire events it produced. */
function script(steps: Array<["down" | "up", Owner]>, from: Owners = NO_OWNERS) {
  let o = from;
  const wire: string[] = [];
  for (const [op, who] of steps) {
    const r = op === "down" ? acquire(o, 0, who) : release(o, 0, who);
    o = r.owners;
    if (r.send) wire.push(op);
  }
  return { o, wire };
}

describe("button ownership", () => {
  it("one owner: down then up", () => {
    expect(script([["down", "mouse"], ["up", "mouse"]]).wire).toEqual(["down", "up"]);
  });

  it("a physical release during Hold does not release the remote", () => {
    const { o, wire } = script([["down", "pad"], ["down", "mouse"], ["up", "mouse"]]);
    expect(wire).toEqual(["down"]);
    expect(isDown(o, 0)).toBe(true);
    expect(owns(o, 0, "pad")).toBe(true);
  });

  it("the remote is released only when the LAST owner lets go, in either order", () => {
    expect(script([["down", "pad"], ["down", "mouse"], ["up", "mouse"], ["up", "pad"]]).wire).toEqual(["down", "up"]);
    expect(script([["down", "mouse"], ["down", "pad"], ["up", "mouse"], ["up", "pad"]]).wire).toEqual(["down", "up"]);
  });

  it("a release by a non-owner (stray compatibility mouseup) sends nothing", () => {
    const { o, wire } = script([["down", "pad"], ["up", "mouse"], ["up", "touch"]]);
    expect(wire).toEqual(["down"]);
    expect(isDown(o, 0)).toBe(true);
  });

  it("acquiring twice as the same owner presses once", () => {
    expect(script([["down", "pad"], ["down", "pad"], ["up", "pad"]]).wire).toEqual(["down", "up"]);
  });

  it("buttons are independent", () => {
    const a = acquire(NO_OWNERS, 0, "mouse");
    const b = acquire(a.owners, 2, "mouse");
    expect(b.send).toBe(true);
    expect(release(b.owners, 2, "mouse").send).toBe(true);
    expect(isDown(release(b.owners, 2, "mouse").owners, 0)).toBe(true);
  });

  it("a synthesised click is suppressed while the button is held by anyone, allowed otherwise", () => {
    expect(clickAllowed(NO_OWNERS, 0)).toBe(true);
    const held = acquire(NO_OWNERS, 0, "mouse").owners;
    expect(clickAllowed(held, 0)).toBe(false);
    expect(clickAllowed(held, 2)).toBe(true);
    expect(clickAllowed(release(held, 0, "mouse").owners, 0)).toBe(true);
  });

  it("releaseAll gives one up per held button and clears everything", () => {
    let o = acquire(NO_OWNERS, 0, "pad").owners;
    o = acquire(o, 0, "mouse").owners;
    o = acquire(o, 2, "touch").owners;
    const r = releaseAll(o);
    expect(r.ups.sort()).toEqual([0, 2]);
    expect(r.owners).toEqual({});
    expect(releaseAll(r.owners).ups).toEqual([]);
  });

  it("random interleavings: the wire is always strictly down/up alternating and ends up when all let go", () => {
    let seed = 99;
    const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
    const owners: Owner[] = ["mouse", "pad", "touch"];
    let o: Owners = NO_OWNERS;
    let open = 0;
    for (let i = 0; i < 2000; i++) {
      const who = owners[Math.floor(rnd() * 3)];
      const r = rnd() < 0.5 ? acquire(o, 0, who) : release(o, 0, who);
      const wasDown = isDown(o, 0);
      if (r.send) open += wasDown ? -1 : 1;
      o = r.owners;
      expect(open).toBe(isDown(o, 0) ? 1 : 0);
    }
  });
});

describe("pad sender (move coalescing and wheel accumulation)", () => {
  function harness() {
    const queue: Array<() => void> = [];
    const sent: string[] = [];
    const s = createPadSender({
      schedule: (cb) => {
        queue.push(cb);
        return () => {
          const i = queue.indexOf(cb);
          if (i >= 0) queue.splice(i, 1);
        };
      },
      sendMove: () => sent.push("move"),
      sendWheel: (dx, dy) => sent.push(`wheel ${dx},${dy}`),
    });
    return { s, sent, tick: () => queue.splice(0).forEach((f) => f()) };
  }

  it("many moves in one tick are one send", () => {
    const { s, sent, tick } = harness();
    for (let i = 0; i < 50; i++) s.move();
    expect(sent).toEqual([]);
    tick();
    expect(sent).toEqual(["move"]);
    tick();
    expect(sent).toEqual(["move"]);
  });

  it("wheel deltas are summed, not dropped", () => {
    const { s, sent, tick } = harness();
    s.wheel(0, 1);
    s.wheel(0, 2);
    s.wheel(1, -1);
    tick();
    expect(sent).toEqual(["wheel 1,2"]);
  });

  it("a wheel that nets to zero sends nothing, and the move goes first", () => {
    const a = harness();
    a.s.wheel(0, 2);
    a.s.wheel(0, -2);
    a.tick();
    expect(a.sent).toEqual([]);
    const b = harness();
    b.s.wheel(0, 3);
    b.s.move();
    b.tick();
    expect(b.sent).toEqual(["move", "wheel 0,3"]);
  });

  it("flush sends pending work immediately (before a button) and cancels the timer", () => {
    const { s, sent, tick } = harness();
    s.move();
    s.wheel(0, 1);
    s.flush();
    expect(sent).toEqual(["move", "wheel 0,1"]);
    tick();
    expect(sent).toEqual(["move", "wheel 0,1"]); // nothing left for the tick
    expect(s.pending()).toBe(false);
  });
});
