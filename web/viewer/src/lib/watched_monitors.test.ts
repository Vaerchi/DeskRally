import { it, expect, vi } from "vitest";
import { watchedMonitors, watchedSender } from "./watched_monitors";
import { encodeControl, decodeControl } from "./control";
const canvas = { width: 6, height: 2, monitors: [0, 1, 2].map(id => ({ id, x: id * 2, y: 0, width: 2, height: 2 })) };
it("unions crops and collapses full coverage", () => {
  expect(watchedMonitors(canvas, 2, [0, 2], false)).toEqual([0, 2]);
  expect(watchedMonitors(canvas, 2, [0, 1], false)).toBeNull();
});
it("fails open for whole canvas, unknown crops and recording", () => {
  expect(watchedMonitors(canvas, null, [], false)).toBeNull();
  expect(watchedMonitors(canvas, 0, [null], false)).toBeNull();
  expect(watchedMonitors(canvas, 9, [], false)).toBeNull();
  expect(watchedMonitors(canvas, 0, [], true)).toBeNull();
});
it("sends first canvas and changes only, resetting between sessions", () => {
  const send = vi.fn(); const update = watchedSender();
  update(undefined, null, send); expect(send).not.toHaveBeenCalled();
  update(canvas, [0], send); update(canvas, [0], send);
  update(canvas, [0, 1], send); update(canvas, null, send); update(canvas, null, send);
  expect(send.mock.calls).toEqual([[[0]], [[0, 1]], [null]]);
  update(undefined, null, send); update(canvas, null, send);
  expect(send).toHaveBeenCalledTimes(4);
});
it("resends the current value when a new canvas arrives (agent session restarted)", () => {
  const send = vi.fn(); const update = watchedSender();
  update(canvas, [0], send); update(canvas, [0], send);
  update({ ...canvas }, [0], send);
  expect(send.mock.calls).toEqual([[[0]], [[0]]]);
});
it.each([{ monitors: null }, { monitors: [0, 2] }])("round trips watched wire %j", ({ monitors }) => {
  const msg = { t: "WatchedMonitors" as const, c: { monitors } };
  const wire = encodeControl(msg);
  expect(new TextDecoder().decode(wire)).toBe(JSON.stringify(msg));
  expect(decodeControl(wire)).toEqual(msg);
});
