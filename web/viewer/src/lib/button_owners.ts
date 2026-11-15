/**
 * Who is holding a remote mouse button down.
 *
 * Several independent sources can press the SAME remote button: a physical mouse, the trackpad's
 * Left/Hold, and the direct-touch drag. One shared "pressed" set with no owner meant one source's
 * release dropped another's press (a physical click during Hold released the remote while the
 * trackpad still thought it was held), and a synthesised click on a button somebody else held went
 * out as an untracked down/up. This module is the single place that decides what reaches the wire:
 *
 * - `down` is sent only when a button goes from NO owners to one;
 * - `up` is sent only when its LAST owner lets go;
 * - a release by a source that does not own the button sends nothing (so a stray compatibility
 *   mouseup cannot release the trackpad's Hold);
 * - a synthesised click (trackpad tap / Right) on a button that is already held is SUPPRESSED, not
 *   sent as a second down/up: the guest would read it as a release in the middle of someone's drag.
 *
 * Pure and immutable, like the rest of the input logic, so every interleaving is unit-testable.
 */

export type Owner = "mouse" | "pad" | "touch";

/** button (DOM numbering) -> owners currently holding it. Buttons with no owners are absent. */
export type Owners = Readonly<Record<number, readonly Owner[]>>;

export const NO_OWNERS: Owners = {};

export function isDown(o: Owners, button: number): boolean {
  return (o[button]?.length ?? 0) > 0;
}

export function owns(o: Owners, button: number, owner: Owner): boolean {
  return o[button]?.includes(owner) ?? false;
}

export interface OwnersResult {
  owners: Owners;
  /** True when the caller must put a button-DOWN (acquire) / button-UP (release) on the wire. */
  send: boolean;
}

export function acquire(o: Owners, button: number, owner: Owner): OwnersResult {
  const cur = o[button] ?? [];
  if (cur.includes(owner)) return { owners: o, send: false };
  return { owners: { ...o, [button]: [...cur, owner] }, send: cur.length === 0 };
}

export function release(o: Owners, button: number, owner: Owner): OwnersResult {
  const cur = o[button];
  if (!cur || !cur.includes(owner)) return { owners: o, send: false };
  const next = cur.filter((x) => x !== owner);
  const { [button]: _gone, ...rest } = o;
  void _gone;
  return next.length === 0
    ? { owners: rest, send: true }
    : { owners: { ...rest, [button]: next }, send: false };
}

/** Everything let go at once (mode off, monitor change, hidden page): one `up` per held button. */
export function releaseAll(o: Owners): { owners: Owners; ups: number[] } {
  return { owners: NO_OWNERS, ups: Object.keys(o).map(Number).filter((b) => isDown(o, b)) };
}

/** A synthesised click may be sent only when nobody holds that button. */
export function clickAllowed(o: Owners, button: number): boolean {
  return !isDown(o, button);
}
