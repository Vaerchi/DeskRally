/**
 * Canonical controller→agent input codec (browser side).
 *
 * Mirror of the Rust `crates/agent-core/src/input_codec.rs` + the `InputEvent` wire shape in
 * `crates/agent-core/src/platform.rs`. `encodeInput` produces exactly the JSON bytes the Rust
 * agent's `input_codec::decode` accepts: an **adjacently-tagged** object `{ "t": <variant>,
 * "c": <content> }`. Adjacent tagging (rather than a flat `{ "t": ..., ...fields }`) is required
 * because the Rust `Text` variant is a newtype wrapping a bare string, which serde cannot flatten
 * into an internally-tagged object. Keep this in lockstep with the Rust side.
 *
 * NOTE (framing, deferred to M4): the Rust agent moves full `Frame`s (`[channel][len][payload]`,
 * see protocol.ts) over ONE "frames" data channel, whereas this browser viewer currently opens six
 * separate named data channels (one per `ChannelId`). Reconciling that framing mismatch — so the
 * browser sends input as a `ChannelId.Input` `Frame` on the single channel — is M4 work. This
 * module produces only the input **payload** bytes; wrapping them in a `Frame` (via
 * `encodeFrame(frame(ChannelId.Input, encodeInput(ev)))`) is the caller's job once framing lands.
 */

/** A pointer button — the bare-string values the Rust `InputButton` enum serializes to. */
export type InputButton = "Left" | "Right" | "Middle" | "Back" | "Forward";

/**
 * A controller→agent input event, in the canonical adjacently-tagged wire shape. Coordinates are
 * absolute, normalized to `0..=65535` across the target monitor (see the Rust `InputEvent` docs).
 */
export type InputEvent =
  | { t: "MouseMove"; c: { x: number; y: number } }
  | { t: "MouseButton"; c: { button: InputButton; down: boolean } }
  | { t: "Scroll"; c: { dx: number; dy: number } }
  | { t: "Key"; c: { code: number; down: boolean } }
  | { t: "Text"; c: string }
  // The Secure Attention Sequence (Ctrl+Alt+Del). A unit variant: serde on the Rust side emits the
  // tag with NO `c` content key, so we must too — `{ t: "Sas" }`, nothing else.
  | { t: "Sas" };

/**
 * Encode one input event to its canonical JSON wire bytes (UTF-8), byte-compatible with Rust
 * `input_codec::decode`. This is the input **payload** only — see the module note on framing.
 */
export function encodeInput(ev: InputEvent): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(ev));
}

// Convenience constructors — keep call sites terse and the tag/content shape in one place.

/** Absolute pointer move, coords normalized to `0..=65535`. */
export const mouseMove = (x: number, y: number): InputEvent => ({ t: "MouseMove", c: { x, y } });

/** Press or release a mouse button. */
export const mouseButton = (button: InputButton, down: boolean): InputEvent => ({
  t: "MouseButton",
  c: { button, down },
});

/** Wheel movement in detents (positive `dy` = up, positive `dx` = right). */
export const scroll = (dx: number, dy: number): InputEvent => ({ t: "Scroll", c: { dx, dy } });

/** Raw key press/release by code. */
export const key = (code: number, down: boolean): InputEvent => ({ t: "Key", c: { code, down } });

/** Inject a run of Unicode text (IME/paste-style). */
export const text = (s: string): InputEvent => ({ t: "Text", c: s });

/**
 * Secure Attention Sequence (Ctrl+Alt+Del). Emitted by the viewer's toolbar button, because the
 * browser never lets Ctrl+Alt+Del reach the page — the local OS intercepts it. The agent maps this
 * to `SendSAS`; a raw `key()` of Ctrl/Alt/Delete would be silently dropped by Windows.
 */
export const sas = (): InputEvent => ({ t: "Sas" });
