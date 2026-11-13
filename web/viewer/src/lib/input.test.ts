/**
 * Input codec tests — pins `encodeInput` to the exact canonical JSON the Rust
 * `crates/agent-core/src/input_codec.rs` unit tests assert, so both sides move identical bytes.
 * The strings here are byte-for-byte the same literals as the Rust `round_trip` expectations.
 */

import { describe, it, expect } from "vitest";
import {
  encodeInput,
  mouseMove,
  mouseButton,
  scroll,
  key,
  text,
  type InputButton,
} from "./input";

const decode = (u: Uint8Array) => new TextDecoder().decode(u);

describe("encodeInput (wire-compat with Rust input_codec.rs)", () => {
  it("MouseMove → adjacently-tagged JSON", () => {
    expect(decode(encodeInput(mouseMove(32768, 100)))).toBe(
      '{"t":"MouseMove","c":{"x":32768,"y":100}}',
    );
  });

  it("MouseButton → button as a bare string, with down flag", () => {
    expect(decode(encodeInput(mouseButton("Left", true)))).toBe(
      '{"t":"MouseButton","c":{"button":"Left","down":true}}',
    );
    expect(decode(encodeInput(mouseButton("Left", false)))).toBe(
      '{"t":"MouseButton","c":{"button":"Left","down":false}}',
    );
  });

  it("every InputButton serializes to its bare string", () => {
    const buttons: InputButton[] = ["Left", "Right", "Middle", "Back", "Forward"];
    for (const b of buttons) {
      expect(decode(encodeInput(mouseButton(b, true)))).toBe(
        `{"t":"MouseButton","c":{"button":"${b}","down":true}}`,
      );
    }
  });

  it("Scroll → dx/dy content", () => {
    expect(decode(encodeInput(scroll(-2, 3)))).toBe('{"t":"Scroll","c":{"dx":-2,"dy":3}}');
  });

  it("Key down and up", () => {
    expect(decode(encodeInput(key(65, true)))).toBe('{"t":"Key","c":{"code":65,"down":true}}');
    expect(decode(encodeInput(key(65, false)))).toBe('{"t":"Key","c":{"code":65,"down":false}}');
  });

  it("Text → content is the bare string", () => {
    expect(decode(encodeInput(text("hi")))).toBe('{"t":"Text","c":"hi"}');
  });

  it("produces UTF-8 bytes (payload only, no frame header)", () => {
    const bytes = encodeInput(mouseMove(1, 2));
    expect(bytes).toBeInstanceOf(Uint8Array);
    // First byte is '{' (0x7b), not a ChannelId frame header — this is the payload, not a Frame.
    expect(bytes[0]).toBe(0x7b);
  });
});
