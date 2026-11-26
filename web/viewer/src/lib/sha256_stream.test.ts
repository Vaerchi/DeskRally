import { describe, expect, it } from "vitest";
import { bitLengthTrailer, Sha256Stream } from "./sha256_stream";
import { sha256Hex } from "./file_transfer";

const enc = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => new Sha256Stream().update(b).digestHex();

describe("Sha256Stream (docs/77 phase 3)", () => {
  it("matches the FIPS 180-4 / NIST vectors", () => {
    expect(hex(enc(""))).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(hex(enc("abc"))).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    expect(hex(enc("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    expect(hex(new Uint8Array(1_000_000).fill(0x61))).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });

  it("gives the same digest however the input is split, at every padding boundary", async () => {
    for (const n of [0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000, 4097]) {
      const data = new Uint8Array(n);
      for (let i = 0; i < n; i++) data[i] = (i * 31 + 7) & 0xff;
      const expected = await sha256Hex(data);
      expect(hex(data), `whole n=${n}`).toBe(expected);
      for (const step of [1, 3, 48, 64, 100]) {
        const s = new Sha256Stream();
        for (let i = 0; i < n; i += step) s.update(data.subarray(i, i + step));
        expect(s.digestHex(), `n=${n} step=${step}`).toBe(expected);
      }
    }
  });

  it("encodes bit lengths over 32 bits (files over 512 MiB) in both words", () => {
    const words = (n: number) => { const v = new DataView(bitLengthTrailer(n).buffer); return [v.getUint32(0), v.getUint32(4)]; };
    expect(words(3)).toEqual([0, 24]);
    expect(words(2 ** 29 - 1)).toEqual([0, 0xfffffff8]); // just under 2^32 bits
    expect(words(2 ** 29)).toEqual([1, 0]); // 512 MiB = 2^32 bits
    expect(words(4 * 2 ** 30 + 5)).toEqual([8, 40]); // 4 GiB + 5 bytes
  });

  it("refuses use after the digest", () => {
    const s = new Sha256Stream();
    s.digestHex();
    expect(() => s.update(enc("x"))).toThrow();
    expect(() => s.digestHex()).toThrow();
  });
});
