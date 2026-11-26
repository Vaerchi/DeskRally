// docs/77 phase 3: an INCREMENTAL SHA-256 for streaming downloads. Web Crypto's digest() needs the whole input at
// once, which a multi-gigabyte Get written straight to disk never has. FIPS 180-4, pure TS, no dependencies; checked
// against the standard vectors and against Web Crypto in sha256_stream.test.ts.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

/** The 8-byte big-endian BIT length that ends SHA-256 padding (exact for any byte count below 2^53 / 8). */
export function bitLengthTrailer(totalBytes: number): Uint8Array {
  const out = new Uint8Array(8);
  const view = new DataView(out.buffer);
  const hi = Math.floor(totalBytes / 0x20000000); // (bytes * 8) / 2^32
  const lo = ((totalBytes % 0x20000000) * 8) >>> 0;
  view.setUint32(0, hi);
  view.setUint32(4, lo);
  return out;
}

export class Sha256Stream {
  private readonly h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  private readonly w = new Uint32Array(64);
  private readonly block = new Uint8Array(64);
  private blockLen = 0;
  /** Total bytes hashed (a JS number is exact far beyond any file this will see: 2^53). */
  private total = 0;
  private finished = false;

  update(data: Uint8Array): this {
    if (this.finished) throw new Error("sha256: update after digest");
    let i = 0;
    this.total += data.length;
    if (this.blockLen > 0) {
      const take = Math.min(64 - this.blockLen, data.length);
      this.block.set(data.subarray(0, take), this.blockLen);
      this.blockLen += take;
      i = take;
      if (this.blockLen < 64) return this;
      this.compress(this.block, 0);
      this.blockLen = 0;
    }
    for (; i + 64 <= data.length; i += 64) this.compress(data, i);
    if (i < data.length) {
      this.block.set(data.subarray(i), 0);
      this.blockLen = data.length - i;
    }
    return this;
  }

  /** Lowercase hex, like Rust `file_transfer::sha256_hex` and `sha256Hex`. Ends the stream. */
  digestHex(): string {
    if (this.finished) throw new Error("sha256: digest twice");
    const pad = new Uint8Array(this.blockLen < 56 ? 64 - this.blockLen : 128 - this.blockLen);
    pad[0] = 0x80;
    pad.set(bitLengthTrailer(this.total), pad.length - 8);
    this.total -= pad.length; // padding is not message length
    this.update(pad);
    this.finished = true;
    let out = "";
    for (const v of this.h) out += v.toString(16).padStart(8, "0");
    return out;
  }

  private compress(src: Uint8Array, off: number): void {
    const w = this.w;
    for (let t = 0; t < 16; t++) {
      const j = off + t * 4;
      w[t] = ((src[j] << 24) | (src[j + 1] << 16) | (src[j + 2] << 8) | src[j + 3]) >>> 0;
    }
    for (let t = 16; t < 64; t++) {
      const a = w[t - 15], b = w[t - 2];
      const s0 = ((a >>> 7) | (a << 25)) ^ ((a >>> 18) | (a << 14)) ^ (a >>> 3);
      const s1 = ((b >>> 17) | (b << 15)) ^ ((b >>> 19) | (b << 13)) ^ (b >>> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = this.h;
    for (let t = 0; t < 64; t++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K[t] + w[t]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    const H = this.h;
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
}
