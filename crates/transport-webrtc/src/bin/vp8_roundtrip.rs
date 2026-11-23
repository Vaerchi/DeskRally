//! `vp8_roundtrip` — an off-wire codec-quality probe. It reads a raw BGRA desktop capture, encodes
//! it with the **shipping** [`Vp8Encoder`] settings (`CPU_USED=-6`, `SCREEN_CONTENT_MODE=1`, …),
//! decodes it back with [`Vp8Decoder`], writes the decoded image out, and reports fidelity. Its
//! whole point is to let a human EYEBALL what our VP8 pipeline does to real desktop content (text
//! legibility, scaling, artifacting) — the one thing a packet-count assertion cannot tell you.
//!
//! I/O is a trivial header-prefixed raw format (`.rgbx`) so no image-codec dependency is dragged in:
//!   `[u32 LE width][u32 LE height][width*height*4 bytes BGRA, top-down, tightly packed]`
//! (PowerShell writes the input via `System.Drawing` and turns the output back into a PNG.)
//!
//! Usage: `vp8_roundtrip <in.rgbx> <out.rgbx> [bitrate_bps]`

use rmt_transport_webrtc::video::{VideoEncoder, Vp8Decoder, Vp8Encoder};

fn read_rgbx(path: &str) -> (usize, usize, Vec<u8>) {
    let raw = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    assert!(raw.len() >= 8, "{path} too short to hold a header");
    let w = u32::from_le_bytes(raw[0..4].try_into().unwrap()) as usize;
    let h = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
    let need = 8 + w * h * 4;
    assert!(raw.len() >= need, "{path}: header says {w}x{h} ({need} bytes) but file is {}", raw.len());
    (w, h, raw[8..need].to_vec())
}

fn write_rgbx(path: &str, w: usize, h: usize, bgra: &[u8]) {
    let mut out = Vec::with_capacity(8 + bgra.len());
    out.extend_from_slice(&(w as u32).to_le_bytes());
    out.extend_from_slice(&(h as u32).to_le_bytes());
    out.extend_from_slice(bgra);
    std::fs::write(path, out).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: vp8_roundtrip <in.rgbx> <out.rgbx> [bitrate_bps]");
        std::process::exit(2);
    }
    let bitrate: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(3_000_000);

    let (w, h, src) = read_rgbx(&args[1]);
    eprintln!("input: {w}x{h} ({} BGRA bytes), target bitrate {bitrate} bps", src.len());

    let mut enc = Vp8Encoder::new(bitrate).expect("Vp8Encoder::new");
    enc.request_keyframe();
    let au = enc.encode_bgra(&src, w, h, 3000).expect("encode_bgra");
    eprintln!("encoded: keyframe={} vp8_bytes={}", au.keyframe, au.data.len());

    let mut dec = Vp8Decoder::new().expect("Vp8Decoder::new");
    let frame = dec.decode(&au.data).expect("decode").expect("a decoded frame");

    // Fidelity over the overlap (the encoder crops odd dims to even).
    let cw = w.min(frame.width);
    let ch = h.min(frame.height);
    let mut sum: u64 = 0;
    let mut peak: u32 = 0;
    for y in 0..ch {
        for x in 0..cw {
            let si = (y * w + x) * 4;
            let di = (y * frame.width + x) * 4;
            for c in 0..3 {
                let d = (src[si + c] as i32 - frame.bgra[di + c] as i32).unsigned_abs();
                sum += d as u64;
                peak = peak.max(d);
            }
        }
    }
    let n = (cw * ch * 3) as f64;
    let mae = sum as f64 / n;
    let mse = {
        let mut s: u64 = 0;
        for y in 0..ch {
            for x in 0..cw {
                let si = (y * w + x) * 4;
                let di = (y * frame.width + x) * 4;
                for c in 0..3 {
                    let d = src[si + c] as i32 - frame.bgra[di + c] as i32;
                    s += (d * d) as u64;
                }
            }
        }
        s as f64 / n
    };
    let psnr = if mse <= 0.0 { f64::INFINITY } else { 10.0 * (255.0f64 * 255.0 / mse).log10() };
    let bpp = (au.data.len() * 8) as f64 / (w * h) as f64;
    let ratio = (w * h * 3) as f64 / au.data.len() as f64;

    write_rgbx(&args[2], frame.width, frame.height, &frame.bgra);

    println!(
        "VP8 ROUNDTRIP: {w}x{h} -> {} vp8 bytes ({bpp:.3} bpp, {ratio:.1}x vs raw RGB) -> decoded {}x{}; \
         mean|d|(BGR)={mae:.2} peak|d|={peak} PSNR={psnr:.1} dB  (settings: shipping Vp8Encoder)",
        au.data.len(),
        frame.width,
        frame.height
    );
}
