//! `agent_host monitors` — what the agent's capture stack actually sees on this machine.
//!
//! # Why this is a product surface and not a scratch script
//!
//! Multi-monitor bugs are diagnosed on somebody else's desk. "The picker only shows one screen" has
//! at least four causes that look identical from the console — the display is an indirect one DXGI
//! cannot enumerate, the agent is running in a session with no desktop, the ids and the capture
//! tier disagree, or the panel really is off. Guessing between them by rebuilding the agent and
//! shipping it to the operator costs a round trip each time.
//!
//! This subcommand prints all three views at once — the authoritative GDI enumeration, the DXGI
//! output list, and the virtual-desktop rect — plus, per monitor, **which tier served a real
//! capture and what came back**. `--capture <dir>` writes one PNG per monitor so the pixels can be
//! looked at, which is the only way to catch the failure mode where every monitor captures
//! *successfully* and they are all the same screen.
//!
//! It is read-only: it enumerates displays and grabs frames. It does not touch config, the service,
//! the network, or the hardened agent root.

use rmt_agent_core::CapturedFrame;

use crate::capture::DxgiCapturer;
use crate::capture_gdi::enumerate_monitors_ordered;
use crate::capture_loop::CaptureLoop;

/// `monitors [--capture <dir>]`. Returns a process exit code: 0 when at least one monitor captured,
/// 1 when none did (which is itself the answer to "why is the screen black").
pub fn monitors_command(args: &[String]) -> i32 {
    // PerMonitorV2 FIRST, before a single measurement — because without it this tool reports a
    // DIFFERENT MACHINE than the one the agent runs on, and reports it confidently.
    //
    // `helper_worker` makes this call as its first action, so the live session always sees physical
    // pixels. This subcommand is answered early in `host_main` (above `logging::init()`), which put
    // it in front of that call: Windows then virtualizes every coordinate API for it while the
    // capture surfaces stay physical, so on a machine with display scaling the output said things
    // like `dpi=96 scale=1.00` for a 150% panel and printed a monitor rect 1.5x smaller than the
    // frame captured from it. Two readers drew real conclusions from that — mixed-scaling bugs that
    // the live agent does not have — before the probe itself turned out to be the thing lying.
    //
    // Third instance this session of a diagnostic manufacturing the fault it reports. The rule
    // earned: a probe must put itself in the same process configuration as the code it describes,
    // and say so.
    if let Err(e) = crate::set_process_dpi_awareness() {
        println!("WARNING: could not set PerMonitorV2 DPI awareness ({e}) — every rect below may be");
        println!("         virtualized and will NOT match what the agent's helper sees.");
    }

    let dump_dir = arg_after(args, "--capture");

    let entries = enumerate_monitors_ordered();
    let (vx, vy, vw, vh) = crate::input::virtual_desktop_rect();
    println!("virtual desktop: origin=({vx},{vy}) size={vw}x{vh}  [PerMonitorV2 DPI-aware: rects are PHYSICAL pixels, as the agent sees them]");

    println!("\nGDI EnumDisplayMonitors (AUTHORITATIVE — ids are these positions, left to right):");
    if entries.is_empty() {
        println!("  (none — no enumerable display on this desktop)");
    }
    for (id, e) in entries.iter().enumerate() {
        println!(
            "  id={id} {device} rect=({l},{t})..({r},{b}) size={w}x{h} dpi={dpi} scale={scale:.2}{prim}",
            device = e.device,
            l = e.rect.left,
            t = e.rect.top,
            r = e.rect.right,
            b = e.rect.bottom,
            w = e.width(),
            h = e.height(),
            dpi = e.dpi_x,
            scale = e.dpi_x as f32 / 96.0,
            prim = if e.primary { "  [PRIMARY]" } else { "" },
        );
    }

    println!("\nDXGI Desktop Duplication outputs (indirect/DisplayLink displays never appear here):");
    match DxgiCapturer::new() {
        Ok(d) => match d.outputs() {
            Ok(outs) if outs.is_empty() => println!("  (no outputs)"),
            Ok(outs) => {
                for (i, (adapter, (l, t, r, b))) in outs.iter().enumerate() {
                    // Which published id this output serves, if any — the mapping capture uses.
                    let served = entries.iter().position(|e| {
                        (e.rect.left, e.rect.top, e.rect.right, e.rect.bottom) == (*l, *t, *r, *b)
                    });
                    let served = match served {
                        Some(id) => format!("serves id={id}"),
                        None => "serves NO published id (detached?)".to_string(),
                    };
                    println!("  output {i}: rect=({l},{t})..({r},{b})  adapter={adapter:?}  {served}");
                }
                // Duplication is adapter-bound, so a split across adapters is worth naming: it is
                // the ordinary laptop/iGPU+dGPU layout and it used to break capture of whichever
                // monitor was not on adapter 0.
                let adapters: std::collections::BTreeSet<&str> =
                    outs.iter().map(|(a, _)| a.as_str()).collect();
                if adapters.len() > 1 {
                    println!(
                        "  => displays are split across {} adapters; the capture device rebinds \
                         per monitor (DuplicateOutput is adapter-bound).",
                        adapters.len()
                    );
                }
                let rects: Vec<(i32, i32, i32, i32)> = outs.iter().map(|(_, r)| *r).collect();
                // The headline number for a dock complaint.
                let indirect = entries
                    .iter()
                    .filter(|e| {
                        !rects.iter().any(|r| {
                            *r == (e.rect.left, e.rect.top, e.rect.right, e.rect.bottom)
                        })
                    })
                    .count();
                if indirect > 0 {
                    println!(
                        "  => {indirect} display(s) have NO DXGI output — they are indirect \
                         (DisplayLink/dock/Miracast) and are captured by WGC or GDI instead."
                    );
                }
            }
            Err(e) => println!("  (enumeration failed: {e})"),
        },
        Err(e) => println!("  (DXGI unavailable: {e})"),
    }

    println!("\nCapture probe (the tier policy the streaming session uses):");
    // Scoped so the loop's DXGI duplication is RELEASED before the per-tier probe below opens its
    // own. An output can only be duplicated once per process: holding both at once makes the
    // second `DuplicateOutput` fail with `E_INVALIDARG`, and the probe then reports a healthy
    // monitor as DXGI-broken. (It did exactly that until this scope was added.)
    let (published, captured_any) = {
        let mut cap = CaptureLoop::new();
        let published = cap.monitors();
        println!("  published monitor list: {} entr(ies)", published.len());
        let mut captured_any = false;
        for m in &published {
            match capture_burst(&mut cap, m.id) {
                Some((tiers, attempts, frame)) => {
                    captured_any = true;
                    let hist = tiers
                        .iter()
                        .map(|(t, c)| format!("{t}x{c}"))
                        .collect::<Vec<_>>()
                        .join("  ");
                    println!(
                        "  id={id} {w}x{h} origin=({l},{t}) frame={fw}x{fh} \
                         (first usable = attempt {attempts} of {BURST}) {fp}\n         \
                         tiers over the burst: {hist}",
                        id = m.id,
                        w = m.width,
                        h = m.height,
                        l = m.left,
                        t = m.top,
                        fw = frame.width,
                        fh = frame.height,
                        fp = fingerprint(&frame),
                    );
                    if let Some(dir) = dump_dir.as_deref() {
                        // Labelled `policy`, not by tier: the `--all-tiers` pass below writes the
                        // same monitor under each tier's own name, and one overwriting the other
                        // would make the dumped pixels ambiguous about which path produced them.
                        dump_png(dir, m.id, &frame, "policy");
                    }
                }
                None => println!("  id={id} -> ALL TIERS FAILED", id = m.id),
            }
        }
        (published, captured_any)
    };

    // "View all" is a real menu entry the moment a second display exists, so its cost is a real
    // number someone should be able to read off rather than discover in a session. It is one GDI
    // blit of the whole virtual desktop — cheaper than it sounds, but a big frame for the encoder,
    // and its content is also the check that the blit is not coming back black.
    if published.len() > 1 {
        use rmt_agent_core::ScreenCapturer;
        let (vx, vy, vw, vh) = crate::input::virtual_desktop_rect();
        println!(
            "  source rect for the single-blit path: origin=({vx},{vy}) size={vw}x{vh} \
             (a composite of any OTHER size came from the per-monitor stitch fallback)"
        );
        let mut fc = crate::following_capturer::FollowingCapturer::new();
        // Timed over a BURST, not once. A single composite is cold — every tier is still building
        // its context and DXGI's first acquire on a fresh duplication hands back a blank surface —
        // so a one-shot number describes the warm-up, not the feature. A live session is warm.
        let mut times = Vec::new();
        let mut last = None;
        for _ in 0..6 {
            let started = std::time::Instant::now();
            match fc.capture_composite() {
                Ok(f) => {
                    times.push(started.elapsed().as_millis());
                    last = Some(f);
                }
                Err(e) => {
                    println!("\nComposite \"view all\": FAILED — {e}");
                    break;
                }
            }
        }
        if let Some(f) = last {
            let warm = times.iter().skip(1).copied().max().unwrap_or(0);
            println!(
                "\nComposite \"view all\": {}x{}  first {} ms, warm worst {} ms (~{} fps)  {}",
                f.width,
                f.height,
                times.first().copied().unwrap_or(0),
                warm,
                if warm > 0 { 1000 / warm } else { 999 },
                fingerprint(&f)
            );
            if let Some(dir) = dump_dir.as_deref() {
                dump_png_named(dir, "composite", &f);
            }
        }
    }

    if args.iter().any(|a| a == "--all-tiers") {
        // Each tier ON ITS OWN, per monitor. The policy probe above only exercises whichever tier
        // wins here, so it cannot tell you that the FALLBACK is broken — and the fallback is the
        // whole path an indirect display takes. A monitor that captures under `dxgi` but returns
        // the wrong panel under `gdi` looks perfectly healthy until someone plugs in a dock.
        println!("\nPer-tier probe (--all-tiers): every tier against every monitor.");
        let mut tiers = Tiers::new();
        for m in &published {
            for tier in ["dxgi", "wgc", "gdi"] {
                match tiers.capture(tier, m) {
                    Ok(frame) => {
                        println!(
                            "  id={id} tier={tier:<4} -> {fw}x{fh} {fp}",
                            id = m.id,
                            fw = frame.width,
                            fh = frame.height,
                            fp = fingerprint(&frame),
                        );
                        if let Some(dir) = dump_dir.as_deref() {
                            dump_png(dir, m.id, &frame, tier);
                        }
                    }
                    Err(e) => println!("  id={id} tier={tier:<4} -> {e}", id = m.id),
                }
            }
        }
    }

    if !captured_any {
        eprintln!("\nno monitor could be captured on this desktop");
        return 1;
    }
    println!(
        "\nNOTE: two monitors reporting the same fingerprint means the same screen was captured \
         twice — the classic symptom of a tier that ignores the monitor selection."
    );
    0
}

/// How many frames the probe pulls per monitor before reporting. See [`capture_burst`].
const BURST: u32 = 12;

/// Capture a full burst: report the first frame with real content, and WHICH TIER served each
/// attempt.
///
/// A single grab is not a fair test of the capture stack, and reading one as if it were would make
/// this tool lie in the most damaging direction — "your second monitor captures black" is the exact
/// conclusion someone would act on. DXGI yields a frame only on a screen CHANGE, so an idle desktop
/// legitimately has nothing new to give, and the first acquire after `DuplicateOutput` reports no
/// change at all. The streaming session rides both out because it captures continuously; a one-shot
/// probe has to do the same or it measures the warm-up instead of the display.
///
/// It runs the WHOLE burst rather than stopping at the first usable frame, because attempt 1 always
/// falls through to GDI for the reason above — so stopping there would report `gdi-fallback` on
/// every machine in the fleet and say nothing about whether the fast path works at all. The tier
/// histogram is the answer to the question a support engineer actually has: on THIS machine, over a
/// couple of seconds of real screen activity, what is serving the picture?
///
/// Returns `(tier counts, the attempt the reported frame came from, frame)`.
fn capture_burst(
    cap: &mut CaptureLoop,
    id: u32,
) -> Option<(Vec<(&'static str, u32)>, u32, CapturedFrame)> {
    let mut tiers: Vec<(&'static str, u32)> = Vec::new();
    let mut best: Option<(u32, CapturedFrame)> = None;
    let bump = |tiers: &mut Vec<(&'static str, u32)>, tier: &'static str| {
        match tiers.iter_mut().find(|(t, _)| *t == tier) {
            Some((_, c)) => *c += 1,
            None => tiers.push((tier, 1)),
        }
    };
    for n in 1..=BURST {
        // Not `secure`/`remote`: this runs interactively on the Default desktop, which is the
        // configuration being diagnosed.
        match cap.capture(false, false, id) {
            Some((tier, frame)) => {
                bump(&mut tiers, tier);
                let blank =
                    frame.bytes.chunks_exact(4).all(|p| p[0] == 0 && p[1] == 0 && p[2] == 0);
                if !blank && best.is_none() {
                    best = Some((n, frame));
                }
            }
            // Not a failure: the screen has not changed and the receiver already has this picture.
            // Counted, because "mostly nothing new" is the correct and expected reading of an idle
            // machine and its absence would be the surprising thing.
            None => bump(&mut tiers, "(no new frame)"),
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    best.map(|(n, f)| (tiers, n, f))
}

/// The three tiers, each constructed ONCE, for the `--all-tiers` probe.
///
/// Holding them matters, it is not tidiness: a monitor can only be duplicated once per process, and
/// building a fresh `DxgiCapturer` per attempt makes `DuplicateOutput` fail with `E_INVALIDARG`
/// against a display that is perfectly healthy. A diagnostic that manufactures the fault it is
/// looking for is worse than no diagnostic — the first version of this probe did exactly that and
/// reported the second monitor as DXGI-broken.
struct Tiers {
    dxgi: Option<DxgiCapturer>,
    wgc: Option<crate::capture_wgc::WgcCapturer>,
    gdi: crate::capture_gdi::GdiCapturer,
}

impl Tiers {
    fn new() -> Self {
        Self {
            dxgi: DxgiCapturer::new().ok(),
            wgc: crate::capture_wgc::WgcCapturer::new().ok(),
            gdi: crate::capture_gdi::GdiCapturer::new(),
        }
    }

    /// Capture one monitor with ONE named tier, bypassing the policy in [`CaptureLoop`].
    ///
    /// Every tier is driven the same way the loop drives it — by the monitor's virtual-desktop
    /// rect — so this reports the tier's real per-monitor behaviour and not a primary-only
    /// shortcut. Each gets a burst for the same reason [`capture_burst`] exists (WGC in particular
    /// has nothing to hand back until its frame pool fills).
    fn capture(
        &mut self,
        tier: &str,
        m: &rmt_agent_core::MonitorInfo,
    ) -> Result<CapturedFrame, String> {
        let (l, t) = (m.left, m.top);
        let (w, h) = (m.width as i32, m.height as i32);
        let mut best: Option<CapturedFrame> = None;
        let mut last_err = String::from("no frame");
        for _ in 0..BURST {
            let attempt: Result<CapturedFrame, String> = match tier {
                "dxgi" => {
                    // Resolve with an IMMUTABLE borrow in its own scope so the no-match arm can
                    // re-read `output_rects()` for evidence, then take the mutable borrow to
                    // capture. Two borrows rather than one because the diagnostic's job on failure
                    // is to show what it compared.
                    let resolved = {
                        let d = self.dxgi.as_ref().ok_or("DXGI unavailable")?;
                        d.output_index_for_rect((l, t, l + w, t + h))
                    };
                    match resolved {
                        Ok(Some(idx)) => self
                            .dxgi
                            .as_mut()
                            .ok_or("DXGI unavailable")?
                            .capture(idx, std::time::Duration::from_millis(120))
                            .map_err(|e| e.to_string())
                            .and_then(|f| f.ok_or_else(|| "no new frame".to_string()))
                            .map(|mut f| {
                                f.monitor_id = m.id;
                                f
                            }),
                        Ok(None) => {
                            // EVIDENCE, not a conclusion. This used to read "indirect display —
                            // expected", which is a claim about the operator's HARDWARE, and on a
                            // real machine it fired for a display that demonstrably had a DXGI
                            // output (the same monitor had just been captured through DXGI seven
                            // times). Two readers concluded the operator had DisplayLink panels.
                            // A probe reports what it compared and lets the reader conclude.
                            let saw = self
                                .dxgi
                                .as_ref()
                                .ok_or("DXGI unavailable")?
                                .output_rects()
                                .map(|rs| {
                                    rs.iter()
                                        .map(|(l, t, r, b)| format!("({l},{t})..({r},{b})"))
                                        .collect::<Vec<_>>()
                                        .join(" ")
                                })
                                .unwrap_or_else(|e| format!("<enumeration failed: {e}>"));
                            return Err(format!(
                                "no DXGI output matched. wanted ({l},{t})..({},{}) — saw {saw}",
                                l + w,
                                t + h
                            ));
                        }
                        Err(e) => Err(e.to_string()),
                    }
                }
                "wgc" => {
                    let c = self.wgc.as_mut().ok_or("WGC unavailable")?;
                    c.capture_monitor(m.id, crate::capture_wgc::hmonitor_for_rect(l, t, w, h))
                        .map_err(|e| e.to_string())
                }
                _ => self
                    .gdi
                    .capture_rect(m.id, l, t, w, h)
                    .map_err(|e| e.to_string()),
            };
            match attempt {
                Ok(f) => {
                    let blank =
                        f.bytes.chunks_exact(4).all(|p| p[0] == 0 && p[1] == 0 && p[2] == 0);
                    if !blank {
                        return Ok(f);
                    }
                    best = Some(f);
                }
                Err(e) => last_err = e,
            }
            std::thread::sleep(std::time::Duration::from_millis(40));
        }
        best.ok_or(last_err)
    }
}

/// A cheap content signature: mean B/G/R plus a checksum over a strided sample.
///
/// The point is *distinguishing* monitors, not hashing them. Two panels showing different content
/// will differ; two captures of the SAME panel will match — which is exactly the bug this
/// subcommand exists to make visible (a tier that silently captures the primary for every id
/// returns a perfectly valid frame per monitor, and only comparing content reveals it).
fn fingerprint(f: &CapturedFrame) -> String {
    if f.bytes.is_empty() {
        return "sig=EMPTY".to_string();
    }
    let (mut b, mut g, mut r) = (0u64, 0u64, 0u64);
    let mut sum = 0u64;
    let mut n = 0u64;
    // Sample every 997th pixel (a prime, so the stride cannot lock onto a repeating pattern).
    for (i, px) in f.bytes.chunks_exact(4).enumerate().step_by(997) {
        b += px[0] as u64;
        g += px[1] as u64;
        r += px[2] as u64;
        sum = sum
            .wrapping_mul(31)
            .wrapping_add(((px[0] as u64) << 16 | (px[1] as u64) << 8 | px[2] as u64) ^ i as u64);
        n += 1;
    }
    if n == 0 {
        return "sig=EMPTY".to_string();
    }
    let black = b == 0 && g == 0 && r == 0;
    format!(
        "sig={sum:016x} mean_bgr=({},{},{}){}",
        b / n,
        g / n,
        r / n,
        if black { "  [ALL BLACK]" } else { "" }
    )
}

/// Write one monitor's frame to `<dir>/monitor-<id>-<tier>.png`.
fn dump_png(dir: &str, id: u32, frame: &CapturedFrame, tier: &str) {
    dump_png_named(dir, &format!("monitor-{id}-{tier}"), frame);
}

/// Write a frame to `<dir>/<stem>.png`, reporting success or the reason not.
fn dump_png_named(dir: &str, stem: &str, frame: &CapturedFrame) {
    let path = std::path::Path::new(dir).join(format!("{stem}.png"));
    if let Err(e) = std::fs::create_dir_all(dir) {
        println!("      (could not create {dir}: {e})");
        return;
    }
    match crate::screenshot::encode_png(frame) {
        Ok(png) => match std::fs::write(&path, &png) {
            Ok(()) => println!("      wrote {} ({} bytes)", path.display(), png.len()),
            Err(e) => println!("      (could not write {}: {e})", path.display()),
        },
        Err(e) => println!("      (could not encode PNG: {e})"),
    }
}

/// The value following `flag` in `args`, if present.
fn arg_after(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, fill: impl Fn(usize) -> [u8; 4]) -> CapturedFrame {
        let mut bytes = Vec::with_capacity((w * h * 4) as usize);
        for i in 0..(w * h) as usize {
            bytes.extend_from_slice(&fill(i));
        }
        CapturedFrame { monitor_id: 0, width: w, height: h, bytes, is_keyframe: true }
    }

    #[test]
    fn fingerprint_separates_different_content() {
        // The whole diagnostic value: two DIFFERENT screens must not share a signature.
        let a = frame(64, 64, |i| [(i % 251) as u8, 10, 20, 255]);
        let b = frame(64, 64, |i| [(i % 241) as u8, 10, 20, 255]);
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_matches_the_same_content() {
        // …and the failure it exists to catch: the SAME screen captured twice must collide, or the
        // "captured the primary for every id" bug stays invisible.
        let a = frame(64, 64, |i| [(i % 251) as u8, 10, 20, 255]);
        let b = frame(64, 64, |i| [(i % 251) as u8, 10, 20, 255]);
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn an_all_black_capture_is_called_out() {
        // A tier can "succeed" and hand back black (DXGI inside RDP does exactly this); a reader
        // scanning the output must not have to notice that mean_bgr is (0,0,0).
        let black = frame(64, 64, |_| [0, 0, 0, 255]);
        assert!(fingerprint(&black).contains("ALL BLACK"));
        let not_black = frame(64, 64, |_| [0, 0, 1, 255]);
        assert!(!not_black.bytes.is_empty());
        assert!(!fingerprint(&not_black).contains("ALL BLACK"));
    }

    #[test]
    fn fingerprint_survives_an_empty_frame() {
        let empty = CapturedFrame {
            monitor_id: 0,
            width: 0,
            height: 0,
            bytes: Vec::new(),
            is_keyframe: true,
        };
        assert_eq!(fingerprint(&empty), "sig=EMPTY");
    }

    #[test]
    fn arg_after_reads_the_following_value_only() {
        let args: Vec<String> = ["monitors", "--capture", "C:\\tmp"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(arg_after(&args, "--capture"), Some("C:\\tmp".to_string()));
        assert_eq!(arg_after(&args, "--missing"), None);
        // A trailing flag with no value must not panic or swallow the flag itself.
        let dangling: Vec<String> = ["monitors", "--capture"].iter().map(|s| s.to_string()).collect();
        assert_eq!(arg_after(&dangling, "--capture"), None);
    }
}
