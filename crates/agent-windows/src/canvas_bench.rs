//! `agent_host canvas-bench [--secs N] [--fps N] [--following [--encode]]` — a READ-ONLY measurement of the DXGI canvas
//! (docs/52) against the GDI composite on this machine's real displays. It reads the screen and
//! prints numbers: it draws nothing, injects nothing, opens no session and saves no image. This is
//! how docs/52's cost and correctness claims are measured on hardware the lab VM cannot stand in for
//! (multiple monitors, a real GPU).

use std::time::{Duration, Instant};

use crate::capture_gdi::{try_enumerate_monitors_checked, GdiCapturer};
use crate::dxgi_canvas::{CanvasOutcome, DxgiCanvas, Rect};
use crate::dxgi_source::{CanvasGdi, DxgiFactory};

fn arg(args: &[String], name: &str) -> Option<u64> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).and_then(|v| v.parse().ok())
}

/// This process's user+kernel CPU time.
fn cpu_time() -> Duration {
    use windows::Win32::Foundation::FILETIME;
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};
    let (mut c, mut e, mut k, mut u) = (FILETIME::default(), FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: the current-process pseudo handle and four out-params we own.
    if unsafe { GetProcessTimes(GetCurrentProcess(), &mut c, &mut e, &mut k, &mut u) }.is_err() {
        return Duration::ZERO;
    }
    let t = |f: FILETIME| (u64::from(f.dwHighDateTime) << 32 | u64::from(f.dwLowDateTime)) * 100;
    Duration::from_nanos(t(k) + t(u))
}

struct Run {
    calls: u32,
    frames: u32,
    no_news: u32,
    fallbacks: u32,
    busy: Duration,
    max: Duration,
    cpu: Duration,
    wall: Duration,
}

impl Run {
    fn print(&self, label: &str) {
        let calls = self.calls.max(1);
        println!(
            "{label:>14}: {} calls, {} frames, {} no-news, {} fallback | {:.1} ms/call mean, {:.1} ms max | CPU {:.0} ms over {:.1} s = {:.0}% of one core",
            self.calls,
            self.frames,
            self.no_news,
            self.fallbacks,
            self.busy.as_secs_f64() * 1000.0 / f64::from(calls),
            self.max.as_secs_f64() * 1000.0,
            self.cpu.as_secs_f64() * 1000.0,
            self.wall.as_secs_f64(),
            self.cpu.as_secs_f64() * 100.0 / self.wall.as_secs_f64().max(0.001),
        );
    }
}

pub fn canvas_bench_command(args: &[String]) -> i32 {
    // Its own log in %TEMP% (RMT_LOG_FILE still overrides): the capture path's tracing lines (canvas
    // built / regions / dropped) are the observable, and they must never land in the installed
    // agent's C:\rmt-agent\helper.log on the machine being measured.
    crate::logging::init_at(crate::logging::tool_log_path("canvas-bench"));
    if let Err(e) = crate::set_process_dpi_awareness() {
        eprintln!("warning: could not set PerMonitorV2 DPI awareness ({e}); rects may be scaled");
    }
    let secs = arg(args, "--secs").unwrap_or(10);
    let fps = arg(args, "--fps").unwrap_or(30).clamp(1, 120);
    let interval = Duration::from_secs_f64(1.0 / fps as f64);
    let (vx, vy, vw, vh) = crate::input::virtual_desktop_rect();
    let vrect = Rect { x: vx, y: vy, w: vw.max(0) as u32, h: vh.max(0) as u32 };
    let Some(monitors) = try_enumerate_monitors_checked() else {
        eprintln!("canvas-bench: monitor enumeration failed or was incomplete");
        return 1;
    };
    let rects: Vec<Rect> = monitors
        .iter()
        .map(|m| Rect { x: m.rect.left, y: m.rect.top, w: m.width().max(0) as u32, h: m.height().max(0) as u32 })
        .collect();
    println!("virtual desktop {}x{} at ({},{}); {} monitor(s); {} s at {} fps each", vrect.w, vrect.h, vrect.x, vrect.y, rects.len(), secs, fps);
    let factory = match DxgiFactory::new() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("canvas-bench: {e}");
            return 1;
        }
    };
    let Some(mut canvas) = DxgiCanvas::new(vrect, &rects, factory, CanvasGdi::new()) else {
        println!("canvas: NOT BUILT (no monitor can be served by DXGI); the GDI composite would be used");
        return 2;
    };

    // DXGI canvas.
    let mut run = Run { calls: 0, frames: 0, no_news: 0, fallbacks: 0, busy: Duration::ZERO, max: Duration::ZERO, cpu: Duration::ZERO, wall: Duration::ZERO };
    let (cpu0, start) = (cpu_time(), Instant::now());
    let mut first = true;
    while start.elapsed() < Duration::from_secs(secs) {
        let t = Instant::now();
        let out = canvas.capture(first, t);
        first = false;
        let took = t.elapsed();
        run.calls += 1;
        run.busy += took;
        run.max = run.max.max(took);
        match out {
            CanvasOutcome::Frame(_) => run.frames += 1,
            CanvasOutcome::NoNews => run.no_news += 1,
            CanvasOutcome::Fallback(why) => {
                run.fallbacks += 1;
                if run.fallbacks == 1 {
                    println!("  first fallback: {why}");
                }
            }
            CanvasOutcome::Demoted(why) => {
                println!("  DEMOTED: {why}");
                break;
            }
        }
        if let Some(rest) = interval.checked_sub(t.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    run.cpu = cpu_time().saturating_sub(cpu0);
    run.wall = start.elapsed();
    run.print("dxgi-canvas");
    println!("  sources: {:?}", canvas.sources());
    println!("  counters: {:?}", canvas.counters);

    // GDI composite, the current production path, same pacing.
    let mut gdi = GdiCapturer::new();
    let mut g = Run { calls: 0, frames: 0, no_news: 0, fallbacks: 0, busy: Duration::ZERO, max: Duration::ZERO, cpu: Duration::ZERO, wall: Duration::ZERO };
    let (cpu0, start) = (cpu_time(), Instant::now());
    while start.elapsed() < Duration::from_secs(secs) {
        let t = Instant::now();
        let ok = gdi.capture_rect(rmt_agent_core::COMPOSITE_MONITOR_ID, vrect.x, vrect.y, vrect.w as i32, vrect.h as i32).is_ok();
        let took = t.elapsed();
        g.calls += 1;
        g.busy += took;
        g.max = g.max.max(took);
        if ok { g.frames += 1 } else { g.fallbacks += 1 }
        if let Some(rest) = interval.checked_sub(t.elapsed()) {
            std::thread::sleep(rest);
        }
    }
    g.cpu = cpu_time().saturating_sub(cpu0);
    g.wall = start.elapsed();
    g.print("gdi-composite");

    // The production wiring: FollowingCapturer::capture_composite_if_changed, exactly as the shared
    // producer calls it (desktop follow, canvas build, release of the tier chain's duplication, no-news
    // and fallback mapping). The canvas above is dropped first: an output can be duplicated only once
    // per process.
    if args.iter().any(|a| a == "--following") {
        drop(canvas);
        use rmt_agent_core::ScreenCapturer as _;
        let mut fc = crate::following_capturer::FollowingCapturer::new();
        let (mut some, mut none, mut err) = (0u32, 0u32, 0u32);
        let mut sizes = std::collections::BTreeSet::new();
        // `--encode`: also VP8-encode every produced frame with the SESSION DEFAULTS (3 Mbps, full
        // size), so the whole per-frame cost on this machine is measured: capture + encode. Nothing
        // is sent anywhere and the bitstream is dropped.
        let mut encoder = if args.iter().any(|a| a == "--encode") {
            match rmt_transport_webrtc::video::Vp8Encoder::new(3_000_000) {
                Ok(e) => Some(e),
                Err(e) => {
                    eprintln!("canvas-bench: encoder: {e}");
                    return 1;
                }
            }
        } else {
            None
        };
        let (mut enc_busy, mut enc_max, mut enc_bytes, mut enc_err) = (Duration::ZERO, Duration::ZERO, 0u64, 0u32);
        let (cpu0, start) = (cpu_time(), Instant::now());
        let mut first = true;
        while start.elapsed() < Duration::from_secs(secs) {
            let t = Instant::now();
            match fc.capture_composite_if_changed(first) {
                Ok(Some(f)) => {
                    some += 1;
                    sizes.insert((f.width, f.height, f.bytes.len()));
                    if let Some(enc) = encoder.as_mut() {
                        use rmt_transport_webrtc::video::VideoEncoder as _;
                        let e0 = Instant::now();
                        match enc.encode_bgra(&f.bytes, f.width as usize, f.height as usize, 90_000 / fps as u32) {
                            Ok(au) => enc_bytes += au.data.len() as u64,
                            Err(_) => enc_err += 1,
                        }
                        let took = e0.elapsed();
                        enc_busy += took;
                        enc_max = enc_max.max(took);
                    }
                }
                Ok(None) => none += 1,
                Err(_) => err += 1,
            }
            first = false;
            if let Some(rest) = interval.checked_sub(t.elapsed()) {
                std::thread::sleep(rest);
            }
        }
        let cpu = cpu_time().saturating_sub(cpu0);
        println!(
            "{:>14}: {} frames, {} no-news, {} errors | frame sizes {:?} | CPU {:.0}% of one core",
            "following", some, none, err, sizes, cpu.as_secs_f64() * 100.0 / start.elapsed().as_secs_f64()
        );
        if encoder.is_some() {
            let n = some.max(1);
            println!(
                "{:>14}: {:.1} ms/frame mean, {:.1} ms max, {} errors, {:.0} kbps out (CPU above INCLUDES encoding; the encoder may use several threads)",
                "vp8 encode",
                enc_busy.as_secs_f64() * 1000.0 / f64::from(n),
                enc_max.as_secs_f64() * 1000.0,
                enc_err,
                enc_bytes as f64 * 8.0 / 1000.0 / start.elapsed().as_secs_f64(),
            );
        }
        return 0;
    }

    // Correctness: a forced canvas frame against a GDI composite read immediately after.
    if let CanvasOutcome::Frame(c) = canvas.capture(true, Instant::now()) {
        if let Ok(f) = gdi.capture_rect(rmt_agent_core::COMPOSITE_MONITOR_ID, vrect.x, vrect.y, vrect.w as i32, vrect.h as i32) {
            let total = (c.len() / 4).max(1);
            let same = c.chunks_exact(4).zip(f.bytes.chunks_exact(4)).filter(|(a, b)| a[..3] == b[..3]).count();
            println!("  canvas vs GDI composite: {same}/{total} pixels identical ({:.3}%) — a moving screen differs between the two reads", same as f64 * 100.0 / total as f64);
        }
    }
    0
}
