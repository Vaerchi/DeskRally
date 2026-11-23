//! `agent_host audio-probe` — can this machine's audio be captured, and by whom?
//!
//! Audio passthrough is a net-new feature with one load-bearing unknown in front of it: the agent's
//! per-session helper runs as **SYSTEM inside the user's session**, audio endpoints are per-session,
//! and whether such a process may open the interactive user's render endpoint for loopback capture
//! is not something to assume on the way to building an encoder and a transport on top of it. This
//! subcommand answers it on a real machine in one command — run it as yourself, then run it as the
//! service, and compare.
//!
//! It also reports the endpoint's **mix format**, which decides whether the Opus stage needs a
//! resampler (Opus wants 48 kHz; plenty of endpoints run at 44.1).
//!
//! Read-only: it opens the render endpoint for capture and reads levels. It plays nothing, changes
//! no device setting, and writes no file.

use std::time::{Duration, Instant};

use crate::audio::{levels_dbfs, LoopbackCapture};

/// How long the probe listens by default. Long enough that a human can start something playing
/// after seeing the first line, short enough not to feel hung.
const DEFAULT_SECS: u64 = 5;

/// `audio-probe [--secs N]`. Exit code 0 when the endpoint opened for capture (whether or not
/// anything was playing), 1 when it did not — the answer to "can this account capture audio here".
pub fn audio_probe_command(args: &[String]) -> i32 {
    let secs = args
        .iter()
        .position(|a| a == "--secs")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_SECS);

    // Match the agent's process configuration before measuring anything — see the note in
    // `monitor_report`. Audio does not depend on DPI, but a diagnostic that configures itself
    // differently from the code it describes is exactly how the display probe came to report a
    // machine that does not exist.
    let _ = crate::set_process_dpi_awareness();

    println!("running as: {}", whoami());

    let mut cap = match LoopbackCapture::new() {
        Ok(c) => c,
        Err(e) => {
            // THE result this subcommand exists for. Say which account failed, because "it works
            // for me" and "it works for the service" are different facts and only the second one
            // ships.
            eprintln!("LOOPBACK CAPTURE UNAVAILABLE for {}: {e}", whoami());
            return 1;
        }
    };

    println!("endpoint : {}", cap.endpoint_id());
    println!("mixformat: {}", cap.format());
    if cap.format().sample_rate != 48_000 {
        println!(
            "  note: Opus encodes at 48 kHz, so this endpoint needs a resample ({} Hz -> 48000 Hz).",
            cap.format().sample_rate
        );
    }
    println!("listening for {secs}s — PLAY SOMETHING (a video, a system sound) to see levels move");

    let mut samples: Vec<f32> = Vec::new();
    let mut packets = 0usize;
    let mut silent_packets = 0usize;
    let mut frames_total = 0u64;
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last_report = Instant::now();

    while Instant::now() < deadline {
        match cap.drain(&mut samples) {
            Ok(stats) => {
                for s in &stats {
                    packets += 1;
                    frames_total += s.frames as u64;
                    if s.silent {
                        silent_packets += 1;
                    }
                }
            }
            Err(e) => {
                eprintln!("capture failed mid-probe: {e}");
                return 1;
            }
        }
        // A per-second line, so a human can start audio playing and watch the level respond rather
        // than wait for one verdict at the end.
        if last_report.elapsed() >= Duration::from_secs(1) {
            match levels_dbfs(&samples) {
                Some((peak, rms)) => println!(
                    "  +{:>2}s  packets={packets:<5} frames={frames_total:<8} peak={peak:>7.1} dBFS  rms={rms:>7.1} dBFS",
                    secs.saturating_sub(deadline.saturating_duration_since(Instant::now()).as_secs()),
                ),
                None => println!(
                    "  +{:>2}s  no packets yet — nothing is playing (loopback is clocked by the \
                     endpoint, so an idle machine delivers nothing at all)",
                    secs.saturating_sub(deadline.saturating_duration_since(Instant::now()).as_secs()),
                ),
            }
            samples.clear();
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    println!("\nRESULT: the render endpoint OPENED for loopback capture as {}.", whoami());
    println!(
        "  packets={packets}  frames={frames_total}  silent-flagged packets={silent_packets}"
    );
    if packets == 0 {
        // Deliberately not a failure. Distinguishing "cannot capture" from "nothing was playing" is
        // the entire point of the exit code, and conflating them would make the probe answer the
        // wrong question — the same trap as reading DXGI's "no new frame" as a broken display.
        println!(
            "  Nothing was playing, so there was nothing to capture. That is NOT a capture failure:\n\
             \x20 the endpoint opened, which is the part that needs permission. Re-run with audio playing\n\
             \x20 to see levels."
        );
    }
    0
}

/// `DOMAIN\user` for this process, so the probe's verdict names the account it applies to.
fn whoami() -> String {
    std::env::var("USERNAME")
        .map(|u| {
            let d = std::env::var("USERDOMAIN").unwrap_or_default();
            if d.is_empty() {
                u
            } else {
                format!("{d}\\{u}")
            }
        })
        .unwrap_or_else(|_| "<unknown>".to_string())
}
