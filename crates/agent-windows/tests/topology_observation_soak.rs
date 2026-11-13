//! Topology-observation soak — **read-only hardware diagnostic**.
//!
//! Repeatedly calls [`FollowingCapturer::topology_snapshot`] (the GDI-checked enumeration path)
//! and records availability, change counts, and query latencies without ever mutating hardware
//! state, capturing a frame, injecting input, or touching services, clipboard, SAS, or audio.
//!
//! # Invocation
//!
//! ```text
//! cargo test -p rmt-agent-windows --test topology_observation_soak \
//!     topology_observation_soak -- --exact --nocapture --ignored
//! ```
//!
//! Environment variables (all optional):
//!
//! | Variable | Default | Range |
//! |---|---|---|
//! | `RMT_TOPOLOGY_SOAK_SECONDS` | 60 | 1 – 36 000 |
//! | `RMT_TOPOLOGY_SOAK_INTERVAL_MS` | 100 | 8 – 1 000 |
//!
//! # Scope and limitations
//!
//! * Runs on the **single ordinary interactive desktop** of the calling process. It does not
//!   exercise RDP session enumeration, UAC/Winlogon desktop switches, or physical monitor hotplug
//!   that is not already in progress. Changes in OS-reported metadata have no independent
//!   physical-layout ground truth in this test.
//! * Uses GDI `EnumDisplayMonitors` (via the production `FollowingCapturer` path). WGC is not
//!   consulted; DirectX is not initialised. No frames are decoded or encoded.
//! * Unavailability (`None` return from `topology_snapshot`) is counted but does NOT assert failure
//!   — the API may legitimately return `None` during a display driver transition.
//! * Topology changes between consecutive *valid* observations are reported, not failed upon.
//!   The test process has no independent ground truth that a change is spurious.
//! * This test is marked `#[ignore]` and must be started deliberately; it is NOT part of the
//!   standard `cargo test` run.

#![cfg(windows)]

use std::time::{Duration, Instant};

use rmt_agent_core::ScreenCapturer;
use rmt_agent_windows::FollowingCapturer;

// ── reservoir sampling ────────────────────────────────────────────────────────

const RESERVOIR_CAP: usize = 8_192;

/// Fixed-capacity reservoir of `u64` nanosecond latency samples.
///
/// Algorithm-R-style bounded sampling estimates p95; mean and maximum are tracked
/// exactly over the full stream. The deterministic PRNG is diagnostic, not cryptographic.
struct Reservoir {
    buf: Vec<u64>,
    total_seen: u64,
    sum: u128,
    maximum: u64,
    random_state: u64,
}

impl Reservoir {
    fn new() -> Self {
        Self { buf: Vec::with_capacity(RESERVOIR_CAP), total_seen: 0, sum: 0, maximum: 0, random_state: 0x4d595df4d0f33173 }
    }

    fn push(&mut self, nanos: u64) {
        self.total_seen += 1;
        self.sum += nanos as u128;
        self.maximum = self.maximum.max(nanos);
        if self.buf.len() < RESERVOIR_CAP {
            self.buf.push(nanos);
        } else {
            self.random_state = lcg_next(self.random_state);
            let idx = self.random_state % self.total_seen;
            if idx < RESERVOIR_CAP as u64 { self.buf[idx as usize] = nanos; }
        }
    }

    fn len(&self) -> usize {
        self.buf.len()
    }

    fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Returns (mean_ns, p95_ns, max_ns). Sorts a copy of the reservoir.
    fn stats(&self) -> Option<(u64, u64, u64)> {
        if self.buf.is_empty() {
            return None;
        }
        let mut sorted = self.buf.clone();
        sorted.sort_unstable();
        let mean = self.sum / self.total_seen as u128;
        let p95_idx = (sorted.len() * 95).saturating_sub(1) / 100;
        let p95 = sorted[p95_idx];
        let max = self.maximum;
        Some((mean as u64, p95, max))
    }
}

/// Minimal linear congruential generator seeded by sample count (no `rand` dep).
fn lcg_next(seed: u64) -> u64 {
    seed.wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

// ── env-var helpers ───────────────────────────────────────────────────────────

/// Parse `var`, fall back to `default`, clamp to `[lo, hi]`.
fn clamp_env(var: &str, default: u64, lo: u64, hi: u64) -> u64 {
    parse_clamped(std::env::var(var).ok().as_deref(), default, lo, hi)
}

fn parse_clamped(raw: Option<&str>, default: u64, lo: u64, hi: u64) -> u64 {
    raw.and_then(|s| s.trim().parse::<u64>().ok()).unwrap_or(default).clamp(lo, hi)
}

// ── the soak ─────────────────────────────────────────────────────────────────

#[test]
#[ignore]
fn topology_observation_soak() {
    let soak_secs = clamp_env("RMT_TOPOLOGY_SOAK_SECONDS", 60, 1, 36_000);
    let interval_ms = clamp_env("RMT_TOPOLOGY_SOAK_INTERVAL_MS", 100, 8, 1_000);

    let soak_dur = Duration::from_secs(soak_secs);
    let interval = Duration::from_millis(interval_ms);

    // DPI awareness must come first — FollowingCapturer reads physical pixels.
    if let Err(e) = rmt_agent_windows::set_process_dpi_awareness() {
        eprintln!("WARN: set_process_dpi_awareness failed (non-fatal): {e}");
    }

    let capturer = FollowingCapturer::new();

    eprintln!(
        "TOPOLOGY_SOAK START duration={}s interval={}ms reservoir_cap={}",
        soak_secs, interval_ms, RESERVOIR_CAP,
    );

    let deadline = Instant::now() + soak_dur;
    let mut next_summary = Instant::now() + Duration::from_secs(60);

    let mut samples: u64 = 0;
    let mut valid: u64 = 0;
    let mut unavailable: u64 = 0;
    let mut changed: u64 = 0;
    let mut last_valid_snap: Option<rmt_agent_core::TopologySnapshot> = None;
    let mut latencies = Reservoir::new();

    while Instant::now() < deadline {
        let t0 = Instant::now();
        let snap = capturer.topology_snapshot();
        let elapsed_ns = t0.elapsed().as_nanos() as u64;
        samples += 1;
        latencies.push(elapsed_ns);

        match snap {
            None => {
                unavailable += 1;
                // Preserve last_valid_snap; do not update baseline.
            }
            Some(s) => {
                if let Some(ref prev) = last_valid_snap {
                    if &s != prev {
                        changed += 1;
                        eprintln!(
                            "TOPOLOGY_SOAK CHANGE observed at sample={} monitors_now={}",
                            samples,
                            s.monitors.len(),
                        );
                    }
                }
                last_valid_snap = Some(s);
                valid += 1;
            }
        }

        let now = Instant::now();
        if now >= next_summary {
            print_summary(samples, valid, unavailable, changed, &latencies, now, deadline);
            next_summary = now + Duration::from_secs(60);
        }

        // Sleep the remaining interval (skip if the query itself took longer).
        let spent = t0.elapsed();
        if spent < interval {
            std::thread::sleep(interval - spent);
        }
    }

    // ── final report ─────────────────────────────────────────────────────────

    let (mean_ns, p95_ns, max_ns) = latencies.stats().unwrap_or((0, 0, 0));
    let mean_us = mean_ns / 1_000;
    let p95_us = p95_ns / 1_000;
    let max_us = max_ns / 1_000;

    // Machine-readable single-line summary for Codex/CI parsing.
    println!(
        "TOPOLOGY_SOAK RESULT duration_s={soak_secs} \
         sample_count={samples} valid={valid} unavailable={unavailable} changed={changed} \
         mean_us={mean_us} estimated_p95_us={p95_us} max_us={max_us} \
         reservoir_filled={}",
        latencies.len(),
    );

    // Diagnostic failure: if every single query failed we have learnt nothing.
    assert!(
        valid > 0,
        "DIAGNOSTIC FAILURE: topology_snapshot returned None for all {samples} samples. \
         The display enumeration API is unavailable on this desktop. \
         Possible causes: session-0 / non-interactive service context, \
         headless / RDSH environment without a monitor, or a driver fault. \
         Run this test from an interactive user session with at least one monitor attached."
    );
}

fn print_summary(
    samples: u64,
    valid: u64,
    unavailable: u64,
    changed: u64,
    lat: &Reservoir,
    now: Instant,
    deadline: Instant,
) {
    let remaining = deadline.saturating_duration_since(now);
    let (mean_ns, p95_ns, max_ns) = lat.stats().unwrap_or((0, 0, 0));
    eprintln!(
        "TOPOLOGY_SOAK SUMMARY remaining={}s samples={} valid={} unavailable={} changed={} \
         mean_us={} estimated_p95_us={} max_us={}",
        remaining.as_secs(),
        samples,
        valid,
        unavailable,
        changed,
        mean_ns / 1_000,
        p95_ns / 1_000,
        max_ns / 1_000,
    );
}

// ── pure unit tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn configuration_parsing_is_bounded() {
        assert_eq!(parse_clamped(None, 42, 1, 1000), 42);
        assert_eq!(parse_clamped(Some("0"), 42, 8, 1000), 8);
        assert_eq!(parse_clamped(Some("99999"), 42, 1, 1000), 1000);
        assert_eq!(parse_clamped(Some("500"), 42, 1, 1000), 500);
        assert_eq!(parse_clamped(Some("bad"), 77, 1, 1000), 77);
    }

    #[test]
    fn global_mean_and_maximum_survive_reservoir_replacements() {
        let mut r = Reservoir::new();
        r.push(1_000_000);
        for _ in 0..100_000 { r.push(1); }
        let (mean, _, maximum) = r.stats().unwrap();
        assert_eq!(mean, 1_100_000 / 100_001);
        assert_eq!(maximum, 1_000_000);
    }

    #[test]
    fn reservoir_stats_single_sample() {
        let mut r = Reservoir::new();
        r.push(1_000);
        let (mean, p95, max) = r.stats().unwrap();
        assert_eq!(mean, 1_000);
        assert_eq!(p95, 1_000);
        assert_eq!(max, 1_000);
    }

    #[test]
    fn reservoir_stats_known_values() {
        let mut r = Reservoir::new();
        // 100 samples: 1..=100 µs in nanos.
        for i in 1u64..=100 {
            r.push(i * 1_000);
        }
        let (mean, p95, max) = r.stats().unwrap();
        // mean of 1..=100 = 50500 ns
        assert_eq!(mean, 50_500);
        // p95: index = (100*95 - 1)/100 = 94 → value 95_000 ns
        assert_eq!(p95, 95_000);
        assert_eq!(max, 100_000);
    }

    #[test]
    fn reservoir_empty_stats_is_none() {
        let r = Reservoir::new();
        assert!(r.stats().is_none());
        assert!(r.is_empty());
    }

    #[test]
    fn reservoir_bounded_at_cap() {
        let mut r = Reservoir::new();
        for i in 0u64..(RESERVOIR_CAP as u64 * 3) {
            r.push(i);
        }
        assert_eq!(r.len(), RESERVOIR_CAP);
        assert_eq!(r.total_seen, RESERVOIR_CAP as u64 * 3);
    }

    #[test]
    fn reservoir_stats_empty_returns_none() {
        let r = Reservoir::new();
        assert!(r.stats().is_none());
    }
}
