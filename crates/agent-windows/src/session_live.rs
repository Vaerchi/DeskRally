//! "A remote session is live on this machine" — the marker the helper stamps and the service's uploader reads
//! (docs/63 R2 §9.1, review item C).
//!
//! The recording uploader runs in the SERVICE and must never compete with a live session for the link. Only the
//! per-session helper knows which session tasks are alive, so it stamps `C:\rmt-agent\session-live` while ANY
//! session task is running, refreshing it at least every [`REFRESH_EVERY_MS`] (well inside the one-minute budget),
//! and removes it when the last session ends. The uploader treats a stamp younger than [`FRESH_MS`] (two minutes)
//! as "live": a helper that died mid-session leaves a stamp that goes stale on its own, so uploads resume.
//!
//! Both sides go through the agent root's trusted route ([`crate::anchor`]): the file is created
//! SYSTEM/Administrators-only AT CREATION (the root's protected descriptor) and replaced atomically (temp file,
//! flush, rename), and the reader validates the file's owner and DACL before believing it — so a non-admin cannot
//! plant a stamp to stall uploads, and nobody ever reads a half-written one.
//!
//! The decision logic is pure ([`LiveStamper::tick`], [`is_fresh`]) and takes the clock as an argument, so the
//! helper side is tested with a fake clock and a fake file; [`AnchorStampIo`] is the production file.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Marker files are `session-live.<pid>`: one per helper process, so two helpers (several consoles, a helper
/// restarting beside its predecessor) never clear each other's signal.
pub const MARKER_PREFIX: &str = "session-live.";
/// The most per-helper stamps the uploader examines in one look. EVERY matching stamp is examined up to this many;
/// more than this is not a real machine and is answered "live" (fail toward pausing uploads), never "no session".
pub const MAX_MARKERS: usize = 1024;
/// A stamp this old belongs to a helper that is gone for good; the reader (the service) removes it.
pub const GC_AFTER_MS: i64 = 3_600_000;

/// This helper's own marker name.
pub fn marker_name(pid: u32) -> String {
    format!("{MARKER_PREFIX}{pid}")
}
/// The helper re-stamps at least this often while any session is alive (the budget is 60 s).
pub const REFRESH_EVERY_MS: i64 = 30_000;
/// A stamp older than this is stale (a crashed helper must not block uploads forever).
pub const FRESH_MS: i64 = 120_000;
/// How far into the future a stamp may be dated before it is not believed (clock steps, not forgery: the file is
/// admin-only already).
pub const MAX_FUTURE_MS: i64 = 60_000;
const POLL: Duration = Duration::from_secs(10);

/// Where the stamp is written and removed.
pub trait StampIo {
    fn write(&mut self, unix_ms: i64) -> io::Result<()>;
    fn clear(&mut self) -> io::Result<()>;
}

/// Decides, tick by tick, whether the marker must be (re)written or removed.
#[derive(Debug, Default)]
pub struct LiveStamper {
    last_write_ms: Option<i64>,
    stamped: bool,
}

/// What a tick did (tests assert it; the helper logs failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stamp {
    Idle,
    Wrote,
    Cleared,
    WriteFailed,
    ClearFailed,
}

impl LiveStamper {
    /// `live`: any session task is alive right now.
    pub fn tick(&mut self, now_ms: i64, live: bool, io: &mut dyn StampIo) -> Stamp {
        if live {
            let due = self.last_write_ms.is_none_or(|t| now_ms.saturating_sub(t) >= REFRESH_EVERY_MS || now_ms < t);
            if !due {
                return Stamp::Idle;
            }
            match io.write(now_ms) {
                Ok(()) => {
                    self.last_write_ms = Some(now_ms);
                    self.stamped = true;
                    Stamp::Wrote
                }
                // Retried on the next tick; the old stamp (if any) goes stale on its own.
                Err(_) => Stamp::WriteFailed,
            }
        } else if self.stamped {
            match io.clear() {
                Ok(()) => {
                    self.stamped = false;
                    self.last_write_ms = None;
                    Stamp::Cleared
                }
                Err(_) => Stamp::ClearFailed,
            }
        } else {
            Stamp::Idle
        }
    }
}

/// Whether the stamp content (decimal unix milliseconds) is fresh at `now_ms`. Anything that is not a plain decimal
/// number is not fresh.
pub fn is_fresh(content: &[u8], now_ms: i64) -> bool {
    let Ok(text) = std::str::from_utf8(content) else { return false };
    let text = text.trim();
    if text.is_empty() || text.len() > 20 || !text.bytes().all(|c| c.is_ascii_digit()) {
        return false;
    }
    let Ok(ts) = text.parse::<i64>() else { return false };
    let age = now_ms.saturating_sub(ts);
    (-MAX_FUTURE_MS..FRESH_MS).contains(&age)
}

/// The production stamp file: this helper's own marker under the agent root, through the anchor. It only ever
/// writes and removes ITS OWN name.
pub struct AnchorStampIo {
    name: String,
}

impl AnchorStampIo {
    pub fn for_this_process() -> Self {
        Self { name: marker_name(std::process::id()) }
    }
}

impl StampIo for AnchorStampIo {
    fn write(&mut self, unix_ms: i64) -> io::Result<()> {
        crate::anchor::Anchor::open()?.dir().write_atomic(&self.name, unix_ms.to_string().as_bytes())
    }
    fn clear(&mut self) -> io::Result<()> {
        crate::anchor::Anchor::open()?.dir().remove(&self.name)
    }
}

/// Where the uploader reads the stamp from.
pub trait MarkerSource: Send + Sync {
    /// The contents of every per-helper stamp. A stamp that is unreadable or fails the owner/DACL check is skipped
    /// (it cannot have been written by a helper, and must not stall uploads); `Err` only when the root itself
    /// cannot be opened.
    fn read_all(&self) -> io::Result<Markers>;
}

/// What a look at the stamps found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Markers {
    /// The contents of every readable stamp that is not long dead.
    Stamps(Vec<Vec<u8>>),
    /// More stamps than [`MAX_MARKERS`]: not examined, and answered "live" by the probe.
    Overflow,
}

/// Examine ALL stamp files in `names` (only those named `session-live.*` count), pure over its two closures so it is
/// testable without a directory. The answer never depends on which stamps were listed first: nothing is dropped
/// before its freshness is looked at, and garbage collection of long-dead stamps (`remove`) happens only AFTER the
/// whole scan and can never change what this call returns.
pub fn collect_markers(
    names: Vec<String>,
    now_ms: i64,
    read: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    remove: &mut dyn FnMut(&str),
) -> Markers {
    collect_markers_from(names, now_ms, read, remove, &mut 0)
}

/// [`collect_markers`] with the overflow inspection window's start remembered across probes in `window_start`: each overflow probe
/// examines the NEXT [`MAX_MARKERS`] stamps (cyclically, in sorted order), so entries that can never be collected (fresh ones, ones
/// that cannot be read) cannot shadow the stale stamps sorted after them: every stamp is eventually examined. Every overflow probe still
/// answers "live" (`Overflow`) until the directory is back under the limit, i.e. until a complete scan can establish freshness.
pub fn collect_markers_from(
    names: Vec<String>,
    now_ms: i64,
    read: &mut dyn FnMut(&str) -> Option<Vec<u8>>,
    remove: &mut dyn FnMut(&str),
    window_start: &mut usize,
) -> Markers {
    let mut names: Vec<String> = names.into_iter().filter(|n| n.starts_with(MARKER_PREFIX)).collect();
    if names.len() > MAX_MARKERS {
        // Too many to establish freshness completely, so this probe still answers "live" (conservative). But the overflow must be
        // able to END: crashing helpers leave stamps behind, and if nothing ever removed them the probe would answer "live" forever.
        // So a bounded GC runs here too: at most MAX_MARKERS stamps are read per probe, from a window that ROTATES across probes (sorted
        // order, cyclic), and the long-dead ones are removed; later probes find the directory under the limit once the dead are gone.
        names.sort_unstable();
        let total = names.len();
        let start = *window_start % total;
        *window_start = (start + MAX_MARKERS) % total;
        names.rotate_left(start);
        names.truncate(MAX_MARKERS);
        for n in names {
            let Some(bytes) = read(&n) else { continue };
            let long_dead = std::str::from_utf8(&bytes)
                .ok()
                .and_then(|t| t.trim().parse::<i64>().ok())
                .is_some_and(|ts| now_ms.saturating_sub(ts) > GC_AFTER_MS);
            if long_dead {
                remove(&n);
            }
        }
        return Markers::Overflow;
    }
    let mut out = Vec::new();
    let mut dead = Vec::new();
    for n in &names {
        let Some(bytes) = read(n) else { continue };
        let long_dead = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|t| t.trim().parse::<i64>().ok())
            .is_some_and(|ts| now_ms.saturating_sub(ts) > GC_AFTER_MS);
        if long_dead {
            dead.push(n.clone());
        } else {
            out.push(bytes);
        }
    }
    for n in dead {
        remove(&n);
    }
    Markers::Stamps(out)
}

pub struct AnchorMarker;

/// Where the next overflow probe starts inspecting (process-wide, rotated by every overflow probe).
static OVERFLOW_WINDOW: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl MarkerSource for AnchorMarker {
    fn read_all(&self) -> io::Result<Markers> {
        let anchor = crate::anchor::Anchor::open()?;
        let dir = anchor.dir();
        let names = dir.list()?;
        let now = crate::recording::now_unix_ms();
        // `read` and `remove` both go through the anchor: validated reads, handle-relative deletes.
        let mut read = |n: &str| dir.read(n, 64).ok().flatten();
        let mut remove = |n: &str| {
            let _ = dir.remove(n);
        };
        let mut start = OVERFLOW_WINDOW.load(std::sync::atomic::Ordering::Relaxed);
        let m = collect_markers_from(names, now, &mut read, &mut remove, &mut start);
        OVERFLOW_WINDOW.store(start, std::sync::atomic::Ordering::Relaxed);
        Ok(m)
    }
}

/// Keeps the stamping task alive; dropping it stops the task (the stamp then goes stale by itself).
pub struct StamperGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for StamperGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// Spawn the helper-side stamping loop on the current tokio runtime. `is_live` is polled every few seconds; the
/// file work runs on a blocking thread. On `stop` the marker is removed.
pub fn spawn_stamper(is_live: impl Fn() -> bool + Send + 'static, stop: Arc<AtomicBool>) -> StamperGuard {
    let handle = tokio::spawn(async move {
        let mut stamper = LiveStamper::default();
        loop {
            let stopping = stop.load(Ordering::Relaxed);
            let live = !stopping && is_live();
            let now = crate::recording::now_unix_ms();
            let st = std::mem::take(&mut stamper);
            let (st, outcome) = tokio::task::spawn_blocking(move || {
                let mut st = st;
                let o = st.tick(now, live, &mut AnchorStampIo::for_this_process());
                (st, o)
            })
            .await
            .unwrap_or_else(|_| (LiveStamper::default(), Stamp::WriteFailed));
            stamper = st;
            if matches!(outcome, Stamp::WriteFailed | Stamp::ClearFailed) {
                tracing::warn!(?outcome, "session-live marker could not be updated");
            }
            if stopping {
                return;
            }
            tokio::time::sleep(POLL).await;
        }
    });
    StamperGuard { handle }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeFile {
        content: Option<i64>,
        fail_write: bool,
        fail_clear: bool,
        writes: u32,
    }
    impl StampIo for FakeFile {
        fn write(&mut self, ms: i64) -> io::Result<()> {
            if self.fail_write {
                return Err(io::Error::other("disk"));
            }
            self.content = Some(ms);
            self.writes += 1;
            Ok(())
        }
        fn clear(&mut self) -> io::Result<()> {
            if self.fail_clear {
                return Err(io::Error::other("busy"));
            }
            self.content = None;
            Ok(())
        }
    }

    #[test]
    fn a_live_session_is_stamped_at_once_and_refreshed_within_the_budget() {
        let (mut s, mut f) = (LiveStamper::default(), FakeFile::default());
        let t0 = 1_000_000i64;
        assert_eq!(s.tick(t0, true, &mut f), Stamp::Wrote);
        assert_eq!(f.content, Some(t0));
        // Ticks inside the refresh period do not rewrite.
        assert_eq!(s.tick(t0 + 10_000, true, &mut f), Stamp::Idle);
        assert_eq!(s.tick(t0 + REFRESH_EVERY_MS - 1, true, &mut f), Stamp::Idle);
        assert_eq!(f.writes, 1);
        // At the period it refreshes: simulate a 10-minute session polled every 10 s and bound the gaps.
        let mut last = t0;
        let mut max_gap = 0;
        for k in 1..=60 {
            let now = t0 + k * 10_000;
            if s.tick(now, true, &mut f) == Stamp::Wrote {
                max_gap = max_gap.max(now - last);
                last = now;
            }
        }
        assert!(max_gap <= 60_000, "never more than a minute between stamps: {max_gap}");
        assert!(max_gap >= REFRESH_EVERY_MS, "and not rewritten more often than needed");
        // The reader (fake clock = now) sees it fresh throughout.
        assert!(is_fresh(f.content.unwrap().to_string().as_bytes(), last + 10_000));
    }

    #[test]
    fn the_marker_is_removed_when_the_last_session_ends_and_not_before() {
        let (mut s, mut f) = (LiveStamper::default(), FakeFile::default());
        s.tick(1000, true, &mut f);
        assert_eq!(s.tick(2000, true, &mut f), Stamp::Idle);
        assert!(f.content.is_some(), "still live: still stamped");
        assert_eq!(s.tick(3000, false, &mut f), Stamp::Cleared);
        assert_eq!(f.content, None);
        assert_eq!(s.tick(4000, false, &mut f), Stamp::Idle, "nothing to clear");
        // A new session stamps again immediately.
        assert_eq!(s.tick(5000, true, &mut f), Stamp::Wrote);
    }

    #[test]
    fn failed_writes_and_clears_are_retried_on_the_next_tick() {
        let (mut s, mut f) = (LiveStamper::default(), FakeFile { fail_write: true, ..Default::default() });
        assert_eq!(s.tick(1000, true, &mut f), Stamp::WriteFailed);
        f.fail_write = false;
        assert_eq!(s.tick(1500, true, &mut f), Stamp::Wrote, "retried at once, not after a full period");
        f.fail_clear = true;
        assert_eq!(s.tick(2000, false, &mut f), Stamp::ClearFailed);
        assert!(f.content.is_some());
        f.fail_clear = false;
        assert_eq!(s.tick(2500, false, &mut f), Stamp::Cleared);
    }

    #[test]
    fn a_clock_that_steps_backwards_does_not_starve_the_stamp() {
        let (mut s, mut f) = (LiveStamper::default(), FakeFile::default());
        s.tick(10_000_000, true, &mut f);
        assert_eq!(s.tick(9_000_000, true, &mut f), Stamp::Wrote);
    }

    fn run(names: Vec<(String, i64)>, now: i64) -> (Markers, Vec<String>) {
        let table: std::collections::HashMap<String, i64> = names.iter().cloned().collect();
        let all: Vec<String> = names.into_iter().map(|(n, _)| n).collect();
        let mut removed = Vec::new();
        let m = collect_markers(all, now, &mut |n| table.get(n).map(|t| t.to_string().into_bytes()), &mut |n| removed.push(n.to_string()));
        (m, removed)
    }

    fn any_fresh(m: &Markers, now: i64) -> bool {
        match m {
            Markers::Overflow => true,
            Markers::Stamps(v) => v.iter().any(|b| is_fresh(b, now)),
        }
    }

    #[test]
    fn many_recent_crashed_helper_markers_cannot_hide_a_live_one_listed_last() {
        let now = 50_000_000i64;
        // 200 markers from helpers that died 10 minutes ago: not fresh, and not yet old enough to be garbage collected.
        let mut names: Vec<(String, i64)> = (1..=200u32).map(|i| (marker_name(i), now - 10 * 60_000)).collect();
        // The live helper's marker sorts/lists LAST.
        names.push((marker_name(999_999), now - 5_000));
        let (m, removed) = run(names, now);
        assert!(any_fresh(&m, now), "the live marker was examined, not cut off by an early limit");
        assert!(removed.is_empty(), "10-minute-old markers are not garbage yet");
        // The same with the live one FIRST: order never matters.
        let mut names: Vec<(String, i64)> = vec![(marker_name(1), now - 1_000)];
        names.extend((2..=200u32).map(|i| (marker_name(i), now - 10 * 60_000)));
        assert!(any_fresh(&run(names, now).0, now));
    }

    #[test]
    fn more_markers_than_the_limit_is_answered_live_never_no_session() {
        let now = 50_000_000i64;
        let names: Vec<(String, i64)> = (0..(MAX_MARKERS as u32 + 1)).map(|i| (marker_name(i), now - 3 * 3_600_000)).collect();
        let (m, removed) = run(names, now);
        assert_eq!(m, Markers::Overflow, "not examined, so it must not read as quiet");
        assert!(any_fresh(&m, now));
        assert!(!removed.is_empty(), "an overflowing look still garbage-collects (bounded), so the overflow can end");
        assert!(removed.len() <= MAX_MARKERS, "and the work it does is bounded");
        // Exactly at the limit is still examined.
        let names: Vec<(String, i64)> = (0..MAX_MARKERS as u32).map(|i| (marker_name(i), now - 10 * 60_000)).collect();
        assert!(matches!(run(names, now).0, Markers::Stamps(_)));
    }

    #[test]
    fn an_overflow_of_dead_stamps_recovers_across_probes_and_never_hides_a_live_one() {
        let now = 50_000_000i64;
        // Far more than the limit, all long dead, plus one live helper.
        let total = MAX_MARKERS as u32 * 2 + 300;
        let mut table: std::collections::BTreeMap<String, i64> = (0..total).map(|i| (marker_name(i), now - 3 * 3_600_000)).collect();
        table.insert(marker_name(total + 5), now - 2_000);
        let mut probes = 0;
        let last = loop {
            let names: Vec<String> = table.keys().cloned().collect();
            let mut removed = Vec::new();
            let m = collect_markers(names, now, &mut |n| table.get(n).map(|t| t.to_string().into_bytes()), &mut |n| removed.push(n.to_string()));
            assert!(any_fresh(&m, now), "every probe answers live: Overflow, or the live stamp itself");
            for n in removed {
                table.remove(&n);
            }
            probes += 1;
            if matches!(m, Markers::Stamps(_)) {
                break m;
            }
            assert!(probes < 10, "the overflow never ended");
        };
        match last {
            Markers::Stamps(v) => assert_eq!(v.len(), 1, "only the live stamp is left"),
            Markers::Overflow => unreachable!(),
        }
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn uncollectible_stamps_sorting_first_cannot_starve_the_stale_ones_behind_them() {
        let now = 50_000_000i64;
        // 1024 stamps that can never be collected (10 minutes old: not fresh, not yet garbage) sort FIRST; 1500 long-dead ones follow.
        let mut table: std::collections::BTreeMap<String, i64> = (0..MAX_MARKERS as u32).map(|i| (marker_name(i), now - 10 * 60_000)).collect();
        for i in 0..1500u32 {
            table.insert(marker_name(100_000 + i), now - 3 * 3_600_000);
        }
        let mut start = 0usize;
        let mut probes = 0;
        loop {
            let names: Vec<String> = table.keys().cloned().collect();
            let mut removed = Vec::new();
            let m = collect_markers_from(names, now, &mut |n| table.get(n).map(|t| t.to_string().into_bytes()), &mut |n| removed.push(n.to_string()), &mut start);
            if matches!(m, Markers::Stamps(_)) {
                break;
            }
            assert!(any_fresh(&m, now), "every overflow probe answers live");
            for n in removed {
                table.remove(&n);
            }
            probes += 1;
            assert!(probes <= 8, "the stale stamps behind the uncollectible prefix were never reached");
        }
        assert_eq!(table.len(), MAX_MARKERS, "exactly the uncollectible ones are left, so the directory is under the limit again");
        // The window really rotates: the first probe over the same set starts where the last one ended.
        let mut s = 0usize;
        let names: Vec<String> = (0..MAX_MARKERS as u32 + 500).map(marker_name).collect();
        let _ = collect_markers_from(names, now, &mut |_| None, &mut |_| {}, &mut s);
        assert_eq!(s, MAX_MARKERS % (MAX_MARKERS + 500));
    }

    #[test]
    fn garbage_collection_runs_after_the_scan_and_never_changes_the_answer() {
        let now = 50_000_000i64;
        let names = vec![
            (marker_name(1), now - 2 * 3_600_000), // dead for good
            (marker_name(2), now - 4_000),         // live
            (marker_name(3), now - 3 * 3_600_000), // dead for good
            ("unrelated.file".to_string(), now),   // not a marker
        ];
        let (m, removed) = run(names, now);
        let mut removed = removed;
        removed.sort();
        assert_eq!(removed, [marker_name(1), marker_name(3)], "only long-dead markers are removed");
        assert!(any_fresh(&m, now), "and the live one is still seen");
        match m {
            Markers::Stamps(v) => assert_eq!(v.len(), 1, "removed ones are not in the answer"),
            Markers::Overflow => panic!("overflow"),
        }
        // Nothing but dead markers: GC removes them and the answer is quiet (a COMPLETE scan said so).
        let (m, _) = run(vec![(marker_name(1), now - 2 * 3_600_000)], now);
        assert!(!any_fresh(&m, now));
    }

    #[test]
    fn freshness_is_two_minutes_and_only_plain_decimal_is_believed() {
        let now = 5_000_000i64;
        let f = |ts: i64| is_fresh(ts.to_string().as_bytes(), now);
        assert!(f(now) && f(now - 1) && f(now - FRESH_MS + 1));
        assert!(!f(now - FRESH_MS), "stale at exactly two minutes");
        assert!(!f(now - FRESH_MS - 1));
        assert!(f(now + MAX_FUTURE_MS) && !f(now + MAX_FUTURE_MS + 1), "a stamp from the far future is not believed");
        for junk in [&b""[..], b"abc", b"-5", b"12 34", b"1e9", b"\xff\xfe", b"999999999999999999999999"] {
            assert!(!is_fresh(junk, now), "{junk:?}");
        }
        assert!(is_fresh(format!("{now}\n").as_bytes(), now), "a trailing newline is tolerated");
    }
}
