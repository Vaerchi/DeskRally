//! Win32 text-clipboard implementation of the portable [`Clipboard`] seam (M9).
//!
//! [`WinClipboard`] reads/writes `CF_UNICODETEXT` on the process's clipboard via the classic
//! `OpenClipboard`/`GetClipboardData`/`SetClipboardData` API, and reports change via
//! `GetClipboardSequenceNumber`.
//!
//! ## Threading / desktop scope
//!
//! Unlike input injection (M7), the Windows clipboard is **window-station-scoped** (WinSta0), **not**
//! desktop-scoped: any thread in the process (which lives in WinSta0) may `OpenClipboard`. So the
//! agent runs its clipboard worker on an *ordinary* worker thread — there is deliberately **no**
//! `SetThreadDesktop` and no marshaling onto the desktop-bound capture thread here. `WinClipboard`
//! holds no OS handles and is cheap to construct; every call opens + closes the clipboard.
//!
//! ## Transient contention
//!
//! Only one process may hold the clipboard open at a time, so `OpenClipboard` can transiently fail
//! when another app (Explorer, the browser, a clipboard-history tool) is mid-operation.
//! [`WinClipboard`] retries a few times with a short sleep before giving up — a set/get is not worth
//! failing over a millisecond of contention.

use std::time::Duration;

use rmt_agent_core::clipboard::Clipboard;

use windows::Win32::Foundation::{HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE};

/// Standard clipboard format id for null-terminated UTF-16 text (`CF_UNICODETEXT` from winuser.h).
/// Defined locally to avoid pulling an extra `windows` feature module just for one constant.
const CF_UNICODETEXT: u32 = 13;

/// How many times to retry `OpenClipboard` before giving up, and the pause between attempts. Another
/// app holding the clipboard open is normally released within a few milliseconds.
const OPEN_RETRIES: u32 = 12;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(8);

/// A [`Clipboard`] backed by the Win32 `CF_UNICODETEXT` clipboard on the process's window station.
///
/// Stateless (holds no handles); construct with [`WinClipboard::new`].
#[derive(Debug, Default, Clone)]
pub struct WinClipboard {
    _private: (),
}

impl WinClipboard {
    /// Create a new clipboard accessor. The hosting process must already belong to an interactive
    /// window station (WinSta0), which the SYSTEM helper does.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Open the clipboard, retrying briefly through transient contention. On success the caller **must**
/// pair it with a `CloseClipboard`.
///
/// SAFETY of the whole module: every call sequence opens the clipboard, operates, and closes it on
/// every path (including early error returns), never holding it across an `await` or a sleep.
fn open_clipboard() -> Result<(), String> {
    for attempt in 0..OPEN_RETRIES {
        // SAFETY: passing a null owner window is valid; associates the open clipboard with the
        // current task. Returns Err (not a panic) on failure.
        if unsafe { OpenClipboard(HWND::default()) }.is_ok() {
            return Ok(());
        }
        if attempt + 1 < OPEN_RETRIES {
            std::thread::sleep(OPEN_RETRY_DELAY);
        }
    }
    Err("OpenClipboard failed after retries (another app held the clipboard)".to_string())
}

impl Clipboard for WinClipboard {
    fn get_text(&self) -> Option<String> {
        open_clipboard().ok()?;
        // Read inside a closure so we always CloseClipboard afterwards, even on an early `None`.
        let out = (|| unsafe {
            // SAFETY: CF_UNICODETEXT is a valid format id. On success the returned HANDLE is owned by
            // the clipboard (we must NOT free it); we only read through it while the clipboard is open.
            let handle = GetClipboardData(CF_UNICODETEXT).ok()?;
            let hmem = HGLOBAL(handle.0);
            let ptr = GlobalLock(hmem) as *const u16;
            if ptr.is_null() {
                return None;
            }
            // The buffer SHOULD be a NUL-terminated UTF-16 string, but any process in the session can
            // put an unterminated allocation on the clipboard, and this runs in the SYSTEM helper: an
            // unbounded scan for the NUL read past the block — a crash, or adjacent heap bytes sent to
            // the technician as clipboard text (security audit 2026-10-18). So the scan is bounded by
            // the allocation's own size, and unterminated text is refused.
            let units = GlobalSize(hmem) / 2;
            let text = if units == 0 {
                None
            } else {
                utf16_until_nul(std::slice::from_raw_parts(ptr, units)).map(String::from_utf16_lossy)
            };
            // GlobalUnlock returns Err when the lock count reaches zero (the normal case), so ignore it.
            let _ = GlobalUnlock(hmem);
            text
        })();
        // SAFETY: we opened the clipboard above; close it exactly once.
        unsafe {
            let _ = CloseClipboard();
        }
        out
    }

    fn set_text(&self, text: &str) -> Result<(), String> {
        // Null-terminated UTF-16, as CF_UNICODETEXT requires.
        let utf16: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let byte_len = utf16.len() * std::mem::size_of::<u16>();

        open_clipboard()?;
        let result = (|| unsafe {
            // SAFETY: EmptyClipboard clears + takes ownership; required before SetClipboardData.
            EmptyClipboard().map_err(|e| format!("EmptyClipboard failed: {e}"))?;
            // GMEM_MOVEABLE is mandatory for clipboard data: the system takes ownership of the block.
            let hmem =
                GlobalAlloc(GMEM_MOVEABLE, byte_len).map_err(|e| format!("GlobalAlloc failed: {e}"))?;
            let ptr = GlobalLock(hmem) as *mut u16;
            if ptr.is_null() {
                return Err("GlobalLock returned null".to_string());
            }
            // SAFETY: `hmem` is at least `byte_len` bytes; `utf16` has exactly `utf16.len()` u16s.
            std::ptr::copy_nonoverlapping(utf16.as_ptr(), ptr, utf16.len());
            let _ = GlobalUnlock(hmem);
            // On success the system takes ownership of `hmem`; we must NOT free it. On failure we
            // would leak `hmem`, which is acceptable for this rare path (and the process is transient).
            SetClipboardData(CF_UNICODETEXT, HANDLE(hmem.0))
                .map_err(|e| format!("SetClipboardData failed: {e}"))?;
            Ok(())
        })();
        // SAFETY: we opened the clipboard above; close it exactly once regardless of outcome.
        unsafe {
            let _ = CloseClipboard();
        }
        result
    }

    fn sequence(&self) -> u64 {
        // SAFETY: no arguments, no pointers; returns 0 if the caller lacks clipboard access.
        unsafe { GetClipboardSequenceNumber() as u64 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test that round-trips real text through the live clipboard on this dev box. `#[ignore]`
    /// because it mutates the machine's actual clipboard and needs an interactive window station —
    /// run it explicitly:
    ///
    /// ```text
    /// cargo test -p rmt-agent-windows --lib -- --ignored
    /// ```
    #[test]
    #[ignore = "touches the real machine clipboard; run with --ignored on an interactive session"]
    fn round_trips_real_clipboard() {
        let clip = WinClipboard::new();
        let sample = "rmt clipboard smoke — 🦀 café 日本語";
        clip.set_text(sample).expect("set_text");
        let seq_after_set = clip.sequence();
        let got = clip.get_text().expect("get_text after set");
        assert_eq!(got, sample, "round-tripped clipboard text");
        // Setting the clipboard must have advanced the sequence number away from 0/unknown.
        assert_ne!(seq_after_set, 0, "sequence should be reported after a set");
        eprintln!("CLIPBOARD SMOKE: set+get ok, seq={seq_after_set}");
    }
}

/// The text before the first NUL in `units`, or `None` when there is no NUL — an unterminated
/// CF_UNICODETEXT block is malformed and is refused rather than read to the allocation's end.
fn utf16_until_nul(units: &[u16]) -> Option<&[u16]> {
    units.iter().position(|&u| u == 0).map(|n| &units[..n])
}

#[cfg(test)]
mod bounded_read_tests {
    use super::utf16_until_nul;

    #[test]
    fn stops_at_the_first_nul_and_refuses_an_unterminated_block() {
        let terminated: Vec<u16> = "hi\0junk".encode_utf16().collect();
        assert_eq!(utf16_until_nul(&terminated), Some(&terminated[..2]));
        assert_eq!(utf16_until_nul(&[0u16]), Some(&[][..]));
        let unterminated: Vec<u16> = "no terminator".encode_utf16().collect();
        assert_eq!(utf16_until_nul(&unterminated), None);
        assert_eq!(utf16_until_nul(&[]), None);
    }
}
