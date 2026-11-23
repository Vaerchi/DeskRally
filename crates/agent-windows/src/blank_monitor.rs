//! Blank the guest's monitors during a session (docs/01 P1 "Blank guest monitor / privacy mode")
//! — a privacy control so a bystander at the machine cannot see what the technician is doing.
//!
//! ## Mechanism
//!
//! A solid black [`WS_POPUP`] + [`WS_EX_TOPMOST`] window is positioned at the virtual desktop
//! origin and sized to cover ALL monitors (`SM_XVIRTUALSCREEN`, `SM_YVIRTUALSCREEN`,
//! `SM_CXVIRTUALSCREEN`, `SM_CYVIRTUALSCREEN`). It carries no title bar, no taskbar entry, and
//! no Alt+Tab presence. `WS_EX_NOACTIVATE` prevents it from pulling focus away from the agent's
//! own session threads when the overlay appears.
//!
//! A bystander at the guest machine sees only a black screen. `Ctrl+Alt+Del` always remains
//! reachable because the kernel routes it to the Winlogon secure desktop before any window sees it.
//!
//! ## What the TECHNICIAN sees (fixed 2026-10-23)
//!
//! The overlay is for the bystander only. Until 2026-10-23 it was also captured: desktop duplication
//! composes every visible window, so the technician's stream went BLACK the moment they blanked (VM-
//! measured: mean brightness 148 -> 0.0 of 255), and the overlay swallowed their clicks too. Privacy
//! mode made the technician blind. Now:
//! - `WDA_EXCLUDEFROMCAPTURE` keeps the overlay out of every capture path (DXGI duplication, WGC,
//!   GDI), so the technician keeps seeing the real desktop;
//! - `WS_EX_LAYERED | WS_EX_TRANSPARENT` (fully opaque, `LWA_ALPHA` 255) makes it click-through, so
//!   the technician's injected input reaches the applications beneath. A bystander's clicks pass
//!   through too: stopping the guest's own input is a separate control, "Block guest input"
//!   ([`crate::input_block`]).
//!
//! Complementary to [`crate::input_block`] — either can be used independently.
//!
//! ## Lifecycle & safety
//!
//! * The window lives on a **dedicated OS thread with its own `GetMessageW` pump**.
//! * Turning the blank on spawns the thread and creates the window; turning it off posts
//!   the private `WM_BLANK_CLOSE` message (a `WM_APP`-range message) to the window HWND.
//! * `Drop` posts `WM_BLANK_CLOSE` unconditionally, so a dropped [`ScreenBlanker`] can never
//!   leave the guest's screen dark after the session ends.
//! * The wndproc intercepts `WM_CLOSE` and ignores it (returns 0 without forwarding to
//!   `DefWindowProcW`), so the guest pressing **Alt+F4** cannot dismiss the overlay.
//! * `WM_BLANK_CLOSE` → `DestroyWindow` → `WM_DESTROY` → `PostQuitMessage(0)` →
//!   `GetMessageW` returns 0 → thread exits cleanly. The HWND is valid from `CreateWindowExW`
//!   until `DestroyWindow`, so `PostMessageW` is safe from a different thread as soon as the
//!   spawner receives the non-zero HWND.
//! * An agent crash drops the process; Windows destroys all windows, so a crash cannot
//!   permanently blank the guest's screen.
//! * The WGC constraint (WGC permanently poisons `SetThreadDesktop` on its calling thread) does
//!   NOT apply here: this thread never touches WGC or DXGI.

#![cfg(windows)]

use std::{mem, sync::mpsc, thread};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        Graphics::Gdi::{GetStockObject, HBRUSH, BLACK_BRUSH},
        System::LibraryLoader::GetModuleHandleW,
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
            GetSystemMetrics, PostMessageW, PostQuitMessage, RegisterClassExW, HMENU, MSG,
            WNDCLASSEXW, WM_CLOSE, WM_DESTROY, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
            WS_EX_LAYERED, WS_EX_TRANSPARENT, SetLayeredWindowAttributes, LWA_ALPHA,
            SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, SetWindowPos, HWND_TOPMOST, SWP_NOACTIVATE,
            WM_DISPLAYCHANGE, GetWindowRect,
            WS_POPUP, WS_VISIBLE, WINDOW_EX_STYLE, WINDOW_STYLE, SM_CXVIRTUALSCREEN,
            SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
        },
    },
};

/// Set by the overlay's window procedure when a display change could not be re-covered (the resize
/// failed, or the overlay no longer spans the virtual screen). The overlay no longer guarantees
/// privacy, so [`ScreenBlanker::take_coverage_lost`] turns blanking off and the session tells the
/// technician (Codex 1.3.8 round 2: "blanked" must never be reported over an uncovered screen).
static COVERAGE_LOST: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Whether `rect` (left, top, right, bottom) covers the whole virtual screen `(x, y, w, h)`.
pub(crate) fn covers(rect: (i32, i32, i32, i32), screen: (i32, i32, i32, i32)) -> bool {
    let (x, y, w, h) = screen;
    rect.0 <= x && rect.1 <= y && rect.2 >= x + w && rect.3 >= y + h
}

/// The overlay's extended styles: topmost, no taskbar/Alt+Tab presence, never activated, and
/// click-through (layered + transparent) so the technician's input reaches the desktop beneath.
pub(crate) fn overlay_ex_style() -> u32 {
    WS_EX_TOPMOST.0 | WS_EX_TOOLWINDOW.0 | WS_EX_NOACTIVATE.0 | WS_EX_LAYERED.0 | WS_EX_TRANSPARENT.0
}

/// The bounding rectangle of ALL monitors (x, y, w, h); x/y are negative when a monitor sits left of or
/// above the primary. Read again on every display change.
fn virtual_screen() -> (i32, i32, i32, i32) {
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

/// Private shutdown message for the overlay window. Posted by [`ScreenBlanker::stop`] instead of
/// `WM_CLOSE` so the guest cannot dismiss the overlay by pressing Alt+F4 (which synthesises a
/// `WM_CLOSE` that `DefWindowProcW` would forward to `DestroyWindow`).
const WM_BLANK_CLOSE: u32 = 0x8000 + 1; // WM_APP + 1

/// Window class name for the blank-screen overlay window.
const CLASS_NAME: PCWSTR = windows::core::w!("DeskRallyBlank");

/// A running blank: the raw HWND inner value (for safe cross-thread `PostMessageW`) and the
/// thread's join handle.
struct Active {
    /// Raw HWND inner pointer stored as `usize` so `Active` is `Send`. Reconstructed as
    /// `HWND(hwnd_raw as *mut _)` only on the spawning thread in `Drop`.
    hwnd_raw: usize,
    thread: thread::JoinHandle<()>,
}

/// Owns the monitor blank for a session. Toggle with [`ScreenBlanker::set_blanked`]; the blank is
/// removed on `Drop`, so teardown never depends on an explicit call arriving.
pub struct ScreenBlanker {
    /// `false` = **mock** mode: track the requested state and answer honestly, but create NO real
    /// OS window. Lets the e2e and the local gate exercise the full control round-trip without
    /// blacking out the build machine's screen. `true` = production: real Win32 window.
    real: bool,
    /// Real mode: `Some` while the overlay window is showing.
    active: Option<Active>,
    /// Mock mode: the tracked blank state (no window behind it).
    mock_blanked: bool,
}

impl ScreenBlanker {
    /// A blanker with no blank in force. `real == false` makes every `set_blanked` a no-op that
    /// still reports the requested state (test/mock mode); `true` creates a real overlay window.
    pub fn new(real: bool) -> Self {
        Self { real, active: None, mock_blanked: false }
    }

    /// If the overlay lost coverage on a display change, turn blanking off (the overlay no longer
    /// guarantees privacy) and return `true` once, so the session can report it.
    pub fn take_coverage_lost(&mut self) -> bool {
        if !self.real || self.active.is_none() || !COVERAGE_LOST.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return false;
        }
        self.stop();
        true
    }

    /// Whether the monitors are blanked right now.
    pub fn is_blanked(&self) -> bool {
        if self.real {
            self.active.is_some()
        } else {
            self.mock_blanked
        }
    }

    /// Request `blanked`; returns the state **actually in force** afterwards (which differs from
    /// the request only if window creation failed — e.g. no interactive desktop). Idempotent.
    pub fn set_blanked(&mut self, blanked: bool) -> bool {
        if !self.real {
            self.mock_blanked = blanked;
            return self.mock_blanked;
        }
        if blanked == self.active.is_some() {
            return self.is_blanked();
        }
        if blanked {
            self.start();
        } else {
            self.stop();
        }
        self.is_blanked()
    }

    fn start(&mut self) {
        COVERAGE_LOST.store(false, std::sync::atomic::Ordering::SeqCst);
        let (tx, rx) = mpsc::channel::<usize>();
        let thread = match thread::Builder::new()
            .name("rmt-blank-monitor".into())
            .spawn(move || blank_thread(tx))
        {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "blank-monitor: could not spawn window thread; screen NOT blanked");
                return;
            }
        };
        match rx.recv() {
            Ok(hwnd_raw) if hwnd_raw != 0 => {
                self.active = Some(Active { hwnd_raw, thread });
            }
            _ => {
                let _ = thread.join();
                tracing::warn!("blank-monitor: window creation failed; screen NOT blanked");
            }
        }
    }

    fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            // Post the private shutdown message. WM_CLOSE is intentionally NOT used: the wndproc
            // intercepts WM_CLOSE and returns 0 so Alt+F4 cannot dismiss the overlay. Only
            // WM_BLANK_CLOSE triggers DestroyWindow → WM_DESTROY → PostQuitMessage(0) → thread
            // exit.
            // SAFETY: `hwnd_raw` is the HWND from `CreateWindowExW`, valid until `DestroyWindow`
            // is called. We have not closed it yet, so PostMessageW is safe.
            unsafe {
                let _ = PostMessageW(
                    HWND(active.hwnd_raw as *mut std::ffi::c_void),
                    WM_BLANK_CLOSE,
                    WPARAM(0),
                    LPARAM(0),
                );
            }
            let _ = active.thread.join();
        }
    }
}

impl Drop for ScreenBlanker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Default for ScreenBlanker {
    /// Production default: a real blanker (creates a Win32 overlay window when armed).
    fn default() -> Self {
        Self::new(true)
    }
}

/// The window thread: create the full-virtual-desktop black overlay, report the HWND, pump
/// messages until `WM_CLOSE`.
fn blank_thread(hwnd_tx: mpsc::Sender<usize>) {
    // SAFETY: all Win32 calls are on this dedicated OS thread. No cross-thread handle
    // sharing occurs; HWND is used only within this function (the raw usize sent to the
    // spawner is used only for `PostMessageW`, which is safe cross-thread).
    unsafe {
        let Ok(hmodule) = GetModuleHandleW(None) else {
            let _ = hwnd_tx.send(0);
            return;
        };
        let hinstance = HINSTANCE(hmodule.0);

        // Register a minimal window class with a solid black background brush.
        // Ignore the return value: if the class is already registered (e.g. a prior blank in
        // the same session) `CreateWindowExW` still succeeds using the existing registration.
        let wc = WNDCLASSEXW {
            cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: CLASS_NAME,
            // BLACK_BRUSH makes Windows paint the window black without a WM_PAINT handler.
            hbrBackground: HBRUSH(GetStockObject(BLACK_BRUSH).0),
            ..Default::default()
        };
        let _ = RegisterClassExW(&wc);

        // Virtual desktop bounds — the bounding rect of ALL monitors, including secondary
        // and indirect-display monitors. Negative coordinates occur when any monitor is
        // positioned to the left or above the primary monitor's origin.
        let (x, y, w, h) = virtual_screen();

        // WS_POPUP: borderless, no title bar, no system menu.
        // WS_VISIBLE: show immediately on creation.
        // WS_EX_TOPMOST: always above all non-topmost windows.
        // WS_EX_TOOLWINDOW: suppresses the Alt+Tab switcher entry and taskbar button, so the
        //   guest cannot cycle the overlay out of topmost z-order via the task switcher.
        // WS_EX_NOACTIVATE: do not steal focus from the agent's session threads or the guest's
        //   foreground app — the overlay is a visual barrier, not an interactive window.
        // WS_EX_LAYERED | WS_EX_TRANSPARENT: click-through, so the technician's input reaches the
        //   desktop beneath (see "What the TECHNICIAN sees" above).
        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE(overlay_ex_style()),
            CLASS_NAME,
            windows::core::w!(""),
            WINDOW_STYLE(WS_POPUP.0 | WS_VISIBLE.0),
            x,
            y,
            w,
            h,
            None,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "blank-monitor: CreateWindowExW failed");
                let _ = hwnd_tx.send(0);
                return;
            }
        };

        // Fully opaque for the bystander. A layered window shows NOTHING until its attributes are set,
        // so a failure here is a blanking FAILURE, not a warning: carrying on would leave an invisible
        // overlay while the agent reports "blanked" and the technician believes the screen is private
        // (Codex 1.3.8 review [high]). Destroy it and report that blanking did not happen.
        if let Err(e) = SetLayeredWindowAttributes(hwnd, windows::Win32::Foundation::COLORREF(0), 255, LWA_ALPHA) {
            tracing::warn!(error = %e, "blank-monitor: could not make the overlay opaque; blanking FAILED");
            let _ = DestroyWindow(hwnd);
            let _ = hwnd_tx.send(0);
            return;
        }
        // Out of the technician's capture: without this the stream goes black while blanked.
        if let Err(e) = SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) {
            tracing::warn!(error = %e, "blank-monitor: capture exclusion unavailable; the technician will see black");
        }

        // Send the HWND back NOW — the window exists, so PostMessageW to it is safe from
        // this point forward, even before GetMessageW is called.
        let _ = hwnd_tx.send(hwnd.0 as usize);
        tracing::info!("blank-monitor: overlay active ({x},{y}) {w}×{h}");

        let mut msg = MSG::default();
        // `.0 > 0` distinguishes a normal quit (0) from a GetMessageW error (-1). Same
        // convention as tray.rs, input_block.rs, and guest_window.rs.
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let _ = DispatchMessageW(&msg);
        }
        // The window is already destroyed (WM_BLANK_CLOSE → wndproc DestroyWindow →
        // WM_DESTROY → PostQuitMessage → GetMessageW returns 0). Nothing to close.
        tracing::info!("blank-monitor: overlay removed");
    }
}

/// Window procedure for the blank overlay.
///
/// * `WM_BLANK_CLOSE` — operator-initiated shutdown: call `DestroyWindow`.
/// * `WM_CLOSE` — guest-initiated (Alt+F4 or any external `WM_CLOSE`): silently ignored.
///   `DefWindowProcW` would forward `WM_CLOSE` to `DestroyWindow`, which would destroy the
///   overlay without the agent knowing. By returning 0 here we preserve the privacy guarantee.
/// * `WM_DESTROY` — window is being destroyed: post `WM_QUIT` to end the message loop.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_DESTROY {
        PostQuitMessage(0);
        return LRESULT(0);
    }
    if msg == WM_BLANK_CLOSE {
        let _ = DestroyWindow(hwnd);
        return LRESULT(0);
    }
    if msg == WM_CLOSE {
        // Ignore: the guest pressed Alt+F4. Only WM_BLANK_CLOSE (from ScreenBlanker::stop)
        // is allowed to tear down the overlay.
        return LRESULT(0);
    }
    if msg == WM_DISPLAYCHANGE {
        // A monitor was added, removed or moved while blanked: re-cover the WHOLE virtual desktop, or the
        // new area shows the desktop while the agent still reports "blanked" (Codex 1.3.8 review).
        let screen = virtual_screen();
        let (x, y, w, h) = screen;
        let moved = SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE).is_ok();
        let mut r = windows::Win32::Foundation::RECT::default();
        let covered = moved && GetWindowRect(hwnd, &mut r).is_ok() && covers((r.left, r.top, r.right, r.bottom), screen);
        if covered {
            tracing::info!("blank-monitor: display change; overlay now covers ({x},{y}) {w}x{h}");
        } else {
            tracing::error!(moved, "blank-monitor: display change could NOT be re-covered; privacy mode will be turned off");
            COVERAGE_LOST.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        return LRESULT(0);
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

#[cfg(test)]
mod coverage_tests {
    use super::covers;

    #[test]
    fn coverage_needs_every_edge_including_negative_origins() {
        let screen = (-1920, 0, 3840, 1080); // a monitor LEFT of the primary
        assert!(covers((-1920, 0, 1920, 1080), screen));
        assert!(!covers((0, 0, 1920, 1080), screen), "the old primary-only rect leaves the left monitor bare");
        assert!(!covers((-1920, 0, 1920, 1000), screen), "short by 80 px at the bottom");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2026-10-23: the overlay must be click-through so the technician's input reaches the desktop
    /// (it used to swallow it). A real overlay cannot be created in a unit test without blacking out
    /// the machine running it, so the behaviour was VM-measured instead (blank-20261023: technician's
    /// stream 148/255 while the real display is 0.0, and a Start click through the overlay opens the
    /// Start menu); this pins the styles that make it so.
    #[test]
    fn the_overlay_is_topmost_inert_and_click_through() {
        let ex = overlay_ex_style();
        for (bit, what) in [
            (WS_EX_TOPMOST.0, "topmost"),
            (WS_EX_TOOLWINDOW.0, "no taskbar / Alt+Tab entry"),
            (WS_EX_NOACTIVATE.0, "never takes focus"),
            (WS_EX_LAYERED.0, "layered (required for click-through and opacity)"),
            (WS_EX_TRANSPARENT.0, "click-through: the technician's input reaches the desktop"),
        ] {
            assert_ne!(ex & bit, 0, "overlay must be {what}");
        }
    }

    #[test]
    fn a_fresh_blanker_is_not_blanking() {
        // Construction alone creates no window — no Win32 touched until set_blanked(true).
        assert!(!ScreenBlanker::new(true).is_blanked());
        assert!(!ScreenBlanker::new(false).is_blanked());
        assert!(!ScreenBlanker::default().is_blanked());
    }

    #[test]
    fn mock_mode_tracks_state_without_touching_win32() {
        // The `--log-input` test path and the local gate run in mock mode so they never black
        // out the build machine's screen. The mock must still report state honestly so the
        // control round-trip (SetMonitorBlanked → MonitorBlankedApplied) is exercised end to end.
        let mut b = ScreenBlanker::new(false);
        assert!(!b.is_blanked());
        assert!(b.set_blanked(true)); // reflects the request; creates nothing
        assert!(b.is_blanked());
        assert!(!b.set_blanked(false));
        assert!(!b.is_blanked());
    }

    #[test]
    fn mock_mode_idempotent_on_duplicate_requests() {
        let mut b = ScreenBlanker::new(false);
        assert!(b.set_blanked(true));
        assert!(b.set_blanked(true)); // second true is a no-op
        assert!(!b.set_blanked(false));
        assert!(!b.set_blanked(false)); // second false is a no-op
    }
}
