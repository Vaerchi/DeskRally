//! Block the guest's own physical keyboard & mouse during a session (docs/01 P1 "block guest
//! keyboard/mouse input") — a privacy/safety control so a bystander at the machine cannot interfere
//! while the technician works, without also blocking the technician.
//!
//! ## Mechanism — one invariant, reused
//!
//! This is the [`crate::input`] injection tag ([`crate::input::RMT_INJECTED_TAG`]) turned into a
//! system-wide filter. Two low-level hooks — `WH_KEYBOARD_LL` and `WH_MOUSE_LL` — sit ahead of every
//! window's input and **swallow any event whose `dwExtraInfo` is not our tag**, i.e. the guest's real
//! keystrokes and clicks. The technician's injected input carries `RMT_INJECTED_TAG` (stamped by
//! [`crate::input`]) and passes straight through, so the remote keeps full control while the guest is
//! frozen. It is the exact complement of the guest-window pump filter, which drops *injected* input to
//! the guest's own affordances ([`crate::guest_window`]); here we drop *non-injected* input everywhere.
//!
//! ## Lifecycle & safety
//!
//! * The hooks live on a **dedicated thread with its own message pump** (a `WH_*_LL` callback is only
//!   dispatched to a thread that pumps messages). The thread exists **only while blocking**: turning
//!   the block on spawns it and installs both hooks; turning it off posts `WM_QUIT`, so the thread
//!   unhooks and exits. `Drop` releases too, so a dropped [`InputBlocker`] can never strand the guest.
//! * A low-level hook is torn down by Windows automatically when its owning thread/process exits, so
//!   **an agent crash cannot permanently lock the guest out** — the block dies with the process.
//! * Coverage is the interactive `Default` desktop only (low-level hooks are per-desktop and this
//!   thread does not follow the input desktop). That is deliberate: `Ctrl+Alt+Del` / UAC run on the
//!   Winlogon **secure desktop**, which stays reachable — the guest always keeps that escape hatch,
//!   matching how `BlockInput` behaves.
//!
//! The blocking is a Win32 side effect that cannot run under `cargo test` (no desktop, no pump), so the
//! only unit-testable piece — and the one that decides whether a given event is blocked — is the pure
//! [`should_pass`], which is exercised below.

use std::sync::mpsc;
use std::thread::JoinHandle;

use windows::Win32::Foundation::{FALSE, GENERIC_ALL, HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, SetThreadDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS,
};
use windows::Win32::System::Threading::GetCurrentThreadId;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, DispatchMessageW, GetMessageW, PeekMessageW, PostThreadMessageW,
    SetWindowsHookExW, TranslateMessage, UnhookWindowsHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT,
    MSG, MSLLHOOKSTRUCT, PM_NOREMOVE, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_QUIT,
};

/// Whether a low-level input event should be allowed through while blocking is active.
///
/// The ONE rule: pass exactly this agent's own injected input (tagged [`crate::input::RMT_INJECTED_TAG`]
/// in `dwExtraInfo`), swallow everything else. Genuine hardware input carries `dwExtraInfo == 0`, and
/// no legitimate source ever forges our tag, so this cleanly separates "the technician driving the
/// remote" from "the guest touching their own keyboard/mouse".
pub(crate) fn should_pass(extra_info: usize) -> bool {
    extra_info == crate::input::RMT_INJECTED_TAG
}

/// A running block: the hook thread's id (to post `WM_QUIT`) and its join handle (to reap it).
struct Active {
    thread_id: u32,
    join: JoinHandle<()>,
}

/// Owns the guest-input block for a session. Toggle with [`InputBlocker::set_blocked`]; the block is
/// released on `Drop`, so teardown never depends on an explicit call arriving.
pub struct InputBlocker {
    /// `false` = **mock** mode: track the requested state and answer honestly, but install NO real OS
    /// hooks. Used by the `--log-input` test path (which also mocks injection), so running the e2e —
    /// or the local gate — can exercise the full control round-trip without freezing the machine's
    /// real keyboard/mouse. `true` = production: real low-level hooks.
    real: bool,
    /// Real mode: `Some` while the hook thread is running.
    active: Option<Active>,
    /// Mock mode: the tracked block state (no hooks behind it).
    mock_blocked: bool,
}

impl InputBlocker {
    /// A blocker with no block in force. `real == false` makes every `set_blocked` a no-op that still
    /// reports the requested state (test/mock mode); `true` installs real OS hooks.
    pub fn new(real: bool) -> Self {
        Self { real, active: None, mock_blocked: false }
    }

    /// Whether the guest's physical input is blocked right now.
    pub fn is_blocked(&self) -> bool {
        if self.real {
            self.active.is_some()
        } else {
            self.mock_blocked
        }
    }

    /// Request `blocked`; returns the state **actually in force** afterwards (which differs from the
    /// request only if the hooks could not be installed — e.g. no interactive desktop). Idempotent.
    pub fn set_blocked(&mut self, blocked: bool) -> bool {
        if !self.real {
            // Mock mode: nothing is hooked, so the request is simply reflected back.
            self.mock_blocked = blocked;
            return self.mock_blocked;
        }
        if blocked == self.active.is_some() {
            return self.is_blocked();
        }
        if blocked {
            self.start();
        } else {
            self.stop();
        }
        self.is_blocked()
    }

    fn start(&mut self) {
        let (tx, rx) = mpsc::channel::<Option<u32>>();
        let join = match std::thread::Builder::new()
            .name("rmt-input-block".into())
            .spawn(move || hook_thread(&tx))
        {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!(error = %e, "input-block: could not spawn hook thread; input NOT blocked");
                return;
            }
        };
        // Wait for the thread to report its id (hooks installed) or None (install failed). Either way
        // the thread has reached a known state before we return.
        match rx.recv() {
            Ok(Some(thread_id)) => self.active = Some(Active { thread_id, join }),
            _ => {
                let _ = join.join();
                tracing::warn!("input-block: hooks failed to install; guest input is NOT blocked");
            }
        }
    }

    fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            // WM_QUIT ends the hook thread's pump; it then unhooks and exits. `Result` is ignored: if
            // the post fails the thread is already gone, and the join below reaps it regardless.
            unsafe {
                let _ = PostThreadMessageW(active.thread_id, WM_QUIT, WPARAM(0), LPARAM(0));
            }
            let _ = active.join.join();
        }
    }
}

impl Drop for InputBlocker {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Default for InputBlocker {
    /// Production default: a real blocker (installs OS hooks when armed).
    fn default() -> Self {
        Self::new(true)
    }
}

/// The hook thread: bind to the input desktop, install both low-level hooks, report readiness, pump
/// until `WM_QUIT`, unhook.
fn hook_thread(up: &mpsc::Sender<Option<u32>>) {
    unsafe {
        // Bind THIS thread to the desktop currently receiving user input BEFORE installing the hooks.
        // A `WH_*_LL` hook only intercepts input on the desktop its installing thread is bound to, and
        // the helper's threads do NOT inherit the interactive `Default` desktop by default (only the
        // capture/injection thread attaches, via `service::DesktopFollower`). Without this, the hooks
        // install on the wrong desktop and silently block NOTHING — VM-caught (loop 24): the guest's
        // keystrokes still reached a focused window while "blocked". Flags/mask match the values the
        // secure-desktop spike proved (`GENERIC_ALL`), same as the injection thread.
        let hdesk = match OpenInputDesktop(
            DESKTOP_CONTROL_FLAGS(0),
            FALSE,
            DESKTOP_ACCESS_FLAGS(GENERIC_ALL.0),
        ) {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(error = %e, "input-block: OpenInputDesktop failed");
                let _ = up.send(None);
                return;
            }
        };
        if let Err(e) = SetThreadDesktop(hdesk) {
            tracing::warn!(error = %e, "input-block: SetThreadDesktop(input) failed");
            let _ = CloseDesktop(hdesk);
            let _ = up.send(None);
            return;
        }

        let hmod: HINSTANCE = match GetModuleHandleW(None) {
            Ok(m) => m.into(),
            Err(e) => {
                tracing::warn!(error = %e, "input-block: GetModuleHandleW failed");
                let _ = CloseDesktop(hdesk);
                let _ = up.send(None);
                return;
            }
        };
        let kbd = match SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), hmod, 0) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "input-block: keyboard hook failed");
                let _ = CloseDesktop(hdesk);
                let _ = up.send(None);
                return;
            }
        };
        let mouse = match SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), hmod, 0) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(error = %e, "input-block: mouse hook failed");
                let _ = UnhookWindowsHookEx(kbd);
                let _ = CloseDesktop(hdesk);
                let _ = up.send(None);
                return;
            }
        };
        // Force this thread's message queue to exist BEFORE we announce our id, so the `WM_QUIT` that
        // `stop()` posts (via the id we send next) can never be dropped on the floor by racing an
        // as-yet-uncreated queue.
        let mut msg = MSG::default();
        let _ = PeekMessageW(&mut msg, None, 0, 0, PM_NOREMOVE);
        let _ = up.send(Some(GetCurrentThreadId()));
        tracing::info!("input-block: guest keyboard & mouse blocked (injected input still passes)");

        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        let _ = UnhookWindowsHookEx(mouse);
        let _ = UnhookWindowsHookEx(kbd);
        let _ = CloseDesktop(hdesk);
        tracing::info!("input-block: guest input released");
    }
}

/// `WH_KEYBOARD_LL` callback: swallow the guest's keystrokes, pass the agent's injected ones.
unsafe extern "system" fn keyboard_proc(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if ncode == HC_ACTION as i32 {
        let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        if !should_pass(info.dwExtraInfo) {
            return LRESULT(1); // non-zero, no CallNextHookEx → the keystroke is dropped
        }
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}

/// `WH_MOUSE_LL` callback: swallow the guest's mouse events, pass the agent's injected ones.
unsafe extern "system" fn mouse_proc(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if ncode == HC_ACTION as i32 {
        let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
        if !should_pass(info.dwExtraInfo) {
            return LRESULT(1);
        }
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_only_this_agents_tagged_input() {
        // The agent's own injections carry the tag → pass (the technician keeps control).
        assert!(should_pass(crate::input::RMT_INJECTED_TAG));
        // Genuine hardware input is dwExtraInfo == 0 → blocked (the guest is frozen).
        assert!(!should_pass(0));
        // Any other value (a different app's injection, a near-miss forgery) is blocked too.
        assert!(!should_pass(crate::input::RMT_INJECTED_TAG.wrapping_sub(1)));
        assert!(!should_pass(crate::input::RMT_INJECTED_TAG.wrapping_add(1)));
        assert!(!should_pass(0xDEAD_BEEF));
    }

    #[test]
    fn a_fresh_blocker_is_not_blocking() {
        // Construction alone installs no hooks — no Win32 touched until set_blocked(true).
        assert!(!InputBlocker::new(true).is_blocked());
        assert!(!InputBlocker::new(false).is_blocked());
        assert!(!InputBlocker::default().is_blocked());
    }

    #[test]
    fn mock_mode_tracks_state_without_touching_win32() {
        // The `--log-input` test path uses a mock blocker so the e2e (and the local gate) never
        // freezes the real keyboard/mouse. It must still report state honestly so the ack round-trip
        // is exercised end to end.
        let mut b = InputBlocker::new(false);
        assert!(!b.is_blocked());
        assert!(b.set_blocked(true)); // reflects the request; installs nothing
        assert!(b.is_blocked());
        assert!(!b.set_blocked(false));
        assert!(!b.is_blocked());
    }
}
