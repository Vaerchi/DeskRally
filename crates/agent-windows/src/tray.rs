//! System-tray presence icon for the interactive-session helper.
//!
//! The icon appears in the notification area while the helper process is alive — that is,
//! while the machine is registered with the signaling server and available for remote
//! sessions. It disappears automatically when the helper exits. Users who notice a
//! background process can look at the notification area and see "DeskRally — Ready for
//! support" rather than a mysterious service with no on-screen presence.
//!
//! Architecture
//! -----------
//! A dedicated OS thread owns the Win32 message loop and the hidden message-only window
//! that anchors the tray icon (`HWND_MESSAGE` parent — no taskbar entry, not enumerable
//! by `FindWindow`). `TrayIcon::spawn()` starts this thread and returns a handle; dropping
//! the handle posts `WM_CLOSE` to the message-only window, which tears down the window and
//! causes the message loop to exit cleanly.
//!
//! ## Shutdown sequencing
//!
//! `PostMessageW(hwnd, WM_CLOSE)` is used rather than `PostThreadMessageW(WM_QUIT)` because
//! a thread's message queue does not exist until its first `GetMessageW`/`PeekMessageW` call.
//! Posting to an HWND is safe as soon as `CreateWindowExW` returns — no race condition with
//! the queue's creation. The chain is:
//!
//!   `WM_CLOSE` → `DefWindowProcW` calls `DestroyWindow` → `WM_DESTROY` is sent synchronously
//!   → wndproc calls `PostQuitMessage(0)` → `GetMessageW` returns 0 → loop exits.
//!
//! The HWND is sent back to the spawner as a raw `isize` (avoids the `!Send` marker on the
//! `HWND` newtype) and stored for use by `TrayIcon::drop`.
//!
//! The WGC constraint (WGC permanently poisons `SetThreadDesktop` on the calling thread)
//! does NOT apply here because this thread never touches WGC or DDA.
//!
//! ## Help requests (docs/64 H3)
//!
//! With a [`HelpHub`] the icon gets a menu, on a left or a right click: "Request help..." (with an optional note) and
//! "Cancel help request", plus a status line and "About DeskRally", and the tooltip follows the request state. The help
//! items exist only while the helper's signaling connection advertised `help_request_v1` (so never for a retired
//! machine); without them the menu says help requests aren't available and still offers "About DeskRally" (menu wave
//! 11: the icon is never dead). A help choice counts only when the guest's own hardware input made it
//! (`tray_menu_provenance`); see `help_request::run_tray_menu` for the logic, which is tested with a UI double. This
//! file holds only the Win32 half.
//!
//! Session-state awareness is intentionally omitted for v1: the helper's process lifetime
//! IS the session's available lifetime, so icon-present ↔ agent-ready is the correct
//! coarse invariant without any IPC between the service and the helper.
#![cfg(windows)]

use std::{cell::{Cell, RefCell}, mem, sync::{mpsc, Arc}, thread, time::Instant};

use crate::help_request::{self, HelpHub, HelpUi, HelpView, MenuChoice, ViewPhase};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
                NOTIFYICONDATAW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu, DispatchMessageW, GetCursorPos,
                GetMessageW, IsWindow, LoadIconW, PostMessageW, PostQuitMessage, RegisterClassExW, SetForegroundWindow,
                TrackPopupMenu, HICON, IDI_APPLICATION, HMENU, MENU_ITEM_FLAGS, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG,
                TPM_NONOTIFY, TPM_RETURNCMD, TPM_RIGHTBUTTON, WINDOW_EX_STYLE, WNDCLASSEXW, WM_APP, WM_CLOSE,
                WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, HWND_MESSAGE,
                MessageBoxW, MB_ICONINFORMATION, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
            },
        },
    },
};

/// Window class name for the hidden message-only window that anchors the tray icon.
const CLASS_NAME: PCWSTR = windows::core::w!("DeskRallyTray");

/// Tray icon UID — arbitrary; must be unique within this process.
const TRAY_UID: u32 = 1;

/// Callback message sent to the hidden window when the user interacts with the tray icon
/// (click, hover, right-click). A left or right click opens the menu (`on_tray_context`).
const WM_TRAY_ICON: u32 = 0x8000 + 1; // WM_APP + 1

/// Posted (from any thread) when the help-request state changed: the tooltip is refreshed on the tray thread.
const WM_HELP_CHANGED: u32 = WM_APP + 2;

/// The tray thread's help context: the hub and the icon the tooltip refresh re-sends. Thread-local because the window
/// procedure runs on this one thread only.
struct HelpCtx {
    hub: Arc<HelpHub>,
    hicon: HICON,
}

thread_local! {
    static HELP: RefCell<Option<HelpCtx>> = const { RefCell::new(None) };
    /// The menu and the note dialog run nested message loops that dispatch further tray messages to this window: a click
    /// during either must not open a second menu or dialog.
    static IN_HELP_UI: Cell<bool> = const { Cell::new(false) };
}

/// Tooltip text shown when the user hovers over the tray icon.
const TOOLTIP_LABEL: &str = "DeskRally \u{2014} Ready for support";

// ──────────────────────────────────────────────────────────────────────────────

/// A running system-tray icon.
///
/// Dropping this handle removes the icon from the notification area and joins the thread.
/// If spawning failed (no interactive session, shell not running, etc.) the handle is
/// absent and the session continues without a tray icon.
pub struct TrayIcon {
    /// Raw `HWND` inner pointer for the message-only window.  `HWND` wraps `*mut c_void`
    /// which is `!Send`; storing the value as `usize` makes `TrayIcon` unconditionally
    /// `Send` without an unsafe impl.  Reconstructed via `HWND(hwnd_raw as *mut c_void)`
    /// only on the tray thread (in `Drop`, which `PostMessageW` handles cross-thread safely).
    hwnd_raw: usize,
    thread: Option<thread::JoinHandle<()>>,
}

impl TrayIcon {
    /// Spawn the tray icon on a dedicated OS thread.
    ///
    /// Returns `None` when the thread or the Win32 window/icon creation fails; this is
    /// treated as non-fatal — the caller ignores the absence and the session proceeds.
    pub fn spawn() -> Option<Self> {
        Self::spawn_with_help(None)
    }

    /// [`spawn`](Self::spawn) with the docs/64 help-request menu wired to `help` (`None` = the plain, menu-less icon).
    pub fn spawn_with_help(help: Option<Arc<HelpHub>>) -> Option<Self> {
        // The thread sends back the raw HWND once the window is created; 0 signals failure.
        // Using the HWND (not the thread ID) as the shutdown target means Drop can safely
        // post WM_CLOSE even before the message loop's first GetMessageW call, because a
        // window's message queue is ready as soon as CreateWindowExW returns.
        let (tx, rx) = mpsc::channel::<usize>();
        let thread = thread::Builder::new()
            .name("deskrally-tray".into())
            .spawn(move || tray_thread(tx, help))
            .ok()?;
        let hwnd_raw = rx.recv().ok()?;
        if hwnd_raw == 0 {
            // Window creation failed; the thread already exited.
            let _ = thread.join();
            return None;
        }
        Some(Self {
            hwnd_raw,
            thread: Some(thread),
        })
    }
}

impl Drop for TrayIcon {
    fn drop(&mut self) {
        // Post WM_CLOSE to the message-only window. DefWindowProcW handles WM_CLOSE by
        // calling DestroyWindow, which synchronously delivers WM_DESTROY to wndproc, which
        // calls PostQuitMessage(0) — causing GetMessageW to return 0 and the loop to exit.
        // This is safe to post as soon as the HWND is valid (window exists from spawn).
        unsafe {
            let _ = PostMessageW(
                HWND(self.hwnd_raw as *mut std::ffi::c_void),
                WM_CLOSE,
                WPARAM(0),
                LPARAM(0),
            );
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tray thread internals

fn tray_thread(hwnd_tx: mpsc::Sender<usize>, help: Option<Arc<HelpHub>>) {
    // SAFETY: all Win32 calls are on this dedicated OS thread. No cross-thread handle
    // sharing occurs; HWND and HICON are used only within this function's scope.
    unsafe {
        let Ok(hmodule) = GetModuleHandleW(None) else {
            let _ = hwnd_tx.send(0);
            return;
        };
        let hinstance = HINSTANCE(hmodule.0);

        // Register a minimal window class. Ignore the return value: if the class is already
        // registered (e.g. a previous spawn in the same process during tests) CreateWindowExW
        // will still succeed using the existing registration.
        let wc = WNDCLASSEXW {
            cbSize: mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: CLASS_NAME,
            ..Default::default()
        };
        let _ = RegisterClassExW(&wc);

        // Message-only window (HWND_MESSAGE parent): invisible, not in the taskbar,
        // not found by FindWindow/EnumWindows. Sole purpose is to receive tray messages.
        // Pattern mirrors guest_window.rs: raw HWND/HINSTANCE values, HMENU(null) for no menu.
        let hwnd = match CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            CLASS_NAME,
            windows::core::w!(""),
            Default::default(),
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        ) {
            Ok(h) => h,
            Err(_) => {
                let _ = hwnd_tx.send(0); // signal failure to spawner
                return;
            }
        };

        // Send the HWND back NOW — the window exists, so PostMessageW to it is safe from
        // this point forward, even before GetMessageW is called.
        let _ = hwnd_tx.send(hwnd.0 as usize);

        // Shared resource101 is embedded in every shipping Windows agent executable.
        let hicon = LoadIconW(hinstance, PCWSTR(101usize as *const u16))
            .or_else(|_| LoadIconW(None, IDI_APPLICATION)).unwrap_or_default();

        let mut nid = build_nid(hwnd, hicon);

        // Add the icon. Failure (Shell not running, no interactive session) is non-fatal.
        let _ = Shell_NotifyIconW(NIM_ADD, &nid);

        // docs/64: from here the hub may tell this window its state changed (a message post, safe from any thread).
        if let Some(hub) = help.clone() {
            let raw = hwnd.0 as usize;
            hub.set_on_change(Arc::new(move || {
                // PostMessageW to a possibly-gone window just fails.
                let _ = PostMessageW(HWND(raw as *mut std::ffi::c_void), WM_HELP_CHANGED, WPARAM(0), LPARAM(0));
            }));
            HELP.with(|h| *h.borrow_mut() = Some(HelpCtx { hub, hicon }));
            refresh_tooltip(hwnd);
        }

        // Message loop.  `.0 > 0` matches every other pump in this codebase (guest_window.rs,
        // code_prompt.rs, input_block.rs) to distinguish the normal quit (0) from a GetMessageW
        // error (-1, cast to BOOL = -1 → as_bool() would return true and spin forever).
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
            let _ = DispatchMessageW(&msg);
        }

        // WM_CLOSE → DefWindowProcW → DestroyWindow → WM_DESTROY → PostQuitMessage(0) → loop exit.
        // The window is already destroyed by the time we get here; do NOT call DestroyWindow again.
        // Only remove the tray icon — it is still live (Shell holds it by UID, not by HWND lifetime).
        nid.uFlags = NIF_ICON;
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
        if let Some(hub) = help {
            hub.set_on_change(Arc::new(|| {}));
        }
        HELP.with(|h| *h.borrow_mut() = None);
    }
}

/// Construct a `NOTIFYICONDATAW` for this process's tray icon.
fn build_nid(hwnd: HWND, hicon: windows::Win32::UI::WindowsAndMessaging::HICON) -> NOTIFYICONDATAW {
    NOTIFYICONDATAW {
        cbSize: mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd,
        uID: TRAY_UID,
        uFlags: NIF_ICON | NIF_TIP | NIF_MESSAGE,
        uCallbackMessage: WM_TRAY_ICON,
        hIcon: hicon,
        szTip: encode_tooltip(TOOLTIP_LABEL),
        ..Default::default()
    }
}

/// Encode a string into the fixed 128-element `szTip` UTF-16 array.
///
/// Truncated to 127 UTF-16 code units (plus a forced null terminator at index 127) so the
/// result always fits in `NOTIFYICONDATAW::szTip`. Surrogate pairs are not split — the
/// iterator produces one `u16` per UTF-16 code unit and we stop before element 127.
pub(crate) fn encode_tooltip(label: &str) -> [u16; 128] {
    let mut buf = [0u16; 128];
    for (i, c) in label.encode_utf16().enumerate() {
        if i >= 127 {
            break;
        }
        buf[i] = c;
    }
    // buf[127] is already 0 from the initializer — explicit null terminator.
    buf
}

/// Minimal window procedure for the hidden message-only window.
///
/// `WM_DESTROY` posts `WM_QUIT` to cause the `GetMessageW` loop in `tray_thread` to exit.
/// `WM_CLOSE` is handled by `DefWindowProcW`, which calls `DestroyWindow`; all other
/// messages including `WM_TRAY_ICON` (shell callbacks) are also dispatched there.
unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    if msg == WM_DESTROY {
        PostQuitMessage(0);
        return LRESULT(0);
    }
    if msg == WM_TRAY_ICON {
        let mouse = lp.0 as u32;
        // Menu wave 11: a left-click opens the same menu as a right-click (it used to do nothing).
        if mouse == WM_RBUTTONUP || mouse == WM_CONTEXTMENU || mouse == WM_LBUTTONUP {
            on_tray_context(hwnd);
        }
        return LRESULT(0);
    }
    if msg == WM_HELP_CHANGED {
        refresh_tooltip(hwnd);
        return LRESULT(0);
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

/// Re-send the tooltip for the hub's current state (NIM_MODIFY; nothing visible appears but the tooltip text).
unsafe fn refresh_tooltip(hwnd: HWND) {
    HELP.with(|h| {
        if let Some(ctx) = h.borrow().as_ref() {
            let view = ctx.hub.view(Instant::now());
            let mut nid = build_nid(hwnd, ctx.hicon);
            nid.szTip = encode_tooltip(&help_request::tooltip_text(&view, TOOLTIP_LABEL));
            let _ = Shell_NotifyIconW(NIM_MODIFY, &nid);
        }
    });
}

/// A click on the icon: run the menu, if there is a hub and nothing of ours is already open.
unsafe fn on_tray_context(hwnd: HWND) {
    let Some(hub) = HELP.with(|h| h.borrow().as_ref().map(|c| c.hub.clone())) else { return };
    if IN_HELP_UI.with(|f| f.replace(true)) {
        return;
    }
    let outcome = help_request::run_tray_menu(&hub, &Win32HelpUi { hwnd }, Instant::now);
    IN_HELP_UI.with(|f| f.set(false));
    tracing::info!(?outcome, "help: tray action");
    if !IsWindow(hwnd).as_bool() {
        // A nested loop retrieved WM_QUIT during teardown: make sure the outer loop exits too.
        PostQuitMessage(0);
    }
}

/// The real menu and dialog. Every OS-visible call of the help feature is here, behind [`HelpUi`], so no test opens one.
struct Win32HelpUi {
    hwnd: HWND,
}

const ID_MENU_REQUEST: usize = 1;
const ID_MENU_CANCEL: usize = 2;
const ID_MENU_ABOUT: usize = 3;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl HelpUi for Win32HelpUi {
    fn menu(&self, view: &HelpView) -> (MenuChoice, bool) {
        // SAFETY: a popup menu created, tracked and destroyed on this thread.
        unsafe {
            let Ok(menu) = CreatePopupMenu() else { return (MenuChoice::Dismissed, false) };
            let status = if view.available { help_request::status_text(view) } else { Some(help_request::HELP_UNAVAILABLE_LINE.to_string()) };
            if let Some(status) = status {
                let w = wide(&status);
                let _ = AppendMenuW(menu, MENU_ITEM_FLAGS(MF_STRING.0 | MF_GRAYED.0), 0, PCWSTR(w.as_ptr()));
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            }
            match view.phase {
                // Without the feature there are no help items at all (docs/64 H3: never for a retired machine).
                _ if !view.available => {}
                ViewPhase::Idle | ViewPhase::Sending | ViewPhase::Checking => {
                    let flags = if view.can_request { MF_STRING.0 } else { MF_STRING.0 | MF_GRAYED.0 };
                    let _ = AppendMenuW(menu, MENU_ITEM_FLAGS(flags), ID_MENU_REQUEST, windows::core::w!("Request help\u{2026}"));
                }
                ViewPhase::Open | ViewPhase::Cancelling => {
                    let flags = if view.phase == ViewPhase::Open { MF_STRING.0 } else { MF_STRING.0 | MF_GRAYED.0 };
                    let _ = AppendMenuW(menu, MENU_ITEM_FLAGS(flags), ID_MENU_CANCEL, windows::core::w!("Cancel help request"));
                }
            }
            if view.available {
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            }
            let _ = AppendMenuW(menu, MF_STRING, ID_MENU_ABOUT, windows::core::w!("About DeskRally"));
            let mut pos = windows::Win32::Foundation::POINT::default();
            let _ = GetCursorPos(&mut pos);
            let _ = SetForegroundWindow(self.hwnd);
            // Who chose the item is recorded by low-level hooks for the menu's lifetime (the modal loop bypasses any pump
            // filter): an injected press anywhere during it disqualifies the choice.
            let (cmd, by_guest) = crate::tray_menu_provenance::watch(|| {
                TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pos.x, pos.y, 0, self.hwnd, None).0
            });
            let _ = DestroyMenu(menu);
            let _ = PostMessageW(self.hwnd, WM_NULL, WPARAM(0), LPARAM(0));
            let choice = match cmd as usize {
                ID_MENU_REQUEST => MenuChoice::RequestHelp,
                ID_MENU_CANCEL => MenuChoice::CancelRequest,
                ID_MENU_ABOUT => MenuChoice::About,
                _ => MenuChoice::Dismissed,
            };
            (choice, by_guest)
        }
    }

    fn note_dialog(&self) -> (Option<String>, bool) {
        // The dialog authenticates Send itself (help_request::SendAuth, fed by its own hooks) and returns a note only for a
        // genuine activation, so a returned note is already the guest's own.
        (crate::help_dialog::prompt_note(), true)
    }

    fn about(&self) {
        let text = windows::core::HSTRING::from(about_text(rmt_agent_core::version::AGENT_VERSION));
        // SAFETY: a modal message box on this thread (IN_HELP_UI keeps a second click from opening another).
        unsafe {
            MessageBoxW(
                None,
                &text,
                &windows::core::HSTRING::from("DeskRally \u{2014} About"),
                MB_OK | MB_ICONINFORMATION | MB_SETFOREGROUND | MB_TOPMOST,
            );
        }
    }
}

/// The "About DeskRally" text: what the icon means, plainly, and the version a technician may ask for.
pub(crate) fn about_text(version: &str) -> String {
    format!(
        "DeskRally remote support agent\nVersion {version}\n\nThis computer is set up to receive remote support from your \
         organization. The DeskRally icon here means the agent is running."
    )
}

// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::encode_tooltip;

    #[test]
    fn about_text_names_the_version_and_what_the_icon_means() {
        let s = super::about_text("0.1.24+abcdef12");
        assert!(s.contains("Version 0.1.24+abcdef12"), "{s}");
        assert!(s.contains("remote support"), "{s}");
        assert!(!s.contains("control plane"), "guests never see 'control plane': {s}");
    }

    #[test]
    fn tooltip_fits_and_is_null_terminated() {
        let tip = encode_tooltip(super::TOOLTIP_LABEL);
        assert_ne!(tip[0], 0, "tooltip must start with real content");
        assert_eq!(tip[127], 0, "last element must be the null terminator");
    }

    #[test]
    fn tooltip_long_input_does_not_overflow() {
        let long = "x".repeat(300);
        let tip = encode_tooltip(&long);
        // All 300 'x' characters would need 300 u16 slots; only 127 should be filled.
        assert_eq!(tip[127], 0, "forced null at index 127 regardless of input length");
        for i in 0..127 {
            assert_eq!(tip[i], b'x' as u16, "slot {i} should be 'x'");
        }
    }

    #[test]
    fn tooltip_empty_string_is_all_zeros() {
        let tip = encode_tooltip("");
        assert!(tip.iter().all(|&c| c == 0));
    }

    /// Boundary: exactly 127 code units must all appear; slot 127 must still be null.
    /// Catches an off-by-one that truncates at 126 instead of 127.
    #[test]
    fn tooltip_exactly_127_units_fits_without_truncation() {
        let exact = "x".repeat(127);
        let tip = encode_tooltip(&exact);
        for i in 0..127 {
            assert_eq!(tip[i], b'x' as u16, "slot {i} must be 'x'");
        }
        assert_eq!(tip[127], 0, "slot 127 must be the null terminator");
    }

    /// Prove the thread spawns cleanly and can be dropped without deadlocking.
    ///
    /// `Shell_NotifyIconW` may fail in headless CI (no Shell / notification area) — that
    /// is non-fatal by design. This test only verifies: no panic, no deadlock, clean join.
    /// The HWND-based shutdown (PostMessageW to the window) avoids the race that
    /// PostThreadMessageW(WM_QUIT) would have before the message queue is created.
    #[test]
    #[cfg(windows)]
    fn spawn_and_drop_does_not_deadlock() {
        // Either Some (interactive session with Shell) or None (headless/CI) — both valid.
        let _icon = super::TrayIcon::spawn();
        // Drop happens here; the test passes if it does not hang or panic.
    }
}
