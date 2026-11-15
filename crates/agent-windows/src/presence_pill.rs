//! The "someone is controlling this PC" pill: a small, always-on-top, always-present indicator on the
//! controlled machine for as long as a session is live (Ed, 2026-10-23).
//!
//! # What the operator chose
//! - **Top-centre pill**: "A DeskRally technician is controlling this PC", or "… is viewing this PC" for a
//!   view-only session. Clicking it opens the existing guest panel (chat + End).
//! - **Collapsible, never dismissable**: the guest may shrink it to a thin strip (and click the strip to
//!   expand it again), but it cannot be closed while the session is live. It disappears at session end.
//! - **Hidden from the technician's picture**: `WDA_EXCLUDEFROMCAPTURE`, honoured by DXGI desktop
//!   duplication, Windows Graphics Capture and GDI capture alike. The technician knows they are
//!   connected; the indicator is for the person at the machine.
//! - **Always on**: no policy switch, even for unattended servers.
//!
//! # Why it lives on the guest window's thread
//! It is created, repainted and destroyed by the guest window's UI thread, so it shares that thread's
//! lifetime (session start to session end), its desktop pinning (`WinSta0\Default`, never the secure
//! desktop; see guest_window.rs decision 2), and its message pump. The pump's injection filter drops the
//! technician's injected clicks on EVERY window of the thread, so collapsing the pill and opening the
//! panel answer only to the guest's own hardware input, the same rule as the panel's End button.
//!
//! # Why it is not owned by the panel
//! An owned window hides with its owner, and the panel is routinely hidden (tucked into the tray). The
//! indicator must stay visible regardless, so it is an independent top-level tool window.

#![cfg(windows)]

use std::sync::Mutex;

use windows::core::w;
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
    InvalidateRect, SelectObject, SetBkMode, SetTextColor, ANTIALIASED_QUALITY, CLIP_DEFAULT_PRECIS,
    DEFAULT_CHARSET, DT_CENTER, DT_END_ELLIPSIS, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, FF_DONTCARE,
    FW_SEMIBOLD, HGDIOBJ, OUT_TT_PRECIS, PAINTSTRUCT, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, GetMessageExtraInfo, GetSystemMetrics,
    GetWindowLongPtrW, LoadCursorW, RegisterClassW, SetWindowDisplayAffinity, SetWindowLongPtrW,
    SetWindowPos, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA, HCURSOR, HWND_TOPMOST,
    IDC_HAND, MA_NOACTIVATE, SM_CXSCREEN, SM_CYSCREEN, WM_DISPLAYCHANGE, SWP_NOACTIVATE, WDA_EXCLUDEFROMCAPTURE, WINDOW_EX_STYLE,
    WM_CLOSE, WM_CREATE, WM_LBUTTONDOWN, WM_MOUSEACTIVATE, WM_NCDESTROY, WM_PAINT, WNDCLASSW,
    WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_POPUP, WS_VISIBLE,
};

/// Window class name (also what a probe uses to assert the indicator exists).
pub const PILL_CLASS: windows::core::PCWSTR = w!("DeskRallyPresencePill");

/// Expanded and collapsed sizes, in logical pixels.
const PILL_W: i32 = 380;
const PILL_H: i32 = 30;
const STRIP_W: i32 = 200;
const STRIP_H: i32 = 6;
/// The collapse control at the pill's right end.
const COLLAPSE_W: i32 = 32;
/// Vertical step between the pills of concurrent sessions (one pill per session).
const SLOT_STEP: i32 = PILL_H + 4;
/// DeskRally orange-red, as COLORREF (0x00BBGGRR) for RGB(196, 64, 0).
const PILL_COLOR: u32 = 0x0000_40C4;
const TEXT_COLOR: u32 = 0x00FF_FFFF;

/// Which vertical slot each live pill occupies, so concurrent sessions stack instead of overlapping.
/// Grows on demand: a fixed table reused its last slot once full, so two pills could share it (Codex
/// 1.3.8 review [low]).
static SLOTS: Mutex<Vec<bool>> = Mutex::new(Vec::new());

/// The pill's words for a live session. Pure, so the wording is testable without a desktop.
pub fn pill_text(view_only: bool) -> &'static str {
    if view_only {
        "A DeskRally technician is viewing this PC"
    } else {
        "A DeskRally technician is controlling this PC"
    }
}

/// What a click at client x-coordinate `x` does. Pure, for the same reason.
#[derive(Debug, PartialEq, Eq)]
pub enum PillClick {
    /// Expand a collapsed strip.
    Expand,
    /// Shrink the pill to a strip.
    Collapse,
    /// Open the guest panel (chat + End).
    OpenPanel,
}

/// Whether a click may actuate the pill: only GENUINE input, never this agent's own injection (the
/// technician's). The guest-window pump already drops injected clicks, but a nested modal loop (the
/// tray menu's `TrackPopupMenu`) dispatches without that pump, so the pill checks for itself too
/// (Codex 1.3.8 review). `extra_info` is `GetMessageExtraInfo()` for the message being handled.
pub fn accepts_click(extra_info: usize) -> bool {
    extra_info != crate::input::RMT_INJECTED_TAG
}

pub fn click_action(collapsed: bool, x: i32, width: i32) -> PillClick {
    if collapsed {
        PillClick::Expand
    } else if x >= width - COLLAPSE_W {
        PillClick::Collapse
    } else {
        PillClick::OpenPanel
    }
}

struct PillState {
    /// The guest panel's HWND, for the live session state and for opening it.
    guest: isize,
    collapsed: bool,
    slot: usize,
    offscreen: bool,
}

fn take_slot() -> usize {
    let mut slots = SLOTS.lock().unwrap();
    match slots.iter().position(|used| !used) {
        Some(i) => {
            slots[i] = true;
            i
        }
        None => {
            slots.push(true);
            slots.len() - 1
        }
    }
}

fn free_slot(i: usize) {
    if let Some(s) = SLOTS.lock().unwrap().get_mut(i) {
        *s = false;
    }
}

/// The pill's screen rectangle (x, y, w, h).
fn placement(collapsed: bool, slot: usize, offscreen: bool) -> (i32, i32, i32, i32) {
    let (w, h) = if collapsed { (STRIP_W, STRIP_H) } else { (PILL_W, PILL_H) };
    if offscreen {
        return (-32_000, -32_000, w, h);
    }
    let (screen_w, screen_h) = unsafe { (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN)) };
    ((screen_w - w).max(0) / 2, row_for(slot, screen_h) * SLOT_STEP, w, h)
}

/// The row a pill in `slot` occupies: its own row while they fit in the top quarter of the screen,
/// then the last such row (pills past it overlap there rather than march off the bottom of the
/// screen; Codex 1.3.8 round 2: with no session cap, `slot * step` eventually left the display).
fn row_for(slot: usize, screen_h: i32) -> i32 {
    let rows = ((screen_h / 4) / SLOT_STEP).max(1);
    (slot as i32).min(rows - 1)
}

/// Create the pill for the session whose panel is `guest`. Must run on the panel's UI thread.
/// `offscreen` mirrors the panel's lab mode: created (so a probe can find it) but not visible.
///
/// # Safety
/// Win32 window creation on the calling thread.
pub(crate) unsafe fn create(guest: HWND, offscreen: bool) -> Option<HWND> {
    let hinstance = GetModuleHandleW(None).ok()?;
    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(pill_proc),
        hInstance: hinstance.into(),
        lpszClassName: PILL_CLASS,
        hCursor: LoadCursorW(None, IDC_HAND).unwrap_or(HCURSOR(std::ptr::null_mut())),
        ..Default::default()
    };
    // Re-registration in a long-lived helper is the norm, not an error (as for the panel's class).
    let _ = RegisterClassW(&wc);
    let slot = take_slot();
    let (x, y, w, h) = placement(false, slot, offscreen);
    let state = Box::into_raw(Box::new(PillState { guest: guest.0 as isize, collapsed: false, slot, offscreen }));
    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(WS_EX_TOPMOST.0 | WS_EX_TOOLWINDOW.0 | WS_EX_NOACTIVATE.0),
        PILL_CLASS,
        w!("DeskRally session in progress"),
        WS_POPUP | WS_VISIBLE,
        x, y, w, h,
        None, None, hinstance, Some(state as *const _),
    );
    match hwnd {
        Ok(hwnd) => {
            // Local screen only: the technician's capture never shows it. Best effort: on a Windows
            // build without WDA_EXCLUDEFROMCAPTURE the pill is simply visible to both sides.
            if SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE).is_err() {
                tracing::debug!("presence pill: capture exclusion unavailable; the technician will see it");
            }
            Some(hwnd)
        }
        Err(e) => {
            drop(Box::from_raw(state));
            free_slot(slot);
            tracing::warn!(error = %e, "presence pill: could not create the indicator");
            None
        }
    }
}

/// Repaint after the session's state changed (controlling ⇄ viewing).
pub(crate) unsafe fn refresh(pill: HWND) {
    let _ = InvalidateRect(pill, None, true);
}

/// Remove the pill (session ended or the panel is being torn down).
pub(crate) unsafe fn destroy(pill: HWND) {
    let _ = DestroyWindow(pill);
}

unsafe fn pill_state<'a>(hwnd: HWND) -> Option<&'a mut PillState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PillState;
    if ptr.is_null() { None } else { Some(&mut *ptr) }
}

/// Place the pill; returns whether it is now on a display (always true in the offscreen lab mode).
unsafe fn apply_size(hwnd: HWND, st: &PillState) -> bool {
    let (x, y, w, h) = placement(st.collapsed, st.slot, st.offscreen);
    let moved = SetWindowPos(hwnd, HWND_TOPMOST, x, y, w, h, SWP_NOACTIVATE).is_ok();
    let _ = InvalidateRect(hwnd, None, true);
    if st.offscreen {
        return true;
    }
    let mut r = RECT::default();
    moved
        && windows::Win32::UI::WindowsAndMessaging::GetWindowRect(hwnd, &mut r).is_ok()
        && !windows::Win32::Graphics::Gdi::MonitorFromRect(&r, windows::Win32::Graphics::Gdi::MONITOR_DEFAULTTONULL).is_invalid()
}

/// Posted to the guest panel after a display change: WPARAM 1 = the pill is on a display, 0 = not.
pub(crate) const WM_RMT_PILL_VISIBLE: u32 = windows::Win32::UI::WindowsAndMessaging::WM_APP + 4;

extern "system" fn pill_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                let cs = lparam.0 as *const CREATESTRUCTW;
                if !cs.is_null() {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
                }
                LRESULT(0)
            }
            // Never take focus from whatever the guest is doing.
            WM_MOUSEACTIVATE => LRESULT(MA_NOACTIVATE as isize),
            // Not dismissable while the session lives (it has no focus, but be explicit about Alt+F4).
            WM_CLOSE => LRESULT(0),
            // Only GENUINE clicks reach here: the guest-window pump drops injected ones (module doc).
            WM_LBUTTONDOWN => {
                if !accepts_click(GetMessageExtraInfo().0 as usize) {
                    return LRESULT(0);
                }
                let x = (lparam.0 & 0xFFFF) as i16 as i32;
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                if let Some(st) = pill_state(hwnd) {
                    match click_action(st.collapsed, x, rc.right - rc.left) {
                        PillClick::Expand => { st.collapsed = false; let _ = apply_size(hwnd, st); }
                        PillClick::Collapse => { st.collapsed = true; let _ = apply_size(hwnd, st); }
                        PillClick::OpenPanel => crate::guest_window::reveal_from_pill(HWND(st.guest as *mut _)),
                    }
                }
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let brush = CreateSolidBrush(COLORREF(PILL_COLOR));
                FillRect(hdc, &rc, brush);
                let _ = DeleteObject(HGDIOBJ(brush.0));
                if let Some(st) = pill_state(hwnd) {
                    if !st.collapsed {
                        let view_only = crate::guest_window::pill_view_only(HWND(st.guest as *mut _));
                        // Segoe UI, as the guest panel uses. Without a selected font GDI draws with the
                        // bitmap SYSTEM font, which has no dash glyph: the collapse control rendered as a
                        // bar (VM-observed 2026-10-23).
                        let font = CreateFontW(-15, 0, 0, 0, FW_SEMIBOLD.0 as i32, 0, 0, 0, DEFAULT_CHARSET.0 as u32,
                            OUT_TT_PRECIS.0 as u32, CLIP_DEFAULT_PRECIS.0 as u32, ANTIALIASED_QUALITY.0 as u32,
                            FF_DONTCARE.0 as u32, w!("Segoe UI"));
                        let previous = SelectObject(hdc, HGDIOBJ(font.0));
                        SetBkMode(hdc, TRANSPARENT);
                        SetTextColor(hdc, COLORREF(TEXT_COLOR));
                        let mut text: Vec<u16> = pill_text(view_only).encode_utf16().collect();
                        let mut body = RECT { right: rc.right - COLLAPSE_W, ..rc };
                        DrawTextW(hdc, &mut text, &mut body, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS);
                        let mut collapse: Vec<u16> = "—".encode_utf16().collect();
                        let mut btn = RECT { left: rc.right - COLLAPSE_W, ..rc };
                        DrawTextW(hdc, &mut collapse, &mut btn, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                        SelectObject(hdc, previous);
                        let _ = DeleteObject(HGDIOBJ(font.0));
                    }
                }
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_DISPLAYCHANGE => {
                // Re-place on the new primary display (resolution or arrangement changed).
                // Tell the panel whether the pill is still on a display: if not, the session is held
                // view-only (host) and the panel becomes the indicator until it is.
                if let Some(st) = pill_state(hwnd) {
                    let visible = apply_size(hwnd, st);
                    let _ = windows::Win32::UI::WindowsAndMessaging::PostMessageW(
                        HWND(st.guest as *mut _), WM_RMT_PILL_VISIBLE, WPARAM(visible as usize), LPARAM(0));
                }
                LRESULT(0)
            }
            WM_NCDESTROY => {
                let ptr = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut PillState;
                if !ptr.is_null() {
                    let st = Box::from_raw(ptr);
                    free_slot(st.slot);
                }
                DefWindowProcW(hwnd, msg, wparam, lparam)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slot table is process-global, and the test harness runs tests in parallel: a test that frees
    /// a slot and expects to get it back raced one taking twelve at once (a gate flake, 2026-10-30:
    /// "a freed slot is reused", left 12, right 0). Every test that touches the table holds this.
    static SLOT_TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn pills_stack_within_the_top_quarter_and_never_leave_the_screen() {
        let h = 1080;
        let rows = (h / 4) / SLOT_STEP;
        assert_eq!(row_for(0, h), 0);
        assert_eq!(row_for(1, h), 1);
        assert_eq!(row_for(500, h), rows - 1, "an overflowing pill shares the last row");
        assert!(row_for(500, h) * SLOT_STEP + PILL_H <= h, "still on screen");
        assert_eq!(row_for(3, 100), 0, "a tiny screen still has one row");
    }

    #[test]
    fn the_wording_says_controlling_or_viewing() {
        assert_eq!(pill_text(false), "A DeskRally technician is controlling this PC");
        assert_eq!(pill_text(true), "A DeskRally technician is viewing this PC");
    }

    #[test]
    fn clicks_collapse_on_the_right_end_open_the_panel_elsewhere_and_expand_a_strip() {
        assert_eq!(click_action(false, PILL_W - 5, PILL_W), PillClick::Collapse);
        assert_eq!(click_action(false, PILL_W - COLLAPSE_W, PILL_W), PillClick::Collapse);
        assert_eq!(click_action(false, PILL_W - COLLAPSE_W - 1, PILL_W), PillClick::OpenPanel);
        assert_eq!(click_action(false, 10, PILL_W), PillClick::OpenPanel);
        assert_eq!(click_action(true, 10, STRIP_W), PillClick::Expand, "a strip only ever expands");
    }

    #[test]
    fn the_technicians_injected_clicks_never_actuate_the_pill() {
        assert!(!accepts_click(crate::input::RMT_INJECTED_TAG), "injected (tagged) input is refused");
        assert!(accepts_click(0), "genuine hardware input carries dwExtraInfo 0");
    }

    /// Wiring: the window procedure applies the provenance rule to every click before acting on it. A real
    /// injected-click test would click on the desktop of the machine running the tests, so the source is
    /// checked instead (needle split with concat! so this test cannot match its own text).
    #[test]
    fn the_click_handler_checks_provenance_first() {
        let src = include_str!("presence_pill.rs");
        let arm = src.find(concat!("WM_LBUTTONDOWN", " => {")).expect("click arm");
        let check = src.find(concat!("if !accepts_click(", "GetMessageExtraInfo().0 as usize)")).expect("provenance check");
        let act = src.find(concat!("match click_action(", "st.collapsed")).expect("click action");
        assert!(arm < check && check < act, "the provenance check must come before any action");
    }

    #[test]
    fn more_sessions_than_any_fixed_table_still_get_unique_slots() {
        let _table = SLOT_TABLE.lock().unwrap_or_else(|e| e.into_inner());
        let taken: Vec<usize> = (0..12).map(|_| take_slot()).collect();
        let mut sorted = taken.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), taken.len(), "every live pill has its own slot");
        for s in taken {
            free_slot(s);
        }
    }

    #[test]
    fn concurrent_sessions_stack_and_slots_are_reused() {
        let _table = SLOT_TABLE.lock().unwrap_or_else(|e| e.into_inner());
        let a = take_slot();
        let b = take_slot();
        assert_ne!(a, b);
        let (_, ya, _, _) = placement(false, a, false);
        let (_, yb, _, _) = placement(false, b, false);
        assert_ne!(ya, yb, "two live sessions never overlap");
        free_slot(a);
        assert_eq!(take_slot(), a, "a freed slot is reused");
        free_slot(a);
        free_slot(b);
    }
}

#[cfg(test)]
mod visibility_wiring_tests {
    #[test]
    fn a_display_change_reports_whether_the_pill_is_on_a_display() {
        let src = include_str!("presence_pill.rs");
        let arm = src.find(concat!("WM_DISPLAY", "CHANGE => {")).expect("the pill handles display changes");
        let body = &src[arm..arm + 700];
        assert!(body.contains(concat!("let visible = apply_", "size(hwnd, st);")), "placement is verified");
        assert!(body.contains(concat!("WM_RMT_PILL_", "VISIBLE")), "and reported to the panel");
        let g = include_str!("guest_window.rs");
        assert!(g.contains(concat!("GuestToHost::Indicator", "Visible(visible)")), "the panel relays it to the host");
    }
}
