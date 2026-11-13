//! Who chose the session tray menu's "End session": the guest, or this agent's injected input?
//!
//! 10-28: the guest (Ed, at his Desktop) chose "End session" in the tray menu. It only revealed the
//! panel, by design, because nothing proved a human chose it: `TrackPopupMenu` runs its own modal
//! loop, so the guest window's pump filter never sees the selecting click, and the thread's
//! `GetMessageExtraInfo` after the menu returns is not documented to belong to that click (Codex
//! tray r1). A technician's injected input must never author the guest's End.
//!
//! The provenance is captured where Windows documents it: low-level hooks installed for the menu's
//! lifetime only, on the menu's own thread (its modal loop services them). Each button and key
//! press records its `dwExtraInfo`. The choice counts as the guest's only when at least one genuine
//! press happened and NO press carried this agent's injection tag ([`crate::input::RMT_INJECTED_TAG`]).
//! Anything else, including a hook that failed to install, falls back to revealing the panel and
//! its own input-filtered End button.
//!
//! The press that SELECTED the item must also have been seen: the last press recorded must be genuine
//! and at most [`SELECTION_FRESH`] before the menu returned (it returns as soon as an item is chosen).
//! Windows silently removes a low-level hook whose thread stalls past `LowLevelHooksTimeout`, after
//! which presses go unseen (Codex tray r2). A selection made after such a removal leaves the last
//! RECORDED press older than the stall, so the choice fails closed and only reveals. The last press
//! must also be one that SELECTS (a button release or Enter), so a fresh navigation key seen by one
//! surviving hook cannot vouch for a click the other, removed hook missed (Codex tray r3).
//!
//! Residual, accepted 10-28: the menu thread stalls past the hook timeout, the guest then presses
//! Enter with nothing highlighted, and within 200 ms an injected click the removed mouse hook missed
//! selects End. The consequence is the technician ending their own session, recorded as the guest's.
//!
//! The hooks never swallow anything: every event is passed on with `CallNextHookEx`.

use std::cell::Cell;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{HINSTANCE, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::VK_RETURN;
use windows::Win32::UI::WindowsAndMessaging::{
    CallNextHookEx, SetWindowsHookExW, UnhookWindowsHookEx, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT,
    MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL, WM_KEYDOWN, WM_LBUTTONDOWN, WM_LBUTTONUP,
    WM_MBUTTONDOWN, WM_MBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_SYSKEYDOWN, WM_XBUTTONDOWN,
    WM_XBUTTONUP,
};

/// How recent the last recorded press must be when the menu returns. A genuine selection returns
/// within milliseconds; the hook-removal timeout is longer than this.
pub(crate) const SELECTION_FRESH: Duration = Duration::from_millis(200);

/// What the hooks saw while the menu was open.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MenuInput {
    pub injected_press: bool,
    /// The last press recorded: whether it was genuine, whether it can select an item, and when.
    pub last_press: Option<(bool, bool, Instant)>,
}

impl MenuInput {
    /// Fold one press (button down/up or key down) with its `dwExtraInfo`, seen at `at`. `selects`:
    /// the press can choose a menu item (a button release or Enter).
    pub(crate) fn note(&mut self, extra_info: usize, selects: bool, at: Instant) {
        let genuine = extra_info != crate::input::RMT_INJECTED_TAG;
        if !genuine {
            self.injected_press = true;
        }
        self.last_press = Some((genuine, selects, at));
    }

    /// The menu choice, made at `returned`, is the guest's own: no injected press was seen, and the
    /// last press seen was a genuine selecting press, recent enough to be the one that selected.
    pub(crate) fn chosen_by_guest(self, returned: Instant) -> bool {
        match self.last_press {
            Some((true, true, at)) => !self.injected_press && returned.saturating_duration_since(at) <= SELECTION_FRESH,
            _ => false,
        }
    }
}

/// True for the mouse messages that can select a menu item (or move to one by pressing).
pub(crate) fn is_mouse_press(message: u32) -> bool {
    matches!(
        message,
        WM_LBUTTONDOWN | WM_LBUTTONUP | WM_RBUTTONDOWN | WM_RBUTTONUP | WM_MBUTTONDOWN | WM_MBUTTONUP
            | WM_XBUTTONDOWN | WM_XBUTTONUP
    )
}

/// True for the keyboard messages that can select a menu item (Enter, a mnemonic) or move to one.
pub(crate) fn is_key_press(message: u32) -> bool {
    matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN)
}

thread_local! {
    static SEEN: Cell<Option<MenuInput>> = const { Cell::new(None) };
}

unsafe extern "system" fn mouse_proc(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if ncode == HC_ACTION as i32 && is_mouse_press(wparam.0 as u32) {
        let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
        record(info.dwExtraInfo, mouse_selects(wparam.0 as u32));
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}

unsafe extern "system" fn keyboard_proc(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if ncode == HC_ACTION as i32 && is_key_press(wparam.0 as u32) {
        let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        record(info.dwExtraInfo, key_selects(info.vkCode));
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}

/// A mouse press that chooses the item under the pointer (the menu selects on release; it is opened
/// with TPM_RIGHTBUTTON, so either button).
pub(crate) fn mouse_selects(message: u32) -> bool {
    matches!(message, WM_LBUTTONUP | WM_RBUTTONUP)
}

/// A key that chooses the highlighted item. The menu has no mnemonics, so only Enter.
pub(crate) fn key_selects(vk: u32) -> bool {
    vk == u32::from(VK_RETURN.0)
}

fn record(extra_info: usize, selects: bool) {
    SEEN.with(|s| {
        if let Some(mut seen) = s.get() {
            seen.note(extra_info, selects, Instant::now());
            s.set(Some(seen));
        }
    });
}

/// Run `menu` (the `TrackPopupMenu` call) with the hooks watching, on this thread. Returns its result
/// and whether the input during it was the guest's own. A hook that cannot be installed yields
/// `false`: the caller then reveals the panel instead of ending.
pub(crate) fn watch<R>(menu: impl FnOnce() -> R) -> (R, bool) {
    unsafe {
        let hmod: HINSTANCE = GetModuleHandleW(None).map(Into::into).unwrap_or_default();
        let mouse = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_proc), hmod, 0).ok();
        let kbd = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_proc), hmod, 0).ok();
        let armed = mouse.is_some() && kbd.is_some();
        if !armed {
            tracing::warn!("guest window: tray menu input hooks unavailable; tray End will only reveal the panel");
        }
        SEEN.with(|s| s.set(Some(MenuInput::default())));
        let result = menu();
        let returned = Instant::now();
        let seen = SEEN.with(|s| s.replace(None)).unwrap_or_default();
        if let Some(h) = mouse {
            let _ = UnhookWindowsHookEx(h);
        }
        if let Some(h) = kbd {
            let _ = UnhookWindowsHookEx(h);
        }
        (result, armed && seen.chosen_by_guest(returned))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_genuine_presses_with_no_injected_one_count_as_the_guest() {
        let t0 = Instant::now();
        let soon = t0 + Duration::from_millis(5);
        let mut t = MenuInput::default();
        assert!(!t.chosen_by_guest(soon), "no press at all is not a guest choice");
        t.note(0, true, t0);
        assert!(t.chosen_by_guest(soon), "a hardware press is the guest's");
        t.note(crate::input::RMT_INJECTED_TAG, true, t0);
        assert!(!t.chosen_by_guest(soon), "any injected press during the menu disqualifies it");
        t.note(0, true, t0);
        assert!(!t.chosen_by_guest(soon), "a later genuine press does not clear an injected one");

        let mut injected_only = MenuInput::default();
        injected_only.note(crate::input::RMT_INJECTED_TAG, true, t0);
        assert!(!injected_only.chosen_by_guest(soon));

        // Another program's injection (not this agent's tag) is treated like hardware, the same rule
        // as the guest window's pump filter and the pill.
        let mut other = MenuInput::default();
        other.note(0xDEAD_BEEF, true, t0);
        assert!(other.chosen_by_guest(soon));
    }

    /// Codex tray r2: a genuine press, then the hook silently removed by a stall, then a technician's
    /// unseen selection. The last RECORDED press is then older than the stall: not the guest's.
    #[test]
    fn a_selection_not_seen_by_the_hooks_fails_closed() {
        let t0 = Instant::now();
        let mut t = MenuInput::default();
        t.note(0, true, t0);
        assert!(t.chosen_by_guest(t0 + SELECTION_FRESH), "a press at the freshness edge still counts");
        assert!(!t.chosen_by_guest(t0 + SELECTION_FRESH + Duration::from_millis(1)), "an older last press is not the selection");
        assert!(!t.chosen_by_guest(t0 + Duration::from_secs(1)), "a stall's worth later is not the selection");
    }

    /// Codex tray r3: the mouse hook removed, the keyboard hook alive, a fresh genuine ARROW key, then
    /// an unseen injected click selects. A navigation key cannot vouch for the selection.
    #[test]
    fn a_fresh_navigation_key_cannot_vouch_for_an_unseen_click() {
        let t0 = Instant::now();
        let mut t = MenuInput::default();
        t.note(0, key_selects(u32::from(windows::Win32::UI::Input::KeyboardAndMouse::VK_DOWN.0)), t0);
        assert!(!t.chosen_by_guest(t0), "the last press seen did not select anything");
        t.note(0, key_selects(u32::from(VK_RETURN.0)), t0);
        assert!(t.chosen_by_guest(t0), "a genuine Enter is a selection");
        t.note(0, mouse_selects(WM_LBUTTONDOWN), t0);
        assert!(!t.chosen_by_guest(t0), "a button DOWN does not select");
        t.note(0, mouse_selects(WM_LBUTTONUP), t0);
        assert!(t.chosen_by_guest(t0), "a genuine button release is a selection");
        assert!(mouse_selects(WM_RBUTTONUP), "the menu is opened with TPM_RIGHTBUTTON");
    }

    #[test]
    fn presses_cover_every_way_a_menu_item_is_chosen() {
        for m in [WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_RBUTTONUP, WM_MBUTTONUP, WM_XBUTTONUP] {
            assert!(is_mouse_press(m));
        }
        assert!(!is_mouse_press(windows::Win32::UI::WindowsAndMessaging::WM_MOUSEMOVE));
        assert!(is_key_press(WM_KEYDOWN) && is_key_press(WM_SYSKEYDOWN));
        assert!(!is_key_press(windows::Win32::UI::WindowsAndMessaging::WM_KEYUP));
    }

    #[test]
    fn watch_reports_nothing_seen_as_not_the_guest() {
        // No input arrives during this "menu", so even with the hooks armed it is not a guest choice.
        let (value, by_guest) = watch(|| 7);
        assert_eq!(value, 7);
        assert!(!by_guest);
        assert!(SEEN.with(|s| s.get()).is_none(), "the watch must disarm");
    }
}
