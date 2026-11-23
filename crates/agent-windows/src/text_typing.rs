//! How an [`InputEvent::Text`](rmt_agent_core::platform::InputEvent::Text) becomes keystrokes.
//!
//! # Why not `VK_PACKET` for everything
//! `KEYEVENTF_UNICODE` (`VK_PACKET`) carries its character OUTSIDE the queued key message, so a target
//! that falls behind its input queue reads the wrong character for queued packets: a burst turns into
//! repeats of a neighbour and drops (the operator's "Type clipboard" into Windows 11 Notepad, 2026-10-24:
//! "example.ttt.  NN", "IIIN", "666"). Bursts are not ours to prevent: network jitter bunches events.
//!
//! # What production types (1.3.9) — see [`plan_unmodified`]
//! Typing NEVER presses Shift, Ctrl, Alt or Win, so it can never release a modifier another session
//! holds nor turn a character into a shortcut (Codex 1.3.9 rounds 1 and 8). A character whose key
//! needs no modifier is that real key alone; every other character is a `VK_PACKET`; Enter and Tab
//! are real taps; and a key a session is physically holding is never pressed by typing.
//!
//! The real-key planner below ([`plan_groups`]) is kept for the tests of the stroke/held machinery.
//!
//! Real keys do NOT cure it either: in the lab VM a 32-character burst of real keystrokes into the same
//! Notepad lost Shift ("IN" became "in"), moved Enters and dropped 55 of 234 characters. Windows 11
//! Notepad processes input asynchronously, so NO keystroke shape survives a burst. The cure is PACING:
//! the sink injects one character at a time with at least [`CHAR_GAP`] between characters, measured
//! across events, so events that the network bunched still reach the target at a typist's pace.
//!
//! Real keys are still preferred over `VK_PACKET` where the layout has the character: VM and remote
//! consoles (a stated use of "Type clipboard") often ignore `VK_PACKET`.
//!
//! # Rules
//! - `\n`, `\r\n` and a lone `\r` press Enter; `\t` presses Tab.
//! - A key needing Ctrl or Alt — INCLUDING AltGr (Ctrl+Alt) — is never pressed: such a character
//!   falls back to `VK_PACKET`. AltGr is LCtrl+RAlt to the system, i.e. a Ctrl+Alt chord to any app or
//!   hotkey that reads it so, and Text must never act as a shortcut (Codex 1.3.9 round 1).
//! - While Ctrl, Alt or Win is physically down (a technician holding one), every character goes as
//!   `VK_PACKET`, so no real key combines with it into a shortcut.
//! - Caps Lock inverts Shift for characters that have case, so the target gets the exact character.
//! - Characters outside the BMP (surrogate pairs) and characters with no key go as `VK_PACKET`.

/// Minimum gap between two typed characters. 10 ms typed the operator's five lines correctly in the lab VM; 15 ms
/// leaves margin for a slower machine (about 66 characters a second, faster than the viewer's 30 ms).
pub(crate) const CHAR_GAP: std::time::Duration = std::time::Duration::from_millis(15);
/// Most pacing one Text event may add. Typing runs on its own thread (the sink's typist), so this only
/// bounds how long one oversized event (an old viewer sent up to 4 KiB) can hold the typing queue:
/// past it, the rest of that event is injected without pauses.
pub(crate) const MAX_PACE_PER_EVENT: std::time::Duration = std::time::Duration::from_secs(10);

/// Longest a single [`sync_with_foreground`] may wait for the target to catch up.
pub(crate) const SYNC_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// Wait (at most `timeout`) until the foreground window's thread is pumping messages again.
///
/// A `WM_NULL` sent with `SendMessageTimeout` is delivered the next time that thread looks at its
/// queue, so this returns at once when the target is keeping up and blocks while it is busy. Pacing
/// alone was not enough: in the lab VM, the first line typed into a fresh Notepad lost a Shift or a
/// character while Notepad's spell checker started on the first words; lines after it were perfect.
/// Syncing after every character means a busy target never has more than one character queued.
/// `SMTO_ABORTIFHUNG` returns at once for a hung window, so a frozen target cannot stall typing.
pub(crate) fn sync_with_foreground(timeout: std::time::Duration) {
    use windows::Win32::Foundation::{LPARAM, WPARAM};
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, SendMessageTimeoutW, SMTO_ABORTIFHUNG, WM_NULL};
    if timeout.is_zero() {
        return;
    }
    // SAFETY: a WM_NULL carries no pointers; the result slot is a local.
    unsafe {
        let fg = GetForegroundWindow();
        if fg.0.is_null() {
            return;
        }
        let mut result = 0usize;
        let _ = SendMessageTimeoutW(fg, WM_NULL, WPARAM(0), LPARAM(0), SMTO_ABORTIFHUNG, timeout.as_millis() as u32, Some(&mut result));
    }
}

/// How long the modifiers (Shift, AltGr) stay down after their key, once the target has caught up.
/// Windows 11 Notepad reads Shift's state when it PROCESSES a key, not when the key was injected: in
/// the lab VM, Shift released in the same SendInput as its key turned capitals into lowercase ("IN" →
/// "in") and, with Caps Lock on, flipped case ("COM", "Net"). A person holds Shift across the key.
pub(crate) const MODIFIER_HOLD: std::time::Duration = std::time::Duration::from_millis(20);

/// Split one character's strokes into the press (modifier downs, key down, key up) and the release
/// (the trailing modifier ups), so the release can wait for the target to process the key.
pub(crate) fn split_release(group: &[Stroke]) -> (&[Stroke], &[Stroke]) {
    let is_mod_up = |s: &Stroke| matches!(*s, Stroke::Vk { vk, down: false, .. } if vk == VK_LSHIFT || vk == VK_LCONTROL || vk == VK_RMENU);
    let mut cut = group.len();
    while cut > 0 && is_mod_up(&group[cut - 1]) {
        cut -= 1;
    }
    group.split_at(cut)
}

/// Virtual-key codes used here.
pub(crate) const VK_RETURN: u16 = 0x0D;
pub(crate) const VK_TAB: u16 = 0x09;
pub(crate) const VK_LSHIFT: u16 = 0xA0;
pub(crate) const VK_SHIFT: u16 = 0x10;
pub(crate) const VK_CONTROL: u16 = 0x11;
pub(crate) const VK_MENU: u16 = 0x12;
pub(crate) const VK_LWIN: u16 = 0x5B;
pub(crate) const VK_RWIN: u16 = 0x5C;
pub(crate) const VK_LCONTROL: u16 = 0xA2;
pub(crate) const VK_RMENU: u16 = 0xA5;

/// The key that produces a character on a layout, and the modifiers it needs (`VkKeyScanExW`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyFor {
    pub vk: u16,
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
}

/// One keystroke to inject, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stroke {
    /// A virtual key; `extended` sets `KEYEVENTF_EXTENDEDKEY` (right Alt).
    Vk { vk: u16, down: bool, extended: bool },
    /// One UTF-16 code unit as `VK_PACKET`.
    Unit { unit: u16, down: bool },
}

fn tap(out: &mut Vec<Stroke>, vk: u16) {
    out.push(Stroke::Vk { vk, down: true, extended: false });
    out.push(Stroke::Vk { vk, down: false, extended: false });
}

fn packet(out: &mut Vec<Stroke>, ch: char) {
    let mut buf = [0u16; 2];
    for &unit in ch.encode_utf16(&mut buf).iter() {
        out.push(Stroke::Unit { unit, down: true });
        out.push(Stroke::Unit { unit, down: false });
    }
}

/// Whether Caps Lock changes this character (it has a distinct other case).
fn has_case(ch: char) -> bool {
    ch.is_lowercase() && ch.to_uppercase().next() != Some(ch) || ch.is_uppercase() && ch.to_lowercase().next() != Some(ch)
}

/// Production plan: one group per character, every printable character a `VK_PACKET`; `\n`, `\r\n`
/// and a lone `\r` an Enter tap and `\t` a Tab tap, unless `key_down` reports that key physically
/// held (then `\r` / `\t` as packets), so typing never presses a key a session is holding.
#[cfg(test)]
pub(crate) fn plan_packets(text: &str, key_down: impl Fn(u16) -> bool) -> Vec<Vec<Stroke>> {
    plan_unmodified(text, false, |_| None, key_down)
}

/// Production plan (1.3.9): never a modifier. A character whose key on the target layout needs NO
/// modifier (and, for a letter, would come out right under the Caps Lock state) is typed as that
/// real key alone; every other character is a `VK_PACKET`; Enter and Tab are real taps. Anything
/// whose key a session is physically holding, and everything while Shift/Ctrl/Alt/Win is physically
/// down (`key_down`), goes as a packet, so typing never presses a key a session holds.
///
/// Why real keys at all: in the lab VM, paced packets still garbled when Notepad was busy (line 1,
/// 32-char events: "333333"; 6-char bunches: one repeat), while unmodified real keys did not; and
/// the characters most text is made of (lowercase, digits, punctuation) need no modifier.
pub(crate) fn plan_unmodified(
    text: &str,
    caps_lock: bool,
    key_for: impl Fn(u16) -> Option<KeyFor>,
    key_down: impl Fn(u16) -> bool,
) -> Vec<Vec<Stroke>> {
    let modifier_down = [VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN].iter().any(|&vk| key_down(vk));
    let mut groups = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        let mut out = Vec::with_capacity(4);
        match ch {
            '\r' | '\n' => {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                // A real Enter while Ctrl/Alt/Win/Shift is held is a chord (Ctrl+Enter): a packet then.
                if modifier_down || key_down(VK_RETURN) { packet(&mut out, '\r') } else { tap(&mut out, VK_RETURN) }
            }
            '\t' => {
                // Alt+Tab switches windows: a packet while any modifier is held.
                if modifier_down || key_down(VK_TAB) { packet(&mut out, '\t') } else { tap(&mut out, VK_TAB) }
            }
            _ => {
                let real = (!modifier_down && (ch as u32) <= 0xFFFF)
                    .then(|| key_for(ch as u16))
                    .flatten()
                    .filter(|k| !k.shift && !k.ctrl && !k.alt)
                    .filter(|_| !(caps_lock && has_case(ch)))
                    .filter(|k| !key_down(k.vk));
                match real {
                    Some(k) => tap(&mut out, k.vk),
                    None => packet(&mut out, ch),
                }
            }
        }
        groups.push(out);
    }
    groups
}

/// Plan the keystrokes for `text`, flattened (see [`plan_groups`]).
#[cfg(test)]
pub(crate) fn plan_text(text: &str, caps_lock: bool, key_for: impl Fn(u16) -> Option<KeyFor>) -> Vec<Stroke> {
    plan_groups(text, caps_lock, key_for).concat()
}

#[cfg(test)]
/// Plan the keystrokes for `text` on a layout described by `key_for` (one BMP code unit to its key, or
/// `None` when the layout has no key for it) with Caps Lock in state `caps_lock`: one group per
/// character (or per Enter/Tab), each complete (every down has its up), to be injected with
/// [`CHAR_GAP`] between groups.
pub(crate) fn plan_groups(text: &str, caps_lock: bool, key_for: impl Fn(u16) -> Option<KeyFor>) -> Vec<Vec<Stroke>> {
    let mut groups = Vec::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        let mut out = Vec::with_capacity(8);
        plan_char(&mut out, ch, &mut chars, caps_lock, &key_for);
        groups.push(out);
    }
    groups
}

#[cfg(test)]
fn plan_char(
    out: &mut Vec<Stroke>,
    ch: char,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    caps_lock: bool,
    key_for: &impl Fn(u16) -> Option<KeyFor>,
) {
    {
        match ch {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                tap(out, VK_RETURN);
                return;
            }
            '\n' => {
                tap(out, VK_RETURN);
                return;
            }
            '\t' => {
                tap(out, VK_TAB);
                return;
            }
            _ => {}
        }
        if (ch as u32) > 0xFFFF {
            packet(out, ch);
            return;
        }
        let Some(k) = key_for(ch as u16) else {
            packet(out, ch);
            return;
        };
        if k.ctrl || k.alt {
            // Ctrl, Alt or AltGr: a shortcut to some app, never pressed for a character.
            packet(out, ch);
            return;
        }
        let shift = k.shift ^ (caps_lock && has_case(ch));
        if shift {
            out.push(Stroke::Vk { vk: VK_LSHIFT, down: true, extended: false });
        }
        out.push(Stroke::Vk { vk: k.vk, down: true, extended: false });
        out.push(Stroke::Vk { vk: k.vk, down: false, extended: false });
        if shift {
            out.push(Stroke::Vk { vk: VK_LSHIFT, down: false, extended: false });
        }
    }
}

/// Decode a `VkKeyScanExW` result: low byte = virtual key, high byte = shift state (1 Shift, 2 Ctrl,
/// 4 Alt; anything higher, e.g. Hankaku, is not pressable here). `-1` means no key.
pub(crate) fn decode_vk_scan(r: i16) -> Option<KeyFor> {
    if r == -1 {
        return None;
    }
    let vk = (r as u16) & 0xFF;
    let mods = ((r as u16) >> 8) & 0xFF;
    if mods & !0x07 != 0 || vk == 0 {
        return None;
    }
    Some(KeyFor { vk, shift: mods & 1 != 0, ctrl: mods & 2 != 0, alt: mods & 4 != 0 })
}

/// Where a Text event's layout comes from. Production reads the foreground window's layout and the
/// Caps Lock state at the moment of injection; tests supply a fixed one.
pub(crate) trait TextLayout: Send + Sync + std::fmt::Debug {
    /// One group of strokes per character, in order (see [`plan_groups`]).
    fn plan(&self, text: &str) -> Vec<Vec<Stroke>>;

    /// Plan with the keys the sessions currently hold (`owned`), so typing never presses one. The
    /// sink calls this UNDER its held lock at the moment of the press. Default: ignore `owned`.
    fn plan_owned(&self, text: &str, _owned: &dyn Fn(u16) -> bool) -> Vec<Vec<Stroke>> {
        self.plan(text)
    }
}

/// Whether `keys` (virtual keys a session holds) include `vk`, counting the left/right variants of a
/// generic modifier (a session may hold VK_LSHIFT while the planner asks about VK_SHIFT).
pub(crate) fn owns(keys: &[u16], vk: u16) -> bool {
    let family: &[u16] = match vk {
        VK_SHIFT => &[VK_SHIFT, 0xA0, 0xA1],
        VK_CONTROL => &[VK_CONTROL, 0xA2, 0xA3],
        VK_MENU => &[VK_MENU, 0xA4, 0xA5],
        _ => &[],
    };
    keys.contains(&vk) || family.iter().any(|k| keys.contains(k))
}

/// The foreground window's keyboard layout (the window the keystrokes will reach), read per event.
#[derive(Debug, Default)]
pub(crate) struct ForegroundLayout;

impl TextLayout for ForegroundLayout {
    fn plan(&self, text: &str) -> Vec<Vec<Stroke>> {
        self.plan_owned(text, &|_| false)
    }

    fn plan_owned(&self, text: &str, owned: &dyn Fn(u16) -> bool) -> Vec<Vec<Stroke>> {
        use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, GetKeyState, GetKeyboardLayout, VkKeyScanExW, VK_CAPITAL};
        use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
        // SAFETY: plain Win32 queries with no pointers held past the call.
        let (hkl, caps) = unsafe {
            let fg = GetForegroundWindow();
            let tid = if fg.0.is_null() { 0 } else { GetWindowThreadProcessId(fg, None) };
            (GetKeyboardLayout(tid), GetKeyState(VK_CAPITAL.0 as i32) & 1 != 0)
        };
        // SAFETY: key-code queries; no pointers.
        plan_unmodified(
            text,
            caps,
            |unit| decode_vk_scan(unsafe { VkKeyScanExW(unit, hkl) }),
            // Held = physically down on the guest OR held by a session through this sink.
            |vk| owned(vk) || unsafe { GetAsyncKeyState(vk as i32) } as u16 & 0x8000 != 0,
        )
    }
}

/// Every character as `VK_PACKET`: the behaviour before 1.3.9, kept for tests of the accounting.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct PacketsOnly;

#[cfg(test)]
impl TextLayout for PacketsOnly {
    fn plan(&self, text: &str) -> Vec<Vec<Stroke>> {
        text.chars().map(|ch| { let mut out = Vec::new(); packet(&mut out, ch); out }).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small US-like layout: letters (Shift for capitals), digits, '.', ' ', '!' (Shift+1),
    /// '@' as AltGr+Q (German-style), '§' on Ctrl alone (a shortcut-only key), nothing for 'é'.
    fn us(unit: u16) -> Option<KeyFor> {
        let ch = char::from_u32(unit as u32)?;
        let k = |vk: u16, shift: bool| Some(KeyFor { vk, shift, ctrl: false, alt: false });
        match ch {
            'a'..='z' => k(ch.to_ascii_uppercase() as u16, false),
            'A'..='Z' => k(ch as u16, true),
            '0'..='9' => k(ch as u16, false),
            '.' => k(0xBE, false),
            ' ' => k(0x20, false),
            '!' => k('1' as u16, true),
            '@' => Some(KeyFor { vk: 'Q' as u16, shift: false, ctrl: true, alt: true }),
            '§' => Some(KeyFor { vk: 'S' as u16, shift: false, ctrl: true, alt: false }),
            _ => None,
        }
    }

    fn vk(vk: u16, down: bool) -> Stroke {
        Stroke::Vk { vk, down, extended: vk == VK_RMENU }
    }
    fn unit(u: u16, down: bool) -> Stroke {
        Stroke::Unit { unit: u, down }
    }

    #[test]
    fn plain_characters_are_real_keys_with_shift_for_capitals() {
        assert_eq!(plan_text("a1.", false, us), vec![
            vk('A' as u16, true), vk('A' as u16, false),
            vk('1' as u16, true), vk('1' as u16, false),
            vk(0xBE, true), vk(0xBE, false),
        ]);
        assert_eq!(plan_text("I!", false, us), vec![
            vk(VK_LSHIFT, true), vk('I' as u16, true), vk('I' as u16, false), vk(VK_LSHIFT, false),
            vk(VK_LSHIFT, true), vk('1' as u16, true), vk('1' as u16, false), vk(VK_LSHIFT, false),
        ]);
    }

    #[test]
    fn line_endings_press_enter_once_and_tab_presses_tab() {
        let enter = vec![vk(VK_RETURN, true), vk(VK_RETURN, false)];
        let tab = vec![vk(VK_TAB, true), vk(VK_TAB, false)];
        let a = vec![vk('A' as u16, true), vk('A' as u16, false)];
        // CRLF is ONE Enter; a lone CR and a lone LF are one Enter each.
        let got = plan_text("a\r\na\ra\na\ta", false, us);
        let want = [a.clone(), enter.clone(), a.clone(), enter.clone(), a.clone(), enter, a.clone(), tab, a].concat();
        assert_eq!(got, want);
    }

    #[test]
    fn caps_lock_inverts_shift_for_letters_only() {
        // Caps on: 'a' needs Shift to stay lowercase, 'A' needs none, '1' is unaffected.
        assert_eq!(plan_text("aA1", true, us), vec![
            vk(VK_LSHIFT, true), vk('A' as u16, true), vk('A' as u16, false), vk(VK_LSHIFT, false),
            vk('A' as u16, true), vk('A' as u16, false),
            vk('1' as u16, true), vk('1' as u16, false),
        ]);
    }

    #[test]
    fn altgr_and_ctrl_alone_are_never_pressed_they_fall_back_to_packets() {
        // '@' needs AltGr (Ctrl+Alt) on this layout: a Ctrl+Alt chord to some apps, so a packet.
        assert_eq!(plan_text("@", false, us), vec![unit(0x40, true), unit(0x40, false)]);
        // '§' would need Ctrl alone: never pressed as a shortcut, sent as VK_PACKET instead.
        assert_eq!(plan_text("§", false, us), vec![unit(0xA7, true), unit(0xA7, false)]);
    }

    #[test]
    fn no_key_and_astral_characters_fall_back_to_packets() {
        assert_eq!(plan_text("é", false, us), vec![unit(0xE9, true), unit(0xE9, false)]);
        assert_eq!(plan_text("😀", false, us), vec![
            unit(0xD83D, true), unit(0xD83D, false), unit(0xDE00, true), unit(0xDE00, false),
        ]);
    }

    #[test]
    fn every_down_has_its_up_and_modifiers_are_released_last() {
        let s = plan_text("Hello World!@\tx\r\né😀", false, us);
        let mut downs: Vec<(u16, bool)> = Vec::new();
        for st in &s {
            let (key, down) = match *st {
                Stroke::Vk { vk, down, .. } => ((vk, true), down),
                Stroke::Unit { unit, down } => ((unit, false), down),
            };
            if down { downs.push(key) } else {
                let i = downs.iter().rposition(|d| *d == key).expect("an up without its down");
                downs.remove(i);
            }
        }
        assert!(downs.is_empty(), "left down: {downs:?}");
    }

    #[test]
    fn one_complete_group_per_character() {
        let g = plan_groups("aB\r\n😀", false, us);
        assert_eq!(g.len(), 4, "a, B, one Enter for CRLF, one emoji");
        assert_eq!(g[1], vec![vk(VK_LSHIFT, true), vk('B' as u16, true), vk('B' as u16, false), vk(VK_LSHIFT, false)]);
        assert_eq!(g[3].len(), 4, "both surrogate units travel in ONE group");
    }

    #[test]
    fn the_release_is_only_the_trailing_modifier_ups() {
        let g = plan_groups("B@a", false, us);
        let (press, release) = split_release(&g[0]);
        assert_eq!(press, &[vk(VK_LSHIFT, true), vk('B' as u16, true), vk('B' as u16, false)]);
        assert_eq!(release, &[vk(VK_LSHIFT, false)]);
        let (press, release) = split_release(&g[1]);
        assert_eq!((press.len(), release.len()), (2, 0), "an AltGr character is a packet now, nothing held");
        let (press, release) = split_release(&g[2]);
        assert_eq!((press.len(), release.len()), (2, 0), "an unmodified key has nothing to hold");
    }

    #[test]
    fn production_types_packets_and_taps_only_enter_and_tab() {
        let none = |_: u16| false;
        assert_eq!(plan_packets("aB@", none), vec![
            vec![unit(0x61, true), unit(0x61, false)],
            vec![unit(0x42, true), unit(0x42, false)],
            vec![unit(0x40, true), unit(0x40, false)],
        ], "no Shift, no AltGr: every printable character is a packet");
        assert_eq!(plan_packets("a\r\nb\tc", none).concat(), vec![
            unit(0x61, true), unit(0x61, false),
            vk(VK_RETURN, true), vk(VK_RETURN, false),
            unit(0x62, true), unit(0x62, false),
            vk(VK_TAB, true), vk(VK_TAB, false),
            unit(0x63, true), unit(0x63, false),
        ]);
        // A session physically holding Enter/Tab: typing must not press (and so release) them.
        let held = |vk: u16| vk == VK_RETURN || vk == VK_TAB;
        assert_eq!(plan_packets("\n\t", held).concat(), vec![
            unit(0x0D, true), unit(0x0D, false), unit(0x09, true), unit(0x09, false),
        ]);
        for g in plan_packets("Hello World!\n\t", none) {
            for st in g {
                if let Stroke::Vk { vk, .. } = st {
                    assert!(vk == VK_RETURN || vk == VK_TAB, "typing pressed a key other than Enter/Tab: {vk:#x}");
                }
            }
        }
    }

    #[test]
    fn production_presses_no_modifier_and_real_keys_only_when_unmodified() {
        let none = |_: u16| false;
        let plan = |t: &str, caps: bool, down: &dyn Fn(u16) -> bool| plan_unmodified(t, caps, us, down).concat();
        // lowercase + digit + '.': real keys alone; 'B' (needs Shift), '!' (Shift), '@' (AltGr): packets
        assert_eq!(plan("a1.B!@", false, &none), vec![
            vk('A' as u16, true), vk('A' as u16, false),
            vk('1' as u16, true), vk('1' as u16, false),
            vk(0xBE, true), vk(0xBE, false),
            unit(0x42, true), unit(0x42, false),
            unit(0x21, true), unit(0x21, false),
            unit(0x40, true), unit(0x40, false),
        ]);
        // Caps Lock on: a lowercase letter would come out upper as a bare key, so it is a packet
        assert_eq!(plan("a1", true, &none), vec![unit(0x61, true), unit(0x61, false), vk('1' as u16, true), vk('1' as u16, false)]);
        // Ctrl held: a newline is a packet, not Ctrl+Enter; Alt held: a tab is a packet, not Alt+Tab
        assert_eq!(plan("\n", false, &|vk| vk == VK_CONTROL), vec![unit(0x0D, true), unit(0x0D, false)]);
        assert_eq!(plan("\t", false, &|vk| vk == VK_MENU), vec![unit(0x09, true), unit(0x09, false)]);
        assert!(owns(&[0xA0], VK_SHIFT) && owns(&[0xA5], VK_MENU) && owns(&[0x41], 0x41) && !owns(&[0x41], 0x42));
        // A session holding Shift: everything is a packet (no real key combines with it)
        assert_eq!(plan("a", false, &|vk| vk == VK_SHIFT), vec![unit(0x61, true), unit(0x61, false)]);
        // A session holding the very key: that character is a packet
        assert_eq!(plan("a", false, &|vk| vk == 'A' as u16), vec![unit(0x61, true), unit(0x61, false)]);
        // Never a modifier, whatever the text
        for st in plan("Hello World! @Ab\n\t", false, &none) {
            if let Stroke::Vk { vk, .. } = st {
                assert!(![VK_LSHIFT, VK_SHIFT, VK_LCONTROL, VK_CONTROL, VK_RMENU, VK_MENU, VK_LWIN, VK_RWIN].contains(&vk), "typing pressed a modifier {vk:#x}");
            }
        }
    }

    #[test]
    fn vk_scan_results_decode() {
        assert_eq!(decode_vk_scan(-1), None);
        assert_eq!(decode_vk_scan(0x0141), Some(KeyFor { vk: 0x41, shift: true, ctrl: false, alt: false }));
        assert_eq!(decode_vk_scan(0x0651), Some(KeyFor { vk: 0x51, shift: false, ctrl: true, alt: true }));
        // Hankaku (8) and above: not pressable here.
        assert_eq!(decode_vk_scan(0x0841), None);
    }
}
