//! The note dialog behind the tray's "Request help..." (docs/64 D2).
//!
//! A small window on the tray thread with an optional single-line note (at most [`MAX_NOTE_CHARS`] characters, enforced by
//! the EDIT itself) and Send / Cancel. It tells the guest, in plain words, what Send does: the request goes to their
//! support team and a technician may then connect to this computer (D6: an unattended session has no consent gate, so the
//! dialog must not imply one).
//!
//! Input provenance (H-C7): the pump drops this product's own injected keyboard and mouse input BEFORE the dialog manager
//! sees it (the `code_prompt` rule), so a technician's session cannot type into the note or press its buttons.
//!
//! Cancel, Escape, closing, typing and focus changes never depend on where the input came from (a guest whose mouse goes through
//! remapping software reports `IMO_INJECTED` for every click and must still be able to dismiss the dialog and type a note). Only Send is
//! authenticated, and it still accepts a guest's remapped input; see docs/64 (H-C7) for the decision and the residual risk.
//!
//! Send is authenticated AT THE ACTION. A `WM_COMMAND` is a message any same-integrity process can post, so it proves
//! nothing; instead low-level hooks (which only real input and `SendInput` pass through) feed a [`SendAuth`] for the
//! dialog's lifetime, and the command is honoured only when the last genuine press was itself an activation of the Send
//! button: a mouse release over it, or Enter/Space while it has the focus. Space typed in the note box does not count, a
//! posted `WM_COMMAND` / `BM_CLICK` finds no record, and any press that is this product's own injected input (a technician) taints the dialog. If the hooks cannot be
//! installed the dialog fails closed (it is not shown and returns no note).
//!
//! Nothing here is exercised by a test: opening a window on the operator's desktop is exactly what tests must not do. The
//! decision logic around it (`help_request::run_tray_menu`) is tested with a UI double. It is checked in the VM.
#![cfg(windows)]

use std::cell::{Cell, RefCell};
use std::time::Instant;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetStockObject, DEFAULT_GUI_FONT, HFONT};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetFocus, SetFocus, VK_RETURN, VK_SPACE};
use windows::Win32::UI::WindowsAndMessaging::{
    BringWindowToTop, GetForegroundWindow, IsChild, SetWindowTextW, WM_ACTIVATE, WM_SETFOCUS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetDlgItem, GetMessageExtraInfo, GetMessageW,
    GetSystemMetrics, GetWindowTextLengthW, GetWindowTextW, IsDialogMessageW, IsWindow, LoadCursorW, PostQuitMessage,
    RegisterClassW, SendMessageW, SetForegroundWindow, ShowWindow, TranslateMessage, BS_DEFPUSHBUTTON, BS_PUSHBUTTON,
    CS_HREDRAW, CS_VREDRAW, ES_AUTOHSCROLL, HCURSOR, HMENU, IDC_ARROW, MSG, SM_CXSCREEN, SM_CYSCREEN, SW_SHOW,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SETFONT, WNDCLASSW, WS_BORDER,
    WS_CAPTION, WS_CHILD, WS_EX_TOPMOST, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, CallNextHookEx, SetWindowsHookExW,
    UnhookWindowsHookEx, WindowFromPoint, HC_ACTION, HHOOK, KBDLLHOOKSTRUCT, MSLLHOOKSTRUCT, WH_KEYBOARD_LL, WH_MOUSE_LL,
    WM_KEYDOWN, WM_KEYUP, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_MBUTTONDOWN, WM_RBUTTONDOWN, WM_SYSKEYDOWN, WM_SYSKEYUP,
    WM_XBUTTONDOWN,
};
use windows::Win32::Foundation::{HINSTANCE, POINT};

use crate::help_diag::{self, HookInfo, LineContext, OriginProbe, Refusal, Stashed, Via};
use crate::help_request::{HookEvent, InputOrigin, PumpStep, SendAuth, MAX_NOTE_CHARS};

const CLASS: &str = "DeskRallyHelpNote";
/// The standard IDOK / IDCANCEL ids, so Enter and Escape behave as in any dialog.
const ID_SEND: isize = 1;
const ID_CANCEL: isize = 2;
const ID_EDIT: isize = 1001;
/// EM_SETLIMITTEXT (the EDIT's own length cap).
const EM_SETLIMITTEXT: u32 = 0x00C5;
const WIN_W: i32 = 460;
const WIN_H: i32 = 230;

thread_local! {
    /// The outcome the wndproc parks for the pump: `Some(Some(text))` = Send, `Some(None)` = Cancel / closed.
    static OUTCOME: RefCell<Option<Option<String>>> = const { RefCell::new(None) };
    /// Set when the dialog window is destroyed, so the pump stops.
    static DONE: Cell<bool> = const { Cell::new(false) };
    /// What the hooks saw; consulted by the wndproc when Send is commanded.
    static AUTH: RefCell<SendAuth> = RefCell::new(SendAuth::default());
    /// The Send button, for "is the pointer / the focus on it".
    static SEND_BTN: Cell<isize> = const { Cell::new(0) };
    /// True ONLY while `IsDialogMessageW` is processing the one `WM_KEYDOWN(VK_RETURN)` the hook vouched for as a genuine Enter press on
    /// the focused Send button. The command Enter produces is sent synchronously inside that call, so the wndproc accepts Send's command
    /// by this flag alone (no time window): a posted or sent `WM_COMMAND` from anywhere else arrives while the flag is clear.
    static ENTER_DISPATCH: Cell<bool> = const { Cell::new(false) };
    /// Set only while the pump dispatches a Space / left-button release to Send that Windows says came through the input queue: the one place
    /// a mouse/Space gesture can authorize Send (see `SendAuth::send_command_allowed`). A command posted, or sent straight to the window
    /// procedure (which never passes through the pump), arrives while it is clear.
    static RELEASE_DISPATCH: Cell<bool> = const { Cell::new(false) };
    /// The child that last had the keyboard focus, so a re-activation puts it back (see [`focus_target`]).
    static LAST_FOCUS: Cell<isize> = const { Cell::new(0) };
    /// The note box.
    static EDIT: Cell<isize> = const { Cell::new(0) };
    /// The explanatory text under the note box, where a refused Send says so.
    static HINT: Cell<isize> = const { Cell::new(0) };
    /// What Windows said about the origin of the message being processed, the last time the gate asked (refusal log only).
    static LAST_PROBE: Cell<Option<OriginProbe>> = const { Cell::new(None) };
    /// A refusal the loop noticed before dispatching (an Enter with no hook record, a release whose origin was not accepted). The
    /// command that follows takes it as its reason; if no command follows, the loop logs it itself.
    static STASH: Cell<Option<Stashed>> = const { Cell::new(None) };
    /// For a refused Send-bound release: its time stamp and the hook's release time stamp, captured before the gesture is voided (log only).
    static RELEASE_TIMES: Cell<Option<(u32, Option<u32>)>> = const { Cell::new(None) };
}

/// `LLMHF_LOWER_IL_INJECTED` / `LLKHF_LOWER_IL_INJECTED` (the same bit in both hook structures).
const LL_LOWER_IL_INJECTED: u32 = 0x02;
/// The explanation shown when a click or key on Send was refused (instead of silently doing nothing).
const SEND_REFUSED_HINT: &str = "Send was not accepted. Click Send again, or select it and press Enter. If it keeps failing, close this window and choose Request help again.";
const DEFAULT_HINT: &str = "This sends a request to your support team from this computer. A technician may then connect to it.";

/// Whether a message's input-queue origin is one a guest's own input can have: the hardware, or `SendInput` (remapping software, a KVM, an
/// on-screen keyboard), or Windows itself (`IMO_SYSTEM`). A posted or sent message (`IMO_UNAVAILABLE`) and anything unknown is not.
fn origin_is_real_input(origin: i32) -> bool {
    use windows::Win32::UI::Input::{IMO_HARDWARE, IMO_INJECTED, IMO_SYSTEM};
    // IMO_SYSTEM: a message Windows itself generated (a posted look-alike reports IMO_UNAVAILABLE, never this); refusing it could only lock out
    // an input path the lab cannot reproduce.
    origin == IMO_HARDWARE.0 || origin == IMO_INJECTED.0 || origin == IMO_SYSTEM.0
}

/// The gates' class for a probe: an input-queue origin, `IMO_UNAVAILABLE` (admitted only when bound to the hook's record, see [`InputOrigin`]),
/// or refused (an unknown origin, or the query failed).
fn origin_class(p: &OriginProbe) -> InputOrigin {
    use windows::Win32::UI::Input::IMO_UNAVAILABLE;
    if p.error.is_some() {
        InputOrigin::Refused
    } else if origin_is_real_input(p.origin) {
        InputOrigin::Queue
    } else if p.origin == IMO_UNAVAILABLE.0 {
        InputOrigin::Unavailable
    } else {
        InputOrigin::Refused
    }
}

/// Where the keyboard focus goes when the dialog (re)gains it. `DefWindowProc` answers a `WM_ACTIVATE` by focusing the TOP-LEVEL window, which
/// has no use for keys, so after any deactivate/activate cycle (a click on the desktop, the tray menu closing) typing went nowhere while
/// `IsDialogMessage` still turned Escape into Cancel. The last focused child is restored; the note box when there is none (or it is gone).
fn focus_target(last_child: isize, last_child_is_live: bool, edit: isize) -> isize {
    if last_child != 0 && last_child_is_live {
        last_child
    } else {
        edit
    }
}

fn hwnd_isize(h: HWND) -> isize {
    h.0 as isize
}

/// Whether `info`'s mouse message is the LEFT button (down or up).
fn is_left(message: u32) -> bool {
    message == WM_LBUTTONDOWN || message == WM_LBUTTONUP
}

/// What one low-level mouse event means for the Send authorization. The source is judged for EVERY event (movement and wheel included)
/// BEFORE filtering for button presses: a technician's input taints the dialog, a lower-integrity injection voids the gesture in progress.
#[derive(Debug, PartialEq, Eq)]
enum MouseEffect {
    NotGuest(HookEvent),
    Press,
    Ignore,
}

fn mouse_effect(message: u32, event: HookEvent) -> MouseEffect {
    if event != HookEvent::Guest {
        MouseEffect::NotGuest(event)
    } else if crate::tray_menu_provenance::is_mouse_press(message) {
        MouseEffect::Press
    } else {
        MouseEffect::Ignore
    }
}

unsafe extern "system" fn mouse_hook(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let message = wparam.0 as u32;
    if ncode != HC_ACTION as i32 {
        return CallNextHookEx(HHOOK::default(), ncode, wparam, lparam);
    }
    let info = &*(lparam.0 as *const MSLLHOOKSTRUCT);
    let event = SendAuth::classify_hook_event(info.dwExtraInfo, info.flags & LL_LOWER_IL_INJECTED != 0);
    // Every event is judged (a non-guest one taints / voids) and counted for the refusal log, BEFORE the press filter.
    AUTH.with(|a| a.borrow_mut().observe_hook_event(event, HookInfo::mouse(message, info.flags, info.dwExtraInfo), Instant::now()));
    match mouse_effect(message, event) {
        MouseEffect::NotGuest(_) => {} // already admitted above
        MouseEffect::Ignore => {}
        MouseEffect::Press => {
            let send = SEND_BTN.with(|b| b.get());
            // The pointer is "over Send" when the window under it is the Send button.
            let under = hwnd_isize(WindowFromPoint(POINT { x: info.pt.x, y: info.pt.y }));
            let over = send != 0 && under == send;
            AUTH.with(|a| {
                let mut a = a.borrow_mut();
                a.note_hit(under, send);
                let is_down = matches!(message, WM_LBUTTONDOWN | WM_RBUTTONDOWN | WM_MBUTTONDOWN | WM_XBUTTONDOWN);
                if is_down {
                    a.note_mouse_down(is_left(message), over);
                } else {
                    a.note_mouse_up(is_left(message), over, Instant::now());
                    a.note_release_time(info.time);
                }
            });
        }
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}

unsafe extern "system" fn keyboard_hook(ncode: i32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let message = wparam.0 as u32;
    let down = message == WM_KEYDOWN || message == WM_SYSKEYDOWN;
    let up = message == WM_KEYUP || message == WM_SYSKEYUP;
    if ncode == HC_ACTION as i32 && (down || up) {
        let info = &*(lparam.0 as *const KBDLLHOOKSTRUCT);
        let event = SendAuth::classify_hook_event(info.dwExtraInfo, info.flags.0 & LL_LOWER_IL_INJECTED != 0);
        let send = SEND_BTN.with(|b| b.get());
        let activating = (info.vkCode == u32::from(VK_RETURN.0) || info.vkCode == u32::from(VK_SPACE.0))
            && send != 0
            && hwnd_isize(GetFocus()) == send;
        AUTH.with(|a| {
            let mut a = a.borrow_mut();
            if !a.observe_hook_event(event, HookInfo::key(message, info.flags.0, info.dwExtraInfo), Instant::now()) {
                // A technician's key (tainted) or a lower-integrity injection (gesture voided): nothing to record.
            } else if down {
                let now = Instant::now();
                a.note_key_down(info.vkCode, activating, now);
                if activating && info.vkCode == u32::from(VK_RETURN.0) {
                    // Identify the event, so the message loop can match THIS key press and no other Enter message.
                    a.note_enter_down(now, info.time, info.scanCode);
                }
            } else {
                a.note_key_up(info.vkCode, activating, Instant::now());
                a.note_release_time(info.time);
            }
        });
    }
    CallNextHookEx(HHOOK::default(), ncode, wparam, lparam)
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Show the dialog and block (on this thread's own message loop) until it closes. `Some(note)` = the guest pressed Send
/// (the note may be empty); `None` = cancelled, closed, or the window could not be created.
pub(crate) fn prompt_note() -> Option<String> {
    OUTCOME.with(|o| *o.borrow_mut() = None);
    DONE.with(|d| d.set(false));
    AUTH.with(|a| *a.borrow_mut() = SendAuth::default());
    SEND_BTN.with(|b| b.set(0));
    RELEASE_DISPATCH.with(|f| f.set(false));
    LAST_PROBE.with(|c| c.set(None));
    STASH.with(|c| c.set(None));
    LAST_FOCUS.with(|l| l.set(0));
    EDIT.with(|e| e.set(0));
    HINT.with(|h| h.set(0));
    // SAFETY: plain Win32 window creation and a message loop on the calling thread; every handle is local to this call.
    unsafe {
        let hinstance = GetModuleHandleW(None).ok()?;
        let class = wide(CLASS);
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance.into(),
            hIcon: windows::Win32::UI::WindowsAndMessaging::LoadIconW(hinstance, PCWSTR(101usize as *const u16)).unwrap_or_default(),
            lpszClassName: PCWSTR(class.as_ptr()),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or(HCURSOR(std::ptr::null_mut())),
            ..Default::default()
        };
        let _ = RegisterClassW(&wc);
        let title = wide("Request help");
        let x = ((GetSystemMetrics(SM_CXSCREEN) - WIN_W) / 2).max(0);
        let y = ((GetSystemMetrics(SM_CYSCREEN) - WIN_H) / 3).max(0);
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST,
            PCWSTR(class.as_ptr()),
            PCWSTR(title.as_ptr()),
            WINDOW_STYLE(WS_OVERLAPPED.0 | WS_CAPTION.0 | WS_SYSMENU.0),
            x,
            y,
            WIN_W,
            WIN_H,
            None,
            HMENU(std::ptr::null_mut()),
            hinstance,
            None,
        )
        .ok()?;
        // The hooks must be live before the dialog can be used, and are removed when it closes. Without both, Send could
        // not be authenticated, so the dialog is not shown at all.
        // NOTHING is logged between installing the hooks and the pump: a low-level hook thread that is not pumping stalls every process's
        // input until LowLevelHooksTimeout, and a log line is a synchronous file append (the process-integrity token query is a syscall too).
        // Who we are is logged first; the hook results and the foreground answer are carried into the closing line.
        tracing::info!("{}", help_diag::open_line(crate::elevation_win::integrity_rid().ok(), process_session()));
        let hmod: HINSTANCE = hinstance.into();
        let mouse_r = SetWindowsHookExW(WH_MOUSE_LL, Some(mouse_hook), hmod, 0);
        let kbd_r = SetWindowsHookExW(WH_KEYBOARD_LL, Some(keyboard_hook), hmod, 0);
        let mut startup = help_diag::Startup {
            mouse_hook: mouse_r.as_ref().map(|_| ()).map_err(|e| e.code().0),
            kbd_hook: kbd_r.as_ref().map(|_| ()).map_err(|e| e.code().0),
            foreground_granted: None,
        };
        let mouse = mouse_r.ok();
        let kbd = kbd_r.ok();
        let opened = Instant::now();
        let both = mouse.is_some() && kbd.is_some();
        if both {
            let _ = ShowWindow(hwnd, SW_SHOW);
            startup.foreground_granted = Some(bring_to_front(hwnd));
            restore_focus(hwnd);
            run_pump(hwnd);
        } else {
            let _ = DestroyWindow(hwnd);
        }
        if let Some(h) = mouse {
            let _ = UnhookWindowsHookEx(h);
        }
        if let Some(h) = kbd {
            let _ = UnhookWindowsHookEx(h);
        }
        if !both {
            // Logged only now that no hook of ours is installed any more.
            tracing::warn!("help: input hooks unavailable; the request dialog cannot authenticate Send and is not shown");
        }
        let outcome = OUTCOME.with(|o| match &*o.borrow() {
            Some(Some(_)) => "send",
            Some(None) => "cancel",
            None => "closed",
        });
        let summary = AUTH.with(|a| a.borrow().diag().summary_line(&startup, outcome, opened.elapsed().as_millis()));
        tracing::info!("{summary}");
    }
    OUTCOME.with(|o| o.borrow_mut().take()).flatten()
}

/// Windows' account of the input message the thread is processing, see [`origin_is_real_input`] (`real`: hardware, or `SendInput`).
/// Posted and sent messages report `IMO_UNAVAILABLE`; if the query fails `real` is `false` (fail closed) and `error` says why.
fn probe_input_source() -> OriginProbe {
    use windows::Win32::UI::Input::{GetCurrentInputMessageSource, INPUT_MESSAGE_SOURCE};
    let mut src = INPUT_MESSAGE_SOURCE::default();
    // SAFETY: a plain query into a local out-parameter, on the thread that dequeued the message.
    match unsafe { GetCurrentInputMessageSource(&mut src) } {
        Ok(()) => OriginProbe { origin: src.originId.0, device: src.deviceType.0, error: None, real: origin_is_real_input(src.originId.0) },
        Err(e) => OriginProbe { origin: -1, device: -1, error: Some(e.code().0), real: false },
    }
}

/// The gate's question, answered from [`probe_input_source`]; the answer is also kept for the refusal log.
fn current_message_origin() -> InputOrigin {
    let p = probe_input_source();
    LAST_PROBE.with(|c| c.set(Some(p)));
    origin_class(&p)
}

/// This process's session id (logged once when the dialog opens).
fn process_session() -> Option<u32> {
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::Threading::GetCurrentProcessId;
    let mut s = 0u32;
    // SAFETY: a plain query for this process into a local out-parameter.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut s).ok().map(|()| s) }
}

/// Logs the refusal as one line (rate limited, see `help_diag`). Diagnostic only: it decides nothing.
unsafe fn log_refusal(hwnd: HWND, refusal: Stashed) {
    let send = SEND_BTN.with(|b| b.get());
    // The gate's own answer for the refused message if it asked; otherwise a fresh query made now, after the message was dispatched, which
    // the line labels `_at_log` so it is not read as what the gate saw.
    let gate_probe = LAST_PROBE.with(|c| c.get());
    let probe = gate_probe.unwrap_or_else(probe_input_source);
    let ctx = LineContext {
        probe: Some(probe),
        probe_fresh_at_log: gate_probe.is_none(),
        focus_on_send: Some(send != 0 && hwnd_isize(GetFocus()) == send),
        foreground_is_dialog: Some(GetForegroundWindow() == hwnd),
        release_times: RELEASE_TIMES.with(|c| c.get()),
    };
    if let Some(line) = AUTH.with(|a| a.borrow_mut().refusal_line(Instant::now(), refusal, &ctx)) {
        tracing::warn!("{line}");
    }
}

/// Remember the focused child (if the focus is inside the dialog) so a re-activation can restore it.
unsafe fn remember_focus(hwnd: HWND) {
    let f = GetFocus();
    if !f.0.is_null() && f != hwnd && IsChild(hwnd, f).as_bool() {
        LAST_FOCUS.with(|l| l.set(hwnd_isize(f)));
    }
}

/// Put the keyboard focus on the child that should have it (see [`focus_target`]).
unsafe fn restore_focus(hwnd: HWND) {
    let last = LAST_FOCUS.with(|l| l.get());
    let live = last != 0 && IsChild(hwnd, HWND(last as *mut core::ffi::c_void)).as_bool();
    let target = focus_target(last, live, EDIT.with(|e| e.get()));
    if target != 0 {
        let _ = SetFocus(HWND(target as *mut core::ffi::c_void));
    }
}

/// Ask for the foreground. The tray click normally gives the helper foreground rights; if they are spent (the menu closing re-activated
/// another window first) Windows refuses and flashes the taskbar button instead. The dialog is topmost and visible either way, and the
/// guest's click on it activates it, whereupon `WM_ACTIVATE` puts the focus back in the note box. No `AttachThreadInput` fallback: joining an
/// arbitrary foreground thread's input queue lets a hung application hang this thread before its message loop runs (Codex release review,
/// 1.3.20).
///
/// Runs while the input hooks are installed and the pump has not started, so it must not log: it returns whether the foreground was granted
/// and the caller reports that in the closing line.
unsafe fn bring_to_front(hwnd: HWND) -> bool {
    let _ = BringWindowToTop(hwnd);
    SetForegroundWindow(hwnd).as_bool() && GetForegroundWindow() == hwnd
}

/// Replaces the text under the note box with [`SEND_REFUSED_HINT`] (both refusal paths: the WM_COMMAND check and a Send-bound release the pump could not vouch for).
unsafe fn show_send_refused_hint() {
    let hint = HINT.with(|h| h.get());
    if hint != 0 {
        let text = wide(SEND_REFUSED_HINT);
        let _ = SetWindowTextW(HWND(hint as *mut core::ffi::c_void), PCWSTR(text.as_ptr()));
    }
}

unsafe fn run_pump(hwnd: HWND) {
    let mut msg = MSG::default();
    loop {
        let r = GetMessageW(&mut msg, None, 0, 0);
        if r.0 == 0 {
            // WM_QUIT arrived while the dialog was open (the tray is being torn down): pass it to the outer loop and
            // close, never swallow it (the guest-window tray menu has the same rule).
            PostQuitMessage(msg.wParam.0 as i32);
            if IsWindow(hwnd).as_bool() {
                let _ = DestroyWindow(hwnd);
            }
            return;
        }
        if r.0 < 0 {
            return;
        }
        // The technician's injected input never reaches the note box or the buttons.
        let tagged = GetMessageExtraInfo().0 as usize == crate::input::RMT_INJECTED_TAG;
        LAST_PROBE.with(|c| c.set(None));
        STASH.with(|c| c.set(None));
        RELEASE_TIMES.with(|c| c.set(None));
        // Windows' provenance of the message just dequeued (queried now, before any other message function runs). A release with no stated
        // origin counts only when its time stamp is the hook's for the release that completed a genuine gesture on Send (see `InputOrigin`).
        let msg_time = msg.time;
        let release_origin_ok = || match current_message_origin() {
            InputOrigin::Unavailable => {
                let delta = AUTH.with(|a| a.borrow().release_bind_delta(msg_time));
                if let Some(d) = delta {
                    AUTH.with(|a| a.borrow_mut().note_unavailable_admitted(d));
                }
                InputOrigin::Unavailable.admits_release(delta.is_some())
            }
            other => other.admits_release(false),
        };
        let enter_origin_ok = || current_message_origin().admits_enter();
        // A Space / left-button RELEASE addressed to Send is always delivered, never dropped: a button that misses its release keeps the mouse
        // capture and swallows every later click. A mouse/Space gesture can authorize Send only inside the dispatch of such a release that
        // came through the input queue (RELEASE_DISPATCH); a command posted, or sent straight to the window procedure, never runs inside one.
        // Anything addressed to Cancel, the note box or the frame is never classified.
        let target_is_send = hwnd_isize(msg.hwnd) == SEND_BTN.with(|b| b.get());
        let send_release = match SendAuth::pump_step(msg.message, msg.wParam.0, tagged, target_is_send, &release_origin_ok) {
            PumpStep::Drop => continue,
            PumpStep::Deliver => None,
            PumpStep::SendRelease { vouched } => Some(vouched),
        };
        if send_release == Some(false) {
            RELEASE_TIMES.with(|c| c.set(Some((msg_time, AUTH.with(|a| a.borrow().release_hook_time())))));
            // The look-alike may have replaced the guest's real release: leave no gesture behind, and say so exactly as the refused WM_COMMAND does.
            AUTH.with(|a| a.borrow_mut().void_activation());
            show_send_refused_hint();
            // Logged with the command that follows (it is refused as "outside a vouched dispatch"), or on its own after the dispatch.
            STASH.with(|c| c.set(Some((Refusal::ReleaseUnvouched, Via::Release))));
        }
        RELEASE_DISPATCH.with(|f| f.set(send_release == Some(true)));
        // Enter: authorize Send's command only inside the dispatch of the genuine Enter DOWN the hook recorded (see `SendAuth`).
        let is_enter_down = (msg.message == WM_KEYDOWN || msg.message == WM_SYSKEYDOWN) && msg.wParam.0 == usize::from(VK_RETURN.0);
        let genuine_enter = if is_enter_down {
            let verdict = AUTH.with(|a| a.borrow_mut().begin_enter_dispatch_why(Instant::now(), msg.time, msg.lParam.0, &enter_origin_ok));
            // An Enter the hook did not vouch for used to vanish without a trace: say why (with the command it produces, if any).
            if let Err(why) = verdict {
                STASH.with(|c| c.set(Some((Refusal::Enter(why), Via::Enter))));
            }
            verdict.is_ok()
        } else {
            false
        };
        ENTER_DISPATCH.with(|f| f.set(genuine_enter));
        let dialog_handled = IsDialogMessageW(hwnd, &msg).as_bool();
        ENTER_DISPATCH.with(|f| f.set(false));
        if !dialog_handled {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        // Only now, after BOTH dispatch paths (IsDialogMessageW above, DispatchMessageW just now): a Send command either path produced has by
        // now taken the stash (one line, with the real reason), and RELEASE_DISPATCH is still set only if no command consumed it.
        // No command took the finding (Enter with the focus elsewhere, a release that clicked nothing): log it here.
        if let Some((refusal, via)) = STASH.with(|c| c.take()) {
            let on_send = hwnd_isize(GetFocus()) == SEND_BTN.with(|b| b.get());
            if help_diag::undelivered_worth_logging(via, on_send) {
                log_refusal(hwnd, (refusal, via));
            }
        }
        if send_release == Some(true) && RELEASE_DISPATCH.with(|f| f.get()) {
            // The vouched release was dispatched but no Send command consumed the flag.
            AUTH.with(|a| a.borrow_mut().note_release_without_command());
        }
        RELEASE_DISPATCH.with(|f| f.set(false));
        if send_release.is_some() {
            // A gesture is usable only by the release that completed it: one that produced no click (the button had already let go) must not
            // leave a record behind.
            AUTH.with(|a| a.borrow_mut().void_activation());
        }
        if DONE.with(|d| d.get()) {
            return;
        }
        remember_focus(hwnd);
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: standard wndproc on the dialog's own thread.
    unsafe {
        match msg {
            WM_CREATE => {
                build_children(hwnd);
                LRESULT(0)
            }
            WM_ACTIVATE => {
                // Remember which child had the focus on the way out; on the way in `DefWindowProc` focuses the frame, and the WM_SETFOCUS below
                // sends it on.
                if wparam.0 & 0xffff == 0 {
                    remember_focus(hwnd);
                }
                let r = DefWindowProcW(hwnd, msg, wparam, lparam);
                if wparam.0 & 0xffff != 0 && !DONE.with(|d| d.get()) {
                    restore_focus(hwnd);
                }
                r
            }
            WM_SETFOCUS => {
                // The frame itself has nothing to type into: hand the focus to the child that had it (the note box at first).
                if !DONE.with(|d| d.get()) {
                    restore_focus(hwnd);
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                match (wparam.0 & 0xffff) as isize {
                    ID_SEND => {
                        // Honoured only for a genuine activation of the Send button; a posted WM_COMMAND / BM_CLICK, an
                        // Enter in the note box, or a Space typed there finds no matching record and is ignored.
                        let from_button = (wparam.0 >> 16) & 0xffff == 0 && lparam.0 == SEND_BTN.with(|b| b.get());
                        // Genuine Enter: only synchronously inside the dispatch of the Enter DOWN the hook vouched for (single use). Mouse and
                        // Space: only synchronously inside the loop's dispatch of a vouched release to Send (single use), with a completed
                        // genuine gesture that is still fresh. A posted or sent command finds neither.
                        let by_enter = ENTER_DISPATCH.with(|f| f.replace(false));
                        let in_vouched_release = RELEASE_DISPATCH.with(|f| f.replace(false));
                        let mut authorize = || AUTH.with(|a| a.borrow_mut().authorize_why(Instant::now()));
                        if let Err(decision) = SendAuth::send_command_decision(from_button, by_enter, in_vouched_release, &mut authorize) {
                            // One line, naming the failing condition and what was observed (see `help_diag`).
                            let finding = help_diag::reconcile(decision, in_vouched_release, STASH.with(|c| c.take()));
                            log_refusal(hwnd, finding);
                            // Say so, rather than leave the guest clicking at a button that silently does nothing.
                            show_send_refused_hint();
                            return LRESULT(0);
                        }
                        let note = read_note(hwnd);
                        OUTCOME.with(|o| *o.borrow_mut() = Some(Some(note)));
                        let _ = DestroyWindow(hwnd);
                    }
                    ID_CANCEL => {
                        OUTCOME.with(|o| *o.borrow_mut() = Some(None));
                        let _ = DestroyWindow(hwnd);
                    }
                    _ => {}
                }
                LRESULT(0)
            }
            WM_CLOSE => {
                OUTCOME.with(|o| {
                    let mut o = o.borrow_mut();
                    if o.is_none() {
                        *o = Some(None);
                    }
                });
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                DONE.with(|d| d.set(true));
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn read_note(hwnd: HWND) -> String {
    let Ok(edit) = GetDlgItem(hwnd, ID_EDIT as i32) else { return String::new() };
    let len = GetWindowTextLengthW(edit).max(0) as usize;
    let mut buf = vec![0u16; len + 1];
    let n = GetWindowTextW(edit, &mut buf).max(0) as usize;
    String::from_utf16_lossy(&buf[..n.min(len)])
}

unsafe fn build_children(hwnd: HWND) {
    let hinst = GetModuleHandleW(None).unwrap_or_default();
    let font = GetStockObject(DEFAULT_GUI_FONT);
    let mk = |class: &str, text: &str, style: u32, x: i32, y: i32, w: i32, h: i32, id: isize| -> HWND {
        let cls = wide(class);
        let txt = wide(text);
        // SAFETY: the closure does not inherit the enclosing unsafe fn's context; both strings outlive the call.
        unsafe {
            let child = CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                PCWSTR(cls.as_ptr()),
                PCWSTR(txt.as_ptr()),
                WINDOW_STYLE(style),
                x,
                y,
                w,
                h,
                hwnd,
                HMENU(id as *mut core::ffi::c_void),
                hinst,
                None,
            )
            .unwrap_or_default();
            let _ = SendMessageW(child, WM_SETFONT, WPARAM(HFONT(font.0).0 as usize), LPARAM(1));
            child
        }
    };
    let child = WS_CHILD.0 | WS_VISIBLE.0;
    let _ = mk("STATIC", "What do you need help with? (optional)", child, 20, 14, 410, 20, 0);
    let edit = mk("EDIT", "", child | WS_BORDER.0 | WS_TABSTOP.0 | ES_AUTOHSCROLL as u32, 20, 38, 410, 26, ID_EDIT);
    SendMessageW(edit, EM_SETLIMITTEXT, WPARAM(MAX_NOTE_CHARS), LPARAM(0));
    let hint = mk("STATIC", DEFAULT_HINT, child, 20, 78, 410, 52, 0);
    HINT.with(|h| h.set(hwnd_isize(hint)));
    let send = mk("BUTTON", "Send", child | WS_TABSTOP.0 | BS_DEFPUSHBUTTON as u32, 240, 140, 90, 30, ID_SEND);
    SEND_BTN.with(|b| b.set(hwnd_isize(send)));
    let _ = mk("BUTTON", "Cancel", child | WS_TABSTOP.0 | BS_PUSHBUTTON as u32, 340, 140, 90, 30, ID_CANCEL);
    EDIT.with(|e| e.set(hwnd_isize(edit)));
    LAST_FOCUS.with(|l| l.set(hwnd_isize(edit)));
    let _ = SetFocus(edit);
}

#[cfg(test)]
mod mouse_effect_tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{WM_MOUSEHWHEEL, WM_MOUSEMOVE, WM_MOUSEWHEEL};

    // The refusal log must be drained AFTER both dispatch paths, or one refused click logs twice (the loop's line, then the command's generic one).
    // A hooked thread that is not pumping stalls every process's input (LowLevelHooksTimeout): nothing may be logged, and no token queried,
    // between installing the hooks and the pump; the open line comes BEFORE the hooks (1.3.21 release review A1).
    #[test]
    fn nothing_is_logged_while_the_hooks_are_installed_but_not_pumping() {
        let src = include_str!("help_dialog.rs");
        let from = src.find(concat!("pub(crate) fn prompt", "_note")).expect("prompt_note");
        let body = &src[from..];
        let hooks = body.find(concat!("SetWindowsHook", "ExW(WH_MOUSE_LL")).expect("mouse hook install");
        let pump = body.find(concat!("run", "_pump(hwnd)")).expect("pump");
        let open_line = body.find(concat!("help_diag::open", "_line(")).expect("open line");
        assert!(open_line < hooks, "the open line (it queries the token) must come before the hooks");
        let window = &body[hooks..pump];
        for forbidden in [concat!("tracing", "::"), concat!("integrity", "_rid"), concat!("process", "_session"), concat!("open", "_line")] {
            assert!(!window.contains(forbidden), "{forbidden} between the hook install and the pump");
        }
        let bf = src.find(concat!("unsafe fn bring_to", "_front")).expect("bring_to_front");
        let bf_end = src[bf..].find(concat!("unsafe fn show_send", "_refused_hint")).expect("next fn") + bf;
        assert!(!src[bf..bf_end].contains(concat!("tracing", "::info!(")), "bring_to_front runs in that window and must not log");
    }

    #[test]
    fn the_pump_drains_its_refusal_stash_after_dispatching_the_message() {
        let src = include_str!("help_dialog.rs");
        let from = src.find(concat!("unsafe fn run", "_pump")).expect("run_pump");
        let to = src[from..].find(concat!("extern \"system\" fn wnd", "proc")).expect("wndproc") + from;
        let body = &src[from..to];
        let at = |needle: &str| body.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
        let dispatch = at(concat!("Dispatch", "MessageW(&msg)"));
        assert!(dispatch > at(concat!("IsDialog", "MessageW(hwnd")));
        assert!(at(concat!("STASH.with(|c| c.", "take())")) > dispatch, "stash drained before DispatchMessageW");
        assert!(at(concat!("note_release_without", "_command()")) > dispatch, "release accounted before DispatchMessageW");
    }
    // Codex H3 r3: the source is judged for EVERY mouse event, so a technician's or a lower-integrity movement or wheel event counts
    // (clears a pending gesture or a completed authorization) just like such a press.
    #[test]
    fn non_guest_movement_and_wheel_count_like_a_non_guest_press() {
        for event in [HookEvent::Product, HookEvent::LowerIntegrity] {
            for m in [WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_MOUSEHWHEEL, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN] {
                assert_eq!(mouse_effect(m, event), MouseEffect::NotGuest(event), "{event:?} message {m:#x}");
            }
        }
    }

    #[test]
    fn genuine_movement_is_ignored_and_genuine_presses_reach_the_gesture() {
        for m in [WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_MOUSEHWHEEL] {
            assert_eq!(mouse_effect(m, HookEvent::Guest), MouseEffect::Ignore, "genuine message {m:#x}");
        }
        for m in [WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_MBUTTONDOWN] {
            assert_eq!(mouse_effect(m, HookEvent::Guest), MouseEffect::Press, "genuine press {m:#x}");
        }
    }

    // The effect wiring end to end on SendAuth: a genuine Send press then a non-guest move before the release leaves nothing to
    // authorize, whichever kind it is.
    #[test]
    fn a_non_guest_move_between_press_and_release_clears_the_gesture() {
        for event in [HookEvent::Product, HookEvent::LowerIntegrity] {
            let mut a = SendAuth::default();
            a.note_mouse_down(true, true);
            if let MouseEffect::NotGuest(e) = mouse_effect(WM_MOUSEMOVE, event) {
                a.admit_hook_event(e);
            }
            a.note_mouse_up(true, true, Instant::now());
            assert!(!a.authorize(Instant::now()), "a {event:?} move must void the gesture");
        }
    }
}

#[cfg(test)]
mod provenance_and_focus_tests {
    use super::*;
    use windows::Win32::UI::Input::{IMO_HARDWARE, IMO_INJECTED, IMO_SYSTEM, IMO_UNAVAILABLE};

    // A guest's own input is hardware, or SendInput from software that is not this product (remappers report IMO_INJECTED). A posted or sent
    // look-alike is IMO_UNAVAILABLE, and an origin this code does not know is refused.
    #[test]
    fn hardware_and_injected_origins_are_real_input_but_posted_ones_are_not() {
        assert!(origin_is_real_input(IMO_HARDWARE.0));
        assert!(origin_is_real_input(IMO_INJECTED.0));
        assert!(origin_is_real_input(IMO_SYSTEM.0));
        assert!(!origin_is_real_input(IMO_UNAVAILABLE.0));
        assert!(!origin_is_real_input(1234));
        assert!(!origin_is_real_input(-1));
    }

    // The operator's PC (1.3.21) answered IMO_UNAVAILABLE / IMDT_UNAVAILABLE for genuine clicks: that is its own class (admitted only when bound to the
    // hook's record), distinct from an unknown origin and from a failed query, which stay refused.
    #[test]
    fn the_origin_class_separates_unavailable_from_unknown_and_failed() {
        let probe = |origin: i32, error: Option<i32>| OriginProbe { origin, device: 0, error, real: origin_is_real_input(origin) };
        assert_eq!(origin_class(&probe(IMO_HARDWARE.0, None)), InputOrigin::Queue);
        assert_eq!(origin_class(&probe(IMO_INJECTED.0, None)), InputOrigin::Queue);
        assert_eq!(origin_class(&probe(IMO_SYSTEM.0, None)), InputOrigin::Queue);
        assert_eq!(origin_class(&probe(IMO_UNAVAILABLE.0, None)), InputOrigin::Unavailable);
        assert_eq!(origin_class(&probe(1234, None)), InputOrigin::Refused);
        assert_eq!(origin_class(&probe(-1, Some(0x80070005u32 as i32))), InputOrigin::Refused, "a failed query");
        assert_eq!(origin_class(&probe(IMO_HARDWARE.0, Some(1))), InputOrigin::Refused, "an error wins over any origin value");
    }

    // Typing went nowhere after a re-activation because DefWindowProc focuses the frame: the last focused child comes back, the note box
    // otherwise (first show, or the remembered child is gone).
    #[test]
    fn focus_goes_back_to_the_last_child_else_the_note_box() {
        const EDIT: isize = 0x5005c;
        const CANCEL: isize = 0x20206;
        assert_eq!(focus_target(0, false, EDIT), EDIT, "first activation");
        assert_eq!(focus_target(CANCEL, true, EDIT), CANCEL, "the guest had tabbed to Cancel");
        assert_eq!(focus_target(EDIT, true, EDIT), EDIT, "the note box again");
        assert_eq!(focus_target(CANCEL, false, EDIT), EDIT, "the remembered child no longer exists");
        assert_eq!(focus_target(0, true, EDIT), EDIT, "no child remembered");
    }
}
