//! The typed-code prompt window for the support client (docs/27 step 10, docs/28 §3).
//!
//! A modal window that asks the customer for the session code and redeems it WITHOUT ever tearing
//! itself down between the ask and the answer (a one-time code cannot be redeemed twice, so
//! prompt→close→redeem→reopen is not an option). The window stays up during the blocking redeem —
//! which runs on a worker thread so the UI never freezes — and reports a rejected code inline,
//! re-selecting the text, capped at [`MAX_ATTEMPTS`] tries per launch.
//!
//! # Two things a VM probe cannot see, so they are pinned by pure tests here
//!
//! 1. **Pump ordering.** The message pump must drop this product's own injected keystrokes
//!    ([`crate::input::RMT_INJECTED_TAG`]) BEFORE `IsDialogMessageW`, not after — otherwise
//!    `IsDialogMessageW` translates and dispatches an injected key into the code box before the
//!    filter runs, and a remote tool could type into the field. [`classify_pump_message`] is the
//!    decision, called first in the real pump; the ordering bug is invisible on screen.
//! 2. **Enter does not submit.** Connect requires a click or Space, never Enter — because the
//!    keystroke that submits the code must not be the same keystroke that, a moment later, could
//!    fall through to the consent dialog's default. The window has no default pushbutton and `IDOK`
//!    is a no-op ([`wndproc`]).
//!
//! Everything visual (DPI crispness, High Contrast, Narrator, the second-monitor drag) is a
//! RECORDED HUMAN CHECKLIST in docs/27 step 10; it cannot be asserted by a green gate.

use crate::attend::{AttendRedeem, AttendRedeemError};
use std::path::PathBuf;

/// The phase the prompt is in, mirrored into the window caption so a VM probe (which reads the
/// caption cross-integrity with `GetWindowTextW`) can observe progress it cannot see pixels for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PromptPhase {
    /// Waiting for the customer to type and submit a code.
    Entering,
    /// A redeem is in flight on the worker thread; the field is disabled.
    Connecting,
    /// The last code was rejected; the message is shown inline and the field re-selected.
    Error,
}

/// Max redeem attempts per launch. A mistyped code is common; an unbounded retry loop against the
/// control plane from a public binary is not. After this the window reports it and the customer must
/// relaunch (and, realistically, get a fresh code).
pub const MAX_ATTEMPTS: u32 = 5;

/// The window caption for a phase. Pure and tested because the caption is the VM-readable signal.
/// It names the product (never the code — the caption is world-readable via `GetWindowTextW`).
pub fn caption_for(phase: PromptPhase, product: &str) -> String {
    let product = if product.trim().is_empty() { "Support" } else { product.trim() };
    match phase {
        PromptPhase::Entering => format!("{product} — enter your code"),
        PromptPhase::Connecting => format!("{product} — connecting"),
        PromptPhase::Error => format!("{product} — check the code"),
    }
}

/// What the pump should do with a retrieved message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PumpAction {
    /// Drop it before `IsDialogMessageW`/dispatch — an injected keystroke or mouse actuator.
    Drop,
    /// Offer it to `IsDialogMessageW`, then translate/dispatch if the dialog did not consume it.
    Process,
}

/// Decide a message's fate from its id and whether it was injected by THIS product.
///
/// Called FIRST in the real pump — before `IsDialogMessageW` — which is the whole point: an injected
/// keystroke must never reach the dialog manager, because the dialog manager would translate and
/// dispatch it into the code field. Genuine hardware input carries `dwExtraInfo == 0` and is
/// `Process`. Reuses the guest window's message classifiers so the two windows agree on what counts
/// as a keystroke / a mouse actuator.
pub fn classify_pump_message(message: u32, injected: bool) -> PumpAction {
    if injected
        && (crate::guest_window::is_keyboard_message(message)
            || crate::guest_window::is_mouse_actuator_message(message))
    {
        PumpAction::Drop
    } else {
        PumpAction::Process
    }
}

/// The result of showing the prompt.
#[derive(Debug)]
pub enum PromptOutcome {
    /// The customer entered a code that redeemed successfully.
    Redeemed(Box<AttendRedeem>),
    /// The customer cancelled, closed the window, or exhausted [`MAX_ATTEMPTS`].
    Cancelled,
}

/// Configuration for the prompt window.
pub struct PromptConfig {
    /// The deployment's product name, for the caption and headline.
    pub product: String,
    /// The control-plane host the session will connect to — shown so the customer sees where their
    /// machine is about to be handed (the same fact the consent dialog leads with).
    pub control_plane_host: String,
}

// ================================================================================================
// The window. Unrunnable here (a real desktop is required); the pure logic above is what the gate
// checks, and docs/27 step 10 carries the human/VM checklist for everything visual.
// ================================================================================================

use std::sync::Arc;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{EM_SETPASSWORDCHAR, EM_SETSEL};
use windows::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    GetMessageExtraInfo, GetParent, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW,
    IsDialogMessageW, LoadCursorW, PostMessageW, PostQuitMessage, RegisterClassW, SendMessageW,
    SetForegroundWindow, SetWindowLongPtrW, SetWindowTextW, ShowWindow, TranslateMessage,
    BM_GETCHECK, BS_AUTOCHECKBOX, BS_PUSHBUTTON, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW,
    GWLP_USERDATA, GWLP_WNDPROC, HCURSOR, HMENU, IDC_ARROW, MSG, SW_SHOW, WINDOW_STYLE, WM_APP,
    WM_CHAR, WM_COMMAND, WM_CREATE, WM_DESTROY, WM_SETTEXT, WNDCLASSW, WS_BORDER, WS_CAPTION,
    WS_CHILD, WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE, ES_AUTOHSCROLL, ES_CENTER,
    ES_PASSWORD,
};

/// The worker thread posts the redeem result back with this message; `lParam` is a boxed
/// `Result<AttendRedeem, AttendRedeemError>` reclaimed in the wndproc.
const WM_REDEEM_RESULT: u32 = WM_APP + 7;

// Control ids.
const ID_EDIT: isize = 1001;
const ID_CONNECT: isize = 1002;
const ID_CANCEL: isize = 1003;
const ID_SHOW: isize = 1004;

type RedeemFn = Arc<dyn Fn(&str) -> Result<AttendRedeem, AttendRedeemError> + Send + Sync>;

/// Window state behind `GWLP_USERDATA`.
struct PromptState {
    redeem: RedeemFn,
    product: String,
    host: String,
    attempts: u32,
    busy: bool,
    /// Code pre-read from the `session.code` sidecar; pre-fills the EDIT on WM_CREATE and shifts
    /// focus to the Connect button so the guest just presses Space (no typing required).
    prefill: Option<String>,
    edit: HWND,
    connect: HWND,
    cancel: HWND,
    show: HWND,
    status: HWND,
    /// The EDIT's original wndproc, for the subclass to chain to.
    edit_proc: isize,
}

/// Show the modal code prompt. Blocks on its own message loop until the customer redeems a code or
/// cancels. `redeem` is called on a WORKER thread so the window never freezes during the blocking
/// HTTP redeem; it must be cheap to clone (an `Arc`) and `Send + Sync`.
///
/// Returns [`PromptOutcome::Redeemed`] with the server's response, or [`PromptOutcome::Cancelled`].
pub fn prompt_for_code<F>(cfg: PromptConfig, redeem: F) -> PromptOutcome
where
    F: Fn(&str) -> Result<AttendRedeem, AttendRedeemError> + Send + Sync + 'static,
{
    let prefill = current_exe_dir().and_then(|dir| crate::support::read_sidecar_code(&dir));
    let state = Box::new(PromptState {
        redeem: Arc::new(redeem),
        product: cfg.product,
        host: cfg.control_plane_host,
        attempts: 0,
        busy: false,
        prefill,
        edit: HWND::default(),
        connect: HWND::default(),
        cancel: HWND::default(),
        show: HWND::default(),
        status: HWND::default(),
        edit_proc: 0,
    });
    // SAFETY: standard Win32 window lifecycle; the state box is reclaimed on WM_DESTROY.
    unsafe {
        match create_prompt_window(state) {
            Ok(hwnd) => run_pump(hwnd),
            Err(e) => {
                tracing::error!(error = %e, "code prompt: could not create the window");
                PromptOutcome::Cancelled
            }
        }
    }
}

/// A STABLE class name for the prompt window.
///
/// docs/27 step 10 proposed a per-run RANDOMIZED class name; that is superseded here because step 11's
/// single-instance behaviour (docs/28 §3.2 #6) finds the existing window with `FindWindowW`, which
/// needs a class it can name. A short-lived modal gains little from a random class, and RegisterClassW
/// tolerates re-registration, so a stable name costs nothing and buys the single-instance lookup.
const PROMPT_CLASS: &str = "DeskRallyCodePrompt";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// If a prompt window from a prior launch already exists on this desktop, bring it to the front and
/// return `true` (the new launch should exit). The single-instance HINT for `support_main`: it uses
/// `FindWindowW` by class, never a `Global\` mutex (which needs `SeCreateGlobalPrivilege` a standard
/// user does not hold — and running as a standard user is the whole premise).
pub fn focus_existing_prompt() -> bool {
    let class = wide(PROMPT_CLASS);
    // SAFETY: FindWindowW/SetForegroundWindow take a class atom string and an HWND; read-only.
    unsafe {
        match windows::Win32::UI::WindowsAndMessaging::FindWindowW(PCWSTR(class.as_ptr()), PCWSTR::null()) {
            Ok(hwnd) if !hwnd.is_invalid() => {
                if windows::Win32::UI::WindowsAndMessaging::IsIconic(hwnd).as_bool() {
                    let _ = ShowWindow(hwnd, windows::Win32::UI::WindowsAndMessaging::SW_RESTORE);
                }
                let _ = SetForegroundWindow(hwnd);
                true
            }
            _ => false,
        }
    }
}

unsafe fn create_prompt_window(state: Box<PromptState>) -> Result<HWND, String> {
    let hinstance = GetModuleHandleW(None).map_err(|e| format!("GetModuleHandleW: {e}"))?;
    let class = wide(PROMPT_CLASS);
    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        hInstance: hinstance.into(),
        // Shared resource handle: Windows owns its lifetime. ID 101 is embedded in the support EXE.
        hIcon: windows::Win32::UI::WindowsAndMessaging::LoadIconW(
            hinstance, PCWSTR(101usize as *const u16),
        ).unwrap_or_default(),
        lpszClassName: PCWSTR(class.as_ptr()),
        hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or(HCURSOR(std::ptr::null_mut())),
        ..Default::default()
    };
    let _ = RegisterClassW(&wc);

    let title = wide(&caption_for(PromptPhase::Entering, &state.product));
    let hwnd = CreateWindowExW(
        Default::default(),
        PCWSTR(class.as_ptr()),
        PCWSTR(title.as_ptr()),
        WINDOW_STYLE(WS_OVERLAPPED.0 | WS_CAPTION.0 | WS_SYSMENU.0),
        // Centre-ish; the human checklist confirms placement + DPI. Fixed size for a simple modal.
        200,
        200,
        420,
        320,
        None,
        HMENU(std::ptr::null_mut()),
        hinstance,
        Some(Box::into_raw(state) as *const _),
    )
    .map_err(|e| format!("CreateWindowExW: {e}"))?;

    let _ = ShowWindow(hwnd, SW_SHOW);
    let _ = SetForegroundWindow(hwnd);
    Ok(hwnd)
}

/// The message pump. Drops this product's own injected input BEFORE `IsDialogMessageW` (the
/// ordering [`classify_pump_message`] and its test exist for), then lets the dialog manager handle
/// Tab/Space navigation, then translates/dispatches.
unsafe fn run_pump(hwnd: HWND) -> PromptOutcome {
    let mut msg = MSG::default();
    while GetMessageW(&mut msg, None, 0, 0).0 > 0 {
        let injected = GetMessageExtraInfo().0 as usize == crate::input::RMT_INJECTED_TAG;
        if classify_pump_message(msg.message, injected) == PumpAction::Drop {
            continue;
        }
        // IsDialogMessageW gives Tab/Space/Escape navigation across the child controls. It returns
        // TRUE when it consumed the message.
        if IsDialogMessageW(hwnd, &msg).as_bool() {
            continue;
        }
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    // The window is gone; reclaim the outcome the wndproc stashed before DestroyWindow. It parked
    // the boxed outcome on the (already-destroyed) window is not possible, so the wndproc instead
    // stored it via a thread-local set just before PostQuitMessage.
    LAST_OUTCOME.with(|c| c.borrow_mut().take()).unwrap_or(PromptOutcome::Cancelled)
}

thread_local! {
    /// The pump and the wndproc run on the same thread; the wndproc parks the final outcome here
    /// just before `PostQuitMessage`, and the pump takes it after the loop ends. Simpler and safer
    /// than trying to read state off a window that is being destroyed.
    static LAST_OUTCOME: std::cell::RefCell<Option<PromptOutcome>> = const { std::cell::RefCell::new(None) };
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    // SAFETY: standard wndproc; the state pointer is installed on WM_CREATE and reclaimed on
    // WM_DESTROY.
    unsafe {
        match msg {
            WM_CREATE => {
                let cs = lparam.0 as *const CREATESTRUCTW;
                let state_ptr = (*cs).lpCreateParams as *mut PromptState;
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, state_ptr as isize);
                build_children(hwnd, &mut *state_ptr);
                LRESULT(0)
            }
            WM_COMMAND => {
                if let Some(state) = state_of(hwnd) {
                    let id = (wparam.0 & 0xffff) as isize;
                    match id {
                        ID_CONNECT => on_connect(hwnd, state),
                        ID_CANCEL => finish(hwnd, PromptOutcome::Cancelled),
                        ID_SHOW => toggle_show(state),
                        // IDOK (Enter) deliberately does nothing: Connect requires a click or Space,
                        // never Enter. See the module docs.
                        _ => {}
                    }
                }
                LRESULT(0)
            }
            WM_REDEEM_RESULT => {
                let boxed = Box::from_raw(lparam.0 as *mut Result<AttendRedeem, AttendRedeemError>);
                on_redeem_result(hwnd, *boxed);
                LRESULT(0)
            }
            WM_DESTROY => {
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PromptState;
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn state_of<'a>(hwnd: HWND) -> Option<&'a mut PromptState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut PromptState;
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

unsafe fn build_children(hwnd: HWND, state: &mut PromptState) {
    let hinst = GetModuleHandleW(None).unwrap_or_default();
    let mk = |class: &str, text: &str, style: WINDOW_STYLE, x, y, w, h, id: isize| -> HWND {
        let cls = wide(class);
        let txt = wide(text);
        // The closure does not inherit the enclosing `unsafe fn`'s unsafe context.
        unsafe {
            CreateWindowExW(
                Default::default(),
                PCWSTR(cls.as_ptr()),
                PCWSTR(txt.as_ptr()),
                style,
                x,
                y,
                w,
                h,
                hwnd,
                HMENU(id as *mut core::ffi::c_void),
                hinst,
                None,
            )
            .unwrap_or_default()
        }
    };

    let child = WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0);
    let _ = mk(
        "STATIC",
        "Enter the session code your technician gave you.",
        child,
        20,
        16,
        380,
        24,
        0,
    );
    let _ = mk(
        "STATIC",
        &format!("This will connect this computer to: {}", state.host),
        child,
        20,
        44,
        380,
        24,
        0,
    );
    state.edit = mk(
        "EDIT",
        "",
        WINDOW_STYLE(
            WS_CHILD.0
                | WS_VISIBLE.0
                | WS_BORDER.0
                | WS_TABSTOP.0
                | ES_CENTER as u32
                | ES_AUTOHSCROLL as u32
                | ES_PASSWORD as u32,
        ),
        20,
        84,
        380,
        30,
        ID_EDIT,
    );
    state.show = mk(
        "BUTTON",
        "Show code",
        WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_AUTOCHECKBOX as u32),
        20,
        122,
        150,
        24,
        ID_SHOW,
    );
    state.status = mk("STATIC", "", child, 20, 156, 380, 48, 0);
    state.connect = mk(
        "BUTTON",
        "Connect",
        WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32),
        210,
        250,
        90,
        30,
        ID_CONNECT,
    );
    state.cancel = mk(
        "BUTTON",
        "Cancel",
        WINDOW_STYLE(WS_CHILD.0 | WS_VISIBLE.0 | WS_TABSTOP.0 | BS_PUSHBUTTON as u32),
        310,
        250,
        90,
        30,
        ID_CANCEL,
    );

    // Mask with a bullet by default; the Show-code box clears it (docs/28 §2 #6: masking blocks a
    // same-user WM_GETTEXT read; the toggle lapses that deliberately for typo-fixing).
    SendMessageW(state.edit, EM_SETPASSWORDCHAR, WPARAM(0x25CF), LPARAM(0));
    // Subclass the EDIT so a disallowed character never reaches the buffer (the filter runs on the
    // raw WM_CHAR; ES_UPPERCASE is display-only and case is irrelevant to code_char_is_safe).
    state.edit_proc =
        SetWindowLongPtrW(state.edit, GWLP_WNDPROC, edit_subclass as *const () as isize);
    // If a sidecar code was found, pre-fill the EDIT and focus Connect so the guest presses Space
    // to connect with no typing. The code is NOT auto-submitted — the user must click Connect.
    if let Some(ref code) = state.prefill {
        let w = wide(code);
        SendMessageW(state.edit, WM_SETTEXT, WPARAM(0), LPARAM(w.as_ptr() as isize));
        let _ = SetFocus(state.connect);
    } else {
        let _ = SetFocus(state.edit);
    }
}

/// The EDIT subclass: drop a character the allow-list rejects, chain everything else (including
/// control characters like backspace, Ctrl+A, Ctrl+V) to the original EDIT proc.
extern "system" fn edit_subclass(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        let parent = GetParent(hwnd).unwrap_or_default();
        let original = state_of(parent).map(|s| s.edit_proc).unwrap_or(0);
        if msg == WM_CHAR {
            let ch = char::from_u32(wparam.0 as u32);
            if let Some(c) = ch {
                // Let control chars through (editing/shortcuts); filter only printable characters.
                if !c.is_control() && !crate::uri::code_char_is_safe(c) {
                    return LRESULT(0); // eat it — nothing appears, exactly as intended
                }
            }
        }
        if original != 0 {
            let proc: unsafe extern "system" fn(HWND, u32, WPARAM, LPARAM) -> LRESULT =
                std::mem::transmute(original);
            proc(hwnd, msg, wparam, lparam)
        } else {
            DefWindowProcW(hwnd, msg, wparam, lparam)
        }
    }
}

unsafe fn toggle_show(state: &mut PromptState) {
    // BST_CHECKED == 1. Read the checkbox and set/clear the password char accordingly.
    let checked = SendMessageW(state.show, BM_GETCHECK, WPARAM(0), LPARAM(0));
    let mask: usize = if checked.0 == 1 { 0 } else { 0x25CF };
    SendMessageW(state.edit, EM_SETPASSWORDCHAR, WPARAM(mask), LPARAM(0));
    // Repaint the field so the change is visible immediately.
    let _ = windows::Win32::Graphics::Gdi::InvalidateRect(state.edit, None, true);
}

unsafe fn read_edit(state: &PromptState) -> String {
    let len = GetWindowTextLengthW(state.edit);
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; (len + 1) as usize];
    let got = GetWindowTextW(state.edit, &mut buf);
    String::from_utf16_lossy(&buf[..got as usize])
}

unsafe fn set_status(state: &PromptState, text: &str) {
    // Bind the wide buffer to a local so the PCWSTR does not dangle across the call.
    let w = wide(text);
    let _ = SetWindowTextW(state.status, PCWSTR(w.as_ptr()));
}

unsafe fn set_caption(hwnd: HWND, state: &PromptState, phase: PromptPhase) {
    let w = wide(&caption_for(phase, &state.product));
    let _ = SetWindowTextW(hwnd, PCWSTR(w.as_ptr()));
}

unsafe fn on_connect(hwnd: HWND, state: &mut PromptState) {
    if state.busy {
        return;
    }
    let code = read_edit(state);
    if code.trim().is_empty() {
        set_status(state, "Type the code first.");
        return;
    }
    state.busy = true;
    state.attempts += 1;
    let _ = EnableWindow(state.edit, false);
    let _ = EnableWindow(state.connect, false);
    set_status(state, "Connecting to the support service...");
    set_caption(hwnd, state, PromptPhase::Connecting);

    // Redeem on a worker thread; post the result back so the pump stays responsive.
    let redeem = state.redeem.clone();
    let hwnd_val = hwnd.0 as isize;
    std::thread::spawn(move || {
        let result = redeem(code.trim());
        let boxed = Box::new(result);
        // SAFETY: PostMessageW copies the LPARAM value; the wndproc reclaims the box on this thread.
        let _ = PostMessageW(
            HWND(hwnd_val as *mut core::ffi::c_void),
            WM_REDEEM_RESULT,
            WPARAM(0),
            LPARAM(Box::into_raw(boxed) as isize),
        );
    });
}

unsafe fn on_redeem_result(hwnd: HWND, result: Result<AttendRedeem, AttendRedeemError>) {
    let Some(state) = state_of(hwnd) else { return };
    state.busy = false;
    match result {
        Ok(redeemed) => finish(hwnd, PromptOutcome::Redeemed(Box::new(redeemed))),
        Err(e) => {
            let failure = e.to_failure();
            let m = rmt_agent_core::support_ui::message(&failure);
            let mut text = m.body;
            if let Some(d) = m.detail {
                text.push_str("  ");
                text.push_str(&d);
            }
            set_status(state, &text);
            set_caption(hwnd, state, PromptPhase::Error);
            let _ = EnableWindow(state.edit, true);
            let _ = EnableWindow(state.connect, true);
            let _ = SetFocus(state.edit);
            // Re-select the text so a correction overtypes it.
            SendMessageW(state.edit, EM_SETSEL, WPARAM(0), LPARAM(-1));
            if state.attempts >= MAX_ATTEMPTS {
                set_status(state, "Too many attempts. Close this and start again with a new code.");
                let _ = EnableWindow(state.connect, false);
            }
        }
    }
}

unsafe fn finish(hwnd: HWND, outcome: PromptOutcome) {
    LAST_OUTCOME.with(|c| *c.borrow_mut() = Some(outcome));
    let _ = DestroyWindow(hwnd);
}

/// The directory containing the running executable, used to find the `session.code` sidecar.
/// Returns `None` when `current_exe` fails — treated as "no sidecar, start with blank prompt".
fn current_exe_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(|p| p.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::WindowsAndMessaging::{WM_CHAR, WM_KEYDOWN, WM_LBUTTONDOWN, WM_MOUSEMOVE};

    #[test]
    fn the_caption_mirrors_the_phase_and_names_the_product() {
        assert!(caption_for(PromptPhase::Entering, "DeskRally").contains("DeskRally"));
        // Each phase is distinguishable — a VM probe reads the caption to tell them apart.
        let e = caption_for(PromptPhase::Entering, "DeskRally");
        let c = caption_for(PromptPhase::Connecting, "DeskRally");
        let x = caption_for(PromptPhase::Error, "DeskRally");
        assert_ne!(e, c);
        assert_ne!(c, x);
        assert_ne!(e, x);
        // A blank product still yields a usable caption, never an empty one.
        assert!(!caption_for(PromptPhase::Connecting, "  ").trim().is_empty());
    }

    /// The ordering test: an INJECTED keystroke is dropped before it can reach `IsDialogMessageW`.
    /// This is the check that catches the bypass no VM probe can see.
    #[test]
    fn an_injected_keystroke_is_dropped_before_the_dialog_stage() {
        assert_eq!(classify_pump_message(WM_KEYDOWN, true), PumpAction::Drop);
        assert_eq!(classify_pump_message(WM_CHAR, true), PumpAction::Drop);
        assert_eq!(classify_pump_message(WM_LBUTTONDOWN, true), PumpAction::Drop);
        // Genuine (untagged) input is processed — the customer can actually type and click.
        assert_eq!(classify_pump_message(WM_KEYDOWN, false), PumpAction::Process);
        assert_eq!(classify_pump_message(WM_CHAR, false), PumpAction::Process);
        assert_eq!(classify_pump_message(WM_LBUTTONDOWN, false), PumpAction::Process);
        // A non-actuating message (a mouse move) is processed even when injected, so the technician
        // can still steer the cursor elsewhere — matching the guest window's policy.
        assert_eq!(classify_pump_message(WM_MOUSEMOVE, true), PumpAction::Process);
    }

    #[test]
    fn the_retry_cap_is_bounded() {
        assert!(MAX_ATTEMPTS >= 1 && MAX_ATTEMPTS <= 10, "a sane, bounded retry cap");
    }
}
