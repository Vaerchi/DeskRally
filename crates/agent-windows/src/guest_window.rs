//! The Win32 shell for the guest-facing window — the **first window this product has ever drawn**.
//!
//! All the judgement lives in [`rmt_agent_core::guest_ui::GuestPresenter`]; this file is the dumb
//! half: it creates one top-level window, runs one message pump, paints what the presenter says,
//! and feeds it keystrokes. Everything below is here because Win32 forced it.
//!
//! # The four decisions, and why
//!
//! **1. Its own thread, and never the capture thread.** `SetThreadDesktop` fails on a thread that
//! owns windows, and the per-session capture thread's entire job is to rebind between `Default` and
//! `Winlogon` on every desktop switch ([`crate::following_capturer`]). A window created there would
//! strand itself — and break capture — at the first UAC prompt. The pump also must not be a tokio
//! worker or the capture loop, both of which would starve it.
//!
//! **2. Pinned to `WinSta0\Default`; it deliberately does NOT follow the input desktop.** When the
//! guest hits Ctrl+Alt+Del the window stops being displayed and comes back untouched afterwards,
//! because a top-level window belongs permanently to the desktop of the thread that created it and
//! `SwitchDesktop` only changes which desktop is shown. That is the behaviour we want: the Winlogon
//! secure desktop is by definition the *pre-authentication* surface, so a chat box rendered there
//! would be a text field an unauthenticated bystander could read and type into, and a channel for a
//! remote party to push text onto a locked machine. Capture and injection follow the secure desktop;
//! the UI must not.
//!
//! **3. Owner-drawn GDI, no child controls.** An `EDIT` control brings IME, its own subclassing, and
//! `Win32_UI_Controls` — surface this repo has never exercised, on a window that in the unattended
//! case is owned by SYSTEM and faced by a medium-integrity user. Painting text and collecting
//! `WM_CHAR` is a fraction of the mechanism and none of the unknowns.
//!
//! **4. Injected input to this window is dropped — keyboard AND mouse.** See
//! [`crate::input::RMT_INJECTED_TAG`]. If this window holds focus, every key the remote technician
//! sends arrives here as an ordinary `WM_CHAR`, and without the tag check it would be typed into the
//! guest's compose box and recorded in the support transcript **as the guest's own words**. The same
//! tag check also drops injected mouse actuators ([`is_mouse_actuator_message`]) — the End button
//! (`WM_LBUTTONDOWN`), the caption `[X]` (`WM_NCLBUTTONDOWN` → `SC_CLOSE` → `WM_CLOSE`), and the
//! caption right-click that would open the system menu — so the guest's own "end the session"
//! affordances answer only to genuine hardware input, never the technician's injection (docs/12
//! §13.6). Both are dropped in the pump before dispatch, for the reason spelled out there.
//! The only mouse exception is the separate layout row: Move corner and Hide/Show chat are
//! handled directly in the pump, without dispatching an injected click to chat or End controls.
//!
//! # Cross-thread rules
//!
//! Window operations run on the owning thread. Other threads never touch the `HWND` except through
//! `PostMessageW` — never `SendMessageW`, which blocks the caller until the UI thread services it
//! and deadlocks whenever that thread is busy, off-screen on another desktop, or already gone.
//!
//! # Two ways the window closes, and why they are different messages
//!
//! **The host tears it down** at end of session via [`GuestWindow::close`], which posts a private
//! `WM_RMT_DESTROY` → `DestroyWindow` → `WM_DESTROY` → `PostQuitMessage` → `GetMessageW` returns 0 →
//! the thread returns → `join`. Posting to the HWND rather than the thread id matters: a `WM_QUIT`
//! posted to a thread that has not yet created its message queue is silently dropped and the thread
//! never exits, whereas an HWND only exists after `CreateWindowExW` has succeeded.
//!
//! **Shell/window close** cannot reliably identify the originating input: Explorer can forward
//! taskbar Close after a technician-injected click. While active, close hides the panel only when
//! a working branded tray restore target exists. Ending still requires the input-filtered End
//! button. Without a tray, restore the panel. Once ended, close dismisses the receipt.
//! Host teardown still uses WM_RMT_DESTROY so it never waits for guest input.

use std::collections::VecDeque;
use std::sync::mpsc as stdmpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::JoinHandle;

use rmt_agent_core::chat::ChatFrom;
use rmt_agent_core::guest_ui::{
    GuestCommand, GuestEvent, GuestPresenter, GuestSurface, GuestToHost, GuestUi, SessionInfo,
    SessionPhase,
};
use tokio::sync::mpsc::UnboundedSender;

use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
    InvalidateRect, SelectObject, SetBkMode, SetTextColor, ANTIALIASED_QUALITY, CLIP_DEFAULT_PRECIS,
    DEFAULT_CHARSET, DT_CENTER, DT_END_ELLIPSIS, DT_LEFT, DT_NOPREFIX, DT_SINGLELINE, DT_TOP,
    DT_VCENTER, DT_WORDBREAK, FF_DONTCARE, FW_BOLD, FW_NORMAL, HBRUSH, HGDIOBJ, OUT_TT_PRECIS,
    PAINTSTRUCT, TRANSPARENT, GetMonitorInfoW, MonitorFromWindow, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::HiDpi::AdjustWindowRectExForDpi;
use windows::Win32::UI::Shell::{Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY, NOTIFYICONDATAW};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, ChangeWindowMessageFilterEx, CreatePopupMenu, DestroyMenu, EndMenu, GetCursorPos, IsWindow, IsWindowVisible,
    RegisterWindowMessageW, SetForegroundWindow, TrackPopupMenu, GWL_EXSTYLE, IDI_APPLICATION,
    LoadIconW, MF_STRING, MSGFLT_ALLOW, SC_MINIMIZE, SW_RESTORE, TPM_NONOTIFY, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, SWP_FRAMECHANGED, SWP_NOMOVE, SWP_NOSIZE, WM_CONTEXTMENU, WM_LBUTTONUP, WM_NULL, WM_RBUTTONUP, WM_SYSCOMMAND,
    WS_EX_TOOLWINDOW, WS_MINIMIZEBOX,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
    GetMessageExtraInfo, GetMessageW, GetSystemMetrics, GetWindowLongPtrW, GetWindowRect, LoadCursorW,
    PostMessageW, PostQuitMessage, RegisterClassW, SetWindowLongPtrW, SetWindowPos, SetWindowTextW,
    ShowWindow,
    TranslateMessage, CREATESTRUCTW, CS_HREDRAW, CS_VREDRAW, GWLP_USERDATA, HCURSOR, HMENU,
    IDC_ARROW, HWND_TOPMOST, MSG, SM_CXSCREEN, SM_CYSCREEN, SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_SHOWNA,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CHAR, WM_CLOSE, WM_CREATE, WM_DESTROY,
    WM_DPICHANGED, WM_ENDSESSION, WM_KEYDOWN, WM_KEYUP, WM_KILLFOCUS, WM_LBUTTONDBLCLK,
    WM_LBUTTONDOWN, WM_NCLBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCRBUTTONDOWN, WM_NCRBUTTONUP, WM_PAINT,
    WM_QUERYENDSESSION, WM_SETFOCUS, WM_SYSCHAR, WM_SYSKEYDOWN, WM_SYSKEYUP,
    WNDCLASSW, WS_CAPTION, WS_EX_APPWINDOW, WS_OVERLAPPED, WS_SYSMENU,
};

/// Window class name. Also the handle a test or a probe uses to assert the window exists — see
/// docs/12 §5, which requires the indicator to be CREATED even when it is rendered off-screen.
pub const GUEST_WINDOW_CLASS: PCWSTR = w!("RmtGuestSessionWindow");

/// Title bar text.
const GUEST_WINDOW_TITLE: PCWSTR = w!("Remote support session");

/// Posted (never sent) to tell the UI thread that events are waiting in the inbox.
const WM_RMT_EVENTS: u32 = WM_APP + 1;

/// Posted (never sent) by [`GuestWindow::close`] to tear the window down from the host at end of
/// session. Distinct from `WM_CLOSE` (the guest's own `[X]`/Alt+F4) so the two close paths can never
/// be confused — see the module doc. Goes straight to `DestroyWindow`, with no End semantics.
const WM_RMT_DESTROY: u32 = WM_APP + 2;
const WM_RMT_TRAY: u32 = WM_APP + 3;
const SESSION_TRAY_ID: u32 = 101;
static TASKBAR_CREATED: OnceLock<u32> = OnceLock::new();

/// Window size in logical pixels at 96 DPI.
const WIN_W: i32 = 360;
const WIN_H: i32 = 240;
/// Gap from the bottom-right corner of the primary display.
const WIN_MARGIN: i32 = 24;

/// Virtual-key codes handled directly (the `windows` crate exposes these as `VIRTUAL_KEY`, but the
/// `WM_KEYDOWN` wParam arrives as a raw `usize`, so plain constants are simpler and clearer).
const VK_BACK: usize = 0x08;
const VK_RETURN: usize = 0x0D;

/// State the WNDPROC owns, reached through `GWLP_USERDATA`.
struct UiState {
    presenter: GuestPresenter,
    /// The "someone is controlling this PC" pill (presence_pill.rs), `0` once removed. Owned by this
    /// thread: created with the panel, removed at session end or with the panel.
    pill: isize,
    /// The pill could not be created, so the PANEL is the session's visible indicator: it is kept
    /// topmost and refuses to hide (to the tray, by minimize or close) while the session is live
    /// (Codex 1.3.8 round 2: showing it once was not enough, a later hide removed the only indicator).
    panel_is_indicator: bool,
    inbox: Arc<Mutex<VecDeque<GuestEvent>>>,
    to_host: UnboundedSender<GuestToHost>,
    /// Set once the guest has typed anything, so an idle window is not repainted.
    offscreen: bool,
    /// The caption last written with `SetWindowTextW`, so [`sync_title`] only re-titles the window
    /// when the presenter's state actually changed it. `None` until the first sync.
    title_shown: Option<&'static str>,
    tray_registered: bool,
    /// Set once the first live technician message has auto-revealed the window, so subsequent
    /// messages respect the guest's hide/background choice and never reopen on their own.
    first_tech_revealed: bool,
    /// `Some(expanded client height)` while the chat is collapsed by the layout row's Hide chat
    /// (the window then shows only the banner + layout row); restored on Show chat. Independent of
    /// the tray: Hide chat COLLAPSES a visible window, the tray HIDES it.
    expanded_height: Option<i32>,
    /// Next corner for the layout row's Move corner (0..4, cycles).
    layout_corner: usize,
}

impl UiState {
    /// Fold one event through the presenter and forward whatever the host must do — chat lines and
    /// the End request both leave through the one `to_host` channel.
    fn dispatch(&mut self, ev: GuestEvent) {
        match self.presenter.on(ev) {
            GuestCommand::SendChat(body) => {
                let _ = self.to_host.send(GuestToHost::Chat(body));
            }
            GuestCommand::EndSession => {
                let _ = self.to_host.send(GuestToHost::End);
            }
            GuestCommand::None => {}
        }
    }

    /// Shell close has no reliable input provenance. Keep active sessions visible and require
    /// the input-filtered End button; an ended receipt may be destroyed.
    fn on_user_close(&mut self) -> bool {
        match close_action(self.presenter.phase()) {
            CloseAction::RevealEndButton => false,
            CloseAction::DestroyNow => true,
        }
    }
}

/// The [`GuestUi`] implementation that draws a real window.
pub struct WindowGuestUi {
    info: SessionInfo,
    /// Create the window but keep it off-screen and hidden.
    ///
    /// This exists for the `--auto-consent` lab path that docs/12 §5 calls out: the indicator is a
    /// product requirement, so a test harness may render it invisibly but must NOT be able to skip
    /// creating it. Making "invisible" a rendering choice rather than a creation choice is what
    /// keeps `FindWindowW(GUEST_WINDOW_CLASS, …)` a valid assertion in both modes.
    offscreen: bool,
}

impl WindowGuestUi {
    /// A factory that will draw the window for a session described by `info`.
    pub fn new(info: SessionInfo) -> Self {
        Self { info, offscreen: false }
    }

    /// As [`WindowGuestUi::new`], but the window is created hidden and off-screen.
    pub fn offscreen(info: SessionInfo) -> Self {
        Self { info, offscreen: true }
    }
}

impl GuestUi for WindowGuestUi {
    fn open(&self, to_host: UnboundedSender<GuestToHost>) -> Result<Box<dyn GuestSurface>, String> {
        GuestWindow::spawn(self.info.clone(), to_host, self.offscreen)
            .map(|w| Box::new(w) as Box<dyn GuestSurface>)
    }
}

/// A live guest window: a UI thread, its HWND, and the inbox feeding it.
pub struct GuestWindow {
    /// `HWND` as an integer so this handle is `Send`. Every use goes through `PostMessageW`.
    hwnd: isize,
    thread: Option<JoinHandle<()>>,
    inbox: Arc<Mutex<VecDeque<GuestEvent>>>,
}

impl GuestWindow {
    /// Create the window on a fresh UI thread and wait until it is up.
    ///
    /// Blocks until the thread reports its `HWND` (or an error), so a caller can never post to a
    /// window that does not exist yet — the silently-dropped-message failure this design's whole
    /// close path depends on avoiding.
    pub fn spawn(
        info: SessionInfo,
        to_host: UnboundedSender<GuestToHost>,
        offscreen: bool,
    ) -> Result<Self, String> {
        let inbox: Arc<Mutex<VecDeque<GuestEvent>>> = Arc::new(Mutex::new(VecDeque::new()));
        let inbox_ui = Arc::clone(&inbox);
        let (up_tx, up_rx) = stdmpsc::channel::<Result<isize, String>>();

        let thread = std::thread::Builder::new()
            .name("rmt-guest-window".to_string())
            .spawn(move || ui_thread(info, to_host, inbox_ui, offscreen, up_tx))
            .map_err(|e| format!("could not spawn the guest-window thread: {e}"))?;

        // If the UI thread dies before signalling, `recv` returns Err rather than hanging forever.
        match up_rx.recv() {
            Ok(Ok(hwnd)) => Ok(Self { hwnd, thread: Some(thread), inbox }),
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err("the guest-window thread exited before it created a window".to_string())
            }
        }
    }

    /// Queue an event and wake the pump.
    fn push(&self, event: GuestEvent) {
        if let Ok(mut q) = self.inbox.lock() {
            q.push_back(event);
        }
        // Best effort: a failed post means the window is already gone, which is not an error at
        // teardown. The event stays in the inbox and is dropped with it.
        unsafe {
            let _ = PostMessageW(HWND(self.hwnd as *mut _), WM_RMT_EVENTS, WPARAM(0), LPARAM(0));
        }
    }
}

impl GuestSurface for GuestWindow {
    fn posted(&self, from: ChatFrom, body: &str, at_unix_ms: i64) {
        self.push(GuestEvent::Posted { from, body: body.to_string(), at_unix_ms });
    }

    fn seed(&self, from: ChatFrom, body: &str, at_unix_ms: i64) {
        self.push(GuestEvent::Seeded { from, body: body.to_string(), at_unix_ms });
    }

    fn ended(&self) {
        self.push(GuestEvent::Ended);
    }

    fn set_view_only(&self, view_only: bool) {
        self.push(GuestEvent::ViewOnly(view_only));
    }

    fn set_recording(&self, recording: bool) {
        self.push(GuestEvent::Recording(recording));
    }

    fn clipboard_shared(&self, to_technician: bool) {
        self.push(GuestEvent::ClipboardShared { to_technician });
    }

    fn close(&mut self) {
        if let Some(thread) = self.thread.take() {
            unsafe {
                // WM_RMT_DESTROY, not WM_CLOSE: this is the host's own teardown, which must destroy
                // the window unconditionally. A user's WM_CLOSE now ends the session instead of
                // destroying (see the module doc), so routing teardown through it would either send a
                // spurious End or, once WM_CLOSE stops destroying, hang this join forever.
                let _ = PostMessageW(HWND(self.hwnd as *mut _), WM_RMT_DESTROY, WPARAM(0), LPARAM(0));
            }
            // Joining is what makes teardown deterministic — the same discipline as the capture and
            // clipboard threads. If the UI thread has already exited, join returns immediately.
            if thread.join().is_err() {
                tracing::warn!("guest window: the UI thread panicked");
            }
        }
    }
}

impl Drop for GuestWindow {
    fn drop(&mut self) {
        // A surface dropped without `close` would leak the thread and leave a window on the guest's
        // screen claiming a session is active after it ended.
        self.close();
    }
}

/// The UI thread body: register, create, signal, pump.
fn ui_thread(
    info: SessionInfo,
    to_host: UnboundedSender<GuestToHost>,
    inbox: Arc<Mutex<VecDeque<GuestEvent>>>,
    offscreen: bool,
    up_tx: stdmpsc::Sender<Result<isize, String>>,
) {
    let state = Box::new(UiState {
        presenter: GuestPresenter::new(info),
        pill: 0,
        panel_is_indicator: false,
        inbox,
        to_host,
        offscreen,
        title_shown: None,
        tray_registered: false,
        first_tech_revealed: false,
        expanded_height: None,
        layout_corner: 0,
    });

    let hwnd = match unsafe { create_window(state, offscreen) } {
        Ok(h) => h,
        Err(e) => {
            let _ = up_tx.send(Err(e));
            return;
        }
    };
    // The always-present indicator (Ed, 2026-10-23), on this same thread so the pump's injection filter
    // covers it and it lives exactly as long as the session's window.
    unsafe {
        match (state_of(hwnd), crate::presence_pill::create(hwnd, offscreen)) {
            (Some(st), Some(pill)) => st.pill = pill.0 as isize,
            // No pill: the session must still have a VISIBLE indicator, so show the panel itself
            // (without taking focus) rather than leave it tucked away (Codex 1.3.8 review).
            (Some(st), None) if !offscreen => {
                tracing::warn!("presence pill unavailable; the session panel is the indicator (topmost, not hideable)");
                st.panel_is_indicator = true;
                let _ = SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                let _ = ShowWindow(hwnd, SW_SHOWNA);
            }
            _ => {}
        }
    }
    if up_tx.send(Ok(hwnd.0 as isize)).is_err() {
        // Nobody is waiting any more; tear down rather than pumping an orphan window.
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
        return;
    }

    let mut msg = MSG::default();
    // GetMessageW returns 0 on WM_QUIT and -1 on error; anything else is a message.
    while unsafe { GetMessageW(&mut msg, None, 0, 0) }.0 > 0 {
        // THE INJECTION FILTER, and it belongs HERE rather than in the WNDPROC.
        //
        // The tag rides on the queued message and is read with `GetMessageExtraInfo` immediately
        // after retrieval, which is exactly what it documents ("of whatever message the thread most
        // recently retrieved"). `msg.lParam`/`wParam` are untouched. Filtering here rather than in
        // the WNDPROC is load-bearing for BOTH input kinds, because both manufacture a *second*
        // message whose provenance would be harder to re-derive:
        //
        //   * KEYBOARD — `TranslateMessage` turns a WM_KEYDOWN into a newly posted WM_CHAR. Deciding
        //     about the WM_CHAR later would read the extra info of whatever was retrieved most
        //     recently, not the keydown. Dropping the keydown before translation means the character
        //     is never manufactured at all. A leaked injected keystroke would be recorded as the
        //     guest's own words in a persisted support transcript.
        //   * MOUSE — the window's only interactive affordances are the End button (WM_LBUTTONDOWN)
        //     and the [X]/caption (an NC button-down that DefWindowProc turns into SC_CLOSE →
        //     WM_CLOSE). Dropping the button-down before `DispatchMessageW` means the End is never
        //     dispatched and DefWindowProc never synthesizes the close. A leaked injected click would
        //     let the remote technician actuate the guest's OWN "end the session" controls; benign
        //     today (an End grants no privilege and cannot hide the indicator), but the guest's
        //     safety affordances must accept only GENUINE hardware input — injected input is never
        //     the guest exercising control over their own machine (docs/12 §13.6).
        //
        // Genuine hardware input carries `dwExtraInfo == 0`, so only this agent's own injections
        // (tagged `RMT_INJECTED_TAG`) are dropped; the guest's real clicks and keystrokes pass.
        let injected = unsafe { GetMessageExtraInfo() }.0 as usize == crate::input::RMT_INJECTED_TAG;
        if !unsafe { pump_filter(hwnd, &msg, injected) } {
            continue;
        }
        unsafe {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    tracing::debug!("guest window: pump exited");
}

/// True for the keyboard messages that can reach a text box.
///
/// A pure function so the filter's *coverage* is testable without a desktop: the interesting failure
/// is not "the check is wrong" but "the check does not cover the message the character actually
/// arrives on". WM_KEYDOWN and WM_SYSKEYDOWN are the sources `TranslateMessage` reads; WM_CHAR and
/// WM_SYSCHAR are covered too so an injected character that somehow reaches the queue directly (a
/// `SendInput` with `KEYEVENTF_UNICODE`, which is exactly how `InputEvent::Text` is injected —
/// `input.rs::unicode_input`) is dropped as well.
pub(crate) fn is_keyboard_message(message: u32) -> bool {
    matches!(message, WM_KEYDOWN | WM_SYSKEYDOWN | WM_CHAR | WM_SYSCHAR | WM_KEYUP | WM_SYSKEYUP)
}

/// True for the mouse messages that could let an injected click end the session — directly, or by
/// opening a path to it.
///
/// A pure function for the same reason [`is_keyboard_message`] is: the interesting failure is not
/// "the check is wrong" but "the check does not cover the message the actuation actually arrives on".
/// Three routes, all closed here:
/// * **The End button** — a `WM_LBUTTONDOWN` the WNDPROC hit-tests.
/// * **The caption `[X]`** — a `WM_NCLBUTTONDOWN` on `HTCLOSE`, which DefWindowProc turns into
///   `SC_CLOSE` → `WM_CLOSE`.
/// * **The system menu's *Close*** — a caption RIGHT-click (`WM_NCRBUTTONUP`, and the down that
///   precedes it) makes DefWindowProc pop the window menu, whose *Close* posts `SC_CLOSE` → `WM_CLOSE`.
///   That menu runs its OWN modal `GetMessage` loop inside user32 which THIS pump never services, so
///   the tag check could not catch the click that selects *Close* — the only place to stop it is to
///   drop the injected right-click BEFORE the menu opens. (Alt+Space, the keyboard route to the same
///   menu, is already covered by [`is_keyboard_message`].)
///
/// The double-click twins are included as a guard: this class is registered without `CS_DBLCLKS`, so
/// it never actually receives `WM_*BUTTONDBLCLK` today (a fast double-click arrives as repeated
/// down/up) — they cost nothing and pre-cover a future `CS_DBLCLKS`.
///
/// Deliberately NOT listed: pointer moves, button-UPs of the left button, and CLIENT-area right/middle
/// buttons. They actuate nothing on this window (a client right-click yields no menu — DefWindowProc
/// only shows the window menu for a NON-client `WM_CONTEXTMENU`), and dropping the injected pointer
/// MOVE would break the technician steering the cursor toward legitimate targets elsewhere (the move
/// is delivered to whatever window it is over). Only the injected right-button's NON-client messages
/// are dropped, so a genuine (untagged) guest right-click still opens the menu.
pub(crate) fn is_mouse_actuator_message(message: u32) -> bool {
    matches!(
        message,
        WM_LBUTTONDOWN
            | WM_LBUTTONDBLCLK
            | WM_NCLBUTTONDOWN
            | WM_NCLBUTTONDBLCLK
            | WM_NCRBUTTONDOWN
            | WM_NCRBUTTONUP
    )
}

/// What the pump does with one message. Pure, so the injected-input boundary is tested directly
/// rather than through a live input queue.
#[derive(Debug, PartialEq, Eq)]
enum PumpDisposition {
    /// Genuine input (or a non-input message): `TranslateMessage` + `DispatchMessageW`.
    Dispatch,
    /// Injected keystroke or mouse actuator: dropped, never dispatched.
    Drop,
    /// Injected left-click on THIS window: offered to the layout row ONLY (Move corner / Hide-Show
    /// chat, see [`handle_layout_click`]) and then dropped. It is never dispatched, so it can never
    /// reach the End hit-test, the chat compose, the caption `[X]`, the system menu or the tray.
    LayoutOnly,
}

/// The pump's provenance gate, applied to one retrieved message. Returns `true` when the message
/// should be translated and dispatched. An injected layout click is HANDLED here (Move corner /
/// Hide-Show chat) and then dropped, so the technician may rearrange the panel but never reaches
/// the End hit-test, the compose line, the caption or the tray. The production pump and the
/// native-window tests both go through this one function.
unsafe fn pump_filter(own: HWND, msg: &MSG, injected: bool) -> bool {
    match pump_disposition(injected, msg.message, msg.hwnd == own) {
        PumpDisposition::Dispatch => true,
        PumpDisposition::Drop => {
            tracing::debug!(message = msg.message, "guest window: dropped an injected input message");
            false
        }
        PumpDisposition::LayoutOnly => {
            handle_layout_click(msg.hwnd, msg.lParam);
            false
        }
    }
}

fn pump_disposition(injected: bool, message: u32, own_window: bool) -> PumpDisposition {
    if !injected {
        return PumpDisposition::Dispatch;
    }
    if is_keyboard_message(message) {
        return PumpDisposition::Drop;
    }
    if is_mouse_actuator_message(message) {
        return if own_window && message == WM_LBUTTONDOWN { PumpDisposition::LayoutOnly } else { PumpDisposition::Drop };
    }
    PumpDisposition::Dispatch
}

/// What a user-initiated window close (`[X]`, Alt+F4, the system menu's Close) should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseAction {
    /// Restore the live indicator and ask the guest to use its End button.
    RevealEndButton,
    /// The session has already ended: the window is a receipt the guest may dismiss, so destroy it.
    DestroyNow,
}

/// Shell close must neither hide the live indicator nor impersonate a guest End click.
fn close_action(phase: SessionPhase) -> CloseAction {
    match phase {
        SessionPhase::Active => CloseAction::RevealEndButton,
        SessionPhase::Ended => CloseAction::DestroyNow,
    }
}

/// Whether a newly-arrived event should auto-reveal a hidden window (without activation).
///
/// Only the FIRST live `Posted` from the Technician while the session is active triggers a reveal.
/// Seeded history, guest echoes, and all non-chat events are excluded so the window never
/// foreground-steals for background status changes. A pure function so the "only first" rule
/// is pinned in a desktop-free test.
pub(crate) fn should_auto_reveal(
    ev: &GuestEvent,
    already_revealed: bool,
    phase: SessionPhase,
) -> bool {
    !already_revealed
        && phase == SessionPhase::Active
        && matches!(ev, GuestEvent::Posted { from: ChatFrom::Technician, .. })
}

/// Register the class (idempotently) and create the window.
///
/// # Safety
/// Calls Win32 window APIs and hands `state` to the window as a raw pointer; the WNDPROC reclaims
/// and drops it on `WM_DESTROY`.
unsafe fn create_window(state: Box<UiState>, offscreen: bool) -> Result<HWND, String> {
    let hinstance = GetModuleHandleW(None).map_err(|e| format!("GetModuleHandleW failed: {e}"))?;

    TASKBAR_CREATED.get_or_init(|| RegisterWindowMessageW(w!("TaskbarCreated")));
    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        hInstance: hinstance.into(),
        hIcon: windows::Win32::UI::WindowsAndMessaging::LoadIconW(
            hinstance, PCWSTR(101usize as *const u16),
        ).unwrap_or_default(),
        lpszClassName: GUEST_WINDOW_CLASS,
        hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or(HCURSOR(std::ptr::null_mut())),
        ..Default::default()
    };
    // A zero return is either a real failure or "already registered" from a previous session in
    // this process — the helper runs many sessions per process, so re-registration is the norm and
    // must not be an error. CreateWindowExW below is the real test of whether the class is usable.
    let _ = RegisterClassW(&wc);

    let (x, y) = if offscreen {
        (-32_000, -32_000)
    } else {
        (
            (GetSystemMetrics(SM_CXSCREEN) - WIN_W - WIN_MARGIN).max(0),
            (GetSystemMetrics(SM_CYSCREEN) - WIN_H - WIN_MARGIN).max(0),
        )
    };

    // Begin with a taskbar restore target; only confirmed tray registration replaces it.
    // No WS_EX_TOPMOST: the guest must be able to send the window behind other content.
    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(WS_EX_APPWINDOW.0),
        GUEST_WINDOW_CLASS,
        GUEST_WINDOW_TITLE,
        WINDOW_STYLE(WS_OVERLAPPED.0 | WS_CAPTION.0 | WS_SYSMENU.0 | WS_MINIMIZEBOX.0),
        x,
        y,
        WIN_W,
        WIN_H,
        None,
        HMENU(std::ptr::null_mut()),
        hinstance,
        Some(Box::into_raw(state) as *const _),
    )
    .map_err(|e| format!("CreateWindowExW failed: {e}"))?;

    if !offscreen { register_session_tray(hwnd); }

    // The window starts hidden in all cases. For non-offscreen windows, register_session_tray
    // above calls set_tray_available, which shows the panel (SW_SHOWNA) only when tray
    // registration fails — the visible fallback. When the tray is registered, the window stays
    // hidden until the first live technician message or an explicit tray-menu "Show session".
    // For offscreen windows, the window stays hidden unconditionally.
    if offscreen { let _ = ShowWindow(hwnd, SW_HIDE); }
    Ok(hwnd)
}

/// Reclaim the `UiState` pointer for the duration of a message.
unsafe fn state_of<'a>(hwnd: HWND) -> Option<&'a mut UiState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut UiState;
    if ptr.is_null() {
        None
    } else {
        Some(&mut *ptr)
    }
}

// Only a successfully registered notification icon may replace the taskbar restore target.
fn panel_ex_style(tray_registered: bool) -> WINDOW_EX_STYLE {
    WINDOW_EX_STYLE(if tray_registered { WS_EX_TOOLWINDOW.0 } else { WS_EX_APPWINDOW.0 })
}

unsafe fn session_nid(hwnd: HWND) -> NOTIFYICONDATAW {
    let icon = GetModuleHandleW(None).ok()
        .and_then(|module| LoadIconW(module, PCWSTR(101usize as *const u16)).ok())
        .or_else(|| LoadIconW(None, IDI_APPLICATION).ok()).unwrap_or_default();
    let title = state_of(hwnd).map(|st| st.presenter.window_title()).unwrap_or("Remote support session");
    NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: hwnd, uID: SESSION_TRAY_ID,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_RMT_TRAY, hIcon: icon,
        szTip: crate::tray::encode_tooltip(&format!("DeskRally — {title}")),
        ..Default::default()
    }
}

unsafe fn set_tray_available(hwnd: HWND, available: bool) {
    let offscreen = match state_of(hwnd) {
        Some(st) => { st.tray_registered = available; st.offscreen },
        None => return,
    };
    if offscreen { return; }
    // Release the state borrow before APIs that can synchronously call this WNDPROC.
    let mask = WS_EX_APPWINDOW.0 | WS_EX_TOOLWINDOW.0;
    let current = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
    let desired = (current & !mask) | (panel_ex_style(available).0 & mask);
    let was_visible = IsWindowVisible(hwnd).as_bool();
    if current != desired {
        // Explorer requires hide/style/show when changing a visible taskbar window into a tool
        // window. Preserve all unrelated extended styles and do not activate during recovery.
        if was_visible { let _ = ShowWindow(hwnd, SW_HIDE); }
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, desired as isize);
        let _ = SetWindowPos(hwnd, None, 0, 0, 0, 0,
            SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        if was_visible { let _ = ShowWindow(hwnd, SW_SHOWNA); }
    }
    if !available { let _ = ShowWindow(hwnd, SW_SHOWNA); }
}

unsafe fn register_session_tray(hwnd: HWND) {
    if state_of(hwnd).map(|st| st.offscreen).unwrap_or(true) { return; }
    // The helper may be elevated while Explorer is not. These messages may only reveal UI;
    // neither callback is allowed to authorize a session or impersonate the guest's End action.
    let mut allowed = ChangeWindowMessageFilterEx(hwnd, WM_RMT_TRAY, MSGFLT_ALLOW, None).is_ok();
    if let Some(&message) = TASKBAR_CREATED.get().filter(|&&m| m != 0) {
        allowed &= ChangeWindowMessageFilterEx(hwnd, message, MSGFLT_ALLOW, None).is_ok();
    } else { allowed = false; }
    let registered = allowed && Shell_NotifyIconW(NIM_ADD, &session_nid(hwnd)).as_bool();
    set_tray_available(hwnd, registered);
}

unsafe fn reveal_session(hwnd: HWND, end_hint: bool) {
    if state_of(hwnd).map(|st| st.offscreen).unwrap_or(true) { return; }
    let _ = ShowWindow(hwnd, SW_RESTORE);
    let _ = SetForegroundWindow(hwnd);
    if end_hint { let _ = SetWindowTextW(hwnd, w!("DeskRally — use End session to stop sharing")); }
}

/// The pill's click: open the guest panel. Runs on this thread (the pill is one of its windows).
pub(crate) unsafe fn reveal_from_pill(guest: HWND) {
    reveal_session(guest, false);
}

/// Whether the session the pill belongs to is view-only (the pill then says "viewing").
pub(crate) unsafe fn pill_view_only(guest: HWND) -> bool {
    state_of(guest).map(|st| st.presenter.view_only()).unwrap_or(false)
}

/// Whether the panel must stay visible: it is the session's only indicator and the session is live.
fn panel_must_stay(panel_is_indicator: bool, phase: SessionPhase) -> bool {
    panel_is_indicator && phase != SessionPhase::Ended
}

unsafe fn hide_session_panel(hwnd: HWND) {
    if state_of(hwnd).map(|st| st.offscreen).unwrap_or(true) { return; }
    // Without a pill, the panel IS the indicator: it stays up for as long as the session is live.
    if state_of(hwnd).map(|st| panel_must_stay(st.panel_is_indicator, st.presenter.phase())).unwrap_or(false) {
        return;
    }
    let registered = state_of(hwnd).map(|st| st.tray_registered).unwrap_or(false);
    // Reconfirm presence before hiding, including the gap before Explorer's restart broadcast.
    if registered && Shell_NotifyIconW(NIM_MODIFY, &session_nid(hwnd)).as_bool() {
        let _ = ShowWindow(hwnd, SW_HIDE);
    } else {
        set_tray_available(hwnd, false);
        reveal_session(hwnd, true);
    }
}

unsafe fn session_tray_menu(hwnd: HWND) {
    let active = state_of(hwnd).map(|st| st.presenter.phase() == SessionPhase::Active).unwrap_or(false);
    let Ok(menu) = CreatePopupMenu() else { reveal_session(hwnd, false); return; };
    let _ = AppendMenuW(menu, MF_STRING, 1, w!("Show session"));
    if active { let _ = AppendMenuW(menu, MF_STRING, 2, w!("End session")); }
    let mut pos = windows::Win32::Foundation::POINT::default();
    let _ = GetCursorPos(&mut pos);
    let _ = SetForegroundWindow(hwnd);
    // The menu's modal loop bypasses this thread's pump filter, so who chose the item is recorded by
    // low-level hooks for the menu's lifetime (crate::tray_menu_provenance; Codex tray r1).
    let (choice, by_guest) = crate::tray_menu_provenance::watch(|| {
        TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON, pos.x, pos.y, 0, hwnd, None).0
    });
    let _ = DestroyMenu(menu);
    if !IsWindow(hwnd).as_bool() {
        // A nested menu pump may have retrieved WM_QUIT during host teardown. Ensure the outer
        // guest pump also exits, so GuestWindow::close never waits on a destroyed window.
        PostQuitMessage(0);
        return;
    }
    let _ = PostMessageW(hwnd, WM_NULL, WPARAM(0), LPARAM(0));
    apply_tray_choice(hwnd, choice, by_guest);
}

/// "End session" in the tray menu ENDS the session when the guest chose it with their own input
/// (10-28: Ed chose it, the panel just reappeared, and the session went on). Chosen with any of this
/// agent's injected input (the technician's), or with provenance unknown, it only reveals the panel
/// and its input-filtered End button: a technician must never author the guest's End.
unsafe fn apply_tray_choice(hwnd: HWND, choice: i32, by_guest: bool) {
    if choice == 2 && by_guest {
        if let Some(st) = state_of(hwnd) {
            st.dispatch(GuestEvent::EndClicked);
            return;
        }
    }
    if choice == 1 || choice == 2 { reveal_session(hwnd, choice == 2); }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        if msg != 0 && TASKBAR_CREATED.get().copied() == Some(msg) {
            register_session_tray(hwnd);
            return LRESULT(0);
        }
        match msg {
            WM_RMT_TRAY => {
                match lparam.0 as u32 {
                    WM_LBUTTONUP | WM_LBUTTONDBLCLK => reveal_session(hwnd, false),
                    WM_RBUTTONUP | WM_CONTEXTMENU => session_tray_menu(hwnd),
                    _ => {},
                }
                LRESULT(0)
            }
            crate::presence_pill::WM_RMT_PILL_VISIBLE => {
                let visible = wparam.0 != 0;
                if let Some(st) = state_of(hwnd) {
                    let _ = st.to_host.send(GuestToHost::IndicatorVisible(visible));
                    if !visible && !st.offscreen {
                        // The pill is off-screen: the panel is the indicator until it is back.
                        st.panel_is_indicator = true;
                        let _ = SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
                        let _ = ShowWindow(hwnd, SW_SHOWNA);
                    } else if visible && st.pill != 0 {
                        st.panel_is_indicator = false;
                    }
                }
                LRESULT(0)
            }
            WM_SYSCOMMAND if wparam.0 as u32 & 0xfff0 == SC_MINIMIZE => {
                hide_session_panel(hwnd);
                LRESULT(0)
            }
            WM_CREATE => {
                let cs = lparam.0 as *const CREATESTRUCTW;
                if !cs.is_null() {
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (*cs).lpCreateParams as isize);
                }
                LRESULT(0)
            }

            WM_RMT_EVENTS => {
                let mut auto_reveal = false;
                if let Some(st) = state_of(hwnd) {
                    // Drain under the lock, fold outside it: `chat_tx.send` and a repaint must not
                    // run while another thread could be blocked pushing an event.
                    let drained: Vec<GuestEvent> = match st.inbox.lock() {
                        Ok(mut q) => q.drain(..).collect(),
                        Err(_) => Vec::new(),
                    };
                    for ev in drained {
                        // Reveal on the first live technician message (SW_SHOWNA: no focus steal).
                        if !st.offscreen
                            && should_auto_reveal(&ev, st.first_tech_revealed, st.presenter.phase())
                        {
                            st.first_tech_revealed = true;
                            auto_reveal = true;
                        }
                        st.dispatch(ev);
                    }
                    // Mirror any phase/control change into the title bar (view-only ⇄ controlling,
                    // active → ended) so an automated probe can read the state; cheap and idempotent.
                    sync_title(hwnd, st);
                    // The pill follows the session: repaint on a change (controlling ⇄ viewing), and
                    // remove it the moment the session ends (the panel stays as the receipt).
                    if st.pill != 0 {
                        let pill = HWND(st.pill as *mut _);
                        if st.presenter.phase() == SessionPhase::Ended {
                            st.pill = 0;
                            crate::presence_pill::destroy(pill);
                        } else {
                            crate::presence_pill::refresh(pill);
                        }
                    }
                    if st.presenter.take_dirty() && !st.offscreen {
                        let _ = InvalidateRect(hwnd, None, true);
                    }
                }
                // Showing can synchronously re-enter this window procedure. Release the mutable
                // state reference first, and fold the full event batch before any painting.
                if auto_reveal { let _ = ShowWindow(hwnd, SW_SHOWNA); }
                if state_of(hwnd).map(|st| st.tray_registered).unwrap_or(false) {
                    if !Shell_NotifyIconW(NIM_MODIFY, &session_nid(hwnd)).as_bool() {
                        set_tray_available(hwnd, false);
                    }
                }
                LRESULT(0)
            }

            // NOTE: injected keystrokes never reach this WNDPROC — the pump drops them before
            // `TranslateMessage`, so nothing here has to re-derive a message's provenance.
            WM_CHAR => {
                if let Some(st) = state_of(hwnd) {
                    if st.expanded_height.is_some() { return LRESULT(0); }
                    if let Some(c) = char::from_u32(wparam.0 as u32) {
                        // Enter and Backspace arrive as WM_KEYDOWN below; ignore their control-char
                        // twins here so one keypress is not counted twice.
                        if c != '\r' && c != '\n' && c != '\u{8}' {
                            st.presenter.on(GuestEvent::Typed(c));
                            repaint_if_dirty(hwnd, st);
                        }
                    }
                }
                LRESULT(0)
            }

            WM_KEYDOWN => {
                if let Some(st) = state_of(hwnd) {
                    if st.expanded_height.is_some() { return LRESULT(0); }
                    let ev = match wparam.0 {
                        VK_BACK => Some(GuestEvent::Backspace),
                        VK_RETURN => Some(GuestEvent::Submit),
                        _ => None,
                    };
                    if let Some(ev) = ev {
                        st.dispatch(ev);
                        repaint_if_dirty(hwnd, st);
                    }
                }
                LRESULT(0)
            }

            // The guest clicking the owner-drawn End button (there are no child controls — see the
            // module's decision 3). Hit-test against the SAME rect `paint` draws, and only while the
            // button is shown; a click elsewhere is ignored. Only a GENUINE hardware click reaches
            // here: an injected (tagged) `WM_LBUTTONDOWN` is dropped by the pump before dispatch (see
            // `is_mouse_actuator_message`), so the remote technician cannot actuate the guest's End
            // button. (UIPI does NOT provide this — the agent injects at its own integrity into a
            // window it owns; the pump's tag filter is what does.)
            WM_LBUTTONDOWN => {
                if handle_layout_click(hwnd, lparam) { return LRESULT(0); }
                if let Some(st) = state_of(hwnd) {
                    if st.presenter.end_button_visible() {
                        let x = (lparam.0 & 0xFFFF) as i16 as i32;
                        let y = ((lparam.0 >> 16) & 0xFFFF) as i16 as i32;
                        let mut rc = RECT::default();
                        let _ = GetClientRect(hwnd, &mut rc);
                        if end_button_hit(&rc, x, y) {
                            st.dispatch(GuestEvent::EndClicked);
                            repaint_if_dirty(hwnd, st);
                        }
                    }
                }
                LRESULT(0)
            }

            WM_SETFOCUS => {
                if let Some(st) = state_of(hwnd) {
                    st.presenter.on(GuestEvent::Focused);
                    repaint_if_dirty(hwnd, st);
                }
                LRESULT(0)
            }

            WM_KILLFOCUS => {
                if let Some(st) = state_of(hwnd) {
                    st.presenter.on(GuestEvent::Blurred);
                }
                LRESULT(0)
            }

            WM_PAINT => {
                if let Some(st) = state_of(hwnd) {
                    paint(hwnd, st);
                }
                LRESULT(0)
            }

            WM_DPICHANGED => {
                // The process is PerMonitorV2-aware, so this arrives whenever the window moves
                // between monitors of different scaling. lParam is the suggested new rect; ignoring
                // it leaves the window mis-sized and blurry.
                let r = lparam.0 as *const RECT;
                if !r.is_null() {
                    let collapsed = state_of(hwnd).is_some_and(|st| st.expanded_height.is_some());
                    let ex_style = WINDOW_EX_STYLE(GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32);
                    let minimum = layout_outer_height((wparam.0 >> 16) as u32, ex_style)
                        .unwrap_or((*r).bottom - (*r).top);
                    let height = if collapsed { minimum } else {
                        ((*r).bottom - (*r).top).max(minimum)
                    };
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        (*r).left,
                        (*r).top,
                        ((*r).right - (*r).left).max(WIN_W),
                        height,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
                LRESULT(0)
            }

            // TRUE, always and promptly. A support tool that vetoes logoff or shutdown is a support
            // tool that hangs the machine it is supposed to be fixing.
            WM_QUERYENDSESSION => LRESULT(1),

            WM_ENDSESSION => {
                if wparam.0 != 0 {
                    let _ = DestroyWindow(hwnd);
                }
                LRESULT(0)
            }

            // Explorer forwards taskbar Close without the originating input tag. An active
            // session keeps its tray presence; End remains an explicit guest action in our own UI.
            WM_CLOSE => {
                let destroy = match state_of(hwnd) {
                    Some(st) => st.on_user_close(),
                    // No state ⇒ already past WM_DESTROY (or the impossible pre-WM_CREATE case);
                    // destroying again is a safe no-op.
                    None => true,
                };
                if destroy {
                    let _ = DestroyWindow(hwnd);
                } else {
                    hide_session_panel(hwnd);
                }
                LRESULT(0)
            }

            // The host's own teardown ([`GuestWindow::close`]). Straight to DestroyWindow: no End, no
            // phase check — the session is already being torn down by the code that posted this.
            WM_RMT_DESTROY => {
                let _ = EndMenu();
                let _ = DestroyWindow(hwnd);
                LRESULT(0)
            }

            WM_DESTROY => {
                if let Some(st) = state_of(hwnd) {
                    if st.pill != 0 {
                        let pill = HWND(st.pill as *mut _);
                        st.pill = 0;
                        crate::presence_pill::destroy(pill);
                    }
                }
                let _ = Shell_NotifyIconW(NIM_DELETE, &NOTIFYICONDATAW {
                    cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                    hWnd: hwnd, uID: SESSION_TRAY_ID, ..Default::default()
                });
                // Reclaim and drop the state exactly once, then stop the pump so the thread returns
                // and `close()`'s join completes.
                let ptr = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) as *mut UiState;
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                }
                PostQuitMessage(0);
                LRESULT(0)
            }

            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

/// Invalidate only when the presenter says something changed.
unsafe fn repaint_if_dirty(hwnd: HWND, st: &mut UiState) {
    if st.presenter.take_dirty() && !st.offscreen {
        let _ = InvalidateRect(hwnd, None, true);
    }
}

/// Mirror the presenter's phase/control state into the window CAPTION (`SetWindowTextW`).
///
/// The headline the guest reads is owner-drawn GDI — pixels an automated check cannot read — so the
/// same fact is also written to the title bar, which `GetWindowTextW` (and guest-window-probe.ps1)
/// can. Not gated on `offscreen`: the indicator is a product requirement in both modes, and the
/// caption is the one part of it a headless test can assert. Idempotent: only re-titles on a real
/// change, so a chat line that leaves the caption alone costs one `&'static str` comparison.
unsafe fn sync_title(hwnd: HWND, st: &mut UiState) {
    let Some(title) = caption_update(st.title_shown, st.presenter.window_title()) else {
        return;
    };
    let wide: Vec<u16> = title.encode_utf16().chain(std::iter::once(0)).collect();
    let _ = SetWindowTextW(hwnd, PCWSTR(wide.as_ptr()));
    st.title_shown = Some(title);
}

/// The caption to write, if any: `Some(want)` when it differs from what is already shown, else
/// `None`. Pure so the "only re-title on a real change" idempotence — the thing that keeps every
/// idle chat line from poking the title bar — is pinned without a desktop.
fn caption_update(shown: Option<&'static str>, want: &'static str) -> Option<&'static str> {
    if shown == Some(want) {
        None
    } else {
        Some(want)
    }
}

/// Colours, as `COLORREF` (0x00BBGGRR).
const COL_BG: u32 = 0x00_1E_1E_1E;
const COL_BANNER_ACTIVE: u32 = 0x00_20_50_C0; // amber-red in BGR: a session in progress
const COL_BANNER_ENDED: u32 = 0x00_50_50_50;
const COL_TEXT: u32 = 0x00_F0_F0_F0;
const COL_DIM: u32 = 0x00_A0_A0_A0;
const COL_COMPOSE_BG: u32 = 0x00_2E_2E_2E;
/// The End-session button: a saturated red (BGR 0x00BBGGRR, so R=0xC8) with white text — "stop this".
const COL_END_BTN: u32 = 0x00_38_38_C8;
const COL_END_BTN_TEXT: u32 = 0x00_FF_FF_FF;

/// Banner height in client pixels. A module const, not a `paint` local, because
/// [`end_button_rect`] positions the button inside the banner and the two must agree.
const BANNER_H: i32 = 56;
/// Compose-box height in client pixels.
const COMPOSE_H: i32 = 28;

/// The End-session button's rect within `client`, in client pixels.
///
/// `paint` (which draws it) and the `WM_LBUTTONDOWN` hit-test (which reads it) MUST both call this,
/// so the pixels the guest sees and the pixels that respond can never drift apart.
fn end_button_rect(client: &RECT) -> RECT {
    const BTN_W: i32 = 96;
    const BTN_H: i32 = 26;
    let top = (BANNER_H - BTN_H) / 2;
    RECT {
        left: (client.right - BTN_W - 10).max(0),
        top,
        right: (client.right - 10).max(0),
        bottom: top + BTN_H,
    }
}

/// Whether a client-area point is inside the End button. Pure, so the clickable region is testable
/// without a window; the `WM_LBUTTONDOWN` handler calls this against the same rect [`paint`] draws.
fn end_button_hit(client: &RECT, x: i32, y: i32) -> bool {
    let b = end_button_rect(client);
    x >= b.left && x < b.right && y >= b.top && y < b.bottom
}

const LAYOUT_H: i32 = 28;

// Painting uses fixed client pixels. A DPI transition must not shrink the compact
// client below its banner/buttons; only the non-client caption/frame scales here.
// `ex_style` is the window's CURRENT extended style: the panel is an app window until the tray
// registers and a tool window after (`panel_ex_style`). Measured 2026-10-11 on Windows 11 (build
// 26300) the two frames are IDENTICAL at 96/144/192 DPI for this window style (39/56/71 px), so
// this is defensive: tool-window captions are the small caption (SM_CYSMCAPTION) where a theme or
// older Windows sizes it differently, and a mismatched style would then clip the layout row.
fn layout_outer_height(dpi: u32, ex_style: WINDOW_EX_STYLE) -> Option<i32> {
    let mut rect = RECT { left: 0, top: 0, right: WIN_W, bottom: BANNER_H + LAYOUT_H + 6 };
    unsafe {
        AdjustWindowRectExForDpi(&mut rect,
            WINDOW_STYLE(WS_OVERLAPPED.0 | WS_CAPTION.0 | WS_SYSMENU.0 | WS_MINIMIZEBOX.0), false,
            ex_style, dpi).ok()?;
    }
    Some(rect.bottom - rect.top)
}

#[derive(Debug, PartialEq, Eq)]
enum LayoutAction { Move, ToggleChat }

fn layout_action(client: &RECT, x: i32, y: i32) -> Option<LayoutAction> {
    if y < BANNER_H || y >= BANNER_H + LAYOUT_H || y >= client.bottom || x < 6 || x >= client.right - 6 {
        return None;
    }
    Some(if x < client.right / 2 { LayoutAction::Move } else { LayoutAction::ToggleChat })
}

unsafe fn handle_layout_click(hwnd: HWND, lparam: LPARAM) -> bool {
    let mut client = RECT::default();
    if GetClientRect(hwnd, &mut client).is_err() { return false; }
    let x = (lparam.0 & 0xffff) as i16 as i32;
    let y = ((lparam.0 >> 16) & 0xffff) as i16 as i32;
    let Some(action) = layout_action(&client, x, y) else { return false; };
    let Some(st) = state_of(hwnd) else { return false; };
    let mut outer = RECT::default();
    if GetWindowRect(hwnd, &mut outer).is_err() { return true; }
    let width = outer.right - outer.left;
    let height = outer.bottom - outer.top;
    match action {
        LayoutAction::ToggleChat => {
            let new_height = height - client.bottom
                + st.expanded_height.unwrap_or(BANNER_H + LAYOUT_H + 6);
            // Update state before SetWindowPos can synchronously repaint; do not retain a
            // mutable UiState borrow across that reentrant Win32 call.
            st.expanded_height = if st.expanded_height.is_some() { None } else { Some(client.bottom) };
            let _ = SetWindowPos(hwnd, None, 0, 0, width, new_height,
                SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE);
        }
        LayoutAction::Move => {
            let mut monitor = MONITORINFO { cbSize: std::mem::size_of::<MONITORINFO>() as u32, ..Default::default() };
            if !GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut monitor).as_bool() {
                return true;
            }
            let work = monitor.rcWork;
            let corner = st.layout_corner % 4;
            st.layout_corner = (corner + 1) % 4;
            let x = if corner % 2 == 0 { work.left + WIN_MARGIN } else { (work.right - width - WIN_MARGIN).max(work.left) };
            let y = if corner < 2 { work.top + WIN_MARGIN } else { (work.bottom - height - WIN_MARGIN).max(work.top) };
            let _ = SetWindowPos(hwnd, None, x, y, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
        }
    }
    let _ = InvalidateRect(hwnd, None, true);
    true
}

/// Paint the window with layout controls that remain visible when chat is collapsed.
unsafe fn paint(hwnd: HWND, st: &mut UiState) {
    let mut ps = PAINTSTRUCT::default();
    let hdc = BeginPaint(hwnd, &mut ps);

    let mut rc = RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);
    paint_content(hdc, rc, st);
    let _ = EndPaint(hwnd, &ps);
}

unsafe fn paint_content(hdc: windows::Win32::Graphics::Gdi::HDC, rc: RECT, st: &mut UiState) {
    let bg = CreateSolidBrush(COLORREF(COL_BG));
    FillRect(hdc, &rc, bg);
    let _ = DeleteObject(bg);

    let banner_h = BANNER_H;
    let compose_h = COMPOSE_H;

    // --- banner -------------------------------------------------------------------------------
    let banner_rc = RECT { left: 0, top: 0, right: rc.right, bottom: banner_h };
    let banner_col = match st.presenter.phase() {
        SessionPhase::Active => COL_BANNER_ACTIVE,
        SessionPhase::Ended => COL_BANNER_ENDED,
    };
    let bb = CreateSolidBrush(COLORREF(banner_col));
    FillRect(hdc, &banner_rc, bb);
    let _ = DeleteObject(bb);

    SetBkMode(hdc, TRANSPARENT);
    let bold = make_font(15, FW_BOLD.0 as i32);
    let normal = make_font(13, FW_NORMAL.0 as i32);
    let old: HGDIOBJ = SelectObject(hdc, bold);

    // Reserve the banner's right edge for the End button so the headline/detail text is not drawn
    // underneath it. When the button is hidden (session ended) the text reclaims the full width.
    let show_end = st.presenter.end_button_visible();
    let btn = end_button_rect(&rc);
    let text_right = if show_end { btn.left - 8 } else { rc.right - 10 };
    let text_w = (text_right - 10).max(0);

    SetTextColor(hdc, COLORREF(COL_TEXT));
    draw_text(hdc, st.presenter.headline(), 10, 6, text_w, 18, true);

    SelectObject(hdc, normal);
    draw_text(hdc, &st.presenter.detail(), 10, 26, text_w, 26, false);

    // --- End-session button (owner-drawn; no child controls — module decision 3) ---------------
    if show_end {
        let eb = CreateSolidBrush(COLORREF(COL_END_BTN));
        FillRect(hdc, &btn, eb);
        let _ = DeleteObject(eb);
        SetTextColor(hdc, COLORREF(COL_END_BTN_TEXT));
        // Centred, unlike the left-aligned body text — hence DrawTextW here rather than draw_text.
        let mut label: Vec<u16> = "End session".encode_utf16().collect();
        let mut lr = btn;
        DrawTextW(
            hdc,
            &mut label,
            &mut lr,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
        );
    }

    SetTextColor(hdc, COLORREF(COL_TEXT));
    draw_text(hdc, "Move corner", 10, banner_h + 5, rc.right / 2 - 20, 18, true);
    draw_text(hdc, if st.expanded_height.is_some() { "Show chat" } else { "Hide chat" },
        rc.right / 2, banner_h + 5, rc.right / 2 - 10, 18, true);
    if st.expanded_height.is_some() {
        SelectObject(hdc, old);
        let _ = DeleteObject(bold);
        let _ = DeleteObject(normal);
        return;
    }

    // --- chat log -----------------------------------------------------------------------------
    let mut y = banner_h + LAYOUT_H + 6;
    let log_bottom = rc.bottom - compose_h - 8;
    // Newest at the bottom: lay the visible tail out from the top of the remaining space.
    let lines: Vec<String> = st
        .presenter
        .lines()
        .iter()
        .map(|l| {
            let who = match l.from {
                ChatFrom::Technician => "Support",
                ChatFrom::Guest => "You",
            };
            format!("{who}: {}", l.body)
        })
        .collect();
    // Show only what fits, keeping the most recent.
    let per_line = 17;
    let room = ((log_bottom - y) / per_line).max(0) as usize;
    let start = lines.len().saturating_sub(room);
    for line in &lines[start..] {
        if y + per_line > log_bottom {
            break;
        }
        SetTextColor(hdc, COLORREF(COL_TEXT));
        draw_text(hdc, line, 10, y, rc.right - 20, per_line, true);
        y += per_line;
    }
    if lines.is_empty() {
        SetTextColor(hdc, COLORREF(COL_DIM));
        draw_text(
            hdc,
            "Type here to talk to the person helping you, then press Enter.",
            10,
            y,
            rc.right - 20,
            34,
            false,
        );
    }

    // --- compose ------------------------------------------------------------------------------
    let compose_rc =
        RECT { left: 6, top: rc.bottom - compose_h - 4, right: rc.right - 6, bottom: rc.bottom - 4 };
    let cb = CreateSolidBrush(COLORREF(COL_COMPOSE_BG));
    FillRect(hdc, &compose_rc, cb);
    let _ = DeleteObject(cb);
    let composing = st.presenter.compose();
    let (txt, col) = if composing.is_empty() {
        ("Message support…", COL_DIM)
    } else {
        (composing, COL_TEXT)
    };
    SetTextColor(hdc, COLORREF(col));
    draw_text(hdc, txt, 12, compose_rc.top + 5, rc.right - 24, 18, true);

    SelectObject(hdc, old);
    let _ = DeleteObject(bold);
    let _ = DeleteObject(normal);
}

/// A UI font at the given point-ish height.
unsafe fn make_font(height: i32, weight: i32) -> HGDIOBJ {
    CreateFontW(
        -height,
        0,
        0,
        0,
        weight,
        0,
        0,
        0,
        DEFAULT_CHARSET.0 as u32,
        OUT_TT_PRECIS.0 as u32,
        CLIP_DEFAULT_PRECIS.0 as u32,
        ANTIALIASED_QUALITY.0 as u32,
        FF_DONTCARE.0 as u32,
        w!("Segoe UI"),
    )
    .into()
}

/// Draw one run of text into a rect.
unsafe fn draw_text(
    hdc: windows::Win32::Graphics::Gdi::HDC,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    single_line: bool,
) {
    let mut wide: Vec<u16> = text.encode_utf16().collect();
    if wide.is_empty() {
        return;
    }
    let mut r = RECT { left: x, top: y, right: x + w, bottom: y + h };
    let flags = if single_line {
        DT_LEFT | DT_TOP | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX
    } else {
        DT_LEFT | DT_TOP | DT_WORDBREAK | DT_END_ELLIPSIS | DT_NOPREFIX
    };
    DrawTextW(hdc, &mut wide, &mut r, flags);
}

/// Unused-brush type alias keeps the `HBRUSH` import honest for readers of the paint code.
#[allow(dead_code)]
type _Brush = HBRUSH;

#[cfg(test)]
mod pill_lifecycle_tests {
    use super::*;
    use windows::Win32::Foundation::BOOL;
    use windows::Win32::UI::WindowsAndMessaging::{
        EnumThreadWindows, GetClassNameW, GetWindowDisplayAffinity, GetWindowThreadProcessId,
        WDA_EXCLUDEFROMCAPTURE, WS_EX_NOACTIVATE, WS_EX_TOPMOST,
    };

    unsafe extern "system" fn collect_pills(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let mut name = [0u16; 64];
        let n = GetClassNameW(hwnd, &mut name) as usize;
        if String::from_utf16_lossy(&name[..n]) == "DeskRallyPresencePill" {
            (*(lparam.0 as *mut Vec<isize>)).push(hwnd.0 as isize);
        }
        BOOL(1)
    }

    /// The pills owned by the UI thread of `guest` (enumerated per thread, so tests running in
    /// parallel never see each other's).
    unsafe fn pills_of(guest: HWND) -> Vec<isize> {
        let tid = GetWindowThreadProcessId(guest, None);
        let mut found: Vec<isize> = Vec::new();
        let _ = EnumThreadWindows(tid, Some(collect_pills), LPARAM(&mut found as *mut _ as isize));
        found
    }

    /// Ed (2026-10-23): a small, persistent "being controlled" indicator for the whole session. The REAL
    /// UI thread (off-screen, so nothing appears on this desktop) must create exactly one pill with the
    /// production window properties, and remove it the moment the session ends.
    #[test]
    fn a_live_session_shows_one_capture_excluded_topmost_pill_and_it_goes_at_session_end() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut w = GuestWindow::spawn(SessionInfo::default(), tx, true).expect("guest window");
        let guest = HWND(w.hwnd as *mut _);
        unsafe {
            let pills = pills_of(guest);
            assert_eq!(pills.len(), 1, "exactly one indicator per live session");
            let pill = HWND(pills[0] as *mut _);
            let mut affinity = 0u32;
            GetWindowDisplayAffinity(pill, &mut affinity).expect("read display affinity");
            assert_eq!(affinity, WDA_EXCLUDEFROMCAPTURE.0, "hidden from the technician's capture");
            let ex = GetWindowLongPtrW(pill, GWL_EXSTYLE) as u32;
            assert_ne!(ex & WS_EX_TOPMOST.0, 0, "always on top");
            assert_ne!(ex & WS_EX_NOACTIVATE.0, 0, "never steals the guest's focus");
            assert_ne!(ex & WS_EX_TOOLWINDOW.0, 0, "no taskbar button or Alt+Tab entry");
            // A WM_CLOSE (Alt+F4) cannot dismiss it while the session lives.
            let _ = PostMessageW(pill, WM_CLOSE, WPARAM(0), LPARAM(0));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        unsafe { assert!(IsWindow(HWND(pills_of(guest)[0] as *mut _)).as_bool(), "not dismissable while live"); }

        w.ended();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while unsafe { !pills_of(guest).is_empty() } && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        unsafe { assert!(pills_of(guest).is_empty(), "the indicator is removed at session end"); }
        w.close();
    }
}

#[cfg(test)]
mod tests {
    /// The panel's OWN show state: its `WS_VISIBLE` bit, which is exactly what `create_window`,
    /// `set_tray_available`, `reveal_session` and `hide_session_panel` control.
    ///
    /// `IsWindowVisible` also requires every ancestor to be `WS_VISIBLE`, and a top-level window's
    /// parent is its desktop's window. On a non-interactive window station (Session 0: a
    /// service-hosted runner, a PowerShell Direct guest) that desktop window is not visible, so
    /// `IsWindowVisible` is false for EVERY top-level window: the visible-fallback assertions fail
    /// and every "stays hidden" assertion passes vacuously. Where the desktop window is visible (any
    /// interactive desktop) the two must agree, and that is asserted rather than assumed.
    unsafe fn panel_shown(hwnd: HWND) -> bool {
        use windows::Win32::UI::WindowsAndMessaging::{GetAncestor, GA_PARENT, GWL_STYLE, WS_VISIBLE};
        let own = GetWindowLongPtrW(hwnd, GWL_STYLE) as u32 & WS_VISIBLE.0 != 0;
        if IsWindowVisible(GetAncestor(hwnd, GA_PARENT)).as_bool() {
            assert_eq!(IsWindowVisible(hwnd).as_bool(), own, "visible desktop: IsWindowVisible must match WS_VISIBLE");
        }
        own
    }

    #[test]
    fn compact_frame_accounts_for_display_scaling() {
        // Both panel styles (taskbar app window before the tray registers, tool window after).
        for tray in [false, true] {
            let mut previous = 0;
            for dpi in [96, 144, 192] {
                let height = layout_outer_height(dpi, panel_ex_style(tray)).unwrap();
                assert!(height >= BANNER_H + LAYOUT_H + 6);
                assert!(height >= previous);
                previous = height;
            }
        }
        // The app-window frame is never shorter than the tool-window one (EQUAL on Windows 11, see
        // layout_outer_height), so sizing with the window's own style never under-sizes the client.
        for dpi in [96, 144, 192] {
            assert!(
                layout_outer_height(dpi, panel_ex_style(false)).unwrap()
                    >= layout_outer_height(dpi, panel_ex_style(true)).unwrap()
            );
        }
    }

    #[test]
    fn render_layout_for_visual_review() {
        // Optional artifact output, using the production painter and an owned memory bitmap.
        // Never captures desktop pixels or opens a support session.
        let Ok(output) = std::env::var("RMT_GUEST_RENDER_DIR") else { return; };
        use windows::Win32::Graphics::Gdi::*;
        unsafe {
            for compact in [false, true] {
                let width = 380i32;
                let height = if compact { BANNER_H + LAYOUT_H + 6 } else { 270 };
                let dc = CreateCompatibleDC(None);
                assert!(!dc.0.is_null());
                let info = BITMAPINFO { bmiHeader: BITMAPINFOHEADER {
                    biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                    biWidth: width, biHeight: -height, biPlanes: 1, biBitCount: 32,
                    biCompression: BI_RGB.0, ..Default::default()
                }, ..Default::default() };
                let mut bits = std::ptr::null_mut();
                let bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, None, 0).unwrap();
                let old = SelectObject(dc, bitmap);
                let (mut st, _) = ui_state(SessionPhase::Active);
                if compact { st.expanded_height = Some(270); }
                st.presenter.on(GuestEvent::Posted { from: ChatFrom::Technician,
                    body: "Testing the support window layout.".into(), at_unix_ms: 0 });
                for c in "Draft stays when chat is hidden".chars() { st.presenter.on(GuestEvent::Typed(c)); }
                paint_content(dc, RECT { left: 0, top: 0, right: width, bottom: height }, &mut st);
                let _ = GdiFlush();
                let pixels = std::slice::from_raw_parts(bits as *const u8, (width * height * 4) as usize);
                let mut bmp = Vec::new();
                bmp.extend_from_slice(b"BM");
                bmp.extend_from_slice(&(54 + pixels.len() as u32).to_le_bytes());
                bmp.extend_from_slice(&[0; 4]);
                bmp.extend_from_slice(&54u32.to_le_bytes());
                bmp.extend_from_slice(&40u32.to_le_bytes());
                bmp.extend_from_slice(&width.to_le_bytes());
                bmp.extend_from_slice(&(-height).to_le_bytes());
                bmp.extend_from_slice(&1u16.to_le_bytes());
                bmp.extend_from_slice(&32u16.to_le_bytes());
                bmp.extend_from_slice(&[0; 24]);
                bmp.extend_from_slice(pixels);
                SelectObject(dc, old);
                let _ = DeleteObject(bitmap);
                let _ = DeleteDC(dc);
                let name = if compact { "compact.bmp" } else { "expanded.bmp" };
                std::fs::write(std::path::Path::new(&output).join(name), bmp).unwrap();
            }
        }
    }

    #[test]
    fn hidden_native_window_collapses_restores_and_moves_without_guest_actions() {
        // A real, hidden Win32 window, owned by this test; no service, session or SendInput.
        // A dedicated thread keeps WM_QUIT from leaking into another test's message queue.
        std::thread::spawn(|| unsafe {
            let (st, mut rx) = ui_state(SessionPhase::Active);
            let hwnd = create_window(Box::new(st), true).expect("create hidden guest window");
            struct Cleanup(HWND);
            impl Drop for Cleanup {
                fn drop(&mut self) { unsafe { let _ = DestroyWindow(self.0); } }
            }
            let _cleanup = Cleanup(hwnd);
            let mut initial = RECT::default();
            GetWindowRect(hwnd, &mut initial).unwrap();
            let click = |x: i32, y: i32| LPARAM(((y << 16) | (x & 0xffff)) as isize);
            assert!(handle_layout_click(hwnd, click(200, BANNER_H + 5)));
            let mut compact = RECT::default();
            GetWindowRect(hwnd, &mut compact).unwrap();
            assert!(compact.bottom - compact.top < initial.bottom - initial.top);
            assert!(state_of(hwnd).unwrap().expanded_height.is_some());
            // Exercise the real DPI message arm without changing the user's display settings.
            for dpi in [144usize, 96] {
                let suggested = RECT { left: 0, top: 0, right: 300, bottom: 50 };
                wndproc(hwnd, WM_DPICHANGED, WPARAM(dpi | (dpi << 16)),
                    LPARAM(&suggested as *const RECT as isize));
                let mut scaled_client = RECT::default();
                GetClientRect(hwnd, &mut scaled_client).unwrap();
                assert!(scaled_client.bottom >= BANNER_H + LAYOUT_H + 6,
                    "DPI transition must retain the status, End and layout controls");
            }
            assert!(handle_layout_click(hwnd, click(200, BANNER_H + 5)));
            let mut restored = RECT::default();
            GetWindowRect(hwnd, &mut restored).unwrap();
            assert_eq!(restored.bottom - restored.top, initial.bottom - initial.top);
            assert!(state_of(hwnd).unwrap().expanded_height.is_none());
            let mut corners = std::collections::HashSet::new();
            for _ in 0..4 {
                assert!(handle_layout_click(hwnd, click(10, BANNER_H + 5)));
                let mut moved = RECT::default();
                GetWindowRect(hwnd, &mut moved).unwrap();
                corners.insert((moved.left, moved.top));
            }
            assert_eq!(corners.len(), 4, "Move corner must actually change position");
            let mut client = RECT::default();
            GetClientRect(hwnd, &mut client).unwrap();
            let end = end_button_rect(&client);
            assert!(!handle_layout_click(hwnd, click(end.left + 1, end.top + 1)));
            assert!(rx.try_recv().is_err(), "layout must never send chat or End");
            assert!(!panel_shown(hwnd));
        }).join().unwrap();
    }

    #[test]
    fn layout_controls_never_overlap_end_or_chat() {
        let rc = RECT { left: 0, top: 0, right: 380, bottom: 270 };
        for y in 0..270 {
            for x in 0..380 {
                if layout_action(&rc, x, y).is_some() {
                    assert!(!end_button_hit(&rc, x, y));
                    assert!((BANNER_H..BANNER_H + LAYOUT_H).contains(&y));
                }
            }
        }
        assert_eq!(layout_action(&rc, 10, BANNER_H + 5), Some(LayoutAction::Move));
        assert_eq!(layout_action(&rc, 200, BANNER_H + 5), Some(LayoutAction::ToggleChat));
        assert_eq!(layout_action(&rc, -1, BANNER_H), None);
        assert_eq!(layout_action(&rc, 10, BANNER_H + LAYOUT_H), None);
    }

    /// The injected-input boundary, exhaustively over the input messages: injected input is NEVER
    /// dispatched; the one exception (an injected left-click on this window) goes to the layout
    /// row only. Genuine input always dispatches.
    #[test]
    fn injected_input_is_never_dispatched_and_only_layout_clicks_are_offered() {
        let keyboard = [WM_KEYDOWN, WM_SYSKEYDOWN, WM_CHAR, WM_SYSCHAR, WM_KEYUP, WM_SYSKEYUP];
        let mouse = [WM_LBUTTONDOWN, WM_LBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCLBUTTONDBLCLK,
            WM_NCRBUTTONDOWN, WM_NCRBUTTONUP];
        for &m in keyboard.iter().chain(mouse.iter()) {
            for own in [false, true] {
                assert_eq!(pump_disposition(false, m, own), PumpDisposition::Dispatch, "genuine {m:#x}");
                let d = pump_disposition(true, m, own);
                assert_ne!(d, PumpDisposition::Dispatch, "injected {m:#x} (own={own}) must not dispatch");
                let layout = m == WM_LBUTTONDOWN && own;
                assert_eq!(d == PumpDisposition::LayoutOnly, layout, "injected {m:#x} (own={own})");
            }
        }
        // Non-input messages are not provenance-gated (they are not the guest's controls).
        assert_eq!(pump_disposition(true, WM_PAINT, true), PumpDisposition::Dispatch);
    }

    /// The whole guest lifecycle on a REAL window, with every technician action going through the
    /// production pump gate ([`pump_filter`]): tray start → first technician message reveals →
    /// injected Hide chat shrinks the VISIBLE panel without hiding it → injected End click and
    /// injected typing change nothing → injected Show chat restores → guest minimize tucks into the
    /// tray (or, with no Explorer tray, stays visible as the fallback) → tray click restores →
    /// injected Move corner physically moves the panel. Nothing reaches the host at any point.
    /// The panel lives at (-32000,-32000) while visible, so it never appears on the desktop.
    #[test]
    fn real_window_reveal_collapse_tray_and_injected_pump_gate() {
        std::thread::spawn(|| unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{IsWindow, PeekMessageW, PM_REMOVE, WM_QUIT};
            let (st, mut rx) = ui_state(SessionPhase::Active);
            let hwnd = create_window(Box::new(st), true).expect("create guest window");
            struct Cleanup(HWND);
            impl Drop for Cleanup {
                fn drop(&mut self) { unsafe {
                    if IsWindow(self.0).as_bool() { let _ = DestroyWindow(self.0); }
                    let mut q = Default::default();
                    let _ = PeekMessageW(&mut q, None, WM_QUIT, WM_QUIT, PM_REMOVE);
                } }
            }
            let _cleanup = Cleanup(hwnd);
            let rect = |h: HWND| { let mut r = RECT::default(); GetWindowRect(h, &mut r).unwrap(); r };
            let injected = |message: u32, x: i32, y: i32| pump_filter(hwnd, &MSG {
                hwnd, message, wParam: WPARAM(0),
                lParam: LPARAM(((y << 16) | (x & 0xffff)) as isize), ..Default::default()
            }, true);

            // Production tray start: a real Explorer icon when available, else the visible fallback.
            state_of(hwnd).unwrap().offscreen = false;
            register_session_tray(hwnd);
            let registered = state_of(hwnd).unwrap().tray_registered;
            if std::env::var_os("RMT_REQUIRE_TRAY_TEST").is_some() {
                assert!(registered, "interactive run requires the real Explorer tray branch");
            }
            assert_eq!(panel_shown(hwnd), !registered);
            let _ = ShowWindow(hwnd, SW_HIDE);

            // First live technician message reveals the panel (mainline 163572c).
            state_of(hwnd).unwrap().inbox.lock().unwrap().push_back(GuestEvent::Posted {
                from: ChatFrom::Technician, body: "hello".into(), at_unix_ms: 1 });
            wndproc(hwnd, WM_RMT_EVENTS, WPARAM(0), LPARAM(0));
            assert!(panel_shown(hwnd), "first technician message reveals");
            let full = rect(hwnd);

            // A NON-EMPTY guest draft, typed through the real dispatch target (genuine input), so
            // every "draft unchanged" check below can fail. Injected characters carry real code
            // points (nonzero wParam), so a leak would visibly alter the draft.
            for c in "keep".chars() { wndproc(hwnd, WM_CHAR, WPARAM(c as usize), LPARAM(0)); }
            let draft = |h: HWND| state_of(h).unwrap().presenter.compose().to_string();
            assert_eq!(draft(hwnd), "keep", "genuine typing reaches the compose line");
            let injected_char = |c: char| pump_filter(hwnd, &MSG {
                hwnd, message: WM_CHAR, wParam: WPARAM(c as usize), ..Default::default()
            }, true);

            // Injected Hide chat: consumed by the gate, shrinks the VISIBLE panel, does not hide it.
            assert!(!injected(WM_LBUTTONDOWN, 200, BANNER_H + 5), "layout click is never dispatched");
            let compact = rect(hwnd);
            assert!(compact.bottom - compact.top < full.bottom - full.top, "Hide chat shrinks the panel");
            assert!(panel_shown(hwnd), "Hide chat collapses; it never hides the window");
            assert_eq!(state_of(hwnd).unwrap().tray_registered, registered, "layout never touches the tray");
            assert_eq!(draft(hwnd), "keep", "collapse preserves the guest's draft");

            // Injected End click and injected typing: not dispatched, no effect, nothing sent.
            let mut client = RECT::default();
            GetClientRect(hwnd, &mut client).unwrap();
            let end = end_button_rect(&client);
            assert!(!injected(WM_LBUTTONDOWN, end.left + 2, end.top + 2), "injected End is never dispatched");
            assert!(!injected_char('x') && !injected(WM_KEYDOWN, 0, 0), "injected typing is never dispatched");
            assert_eq!(draft(hwnd), "keep", "injected typing must not alter the draft");
            assert_eq!(rect(hwnd), compact, "an injected End click must not move or resize anything");

            // Injected Show chat restores the full panel; injected typing on the open compose line
            // is still never dispatched.
            assert!(!injected(WM_LBUTTONDOWN, 200, BANNER_H + 5));
            assert_eq!(rect(hwnd).bottom - rect(hwnd).top, full.bottom - full.top);
            assert!(!injected_char('y'));
            assert_eq!(draft(hwnd), "keep", "Show chat preserves the draft; injected typing never lands");

            // Guest minimize → tray (or the visible fallback when Explorer has no tray), then a tray
            // click restores. Tray paths are mainline's, unchanged by the layout row.
            wndproc(hwnd, WM_SYSCOMMAND, WPARAM(SC_MINIMIZE as usize), LPARAM(0));
            assert_eq!(panel_shown(hwnd), !registered, "minimize tucks into the tray only when one exists");
            if registered {
                wndproc(hwnd, WM_RMT_TRAY, WPARAM(SESSION_TRAY_ID as usize), LPARAM(WM_LBUTTONUP as isize));
                assert!(panel_shown(hwnd), "tray click restores the panel");
            }
            assert_eq!(draft(hwnd), "keep", "tray hide/restore preserves the draft");

            // Injected Move corner physically moves the panel (hidden first, so it never shows on
            // the desktop at the real corners).
            let _ = ShowWindow(hwnd, SW_HIDE);
            let mut corners = std::collections::HashSet::new();
            for _ in 0..4 {
                assert!(!injected(WM_LBUTTONDOWN, 10, BANNER_H + 5));
                let r = rect(hwnd);
                corners.insert((r.left, r.top));
            }
            assert_eq!(corners.len(), 4, "injected Move corner must change the real window rect");
            assert_eq!(draft(hwnd), "keep", "moving preserves the draft");

            assert!(rx.try_recv().is_err(), "no technician action may send chat or End for the guest");
            state_of(hwnd).unwrap().presenter.on(GuestEvent::Ended);
            wndproc(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
        }).join().unwrap();
    }

    /// Tray + layout row TOGETHER (the merge this release exists for), on a real hidden window:
    /// the layout row works on a tray-style (tool) panel, a collapse keeps the banner/End/layout row
    /// on BOTH panel styles, and no layout action or tray-menu choice can hide to the tray, change
    /// tray state, or send anything (chat or End) to the host.
    #[test]
    fn tray_and_layout_row_coexist_without_guest_actions() {
        std::thread::spawn(|| unsafe {
            use windows::Win32::UI::WindowsAndMessaging::{PeekMessageW, PM_REMOVE, WM_QUIT};
            let (st, mut rx) = ui_state(SessionPhase::Active);
            let hwnd = create_window(Box::new(st), true).expect("create hidden guest window");
            struct Cleanup(HWND);
            impl Drop for Cleanup {
                fn drop(&mut self) { unsafe {
                    let _ = DestroyWindow(self.0);
                    let mut q = Default::default();
                    let _ = PeekMessageW(&mut q, None, WM_QUIT, WM_QUIT, PM_REMOVE);
                } }
            }
            let _cleanup = Cleanup(hwnd);
            let click = |x: i32, y: i32| LPARAM(((y << 16) | (x & 0xffff)) as isize);
            // NOT offscreen while exercising layout: hide/reveal paths are no-ops for offscreen
            // windows, so a layout action wrongly routed into the tray hide would go unseen. The
            // window was created at (-32000,-32000), so even a buggy show stays off the desktop.
            state_of(hwnd).unwrap().offscreen = false;

            for tray in [true, false] {
                // Put the panel in each tray state's real style WITHOUT showing it: offscreen
                // windows skip set_tray_available, so set the style the way it would.
                state_of(hwnd).unwrap().tray_registered = tray;
                SetWindowLongPtrW(hwnd, GWL_EXSTYLE, panel_ex_style(tray).0 as isize);
                let _ = SetWindowPos(hwnd, None, 0, 0, 0, 0,
                    SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

                // Collapse (Hide chat) then a DPI round-trip: the compact client keeps the
                // banner + End + layout row on THIS style's frame.
                assert!(handle_layout_click(hwnd, click(200, BANNER_H + 5)));
                assert!(state_of(hwnd).unwrap().expanded_height.is_some());
                for dpi in [144usize, 96] {
                    let suggested = RECT { left: 0, top: 0, right: 300, bottom: 40 };
                    wndproc(hwnd, WM_DPICHANGED, WPARAM(dpi | (dpi << 16)),
                        LPARAM(&suggested as *const RECT as isize));
                    let mut c = RECT::default();
                    GetClientRect(hwnd, &mut c).unwrap();
                    assert!(c.bottom >= BANNER_H + LAYOUT_H + 6,
                        "tray={tray} dpi={dpi}: collapsed client {} clips the layout row", c.bottom);
                }
                // Typing while collapsed must not reach the hidden compose line.
                wndproc(hwnd, WM_CHAR, WPARAM('x' as usize), LPARAM(0));
                assert!(handle_layout_click(hwnd, click(200, BANNER_H + 5)), "Show chat");
                assert!(state_of(hwnd).unwrap().expanded_height.is_none());
                assert!(handle_layout_click(hwnd, click(10, BANNER_H + 5)), "Move corner");

                // Layout never hides to the tray, never changes tray state, never shows the panel.
                assert_eq!(state_of(hwnd).unwrap().tray_registered, tray);
                assert!(!panel_shown(hwnd));
            }

            // "Show session" only reveals; "End session" not proven to be the guest's only reveals.
            // (Offscreen again so the reveal itself does not take the foreground during a test run.)
            state_of(hwnd).unwrap().offscreen = true;
            apply_tray_choice(hwnd, 1, true);
            apply_tray_choice(hwnd, 2, false);
            assert!(rx.try_recv().is_err(), "layout, Show session and an unproven tray End must never send chat or End");
            // The guest's own choice of tray "End session" ends the session (10-28).
            apply_tray_choice(hwnd, 2, true);
            assert_eq!(rx.try_recv().ok(), Some(GuestToHost::End), "the guest's tray End must end the session");
            assert!(state_of(hwnd).unwrap().presenter.compose().is_empty(), "collapsed typing leaked into the draft");
        }).join().unwrap();
    }

    use super::*;

    /// A 360×240 client area, the window's own size at 96 DPI.
    fn client() -> RECT {
        RECT { left: 0, top: 0, right: WIN_W, bottom: WIN_H }
    }

    #[test]
    fn the_end_button_sits_inside_the_banner_at_the_right_edge() {
        let c = client();
        let b = end_button_rect(&c);
        assert!(b.right <= c.right, "not off the right edge");
        assert!(b.left > c.right / 2, "right-aligned, out of the headline's way");
        assert!(b.top >= 0 && b.bottom <= BANNER_H, "vertically within the banner");
        assert!(b.right > b.left && b.bottom > b.top, "a non-empty rect");
    }

    #[test]
    fn the_hit_test_matches_the_drawn_rect_and_only_it() {
        let c = client();
        let b = end_button_rect(&c);
        let cx = (b.left + b.right) / 2;
        let cy = (b.top + b.bottom) / 2;
        assert!(end_button_hit(&c, cx, cy), "the centre of the button is a hit");
        // Just outside each edge is a miss (half-open interval on right/bottom).
        assert!(!end_button_hit(&c, b.left - 1, cy), "left of the button");
        assert!(!end_button_hit(&c, b.right, cy), "the right edge is exclusive");
        assert!(!end_button_hit(&c, cx, b.top - 1), "above the button");
        assert!(!end_button_hit(&c, cx, b.bottom), "the bottom edge is exclusive");
        // A click down in the compose box is never on the End button.
        assert!(!end_button_hit(&c, 20, WIN_H - 12), "the compose area is not the button");
    }

    // --- closing the window (docs/12 §1 footgun) ----------------------------------------------

    #[test]
    fn closing_a_live_window_reveals_end_without_hiding_the_indicator() {
        assert_eq!(close_action(SessionPhase::Active), CloseAction::RevealEndButton);
    }

    #[test]
    fn closing_an_ended_window_just_dismisses_it() {
        // Once the session is over there is nothing to end; the window is a receipt, so a close
        // destroys it rather than sending an End the host has no session to act on.
        assert_eq!(close_action(SessionPhase::Ended), CloseAction::DestroyNow);
    }

    /// Build the WNDPROC's `UiState` in a given phase, with a receiver for the `to_host` channel so a
    /// test can observe what a close actually SENDS. No window, no desktop — `on_user_close` is the
    /// exact code the `WM_CLOSE` arm runs, minus the `DestroyWindow` FFI it decides to call.
    fn ui_state(
        phase: SessionPhase,
    ) -> (UiState, tokio::sync::mpsc::UnboundedReceiver<GuestToHost>) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let mut presenter = GuestPresenter::new(SessionInfo::default());
        if phase == SessionPhase::Ended {
            presenter.on(GuestEvent::Ended);
        }
        let st = UiState {
            presenter,
            pill: 0,
            panel_is_indicator: false,
            inbox: Arc::new(Mutex::new(VecDeque::new())),
            to_host: tx,
            offscreen: true,
            title_shown: None,
            tray_registered: false,
            first_tech_revealed: false,
            expanded_height: None,
            layout_corner: 0,
        };
        (st, rx)
    }

    #[test]
    fn caption_update_re_titles_only_on_a_real_change() {
        // First sight (nothing shown yet) writes the caption; re-asserting the same one is a no-op so
        // an idle window is not re-titled on every WM_RMT_EVENTS; a genuinely new caption writes again.
        assert_eq!(caption_update(None, "controlling"), Some("controlling"), "first sight titles");
        assert_eq!(caption_update(Some("controlling"), "controlling"), None, "unchanged ⇒ no re-title");
        assert_eq!(
            caption_update(Some("controlling"), "VIEW ONLY"),
            Some("VIEW ONLY"),
            "a changed state re-titles"
        );
    }

    #[test]
    fn session_window_has_a_taskbar_entry_for_restore() {
        use windows::Win32::UI::WindowsAndMessaging::{GWL_EXSTYLE, WS_EX_TOOLWINDOW, PeekMessageW, PM_REMOVE, WM_QUIT};
        let (state, _rx) = ui_state(SessionPhase::Ended);
        // Exercise the real window factory without showing a window or starting a session.
        unsafe {
            let hwnd = create_window(Box::new(state), true).expect("create offscreen guest window");
            let styles = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
            let _ = DestroyWindow(hwnd);
            // WM_DESTROY posts quit for the real UI pump; don't leave it on a reused test thread.
            let mut quit = Default::default();
            let _ = PeekMessageW(&mut quit, None, WM_QUIT, WM_QUIT, PM_REMOVE);
            assert_ne!(styles & WS_EX_APPWINDOW.0, 0, "must offer a taskbar restore target");
            assert_eq!(styles & WS_EX_TOOLWINDOW.0, 0, "tool windows disappear from taskbar/Alt+Tab");
        }
    }

    #[test]
    #[ignore = "requires an interactive desktop to exercise the native menu loop"]
    fn host_teardown_while_tray_menu_is_open_preserves_outer_quit() {
        use windows::Win32::UI::WindowsAndMessaging::{PeekMessageW, PM_REMOVE, WM_QUIT};
        let (state, mut rx) = ui_state(SessionPhase::Active);
        unsafe {
            let hwnd = create_window(Box::new(state), true).expect("create isolated menu owner");
            state_of(hwnd).unwrap().offscreen = false;
            let _ = ShowWindow(hwnd, SW_SHOWNA);
            let raw = hwnd.0 as usize;
            let shutdown = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(150));
                PostMessageW(HWND(raw as *mut _), WM_RMT_DESTROY, WPARAM(0), LPARAM(0))
                    .expect("post host teardown to open menu");
            });
            session_tray_menu(hwnd);
            shutdown.join().expect("shutdown worker");
            assert!(!IsWindow(hwnd).as_bool(), "host teardown dispatched inside modal menu");
            let mut quit = Default::default();
            assert!(PeekMessageW(&mut quit, None, WM_QUIT, WM_QUIT, PM_REMOVE).as_bool(),
                "outer guest pump must receive quit after nested menu returns");
            assert!(rx.try_recv().is_err(), "host teardown must not send a guest End");
        }
    }

    /// The REAL tray menu, chosen with real SendInput: "End session" picked by input carrying this
    /// agent's injection tag must only reveal; the same keys untagged (standing in for the guest's
    /// hardware) must end the session. Proves the low-level hooks see the selecting input's
    /// `dwExtraInfo` through TrackPopupMenu's modal loop (Codex tray r1). Run in the VM's interactive
    /// session: `--ignored tray_end_by_real_menu`.
    #[test]
    #[ignore = "requires an interactive desktop to exercise the native menu loop"]
    fn tray_end_by_real_menu_ends_only_for_untagged_input() {
        use windows::Win32::UI::Input::KeyboardAndMouse::{
            SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
            VIRTUAL_KEY, VK_DOWN, VK_RETURN,
        };
        fn press(vk: VIRTUAL_KEY, extra: usize) {
            let key = |flags: KEYBD_EVENT_FLAGS| INPUT {
                r#type: INPUT_KEYBOARD,
                Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: 0, dwFlags: flags, time: 0, dwExtraInfo: extra } },
            };
            let sent = unsafe { SendInput(&[key(KEYBD_EVENT_FLAGS(0)), key(KEYEVENTF_KEYUP)], std::mem::size_of::<INPUT>() as i32) };
            assert_eq!(sent, 2, "SendInput refused (no interactive desktop?)");
        }
        for (extra, expect_end) in [(crate::input::RMT_INJECTED_TAG, false), (0usize, true)] {
            let (state, mut rx) = ui_state(SessionPhase::Active);
            unsafe {
                let hwnd = create_window(Box::new(state), true).expect("create menu owner");
                state_of(hwnd).unwrap().offscreen = false;
                let _ = ShowWindow(hwnd, SW_SHOWNA);
                let driver = std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                    press(VK_DOWN, extra);
                    press(VK_DOWN, extra);
                    press(VK_RETURN, extra);
                });
                session_tray_menu(hwnd);
                driver.join().expect("input driver");
                let got = rx.try_recv().ok();
                eprintln!("tray menu chosen with extra={extra:#x}: sent {got:?}");
                if expect_end {
                    assert_eq!(got, Some(GuestToHost::End), "untagged tray End must end the session");
                } else {
                    assert!(got.is_none(), "tagged tray End must not end the session");
                    assert!(panel_shown(hwnd), "tagged tray End reveals the panel instead");
                }
                if IsWindow(hwnd).as_bool() { let _ = DestroyWindow(hwnd); }
                let mut quit = Default::default();
                let _ = windows::Win32::UI::WindowsAndMessaging::PeekMessageW(&mut quit, None,
                    windows::Win32::UI::WindowsAndMessaging::WM_QUIT, windows::Win32::UI::WindowsAndMessaging::WM_QUIT,
                    windows::Win32::UI::WindowsAndMessaging::PM_REMOVE);
            }
        }
    }

    // --- bounded guest chat UX: initial-hidden, auto-reveal, topmost removal --------------------

    #[test]
    fn production_window_starts_hidden_when_tray_is_available() {
        use windows::Win32::UI::WindowsAndMessaging::{PeekMessageW, PM_REMOVE, WM_QUIT};
        let (mut state, _rx) = ui_state(SessionPhase::Active);
        state.offscreen = false;
        unsafe {
            let hwnd = create_window(Box::new(state), false).expect("create production-path panel");
            let registered = state_of(hwnd).unwrap().tray_registered;
            let visible = panel_shown(hwnd);
            let _ = DestroyWindow(hwnd);
            let mut quit = Default::default();
            let _ = PeekMessageW(&mut quit, None, WM_QUIT, WM_QUIT, PM_REMOVE);
            if std::env::var_os("RMT_REQUIRE_TRAY_TEST").is_some() {
                assert!(registered, "interactive test requires real Explorer tray registration");
            }
            assert_eq!(visible, !registered, "only missing tray makes the initial panel visible");
        }
    }

    #[test]
    fn no_topmost_in_panel_ex_style() {
        use windows::Win32::UI::WindowsAndMessaging::WS_EX_TOPMOST;
        assert_eq!(
            panel_ex_style(false).0 & WS_EX_TOPMOST.0, 0,
            "taskbar-restore window must not be always-on-top",
        );
        assert_eq!(
            panel_ex_style(true).0 & WS_EX_TOPMOST.0, 0,
            "tray-icon window must not be always-on-top",
        );
    }

    #[test]
    fn should_auto_reveal_only_first_live_technician_message() {
        // Seeded history must not open the window.
        assert!(
            !should_auto_reveal(
                &GuestEvent::Seeded { from: ChatFrom::Technician, body: "hi".into(), at_unix_ms: 0 },
                false, SessionPhase::Active,
            ),
            "seeded technician message must not reveal",
        );
        // Guest's own echo must not open the window.
        assert!(
            !should_auto_reveal(
                &GuestEvent::Posted { from: ChatFrom::Guest, body: "ok".into(), at_unix_ms: 0 },
                false, SessionPhase::Active,
            ),
            "guest echo must not reveal",
        );
        // Non-chat events must not open the window.
        assert!(
            !should_auto_reveal(&GuestEvent::ViewOnly(true), false, SessionPhase::Active),
            "view-only event must not reveal",
        );
        assert!(
            !should_auto_reveal(&GuestEvent::Recording(true), false, SessionPhase::Active),
            "recording event must not reveal",
        );
        // First live technician message while active: reveal.
        assert!(
            should_auto_reveal(
                &GuestEvent::Posted { from: ChatFrom::Technician, body: "hello".into(), at_unix_ms: 1 },
                false, SessionPhase::Active,
            ),
            "first live technician message must trigger reveal",
        );
        // Subsequent messages after reveal flag set must NOT re-open (guest hid the window).
        assert!(
            !should_auto_reveal(
                &GuestEvent::Posted { from: ChatFrom::Technician, body: "again".into(), at_unix_ms: 2 },
                true,  // already_revealed
                SessionPhase::Active,
            ),
            "subsequent technician message must not re-reveal after first",
        );
        // Tech message after session ended: no reveal.
        assert!(
            !should_auto_reveal(
                &GuestEvent::Posted { from: ChatFrom::Technician, body: "late".into(), at_unix_ms: 3 },
                false, SessionPhase::Ended,
            ),
            "technician message after session end must not reveal",
        );
    }

    /// Extends `session_window_has_a_taskbar_entry_for_restore` with: no topmost, initial-hidden
    /// for tray success, and visible fallback for tray failure — exercised through the same native
    /// window factory without showing a real window.
    #[test]
    fn initialhidden_trayfallback_and_no_topmost() {
        use windows::Win32::UI::WindowsAndMessaging::{
            PeekMessageW, PM_REMOVE, WM_QUIT, WS_EX_TOPMOST,
        };
        struct Guard(HWND);
        impl Drop for Guard {
            fn drop(&mut self) { unsafe {
                if IsWindow(self.0).as_bool() { let _ = DestroyWindow(self.0); }
                let mut q = Default::default();
                let _ = PeekMessageW(&mut q, None, WM_QUIT, WM_QUIT, PM_REMOVE);
            } }
        }
        let (state, _rx) = ui_state(SessionPhase::Active);
        unsafe {
            let hwnd = create_window(Box::new(state), true).expect("create isolated test panel");
            let _g = Guard(hwnd);
            let styles = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
            assert_eq!(styles & WS_EX_TOPMOST.0, 0, "window must not be always-on-top");

            // Switch out of offscreen so set_tray_available is not a no-op.
            state_of(hwnd).unwrap().offscreen = false;

            // Tray failure must make the window visible as a fallback (no icon to restore from).
            set_tray_available(hwnd, false);
            assert!(
                panel_shown(hwnd),
                "tray failure must show the fallback panel",
            );

            // Run actual queued events through WNDPROC, rather than just testing the predicate.
            let _ = ShowWindow(hwnd, SW_HIDE);
            let foreground = windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow();
            let post = |event| {
                state_of(hwnd).unwrap().inbox.lock().unwrap().push_back(event);
                wndproc(hwnd, WM_RMT_EVENTS, WPARAM(0), LPARAM(0));
            };
            post(GuestEvent::Seeded { from: ChatFrom::Technician, body: "old".into(), at_unix_ms: 1 });
            post(GuestEvent::Posted { from: ChatFrom::Guest, body: "echo".into(), at_unix_ms: 2 });
            post(GuestEvent::ViewOnly(true));
            assert!(!panel_shown(hwnd), "history, echoes and status do not open chat");
            post(GuestEvent::Posted { from: ChatFrom::Technician, body: "hello".into(), at_unix_ms: 3 });
            assert!(panel_shown(hwnd), "first new technician message opens chat");
            assert_eq!(windows::Win32::UI::WindowsAndMessaging::GetForegroundWindow(), foreground,
                "automatic reveal must preserve the foreground window");
            assert_eq!(state_of(hwnd).unwrap().presenter.lines().back().unwrap().body, "hello");
            let _ = ShowWindow(hwnd, SW_HIDE);
            post(GuestEvent::Posted { from: ChatFrom::Technician, body: "later".into(), at_unix_ms: 4 });
            assert!(!panel_shown(hwnd), "later messages respect hiding");

            // Even a first live message must not reveal the lab's offscreen surface.
            state_of(hwnd).unwrap().offscreen = true;
            state_of(hwnd).unwrap().first_tech_revealed = false;
            post(GuestEvent::Posted { from: ChatFrom::Technician, body: "lab".into(), at_unix_ms: 5 });
            assert!(!panel_shown(hwnd), "offscreen surface stays hidden");
            state_of(hwnd).unwrap().offscreen = false;

            // Re-hide, then simulate tray success: window must stay hidden.
            let _ = ShowWindow(hwnd, SW_HIDE);
            set_tray_available(hwnd, true);
            assert!(
                !panel_shown(hwnd),
                "tray success must keep the panel hidden (tray icon is the only entry point)",
            );
        }
    }

    #[test]
    fn session_tray_lifecycle_keeps_restore_and_end_available() {
        use windows::Win32::UI::WindowsAndMessaging::{IsWindow, PeekMessageW, PM_REMOVE, WM_QUIT};
        struct TestWindow(HWND);
        impl Drop for TestWindow {
            fn drop(&mut self) { unsafe {
                if IsWindow(self.0).as_bool() { let _ = DestroyWindow(self.0); }
                let mut quit = Default::default();
                let _ = PeekMessageW(&mut quit, None, WM_QUIT, WM_QUIT, PM_REMOVE);
            } }
        }
        let (state, mut rx) = ui_state(SessionPhase::Active);
        unsafe {
            let hwnd = create_window(Box::new(state), true).expect("create isolated test panel");
            let _cleanup = TestWindow(hwnd);
            assert!(!state_of(hwnd).unwrap().tray_registered, "offscreen mode must not add an icon");
            state_of(hwnd).unwrap().offscreen = false;
            register_session_tray(hwnd);
            let registered = state_of(hwnd).unwrap().tray_registered;
            if std::env::var_os("RMT_REQUIRE_TRAY_TEST").is_some() {
                assert!(registered, "interactive test requires real Explorer tray registration");
            }
            // Windows adds WS_EX_WINDOWEDGE for the caption; compare only our restore-target bits.
            let mask = WS_EX_APPWINDOW.0 | WS_EX_TOOLWINDOW.0;
            assert_eq!(GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 & mask, panel_ex_style(registered).0 & mask);
            wndproc(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
            assert!(IsWindow(hwnd).as_bool(), "active Close must not destroy panel");
            assert_eq!(panel_shown(hwnd), !registered);
            assert!(rx.try_recv().is_err(), "shell Close must not end the session");
            apply_tray_choice(hwnd, 2, false);
            assert!(panel_shown(hwnd), "an unproven tray End reveals the protected End control");
            assert!(rx.try_recv().is_err(), "an unproven tray End cannot impersonate a guest End click");
            if registered {
                wndproc(hwnd, WM_SYSCOMMAND, WPARAM(SC_MINIMIZE as usize), LPARAM(0));
                assert!(!panel_shown(hwnd), "minimize tucks panel into tray");
                // Simulate loss of this icon, not an actual Explorer restart.
                let nid = session_nid(hwnd);
                assert!(Shell_NotifyIconW(NIM_DELETE, &nid).as_bool());
                hide_session_panel(hwnd);
                assert!(panel_shown(hwnd), "missing tray restores a visible fallback");
                assert!(!state_of(hwnd).unwrap().tray_registered);
                assert_ne!(GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 & WS_EX_APPWINDOW.0, 0);
                let message = *TASKBAR_CREATED.get().unwrap();
                wndproc(hwnd, message, WPARAM(0), LPARAM(0));
                assert!(state_of(hwnd).unwrap().tray_registered, "Explorer recreation restores icon");
                assert!(panel_shown(hwnd), "style transition preserves panel visibility");
                assert_eq!(GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 & mask, WS_EX_TOOLWINDOW.0);
                hide_session_panel(hwnd);
                wndproc(hwnd, WM_RMT_TRAY, WPARAM(SESSION_TRAY_ID as usize), LPARAM(WM_LBUTTONUP as isize));
                assert!(panel_shown(hwnd), "tray click restores the panel");
            }
            assert!(rx.try_recv().is_err());
            state_of(hwnd).unwrap().presenter.on(GuestEvent::Ended);
            let nid = session_nid(hwnd);
            wndproc(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0));
            assert!(!IsWindow(hwnd).as_bool(), "ended receipt closes normally");
            assert!(!Shell_NotifyIconW(NIM_MODIFY, &nid).as_bool(), "destroy must remove tray icon");
            let mut quit = Default::default();
            let _ = PeekMessageW(&mut quit, None, WM_QUIT, WM_QUIT, PM_REMOVE);
        }
    }

    #[test]
    fn shell_close_keeps_the_indicator_without_impersonating_guest_end() {
        let (mut st, mut rx) = ui_state(SessionPhase::Active);
        assert!(!st.on_user_close(), "keep the active indicator alive");
        assert!(rx.try_recv().is_err(), "shell close must not send End");
        st.dispatch(GuestEvent::EndClicked);
        assert_eq!(rx.try_recv().ok(), Some(GuestToHost::End), "the real End button still works");
    }

    #[test]
    fn a_user_close_after_the_session_ended_destroys_and_sends_nothing() {
        // Once ended there is no session to end; the window is a receipt, so a close destroys it and
        // sends no End (an End the host would have no session to act on).
        let (mut st, mut rx) = ui_state(SessionPhase::Ended);
        let must_destroy = st.on_user_close();
        assert!(must_destroy, "an ended window is dismissed by closing it");
        assert!(rx.try_recv().is_err(), "no End is sent once the session has already ended");
    }

    // --- the injected-mouse filter (docs/12 §13.6) --------------------------------------------

    #[test]
    fn the_mouse_actuator_filter_covers_every_way_an_injected_click_could_end_the_session() {
        use windows::Win32::UI::WindowsAndMessaging::{
            WM_LBUTTONUP, WM_MBUTTONDOWN, WM_MOUSEMOVE, WM_RBUTTONDOWN,
        };
        // Every message an injected click MUST be dropped on:
        //   * the End button's LBUTTONDOWN;
        //   * the caption [X]'s NC left button-down (DefWindowProc -> SC_CLOSE -> WM_CLOSE);
        //   * the caption right button (down AND up) — its up opens the system menu whose Close ends
        //     the session via a modal loop this pump can't see, so it must be stopped before the menu
        //     opens (see the fn doc);
        //   * the double-click twins (unreachable today without CS_DBLCLKS — a guard, see the fn doc).
        // Miss any of these and the technician's injected click can actuate the guest's End/close.
        for m in [
            WM_LBUTTONDOWN, WM_LBUTTONDBLCLK, WM_NCLBUTTONDOWN, WM_NCLBUTTONDBLCLK,
            WM_NCRBUTTONDOWN, WM_NCRBUTTONUP,
        ] {
            assert!(is_mouse_actuator_message(m), "actuator message {m:#x} must be filtered");
        }
        // Non-actuators must NOT be filtered: dropping the pointer MOVE would break the technician
        // steering the cursor toward legitimate targets, a left button-UP changes nothing, and a
        // CLIENT-area right/middle button opens no menu on this window (DefWindowProc shows the window
        // menu only for a NON-client context menu). Over-broad filtering is its own defect.
        for m in [WM_MOUSEMOVE, WM_LBUTTONUP, WM_RBUTTONDOWN, WM_MBUTTONDOWN] {
            assert!(!is_mouse_actuator_message(m), "non-actuator message {m:#x} must NOT be filtered");
        }
    }
}

#[cfg(test)]
mod panel_indicator_tests {
    use super::*;

    #[test]
    fn without_a_pill_the_panel_stays_up_until_the_session_ends() {
        assert!(panel_must_stay(true, SessionPhase::Active));
        assert!(!panel_must_stay(true, SessionPhase::Ended), "the ended panel is a receipt, hideable");
        assert!(!panel_must_stay(false, SessionPhase::Active), "with a pill the panel may tuck away");
    }

    #[test]
    fn hide_session_panel_consults_the_indicator_rule_before_hiding() {
        let src = include_str!("guest_window.rs");
        let f = src.find(concat!("unsafe fn hide_session_", "panel(hwnd: HWND) {")).expect("hide_session_panel");
        let body = &src[f..f + 900];
        let rule = body.find(concat!("panel_must_", "stay(")).expect("hide_session_panel must consult panel_must_stay");
        let hide = body.find(concat!("ShowWindow(hwnd, SW_", "HIDE)")).expect("the hide");
        assert!(rule < hide, "the rule must run before the panel is hidden");
    }
}
