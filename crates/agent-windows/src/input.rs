//! Input injection via the Win32 `SendInput` API.
//!
//! `SendInput` is the **only** correct primitive here (ADR-005). We deliberately avoid:
//! * `mouse_event` / `keybd_event` — legacy shims that route through `SendInput` anyway and
//!   drop events under load;
//! * `SetCursorPos` — cannot express buttons and is subject to pointer acceleration, so the
//!   remote pointer drifts relative to the controller.
//!
//! Mouse motion is delivered as **absolute** input across the whole virtual desktop
//! (`MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK`) using coordinates normalized to the
//! `0..=65535` range. That range maps onto the virtual-desktop bounding box
//! (`SM_XVIRTUALSCREEN`/`SM_CXVIRTUALSCREEN`, …) *by Windows*, which is exactly why the
//! injecting process must be **PerMonitorV2 DPI-aware** (see
//! [`crate::set_process_dpi_awareness`]): otherwise Windows virtualizes the pixel space and
//! the mapping shifts under mixed-DPI fractional scaling — the classic "cursor lands in the
//! wrong place" bug.
//!
//! The controller computes normalized coordinates, so injection itself needs no live
//! hardware. The pure mapping math lives in [`norm`] and is unit-tested below.

use rmt_agent_core::platform::{MonitorInfo, PlatformError, PlatformResult};
use rmt_agent_core::{InputButton, InputEvent, InputSink, COMPOSITE_MONITOR_ID};

use windows::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_EXTENDEDKEY, KEYEVENTF_KEYUP, KEYEVENTF_SCANCODE, KEYEVENTF_UNICODE, MOUSEINPUT, MOUSE_EVENT_FLAGS,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEEVENTF_XDOWN,
    MOUSEEVENTF_XUP, VIRTUAL_KEY,
};

/// One wheel "notch" (`WHEEL_DELTA` from winuser.h). A positive multiple scrolls up / right.
const WHEEL_DELTA: i32 = 120;
/// `mouseData` values identifying the extended mouse buttons for `MOUSEEVENTF_XDOWN/XUP`.
const XBUTTON1: i32 = 0x0001;
const XBUTTON2: i32 = 0x0002;

/// Errors raised while dispatching input.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    /// `SendInput` inserted fewer events than requested. This happens when another thread's
    /// input is blocked (e.g. UIPI / a higher-integrity foreground window, or the secure
    /// desktop when the injecting thread is not on it). The inner value is the Win32 error.
    #[error("SendInput injected {injected}/{expected} events: {source}")]
    Rejected {
        injected: u32,
        expected: u32,
        #[source]
        source: windows::core::Error,
    },
}

impl From<InputError> for PlatformError {
    fn from(e: InputError) -> Self {
        // Any short/blocked injection is the OS refusing input (UIPI, secure desktop, etc.).
        PlatformError::InputRefused(e.to_string())
    }
}

/// Pure, hardware-free coordinate math for absolute mouse positioning.
///
/// These functions are the testable heart of the input path — no Win32 calls, no display
/// required. They map a pixel position inside the virtual-desktop bounding box onto the
/// `0..=65535` absolute range that `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` expects.
pub mod norm {
    /// The `0..=65535` absolute coordinate space Windows uses for absolute mouse input.
    pub const ABS_MAX: i32 = 65535;

    /// Map a single-axis pixel coordinate to the `0..=65535` absolute range.
    ///
    /// * `pixel` — position along the axis, in virtual-desktop pixels. It may sit outside the
    ///   `[origin, origin + extent]` span (e.g. a controller dragging past an edge); the
    ///   result is clamped to `0..=65535`.
    /// * `origin` — the axis origin of the virtual desktop (`SM_XVIRTUALSCREEN` /
    ///   `SM_YVIRTUALSCREEN`), which can be negative when a monitor is left of / above the
    ///   primary.
    /// * `extent` — the axis size of the virtual desktop (`SM_CXVIRTUALSCREEN` /
    ///   `SM_CYVIRTUALSCREEN`), in pixels.
    ///
    /// Per Microsoft's documented convention the divisor is `extent - 1`, so the last pixel
    /// column/row maps exactly to `65535`.
    pub fn pixel_to_absolute(pixel: i32, origin: i32, extent: i32) -> i32 {
        if extent <= 1 {
            return 0;
        }
        let offset = pixel - origin;
        // Round to nearest to keep the mapping symmetric rather than always truncating down.
        let scaled = (offset as i64 * ABS_MAX as i64 + (extent as i64 - 1) / 2)
            / (extent as i64 - 1);
        scaled.clamp(0, ABS_MAX as i64) as i32
    }

    /// Convenience wrapper mapping an `(x, y)` pixel point across a virtual-desktop rect.
    ///
    /// `virtual_rect` is `(origin_x, origin_y, width, height)`.
    pub fn point_to_absolute(x: i32, y: i32, virtual_rect: (i32, i32, i32, i32)) -> (i32, i32) {
        let (ox, oy, w, h) = virtual_rect;
        (pixel_to_absolute(x, ox, w), pixel_to_absolute(y, oy, h))
    }
}

/// The virtual-desktop bounding rect `(origin_x, origin_y, width, height)` in pixels, from the live
/// display metrics. `origin_*` are negative when a monitor sits left of / above the primary. This is
/// the rect that `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` normalizes `0..=65535` against.
pub fn virtual_desktop_rect() -> (i32, i32, i32, i32) {
    // SAFETY: GetSystemMetrics takes a constant index and returns an int; no pointers involved.
    unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    }
}

/// Remap a controller `MouseMove` from **frame-normalized** coordinates (`0..=65535` across the
/// SELECTED monitor — all the viewer can compute, since it only ever receives that one monitor's
/// frame) into **virtual-desktop-normalized** coordinates (`0..=65535` across every monitor), which
/// is what the injector's `MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK` actually interprets.
///
/// This is the step the pipeline was missing. The viewer normalizes to the frame and, by contract,
/// expects the agent to place it on the target monitor; the agent instead fed the frame coordinate
/// straight to a virtual-desktop injector. On a single monitor at the origin the two spaces coincide,
/// so it worked and stayed hidden; on a multi-monitor host the pointer lands offset, and — because
/// the error grows with distance from the virtual-desktop origin — near one edge clicks still land
/// and near the far edge they miss entirely (the "some clicks work, some don't" report).
///
/// Pure (takes `virtual_rect`), so it is unit-testable without a live display. Non-`MouseMove`
/// events, the composite "view all" selection (its stitched frame already spans the whole virtual
/// desktop), an unknown selection, and a degenerate zero-size monitor all pass through unchanged.
pub fn remap_input_for_monitor(
    ev: InputEvent,
    selected: u32,
    monitors: &[MonitorInfo],
    virtual_rect: (i32, i32, i32, i32),
) -> InputEvent {
    let InputEvent::MouseMove { x, y } = ev else {
        return ev;
    };
    if selected == COMPOSITE_MONITOR_ID {
        return ev;
    }
    let Some(m) = monitors.iter().find(|mon| mon.id == selected) else {
        return ev;
    };
    if m.width == 0 || m.height == 0 {
        return ev;
    }
    // Frame fraction (x / 65535, matching the viewer's `round(fraction * 65535)`) → pixel within the
    // monitor → its position in the virtual desktop → the absolute range the injector wants.
    let px = m.left + (x as i64 * m.width as i64 / norm::ABS_MAX as i64) as i32;
    let py = m.top + (y as i64 * m.height as i64 / norm::ABS_MAX as i64) as i32;
    let (ax, ay) = norm::point_to_absolute(px, py, virtual_rect);
    InputEvent::MouseMove { x: ax as u16, y: ay as u16 }
}

/// The `dwExtraInfo` signature stamped on **every** event this agent injects.
///
/// # Why injected input has to be identifiable
///
/// `SendInput` events are indistinguishable from a real keypress by design — that is what makes
/// remote control work. But this agent now also draws a window on the guest's own desktop
/// ([`crate::guest_window`]) containing a **text box the guest types into**, and the two facts
/// collide: if the guest window happens to hold focus, every keystroke the remote technician sends
/// is delivered to it, typed into the guest's compose box, and — since the agent decides the role
/// by construction — would be recorded in the persisted support transcript **as the guest's own
/// words**. The technician would be authoring the guest's side of the conversation without either
/// party realising.
///
/// A window cannot ask "was this injected?" any other way: `LLKHF_INJECTED` is visible only to a
/// low-level hook, not in a `WNDPROC`. `dwExtraInfo` is the documented channel — it rides with the
/// event and comes back from `GetMessageExtraInfo()` while the message is being dispatched.
///
/// This is **not** a security boundary. Any process can set any `dwExtraInfo`, so a hostile local
/// program could forge or omit it; it is a correctness signal that separates *this agent's own*
/// injection from a human at the keyboard, which is exactly the distinction the guest window needs.
///
/// The value is arbitrary but must not be 0 (the value every ordinary event carries): `'R','M','T'`
/// with a version byte.
pub const RMT_INJECTED_TAG: usize = 0x524D_5401;

/// Tracked "still-down" input the sink is responsible for releasing on teardown.
///
/// Held state is deliberately narrow — the sink cannot know which keys a human is physically
/// pressing on the guest, so it releases only what IT injected and has not yet seen released.
/// Duplicate downs are collapsed to a single tracked entry; a release removes it.
#[derive(Debug, Default)]
struct Held {
    /// Virtual-key `code` values with an unreleased down (from [`InputEvent::Key`]).
    keys: Vec<u16>,
    /// UTF-16 code units with an unreleased down (from a partially-injected [`InputEvent::Text`]).
    unicode: Vec<u16>,
    /// Virtual keys TYPING pressed and has not released (a Shift whose character failed, or whose
    /// release failed). Kept apart from `keys` (the sessions' own Key events, which the shared
    /// coordinator releases per session) so a typing cancel can release exactly these without
    /// touching another session's held keys (Codex 1.3.9 round 7).
    typing_keys: Vec<u16>,
    /// Mouse buttons with an unreleased down.
    buttons: Vec<InputButton>,
}

impl Held {
    fn add_key(&mut self, code: u16) {
        if !self.keys.contains(&code) { self.keys.push(code); }
    }
    fn remove_key(&mut self, code: u16) {
        self.keys.retain(|&k| k != code);
    }
    fn add_typing_key(&mut self, code: u16) {
        if !self.typing_keys.contains(&code) { self.typing_keys.push(code); }
    }
    fn remove_typing_key(&mut self, code: u16) {
        self.typing_keys.retain(|&k| k != code);
    }
    fn add_unicode(&mut self, unit: u16) {
        if !self.unicode.contains(&unit) { self.unicode.push(unit); }
    }
    fn remove_unicode(&mut self, unit: u16) {
        self.unicode.retain(|&u| u != unit);
    }
    fn add_button(&mut self, b: InputButton) {
        if !self.buttons.contains(&b) { self.buttons.push(b); }
    }
    fn remove_button(&mut self, b: InputButton) {
        self.buttons.retain(|&x| x != b);
    }
}

/// Backend seam. Production uses [`SendInputBackend`] (calls Win32 `SendInput`). Only the
/// alternate-backend *constructor* is `cfg(test)`; the trait itself is compiled in every build so
/// the sink's method bodies can dispatch through the same trait object in both configurations
/// without additional cfg branching.
trait Backend: Send + Sync + std::fmt::Debug {
    /// Return the number of INPUT structures actually injected (Win32 semantics).
    fn submit(&self, inputs: &[INPUT]) -> u32;
}

#[derive(Debug, Default)]
struct SendInputBackend;

impl Backend for SendInputBackend {
    fn submit(&self, inputs: &[INPUT]) -> u32 {
        // Unit-test builds must never reach the OS: a unit test that wires the real sink would
        // type into whatever window has focus on the developer's desktop. Checked FIRST (before
        // even the empty-batch shortcut) so the guard itself is testable without any OS call.
        #[cfg(test)]
        refuse_real_submit_in_unit_tests(inputs.len());
        if inputs.is_empty() { return 0; }
        // SAFETY: `inputs` is a valid, correctly-sized slice of `INPUT`, and we pass the exact
        // element size. `SendInput` copies out of the buffer synchronously.
        unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) }
    }
}

/// docs/53 §3.3: the elevated helper's injection boundary. Each `INPUT` goes to the OS on its own,
/// and anything that is not a release is sent only while `permit()` says yes (the helper's admission
/// lease). It runs inside every submission, which the sink makes under its `held` mutex, so that
/// mutex is the helper-wide injection lock: at most one checked-but-unsent event exists at a time.
///
/// The first refused press STOPS the batch and the injected prefix is reported, so the sink's held
/// accounting stays exact; whatever that prefix left down is lifted by the revocation's
/// `release_held`, and releases always pass `permit`.
struct PermitBackend {
    inner: std::sync::Arc<dyn Backend>,
    permit: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}

impl std::fmt::Debug for PermitBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PermitBackend").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl Backend for PermitBackend {
    fn submit(&self, inputs: &[INPUT]) -> u32 {
        let mut injected = 0;
        for input in inputs {
            if !is_release_input(input) && !(self.permit)() {
                break;
            }
            if self.inner.submit(std::slice::from_ref(input)) != 1 {
                break;
            }
            injected += 1;
        }
        injected
    }
}

/// Whether an `INPUT` only lifts something: a key-up, or a mouse button-up (which may carry the
/// pointer position it is released at). Wheels, moves and every down are presses.
fn is_release_input(input: &INPUT) -> bool {
    // SAFETY: the union member read matches `r#type`.
    unsafe {
        if input.r#type == INPUT_KEYBOARD {
            return input.Anonymous.ki.dwFlags.contains(KEYEVENTF_KEYUP);
        }
        if input.r#type == INPUT_MOUSE {
            let f = input.Anonymous.mi.dwFlags;
            let up = MOUSEEVENTF_LEFTUP | MOUSEEVENTF_RIGHTUP | MOUSEEVENTF_MIDDLEUP | MOUSEEVENTF_XUP;
            let press = MOUSEEVENTF_LEFTDOWN | MOUSEEVENTF_RIGHTDOWN | MOUSEEVENTF_MIDDLEDOWN | MOUSEEVENTF_XDOWN
                | MOUSEEVENTF_WHEEL | MOUSEEVENTF_HWHEEL;
            return (f.0 & up.0) != 0 && (f.0 & press.0) == 0;
        }
    }
    false
}

/// Fail-closed guard for `cfg(test)` builds of this crate: panics BEFORE `SendInput` so an
/// accidental real-backend call fails loudly instead of injecting (or silently faking success).
/// Unit tests that need injection must use a recording/fake [`Backend`] or [`InputSink`].
/// Integration tests (`tests/*.rs`) and the `test-harness` feature compile the library without
/// `cfg(test)` and are NOT covered by this guard.
#[cfg(test)]
fn refuse_real_submit_in_unit_tests(count: usize) {
    panic!(
        "real SendInput backend reached from a unit-test build ({count} INPUTs refused before \
         the OS call); use a recording backend/sink instead"
    );
}

/// [`InputSink`] implementation backed by `SendInput`.
///
/// Cheap to construct and holds no OS handles — `SendInput` targets the calling thread's input
/// desktop, so *which desktop this runs on* is controlled by the hosting thread
/// (`SetThreadDesktop`), not by this struct. The per-session helper is responsible for following
/// the input desktop; see [`crate::service`].
///
/// Held-input state (currently-down keys / unicode units / mouse buttons this sink injected)
/// lives behind an `Arc<Mutex<..>>` so a clone of the sink shares the SAME held set — a session
/// teardown initiated after the sink has been cloned onto a worker still releases everything the
/// original tracked. All submissions and tracking edits happen under that mutex so the two
/// cannot diverge under concurrent use.
#[derive(Debug, Clone)]
pub struct SendInputSink {
    backend: std::sync::Arc<dyn Backend>,
    held: std::sync::Arc<std::sync::Mutex<Held>>,
    /// How Text becomes keystrokes: real keys on the foreground layout (see crate::text_typing).
    layout: std::sync::Arc<dyn crate::text_typing::TextLayout>,
    /// Pacing between typed characters (crate::text_typing::CHAR_GAP; zero in accounting tests).
    pace: TypingPace,
    /// Where Text is typed: a dedicated, desktop-following worker thread (started on first use),
    /// so pacing never sleeps on the shared capture thread. `None` types inline (tests).
    typist: Option<std::sync::Arc<TypistCell>>,
    /// Set on the typist thread's own clone: its typing loop checks `cancel` before every character.
    typing_state: Option<std::sync::Arc<TypistState>>,
}

/// The typing worker, started lazily and shared by every clone of one sink.
#[derive(Debug)]
struct TypistCell {
    started: std::sync::OnceLock<Typist>,
    /// Bind the worker to the input desktop before each job (production); off in unit tests.
    follow_desktop: bool,
}

#[derive(Debug)]
struct Typist {
    tx: std::sync::Mutex<std::sync::mpsc::Sender<(InputEvent, u64)>>,
    state: std::sync::Arc<TypistState>,
}

#[derive(Debug)]
struct TypistState {
    /// Jobs queued or running. While non-zero, Key events queue BEHIND the typing so an Enter
    /// cannot overtake the text before it.
    pending: std::sync::atomic::AtomicUsize,
    /// The cancel GENERATION. Every job is stamped with the generation current when it was queued;
    /// `cancel_typing` bumps it, which permanently invalidates every older job, queued or running.
    /// A later enqueue (by any session) does not lower it, so it can never revive a cancelled job
    /// (Codex 1.3.9 round 5: one shared flag let session B's next Text undo session A's revocation).
    generation: std::sync::atomic::AtomicU64,
    /// The generation of the job being typed, `0` when idle.
    running: std::sync::atomic::AtomicU64,
}

impl Default for TypistState {
    fn default() -> Self {
        Self {
            pending: Default::default(),
            generation: std::sync::atomic::AtomicU64::new(1),
            running: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// Longest a Key waits for typing queued before it. Longer than any one Text event's pacing
/// (crate::text_typing::MAX_PACE_PER_EVENT, 10 s) so a key never overtakes typing that is progressing.
const KEY_WAIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(15);

/// The minimum gap between typed characters, measured ACROSS Text events (events the network bunched
/// must still reach the target at a typist's pace), with a per-event budget.
#[derive(Debug, Clone)]
struct TypingPace {
    gap: std::time::Duration,
    max_per_event: std::time::Duration,
    last_char_at: std::sync::Arc<std::sync::Mutex<Option<std::time::Instant>>>,
    /// After each character: wait (at most the given time) for the target to catch up
    /// (crate::text_typing::sync_with_foreground). `None` in tests.
    settle: Option<fn(std::time::Duration)>,
}

impl TypingPace {
    fn new(gap: std::time::Duration, max_per_event: std::time::Duration) -> Self {
        Self { gap, max_per_event, last_char_at: Default::default(), settle: None }
    }

    /// Let the target catch up after a character, spending at most what is left of `budget` (and at
    /// most crate::text_typing::SYNC_TIMEOUT); returns the time spent.
    fn settle(&self, budget: std::time::Duration) -> std::time::Duration {
        let Some(settle) = self.settle else { return std::time::Duration::ZERO };
        let t0 = std::time::Instant::now();
        settle(budget.min(crate::text_typing::SYNC_TIMEOUT));
        t0.elapsed()
    }

    /// Sleep until `gap` has passed since the previous typed character, spending at most what is left
    /// of `budget`; returns the time slept.
    fn wait(&self, budget: std::time::Duration) -> std::time::Duration {
        let last = *self.last_char_at.lock().unwrap();
        let Some(last) = last else { return std::time::Duration::ZERO };
        let due = self.gap.saturating_sub(last.elapsed()).min(budget);
        if !due.is_zero() {
            std::thread::sleep(due);
        }
        due
    }

    /// Keep the modifiers down for crate::text_typing::MODIFIER_HOLD (zero when pacing is off),
    /// spending at most what is left of `budget`; returns the time slept.
    fn hold(&self, budget: std::time::Duration) -> std::time::Duration {
        if self.gap.is_zero() {
            return std::time::Duration::ZERO;
        }
        let due = crate::text_typing::MODIFIER_HOLD.min(budget);
        if !due.is_zero() {
            std::thread::sleep(due);
        }
        due
    }

    fn typed(&self) {
        *self.last_char_at.lock().unwrap() = Some(std::time::Instant::now());
    }
}

impl Default for SendInputSink {
    fn default() -> Self {
        Self {
            backend: std::sync::Arc::new(SendInputBackend),
            held: std::sync::Arc::new(std::sync::Mutex::new(Held::default())),
            layout: std::sync::Arc::new(crate::text_typing::ForegroundLayout),
            pace: TypingPace {
                settle: Some(crate::text_typing::sync_with_foreground),
                ..TypingPace::new(crate::text_typing::CHAR_GAP, crate::text_typing::MAX_PACE_PER_EVENT)
            },
            typist: Some(std::sync::Arc::new(TypistCell { started: std::sync::OnceLock::new(), follow_desktop: true })),
            typing_state: None,
        }
    }
}

impl SendInputSink {
    /// Create a new sink. The hosting process should already be PerMonitorV2 DPI-aware.
    pub fn new() -> Self { Self::default() }

    /// The elevated helper's sink (docs/53 §3.3): every press is checked against `permit` at the
    /// moment it would reach the OS, typed characters included; releases always pass.
    pub(crate) fn with_press_permit(permit: std::sync::Arc<dyn Fn() -> bool + Send + Sync>) -> Self {
        let mut sink = Self::default();
        sink.backend = std::sync::Arc::new(PermitBackend { inner: sink.backend, permit });
        sink
    }

    /// Test constructor: swap the backend for one that records / returns a configurable injected
    /// count. Reachable only under `cfg(test)`.
    /// Text goes out as `VK_PACKET` only (the pre-1.3.9 shape the accounting tests were written for).
    #[cfg(test)]
    fn with_backend(backend: std::sync::Arc<dyn Backend>) -> Self {
        Self::with_backend_and_layout(backend, std::sync::Arc::new(crate::text_typing::PacketsOnly))
    }

    #[cfg(test)]
    fn with_backend_and_layout(
        backend: std::sync::Arc<dyn Backend>,
        layout: std::sync::Arc<dyn crate::text_typing::TextLayout>,
    ) -> Self {
        Self {
            backend,
            held: std::sync::Arc::new(std::sync::Mutex::new(Held::default())),
            layout,
            pace: TypingPace::new(std::time::Duration::ZERO, std::time::Duration::ZERO),
            typist: None,
            typing_state: None,
        }
    }

}

/// Build a mouse `INPUT` with the given flags and normalized absolute coordinates.
fn mouse_input(flags: MOUSE_EVENT_FLAGS, abs_x: i32, abs_y: i32, data: i32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx: abs_x,
                dy: abs_y,
                // `mouseData` is reinterpreted per-flag: wheel delta for WHEEL/HWHEEL, or the
                // XBUTTON id for XDOWN/XUP. Unused for plain moves/left/right/middle.
                mouseData: data as u32,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: RMT_INJECTED_TAG,
            },
        },
    }
}

/// Build a keyboard `INPUT`. `by_scancode` selects hardware-scancode injection
/// (`KEYEVENTF_SCANCODE`), which is layout-independent and preferred for games and the secure
/// desktop; otherwise the value is treated as a virtual-key code.
fn key_input(code: u16, pressed: bool, by_scancode: bool) -> INPUT {
    let mut flags = KEYBD_EVENT_FLAGS(0);
    if !pressed {
        flags |= KEYEVENTF_KEYUP;
    }
    let (vk, scan) = if by_scancode {
        flags |= KEYEVENTF_SCANCODE;
        (VIRTUAL_KEY(0), code)
    } else {
        (VIRTUAL_KEY(code), 0)
    };
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: RMT_INJECTED_TAG,
            },
        },
    }
}

impl SendInputSink {
    /// Submit planned Text strokes in one SendInput. Held lock spans submission AND accounting: every
    /// stroke in the injected prefix is applied to the tracked set in order (a down ADDS its key or
    /// unit, an up REMOVES it, so a later successful "A" clears a stranded "A" left by a prior partial
    /// injection). Whatever a partial injection left down (a Shift, a key, a unit) is therefore
    /// tracked and released at teardown; zero-injected strokes are not tracked at all.
    ///
    /// `press == true` marks a press: it is refused (returns `Ok(false)`, nothing submitted) if the
    /// typing job was cancelled. That check runs UNDER the held lock, the same lock `cancel_typing`
    /// bumps the generation under, so a cancel and a press are strictly ordered: once a cancel has
    /// returned, no press of an older job can follow (Codex 1.3.9 round 6). Releases always run.
    fn submit_strokes(&self, strokes: &[crate::text_typing::Stroke], press: bool) -> PlatformResult<bool> {
        let mut held = self.held.lock().unwrap();
        if press && self.typing_cancelled() {
            return Ok(false);
        }
        self.submit_locked(&mut held, strokes)?;
        Ok(true)
    }

    /// Submit `strokes` with the held lock already taken, and account them (see `submit_strokes`).
    fn submit_locked(&self, held: &mut Held, strokes: &[crate::text_typing::Stroke]) -> PlatformResult<()> {
        let inputs: Vec<INPUT> = strokes.iter().map(stroke_input).collect();
        if inputs.is_empty() {
            return Ok(());
        }
        let injected = self.backend.submit(&inputs) as usize;
        for st in &strokes[..injected.min(strokes.len())] {
            match *st {
                crate::text_typing::Stroke::Vk { vk, down: true, .. } => held.add_typing_key(vk),
                crate::text_typing::Stroke::Vk { vk, down: false, .. } => held.remove_typing_key(vk),
                crate::text_typing::Stroke::Unit { unit, down: true } => held.add_unicode(unit),
                crate::text_typing::Stroke::Unit { unit, down: false } => held.remove_unicode(unit),
            }
        }
        if injected != inputs.len() {
            return Err(InputError::Rejected {
                injected: injected as u32,
                expected: inputs.len() as u32,
                source: windows::core::Error::from_win32(),
            }
            .into());
        }
        Ok(())
    }
}

impl SendInputSink {
    /// The typing worker, started on first use. It owns a clone of this sink WITHOUT a typist (so it
    /// types inline on its own thread) and, in production, follows the input desktop like the capture
    /// thread does, so typing reaches the sign-in screen and UAC prompts too.
    fn typist<'a>(&self, cell: &'a TypistCell) -> &'a Typist {
        cell.started.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::channel::<(InputEvent, u64)>();
            let state = std::sync::Arc::new(TypistState::default());
            let worker = Self { typist: None, typing_state: Some(state.clone()), ..self.clone() };
            let (st, follow) = (state.clone(), cell.follow_desktop);
            std::thread::Builder::new()
                .name("rmt-typist".into())
                .spawn(move || {
                    let mut follower = follow.then(crate::service::DesktopFollower::new);
                    while let Ok((ev, gen)) = rx.recv() {
                        // A job from before the latest cancel is dropped, never typed.
                        st.running.store(gen, std::sync::atomic::Ordering::SeqCst);
                        if gen == st.generation.load(std::sync::atomic::Ordering::SeqCst) {
                            if let Some(f) = follower.as_mut() {
                                if let Err(e) = f.poll() {
                                    tracing::debug!(error = %e, "typist: could not follow the input desktop");
                                }
                            }
                            if let Err(e) = worker.inject_now(ev) {
                                tracing::warn!(error = %e, "typist: typing was refused");
                            }
                        }
                        st.running.store(0, std::sync::atomic::Ordering::SeqCst);
                        st.pending.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
                .expect("spawn the typist thread");
            Typist { tx: std::sync::Mutex::new(tx), state }
        })
    }

    /// On the typist thread: whether the job being typed was cancelled (its generation is stale).
    fn typing_cancelled(&self) -> bool {
        self.typing_state.as_ref().is_some_and(|s| {
            s.running.load(std::sync::atomic::Ordering::SeqCst) != s.generation.load(std::sync::atomic::Ordering::SeqCst)
        })
    }

    fn enqueue(&self, t: &Typist, ev: InputEvent) -> PlatformResult<()> {
        t.state.pending.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let gen = t.state.generation.load(std::sync::atomic::Ordering::SeqCst);
        if t.tx.lock().unwrap().send((ev, gen)).is_err() {
            t.state.pending.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Err(PlatformError::InputRefused("the typist thread is gone".into()));
        }
        Ok(())
    }
}

impl InputSink for SendInputSink {
    /// Inject one input event. Text is typed on the typist thread (paced, so it must not sleep on
    /// the shared capture thread, which would freeze the picture while text is typed); a Key that
    /// arrives while typing is pending queues behind it so it cannot overtake the text. Everything
    /// else is injected at once.
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        let Some(cell) = self.typist.as_ref() else { return self.inject_now(event) };
        match &event {
            InputEvent::Text(text) => {
                if text.len() > 4096 {
                    return Err(PlatformError::InputRefused("text exceeds 4096-byte limit".into()));
                }
                let t = self.typist(cell);
                self.enqueue(t, event)
            }
            // A Key never joins the typing queue (Codex 1.3.9 round 10: a queued key-up dropped by a
            // typing cancel left the key down with nobody owning its release, and a dropped key-down
            // left the coordinator counting a press that never happened). It waits for ALL typing
            // queued before it, so an Enter never overtakes its text (round 11), then goes in
            // synchronously: what the coordinator records is exactly what reached the OS. A cancel
            // drains the queue at once, so a revocation ends the wait too. Only a typist stuck past
            // KEY_WAIT_LIMIT ends it otherwise: a key-DOWN is then refused (never sent ahead of the
            // text; the coordinator rolls back its holder), a key-UP is still sent so nothing sticks.
            InputEvent::Key { down, .. } => {
                if let Some(t) = cell.started.get() {
                    let deadline = std::time::Instant::now() + KEY_WAIT_LIMIT;
                    while t.state.pending.load(std::sync::atomic::Ordering::SeqCst) > 0 {
                        if std::time::Instant::now() >= deadline {
                            if *down {
                                tracing::warn!("input: a key press waited too long behind typing; refused, not sent ahead of it");
                                return Err(PlatformError::InputRefused("typing still pending".into()));
                            }
                            break;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                self.inject_now(event)
            }
            _ => self.inject_now(event),
        }
    }

    /// Release everything held, after stopping any typing (so teardown cannot be followed by more
    /// keystrokes).
    fn release_held(&self) -> PlatformResult<()> {
        self.cancel_typing(true);
        self.release_held_now()
    }

    /// Admission revoked (direct, non-shared sessions): stop typing and release what is held. The
    /// sink is not retired, so input is accepted again when the session is re-admitted.
    fn set_admitted(&self, admitted: bool) {
        if !admitted {
            // Not waiting here: this may run on an async task. Callers that must know typing has
            // stopped wait with cancel_typing(true) off the async thread (host: set_input_admitted).
            self.cancel_typing(false);
            if let Err(e) = self.release_held_now() {
                tracing::debug!(error = %e, "input: release on admission revoke failed");
            }
        }
    }

    /// Cancel every job queued or running NOW (bump the generation): queued ones are dropped, the
    /// running one stops at its next press. Jobs queued later are unaffected.
    ///
    /// Returning IS the guarantee that no press of a cancelled job can follow: the bump happens under
    /// the held lock that every press re-checks under. `wait` additionally waits for the cancelled job
    /// to finish its remaining RELEASES (a Shift held for the character in flight), so a caller that
    /// releases held keys afterwards does not race them; a stuck SendInput is reported after 5 s, and
    /// even then no further press can happen.
    /// Retry typing's leftover releases, only while no typing job is queued or running (a release
    /// mid-character would cut a character short).
    fn retry_typing_releases(&self) {
        let busy = self
            .typist
            .as_ref()
            .and_then(|c| c.started.get())
            .is_some_and(|t| t.state.pending.load(std::sync::atomic::Ordering::SeqCst) > 0);
        let holds = { let h = self.held.lock().unwrap(); !h.typing_keys.is_empty() || !h.unicode.is_empty() };
        if !busy && holds {
            if let Err(e) = self.release_typing_now() {
                tracing::debug!(error = %e, "typist: typing release still refused; will retry");
            }
        }
    }

    fn cancel_typing(&self, wait: bool) {
        self.cancel_typing_jobs(wait);
        if wait {
            // After the cancel completed: release whatever TYPING still holds (a Shift whose
            // character or release failed, a dangling Unicode unit). Failures stay held and are
            // retried by the next cancel or release.
            if let Err(e) = self.release_typing_now() {
                tracing::debug!(error = %e, "typist: a typing-held key could not be released yet");
            }
        }
    }
}

impl SendInputSink {
    /// Release the keys and Unicode units TYPING holds (not the sessions' own keys, which the shared
    /// coordinator owns per session). Failures stay held for the next attempt.
    fn release_typing_now(&self) -> PlatformResult<()> {
        let mut held = self.held.lock().unwrap();
        let mut failed = 0u32;
        for code in std::mem::take(&mut held.typing_keys) {
            // A session pressed this key since typing left it down: it is the session's now, and its
            // own release will lift it. Never send a key-up a session owns (Codex 1.3.9 round 9).
            if crate::text_typing::owns(&held.keys, code) {
                continue;
            }
            if self.backend.submit(&[key_input(code, false, false)]) != 1 {
                held.typing_keys.push(code);
                failed += 1;
            }
        }
        for unit in std::mem::take(&mut held.unicode) {
            if self.backend.submit(&[unicode_input(unit, false)]) != 1 {
                held.unicode.push(unit);
                failed += 1;
            }
        }
        if failed > 0 {
            return Err(PlatformError::InputRefused(format!("{failed} typing release(s) refused; kept for retry")));
        }
        Ok(())
    }

    fn cancel_typing_jobs(&self, wait: bool) {
        let Some(t) = self.typist.as_ref().and_then(|c| c.started.get()) else { return };
        // Under the held lock: every press re-checks the generation under it, so after this line no
        // press of an older job can be submitted (a press already in progress finished first).
        let fence = {
            let _held = self.held.lock().unwrap();
            t.state.generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
        };
        if wait {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let running = t.state.running.load(std::sync::atomic::Ordering::SeqCst);
                if running == 0 || running >= fence {
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    tracing::warn!("typist: a cancelled character is still being injected after 5 s");
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        }
    }
}

/// The `INPUT` for one planned Text keystroke.
fn stroke_input(st: &crate::text_typing::Stroke) -> INPUT {
    match *st {
        crate::text_typing::Stroke::Vk { vk, down, extended } => {
            let mut i = key_input(vk, down, /* by_scancode */ false);
            if extended {
                // SAFETY: `key_input` builds a keyboard INPUT, so `ki` is the active union field.
                unsafe { i.Anonymous.ki.dwFlags |= KEYEVENTF_EXTENDEDKEY };
            }
            i
        }
        crate::text_typing::Stroke::Unit { unit, down } => unicode_input(unit, down),
    }
}

/// Build a keyboard `INPUT` that injects one UTF-16 code unit directly (`KEYEVENTF_UNICODE`),
/// bypassing scancodes entirely — the IME/paste-style path for [`InputEvent::Text`].
fn unicode_input(unit: u16, pressed: bool) -> INPUT {
    let mut flags = KEYEVENTF_UNICODE;
    if !pressed {
        flags |= KEYEVENTF_KEYUP;
    }
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(0),
                wScan: unit,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: RMT_INJECTED_TAG,
            },
        },
    }
}

impl SendInputSink {
    /// Translate one portable [`InputEvent`] into `INPUT` structures and inject them NOW, on the
    /// calling thread. [`InputSink::inject`] routes Text (and keys queued behind it) to the typist.
    ///
    /// Mouse coordinates are pre-normalized `u16` in `0..=65535` across the virtual desktop
    /// (the controller does the DPI-independent mapping), buttons carry press/release, scroll
    /// carries wheel notches, and keys carry a Windows virtual-key code.
    fn inject_now(&self, event: InputEvent) -> PlatformResult<()> {
        match event {
            InputEvent::MouseMove { x, y } => {
                // No tracked state to update, but still take the lock so any concurrent clone's
                // release/inject is serialized with respect to this submission — the wire order
                // of injected events across threads is a property callers rely on.
                let _held = self.held.lock().unwrap();
                let flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK;
                let inputs = [mouse_input(flags, x as i32, y as i32, 0)];
                let injected = self.backend.submit(&inputs);
                if injected as usize != inputs.len() {
                    return Err(InputError::Rejected {
                        injected, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    }.into());
                }
            }
            InputEvent::MouseButton { button, down } => {
                let (flags, data) = button_flags(button, down);
                // Serialize submission AND tracking under ONE lock so a clone racing this update
                // never observes the wire event without the corresponding held-state edit, and
                // vice versa. The whole point of the mutex is this atomicity; do not narrow it.
                let mut held = self.held.lock().unwrap();
                let inputs = [mouse_input(flags, 0, 0, data)];
                let injected = self.backend.submit(&inputs);
                if injected as usize == inputs.len() {
                    if down { held.add_button(button); } else { held.remove_button(button); }
                    Ok::<(), PlatformError>(())
                } else {
                    Err(InputError::Rejected {
                        injected, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    }.into())
                }?;
            }
            InputEvent::Scroll { dx, dy } => {
                let _held = self.held.lock().unwrap();
                let mut inputs: Vec<INPUT> = Vec::with_capacity(2);
                if dy != 0 { inputs.push(mouse_input(MOUSEEVENTF_WHEEL, 0, 0, dy * WHEEL_DELTA)); }
                if dx != 0 { inputs.push(mouse_input(MOUSEEVENTF_HWHEEL, 0, 0, dx * WHEEL_DELTA)); }
                if inputs.is_empty() { return Ok(()); }
                let injected = self.backend.submit(&inputs);
                if injected as usize != inputs.len() {
                    return Err(InputError::Rejected {
                        injected, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    }.into());
                }
            }
            InputEvent::Key { code, down } => {
                let mut held = self.held.lock().unwrap();
                // A key-down queued behind typing and run by the typist is a press of a typing job:
                // refused under the held lock once that job is cancelled (key-ups always pass).
                if down && self.typing_cancelled() {
                    return Ok(());
                }
                let inputs = [key_input(code as u16, down, /* by_scancode */ false)];
                let injected = self.backend.submit(&inputs);
                if injected as usize == inputs.len() {
                    if down { held.add_key(code as u16); } else { held.remove_key(code as u16); }
                    Ok::<(), PlatformError>(())
                } else {
                    Err(InputError::Rejected {
                        injected, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    }.into())
                }?;
            }
            InputEvent::Text(text) => {
                if text.len() > 4096 {
                    return Err(PlatformError::InputRefused("text exceeds 4096-byte limit".into()));
                }
                // Real keys on the foreground layout where possible, VK_PACKET for the rest: a burst of
                // VK_PACKETs garbles a target that lags its input queue (crate::text_typing).
                // One character at a time, paced (crate::text_typing::CHAR_GAP), so a target that
                // processes input asynchronously (Windows 11 Notepad) is never handed a burst.
                let mut budget = self.pace.max_per_event;
                // Planned ONE CHARACTER AT A TIME, against the foreground window and layout of that
                // moment (focus can move while a long text is typed), and stopped between characters
                // when typing is cancelled (session end, view-only). A character already pressed is
                // always completed, so its Shift is released.
                let normalized = text.replace("\r\n", "\n").replace('\r', "\n");
                let mut utf8 = [0u8; 4];
                for ch in normalized.chars() {
                  if self.typing_cancelled() { break; }
                  // Outside the held lock: let a busy target catch up, then keep the minimum gap.
                  budget = budget.saturating_sub(self.pace.settle(budget));
                  budget = budget.saturating_sub(self.pace.wait(budget));
                  // PLAN AND PRESS UNDER THE HELD LOCK (Codex 1.3.9 round 9): the cancel check, the
                  // choice of real key vs packet (against the keys sessions hold through this sink,
                  // whose events take this same lock, and the physical key state) and the press are
                  // one step, so nothing can change between deciding and pressing.
                  let releases = {
                      let mut held = self.held.lock().unwrap();
                      if self.typing_cancelled() { break; }
                      let session_keys = held.keys.clone();
                      let groups = self.layout.plan_owned(ch.encode_utf8(&mut utf8), &|vk| crate::text_typing::owns(&session_keys, vk));
                      let mut releases = Vec::new();
                      for group in groups.iter().filter(|g| !g.is_empty()) {
                          let (press, release) = crate::text_typing::split_release(group);
                          self.submit_locked(&mut held, press)?;
                          releases.push(release.to_vec());
                      }
                      releases
                  };
                  self.pace.typed();
                  // Any modifier release after the hold (only the test planner presses modifiers;
                  // production typing never does, see crate::text_typing).
                  for release in releases.iter().filter(|r| !r.is_empty()) {
                      budget = budget.saturating_sub(self.pace.settle(budget));
                      budget = budget.saturating_sub(self.pace.hold(budget));
                      self.submit_strokes(release, false)?;
                  }
                }
            }
            InputEvent::Sas => {
                // Ctrl+Alt+Del cannot be forged through `SendInput` (Windows drops the synthetic
                // combo by design). It also cannot be generated from this session-1 helper directly —
                // `SendSAS(FALSE)` is a session-0 *service* primitive (proven on LAB-VM). So signal
                // the service's responder, which makes the call from session 0. Cannot fail: a
                // missing responder falls back to a best-effort direct call inside `request_*`.
                let via_service = crate::sas::request_secure_attention();
                tracing::info!(via_service, "input: secure attention sequence requested");
            }
        }
        Ok(())
    }

    /// Release everything this sink still tracks as held (keys, unicode units, mouse buttons)
    /// through the ordinary INPUT encoders. Runs on the CALLING thread; best effort: an entry
    /// that fails to release stays in `held` so a subsequent call can retry.
    ///
    /// The tracked-desktop caveat: the sink cannot verify that the calling thread's `SetThread
    /// Desktop`-bound desktop is the same one where each tracked event originally landed. A
    /// desktop switch between the original down and this release will send the release into
    /// the current desktop, which may not match; the release is still attempted because that is
    /// the correct behavior in the common case (no switch), and the alternative (leaving keys
    /// stranded down) is worse. Physical-key parity is not claimed: the sink knows only what
    /// IT injected and has not seen released.
    ///
    /// Holds the SAME mutex across submission AND tracking edits so a concurrent clone cannot
    /// observe divergent state or race a new down into the set mid-release.
    fn release_held_now(&self) -> PlatformResult<()> {
        let mut held = self.held.lock().unwrap();
        let mut first_err: Option<InputError> = None;
        // Drain by draining local copies then re-inserting only what failed; this avoids
        // mutating the vector we are iterating.
        let keys = std::mem::take(&mut held.keys);
        for code in keys {
            let inputs = [key_input(code, false, /* by_scancode */ false)];
            let n = self.backend.submit(&inputs);
            if n as usize != inputs.len() {
                held.keys.push(code);
                if first_err.is_none() {
                    first_err = Some(InputError::Rejected {
                        injected: n, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    });
                }
            }
        }
        let typing_keys = std::mem::take(&mut held.typing_keys);
        for code in typing_keys {
            let inputs = [key_input(code, false, /* by_scancode */ false)];
            let n = self.backend.submit(&inputs);
            if n as usize != inputs.len() {
                held.typing_keys.push(code);
                if first_err.is_none() {
                    first_err = Some(InputError::Rejected {
                        injected: n, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    });
                }
            }
        }
        let unicode = std::mem::take(&mut held.unicode);
        for unit in unicode {
            let inputs = [unicode_input(unit, false)];
            let n = self.backend.submit(&inputs);
            if n as usize != inputs.len() {
                held.unicode.push(unit);
                if first_err.is_none() {
                    first_err = Some(InputError::Rejected {
                        injected: n, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    });
                }
            }
        }
        let buttons = std::mem::take(&mut held.buttons);
        for b in buttons {
            let (flags, data) = button_flags(b, false);
            let inputs = [mouse_input(flags, 0, 0, data)];
            let n = self.backend.submit(&inputs);
            if n as usize != inputs.len() {
                held.buttons.push(b);
                if first_err.is_none() {
                    first_err = Some(InputError::Rejected {
                        injected: n, expected: inputs.len() as u32,
                        source: windows::core::Error::from_win32(),
                    });
                }
            }
        }
        match first_err { Some(e) => Err(e.into()), None => Ok(()) }
    }
}

/// Map a portable [`InputButton`] + press state to `SendInput` flags and `mouseData`.
fn button_flags(button: InputButton, pressed: bool) -> (MOUSE_EVENT_FLAGS, i32) {
    match button {
        InputButton::Left => (
            if pressed { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP },
            0,
        ),
        InputButton::Right => (
            if pressed { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP },
            0,
        ),
        InputButton::Middle => (
            if pressed { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP },
            0,
        ),
        // Back / Forward navigation map to the extended X buttons (X1 / X2).
        InputButton::Back => (
            if pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP },
            XBUTTON1,
        ),
        InputButton::Forward => (
            if pressed { MOUSEEVENTF_XDOWN } else { MOUSEEVENTF_XUP },
            XBUTTON2,
        ),
    }
}

#[cfg(test)]
mod backend_tests {
    //! Tests for the tracked-held state and `release_held`, using the `cfg(test)` backend seam.
    //! No OS calls: every INPUT goes through `TestBackend`, which returns a configurable injected
    //! count and records the submitted structs.
    use super::*;
    use rmt_agent_core::InputSink;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct TestBackend {
        submitted: Mutex<Vec<Vec<INPUT>>>,
        // If Some(n), the NEXT submit returns n regardless of the batch length (used to model a
        // partial or total OS refusal); consumed after one use.
        override_next: Mutex<Option<u32>>,
    }
    impl std::fmt::Debug for TestBackend {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("TestBackend")
        }
    }
    impl TestBackend {
        fn record_count(&self) -> usize { self.submitted.lock().unwrap().len() }
        fn set_next(&self, n: u32) { *self.override_next.lock().unwrap() = Some(n); }
    }
    impl Backend for TestBackend {
        fn submit(&self, inputs: &[INPUT]) -> u32 {
            let n = self.override_next.lock().unwrap().take().unwrap_or(inputs.len() as u32);
            self.submitted.lock().unwrap().push(inputs.to_vec());
            n
        }
    }

    fn sink() -> (SendInputSink, Arc<TestBackend>) {
        let backend = Arc::new(TestBackend::default());
        let sink = SendInputSink::with_backend(backend.clone() as Arc<dyn Backend>);
        (sink, backend)
    }

    #[test]
    fn key_down_is_tracked_and_released_by_release_held() {
        let (s, b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        assert_eq!(s.held.lock().unwrap().keys, vec![65]);
        s.release_held().unwrap();
        assert!(s.held.lock().unwrap().keys.is_empty(), "released keys are cleared from tracking");
        // One submit for the down, one for the release.
        assert_eq!(b.record_count(), 2);
    }

    #[test]
    fn key_up_removes_tracking() {
        let (s, _b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 65, down: false }).unwrap();
        assert!(s.held.lock().unwrap().keys.is_empty());
    }

    #[test]
    fn duplicate_key_down_tracks_once() {
        let (s, _b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        assert_eq!(s.held.lock().unwrap().keys, vec![65], "duplicate downs collapse to one entry");
    }

    #[test]
    fn button_down_is_tracked_and_released() {
        let (s, _b) = sink();
        s.inject(InputEvent::MouseButton { button: InputButton::Left, down: true }).unwrap();
        assert_eq!(s.held.lock().unwrap().buttons, vec![InputButton::Left]);
        s.release_held().unwrap();
        assert!(s.held.lock().unwrap().buttons.is_empty());
    }

    #[test]
    fn text_partial_injection_retains_dangling_down_as_held() {
        let (s, b) = sink();
        // Each character is its own paced SendInput: "A" goes in full, then "B" is (down B, up B)
        // and the OS accepts only 1 — the "up B" was refused, so B remains DOWN and must be
        // tracked for release.
        s.inject(InputEvent::Text("A".into())).unwrap();
        b.set_next(1);
        let err = s.inject(InputEvent::Text("B".into())).unwrap_err();
        match err {
            PlatformError::InputRefused(_) => {}
            other => panic!("expected InputRefused, got {other:?}"),
        }
        let held = s.held.lock().unwrap();
        // 'B' = 0x42
        assert_eq!(held.unicode, vec![0x42u16], "the dangling B-down is tracked");
    }

    /// A fixed layout for sink-level tests: capitals need Shift, nothing else has a key.
    #[derive(Debug)]
    struct CapitalsOnly;
    impl crate::text_typing::TextLayout for CapitalsOnly {
        fn plan(&self, text: &str) -> Vec<Vec<crate::text_typing::Stroke>> {
            crate::text_typing::plan_groups(text, false, |u| {
                (0x41..=0x5A).contains(&u).then_some(crate::text_typing::KeyFor { vk: u, shift: true, ctrl: false, alt: false })
            })
        }
    }

    #[test]
    fn text_types_real_keys_and_a_partial_injection_leaves_its_shift_tracked_for_release() {
        // Refuses the Shift release (a lone LShift-up), accepts everything else.
        #[derive(Default)]
        struct RefuseShiftUp(Mutex<Vec<Vec<INPUT>>>, std::sync::atomic::AtomicBool);
        impl std::fmt::Debug for RefuseShiftUp {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("RefuseShiftUp") }
        }
        impl Backend for RefuseShiftUp {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                self.0.lock().unwrap().push(inputs.to_vec());
                // SAFETY: keyboard INPUTs built by key_input.
                let lone_shift_up = inputs.len() == 1 && unsafe { inputs[0].Anonymous.ki.wVk.0 } == crate::text_typing::VK_LSHIFT
                    && unsafe { inputs[0].Anonymous.ki.dwFlags } == KEYEVENTF_KEYUP;
                if lone_shift_up && !self.1.swap(true, std::sync::atomic::Ordering::SeqCst) { 0 } else { inputs.len() as u32 }
            }
        }
        let backend = Arc::new(RefuseShiftUp::default());
        let s = SendInputSink::with_backend_and_layout(backend.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        assert!(s.inject(InputEvent::Text("A".into())).is_err(), "the refused Shift release is reported");
        let sent = backend.0.lock().unwrap().clone();
        // SAFETY: keyboard INPUTs built by key_input.
        let vks: Vec<Vec<u16>> = sent.iter().map(|b| b.iter().map(|i| unsafe { i.Anonymous.ki.wVk.0 }).collect()).collect();
        assert_eq!(vks, vec![vec![crate::text_typing::VK_LSHIFT, 0x41, 0x41], vec![crate::text_typing::VK_LSHIFT]],
            "a capital is Shift + the real key (not a VK_PACKET), with the Shift released in its own, later SendInput");
        assert_eq!(s.held.lock().unwrap().typing_keys, vec![crate::text_typing::VK_LSHIFT], "the dangling Shift is tracked as TYPING-held");
        s.release_held().unwrap();
        let last_batch = backend.0.lock().unwrap().last().unwrap().clone();
        assert!(is_key_release(&last_batch[0], crate::text_typing::VK_LSHIFT), "teardown releases the Shift");
        assert!(s.held.lock().unwrap().typing_keys.is_empty());
    }

    /// A burst of Text (events the network bunched) still reaches SendInput one character at a time,
    /// at least the gap apart ACROSS events; and one huge event cannot stall past its budget.
    #[test]
    fn typed_characters_are_paced_across_events_within_a_per_event_budget() {
        #[derive(Debug, Default)]
        struct Timed(Mutex<Vec<std::time::Instant>>);
        impl Backend for Timed {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                self.0.lock().unwrap().push(std::time::Instant::now());
                inputs.len() as u32
            }
        }
        let gap = std::time::Duration::from_millis(25);
        let timed = Arc::new(Timed::default());
        let mut s = SendInputSink::with_backend_and_layout(timed.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        s.pace = TypingPace::new(gap, std::time::Duration::from_secs(5));
        // Lowercase: CapitalsOnly has no key for it, so each character is ONE submit (no held modifier).
        s.inject(InputEvent::Text("ab".into())).unwrap();
        s.inject(InputEvent::Text("c".into())).unwrap(); // arrives at once, like a bunched event
        let at = timed.0.lock().unwrap().clone();
        assert_eq!(at.len(), 3, "one SendInput per character");
        for w in at.windows(2) {
            assert!(w[1] - w[0] >= gap - std::time::Duration::from_millis(2), "characters {:?} apart", w[1] - w[0]);
        }

        // Budget: 20 characters at a 25 ms gap would take ~475 ms; a 100 ms budget caps the event.
        let timed = Arc::new(Timed::default());
        let mut s = SendInputSink::with_backend_and_layout(timed.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        s.pace = TypingPace::new(gap, std::time::Duration::from_millis(100));
        let t0 = std::time::Instant::now();
        s.inject(InputEvent::Text("abcdefghijklmnopqrst".into())).unwrap();
        assert!(t0.elapsed() < std::time::Duration::from_millis(300), "the per-event budget did not cap pacing: {:?}", t0.elapsed());
        assert_eq!(timed.0.lock().unwrap().len(), 20, "every character is still typed");
    }

    /// A sink that types on a typist thread (as production does) without following the desktop.
    fn typist_sink(backend: Arc<dyn Backend>, gap_ms: u64) -> SendInputSink {
        let mut s = SendInputSink::with_backend_and_layout(backend, Arc::new(CapitalsOnly));
        s.pace = TypingPace::new(std::time::Duration::from_millis(gap_ms), std::time::Duration::from_secs(10));
        s.typist = Some(Arc::new(TypistCell { started: std::sync::OnceLock::new(), follow_desktop: false }));
        s
    }

    #[derive(Debug, Default)]
    struct Recorder(Mutex<Vec<(std::thread::ThreadId, Vec<u16>)>>);
    impl Backend for Recorder {
        fn submit(&self, inputs: &[INPUT]) -> u32 {
            // SAFETY: keyboard INPUTs built by key_input / unicode_input.
            let keys = inputs.iter().map(|i| unsafe { if i.Anonymous.ki.wVk.0 != 0 { i.Anonymous.ki.wVk.0 } else { i.Anonymous.ki.wScan } }).collect();
            self.0.lock().unwrap().push((std::thread::current().id(), keys));
            inputs.len() as u32
        }
    }

    fn wait_idle(s: &SendInputSink) {
        let t = s.typist.as_ref().unwrap().started.get().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while t.state.pending.load(std::sync::atomic::Ordering::SeqCst) > 0 {
            assert!(std::time::Instant::now() < deadline, "typing never finished");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// Pacing must not sleep on the caller (the shared capture thread: the picture would freeze while
    /// text is typed), and a key sent after text must not overtake it.
    #[test]
    fn text_is_typed_off_the_calling_thread_and_a_following_key_waits_for_it() {
        let rec = Arc::new(Recorder::default());
        let s = typist_sink(rec.clone() as Arc<dyn Backend>, 30);
        let t0 = std::time::Instant::now();
        s.inject(InputEvent::Text("abcd".into())).unwrap();
        assert!(t0.elapsed() < std::time::Duration::from_millis(25), "Text blocked the caller for {:?}", t0.elapsed());
        // A Key waits for the typing before it, then goes in on the CALLING thread (synchronously, so
        // the coordinator's ownership matches the OS), never on the typing queue.
        s.inject(InputEvent::Key { code: 0x0D, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 0x0D, down: false }).unwrap();
        let got = rec.0.lock().unwrap().clone();
        let keys: Vec<Vec<u16>> = got.iter().map(|(_, k)| k.clone()).collect();
        assert_eq!(keys, vec![vec![0x61, 0x61], vec![0x62, 0x62], vec![0x63, 0x63], vec![0x64, 0x64], vec![0x0D], vec![0x0D]],
            "a b c d, THEN Enter down and up");
        assert!(got[..4].iter().all(|(id, _)| *id != std::thread::current().id()), "text typed on the typist thread");
        assert!(got[4..].iter().all(|(id, _)| *id == std::thread::current().id()), "keys injected synchronously on the caller");
    }

    /// Codex 1.3.9 round 11: typing pending for well over 2 s; the Enter that follows must still wait
    /// for ALL of it.
    #[test]
    fn a_key_never_overtakes_long_pending_text() {
        let rec = Arc::new(Recorder::default());
        let s = typist_sink(rec.clone() as Arc<dyn Backend>, 30);
        s.inject(InputEvent::Text("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuv".into())).unwrap(); // ~3 s
        s.inject(InputEvent::Key { code: 0x0D, down: true }).unwrap();
        let got = rec.0.lock().unwrap().clone();
        assert_eq!(got.len(), 101, "all 100 characters, then the Enter: {}", got.len());
        assert_eq!(got.last().unwrap().1, vec![0x0D], "the Enter came last");
    }

    /// Codex 1.3.9 round 10: a key-up after pending text must reach the OS even if the typing is then
    /// cancelled (it is never queued, so a cancel cannot drop it).
    #[test]
    fn a_key_up_after_pending_text_survives_a_typing_cancel() {
        let rec = Arc::new(Recorder::default());
        let s = typist_sink(rec.clone() as Arc<dyn Backend>, 30);
        s.inject(InputEvent::Key { code: 0x4B, down: true }).unwrap(); // a session holds K
        s.inject(InputEvent::Text("abcdefgh".into())).unwrap(); // typing pending
        let canceller = {
            let s = s.clone();
            std::thread::spawn(move || { std::thread::sleep(std::time::Duration::from_millis(40)); s.cancel_typing(false); })
        };
        s.inject(InputEvent::Key { code: 0x4B, down: false }).unwrap(); // K released while typing pending
        canceller.join().unwrap();
        wait_idle(&s);
        let ups: Vec<u16> = rec.0.lock().unwrap().iter().filter(|(_, k)| k == &vec![0x4B]).map(|(_, k)| k[0]).collect();
        assert_eq!(ups.len(), 2, "K's down and its up both reached the OS");
        assert!(s.held.lock().unwrap().keys.is_empty(), "nothing is left held");
    }

    /// Codex 1.3.9 round 1 [high]: a cancel must stop a RUNNING long event between characters, not
    /// only drop queued ones, and must not strand the Shift of the character in flight.
    #[test]
    fn a_cancel_stops_a_running_long_event_within_a_character_and_strands_nothing() {
        let rec = Arc::new(Recorder::default());
        let s = typist_sink(rec.clone() as Arc<dyn Backend>, 30);
        s.inject(InputEvent::Text("ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ".into())).unwrap(); // ~3 s of typing
        std::thread::sleep(std::time::Duration::from_millis(200));
        let t0 = std::time::Instant::now();
        s.cancel_typing(true);
        assert!(t0.elapsed() < std::time::Duration::from_millis(500), "cancel took {:?}: the running event kept typing", t0.elapsed());
        let n = rec.0.lock().unwrap().len();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert_eq!(rec.0.lock().unwrap().len(), n, "keystrokes after the cancel returned");
        assert!(n < 52, "the event was cut short ({n} submissions)");
        assert!(s.held.lock().unwrap().keys.is_empty(), "the in-flight character's Shift was released");
    }

    #[test]
    fn each_character_is_planned_when_it_is_typed() {
        // Focus or layout can change during a long text: the plan is made per character, at its turn.
        #[derive(Debug, Default)]
        struct Counting(std::sync::atomic::AtomicUsize);
        impl crate::text_typing::TextLayout for Counting {
            fn plan(&self, text: &str) -> Vec<Vec<crate::text_typing::Stroke>> {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                crate::text_typing::plan_groups(text, false, |_| None)
            }
        }
        let layout = Arc::new(Counting::default());
        let s = SendInputSink::with_backend_and_layout(Arc::new(TestBackend::default()) as Arc<dyn Backend>, layout.clone());
        s.inject(InputEvent::Text("a\r\nbc".into())).unwrap();
        assert_eq!(layout.0.load(std::sync::atomic::Ordering::SeqCst), 4, "a, one Enter for CRLF, b, c");
    }

    /// Codex 1.3.9 round 5: one session's cancel must not be undone by ANOTHER session's next Text.
    /// A's worker is paused mid-character, A is cancelled, B enqueues Text, the worker resumes: none
    /// of A's remaining characters may be typed; B's are.
    #[test]
    fn another_sessions_text_cannot_revive_a_cancelled_job() {
        struct Gate { rec: Mutex<Vec<u16>>, first: std::sync::Mutex<Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>> }
        impl std::fmt::Debug for Gate {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Gate") }
        }
        impl Backend for Gate {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                // SAFETY: keyboard INPUTs built by unicode_input.
                self.rec.lock().unwrap().push(unsafe { let k = inputs[0].Anonymous.ki; if k.wVk.0 != 0 { k.wVk.0 } else { k.wScan } });
                if let Some((started, resume)) = self.first.lock().unwrap().take() {
                    started.send(()).unwrap();
                    resume.recv().unwrap(); // paused inside A's first character
                }
                inputs.len() as u32
            }
        }
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        let gate = Arc::new(Gate { rec: Mutex::new(Vec::new()), first: std::sync::Mutex::new(Some((started_tx, resume_rx))) });
        // A 20 ms gap between characters, as in production (15 ms), so the worker releases the held lock
        // between characters and the cancel takes it within one character.
        let s = typist_sink(gate.clone() as Arc<dyn Backend>, 20);
        s.inject(InputEvent::Text("aaaa".into())).unwrap(); // session A
        s.inject(InputEvent::Text("aaaa".into())).unwrap(); // more of A, queued
        started_rx.recv().unwrap();
        // A revoked while its press is IN PROGRESS: the cancel takes the held lock the press holds, so
        // it returns only after that press completes (the strict order is the guarantee).
        let canceller = {
            let s = s.clone();
            std::thread::spawn(move || { s.cancel_typing(false); std::time::Instant::now() })
        };
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(!canceller.is_finished(), "the cancel must wait for the press in progress");
        let resumed_at = std::time::Instant::now();
        resume_tx.send(()).unwrap();
        assert!(canceller.join().unwrap() >= resumed_at, "the cancel returned before the in-progress press finished");
        // What A pressed before the cancel took effect (the worker may win the lock for a few more
        // characters after resuming: those are BEFORE the cancel). Nothing of A may follow it.
        let before_cancel = gate.rec.lock().unwrap().len();
        s.inject(InputEvent::Text("bb".into())).unwrap(); // session B, AFTER the cancel
        wait_idle(&s);
        let typed = gate.rec.lock().unwrap().clone();
        let a = 'a' as u16;
        let b = 'b' as u16;
        let after = &typed[before_cancel..];
        assert!(!after.contains(&a), "A typed after its cancel returned: {typed:?} (cancel at {before_cancel})");
        assert_eq!(after.iter().filter(|&&u| u == b).count(), 2, "B's text is typed: {typed:?}");
        assert!(before_cancel < 8, "the cancel never overtook A's queued work, so revival was not exercised: {typed:?}");
    }

    /// Codex 1.3.9 rounds 6 and 9: a character whose cancel arrives after the job started but before
    /// its press (paused in the per-character sync, before the held lock under which it is planned
    /// and pressed) must not be pressed.
    #[test]
    fn a_cancel_before_the_press_prevents_the_press() {
        type Pause = (std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
        static PAUSE: std::sync::Mutex<Option<Pause>> = std::sync::Mutex::new(None);
        fn pausing_settle(_: std::time::Duration) {
            let pause = PAUSE.lock().unwrap().take();
            if let Some((started, resume)) = pause {
                started.send(()).unwrap();
                resume.recv().unwrap(); // paused BEFORE the held lock
            }
        }
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel();
        *PAUSE.lock().unwrap() = Some((started_tx, resume_rx));
        let rec = Arc::new(Recorder::default());
        let mut s = SendInputSink::with_backend_and_layout(rec.clone() as Arc<dyn Backend>, Arc::new(ProductionPolicy));
        s.pace = TypingPace { settle: Some(pausing_settle), ..TypingPace::new(std::time::Duration::ZERO, std::time::Duration::from_secs(10)) };
        s.typist = Some(Arc::new(TypistCell { started: std::sync::OnceLock::new(), follow_desktop: false }));
        s.inject(InputEvent::Text("x".into())).unwrap();
        started_rx.recv().unwrap();
        s.cancel_typing(false);
        resume_tx.send(()).unwrap();
        wait_idle(&s);
        assert!(rec.0.lock().unwrap().is_empty(), "a character was pressed after its job was cancelled");
    }

    /// Codex 1.3.9 round 9: the real-key choice is made under the held lock against the keys the
    /// sessions hold; a leftover typing release never lifts a key a session now owns.
    #[test]
    fn typing_respects_keys_sessions_hold_at_the_press_and_at_the_leftover_release() {
        #[derive(Debug)]
        struct LowerUs;
        impl crate::text_typing::TextLayout for LowerUs {
            fn plan(&self, text: &str) -> Vec<Vec<crate::text_typing::Stroke>> { self.plan_owned(text, &|_| false) }
            fn plan_owned(&self, text: &str, owned: &dyn Fn(u16) -> bool) -> Vec<Vec<crate::text_typing::Stroke>> {
                let key_for = |u: u16| (0x61..=0x7A).contains(&u).then_some(crate::text_typing::KeyFor { vk: u - 0x20, shift: false, ctrl: false, alt: false });
                crate::text_typing::plan_unmodified(text, false, key_for, |vk| owned(vk))
            }
        }
        // 1. A session holds 'A' (VK 0x41): typing 'a' must be a packet, not a press of the session's key.
        let rec = Arc::new(Recorder::default());
        let s = SendInputSink::with_backend_and_layout(rec.clone() as Arc<dyn Backend>, Arc::new(LowerUs));
        s.inject(InputEvent::Key { code: 0x41, down: true }).unwrap();
        s.inject(InputEvent::Text("ab".into())).unwrap();
        let sent: Vec<Vec<u16>> = rec.0.lock().unwrap().iter().map(|(_, k)| k.clone()).collect();
        assert_eq!(sent[1], vec![0x61, 0x61], "'a' went as a packet (unit 0x61), not as the session-held key: {sent:?}");
        assert_eq!(sent[2], vec![0x42, 0x42], "'b' (not held) is its real key: {sent:?}");

        // 2. Typing left 'C' down (its key-up refused); then a session presses 'C'; the leftover retry
        //    must not lift it.
        #[derive(Debug, Default)]
        struct RefuseCUpOnce(std::sync::atomic::AtomicBool, Mutex<Vec<Vec<u16>>>);
        impl Backend for RefuseCUpOnce {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                // SAFETY: keyboard INPUTs.
                let k: Vec<(u16, bool)> = inputs.iter().map(|i| unsafe { (i.Anonymous.ki.wVk.0, i.Anonymous.ki.dwFlags.contains(KEYEVENTF_KEYUP)) }).collect();
                self.1.lock().unwrap().push(k.iter().map(|x| x.0).collect());
                if k.len() == 2 && k[1] == (0x43, true) && !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return 1; // 'C' down went in, its up was refused
                }
                inputs.len() as u32
            }
        }
        let b = Arc::new(RefuseCUpOnce::default());
        let s = SendInputSink::with_backend_and_layout(b.clone() as Arc<dyn Backend>, Arc::new(LowerUs));
        assert!(s.inject(InputEvent::Text("c".into())).is_err());
        assert_eq!(s.held.lock().unwrap().typing_keys, vec![0x43]);
        s.inject(InputEvent::Key { code: 0x43, down: true }).unwrap(); // the session now holds 'C'
        let before = b.1.lock().unwrap().len();
        s.retry_typing_releases();
        assert_eq!(b.1.lock().unwrap().len(), before, "a key-up was sent for a key a session holds");
        assert!(s.held.lock().unwrap().typing_keys.is_empty(), "typing gave up its claim to the session's key");
        assert_eq!(s.held.lock().unwrap().keys, vec![0x43], "the session still holds it");
    }

    /// A key-DOWN run by the typist for a cancelled job is refused under the held lock; key-ups pass.
    #[test]
    fn a_cancelled_typist_refuses_key_downs_but_passes_key_ups() {
        let rec = Arc::new(Recorder::default());
        let mut worker = SendInputSink::with_backend_and_layout(rec.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        let state = Arc::new(TypistState::default());
        state.running.store(1, std::sync::atomic::Ordering::SeqCst);
        state.generation.store(2, std::sync::atomic::Ordering::SeqCst); // job 1 was cancelled
        worker.typing_state = Some(state);
        worker.inject_now(InputEvent::Key { code: 0x0D, down: true }).unwrap();
        assert!(rec.0.lock().unwrap().is_empty(), "a cancelled job's key-down was injected");
        worker.inject_now(InputEvent::Key { code: 0x0D, down: false }).unwrap();
        assert_eq!(rec.0.lock().unwrap().len(), 1, "a key-up must still pass");
    }

    /// Codex 1.3.9 round 7: what TYPING holds (a Shift whose character failed, or whose release
    /// failed) is released when typing is cancelled, which is what shared revocation and teardown
    /// call, and a session's own held key is left to the coordinator.
    #[test]
    fn a_typing_cancel_releases_what_typing_holds_and_only_that() {
        struct Scripted(Mutex<Vec<Vec<u16>>>, Mutex<std::collections::VecDeque<bool>>);
        impl std::fmt::Debug for Scripted {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Scripted") }
        }
        impl Backend for Scripted {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                // SAFETY: keyboard INPUTs.
                self.0.lock().unwrap().push(inputs.iter().map(|i| unsafe { i.Anonymous.ki.wVk.0 }).collect());
                // Scripted: `false` = refuse everything after the first INPUT of this submit.
                if self.1.lock().unwrap().pop_front().unwrap_or(true) { inputs.len() as u32 } else { 1 }
            }
        }
        // 1. A session holds 'Q' (its own Key event). 2. Typing "A": Shift down OK, 'A' refused.
        let b = Arc::new(Scripted(Mutex::new(Vec::new()), Mutex::new(std::collections::VecDeque::from([true, false]))));
        let s = SendInputSink::with_backend_and_layout(b.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        s.inject(InputEvent::Key { code: 0x51, down: true }).unwrap();
        assert!(s.inject(InputEvent::Text("A".into())).is_err());
        assert_eq!(s.held.lock().unwrap().typing_keys, vec![crate::text_typing::VK_LSHIFT]);
        s.cancel_typing(true);
        let h = s.held.lock().unwrap();
        assert!(h.typing_keys.is_empty(), "the typing-held Shift was released by the cancel");
        assert_eq!(h.keys, vec![0x51], "the session's own held key is the coordinator's to release");
        drop(h);
        assert!(b.0.lock().unwrap().last().unwrap() == &vec![crate::text_typing::VK_LSHIFT], "a Shift-up was sent");
    }

    #[test]
    fn a_refused_typing_release_is_kept_and_retried_by_the_next_cancel() {
        #[derive(Debug, Default)]
        struct RefuseOnce(std::sync::atomic::AtomicBool, Mutex<usize>);
        impl Backend for RefuseOnce {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                *self.1.lock().unwrap() += 1;
                // SAFETY: keyboard INPUTs.
                let shift_up = inputs.len() == 1 && unsafe { inputs[0].Anonymous.ki.wVk.0 } == crate::text_typing::VK_LSHIFT
                    && unsafe { inputs[0].Anonymous.ki.dwFlags } == KEYEVENTF_KEYUP;
                if shift_up && !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) { 0 } else { inputs.len() as u32 }
            }
        }
        let b = Arc::new(RefuseOnce::default());
        let s = SendInputSink::with_backend_and_layout(b.clone() as Arc<dyn Backend>, Arc::new(CapitalsOnly));
        assert!(s.inject(InputEvent::Text("A".into())).is_err(), "the character's Shift release was refused");
        assert_eq!(s.held.lock().unwrap().typing_keys, vec![crate::text_typing::VK_LSHIFT]);
        s.cancel_typing(true);
        assert!(s.held.lock().unwrap().typing_keys.is_empty(), "the retry released it");
    }

    /// The production planning policy (packets; Enter/Tab real), with no key physically held.
    #[derive(Debug)]
    struct ProductionPolicy;
    impl crate::text_typing::TextLayout for ProductionPolicy {
        fn plan(&self, text: &str) -> Vec<Vec<crate::text_typing::Stroke>> {
            crate::text_typing::plan_packets(text, |_| false)
        }
    }

    /// Codex 1.3.9 round 8: a refused typing release is retried WITHOUT another cancel (the shared
    /// capture thread calls retry_typing_releases every iteration and at shutdown).
    #[test]
    fn a_refused_typing_release_is_retried_without_another_cancel() {
        #[derive(Debug, Default)]
        struct RefuseEnterUpOnce(std::sync::atomic::AtomicBool);
        impl Backend for RefuseEnterUpOnce {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                // SAFETY: keyboard INPUTs.
                let enter_up = inputs.len() == 1 && unsafe { inputs[0].Anonymous.ki.wVk.0 } == 0x0D
                    && unsafe { inputs[0].Anonymous.ki.dwFlags } == KEYEVENTF_KEYUP;
                let tap_with_refused_up = inputs.len() == 2 && unsafe { inputs[1].Anonymous.ki.wVk.0 } == 0x0D;
                if (enter_up || tap_with_refused_up) && !self.0.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return 1; // the down went in, the up was refused
                }
                inputs.len() as u32
            }
        }
        let s = SendInputSink::with_backend_and_layout(Arc::new(RefuseEnterUpOnce::default()) as Arc<dyn Backend>, Arc::new(ProductionPolicy));
        assert!(s.inject(InputEvent::Text("\n".into())).is_err());
        assert_eq!(s.held.lock().unwrap().typing_keys, vec![0x0D], "the Enter left down is typing-held");
        s.retry_typing_releases();
        assert!(s.held.lock().unwrap().typing_keys.is_empty(), "the capture thread's retry released it");
    }

    /// Codex 1.3.9 round 8: typing must never release a modifier a session holds. Production typing
    /// sends no Shift at all, so a session's held Shift stays held (and is the session's to release).
    #[test]
    fn typing_never_touches_a_shift_a_session_holds() {
        let rec = Arc::new(Recorder::default());
        let s = SendInputSink::with_backend_and_layout(rec.clone() as Arc<dyn Backend>, Arc::new(ProductionPolicy));
        s.inject(InputEvent::Key { code: crate::text_typing::VK_LSHIFT as u32, down: true }).unwrap(); // the session's Shift
        s.inject(InputEvent::Text("AB c".into())).unwrap();
        s.cancel_typing(true);
        let shift_strokes = rec.0.lock().unwrap().iter().flat_map(|(_, k)| k.clone()).filter(|&k| k == crate::text_typing::VK_LSHIFT).count();
        assert_eq!(shift_strokes, 1, "only the session's own Shift-down: typing sent no Shift");
        assert_eq!(s.held.lock().unwrap().keys, vec![crate::text_typing::VK_LSHIFT], "the session's Shift is still held");
    }

    #[test]
    fn release_held_cancels_queued_typing() {
        let rec = Arc::new(Recorder::default());
        let s = typist_sink(rec.clone() as Arc<dyn Backend>, 30);
        s.inject(InputEvent::Text("abcdefghijklmnopqrst".into())).unwrap();
        s.inject(InputEvent::Text("uvwxyz".into())).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        s.release_held().unwrap();
        let typed = rec.0.lock().unwrap().len();
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert_eq!(rec.0.lock().unwrap().len(), typed, "nothing is typed after teardown released");
        assert!(typed < 26, "queued typing was cancelled, not typed out ({typed} characters)");
    }

    #[test]
    fn text_full_success_tracks_nothing() {
        let (s, _b) = sink();
        s.inject(InputEvent::Text("hi".into())).unwrap();
        assert!(s.held.lock().unwrap().unicode.is_empty());
    }

    #[test]
    fn release_held_retries_failed_entries() {
        let (s, b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        // First release attempt: the OS refuses.
        b.set_next(0);
        let _ = s.release_held();
        assert_eq!(s.held.lock().unwrap().keys, vec![65], "failed releases stay tracked");
        // Second attempt succeeds.
        s.release_held().unwrap();
        assert!(s.held.lock().unwrap().keys.is_empty());
    }

    #[test]
    fn clones_share_held_state() {
        let (s, _b) = sink();
        let clone = s.clone();
        s.inject(InputEvent::Key { code: 12, down: true }).unwrap();
        assert_eq!(clone.held.lock().unwrap().keys, vec![12]);
        clone.release_held().unwrap();
        assert!(s.held.lock().unwrap().keys.is_empty());
    }

    #[test]
    fn text_over_limit_is_refused() {
        let (s, _b) = sink();
        let big = "x".repeat(4097);
        assert!(matches!(s.inject(InputEvent::Text(big)), Err(PlatformError::InputRefused(_))));
    }

    // Raw-INPUT inspection helpers. Every assertion below reads back the ACTUAL bytes the sink
    // handed to the backend — bookkeeping-only asserts would let a broken release encoder pass.

    fn last(b: &TestBackend) -> Vec<INPUT> {
        b.submitted.lock().unwrap().last().cloned().expect("at least one submit")
    }
    fn all(b: &TestBackend) -> Vec<Vec<INPUT>> { b.submitted.lock().unwrap().clone() }

    fn is_key_release(i: &INPUT, vk: u16) -> bool {
        i.r#type == INPUT_KEYBOARD && unsafe {
            i.Anonymous.ki.wVk.0 == vk
                && i.Anonymous.ki.dwFlags == KEYEVENTF_KEYUP
                && i.Anonymous.ki.dwExtraInfo == RMT_INJECTED_TAG
        }
    }
    fn is_unicode_release(i: &INPUT, unit: u16) -> bool {
        i.r#type == INPUT_KEYBOARD && unsafe {
            i.Anonymous.ki.wVk.0 == 0
                && i.Anonymous.ki.wScan == unit
                && i.Anonymous.ki.dwFlags == (KEYEVENTF_KEYUP | KEYEVENTF_UNICODE)
                && i.Anonymous.ki.dwExtraInfo == RMT_INJECTED_TAG
        }
    }
    fn is_button_release(i: &INPUT, expect_flags: MOUSE_EVENT_FLAGS, expect_data: i32) -> bool {
        i.r#type == INPUT_MOUSE && unsafe {
            i.Anonymous.mi.dwFlags.0 == expect_flags.0
                && i.Anonymous.mi.mouseData == expect_data as u32
                && i.Anonymous.mi.dwExtraInfo == RMT_INJECTED_TAG
        }
    }

    #[test]
    fn release_key_emits_expected_raw_input_with_tag() {
        let (s, b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.release_held().unwrap();
        let batch = last(&b);
        assert_eq!(batch.len(), 1);
        assert!(is_key_release(&batch[0], 65), "release must be VK 65, KEYUP, tagged, no SCANCODE flag");
    }

    #[test]
    fn release_unicode_emits_up_pair_with_unicode_and_tag() {
        let (s, b) = sink();
        // Force a dangling down so a unicode unit ends up in held.
        b.set_next(1);
        let _ = s.inject(InputEvent::Text("A".into()));
        s.release_held().unwrap();
        let batch = last(&b);
        assert_eq!(batch.len(), 1);
        assert!(is_unicode_release(&batch[0], 0x41), "release must be UNICODE up for 'A', tagged");
    }

    #[test]
    fn release_emits_correct_flags_and_xbutton_data_for_all_five_buttons() {
        // For each button, press then release_held and inspect the RELEASE submit.
        let cases: &[(InputButton, MOUSE_EVENT_FLAGS, i32)] = &[
            (InputButton::Left,    MOUSEEVENTF_LEFTUP,   0),
            (InputButton::Right,   MOUSEEVENTF_RIGHTUP,  0),
            (InputButton::Middle,  MOUSEEVENTF_MIDDLEUP, 0),
            (InputButton::Back,    MOUSEEVENTF_XUP,      XBUTTON1),
            (InputButton::Forward, MOUSEEVENTF_XUP,      XBUTTON2),
        ];
        for &(btn, expect_flags, expect_data) in cases {
            let (s, b) = sink();
            s.inject(InputEvent::MouseButton { button: btn, down: true }).unwrap();
            s.release_held().unwrap();
            let batch = last(&b);
            assert_eq!(batch.len(), 1, "{btn:?}: exactly one release INPUT");
            assert!(
                is_button_release(&batch[0], expect_flags, expect_data),
                "{btn:?}: wrong flags / mouseData / tag on release"
            );
        }
    }

    #[test]
    fn duplicate_key_down_yields_only_one_release_input() {
        let (s, b) = sink();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.release_held().unwrap();
        // Two downs and exactly one release submission.
        assert_eq!(b.record_count(), 3);
        let batch = last(&b);
        assert_eq!(batch.len(), 1, "one held entry → one release INPUT");
        assert!(is_key_release(&batch[0], 65));
    }

    #[test]
    fn partial_text_a_then_full_a_leaves_no_held_a() {
        let (s, b) = sink();
        // First attempt: only the DOWN of 'A' lands (1 of 2 INPUTs). 'A' now held.
        b.set_next(1);
        let _ = s.inject(InputEvent::Text("A".into()));
        assert_eq!(s.held.lock().unwrap().unicode, vec![0x41u16]);
        // Second attempt: full success (2 of 2). The COMPLETED pair must REMOVE the stranded 'A'.
        s.inject(InputEvent::Text("A".into())).unwrap();
        assert!(
            s.held.lock().unwrap().unicode.is_empty(),
            "a completed pair on the same unit clears the previously held unit"
        );
        // Second submit should be 2 INPUTs (down+up), first was 2 INPUTs but only 1 landed.
        assert_eq!(all(&b).len(), 2);
    }

    #[test]
    fn zero_injected_down_is_not_tracked() {
        let (s, b) = sink();
        // Force zero-injected on the text: nothing lands, nothing tracked.
        b.set_next(0);
        let _ = s.inject(InputEvent::Text("A".into()));
        assert!(s.held.lock().unwrap().unicode.is_empty(),
            "an event that did not land must not be tracked as held");
    }

    #[test]
    fn rejected_key_and_button_downs_create_no_cleanup_events() {
        let (s, b) = sink();
        for ev in [InputEvent::Key { code: 65, down: true },
                   InputEvent::MouseButton { button: InputButton::Left, down: true }] {
            b.set_next(0);
            assert!(s.inject(ev).is_err());
        }
        s.release_held().unwrap();
        assert_eq!(b.record_count(), 2, "never release a down that was rejected");
    }

    #[test]
    fn submission_and_cleanup_hold_the_shared_state_lock() {
        #[derive(Debug, Default)]
        struct LockedBackend {
            state: Mutex<Option<std::sync::Weak<Mutex<Held>>>>,
            calls: std::sync::atomic::AtomicUsize,
        }
        impl Backend for LockedBackend {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                let state = self.state.lock().unwrap().as_ref().unwrap().upgrade().unwrap();
                assert!(matches!(state.try_lock(), Err(std::sync::TryLockError::WouldBlock)),
                    "submit and held-state accounting must be serialized across clones");
                self.calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                inputs.len() as u32
            }
        }
        let b = Arc::new(LockedBackend::default());
        let s = SendInputSink::with_backend(b.clone());
        *b.state.lock().unwrap() = Some(Arc::downgrade(&s.held));
        for ev in [
            InputEvent::Key { code: 65, down: true },
            InputEvent::MouseButton { button: InputButton::Back, down: true },
            InputEvent::Text("test".into()),
            InputEvent::MouseMove { x: 0, y: 0 },
            InputEvent::Scroll { dx: 0, dy: 1 },
        ] {
            s.inject(ev).unwrap();
        }
        s.clone().release_held().unwrap();
        // Key 1 + button 1 + Text "test" 4 (one paced SendInput per character) + move 1 + scroll 1
        // + release 2, every one of them under the held lock.
        assert_eq!(b.calls.load(std::sync::atomic::Ordering::Relaxed), 10);
    }

    #[test]
    fn rejected_up_leaves_down_held() {
        let (s, _b) = sink();
        // Regular key path: successful down.
        s.inject(InputEvent::Key { code: 42, down: true }).unwrap();
        assert_eq!(s.held.lock().unwrap().keys, vec![42]);
        // Force the up to be refused (0 injected out of 1). Tracked set must retain 42.
        _b.set_next(0);
        let err = s.inject(InputEvent::Key { code: 42, down: false }).unwrap_err();
        assert!(matches!(err, PlatformError::InputRefused(_)));
        assert_eq!(s.held.lock().unwrap().keys, vec![42],
            "a failed up leaves the down in held for later release");
    }

    #[test]
    fn partial_release_retains_only_failed_entries() {
        // Track three keys; make the SECOND release fail; verify only that one is retained.
        let backend = Arc::new(TestBackend::default());
        let s = SendInputSink::with_backend(backend.clone() as Arc<dyn Backend>);
        s.inject(InputEvent::Key { code: 1, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 2, down: true }).unwrap();
        s.inject(InputEvent::Key { code: 3, down: true }).unwrap();
        // Custom backend that fails only when releasing VK 2.
        #[derive(Default)]
        struct FailOnVk2(Mutex<Vec<Vec<INPUT>>>);
        impl std::fmt::Debug for FailOnVk2 {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("FailOnVk2")
            }
        }
        impl Backend for FailOnVk2 {
            fn submit(&self, inputs: &[INPUT]) -> u32 {
                self.0.lock().unwrap().push(inputs.to_vec());
                let vk2 = inputs.iter().any(|i| i.r#type == INPUT_KEYBOARD
                    && unsafe { i.Anonymous.ki.wVk.0 == 2 && (i.Anonymous.ki.dwFlags.0 & KEYEVENTF_KEYUP.0) != 0 });
                if vk2 { 0 } else { inputs.len() as u32 }
            }
        }
        let failing = Arc::new(FailOnVk2::default());
        // Swap backend on the sink (rebuild sharing the same held set).
        let s2 = SendInputSink {
            backend: failing.clone() as Arc<dyn Backend>,
            held: s.held.clone(),
            layout: s.layout.clone(),
            pace: s.pace.clone(),
            typist: None,
            typing_state: None,
        };
        let err = s2.release_held().unwrap_err();
        assert!(matches!(err, PlatformError::InputRefused(_)));
        let remaining = &s2.held.lock().unwrap().keys;
        assert_eq!(remaining, &vec![2u16], "only the failed entry stays held");
    }

    /// Fail-closed regression: in a unit-test build the REAL backend panics before `SendInput`.
    /// Uses an EMPTY batch so that, if the guard were removed, the call would take the empty
    /// shortcut and return 0 without touching the OS — the test then fails, but nothing is typed.
    #[test]
    fn real_backend_panics_before_os_call_in_unit_tests() {
        let r = std::panic::catch_unwind(|| SendInputBackend.submit(&[]));
        let msg = r.expect_err("real SendInput backend must refuse in unit-test builds");
        let msg = msg.downcast_ref::<String>().map(String::as_str).unwrap_or("");
        assert!(msg.contains("real SendInput backend reached from a unit-test build"), "{msg}");
    }

    /// The production constructor routes through the guarded real backend (not a silent fake):
    /// a unit test that builds `SendInputSink::new()` and injects would hit the panic above.
    #[test]
    fn production_constructor_uses_guarded_real_backend() {
        let s = SendInputSink::new();
        assert_eq!(format!("{:?}", s.backend), "SendInputBackend");
    }
}

#[cfg(test)]
mod tests {
    use super::norm::*;
    use super::remap_input_for_monitor;
    use rmt_agent_core::platform::MonitorInfo;
    use rmt_agent_core::{InputButton, InputEvent, COMPOSITE_MONITOR_ID};

    fn mon(id: u32, left: i32, top: i32, width: u32, height: u32) -> MonitorInfo {
        MonitorInfo { id, width, height, dpi_scale: 1.0, left, top }
    }

    #[test]
    fn origin_maps_to_zero() {
        assert_eq!(pixel_to_absolute(0, 0, 1920), 0);
        // Non-zero (negative) origin: a monitor to the left of primary.
        assert_eq!(pixel_to_absolute(-1920, -1920, 3840), 0);
    }

    #[test]
    fn far_edge_maps_to_max() {
        // The last pixel column maps exactly to 65535 (divisor is extent-1).
        assert_eq!(pixel_to_absolute(1919, 0, 1920), ABS_MAX);
        // Negative-origin desktop (origin -1920, width 3840): the far edge is the last
        // column, pixel 1919 (offset 3839 == divisor), not pixel -1 (which is mid-span).
        assert_eq!(pixel_to_absolute(1919, -1920, 3840), ABS_MAX);
    }

    #[test]
    fn midpoint_is_centered() {
        // Middle pixel of a 1921-wide span lands at the center of the range. 960/1920*65535
        // = 32767.5; the mapping rounds half up, so the center resolves to 32768.
        let mid = pixel_to_absolute(960, 0, 1921);
        assert_eq!(mid, ABS_MAX / 2 + 1);
    }

    #[test]
    fn clamps_outside_bounds() {
        assert_eq!(pixel_to_absolute(-100, 0, 1920), 0);
        assert_eq!(pixel_to_absolute(5000, 0, 1920), ABS_MAX);
    }

    #[test]
    fn negative_origin_virtual_desktop() {
        // Two 1920-wide monitors, primary on the right: virtual origin at -1920, width 3840.
        // The seam (x=0, start of the primary) should sit at the halfway mark.
        let seam = pixel_to_absolute(0, -1920, 3840);
        // 1920 / 3839 * 65535 ≈ 32776
        assert!((seam - ABS_MAX / 2).abs() <= 20, "seam={seam}");
    }

    #[test]
    fn point_helper_maps_both_axes() {
        let (ax, ay) = point_to_absolute(1919, 1079, (0, 0, 1920, 1080));
        assert_eq!((ax, ay), (ABS_MAX, ABS_MAX));
    }

    #[test]
    fn degenerate_extent_is_safe() {
        // A 0- or 1-pixel extent must not divide by zero.
        assert_eq!(pixel_to_absolute(10, 0, 0), 0);
        assert_eq!(pixel_to_absolute(10, 0, 1), 0);
    }

    #[test]
    fn monotonic_across_span() {
        // The mapping must be non-decreasing as the pixel advances.
        let mut prev = -1;
        for px in 0..1920 {
            let v = pixel_to_absolute(px, 0, 1920);
            assert!(v >= prev, "not monotonic at px={px}: {v} < {prev}");
            prev = v;
        }
    }

    // ---- remap_input_for_monitor (the multi-monitor pointer fix) -------------------------------

    #[test]
    fn remap_second_monitor_puts_frame_origin_at_the_desktop_middle() {
        // Two side-by-side 1920-wide monitors; the SECOND is selected. Its frame-left (x=0) is the
        // MIDDLE of the virtual desktop, and its frame-right (x=65535) is the desktop's right edge.
        // This is the whole bug: pre-fix, x=0 injected as 0 (far-left of the desktop) and the click
        // landed a full monitor off. The tolerance covers the /width vs /(extent-1) rounding.
        let mons = [mon(0, 0, 0, 1920, 1080), mon(1, 1920, 0, 1920, 1080)];
        let vd = (0, 0, 3840, 1080);

        let left = remap_input_for_monitor(InputEvent::MouseMove { x: 0, y: 0 }, 1, &mons, vd);
        match left {
            InputEvent::MouseMove { x, .. } => {
                assert!((32000..=33500).contains(&x), "frame-left of monitor 2 should map to ~middle, got {x}");
            }
            other => panic!("expected MouseMove, got {other:?}"),
        }

        let right =
            remap_input_for_monitor(InputEvent::MouseMove { x: 65535, y: 0 }, 1, &mons, vd);
        match right {
            InputEvent::MouseMove { x, .. } => {
                assert!(x >= 65000, "frame-right of monitor 2 should map to the desktop right edge, got {x}");
            }
            other => panic!("expected MouseMove, got {other:?}"),
        }
    }

    #[test]
    fn remap_single_monitor_at_origin_is_near_identity() {
        // The control that must NOT regress: with one monitor that IS the virtual desktop, the two
        // coordinate spaces coincide, so the remap barely moves the point. (An always-offset remap
        // would fail this — it is the negative control for the test above.)
        let mons = [mon(0, 0, 0, 1920, 1080)];
        let vd = (0, 0, 1920, 1080);
        let out = remap_input_for_monitor(InputEvent::MouseMove { x: 32768, y: 40000 }, 0, &mons, vd);
        match out {
            InputEvent::MouseMove { x, y } => {
                assert!((x as i32 - 32768).abs() <= 40, "x drifted too far: {x}");
                assert!((y as i32 - 40000).abs() <= 40, "y drifted too far: {y}");
            }
            other => panic!("expected MouseMove, got {other:?}"),
        }
    }

    #[test]
    fn remap_negative_origin_monitor_left_of_primary() {
        // A monitor positioned LEFT of the primary (negative origin) — frame-middle must land in the
        // left half of the virtual desktop, proving negative origins are handled (they are why the
        // math uses i32 origins, not u32).
        let mons = [mon(0, 0, 0, 1920, 1080), mon(1, -1920, 0, 1920, 1080)];
        let vd = (-1920, 0, 3840, 1080);
        let out = remap_input_for_monitor(InputEvent::MouseMove { x: 32768, y: 32768 }, 1, &mons, vd);
        match out {
            InputEvent::MouseMove { x, .. } => {
                assert!(x < 32768, "middle of the LEFT monitor should be in the desktop's left half, got {x}");
            }
            other => panic!("expected MouseMove, got {other:?}"),
        }
    }

    #[test]
    fn remap_passes_through_composite_unknown_and_non_move() {
        let mons = [mon(0, 0, 0, 1920, 1080), mon(1, 1920, 0, 1920, 1080)];
        let vd = (0, 0, 3840, 1080);
        let mv = InputEvent::MouseMove { x: 100, y: 200 };

        // Composite "view all": the stitched frame already spans the virtual desktop → unchanged.
        assert_eq!(
            remap_input_for_monitor(mv.clone(), COMPOSITE_MONITOR_ID, &mons, vd),
            mv
        );
        // Unknown selection → unchanged (safer than guessing).
        assert_eq!(remap_input_for_monitor(mv.clone(), 42, &mons, vd), mv);
        // A non-MouseMove event → untouched.
        let click = InputEvent::MouseButton { button: InputButton::Left, down: true };
        assert_eq!(remap_input_for_monitor(click.clone(), 1, &mons, vd), click);
    }
}

#[cfg(test)]
mod permit_tests {
    //! docs/53 §3.3: the elevated helper's press permit, checked per INPUT at the OS boundary.
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Sent(Mutex<Vec<INPUT>>);
    impl std::fmt::Debug for Sent {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("Sent") }
    }
    impl Backend for Sent {
        fn submit(&self, inputs: &[INPUT]) -> u32 {
            self.0.lock().unwrap().extend_from_slice(inputs);
            inputs.len() as u32
        }
    }

    fn permitted(open: Arc<AtomicBool>) -> (SendInputSink, Arc<Sent>) {
        let sent = Arc::new(Sent::default());
        let mut sink = SendInputSink::with_backend(sent.clone() as Arc<dyn Backend>);
        sink.backend = Arc::new(PermitBackend { inner: sink.backend, permit: Arc::new(move || open.load(Ordering::SeqCst)) });
        (sink, sent)
    }

    #[test]
    fn presses_need_the_permit_and_releases_never_do() {
        let open = Arc::new(AtomicBool::new(true));
        let (s, sent) = permitted(open.clone());
        s.inject(InputEvent::Key { code: 65, down: true }).unwrap();
        s.inject(InputEvent::MouseButton { button: InputButton::Left, down: true }).unwrap();
        assert_eq!(sent.0.lock().unwrap().len(), 2, "presses pass while permitted");

        open.store(false, Ordering::SeqCst);
        assert!(s.inject(InputEvent::Key { code: 66, down: true }).is_err(), "a refused press is reported");
        assert!(s.inject(InputEvent::MouseMove { x: 10, y: 10 }).is_err(), "a move is a press");
        assert!(s.inject(InputEvent::Scroll { dx: 0, dy: 1 }).is_err(), "a wheel is a press");
        assert_eq!(sent.0.lock().unwrap().len(), 2, "nothing reached the OS");

        s.inject(InputEvent::Key { code: 65, down: false }).unwrap();
        s.inject(InputEvent::MouseButton { button: InputButton::Left, down: false }).unwrap();
        assert_eq!(sent.0.lock().unwrap().len(), 4, "releases pass a closed permit");
        assert!(s.held.lock().unwrap().keys.is_empty() && s.held.lock().unwrap().buttons.is_empty());
    }

    /// Typed text is checked per character: the permit closing mid-text stops it at the next one,
    /// and held accounting covers exactly what was sent.
    #[test]
    fn typing_is_checked_before_every_character() {
        let checks = Arc::new(AtomicUsize::new(0));
        let sent = Arc::new(Sent::default());
        let mut s = SendInputSink::with_backend(sent.clone() as Arc<dyn Backend>);
        let c = checks.clone();
        // Permit the first three presses only.
        s.backend = Arc::new(PermitBackend { inner: s.backend, permit: Arc::new(move || c.fetch_add(1, Ordering::SeqCst) < 3) });
        let _ = s.inject(InputEvent::Text("abcdef".into()));
        let inputs = sent.0.lock().unwrap().clone();
        let downs = inputs.iter().filter(|i| !is_release_input(i)).count();
        assert_eq!(downs, 3, "exactly the permitted presses reached the OS: {}", inputs.len());
        s.release_held().unwrap();
        let after = sent.0.lock().unwrap().clone();
        let ups = after.iter().filter(|i| is_release_input(i)).count();
        assert_eq!(ups, downs, "every press that went out is released: nothing stays down");
    }

    /// docs/53 §6(e2), end to end: the real sink and permit over the helper's admission state, with
    /// NO gate frame after the first renewal (the reader is stalled). Each check advances the clock
    /// 50 ms; the lease (stamped at 0, `LEASE_MS` = 250) must stop typing at the press checked at
    /// 250 ms, by itself.
    #[test]
    fn the_lease_alone_stops_typing_with_the_reader_stalled() {
        use rmt_agent_core::elevation_gate::{Admission, LEASE_MS};
        use std::sync::atomic::AtomicU64;
        let now = Arc::new(AtomicU64::new(0));
        let n = now.clone();
        let state = Arc::new(crate::elevated_input::HelperState::new(Arc::new(move || n.fetch_add(50, Ordering::SeqCst))));
        let mut adm = Admission::new();
        state.apply_for_tests(adm.admit());
        state.apply_for_tests(adm.renew(0).unwrap());
        // Reset: the two applies above did not read the clock, but be explicit.
        now.store(0, Ordering::SeqCst);

        let sent = Arc::new(Sent::default());
        let mut s = SendInputSink::with_backend(sent.clone() as Arc<dyn Backend>);
        let st = state.clone();
        s.backend = Arc::new(PermitBackend { inner: s.backend, permit: Arc::new(move || st.may_press()) });
        let _ = s.inject(InputEvent::Text("abcdefghij".into()));
        let presses = sent.0.lock().unwrap().iter().filter(|i| !is_release_input(i)).count();
        assert_eq!(presses as u64, LEASE_MS / 50, "checks at 0..200 ms pass, the one at 250 ms is refused");
    }

    #[test]
    fn release_classification() {
        assert!(is_release_input(&key_input(65, false, false)));
        assert!(!is_release_input(&key_input(65, true, false)));
        assert!(is_release_input(&mouse_input(MOUSEEVENTF_LEFTUP | MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 1, 1, 0)));
        assert!(!is_release_input(&mouse_input(MOUSEEVENTF_LEFTDOWN, 0, 0, 0)));
        assert!(!is_release_input(&mouse_input(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, 1, 1, 0)));
        assert!(!is_release_input(&mouse_input(MOUSEEVENTF_WHEEL, 0, 0, 120)));
        assert!(!is_release_input(&mouse_input(MOUSEEVENTF_LEFTUP | MOUSEEVENTF_RIGHTDOWN, 0, 0, 0)), "a mixed up+down is a press");
    }
}