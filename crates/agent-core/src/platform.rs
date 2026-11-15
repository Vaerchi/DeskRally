//! Platform seams — the traits each OS layer (Windows / macOS / Linux) implements so the core
//! can capture the screen, inject input, and run as a service without knowing *how*.
//!
//! These are intentionally **plain** (non-`async`) traits. Screen capture and input injection
//! are backed by blocking OS calls (DXGI Desktop Duplication, `SendInput`, `CGEvent`, `XTest`);
//! the OS crate decides whether to run them on a dedicated thread or a blocking task. Keeping
//! the trait object-safe and `async`-free avoids pulling an async-trait dependency into a seam
//! that many callers only ever drive from a capture thread. Every method returns
//! [`PlatformResult`] so a lost display / denied session surfaces as an error, never a panic.

use std::fmt;

/// Result alias for platform operations.
pub type PlatformResult<T> = Result<T, PlatformError>;

/// Errors a platform layer can raise. Kept coarse on purpose — the core reacts to *categories*
/// (retryable vs fatal), while the OS layer logs the precise `HRESULT`/errno in the message.
#[derive(Debug, thiserror::Error)]
pub enum PlatformError {
    /// The requested monitor id is not (or no longer) present.
    #[error("unknown monitor id {0}")]
    UnknownMonitor(u32),
    /// A transient capture failure (e.g. desktop switch, mode change) — retry is appropriate.
    #[error("capture temporarily unavailable: {0}")]
    CaptureUnavailable(String),
    /// Input injection was refused (e.g. secure desktop, insufficient integrity level).
    #[error("input injection refused: {0}")]
    InputRefused(String),
    /// The OS session/service is not in a state where this can run.
    #[error("service host error: {0}")]
    Service(String),
    /// Anything else, with the underlying platform detail preserved as text.
    #[error("platform error: {0}")]
    Other(String),
}

/// Reserved monitor id meaning **"view all"** — a single composite frame of every attached monitor
/// stitched together, rather than one physical display. A controller requests it with
/// [`crate::control::ControlMessage::SelectMonitor`] `{ id: COMPOSITE_MONITOR_ID }`; the capture side
/// answers via [`ScreenCapturer::capture_composite`]. `u32::MAX` is used so it can never collide with
/// a real capturer index (monitors are `0..N`). The TypeScript controller mirrors it in
/// `web/viewer/src/lib/control.ts`.
pub const COMPOSITE_MONITOR_ID: u32 = u32::MAX;

/// A single observation of the machine's display topology used by the host to detect a
/// runtime change (add/remove/move/resize/DPI/name reassignment) and terminate the session
/// rather than continue routing input against a stale layout.
///
/// Deliberately platform-neutral: [`MonitorInfo`] fields plus a **logical output name** (e.g. the
/// GDI device string `\\.\DISPLAY1`) — never a physical device instance path or EDID. The name
/// participates in equality, so a replacement that changes the logical name is detectable; a
/// same-name, same-rect, same-DPI substitution (physical panel swapped underneath an identical
/// logical output) is *not* detectable and is out of scope for this guard.
/// Ordering follows the enumeration's own order and is significant for comparison.
///
/// A `None` from [`ScreenCapturer::topology_snapshot`] means the platform can neither observe nor
/// guarantee a fresh, complete snapshot on this call — the host treats that as *no signal* (it
/// preserves the previous baseline) rather than a change.
#[derive(Debug, Clone, PartialEq)]
pub struct TopologySnapshot {
    /// Ordered monitors (same order the platform's own enumeration produced).
    pub monitors: Vec<MonitorInfo>,
    /// Logical output name per monitor, positionally aligned with [`Self::monitors`]. Empty entries
    /// are allowed for platforms whose enumeration cannot name an output.
    pub names: Vec<String>,
}

/// Static description of a monitor as reported by the platform layer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MonitorInfo {
    /// Stable-within-a-session id used to select a monitor in [`ScreenCapturer::capture_frame`].
    pub id: u32,
    /// Width in physical pixels.
    pub width: u32,
    /// Height in physical pixels.
    pub height: u32,
    /// DPI scale factor (1.0 = 96 DPI, 1.5 = 150%, …). Used to map absolute pointer coordinates.
    pub dpi_scale: f32,
    /// X origin of this monitor within the VIRTUAL DESKTOP, in pixels. Can be negative (a monitor
    /// left of the primary). Required to map a controller's frame-normalized pointer onto the right
    /// place in the virtual desktop when more than one monitor exists — see the input-remap in the
    /// Windows host. Platforms that don't report it use 0 (correct for a single primary at origin).
    pub left: i32,
    /// Y origin of this monitor within the virtual desktop, in pixels. Can be negative. See `left`.
    pub top: i32,
}

/// One captured screen image, ready to be handed to the encoder / video channel.
///
/// `bytes` is the raw frame in whatever pixel/encoded form the capturer produces (the encoder
/// stage, not defined here, normalizes it). `is_keyframe` lets the video pipeline decide whether
/// this frame can stand alone or depends on a previous one.
#[derive(Debug, Clone, PartialEq)]
pub struct CapturedFrame {
    /// Which monitor this frame came from (matches a [`MonitorInfo::id`]).
    pub monitor_id: u32,
    /// Frame width in pixels.
    pub width: u32,
    /// Frame height in pixels.
    pub height: u32,
    /// Raw frame payload (pixels or pre-encoded bytes — the capturer documents which).
    pub bytes: Vec<u8>,
    /// Whether this frame is self-contained (a keyframe) vs a delta on the previous one.
    pub is_keyframe: bool,
}

/// Stitch per-monitor BGRA frames into one composite ("view all") image, laid out left-to-right in
/// the given order. The result is `Σ widths` wide by `max height` tall; each source is copied at its
/// running x offset, and rows below a shorter monitor are left black. Assumes packed BGRA (4 bytes /
/// pixel), which every [`ScreenCapturer`] produces. `frames` must be non-empty (the caller — today
/// [`ScreenCapturer::capture_composite`] — guarantees it); an empty slice yields a 0×0 frame.
///
/// The layout is a simple horizontal strip, not the monitors' true virtual-desktop geometry
/// (`MonitorInfo` carries no origin offsets yet) — enough to *see* every display at once; matching
/// the physical arrangement is a later refinement.
///
/// Validation rules (the capturer is not trusted to be self-consistent):
/// - A source whose `bytes.len()` is not exactly `width * height * 4` (short *or* longer, e.g. a
///   padded row pitch) is invalid: it is not copied at all (its region stays black, all-or-nothing)
///   but its width still advances the x offset so the other monitors keep their positions.
/// - If the summed width overflows `u32`, or the composite would exceed [`MAX_COMPOSITE_BYTES`],
///   an empty 0×0 composite is returned (same monitor id / keyframe rules) instead of panicking or
///   allocating.
pub fn composite_frames(frames: &[CapturedFrame]) -> CapturedFrame {
    let is_keyframe = frames.first().map(|f| f.is_keyframe).unwrap_or(true);
    let empty = || CapturedFrame {
        monitor_id: COMPOSITE_MONITOR_ID,
        width: 0,
        height: 0,
        bytes: Vec::new(),
        is_keyframe,
    };
    let width = match frames
        .iter()
        .try_fold(0u32, |acc, f| acc.checked_add(f.width))
    {
        Some(w) => w,
        None => return empty(),
    };
    let height: u32 = frames.iter().map(|f| f.height).max().unwrap_or(0);
    // u32*u32 fits in u64 but the *4 may not, so use checked math.
    let total = match u64::from(width)
        .checked_mul(u64::from(height))
        .and_then(|px| px.checked_mul(4))
    {
        Some(t) if t <= MAX_COMPOSITE_BYTES => t,
        _ => return empty(),
    };
    // Every usize conversion/multiply is checked too: on a 32-bit target a huge width with a zero
    // height passes the u64 size check (total == 0) yet `width * 4` would not fit in usize.
    let (Ok(total), Some(stride)) = (usize::try_from(total), (width as usize).checked_mul(4))
    else {
        return empty();
    };
    let mut bytes = vec![0u8; total];
    let mut x_off = 0usize; // pixels from the left edge
    for f in frames {
        let valid = (f.width as usize)
            .checked_mul(f.height as usize)
            .and_then(|px| px.checked_mul(4))
            == Some(f.bytes.len());
        if valid {
            // Valid implies width * 4 fits in usize (it divides the buffer length).
            let src_stride = f.width as usize * 4;
            for y in 0..f.height as usize {
                let src = y * src_stride;
                let dst = y * stride + x_off * 4;
                bytes[dst..dst + src_stride].copy_from_slice(&f.bytes[src..src + src_stride]);
            }
        }
        x_off += f.width as usize;
    }
    CapturedFrame {
        monitor_id: COMPOSITE_MONITOR_ID,
        width,
        height,
        bytes,
        // Preserve the capture cadence from the first (primary) monitor rather than forcing every
        // composite to a keyframe, which would bloat the stream.
        is_keyframe,
    }
}

/// Largest composite buffer [`composite_frames`] will allocate (1 GiB), mirroring the encoder's
/// decoded-frame cap; anything larger yields an empty 0×0 composite.
pub const MAX_COMPOSITE_BYTES: u64 = 1 << 30;

/// Captures frames from the machine's displays. Implemented per-OS (DXGI on Windows, etc.).
///
/// Object-safe so the core can hold `Box<dyn ScreenCapturer + Send>`.
pub trait ScreenCapturer: Send {
    /// Enumerate the currently attached monitors. May change across calls (hotplug); the core
    /// re-queries when a capture returns [`PlatformError::UnknownMonitor`].
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>>;

    /// Capture a single frame from the given monitor. Blocking; the OS layer chooses the thread.
    fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame>;
    /// **Optional** — the frame rate the session pulling from this capturer currently wants (after
    /// policy). A capturer that feeds several sessions from one producer paces the producer to the
    /// fastest live demand, so nobody captures faster than any viewer asked. Default: ignored.
    fn set_frame_rate_hint(&mut self, _fps: u32) {}
    /// **Optional** — the next [`Self::capture_frame`] must deliver a complete current frame even if
    /// nothing on screen changed: a new viewer joined and has no picture yet. A capturer whose
    /// `capture_frame` can report an unchanged screen as "no news" overrides this; the default does
    /// nothing, which suits capturers that always capture.
    fn force_next_frame(&mut self) {}
    /// **Optional** — a composite capture that may report *no news*: `Ok(None)` when nothing on
    /// screen changed since the last frame this capturer handed out, so the caller sends nothing
    /// (sessions keep their keep-alive). `force` asks for a complete current frame even when nothing
    /// changed (a new viewer joined and has no picture yet). The default is
    /// [`Self::capture_composite`], which always captures; a capturer that can tell an unchanged
    /// screen apart (docs/52, DXGI duplication) overrides this.
    fn capture_composite_if_changed(&mut self, _force: bool) -> PlatformResult<Option<CapturedFrame>> {
        self.capture_composite().map(Some)
    }

    /// **Optional** — return a single, fresh, complete topology observation, or `None` when the
    /// platform cannot make one on this call (unsupported OS, enumeration API failed, callback
    /// incomplete, empty/degenerate result). The default returns `None` so existing capturers
    /// remain source-compatible.
    ///
    /// The host uses this to detect runtime topology change and terminate the session; a `None`
    /// is *not* a signal of change (the host preserves the previous baseline).
    fn topology_snapshot(&self) -> Option<TopologySnapshot> {
        None
    }

    /// Capture a single **composite** ("view all") frame: every attached monitor captured and
    /// stitched into one image (see [`composite_frames`]). The default implementation enumerates
    /// [`Self::monitors`] and composes their [`Self::capture_frame`] results, so every capturer gets
    /// view-all for free; a platform may override with a native composite. Selected via the reserved
    /// [`COMPOSITE_MONITOR_ID`].
    ///
    /// Layout note: monitors are stitched left-to-right **in `monitors()` order**, so a platform
    /// whose ids are not positional produces a view-all whose panes sit in the wrong places. The
    /// Windows capturer orders its ids by virtual-desktop position for exactly this reason.
    ///
    /// Fidelity note: a tier that ignores `monitor_id` and only ever captures the primary would
    /// stitch repeats of the primary. Every Windows tier now addresses a monitor by its
    /// virtual-desktop rect, so the composite is distinct displays.
    fn capture_composite(&mut self) -> PlatformResult<CapturedFrame> {
        let mons = self.monitors()?;
        if mons.is_empty() {
            return Err(PlatformError::CaptureUnavailable(
                "no monitors to composite".to_string(),
            ));
        }
        let mut frames = Vec::with_capacity(mons.len());
        for m in &mons {
            frames.push(self.capture_frame(m.id)?);
        }
        Ok(composite_frames(&frames))
    }
}

/// A pointer button in an [`InputEvent::MouseButton`] event.
///
/// Serializes as a bare JSON string (`"Left"`, `"Right"`, `"Middle"`, `"Back"`, `"Forward"`) —
/// the value carried in the `button` field of a `MouseButton` event on the input wire (see
/// [`crate::input_codec`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InputButton {
    /// Primary (usually left) button.
    Left,
    /// Secondary (usually right) button.
    Right,
    /// Middle / wheel button.
    Middle,
    /// Backward navigation (X1).
    Back,
    /// Forward navigation (X2).
    Forward,
}

/// A controller→agent input event to be injected into the local desktop.
///
/// Pointer coordinates are **absolute, normalized to `0..=65535`** across the target monitor's
/// full extent (the Win32 `MOUSEEVENTF_ABSOLUTE` convention). This makes them resolution- and
/// DPI-independent on the wire; the [`InputSink`] scales to physical pixels using
/// [`MonitorInfo::dpi_scale`].
///
/// # Wire shape (canonical input codec)
///
/// [`crate::input_codec`] serializes this enum as **adjacently-tagged** JSON: a `"t"` tag naming
/// the variant plus a `"c"` content holding the variant's fields. Adjacent tagging (rather than
/// the flat internal `#[serde(tag = "t")]`) is required because [`InputEvent::Text`] is a newtype
/// variant wrapping a bare `String`, which serde cannot flatten into an internally-tagged object.
/// This shape is STABLE — the browser controller (`web/viewer/src/lib/input.ts`) must emit exactly
/// these bytes. Per variant:
///
/// * `MouseMove { x, y }`        → `{"t":"MouseMove","c":{"x":32768,"y":100}}`
/// * `MouseButton { button, down }` → `{"t":"MouseButton","c":{"button":"Left","down":true}}`
/// * `Scroll { dx, dy }`         → `{"t":"Scroll","c":{"dx":0,"dy":3}}`
/// * `Key { code, down }`        → `{"t":"Key","c":{"code":65,"down":true}}`
/// * `Text(String)`             → `{"t":"Text","c":"hello"}`
/// * `Sas`                       → `{"t":"Sas"}`  (unit variant — no content object)
///
/// `button` is the bare-string [`InputButton`] (`"Left"` | `"Right"` | `"Middle"` | `"Back"` |
/// `"Forward"`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "t", content = "c")]
pub enum InputEvent {
    /// Move the pointer to an absolute normalized position.
    MouseMove {
        /// X in `0..=65535` across the monitor width.
        x: u16,
        /// Y in `0..=65535` across the monitor height.
        y: u16,
    },
    /// Press (`down = true`) or release (`down = false`) a mouse button.
    MouseButton {
        /// Which button.
        button: InputButton,
        /// `true` = press, `false` = release.
        down: bool,
    },
    /// Scroll wheel movement. Positive `dy` scrolls up, positive `dx` scrolls right (units are
    /// wheel detents; the sink maps to `WHEEL_DELTA`).
    Scroll {
        /// Horizontal wheel movement.
        dx: i32,
        /// Vertical wheel movement.
        dy: i32,
    },
    /// A raw key press/release by platform-independent scancode/keycode.
    Key {
        /// Key code (USB HID usage in v1; the sink maps to the OS virtual-key/scancode).
        code: u32,
        /// `true` = press, `false` = release.
        down: bool,
    },
    /// Inject a run of Unicode text directly (IME / paste-style), bypassing scancodes.
    Text(String),
    /// Trigger the **Secure Attention Sequence** (Ctrl+Alt+Del).
    ///
    /// SAS is special: Windows deliberately ignores a Ctrl+Alt+Del synthesized through
    /// `SendInput`, so it cannot ride the ordinary [`InputEvent::Key`] path. The platform
    /// [`InputSink`] instead routes this variant to `SendSAS` (Windows), which asks Winlogon to
    /// raise the secure desktop. That call is only honored for a process running as a
    /// LocalSystem service **and** with the machine's software-SAS policy enabled — both of which
    /// the installed SYSTEM helper satisfies. A unit variant, so it carries no content on the
    /// wire (`{"t":"Sas"}`).
    Sas,
}

/// Injects [`InputEvent`]s into the local desktop. Implemented per-OS (`SendInput`, etc.).
///
/// Takes `&self` (not `&mut self`) so a single sink can be shared behind an `Arc` and driven
/// from the input-channel task without locking.
pub trait InputSink: Send + Sync {
    /// Inject one input event. Returns [`PlatformError::InputRefused`] if the OS blocked it
    /// (e.g. the secure/login desktop, where a service-level helper is required).
    fn inject(&self, event: InputEvent) -> PlatformResult<()>;

    /// **Optional** — release every input the sink has tracked as currently held (keys, unicode
    /// units, mouse buttons). Called on session teardown so a topology-triggered end does not
    /// strand a modifier down on the guest. Best effort: a failed release is retained in state
    /// so a later attempt can re-release. Default no-op keeps existing sinks source-compatible.
    fn release_held(&self) -> PlatformResult<()> {
        Ok(())
    }

    /// **Optional** — stop typing (Text) that is queued or in progress, without releasing anything
    /// else. `wait == true` blocks until it has stopped (never call that from an async task).
    /// Default no-op: a sink that types synchronously has nothing in flight to stop.
    fn cancel_typing(&self, _wait: bool) {}

    /// **Optional** — admit or refuse this session's input at the FINAL injection boundary. Refusing
    /// (view-only, a lost indicator, the guest ending the session) drops input already queued
    /// upstream as well as new input (key and button RELEASES still pass, so nothing sticks), stops
    /// typing, and releases the session's held keys without retiring the session. Default no-op.
    fn set_admitted(&self, _admitted: bool) {}

    /// **Optional** — release the keys and buttons this session holds WITHOUT retiring it (unlike
    /// [`InputSink::release_held`] on a coordinated sink, after which the session's input is ignored
    /// for good). Default: no-op.
    fn release_keys(&self) -> PlatformResult<()> {
        Ok(())
    }

    /// **Optional** — retry releasing anything TYPING still holds after a refused release, when no
    /// typing is in progress. Called every capture-thread iteration and at shutdown. Default no-op.
    fn retry_typing_releases(&self) {}
}

/// Service/daemon lifecycle hooks. The OS layer wires these into its service control manager
/// (Windows SCM), launchd job, or systemd unit; the core calls them to start and stop cleanly.
pub trait ServiceHost: Send {
    /// Called when the agent should begin doing work (session accepted / service started).
    /// Should return promptly — long-running work belongs on spawned tasks/threads.
    fn run(&mut self) -> PlatformResult<()>;

    /// Called on shutdown (service stop, session end). Must be idempotent and best-effort.
    fn stop(&mut self) -> PlatformResult<()>;
}

impl fmt::Display for MonitorInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "monitor#{} {}x{} @{:.2}x",
            self.id, self.width, self.height, self.dpi_scale
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial in-memory capturer used to prove the trait is object-safe and drivable without
    /// any real display. The real OS implementation lives in the per-platform crate.
    struct FakeCapturer {
        monitors: Vec<MonitorInfo>,
    }

    impl ScreenCapturer for FakeCapturer {
        fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
            Ok(self.monitors.clone())
        }
        fn capture_frame(&mut self, monitor_id: u32) -> PlatformResult<CapturedFrame> {
            let m = self
                .monitors
                .iter()
                .find(|m| m.id == monitor_id)
                .ok_or(PlatformError::UnknownMonitor(monitor_id))?;
            Ok(CapturedFrame {
                monitor_id,
                width: m.width,
                height: m.height,
                bytes: vec![0u8; 4],
                is_keyframe: true,
            })
        }
    }

    #[derive(Default)]
    struct RecordingSink {
        last: std::sync::Mutex<Option<InputEvent>>,
    }
    impl InputSink for RecordingSink {
        fn inject(&self, event: InputEvent) -> PlatformResult<()> {
            *self.last.lock().unwrap() = Some(event);
            Ok(())
        }
    }

    #[test]
    fn capturer_is_object_safe_and_reports_monitors() {
        let mut cap: Box<dyn ScreenCapturer> = Box::new(FakeCapturer {
            monitors: vec![MonitorInfo {
                id: 0,
                width: 1920,
                height: 1080,
                dpi_scale: 1.0,
                left: 0,
                top: 0,
            }],
        });
        assert_eq!(cap.monitors().unwrap().len(), 1);
        let frame = cap.capture_frame(0).unwrap();
        assert_eq!(frame.width, 1920);
        assert!(frame.is_keyframe);
    }

    #[test]
    fn unknown_monitor_is_an_error() {
        let mut cap = FakeCapturer { monitors: vec![] };
        assert!(matches!(
            cap.capture_frame(7),
            Err(PlatformError::UnknownMonitor(7))
        ));
    }

    #[test]
    fn input_sink_is_shareable_and_records_events() {
        let sink = RecordingSink::default();
        sink.inject(InputEvent::MouseMove { x: 32768, y: 100 }).unwrap();
        assert_eq!(
            *sink.last.lock().unwrap(),
            Some(InputEvent::MouseMove { x: 32768, y: 100 })
        );
    }

    #[test]
    fn composite_stitches_left_to_right() {
        // Two 2x1 BGRA frames → a 4x1 composite: A (0x11) on the left, B (0x22) on the right.
        let a = CapturedFrame { monitor_id: 0, width: 2, height: 1, bytes: vec![0x11; 2 * 1 * 4], is_keyframe: true };
        let b = CapturedFrame { monitor_id: 1, width: 2, height: 1, bytes: vec![0x22; 2 * 1 * 4], is_keyframe: false };
        let c = composite_frames(&[a, b]);
        assert_eq!((c.width, c.height, c.monitor_id), (4, 1, COMPOSITE_MONITOR_ID));
        assert_eq!(c.bytes.len(), 4 * 1 * 4);
        assert!(c.bytes[0..8].iter().all(|&x| x == 0x11), "left 2 px come from A");
        assert!(c.bytes[8..16].iter().all(|&x| x == 0x22), "right 2 px come from B");
        assert!(c.is_keyframe, "cadence is taken from the first (primary) monitor");
    }

    fn solid(id: u32, w: u32, h: u32, len: usize, px: u8) -> CapturedFrame {
        CapturedFrame { monitor_id: id, width: w, height: h, bytes: vec![px; len], is_keyframe: true }
    }

    #[test]
    fn composite_padded_pitch_source_is_blacked_out_without_shearing() {
        // A is 2x2 but its buffer is 1 byte-row longer (padded pitch); B is a valid 1x2.
        let a = solid(0, 2, 2, 2 * 2 * 4 + 8, 0x11);
        let b = solid(1, 1, 2, 1 * 2 * 4, 0x22);
        let c = composite_frames(&[a, b]);
        assert_eq!((c.width, c.height), (3, 2));
        assert_eq!(c.bytes.len(), 3 * 2 * 4);
        for y in 0..2 {
            let row = &c.bytes[y * 12..(y + 1) * 12];
            assert!(row[0..8].iter().all(|&x| x == 0), "A's region stays black");
            assert!(row[8..12].iter().all(|&x| x == 0x22), "B keeps its x offset and pixels");
        }
    }

    #[test]
    fn composite_short_source_is_blacked_out_entirely() {
        // A's buffer holds only its first row; all-or-nothing means row 0 is black too.
        let a = solid(0, 2, 2, 2 * 4, 0x11);
        let b = solid(1, 1, 2, 1 * 2 * 4, 0x22);
        let c = composite_frames(&[a, b]);
        assert_eq!((c.width, c.height), (3, 2));
        for y in 0..2 {
            let row = &c.bytes[y * 12..(y + 1) * 12];
            assert!(row[0..8].iter().all(|&x| x == 0));
            assert!(row[8..12].iter().all(|&x| x == 0x22));
        }
    }

    #[test]
    fn composite_width_overflow_returns_empty_without_panic() {
        let a = solid(0, u32::MAX, 1, 0, 0);
        let b = solid(1, 1, 1, 4, 0x22);
        let c = composite_frames(&[a, b]);
        assert_eq!((c.width, c.height, c.monitor_id), (0, 0, COMPOSITE_MONITOR_ID));
        assert!(c.bytes.is_empty());
        assert!(c.is_keyframe);
    }

    #[test]
    fn composite_zero_height_huge_width_does_not_overflow_stride() {
        // total == 0 passes the u64 cap check; on 32-bit targets `width * 4` overflows usize and
        // must yield the empty composite instead of panicking/wrapping. On 64-bit it is a
        // zero-length buffer either way.
        let a = solid(0, u32::MAX, 0, 0, 0);
        let c = composite_frames(&[a]);
        assert!(c.bytes.is_empty());
        assert_eq!(c.monitor_id, COMPOSITE_MONITOR_ID);
        #[cfg(target_pointer_width = "32")]
        assert_eq!((c.width, c.height), (0, 0));
        #[cfg(not(target_pointer_width = "32"))]
        assert_eq!((c.width, c.height), (u32::MAX, 0));
    }

    #[test]
    fn composite_over_cap_returns_empty_without_allocating() {
        // 65536 x 65536 px * 4 = 16 GiB, far over the cap; sources are tiny/invalid.
        let a = solid(0, 65536, 65536, 0, 0);
        let mut b = solid(1, 1, 1, 4, 0x22);
        b.is_keyframe = false;
        let c = composite_frames(&[b, a]);
        assert_eq!((c.width, c.height), (0, 0));
        assert!(c.bytes.is_empty());
        assert!(!c.is_keyframe, "keyframe flag still comes from the first frame");
    }

    #[test]
    fn composite_three_monitors_still_correct() {
        let a = solid(0, 1, 1, 4, 0xA1);
        let b = solid(1, 2, 2, 2 * 2 * 4, 0xB2);
        let c3 = solid(2, 1, 1, 4, 0xC3);
        let c = composite_frames(&[a, b, c3]);
        assert_eq!((c.width, c.height), (4, 2));
        assert_eq!(&c.bytes[0..4], &[0xA1; 4]);
        assert_eq!(&c.bytes[4..12], &[0xB2; 8]);
        assert_eq!(&c.bytes[12..16], &[0xC3; 4]);
        assert_eq!(&c.bytes[16..20], &[0u8; 4], "below A is black");
        assert_eq!(&c.bytes[20..28], &[0xB2; 8]);
        assert_eq!(&c.bytes[28..32], &[0u8; 4], "below C is black");
    }

    #[test]
    fn composite_uses_max_height_and_black_pads_shorter_monitors() {
        // A is 1x2 (taller), B is 1x1 → composite is 2x2; B's second row stays black.
        let a = CapturedFrame { monitor_id: 0, width: 1, height: 2, bytes: vec![0xAA; 1 * 2 * 4], is_keyframe: true };
        let b = CapturedFrame { monitor_id: 1, width: 1, height: 1, bytes: vec![0xBB; 1 * 1 * 4], is_keyframe: true };
        let c = composite_frames(&[a, b]);
        assert_eq!((c.width, c.height), (2, 2));
        assert_eq!(&c.bytes[0..4], &[0xAA; 4], "(0,0) from A");
        assert_eq!(&c.bytes[4..8], &[0xBB; 4], "(1,0) from B");
        assert_eq!(&c.bytes[8..12], &[0xAA; 4], "(0,1) from A");
        assert_eq!(&c.bytes[12..16], &[0u8; 4], "(1,1) is the black gap below the shorter monitor");
    }

    #[test]
    fn capture_composite_default_dispatches_to_all_monitors() {
        // Exercises the DEFAULT trait method (FakeCapturer does not override it) — the path the real
        // DXGI/GDI/WGC capturers use: enumerate → capture each → stitch. Dimensions come from the
        // monitors, so 4x4 + 2x2 composites to 6x4 tagged COMPOSITE_MONITOR_ID.
        let mut cap = FakeCapturer {
            monitors: vec![
                MonitorInfo { id: 0, width: 4, height: 4, dpi_scale: 1.0, left: 0, top: 0 },
                MonitorInfo { id: 1, width: 2, height: 2, dpi_scale: 1.0, left: 0, top: 0 },
            ],
        };
        let comp = cap.capture_composite().unwrap();
        assert_eq!(comp.monitor_id, COMPOSITE_MONITOR_ID);
        assert_eq!((comp.width, comp.height), (6, 4));
    }

    #[test]
    fn capture_composite_default_errors_with_no_monitors() {
        // The default method must not produce a degenerate 0-size frame when there are no monitors.
        let mut cap = FakeCapturer { monitors: vec![] };
        assert!(matches!(cap.capture_composite(), Err(PlatformError::CaptureUnavailable(_))));
    }
}
