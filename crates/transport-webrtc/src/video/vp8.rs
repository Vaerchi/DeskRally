//! Software **VP8** encode via libvpx (`env-libvpx-sys`), tuned for realtime desktop capture.
//!
//! Why VP8: libvpx is BSD-3-Clause **with an explicit patent grant**, and every WebRTC-capable
//! browser is required to decode VP8 (RFC 7742). H.264 needs an MPEG-LA licence for the encoder we
//! previously shipped, which is a hard blocker for open-sourcing this project.
//!
//! Configuration follows what WebRTC implementations do for *screen* content rather than camera
//! video — see [`Vp8Encoder::init`] for the per-setting reasoning:
//! CBR, zero lookahead, `VPX_DL_REALTIME`, a realtime `VP8E_SET_CPUUSED`, `kf_max_dist` short
//! enough that a late joiner is not stuck on black, and crucially `VP8E_SET_SCREEN_CONTENT_MODE`.
//!
//! ## Safety model for the FFI in this file
//!
//! Every `unsafe` block below is justified inline. The invariants they all rest on:
//! * `self.live` is either `None` (no libvpx state exists) or a [`LiveCtx`] whose `ctx` is a
//!   `Box`ed, **zeroed-then-initialised** `vpx_codec_ctx_t` that `vpx_codec_enc_init_ver` returned
//!   `VPX_CODEC_OK` for. It is boxed so its address is stable for libvpx's lifetime even if the
//!   encoder itself is moved.
//! * The context is destroyed exactly once, by [`Drop`], and `live` is cleared before any
//!   re-initialisation, so a resolution change cannot leak or double-free it.
//! * Every libvpx call's `vpx_codec_err_t` is checked; none is discarded.
//! * Pixel buffers handed to libvpx (`self.i420`) outlive the `vpx_codec_encode` call that reads
//!   them, and libvpx copies what it needs before returning (VP8 with `g_lag_in_frames == 0`
//!   produces its packet synchronously).
//!
//! ## The stored `vpx_codec_enc_cfg_t`, and what it bets on (M11)
//!
//! [`LiveCtx`] keeps the config **beside** the context it was accepted with, so live retargeting
//! ([`VideoEncoder::set_bitrate`] → `vpx_codec_enc_config_set`) hands libvpx a struct it has already
//! validated, with exactly one field changed. Binding the two in one struct makes "a cached config
//! with no live context" unrepresentable.
//!
//! It also **widens an existing bet**. `env-libvpx-sys` ships bindings generated from libvpx 1.13.0
//! while this project links 1.16.0 (see [`encoder_abi_version`]); the struct layouts we depend on
//! are field-for-field identical, and `resolves_the_linked_libvpx_encoder_abi` is the tripwire that
//! detects a future drift. Until M11 a mis-shaped `vpx_codec_enc_cfg` could only make *init* fail
//! cleanly. Now it could also reconfigure a **live** context. Same bet, larger blast radius — which
//! is why both facts are stated here together.

use std::ffi::CStr;
use std::os::raw::c_int;
use std::sync::atomic::{AtomicI32, Ordering};

use vpx_sys as vpx;

use super::color::{bgra_to_i420_into_mode, I420Layout};
use super::{ChromaMode, EncodedAu, VideoEncoder, MAX_BITRATE_BPS, MIN_BITRATE_BPS, VIDEO_CLOCK_RATE};

/// Longest gap between keyframes, in **90 kHz ticks** (60 s): a last-resort BACKSTOP, not a cadence.
///
/// **Why not 4 s any more (2026-10-14).** Every keyframe on this constant-bitrate stream is coded
/// coarse: measured on a static 1280x720 desktop at 3 Mbps, picture quality sits at ~50 dB PSNR and
/// a keyframe drops it to 31-33 dB for one frame before the next delta restores it (see
/// `idle_quality`). A 4 s backstop therefore put a visible blur flash on an IDLE screen every four
/// seconds, which the operator reported as "a pulse". Lowering the quantizer cap does not fix the
/// keyframe itself (33 -> 38 dB even at qmax 32), so the cadence is what had to go.
///
/// What the backstop is still for is narrow: recovery is driven by the receiver. A PLI/FIR reaches
/// [`VideoEncoder::request_keyframe`] through the RTCP loop, browsers keep re-requesting a keyframe
/// while they cannot decode, and every peer connection builds its own encoder, so a joining viewer
/// starts with one. The backstop only bounds the case where a keyframe AND every request for its
/// replacement are lost, so it can be long.
///
/// **Why ticks and not frames.** `cfg.kf_max_dist` counts FRAMES, and since M11 the operator
/// chooses the frame rate. A frame-counted 120 is 4 s at 30 fps but **24 s at 5 fps** — so the
/// low-bandwidth preset would itself introduce a 24-second black screen for any receiver that lost
/// a keyframe *and* whose PLI was also lost. Time is the invariant the guarantee is stated in, so
/// time is what must be counted. `cfg.kf_max_dist` is still set (at `MAX_FPS * KF_BACKSTOP_SECS`)
/// as a pure libvpx-side backstop, but this is the mechanism.
const KF_MAX_TICKS: u32 = KF_BACKSTOP_SECS * VIDEO_CLOCK_RATE;

/// The quantizer floor while the picture is changing: libvpx may spend bits down to q=2.
const MIN_QUANTIZER: u32 = 2;
/// The quantizer floor once the input has been IDENTICAL for [`IDLE_SETTLE_TICKS`].
///
/// An unchanged screen is still encoded at the keep-alive cadence (15 fps by default; it is what
/// keeps the receiver's jitter buffer from flickering). With the floor at q=2, CBR rate control
/// keeps re-coding the same residual quantization noise forever: measured on a 1280x720 static
/// desktop, a settled 49.5 dB picture cost ~4.4 KB per frame (~530 kbps) with no gain in quality.
/// At q>=10 that residual quantizes to zero, the blocks are skipped (copied from the sharp
/// reference), and the same picture costs ~0.5 KB per frame (~64 kbps). Measured over floors 6..56:
/// 10 is the highest floor whose FIRST frame after a content change is exactly as sharp as with no
/// floor (48.5 dB); from 12 up the rate controller carries the raised quantizer into that frame.
const IDLE_MIN_QUANTIZER: u32 = 10;
/// How long the input must be unchanged before [`IDLE_MIN_QUANTIZER`] applies. Natural refinement
/// of a static picture reaches its ~49.5 dB plateau in ~1.5 s, so the floor never caps a picture
/// that is still sharpening.
const IDLE_SETTLE_TICKS: u32 = 2 * VIDEO_CLOCK_RATE;

/// The keyframe backstop, in seconds (see [`KF_MAX_TICKS`]).
const KF_BACKSTOP_SECS: u32 = 60;

/// libvpx-side keyframe cap, in frames. Sized for the fastest frame rate the operator can select
/// (60 fps × the backstop) so it never fires before [`KF_MAX_TICKS`] does. It must move WITH the
/// backstop: left at its old 60 × 4 = 240 frames, libvpx itself would force a keyframe every 8 s at
/// the 30 fps keep-alive cadence and the pulse would simply come back at a different period.
const KF_MAX_DIST: u32 = 60 * KF_BACKSTOP_SECS;

/// `VP8E_SET_CPUUSED`. VP8's valid range is -16..16, and libvpx's default (0) is far too slow for
/// realtime. This is the value WebRTC's own libvpx VP8 wrapper uses as its desktop realtime default
/// (`cpu_speed_default_ = -6` in `libvpx_vp8_encoder.cc`).
///
/// NOTE the sign. `vp8cx.h` says "values greater than 0 will increase encoder speed", which is the
/// VP9 convention; for VP8, negative values select libvpx's realtime speed-feature path and are the
/// fast ones. Measured on this box (1920×1080, single thread, libvpx 1.16.0, release build,
/// microseconds per encode):
///
/// ```text
/// cpu_used   -16    -12     -6     -4      0     +4     +6    +12    +16
/// us/frame  10134   9808   9758  14901  18972  18860  20048  10058  11112
/// ```
///
/// So -6 is ~2× faster than the default, leaves a 1080p frame at ~10 ms (comfortably inside a
/// 33 ms budget on a machine with no hardware encoder — the class this agent targets), and is less
/// aggressive quality-wise than -12/-16.
const CPU_USED: c_int = -6;

/// `VP8E_SET_SCREEN_CONTENT_MODE`: 0 = off, 1 = on, 2 = on with more aggressive rate control.
/// 1 is the plain screen-content mode; it is the single largest quality/bitrate win for desktop
/// content (sharp text, large flat regions, abrupt full-frame changes) and is VP8-specific.
const SCREEN_CONTENT_MODE: c_int = 1;

/// `VP8E_SET_STATIC_THRESHOLD`: 0 means "never skip a macroblock just because it looks static".
/// Screen content is mostly static; skipping blocks aggressively is what makes remote-desktop
/// video look smeared after a scroll.
const STATIC_THRESHOLD: c_int = 0;

/// `VP8E_SET_NOISE_SENSITIVITY` (the temporal denoiser). Off: a screen has no sensor noise, and the
/// denoiser only costs CPU and blurs text.
const NOISE_SENSITIVITY: c_int = 0;

/// A live libvpx encoder: the context **and** the config it was initialised with, bound together.
///
/// They are one struct rather than two fields because [`VideoEncoder::set_bitrate`] must hand
/// `vpx_codec_enc_config_set` the *same* config libvpx already accepted, with one field changed.
/// Keeping them separate would make "a cached config with no live context" — or worse, a config
/// belonging to a previous context — representable states.
struct LiveCtx {
    /// Boxed so libvpx sees a stable address even if the encoder is moved.
    ctx: Box<vpx::vpx_codec_ctx_t>,
    /// The config this context was initialised with, kept in step with every successful
    /// `vpx_codec_enc_config_set`. `vpx_codec_enc_cfg` derives `Copy`, so storing it by value is
    /// legal and costs one memcpy at init.
    cfg: vpx::vpx_codec_enc_cfg_t,
}

/// A stateful VP8 encoder. Holds raw libvpx state, so it is **not** `Send`/`Sync` and must be owned
/// by exactly one thread — the transport keeps it on a dedicated OS thread.
pub struct Vp8Encoder {
    /// `None` until the first frame establishes the frame size, and cleared+rebuilt on a size
    /// change.
    live: Option<LiveCtx>,
    /// Dimensions the live context was initialised for (always even).
    dims: (usize, usize),
    /// Target bitrate as the caller gave it (bits/sec). libvpx wants **kilobits**/sec; the
    /// conversion happens in [`Vp8Encoder::init`] and [`VideoEncoder::set_bitrate`]. Getting this
    /// wrong is a silent 1000× error.
    bitrate_bps: u32,
    /// Colour handling for subsequent frames (M11).
    chroma: ChromaMode,
    /// Set by [`VideoEncoder::request_keyframe`]; consumed by the next successful encode.
    force_keyframe: bool,
    /// Presentation timestamp in 90 kHz ticks.
    pts: i64,
    /// 90 kHz ticks since the last emitted keyframe — drives the time-based [`KF_MAX_TICKS`]
    /// backstop, which is what keeps its time bound true at any operator-chosen frame rate.
    ticks_since_kf: u32,
    /// Reused I420 scratch so steady-state encoding does not allocate.
    i420: Vec<u8>,
    /// The I420 of the last frame whose content differed from its predecessor. Swapped with
    /// `i420` (never copied) when the content changes.
    prev_i420: Vec<u8>,
    /// 90 kHz ticks of consecutive identical input; drives [`IDLE_MIN_QUANTIZER`].
    unchanged_ticks: u32,
    /// Whether the live config currently carries [`IDLE_MIN_QUANTIZER`].
    idle_floor: bool,
    /// Layout of `i420` for the current dimensions.
    layout: I420Layout,
}

// A `vpx_codec_ctx_t` is raw C state with no interior thread affinity, but libvpx is not
// thread-safe per context, so we deliberately do NOT implement Send/Sync (the raw pointers in the
// struct already make it !Send; this comment records that it is intentional, not accidental).

impl Vp8Encoder {
    /// Build an encoder tuned for desktop capture at the given target bitrate (**bits/sec**, to
    /// match the previous H.264 encoder's constructor). libvpx is not touched until the first
    /// frame, because the frame size is not known yet.
    pub fn new(bitrate_bps: u32) -> Result<Self, String> {
        if bitrate_bps == 0 {
            return Err("bitrate_bps must be > 0".to_string());
        }
        Ok(Self {
            live: None,
            dims: (0, 0),
            bitrate_bps,
            chroma: ChromaMode::Full,
            force_keyframe: false,
            pts: 0,
            ticks_since_kf: 0,
            i420: Vec::new(),
            prev_i420: Vec::new(),
            unchanged_ticks: 0,
            idle_floor: false,
            layout: I420Layout::new(0, 0),
        })
    }

    /// Tear down any live context and create one for `w`×`h` (both even, both > 0).
    ///
    /// libvpx cannot be resized in place for VP8 in a way that is safe across arbitrary capture
    /// changes (a monitor switch, a resolution change, an RDP reconnect), and feeding a context
    /// frames of a different size than it was configured for produces `VPX_CODEC_INVALID_PARAM` at
    /// best and garbage at worst — so a size change is a full re-init.
    fn init(&mut self, w: usize, h: usize) -> Result<(), String> {
        self.destroy();

        // SAFETY: `vpx_codec_vp8_cx()` returns libvpx's statically allocated VP8 encoder interface;
        // it never fails and the pointer is valid for the process lifetime.
        let iface = unsafe { vpx::vpx_codec_vp8_cx() };
        if iface.is_null() {
            return Err("vpx_codec_vp8_cx() returned NULL (libvpx built without VP8 encode?)".into());
        }

        // `vpx_codec_enc_cfg` embeds C enums that bindgen turned into Rust enums, and zero is NOT a
        // valid discriminant for all of them (`vpx_bit_depth_t::VPX_BITS_8 == 8`), so
        // `mem::zeroed()` here is genuine UB — rustc's debug assertion catches it and aborts.
        // `MaybeUninit` is the correct tool: libvpx memcpy's a complete default config over the
        // whole struct, so it is fully initialised the moment the call returns OK.
        //
        // SAFETY: `as_mut_ptr()` is a valid, exclusively-owned, correctly-sized+aligned pointer.
        // We only `assume_init()` after `vpx_codec_enc_config_default` returned `VPX_CODEC_OK`,
        // which is exactly the contract under which it guarantees every field is written.
        let mut cfg_uninit = std::mem::MaybeUninit::<vpx::vpx_codec_enc_cfg_t>::uninit();
        let res = unsafe { vpx::vpx_codec_enc_config_default(iface, cfg_uninit.as_mut_ptr(), 0) };
        check(res, "vpx_codec_enc_config_default")?;
        let mut cfg = unsafe { cfg_uninit.assume_init() };

        cfg.g_w = w as u32;
        cfg.g_h = h as u32;
        // Timebase = 1/90000 — the RTP video clock, which is also what libwebrtc's own libvpx VP8
        // wrapper uses. Presentation timestamps and per-frame durations are therefore expressed in
        // the SAME unit the RTP timestamp advances in, so one measured number can drive both.
        //
        // A 1/TARGET_FPS timebase (what this was before M11) can only express "n frames", which is
        // a lie the moment the operator picks a different frame rate: libvpx derives its
        // rate-control frame rate from the interval between successive timestamps, so a 5 fps
        // capture reported as one 1/30 s frame makes it budget six times too few bits.
        //
        // At init libvpx clamps an implied 90000 fps to 30 (onyx_if.c's `if (framerate > 180)`),
        // then the real per-frame durations take over via its smoothing; `vp8_change_config`
        // preserves that learned rate, so live retargeting does not reset it.
        cfg.g_timebase.num = 1;
        cfg.g_timebase.den = VIDEO_CLOCK_RATE as c_int;
        // Realtime: never buffer frames looking ahead. Any lag is added end-to-end latency.
        cfg.g_lag_in_frames = 0;
        cfg.g_pass = vpx::vpx_enc_pass::VPX_RC_ONE_PASS;
        // Error resilience on: RTP loses packets, and without this a single lost packet corrupts
        // every subsequent inter frame until the next keyframe.
        cfg.g_error_resilient = 1;
        cfg.g_threads = encoder_threads(w, h);

        // Constant bitrate: a screen share runs over a fixed-ish link and we want a predictable
        // rate, not VBR spikes that blow up the jitter buffer.
        cfg.rc_end_usage = vpx::vpx_rc_mode::VPX_CBR;
        // *** libvpx takes KILObits/sec; the public API here is bits/sec. ***
        cfg.rc_target_bitrate = (self.bitrate_bps / 1000).max(1);
        cfg.rc_min_quantizer = MIN_QUANTIZER;
        cfg.rc_max_quantizer = 56;
        cfg.rc_undershoot_pct = 50;
        cfg.rc_overshoot_pct = 50;
        // Buffer model in milliseconds — a small buffer keeps latency down.
        cfg.rc_buf_sz = 1000;
        cfg.rc_buf_initial_sz = 500;
        cfg.rc_buf_optimal_sz = 600;
        // Never drop frames: a dropped frame on a screen share means a stale, wrong picture.
        cfg.rc_dropframe_thresh = 0;
        cfg.rc_resize_allowed = 0;

        cfg.kf_mode = vpx::vpx_kf_mode::VPX_KF_AUTO;
        cfg.kf_min_dist = 0;
        cfg.kf_max_dist = KF_MAX_DIST;

        // SAFETY: `ctx` is a zeroed `vpx_codec_ctx_t` (all-NULL/0 is the documented "uninitialised"
        // state libvpx expects, and is what it checks before writing `err`/`priv`). `iface` is
        // valid, `cfg` outlives the call (libvpx copies it), and we check the result before
        // treating the context as live. On failure the box is dropped without `vpx_codec_destroy`,
        // which is correct: libvpx allocated nothing.
        let mut ctx: Box<vpx::vpx_codec_ctx_t> = Box::new(unsafe { std::mem::zeroed() });
        let abi = encoder_abi_version(iface, &cfg, &mut ctx)?;
        let res = unsafe {
            vpx::vpx_codec_enc_init_ver(ctx.as_mut() as *mut _, iface, &cfg, 0, abi)
        };
        if res != vpx::VPX_CODEC_OK {
            return Err(ctx_error(&mut ctx, res, "vpx_codec_enc_init_ver"));
        }

        // Realtime/screen-content tuning. These are all `int`-valued controls.
        for (id, val) in [
            (vpx::vp8e_enc_control_id::VP8E_SET_CPUUSED, CPU_USED),
            (
                vpx::vp8e_enc_control_id::VP8E_SET_SCREEN_CONTENT_MODE,
                SCREEN_CONTENT_MODE,
            ),
            (
                vpx::vp8e_enc_control_id::VP8E_SET_STATIC_THRESHOLD,
                STATIC_THRESHOLD,
            ),
            (
                vpx::vp8e_enc_control_id::VP8E_SET_NOISE_SENSITIVITY,
                NOISE_SENSITIVITY,
            ),
        ] {
            // SAFETY: `ctx` is a live, successfully-initialised encoder context. Every control in
            // this list is documented in vp8cx.h as taking exactly one `int`
            // (`VPX_CTRL_USE_TYPE(..., int)` / `unsigned int`, same 32-bit varargs slot), which is
            // what we pass through the variadic. The return code is checked.
            let res = unsafe { vpx::vpx_codec_control_(ctx.as_mut() as *mut _, id as c_int, val) };
            if res != vpx::VPX_CODEC_OK {
                let detail = ctx_error(&mut ctx, res, "vpx_codec_control_");
                // SAFETY: `ctx` is live; destroying it here is the only way to avoid leaking it,
                // and nothing else will touch it because we return `Err` and never store it.
                unsafe {
                    vpx::vpx_codec_destroy(ctx.as_mut() as *mut _);
                }
                return Err(format!("{detail} (control {id:?})"));
            }
        }

        // The config is stored BESIDE the context it was accepted with — that pairing is what
        // makes a later `vpx_codec_enc_config_set` safe (see the module docs).
        self.live = Some(LiveCtx { ctx, cfg });
        self.dims = (w, h);
        self.layout = I420Layout::new(w, h);
        self.i420.clear();
        // A fresh context starts at MIN_QUANTIZER with no history of identical input.
        self.prev_i420.clear();
        self.unchanged_ticks = 0;
        self.idle_floor = false;
        // A fresh context always emits a keyframe first, so an outstanding request is satisfied.
        self.force_keyframe = false;
        self.pts = 0;
        self.ticks_since_kf = 0;
        tracing::debug!(
            width = w,
            height = h,
            kbps = cfg.rc_target_bitrate,
            threads = cfg.g_threads,
            "VP8 encoder initialised"
        );
        Ok(())
    }

    /// Destroy the live context, if any. Idempotent.
    fn destroy(&mut self) {
        if let Some(mut live) = self.live.take() {
            // SAFETY: `live.ctx` came out of `self.live`, which only ever holds a context that
            // `vpx_codec_enc_init_ver` returned OK for. `take()` guarantees this runs at most once
            // per context, so there is no double free.
            unsafe {
                vpx::vpx_codec_destroy(live.ctx.as_mut() as *mut _);
            }
        }
    }
}

impl Vp8Encoder {
    /// Retarget the live context's quantizer floor (same `enc_config_set` discipline as
    /// [`VideoEncoder::set_bitrate`]: one field changed on the config libvpx already accepted, no
    /// keyframe). Best-effort: on failure the cached config is rolled back, `idle_floor` keeps its
    /// old value, and the frame is still encoded.
    fn set_min_quantizer(&mut self, q: u32) {
        let Some(live) = self.live.as_mut() else { return };
        let prev = live.cfg.rc_min_quantizer;
        live.cfg.rc_min_quantizer = q;
        // SAFETY: as in `set_bitrate`: a live context and the config it accepted, one field changed.
        let res = unsafe { vpx::vpx_codec_enc_config_set(live.ctx.as_mut() as *mut _, &live.cfg) };
        if res != vpx::VPX_CODEC_OK {
            live.cfg.rc_min_quantizer = prev;
            let detail = ctx_error(&mut live.ctx, res, "vpx_codec_enc_config_set (min quantizer)");
            tracing::debug!(error = %detail, q, "vp8: idle quantizer floor not applied");
            return;
        }
        self.idle_floor = q == IDLE_MIN_QUANTIZER;
    }
}

impl Drop for Vp8Encoder {
    fn drop(&mut self) {
        self.destroy();
    }
}

impl VideoEncoder for Vp8Encoder {
    fn encode_bgra(
        &mut self,
        bgra: &[u8],
        w: usize,
        h: usize,
        duration_90khz: u32,
    ) -> Result<EncodedAu, String> {
        // VP8 supports odd dimensions, but the rest of the pipeline (and `vpx_img_wrap`'s tight
        // packing assumptions) is simplest with even ones, and the capturers already produce even
        // sizes. Crop by at most one pixel, as the H.264 encoder did before it.
        let ew = w & !1;
        let eh = h & !1;
        if ew == 0 || eh == 0 {
            return Err(format!("frame too small: {w}x{h}"));
        }

        // Validate the buffer BEFORE touching libvpx. init() tears down and rebuilds the codec,
        // which resets pts and drops every reference frame — so re-initialising and only then
        // discovering the frame is short would emit a keyframe per recovered frame during, say, a
        // monitor-hotplug race where the dimensions update before the buffer does.
        let needed = ew.saturating_mul(eh).saturating_mul(4);
        if bgra.len() < needed || (h > 1 && bgra.len() < (h - 1) * w * 4 + ew * 4) {
            return Err(format!(
                "frame buffer is {} bytes, too short for {w}x{h} BGRA",
                bgra.len()
            ));
        }

        if self.live.is_none() || self.dims != (ew, eh) {
            self.init(ew, eh)?;
        }

        // Time-based keyframe backstop (M11). Accumulate BEFORE choosing flags so a frame that
        // crosses the backstop boundary is itself the keyframe rather than the one after it.
        // `cfg.kf_max_dist` counts frames and so cannot express a time guarantee once the
        // frame rate is the operator's to choose — see KF_MAX_TICKS.
        self.ticks_since_kf = self.ticks_since_kf.saturating_add(duration_90khz);
        if self.ticks_since_kf >= KF_MAX_TICKS {
            self.force_keyframe = true;
        }

        // Convert straight out of the source buffer — cropping is expressed as "read `ew` pixels
        // from each of the first `eh` rows at the source pitch", so no repacking copy is needed.
        let layout = bgra_to_i420_into_mode(bgra, ew, eh, w * 4, self.chroma, &mut self.i420)?;
        debug_assert_eq!(layout, self.layout);

        // IDLE QUANTIZER FLOOR (see IDLE_MIN_QUANTIZER). A forced keyframe counts as a change: a
        // receiver recovering from loss gets the full refinement again before the floor re-arms.
        let unchanged = !self.force_keyframe && self.prev_i420 == self.i420;
        self.unchanged_ticks = if unchanged { self.unchanged_ticks.saturating_add(duration_90khz) } else { 0 };
        let want_floor = self.unchanged_ticks >= IDLE_SETTLE_TICKS;
        if want_floor != self.idle_floor {
            self.set_min_quantizer(if want_floor { IDLE_MIN_QUANTIZER } else { MIN_QUANTIZER });
        }

        // SAFETY: `img` is a zeroed `vpx_image_t`; `vpx_img_wrap` fully populates it. We pass our
        // own buffer, so libvpx takes no ownership (`img_data_owner`/`self_allocd` stay 0 and
        // `vpx_img_free` would be a no-op — hence we do not call it). `self.i420` is exactly
        // `I420Layout::len` bytes, which for even w/h with `stride_align = 1` is precisely the
        // Y+U+V extent `vpx_img_wrap` computes, so libvpx never reads out of bounds. The buffer
        // outlives the encode call below.
        let mut img: vpx::vpx_image_t = unsafe { std::mem::zeroed() };
        let wrapped = unsafe {
            vpx::vpx_img_wrap(
                &mut img,
                vpx::vpx_img_fmt::VPX_IMG_FMT_I420,
                ew as u32,
                eh as u32,
                1,
                self.i420.as_mut_ptr(),
            )
        };
        if wrapped.is_null() {
            return Err("vpx_img_wrap failed".to_string());
        }
        // Declare what `color.rs` actually produced. VP8's bitstream only carries a 1-bit colour
        // space field (always 0 = BT.601) so this is mostly informational, but it keeps the image
        // description honest for anything that inspects it.
        img.cs = vpx::vpx_color_space::VPX_CS_BT_601;
        img.range = vpx::vpx_color_range::VPX_CR_STUDIO_RANGE;

        let flags: vpx::vpx_enc_frame_flags_t = if self.force_keyframe {
            vpx::VPX_EFLAG_FORCE_KF as vpx::vpx_enc_frame_flags_t
        } else {
            0
        };

        let live = self
            .live
            .as_mut()
            .ok_or_else(|| "VP8 context missing after init".to_string())?;

        // SAFETY: live context, valid image describing a buffer we own, and `VPX_DL_REALTIME` as
        // the deadline (never spend more time than a realtime frame allows). `duration` is this
        // frame's measured length in our 1/90000 timebase — libvpx converts pts/duration to its own
        // 10 MHz ticks and derives the rate-control frame rate from the interval, so passing a
        // constant here is what makes a 5 fps capture spend a 30 fps per-frame budget.
        //
        // The cast is to `c_ulong`, NOT `u64`: `c_ulong` is 32-bit on Windows MSVC, the only
        // platform this crate's agent ships on, and `u64` does not compile there.
        let res = unsafe {
            vpx::vpx_codec_encode(
                live.ctx.as_mut() as *mut _,
                &img,
                self.pts,
                duration_90khz as std::os::raw::c_ulong,
                flags,
                vpx::VPX_DL_REALTIME as std::os::raw::c_ulong,
            )
        };
        if res != vpx::VPX_CODEC_OK {
            return Err(ctx_error(&mut live.ctx, res, "vpx_codec_encode"));
        }
        // The PTS step is the LOAD-BEARING half of telling libvpx the frame rate, and it is worth
        // saying so because it is not obvious: libvpx derives its rate-control frame rate from the
        // gap between successive presentation timestamps, not from the `duration` argument above.
        //
        // Measured, by mutation: replacing the `duration` argument with a constant leaves
        // `duration_drives_libvpxs_framerate` GREEN, while replacing this `+=` with a constant
        // turns it red. Both are passed, and both should be — `duration` feeds libvpx's buffer
        // model — but anyone "simplifying" this line is removing the mechanism.
        self.pts += duration_90khz as i64;
        self.force_keyframe = false;

        // Drain the compressed-data packets for this frame.
        let mut data = Vec::new();
        let mut keyframe = false;
        let mut iter: vpx::vpx_codec_iter_t = std::ptr::null();
        loop {
            // SAFETY: live context; `iter` starts NULL and is only ever passed back to
            // `vpx_codec_get_cx_data`, which is exactly the documented iteration protocol. The
            // returned pointer (when non-NULL) is owned by libvpx and stays valid until the next
            // call into the codec, which is why we copy the bytes out immediately.
            let pkt = unsafe { vpx::vpx_codec_get_cx_data(live.ctx.as_mut() as *mut _, &mut iter) };
            if pkt.is_null() {
                break;
            }
            let pkt = unsafe { &*pkt };
            if pkt.kind != vpx::vpx_codec_cx_pkt_kind::VPX_CODEC_CX_FRAME_PKT {
                continue; // stats/psnr packets: not requested, but skip defensively.
            }
            // SAFETY: `kind == VPX_CODEC_CX_FRAME_PKT` selects the `frame` arm of the union, and
            // libvpx guarantees `buf`/`sz` describe `sz` readable bytes of compressed data.
            let frame = unsafe { &pkt.data.frame };
            if frame.buf.is_null() || frame.sz == 0 {
                continue;
            }
            let bytes = unsafe { std::slice::from_raw_parts(frame.buf as *const u8, frame.sz) };
            data.extend_from_slice(bytes);
            keyframe |= (frame.flags & vpx::VPX_FRAME_IS_KEY) != 0;
        }

        if data.is_empty() {
            return Err("VP8 produced no frame packet".to_string());
        }
        if keyframe {
            self.ticks_since_kf = 0;
        }
        if !unchanged {
            // The just-encoded content becomes the reference for the next comparison. A swap, so
            // a changing screen costs no copy; `i420` is fully rewritten by the next conversion.
            std::mem::swap(&mut self.i420, &mut self.prev_i420);
        }
        Ok(EncodedAu {
            data,
            keyframe,
            // Echoed, never recomputed: this is the same number libvpx just budgeted against, and
            // the transport turns it into the RTP timestamp step. See `EncodedAu::duration_90khz`.
            duration_90khz,
            width: ew as u32,
            height: eh as u32,
        })
    }

    /// Force the next encoded frame to be a keyframe (`VPX_EFLAG_FORCE_KF`).
    ///
    /// This is what an RTCP **PLI/FIR** from the far end should trigger: the receiver is telling us
    /// it cannot decode until it gets an intra frame.
    fn request_keyframe(&mut self) {
        self.force_keyframe = true;
    }

    /// Retarget the **live** context with `vpx_codec_enc_config_set` — never a re-init.
    ///
    /// `init()` would `destroy()` and rebuild: it resets `pts`, drops every reference frame, and
    /// forces an intra on the next encode. At the rate controller's ~1 Hz cadence that is a
    /// keyframe every second — a 60–150 KB burst at 1080p, delivered precisely when the controller
    /// has concluded there is no bandwidth. Re-init stays reserved for the one case libvpx
    /// genuinely requires it: a **dimension** change, which `encode_bgra` already handles (VP8
    /// signals frame dimensions only in a keyframe header, so a resolution change is a keyframe by
    /// bitstream law regardless).
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), String> {
        let bps = bitrate_bps.clamp(MIN_BITRATE_BPS, MAX_BITRATE_BPS);
        if bps == self.bitrate_bps {
            return Ok(()); // no FFI call for a no-op
        }
        // Recorded FIRST, so a later `init()` — a scale change, a monitor switch — comes up at the
        // CURRENT rate rather than the constructor's. Forgetting this is the classic version of
        // this bug: the encoder adapts down, the user switches monitor, and the rate silently
        // jumps back to 3 Mbps on a link that cannot carry it.
        self.bitrate_bps = bps;
        let Some(live) = self.live.as_mut() else {
            return Ok(()); // no context yet; init() will pick the new rate up
        };
        let prev = live.cfg.rc_target_bitrate;
        // *** libvpx takes KILObits/sec; this API is bits/sec. ***
        live.cfg.rc_target_bitrate = (bps / 1000).max(1);
        // SAFETY: `live.ctx` is a live, successfully-initialised context, and `live.cfg` is exactly
        // the config libvpx accepted at init with a single field changed — so it re-validates a
        // struct it has already approved. `g_w`/`g_h` are unchanged, which is the condition under
        // which `vp8_change_config` does NOT set `force_next_frame_intra`: no keyframe, no
        // reference-frame loss. Return code checked.
        let res = unsafe { vpx::vpx_codec_enc_config_set(live.ctx.as_mut() as *mut _, &live.cfg) };
        if res != vpx::VPX_CODEC_OK {
            // Roll BOTH back, so the cached config stays truthful about libvpx's actual state. A
            // cached config that disagrees with the context is the input to the next
            // `enc_config_set`, and it would carry the rejected value forward forever.
            live.cfg.rc_target_bitrate = prev;
            let detail = ctx_error(&mut live.ctx, res, "vpx_codec_enc_config_set");
            self.bitrate_bps = prev.saturating_mul(1000);
            return Err(detail);
        }
        Ok(())
    }

    fn set_chroma_mode(&mut self, mode: ChromaMode) -> Result<(), String> {
        // Pure state: the next `encode_bgra` passes it to the converter. No libvpx call, no
        // keyframe — VP8's bitstream does not care that the chroma planes became constant.
        self.chroma = mode;
        Ok(())
    }

    fn webrtc_mime_type(&self) -> &'static str {
        webrtc::api::media_engine::MIME_TYPE_VP8
    }

    fn codec_name(&self) -> &'static str {
        "VP8 (libvpx)"
    }
}

/// One encode thread per ~1 MPixel, clamped to 1..=4. VP8 splits a frame into at most 8 token
/// partitions but its threading gain flattens quickly; more threads on a small frame just adds
/// synchronisation latency, which is the thing we are optimising against.
fn encoder_threads(w: usize, h: usize) -> u32 {
    let mpixels = (w * h) / 1_000_000;
    let by_size = (mpixels as u32).clamp(1, 4);
    let by_cpu = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    by_size.min(by_cpu.max(1))
}

/// Resolve the `VPX_ENCODER_ABI_VERSION` the *linked* libvpx will accept.
///
/// `env-libvpx-sys` ships pre-generated bindings only for libvpx ≤ 1.13.0, and the constant baked
/// into those bindings (30) is not what a newer libvpx compares against — 1.16.0 wants 39, and
/// `vpx_codec_enc_init_ver` answers a stale value with `VPX_CODEC_ABI_MISMATCH` rather than
/// anything subtle. The struct layouts we depend on (`vpx_codec_enc_cfg`, `vpx_image`,
/// `vpx_codec_ctx`, `vpx_codec_cx_pkt`) are field-for-field identical between the 1.13 bindings and
/// the 1.16.0 headers, so the only thing that has to be discovered is this integer.
///
/// We discover it by asking: try the bindings' constant first, then probe a bounded range. Exactly
/// one value can be accepted (libvpx tests `ver != VPX_ENCODER_ABI_VERSION`), so this cannot
/// silently pick a "close enough" answer. The result is cached for the process.
///
/// If the probe fails entirely, the caller gets a plain `VPX_CODEC_ABI_MISMATCH` error — which is
/// the honest outcome: the linked libvpx is too far from the bindings to be used safely.
fn encoder_abi_version(
    iface: *const vpx::vpx_codec_iface,
    cfg: &vpx::vpx_codec_enc_cfg_t,
    scratch: &mut Box<vpx::vpx_codec_ctx_t>,
) -> Result<c_int, String> {
    static CACHED: AtomicI32 = AtomicI32::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return Ok(cached);
    }

    let from_bindings = vpx::VPX_ENCODER_ABI_VERSION as c_int;
    let candidates = std::iter::once(from_bindings).chain((1..=80).filter(|v| *v != from_bindings));
    for ver in candidates {
        // SAFETY: a freshly zeroed context each attempt (libvpx inspects `priv`, which must be
        // NULL going in). On `VPX_CODEC_ABI_MISMATCH` libvpx allocates nothing, so there is nothing
        // to destroy; on success we destroy immediately — the caller re-initialises its own context
        // with the version we return.
        **scratch = unsafe { std::mem::zeroed() };
        let res =
            unsafe { vpx::vpx_codec_enc_init_ver(scratch.as_mut() as *mut _, iface, cfg, 0, ver) };
        if res == vpx::VPX_CODEC_OK {
            // SAFETY: the probe context is live and owned solely by us.
            unsafe {
                vpx::vpx_codec_destroy(scratch.as_mut() as *mut _);
            }
            **scratch = unsafe { std::mem::zeroed() };
            if ver != from_bindings {
                tracing::info!(
                    bindings_abi = from_bindings,
                    libvpx_abi = ver,
                    "linked libvpx is newer than the bundled bindings; using its encoder ABI version"
                );
            }
            CACHED.store(ver, Ordering::Relaxed);
            return Ok(ver);
        }
        if res != vpx::VPX_CODEC_ABI_MISMATCH {
            // A non-ABI failure means this version WAS accepted and something else went wrong;
            // report it rather than blindly walking the rest of the range.
            **scratch = unsafe { std::mem::zeroed() };
            return Err(format!(
                "vpx_codec_enc_init_ver: {} (encoder ABI {ver})",
                err_str(res)
            ));
        }
    }
    Err(format!(
        "no VPX_ENCODER_ABI_VERSION in 1..=80 was accepted by the linked libvpx \
         (bindings say {from_bindings}); the installed libvpx is incompatible with env-libvpx-sys"
    ))
}

/// libvpx's own string for an error code.
fn err_str(res: vpx::vpx_codec_err_t) -> String {
    // SAFETY: `vpx_codec_err_to_string` returns a pointer to a static, NUL-terminated string for
    // every input (it has a `default:` arm), and never NULL.
    let p = unsafe { vpx::vpx_codec_err_to_string(res) };
    if p.is_null() {
        return format!("{res:?}");
    }
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}

fn check(res: vpx::vpx_codec_err_t, what: &str) -> Result<(), String> {
    if res == vpx::VPX_CODEC_OK {
        Ok(())
    } else {
        Err(format!("{what}: {}", err_str(res)))
    }
}

/// Format an error, pulling libvpx's per-context detail string when it has one.
fn ctx_error(ctx: &mut Box<vpx::vpx_codec_ctx_t>, res: vpx::vpx_codec_err_t, what: &str) -> String {
    // SAFETY: `ctx` points at a valid (possibly failed) context; `vpx_codec_error_detail` reads
    // `ctx->priv` and returns NULL when there is no detail, which we handle.
    let detail = unsafe {
        let p = vpx::vpx_codec_error_detail(ctx.as_mut() as *mut _);
        if p.is_null() {
            None
        } else {
            Some(CStr::from_ptr(p).to_string_lossy().into_owned())
        }
    };
    match detail {
        Some(d) => format!("{what}: {} ({d})", err_str(res)),
        None => format!("{what}: {}", err_str(res)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One 30 fps frame in 90 kHz ticks — the duration these tests pass when the frame rate is not
    /// the thing under test.
    const NOM: u32 = VIDEO_CLOCK_RATE / 30;

    /// A varied BGRA frame so the encoder has real content to compress.
    fn bgra(w: usize, h: usize, tick: u8) -> Vec<u8> {
        let mut v = vec![0u8; w * h * 4];
        for (i, px) in v.chunks_mut(4).enumerate() {
            px[0] = (i as u8).wrapping_mul(3).wrapping_add(tick); // B
            px[1] = (i as u8).wrapping_mul(5); // G
            px[2] = (i as u8).wrapping_mul(7).wrapping_add(tick); // R
            px[3] = 0xFF;
        }
        v
    }

    /// Desktop-like BGRA: an 8×8 grid of flat, pseudo-randomly coloured blocks that changes every
    /// frame.
    ///
    /// Both extremes are traps, and this content is chosen to sit between them — **measured**, not
    /// assumed (`retarget_profile` below is the instrument):
    ///
    /// * [`bgra`] above is a smooth per-pixel ramp offset by `tick`, which VP8 codes for almost
    ///   nothing. Any bitrate-CEILING assertion against it is vacuous: the encoder is content-limited
    ///   long before the target binds, so the test passes whatever the target is.
    /// * Per-pixel xorshift noise is the opposite trap and is just as bad. Measured at 256×256, it
    ///   pins libvpx at `rc_max_quantizer` and bottoms out near **1.3 Mbps** — so a test asserting
    ///   the encoder reached 300 kbps fails against *correct* code, because the content makes that
    ///   rate physically unreachable.
    ///
    /// Flat blocks with abrupt full-frame change is what a real desktop looks like, and it stays
    /// genuinely rate-controlled across the whole range these tests use.
    fn noisy(w: usize, h: usize, frame: u32) -> Vec<u8> {
        const BLOCK: usize = 8;
        let mut v = vec![0u8; w * h * 4];
        for y in 0..h {
            for x in 0..w {
                let bx = (x / BLOCK) as u32;
                let by = (y / BLOCK) as u32;
                let mut s = bx
                    .wrapping_mul(0x9E37_79B9)
                    ^ by.wrapping_mul(0x85EB_CA6B)
                    ^ frame.wrapping_mul(0xC2B2_AE35);
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                let i = (y * w + x) * 4;
                v[i] = s as u8;
                v[i + 1] = (s >> 8) as u8;
                v[i + 2] = (s >> 16) as u8;
                v[i + 3] = 0xFF;
            }
        }
        v
    }

    #[test]
    fn encodes_bgra_to_vp8() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        let au = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).expect("encode");
        assert!(!au.data.is_empty(), "encoder produced bytes");
        assert!(au.keyframe, "first frame is a keyframe");
        // VP8 uncompressed data chunk, keyframe form: 3-byte tag then the start code 9d 01 2a.
        // (RFC 6386 §9.1.) Proves this is really a VP8 keyframe bitstream, not just "some bytes".
        assert_eq!(au.data[0] & 0x01, 0, "frame tag says keyframe");
        assert_eq!(&au.data[3..6], &[0x9d, 0x01, 0x2a], "VP8 keyframe start code");
        // ...and the dimensions libvpx wrote into the keyframe header are the ones we asked for.
        let w = u16::from_le_bytes([au.data[6], au.data[7]]) & 0x3FFF;
        let h = u16::from_le_bytes([au.data[8], au.data[9]]) & 0x3FFF;
        assert_eq!((w, h), (64, 64), "keyframe header carries 64x64");
    }

    #[test]
    fn later_frames_are_deltas() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        let k = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).unwrap();
        assert!(k.keyframe);
        let p = enc.encode_bgra(&bgra(64, 64, 1), 64, 64, NOM).unwrap();
        assert!(!p.data.is_empty());
        assert!(!p.keyframe, "second frame is an inter frame");
        assert_eq!(p.data[0] & 0x01, 1, "frame tag says inter frame");
    }

    #[test]
    fn request_keyframe_forces_one() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        assert!(enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).unwrap().keyframe);
        assert!(!enc.encode_bgra(&bgra(64, 64, 1), 64, 64, NOM).unwrap().keyframe);
        enc.request_keyframe();
        let forced = enc.encode_bgra(&bgra(64, 64, 2), 64, 64, NOM).unwrap();
        assert!(forced.keyframe, "request_keyframe() forced an intra frame");
        // ...and the request is one-shot.
        assert!(!enc.encode_bgra(&bgra(64, 64, 3), 64, 64, NOM).unwrap().keyframe);
    }

    #[test]
    fn crops_odd_dimensions() {
        let mut enc = Vp8Encoder::new(1_000_000).expect("encoder");
        let au = enc.encode_bgra(&bgra(65, 65, 0), 65, 65, NOM).expect("encode odd");
        assert!(!au.data.is_empty());
        let w = u16::from_le_bytes([au.data[6], au.data[7]]) & 0x3FFF;
        let h = u16::from_le_bytes([au.data[8], au.data[9]]) & 0x3FFF;
        assert_eq!((w, h), (64, 64), "cropped to even");
    }

    /// A resolution change must re-initialise libvpx rather than feed it mismatched frames.
    #[test]
    fn survives_a_resolution_change() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        let a = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).unwrap();
        assert_eq!(u16::from_le_bytes([a.data[6], a.data[7]]) & 0x3FFF, 64);
        let _ = enc.encode_bgra(&bgra(64, 64, 1), 64, 64, NOM).unwrap();

        // Grow.
        let b = enc.encode_bgra(&bgra(128, 96, 0), 128, 96, NOM).unwrap();
        assert!(b.keyframe, "re-init emits a keyframe");
        assert_eq!(u16::from_le_bytes([b.data[6], b.data[7]]) & 0x3FFF, 128);
        assert_eq!(u16::from_le_bytes([b.data[8], b.data[9]]) & 0x3FFF, 96);

        // Shrink again, and keep encoding afterwards.
        let c = enc.encode_bgra(&bgra(32, 32, 0), 32, 32, NOM).unwrap();
        assert!(c.keyframe);
        assert_eq!(u16::from_le_bytes([c.data[6], c.data[7]]) & 0x3FFF, 32);
        assert!(!enc.encode_bgra(&bgra(32, 32, 1), 32, 32, NOM).unwrap().data.is_empty());
    }

    #[test]
    fn rejects_degenerate_frames() {
        let mut enc = Vp8Encoder::new(1_000_000).expect("encoder");
        assert!(enc.encode_bgra(&[], 1, 1, NOM).is_err(), "1x1 crops to 0x0");
        assert!(enc.encode_bgra(&[0u8; 4], 4, 4, NOM).is_err(), "short buffer");
        assert!(Vp8Encoder::new(0).is_err(), "zero bitrate");
    }

    /// The bindings we compile against (libvpx 1.13.0, the newest `env-libvpx-sys` ships) are
    /// older than the libvpx we link (1.16.0), and the two disagree about
    /// `VPX_ENCODER_ABI_VERSION`. This pins that down: the probe must find *some* version the
    /// linked library accepts, and `--nocapture` prints which — if a future libvpx bump breaks the
    /// bindings outright, this is the test that says so instead of a confusing init failure.
    #[test]
    fn resolves_the_linked_libvpx_encoder_abi() {
        let iface = unsafe { vpx::vpx_codec_vp8_cx() };
        assert!(!iface.is_null());
        let mut cfg = std::mem::MaybeUninit::<vpx::vpx_codec_enc_cfg_t>::uninit();
        assert_eq!(
            unsafe { vpx::vpx_codec_enc_config_default(iface, cfg.as_mut_ptr(), 0) },
            vpx::VPX_CODEC_OK
        );
        let cfg = unsafe { cfg.assume_init() };
        let mut scratch: Box<vpx::vpx_codec_ctx_t> = Box::new(unsafe { std::mem::zeroed() });
        let abi = encoder_abi_version(iface, &cfg, &mut scratch).expect("ABI resolved");
        eprintln!(
            "libvpx encoder ABI: bindings say {}, linked library accepts {abi}",
            vpx::VPX_ENCODER_ABI_VERSION
        );
        // Pinned, not merely printed. This assertion IS the guard against the one real hazard of
        // pairing 1.13.0 bindings with a 1.16.0 library: if a future libvpx changed the layout of
        // `vpx_codec_enc_cfg`, `vpx_codec_enc_config_default` would memcpy the library's larger
        // struct into a stack buffer sized by our older bindings — a stack overflow, silent rather
        // than a clean error. libvpx bumps this integer whenever those structs change, so a
        // changed number is the signal. Printing it could never fail a run (cargo captures stdout
        // on a passing test, and nobody reads it); equality can.
        //
        // If this fires: re-diff `vpx_codec_enc_cfg`, `vpx_image`, `vpx_codec_ctx` and
        // `vpx_codec_cx_pkt` against the new headers BEFORE bumping the number. They were verified
        // field-by-field for the 1.13-bindings/1.16.0-library pairing (identical: 504/136/56/136
        // bytes and every field offset).
        const EXPECTED_LINKED_ABI: i32 = 39; // libvpx 1.16.0
        assert_eq!(
            abi, EXPECTED_LINKED_ABI,
            "the linked libvpx's encoder ABI changed — re-verify the struct layouts against the \
             new headers before updating EXPECTED_LINKED_ABI, or the bindings/library mismatch \
             becomes silent memory corruption"
        );
    }

    /// The bitrate must reach libvpx in KILObits. If the bits/sec value were passed straight
    /// through, a 2 Mbps ask would configure 2 Gbps and the encoder would barely compress at all.
    /// Encoding the same content at 100 kbps must therefore be markedly smaller than at 8 Mbps.
    #[test]
    fn bitrate_is_converted_to_kilobits() {
        fn total_bytes(bps: u32) -> usize {
            let mut enc = Vp8Encoder::new(bps).expect("encoder");
            let mut n = 0;
            for t in 0..40u8 {
                n += enc.encode_bgra(&bgra(256, 256, t), 256, 256, NOM).unwrap().data.len();
            }
            n
        }
        let low = total_bytes(100_000);
        let high = total_bytes(8_000_000);
        assert!(
            high > low * 2,
            "rate control responds to the target (100kbps={low}B, 8Mbps={high}B)"
        );
    }

    // --- M11: live retargeting, real durations, the time-based keyframe backstop ---------------

    /// Fine-detail BGRA: per-pixel xorshift.
    ///
    /// The third content type, and the reason there are three. Measured at 256×256:
    /// [`noisy`]'s flat blocks are so compressible that at a *large* per-frame budget the encoder
    /// hits `rc_min_quantizer` and physically cannot spend it — so a test asking "does a 5 fps frame
    /// carry six times the bits?" fails against correct code. This content has detail to absorb a
    /// large budget. It is the wrong choice for a low-bitrate test (it hits `rc_max_quantizer` at
    /// ~1.3 Mbps instead), which is exactly why the two are separate.
    fn fine(w: usize, h: usize, frame: u32) -> Vec<u8> {
        let mut v = vec![0u8; w * h * 4];
        for (i, px) in v.chunks_mut(4).enumerate() {
            let mut x = (i as u32).wrapping_mul(2_654_435_761) ^ frame.wrapping_mul(0x9E37_79B9);
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            px[0] = x as u8;
            px[1] = (x >> 8) as u8;
            px[2] = (x >> 16) as u8;
            px[3] = 0xFF;
        }
        v
    }

    /// Encode `n` noisy frames at `ticks` each, returning (total bytes, keyframe count).
    fn run(enc: &mut Vp8Encoder, n: u32, first_frame: u32, ticks: u32) -> (usize, usize) {
        let (mut bytes, mut kf) = (0usize, 0usize);
        for i in 0..n {
            let f = first_frame + i;
            let au = enc.encode_bgra(&noisy(256, 256, f), 256, 256, ticks).expect("encode");
            bytes += au.data.len();
            if au.keyframe {
                kf += 1;
            }
        }
        (bytes, kf)
    }

    /// DIAGNOSTIC (ignored): print per-bucket bytes across a live retarget, so convergence time is
    /// measured rather than assumed. `cargo test -p rmt-transport-webrtc retarget_profile -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn retarget_profile() {
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        for bucket in 0..16u32 {
            if bucket == 6 {
                enc.set_bitrate(300_000).expect("retarget");
                eprintln!("--- set_bitrate(300_000) ---");
            }
            let (bytes, kf) = run(&mut enc, 10, bucket * 10, NOM);
            eprintln!(
                "bucket {bucket:2}: {bytes:7}B  ({:6.0} kbps over 10 frames @30fps)  kf={kf}",
                (bytes as f64 * 8.0) / 1000.0 / (10.0 / 30.0)
            );
        }
    }

    /// **The whole of the live-retarget contract, in one test with two independent assertions.**
    ///
    /// Two different mutations must each turn exactly one of them red:
    /// * update the field but skip `vpx_codec_enc_config_set` → the bytes never fall (assertion ii);
    /// * re-`init()` instead of `enc_config_set` → a keyframe appears (assertion i).
    ///
    /// Either mutation alone would pass a naive "did the output get smaller?" test.
    #[test]
    fn set_bitrate_changes_a_live_context_without_a_keyframe() {
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        // Warm up: frame 0 is the unavoidable keyframe, and libvpx's rate controller needs a few
        // frames before its output reflects the target.
        let _ = run(&mut enc, 10, 0, NOM);
        let (high_bytes, _) = run(&mut enc, 40, 10, NOM);
        let pts_before = enc.pts;

        enc.set_bitrate(300_000).expect("live retarget");

        let (low_bytes, low_kf) = run(&mut enc, 40, 50, NOM);

        // (i) NO keyframe. This is what distinguishes enc_config_set from a re-init, and it is the
        // property that matters in production: a keyframe per adjustment spends the bandwidth the
        // adjustment exists to save, at the exact moment there is none.
        assert_eq!(
            low_kf, 0,
            "a bitrate change must not force a keyframe (got {low_kf}) — that means re-init, \
             not vpx_codec_enc_config_set"
        );
        // (ii) The bytes actually fell — libvpx was really told, not just our field updated.
        assert!(
            high_bytes > low_bytes * 2,
            "4 Mbps produced {high_bytes}B over 40 frames but 300 kbps produced {low_bytes}B; \
             the new target never reached libvpx"
        );
        // The presentation clock kept advancing across the change (a re-init resets it to 0).
        assert!(enc.pts > pts_before, "pts must keep climbing across a retarget");
    }

    /// The kilobit conversion must survive the LIVE path too, not only `init`. Passing bits/sec
    /// into `rc_target_bitrate` would configure 300 Mbps for a 300 kbps ask — which looks like
    /// "adaptation does nothing" rather than like a unit bug.
    #[test]
    fn bitrate_is_still_in_kilobits_after_a_live_change() {
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        let _ = run(&mut enc, 5, 0, NOM);
        enc.set_bitrate(300_000).expect("retarget");
        assert_eq!(
            enc.live.as_ref().expect("live ctx").cfg.rc_target_bitrate,
            300,
            "libvpx must be configured in kilobits/sec"
        );
        enc.set_bitrate(4_000_000).expect("retarget back");
        assert_eq!(enc.live.as_ref().unwrap().cfg.rc_target_bitrate, 4_000);
    }

    /// An adapted-down bitrate must survive the re-init a resolution change forces.
    ///
    /// This is the classic version of the bug: the link degrades, the controller backs off to
    /// 300 kbps, the operator switches monitor — and the encoder silently comes back up at the
    /// constructor's 4 Mbps on a link that cannot carry it. A getter-only assertion would pass
    /// while the encoder did the wrong thing, so this checks the ENCODED SIZE as well.
    #[test]
    fn an_adapted_bitrate_survives_a_resolution_change() {
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        let _ = run(&mut enc, 10, 0, NOM);
        enc.set_bitrate(300_000).expect("retarget");
        let (small_before, _) = run(&mut enc, 30, 10, NOM);

        // Change dimensions -> init() -> a fresh libvpx context.
        let _ = enc.encode_bgra(&noisy(128, 128, 99), 128, 128, NOM).expect("resized");
        // ...and back, so the byte counts are comparable at the same resolution.
        let _ = enc.encode_bgra(&noisy(256, 256, 100), 256, 256, NOM).expect("restored");
        let _ = run(&mut enc, 10, 101, NOM);
        let (small_after, _) = run(&mut enc, 30, 111, NOM);

        assert_eq!(enc.bitrate_bps, 300_000, "the adapted target must be remembered");
        assert_eq!(
            enc.live.as_ref().unwrap().cfg.rc_target_bitrate,
            300,
            "the rebuilt context must come up at the ADAPTED rate, not the constructor's"
        );
        // The observable that a getter cannot fake: output stayed small across the rebuild.
        assert!(
            small_after < small_before * 3,
            "after a resolution change the encoder spent {small_after}B vs {small_before}B before \
             — it came back up at the constructor's rate"
        );
    }

    /// libvpx derives its rate-control frame rate from the interval between presentation
    /// timestamps. At the same target bitrate, frames declared six times longer must each carry
    /// roughly six times the bits — because six times fewer of them fit in a second.
    ///
    /// Mutation: pass a constant duration to `vpx_codec_encode`. Then both runs are budgeted as
    /// 30 fps, the per-frame sizes match, and this fails. That mutation is otherwise invisible: the
    /// stream still decodes, it is just at the wrong bitrate.
    #[test]
    fn duration_drives_libvpxs_framerate() {
        // `fine`, not `noisy`: a 5 fps frame at 2 Mbps has a 50 KB budget, and the flat-block
        // content cannot absorb that (measured: it bottoms out against `rc_min_quantizer` and the
        // two runs come out within 16 % of each other, failing against correct code).
        fn bytes_per_frame(ticks: u32) -> f64 {
            let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
            let mut push = |n: u32, first: u32| {
                let mut bytes = 0usize;
                for i in 0..n {
                    bytes += enc
                        .encode_bgra(&fine(256, 256, first + i), 256, 256, ticks)
                        .expect("encode")
                        .data
                        .len();
                }
                bytes
            };
            let _ = push(15, 0); // let libvpx's frame-rate smoothing settle
            push(40, 15) as f64 / 40.0
        }
        let at_30fps = bytes_per_frame(NOM); // 3000 ticks
        let at_5fps = bytes_per_frame(NOM * 6); // 18000 ticks
        assert!(
            at_5fps > at_30fps * 2.0,
            "a 5 fps frame ({at_5fps:.0}B) must carry far more bits than a 30 fps frame \
             ({at_30fps:.0}B) at the same target — libvpx is being told the wrong frame rate"
        );
    }

    /// The AU must echo the duration it was handed, not recompute one. The transport turns this
    /// number into the RTP timestamp step, and if it were derived twice the encoder's bit budget
    /// and the wire clock could disagree with nothing to catch it.
    #[test]
    fn encoded_au_echoes_the_duration_and_the_encoded_dimensions() {
        let mut enc = Vp8Encoder::new(1_000_000).expect("encoder");
        for ticks in [1u32, 1500, NOM, 18_000, 90_000] {
            let au = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, ticks).expect("encode");
            assert_eq!(au.duration_90khz, ticks, "the AU must echo its duration");
            assert_eq!((au.width, au.height), (64, 64));
        }
        // Odd dimensions report the CROPPED size — what a receiver reads out of the keyframe header.
        let au = enc.encode_bgra(&bgra(65, 65, 0), 65, 65, NOM).expect("encode odd");
        assert_eq!((au.width, au.height), (64, 64), "post-crop dimensions");
    }

    /// The keyframe backstop's time bound must hold at the SLOWEST frame rate the operator can pick.
    ///
    /// `cfg.kf_max_dist` counts frames, so relying on it would mean 240 frames at 5 fps = 48 s of
    /// black for a receiver that lost a keyframe and whose PLI was also lost. Mutation: delete the
    /// `ticks_since_kf` backstop and this fails immediately.
    #[test]
    fn a_keyframe_still_arrives_at_the_backstop_at_five_fps() {
        let mut enc = Vp8Encoder::new(2_000_000).expect("encoder");
        let ticks = VIDEO_CLOCK_RATE / 5; // 18000 = one 5 fps frame
        let first = enc.encode_bgra(&noisy(64, 64, 0), 64, 64, ticks).unwrap();
        assert!(first.keyframe, "frame 0 is always a keyframe");

        // The backstop at 5 fps is KF_BACKSTOP_SECS * 5 frames. Allow the boundary frame itself.
        let boundary = KF_BACKSTOP_SECS * 5;
        let mut saw_kf_at = None;
        for i in 1..=boundary + 1 {
            if enc.encode_bgra(&noisy(64, 64, i), 64, 64, ticks).unwrap().keyframe {
                saw_kf_at = Some(i);
                break;
            }
        }
        let at = saw_kf_at.expect("a keyframe must arrive at the time backstop");
        assert!(
            (boundary - 1..=boundary + 1).contains(&at),
            "keyframe at frame {at} (= {}s); expected the {KF_BACKSTOP_SECS}-second backstop",
            at as f64 / 5.0
        );
    }

    /// `set_bitrate` before any frame has established a size must still be honoured when the
    /// context is finally built. Mutation: early-return before recording `self.bitrate_bps`.
    #[test]
    fn set_bitrate_before_the_first_frame_is_honoured_at_init() {
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        assert!(enc.live.is_none(), "no context before the first frame");
        enc.set_bitrate(500_000).expect("retarget with no context");
        assert_eq!(enc.bitrate_bps, 500_000);
        let _ = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).expect("first frame");
        assert_eq!(
            enc.live.as_ref().unwrap().cfg.rc_target_bitrate,
            500,
            "init() must use the retargeted rate"
        );
    }

    /// The trait's bitrate clamp, and the no-op fast path.
    #[test]
    fn set_bitrate_clamps_and_skips_a_no_op() {
        let mut enc = Vp8Encoder::new(1_000_000).expect("encoder");
        let _ = enc.encode_bgra(&bgra(64, 64, 0), 64, 64, NOM).unwrap();
        enc.set_bitrate(0).expect("zero clamps rather than erroring");
        assert_eq!(enc.bitrate_bps, MIN_BITRATE_BPS);
        enc.set_bitrate(u32::MAX).expect("max clamps");
        assert_eq!(enc.bitrate_bps, MAX_BITRATE_BPS);
        // Setting the same value again is a no-op that still reports success.
        enc.set_bitrate(MAX_BITRATE_BPS).expect("idempotent");
        assert_eq!(enc.bitrate_bps, MAX_BITRATE_BPS);
    }

    /// Greyscale must reach the bitstream, and must not cost a keyframe.
    #[test]
    fn gray_mode_shrinks_the_stream_without_a_keyframe() {
        fn colourful(w: usize, h: usize, frame: u32) -> Vec<u8> {
            // Strong, noisy CHROMA with fairly flat luma, so what Gray removes is most of the cost.
            let mut v = vec![0u8; w * h * 4];
            for (i, px) in v.chunks_mut(4).enumerate() {
                let mut x = (i as u32).wrapping_mul(0x27D4_EB2D) ^ frame.wrapping_mul(0x1656_67B1);
                x ^= x << 13;
                x ^= x >> 17;
                let c = (x & 0xFF) as u8;
                px[0] = c; // B varies wildly
                px[1] = 128; // G flat
                px[2] = 255u8.wrapping_sub(c); // R varies opposite to B -> big chroma swings
                px[3] = 0xFF;
            }
            v
        }
        fn total(mode: ChromaMode) -> (usize, usize) {
            let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
            enc.set_chroma_mode(mode).expect("chroma");
            let (mut bytes, mut kf) = (0usize, 0usize);
            for i in 0..30u32 {
                let au = enc.encode_bgra(&colourful(128, 128, i), 128, 128, NOM).unwrap();
                bytes += au.data.len();
                if au.keyframe {
                    kf += 1;
                }
            }
            (bytes, kf)
        }
        let (full, full_kf) = total(ChromaMode::Full);
        let (gray, gray_kf) = total(ChromaMode::Gray);
        assert!(gray < full, "Gray ({gray}B) must be smaller than Full ({full}B)");
        assert_eq!(full_kf, gray_kf, "colour mode must not change the keyframe cadence");

        // And switching mode mid-stream costs no keyframe.
        let mut enc = Vp8Encoder::new(4_000_000).expect("encoder");
        let _ = enc.encode_bgra(&colourful(128, 128, 0), 128, 128, NOM).unwrap();
        let _ = enc.encode_bgra(&colourful(128, 128, 1), 128, 128, NOM).unwrap();
        enc.set_chroma_mode(ChromaMode::Gray).expect("switch");
        let after = enc.encode_bgra(&colourful(128, 128, 2), 128, 128, NOM).unwrap();
        assert!(!after.keyframe, "a colour-mode switch must not force a keyframe");
    }
}

/// Picture quality of a STATIC desktop over time, as the viewer would see it: a desktop-like frame
/// is re-encoded at the keep-alive cadence, every output is decoded, and PSNR against the source is
/// recorded per frame. This is the measurement behind the operator's "a pulse of blur every few
/// seconds" report, and the guard that it stays gone.
#[cfg(test)]
mod idle_quality {
    use super::super::vp8_decode::Vp8Decoder;
    use super::*;

    /// White background, a coloured title bar, icon blocks, and rows of 1-2 px dark "glyph" strokes:
    /// the high-contrast fine detail that blurs visibly when the quantizer rises.
    pub(super) fn desktop(w: usize, h: usize) -> Vec<u8> {
        desktop_seeded(w, h, 0x1234_5678)
    }

    /// [`desktop`] with a different text layout per `seed` (a window switch changes the text).
    pub(super) fn desktop_seeded(w: usize, h: usize, seed: u32) -> Vec<u8> {
        let mut v = vec![0xFFu8; w * h * 4];
        let mut put = |x: usize, y: usize, b: u8, g: u8, r: u8| {
            if x < w && y < h {
                let i = (y * w + x) * 4;
                v[i] = b;
                v[i + 1] = g;
                v[i + 2] = r;
            }
        };
        for y in 0..28 {
            for x in 0..w {
                put(x, y, 0xC0, 0x60, 0x20); // title bar
            }
        }
        for k in 0..6 {
            for y in 40..72 {
                for x in (20 + k * 50)..(52 + k * 50) {
                    put(x, y, (40 * k) as u8, 0x90, (200 - 30 * k) as u8); // icons
                }
            }
        }
        // Text: 7x12 cells, each glyph a few deterministic strokes.
        let mut s: u32 = seed;
        let mut rnd = || {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            s
        };
        for line in 0..((h - 90) / 16) {
            let y0 = 90 + line * 16;
            for cell in 0..((w - 40) / 8) {
                if rnd() % 7 == 0 {
                    continue; // spaces
                }
                let x0 = 20 + cell * 8;
                for _ in 0..3 {
                    let vertical = rnd() % 2 == 0;
                    let (sx, sy) = ((rnd() % 6) as usize, (rnd() % 10) as usize);
                    for t in 0..((rnd() % 6) as usize + 3) {
                        let (x, y) = if vertical { (x0 + sx, y0 + sy.min(4) + t) } else { (x0 + (sx.min(2) + t).min(6), y0 + sy) };
                        put(x, y, 0x20, 0x20, 0x20);
                    }
                }
            }
        }
        v
    }

    /// PSNR (dB) over the B,G,R channels of two BGRA frames.
    pub(super) fn psnr(a: &[u8], b: &[u8]) -> f64 {
        let mut se = 0f64;
        let mut n = 0f64;
        for (pa, pb) in a.chunks_exact(4).zip(b.chunks_exact(4)) {
            for c in 0..3 {
                let d = pa[c] as f64 - pb[c] as f64;
                se += d * d;
                n += 1.0;
            }
        }
        let mse = se / n;
        if mse == 0.0 { 99.0 } else { 10.0 * (255.0f64 * 255.0 / mse).log10() }
    }

    /// (seconds, psnr, keyframe, bytes) for `secs` of a static desktop at `fps`, `bps`.
    pub(super) fn timeline(w: usize, h: usize, fps: u32, secs: u32, bps: u32) -> Vec<(f64, f64, bool, usize)> {
        let src = desktop(w, h);
        let mut enc = Vp8Encoder::new(bps).expect("encoder");
        let mut dec = Vp8Decoder::new().expect("decoder");
        let ticks = VIDEO_CLOCK_RATE / fps;
        let mut out = Vec::new();
        for i in 0..(fps * secs) {
            let au = enc.encode_bgra(&src, w, h, ticks).unwrap();
            let f = dec.decode(&au.data).unwrap().expect("a decoded frame");
            out.push((i as f64 / fps as f64, psnr(&src, &f.bgra), au.keyframe, au.data.len()));
        }
        out
    }

    /// (seconds, psnr, keyframe, bytes): `secs_each` of desktop A, then a switch to desktop B.
    pub(super) fn switch_timeline(w: usize, h: usize, fps: u32, secs_each: u32, bps: u32) -> Vec<(f64, f64, bool, usize)> {
        let (a, b) = (desktop_seeded(w, h, 0x1234_5678), desktop_seeded(w, h, 0x0BAD_F00D));
        let mut enc = Vp8Encoder::new(bps).expect("encoder");
        let mut dec = Vp8Decoder::new().expect("decoder");
        let ticks = VIDEO_CLOCK_RATE / fps;
        let mut out = Vec::new();
        for i in 0..(fps * secs_each * 2) {
            let src = if i < fps * secs_each { &a } else { &b };
            let au = enc.encode_bgra(src, w, h, ticks).unwrap();
            let f = dec.decode(&au.data).unwrap().expect("a decoded frame");
            out.push((i as f64 / fps as f64, psnr(src, &f.bgra), au.keyframe, au.data.len()));
        }
        out
    }

    /// REGRESSION (the operator's "pulse"): a static desktop at the 30 fps keep-alive cadence (the
    /// cadence a 30 fps session idles at) emits no keyframe after the first for 10 s, and once it has
    /// sharpened (2 s) the picture never drops more than 1 dB. With the old 4 s backstop this fails at
    /// t = 4 s (keyframe, ~33 dB). 30 fps, not 15, so a libvpx `kf_max_dist` left at the old 240
    /// frames (a keyframe at 8 s) fails here too.
    #[test]
    fn an_idle_desktop_has_no_keyframe_pulse() {
        let tl = timeline(640, 360, 30, 10, 3_000_000);
        assert!(tl[0].2, "frame 0 is a keyframe");
        let kfs: Vec<f64> = tl.iter().skip(1).filter(|f| f.2).map(|f| f.0).collect();
        assert!(kfs.is_empty(), "keyframes on an idle screen at t = {kfs:?}");
        let settled: Vec<f64> = tl.iter().filter(|f| f.0 >= 2.0).map(|f| f.1).collect();
        let (lo, hi) = settled.iter().fold((f64::MAX, f64::MIN), |(l, h), &p| (l.min(p), h.max(p)));
        assert!(lo > 40.0, "the settled picture must be sharp, min {lo:.2} dB");
        assert!(hi - lo < 1.0, "the settled picture pulses: {lo:.2}..{hi:.2} dB");
    }

    /// The idle quantizer floor: an UNCHANGED picture stops costing ~4.4 KB per keep-alive frame
    /// once it has settled, without losing any sharpness (measured: ~530 kbps -> ~64 kbps at 15 fps).
    #[test]
    fn an_unchanged_picture_stops_spending_bits_once_settled() {
        let (w, h, fps) = (1280usize, 720usize, 15u32);
        let src = desktop(w, h);
        let mut enc = Vp8Encoder::new(3_000_000).expect("encoder");
        let mut dec = Vp8Decoder::new().expect("decoder");
        let ticks = VIDEO_CLOCK_RATE / fps;
        let (mut early, mut late) = (Vec::new(), Vec::new());
        for i in 0..(fps * 5) {
            let au = enc.encode_bgra(&src, w, h, ticks).unwrap();
            let p = psnr(&src, &dec.decode(&au.data).unwrap().expect("frame").bgra);
            let t = i as f64 / fps as f64;
            if (1.5..2.0).contains(&t) { early.push((au.data.len(), p)); }
            if t >= 3.0 { late.push((au.data.len(), p)); }
            if i > 0 { assert!(!au.keyframe, "no keyframe on an idle screen (t={t})"); }
        }
        let avg = |v: &[(usize, f64)]| v.iter().map(|f| f.0).sum::<usize>() / v.len();
        assert!(enc.idle_floor, "the floor must be armed after {IDLE_SETTLE_TICKS} ticks of identical input");
        assert!(avg(&late) * 4 < avg(&early), "idle frames must cost under a quarter of a settling frame: {} vs {} B", avg(&late), avg(&early));
        assert!(avg(&late) < 1_000, "an idle 720p frame costs {} B", avg(&late));
        let early_best = early.iter().map(|f| f.1).fold(f64::MIN, f64::max);
        let late_worst = late.iter().map(|f| f.1).fold(f64::MAX, f64::min);
        assert!(late_worst > early_best - 0.5, "the floor cost sharpness: {late_worst:.2} dB after vs {early_best:.2} dB before");
    }

    /// A content change releases the floor BEFORE that frame is encoded, so the new content is coded
    /// exactly as without the floor; a forced keyframe (a receiver's PLI) releases it too.
    #[test]
    fn a_change_or_a_keyframe_request_releases_the_floor_first() {
        let (w, h, fps) = (640usize, 360usize, 15u32);
        let (a, b) = (desktop_seeded(w, h, 1), desktop_seeded(w, h, 2));
        let ticks = VIDEO_CLOCK_RATE / fps;
        let min_q = |enc: &Vp8Encoder| enc.live.as_ref().unwrap().cfg.rc_min_quantizer;
        let mut enc = Vp8Encoder::new(3_000_000).expect("encoder");
        for _ in 0..(fps * 3) {
            enc.encode_bgra(&a, w, h, ticks).unwrap();
        }
        assert_eq!(min_q(&enc), IDLE_MIN_QUANTIZER, "armed after 3 s of identical input");
        enc.encode_bgra(&b, w, h, ticks).unwrap();
        assert_eq!(min_q(&enc), MIN_QUANTIZER, "a changed frame is encoded with the floor released");
        assert!(!enc.idle_floor);
        for _ in 0..(fps * 3) {
            enc.encode_bgra(&b, w, h, ticks).unwrap();
        }
        assert_eq!(min_q(&enc), IDLE_MIN_QUANTIZER, "re-armed on the new content");
        enc.request_keyframe();
        let au = enc.encode_bgra(&b, w, h, ticks).unwrap();
        assert!(au.keyframe);
        assert_eq!(min_q(&enc), MIN_QUANTIZER, "a keyframe request releases the floor for that keyframe");
        // The floor must not arm before the picture has had IDLE_SETTLE_TICKS to sharpen.
        let mut enc = Vp8Encoder::new(3_000_000).expect("encoder");
        for _ in 0..(fps * 2 - 2) {
            enc.encode_bgra(&a, w, h, ticks).unwrap();
        }
        assert_eq!(min_q(&enc), MIN_QUANTIZER, "armed too early");
    }

    /// The first frame of new content is as sharp with the idle floor as without it (the reason the
    /// floor is 10 and not higher): the rate controller must not carry the floor into that frame.
    #[test]
    fn the_first_frame_after_idle_is_as_sharp_as_without_the_floor() {
        let (w, h, fps) = (1280usize, 720usize, 15u32);
        let tl = switch_timeline(w, h, fps, 4, 3_000_000);
        let switch = tl[(fps * 4) as usize].1;
        // Measured 48.5 dB with no floor and with a floor of 10; 47.0 at 12, 45.0 at 16.
        assert!(switch >= 48.0, "first frame after a switch {switch:.2} dB");
    }

    /// A LONG idle (30 s at the floor, where rate control's buffer fills) must not change the
    /// transition: the first frames of new content are no larger and no blurrier than after 4 s.
    #[test]
    fn a_long_idle_does_not_inflate_or_blur_the_transition() {
        let (w, h, fps) = (640usize, 360usize, 15u32);
        let transition = |idle_secs: u32| {
            let tl = switch_timeline(w, h, fps, idle_secs, 3_000_000);
            let at = (fps * idle_secs) as usize;
            let first = tl[at];
            let next_bytes: usize = tl[at + 1..at + 1 + fps as usize].iter().map(|f| f.3).sum();
            let next_worst = tl[at + 1..at + 1 + fps as usize].iter().map(|f| f.1).fold(f64::MAX, f64::min);
            (first.1, first.3, next_bytes, next_worst)
        };
        let (p4, b4, n4, w4) = transition(4);
        let (p30, b30, n30, w30) = transition(30);
        assert!(p30 > p4 - 0.5, "first frame after 30 s idle {p30:.2} dB vs {p4:.2} dB after 4 s");
        assert!(w30 > w4 - 0.5, "the following second dips to {w30:.2} dB vs {w4:.2} dB");
        assert!(b30 * 10 <= b4 * 12, "first frame after 30 s idle {b30} B vs {b4} B after 4 s");
        assert!(n30 * 10 <= n4 * 12, "the following second costs {n30} B vs {n4} B");
    }

    /// Diagnostic: the window-switch timeline.
    #[test]
    #[ignore]
    fn print_switch_timeline() {
        for (t, p, kf, b) in switch_timeline(1280, 720, 15, 3, 3_000_000) {
            println!("t={t:5.2}s psnr={p:6.2} kf={} bytes={b}", kf as u8);
        }
    }

    /// Diagnostic, not a guard: prints the timeline. `cargo test -p rmt-transport-webrtc --lib
    /// idle_quality::print_timeline -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn print_timeline() {
        for (t, p, kf, b) in timeline(1280, 720, 15, 10, 3_000_000) {
            println!("t={t:5.2}s psnr={p:6.2} kf={} bytes={b}", kf as u8);
        }
    }
}
