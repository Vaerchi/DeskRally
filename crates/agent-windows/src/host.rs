//! Agent host CLI: the process that is installed as a service and re-launched as the
//! per-session SYSTEM helper.
//!
//! Subcommands (dispatched by [`host_main`]):
//! * `install`   — register + start the LocalSystem auto-start service.
//! * `uninstall` — stop + delete the service.
//! * `run-service` — SCM dispatcher entry point (the service binPath).
//! * `--helper --session <id>` — runs as SYSTEM in the interactive session; follows the input
//!   desktop and captures it with the appropriate tier (DXGI on `Default`, GDI on the secure
//!   desktop / RDP). This is the productized form of the proven secure-desktop spike.
//!
//! The helper writes a small capture-proof BMP per desktop switch to [`PROOF_DIR`] when
//! `RMT_HELPER_PROOF=1` is set in its environment. That is a verification aid, not a product
//! path — the real helper hands frames to the encoder/transport instead.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use rmt_agent::backstage::audit::{AuditAction, Direction, Outcome, SharedAuditChain};
use rmt_agent::backstage::grant::SignedGrant;
use rmt_agent::elevation::SignedElevationGrant;
use rmt_agent::session_policy::{
    LeaseLapse, LeaseStatus, SessionAccessState, SessionBinding, SessionLease, SessionLeaseMode,
    SessionPolicyError, SignedSessionPolicy, DEFAULT_LEASE_GRACE, LEASE_TICK,
};
use rmt_agent::backstage::rbac::{Capability, Grant};
use rmt_agent::backstage::Dispatcher;
use rmt_agent::transport::backstage_api;

use rmt_crypto::PublicIdentity;

use rmt_agent_core::chat::{self, ChatFrom, ChatMessage, Transcript};
use rmt_agent_core::clipboard::{self, Clipboard, ClipboardMessage};
use rmt_agent_core::control::{self, ControlMessage, MonitorDesc};
use rmt_agent_core::file_transfer::{self, Chunk, Message as FtMessage, Offer};
use rmt_agent_core::guest_ui::{GuestSurface, GuestToHost, GuestUi, SessionInfo};
use rmt_agent_core::platform::PlatformResult;
use rmt_agent_core::quality::{self, ColorMode, QualitySettings};
use rmt_agent_core::scale::scale_bgra;
use rmt_agent_core::{
    input_codec, CapturedFrame, InputEvent, InputSink, MonitorInfo, ScreenCapturer,
    COMPOSITE_MONITOR_ID,
};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{
    BrokeredAccess, ChallengeSigner, ChromaMode, IceServer, Role, VideoFrameSender, VideoQuality, WebRtcTransport,
};

use rmt_agent_core::transport::Transport;

use crate::input::SendInputSink;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::WindowsAndMessaging::{GetSystemMetrics, SM_REMOTESESSION};

use crate::capture::DxgiCapturer;
use crate::capture_loop::CaptureLoop;
use crate::clipboard::WinClipboard;
use crate::config::ClipboardMode;
use crate::following_capturer::FollowingCapturer;
use crate::service;

/// Global name for the single-instance helper mutex (one helper across the machine at a time —
/// there is only ever one active console session to serve).
const HELPER_SINGLETON: &str = "Global\\RmtAgentHelperSingleton";

/// Service identity.
const SERVICE_NAME: &str = "RmtAgent";
const SERVICE_DISPLAY: &str = "DeskRally Remote Agent";

/// Where the helper drops capture-proof BMPs (only when `RMT_HELPER_PROOF=1`).
const PROOF_DIR: &str = r"C:\rmt-agent";
/// Create this file to end the helper loop early.
const STOP_FILE: &str = r"C:\rmt-agent\stop";
/// Helper self-terminates after this long as a safety net.
const HELPER_MAX_RUN: Duration = Duration::from_secs(300);

/// Default signaling server WebSocket endpoint for the `stream` subcommand.
const DEFAULT_SIGNALING_URL: &str = "ws://127.0.0.1:8080/ws";

/// Longest a single remote-control session may run before the driver ends it.
///
/// **This was 5 minutes**, described as a "safety net" — correct for the dev harness it was written
/// for, and a hard blocker for actually using the product: every session died mid-work and the
/// operator had to reconnect. Nothing about the driver needs a short bound; the flag that ends a
/// session is `stop`, and a controller disconnecting is detected directly (the data channel closes).
///
/// Four hours is a bound rather than "unlimited" on purpose. A session is the thing holding a
/// capture thread, a libvpx context and an encoder queue, and an unbounded one turns any leak in
/// that path into an indefinite one. (The encoder queue itself was the concrete instance of that
/// worry when this constant was raised in loop 16; it is bounded as of loop 17 by drain-to-latest,
/// so this bound now guards the remaining per-session resources rather than a known growth path.)
/// Four hours is longer than any plausible single support session
/// and short enough that a forgotten window does not hold resources overnight. Configurable per
/// machine via `max_session_secs`.
const DEFAULT_STREAM_MAX_RUN: Duration = Duration::from_secs(4 * 60 * 60);
/// Default target capture/encode rate for the `stream` subcommand.
const DEFAULT_STREAM_FPS: u32 = 30;

/// How finely the capture thread's pacing sleep is sliced so controller input can be injected
/// between slices (M11).
///
/// This is the bound on input latency, and it must stay INDEPENDENT of the operator's frame rate —
/// that coupling is the defect it exists to remove. ~8 ms is well under human perception, costs a
/// handful of extra wakeups per second on an otherwise sleeping thread, and keeps a click at 1 fps
/// as responsive as one at 60.
const INPUT_DRAIN_SLICE: Duration = Duration::from_millis(8);

/// Minimum frame cadence: the longest the receiver should ever go without a fresh video frame.
///
/// This is the anti-blink fix. DXGI Desktop Duplication only yields a frame when the screen CHANGES,
/// so a static desktop produces almost nothing to send — and a browser's video pipeline (its render
/// overlay and its jitter buffer) flickers and stalls when frames arrive sparsely and irregularly.
/// That is the "blink", and it is why NONE of quality/bitrate/adaptive/keyframes touched it (they
/// change what a frame contains, never how OFTEN one arrives) while a playing video — continuous
/// frames — makes it vanish. Confirmed from the receiver's own stats: 0 packets lost, 0 frames
/// dropped, but a 69 ms inter-frame-delay stddev and a 455 ms jitter buffer — clean but sparse and
/// uneven delivery. So when the screen produces nothing, re-send the LAST frame at this cadence to
/// keep the pipeline continuously fed. The re-sends are near-empty VP8 deltas (the image is
/// unchanged), so the bandwidth cost is negligible. Repair is NOT the goal here — delivery is.
/// Intra refresh is receiver-driven (PLI/FIR → `request_keyframe`); the encoder's time backstop is
/// now a 60 s last resort, because every keyframe is a visible blur flash (see `vp8::KF_MAX_TICKS`).
///
/// It is a FLOOR ON SPARSENESS, not a frame rate: see [`min_frame_interval`] for why it must never
/// out-run the frame rate the operator asked for.
const MIN_FRAME_INTERVAL: Duration = Duration::from_millis(66); // ~15 fps floor

/// The keep-alive re-send interval for a session running at `commanded_fps`: the **shorter** of
/// [`MIN_FRAME_INTERVAL`] and the operator's own frame interval — i.e. deliver at
/// `max(commanded_fps, ~15) fps`.
///
/// # The two numbers answer different questions
///
/// This function got it backwards once, shipped, and brought the blink back, so it is worth being
/// explicit about which concern each number serves:
///
/// * **`commanded_fps` is a BANDWIDTH budget** — how much NEW PICTURE the operator is willing to
///   pay for. The "Text (slow link)" preset is 5 fps because a bad link cannot afford 30.
/// * **[`MIN_FRAME_INTERVAL`] is a LIVENESS guarantee** — how often the receiver's pipeline must be
///   fed so its jitter buffer and render overlay do not stall. That is the blink.
///
/// A keep-alive re-send carries **no new picture**: it is a near-empty delta of a frame the
/// receiver already has. Letting the bandwidth budget throttle it is a category error — it costs
/// almost nothing and delivers nothing new, so an operator who asked for 5 fps is not getting
/// 15 fps of *content* when the floor fires. Taking the LONGER of the two (which is what the first
/// version did) lets a slow budget starve the guarantee, which is precisely the sparse delivery the
/// guarantee exists to prevent.
///
/// # Why 30 fps needs it too, which is the part that was missed
///
/// The first version reasoned that at 30 fps `max(66ms, 33ms)` = 66 ms was "unchanged, so the blink
/// stays fixed". Unchanged it was — and still wrong, because something ELSE had changed underneath
/// it. Before the capture loop learned to report "nothing changed" as *no news*, an idle screen
/// still fell through the tier chain to a GDI blit, which never reports nothing-changed and so
/// produced a real (duplicate) frame **every iteration, at the commanded rate**. Idle delivery was
/// therefore ~30 fps and this floor was a backstop that rarely fired — it had never been
/// load-bearing on its own when it was validated. Removing the fall-through left it carrying idle
/// delivery alone, at half the old cadence, and the blink came back.
///
/// So the floor must rise to the commanded rate, not merely sit under it: 30 fps commanded means
/// keep-alives at 30 fps on an idle screen, restoring exactly the cadence that was there before, at
/// a fraction of the cost (a near-empty delta instead of a full-screen blit, readback and encode).
///
/// `commanded_fps` of 0 is treated as 1: a zero would divide by zero, and no frame rate at all is
/// not something the quality controller can mean.
/// The frame rate a session runs at while its viewer is in the background
/// ([`ControlMessage::SetBackground`]): enough that the picture is current the moment the viewer
/// comes back, and no keep-alive frames in between.
const BACKGROUND_FPS: u32 = 1;

/// The rate a session's capture thread paces to: the operator's applied rate, or
/// [`BACKGROUND_FPS`] while the viewer is hidden (never faster than the applied rate).
fn session_fps(applied_fps: u32, background: bool) -> u32 {
    if background { BACKGROUND_FPS.min(applied_fps.max(1)) } else { applied_fps }
}

fn min_frame_interval(commanded_fps: u32) -> Duration {
    let fps = commanded_fps.max(1) as u64;
    MIN_FRAME_INTERVAL.min(Duration::from_micros(1_000_000 / fps))
}

/// Reconnect backoff floor after a failed connect/session (M3). A rejected registration is a
/// *persistent* condition — a missing enrollment, a key the control plane no longer pins — so
/// retrying every couple of seconds would hammer the signaling server and, through its identity
/// resolver, the control plane behind it.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_secs(5);
/// Reconnect backoff ceiling: long enough not to be a load source, short enough that a machine
/// recovers within a minute of the problem being fixed.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(60);

/// Spread a backoff over `[d, 1.5d)` so a fleet that lost its signaling server together does not
/// come back in lockstep. Seeded from the wall clock — this is jitter, not a security primitive.
fn jittered(d: Duration) -> Duration {
    let spread = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.subsec_nanos() as u64 % 500)
        .unwrap_or(0);
    d + (d * spread as u32) / 1000
}

/// Parse argv and dispatch. Returns a process exit code.
pub fn host_main() -> i32 {
    let args: Vec<String> = std::env::args().collect();

    // `version` is answered BEFORE the logging subscriber is installed, and that ordering is
    // deliberate rather than tidy. `logging::init()` creates and appends to C:\rmt-agent\helper.log;
    // the release packager runs this subcommand on the freshly staged binary to read its build
    // identity (see the match arm below for why the identity cannot be scanned out of the image),
    // and a packaging step must not create files under the agent's hardened root on the build box,
    // nor stamp an unrelated line into a real machine's log when an operator simply asks what is
    // installed. Nothing here reads config, touches the service, or opens a socket.
    if args.get(1).map(String::as_str) == Some("version") {
        println!("{}", rmt_agent_core::version::AGENT_VERSION);
        return 0;
    }

    // Read-only packaging ABI probe; no logging/config/service side effects.
    // Packaging reads every line: the provisioning ABI, the auto-update ABI the MSI's custom
    // actions call, which feed this build talks to, and the compiled update signer pin.
    if args.get(1).map(String::as_str) == Some("msi-capabilities") {
        println!("RMT-MSI-PROVISION-v1");
        println!("RMT-MSI-AUTOUPDATE-v1");
        let feed = crate::update_feed::FEED;
        println!("FEED={}", if feed.is_empty() { "none" } else { feed });
        let pin = crate::update_provision::UPDATE_PIN;
        println!("UPDATE-PIN={}", if pin.is_empty() { "none" } else { pin });
        let publisher = env!("DESKRALLY_UPDATE_PUBLISHER");
        println!("UPDATE-PUBLISHER={}", if publisher.is_empty() { "none" } else { publisher });
        return 0;
    }

    // Installer entry point: avoid the logging subscriber and never print provisioning data.
    if args.get(1).map(String::as_str) == Some("msi-provision") {
        return crate::msi::command(&args);
    }

    // Auto-update provisioning, run by the MSI's deferred / rollback / commit custom actions.
    if args.get(1).map(String::as_str) == Some("msi-autoupdate") {
        if !crate::update_worker::is_local_system() {
            return 1;
        }
        crate::logging::init();
        return crate::update_provision::command(&args);
    }

    // HealthGate, run by the MSI's deferred custom action inside the install transaction.
    if args.get(1).map(String::as_str) == Some("msi-health-gate") {
        if !crate::update_worker::is_local_system() {
            return crate::update_gate::EXIT_VERIFICATION;
        }
        crate::logging::init();
        return crate::update_gate::command(&args);
    }

    // docs/65 D-C6: the removal helper, a COPY of this image in a SYSTEM-only temp directory, started by the directive engine.
    // It validates its own location and handoff itself (directive_win::removal_command) and needs no logging subscriber:
    // the agent root it would log into is the thing it deletes.
    if args.get(1).map(String::as_str) == Some("directive-removal") {
        return crate::directive_win::removal_command(&args);
    }

    // Auto-update (design v3..v10.1): the scheduled worker, and the relocated runner it starts.
    // Both require LocalSystem; each validates its own image location before acting.
    if matches!(args.get(1).map(String::as_str), Some("auto-update-worker") | Some("auto-update-run")) {
        if !crate::update_worker::is_local_system() {
            return 1;
        }
        crate::logging::init();
        let result = if args[1] == "auto-update-worker" {
            if args.len() != 2 {
                return 1;
            }
            crate::update_worker::run()
        } else {
            crate::update_worker::run_runner(&args)
        };
        return match result {
            Ok(()) => 0,
            Err(error) => {
                tracing::error!(%error, cmd = %args[1], "automatic update failed");
                1
            }
        };
    }

    // `monitors` is answered BEFORE the logging subscriber for the same reason as `version`: it is
    // a read-only question an operator (or a support engineer over the phone) asks of a binary,
    // including one sitting in a download folder on a machine that has no agent installed. Creating
    // C:\rmt-agent\helper.log as a side effect of "what screens do you see?" would have this
    // subcommand write into the hardened agent root on a box that is not running the agent.
    if args.get(1).map(String::as_str) == Some("monitors") {
        return crate::monitor_report::monitors_command(&args);
    }
    // `canvas-bench` (docs/52): read-only, like `monitors`, so it is answered before logging too.
    if args.get(1).map(String::as_str) == Some("canvas-bench") {
        return crate::canvas_bench::canvas_bench_command(&args);
    }

    // `audio-probe` is answered early for the same reason as `version` and `monitors`: it is a
    // read-only question about the machine, asked of a binary that may not be an installed agent.
    if args.get(1).map(String::as_str) == Some("audio-probe") {
        return crate::audio_report::audio_probe_command(&args);
    }

    // Install the tracing subscriber FIRST: everything after this line — enroll's plaintext-http
    // warning, registration identity, the helper's desktop following — reports through it into
    // C:\rmt-agent\helper.log (+ stderr). Before crate::logging existed, every tracing::* in the
    // agent was a silent no-op (docs/07 loop 6 §2).
    crate::logging::init();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    // The subcommand only — NEVER full argv, which can carry an enrollment token (a bearer secret).
    tracing::info!(pid = std::process::id(), cmd, "agent host start");
    match cmd {
        "install" => match service::install_service(SERVICE_NAME, SERVICE_DISPLAY, "run-service") {
            Ok(()) => {
                println!("installed + started service '{SERVICE_NAME}'");
                0
            }
            Err(e) => {
                eprintln!("install failed: {e}");
                1
            }
        },
        "uninstall" => match service::uninstall_service(SERVICE_NAME) {
            Ok(()) => {
                println!("uninstalled service '{SERVICE_NAME}'");
                0
            }
            Err(e) => {
                eprintln!("uninstall failed: {e}");
                1
            }
        },
        "run-service" => match service::run_service_dispatcher(SERVICE_NAME) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("run-service failed: {e}");
                1
            }
        },
        "--helper" => {
            let session = parse_session_arg(&args);
            let stop_event = crate::helper_stop::parse_stop_event_arg(&args);
            helper_worker(session, stop_event)
        }
        // `version` is handled EARLY, above `logging::init()` — see the top of this function.
        // This arm is unreachable and exists so the subcommand is discoverable where every other
        // subcommand is listed.
        //
        // WHY IT EXISTS, beyond an operator asking "what is installed on this box". The release
        // packager needs the staged binary's identity so `dist/MANIFEST.txt` cannot claim a
        // freshness it never checked, and **scanning the image for the literal does not work on an
        // optimized build**. `AGENT_VERSION` is a `concat!` of two short strs, and at opt-level 3
        // rustc materializes the 13-byte result as two overlapping 8-byte immediate MOVs inside
        // the code rather than as one contiguous run in `.rdata`:
        //
        //     48 b8 '+4f56580'      mov rax, imm64
        //     49 89 45 05           mov [r13+5], rax
        //     48 b8 '0.0.1+4f'      mov rax, imm64
        //     49 89 45 00           mov [r13+0], rax
        //
        // so `0.0.1+` and `4f56580` are both present and never adjacent. A byte scan therefore
        // reports UNSTAMPED for every release build — which would have made the packager's STALE
        // banner fire on every genuine release forever, training the reader to ignore the one
        // warning that matters. Asking the binary is authoritative because it returns the value
        // the fleet will actually see, not a guess about how the compiler stored it.
        //
        // Same family of trap as `crate::stub`'s placeholder slot: an unoptimized test cannot
        // validate an optimized-build invariant.
        "version" => {
            println!("{}", rmt_agent_core::version::AGENT_VERSION);
            0
        }
        // Like `version`, handled EARLY (above `logging::init()`) — see the top of this function.
        // This arm exists so the subcommand is discoverable where the others are listed.
        "monitors" => crate::monitor_report::monitors_command(&args),
        // Also handled EARLY (above `logging::init()`) — see the top of this function.
        "audio-probe" => crate::audio_report::audio_probe_command(&args),
        "stream" => stream_command(&args),
        #[cfg(feature = "test-harness")]
        "multi-stream" => multi_stream_command(&args),
        "enroll" => enroll_command(&args),
        "attend" => attend_command(&args),
        // test-harness only: show the tray's "Request help" note dialog standalone (VM lab probe; prints the outcome).
        #[cfg(feature = "test-harness")]
        "help-dialog-probe" => {
            let note = crate::help_dialog::prompt_note();
            println!("HELP-DIALOG-OUTCOME {note:?}");
            0
        }
        // docs/53: the elevated, input-only helper an attended session launches through UAC.
        "elevated-input" => crate::elevation_win::run_helper(&args),
        // docs/53 §6 VM self-test (test-harness only): the real UAC launch + pipe handshake.
        #[cfg(feature = "test-harness")]
        "elevated-input-selftest" => crate::elevation_win::run_selftest(&args),
        // The `rmt://` browser handoff. Registered by `install`; invoked by the shell, not by a
        // human. See `uri_command` for why the URI stays a single argv entry.
        "uri" => uri_command(&args),
        // Server-side patcher: stamp an attend URI into a copy of the agent binary, producing the
        // per-download guest stub. See `make_stub_command` and [`crate::stub`].
        "make-stub" => make_stub_command(&args),
        // No subcommand. A **configured guest stub** (a per-download copy with an embedded attend
        // link) self-configures and runs the attended flow here; a normally-built agent_host run
        // with no arguments just prints usage. See `stub_command`.
        "" => stub_command(),
        other => {
            eprintln!("rmt agent host — unknown command {other:?}");
            print_usage();
            2
        }
    }
}

/// The one-line usage banner, shared by the unknown-command path and an unconfigured no-argument
/// run (a normal agent_host that is not a stub).
fn print_usage() {
    #[cfg(not(feature = "test-harness"))]
    eprintln!(
        "usage: install | uninstall | run-service | --helper --session <id>\n       \
         monitors [--all-tiers] [--capture <dir>]  (diagnostic: every display this machine's capture stack sees)\n       \\n         canvas-bench [--secs N] [--fps N] [--following [--encode]]  (diagnostic: DXGI canvas vs GDI composite cost on this machine; read-only)\n       \
         enroll --control-plane-url <https-url> --token <enrollment-token> [--name <machine-name>] [--config <path>]\n       \
         attend --code <CODE> --control-plane-url <https-url> [--signaling <ws-url>] [--reason <text>] [--auto-consent] [--fps <n>] [--synthetic] [--log-input]\n       \
         uri \"rmt://attend?code=<CODE>&cp=<https-url>[&reason=<text>]\"  (browser handoff; the handler `install` registers)\n       \
         make-stub --uri \"rmt://attend?code=<CODE>&cp=<https-url>[&reason=<text>]\" --out <path> [--template <exe>] | --uri-file <path>  (server-side: build a per-download guest stub)\n       \
         stream [--signaling <ws-url>] [--device <uuid>] [--fps <n>] [--synthetic [--synthetic-tone]] [--log-input] [--log-clipboard] [--grant-issuer <hex-pubkey>] [--identity <path>] [--tenant <uuid>] [--recording-dir <path> | --recording-service] [--stun <url>]..."
    );
    #[cfg(feature = "test-harness")]
    eprintln!(
        "usage: install | uninstall | run-service | --helper --session <id>\n       \
         monitors [--all-tiers] [--capture <dir>]  (diagnostic: every display this machine's capture stack sees)\n       \\n         canvas-bench [--secs N] [--fps N] [--following [--encode]]  (diagnostic: DXGI canvas vs GDI composite cost on this machine; read-only)\n       \
         enroll --control-plane-url <https-url> --token <enrollment-token> [--name <machine-name>] [--config <path>]\n       \
         attend --code <CODE> --control-plane-url <https-url> [--signaling <ws-url>] [--reason <text>] [--auto-consent] [--fps <n>] [--synthetic] [--log-input]\n       \
         uri \"rmt://attend?code=<CODE>&cp=<https-url>[&reason=<text>]\"  (browser handoff; the handler `install` registers)\n       \
         make-stub --uri \"rmt://attend?code=<CODE>&cp=<https-url>[&reason=<text>]\" --out <path> [--template <exe>] | --uri-file <path>  (server-side: build a per-download guest stub)\n       \
         stream [--signaling <ws-url>] [--device <uuid>] [--fps <n>] [--synthetic [--synthetic-tone]] [--log-input] [--log-clipboard] [--grant-issuer <hex-pubkey>] [--identity <path>] [--tenant <uuid>] [--recording-dir <path> | --recording-service] [--stun <url>]...\n       \
         multi-stream --synthetic [--signaling <ws-url>] [--device <uuid>] [--fps <n>] [--identity <path>] [--tenant <uuid>]  (test-harness only: multi_session_capable synthetic agent, recording injector, no service install)"
    );
}

/// No-subcommand entry. If THIS binary is a configured guest stub — a per-download copy with an
/// attend link patched into its embedded slot ([`crate::stub`]) — recover that link and run the
/// attended flow through the **exact same** hardened path a clicked `rmt://` link takes
/// ([`attend_params_from_uri`], `auto_consent = false`). Otherwise this is a normally-built
/// `agent_host` double-clicked or run bare: print usage.
///
/// The embedded URI is NEVER logged: it carries the one-time attend code, a bearer secret — the same
/// discipline `uri_command` and `host_main`'s argv logging follow.
fn stub_command() -> i32 {
    match crate::stub::embedded_config() {
        Some(uri) => match crate::uri::parse_attend_uri(&uri) {
            Ok(parsed) => {
                println!("rmt guest client starting");
                run_attend(attend_params_from_uri(parsed))
            }
            Err(e) => {
                // A configured stub whose embedded link does not parse is a build/patch error, not
                // attacker input — but still refuse rather than act on a value we cannot validate.
                eprintln!("stub: embedded configuration is not a valid attend link — {e}");
                2
            }
        },
        None => {
            print_usage();
            2
        }
    }
}

/// `make-stub --uri "<rmt-uri>" --out <path> [--template <exe>]` (or `--uri-file <path>`): write an
/// attend link into a copy of the agent binary, producing the per-download guest stub
/// ([`crate::stub::patch`]).
///
/// The template defaults to THIS running executable — the shipped `agent_host.exe` IS the stub
/// template, so a server generates a download by calling `agent_host make-stub` on itself. The
/// output is UNSIGNED: patching the slot invalidates any Authenticode signature the template
/// carried, so the caller MUST re-sign the result (`scripts/sign-release.ps1`, which timestamps)
/// before distributing it. This is the ScreenConnect model — a per-download-unique, re-signed binary
/// (see [`crate::stub`]).
///
/// `--uri-file` reads the link from a file so the one-time code need not appear on a command line.
fn make_stub_command(args: &[String]) -> i32 {
    let out = match parse_str_arg(args, "--out") {
        Some(p) => p.to_string(),
        None => {
            eprintln!("make-stub: --out <path> is required");
            return 2;
        }
    };
    // The attend URI, from --uri or --uri-file (exactly one).
    let uri = match (parse_str_arg(args, "--uri"), parse_str_arg(args, "--uri-file")) {
        (Some(_), Some(_)) => {
            eprintln!("make-stub: pass --uri OR --uri-file, not both");
            return 2;
        }
        (Some(u), None) => u.trim().to_string(),
        (None, Some(f)) => match std::fs::read_to_string(f) {
            Ok(s) => s.trim().to_string(),
            Err(e) => {
                eprintln!("make-stub: could not read --uri-file {f:?}: {e}");
                return 2;
            }
        },
        (None, None) => {
            eprintln!("make-stub: one of --uri or --uri-file is required");
            return 2;
        }
    };

    let template_path = match parse_str_arg(args, "--template") {
        Some(p) => PathBuf::from(p),
        None => match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("make-stub: could not resolve the running exe as the default template: {e}");
                return 2;
            }
        },
    };

    let template = match std::fs::read(&template_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("make-stub: could not read template {}: {e}", template_path.display());
            return 2;
        }
    };

    let patched = match crate::stub::patch(&template, &uri) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("make-stub: {e}");
            return 2;
        }
    };

    if let Err(e) = std::fs::write(&out, &patched) {
        eprintln!("make-stub: could not write {out}: {e}");
        return 1;
    }

    // The URI is NOT echoed — it carries the one-time code (a bearer secret).
    println!(
        "make-stub: wrote {} ({} bytes) from template {}",
        out,
        patched.len(),
        template_path.display()
    );
    println!(
        "make-stub: the output is UNSIGNED — re-sign it before distributing \
         (scripts/sign-release.ps1 timestamps)."
    );
    0
}

/// Parse a `--flag value` string argument.
pub(crate) fn parse_str_arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).map(String::as_str)
}

/// `enroll --control-plane-url <URL> --token <TOKEN> [--name <n>] [--config <path>]`: redeem a
/// one-shot enrollment token for a **server-minted** device id + tenant, pinning this machine's
/// Ed25519 public key in the control plane (M3).
///
/// Runs before `install` in the installer flow, and is idempotent in the only way that matters: an
/// already-enrolled config is left alone rather than burning another token use. There is no
/// fallback — a failure exits non-zero so the installer aborts instead of leaving behind an agent
/// with a self-invented device id that no session ticket can ever authorize.
/// Whether an `enroll` invocation should short-circuit as "already enrolled — nothing to do".
///
/// Only when the config names a device id AND its identity key actually exists on disk AND `--force`
/// was not given. The `key_exists` term is the fix for a real trap: a device id in config with NO
/// key file is a HALF-enrolled state that MUST re-enroll — keying the guard on the device id alone
/// stranded such an agent unauthenticated permanently, with no `--force` to recover.
fn enroll_already_done(has_device_id: bool, key_exists: bool, force: bool) -> bool {
    has_device_id && key_exists && !force
}

fn enroll_command(args: &[String]) -> i32 {
    let config_path = parse_str_arg(args, "--config")
        .unwrap_or(crate::config::CONFIG_FILE)
        .to_string();
    let mut cfg = crate::config::HelperConfig::load_from(&config_path).unwrap_or_default();

    if let Some(url) = parse_str_arg(args, "--control-plane-url") {
        cfg.control_plane_url = Some(url.trim().to_string());
    }
    if let Some(tok) = parse_str_arg(args, "--token") {
        cfg.enrollment_token = Some(tok.trim().to_string());
    }

    let force = args.iter().any(|a| a == "--force");
    let key_exists = std::path::Path::new(&cfg.identity_path_or_default()).exists();
    if let Some(existing) = cfg.device_id.as_deref().filter(|s| !s.trim().is_empty()).map(str::to_string) {
        if enroll_already_done(true, key_exists, force) {
            println!("enroll: already enrolled as device {existing} — nothing to do");
            return 0;
        }
        // A config that NAMES a device but has no identity key on disk is HALF-enrolled: a prior
        // enroll wrote the device id but the key never persisted (or was removed). The old guard
        // no-op'd on the device id ALONE, so such an agent stayed unauthenticated forever (found the
        // hard way installing the first real agent — the fleet showed nothing and the helper logged
        // "registering UNAUTHENTICATED"). Clear the stale device id so `enroll_once` mints a fresh
        // identity + device id. `--force` takes the same path deliberately.
        if key_exists {
            eprintln!("enroll: --force — re-enrolling (was device {existing})");
        } else {
            eprintln!(
                "enroll: config names device {existing} but no identity key at {} — re-enrolling",
                cfg.identity_path_or_default()
            );
        }
        cfg.device_id = None;
    }
    if !cfg.is_control_plane_managed() {
        eprintln!("enroll: --control-plane-url is required (or set control_plane_url in {config_path})");
        return 2;
    }
    if cfg.enrollment_token.as_deref().is_none_or(|s| s.trim().is_empty()) {
        eprintln!("enroll: --token is required (or set enrollment_token in {config_path})");
        return 2;
    }

    match crate::enroll::enroll_once(&mut cfg, &config_path, parse_str_arg(args, "--name")) {
        Ok(id) => {
            println!(
                "enroll: enrolled as device {} in tenant {} (config {config_path})",
                id.device_id, id.tenant_id
            );
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// Synthetic capture dimensions for the `--synthetic` streaming path (a realistic-ish frame size
/// that still encodes cheaply). Both even, which is what the video encoder wants (odd sizes are
/// cropped by a pixel).
const SYNTHETIC_DIMS: (u32, u32) = (1280, 720);
/// Keyframe cadence for the synthetic capturer (a keyframe every N frames helps a real browser
/// decoder start promptly).
const SYNTHETIC_KEYFRAME_INTERVAL: u64 = 30;

/// `stream [--signaling <url>] [--device <uuid>] [--fps <n>] [--synthetic] [--log-input] [--log-clipboard]`: build a multi-thread
/// tokio runtime and drive [`serve_session`], streaming a display over a WebRTC video track to a
/// controller that reaches us through the signaling server, and injecting the controller's input
/// events via [`SendInputSink`].
///
/// By default the source is a real [`DxgiCapturer`] (this session's live display). The hidden
/// `--synthetic` flag swaps in a [`rmt_agent_core::SyntheticCapturer`] that emits deterministic
/// frames unconditionally — no display, no GPU, no dependence on the screen changing. That makes
/// the streaming path drivable headlessly (e.g. the automated browser↔agent e2e test), where DXGI
/// is unavailable or would starve the encoder of frames.
///
/// A `stop` file (same path the helper watches) or the [`DEFAULT_STREAM_MAX_RUN`] bound ends the run.
fn stream_command(args: &[String]) -> i32 {
    let _ = crate::set_process_dpi_awareness();

    let url = parse_str_arg(args, "--signaling")
        .unwrap_or(DEFAULT_SIGNALING_URL)
        .to_string();
    let device = match parse_str_arg(args, "--device") {
        Some(s) => match s.parse::<uuid::Uuid>() {
            Ok(u) => DeviceId(u),
            Err(e) => {
                eprintln!("stream: invalid --device uuid {s:?}: {e}");
                return 2;
            }
        },
        None => DeviceId::new(),
    };
    let fps = parse_str_arg(args, "--fps")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_STREAM_FPS);
    let synthetic = args.iter().any(|a| a == "--synthetic");
    let log_input = args.iter().any(|a| a == "--log-input");
    // `--require-session-policy` opens the session under the PROVISIONAL view-only floor, mirroring
    // the installed helper's `require_session_policy` config flag. It exists on this dev entry point
    // for one reason: without it the loop-86 unattended floor is unreachable from any automated test
    // — the flag lives in a config file only the installed service reads, so the e2e would have to
    // install a service to exercise it, and an untestable hop is where an inert feature hides
    // (loop 82's lesson, and loop 85's).
    //
    // It also drives what this agent ANNOUNCES on register_agent, which is the input the control
    // plane's presence refresh writes to machine.require_session_policy — so the same flag makes the
    // report hop testable too.
    let require_session_policy = args.iter().any(|a| a == "--require-session-policy");
    let log_clipboard = args.iter().any(|a| a == "--log-clipboard");
    // `--simulate-unattended-host` makes this dev process take the UNATTENDED (SYSTEM per-session
    // helper) posture instead of its true one, so an automated test can reach the code paths that
    // exist only there — today that means ELEVATION (docs/01 §3, loop 87), which is refused outright
    // on a host that runs as the interactive user.
    //
    // The same reasoning as `--require-session-policy` above: the real flag lives in the installed
    // service's shape, not in a config file, so without this the whole elevate feature would be
    // unreachable from any test and an inert implementation would look identical to a working one
    // (loop 82's lesson; loop 86's `SessionAccessState::new(false)` mutation is the concrete
    // version of it).
    //
    // GATED on a lab flag, deliberately. It is a SIMULATION: this process really is the interactive
    // user, so under the unattended posture a REAL `as_user`/elevated command would call
    // `WTSQueryUserToken`, fail `ERROR_PRIVILEGE_NOT_HELD` (0x522), and report a confusing error —
    // loop 84's bug, re-created on purpose. Requiring `--synthetic` or `--log-input` means the
    // command runner is always MOCKED when this is set, so the flag can only ever change the
    // AUTHORIZATION posture and never the token path. A footgun that cannot be pointed at
    // production is not a footgun.
    let simulate_unattended_host = args.iter().any(|a| a == "--simulate-unattended-host");
    if simulate_unattended_host && !(synthetic || log_input) {
        eprintln!(
            "stream: --simulate-unattended-host requires --synthetic or --log-input. It fakes the \
             SYSTEM helper's posture for tests; on a real capture it would only make every as-user \
             command fail ERROR_PRIVILEGE_NOT_HELD, because this process IS the interactive user."
        );
        return 2;
    }
    // TRUE unless simulated away: `stream` is run from a console by a developer, so this process IS
    // the interactive user — the same relationship the attended host has, and not the helper's.
    let host_runs_as_interactive_user = !simulate_unattended_host;
    // `--synthetic-tone` replaces the audio track's source with a 440 Hz tone, so an e2e can assert
    // that a real browser decodes audible sound. Synthetic-only: a test tone over a real capture
    // would hide the machine's real audio behind a fake one.
    let synthetic_tone = args.iter().any(|a| a == "--synthetic-tone");
    if synthetic_tone && !synthetic {
        eprintln!("stream: --synthetic-tone requires --synthetic (it is a test source for the e2e)");
        return 2;
    }
    // `--grant-issuer <hex-ed25519-pubkey>` selects SECURE backstage mode (H1/V4): the session
    // starts with NO backstage dispatcher and denies every backstage request until a
    // `Control::InstallGrant` carrying a grant signed by THIS issuer verifies. The console mints
    // that grant from the control plane (`POST /grant/mint`) and installs it. Absent ⇒ dev mode as
    // before (self-issued full demo grant, with a warning). The value is the same hex the control
    // plane serves at `GET /grant/pubkey` (its `grant_issuer_pubkey`).
    // Absent ⇒ dev mode as before (self-issued full demo grant, with a warning) — `stream` is the
    // local/LAN developer entry point and is documented as such. It is spelled out as
    // `InsecureSelfIssued` rather than inherited from a default, so this stays the ONE deliberate
    // insecure call site instead of the behaviour every new caller silently picks up.
    let backstage_auth: BackstageAuth = match parse_str_arg(args, "--grant-issuer") {
        Some(hex) => match PublicIdentity::from_hex(hex.trim()) {
            Ok(id) => {
                println!("stream: SECURE backstage mode — pinned grant issuer {}", id.to_hex());
                BackstageAuth::SignedBy(id)
            }
            Err(e) => {
                eprintln!("stream: invalid --grant-issuer hex pubkey {hex:?}: {e:?}");
                return 2;
            }
        },
        None => BackstageAuth::InsecureSelfIssued,
    };
    // `--stun <url>` (repeatable) adds STUN servers for WAN NAT traversal; none = LAN/loopback.
    // (TURN for symmetric NAT comes from the signaling RelayAssignment in production, not the CLI.)
    let ice: Vec<IceServer> = args
        .iter()
        .enumerate()
        .filter_map(|(i, a)| (a == "--stun").then(|| args.get(i + 1)).flatten())
        .map(|u| IceServer::stun(u.as_str()))
        .collect();
    // `--transfer-dir <path>` overrides where M8 uploads land / downloads are served from
    // (default `C:\rmt-agent\transfers`).
    let transfer_dir = PathBuf::from(
        parse_str_arg(args, "--transfer-dir").unwrap_or(crate::config::DEFAULT_TRANSFER_DIR),
    );
    // `--recording-dir <path>` turns session recording ON for this run and says where the files go
    // (loop 89). Opt-IN for `stream`, unlike the installed helper which always has a location:
    // `stream` is a developer/test entry point that a person runs on their OWN desktop, and a
    // subcommand that can be told to write a gigabyte of video of the operator's screen into a
    // fixed path is not something to enable by omission. The e2e and the VM probe pass a scratch
    // directory; a developer who wants it says so.
    let recording_dir = parse_str_arg(args, "--recording-dir").map(PathBuf::from);
    let recording_via_service = args.iter().any(|arg| arg == "--recording-service");
    if recording_via_service && recording_dir.is_some() {
        eprintln!("stream: --recording-service and --recording-dir are mutually exclusive");
        return 2;
    }

    // `--identity <path> [--tenant <uuid>]` (M3) registers with the enrolled Ed25519 key so an
    // ENFORCING signaling server (one started without `-insecure-no-agent-auth`) will accept the
    // registration. Absent ⇒ the unauthenticated dev path this subcommand has always taken.
    let identity: Option<AgentIdentity> = match parse_str_arg(args, "--identity") {
        Some(path) => match crate::enroll::read_identity(path) {
            Ok(Some(id)) => {
                let pubkey = id.public_hex();
                println!("stream: authenticated registration — agent pubkey {pubkey}");
                Some(AgentIdentity {
                    pubkey,
                    tenant_id: parse_str_arg(args, "--tenant").map(str::to_string),
                    signer: Arc::new(crate::enroll::IdentitySigner::new(id)),
                })
            }
            Ok(None) => {
                eprintln!("stream: --identity {path} does not exist");
                return 2;
            }
            Err(e) => {
                eprintln!("stream: {e}");
                return 2;
            }
        },
        None => None,
    };

    // A `stop` file lets an operator end the stream early, mirroring the helper's stop path.
    let stop = Arc::new(AtomicBool::new(false));
    spawn_stop_file_watcher(stop.clone());

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("stream: tokio runtime build failed: {e}");
            return 1;
        }
    };
    // The CLI streaming path injects controller input via the real `SendInput` sink by default.
    // `--log-input` swaps in a `LoggingSink` that prints each decoded event as `INJECTED <json>`
    // and does NOT touch `SendInput` — so an automated test (the browser↔agent e2e) can prove
    // input arrived and decoded without moving the real cursor. Composes with `--synthetic`.
    let sink: Arc<dyn InputSink> = if log_input {
        Arc::new(LoggingSink)
    } else {
        Arc::new(SendInputSink::new())
    };

    // Clipboard sink (M9/V3). By default a real `WinClipboard` bridges the OS clipboard both ways.
    // `--log-clipboard` swaps in a `LoggingClipboard` that prints `CLIPBOARD-SET <text>` per inbound
    // set and does NOT touch the real OS clipboard — so the browser↔agent clipboard path is provable
    // in the e2e without an interactive window station and without clobbering the tester's clipboard.
    // Composes with `--synthetic` (headless). Moved into whichever capture branch runs below.
    let clipboard: Box<dyn Clipboard> = if log_clipboard {
        Box::new(LoggingClipboard::default())
    } else {
        Box::new(WinClipboard::new())
    };

    // `serve_session` is generic over the capturer, so branch on the concrete source here. The
    // synthetic path never touches DXGI, letting it run headless.
    let result = if synthetic {
        let (w, h) = SYNTHETIC_DIMS;
        println!("stream: agent device={device} → signaling {url} @ {fps} fps (SYNTHETIC {w}x{h})");
        let capturer =
            rmt_agent_core::SyntheticCapturer::new(w, h, SYNTHETIC_KEYFRAME_INTERVAL);
        rt.block_on(serve_session_with_ice(
            &url, device, capturer, fps, stop, ice,
            SessionOptions {
                sink,
                transfer_dir,
                clipboard: Some(clipboard),
                // `--grant-issuer` (secure mode) pins the issuer; absent ⇒ dev-mode demo grant.
                backstage_auth,
                identity,
                // Mock the guest-input block whenever input itself is mocked (--log-input), so the
                // dev tool never freezes the real machine.
                mock_input: log_input,
                // Mock the reboot for ANY headless test agent: `--log-input` OR `--synthetic`. The
                // gate's e2e specs launch `--synthetic` WITHOUT `--log-input` (backstage/secure_grant/
                // attended/transfer), so a real rebooter there would let a future spot-check reboot the
                // CI box. A synthetic capturer means "test", and a test must never actuate a reboot.
                mock_reboot: log_input || synthetic,
                // Same for tool launches — a headless test agent must never spawn a real GUI tool.
                mock_launch: log_input || synthetic,
                // Same for the command bar — a headless test agent must never execute a command.
                mock_command: log_input || synthetic, mock_lock: log_input || synthetic,
                mock_logoff: log_input || synthetic,
                // `--synthetic-tone`: the audio track carries a test tone (validated above).
                synthetic_tone,
                // The provisional view-only floor (`--require-session-policy`), and the value this
                // agent announces on register_agent.
                require_session_policy,
                // See `--simulate-unattended-host` above: TRUE for a real developer run, FALSE only
                // for a mocked test that needs the SYSTEM helper's posture.
                host_runs_as_interactive_user,
                // Explicit direct or service recording opt-in; both are off by default.
                recording_dir: recording_dir.clone(),
                recording_via_service,
                // The CLI is a developer tool: no administrative ceiling beyond the compiled-in
                // default (which is exactly today's 3 Mbps).
                ..Default::default()
            },
        ))
    } else {
        let capturer = match DxgiCapturer::new() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("stream: DXGI capturer init failed (need an interactive session with a display): {e}");
                return 1;
            }
        };
        println!("stream: agent device={device} → signaling {url} @ {fps} fps ({} ice)", ice.len());
        rt.block_on(serve_session_with_ice(
            &url, device, capturer, fps, stop, ice,
            SessionOptions {
                sink,
                transfer_dir,
                clipboard: Some(clipboard),
                backstage_auth,
                identity,
                mock_input: log_input,
                mock_reboot: log_input || synthetic,
                mock_launch: log_input || synthetic,
                mock_command: log_input || synthetic, mock_lock: log_input || synthetic,
                mock_logoff: log_input || synthetic,
                // As above: the provisional floor and the value announced on register_agent.
                require_session_policy,
                // As above: the CLI runs as the interactive user who launched it, unless a mocked
                // test asked for the unattended posture with `--simulate-unattended-host`.
                host_runs_as_interactive_user,
                // As above: explicit direct or service recording opt-in.
                recording_dir: recording_dir.clone(),
                recording_via_service,
                ..Default::default()
            },
        ))
    };

    match result {
        Ok(()) => {
            println!("stream: done");
            0
        }
        Err(e) => {
            eprintln!("stream: failed: {e}");
            1
        }
    }
}

/// `multi-stream --synthetic [--signaling <ws>] [--device <uuid>] [--fps <n>]`
///
/// Test-harness entry point for the F2 multi-technician shared-control gate. Compiled only when
/// the `test-harness` Cargo feature is active; excluded from release artifacts. Runs
/// [`run_multi_session_stream`] with a [`rmt_agent_core::SyntheticCapturer`] so two or more
/// browser sessions can connect concurrently to the same device without a physical display or an
/// installed Windows service.
///
/// Registers with `multi_session_capable: true`, so the signaling broker admits concurrent
/// controller connections to this device instead of rejecting the second one with "agent busy".
///
/// Uses [`crate::shared_capture::SharedCapture::spawn_recording`] so the `InputCoordinator`'s
/// OS layer is a [`crate::shared_capture::RecordingOsSink`] — no real keyboard injection, no
/// real machine actions. Transfer directory is a disposable temp directory (not the process cwd).
///
/// REQUIRES `--synthetic`. Real DXGI capture is intentionally unsupported here: `SharedCapture`
/// must not hold a `FollowingCapturer` from an interactive process (it would compete with the
/// installed SYSTEM helper and surface on the wrong desktop). Requiring the flag makes the
/// constraint explicit.
#[cfg(feature = "test-harness")]
fn multi_stream_command(args: &[String]) -> i32 {
    if !args.iter().any(|a| a == "--synthetic") {
        eprintln!(
            "multi-stream: --synthetic is required (this entry point is for automated tests; \
             use 'stream' for real capture from an interactive process)"
        );
        return 2;
    }
    let url = parse_str_arg(args, "--signaling")
        .unwrap_or(DEFAULT_SIGNALING_URL)
        .to_string();
    // Loopback enforcement with proper RFC 3986 parsing. The old authority.split(':').next()
    // approach passes ws://127.0.0.1:password@external.example/ws because the ':' split
    // sees "127.0.0.1" before the credentials@host portion. Fix: require ws/wss scheme via
    // strip_prefix (rejects other schemes), reject userinfo '@', then parse host correctly.
    {
        let rest = if let Some(r) = url.strip_prefix("ws://") {
            r
        } else if let Some(r) = url.strip_prefix("wss://") {
            r
        } else {
            eprintln!("multi-stream: signaling URL must use ws:// or wss:// scheme; got {url:?}");
            return 2;
        };
        // Authority: everything up to the first path/query/fragment separator.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        // Reject credentials: any '@' in authority means userinfo@host[:port] form.
        if authority.contains('@') {
            eprintln!(
                "multi-stream: signaling URL must not include credentials (userinfo); \
                 got authority {authority:?}"
            );
            return 2;
        }
        // Extract host. IPv6 literal: [::1] or [::1]:port — host is between '[' and ']'.
        // Otherwise: host or host:port — ':' split gives the host.
        let host = if authority.starts_with('[') {
            authority.trim_start_matches('[').split(']').next().unwrap_or("")
        } else {
            authority.split(':').next().unwrap_or("")
        };
        if host != "127.0.0.1" && host != "localhost" && host != "::1" {
            eprintln!(
                "multi-stream: signaling URL must be loopback (127.0.0.1 / localhost / ::1); \
                 got host {host:?} — test-harness sessions are confined to loopback"
            );
            return 2;
        }
    }
    let device = match parse_str_arg(args, "--device") {
        Some(s) => match s.parse::<uuid::Uuid>() {
            Ok(u) => DeviceId(u),
            Err(e) => {
                eprintln!("multi-stream: invalid --device uuid {s:?}: {e}");
                return 2;
            }
        },
        None => DeviceId::new(),
    };
    let fps = parse_str_arg(args, "--fps")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(DEFAULT_STREAM_FPS);
    // `--identity <path>` — same as `stream`: load an enrolled Ed25519 key so an ENFORCING
    // signaling server accepts the registration. Absent ⇒ unauthenticated (insecure signaling only).
    let identity: Option<AgentIdentity> = match parse_str_arg(args, "--identity") {
        Some(path) => match crate::enroll::read_identity(path) {
            Ok(Some(id)) => {
                let pubkey = id.public_hex();
                println!("multi-stream: authenticated registration — agent pubkey {pubkey}");
                Some(AgentIdentity {
                    pubkey,
                    tenant_id: parse_str_arg(args, "--tenant").map(str::to_string),
                    signer: Arc::new(crate::enroll::IdentitySigner::new(id)),
                })
            }
            Ok(None) => {
                eprintln!("multi-stream: --identity {path} does not exist");
                return 2;
            }
            Err(e) => {
                eprintln!("multi-stream: {e}");
                return 2;
            }
        },
        None => None,
    };
    // insecure-mechanics profile (default, no --grant-issuer): BackstageAuth::Deny — no real
    // Dispatcher is constructed even if a grant frame arrives, so tool RPC side-effects are
    // structurally impossible. secure-required-issuer profile (--grant-issuer present): SignedBy
    // pins the verifying key and enables require_session_policy. No silent InsecureSelfIssued
    // fallback — callers must opt in to an issuer explicitly to get backstage.
    let (backstage_auth, require_session_policy) = match parse_str_arg(args, "--grant-issuer") {
        Some(hex) => match PublicIdentity::from_hex(hex.trim()) {
            Ok(id) => {
                // BLOCKED in production builds (no secure-test feature): force Deny because the
                // backstage executor is not independently inert and a valid InstallGrant would
                // reach the real backend if SignedBy were used.
                //
                // UNBLOCKED when cfg(feature = "secure-test") is active: verify_grant_inert
                // (secure_test_harness.rs) runs all the same Ed25519 checks as production but
                // does not call Dispatcher::with_chain — execution is structurally absent.
                // DO NOT run with the secure-test feature until Codex re-review of isolation.
                #[cfg(feature = "secure-test")]
                {
                    println!(
                        "multi-stream: --grant-issuer present — secure-test-harness mode \
                         (BackstageAuth::SignedBy + verify_grant_inert, no real Dispatcher)"
                    );
                    (BackstageAuth::SignedBy(id), true)
                }
                #[cfg(not(feature = "secure-test"))]
                {
                    let _ = id;
                    println!(
                        "multi-stream: --grant-issuer present — overriding to Deny \
                         (secure profile BLOCKED: build with --features secure-test to enable \
                         verify_grant_inert and unblock this profile)"
                    );
                    (BackstageAuth::Deny, true)
                }
            }
            Err(e) => {
                eprintln!("multi-stream: invalid --grant-issuer hex pubkey {hex:?}: {e:?}");
                return 2;
            }
        },
        None => {
            // insecure-mechanics: deny backstage structurally — no Dispatcher even with a grant.
            (BackstageAuth::Deny, false)
        }
    };
    let (w, h) = SYNTHETIC_DIMS;
    println!(
        "multi-stream: device={device} → signaling {url} @ {fps} fps \
         (SYNTHETIC {w}x{h}, multi_session_capable=true)"
    );
    let stop = Arc::new(AtomicBool::new(false));
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi-stream: tokio runtime");
    // Disposable temp dir: owned by a drop guard so removal happens at normal process exit, not
    // at OS-periodic temp cleanup (which is non-deterministic and not suitable for test teardown).
    // File-transfer writes inside this root are allowed as deliberate disposable test effects;
    // no paths outside this dir are touched.
    struct TempDirGuard(std::path::PathBuf);
    impl Drop for TempDirGuard {
        fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
    }
    let transfer_dir = std::env::temp_dir()
        .join(format!("rmt-multi-stream-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&transfer_dir).ok();
    let _transfer_guard = TempDirGuard(transfer_dir.clone());
    // Compute secure_test_harness BEFORE backstage_auth is moved into the struct literal.
    // BackstageAuth implements Clone but reading the variant after a move is a compile error
    // when the struct initialiser is the first use.
    #[cfg(feature = "secure-test")]
    let secure_test_harness = matches!(backstage_auth, BackstageAuth::SignedBy(_));
    let ms_opts = Arc::new(MultiSessionOpts {
        // The same docs/49 end reporting as the installed helper, so the live e2e gate exercises
        // it. Reports go only for sessions signaling vouched for (a verified ticket's id).
        guest_end_reports: Some(rmt_agent_core::guest_end::GuestEndShared::new()),
        session_tasks: Default::default(),
        device,
        ice: Vec::new(),
        identity,
        transfer_dir,
        clipboard_mode: ClipboardMode::Disabled,
        backstage_auth,
        require_session_policy,
        quality_policy: QualityPolicy::default(),
        max_session: Duration::from_secs(3600),
        recording_dir: None,
        spent_grants: Arc::new(SpentGrants::default()),
        spent_elevations: Arc::new(SpentGrants::default()),
        uninstall_requested: Arc::new(AtomicBool::new(false)),
        directive_hub: None,
        // The lab harness has no tray and never advertises help requests.
        help_hub: None,
        guest_banner_host: String::new(),
        // All machine actions mocked: no real keyboard (recording backend), no real
        // reboot/launch/command/lock/logoff — structurally unable to cause OS side-effects.
        mock_actions: true,
        // When --grant-issuer is present and the secure-test feature is active, each session
        // runs grant verification through verify_grant_inert (no Dispatcher constructed).
        #[cfg(feature = "secure-test")]
        secure_test_harness,
    });
    let capturer = rmt_agent_core::SyntheticCapturer::new(w, h, SYNTHETIC_KEYFRAME_INTERVAL);
    // spawn_recording uses RecordingOsSink instead of SendInputSink — no real keyboard injection.
    let (shared, _capture_thread) =
        crate::shared_capture::SharedCapture::spawn_recording(capturer, fps, stop.clone());
    let shared = Arc::new(shared);
    // Reconnect loop: when the registration WebSocket closes (mux.accept() returns None →
    // run_multi_session_stream returns Ok(())), reconnect immediately so existing in-flight
    // session tasks (A, B) keep serving while a new registration admits new sessions (C).
    // Spawned session tasks outlive each run_multi_session_stream call on the shared Tokio
    // runtime — they are not killed when the mux registration connection is retired.
    // This loop is test-harness only; the production helper in run_helper_stream has its own
    // reconnect loop that is NOT inside this function.
    loop {
        // Guard: exit on stop or uninstall_requested (test-harness: break only, no actual
        // self-uninstall — perform_self_uninstall is never called from this path).
        if stop.load(Ordering::Relaxed)
            || ms_opts.uninstall_requested.load(Ordering::Relaxed)
        {
            break;
        }
        match rt.block_on(run_multi_session_stream(
            &url,
            Arc::clone(&shared),
            stop.clone(),
            Arc::clone(&ms_opts),
        )) {
            Ok(()) => {
                if stop.load(Ordering::Relaxed)
                    || ms_opts.uninstall_requested.load(Ordering::Relaxed)
                {
                    break;
                }
                println!("multi-stream: registration connection ended; reconnecting");
                // Production-like 2 s delay on a clean mux close before re-registering,
                // matching run_helper_stream's behaviour on the non-failed path.
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(e) => {
                eprintln!("multi-stream: connect error: {e}");
                if stop.load(Ordering::Relaxed)
                    || ms_opts.uninstall_requested.load(Ordering::Relaxed)
                {
                    break;
                }
                // Test-only failure backoff: 1 s flat. Does NOT match production —
                // production uses RECONNECT_BACKOFF_MIN = 5 s (see constant above).
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    println!("multi-stream: done");
    0
}

/// `attend --code <CODE> --control-plane-url <URL> [--signaling <ws>] [--reason <text>]
/// [--auto-consent] [--fps <n>] [--synthetic] [--log-input]`: the ATTENDED (on-demand) guest client
/// (docs/12). It generates an EPHEMERAL in-memory identity, redeems the one-time code for a
/// server-minted device id + attend token, shows a consent prompt, and — only on consent — streams
/// over the SAME `serve_session` path unattended uses. It polls session status to exit on end and
/// to pick up a promote-to-unattended request. Nothing is persisted; on exit there is nothing to
/// clean up.
fn attend_command(args: &[String]) -> i32 {
    match attend_params_from_args(args) {
        Ok(params) => run_attend(params),
        Err(code) => code,
    }
}

/// Assemble [`AttendParams`] from the `attend` command line, or an exit code for a missing required
/// argument. Split from [`attend_command`] (which dials a control plane and cannot be tested) so the
/// one property that matters here can be pinned: this is the ONE path that may promote to a
/// permanent install (`allow_promote: true`), and it runs the console UX.
fn attend_params_from_args(args: &[String]) -> Result<AttendParams, i32> {
    let base = match parse_str_arg(args, "--control-plane-url") {
        Some(u) => u.trim().to_string(),
        None => {
            eprintln!("attend: --control-plane-url is required");
            return Err(2);
        }
    };
    let code = match parse_str_arg(args, "--code") {
        Some(c) => c.trim().to_string(),
        None => {
            eprintln!("attend: --code is required");
            return Err(2);
        }
    };
    // `--secure-test-harness`: enable inert execution path for automated policy/grant
    // verification tests. Only meaningful with feature = "secure-test"; the flag is accepted
    // in all builds but validated only when the feature is compiled in.
    #[cfg(feature = "secure-test")]
    let secure_test_harness = args.iter().any(|a| a == "--secure-test-harness");
    #[cfg(feature = "secure-test")]
    if secure_test_harness {
        // P1: --grant-issuer is required (no InsecureSelfIssued fallback).
        // P2: control-plane URL must be loopback.
        // P3: %TEMP% owner check deferred to run_attend (needs OS access).
        if let Err(e) = crate::secure_test_harness::check_secure_test_preconditions(
            parse_str_arg(args, "--grant-issuer"),
            &base,
            false, // temp check deferred
        ) {
            eprintln!("attend: {e}");
            return Err(2);
        }
    }
    Ok(AttendParams {
        base,
        code,
        reason: parse_str_arg(args, "--reason").unwrap_or("").to_string(),
        auto_consent: args.iter().any(|a| a == "--auto-consent")
            || std::env::var("RMT_ATTEND_AUTO_CONSENT").ok().as_deref() == Some("1"),
        fps: parse_str_arg(args, "--fps")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_STREAM_FPS),
        synthetic: args.iter().any(|a| a == "--synthetic"),
        log_input: args.iter().any(|a| a == "--log-input"),
        signaling_override: parse_str_arg(args, "--signaling").map(str::to_string),
        // The installed agent's own command line: default disk, operator stop-file watcher, and the
        // one path that may promote to a permanent install (a technician-initiated action).
        transfer_root: None,
        stop_file: None,
        allow_promote: true,
        ux: AttendUx::Console,
        #[cfg(feature = "secure-test")]
        secure_test_harness,
        pass: None,
    })
}

/// `uri <rmt://attend?code=…&cp=…[&reason=…]>`: the BROWSER HANDOFF entry point, invoked by the
/// shell when a guest clicks a `rmt://` link on the `/join` page (see [`crate::uri`], and
/// [`service::install_service`], which registers the handler).
///
/// # The `%1` argument-injection surface, and how it is closed
///
/// Registering a URL protocol handler for a remote-access binary hands an arbitrary web page part
/// of our command line: the shell substitutes the clicked URI into the registered
/// `"<exe>" uri "%1"`. The classic exploitation of this is a handler that takes the substituted
/// text and *rebuilds* a command line (or an argv vector) from pieces of it — at which point a
/// crafted URI can smuggle a flag the user never asked for. This crate has a live example of what
/// that would cost: `attend`'s argv carries `--auto-consent`, the TEST-ONLY consent bypass, and it
/// is detected by a bare `args.iter().any(|a| a == "--auto-consent")` — so a link whose *code* was
/// the literal string `--auto-consent`, fed back through an argv rebuild, would start a session on
/// a member of the public's machine with no prompt at all.
///
/// So: the URI arrives as **one argv entry**, is re-parsed in-process by [`crate::uri`], and its
/// fields are placed into a typed [`AttendParams`] whose `auto_consent` is hard-coded `false`. No
/// command string is assembled, no process is spawned, no shell is involved, and there is no argv
/// re-parse for a smuggled flag to be found by. ([`crate::uri`] additionally refuses a
/// flag-shaped code, as a belt to this braces.)
fn uri_command(args: &[String]) -> i32 {
    let raw = match crate::uri::uri_arg(args) {
        Ok(u) => u,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    let parsed = match crate::uri::parse_attend_uri(raw) {
        Ok(p) => p,
        Err(e) => {
            // The URI itself is NOT logged: it carries the one-time attend code, which is a bearer
            // secret (same reason `host_main` logs only the subcommand and never full argv).
            eprintln!("uri: refusing to act on this link — {e}");
            return 2;
        }
    };
    run_attend(attend_params_from_uri(parsed))
}

/// Turn a parsed `rmt://attend` link into the attended session's inputs.
///
/// Split out from [`uri_command`] (which is untestable — it dials a control plane) so the one
/// decision that matters can be pinned by a test: **a link launch always faces a human.**
fn attend_params_from_uri(parsed: crate::uri::AttendUri) -> AttendParams {
    AttendParams {
        base: parsed.control_plane_url,
        code: parsed.code,
        reason: parsed.reason,
        // NEVER from the link, and deliberately not from `RMT_ATTEND_AUTO_CONSENT` either — note
        // this is the ONE difference from `attend_command`, which does honour that variable. A
        // web-triggered launch must always face a human: the consent dialog is the only thing
        // standing between a link on an attacker's page and their session on this machine, and an
        // environment variable set for some unrelated reason (a lab image, a CI leftover) must not
        // be able to remove it.
        auto_consent: false,
        // The link carries no tuning knobs. Everything below is the shipped default; adding them to
        // the grammar would widen an attacker-controlled surface for no user benefit (`--synthetic`
        // and `--log-input` are test instrumentation, and `--signaling` would let a link point the
        // guest's media at a server the control plane never named).
        fps: DEFAULT_STREAM_FPS,
        synthetic: false,
        log_input: false,
        signaling_override: None,
        // A link launch runs on an installed machine's console UX, but it must NOT be able to
        // trigger a permanent install: allow_promote stays false so only the deliberate
        // `agent_host attend` command line can promote. Disk + stop-file are the console defaults.
        transfer_root: None,
        stop_file: None,
        allow_promote: false,
        ux: AttendUx::Console,
        #[cfg(feature = "secure-test")]
        secure_test_harness: false,
        pass: None,
    }
}

/// One attended guest session's inputs, independent of HOW the request arrived (the `attend`
/// command line, or a clicked `rmt://` link). Introduced so the URI handler feeds the attended flow
/// through a TYPED value rather than by rebuilding an argv vector — see [`uri_command`] for why
/// that distinction is a security property and not a style preference.
#[derive(Debug, PartialEq)]
pub(crate) struct AttendParams {
    /// Control-plane base URL. Validated by [`crate::uri`] on the link path and by
    /// [`crate::attend::redeem`] on both.
    base: String,
    /// The one-time attend code (a bearer secret — never logged).
    code: String,
    /// Requester text for the consent prompt; sanitized at render time. On the support path the
    /// control-plane-supplied `reason` (from the redeem response) takes precedence over this.
    reason: String,
    /// TEST-ONLY consent bypass. Reachable from the command line, never from a link.
    auto_consent: bool,
    fps: u32,
    synthetic: bool,
    log_input: bool,
    signaling_override: Option<String>,
    /// Where delivered/received files and the chat transcript live. `None` ⇒ the installed agent's
    /// default (`DEFAULT_TRANSFER_DIR`); the support path passes `Some(<per-run root>)` and a `None`
    /// there is a hard error, never a silent default (see [`run_attend_after_redeem`]).
    transfer_root: Option<PathBuf>,
    /// Whether this path may be promoted to a permanent unattended install. `true` only for the
    /// `attend` command line; a clicked link and the public support client must never leave a
    /// service behind on a guest's machine without a deliberate operator action.
    stop_file: Option<PathBuf>,
    /// Whether a status-poll promote request is honoured. See [`AttendParams::stop_file`] ordering
    /// note — kept adjacent so the two "what may this path do to the machine" knobs read together.
    allow_promote: bool,
    /// How the guest reaches this session, which decides the OS-facing behaviours that differ
    /// between the installed agent and the throwaway support client (the stop-file watcher, the
    /// disk root policy).
    ux: AttendUx,
    /// Secure-test-harness mode: grant verification runs real Ed25519 checks but no Dispatcher
    /// is constructed, so no Win32 backend is ever armed. Requires --grant-issuer and a loopback
    /// control-plane URL. Structurally false (field absent) in production builds.
    #[cfg(feature = "secure-test")]
    secure_test_harness: bool,
    /// A GENERIC (pass-mode) Support's verified deployment pass: the redeem response must match it,
    /// and the consent prompt names whom it was issued to. `None` everywhere else.
    pass: Option<PassBinding>,
}

/// What a verified deployment pass (docs/48 C) pins about the server a generic Support talks to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PassBinding {
    /// `wss://host[:port]/ws`, derived from the pass's origin.
    pub(crate) signaling_url: String,
    /// The server's grant issuer key named in the pass (64 lowercase hex).
    pub(crate) grant_issuer_pubkey: String,
    /// The accountable customer the pass was issued to (charset-restricted; safe to display).
    pub(crate) issued_to: String,
}

impl PassBinding {
    /// Whether a redeem response is from the server the pass names: exact equality on both the
    /// signaling URL and the grant issuer key. A compromised server answering within the pinned
    /// origin is an accepted residual (docs/48); a DIFFERENT signaling host or grant key is not.
    pub(crate) fn matches(&self, redeemed: &crate::attend::AttendRedeem) -> bool {
        redeemed.signaling_url == self.signaling_url
            && redeemed.grant_issuer_pubkey.as_deref() == Some(self.grant_issuer_pubkey.as_str())
    }
}

/// How an attended session was entered, which governs the behaviours that must differ between the
/// installed agent's `attend`/link paths and the public support client.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AttendUx {
    /// The installed `agent_host attend` command or a clicked `rmt://` link: the operator's
    /// stop-file watcher runs, and disk defaults to `DEFAULT_TRANSFER_DIR`.
    Console,
    /// The downloadable support client: no stop-file watcher (nothing under `C:\rmt-agent` and
    /// no operator kill-switch on a stranger's machine), and disk is scoped to a per-run root.
    GuestFacing,
}

/// The attended path's [`SessionOptions`], in ONE place.
///
/// Extracted in loop 82 for two reasons that turned out to be the same reason. The synthetic and DXGI
/// branches of [`run_attend`] each carried their own twelve-field copy of this literal, so every new
/// per-session knob had to be added twice by hand or the two paths silently diverged — and the knob
/// being added here, `require_session_policy`, is precisely one whose absence is INVISIBLE (the session
/// just quietly keeps full control).
///
/// The second reason is that `run_attend` cannot be unit-tested: it needs a live transport and a Windows
/// desktop. So the wiring from what the control plane said at redeem to what the session actually
/// enforces had no automated coverage at all, which is the failure loop 80's review caught on the
/// viewer side — a hop exercised only through TYPES is not exercised. As a free function it is a pure
/// mapping and a test can assert it.
fn attend_session_options(
    redeemed: &crate::attend::AttendRedeem,
    sink: Arc<dyn InputSink>,
    transfer_dir: PathBuf,
    backstage_auth: BackstageAuth,
    identity: Option<AgentIdentity>,
    guest_ui: Option<Box<dyn GuestUi>>,
    log_input: bool,
    synthetic: bool,
) -> SessionOptions {
    // Every ACTUATING control is mocked under either lab flag, so a gate run cannot reboot, lock, log
    // off or launch anything on the machine running it. `mock_input` tracks `--log-input` alone, as it
    // always has: a synthetic capture still injects real input.
    let mocked = log_input || synthetic;
    SessionOptions {
        sink,
        transfer_dir,
        clipboard: None,
        backstage_auth,
        identity,
        guest_ui,
        mock_input: log_input,
        mock_reboot: mocked,
        mock_launch: mocked,
        mock_command: mocked,
        // THE FIX (loop 84). `run_attend` runs as the guest's own user in their own session, so it
        // must NOT try to fetch somebody's token: `WTSQueryUserToken` needs SeTcbPrivilege, which an
        // administrator does not hold, and every LaunchTool / RunCommand{as_user} on every attended
        // session failed 0x80070522 because of it. Measured on LAB-VM before and after.
        host_runs_as_interactive_user: true,
        mock_lock: mocked,
        mock_logoff: mocked,
        // LOOP 82. The control plane sets this at redeem when the invite's group enforces view-only.
        // Without it an attended guest had no way to ask for the provisional floor at all — no
        // config.json, no argv flag — so the per-group mandate bound only a viewer that chose to
        // forward the very policy restricting it.
        require_session_policy: redeemed.require_session_policy,
        // NO SESSION LEASE ON THE ATTENDED PATH (docs/25 F03), stated rather than inherited from
        // `Default` because it is a decision and not an omission — the same reasoning as
        // `recording_dir` below it.
        //
        // An attended guest already has a revocation channel, and a better one than a lease:
        // `spawn_attend_status_poller` asks `GET /attended-sessions/status` every three seconds and
        // sets this agent's `stop` when the control plane reports the session ended, so an attended
        // session dies within ~3 s of the technician (or an administrator) ending it — an order of
        // magnitude faster than a lease can manage, and without the controller's cooperation either.
        //
        // Leasing one would also simply break it. Attended and unattended sessions live in SEPARATE
        // tables (`attended_session` vs `session_record`); the renewal endpoint reads `session_record`
        // and knows nothing about attended sessions, so every renewal would 404 and every attended
        // session would die at the grace deadline for no security gain whatsoever. docs/25 F03 says
        // this in as many words: "do not conflate it with unattended sessions".
        session_lease: SessionLeaseMode::NotApplicable,
        // NO RECORDING ON THE ATTENDED HOST (loop 89), stated rather than inherited from `Default`
        // because it is a decision and not an omission.
        //
        // The recorder's TTL is what keeps a staging area from becoming a permanent video vault on
        // someone else's machine, and it is swept at exactly two moments: helper start and session
        // start. An attended client is an ephemeral, uninstalled download that runs ONCE and is not
        // a resident agent — it does NOT delete its own exe (that is deliberate; the receipt tells
        // the customer where the file is) — so on an attended machine NEITHER moment ever comes back
        // after this run: a recording made here
        // would sit on a member of the public's disk with a deletion deadline nothing will ever
        // read. That is the one deployment where the mechanism that makes recording acceptable is
        // structurally absent, so the feature is absent with it. Recording needs a resident agent;
        // when attended recording is wanted, it needs its own sweeper, not this flag flipped.
        recording_dir: None,
        recording_via_service: false,
        #[cfg(feature = "secure-test")]
        secure_test_harness: false, // overridden by run_attend_after_redeem when params.secure_test_harness
        ..Default::default()
    }
}

/// Run one attended guest session end to end: redeem → consent → stream. Shared by the `attend`
/// subcommand and the `rmt://` URI handler.
fn run_attend(params: AttendParams) -> i32 {
    let _ = crate::set_process_dpi_awareness();

    // 1. Ephemeral identity — generated in memory, NEVER written to disk (contrast enroll.rs).
    let identity = rmt_crypto::Identity::generate();
    let pubkey = identity.public_hex();
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();

    // 2. Redeem the one-time code → server-minted ephemeral device id + attend token (blocking; must
    // run BEFORE any tokio runtime exists, like enroll).
    let redeemed = match crate::attend::redeem(&params.base, &params.code, &pubkey, &name) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("attend: {e}");
            return 1;
        }
    };
    println!("attend: redeemed device={} tenant={}", redeemed.device_id, redeemed.tenant_id);

    run_attend_after_redeem(params, redeemed, identity)
}

/// Build the GuestFacing [`AttendParams`] for the public support client: the baked origin, a per-run
/// transfer root, explicit-consent-gated promote, no stop-file watcher, and always a real consent
/// prompt. Exposed so `support.rs` can drive the flow without touching `AttendParams`'s private fields.
///
/// Promote is `true` so the control plane may offer a permanent install during a support session,
/// but the pre-UAC consent dialog in `run_attend_promote` is always shown first — `auto_consent`
/// is `false`, so the guest sees both the session consent and, if promote is offered, the install
/// consent. A guest who clicks Cancel on either stops the flow.
pub(crate) fn support_attend_params(base: String, transfer_root: PathBuf, pass: Option<PassBinding>) -> AttendParams {
    AttendParams {
        pass,
        base,
        code: String::new(), // supplied by the prompt window, redeemed there; unused downstream
        reason: String::new(), // the control plane supplies the reason on the support path
        auto_consent: false, // a public binary must ALWAYS face the consent prompt
        fps: DEFAULT_STREAM_FPS,
        synthetic: false,
        log_input: false,
        signaling_override: None,
        transfer_root: Some(transfer_root),
        stop_file: None,
        allow_promote: true,
        ux: AttendUx::GuestFacing,
        #[cfg(feature = "secure-test")]
        secure_test_harness: false,
    }
}

/// The support client's entry into an attended session (docs/27 step 11): show the code prompt,
/// which redeems WHILE it is up (a one-time code cannot be redeemed twice), then reach the shared
/// consent + stream tail via [`run_attend_after_redeem`].
///
/// DPI awareness must already be set by `support_main` BEFORE the prompt window is created, so this
/// deliberately does NOT call `set_process_dpi_awareness` — doing it after the window exists would
/// leave the window DPI-unaware.
pub(crate) fn run_attend_prompted(params: AttendParams, product: String) -> i32 {
    let identity = rmt_crypto::Identity::generate();
    let pubkey = identity.public_hex();
    let name = std::env::var("COMPUTERNAME").unwrap_or_default();
    let base = params.base.clone();
    let cp_host = crate::uri::control_plane_host(&base);
    // The redeem closure runs on the prompt's worker thread; it owns its inputs so it is Send+Sync.
    let redeem = move |code: &str| crate::attend::redeem_detailed(&base, code, &pubkey, &name);
    let cfg = crate::code_prompt::PromptConfig { product, control_plane_host: cp_host };
    match crate::code_prompt::prompt_for_code(cfg, redeem) {
        crate::code_prompt::PromptOutcome::Cancelled => {
            println!("support: cancelled at the code prompt");
            0
        }
        crate::code_prompt::PromptOutcome::Redeemed(redeemed) => {
            println!(
                "support: redeemed device={} tenant={}",
                redeemed.device_id, redeemed.tenant_id
            );
            run_attend_after_redeem(params, *redeemed, identity)
        }
    }
}

/// Everything after the one-time code has been redeemed: consent, then stream. **This is the ONLY
/// call site of [`crate::attend::obtain_consent_detailed`] in the workspace** — both the console
/// paths ([`run_attend`]) and the support client ([`run_attend_prompted`]) funnel through here, so
/// the consent gate exists in exactly one place and cannot be forgotten on a new entry point.
///
/// It takes the already-redeemed [`crate::attend::AttendRedeem`] and the ephemeral `identity` whose
/// public key was presented at redeem, because the support path must redeem WHILE its prompt window
/// is still up (a one-time code cannot be redeemed twice) and only then reach the consent + stream
/// tail. `identity` and `redeemed` therefore arrive already paired.
///
/// The invariant this split preserves — and the one docs/27 step 20 asks stated truthfully — is:
/// **nothing that reads the guest's screen, input, clipboard or files runs before this function's
/// `obtain_consent_detailed` returns Granted.** Redeem (above) exchanges a code for a token and
/// touches none of those; the capturer, input sink and guest window are all built below the consent
/// gate here.
fn run_attend_after_redeem(
    params: AttendParams,
    redeemed: crate::attend::AttendRedeem,
    identity: rmt_crypto::Identity,
) -> i32 {
    #[cfg(feature = "secure-test")]
    let params_secure_test_harness = params.secure_test_harness;
    let AttendParams {
        base,
        code: _,
        reason,
        auto_consent,
        fps,
        synthetic,
        log_input,
        signaling_override,
        transfer_root,
        stop_file,
        allow_promote,
        ux,
        pass,
        ..
    } = params;
    let pubkey = identity.public_hex();

    // 2b. A generic Support's server answer must be the server its deployment pass names (docs/48
    // "Binding the redeem response to the pass"). Checked BEFORE consent: a guest is never asked to
    // allow a session with a server the pass does not cover. The decline is recorded either way.
    if let Some(binding) = &pass {
        if !binding.matches(&redeemed) {
            tracing::error!(
                signaling = %redeemed.signaling_url,
                expected = %binding.signaling_url,
                "attend: the redeem response does not match the deployment pass; refusing before consent"
            );
            let _ = crate::attend::post_consent(&base, &redeemed.attend_token, false, &crate::attend::consent_user());
            if ux == AttendUx::GuestFacing {
                support_failure_dialog(&rmt_agent_core::support_ui::Failure::PassRejected);
            }
            return 1;
        }
    }

    // 3. Consent. No consent ⇒ tell the control plane (so it records the decline) and exit.
    //
    // The prompt NAMES the control-plane host. `validate_control_plane_url` proved the URL is https
    // (or loopback http); it cannot prove whose it is, and a code — read over the phone, or clicked
    // as a `rmt://` link on a page the attacker controls — can point here at anyone's control
    // plane. That one line is the difference between consenting to a support session and consenting
    // to a support session with whoever sent the link.
    //
    // The reason shown prefers the control-plane-supplied one (the support path has no link to carry
    // it), falling back to the caller-supplied `reason` (the `--reason` command-line / link value).
    let cp_host = crate::uri::control_plane_host(&base);
    let reason_text = redeemed.reason.clone().unwrap_or(reason);
    let issued_to = pass.as_ref().map(|b| b.issued_to.as_str());
    match crate::attend::obtain_consent_with_issuer(&reason_text, &cp_host, issued_to, auto_consent) {
        crate::attend::ConsentOutcome::Granted => {}
        crate::attend::ConsentOutcome::Declined => {
            let _ = crate::attend::post_consent(&base, &redeemed.attend_token, false, &crate::attend::consent_user());
            println!("attend: user DECLINED — exiting without streaming");
            if ux == AttendUx::GuestFacing {
                support_failure_dialog(&rmt_agent_core::support_ui::Failure::ConsentDeclined);
            }
            return 0;
        }
        crate::attend::ConsentOutcome::CouldNotDisplay => {
            // Distinct from a decline: the guest never saw a prompt, so "you declined" would be a
            // lie. Still record a non-accept with the control plane and fail closed.
            let _ = crate::attend::post_consent(&base, &redeemed.attend_token, false, &crate::attend::consent_user());
            eprintln!("attend: consent prompt could not be displayed — declining (no interactive desktop)");
            if ux == AttendUx::GuestFacing {
                support_failure_dialog(&rmt_agent_core::support_ui::Failure::ConsentUndisplayable);
            }
            return 1;
        }
    }
    if let Err(e) = crate::attend::post_consent(&base, &redeemed.attend_token, true, &crate::attend::consent_user()) {
        eprintln!("attend: could not record consent: {e}");
        return 1;
    }
    println!("attend: consent granted — starting session");

    let device = match redeemed.device_id.parse::<uuid::Uuid>() {
        Ok(u) => DeviceId(u),
        Err(e) => {
            eprintln!("attend: control plane returned a non-uuid device id {:?}: {e}", redeemed.device_id);
            return 1;
        }
    };
    let signaling_url = signaling_override.unwrap_or_else(|| redeemed.signaling_url.clone());

    // 4. On-screen indicator: a visible, standing cue for the whole session (product + legal
    // requirement). Best-effort — a headless/Session-0 context cannot show it, and that must not
    // block streaming. NOTE: a persistent topmost indicator WINDOW is a hardware-gated follow-up;
    // today this emits a prominent, auditable marker at start and end. See docs/12 §7.
    println!("attend: SESSION INDICATOR — remote support session ACTIVE for device {device}");

    // 5. The streaming identity is the ephemeral key, so an ENFORCING signaling server authenticates
    // the guest exactly as it does an enrolled agent (RMTAGENTAUTHv1).
    let agent_identity = AgentIdentity {
        pubkey,
        tenant_id: Some(redeemed.tenant_id.clone()),
        signer: Arc::new(crate::enroll::IdentitySigner::new(identity)),
    };

    let stop = Arc::new(AtomicBool::new(false));
    // The operator's stop-file kill switch runs ONLY on the installed-agent console path. The public
    // support client (GuestFacing) never spawns it: there is nothing under `C:\rmt-agent` on a
    // stranger's machine to watch, and an operator kill switch on a member of the public's box is
    // neither wanted nor ours to place. The Console path logs which mechanism trips `stop`.
    if ux == AttendUx::Console {
        let watch_path = stop_file
            .clone()
            .unwrap_or_else(|| PathBuf::from(STOP_FILE));
        spawn_stop_file_watcher_at(stop.clone(), watch_path);
    }
    // 6. Status poller: exit on `ended`, pick up a promote request. Blocking reqwest on its own
    // thread. `allow_promote` gates the promote-to-permanent flow — false for clicked join-links,
    // true for both the CLI attend path and the downloaded support client.
    //
    // The pending_installer_waiter Arc carries the JoinHandle of a background Setup observer back
    // to this function: we join it after the streaming session ends so that the Support process
    // cannot exit (via process::exit or normal return) while elevated Setup is still running.
    let pending_installer_waiter: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut poller_guard = PollerGuard::new(
        stop.clone(),
        spawn_attend_status_poller(
            base.clone(),
            redeemed.attend_token.clone(),
            stop.clone(),
            allow_promote,
            pending_installer_waiter.clone(),
        ),
        pending_installer_waiter.clone(),
    );

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("attend: tokio runtime build failed: {e}");
            return 1;
        }
    };
    // docs/53: a real attended session can ask the guest for admin rights; its sink forwards input to
    // the elevated helper while one is granted. The mocked `--log-input` path has nothing to elevate.
    let (sink, admin_rights): (Arc<dyn InputSink>, _) = if log_input {
        (Arc::new(LoggingSink), None)
    } else {
        let (elevated, rights, updates) =
            crate::admin_rights::AdminRights::for_attended_session(Arc::new(SendInputSink::new()));
        (elevated, Some((rights, updates)))
    };
    // Disk scoping (docs/27 step 7). The support path passes a per-run root and a `None` there is a
    // hard error — NEVER a silent fall back to the installed agent's machine-wide directory. The
    // console path defaults to `DEFAULT_TRANSFER_DIR` as before.
    let transfer_dir = match (ux, transfer_root) {
        (AttendUx::GuestFacing, Some(root)) => root,
        (AttendUx::GuestFacing, None) => {
            eprintln!("support: a guest-facing session requires a per-run transfer root — refusing");
            support_failure_dialog(&rmt_agent_core::support_ui::Failure::WorkspaceSetupFailed);
            return 1;
        }
        (AttendUx::Console, Some(root)) => root,
        (AttendUx::Console, None) => PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
    };

    // H1 for the attended guest: pin the grant issuer the control plane advertised at redeem, so a
    // technician gets exactly the capabilities `BackstageCapsFor` signed for them. No key ⇒ DENY.
    // Never self-issued: the guest consented to a support session, not to `ShellAsSystem`.
    let backstage_auth = attend_backstage_auth(redeemed.grant_issuer_pubkey.as_deref());
    println!(
        "attend: backstage {}",
        match &backstage_auth {
            BackstageAuth::SignedBy(_) => "requires a control-plane-signed grant",
            _ => "DISABLED (control plane advertised no grant issuer key)",
        }
    );
    // Loop 82: the attended path's opt-in to the provisional view-only floor. The control plane sets
    // this at redeem when the invite's group enforces view-only; before it existed an attended guest
    // had no way to ask for the floor AT ALL (no config.json, no argv flag), so the per-group mandate
    // bound only a viewer that chose to forward the policy it was being restricted by.
    //
    // Printed because it is the observable a VM run reads back — like the guest-window caption, it
    // states which regime the session actually opened in rather than which one was configured.
    println!(
        "attend: session policy {}",
        if redeemed.require_session_policy {
            "REQUIRED — opening VIEW-ONLY until a signed policy verifies"
        } else {
            "not required by this group"
        }
    );

    // The on-screen indicator + guest chat window (docs/01 §5, §7; docs/12 §5). ATTENDED HOST: this
    // process runs as the guest's own user in their interactive session, so the window is an
    // ordinary same-integrity window on their desktop.
    //
    // `--auto-consent` renders it OFF-SCREEN but still CREATES it, exactly as docs/12 §5 requires —
    // the indicator is a product requirement, so a lab flag may make it invisible but must never be
    // able to skip it. That is what keeps "the window exists" assertable in the e2e that runs with
    // the flag set.
    let guest_info = SessionInfo {
        control_plane_host: cp_host.clone(),
        reason: crate::uri::sanitize_reason(&reason_text),
    };
    let make_guest_ui = || -> Option<Box<dyn GuestUi>> {
        Some(if auto_consent {
            Box::new(crate::guest_window::WindowGuestUi::offscreen(guest_info.clone()))
        } else {
            Box::new(crate::guest_window::WindowGuestUi::new(guest_info.clone()))
        })
    };

    let result = if synthetic {
        let (w, h) = SYNTHETIC_DIMS;
        println!("attend: streaming device={device} → signaling {signaling_url} @ {fps} fps (SYNTHETIC {w}x{h})");
        let capturer = rmt_agent_core::SyntheticCapturer::new(w, h, SYNTHETIC_KEYFRAME_INTERVAL);
        let mut opts = attend_session_options(&redeemed, sink, transfer_dir, backstage_auth,
            Some(agent_identity), make_guest_ui(), log_input, synthetic);
        opts.admin_rights = admin_rights;
        #[cfg(feature = "secure-test")]
        { opts.secure_test_harness = params_secure_test_harness; }
        rt.block_on(serve_session_with_ice(&signaling_url, device, capturer, fps, stop.clone(), Vec::new(), opts))
    } else {
        // Capture availability is checked HERE, AFTER consent — never before it, so nothing reads
        // the screen until the guest has said Yes (docs/27: this is what lets the page say "nothing
        // is sent until you say Yes"). This is also the check that actually fails on the machines it
        // exists to catch: DXGI desktop duplication init fails over Remote Desktop and on headless
        // hosts. (A one-frame pull for the RDP case where init succeeds but the first frame does not
        // is the VM-verified refinement noted in docs/28; init failure is the common case.)
        let capturer = match DxgiCapturer::new() {
            Ok(c) => c,
            Err(e) => {
                eprintln!(
                    "attend: screen capture is unavailable on this machine — this is expected over \
                     Remote Desktop and on some virtual machines: {e}"
                );
                if ux == AttendUx::GuestFacing {
                    support_failure_dialog(&rmt_agent_core::support_ui::Failure::CaptureUnavailable);
                }
                return 1;
            }
        };
        println!("attend: streaming device={device} → signaling {signaling_url} @ {fps} fps");
        let mut opts = attend_session_options(&redeemed, sink, transfer_dir, backstage_auth,
            Some(agent_identity), make_guest_ui(), log_input, synthetic);
        opts.admin_rights = admin_rights;
        #[cfg(feature = "secure-test")]
        { opts.secure_test_harness = params_secure_test_harness; }
        rt.block_on(serve_session_with_ice(&signaling_url, device, capturer, fps, stop.clone(), Vec::new(), opts))
    };

    println!("attend: SESSION INDICATOR — remote support session ENDED for device {device}");
    poller_guard.shutdown();
    match result {
        Ok(()) => {
            println!("attend: done");
            0
        }
        Err(e) => {
            eprintln!("attend: session failed: {e}");
            1
        }
    }
}

/// Poll attended session status on a background thread: flip `stop` when the control plane reports
/// the session `ended`, and run the promote-to-unattended flow when a promote enrollment token
/// appears (docs/12 §8). Uses the blocking attend client, off the tokio runtime.
/// Show a customer-facing failure dialog for the SUPPORT client. Called only on the GuestFacing
/// path; the console/link paths log to stderr. Copy comes from the shared [`rmt_agent_core::support_ui`]
/// table so it obeys docs/27's "may NOT claim" list. Best-effort — a failure to display is ignored.
#[cfg(windows)]
pub(crate) fn support_failure_dialog(failure: &rmt_agent_core::support_ui::Failure) {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};
    let m = rmt_agent_core::support_ui::message(failure);
    let mut body = m.body;
    if let Some(detail) = m.detail {
        body.push_str("\n\n");
        body.push_str(&detail);
    }
    let text = HSTRING::from(body);
    let title = HSTRING::from(m.title);
    // SAFETY: owned HSTRING buffers; NULL owner is fine for a standalone process dialog.
    unsafe {
        let _ = MessageBoxW(None, &text, &title, MB_OK | MB_ICONWARNING);
    }
}

#[cfg(not(windows))]
pub(crate) fn support_failure_dialog(_failure: &rmt_agent_core::support_ui::Failure) {}

/// RAII owner for the status-poller lifecycle.
///
/// `Drop` signals stop, joins the poller thread (ensuring any in-flight `run_attend_promote`
/// has pushed its installer handle before the drain), then drains and joins every pending
/// installer observer. Every exit point in `run_attend_after_redeem` — runtime failure,
/// missing transfer root, DXGI unavailability, normal session end — runs the identical
/// shutdown sequence, so no poller thread or installer observer is ever orphaned.
struct PollerGuard {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    pending: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl PollerGuard {
    fn new(
        stop: Arc<AtomicBool>,
        handle: std::thread::JoinHandle<()>,
        pending: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
    ) -> Self {
        Self { stop, handle: Some(handle), pending }
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let waiters: Vec<_> = self.pending.lock().unwrap().drain(..).collect();
        for w in waiters {
            tracing::info!("attend: waiting for background installer observer (Setup may still be running)");
            let _ = w.join();
        }
    }
}

impl Drop for PollerGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Returns true when a new promote request should be dispatched: stop has not fired AND the
/// token is new (differs from the last accepted token to avoid re-prompting the guest for the
/// same technician request). Both the post-sleep and post-I/O stop checks must pass before
/// this is called; this is the final admission gate before `run_attend_promote` is entered.
fn should_dispatch_promote(stop: &AtomicBool, last_token: Option<&str>, new_token: &str) -> bool {
    !stop.load(Ordering::Relaxed) && last_token != Some(new_token)
}

fn spawn_attend_status_poller(
    base: String,
    attend_token: String,
    stop: Arc<AtomicBool>,
    allow_promote: bool,
    pending_installer_waiter: Arc<std::sync::Mutex<Vec<std::thread::JoinHandle<()>>>>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        // Track the last promotion token we attempted so we do not re-prompt the guest for the
        // same technician request. A new token value means the technician re-issued promote (e.g.
        // after a guest decline), which IS a new authorized attempt → re-prompt.
        let mut last_promote_token: Option<String> = None;
        while !stop.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_secs(3));
            // Check stop after the blocking sleep — session may have ended while we waited.
            if stop.load(Ordering::Relaxed) { break; }
            match crate::attend::get_status(&base, &attend_token) {
                Ok(st) => {
                    // Check stop after blocking network I/O — session may have ended while
                    // the status call was in flight; do not start new work on a dead session.
                    if stop.load(Ordering::Relaxed) { break; }
                    // Promote leaves a PERMANENT service behind. It is honoured only where the
                    // caller allowed it (`allow_promote: true`). A clicked join-link sets false
                    // so the control plane cannot silently install itself from a link click.
                    if allow_promote {
                        if let Some(tok) = st.promote_enrollment_token.as_deref() {
                            // `should_dispatch_promote` is the final admission gate: stop must not
                            // have fired AND the token must be new (different technician request).
                            // Already-admitted work (handle in pending_installer_waiter) is fully
                            // owned and will be joined on shutdown regardless of stop.
                            if should_dispatch_promote(&stop, last_promote_token.as_deref(), tok) {
                                last_promote_token = Some(tok.to_string());
                                if let Some(handle) = run_attend_promote(
                                    &base,
                                    &attend_token,
                                    st.installer_available,
                                    st.promote_attempt_nonce.clone(),
                                ) {
                                    // Setup is still running after the 5-minute wait: push the
                                    // JoinHandle so run_attend_after_redeem joins it before exit.
                                    // Vec (not Option) ensures a prior handle is never silently
                                    // overwritten by a subsequent promote request.
                                    pending_installer_waiter.lock().unwrap().push(handle);
                                }
                            }
                            // Same token or stop fired → do not re-prompt or start new work.
                        }
                    } else if !allow_promote && st.promote_enrollment_token.is_some() {
                        // Observable, and honest: the control plane asked, and this path said no.
                        tracing::warn!("attend: promote requested but this path may not promote — ignoring");
                    }
                    if st.state == "ended" {
                        println!("attend: control plane reports session ended — stopping");
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(e) => tracing::warn!(error = %e, "attend: status poll failed (will retry)"),
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Attend → promote: Setup-bundle download + launch (docs/12 §8, docs/40)
// ---------------------------------------------------------------------------
//
// The promote flow is reached via `allow_promote: true`, which is set both on the `attend` CLI
// and on the public support client (`DeskRallySupport.exe`). Promotion never happens silently.
//
// When the technician issues POST /attended-sessions/{id}/promote, the control plane stashes a
// single-use enrollment token. The guest's status poll returns it together with
// `installer_available`, indicating whether the managed Setup bundle is published.
//
// If the bundle is available, the guest:
//   1. Asks for explicit pre-consent (attend_promote_consent_dialog).
//   2. Downloads the bundle via GET /attended-sessions/installer (Bearer attend token).
//      The bundle is a ZIP containing DeskRallySetup.exe, DeskRallyAgent.msi, enrollment.token.
//   3. Extracts the ZIP to a UUID temp directory.
//   4. Launches DeskRallySetup.exe (which handles its own UAC via its embedded manifest).
//   5. Waits for Setup to exit (up to 5 minutes).
//   6. Reports success/failure to POST /attended-sessions/promote-complete.
//   7. Cleans up the extracted temp directory.
//
// DeskRallySetup.exe is the deployment-validated, signed installer. It enrolls using the
// enrollment.token it reads from its own directory, installs the MSI, and registers the service.
// The Support binary is NEVER staged as a service binary.

/// Exact set of filenames the installer bundle is permitted to contain (case-insensitive).
/// Any entry whose name does not match one of these exactly — including names with path
/// separators, drive letters, ADS colons, or `..` components — is rejected and the whole
/// extraction fails closed. Files are written under the canonical (allowlisted) name, never
/// the raw ZIP entry name, so a crafted name cannot influence the output path.
const BUNDLE_ALLOWED_FILES: &[&str] =
    &["DeskRallySetup.exe", "DeskRallyAgent.msi", "enrollment.token", "README.txt"];

/// Files that must be present for the bundle to be considered complete.
const BUNDLE_REQUIRED_FILES: &[&str] =
    &["DeskRallySetup.exe", "DeskRallyAgent.msi", "enrollment.token"];

/// Per-entry size cap (128 MiB).
const BUNDLE_MAX_ENTRY_BYTES: u64 = 128 * 1024 * 1024;

/// Total decompressed size cap (256 MiB).
const BUNDLE_MAX_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

/// Extract the installer bundle ZIP to a fresh temp directory and return the path to
/// `DeskRallySetup.exe` within it.
///
/// Uses `zip::ZipArchive` so that entries written by Go's `archive/zip` streaming writer
/// (local headers with zero sizes + trailing data descriptors) are handled correctly via the
/// central directory. A hand-rolled local-header parser returns empty files for these ZIPs.
///
/// Only entries on the exact [`BUNDLE_ALLOWED_FILES`] allowlist are extracted; all others
/// (unexpected names, duplicates, missing required entries) cause the extraction to fail
/// closed and clean up the temp directory. The caller is responsible for deleting the parent
/// directory after a successful extraction once the installer has finished.
fn extract_setup_zip(zip_bytes: &[u8]) -> Result<PathBuf, String> {
    use std::io::Read as _;

    let dest = std::env::temp_dir()
        .join("DeskRally")
        .join(format!("promote-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dest)
        .map_err(|e| format!("could not create extract directory: {e}"))?;

    // Wrap the cleanup so early returns don't leak the temp dir on validation failure.
    let cleanup = |dest: &std::path::Path| { let _ = std::fs::remove_dir_all(dest); };

    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor).map_err(|e| {
        cleanup(&dest);
        format!("installer bundle is not a valid ZIP: {e}")
    })?;

    // Pass 1: validate all entries (name allowlist, duplicates, size bounds).
    let n = archive.len();
    let mut canonical_names: Vec<&'static str> = Vec::with_capacity(n);
    let mut total_bytes: u64 = 0;

    for i in 0..n {
        let entry = archive.by_index(i).map_err(|e| {
            cleanup(&dest);
            format!("could not read installer bundle entry {i}: {e}")
        })?;
        let raw_name = entry.name().to_string();
        let uncompressed = entry.size();
        drop(entry); // release borrow so archive is usable again

        // Exact allowlist: anything not matching is an unexpected file — fail closed.
        let canonical: &'static str = BUNDLE_ALLOWED_FILES
            .iter()
            .find(|&&f| f.eq_ignore_ascii_case(&raw_name))
            .copied()
            .ok_or_else(|| {
                cleanup(&dest);
                format!("installer bundle contains unexpected entry {raw_name:?} — bundle rejected")
            })?;

        // Duplicates fail closed.
        if canonical_names.contains(&canonical) {
            cleanup(&dest);
            return Err(format!("installer bundle contains duplicate entry {raw_name:?}"));
        }
        canonical_names.push(canonical);

        // Size bounds.
        if uncompressed > BUNDLE_MAX_ENTRY_BYTES {
            cleanup(&dest);
            return Err(format!("installer bundle entry {canonical:?} exceeds entry size limit"));
        }
        total_bytes = total_bytes.saturating_add(uncompressed);
        if total_bytes > BUNDLE_MAX_TOTAL_BYTES {
            cleanup(&dest);
            return Err("installer bundle exceeds total size limit".to_string());
        }
    }

    // Required entries must all be present.
    for &req in BUNDLE_REQUIRED_FILES {
        if !canonical_names.contains(&req) {
            cleanup(&dest);
            return Err(format!("installer bundle is missing required file: {req}"));
        }
    }

    // Pass 2: extract, writing under the canonical allowlisted name (not the raw entry name).
    for (i, &canonical) in canonical_names.iter().enumerate() {
        let mut entry = archive.by_index(i).map_err(|e| {
            cleanup(&dest);
            format!("could not re-read installer bundle entry {i}: {e}")
        })?;
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data).map_err(|e| {
            cleanup(&dest);
            format!("could not read installer bundle entry {canonical}: {e}")
        })?;
        let out_path = dest.join(canonical);
        std::fs::write(&out_path, &data).map_err(|e| {
            cleanup(&dest);
            format!("could not extract {canonical}: {e}")
        })?;
    }

    Ok(dest.join("DeskRallySetup.exe"))
}

/// Owns a Windows process `HANDLE` and closes it when dropped. `Send` so it can move into the
/// background waiter thread without the caller having to explicitly close it first.
struct OwnedProcessHandle(HANDLE);
impl Drop for OwnedProcessHandle {
    fn drop(&mut self) {
        unsafe { let _ = CloseHandle(self.0); }
    }
}
// SAFETY: Windows process HANDLEs are valid across threads.
unsafe impl Send for OwnedProcessHandle {}

/// Error from `launch_setup_exe`.
enum SetupLaunchError {
    /// Setup is still running after the 5-minute wait (WAIT_TIMEOUT), or `WaitForSingleObject`
    /// returned WAIT_FAILED while the process appears alive (exit code = STILL_ACTIVE / 259).
    /// The caller MUST call `spawn_setup_waiter` with this handle; closing it here would leak the
    /// reference without observing termination.
    StillRunning(OwnedProcessHandle),
    /// Launch failed or the wait/exit-code path returned a terminal error.
    Failed(String),
}

/// Launch `DeskRallySetup.exe` via `ShellExecuteExW("open")` and wait up to 5 minutes.
/// Setup handles its own UAC elevation via its embedded application manifest.
///
/// Returns `Ok(exit_code)` when Setup terminated, `Err(StillRunning(handle))` when the 5-minute
/// wait elapsed with the process still alive, or `Err(Failed(...))` for any launch error.
/// The StillRunning variant MUST be handled by calling `spawn_setup_waiter` — do not drop the
/// handle without that call or the process becomes untraceable.
fn launch_setup_exe(setup_path: &std::path::Path) -> Result<i32, SetupLaunchError> {
    use windows::core::HSTRING;
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

    // The bundle comes from whatever control plane the attended link named, and Setup elevates, so
    // its signature is the trust decision: Authenticode-valid AND our pinned publisher, exactly the
    // check the auto-updater applies to the MSI (security audit 2026-10-18, agent SEC-002). Before
    // this, a hostile or compromised control plane was one UAC click from running its own code.
    crate::update_download::verify_authenticode(setup_path).map_err(|e| {
        SetupLaunchError::Failed(format!(
            "DeskRallySetup.exe is not signed by DeskRally's publisher; not launched ({e})"
        ))
    })?;
    let verb = HSTRING::from("open"); // Setup's own manifest requests elevation
    let file = HSTRING::from(
        setup_path.to_str().ok_or_else(|| SetupLaunchError::Failed("Setup path is not valid UTF-8".to_string()))?,
    );

    // SAFETY: SHELLEXECUTEINFOW is a C struct; zeroing sets all handles/pointers to NULL/0.
    unsafe {
        let mut info: SHELLEXECUTEINFOW = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS;
        info.lpVerb = PCWSTR(verb.as_ptr());
        info.lpFile = PCWSTR(file.as_ptr());
        info.nShow = 1; // SW_SHOWNORMAL

        ShellExecuteExW(&mut info).map_err(|e| {
            SetupLaunchError::Failed(if e.code().0 as u32 == 0x8007_04C7 {
                "installer UAC prompt was dismissed by the user".to_string()
            } else {
                format!("could not launch DeskRallySetup.exe: {e}")
            })
        })?;

        if info.hProcess.is_invalid() {
            return Err(SetupLaunchError::Failed(
                "Setup process handle unavailable — UAC may have been dismissed".to_string(),
            ));
        }

        // Wait up to 5 minutes: enroll (network) + MSI install + service registration.
        // WAIT_OBJECT_0 (0x0): exited.  WAIT_TIMEOUT (0x102): still alive.  WAIT_FAILED (0xFFFF_FFFF): error.
        let wait = WaitForSingleObject(info.hProcess, 300_000);
        if wait.0 == 0x0000_0102 {
            // WAIT_TIMEOUT — process still alive. Wrap the handle and hand it to the caller for
            // the background waiter. Do NOT close the handle here.
            return Err(SetupLaunchError::StillRunning(OwnedProcessHandle(info.hProcess)));
        }

        // WAIT_OBJECT_0 or WAIT_FAILED: attempt to read exit code either way.
        let mut exit_code: u32 = 1;
        let gc_ok = GetExitCodeProcess(info.hProcess, &mut exit_code).is_ok();

        // Fail closed on unknown liveness: STILL_ACTIVE (259) or GetExitCodeProcess failure both
        // mean we cannot confirm the process has stopped — hand the handle to the background waiter
        // rather than closing it here and losing our only reference to the running process.
        if exit_code == 259 || !gc_ok {
            return Err(SetupLaunchError::StillRunning(OwnedProcessHandle(info.hProcess)));
        }

        let _ = CloseHandle(info.hProcess);
        Ok(exit_code as i32)
    }
}

/// Spawn a background thread that waits (up to 24 hours) for `handle` to exit, then posts the
/// install outcome to the control plane and cleans up the extracted temp directory.
/// Called when `launch_setup_exe` returns `StillRunning`; must not be skipped.
///
/// Returns the `JoinHandle` so the caller can join it before the process exits — this is the
/// mechanism that prevents `process::exit` from killing the observer while elevated Setup is
/// still running. `run_attend_after_redeem` stores the handle in an `Arc<Mutex<Option<...>>>`
/// and joins it after the streaming session ends but before returning.
fn spawn_setup_waiter(
    handle: OwnedProcessHandle,
    extract_dir: Option<PathBuf>,
    base: String,
    attend_token: String,
    attempt_nonce: Option<String>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        use windows::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};

        // Bounded wait: 24 hours is the same age-bound the server applies.
        // WAIT_OBJECT_0 = 0x0 (exited), WAIT_TIMEOUT = 0x102, WAIT_FAILED = 0xFFFF_FFFF.
        let wait = unsafe { WaitForSingleObject(handle.0, 24_u32 * 3600 * 1000) };
        let mut exit_code: u32 = 1;
        let gc_ok = unsafe { GetExitCodeProcess(handle.0, &mut exit_code).is_ok() };
        drop(handle); // CloseHandle via OwnedProcessHandle::drop

        // Positively observed exit: WAIT_OBJECT_0 + GetExitCodeProcess succeeded + not STILL_ACTIVE.
        // Only when this is true can we be certain the installer is no longer reading the files.
        let positively_exited = wait.0 == 0x0000_0000 && gc_ok && exit_code != 259;

        if positively_exited {
            if let Some(ref dir) = extract_dir {
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(path = %dir.display(), error = %e, "attend: waiter could not clean up extracted Setup dir");
                }
            }
        } else {
            // Timeout, WAIT_FAILED, or unknown liveness: retain files.
            // The installer may still be reading them; deleting would corrupt an in-progress install.
            tracing::warn!(
                wait = %format!("{:#x}", wait.0), gc_ok,
                "attend: waiter: installer exit not positively observed — retaining extracted files"
            );
        }

        let exited_ok = positively_exited && exit_code == 0;
        let err_str;
        let error: Option<&str> = if exited_ok {
            None
        } else if !positively_exited {
            err_str = if wait.0 == 0x0000_0102 {
                "installer did not complete within 24 hours".to_string()
            } else {
                format!("installer liveness unknown (wait: {:#x}, GetExitCodeProcess: {})", wait.0, if gc_ok { "ok" } else { "failed" })
            };
            Some(&err_str)
        } else {
            err_str = format!("installer exited with code {exit_code}");
            Some(&err_str)
        };

        if let Err(e) = crate::attend::post_promote_complete(
            &base, &attend_token, exited_ok, error, attempt_nonce.as_deref(),
        ) {
            tracing::warn!(error = %e, "attend: background waiter could not report promote result to control plane");
        }
    })
}

/// Show the pre-download consent dialog. Returns false if the guest clicked Cancel.
#[cfg(windows)]
fn attend_promote_consent_dialog() -> bool {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONINFORMATION, MB_OKCANCEL, IDOK,
    };
    let title = HSTRING::from("DeskRally — Remote Access Request");
    let text = HSTRING::from(
        "Your technician has requested to install permanent remote access on this computer.\n\n\
         Clicking OK will download and launch the DeskRally installer. Windows will ask for \
         administrator permission during installation.\n\n\
         Click Cancel to decline without installing anything.",
    );
    // SAFETY: owned HSTRING buffers; NULL hwnd is fine for a standalone dialog.
    unsafe { MessageBoxW(None, &text, &title, MB_OKCANCEL | MB_ICONINFORMATION) == IDOK }
}

#[cfg(not(windows))]
fn attend_promote_consent_dialog() -> bool { true }

/// Dialog shown when the managed installer is not available on this server.
#[cfg(windows)]
fn attend_promote_no_installer_dialog() {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_ICONWARNING, MB_OK};
    let title = HSTRING::from("DeskRally — Installer Not Available");
    let text = HSTRING::from(
        "Your technician requested permanent installation, but the automated installer \
         is not available on this server.\n\n\
         Please ask your technician for a manual installer link or bundle.",
    );
    // SAFETY: owned HSTRING buffers; NULL hwnd is fine for a standalone dialog.
    unsafe {
        let _ = MessageBoxW(None, &text, &title, MB_OK | MB_ICONWARNING);
    }
}

#[cfg(not(windows))]
fn attend_promote_no_installer_dialog() {}

/// Show a result dialog (success or failure) after the promote attempt.
#[cfg(windows)]
fn attend_promote_result_dialog(success: bool, detail: Option<&str>) {
    use windows::core::HSTRING;
    use windows::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONINFORMATION, MB_ICONWARNING, MB_OK,
    };
    let (title_s, body_s, icon) = if success {
        (
            "DeskRally — Installation Complete",
            // "Setup exited 0" means the installer ran to completion, not that the service has
            // enrolled or is reachable. Claiming "technician can now connect" without verified
            // online identity overstates what exit code 0 proves.
            "DeskRally Setup finished successfully.\n\n\
             The agent service will start automatically and enroll with the server. \
             Your technician will be able to connect once it is running."
                .to_string(),
            MB_ICONINFORMATION,
        )
    } else {
        let uac_cancelled = detail
            .map(|d| d.contains("UAC cancelled") || d.contains("cancelled by user"))
            .unwrap_or(false);
        let mut body = if uac_cancelled {
            "Installation was cancelled.\n\n\
             You chose not to allow administrator access. \
             You can ask your technician to send another install request."
                .to_string()
        } else {
            let mut b = "Installation encountered a problem.\n\n".to_string();
            if let Some(d) = detail {
                b.push_str("Error: ");
                b.push_str(d);
                b.push_str("\n\nPlease share this message with your technician.");
            }
            b
        };
        // Truncate very long error strings to avoid a wall of text
        if body.len() > 800 {
            body.truncate(797);
            body.push_str("...");
        }
        ("DeskRally — Installation", body, MB_ICONWARNING)
    };
    let title = HSTRING::from(title_s);
    let text = HSTRING::from(body_s);
    // SAFETY: owned HSTRING buffers; NULL hwnd is fine for a standalone dialog.
    unsafe {
        let _ = MessageBoxW(None, &text, &title, MB_OK | icon);
    }
}

#[cfg(not(windows))]
fn attend_promote_result_dialog(_success: bool, _detail: Option<&str>) {}

/// Promote this ephemeral guest to a permanent unattended install. Called from the status-poll
/// background thread when `promote.enrollment_token` arrives (docs/12 §8) with
/// `installer_available = true`.
///
/// Blocks until the attempt concludes (consent, download, Setup launch, wait up to 5 min).
/// Returns `Some(JoinHandle)` only when Setup is still running after the 5-minute wait; the
/// caller MUST store that handle in the shared `pending_installer_waiter` Arc so that
/// `run_attend_after_redeem` can join it before the process exits — this is what prevents
/// `process::exit` from killing the observer while elevated Setup continues.
///
/// Reports all outcomes to POST /attended-sessions/promote-complete (except a pre-consent
/// decline and the installer-not-available case, which have no install attempt to report).
fn run_attend_promote(
    base: &str,
    attend_token: &str,
    installer_available: bool,
    attempt_nonce: Option<String>,
) -> Option<std::thread::JoinHandle<()>> {
    println!("attend: PROMOTE requested — launching managed Setup installer");

    if !installer_available {
        println!("attend: promote requested but managed installer is not available on this server");
        attend_promote_no_installer_dialog();
        return None;
    }

    // Pre-consent: guest must explicitly approve before any download starts.
    if !attend_promote_consent_dialog() {
        println!("attend: promote declined by guest at consent dialog");
        if let Err(e) = crate::attend::post_promote_complete(
            base,
            attend_token,
            false,
            Some("Guest declined the installation consent dialog"),
            attempt_nonce.as_deref(),
        ) {
            tracing::warn!(error = %e, "attend: could not report promote decline to control plane");
        }
        return None;
    }

    // Download the managed installer bundle (DeskRallySetup.exe + MSI + enrollment.token in a ZIP).
    // The attempt nonce is sent so the server rejects stale downloads when the technician re-issued.
    let zip_bytes = match crate::attend::download_installer_bundle(base, attend_token, attempt_nonce.as_deref()) {
        Ok(bytes) => {
            println!("attend: installer bundle downloaded ({} bytes)", bytes.len());
            bytes
        }
        Err(e) => {
            eprintln!("attend: promote bundle download failed: {e}");
            attend_promote_result_dialog(false, Some(&e));
            if let Err(re) = crate::attend::post_promote_complete(base, attend_token, false, Some(&e), attempt_nonce.as_deref()) {
                tracing::warn!(error = %re, "attend: could not report download failure to control plane");
            }
            return None;
        }
    };

    // Extract to a UUID temp dir and locate DeskRallySetup.exe.
    let setup_path = match extract_setup_zip(&zip_bytes) {
        Ok(p) => {
            println!("attend: installer extracted to {}", p.display());
            p
        }
        Err(e) => {
            eprintln!("attend: promote extract failed: {e}");
            attend_promote_result_dialog(false, Some(&e));
            if let Err(re) = crate::attend::post_promote_complete(base, attend_token, false, Some(&e), attempt_nonce.as_deref()) {
                tracing::warn!(error = %re, "attend: could not report extract failure to control plane");
            }
            return None;
        }
    };
    let extract_dir = setup_path.parent().map(|p| p.to_path_buf());

    // Launch Setup.exe. It handles its own UAC elevation via its embedded manifest.
    match launch_setup_exe(&setup_path) {
        Ok(0) => {
            if let Some(dir) = &extract_dir {
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(path = %dir.display(), error = %e, "attend: could not clean up extracted Setup dir");
                }
            }
            println!("attend: promote Setup exited successfully");
            attend_promote_result_dialog(true, None);
            if let Err(e) = crate::attend::post_promote_complete(base, attend_token, true, None, attempt_nonce.as_deref()) {
                tracing::warn!(error = %e, "attend: could not report promote success to control plane");
            }
            None
        }
        Ok(code) => {
            if let Some(dir) = &extract_dir {
                if let Err(e) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(path = %dir.display(), error = %e, "attend: could not clean up extracted Setup dir");
                }
            }
            let e = format!("installer exited with code {code}");
            eprintln!("attend: promote failed: {e}");
            attend_promote_result_dialog(false, Some(&e));
            if let Err(re) = crate::attend::post_promote_complete(base, attend_token, false, Some(&e), attempt_nonce.as_deref()) {
                tracing::warn!(error = %re, "attend: could not report Setup failure to control plane");
            }
            None
        }
        Err(SetupLaunchError::StillRunning(handle)) => {
            // Installer still running after the 5-minute wait. Spawn a bounded background waiter
            // (24h) that will post the result and clean up the temp directory when Setup exits.
            // Do NOT clean up or post a result here: the process is live and reading the files.
            // The caller stores the returned JoinHandle in the shared Arc so that
            // run_attend_after_redeem joins it before the support process exits.
            eprintln!("attend: promote timed out; spawning background waiter for Setup exit");
            Some(spawn_setup_waiter(
                handle,
                extract_dir,
                base.to_string(),
                attend_token.to_string(),
                attempt_nonce,
            ))
        }
        Err(SetupLaunchError::Failed(e)) => {
            if let Some(dir) = &extract_dir {
                if let Err(ce) = std::fs::remove_dir_all(dir) {
                    tracing::warn!(path = %dir.display(), error = %ce, "attend: could not clean up extracted Setup dir");
                }
            }
            eprintln!("attend: promote launch failed: {e}");
            attend_promote_result_dialog(false, Some(&e));
            if let Err(re) = crate::attend::post_promote_complete(base, attend_token, false, Some(&e), attempt_nonce.as_deref()) {
                tracing::warn!(error = %re, "attend: could not report launch failure to control plane");
            }
            None
        }
    }
}

/// Background watcher that flips `stop` when the [`STOP_FILE`] appears (operator-driven shutdown).
fn spawn_stop_file_watcher(stop: Arc<AtomicBool>) {
    spawn_stop_file_watcher_at(stop, PathBuf::from(STOP_FILE));
}

/// [`spawn_stop_file_watcher`] against an explicit path, and logging which mechanism tripped the
/// flag. The support client does NOT call this (see [`run_attend_after_redeem`]); the installed
/// agent's console path does, defaulting to [`STOP_FILE`].
fn spawn_stop_file_watcher_at(stop: Arc<AtomicBool>, path: PathBuf) {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) {
            if path.exists() {
                tracing::info!(path = %path.display(), "attend: stop-file present — stopping session");
                stop.store(true, Ordering::Relaxed);
                break;
            }
            // The service's graceful stop (crate::helper_stop) arrives here too, so it takes the
            // stop file's exact path, drain included. Never set outside an installed helper.
            if crate::helper_stop::requested() {
                tracing::info!("helper: service stop requested — stopping sessions");
                stop.store(true, Ordering::Relaxed);
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    });
}

/// Sleep up to `total`, returning early once `stop` is set. The helper's reconnect backoff reaches
/// minutes; a service stop must not wait that out before the helper notices.
fn sleep_unless_stopped(stop: &AtomicBool, total: Duration) {
    const SLICE: Duration = Duration::from_millis(200);
    let deadline = Instant::now() + total;
    while !stop.load(Ordering::Relaxed) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(left.min(SLICE));
    }
}

/// An [`InputSink`] that swallows every event. Used by [`stream_screen`], which streams video but
/// does not inject input (the M1 path); the real CLI path wires a [`SendInputSink`] instead.
struct NoopSink;
impl InputSink for NoopSink {
    fn inject(&self, _event: InputEvent) -> PlatformResult<()> {
        Ok(())
    }
}

/// A test-observability [`InputSink`] (behind `stream --log-input`). It prints one line per event —
/// `INJECTED <compact-json>`, the same canonical JSON [`input_codec`] moves — and deliberately does
/// **not** call `SendInput`, so an automated end-to-end test can prove input arrived + decoded in
/// order without perturbing the real cursor/keyboard. Reuses [`input_codec::encode`] so the logged
/// bytes are byte-identical to what crossed the wire.
struct LoggingSink;
impl InputSink for LoggingSink {
    fn inject(&self, event: InputEvent) -> PlatformResult<()> {
        let json = String::from_utf8(input_codec::encode(&event)).unwrap_or_default();
        println!("INJECTED {json}");
        // Flush so the test reading our piped stdout sees each line promptly (line-buffered
        // pipes can otherwise hold the line until the buffer fills or the process exits).
        let _ = std::io::stdout().flush();
        Ok(())
    }
}

/// A test-observability [`Clipboard`] (behind `stream --log-clipboard`). Each inbound remote set
/// prints one line — `CLIPBOARD-SET <text>` — and deliberately does **not** touch the real OS
/// clipboard, so an automated end-to-end test can prove the console→agent clipboard path without an
/// interactive window station and without clobbering the tester's clipboard.
///
/// [`get_text`](Clipboard::get_text) returns `None` (there is no local clipboard to forward) and
/// [`sequence`](Clipboard::sequence) is a monotonic counter bumped on each set. The clipboard worker
/// seeds `last_seen` from `sequence()` and, after each `set_text`, records `sequence()` again — so
/// bumping on our own write keeps its echo-suppression happy and nothing is ever spuriously forwarded
/// back to the controller.
#[derive(Default)]
struct LoggingClipboard {
    seq: AtomicU64,
}
impl Clipboard for LoggingClipboard {
    fn get_text(&self) -> Option<String> {
        None
    }
    fn set_text(&self, text: &str) -> Result<(), String> {
        println!("CLIPBOARD-SET {text}");
        // Flush so the test reading our piped stdout sees the line promptly (see LoggingSink).
        let _ = std::io::stdout().flush();
        self.seq.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn sequence(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

/// Stream a live display to a controller over a real WebRTC video track (video only — no input).
///
/// Thin wrapper over [`serve_session`] with a no-op input sink; kept as the M1 public entry point
/// (and exercised by `tests/e2e_stream.rs`). New callers that also want to inject controller input
/// should call [`serve_session`] with a real [`InputSink`].
pub async fn stream_screen(
    signaling_url: &str,
    device: DeviceId,
    capturer: impl ScreenCapturer + 'static,
    target_fps: u32,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    serve_session(
        signaling_url,
        device,
        capturer,
        target_fps,
        Arc::new(NoopSink),
        stop,
        PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
    )
    .await
}

/// This agent's own exe file name. Passed to every [`Dispatcher`] so its guard rail can refuse to
/// terminate the agent process itself.
fn own_exe_name() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "rmt-agent.exe".to_string())
}

/// Build the **dev-mode** backstage [`Dispatcher`]: a self-issued full/demo [`Grant`] (every
/// [`Capability`], nil ids), mirroring the demo HTTP adapter. Used **only** when no trusted grant
/// issuer is configured and the caller explicitly asked for [`BackstageAuth::InsecureSelfIssued`]
/// — i.e. the CLI `stream` path and most tests. A loud warning is logged by the caller so this
/// insecure path is never silent.
///
/// H1: when an issuer key IS configured the session starts with **no** dispatcher and this is never
/// called; a dispatcher is built only from a control-plane-signed grant that verifies (see
/// [`dispatcher_from_signed_grant`]).
fn new_backstage_dispatcher(device: uuid::Uuid, chain: SharedAuditChain) -> Dispatcher {
    use Capability::*;
    let grant = Grant {
        technician_id: uuid::Uuid::nil(),
        session_id: uuid::Uuid::nil(),
        machine_id: device,
        capabilities: vec![
            ProcessList, ServiceList, EventLogRead, FileBrowse, FileDownload, RegistryRead,
            SystemInfoRead, ServiceControl, ProcessKill, FileUpload, ShellAsUser, RegistryWrite,
            RegistryHiveLoad, ServiceConfig, FileDelete, ShellAsSystem, ShellAsCredential,
            UninstallProgram, LocalUserAdmin,
        ],
    };
    Dispatcher::with_chain(grant, own_exe_name(), chain)
}

/// Decode + verify a control-plane-signed grant blob (the opaque `signed_grant` string from a
/// `Control::InstallGrant`) against the pinned `issuer` at `now_ms`, and on success build the
/// session [`Dispatcher`] armed with exactly the granted capabilities. Returns a human-readable
/// error string (for a `Control::Error` reply) on a malformed blob, a bad/wrong-key signature, a
/// grant outside its validity window, or a grant minted for a different machine (H3 device binding:
/// `expected_machine_id` is THIS session's device, so a grant for machine A is not replayable to B).
///
/// The dispatcher JOINS `chain` rather than starting one from the grant. The grant's own
/// `session_id`/`technician_id` still decide what it may DO, but they do not get to rename the
/// session's trail — that identity comes from what signaling vouched for, and a second grant must
/// continue the chain, not fork a new one at `seq 0`.
fn grant_matches_live_session(blob: &str, session: Option<uuid::Uuid>, technician: Option<uuid::Uuid>) -> Result<(), String> {
    let (Some(session), Some(technician)) = (session, technician) else {
        return Err("backstage requires a verified live session and technician".into());
    };
    let signed = SignedGrant::from_json(blob).map_err(|e| e.to_string())?;
    if signed.claims.grant.session_id != session || signed.claims.grant.technician_id != technician {
        return Err("grant does not belong to this live session and technician".into());
    }
    Ok(())
}

fn dispatcher_from_signed_grant(
    blob: &str,
    issuer: &PublicIdentity,
    now_ms: i64,
    expected_machine_id: uuid::Uuid,
    spent: &SpentGrants,
    chain: SharedAuditChain,
) -> Result<Dispatcher, String> {
    let signed = SignedGrant::from_json(blob).map_err(|e| e.to_string())?;
    let grant = signed
        .verify(issuer, now_ms, expected_machine_id)
        .map_err(|e| e.to_string())?;
    // Burn the verified token, not its session: a newly signed renewal for the same
    // live session must work while replaying the exact prior token must fail.
    let signature: [u8; 64] = hex::decode(&signed.sig)
        .map_err(|e| e.to_string())?.try_into()
        .map_err(|_| "invalid signature length".to_string())?;
    if !spent.claim_key(SpentArtifact::Backstage(signature), signed.claims.expires_at_ms, now_ms) {
        return Err("grant has already been installed (grants are single use)".into());
    }
    Ok(Dispatcher::with_chain(grant, own_exe_name(), chain))
}

/// A single-use ledger over signed, expiring artifacts, so none can be presented twice.
///
/// **Two live instances with DIFFERENT key spaces**, and the type is deliberately generic over
/// neither — the KEY is whatever the caller passes:
///
/// * `spent_grants` — backstage grants, keyed by verified signature bytes, "installed once".
/// * `spent_elevations` — elevation grants (loop 87), keyed `(session_id, elevation_id)`, "burned
///   once". A different pair, because elevation is per COMMAND: a technician mints many grants for
///   one session, so a `(technician, session)` key would silently allow exactly one elevated command
///   per session and look correct doing it.
///
/// Everything below is written about the backstage tenant because it came first; every word of it
/// applies to the elevation tenant unchanged, including where the claim must sit relative to
/// verification.
///
/// A signed grant is a **bearer credential**. The signature binds it to a machine, a technician, a
/// session and a validity window — but nothing inside the blob stops the same blob being presented
/// again. Anyone who obtains one (a console log, a crashed browser session, a compromised
/// technician workstation) can install it on that machine for the remainder of its TTL, and the TTL
/// is minutes, not seconds. This ledger makes each signed token single-use while
/// permitting freshly signed renewals within the same session.
///
/// **Deliberately not enforced inside `SignedGrant::verify`.** That function is a pure predicate
/// over the blob, pinned by byte-for-byte golden vectors shared with the Go issuer; making it
/// stateful would make those vectors meaningless and would put replay memory in a crate that has
/// no state to keep it in. The party that has state is the agent, so the agent owns the ledger.
///
/// Scope is the caller's choice and it matters: the [`Default`] is a fresh ledger, so an isolated
/// session at least cannot install the same grant twice, and the long-lived helper deliberately
/// shares ONE across its reconnect loop so a grant cannot be replayed into a *later* session.
#[derive(Hash, Eq, PartialEq)]
enum SpentArtifact {
    Backstage([u8; 64]),
    Elevation(uuid::Uuid, uuid::Uuid),
}

#[derive(Default)]
pub struct SpentGrants {
    seen: Mutex<HashMap<SpentArtifact, i64>>,
}

impl SpentGrants {
    /// Claim a grant. Returns `false` if it was already installed — i.e. this is a replay.
    ///
    /// Check-and-insert under a single lock, so two concurrent installs of the same blob cannot
    /// both win. Expired entries are pruned on the way in: the grants' own TTLs bound this map for
    /// free, so it needs no sweeper thread and cannot grow without limit across a four-hour session.
    pub fn claim(&self, key: (uuid::Uuid, uuid::Uuid), expires_at_ms: i64, now_ms: i64) -> bool {
        self.claim_key(SpentArtifact::Elevation(key.0, key.1), expires_at_ms, now_ms)
    }

    fn claim_key(&self, key: SpentArtifact, expires_at_ms: i64, now_ms: i64) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        seen.retain(|_, expires| *expires > now_ms);
        if seen.contains_key(&key) { return false; }
        seen.insert(key, expires_at_ms);
        true
    }

    #[cfg(feature = "secure-test")]
    pub(crate) fn claim_backstage(&self, sig: [u8; 64], expires_at_ms: i64, now_ms: i64) -> bool {
        self.claim_key(SpentArtifact::Backstage(sig), expires_at_ms, now_ms)
    }
}

/// Per-session behavior knobs for [`serve_session_with_ice`], bundled so the driver keeps a
/// manageable arity as features accrete (M8 transfer dir, M9 clipboard, H1 backstage auth). All
/// fields have a sensible [`Default`], so a caller sets only what it needs
/// (`SessionOptions { sink, backstage_auth, ..Default::default() }`). The `backstage_auth` default
/// is [`BackstageAuth::Deny`] — a caller that has not considered backstage authorization gets none.
pub struct SessionOptions {
    /// Helper-owned reporting survives this session and registration connection teardown.
    /// Default: `None` for callers without an authenticated signaling mux.
    pub guest_end_reports: Option<rmt_agent_core::guest_end::GuestEndReports>,
    /// Where decoded controller input is injected (M7). Default: a no-op sink.
    pub sink: Arc<dyn InputSink>,
    /// File-transfer root: uploads land here, downloads are confined here (M8). Default:
    /// [`crate::config::DEFAULT_TRANSFER_DIR`].
    pub transfer_dir: PathBuf,
    /// Optional platform clipboard for bidirectional text sync (M9). Default: `None` (disabled).
    pub clipboard: Option<Box<dyn Clipboard>>,
    /// Which directions the clipboard may move, from the machine's config. Composes with — and is
    /// never able to override — the session's view-only state: view-only refuses both directions
    /// regardless. Default: [`ClipboardMode::Bidirectional`], the pre-existing behaviour.
    /// Ignored when [`clipboard`](Self::clipboard) is `None`; there is nothing to govern.
    pub clipboard_mode: ClipboardMode,
    /// H1 trust policy — see [`BackstageAuth`]. Default: [`BackstageAuth::Deny`] (fail closed).
    pub backstage_auth: BackstageAuth,
    /// Loops 79/80: refuse injected input until a control-plane-signed session policy has verified.
    /// See [`crate::config::HelperConfig::require_session_policy`] for why an agent that merely
    /// *accepts* policies is not enough. Default: `false` (unchanged behaviour).
    pub require_session_policy: bool,
    /// docs/25 F03: whether this session's authority is a control-plane LEASE the controller has to
    /// keep renewing. Default: [`SessionLeaseMode::FromSessionBinding`] — enforce exactly when
    /// signaling vouched for a control-plane session AND this agent has a pinned issuer key to
    /// verify a lease with. The attended path sets [`SessionLeaseMode::NotApplicable`]; see that
    /// variant's doc for why leasing an attended session would break it for no gain.
    pub session_lease: SessionLeaseMode,
    /// docs/25 F03: how long a leased session may run before its FIRST lease arrives. Default:
    /// [`DEFAULT_LEASE_GRACE`]. An absolute window measured from the start of the session loop;
    /// the e2e harness shortens it so a teardown test does not take twenty seconds.
    pub session_lease_grace: Duration,
    /// M3 registration identity. `Some(..)` ⇒ the agent announces its real enrolled public key and
    /// answers the signaling server's `agent_auth_challenge`, which is the only way it enters the
    /// registry on a server running without `-insecure-no-agent-auth`. `None` ⇒ the unauthenticated
    /// dev/LAN path (placeholder pubkey, challenges unanswered). Default: `None`.
    pub identity: Option<AgentIdentity>,
    /// Longest a single session may run. Default: [`DEFAULT_STREAM_MAX_RUN`] (4 hours).
    ///
    /// This is a resource bound, not a policy one: it exists so a session that is never closed
    /// cleanly cannot hold a capture thread and a libvpx context forever. Lower it on a machine
    /// where sessions should be short. The caveat that used to be here — "raising it past a few
    /// hours is not advisable until the encoder queue is bounded" — no longer applies: the encoder
    /// queue is bounded as of loop 17 (drain-to-latest, `transport-webrtc::run_encoder_loop`), so a
    /// long session no longer converts capture outrunning encode into unbounded memory growth.
    pub max_session: Duration,
    /// M11 administrative ceiling on what a technician may ask this machine for. Default:
    /// [`QualityPolicy::default`], which permits requests up to 20 Mbps (60 fps, adaptation
    /// allowed). Sessions still start at the 3 Mbps quality default.
    pub quality_policy: QualityPolicy,
    /// The on-screen window the person at this machine sees (docs/01 §5 indicator + §7 guest chat,
    /// merged into one window and one message pump). Default: `None` (no on-screen surface).
    ///
    /// `Option<Box<dyn GuestUi>>` mirrors [`SessionOptions::clipboard`] deliberately: a factory
    /// rather than a live window, because the surface needs the session's chat channel, which does
    /// not exist until the session is running.
    ///
    /// **`None` is not "the indicator is suppressed".** It is "this host draws nothing" — the shape
    /// every headless test and the `stream` dev command need. The product requirement that a live
    /// session is always visible to the guest is carried by the two production call sites
    /// (`run_attend` and `run_helper_stream`), which both pass `Some(..)`, and by the test that
    /// asserts they do. A `Default` that spawned a window would break every test in the workspace.
    pub guest_ui: Option<Box<dyn GuestUi>>,
    /// H1: the single-use ledger for backstage grants (see [`SpentGrants`]).
    ///
    /// Not an `Option`. A `None`-means-no-replay-protection default is exactly the shape that
    /// shipped an insecure default nobody chose in this codebase before: the [`Default`] here is a
    /// working ledger, so a caller that never thinks about replay still gets in-session protection.
    /// Sharing one across a reconnect loop — which the helper does — is the deliberate upgrade.
    pub spent_grants: Arc<SpentGrants>,
    /// Loop 87: the single-use ledger for ELEVATION grants (docs/01 §3), a SECOND
    /// [`SpentGrants`] rather than a shared one.
    ///
    /// Separate on purpose. The two artifacts are keyed differently — a backstage grant burns
    /// `(technician_id, session_id)`, an elevation burns `(session_id, elevation_id)` — and sharing
    /// one map would let a collision between those key spaces make one artifact deny the other.
    /// They are also spent at very different rates: one backstage grant per session, one elevation
    /// per elevated COMMAND.
    ///
    /// Not an `Option`, for the same reason `spent_grants` is not: the [`Default`] is a working
    /// ledger, so a caller who never thinks about replay still gets in-session protection, and the
    /// helper's deliberate upgrade is to share ONE across its reconnect loop.
    pub spent_elevations: Arc<SpentGrants>,
    /// `true` ⇒ input is MOCKED (the `--log-input` test path): decoded input is logged, not injected,
    /// and the guest-input block ([`crate::input_block`]) tracks state + acks but installs NO real OS
    /// hooks. This is what lets the e2e — and a local gate run — exercise `SetInputBlocked` end to end
    /// without freezing the real machine's keyboard/mouse. Default: `false` (production: real).
    pub mock_input: bool,
    /// docs/53: this attended session's "Request admin rights", and the updates it sends the
    /// controller. `None` (the default) on every unattended and mocked path: `RequestAdminRights` is
    /// then answered `Unavailable` and nothing is advertised.
    pub admin_rights: Option<(Arc<crate::admin_rights::AdminRights>, tokio::sync::mpsc::UnboundedReceiver<crate::admin_rights::AdminRightsUpdate>)>,
    /// TEST HOOK (e2e only): serve this session as a view-only OBSERVER even though signaling did not
    /// say so. Dev-mode signaling deliberately never selects observer mode from an unverified ticket,
    /// so without this the agent's observer enforcement could not be exercised end to end. It can only
    /// TIGHTEN a session (an observer is a strict subset of a controller), and no production path sets
    /// it. Default: `false`.
    pub force_observer: bool,
    /// `true` ⇒ a `RebootGuest` control message is MOCKED (the `--log-input` test path): the agent
    /// logs the intent, replies `RebootScheduled`, and **does not reboot** — so the Playwright e2e and
    /// a local gate run can exercise the whole reboot round-trip without rebooting the dev box. Set
    /// together with [`SessionOptions::mock_input`] on the dev/e2e paths. Default: `false`
    /// (production: a real reboot). See [`crate::reboot::Rebooter`].
    pub mock_reboot: bool,
    /// `true` ⇒ a `LaunchTool` control message is MOCKED (the `--log-input` / `--synthetic` test
    /// paths): the agent resolves the whitelist and acks `ToolLaunched` but spawns NO process — so a
    /// gate/e2e never pops Task Manager on the CI box. Set alongside [`SessionOptions::mock_reboot`].
    /// Default: `false` (production: really launches). See [`crate::launch::Launcher`].
    pub mock_launch: bool,
    /// `true` ⇒ a `RunCommand` control message is MOCKED (the `--log-input` / `--synthetic` test
    /// paths): the agent logs the intent and acks a canned `CommandResult` but executes NOTHING — so a
    /// gate/e2e that sends `RunCommand` never runs a command on the CI box. Set alongside
    /// [`SessionOptions::mock_launch`]. Default: `false` (production: really runs). See
    /// [`crate::command_run::CommandRunner`].
    pub mock_command: bool,
    /// `true` ⇒ THIS PROCESS IS the guest's interactive user (the `agent_host attend` host); `false`
    /// ⇒ it is the SYSTEM per-session helper, which is not the user and must fetch their token.
    ///
    /// It exists because getting this wrong silently broke two shipped features on the attended path.
    /// `LaunchTool` and `RunCommand{as_user}` both called `WTSQueryUserToken`, which needs
    /// `SeTcbPrivilege` — SYSTEM has it, an administrator does not — so on every attended session both
    /// failed with `ERROR_PRIVILEGE_NOT_HELD` (0x522). The gate could not see it: `--log-input` /
    /// `--synthetic` enable the mocks, so the real token path never ran there.
    ///
    /// An explicit flag rather than a runtime probe, deliberately: "am I the user?" is something the
    /// caller KNOWS (it is which entry point ran), and a flag makes the resulting choice a pure,
    /// testable function instead of a privileged call that fails late and misreports why.
    ///
    /// Default: `false` — the historical behaviour, and the safe reading for any caller that has not
    /// thought about it (the SYSTEM path merely needs a privilege it has).
    pub host_runs_as_interactive_user: bool,
    /// `true` ⇒ a `LockWorkstation` control message is MOCKED (the `--log-input` / `--synthetic` test
    /// paths): the agent acks `WorkstationLocked` but does NOT call `LockWorkStation` — so a gate/e2e
    /// that sends the lock never locks the CI box's own session. Set alongside
    /// [`SessionOptions::mock_reboot`]. Default: `false` (production: really locks). See
    /// [`crate::lock::Locker`].
    pub mock_lock: bool,
    /// `true` ⇒ a `LogOffGuest` control message is MOCKED (the `--log-input` / `--synthetic` test
    /// paths): the agent acks `LogOffScheduled` but does NOT call `WTSLogoffSession` — so a gate/e2e
    /// that sends the logoff never logs the CI box's operator out of their own session. Set alongside
    /// [`SessionOptions::mock_lock`]. Default: `false` (production: really logs off). See
    /// [`crate::logoff::Logoffer`].
    pub mock_logoff: bool,
    /// TEST HOOK (`stream --synthetic --synthetic-tone` only): feed the session's audio track a
    /// steady 440 Hz tone instead of the machine's real output, so an e2e can assert that a real
    /// browser DECODES audible sound (silence would prove nothing: with DTX a silent frame is one
    /// byte). It also keeps the test from ever streaming the machine's own audio. Default: `false`
    /// (production: the real loopback, or nothing).
    pub synthetic_tone: bool,
    /// Secure-test-harness mode: grant verification runs real Ed25519 checks (same as production)
    /// but `Dispatcher::with_chain` is never called — no Win32 backend is ever armed. The promote
    /// path uses inert sinks (no FS write, no ShellExecuteExW). Structurally `false` in production
    /// builds (field absent without `cfg(feature = "secure-test")`).
    ///
    /// Required preconditions (enforced at CLI parse time in `attend_params_from_args`):
    ///   - `backstage_auth` must be `BackstageAuth::SignedBy` (not Deny, not InsecureSelfIssued)
    ///   - control-plane URL must be loopback
    #[cfg(feature = "secure-test")]
    pub secure_test_harness: bool,
    /// Where session recordings are written (loop 89, docs/01 §5), or `None` ⇒ **this host cannot
    /// record directly**. Service-backed CLI recording is selected separately below.
    ///
    /// An `Option<PathBuf>` and not a defaulted path, because "record into whatever directory the
    /// default resolves to" is not a decision this struct may make silently on someone else's
    /// machine: a recorder writes up to a gigabyte of video onto a customer's disk, so the location
    /// is stated by the caller that knows the agent's config root, or the capability is off. The
    /// helper/CLI paths set `<config root>/`[`crate::recording::DEFAULT_RECORDING_SUBDIR`]; the
    /// dev/e2e paths point it at a scratch directory; `Default` is `None`.
    ///
    /// Note the difference from the `mock_*` flags above: this is NOT a mock. Everything downstream
    /// of it is the production code path — real IVF files, real DACL, real digests — because a
    /// recorder's failure modes live in the filesystem and a mocked one would prove nothing. The
    /// only thing a test changes is WHERE.
    pub recording_dir: Option<PathBuf>,
    /// Explicit CLI opt-in to the installed, enabled SYSTEM recording broker.
    pub recording_via_service: bool,
    /// OUTPUT flag: set to `true` by the session dispatch when the controller sends
    /// `EndSession { uninstall: true }` ("remove client"). The CALLER reads its own clone after the
    /// session returns and, if set, performs the self-uninstall (see `run_helper_stream`). An `Arc` so
    /// the caller keeps a handle to read after `serve_session_with_ice` has consumed the options.
    /// Default: a fresh `false` (nothing requested).
    pub uninstall_requested: Arc<AtomicBool>,
    /// Multi-session path (F2 many-tech): a transport already connected and positioned after
    /// `Brokered`, produced by [`WebRtcTransport::from_brokered`]. When `Some`,
    /// `serve_session_with_ice` skips its own `connect_with_ice` call and uses this transport
    /// directly. When `None` (the default), the existing single-session signaling path is used.
    ///
    /// Not an `Option<Box<dyn ...>>` — the transport is a concrete type and the caller in
    /// `run_multi_session_stream` already has a `WebRtcTransport` in hand. Wrapping it would
    /// add an unnecessary heap allocation with no trait-object benefit.
    pub pre_built_transport: Option<WebRtcTransport>,
    /// Multi-session path (F2 many-tech): the shared selected-monitor `Arc` from
    /// [`crate::shared_capture::SharedCapture`]. When `Some`, `serve_session_with_ice` uses this
    /// instead of creating a fresh `AtomicU32`, so the session's coordinate remap and the capture
    /// thread's frame production always reference the same selected monitor — establishing the
    /// single remap boundary the review requires. When `None` (single-session path), a fresh
    /// `AtomicU32` is created as before.
    pub shared_selected_monitor: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    /// Multi-session path: coherent (monitor, generation) pair from
    /// [`crate::shared_capture::SharedCapture`].  When `Some`, the `SelectMonitor` handler
    /// uses this to implement pinned-display logic (pin on first call, reject different id).
    /// `BroadcastCapturer` reads this pair coherently for frame validation.
    /// When `None` (single-session path), no shared selection state is managed.
    pub shared_selection_state: Option<std::sync::Arc<std::sync::Mutex<crate::shared_capture::SelectionState>>>,
    pub shared_canvas: Option<control::MonitorCanvas>,
    /// The installed multi-session path's activity clock (update_guard.rs idle release): received
    /// frames on technician channels touch it. None everywhere else.
    pub activity: Option<std::sync::Arc<crate::update_guard::SessionActivity>>,
    /// docs/61: in-session input hand-off between concurrent technicians. `Some` only on the
    /// multi-session path, where every session shares one `SharedCapture` (and so one arbiter);
    /// `None` elsewhere, where the capability is never advertised and a hand is refused.
    pub input_handoff: Option<InputHandoffWiring>,
}

/// What a multi-session task hands its session loop so it can take part in input arbitration
/// (docs/61 stage 3b). Public so `SessionOptions { .., ..Default::default() }` stays usable outside the
/// crate; its fields are crate-private, so only the agent itself can build one.
pub struct InputHandoffWiring {
    /// The machine-wide capture, which owns the input arbiter and the session directory.
    pub(crate) shared: Arc<crate::shared_capture::SharedCapture>,
    /// This session's own arbiter handle. A hand is ALWAYS sent as this handle — the sender is never
    /// taken from the message, so one technician cannot hand away another's control.
    pub(crate) handle: u64,
    /// This session's signaling session id: how the viewers name it in `session_participants`.
    pub(crate) signaling_id: String,
}

/// The administrative bound on a session's quality (M11), read from the agent's config.
///
/// This is a **ceiling, not a setting**: it never raises what a controller asked for, only lowers
/// it, and the controller is told when it bit (`QualityApplied::capped_by_policy`) so the operator
/// can tell "I asked for too much" from "this machine is administratively capped".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualityPolicy {
    /// Largest bitrate ceiling a controller may set, bits/sec.
    pub max_bitrate_bps: u32,
    /// Only an explicitly configured bitrate cap binds the scaled effective ceiling.
    pub bitrate_cap_configured: bool,
    /// The config held exactly [`LEGACY_INSTALLER_BITRATE_BPS`], which the installer wrote on every
    /// machine through 1.3.24, so it was read as "not configured". Kept so the startup line can say so.
    pub legacy_installer_bitrate_ignored: bool,
    /// Largest frame rate a controller may set.
    pub max_fps: u32,
    /// When `false`, the adaptive rate controller is disabled for every session on this machine
    /// regardless of what the controller asks — the fleet-wide kill switch for a site where
    /// loss-based backoff misreads a lossy-but-uncongested link.
    pub adaptive: bool,
}

impl Default for QualityPolicy {
    fn default() -> Self {
        Self {
            max_bitrate_bps: quality::MAX_MAX_BITRATE_BPS,
            bitrate_cap_configured: false,
            legacy_installer_bitrate_ignored: false,
            max_fps: quality::MAX_FPS,
            adaptive: true,
        }
    }
}

/// The `quality.max_bitrate_bps` value install-agent.ps1 wrote into EVERY config.json through 1.3.24,
/// whether or not the operator asked for a cap: the script's comment said the value was the agent's own
/// default, so writing it "changes no behaviour". 1.3.24 made a configured cap hard, which turned that
/// default into a fleet-wide 3 Mbps cap. That cap also clamped the "Best (LAN)" request and stopped the
/// pixel-scaled ceiling. A config holding exactly this value is therefore read as "not configured".
/// An administrator who really wants a hard cap near 3 Mbps writes any other value, such as 2_900_000.
/// The installer now writes the key only when `-MaxBitrateBps` is passed, and it refuses this exact value.
pub const LEGACY_INSTALLER_BITRATE_BPS: u32 = 3_000_000;

impl QualityPolicy {
    /// Build from the on-disk config, using the default request maximum for an absent bitrate cap.
    pub fn from_config(cfg: Option<crate::config::QualityPolicyConfig>) -> Self {
        let d = Self::default();
        match cfg {
            None => d,
            Some(mut c) => {
                let legacy = c.max_bitrate_bps == Some(LEGACY_INSTALLER_BITRATE_BPS);
                if legacy {
                    c.max_bitrate_bps = None;
                }
                Self {
                legacy_installer_bitrate_ignored: legacy,
                bitrate_cap_configured: c.max_bitrate_bps.is_some(),
                // Each bound is itself clamped into the wire's legal range, so an administrator
                // cannot configure a ceiling the protocol cannot express — a 500 Mbps entry in
                // config.json must not become a value `QualityApplied` reports but the agent then
                // silently re-clamps.
                max_bitrate_bps: c
                    .max_bitrate_bps
                    .unwrap_or(d.max_bitrate_bps)
                    .clamp(quality::MIN_MAX_BITRATE_BPS, quality::MAX_MAX_BITRATE_BPS),
                max_fps: c
                    .max_fps
                    .unwrap_or(d.max_fps)
                    .clamp(quality::MIN_FPS, quality::MAX_FPS),
                adaptive: c.adaptive.unwrap_or(d.adaptive),
                }
            }
        }
    }

    /// Apply the ceiling. Returns the bounded settings and whether the policy actually bit.
    ///
    /// Separated from [`QualitySettings::clamped`] on purpose: the wire clamp defends the *agent*
    /// against a malformed request, while this defends the *customer's link* against a legitimate
    /// one. They fire for different reasons and the controller is told about them differently.
    pub fn apply(&self, want: QualitySettings) -> (QualitySettings, bool) {
        let bounded = QualitySettings {
            max_bitrate_bps: want.max_bitrate_bps.min(self.max_bitrate_bps),
            fps: want.fps.min(self.max_fps),
            adaptive: want.adaptive && self.adaptive,
            ..want
        };
        (bounded, bounded != want)
    }
}

#[cfg(test)]
mod quality_policy_release_tests {
    use super::*;
    #[test]
    fn configured_and_default_bitrate_limits() {
        for cfg in [None, Some(crate::config::QualityPolicyConfig::default())] {
            let policy = QualityPolicy::from_config(cfg);
            assert_eq!(policy.max_bitrate_bps, quality::MAX_MAX_BITRATE_BPS);
            assert!(!policy.bitrate_cap_configured);
            let best = QualitySettings { max_bitrate_bps: 8_000_000, ..QualitySettings::DEFAULT };
            assert_eq!(policy.apply(best), (best, false));
        }
        let policy = QualityPolicy::from_config(Some(crate::config::QualityPolicyConfig {
            max_bitrate_bps: Some(2_900_000), ..Default::default()
        }));
        assert!(policy.bitrate_cap_configured);
        assert!(!policy.legacy_installer_bitrate_ignored);
        assert_eq!(policy.max_bitrate_bps, 2_900_000);
        assert_eq!(QualitySettings::DEFAULT.max_bitrate_bps, 3_000_000);
    }

    /// The operator's Desktop on 1.3.24 (2026-11-11): the config that every install-agent.ps1 run wrote
    /// (`{"max_bitrate_bps":3000000,"max_fps":60,"adaptive":true}`) made 1.3.24 log "quality
    /// ceiling 3000 kbps (configured hard cap)". That clamped "Best (LAN)" and stopped the
    /// multi-display ceiling. The exact legacy value must read as unconfigured.
    #[test]
    fn the_installers_legacy_3_mbps_value_is_not_a_configured_cap() {
        let installed: crate::config::QualityPolicyConfig =
            serde_json::from_str(r#"{"max_bitrate_bps":3000000,"max_fps":60,"adaptive":true}"#).unwrap();
        let policy = QualityPolicy::from_config(Some(installed));
        assert!(!policy.bitrate_cap_configured, "the installer's default is not an administrator's cap");
        assert!(policy.legacy_installer_bitrate_ignored, "the startup line must be able to say why");
        assert_eq!(policy.max_bitrate_bps, quality::MAX_MAX_BITRATE_BPS);
        assert_eq!((policy.max_fps, policy.adaptive), (60, true), "the other keys still apply");
        let best = QualitySettings { max_bitrate_bps: 8_000_000, ..QualitySettings::DEFAULT };
        assert_eq!(policy.apply(best), (best, false), "Best (LAN) must pass through unclamped");
    }
}

/// Build the signaling role this host announces. M3: register with the enrolled identity when we
/// have one; without it the peer registers with a placeholder pubkey and cannot answer an
/// `agent_auth_challenge` — fine on a signaling server started with `-insecure-no-agent-auth`
/// (LAN/dev/e2e), never accepted by an enforcing one.
///
/// BOTH branches report the CURRENT `os` description: `machine.os` is otherwise write-once at
/// enrollment, and this register_agent → presence feed → control plane hop is how the row stays
/// true across OS upgrades. Fresh per (re)connect on purpose — the reconnect loop re-enters the
/// session setup, so an upgrade reboot re-reads the registry rather than reporting the
/// pre-upgrade value for the life of the process.
///
/// BOTH branches also report `require_session_policy` — this session's ACTUAL floor setting, not the
/// config file's, so what the control plane learns is what the agent is really doing. That is the hop
/// which lets the control plane mint the policy discharging a floor its groups never asked for
/// (migrations/0037); without it an operator who sets the flag on an already-enrolled agent strands it
/// view-only forever, because enrollment ran once, long ago, from a config that did not have the flag.
///
/// Factored out of the session setup so a test can pin the identity→Role wiring — the send side
/// of the os refresh starts here, and an `os: None` here would revert the whole feature while
/// every socket-level test stayed green (transport pins Role→wire; this pins identity→Role). The
/// same is true of the floor flag, which is why the test asserts both on both branches.
fn agent_role(
    device: DeviceId,
    identity: Option<AgentIdentity>,
    require_session_policy: bool,
) -> Role {
    let os = Some(crate::enroll::os_description()).filter(|s| !s.is_empty());
    // A compile-time constant, unlike os_description() which deliberately re-reads the registry on
    // every call so an OS upgrade is picked up. A build identity cannot change while the process
    // runs, and this function is called on EVERY reconnect (roughly every 20s per agent), so it
    // must not allocate or do work per call beyond the one to_string.
    let agent_version = Some(rmt_agent_core::version::AGENT_VERSION.to_string());
    // Re-read on every reconnect so a log-in/log-out cycle is visible to the next console poll
    // without requiring a service restart. Like os_description(), None on failure or when no user
    // is logged in.
    let logged_in_user = query_logged_in_user();
    match identity {
        Some(AgentIdentity { pubkey, tenant_id, signer }) => {
            tracing::info!(%device, tenant = tenant_id.as_deref().unwrap_or("<none>"), "registering with the enrolled agent identity");
            Role::Agent {
                device,
                pubkey,
                tenant: tenant_id,
                signer: Some(signer),
                os,
                require_session_policy,
                agent_version,
                logged_in_user,
                // NOT set here. multi_session_capable is only advertised when this role is used
                // in run_multi_session_stream (which wires SignalingMux + SharedCapture +
                // BroadcastCapturer). The single-session callers (CLI `stream`, attended path)
                // use this same function but must NOT claim multi-session support — they only
                // handle one session at a time. The mux path sets Some(true) after calling this.
                multi_session_capable: None,
                features: Vec::new(),
            }
        }
        None => {
            tracing::warn!(
                %device,
                "registering UNAUTHENTICATED (no enrolled identity) — an enforcing signaling server \
                 will not add this peer to its registry"
            );
            Role::Agent {
                device,
                pubkey: "ed25519:rmt-agent".into(),
                tenant: None,
                signer: None,
                os,
                require_session_policy,
                agent_version,
                logged_in_user,
                // Same as enrolled branch: None here; run_multi_session_stream sets Some(true).
                multi_session_capable: None,
                features: Vec::new(),
            }
        }
    }
}

/// Returns the current interactive Windows session user as `"DOMAIN\\user"` or `"user"` when
/// the domain is empty. Returns `None` when no user is logged in or the WTS query fails.
///
/// The helper process runs in the interactive session (spawned by the SYSTEM service into the
/// console session), so `WTS_CURRENT_SESSION` refers to the session of the logged-in user.
#[cfg(windows)]
fn query_logged_in_user() -> Option<String> {
    use windows::Win32::System::RemoteDesktop::{
        WTSDomainName, WTSFreeMemory, WTSQuerySessionInformationW, WTSUserName,
        WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
    };

    // Query one WTS_INFO_CLASS string for the current session and return it as a Rust String,
    // or None on failure or an empty result. Frees the WTS-allocated buffer on success.
    let query = |cls| -> Option<String> {
        let mut ptr = windows::core::PWSTR::null();
        let mut bytes: u32 = 0;
        // SAFETY: WTSQuerySessionInformationW allocates *ptr; we free it with WTSFreeMemory below.
        unsafe {
            WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, cls, &mut ptr, &mut bytes).ok()?;
            if ptr.is_null() {
                return None;
            }
            let s = ptr.to_string().ok().filter(|s| !s.is_empty());
            WTSFreeMemory(ptr.0 as *mut core::ffi::c_void);
            s
        }
    };

    let user = query(WTSUserName)?;
    match query(WTSDomainName).filter(|d| !d.is_empty()) {
        Some(domain) => Some(format!("{domain}\\{user}")),
        None => Some(user),
    }
}

#[cfg(not(windows))]
fn query_logged_in_user() -> Option<String> {
    None
}

/// The enrolled identity a session registers with (M3): what we claim, which tenant we claim it in,
/// and the key that proves it. Built from `identity.key` + the enrolled `tenant_id`. Cheap to clone
/// (the signer is behind an `Arc`), so the helper's reconnect loop reuses one per attempt.
#[derive(Clone)]
pub struct AgentIdentity {
    /// Long-term Ed25519 public key, bare lowercase hex — the exact encoding `machine.pubkey`
    /// stores, because the signaling server compares the announced key against the pinned one.
    pub pubkey: String,
    /// Tenant recorded at enrollment; bound into the signed preimage by the server.
    pub tenant_id: Option<String>,
    /// Signs the `RMTAGENTAUTHv1` preimage with the private half of `pubkey`.
    pub signer: Arc<dyn ChallengeSigner>,
}

/// How a session decides whether a backstage request is authorized (H1).
///
/// This is deliberately a three-state enum rather than `Option<PublicIdentity>`. Under the old
/// `Option`, "no issuer" and "self-issue a grant carrying all 19 capabilities" were the SAME value,
/// and it was the value you got from `Default`, from `..Default::default()`, and from writing
/// `None` at a new call site. The attended guest client did exactly that (`grant_issuer: None`) and
/// silently handed every brokered peer `ShellAsSystem`/`ProcessKill`/`RegistryWrite` on a member of
/// the public's machine — measured, not theorised: an un-granted `KillProcess` came back
/// `exec_failed` ("target not found"), i.e. authorized, rather than `denied`.
///
/// Making the insecure mode a NAMED variant means no call site can reach it by accident: a new
/// session either pins an issuer, or denies, and self-issuing has to be spelled out.
#[derive(Clone, Debug)]
pub enum BackstageAuth {
    /// **Secure.** Start with no dispatcher and deny every backstage request until a
    /// `Control::InstallGrant` signed by this issuer verifies; the dispatcher is then scoped to
    /// exactly the capabilities that grant carries.
    SignedBy(PublicIdentity),
    /// **Fail closed.** No issuer key is available, so no grant could ever be verified — deny all
    /// backstage for the whole session. Streaming, input, and clipboard are unaffected: this gates
    /// the tool panels, not the remote-control session itself.
    Deny,
    /// **INSECURE — local dev/test only.** Self-issue a full-capability grant at session start.
    /// Never reachable by default; a caller must name it.
    InsecureSelfIssued,
}

/// The backstage trust policy for an ATTENDED (on-demand) guest session, given whatever
/// `grant_issuer_pubkey` the control plane advertised at redeem time.
///
/// Fail-closed by construction, and the single place that decision is made so a test can assert on
/// the same code the guest client runs (see `attended_guest_denies_backstage_without_a_signed_grant`):
///
/// * a well-formed key ⇒ [`BackstageAuth::SignedBy`] — the technician gets exactly the capabilities
///   the control plane signed for them (`BackstageCapsFor`), and nothing more;
/// * absent, empty, or malformed ⇒ [`BackstageAuth::Deny`].
///
/// It never falls back to self-issuing. An attended guest consented to a *support session*; consent
/// to being viewed is not consent to `ShellAsSystem`, so "we could not verify a grant" must mean
/// "no backstage", not "all of it".
pub fn attend_backstage_auth(issuer_pubkey_hex: Option<&str>) -> BackstageAuth {
    match issuer_pubkey_hex.map(str::trim) {
        Some(hex) if !hex.is_empty() => match PublicIdentity::from_hex(hex) {
            Ok(pk) => BackstageAuth::SignedBy(pk),
            Err(e) => {
                tracing::warn!(
                    "attend: control plane advertised an invalid grant_issuer_pubkey ({e:?}); \
                     backstage is DENIED for this session"
                );
                BackstageAuth::Deny
            }
        },
        _ => {
            tracing::warn!(
                "attend: control plane advertised no grant_issuer_pubkey; backstage is DENIED for \
                 this session (screen sharing and input are unaffected)"
            );
            BackstageAuth::Deny
        }
    }
}

/// Render one [`UpdateCheck`] as a helper.log message, and say whether it is a LOUD one.
///
/// Pure, so every branch is asserted without a filesystem or a clock
/// (`tests::every_update_check_outcome_renders_a_distinct_line`). The I/O half is
/// [`log_update_status`], which is short precisely because everything worth testing lives here. The
/// returned message carries no `helper: ` prefix — the caller adds that, and adds `WARNING - ` when
/// the flag is set, so loudness is one decision made in one place and greppable in helper.log.
///
/// **This is the ENTIRE behaviour of docs/21 step 2 on the agent.** Nothing downloads, nothing is
/// staged, nothing is applied. §8 orders the steps so the trust model can be exercised - signed,
/// verified, and visible in the log - before anything exists that could act on it, and this
/// function is where "visible in the log" happens. A future step 3 acts on
/// `UpdateAvailability::Available`; until then, a human reads it.
///
/// Loudness is decided per OUTCOME rather than by "errors are loud":
/// * a refusal or a failed verification is LOUD, because somebody placed a file this agent will
///   never act on and nothing else in the system would ever tell them;
/// * an available update is LOUD, because reporting it is the whole point of the step;
/// * "no manifest" and "no update available" are quiet, so that the loud lines keep meaning
///   something on a machine that has been logging for weeks.
fn describe_update_check(check: &rmt_agent::update::UpdateCheck, running: &str) -> (bool, String) {
    use rmt_agent::update::{UpdateAvailability, UpdateCheck};
    match check {
        UpdateCheck::NoManifest => {
            (false, format!("agent version {running}; no update manifest present"))
        }
        UpdateCheck::Refused(reason) => (
            true,
            format!(
                "an update manifest is present but this agent REFUSES ALL UPDATES - {reason}. \
                 No update can ever be applied on this machine until that is fixed (docs/21 §3)."
            ),
        ),
        UpdateCheck::Invalid(e) => (
            true,
            format!(
                "the update manifest FAILED VERIFICATION and is being ignored: {e}. An unexpected \
                 signature failure is tampering until proven otherwise, not a typo."
            ),
        ),
        UpdateCheck::Incomparable { running, offered, reason } => (
            true,
            format!(
                "the update manifest verified but its version cannot be compared with this build \
                 (running {running}, manifest {offered}): {reason}"
            ),
        ),
        UpdateCheck::Verified { release, availability } => match availability {
            UpdateAvailability::Available { running, offered } => (
                true,
                format!(
                    "UPDATE AVAILABLE - running {running}, verified manifest offers {offered} \
                     (sha256 {}). Nothing is downloaded or installed; this build only reports it.",
                    release.sha256
                ),
            ),
            UpdateAvailability::NoUpdate { running, offered } => (
                false,
                format!(
                    "agent version {running}; verified manifest offers {offered} - no update \
                     available"
                ),
            ),
            UpdateAvailability::UpgradePathUnsupported {
                running,
                offered,
                min_upgradable_from,
            } => (
                true,
                format!(
                    "update {offered} is available but NOT reachable from this build (running \
                     {running}, the manifest requires at least {min_upgradable_from}). This \
                     machine needs a manual upgrade."
                ),
            ),
        },
    }
}

/// Read, verify and report the update manifest - once, at helper start.
///
/// Deliberately a ONE-SHOT at startup rather than a timer. docs/21 §4's daily jittered check is
/// step 5, and §8 says explicitly not to reorder it earlier: a scheduled updater built before the
/// rollback watchdog is a mechanism that can break the fleet and cannot repair it. There is also
/// nothing here to schedule against - `crate::service`'s helper-lifetime loop is a bare stop-file
/// poll, and every other ticker in this file is session-scoped.
fn log_update_status(cfg: &crate::config::HelperConfig) {
    use rmt_agent::update::{check_for_update, UpdateTrust};
    let running = rmt_agent_core::version::AGENT_VERSION;
    // BOTH keys go in, and the comparison between them is the point: see `UpdateTrust::from_config`
    // and docs/21 §3. An operator who pasted the control plane's key into `update_signer_pubkey`
    // has silently merged two very different threat models, and this is the only place in the
    // system that would ever notice.
    let trust = UpdateTrust::from_config(
        cfg.update_signer_pubkey.as_deref(),
        cfg.grant_issuer_pubkey.as_deref(),
    );
    // A clock that will not read is treated as epoch, which makes every manifest look
    // not-yet-valid and therefore REFUSED. That is the correct direction: an agent that cannot tell
    // the time must not be the one deciding a signed instruction is still fresh.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let check = check_for_update(
        std::path::Path::new(crate::config::UPDATE_MANIFEST_FILE),
        &trust,
        running,
        now_ms,
    );
    let (loud, msg) = describe_update_check(&check, running);
    log_line(false, &format!("helper: {}{msg}", if loud { "WARNING - " } else { "" }));
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            guest_end_reports: None,
            sink: Arc::new(NoopSink),
            transfer_dir: PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
            clipboard: None,
            // Today's behaviour exactly. The restriction that matters for an ungoverned clipboard —
            // view-only refusing both directions — is unconditional in the session loop and does not
            // depend on this default.
            clipboard_mode: ClipboardMode::Bidirectional,
            // Fail closed: a caller that has not thought about backstage authorization gets none.
            backstage_auth: BackstageAuth::Deny,
            // Default OFF, NOT fail-closed like backstage_auth: an agent with no pinned issuer key
            // cannot verify a policy at all, so defaulting this on would strand every session in
            // view-only for every existing install. The enforcing deployment opts in explicitly.
            require_session_policy: false,
            // The DERIVING mode, not "never" — the opposite of `require_session_policy` above, and
            // deliberately so. `require_session_policy` defaults off because turning it on where it
            // cannot work strands a session view-only; the lease mode defaults to deriving because
            // the derivation itself already answers "can it work here?" (a bound session on an agent
            // with a pinned issuer key), so a caller who has not thought about it gets enforcement
            // exactly where enforcement is possible and nothing where it is not.
            session_lease: SessionLeaseMode::FromSessionBinding,
            session_lease_grace: DEFAULT_LEASE_GRACE,
            identity: None,
            max_session: DEFAULT_STREAM_MAX_RUN,
            // Today's behaviour exactly — a caller that has not thought about quality policy gets
            // the ceiling the agent already had compiled in.
            quality_policy: QualityPolicy::default(),
            // No on-screen surface by default — see the field doc. The two production paths pass
            // `Some(..)`; everything headless wants nothing drawn.
            guest_ui: None,
            // A working ledger, not `None`. In-session replay protection is the floor; the helper
            // raises it by sharing one across reconnects.
            spent_grants: Arc::new(SpentGrants::default()),
            spent_elevations: Arc::new(SpentGrants::default()),
            // Production default: real input. The `--log-input` call sites set this true.
            mock_input: false,
            admin_rights: None,
            force_observer: false,
            // Production default: a real reboot. The `--log-input` call sites set this true so a gate
            // run / e2e can round-trip RebootGuest without rebooting the box.
            mock_reboot: false,
            // Production default: really launch tools. The dev/e2e paths set this true so a gate run
            // never spawns Task Manager / regedit on the CI box.
            mock_launch: false,
            // Production default: really run commands. The dev/e2e paths set this true so a gate run
            // never executes a controller-supplied command on the CI box.
            mock_command: false,
            // Default false = the SYSTEM per-session helper's posture: not the user, so fetch their
            // token. The attended host overrides it; see the field's own doc.
            host_runs_as_interactive_user: false,
            // Production default: really lock. The dev/e2e paths set this true so a gate run never
            // locks the CI box's own session.
            mock_lock: false,
            // Production default: really log off. The dev/e2e paths set this true so a gate run never
            // logs the CI box's operator out of their own session.
            mock_logoff: false,
            // Production default: the real loopback. Only `stream --synthetic-tone` sets it.
            synthetic_tone: false,
            // Off by default: a caller that has not named a location has not decided to write video
            // to this machine's disk, and inferring one for them is exactly the kind of permissive
            // Default this repo has shipped once already (docs/07 `insecure-default-nobody-chose`).
            recording_dir: None,
            recording_via_service: false,
            // Safe default: production semantics unchanged. Only the attend + multi-stream paths
            // with --secure-test-harness (and --features secure-test) set this true.
            #[cfg(feature = "secure-test")]
            secure_test_harness: false,
            // Nothing requested by default; the dispatch flips it on `EndSession { uninstall: true }`.
            uninstall_requested: Arc::new(AtomicBool::new(false)),
            // Single-session path by default; `run_multi_session_stream` sets this to `Some`.
            pre_built_transport: None,
            // Single-session path by default; `run_multi_session_stream` passes the SharedCapture's
            // selected_monitor so the remap boundary in inject_ev is coherent with capture.
            shared_selected_monitor: None,
            // Multi-session only; None for single-session path.
            shared_selection_state: None,
            shared_canvas: None,
            activity: None,
            // Multi-session only (docs/61); elsewhere hand-off is neither advertised nor honored.
            input_handoff: None,
        }
    }
}

/// Aborts a spawned task when dropped, so a task tied to a scope ends with it on every exit path.
struct AbortOnDrop<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Pass a received frame through unchanged, noting technician activity for the idle release
/// (update_guard.rs). Errors and non-technician channels are not activity.
fn note_activity(
    received: rmt_agent_core::transport::TransportResult<Frame>,
    activity: Option<&crate::update_guard::SessionActivity>,
) -> rmt_agent_core::transport::TransportResult<Frame> {
    if let (Ok(frame), Some(a)) = (&received, activity) {
        a.note_channel(frame.channel);
    }
    received
}
/// Load the persisted chat transcript (M12), or an empty one.
///
/// **JSONL, one entry per line, not a JSON array.** A single malformed or half-written line — the
/// state a crash mid-write leaves behind — costs exactly that line here; with an array it would
/// make the whole file unparseable and silently discard the entire support conversation. Bad lines
/// are skipped with a count rather than failing the load, for the same reason.
///
/// A missing file is the normal first-run state and is not an error.
fn load_transcript(path: &std::path::Path) -> Transcript {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Transcript::new(),
        Err(e) => {
            tracing::warn!(error = %e, path = %path.display(), "could not read the chat transcript; starting empty");
            return Transcript::new();
        }
    };
    let mut entries = Vec::new();
    let mut skipped = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        match serde_json::from_str::<rmt_agent_core::ChatEntry>(line) {
            Ok(e) => entries.push(e),
            Err(_) => skipped += 1,
        }
    }
    if skipped > 0 {
        tracing::warn!(skipped, path = %path.display(), "skipped unparseable chat transcript lines");
    }
    // Sort by sequence: `restore` derives the next sequence from the maximum, but `history_since`
    // relies on the retained window being in order, and a hand-edited or concatenated file need not
    // be.
    entries.sort_by_key(|e: &rmt_agent_core::ChatEntry| e.seq);
    Transcript::restore(entries)
}

/// Persist the transcript, replacing the file.
///
/// Best-effort: a failure to write must never break a live session — the operator would rather have
/// working chat with no history than a session that dies because a disk is full. It is logged at
/// debug and the in-memory transcript keeps working.
///
/// Written whole rather than appended because the transcript is a bounded window that EVICTS its
/// oldest entries; appending would grow the file without bound and re-load a window larger than
/// `MAX_TRANSCRIPT` on every restart.
fn save_transcript(path: &std::path::Path, transcript: &Transcript) {
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    let mut out = String::new();
    for e in transcript.entries() {
        match serde_json::to_string(e) {
            Ok(line) => {
                out.push_str(&line);
                out.push('\n');
            }
            Err(e) => tracing::debug!(error = %e, "could not serialize a chat entry"),
        }
    }
    if let Err(e) = std::fs::write(path, out) {
        tracing::debug!(error = %e, path = %path.display(), "could not persist the chat transcript");
    }
}

/// Current wall-clock time as Unix milliseconds, for the backstage audit chain's `occurred_at`.
/// This is product code (not a workflow script), so ambient `SystemTime` is acceptable here.
fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Serve one remote-control session over a single [`WebRtcTransport`]: stream the display **and**
/// receive + inject controller input, both over the same connection.
///
/// Connects as [`Role::Agent`] (rendezvous via the signaling server at `signaling_url`), then runs
/// two concurrent halves against the one transport:
///
/// * **Video (down):** a dedicated OS thread owns the blocking `capturer`, paces to `target_fps`,
///   and pushes each [`CapturedFrame`] across a small bounded channel; the async loop drains it and
///   hands frames to a [`VideoFrameSender`](rmt_transport_webrtc::VideoFrameSender) obtained from
///   [`WebRtcTransport::video_sender`]. That handle does not borrow the transport, which is what
///   lets the same task also…
/// * **Input (up):** call [`Transport::recv_frame`] (`&mut transport`) and, for every frame tagged
///   [`ChannelId::Input`], [`input_codec::decode`] it and **forward** the event to the capture
///   thread over an `mpsc` channel; that thread drains the queue each iteration and `sink.inject`s
///   each event. Injection therefore runs on the **same** thread the capturer binds (M7) — required
///   for the SYSTEM helper, whose `capturer` is a [`FollowingCapturer`](crate::following_capturer)
///   that `SetThreadDesktop`s that thread onto the active input desktop (incl. Winlogon/UAC).
///   `SendInput` acts on the calling thread's desktop, so injecting anywhere else would miss it.
/// * **Backstage (up+down):** frames tagged [`ChannelId::Backstage`] are backstage request JSON;
///   each is run through a session-scoped [`Dispatcher`] (M5) and the resulting `Envelope` JSON is
///   sent straight back on the same channel. Frames on other channels are ignored (logged at debug).
///
/// The two halves share one `tokio::select!` loop, so the video-send path (which needs no transport
/// borrow) and the input-receive path (which needs `&mut transport`) never borrow it at once. The
/// loop ends when `stop` is set, the capture thread stops, the data channel closes, or
/// [`SessionOptions::max_session`] elapses.
/// The session's input gate at ITS final injection boundary: the capture thread calls `inject` on
/// this, so input queued in the session's channel before a restriction (view-only, a lost indicator,
/// guest End) is dropped when it is drained, not injected after it (Codex 1.3.9 round 2). Key and
/// button releases always pass. `set_admitted` also reaches the wrapped sink, whose own queue (the
/// shared capture channel) is gated the same way.
struct GatedSink {
    inner: Arc<dyn InputSink>,
    /// Held for READ across the check AND the injection, taken for WRITE to change admission: a
    /// revocation waits for an injection already past the check (Codex 1.3.9 round 3).
    admitted: std::sync::RwLock<bool>,
    /// Bumped (under the write fence) by every revocation. The session queue stamps each event with
    /// the epoch it was queued under; a press from an older epoch is dropped even after re-admission
    /// (Codex 1.3.9 round 14).
    epoch: std::sync::atomic::AtomicU64,
}

impl GatedSink {
    fn new(inner: Arc<dyn InputSink>) -> Self {
        Self { inner, admitted: std::sync::RwLock::new(true), epoch: std::sync::atomic::AtomicU64::new(0) }
    }

    fn epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Inject an event queued under admission epoch `queued_epoch`: a press is dropped unless the
    /// session is admitted AND nothing was revoked since it was queued. Releases always pass.
    fn inject_stamped(&self, event: InputEvent, queued_epoch: u64) -> rmt_agent_core::platform::PlatformResult<()> {
        let admitted = self.admitted.read().unwrap_or_else(|e| e.into_inner());
        if (!*admitted || queued_epoch != self.epoch()) && !crate::shared_capture::is_release_event(&event) {
            return Ok(());
        }
        self.inner.inject(event)
    }
}

impl InputSink for GatedSink {
    fn inject(&self, event: InputEvent) -> rmt_agent_core::platform::PlatformResult<()> {
        self.inject_stamped(event, self.epoch())
    }
    fn release_held(&self) -> rmt_agent_core::platform::PlatformResult<()> {
        self.inner.release_held()
    }
    fn cancel_typing(&self, wait: bool) {
        self.inner.cancel_typing(wait);
    }
    fn set_admitted(&self, admitted: bool) {
        if admitted {
            // Downstream first (it waits for the revocation's cleanup), then open this gate.
            self.inner.set_admitted(true);
            *self.admitted.write().unwrap_or_else(|e| e.into_inner()) = true;
        } else {
            {
                let mut g = self.admitted.write().unwrap_or_else(|e| e.into_inner());
                if *g {
                    self.epoch.fetch_add(1, Ordering::SeqCst);
                }
                *g = false;
            }
            self.inner.set_admitted(false);
        }
    }
    fn release_keys(&self) -> rmt_agent_core::platform::PlatformResult<()> {
        self.inner.release_keys()
    }
}

/// Admit or refuse the session's input. Refusing returns only once nothing more can reach the guest:
/// the gates' write fences wait out injections already past their checks, and typing is awaited to
/// a stop off the async thread (a character in flight completes, then nothing).
async fn set_input_admitted(sink: &Arc<dyn InputSink>, admitted: bool) {
    // Off the async thread: the fences may wait for an injection in progress (SendInput holds the
    // sink's lock for its duration).
    let s = Arc::clone(sink);
    let _ = tokio::task::spawn_blocking(move || {
        if !admitted {
            // Cancel typing BEFORE taking the fences: a key waiting behind typing holds a read fence,
            // and the cancel drains the typing it waits for, so the fences below are not held up.
            s.cancel_typing(false);
        }
        s.set_admitted(admitted);
        if !admitted {
            s.cancel_typing(true);
        }
    })
    .await;
}

/// The admin-rights updates arm (docs/53): pends forever when this session has none.
async fn recv_admin_rights(
    rx: &mut Option<tokio::sync::mpsc::UnboundedReceiver<crate::admin_rights::AdminRightsUpdate>>,
) -> Option<crate::admin_rights::AdminRightsUpdate> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// docs/61 (cross-stage review): a session may hand or hold input control only while it is registered,
/// not an observer, and NOT view-only (a policy floor, the toggle, or a lost guest indicator). Called at
/// registration and again wherever view-only changes; an owner that turns view-only frees input to
/// `Blocked` (see `InputArbiterHub::set_control_eligible`).
fn sync_handoff_eligibility(handoff: &Option<InputHandoffWiring>, registered: bool, observer: bool, view_only: bool) {
    if let Some(w) = handoff {
        w.shared.arb.set_control_eligible(w.handle, registered && !observer && !view_only);
    }
}

/// The input hand-off channel arm (docs/61): pends forever when this session takes no part.
async fn recv_handoff(
    rx: &mut Option<crate::session_directory::HandoffRx>,
) -> Option<crate::session_directory::HandoffOutbound> {
    match rx {
        Some(r) => r.recv().await,
        None => std::future::pending().await,
    }
}

/// One session's admission slot for input hand-offs (docs/61, Codex 3b review): at most ONE hand in
/// flight per session, taken synchronously BEFORE any task is spawned and moved into the blocking job,
/// so it is released only when `hand_input_control` returns. A controller that floods
/// `HandInputControl` therefore cannot pile up tasks or blocking jobs (each of which briefly holds the
/// dispatch gate every session's input passes). The machine-wide bound is separate: the hub's
/// `MAX_HANDS_IN_FLIGHT` permit, which also covers jobs left running by sessions that already ended.
#[derive(Clone, Default)]
struct HandSlot(Arc<AtomicBool>);

/// Proof that a [`HandSlot`] is held; dropping it frees the slot.
struct HandPermit(Arc<AtomicBool>);

impl HandSlot {
    fn try_acquire(&self) -> Option<HandPermit> {
        (!self.0.swap(true, Ordering::SeqCst)).then(|| HandPermit(Arc::clone(&self.0)))
    }
}

impl Drop for HandPermit {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// What the input hand-off audit arm does with one `SealAudit` directive (docs/61 stage 3c, Codex 3c
/// review). A sealed event that is never delivered is a seq hole, and the control plane can never
/// get past a hole: every LATER event of this chain would be refused forever. So:
///
/// * once this session's data channels are known broken (`input_open == false`), nothing is sealed —
///   the directive is dropped and the chain does not advance;
/// * a sealed event that cannot even be encoded is reported as `Broken`, and the caller closes input,
///   so no later event can be sealed behind it;
/// * the caller closes input on a failed send for the same reason.
///
/// A hole can therefore only ever be the LAST event of a chain, and a chain lives for exactly one
/// transport (a reconnect is a new brokered session with a new chain; cancelling the send drops the
/// session, ending its chain).
enum HandoffSealStep {
    /// Input is closed: nothing sealed.
    Skip,
    /// The chain is unidentified (dev/LAN): `try_record_shared` sealed nothing.
    Unidentified,
    /// Sealed; send this frame on the FileTransfer channel.
    Deliver(FtMessage),
    /// Sealed but unencodable: the caller must close input.
    Broken,
}

fn handoff_seal_step(
    input_open: bool,
    chain: &SharedAuditChain,
    action: AuditAction,
    now_ms: i64,
) -> HandoffSealStep {
    if !input_open {
        return HandoffSealStep::Skip;
    }
    match rmt_agent::backstage::audit::try_record_shared(chain, action, Outcome::Ok, now_ms) {
        None => HandoffSealStep::Unidentified,
        Some(event) => match ft_audit(event.id, &event) {
            Some(message) => HandoffSealStep::Deliver(message),
            None => HandoffSealStep::Broken,
        },
    }
}

/// Every input hand-off refusal starts with this, so the viewer can attribute an `Error` to its pending
/// hand without mistaking an unrelated agent error for one (docs/61 stage 3d). Pinned in the viewer's
/// `lib/input_handoff.ts` (`INPUT_CONTROL_ERROR_PREFIX`) — change both or neither.
const INPUT_CONTROL_ERROR_PREFIX: &str = "input control: ";

fn input_control_error(text: &str) -> String {
    format!("{INPUT_CONTROL_ERROR_PREFIX}{text}")
}

/// What to tell the requesting technician about a finished hand (docs/61), or `None` when it
/// committed — success is announced by the `Owned` snapshot every participant receives, never by a
/// reply that could disagree with it.
fn hand_outcome_message(
    outcome: &Result<crate::input_arbiter::CommitOutcome, crate::shared_capture::HandError>,
) -> Option<String> {
    use crate::input_arbiter::{CommitOutcome, HandRefusal};
    use crate::shared_capture::HandError;
    let text = match outcome {
        Ok(CommitOutcome::Owned { .. }) => return None,
        Ok(CommitOutcome::BlockedTargetGone) | Ok(CommitOutcome::StaleTransition) => {
            "the hand-off did not complete: that technician left the session"
        }
        Err(HandError::FenceAborted) => "the hand-off did not complete: the agent is stopping",
        Err(HandError::Refused(r)) => match r {
            HandRefusal::NotOwner { .. } => "another technician has input control; only they can hand it on",
            HandRefusal::Busy => "a hand-off is already in progress",
            HandRefusal::SenderNotLive | HandRefusal::SenderNotEligible => "this session cannot hand input control",
            HandRefusal::TargetNotLive => "that technician is no longer in this session",
            HandRefusal::TargetNotEligible => "that technician is observing and cannot take input control",
            HandRefusal::SelfHandMeaningless => "input is shared; you already have control",
        },
    };
    Some(input_control_error(text))
}

/// Whether a session must be held view-only because the guest's indicator could not be shown: a
/// guest window was asked for (an interactive production session) and it did not open.
fn no_indicator_floor(guest_ui_requested: bool, guest_window_open: bool) -> bool {
    guest_ui_requested && !guest_window_open
}

pub async fn serve_session(
    signaling_url: &str,
    device: DeviceId,
    capturer: impl ScreenCapturer + 'static,
    target_fps: u32,
    sink: Arc<dyn InputSink>,
    stop: Arc<AtomicBool>,
    transfer_dir: PathBuf,
) -> Result<(), String> {
    // LAN/loopback: no ICE servers (host candidates suffice). No clipboard, no grant issuer — the
    // public `serve_session` entry point stays a thin dev-mode convenience so its existing callers
    // (the e2e input/backstage/file-transfer tests, `stream_screen`) are unchanged; it runs
    // backstage in **insecure dev mode** (self-issued demo grant). The CLI/helper paths call
    // `serve_session_with_ice` with a full `SessionOptions` (clipboard + optional grant issuer).
    serve_session_with_ice(
        signaling_url,
        device,
        capturer,
        target_fps,
        stop,
        Vec::new(),
        // `backstage_auth` is stated, not defaulted: `SessionOptions::default()` fails CLOSED
        // (`Deny`), and this entry point's documented contract is dev mode.
        SessionOptions {
            sink,
            transfer_dir,
            backstage_auth: BackstageAuth::InsecureSelfIssued,
            ..Default::default()
        },
    )
    .await
}

/// Like [`serve_session`], but with STUN/TURN [`IceServer`]s for WAN NAT traversal (M6). Pass an
/// empty `ice` for LAN/loopback. STUN lets peers discover server-reflexive candidates; TURN relays
/// media for symmetric NAT. In production the TURN credential comes from the signaling
/// `RelayAssignment`, not a static config.
///
/// Per-session behavior (input sink, transfer dir, clipboard, H1 backstage auth) is bundled into
/// [`SessionOptions`] (all fields have a `Default`) — pass `SessionOptions { sink, .. }` and set
/// only what you need. `clipboard` (M9): `Some(Box::new(WinClipboard::new()))` enables
/// bidirectional text sync over [`ChannelId::Clipboard`]; `None` disables it. `backstage_auth`
/// (H1): see [`BackstageAuth`] — pin an issuer, deny, or (dev only, never by default) self-issue.
/// See [`clipboard_worker`] for the clipboard worker + echo-suppression design.
#[allow(clippy::too_many_arguments)]
pub async fn serve_session_with_ice(
    signaling_url: &str,
    device: DeviceId,
    mut capturer: impl ScreenCapturer + 'static,
    target_fps: u32,
    stop: Arc<AtomicBool>,
    ice: Vec<IceServer>,
    opts: SessionOptions,
) -> Result<(), String> {
    // Extract the cfg-gated secure_test_harness field BEFORE destructuring opts (which moves it).
    // bool is Copy so this reads without consuming; opts is still fully movable after.
    #[cfg(feature = "secure-test")]
    let opts_secure_test_harness = opts.secure_test_harness;
    let SessionOptions {
        guest_end_reports,
        sink,
        transfer_dir,
        clipboard,
        clipboard_mode,
        backstage_auth,
        require_session_policy,
        session_lease: session_lease_mode,
        session_lease_grace,
        identity,
        quality_policy: opts_quality_policy,
        max_session,
        guest_ui,
        spent_grants,
        spent_elevations,
        mock_input,
        force_observer,
        mock_reboot,
        mock_launch,
        mock_command,
        host_runs_as_interactive_user,
        mock_lock,
        mock_logoff,
        synthetic_tone,
        recording_dir,
        recording_via_service,
        uninstall_requested,
        pre_built_transport,
        shared_selected_monitor,
        shared_selection_state,
        shared_canvas,
        activity,
        admin_rights,
        input_handoff,
        ..
    } = opts;
    // docs/53: the request handle, and the updates it sends the controller.
    let (admin_rights, mut admin_rights_rx) = match admin_rights {
        Some((rights, updates)) => (Some(rights), Some(updates)),
        None => (None, None),
    };
    // Every injection of this session passes the admission gate (see GatedSink).
    let gated = Arc::new(GatedSink::new(sink));
    let sink: Arc<dyn InputSink> = gated.clone();
    // File-transfer root (M8): uploads land here, downloads are confined here. Create it up front
    // (best-effort; the per-transfer handlers also create it, so a late-created dir still works).
    if let Err(e) = std::fs::create_dir_all(&transfer_dir) {
        tracing::debug!(error = %e, dir = %transfer_dir.display(), "could not pre-create transfer dir");
    }
    // Expire old recordings BEFORE this session can add one (loop 89). There is no background job
    // anywhere in this repo and a video recorder is not the feature to introduce one with, so the
    // TTL is enforced at the two moments the agent is already awake: helper start and session start.
    // Here, rather than after the transport connects, so the sweep's IO is off the session's own
    // critical path and a machine that is supported regularly keeps clearing itself even when no
    // recording is ever started.
    if let Some(dir) = recording_dir.as_deref() {
        let removed = crate::recording::sweep_expired(dir, crate::recording::now_unix_ms());
        if removed > 0 {
            tracing::info!(removed, dir = %dir.display(), "recordings: expired copies deleted");
        }
    }
    // The broker generates each recording's final subdirectory. This root only selects
    // the backend; ordinary CLI code never creates, sweeps or opens service storage.
    let recording_dir = if recording_via_service {
        Some(PathBuf::from(crate::recording_broker::DIRECTORY))
    } else { recording_dir };
    // Active inbound uploads keyed by transfer id. One entry per in-flight controller→agent upload;
    // downloads (agent→controller) are served synchronously within a single Request and hold no
    // state here.
    // docs/58 §1, §12: uploads are owned by ONE writer thread (state, `.part` handles, all upload disk
    // I/O); this loop only forwards frames with `try_send` and keeps each upload's cancel flag (with
    // its offered name, for teardown's record). The transfer root is opened by the writer on the
    // first authorized upload: on a LocalSystem host only the agent's own anchored folder, anything
    // else disables uploads for the session. `upload_root_slot` publishes the opened root to the file
    // manager (placement).
    let mut live_uploads: HashMap<Uuid, (crate::upload_writer::Flag, String)> = HashMap::new();
    let upload_root_slot: Arc<std::sync::Mutex<Option<Arc<crate::upload_root::UploadRoot>>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Placement works only from the agent's own anchored folder, which a LocalSystem host whose
    // transfer_dir is the default will use (docs/58 §12).
    let can_place_uploads = (crate::update_worker::is_local_system()
        && crate::upload_root::is_default_transfer_dir(&transfer_dir))
        || crate::upload_root::test_harness_anchored();

    let audit_signer = identity.as_ref().map(|id| (id.pubkey.clone(), id.signer.clone()));
    let role = agent_role(device, identity, require_session_policy);

    // Multi-session path: transport already connected by `run_multi_session_stream`. Single-session
    // path: connect now, which blocks until a controller connects or CONNECT_TIMEOUT elapses.
    let mut transport = if let Some(t) = pre_built_transport {
        t
    } else {
        WebRtcTransport::connect_with_ice(signaling_url, role, ice).await?
    };

    // WHICH control-plane session this connection is, for binding a signed session policy to it.
    // Read ONCE here, for the same borrow reason as `video` below: the select! loop holds
    // `&mut transport`, and this value never changes for the life of the connection.
    //
    // Absent means the signaling server did not vouch for a session id — it verifies no tickets
    // (dev/LAN/e2e), or it predates the field. `SessionBinding::Unknown` then REJECTS every policy
    // rather than accepting one it cannot bind; the enum spells both readings so neither is a
    // default nobody chose.
    // Kept as well as folded into the binding: a recording's sidecar names the control-plane session
    // it belongs to, and it wants the raw id rather than the binding's fail-closed reading. The two
    // must come from ONE read of the transport — deriving the sidecar's copy separately would let a
    // future change give the policy and the artifact different answers about which session this is.
    let control_plane_session = transport.control_plane_session();
    let session_binding = match control_plane_session {
        Some(id) => SessionBinding::Session(id),
        None => SessionBinding::Unknown,
    };
    // WHO the technician is, from the same verified ticket and read once for the same borrow reason.
    // The agent has no other source: the viewer must not self-attribute (that is the forgery
    // `POST /audit/ingest` answers 403 to) and an unverified ticket is attacker-chosen.
    let session_technician = transport.session_technician();
    // HOW this session may act (observer design v2), from the same verified ticket, read once. Decided
    // here, before any frame, guest-window update or input path exists: an observer is view-only from
    // the first frame, and a session whose access signaling stated wrongly never starts at all.
    let observer = match session_observer(transport.session_access(), force_observer) {
        Ok(observer) => observer,
        Err(reason) => {
            tracing::warn!(cp_session = ?control_plane_session, "{reason}");
            report_session_end(guest_end_reports.as_ref(), control_plane_session, rmt_protocol::signaling::SessionEndReason::Policy);
            return Err(reason.into());
        }
    };
    if observer {
        tracing::info!(cp_session = ?control_plane_session, "observer session: view-only from the first frame");
    }
    // THE SESSION'S AUDIT CHAIN (loop 91). Built here, unconditionally, from the session itself
    // rather than from a backstage grant — which is the whole point of the lift:
    //
    //  * a session with NO grant used to have no chain at all, so ADR-008's file-transfer trail was
    //    silently absent for every such session and recording had nowhere to record; and
    //  * a second `InstallGrant` used to replace the dispatcher and restart the chain at `seq 0`,
    //    a fork the console's forwarder then de-duplicates away because it keys `seen` on `seq`.
    //
    // Nil ids where signaling vouched for nothing. That is deliberate and fail-closed: the control
    // plane compares `technician_id` to the authenticated forwarder and REFUSES a mismatch, so a
    // dev/LAN session keeps its local trail (helper log, recording sidecar) and gains no central
    // record attributed to nobody. It is NOT a licence to substitute something more convenient.
    let audit_chain: SharedAuditChain = rmt_agent::backstage::audit::new_shared_chain(
        control_plane_session.unwrap_or_else(uuid::Uuid::nil),
        session_technician.unwrap_or_else(uuid::Uuid::nil),
        device.0,
    );
    if let Some((pubkey, signer)) = audit_signer {
        audit_chain.lock().expect("new audit chain").set_signer(pubkey, Arc::new(move |bytes| signer.sign(bytes)));
    }
    tracing::debug!(
        cp_session = control_plane_session.map(|u| u.to_string()).unwrap_or_else(|| "<none>".into()),
        technician = session_technician.map(|u| u.to_string()).unwrap_or_else(|| "<none>".into()),
        "session audit chain opened"
    );
    tracing::debug!(
        binding = ?session_binding,
        "session policy binding resolved from the brokered rendezvous"
    );
    // THE SESSION LEASE (docs/25 F03). Built here, from the binding just resolved, because this is
    // the first point at which both facts it needs are known: whether the control plane is
    // authoritative for this session, and whether this agent can verify anything the control plane
    // signs.
    //
    // WHY THE BINDING AND NOT `require_session_policy`. That flag is an operator opt-in that
    // defaults FALSE, and defaults false for a good reason (an agent with no pinned issuer key
    // cannot verify a policy, so turning it on by default would strand every session view-only). A
    // lease keyed on it would bind on almost no deployment in the field — worse than useless,
    // because the finding would look closed while nothing changed. `control_plane_session` is the
    // honest signal: `Some` means a signaling server verified a real control-plane session ticket
    // for this connection, so the control plane IS authoritative here and may therefore revoke.
    // `None` means it is not (dev/LAN, or signaling run with `-insecure-no-ticket-verification`),
    // and a lease is inapplicable — the same fail-closed reasoning `SessionBinding::Unknown` already
    // spells out, reused rather than re-invented.
    let can_verify_policies = matches!(backstage_auth, BackstageAuth::SignedBy(_));
    let mut session_lease = SessionLease::new(
        session_lease_mode,
        session_binding,
        can_verify_policies,
        session_lease_grace,
    );
    if session_lease.is_enforced() {
        tracing::info!(
            grace_ms = session_lease_grace.as_millis() as u64,
            "session lease REQUIRED: this session ends unless the controller keeps renewing a \
             control-plane-signed policy"
        );
    } else if matches!(session_binding, SessionBinding::Session(_))
        && !can_verify_policies
        && matches!(session_lease_mode, SessionLeaseMode::FromSessionBinding)
    {
        // THE ONE CONFIGURATION WHERE docs/25 F03 IS STILL OPEN, said out loud rather than left to
        // be inferred from silence. A control-plane-managed agent with no `grant_issuer_pubkey`
        // cannot tell a control-plane lease from an attacker's forgery, so it cannot hold one; an
        // administrator's "End session" therefore still does not reach this session. This is a
        // capability limit, not a tolerance we chose: the fix is to pin the key, and the control
        // plane never mints a lease for such an agent because the agent never asks for one.
        tracing::warn!(
            "session lease NOT ENFORCED: the control plane vouched for this session but no \
             grant_issuer_pubkey is pinned, so a signed lease cannot be verified — an \
             administrator ending this session centrally will NOT terminate it \
             (set grant_issuer_pubkey in config.json)"
        );
    }


    // Cloneable video handle that does NOT borrow `transport`, leaving `transport` free for the
    // `&mut self` input-receive path below (the borrow hazard the workplan flags).
    let video = transport
        .video_sender()
        .ok_or_else(|| "agent transport has no video sender".to_string())?;

    // Backstage tool RPC over the same transport (M5): one Dispatcher per session owns the running
    // audit chain. Inbound ChannelId::Backstage frames are request JSON; each is authorized +
    // executed through this choke point and the resulting Envelope JSON is sent straight back.
    //
    // H1 trust policy — the dispatcher is `Option`, initialized from `backstage_auth`:
    //  * `SignedBy` (production/secure) ⇒ start with NO dispatcher. Every backstage request is
    //    denied ("no valid grant installed") until a `Control::InstallGrant` carrying a grant signed
    //    by the issuer verifies, at which point the dispatcher is built scoped to exactly the
    //    granted capabilities.
    //  * `Deny` ⇒ start with no dispatcher and never arm one. No issuer means no grant could be
    //    verified, so backstage stays denied for the session.
    //  * `InsecureSelfIssued` (dev/local CLI + some tests, and never a default) ⇒ self-issue the
    //    full demo grant, with a loud warning.
    // Secure-test: tracks whether a grant has been verified (but not executed) in harness mode.
    // In production builds this variable does not exist.
    #[cfg(feature = "secure-test")]
    let mut secure_test_grant_installed = false;
    // docs/58 §1: revoked when the guest's indicator is lost and at teardown; every dispatcher this
    // session arms shares it, and file transfers consult it too.
    let mutation_gate = Arc::new(rmt_agent::backstage::gate::MutationGate::new());
    let mut dispatcher: Option<Dispatcher> = match &backstage_auth {
        BackstageAuth::SignedBy(issuer) => {
            tracing::info!(
                issuer = %issuer.to_hex(),
                "backstage: secure grant mode — denying backstage until a signed grant is installed"
            );
            None
        }
        BackstageAuth::Deny => {
            tracing::info!(
                "backstage: DENIED for this session — no grant issuer available to verify a grant \
                 against. Streaming and input are unaffected."
            );
            None
        }
        BackstageAuth::InsecureSelfIssued => {
            tracing::warn!(
                "backstage: INSECURE DEV MODE — self-issuing a full demo grant. Production sessions \
                 must pin a grant issuer so signed grants are required."
            );
            Some(equip_dispatcher(new_backstage_dispatcher(device.0, audit_chain.clone()), &mutation_gate, &upload_root_slot))
        }
    };
    // docs/58 §1, §12: Backstage requests run on a serial worker with its own twin dispatcher, so a
    // request stalled in a system call never stalls this loop. Replies come back in order on
    // `backstage_reply_rx`.
    let (backstage_reply_tx, mut backstage_reply_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let backstage_worker = crate::backstage_worker::BackstageWorker::spawn(backstage_reply_tx, now_unix_ms);
    let (upload_out_tx, mut upload_out_rx) = tokio::sync::mpsc::unbounded_channel::<crate::upload_writer::Out>();
    let upload_ledger = Arc::new(crate::upload_writer::Ledger::default());
    let upload_writer = crate::upload_writer::UploadWriter::spawn(
        audit_chain.clone(),
        Arc::clone(&upload_ledger),
        crate::upload_root::LazyRoot::new(transfer_dir.clone(), crate::update_worker::is_local_system()),
        Arc::clone(&upload_root_slot),
        Arc::clone(&mutation_gate),
        upload_out_tx,
        now_unix_ms,
    );
    if let Some(d) = dispatcher.as_ref() {
        backstage_worker.install(equip_dispatcher(d.twin(), &mutation_gate, &upload_root_slot));
        upload_writer.install(d.twin());
    }

    // Quality control (M11). The caller's `target_fps` is the session's starting frame rate; from
    // here it is the operator's to change, so it lives in an atomic the capture thread re-reads
    // every iteration rather than in a `Duration` computed once.
    //
    // `quality_armed` is the fail-safe (see `control::ControlMessage`'s module docs): until this
    // session hears `RequestQuality` or `SetQuality`, the agent emits NOTHING new — an older
    // controller's traffic is byte-for-byte what it is today.
    let mut quality = QualitySettings {
        fps: target_fps.clamp(quality::MIN_FPS, quality::MAX_FPS),
        ..QualitySettings::DEFAULT
    };
    let policy = opts_quality_policy;
    // Apply the machine policy THROUGH the same function a `SetQuality` uses, and keep its verdict.
    //
    // Hard-coding `capped_by_policy = false` here (which is what this did first) makes the very
    // first `QualityApplied` of every session lie: an agent configured `{"quality":{"max_fps":10}}`
    // answers the console's connect-time `RequestQuality` with `fps: 10, capped_by_policy: false`,
    // so the operator sees a frame rate they did not choose with nothing saying an administrator
    // chose it for them. The flag exists precisely to distinguish those two cases.
    let (bounded, capped_at_start) = policy.apply(quality);
    quality = bounded;
    let mut capped_by_policy = capped_at_start;
    let mut quality_armed = false;
    // The viewer's window is hidden (ControlMessage::SetBackground): pace at BACKGROUND_FPS and send
    // no keep-alives, without touching `quality`.
    let mut background = false;
    let fps_now = Arc::new(AtomicU32::new(quality.fps));
    let scale_div = Arc::new(AtomicU32::new(quality.scale_div));
    // Fresh frames the capture loop obtained vs pulls that yielded none. The encoder's frame count
    // cannot tell them apart (the keep-alive re-sends the last frame), so a session showing a
    // frozen picture was invisible in telemetry. Reported on the quality-telemetry debug line.
    let capture_counts = Arc::new((std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0)));
    let mut stats = transport.video_stats();
    // Apply the starting quality once, so the encoder begins the session at the machine's policy
    // ceiling rather than at the transport's compiled-in default. On a machine with no policy this
    // is the same 3 Mbps it already used, so the default path is unchanged.
    if let Err(e) = video.set_quality(VideoQuality {
        color: ChromaMode::Full,
        max_bitrate_bps: quality.max_bitrate_bps,
        hard_cap_bps: policy.bitrate_cap_configured.then_some(policy.max_bitrate_bps),
        adaptive: quality.adaptive,
    }) {
        tracing::debug!(error = %e, "could not apply the initial quality");
    }

    // In-session chat (M12). The transcript lives on the AGENT because the agent is the only party
    // present for every session with this machine — see `chat`'s module docs for why that is what
    // makes the sequence numbers a usable resume cursor.
    //
    // It is loaded from disk at session start and saved after every post, so a technician who
    // reconnects (or a second technician later) sees the conversation rather than an empty box.
    let chat_path = transfer_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new(r"C:\rmt-agent"))
        .join("chat.jsonl");
    let mut transcript = load_transcript(&chat_path);
    tracing::debug!(
        path = %chat_path.display(),
        entries = transcript.entries().len(),
        last_seq = transcript.last_seq(),
        "chat transcript loaded"
    );

    // The guest's own window (docs/01 §5 + §7). Per SESSION, not per process: the banner says "a
    // technician is connected right now", which is only true inside this function, and the teardown
    // block below joins its thread exactly like the capture and clipboard threads.
    //
    // A failure to open does NOT end the session (refusing to stream because a window could not be
    // drawn would turn a drawing failure into an outage for the technician trying to fix the machine),
    // but it does take CONTROL away: with no window and no pill, a person at the machine could be
    // controlled with nothing telling them so, and the indicator is always on by the operator's choice
    // (Ed, 2026-10-23). So the session continues as an OBSERVER, view-only from the first frame with no
    // way to lift it, and the technician is told why (Codex 1.3.8 round 2).
    let (guest_tx, mut guest_rx) = tokio::sync::mpsc::unbounded_channel::<GuestToHost>();
    let guest_ui_requested = guest_ui.is_some();
    let mut guest_surface: Option<Box<dyn GuestSurface>> = match guest_ui {
        Some(ui) => match ui.open(guest_tx) {
            Ok(s) => {
                tracing::info!("guest window: open");
                Some(s)
            }
            Err(e) => {
                tracing::warn!(error = %e, "guest window: could not open; the session continues VIEW-ONLY (no indicator, no control)");
                None
            }
        },
        None => None,
    };
    let indicator_missing = no_indicator_floor(guest_ui_requested, guest_surface.is_some());
    let observer = observer || indicator_missing;
    // docs/61 stage 3b: this session's hand-off channel. It carries the machine-wide
    // InputControlChanged snapshots (queued by the arbiter on every mode change) and this session's
    // own hand refusals; the select loop drains it onto the transport. The session joins the
    // directory at its start announcements, and `handoff_registration` unregisters it on every exit.
    let (handoff_tx, handoff_rx) = crate::session_directory::handoff_channel();
    let mut handoff_rx = input_handoff.as_ref().map(|_| handoff_rx);
    let mut handoff_registration: Option<crate::shared_capture::DirectoryRegistration> = None;
    // At most ONE hand in flight per session: a controller flooding HandInputControl cannot pile up
    // blocking tasks, each of which briefly holds the dispatch gate every session's input passes.
    let hand_slot = HandSlot::default();
    if indicator_missing {
        let payload = control::encode(&ControlMessage::Error {
            message: "The guest's on-screen indicator could not be shown, so this session is view-only.".to_string(),
        });
        let _ = transport.send_frame(Frame::new(ChannelId::Control, payload)).await;
    }
    // Replay what the transcript already holds so a guest who reconnects mid-conversation is not
    // shown an empty window beside a technician who can see the whole history.
    //
    // `seed`, NOT `posted`. The two differ in exactly one respect: seeded lines are not counted as
    // unread. Replaying through `posted` made a machine with any support history open its window
    // announcing dozens of unread messages from previous sessions — a badge asserting the guest
    // missed something, for text that predates the window's existence.
    if let Some(s) = guest_surface.as_ref() {
        for e in transcript.entries() {
            s.seed(e.from, &e.body, e.at_unix_ms);
        }
    }

    // Multi-monitor control (M10). Two pieces of shared state connect the async Control branch to
    // the (blocking) capture thread that owns the capturer:
    //  * `selected` — the monitor id the capture thread streams. The Control branch writes it on a
    //    `SelectMonitor`; the capture thread reads it each iteration. Default 0 (primary), so every
    //    caller of `serve_session_with_ice` gets monitor control for free with no signature change.
    //  * `published` — the monitor list the capture thread enumerates **once** at start-up (the
    //    capturer lives only on that thread and must not be touched from the async side). The
    //    Control branch answers `RequestMonitors` from this snapshot and validates `SelectMonitor`
    //    ids against it.
    //
    // Multi-session path: `shared_selected_monitor` is the SharedCapture's own AtomicU32, shared
    // across all concurrent sessions. Using it here makes the single remap boundary in `inject_ev`
    // coherent with what the SharedCapture capture thread actually captures: a `SelectMonitor` from
    // any session updates this Arc, and both the remap and the capture see the same value.
    // Determine multi-session mode before consuming the Option fields.
    let is_multi_session = shared_selection_state.is_some();
    let selected: Arc<AtomicU32> = shared_selected_monitor
        .unwrap_or_else(|| Arc::new(AtomicU32::new(0)));
    let published: Arc<Mutex<Vec<MonitorDesc>>> = Arc::new(Mutex::new(Vec::new()));
    // Buffered notification: even if enumeration precedes the async loop, its list is retained.
    let (monitor_ready_tx, mut monitor_ready_rx) = tokio::sync::oneshot::channel();
    let mut monitor_announcement_pending = true;


    // Capture thread: owns the blocking capturer, paces to `target_fps`, pushes frames across.
    //
    // This channel is bounded, but — corrected loop 17 — it is NOT what bounds the pipeline, and
    // the comment that used to sit here saying it "back-pressures capture to the encode/send rate"
    // was simply false. The async `select!` loop below drains it in the time of one `Vec` clone
    // straight into the transport's UNBOUNDED `EncoderCommand` queue, so capture never blocked on
    // encode and the queue grew linearly with the overload (measured: 106 frames deep after 600 ms,
    // 315 after 1800 ms). What actually bounds it now is drain-to-latest in the encoder thread
    // (`transport-webrtc`'s `run_encoder_loop`). This bound of 4 remains useful for a different
    // reason: it caps how many full-resolution frames exist between the two threads at once.
    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<CapturedFrame>(4);

    // Input marshaling (M7): the async `select!` loop below DECODES inbound controller input but no
    // longer injects it — it forwards each `InputEvent` to THIS capture thread over an unbounded
    // `std::sync::mpsc` channel, and the capture thread drains + `sink.inject`s it each iteration.
    //
    // Why: for the SYSTEM helper the capturer is a `FollowingCapturer`, so this thread is the one
    // `DesktopFollower::poll`→`SetThreadDesktop` binds to the active input desktop. `SendInput` acts
    // on the *calling* thread's desktop, so injection MUST run here (not on a tokio worker on the
    // wrong desktop) to reach Winlogon/UAC. For the CLI/tests the capturer is synthetic and this
    // thread is an ordinary one, so injection is equally correct there.
    //
    // Ordering is preserved because a single consumer (this thread) drains the FIFO channel in
    // order; unbounded is safe because input is small and low-rate. Injecting BEFORE each capture
    // keeps worst-case input latency at one frame interval.
    // Each queued event carries the admission epoch it was queued under (see GatedSink::inject_stamped).
    let (input_tx, input_rx) = std::sync::mpsc::sync_channel::<(InputEvent, u64)>(256);

    // Session-scoped shutdown for this session's worker threads (capture + clipboard).
    //
    // This must NOT be the caller's `stop`. That flag is the AGENT'S lifetime switch — the helper's
    // reconnect loop runs `while !stop` — whereas the workers only need to end when THIS session
    // ends. Reusing the caller's flag as the end-of-session signal meant the first completed session
    // permanently stopped the reconnect loop: the helper process exited and the service only ever
    // respawns a helper on start / SESSIONCHANGE, so an installed agent went silently offline after
    // one remote session and stayed offline until the service was restarted. Observed on the lab VM.
    let session_stop = Arc::new(AtomicBool::new(false));

    // Runtime display-topology guard (docs/33 round 4). On a detected change the capture thread
    // flips `session_stop` AND fires this one-shot so the async select! ends promptly with an
    // explicit terminal reason, rather than waiting for the outer condition to notice. Distinct
    // from `stop` (agent lifetime) and from `session_stop` (any-teardown flag): this specifically
    // carries the "topology change" signal so the async loop can distinguish it in logs and refuse
    // to process further queued/cached media.
    let (topology_stop_tx, mut topology_stop_rx) =
        tokio::sync::oneshot::channel::<()>();
    let mut topology_stop_pending = true;
    let mut topology_stop_tx = Some(topology_stop_tx);

    // AUDIO PASSTHROUGH: pump the machine's own output into the Opus track on a dedicated thread.
    //
    // A THREAD, not a tokio task, for the same reason capture has one: WASAPI is a blocking COM API
    // and `LoopbackCapture` initialises a COM apartment on the thread that constructs it, so it must
    // live on exactly one thread for its lifetime.
    //
    // BEST EFFORT and deliberately never fatal. A machine with no render endpoint — a server, a VM,
    // a laptop with the audio device disabled — must still get a picture and a mouse. Losing the
    // whole session because the guest has no speakers would be a plainly worse product than a silent
    // one, so a failure here is one log line and the session continues without sound. That is also
    // exactly what a controller sees for an agent predating this feature.
    //
    // VIEW-ONLY: a view-only participant HEARS the machine. **Decided by the operator on
    // 2026-09-02** ("i agree a viewer hears"), so this is settled product behaviour and not a
    // default nobody chose — do not re-litigate it, and do not gate it without a new decision.
    //
    // The reasoning, kept because it is the reasoning that would have to be overturned: audio
    // follows the SCREEN, not the clipboard. The clipboard's outbound gate exists because clipboard
    // content is user data the technician cannot otherwise see (a password copied out of a vault);
    // a desktop's audio is the audible half of a picture they are already watching. View-only
    // restricts what a technician may DO, not what they may OBSERVE.
    //
    // This is nonetheless the line that WOULD gate it, so a future reversal is a one-line change
    // here rather than an archaeology exercise.
    //
    // Suppressed when mock_input is set: the recording backend (test-harness) must not open real
    // WASAPI endpoints. mock_input is the canonical "I am a recording/synthetic backend" signal;
    // real audio capture on a synthetic session is a genuine OS side-effect.
    if synthetic_tone {
        if let Some(audio) = transport.audio_sender() {
            let stop_audio = session_stop.clone();
            std::thread::spawn(move || {
                tracing::info!("audio: streaming a synthetic 440 Hz test tone (--synthetic-tone)");
                let start = Instant::now();
                let mut sent_frames: u64 = 0;
                let mut pcm: Vec<f32> = Vec::new();
                while !stop_audio.load(Ordering::Relaxed) {
                    // Paced by the wall clock, not by the sleep, so the stream never drifts.
                    let due = start.elapsed().as_micros() as u64 * 48 / 1000;
                    pcm.clear();
                    while sent_frames < due {
                        let t = sent_frames as f32 / 48_000.0;
                        let s = 0.2 * (2.0 * std::f32::consts::PI * 440.0 * t).sin();
                        pcm.extend_from_slice(&[s, s]); // interleaved stereo
                        sent_frames += 1;
                    }
                    if !pcm.is_empty() && audio.send(&pcm).is_err() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
        }
    } else if !mock_input { if let Some(audio) = transport.audio_sender() {
        let stop_audio = session_stop.clone();
        std::thread::spawn(move || {
            let mut cap = match crate::audio::LoopbackCapture::new() {
                Ok(c) => c,
                Err(e) => {
                    tracing::info!(
                        error = %e,
                        "audio: loopback capture unavailable; this session streams video only"
                    );
                    return;
                }
            };
            tracing::info!(
                endpoint = cap.endpoint_id(),
                format = %cap.format(),
                "audio: streaming the machine's output to the controller"
            );
            let mut pcm: Vec<f32> = Vec::new();
            while !stop_audio.load(Ordering::Relaxed) {
                pcm.clear();
                match cap.drain(&mut pcm) {
                    // An IDLE machine yields no packets at all — loopback is clocked by the render
                    // endpoint and Windows stops that clock when nothing holds it open. That is
                    // silence, not a fault, and it must not be logged per iteration.
                    Ok(_) if pcm.is_empty() => {}
                    Ok(_) => {
                        // Framing is the transport's job (one `FrameAccumulator`, tested there), so
                        // any length goes. A send error means the session is gone.
                        if audio.send(&pcm).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        // Endpoint changed under us (device switched, unplugged). Rebuilding is the
                        // self-healing shape the capture tiers use; give up only if that fails too.
                        tracing::debug!(error = %e, "audio: capture failed; rebuilding the endpoint");
                        match crate::audio::LoopbackCapture::new() {
                            Ok(c) => cap = c,
                            Err(e) => {
                                tracing::info!(error = %e, "audio: endpoint gone; stopping audio");
                                return;
                            }
                        }
                    }
                }
                // WASAPI's shared-mode engine period is ~10 ms; polling at that cadence keeps
                // latency low without spinning.
                std::thread::sleep(Duration::from_millis(10));
            }
            tracing::debug!("audio: pump stopped with the session");
        });
    } } // end audio_sender / !mock_input guard

    let stop_cap = session_stop.clone();
    let selected_cap = selected.clone();
    let published_cap = published.clone();
    let fps_cap = fps_now.clone();
    let scale_cap = scale_div.clone();
    let counts_cap = capture_counts.clone();
    let max_session_cap = max_session;
    let sink_cap = sink.clone();
    let gated_cap = gated.clone();
    let topology_stop_tx_cap = topology_stop_tx.take().expect("topology_stop sender present");
    let gate = crate::topology_guard::InputGate::from_shared(session_stop.clone());
    let gate_cap = gate.clone();
    let cap_thread = std::thread::spawn(move || {
        let sink = sink_cap;
        let gate = gate_cap;
        // Take a single fresh topology snapshot up front — the SAME observation used for the
        // advertised monitor geometry below, so the baseline the guard compares against is what
        // the session opened with. `None` means the capturer does not implement the optional
        // observation seam (or the platform call failed); the session runs UNGUARDED — the
        // unsupported/empty-startup policy explicitly forbids silently adopting a later baseline.
        let initial_topology: Option<rmt_agent_core::TopologySnapshot> =
            capturer.topology_snapshot();
        if initial_topology.is_none() {
            tracing::debug!(
                "capture: topology snapshot unavailable at session start; runtime topology guard \
                 disabled for this session"
            );
        }
        // The shared topology guard: observation + comparison + one-shot terminal notification
        // are coordinated in one place, so every drain and capture site uses the SAME rule.
        let topo_guard = crate::topology_guard::TopologyGuard::new(
            initial_topology.clone(),
            gate.clone(),
            topology_stop_tx_cap,
        );
        // Publish the monitor list ONCE, up front, from this thread (the only one allowed to touch
        // the capturer). The async Control branch answers `RequestMonitors` from this snapshot.
        //
        // `monitor_geom` keeps the FULL `MonitorInfo` (incl. each monitor's virtual-desktop origin),
        // which the input remap below needs to place a frame-normalized pointer on the correct
        // monitor. `MonitorDesc` (what the viewer gets) deliberately omits position; the geometry
        // never leaves the agent.
        // Advertised geometry comes from the SAME observation as the frozen baseline when the
        // capturer supports the optional topology snapshot. Falls back to `monitors()` when the
        // snapshot is unavailable — the session then runs unguarded (see the `initial_topology`
        // declaration above) but is otherwise unchanged from the previous behavior.
        let monitors_result: PlatformResult<Vec<MonitorInfo>> = match initial_topology.as_ref() {
            Some(snap) => Ok(snap.monitors.clone()),
            None => capturer.monitors(),
        };
        let monitor_geom: Vec<MonitorInfo> = match monitors_result {
            Ok(mons) => {
                let descs: Vec<MonitorDesc> = mons
                    .iter()
                    .map(|m| MonitorDesc {
                        id: m.id,
                        width: m.width,
                        height: m.height,
                        // The primary is the monitor at the VIRTUAL-DESKTOP ORIGIN — that is what
                        // "primary" means in Windows' coordinate space, every other monitor's
                        // position being expressed relative to it. Ids are positional (left to
                        // right), so `id == 0` is the LEFTMOST monitor and marking it primary would
                        // put the star on the wrong panel for anyone whose second screen sits to
                        // the left of their main one.
                        primary: m.left == 0 && m.top == 0,
                    })
                    .collect();
                // Single-session only: seed the local AtomicU32 with the primary monitor so the
                // session opens on the screen the user is looking at, not always on id 0.
                // In shared (multi-session) mode, SharedCapture::spawn already set the coherent
                // (monitor, generation) pair via write_selection before any session registered;
                // a per-session compare_exchange on the shared state is incorrect.
                if !is_multi_session {
                    if let Some(primary) = mons.iter().find(|m| m.left == 0 && m.top == 0) {
                        if primary.id != 0 {
                            let _ = selected_cap.compare_exchange(
                                0,
                                primary.id,
                                Ordering::Relaxed,
                                Ordering::Relaxed,
                            );
                        }
                    }
                }
                // One line naming every display the agent will offer. Multi-monitor complaints are
                // diagnosed from the guest's helper.log, and "the picker shows one screen" is only
                // actionable if the log says whether the agent saw one or saw three and published
                // one. `agent_host monitors` prints the same view interactively.
                tracing::info!(
                    count = mons.len(),
                    monitors = %mons
                        .iter()
                        .map(|m| format!(
                            "id={} {}x{}@({},{}){}",
                            m.id,
                            m.width,
                            m.height,
                            m.left,
                            m.top,
                            if m.left == 0 && m.top == 0 { "*" } else { "" }
                        ))
                        .collect::<Vec<_>>()
                        .join(" "),
                    "capture: displays advertised to the controller (* = primary)"
                );
                publish_monitor_list(&published_cap, monitor_ready_tx, descs);
                mons
            }
            Err(e) => {
                tracing::debug!(error = %e, "capturer.monitors() failed; monitor list stays empty");
                Vec::new()
            }
        };

        // Inject one controller event, remapping a MouseMove from the SELECTED monitor's frame into
        // virtual-desktop coordinates first (see `input::remap_input_for_monitor`). All four drain
        // sites below go through this so the remap can never be applied at some and missed at others.
        // The stopped-state gate is checked by `drain_events` — the ONLY caller of `inject_ev` —
        // so gating here would double-check and hide bugs in the drain wiring rather than defend
        // against them. This closure remaps and injects the event.
        // The admission epoch of the event being drained (set by each drain's map, read here): the
        // gate drops a press queued before a revocation even if the session was re-admitted since.
        let queued_epoch = std::cell::Cell::new(0u64);
        let inject_ev = |ev: InputEvent| -> PlatformResult<()> {
            let sel = selected_cap.load(Ordering::Relaxed);
            let ev = crate::input::remap_input_for_monitor(
                ev,
                sel,
                &monitor_geom,
                crate::input::virtual_desktop_rect(),
            );
            gated_cap.inject_stamped(ev, queued_epoch.get())
        };

        let start = Instant::now();
        // M11 pacing instrumentation: how often an iteration overran its own interval. Scaling runs
        // on THIS thread (it is also the desktop-bound injection thread), and the trade — one box
        // filter here against an 8.3 MB per-frame clone in the transport — is measured rather than
        // asserted. A climbing `pace_miss` at div 1 is the signal that it was the wrong trade.
        let mut pace_miss: u64 = 0;
        let mut paced: u64 = 0;
        let mut last_pace_log = Instant::now();
        let mut hinted_fps: Option<u32> = None;
        while !stop_cap.load(Ordering::Relaxed) && start.elapsed() < max_session_cap {
            let t0 = Instant::now();
            // Re-read every iteration: the operator can change the frame rate mid-session, and a
            // `Duration` computed once outside the loop would silently ignore them (that is the
            // whole mutation this placement defends against).
            let fps_wanted = fps_cap.load(Ordering::Relaxed);
            let frame_interval = quality::frame_interval(fps_wanted);
            // Tell a shared producer what this session wants, so capture runs no faster than the
            // fastest viewer asked (a no-op for a capturer this session owns alone).
            if hinted_fps != Some(fps_wanted) {
                capturer.set_frame_rate_hint(fps_wanted);
                hinted_fps = Some(fps_wanted);
            }
            // Topology guard, BEFORE the pre-capture drain: catches a change that happened while
            // the thread was asleep on the previous iteration's pacing slice.
            if topo_guard.check(|| capturer.topology_snapshot()) { break; }
            // Inject any pending controller input on this (possibly desktop-bound) thread first.
            // Every drain site — this one, the backoff loop below, the pacing-slice loop, and the
            // final teardown drain — routes through `topology_guard::drain_events` with the shared
            // gate, so a stopped session cannot leak queued input onto the guest desktop.
            crate::topology_guard::drain_events(
                input_rx.try_iter().map(|(ev, epoch)| { queued_epoch.set(epoch); ev }), 256, &gate,
                |e| { if let Err(err) = inject_ev(e) { tracing::debug!(error = %err, "input inject refused"); } Ok(()) },
                /* discard_only */ false,
            );
            // Topology guard, AGAIN before the capture call. A change here would otherwise be
            // forwarded — the captured frame stamped with an id whose meaning has shifted.
            if topo_guard.check(|| capturer.topology_snapshot()) { break; }
            // An idle or temporarily unavailable target must never substitute another display.
            let sel = selected_cap.load(Ordering::Relaxed);
            let captured = capture_selected_frame(&mut capturer, sel);
            // Topology guard, POST-capture: catches a desktop-follow / hotplug change that
            // completed during the capture blit, before the frame is handed to the transport.
            if topo_guard.check(|| capturer.topology_snapshot()) { break; }
            match captured {
                Some(f) => {
                    counts_cap.0.fetch_add(1, Ordering::Relaxed);
                    // M11 resolution scaling, applied HERE — before the frame crosses into the
                    // transport, where `VideoFrameSender::send` clones every byte of it. Scaling
                    // first removes both the pixels and that memcpy; scaling on the encoder thread
                    // would pay the full-resolution clone on every frame and buy nothing.
                    //
                    // At the default divisor of 1 this is a borrow and copies nothing, so the
                    // untouched path is exactly what it was.
                    let f = scale_bgra(
                        std::borrow::Cow::Owned(f),
                        scale_cap.load(Ordering::Relaxed),
                    )
                    .into_owned();
                    // blocking_send waits if the encoder is behind (paces us) and errors when the
                    // async side has hung up — either way we stop cleanly.
                    if frame_tx.blocking_send(f).is_err() {
                        break;
                    }
                }
                None => {
                    counts_cap.1.fetch_add(1, Ordering::Relaxed);
                    // Transient capture loss (desktop switch, mode change): back off one interval,
                    // in the same input-draining slices as the pacing sleep. A desktop switch is
                    // precisely when an operator is clicking at a UAC prompt, so this is the worst
                    // possible place to stop accepting input for a whole frame interval.
                    let mut slept = Duration::ZERO;
                    let mut topo_changed = false;
                    while slept < frame_interval && !stop_cap.load(Ordering::Relaxed) {
                        let slice = INPUT_DRAIN_SLICE.min(frame_interval - slept);
                        std::thread::sleep(slice);
                        slept += slice;
                        // Topology guard, BEFORE each sleep-slice drain: a hotplug during the
                        // backoff must not run more input against the pre-change layout.
                        if topo_guard.check(|| capturer.topology_snapshot()) {
                            topo_changed = true;
                            break;
                        }
                        crate::topology_guard::drain_events(
                            input_rx.try_iter().map(|(ev, epoch)| { queued_epoch.set(epoch); ev }), 256, &gate,
                            |e| { let _ = inject_ev(e); Ok(()) }, false,
                        );
                    }
                    if topo_changed { break; }
                    continue;
                }
            }
            let spent = t0.elapsed();
            paced += 1;
            if spent < frame_interval {
                // Sleep in SLICES, draining input between them, instead of one long sleep.
                //
                // Injection has to happen on this thread — it is the one `FollowingCapturer`
                // binds to the active input desktop, and `SendInput` acts on the calling thread's
                // desktop. Before M11 that cost nothing: the interval was a fixed 33 ms, so
                // "inject once per iteration" bounded input latency at 33 ms. Now the operator
                // chooses the frame rate down to 1 fps, and the same code would make a click wait
                // up to a full second — throttling the keyboard and mouse with the *video* knob.
                //
                // That is worst exactly where it is least acceptable: the shipped "Text (slow
                // link)" preset is 5 fps, and it exists for an operator reading a dialog and then
                // clicking a button on it.
                let remaining = frame_interval - spent;
                let mut slept = Duration::ZERO;
                let mut topo_changed = false;
                while slept < remaining && !stop_cap.load(Ordering::Relaxed) {
                    // The operator (or a viewer returning from the background) raised the rate:
                    // stop waiting out the old, longer interval.
                    if fps_cap.load(Ordering::Relaxed) > fps_wanted {
                        break;
                    }
                    let slice = INPUT_DRAIN_SLICE.min(remaining - slept);
                    std::thread::sleep(slice);
                    slept += slice;
                    // Topology guard, BEFORE each sleep-slice drain: same rule as the pre-capture
                    // and backoff sites — a change during pacing must stop input flow immediately.
                    if topo_guard.check(|| capturer.topology_snapshot()) {
                        topo_changed = true;
                        break;
                    }
                    crate::topology_guard::drain_events(
                        input_rx.try_iter().map(|(ev, epoch)| { queued_epoch.set(epoch); ev }), 256, &gate,
                        |e| { if let Err(err) = inject_ev(e) { tracing::debug!(error = %err, "input inject refused"); } Ok(()) },
                        false,
                    );
                }
                if topo_changed { break; }
            } else {
                pace_miss += 1;
            }
            if last_pace_log.elapsed() >= Duration::from_secs(1) {
                if pace_miss > 0 {
                    tracing::debug!(
                        pace_miss,
                        paced,
                        fps = fps_cap.load(Ordering::Relaxed),
                        div = scale_cap.load(Ordering::Relaxed),
                        "capture thread missed its pacing target"
                    );
                }
                pace_miss = 0;
                paced = 0;
                last_pace_log = Instant::now();
            }
        }
        // Session teardown: stop the gate, DISCARD any remaining queued input (a burst arriving
        // at shutdown must not land on the guest desktop — the disconnect is the moment beyond
        // which injection could reach a display the technician can no longer see), then release
        // tracked input on the capture thread. Cleanup does not switch desktops; releases
        // across a prior desktop transition remain best effort.
        let teardown = crate::topology_guard::teardown_capture(
            &gate,
            || {
                crate::topology_guard::drain_events(
                    input_rx.try_iter().map(|(ev, epoch)| { queued_epoch.set(epoch); ev }), 256, &gate,
                    |_e| Ok(()),
                    /* discard_only */ true,
                );
            },
            &*sink,
        );
        if let Err(e) = teardown {
            tracing::debug!(error = %e, "teardown_capture: release_held reported an error");
        }
    });

    // Clipboard sync (M9): if a `Clipboard` was provided, a dedicated worker thread owns it and
    // bridges two channels with the async loop below:
    //  * `clip_set_tx` (async → worker, std mpsc): remote text decoded off `ChannelId::Clipboard`
    //    that the worker should write to the local clipboard.
    //  * `clip_out_rx` (worker → async, tokio mpsc): text the worker read from a LOCAL clipboard
    //    change, to be framed back out on `ChannelId::Clipboard`.
    // The worker also performs echo suppression (see `clipboard_worker`). When no clipboard is
    // provided, no worker is spawned; `clip_out_rx` then yields `None` immediately and its select!
    // arm disables itself, and inbound clipboard frames are dropped (the send half has no receiver).
    let (clip_set_tx, clip_set_rx) = std::sync::mpsc::sync_channel::<String>(8);
    let (clip_out_tx, mut clip_out_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    // May the guest's clipboard leave the machine RIGHT NOW? Read by the worker immediately before
    // it reads the clipboard's contents, republished by the session loop on every iteration.
    //
    // Starts CLOSED. The worker begins polling the moment it is spawned, which is before the loop
    // below has computed `view_only` even once, so the honest initial answer is "not yet known" and
    // the safe reading of that is "no". One poll of latency at session start costs nothing; the
    // opposite default would forward whatever was on the guest's clipboard when the session opened.
    let clip_egress = Arc::new(AtomicBool::new(false));
    // Set by the session loop when egress goes shut → open; consumed (swapped back to false) by the
    // worker, which then rebaselines `last_seen` so a change made while egress was shut can never be
    // released afterwards.
    let clip_resync = Arc::new(AtomicBool::new(false));
    let clip_thread = match clipboard {
        Some(clip) => {
            let stop_clip = session_stop.clone();
            let egress = Arc::clone(&clip_egress);
            let resync = Arc::clone(&clip_resync);
            Some(std::thread::spawn(move || {
                clipboard_worker(
                    clip,
                    clip_set_rx,
                    clip_out_tx,
                    stop_clip,
                    move || egress.load(Ordering::Relaxed),
                    move || resync.swap(false, Ordering::Relaxed),
                )
            }))
        }
        None => {
            // Drop both worker-side halves so the async side sees a closed out-channel and inbound
            // clipboard frames enqueue into a dead set-channel (send errors, ignored).
            drop(clip_set_rx);
            drop(clip_out_tx);
            None
        }
    };
    let mut clip_open = clip_thread.is_some();
    // Only poll the guest arm when something can actually send on it. With no window the sender is
    // still alive (it is owned by this function), so `recv()` would park forever rather than
    // returning `None` — a permanently-pending branch in a `select!` that is polled every loop.
    let mut guest_open = guest_surface.is_some();

    // Async side: one select! loop drives both halves against the single transport.
    // - `frame_rx.recv()` → hand pixels to the video encoder (via the non-borrowing `video` handle);
    // - `transport.recv_frame()` → decode + inject any input frame.
    // A short periodic tick re-checks `stop`/max-run even when neither side produces anything.
    let start = Instant::now();
    let session_start_unix_ms = now_unix_ms();
    let mut sent: u64 = 0;
    let mut forwarded: u64 = 0;
    let mut result = Ok(());
    // docs/49: WHY this session ended, set by the arm that decides it (first cause wins) and
    // classified after the loop otherwise. Reported to the control plane after teardown.
    let mut end_reason: Option<rmt_protocol::signaling::SessionEndReason> = None;
    let mut end_notice_sent = false;
    let mut end_detail: Option<&'static str> = None;
    let mut pending_move: Option<(InputEvent, u64)> = None;
    let mut video_open = true;
    let mut input_open = true;
    // The peer-gone signal, held apart from `transport` so the arm that watches it can share the
    // select! with the `&mut transport` input arm. See the `peer_gone.wait()` arm for why.
    let peer_gone = transport.peer_gone();
    // Guest-input block (privacy). Off by the constructor; toggled by `SetInputBlocked`, and released
    // unconditionally in the teardown block below (its own `Drop` is the final backstop). Owning it
    // here scopes the block to exactly this session. In mocked-input mode (the `--log-input` test
    // path) it installs no real OS hooks — see `SessionOptions::mock_input`.
    let mut input_blocker = crate::input_block::InputBlocker::new(!mock_input);
    // Monitor blank (privacy). Off by the constructor; toggled by `SetMonitorBlanked`, and removed
    // unconditionally in the teardown block below (`Drop` is the final backstop). Like
    // `InputBlocker`, mock_input mode skips real Win32 so the gate/e2e can exercise the
    // round-trip without blacking out the build machine's screen.
    let mut screen_blanker = crate::blank_monitor::ScreenBlanker::new(!mock_input);
    // View-only / presentation mode (§1). When on, the agent DROPS the controller's injected
    // keyboard/mouse input — the technician watches without controlling. Enforced HERE, at the agent,
    // not by the controller declining to send: even input that arrives is dropped.
    //
    // The RULES live in `SessionAccessState` (rmt_agent::session_policy), not inline here. Three
    // sources compose — the technician's toggle, a control-plane-signed policy's floor, and the
    // provisional floor `require_session_policy` opens the session with — and they interact through a
    // ratchet that must let exactly one of them be lifted exactly once. Inline, that logic was
    // unreachable by any test (this loop needs a live transport, a capturer and a Windows desktop);
    // as a plain struct it is a truth table with ten unit tests behind it.
    // Session recording (loop 89). `None` = not recording; `Some` = a live recorder whose tee is
    // installed in the encoder loop. Owned HERE, by the session, so the recording's lifetime is the
    // session's: the teardown below finalizes it on every exit path, including the ones nobody sends
    // a `StopRecording` on (peer gone, guest End, max-session).
    let mut recorder: Option<crate::recording_broker::SessionRecorder> = None;
    // Tracks the last verified policy's allow_recording value. Defaults to true (allow) so a
    // session that never installs a policy keeps full access — fail-open on recording is safe
    // because a ban is the restriction, not the baseline. Updated on every verified policy.
    let mut recording_policy_allowed = true;
    // `issued_at_ms` of the newest verified policy installed so far. A verified policy OLDER than
    // it is a replay and is ignored (security audit 2026-10-18): the access level has its own
    // ratchet, but recording and idle restrictions are "last policy wins", so a viewer replaying
    // an earlier, still-valid permissive policy could lift a ban or a requirement the newer one
    // imposed. The control plane mints renewals in order, so a legitimate one is never older.
    let mut newest_policy_issued_at_ms = i64::MIN;
    // Tracks the last verified policy's require_recording value. Defaults to false (optional) so a
    // session that never installs a policy keeps the permissive baseline. Updated on every verified
    // policy. When true, StopRecording is refused for the session's lifetime — the group policy
    // says every session MUST be recorded and the agent enforces that unconditionally.
    let mut recording_required_by_policy = false;
    // Absolute wall-clock deadline (Unix ms) derived from the group's max_session_duration_seconds.
    // Set on the FIRST verified policy that carries a non-zero limit; never relaxed (the limit is a
    // fixed group property, not something the control plane ratchets). `None` = unlimited.
    let mut duration_deadline_ms: Option<i64> = None;
    // Idle timeout in ms derived from the group's max_idle_seconds. Updated unconditionally on
    // every verified policy so a group-policy change that tightens or clears the limit takes effect
    // at the next renewal; 0 = unlimited. Unlike the duration deadline, this is a rolling window,
    // not a fixed start-anchored deadline, so there is no reason to freeze it at the first value.
    let mut idle_limit_ms: i64 = 0;
    // Wall-clock timestamp (Unix ms) of the last decoded input frame from the controller.
    // Initialised to `session_start_unix_ms` but RESET to `now` when the idle limit first becomes
    // non-zero, so the clock does not accumulate time during the policy-install handshake.
    let mut last_input_unix_ms = session_start_unix_ms;
    // An observer's floor is permanent: no toggle, policy or grant can lift it.
    let mut access_state = if observer {
        SessionAccessState::new_observer(require_session_policy)
    } else {
        SessionAccessState::new(require_session_policy)
    };
    // The EFFECTIVE flag every gate below reads, recomputed from `access_state` after each change.
    // Kept as a plain bool so all the existing `if view_only` gates — input, reboot, tool-launch,
    // command-run, lock, log-off, shut-down — keep reading one value and cannot drift apart.
    let mut view_only = access_state.view_only();
    // The guest's indicator went off-screen (a display change it could not be re-placed after): held
    // view-only, on top of `access_state`, until the window reports it visible again.
    let mut indicator_lost = false;
    set_input_admitted(&sink, !view_only).await;
    sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
    // Tell the guest what the session ACTUALLY opened as, before anyone touches it.
    //
    // Every other `set_view_only` call below is REACTIVE — it runs when a Control message changes the
    // state. That was complete while view-only could only ever start off. It is not complete under a
    // provisional floor: `require_session_policy` makes the agent drop injected input from the very
    // first frame, while the window this guest is looking at still says "controlling". The window is
    // the only thing that tells them which regime they are in, and it was wrong for the entire span
    // before the technician happened to send a toggle (in a session where they never do, forever).
    if let Some(s) = guest_surface.as_ref() {
        s.set_view_only(view_only);
    }
    // Guest reboot (remote support). A real rebooter actuates `InitiateSystemShutdownEx` + `bcdedit`;
    // the mock (the `--log-input` path) logs and acks without rebooting, so a gate run / e2e can
    // round-trip `RebootGuest` safely. See `SessionOptions::mock_reboot` and `crate::reboot`.
    let rebooter = crate::reboot::Rebooter::new(!mock_reboot);
    // Once a reboot is scheduled the machine goes down in a few seconds; a SECOND `RebootGuest` in
    // that window must be refused. Actuating it again re-runs `bcdedit` and can, via the failed
    // second syscall's rollback, clear the FIRST (still-pending) reboot's safeboot element — silently
    // downgrading a Safe-Mode reboot to a normal one (a review finding). One latch closes that race.
    let mut reboot_armed = false;
    // System tool launcher (remote support): spawns a whitelisted admin tool on the interactive
    // desktop. The mock (dev/e2e path) resolves + acks without spawning. See `crate::launch`.
    let launcher = crate::launch::Launcher::new(!mock_launch, host_runs_as_interactive_user);
    // One-line command bar (remote support): runs a single command, captures output, acks a
    // `CommandResult`. The mock (dev/e2e path) executes nothing. See `crate::command_run`.
    let command_runner = crate::command_run::CommandRunner::new(!mock_command, host_runs_as_interactive_user);
    // Guest lock (remote support): a real locker calls `LockWorkStation`; the mock (dev/e2e path) acks
    // without locking, so a gate run never locks the CI box's own session. See `crate::lock`.
    let locker = crate::lock::Locker::new(!mock_lock);
    // Guest log off (remote support): a real logoffer calls `WTSLogoffSession` on the streamed session;
    // the mock (dev/e2e path) acks without logging anyone off, so a gate run never logs the CI box's
    // operator out of their own session. See `crate::logoff`.
    let logoffer = crate::logoff::Logoffer::new(!mock_logoff);
    // At most one command runs at a time (a command bar is one-at-a-time on the controller too). It
    // runs on a blocking task held HERE — never awaited inline in the `RunCommand` arm — because a
    // command may run for its full timeout, and awaiting it inline would freeze the whole `select!`
    // loop (video, input, telemetry) for that long. Its own arm below sends the result when it lands;
    // a second `RunCommand` while one is pending is refused, like `reboot_armed`.
    let mut pending_command: Option<
        tokio::task::JoinHandle<Result<crate::command_run::CommandOutput, crate::command_run::CommandError>>,
    > = None;
    // Was the command in `pending_command` an `ElevatedRun`? The completion arm needs to know,
    // because the two requests want DIFFERENT answers to the same failure: a `RunCommand` that could
    // not start is an `Error` ("that command did not run"), while an `ElevatedRun` that could not
    // start is an `ElevationDenied` ("nothing ran AND the elevation did not happen") — a distinct
    // fact about whether a privileged action occurred, which is the whole reason that channel
    // exists. Carried beside the handle rather than inside the task's result because the identity is
    // a property of the REQUEST, not of the outcome. Cleared with the slot.
    let mut pending_command_elevated = false;
    // Screenshot (remote support): the newest raw BGRA frame the stream produced, kept so a
    // `RequestScreenshot` can encode a full-resolution lossless PNG of it without a second capturer
    // fighting the DXGI duplication. Updated (moved, not cloned) in the video arm. The PNG encode runs
    // on a blocking task held here — like `pending_command` — so encoding a multi-megabyte frame never
    // stalls the `select!` loop; its own arm pushes the PNG over FileTransfer when it lands.
    let mut last_frame: Option<CapturedFrame> = None;
    // Displays the viewer is not watching are held still so the encoder spends the bitrate on the watched
    // ones (WatchedMonitors; see watched_freeze.rs). `last_frame` stays RAW for screenshots.
    let mut freeze = crate::watched_freeze::FreezeState::default();
    let mut pending_screenshot: Option<
        tokio::task::JoinHandle<Result<Vec<u8>, crate::screenshot::ScreenshotError>>,
    > = None;

    // M11 telemetry timer — created ONCE, OUTSIDE the loop, and this placement is the whole point.
    //
    // The obvious implementation is another `_ = tokio::time::sleep(..)` arm alongside the existing
    // 500 ms one below. It would never fire. `select!` here is `biased;` with `frame_rx.recv()`
    // first, a frame arrives every ~33 ms, and a `sleep` future built inside the loop body is
    // reconstructed from scratch on every iteration — so it is dropped long before a one-second
    // deadline it can never reach. (That is also why the existing 500 ms "periodic re-check" arm is
    // effectively dead: it is harmless only because the `while` condition re-checks the same things.)
    //
    // An `Interval` outlives the iteration and `Interval::tick` is cancel-safe, so it actually
    // fires. `Delay` rather than the default `Burst` because a stall must not be repaid as a volley
    // of catch-up reports — the reader wants one sample per second, not a backlog.
    let mut quality_tick = tokio::time::interval(Duration::from_secs(1));
    quality_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Minimum frame cadence (see MIN_FRAME_INTERVAL). `last_sent_at` tracks when a frame last went to
    // the encoder — REAL or re-sent — so the cadence tick can tell when the browser is about to go
    // hungry and re-send the last frame to keep its video pipeline fed. `cadence_tick` fires even
    // while `frame_rx` is idle (an `Interval` outlives the iteration, unlike an in-body `sleep` under
    // this `biased;` select! — same reason spelled out above `quality_tick`), which is exactly the
    // idle-screen case it exists for.
    let mut last_sent_at = Instant::now();
    // The tick is the WAKEUP granularity, not the floor — the arm re-reads the commanded rate and
    // decides ([`min_frame_interval`]). Keeping it at the tightest possible floor means a mid-session
    // change to a faster frame rate takes effect on the next tick rather than after a slow session's
    // whole interval.
    let mut cadence_tick = tokio::time::interval(MIN_FRAME_INTERVAL);
    cadence_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // THE SESSION-LEASE TIMER (docs/25 F03). Declared here, OUTSIDE the loop, for exactly the reason
    // spelled out above `quality_tick`: an in-body `sleep` arm under `biased;` with a ~33 ms frame
    // arm ahead of it is reconstructed every iteration and never reaches its deadline. (The 500 ms
    // "periodic re-check" arm at the bottom of the `select!` is the documented casualty of that, and
    // hanging revocation off it would have made this whole fix inert — the exact "feature inert at
    // its untested layer" shape this repo keeps rediscovering.)
    //
    // `Interval`'s FIRST tick completes immediately, which is what we want: the announcement below
    // goes out on the session's first loop iteration rather than two seconds into it, so the console
    // starts renewing as early as it possibly can.
    //
    // `Delay` rather than `Burst` so a stalled session does not repay the backlog as a volley of
    // announcements; the lease decision only ever depends on the clock, never on the tick count.
    let mut lease_tick = tokio::time::interval(LEASE_TICK);
    lease_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    while (video_open || input_open)
        && !stop.load(Ordering::Relaxed)
        && !session_stop.load(Ordering::Relaxed)
        && start.elapsed() < max_session
    {
        // Reconcile hint/recording changes before waiting, including on an idle desktop: a newly
        // watched display gets its real pixels now, not at the next screen change.
        if freeze.reconcile(last_frame.as_ref(), shared_canvas.as_ref(), recorder.is_some(), Instant::now())
            && video_open
            && !session_stop.load(Ordering::Relaxed)
        {
            if let Some(f) = freeze.outgoing(last_frame.as_ref()) {
                if let Err(e) = video.send(f) { result = Err(e); break; }
                sent += 1;
                last_sent_at = Instant::now();
            }
        }
        // A mouse move held back by a full input queue goes out as soon as there is room, not only
        // when the next input arrives: otherwise a technician who moved and stopped during a capture
        // stall would leave the guest's pointer behind (Codex input r1). Every iteration is cheap
        // (a non-blocking try_send) and iterations come at least at the frame cadence.
        if pending_move.is_some() {
            match flush_pending_move(&mut pending_move, |item| input_tx.try_send(item)) {
                Ok(sent) => forwarded += sent as u64,
                Err(()) => {
                    tracing::warn!("closing session: input queue unavailable");
                    end_detail = Some("session ended: this machine stopped accepting input for too long (it may be busy or switching screens); reconnect to continue");
                    break;
                }
            }
        }
        // Republish the clipboard egress decision to the worker thread, ONCE, here.
        //
        // Deliberately at the top of the loop rather than beside each of the five places
        // `view_only` is assigned. Those five are easy to add a sixth to and easy to forget, and a
        // forgotten one leaves the worker reading the guest's clipboard under a restriction the
        // rest of the session is honouring — the "defence built and not applied" shape this repo
        // keeps rediscovering. Here it cannot be forgotten: any change to `view_only`, from any
        // source, is published on the next iteration, and view-only only ever changes as the result
        // of an event this loop just processed, so "the next iteration" is immediately.
        let clip_allow = !view_only && clipboard_mode.allows_to_technician();
        // The swap is UNCONDITIONAL and its result is bound before it is tested. Writing this as
        // `if clip_allow && !clip_egress.swap(..)` reads identically and is badly wrong: `&&`
        // short-circuits, so the store never runs on the `clip_allow == false` path and egress would
        // never actually CLOSE at the worker — view-only would be published to every gate in the
        // session except the one thread that reads the clipboard.
        let clip_was_allowed = clip_egress.swap(clip_allow, Ordering::Relaxed);
        if clip_allow && !clip_was_allowed {
            // Egress just RE-OPENED. Tell the worker to discard its baseline before it next looks.
            //
            // Without this the fix is still racy in the one direction that matters. The worker
            // notices a local copy only at its next 300ms poll, so a secret copied at T under
            // view-only, with view-only lifted at T+50ms, is first SEEN at T+300ms — by which time
            // egress is open and it ships. Checking permission at read time is necessary but not
            // sufficient; the worker also has to be told that the window it slept through was a
            // restricted one.
            //
            // Resyncing consumes any change that happened while egress was shut, so it can never
            // be released afterwards. The cost is that a copy made in the moments right after a
            // lift is consumed too, and does not sync until the guest copies again — a missed
            // paste, against a leaked password. That trade is not close.
            clip_resync.store(true, Ordering::Relaxed);
        }
        tokio::select! {
            biased;
            // TERMINAL: the capture thread observed a runtime display-topology change and asked
            // this session to end. FIRST arm under `biased;` so it wins over a queued frame or a
            // live input drain — the whole point of firing this notification is that we STOP
            // processing further media/input from before the change was seen. Handled by closing
            // both halves; the outer `while` condition (which also reads `session_stop`) exits on
            // the next iteration.
            recv = &mut topology_stop_rx, if topology_stop_pending => {
                topology_stop_pending = false;
                // `recv` is `Ok(())` iff the capture thread actually sent — a plain sender-drop
                // (normal cap-thread exit) yields `Err(RecvError)` and MUST NOT be treated as a
                // topology change. `session_stop` and the frame/input arms handle that ordinary
                // teardown; this arm's job is only the explicit topology terminal signal.
                if recv.is_ok() {
                    tracing::info!("session: topology change signaled by capture thread; ending session");
                    end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::Other);
                    end_detail = Some("session ended: the display layout on this machine changed (a monitor was connected, disconnected or woke up, or the resolution changed); reconnect to continue");
                    video_open = false;
                    input_open = false;
                    last_frame = None;
                    continue;
                }
            }
            // PRIORITY (security audit 2026-10-18): this arm sits directly under the topology terminal.
            // It used to come after the receive arm, and under `biased;` a viewer that keeps the receive
            // queue ready (a flood of input or cheap control messages) starved it indefinitely — so a
            // session ended centrally, an expired lease, the group max-duration and idle limits were
            // never acted on while the flood lasted. The tick fires every LEASE_TICK, so polling it
            // first costs nothing and starves nothing.
            // docs/25 F03 — THE SESSION LEASE. This arm is what makes an administrator's "End
            // session" reach an unattended desktop: the control plane stops re-authorizing the
            // session, so the lease runs out and the agent ends the session itself, with no
            // cooperation from the controller at any point.
            //
            // Guarded on `is_enforced()` so it is inert for every session that is not leased —
            // dev/LAN (no control-plane session id), attended (its own three-second status poll
            // revokes), and any agent with no pinned issuer key. Those sessions behave exactly as
            // they did before this existed.
            _ = lease_tick.tick(), if session_lease.is_enforced() => {
                match session_lease.status(now_unix_ms(), start.elapsed()) {
                    // A lease is in force. Nothing to do — and deliberately nothing logged, because
                    // this fires every couple of seconds for the whole life of every session.
                    LeaseStatus::Held { .. } => {}
                    // Unreachable while the arm's guard holds; matched exhaustively rather than with
                    // a catch-all so a future variant fails to compile until someone decides what it
                    // means for a live session.
                    LeaseStatus::NotEnforced => {}
                    LeaseStatus::AwaitingFirst { remaining_ms } => {
                        // (RE-)ANNOUNCE. The controller cannot know it must renew — the console has
                        // no way to tell whether a given agent can verify a signed policy at all —
                        // so the agent asks, and keeps asking until a lease verifies.
                        let payload = control::encode(&ControlMessage::SessionLeaseRequired {
                            renew_within_ms: remaining_ms.max(0) as u64,
                        });
                        if let Err(e) = transport
                            .send_frame(Frame::new(ChannelId::Control, payload))
                            .await
                        {
                            // NOT fatal, unlike the quality-stats send failure below it, and the
                            // difference is worth stating: a failed announcement costs nothing
                            // because the grace deadline still stands and the next tick asks again.
                            // Ending the session here would convert one dropped frame into a lost
                            // session, and would do it on the arm whose entire job is to be the
                            // thing that ends sessions — the worst possible place for a false
                            // positive.
                            tracing::debug!(
                                error = %e,
                                "session-lease announcement could not be sent (retrying next tick)"
                            );
                        }
                    }
                    LeaseStatus::Lapsed(lapse) => {
                        // OUT OF AUTHORITY. Tear the session down exactly the way the guest's End
                        // button does — drop BOTH flags so the `while` condition fails and the
                        // ordinary teardown below runs (input block released, recording finalized,
                        // guest window told the session ended). `stop` is deliberately NOT set: that
                        // flag ends the whole helper's reconnect loop, and this machine must stay
                        // reachable for the next authorized session.
                        match lapse {
                            LeaseLapse::NeverArrived => tracing::warn!(
                                grace_ms = session_lease_grace.as_millis() as u64,
                                "session lease NEVER ARRIVED — ending the session. The controller \
                                 did not install a control-plane-signed policy within the grace \
                                 window (an out-of-date console that does not renew looks exactly \
                                 like this)"
                            ),
                            LeaseLapse::Expired { by_ms } => tracing::warn!(
                                expired_by_ms = by_ms,
                                "session lease EXPIRED — ending the session. The control plane \
                                 stopped re-authorizing it (session ended centrally, principal \
                                 disabled, tenant suspended or machine quarantined), or the \
                                 controller stopped renewing"
                            ),
                        }
                        // Tell the peer WHY before the transport goes away. Best-effort: the console
                        // gets a legible banner when this lands, and the teardown happens either way.
                        let payload = control::encode(&ControlMessage::Error {
                            message: match lapse {
                                LeaseLapse::NeverArrived =>
                                    "session ended: no control-plane session lease was installed \
                                     within the grace period".to_string(),
                                LeaseLapse::Expired { .. } =>
                                    "session ended: the control-plane session lease expired and was \
                                     not renewed".to_string(),
                            },
                        });
                        let _ = transport
                            .send_frame(Frame::new(ChannelId::Control, payload))
                            .await;
                        end_notice_sent = true;
                        end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::LeaseLapsed);
                        input_open = false;
                        video_open = false;
                    }
                }
                // GROUP MAX-DURATION ENFORCEMENT. If a lease carried max_session_duration_seconds
                // and the wall clock has passed the computed deadline, end the session now. Checked
                // here — on the same tick as the lease check — so there is no second timer to
                // configure and no new wakeup path. The control plane also enforces the limit at
                // the tenant level through `SessionPolicies.MaxSessionSeconds`; this is the
                // PER-GROUP enforcement at the agent, where the session is actually running.
                if let Some(deadline) = duration_deadline_ms {
                    if now_unix_ms() >= deadline {
                        tracing::warn!(
                            deadline_unix_ms = deadline,
                            "session has reached its maximum duration — ending"
                        );
                        end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::MaxDuration);
                        let payload = control::encode(&ControlMessage::Error {
                            message: "session ended: maximum session duration reached".to_string(),
                        });
                        let _ = transport
                            .send_frame(Frame::new(ChannelId::Control, payload))
                            .await;
                        end_notice_sent = true;
                        input_open = false;
                        video_open = false;
                    }
                }
                // IDLE TIMEOUT ENFORCEMENT. If a policy carried max_idle_seconds and no controller
                // input has arrived in that window, end the session. Checked here — on the same tick
                // as the lease and duration checks — so there is no second timer to configure.
                // PRIVACY COVERAGE: a display change the overlay could not re-cover turns privacy
                // mode OFF (blank_monitor::take_coverage_lost), and the technician is told, so the
                // console never shows "blanked" over a screen that is not.
                if screen_blanker.take_coverage_lost() {
                    for msg in [
                        ControlMessage::MonitorBlankedApplied { blanked: false },
                        ControlMessage::Error {
                            message: "Privacy mode was turned off: the screen layout changed and could not be fully covered.".to_string(),
                        },
                    ] {
                        let _ = transport.send_frame(Frame::new(ChannelId::Control, control::encode(&msg))).await;
                    }
                }
                if idle_limit_ms > 0 && now_unix_ms() - last_input_unix_ms >= idle_limit_ms {
                    tracing::warn!(
                        idle_limit_ms,
                        "session has reached its idle timeout — ending"
                    );
                    end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::Idle);
                    let payload = control::encode(&ControlMessage::Error {
                        message: "session ended: idle timeout reached".to_string(),
                    });
                    let _ = transport
                        .send_frame(Frame::new(ChannelId::Control, payload))
                        .await;
                    end_notice_sent = true;
                    input_open = false;
                    video_open = false;
                }
            },
            // VIDEO-ONLY TAIL: input is closed but video is not. Every failed data-channel send clears
            // `input_open` alone, and from then on nothing calls `recv_frame` — the one call that
            // reports the peer leaving — while `video.send` only queues and never fails. Without this
            // arm the agent kept encoding into a dead peer connection until a lease lapsed or the
            // session's lifetime bound, whichever came first. The transport's own terminal signal ends
            // it instead, so a send failure that WAS transient (the peer is still there) changes
            // nothing beyond what it already did.
            //
            // Second only to the topology terminal, AHEAD of frame forwarding: under `biased;` a
            // capture queue that is always ready would otherwise win every iteration and starve it.
            _ = peer_gone.wait(), if video_open && !input_open => {
                tracing::info!("session: peer connection ended while input was closed; ending session");
                end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::ViewerLeft);
                video_open = false;
            }
            ready = &mut monitor_ready_rx, if monitor_announcement_pending => {
                // Disable on success OR sender drop; polling a completed oneshot again panics.
                monitor_announcement_pending = false;
                if let Ok(monitors) = ready {
                    tracing::info!(count = monitors.len(), "sending initial monitor list");
                    let payload = control::encode(&ControlMessage::MonitorList { monitors });
                    if let Err(e) = transport.send_frame(Frame::new(ChannelId::Control, payload)).await {
                        tracing::debug!(error = %e, "initial monitor-list send failed");
                        input_open = false;
                    }
                    // Advertise the configured transfer root so the viewer can mark downloadable
                    // entries correctly without relying on the hardcoded default path.
                    let td_path = transfer_dir.to_string_lossy().into_owned();
                    if td_path.contains('\u{FFFD}') {
                        tracing::warn!(path = %transfer_dir.display(),
                            "transfer_dir contains non-UTF-8 characters; viewer will not show download buttons");
                    }
                    let td_payload = control::encode(&ControlMessage::TransferDir { path: td_path });
                    if let Err(e) = transport.send_frame(Frame::new(ChannelId::Control, td_payload)).await {
                        tracing::debug!(error = %e, "transfer-dir advertisement send failed");
                    }
                    // docs/53: whether this session can ask the guest for admin rights. Only an
                    // attended session has the handle; an observer is told it cannot.
                    if let Some(rights) = &admin_rights {
                        let msg = if observer {
                            ControlMessage::AdminRightsAvailable { available: false, reason: Some("this is a view-only observer session".into()) }
                        } else {
                            rights.advertisement()
                        };
                        let payload = control::encode(&msg);
                        if let Err(e) = transport.send_frame(Frame::new(ChannelId::Control, payload)).await {
                            tracing::debug!(error = %e, "admin-rights advertisement send failed");
                        }
                    }
                    // docs/61: input hand-off. Advertise it affirmatively (an observer is told no — it
                    // has no control to hand and can never receive it), set eligibility, and join the
                    // directory, which queues this session's join snapshot when arbitration is armed.
                    // One-shot: re-registering under the same signaling id AND handle would drop the old
                    // guard after the insert and remove the fresh entry (Codex 3b review).
                    if let (Some(w), true) = (&input_handoff, handoff_registration.is_none()) {
                        let payload = control::encode(&ControlMessage::InputHandoffAvailable { available: !observer });
                        if let Err(e) = transport.send_frame(Frame::new(ChannelId::Control, payload)).await {
                            tracing::debug!(error = %e, "input-handoff advertisement send failed");
                        }
                        handoff_registration = Some(w.shared.arb.join_directory(
                            w.signaling_id.clone(),
                            crate::session_directory::SessionIdentity {
                                handle: w.handle,
                                control_plane_session,
                                technician_id: session_technician,
                            },
                            handoff_tx.clone(),
                        ));
                        sync_handoff_eligibility(&input_handoff, true, observer, view_only);
                    }
                }
            }

            // docs/61: InputControlChanged snapshots and this session's hand refusals.
            out = recv_handoff(&mut handoff_rx) => match out {
                Some(crate::session_directory::HandoffOutbound::Control(msg)) => {
                    let payload = control::encode(&msg);
                    if transport.send_frame(Frame::new(ChannelId::Control, payload)).await.is_err() {
                        input_open = false;
                    }
                }
                // docs/61 stage 3c: seal into THIS session's chain and send on THIS transport — the only
                // way the event reaches this session's own forwarder. Never sealed behind a known-failed
                // delivery: see `handoff_seal_step`.
                Some(crate::session_directory::HandoffOutbound::SealAudit(action)) => {
                    match handoff_seal_step(input_open, &audit_chain, action, now_unix_ms()) {
                        HandoffSealStep::Deliver(message) => {
                            let payload = file_transfer::encode(&message);
                            if transport.send_frame(Frame::new(ChannelId::FileTransfer, payload)).await.is_err() {
                                input_open = false;
                            }
                        }
                        HandoffSealStep::Broken => {
                            tracing::warn!("input hand-off audit sealed but unencodable; closing input so nothing seals behind it");
                            input_open = false;
                        }
                        HandoffSealStep::Skip => tracing::debug!("input hand-off audit skipped: input is closed"),
                        HandoffSealStep::Unidentified => {}
                    }
                }
                // The outbound queue overflowed because THIS session's loop stopped draining it: an audit record could not be queued
                // and audit is never dropped, so the session ends here, with the reason logged and sent to the controller.
                Some(crate::session_directory::HandoffOutbound::Disconnect(reason)) => {
                    tracing::error!(reason, "input hand-off: ending this session");
                    end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::Other);
                    end_detail = Some("session ended: this connection fell behind on input hand-off records and was disconnected");
                    video_open = false;
                    input_open = false;
                    last_frame = None;
                    handoff_rx = None;
                }
                None => handoff_rx = None,
            },

            // docs/53: a request's progress, from its own thread, to the controller.
            update = recv_admin_rights(&mut admin_rights_rx) => match update {
                Some((state, reason)) => {
                    tracing::info!(?state, reason = reason.as_deref().unwrap_or(""), "admin rights: update");
                    let payload = control::encode(&ControlMessage::AdminRightsResult { state, reason });
                    if transport.send_frame(Frame::new(ChannelId::Control, payload)).await.is_err() {
                        input_open = false;
                    }
                }
                None => admin_rights_rx = None,
            },

            captured = frame_rx.recv(), if video_open => match captured {
                Some(f) => {
                    // Session-stop guard: a topology-change notification is racing this arm;
                    // if the capture thread has already flipped `session_stop`, the queued frame
                    // reflects the pre-change layout and MUST NOT be forwarded.
                    if session_stop.load(Ordering::Relaxed) {
                        video_open = false;
                        input_open = false;
                        last_frame = None;
                        continue;
                    }
                    if let Err(e) = video.send(freeze.on_frame(&f, shared_canvas.as_ref(), recorder.is_some())) {
                        result = Err(e);
                        break;
                    }
                    sent += 1;
                    last_sent_at = Instant::now(); // a REAL frame resets the min-cadence timer
                    // Keep the newest raw frame (moved in — `video.send` only borrowed it) so an
                    // on-demand `RequestScreenshot` can encode a full-res PNG of the current view,
                    // AND so the cadence tick below can re-send it while the screen is idle.
                    last_frame = Some(f);
                }
                None => video_open = false, // capture thread finished
            },
            // Minimum frame cadence (see MIN_FRAME_INTERVAL). When the screen has produced no frame
            // for one interval, re-send the LAST frame so the browser's video pipeline stays fed and
            // does not flicker/stall on sparse delivery — the "blink" a playing video makes vanish.
            // A plain re-send (NOT a forced keyframe): the image is unchanged, so the encoder emits a
            // near-empty delta, and the receiver reported 0 loss / 0 drops so there is nothing to
            // repair — only to keep flowing. Ordered after the frame arm; a screen producing real
            // frames faster than the interval keeps `last_sent_at` fresh and this never fires.
            _ = cadence_tick.tick(), if video_open => {
                // Session-stop guard: same reason as the frame arm above — if the capture thread
                // has already signalled a topology change, the LAST frame we cached is pre-change
                // and MUST NOT be re-sent even to keep the pipe warm.
                if session_stop.load(Ordering::Relaxed) {
                    video_open = false;
                    input_open = false;
                    last_frame = None;
                    continue;
                }
                // Read the CURRENT commanded rate, not the one this session opened with: the
                // operator can drop to the 5 fps "Text (slow link)" preset mid-session, and a floor
                // computed once would go on delivering 15 fps after they asked for 5.
                let floor = min_frame_interval(fps_now.load(Ordering::Relaxed));
                // A hidden viewer has no picture to keep alive: only real frames, at BACKGROUND_FPS.
                if !background && last_sent_at.elapsed() >= floor {
                    if let Some(f) = freeze.outgoing(last_frame.as_ref()) {
                        // Best-effort: a closed pipeline is caught by the frame arm's error path.
                        if let Err(e) = video.send(f) {
                            result = Err(e);
                            break;
                        }
                        sent += 1;
                        last_sent_at = Instant::now();
                    }
                }
            },
            // Clipboard (up, M9): the worker read a LOCAL clipboard change → frame it out on
            // ChannelId::Clipboard. `clip_out_rx.recv()` borrows no transport, so (like the video
            // arm) it never conflicts with the recv_frame borrow; the body sends after selection.
            outbound = clip_out_rx.recv(), if clip_open => match outbound {
                // VIEW-ONLY (outbound): the guest's clipboard does not leave this machine over THIS
                // channel. Scoped deliberately — `ChannelId::Backstage` and `ChannelId::FileTransfer`
                // are still ungated on view-only and can both read the disk given an installed
                // grant, so "nothing leaves the machine" would be a false claim to make here.
                //
                // Dropped at the agent rather than trusted to the controller, the same discipline as
                // the `ChannelId::Input` arm: a mode the controller could bypass by not honouring it
                // is not a guarantee. Note the analogy is only that. Input drops an inbound ACTION;
                // this drops an EGRESS. The true sibling of the Input gate is the inbound clipboard
                // arm below.
                //
                // This is the SECOND of two gates on this direction, and the backstop rather than
                // the primary. The worker checks the same permission before it reads the clipboard
                // at all (see `clipboard_worker`), because the two run on different clocks and a
                // delivery-time check alone loses a copy made in the poll window before a lift.
                //
                // This is the EXFILTRATION direction and it is the one a screen-watching threat
                // model misses: the frame buffer shows what is displayed, but the clipboard holds
                // what was COPIED, which is routinely a password-manager secret that never renders.
                //
                // The gate is INSIDE the arm, deliberately, and not a `&& !view_only` on the arm's
                // condition. Disabling the arm would leave the worker's texts queued in the
                // unbounded `clip_out_rx`, and the moment view-only was lifted the whole backlog
                // copied DURING the restricted period would flush out at once. Receiving and
                // dropping keeps the channel drained, so lifting view-only shares only what the
                // guest copies from then on.
                Some(_) if view_only => {}
                // MACHINE POLICY: this machine's config forbids the guest's clipboard leaving it.
                // Checked separately from `view_only` and after it, so the two reasons a copy can be
                // refused stay distinguishable in the code as they are in the model: view-only is
                // the session's floor, this is the machine's ceiling.
                Some(_) if !clipboard_mode.allows_to_technician() => {}
                Some(text) => {
                    // Tell the guest their clipboard left the machine. AFTER the view-only gate, so
                    // the notice only ever describes something that really happened, and BEFORE the
                    // send, so a transport failure cannot leave the guest un-told about a copy that
                    // may already be on the wire. The presenter latches, so this is one repaint per
                    // direction per session, not one per copy.
                    if let Some(s) = guest_surface.as_ref() {
                        s.clipboard_shared(true);
                    }
                    let payload = clipboard::encode(&ClipboardMessage::Text(text));
                    if let Err(e) = transport
                        .send_frame(Frame::new(ChannelId::Clipboard, payload))
                        .await
                    {
                        tracing::debug!(error = %e, "clipboard frame send failed");
                        input_open = false;
                    }
                }
                None => clip_open = false, // clipboard worker finished (or was never started)
            },
            // docs/58 §12: replies from the upload writer (acks, errors, audit records), and the
            // uploads that reached their terminal outcome.
            Some(out) = upload_out_rx.recv() => {
                for id in &out.finished {
                    live_uploads.remove(id);
                }
                for reply in out.frames {
                    if let Some(a) = activity.as_deref() { a.touch(); }
                    if let Err(e) = transport
                        .send_frame(Frame::new(ChannelId::FileTransfer, file_transfer::encode(&reply)))
                        .await
                    {
                        tracing::debug!(error = %e, "file-transfer reply send failed");
                        input_open = false;
                        break;
                    }
                }
            }
            // docs/58 §12: a Backstage reply from the worker, in request order.
            Some(envelope_json) = backstage_reply_rx.recv() => {
                // A reply is technician work in progress too (a long operation's result).
                if let Some(a) = activity.as_deref() { a.touch(); }
                if let Err(e) = transport
                    .send_frame(Frame::new(ChannelId::Backstage, envelope_json.into_bytes()))
                    .await
                {
                    tracing::debug!(error = %e, "backstage envelope send failed");
                    input_open = false;
                }
            }
            // GUEST INGRESS — the first path by which anything originates ON this machine: a chat
            // line the guest typed, or the guest pressing the window's End button.
            //
            // A chat message carries a bare `String` and the role is supplied HERE, exactly as the
            // inbound arm supplies `Technician` for anything arriving over the transport. A window
            // that sent its own `ChatFrom` would re-open, from the local end, the hole that was
            // closed at the remote end: the agent must decide who wrote a line, never be told.
            from_guest = guest_rx.recv(), if guest_open => match from_guest {
                Some(GuestToHost::Chat(body)) => {
                    let entry = transcript.post(ChatFrom::Guest, &body, now_unix_ms());
                    // Save before acknowledging, same ordering as the technician path: a crash
                    // between the two must not lose a line that has already been shown as sent.
                    save_transcript(&chat_path, &transcript);
                    tracing::info!(seq = entry.seq, chars = entry.body.chars().count(), "chat: guest posted");
                    // Show it in the guest's own window only now, with the sequence and timestamp
                    // the transcript assigned — never optimistically at the keystroke.
                    if let Some(s) = guest_surface.as_ref() {
                        s.posted(entry.from, &entry.body, entry.at_unix_ms);
                    }
                    let payload = chat::encode(&ChatMessage::Posted { entry });
                    if let Err(e) = transport.send_frame(Frame::new(ChannelId::Chat, payload)).await {
                        tracing::debug!(error = %e, "guest chat frame send failed");
                        input_open = false;
                    }
                }
                // THE GUEST ENDED THE SESSION (docs/12 §5). This is the person at the controlled
                // machine revoking access — it tears the whole session down, unlike the technician
                // side going away. Tell the window first so it shows ENDED, then drop BOTH flags to
                // leave the loop; the surface is closed when this function returns.
                Some(GuestToHost::End) => {
                    tracing::info!("guest ended the session from the window");
                    // Input stops BEFORE the indicator comes down: revoke admission (queued input is
                    // dropped at injection) and wait, off the async thread, for typing to stop.
                    set_input_admitted(&sink, false).await;
                    if let Some(s) = guest_surface.as_ref() {
                        s.ended();
                    }
                    // Record the cause only. The control-plane report is queued after teardown at the
                    // end of this function (docs/49 v4): closing the row while capture, recording or
                    // the input block is still live would misstate what is running. Every exit path
                    // reaches that tail, so a lost viewer message cannot lose the report.
                    end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::GuestEnded);
                    if control_plane_session.is_none() {
                        tracing::info!("guest ended session has no control-plane record to end");
                    }
                    let payload = control::encode(&ControlMessage::SessionEndedByGuest);
                    if let Err(e) = transport
                        .send_frame(Frame::new(ChannelId::Control, payload))
                        .await
                    {
                        tracing::debug!(error = %e, "guest-ended notification send failed");
                    }
                    input_open = false;
                    video_open = false;
                }
                // The indicator left the screen (or came back). No visible indicator means no control:
                // hold view-only (stopping any typing) until it is visible again, and tell both sides.
                Some(GuestToHost::IndicatorVisible(visible)) => {
                    indicator_lost = !visible;
                    view_only = access_state.view_only() || indicator_lost;
                    set_input_admitted(&sink, !view_only).await;
                    sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
                    tracing::warn!(visible, view_only, "guest indicator visibility changed");
                    // docs/58 §1: no visible indicator, no changes to this machine. Revoke the gate
                    // (queued and new Backstage mutations and uploads are refused; nothing admitted
                    // before can be admitted again) and abort the uploads in flight. Their later chunks
                    // and Done get the existing "unknown transfer" failure.
                    if visible {
                        mutation_gate.reopen();
                    } else {
                        mutation_gate.revoke();
                        // The writer ends each one (disposes its `.part`, one failed reply and one
                        // record) without this loop waiting on it.
                        for (flag, _) in live_uploads.values() {
                            crate::upload_writer::cancel(flag, crate::upload_writer::INDICATOR_LOST);
                        }
                        if !live_uploads.is_empty() {
                            tracing::warn!(aborted = live_uploads.len(), "uploads stopped: guest indicator lost");
                        }
                    }
                    if let Some(s) = guest_surface.as_ref() {
                        s.set_view_only(view_only);
                    }
                    let mut msgs = vec![ControlMessage::ViewOnlyApplied { enabled: view_only }];
                    if !visible {
                        msgs.push(ControlMessage::Error {
                            message: "The guest's on-screen indicator could not be shown after a display change, so the session is view-only until it is.".to_string(),
                        });
                    }
                    for m in msgs {
                        let _ = transport.send_frame(Frame::new(ChannelId::Control, control::encode(&m))).await;
                    }
                }
                // Every sender is gone — the window closed. Stop polling this arm, but do NOT touch
                // `input_open`: the technician's session is unaffected by the guest closing a window.
                None => guest_open = false,
            },
            received = transport.recv_frame(), if input_open => match note_activity(received, activity.as_deref()) {
                Ok(frame) if frame.channel == ChannelId::Input => {
                    match input_codec::decode(&frame.payload) {
                        // VIEW-ONLY: drop the controller's input HERE, at the agent, rather than
                        // forwarding it to the injection thread. This is the enforcement that makes
                        // view-only a guarantee and not just the controller's "capture input" toggle —
                        // input that reaches the agent is still refused. Silently dropped (the controller
                        // learned the mode is on from the `ViewOnlyApplied` ack).
                        // The idle clock is still reset even when input is dropped: the technician IS
                        // present and active, so falsely timing them out would be wrong.
                        Ok(_) if view_only => {
                            last_input_unix_ms = now_unix_ms();
                        }
                        Ok(ev) => {
                            last_input_unix_ms = now_unix_ms();
                            // Marshal to the desktop-bound capture thread; injection happens there
                            // (see the capture thread above) so `SendInput` lands on the followed
                            // input desktop, not on this tokio worker thread.
                            if matches!(&ev, InputEvent::Text(text) if text.len() > 4096) {
                                tracing::warn!("closing session: input text exceeds limit");
                                break;
                            }
                            match forward_input(&mut pending_move, ev, gated.epoch(), |item| input_tx.try_send(item)) {
                                Ok(sent) => forwarded += sent as u64,
                                Err(()) => {
                                    tracing::warn!("closing session: input queue unavailable");
                                    end_detail = Some("session ended: this machine stopped accepting input for too long (it may be busy or switching screens); reconnect to continue");
                                    break;
                                }
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "input decode failed; dropping frame"),
                    }
                }
                Ok(frame) if frame.channel == ChannelId::Backstage => {
                    // Backstage request JSON → authorize + execute through the Dispatcher choke
                    // point → send the Envelope JSON back on the same channel. The `recv_frame`
                    // borrow of `transport` ended when select! yielded this frame, so borrowing
                    // `transport` again to send the reply here is fine.
                    //
                    // H1: with no dispatcher yet (secure mode, before a signed grant is installed)
                    // reply a well-formed **denied** Envelope rather than dispatching anything.
                    let reply: Option<String> = match &dispatcher {
                        Some(_) => {
                            // docs/58 §12: queued to the serial worker, stamped with the gate's
                            // generation NOW, so a request queued before the indicator is lost is
                            // refused even if it is visible again by the time it runs. The reply
                            // arrives on `backstage_reply_rx`, in order.
                            let req = String::from_utf8_lossy(&frame.payload).into_owned();
                            if backstage_worker.submit(req, mutation_gate.stamp(), observer) {
                                if let Some(a) = activity.as_deref() { a.touch(); }
                                None
                            } else {
                                Some(backstage_api::denied_no_grant_json())
                            }
                        }
                        None => {
                            // Seam C: if a grant was verified in secure-test mode (but no
                            // Dispatcher was constructed), log a distinct message so tests can
                            // observe the structural denial. The response is still the same
                            // denied_no_grant_json — the caller gets a well-formed denial.
                            #[cfg(feature = "secure-test")]
                            if secure_test_grant_installed {
                                tracing::info!(
                                    "secure-test-harness: backstage request received after grant \
                                     verification — returning denial (execution structurally \
                                     denied; no Dispatcher was ever constructed)"
                                );
                            } else {
                                tracing::info!(
                                    "secure-test-harness: backstage request with no grant \
                                     installed → denied"
                                );
                            }
                            #[cfg(not(feature = "secure-test"))]
                            tracing::debug!("backstage request with no grant installed → denied");
                            Some(backstage_api::denied_no_grant_json())
                        }
                    };
                    if let Some(envelope_json) = reply {
                        // A reply is technician work in progress too (a long operation's result).
                        if let Some(a) = activity.as_deref() { a.touch(); }
                        if let Err(e) = transport
                            .send_frame(Frame::new(ChannelId::Backstage, envelope_json.into_bytes()))
                            .await
                        {
                            tracing::debug!(error = %e, "backstage envelope send failed");
                            input_open = false;
                        }
                    }
                }
                Ok(frame) if frame.channel == ChannelId::FileTransfer => {
                    // File transfer (M8) over the same reliable transport. Decode the frame, run the
                    // upload/download state machine (synchronous disk I/O — chunks are ≤48 KiB, so a
                    // straight write-per-chunk is acceptable here; it briefly occupies this select!
                    // task but does not touch the video-send path, which runs off the non-borrowing
                    // `video` handle on its own capture thread), and send any reply frames back on
                    // the same channel. The `recv_frame` borrow ended when select! yielded, so
                    // borrowing `transport` again to reply is fine (same pattern as Backstage).
                    match file_transfer::decode(&frame.payload) {
                        Ok(msg) => {
                            // ADR-008: the session's dispatcher gates + audits the transfer. In
                            // secure mode it is None until a signed grant is installed, and every
                            // transfer is refused until then.
                            // The indicator rule first, for EVERY session: an observer may still download,
                            // but not while the guest cannot see that anyone is connected.
                            let refused = if !mutation_gate.is_open() {
                                indicator_lost_file_transfer_refusal(&msg)
                            } else if observer {
                                observer_file_transfer_refusal(&msg)
                            } else {
                                None
                            };
                            let replies = match refused {
                                Some(replies) => replies,
                                None => route_file_transfer(
                                    &audit_chain,
                                    msg,
                                    &upload_writer,
                                    &mut live_uploads,
                                    mutation_gate.stamp(),
                                    &transfer_dir,
                                    dispatcher.as_mut(),
                                    now_unix_ms(),
                                ),
                            };
                            for reply in replies {
                                // A download is pushed after ONE request, so its outbound chunks are the
                                // only sign of a transfer still running: count them as activity.
                                if let Some(a) = activity.as_deref() { a.touch(); }
                                let payload = file_transfer::encode(&reply);
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::FileTransfer, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "file-transfer reply send failed");
                                    input_open = false;
                                    break;
                                }
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "file-transfer decode failed; dropping frame"),
                    }
                }
                Ok(frame) if frame.channel == ChannelId::Chat => {
                    // In-session chat (M12). The agent owns the transcript: it assigns the
                    // sequence and timestamp, echoes the recorded entry back, and persists.
                    match chat::decode(&frame.payload) {
                        Ok(ChatMessage::Send { from: claimed, body }) => {
                            // The role is DECIDED here, not taken from the wire.
                            //
                            // `ChatFrom`'s own contract says the role is "something the agent
                            // *knows*" — and it does know it: this transport has exactly two peers,
                            // the agent (this machine, where the guest sits) and the controller
                            // (the remote technician). Anything arriving over it therefore came
                            // from the technician, in the attended case included, because the
                            // guest's `agent_host attend` process IS the agent end.
                            //
                            // Trusting the claim let the controller write lines that were recorded
                            // and replayed as the GUEST's — in a persisted support transcript
                            // (`chat.jsonl`) whose whole value is being an account of what each
                            // party said. A guest line will become possible when a local guest
                            // ingress exists; it will not arrive over this channel.
                            let from = ChatFrom::Technician;
                            if claimed != from {
                                tracing::warn!(
                                    ?claimed,
                                    "chat: peer claimed a role it cannot hold; recording as Technician"
                                );
                            }
                            let entry = transcript.post(from, &body, now_unix_ms());
                            // Persist BEFORE acknowledging. A crash between the two loses an
                            // acknowledged message otherwise, and a support transcript that is
                            // missing the line the technician can see on their screen is worse
                            // than one that is merely behind.
                            save_transcript(&chat_path, &transcript);
                            tracing::info!(seq = entry.seq, ?from, "chat message recorded");
                            // Show it to the guest too. This is the half that makes chat a
                            // conversation rather than a technician talking into a log: before the
                            // guest window existed, nothing on this machine displayed an incoming
                            // message at all.
                            if let Some(s) = guest_surface.as_ref() {
                                s.posted(entry.from, &entry.body, entry.at_unix_ms);
                            }
                            let payload = chat::encode(&ChatMessage::Posted { entry });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Chat, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "chat echo send failed");
                                input_open = false;
                            }
                        }
                        Ok(ChatMessage::RequestHistory { since_seq }) => {
                            let (entries, truncated) = transcript.history_since(since_seq);
                            let payload =
                                chat::encode(&ChatMessage::History { entries, truncated });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Chat, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "chat history send failed");
                                input_open = false;
                            }
                        }
                        // agent→controller messages; ignore a reflection (mirrors the other arms).
                        Ok(ChatMessage::Posted { .. }) | Ok(ChatMessage::History { .. }) => {}
                        Err(e) => tracing::debug!(error = %e, "chat decode failed; dropping frame"),
                    }
                }
                Ok(frame) if frame.channel == ChannelId::Clipboard => {
                    // Clipboard (down, M9): remote clipboard text → enqueue to the worker, which
                    // writes it to the local clipboard and records the resulting sequence to suppress
                    // the echo. Decoding is cheap; the actual OpenClipboard/SetClipboardData happens
                    // off this task on the worker thread.
                    match clipboard::decode(&frame.payload) {
                        // VIEW-ONLY (inbound): refuse to write the controller's text into the
                        // guest's clipboard. On the installed service the write runs as SYSTEM on
                        // the guest's desktop, so this is the agent ACTING on the machine — the same
                        // class of thing as injected input, and gated the same way. (On the attended
                        // path no clipboard is passed at all, so there is nothing to gate there; the
                        // SYSTEM framing describes the unattended install, which is where this
                        // channel is actually live.) A view-only session that can still stage
                        // arbitrary text for the guest to paste is not view-only.
                        //
                        // `Ok(_)`, not `Ok(ClipboardMessage::Text(_))`, and matching the Input gate's
                        // shape on purpose: `ClipboardMessage` has one variant today, so the two are
                        // equivalent now and stop being equivalent the day someone adds `Files` or
                        // `Image` — at which point a variant-specific pattern would let the new one
                        // through a view-only session in silence.
                        Ok(_) if view_only => {}
                        // MACHINE POLICY: this machine's config forbids the technician writing into
                        // the guest's clipboard. Same split as the outbound arm.
                        Ok(_) if !clipboard_mode.allows_to_guest() => {}
                        Ok(ClipboardMessage::Text(text)) => {
                            // Clipboard is best-effort, never fatal: drop oversized text or text
                            // the worker cannot accept, and keep the session running.
                            if text.len() > CLIPBOARD_INBOUND_MAX_BYTES {
                                tracing::warn!(bytes = text.len(), "clipboard: inbound text over the 1 MiB limit; dropped (the session continues)");
                            } else {
                                match clip_set_tx.try_send(text) {
                                    Ok(()) => {
                                        // Disclose only text actually queued for the guest's clipboard.
                                        if let Some(s) = guest_surface.as_ref() {
                                            s.clipboard_shared(false);
                                        }
                                    }
                                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                                        tracing::warn!(reason = "Full", "clipboard: inbound text dropped (worker busy or gone); the session continues");
                                    }
                                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                                        tracing::warn!(reason = "Disconnected", "clipboard: inbound text dropped (worker busy or gone); the session continues");
                                    }
                                }
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "clipboard decode failed; dropping frame"),
                    }
                }
                Ok(frame) if frame.channel == ChannelId::Control => {
                    // Multi-monitor control (M10). `RequestMonitors` is answered from the snapshot
                    // the capture thread published; `SelectMonitor` retargets the capture thread via
                    // the shared `selected` atomic (validated against that snapshot). The `recv_frame`
                    // borrow ended when select! yielded this frame, so replying on the same channel
                    // here is fine (same pattern as the Backstage/FileTransfer branches).
                    match control::decode(&frame.payload) {
                        // Observer design v2: refused at dispatch, before any handler runs. Messages
                        // the handlers already refuse under view-only keep their own replies.
                        Ok(ref msg) if observer && control::observer_rule(msg) == control::ObserverRule::Refuse => {
                            tracing::info!("observer session: refused a control message an observer may not send");
                            let payload = control::encode(&ControlMessage::Error {
                                message: "this is a view-only observer session".to_string(),
                            });
                            if transport.send_frame(Frame::new(ChannelId::Control, payload)).await.is_err() {
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::WatchedMonitors { monitors }) => {
                            if freeze.set_watched(monitors, shared_canvas.as_ref()) {
                                match freeze.watched() {
                                    Some(ids) => tracing::info!("watched monitors: {:?} (freezing others)", ids),
                                    None => tracing::info!("watched monitors: all"),
                                }
                            }
                        }
                        Ok(ControlMessage::RequestMonitors) => {
                            if let Some(ref canvas) = shared_canvas {
                                let payload = control::encode(&ControlMessage::MonitorCanvas(canvas.clone()));
                                if transport.send_frame(Frame::new(ChannelId::Control,payload)).await.is_err() {
                                    input_open = false;
                                }
                            }
                            let monitors =
                                published.lock().map(|g| g.clone()).unwrap_or_default();
                            tracing::info!(count = monitors.len(), "replying to monitor-list request");
                            let payload =
                                control::encode(&ControlMessage::MonitorList { monitors });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "monitor-list reply send failed");
                                input_open = false;
                            }
                            // In multi-session pinned-display mode, immediately follow the monitor
                            // list with MonitorPinned so every session learns the locked display
                            // without waiting for a SelectMonitor round-trip.  The pin is
                            // established by SharedCapture::spawn before any session registers.
                            if let Some(ref ss) = shared_selection_state {
                                let pinned_id = ss.lock().unwrap().monitor;
                                let payload = control::encode(
                                    &ControlMessage::MonitorPinned { monitor_id: pinned_id },
                                );
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "MonitorPinned send failed on monitor-list reply");
                                    input_open = false;
                                }
                            }
                        }
                        Ok(ControlMessage::SelectMonitor { id }) => {
                            // COMPOSITE_MONITOR_ID ("view all") is only accepted on the
                            // single-session path; composite is rejected in multi-session
                            // pinned-display mode (checked below).
                            let known = id == COMPOSITE_MONITOR_ID
                                || published
                                    .lock()
                                    .map(|g| g.iter().any(|m| m.id == id))
                                    .unwrap_or(false);
                            if !known {
                                let payload = control::encode(&ControlMessage::Error {
                                    message: format!("unknown monitor id {id}"),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "control error reply send failed");
                                    input_open = false;
                                }
                            } else if let Some(ref ss) = shared_selection_state {
                                // Multi-session pinned-display mode.  The primary monitor is pinned
                                // by SharedCapture::spawn before any session registers.
                                // Same id → idempotent no-op.  Any other id (including composite)
                                // → rejected with zero mutation; the pin is never changed here.
                                enum PinResult { AlreadyPinned, Rejected { pinned: u32 } }
                                let result = {
                                    let s = ss.lock().unwrap();
                                    if s.monitor == id {
                                        PinResult::AlreadyPinned
                                    } else {
                                        PinResult::Rejected { pinned: s.monitor }
                                    }
                                };
                                match result {
                                    PinResult::AlreadyPinned => {
                                        // Idempotent no-op: same monitor, zero mutation, no ack.
                                        tracing::debug!(
                                            monitor = id,
                                            "multi-session: SelectMonitor same-pin idempotent no-op"
                                        );
                                    }
                                    PinResult::Rejected { pinned } => {
                                        let message = format!(
                                            "monitor selection is locked to display {pinned} \
                                             for this session group; dynamic switching is not \
                                             supported in multi-session mode"
                                        );
                                        let payload =
                                            control::encode(&ControlMessage::Error { message });
                                        if let Err(e) = transport
                                            .send_frame(Frame::new(ChannelId::Control, payload))
                                            .await
                                        {
                                            tracing::debug!(
                                                error = %e,
                                                "SelectMonitor rejection send failed"
                                            );
                                        }
                                        tracing::debug!(
                                            requested = id,
                                            pinned,
                                            "multi-session: SelectMonitor rejected — \
                                             pinned-display limitation"
                                        );
                                    }
                                }
                            } else {
                                // Single-session path: move the capture selection, no ack needed.
                                selected.store(id, Ordering::Relaxed);
                                tracing::debug!(monitor = id, "controller selected monitor");
                            }
                        }
                        Ok(ControlMessage::FrameDisplayed { .. }) => {
                            // Not processed.  Single-session never sends SelectMonitorAccepted so
                            // no FrameDisplayed arrives.  Multi-session uses pinned-display mode
                            // where input readiness is unconditional — no ack cycle needed.
                        }
                        Ok(ControlMessage::InstallGrant { signed_grant }) => {
                            // H1: install a control-plane-signed backstage grant. Only meaningful
                            // when an issuer is pinned — `Deny` has nothing to verify against and
                            // `InsecureSelfIssued` already has a full demo grant active.
                            let reply = match &backstage_auth {
                                BackstageAuth::SignedBy(issuer) => {
                                    // Seam B: in secure-test-harness mode, run all the same
                                    // verification steps but do NOT construct a Dispatcher. The
                                    // real executor is structurally absent. Production path (no
                                    // secure-test feature, or secure_test_harness=false) is unchanged.
                                    #[cfg(feature = "secure-test")]
                                    if opts_secure_test_harness {
                                        match grant_matches_live_session(&signed_grant, control_plane_session, session_technician)
                                            .and_then(|_| crate::secure_test_harness::verify_grant_inert(
                                                &signed_grant, issuer, now_unix_ms(), device.0, &spent_grants,
                                            )) {
                                            Ok(()) => {
                                                secure_test_grant_installed = true;
                                                tracing::info!(
                                                    "secure-test-harness: signed grant verified; \
                                                     execution is structurally denied — \
                                                     Dispatcher::with_chain was NOT called"
                                                );
                                            }
                                            Err(msg) => {
                                                tracing::warn!(error = %msg, "secure-test-harness: rejected InstallGrant");
                                                let payload = control::encode(&ControlMessage::Error {
                                                    message: format!("grant rejected: {msg}"),
                                                });
                                                if let Err(e) = transport
                                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                                    .await
                                                {
                                                    tracing::debug!(error = %e, "secure-test install-grant reply send failed");
                                                    input_open = false;
                                                }
                                                continue;
                                            }
                                        }
                                        let payload = control::encode(&ControlMessage::GrantInstalled);
                                        if let Err(e) = transport
                                            .send_frame(Frame::new(ChannelId::Control, payload))
                                            .await
                                        {
                                            tracing::debug!(error = %e, "secure-test install-grant reply send failed");
                                            input_open = false;
                                        }
                                        continue;
                                    }
                                    // Production path: real Dispatcher.
                                    match grant_matches_live_session(&signed_grant, control_plane_session, session_technician)
                                        .and_then(|_| dispatcher_from_signed_grant(&signed_grant, issuer, now_unix_ms(), device.0, &spent_grants, audit_chain.clone())) {
                                        Ok(disp) => {
                                            let disp = equip_dispatcher(disp, &mutation_gate, &upload_root_slot);
                                            backstage_worker.install(equip_dispatcher(disp.twin(), &mutation_gate, &upload_root_slot));
                                            upload_writer.install(disp.twin());
                                            dispatcher = Some(disp);
                                            tracing::info!("backstage: signed grant verified and installed");
                                            ControlMessage::GrantInstalled
                                        }
                                        Err(msg) => {
                                            // Bad/expired/wrong-key grant → do NOT install; report it.
                                            tracing::warn!(error = %msg, "backstage: rejected InstallGrant");
                                            ControlMessage::Error {
                                                message: format!("grant rejected: {msg}"),
                                            }
                                        }
                                    }
                                }
                                BackstageAuth::Deny => {
                                    tracing::warn!("backstage: InstallGrant refused — no grant issuer available to verify against");
                                    ControlMessage::Error {
                                        message: "backstage is disabled for this session: the agent has no grant issuer key to verify a grant against".into(),
                                    }
                                }
                                BackstageAuth::InsecureSelfIssued => {
                                    tracing::debug!("backstage: InstallGrant ignored (dev mode, no issuer pinned)");
                                    ControlMessage::Error {
                                        message: "agent is in dev mode; no grant issuer is pinned".into(),
                                    }
                                }
                            };
                            let payload = control::encode(&reply);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "install-grant reply send failed");
                                input_open = false;
                            }
                        }
                        // docs/58 §2: the controller asks which Backstage features this agent
                        // understands; it offers nothing until it hears back (an older agent never
                        // answers, because it drops this message as undecodable).
                        Ok(ControlMessage::RequestBackstageFeatures) => {
                            let payload = control::encode(&ControlMessage::BackstageFeatures {
                                features: backstage_features(
                                    dispatcher.as_ref().is_some_and(|d| d.allows_file_management()),
                                    can_place_uploads,
                                ),
                            });
                            if let Err(e) = transport.send_frame(Frame::new(ChannelId::Control, payload)).await {
                                tracing::debug!(error = %e, "backstage-features reply send failed");
                                input_open = false;
                            }
                        }
                        // M11 quality control. Both arms ARM the session for telemetry: until one
                        // of them runs, the agent has emitted nothing an older controller could
                        // fail to decode (see `control`'s module docs for why that matters more
                        // than it looks).
                        Ok(ControlMessage::RequestQuality) => {
                            quality_armed = true;
                            // `encoder_bitrate` — NOT `stats.sample()`. `sample()` consumes the
                            // measurement window (it computes bits/sec since the PREVIOUS call and
                            // resets the baseline), so answering a request with it stole the 1 Hz
                            // reporter's window: the first `QualityStats` of every session then
                            // reported a `measured_bitrate_bps` covering a few milliseconds, and a
                            // controller polling `RequestQuality` at 1 Hz could keep it fabricated
                            // indefinitely. A plain read has no such side effect.
                            let payload = control::encode(&ControlMessage::QualityApplied {
                                quality,
                                encoder_bitrate_bps: stats
                                    .as_ref()
                                    .map(|s| s.encoder_bitrate_bps())
                                    .unwrap_or(quality.max_bitrate_bps),
                                capped_by_policy: capped_by_policy || stats.as_ref().is_some_and(|s| s.capped_by_bitrate_policy()),
                            });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "quality-applied reply send failed");
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::SetBackground { background: hidden }) => {
                            if hidden != background {
                                background = hidden;
                                fps_now.store(session_fps(quality.fps, background), Ordering::Relaxed);
                                tracing::debug!(background, fps = fps_now.load(Ordering::Relaxed), "viewer background state");
                            }
                        }
                        Ok(ControlMessage::SetQuality { quality: want }) => {
                            quality_armed = true;
                            // Wire clamp FIRST (defends this agent against a malformed ask), then
                            // machine policy (defends the customer's link against a legitimate
                            // one). `capped_by_policy` reports only the second, so the operator can
                            // tell the two apart.
                            let asked = want.clamped();
                            let (applied, capped) = policy.apply(asked);
                            capped_by_policy = capped;
                            let unchanged = applied == quality;
                            quality = applied;
                            fps_now.store(session_fps(applied.fps, background), Ordering::Relaxed);
                            scale_div.store(applied.scale_div, Ordering::Relaxed);
                            // A repeat of the settings already in force is ACKNOWLEDGED but not
                            // re-applied.
                            //
                            // `scale_div` changes the encoded dimensions, and a dimension change
                            // forces a full libvpx re-init — a torn-down context, dropped reference
                            // frames and a fresh keyframe. Nothing rate-limits `SetQuality`, so a
                            // controller alternating `scale_div` 1/2 at ~60 messages/sec (about
                            // 9 KB/s of control traffic) would re-init the encoder once per frame
                            // and emit a keyframe storm from a trickle of input.
                            //
                            // Deduplicating is the honest 80% of the fix and costs nothing: it
                            // removes the *repeat* case entirely. A determined alternation still
                            // gets one re-init per genuine change — bounded by the capture rate
                            // because the atomics are read once per frame, not per message — and
                            // the remaining exposure is recorded in docs/07 rather than papered
                            // over with a throttle that would also delay a legitimate change.
                            if unchanged {
                                tracing::debug!("SetQuality repeats the settings in force; not re-applying");
                            } else if let Err(e) = video.set_quality(VideoQuality {
                                color: match applied.color {
                                    ColorMode::Full => ChromaMode::Full,
                                    ColorMode::Gray => ChromaMode::Gray,
                                },
                                max_bitrate_bps: applied.max_bitrate_bps,
                                hard_cap_bps: policy.bitrate_cap_configured.then_some(policy.max_bitrate_bps),
                                adaptive: applied.adaptive,
                            }) {
                                tracing::debug!(error = %e, "set_quality failed");
                            }
                            tracing::info!(
                                scale_div = applied.scale_div,
                                fps = applied.fps,
                                color = ?applied.color,
                                bps = applied.max_bitrate_bps,
                                adaptive = applied.adaptive,
                                capped_by_policy,
                                "controller set quality"
                            );
                            let payload = control::encode(&ControlMessage::QualityApplied {
                                quality: applied,
                                encoder_bitrate_bps: applied.max_bitrate_bps,
                                capped_by_policy: capped_by_policy || stats.as_ref().is_some_and(|s| s.capped_by_bitrate_policy()),
                            });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "quality-applied reply send failed");
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::SetInputBlocked { blocked: want }) => {
                            // VIEW-ONLY: refuse to FREEZE the guest's own keyboard and mouse.
                            // docs/23 finding #15, and the worst of the ungated siblings.
                            //
                            // Every other view-only gate stops the technician doing something TO the
                            // machine. This one is worse than that: blocking input takes away the
                            // guest's ability to intervene on their own computer. Their keyboard and
                            // mouse are their only in-band way to revoke a session they are unhappy
                            // with — the guest window's End button included, since a frozen guest
                            // cannot click it. A "view only, no control" session that can leave
                            // someone unable to touch their own machine is not view-only in any
                            // sense the guest would recognise.
                            //
                            // Refused LOUDLY, unlike the input and clipboard drops. This is a
                            // discrete request with a UI toggle behind it, so the controller must
                            // learn it did not take; a silent drop would leave the console showing
                            // "input blocked" over a machine whose guest is typing freely.
                            //
                            // UNBLOCKING is always allowed. The gate is on `want`, not on the
                            // message: a session that became view-only while a block was in force
                            // must still be able to lift it, and refusing that would strand the
                            // guest frozen with the only release being session teardown.
                            if want && view_only {
                                tracing::info!("input-block refused: session is view-only");
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "view-only mode: blocking the guest's input is not allowed"
                                        .to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "input-block refusal send failed");
                                    input_open = false;
                                    video_open = false;
                                }
                                continue;
                            }
                            // Block/unblock the guest's own physical keyboard & mouse. The reply
                            // carries the state ACTUALLY in force — blocking can fail to arm (no
                            // interactive desktop) — so the controller reflects reality, not its ask.
                            let in_force = input_blocker.set_blocked(want);
                            tracing::info!(requested = want, in_force, "controller set input-block");
                            let payload = control::encode(&ControlMessage::InputBlockApplied {
                                blocked: in_force,
                            });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "input-block reply send failed");
                                // Clear BOTH flags, not just input_open. `video_open` never falls on
                                // its own (video.send only queues into an unbounded channel that
                                // outlives the transport — see the recv_frame Err arm), so clearing
                                // input_open alone would wedge the loop in a video-only state until
                                // max_session while the guest's physical input STAYS FROZEN. Ending
                                // the session promptly is what runs the teardown that releases the
                                // block. This arm is unique among the Control replies in holding an
                                // OS-level side effect, so it must fail the whole session, not half.
                                input_open = false;
                                video_open = false;
                            }
                        }
                        Ok(ControlMessage::SetMonitorBlanked { blanked: want }) => {
                            // VIEW-ONLY: blanking the guest's screen is a control action on the
                            // machine. A view-only session must not be able to leave the guest
                            // looking at a black screen while "merely watching". As with
                            // `SetInputBlocked`, UNBLANKING is always allowed so a session that
                            // became view-only while the screen was already blanked can still
                            // restore it.
                            if want && view_only {
                                tracing::info!("blank-monitor refused: session is view-only");
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "view-only mode: blanking the guest's screen is not allowed"
                                        .to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "blank-monitor refusal send failed");
                                    input_open = false;
                                    video_open = false;
                                }
                                continue;
                            }
                            let in_force = screen_blanker.set_blanked(want);
                            tracing::info!(requested = want, in_force, "controller set monitor-blank");
                            let payload = control::encode(&ControlMessage::MonitorBlankedApplied {
                                blanked: in_force,
                            });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "blank-monitor reply send failed");
                                // Same reasoning as the `SetInputBlocked` arm: a send failure
                                // while the screen is black must end the session promptly so the
                                // teardown removes the overlay. Holding only `input_open = false`
                                // would leave the session in a video-only loop while the guest
                                // stares at a black screen.
                                input_open = false;
                                video_open = false;
                            }
                        }
                        Ok(ControlMessage::InstallSessionPolicy { signed_policy }) => {
                            // Loop 79: install a control-plane-signed SESSION ACCESS policy — what
                            // the organisation says this session may do, as distinct from what the
                            // controller asks for. Verified against the SAME pinned issuer key as a
                            // backstage grant; the two are separated by a domain tag inside the
                            // signed bytes, not by a second key.
                            let mut recording_autostart_reply: Option<ControlMessage> = None;
                            let reply = match &backstage_auth {
                                BackstageAuth::SignedBy(issuer) => {
                                    match SignedSessionPolicy::from_json(&signed_policy)
                                        .and_then(|p| {
                                            // Carry the claims' EXPIRY out with the verified policy:
                                            // it is what arms the session lease (docs/25 F03), and
                                            // `verify` returns only the policy body. Reading it off
                                            // the artifact after verification is exactly as
                                            // trustworthy as the level itself — the Ed25519
                                            // signature covers the whole claims struct, expiry
                                            // included.
                                            let expires_at_ms = p.claims.expires_at_ms;
                                            let issued_at_ms = p.claims.issued_at_ms;
                                            p.verify(
                                                issuer,
                                                now_unix_ms(),
                                                device.0,
                                                session_binding,
                                            )
                                            .map(|policy| (policy, expires_at_ms, issued_at_ms))
                                        })
                                    {
                                        // A REPLAY of an older verified policy changes nothing —
                                        // not the restrictions, not the lease. Not the fail-closed
                                        // path below: the signature is good, so this is not a
                                        // tampered policy, just a stale one.
                                        Ok((_, _, issued_at_ms)) if issued_at_ms < newest_policy_issued_at_ms => {
                                            tracing::warn!(
                                                issued_at_ms,
                                                newest_policy_issued_at_ms,
                                                "ignored a session policy older than the one in force"
                                            );
                                            ControlMessage::Error {
                                                message: "session policy is older than the one in force; ignored".to_string(),
                                            }
                                        }
                                        Ok((policy, expires_at_ms, issued_at_ms)) => {
                                            newest_policy_issued_at_ms = issued_at_ms;
                                            // THE RATCHET + the provisional floor, both in
                                            // `install_verified`: the policy floor only ever tightens
                                            // (so a replayed `control` policy cannot lift a `view_only`
                                            // one), while the FIRST verified policy discharges the
                                            // provisional floor that `require_session_policy` opened
                                            // the session with.
                                            access_state.install_verified(policy.access);
                                            // Recording ban: no ratchet — the last verified policy
                                            // wins. Safe: the control plane is the only minter, and
                                            // it re-evaluates `prohibit_recording` on every lease
                                            // renewal, so a group taken off the ban lifts it within
                                            // one lease without the agent needing any special logic.
                                            recording_policy_allowed = policy.allow_recording;
                                            recording_required_by_policy = policy.require_recording;
                                            // A ban that arrives WHILE recording stops the recording
                                            // (security audit 2026-10-18). It used to refuse only the
                                            // next StartRecording, so a recording begun while it was
                                            // permitted ran on after the administrator prohibited it.
                                            // Finalized off the loop exactly as StopRecording does.
                                            if !recording_policy_allowed {
                                                if let Some(handle) = recorder.take() {
                                                    let dir = handle.dir().to_path_buf();
                                                    let video_for_stop = video.clone();
                                                    let finished = tokio::task::spawn_blocking(move || {
                                                        finish_recording(&video_for_stop, handle)
                                                    })
                                                    .await
                                                    .unwrap_or_else(|e| {
                                                        Err(std::io::Error::other(format!(
                                                            "recording finalize task failed: {e}"
                                                        )))
                                                    });
                                                    if let Some(s) = guest_surface.as_ref() {
                                                        s.set_recording(false);
                                                    }
                                                    let stopped = match finished {
                                                        Ok(side) => recording_stopped_message(&side, &dir, &audit_chain),
                                                        Err(e) => ControlMessage::Error {
                                                            message: format!("recording stop failed: {e}"),
                                                        },
                                                    };
                                                    tracing::info!("session policy prohibits recording; stopped the active recording");
                                                    if let Err(e) = transport
                                                        .send_frame(Frame::new(ChannelId::Control, control::encode(&stopped)))
                                                        .await
                                                    {
                                                        tracing::debug!(error = %e, "policy recording-stop notice send failed");
                                                    }
                                                }
                                            }
                                            // Latch the group's max-duration deadline on first
                                            // non-zero arrival. Never relaxed: the limit is a group
                                            // property, and a later policy with a different (or zero)
                                            // value should not extend a session already running against
                                            // a tight limit. The control plane re-evaluates the field
                                            // on every lease renewal, so any tightening arrives
                                            // naturally; a loosening is just ignored.
                                            if duration_deadline_ms.is_none()
                                                && policy.max_session_duration_seconds > 0
                                            {
                                                duration_deadline_ms = Some(
                                                    session_start_unix_ms
                                                        + policy.max_session_duration_seconds as i64
                                                            * 1_000,
                                                );
                                            }
                                            {
                                                let prev = idle_limit_ms;
                                                idle_limit_ms =
                                                    policy.max_idle_seconds as i64 * 1_000;
                                                // First non-zero arrival: reset the idle clock so
                                                // the handshake window does not count as idle time.
                                                if prev == 0 && idle_limit_ms > 0 {
                                                    last_input_unix_ms = now_unix_ms();
                                                }
                                            }
                                            // LIVENESS CHECK: if the recorder has stopped
                                            // mid-session (size limit, disk low, I/O error),
                                            // `recorder` is still `Some` — the handle was not
                                            // taken. `is_stopped()` reads the `Arc<AtomicBool>`
                                            // the writer thread sets, so it crosses the thread
                                            // boundary without a lock.
                                            //
                                            // A session continuing with mandatory recording
                                            // silently absent is a policy violation; terminate.
                                            if recording_required_by_policy {
                                                if let Some(ref r) = recorder {
                                                    if r.is_stopped() {
                                                        tracing::error!(
                                                            "required recording stopped \
                                                             mid-session (size/disk/IO failure) \
                                                             — terminating session"
                                                        );
                                                        end_detail = Some("session ended: this session requires recording and the recording could not continue");
                                                        session_stop
                                                            .store(true, Ordering::Relaxed);
                                                        break;
                                                    }
                                                }
                                            }
                                            // require_recording: the agent starts the recording
                                            // itself rather than waiting for the controller to send
                                            // StartRecording. This closes the bypass against an
                                            // old or adversarial viewer that skips the auto-start:
                                            // the controller can stop the recording mid-session
                                            // only on groups that permit it (StopRecording is
                                            // refused when recording_required_by_policy is true),
                                            // but the START must not depend on the viewer
                                            // cooperating.
                                            //
                                            // Fail CLOSED on every start error. A session running
                                            // with control while mandatory recording is absent is a
                                            // policy violation — we must not expose the desktop.
                                            if recording_required_by_policy && recorder.is_none() {
                                                let recording_started = match recording_dir
                                                    .as_deref()
                                                {
                                                    None => {
                                                        tracing::error!(
                                                            "require_recording active but \
                                                             recording_dir is not configured — \
                                                             terminating session"
                                                        );
                                                        false
                                                    }
                                                    Some(dir) => match crate::recording_broker::SessionRecorder::start(
                                                        dir,
                                            recording_via_service,
                                                        &device.to_string(),
                                                        control_plane_session
                                                            .map(|s| s.to_string())
                                                            .as_deref(),
                                                        crate::recording::DEFAULT_MAX_BYTES,
                                                        crate::recording::DEFAULT_MIN_FREE_BYTES,
                                                    ) {
                                                        Err(e) => {
                                                            tracing::error!(
                                                                error = %e,
                                                                "require_recording: start failed \
                                                                 — terminating session"
                                                            );
                                                            false
                                                        }
                                                        Ok(handle) => match {
                                                            let raw = freeze.suspend_for_recording();
                                                            let refresh = if raw { last_frame.as_ref().map_or(Ok(()), |f| video.send(f)) } else { Ok(()) };
                                                            refresh.and_then(|_| video.set_recording(Some(handle.sink())))
                                                        }
                                                        {
                                                            Err(e) => {
                                                                let _ = handle.stop();
                                                                tracing::error!(
                                                                    error = %e,
                                                                    "require_recording: \
                                                                     set_recording failed — \
                                                                     terminating session"
                                                                );
                                                                false
                                                            }
                                                            Ok(()) => {
                                                                let actual_dir = handle.dir().to_path_buf();
                                                        let started_at_unix_ms =
                                                                    handle.started_at_unix_ms();
                                                                recorder = Some(handle);
                                                                if let Some(s) =
                                                                    guest_surface.as_ref()
                                                                {
                                                                    s.set_recording(true);
                                                                }
                                                                tracing::info!(
                                                                    dir = %actual_dir.display(),
                                                                    "policy requires recording \
                                                                     — auto-started"
                                                                );
                                                                recording_autostart_reply = Some(
                                                                    ControlMessage::RecordingStarted {
                                                                        started_at_unix_ms,
                                                                        audit: recording_audit(
                                                                            &audit_chain,
                                                                            AuditAction::RecordingStarted {
                                                                                started_at_unix_ms,
                                                                                directory: actual_dir
                                                                                    .display()
                                                                                    .to_string(),
                                                                            },
                                                                            now_unix_ms(),
                                                                        ),
                                                                    },
                                                                );
                                                                true
                                                            }
                                                        },
                                                    },
                                                };
                                                if !recording_started {
                                                    end_detail = Some("session ended: this session requires recording and the recording could not continue");
                                                    session_stop.store(true, Ordering::Relaxed);
                                                    break;
                                                }
                                            }
                                            // ARM (or extend) THE SESSION LEASE, docs/25 F03. This
                                            // one line is the whole reason a central "End session"
                                            // now reaches an unattended desktop: the control plane
                                            // refuses to mint the NEXT policy for a session it has
                                            // ended, so the deadline recorded here is the last one
                                            // this session will ever get.
                                            //
                                            // Unconditional, not gated on `is_enforced()`: a lease
                                            // recorded on a session that is not leased is inert
                                            // (`status` returns `NotEnforced` before it looks at the
                                            // deadline), and a gate here would be one more place for
                                            // the two decisions to drift apart.
                                            session_lease.record_verified(expires_at_ms);
                                            view_only = access_state.view_only() || indicator_lost;
                                            set_input_admitted(&sink, !view_only).await;
                                            sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
                                            tracing::info!(
                                                access = policy.access.name(),
                                                view_only,
                                                allow_recording = policy.allow_recording,
                                                require_recording = policy.require_recording,
                                                max_session_duration_seconds = policy.max_session_duration_seconds,
                                                lease_ms = expires_at_ms - now_unix_ms(),
                                                "session policy verified and in force"
                                            );
                                            if let Some(s) = guest_surface.as_ref() {
                                                s.set_view_only(view_only);
                                            }
                                            ControlMessage::SessionPolicyInstalled {
                                                access: policy.access.name().to_string(),
                                                view_only,
                                                allow_recording: recording_policy_allowed,
                                                require_recording: recording_required_by_policy,
                                            }
                                        }
                                        // ONE EXCEPTION, and only on a LEASED session (docs/25 F03):
                                        // a policy that arrives already EXPIRED is not terminal.
                                        //
                                        // The terminal treatment below was written when a policy was
                                        // minted once per session with a fifteen-minute life, so an
                                        // expired one really did mean "something is wrong". Under
                                        // leases a policy lives thirty seconds and the console mints
                                        // a new one every ten, so expiry is an ORDINARY transit
                                        // outcome — a slow round trip, a laptop that suspended, a
                                        // machine clock running fast. Treating that as terminal would
                                        // convert routine lateness into permanent loss of control for
                                        // the rest of the session.
                                        //
                                        // Nothing is weakened by it. The expired policy is still NOT
                                        // applied (no level, no lease extension), and on a leased
                                        // session the fallback is far stronger than view-only: if the
                                        // controller cannot produce a policy the agent can verify,
                                        // the lease lapses and the SESSION ENDS. The narrow scope is
                                        // load-bearing — every other rejection (bad signature, wrong
                                        // machine, wrong session, unbound, malformed) stays terminal,
                                        // and so does an expired policy on a session with no lease to
                                        // fall back on.
                                        Err(e)
                                            if session_lease.is_enforced()
                                                && matches!(e, SessionPolicyError::Expired) =>
                                        {
                                            // Diagnostic re-parse, error path only: report HOW stale
                                            // it was. A policy expired by a second or two is a slow
                                            // network; one expired by minutes is a machine clock
                                            // running ahead of the control plane's, which is the
                                            // failure short leases newly expose and the one an
                                            // operator will otherwise spend a day chasing.
                                            let stale_by_ms =
                                                SignedSessionPolicy::from_json(&signed_policy)
                                                    .ok()
                                                    .map(|p| now_unix_ms() - p.claims.expires_at_ms)
                                                    .unwrap_or_default();
                                            tracing::warn!(
                                                stale_by_ms,
                                                "session lease arrived EXPIRED and was not applied; \
                                                 the session continues on its existing lease. If \
                                                 stale_by_ms is large, this machine's clock is ahead \
                                                 of the control plane's"
                                            );
                                            ControlMessage::Error {
                                                message: format!(
                                                    "session policy arrived expired ({e}) and was not \
                                                     applied; install a freshly minted one — this \
                                                     session ends when its current lease runs out"
                                                ),
                                            }
                                        }
                                        Err(e) => {
                                            // FAIL CLOSED. The controller asked us to install a policy
                                            // and we could not verify it, so we do not know what this
                                            // session is allowed to do — and since a policy is minted
                                            // ONLY for a group that enforces something, its arrival is
                                            // itself the signal that this session is restricted.
                                            // Proceeding with full control would mean a tampered,
                                            // expired or replayed policy buying MORE access than a
                                            // valid one.
                                            //
                                            // Not abusable: it only ever restricts, so a hostile
                                            // controller spamming garbage merely denies itself input.
                                            // Nor does it count as the policy a `require_session_policy`
                                            // session is waiting for — see `reject_unverified`.
                                            //
                                            // Also ban recording: the policy arrived because this
                                            // group enforces SOMETHING — we cannot know whether that
                                            // something includes a recording prohibition, so the
                                            // safe default is to treat it as banned. The default
                                            // `recording_policy_allowed = true` is correct for a
                                            // session that NEVER receives a policy; a rejected one
                                            // has received a policy and cannot verify it.
                                            recording_policy_allowed = false;
                                            access_state.reject_unverified();
                                            view_only = access_state.view_only() || indicator_lost;
                                            set_input_admitted(&sink, !view_only).await;
                                            sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
                                            tracing::warn!(
                                                error = %e,
                                                "rejected InstallSessionPolicy — failing CLOSED to \
                                                 view-only and banning recording"
                                            );
                                            if let Some(s) = guest_surface.as_ref() {
                                                s.set_view_only(view_only);
                                            }
                                            ControlMessage::Error {
                                                // "until a valid policy is installed" is what this said
                                                // before, and it was FALSE. `reject_unverified` raises
                                                // the floor by writing `policy_view_only`, and
                                                // `install_verified` then folds through
                                                // `most_restrictive` — so no later policy, however
                                                // valid, can release it. A rejection is TERMINAL for
                                                // this session. Promising recovery sent the operator to
                                                // retry something that cannot work, and on the attended
                                                // path there is no reconnect to recover with either:
                                                // one `serve_session_with_ice` per process.
                                                message: format!(
                                                    "session policy rejected ({e}); this session stays \
                                                     view-only for the rest of its life — fix the cause \
                                                     and start a new session"
                                                ),
                                            }
                                        }
                                    }
                                }
                                // An INSTALLED SERVICE with no issuer key configured. It cannot verify
                                // anything, so it FAILS CLOSED: the control plane only sends a policy
                                // when it has decided something about this session, and an agent that
                                // cannot check that decision must not assume the permissive reading.
                                //
                                // This is the deployment hole worth naming: `config.json`'s
                                // `grant_issuer_pubkey` is optional, and an operator who leaves it blank
                                // would otherwise get a control plane that believes a machine group is
                                // view-only while every agent in it silently grants full control. Better
                                // a session that is too restricted (and says so) than one the console
                                // reports as restricted and is not.
                                BackstageAuth::Deny => {
                                    // An INSTALLED SERVICE with no issuer key configured. It cannot
                                    // verify anything, and a policy only ever arrives for a group that
                                    // enforces something, so it FAILS CLOSED.
                                    //
                                    // This is the deployment hole worth naming: `config.json`'s
                                    // `grant_issuer_pubkey` is optional, and an operator who leaves it
                                    // blank would otherwise get a control plane that believes a machine
                                    // group is view-only while every agent in it silently grants full
                                    // control. Better a session that is too restricted and says so.
                                    access_state.reject_unverified();
                                    view_only = access_state.view_only() || indicator_lost;
                                    set_input_admitted(&sink, !view_only).await;
                                    sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
                                    tracing::warn!(
                                        "InstallSessionPolicy refused — no issuer key is pinned; failing \
                                         CLOSED to view-only (set grant_issuer_pubkey in config.json)"
                                    );
                                    if let Some(s) = guest_surface.as_ref() {
                                        s.set_view_only(view_only);
                                    }
                                    ControlMessage::Error {
                                        message: "agent has no pinned issuer key, so session policies cannot \
                                                  be verified; this session is view-only".into(),
                                    }
                                }
                                // DEV MODE (`stream` with no `--grant-issuer`) is explicitly and
                                // documentedly not a security context — it already self-issues a full
                                // 19-capability backstage grant. Restricting it here would break the
                                // local dev/e2e flows without protecting anything real, so the policy is
                                // simply declined and the session is left as it was.
                                BackstageAuth::InsecureSelfIssued => {
                                    tracing::debug!(
                                        "InstallSessionPolicy ignored (dev mode, no issuer pinned)"
                                    );
                                    ControlMessage::Error {
                                        message: "agent is in dev mode; no grant issuer is pinned".into(),
                                    }
                                }
                            };
                            let payload = control::encode(&reply);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "session-policy reply send failed");
                            }
                            // Notify the controller about the auto-started recording AFTER the
                            // SessionPolicyInstalled ack so the viewer's onSessionPolicyInstalled
                            // callback fires before the RecordingStarted one. Either ordering
                            // works (the controller's duplicate StartRecording is idempotent),
                            // but this order gives the viewer the policy state first.
                            if let Some(rec_msg) = recording_autostart_reply {
                                let payload = control::encode(&rec_msg);
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(
                                        error = %e,
                                        "policy-required recording ack send failed"
                                    );
                                }
                            }
                        }
                        Ok(ControlMessage::SetViewOnly { enabled }) => {
                            // View-only / presentation mode: the agent drops the controller's injected
                            // input while on. A pure in-loop bool (no OS side effect), so unlike the
                            // input-block reply a failed ack does not need to tear the session down.
                            //
                            // The reply carries the state IN FORCE, which is not always what was
                            // requested: a control-plane session policy can hold a view-only FLOOR
                            // this toggle cannot lift. Turning view-only ON is always honoured (it
                            // only restricts further); turning it OFF is honoured only if no policy
                            // floor is in force. `ViewOnlyApplied` therefore reports the effective
                            // value, so a controller that tried to leave view-only sees that it
                            // did not happen instead of desynchronising its indicator.
                            // The state machine decides what is actually in force: the toggle can
                            // always ADD restriction, but it can only remove its OWN — a policy floor,
                            // or the provisional floor of a session still awaiting a required policy,
                            // both survive it. Otherwise "withhold the policy, then toggle" would be
                            // the same bypass wearing a hat.
                            view_only = access_state.set_toggle(enabled) || indicator_lost;
                            // View-only takes effect for typing already queued too, not only new input.
                            set_input_admitted(&sink, !view_only).await;
                            sync_handoff_eligibility(&input_handoff, handoff_registration.is_some(), observer, view_only);
                            if !enabled && view_only {
                                tracing::info!(
                                    awaiting_policy = access_state.awaiting_required_policy(),
                                    "controller asked to leave view-only; refused — a floor is in force"
                                );
                            }
                            tracing::info!(view_only, "controller set view-only");
                            // Tell the guest's own window so its indicator (headline + title bar) shows
                            // whether the technician is watching or controlling — the consent signal the
                            // guest was previously never given for a view-only session.
                            if let Some(s) = guest_surface.as_ref() {
                                s.set_view_only(view_only);
                            }
                            let payload =
                                control::encode(&ControlMessage::ViewOnlyApplied { enabled: view_only });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "view-only reply send failed");
                            }
                        }
                        Ok(ControlMessage::RebootGuest { safe_mode }) => {
                            // Remote-support reboot (normal or Safe Mode with Networking). Auto-reconnect
                            // brings the session back once the guest re-registers on boot. The reply is
                            // sent BEFORE the machine goes down and reflects reality: `RebootScheduled`
                            // only if the reboot was actually armed, otherwise an `Error` and the session
                            // keeps running. See `crate::reboot`.
                            tracing::info!(safe_mode, "controller requested guest reboot");
                            let reply = if view_only {
                                // Read-only session: the technician is watching, not controlling — a
                                // reboot is a control action on the guest machine and is refused (with an
                                // explicit Error so the operator learns why, unlike silently-dropped input).
                                tracing::info!("reboot refused: session is view-only");
                                ControlMessage::Error {
                                    message: "view-only mode: reboot is not allowed".to_string(),
                                }
                            } else if reboot_armed {
                                // A reboot is already in flight; refuse a second one rather than let its
                                // failed syscall's rollback clear the pending reboot's safeboot element.
                                ControlMessage::Error {
                                    message: "a reboot is already scheduled".to_string(),
                                }
                            } else {
                                match rebooter.reboot(safe_mode) {
                                    Ok(()) => {
                                        reboot_armed = true;
                                        ControlMessage::RebootScheduled { safe_mode }
                                    }
                                    Err(e) => {
                                        tracing::warn!(safe_mode, error = %e, "reboot could not be armed");
                                        ControlMessage::Error {
                                            message: format!("reboot failed: {e}"),
                                        }
                                    }
                                }
                            };
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                                .await
                            {
                                tracing::debug!(error = %e, "reboot reply send failed");
                            }
                        }
                        Ok(ControlMessage::LockWorkstation) => {
                            // Lock the guest (Win+L): return the machine to its sign-in screen so a
                            // bystander cannot use the session the technician leaves behind. Locking is
                            // a control action on the guest, so a view-only session refuses it (explicit
                            // Error, like reboot/tool/command) rather than silently doing nothing.
                            tracing::info!("controller requested workstation lock");
                            let reply = if view_only {
                                tracing::info!("lock refused: session is view-only");
                                ControlMessage::Error {
                                    message: "view-only mode: locking the workstation is not allowed"
                                        .to_string(),
                                }
                            } else {
                                match locker.lock() {
                                    Ok(()) => {
                                        tracing::info!("workstation locked");
                                        ControlMessage::WorkstationLocked
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "workstation lock failed");
                                        ControlMessage::Error { message: format!("lock failed: {e}") }
                                    }
                                }
                            };
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                                .await
                            {
                                tracing::debug!(error = %e, "lock reply send failed");
                            }
                        }
                        Ok(ControlMessage::LogOffGuest) => {
                            // Log off the guest's interactive user: end their session and return the
                            // machine to the sign-in screen with no user logged in (unlike lock, which
                            // leaves them logged in behind a shade). Logging off is a control action on
                            // the guest, so a view-only session refuses it (explicit Error, like
                            // reboot/tool/command/lock). On success the streamed session drops as the
                            // user's session tears down; auto-reconnect re-establishes at the sign-in
                            // screen once the SYSTEM service re-registers.
                            tracing::info!("controller requested guest log off");
                            let reply = if view_only {
                                tracing::info!("log off refused: session is view-only");
                                ControlMessage::Error {
                                    message: "view-only mode: logging off the guest is not allowed"
                                        .to_string(),
                                }
                            } else {
                                match logoffer.logoff() {
                                    Ok(()) => {
                                        tracing::info!("guest log off initiated");
                                        ControlMessage::LogOffScheduled
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "guest log off failed");
                                        ControlMessage::Error { message: format!("log off failed: {e}") }
                                    }
                                }
                            };
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                                .await
                            {
                                tracing::debug!(error = %e, "log off reply send failed");
                            }
                        }
                        Ok(ControlMessage::ShutDownGuest) => {
                            // Shut the guest DOWN (power off) — the last power-menu action. Unlike a
                            // reboot the agent will NOT come back on its own; the machine stays off until
                            // it is powered on. Reuses the SAME rebooter (gated by mock_reboot), so the
                            // gate/e2e's synthetic agent acks without powering off the CI box. A view-only
                            // session refuses it (explicit Error, like reboot/lock/logoff/tool/command).
                            tracing::info!("controller requested guest shutdown");
                            let reply = if view_only {
                                tracing::info!("shutdown refused: session is view-only");
                                ControlMessage::Error {
                                    message: "view-only mode: shutting down the guest is not allowed"
                                        .to_string(),
                                }
                            } else {
                                match rebooter.shutdown() {
                                    Ok(()) => {
                                        tracing::info!("guest shutdown scheduled");
                                        ControlMessage::ShutDownScheduled
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "guest shutdown could not be armed");
                                        ControlMessage::Error { message: format!("shutdown failed: {e}") }
                                    }
                                }
                            };
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                                .await
                            {
                                tracing::debug!(error = %e, "shutdown reply send failed");
                            }
                        }
                        Ok(ControlMessage::LaunchTool { tool }) => {
                            // Launch a whitelisted admin tool on the interactive desktop so it shows up
                            // in the technician's stream. Reply reflects reality: `ToolLaunched` only if
                            // the whitelist resolved AND the spawn succeeded, otherwise an `Error`.
                            tracing::info!(tool = %tool, "controller requested tool launch");
                            let reply = if view_only {
                                // Read-only session: launching a tool spawns a process on the guest — a
                                // control action, refused.
                                tracing::info!(tool = %tool, "tool launch refused: session is view-only");
                                ControlMessage::Error {
                                    message: "view-only mode: launching a tool is not allowed".to_string(),
                                }
                            } else {
                                match launcher.launch(&tool) {
                                    Ok(_) => ControlMessage::ToolLaunched { tool: tool.clone() },
                                    Err(e) => {
                                        tracing::warn!(tool = %tool, error = %e, "tool launch failed");
                                        ControlMessage::Error { message: format!("launch failed: {e}") }
                                    }
                                }
                            };
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                                .await
                            {
                                tracing::debug!(error = %e, "tool-launch reply send failed");
                            }
                        }
                        Ok(ControlMessage::RunCommand { command, shell, as_user }) => {
                            // One-line command bar: run a single command, capture its output, and ack a
                            // `CommandResult`. Runs on a BLOCKING task (a command can take its whole
                            // timeout) held in `pending_command`, whose own `select!` arm sends the
                            // result — so a slow command never freezes video/input. A second command
                            // while one is pending is refused, like the reboot latch.
                            tracing::info!(
                                as_user,
                                ?shell,
                                cmd_len = command.len(),
                                "controller requested command run"
                            );
                            if view_only {
                                // Read-only session: running a command executes on the guest — a control
                                // action, refused (before spawning anything).
                                tracing::info!("command refused: session is view-only");
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "view-only mode: running a command is not allowed".to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "view-only command reply send failed");
                                }
                            } else if pending_command.is_some() {
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "a command is already running".to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "busy command reply send failed");
                                }
                            } else {
                                let runner = command_runner;
                                let identity = crate::command_run::RunIdentity::from_as_user(as_user);
                                pending_command = Some(tokio::task::spawn_blocking(move || {
                                    runner.run(shell, &command, identity)
                                }));
                            }
                        }
                        Ok(ControlMessage::ElevatedRun { signed_elevation, command, shell }) => {
                            // ELEVATE TO ADMIN, one command at a time (docs/01 §3, loop 87). Run this
                            // command with the interactive user's LINKED ELEVATED token — their own
                            // full administrator rights, never SYSTEM — but only against a
                            // control-plane-signed grant that names THIS session, verifies against the
                            // pinned issuer, and has never been used.
                            //
                            // Deliberately NOT a session policy: a policy may only RESTRICT, and that
                            // one-way ratchet is what makes replaying an old one harmless. This GRANTS,
                            // so it needs freshness of its own — see `rmt_agent::elevation`.
                            tracing::info!(
                                ?shell,
                                cmd_len = command.len(),
                                "controller requested an ELEVATED command run"
                            );
                            // The view-only gate FIRST and unconditionally: an elevation grant
                            // authorizes a TOKEN, never an action a floored session may not take.
                            // Ordering matters — checking it after verification would let a floored
                            // session burn grants it can never use.
                            // ONE clock sample for the whole decision. Verification and the ledger
                            // burn must agree on "now": sampling twice lets a grant expire BETWEEN
                            // the two, so it verifies and is then never recorded as spent — and the
                            // next presentation of the same grant, if the clock crosses back or the
                            // prune races, is a second use. The backstage sibling passes one value
                            // for the same reason.
                            let now_ms = now_unix_ms();
                            let refusal: Option<String> = if view_only {
                                tracing::info!("elevated command refused: session is view-only");
                                Some("view-only mode: running a command is not allowed".to_string())
                            } else if pending_command.is_some() {
                                Some("a command is already running".to_string())
                            } else {
                                match &backstage_auth {
                                    BackstageAuth::SignedBy(issuer) => {
                                        // Decoded and kept, not folded into one `and_then`: the ledger
                                        // entry is bounded by the grant's OWN `expires_at_ms`, which
                                        // lives on the claims and not on the verified body.
                                        match SignedElevationGrant::from_json(&signed_elevation)
                                            .and_then(|g| {
                                                let e = g.verify(
                                                    issuer,
                                                    now_ms,
                                                    device.0,
                                                    session_binding,
                                                )?;
                                                Ok((e, g.claims.expires_at_ms))
                                            }) {
                                            Ok((elevation, grant_expires_at_ms)) => {
                                                // CAN this host elevate at all? Checked AFTER
                                                // verification (so an unverifiable blob learns nothing
                                                // about the host) but BEFORE the burn: a grant must not
                                                // be spent by a host that could never have honoured it.
                                                if !command_runner.can_elevate() {
                                                    Some(
                                                        "this agent runs as the guest's own user and \
                                                         cannot elevate without a UAC prompt; \
                                                         elevation is available on unattended (SYSTEM \
                                                         helper) agents only"
                                                            .to_string(),
                                                    )
                                                } else if !spent_elevations.claim(
                                                    (elevation.session_id, elevation.elevation_id),
                                                    // The grant's OWN expiry bounds the ledger entry,
                                                    // so the map self-prunes and needs no sweeper.
                                                    grant_expires_at_ms,
                                                    now_ms,
                                                ) {
                                                    // Single use, claimed strictly AFTER verification —
                                                    // the same ordering rule the backstage ledger has,
                                                    // and for the same reason: a forgery naming a real
                                                    // id must not be able to burn it out from under the
                                                    // technician who legitimately holds it.
                                                    Some(
                                                        "elevation grant has already been used \
                                                         (elevation grants are single use)"
                                                            .to_string(),
                                                    )
                                                } else {
                                                    tracing::info!(
                                                        elevation_id = %elevation.elevation_id,
                                                        token = elevation.token.name(),
                                                        "elevation grant verified; running ONE command \
                                                         with the interactive user's elevated token"
                                                    );
                                                    None
                                                }
                                            }
                                            Err(e) => Some(e.to_string()),
                                        }
                                    }
                                    // No pinned issuer means nothing can authorize an elevation. Both
                                    // the installed-but-unconfigured service and DEV mode land here,
                                    // and unlike a session policy there is no "dev mode is not a
                                    // security context" argument to make: an agent that self-elevated
                                    // on an unsigned request would be a strictly worse local privilege
                                    // escalation than anything a dev grant confers.
                                    BackstageAuth::Deny | BackstageAuth::InsecureSelfIssued => Some(
                                        "this agent has no pinned issuer key, so an elevation grant \
                                         cannot be verified (set grant_issuer_pubkey in config.json)"
                                            .to_string(),
                                    ),
                                }
                            };
                            match refusal {
                                Some(reason) => {
                                    tracing::warn!(reason = %reason, "rejected ElevatedRun");
                                    let payload = control::encode(&ControlMessage::ElevationDenied {
                                        reason,
                                    });
                                    if let Err(e) = transport
                                        .send_frame(Frame::new(ChannelId::Control, payload))
                                        .await
                                    {
                                        tracing::debug!(error = %e, "elevation-denied reply send failed");
                                    }
                                }
                                None => {
                                    // Authorized. Same pending slot and same blocking task as an
                                    // ordinary RunCommand, so an elevated command cannot freeze the
                                    // video/input loop either — and so it goes through the SAME
                                    // `mock_command` gate, which is what keeps a gate run from
                                    // actually elevating on the CI box.
                                    let runner = command_runner;
                                    pending_command_elevated = true;
                                    pending_command = Some(tokio::task::spawn_blocking(move || {
                                        runner.run(
                                            shell,
                                            &command,
                                            crate::command_run::RunIdentity::UserElevated,
                                        )
                                    }));
                                }
                            }
                        }
                        Ok(ControlMessage::RequestScreenshot) => {
                            // Full-resolution lossless still of the current stream frame. The PNG encode
                            // (multi-megabyte) runs on a blocking task held in `pending_screenshot`,
                            // whose own arm pushes the result over FileTransfer — so it never stalls the
                            // loop. If no frame has arrived yet, or one is already encoding, say so
                            // rather than silently doing nothing.
                            if pending_screenshot.is_some() {
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "a screenshot is already in progress".to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "busy screenshot reply send failed");
                                }
                            } else if let Some(frame) = last_frame.clone() {
                                tracing::info!(
                                    width = frame.width,
                                    height = frame.height,
                                    "controller requested screenshot"
                                );
                                pending_screenshot = Some(tokio::task::spawn_blocking(move || {
                                    crate::screenshot::encode_png(&frame)
                                }));
                            } else {
                                let payload = control::encode(&ControlMessage::Error {
                                    message: "no frame has been captured yet".to_string(),
                                });
                                if let Err(e) = transport
                                    .send_frame(Frame::new(ChannelId::Control, payload))
                                    .await
                                {
                                    tracing::debug!(error = %e, "no-frame screenshot reply send failed");
                                }
                            }
                        }
                        Ok(ControlMessage::ListDirectory { path }) => {
                            // Read-only file-browser listing (docs/01 §3), GATED AND AUDITED since
                            // docs/25 F04 — see `directory_listing_reply`, which owns the whole
                            // decision so that it is reachable by a test. Nothing is decided here.
                            let reply = directory_listing_reply(
                                &audit_chain,
                                dispatcher.as_ref(),
                                path,
                                now_unix_ms(),
                            );
                            let payload = control::encode(&reply);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "directory-listing reply send failed");
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::StartRecording) => {
                            // Session recording (loop 89, docs/01 §5). NOT gated on view-only, and
                            // that is a decision with a reason: recording writes down exactly what
                            // the technician is already permitted to watch, so refusing it here
                            // would not stop the recording — it would move it to a local screen
                            // recorder on the technician's own machine, where the guest sees no
                            // indicator, no TTL applies and no digest exists. What makes that
                            // trade honest is the indicator below, which is why it is not
                            // conditional on anything.
                            //
                            // Group recording ban (loop 93): if the verified policy says
                            // allow_recording=false the agent refuses here, hard. No fallback to a
                            // local recorder — if the organisation banned it, the ban holds.
                            let reply = if !recording_policy_allowed {
                                ControlMessage::Error {
                                    message: "recording is prohibited by session policy".to_string(),
                                }
                            } else if recorder.is_some() {
                                // Not idempotent, deliberately: the operator's belief about which
                                // file their session is in has to stay true, and a silent "already
                                // recording" ack would let them believe a second recording started.
                                ControlMessage::Error {
                                    message: "already recording this session".to_string(),
                                }
                            } else {
                                match recording_dir.as_deref() {
                                    None => ControlMessage::Error {
                                        message: "recording is not available on this host"
                                            .to_string(),
                                    },
                                    Some(dir) => {
                                        match crate::recording_broker::SessionRecorder::start(
                                            dir,
                                                        recording_via_service,
                                            &device.to_string(),
                                            control_plane_session
                                                .map(|s| s.to_string())
                                                .as_deref(),
                                            crate::recording::DEFAULT_MAX_BYTES,
                                            crate::recording::DEFAULT_MIN_FREE_BYTES,
                                        ) {
                                            Ok(handle) => {
                                                // Install the tee, THEN tell the guest, THEN ack.
                                                // If the tee cannot be installed the encoder is
                                                // gone and this recording would silently capture
                                                // nothing — so that is an error, not a start.
                                                match {
                                                    let raw = freeze.suspend_for_recording();
                                                    let refresh = if raw { last_frame.as_ref().map_or(Ok(()), |f| video.send(f)) } else { Ok(()) };
                                                    refresh.and_then(|_| video.set_recording(Some(handle.sink())))
                                                } {
                                                    Ok(()) => {
                                                        let actual_dir = handle.dir().to_path_buf();
                                                                let started_at_unix_ms =
                                                            handle.started_at_unix_ms();
                                                        recorder = Some(handle);
                                                        if let Some(s) = guest_surface.as_ref() {
                                                            s.set_recording(true);
                                                        }
                                                        tracing::info!(
                                                            dir = %actual_dir.display(),
                                                            "controller started recording"
                                                        );
                                                        // Seal the start into the SESSION chain
                                                        // and carry it on this very reply. Sealing
                                                        // without delivering would leave a `seq`
                                                        // hole, and the control plane requires
                                                        // strict contiguity — one hole wedges the
                                                        // whole session's trail at ingest. So the
                                                        // two acts are one, here, on the success
                                                        // path only.
                                                        let ev = recording_audit(
                                                            &audit_chain,
                                                            AuditAction::RecordingStarted {
                                                                started_at_unix_ms,
                                                                directory: actual_dir
                                                                    .display()
                                                                    .to_string(),
                                                            },
                                                            now_unix_ms(),
                                                        );
                                                        ControlMessage::RecordingStarted {
                                                            started_at_unix_ms,
                                                            audit: ev,
                                                        }
                                                    }
                                                    Err(e) => {
                                                        // Finalize the empty artifact rather than
                                                        // leaking the writer thread and its files.
                                                        let _ = handle.stop();
                                                        ControlMessage::Error {
                                                            message: format!(
                                                                "cannot record: {e}"
                                                            ),
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => ControlMessage::Error {
                                                message: format!("cannot record: {e}"),
                                            },
                                        }
                                    }
                                }
                            };
                            let payload = control::encode(&reply);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "recording-started reply send failed");
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::StopRecording) => {
                            let reply = if recording_required_by_policy {
                                ControlMessage::Error {
                                    message: "recording is required by session policy".to_string(),
                                }
                            } else {
                            match recorder.take() {
                                None => ControlMessage::Error {
                                    message: "not recording".to_string(),
                                },
                                Some(handle) => {
                                    // From the RECORDER, not from `recording_dir`. They are the
                                    // same value today (one is what the other was started with),
                                    // and asking the recorder is what keeps them the same value —
                                    // it also means the reply has no "if the dir is unknown" branch
                                    // to get wrong, because a live recorder always has one.
                                    let dir = handle.dir().to_path_buf();
                                    // OFF THE SELECT! LOOP, like every other multi-hundred-ms
                                    // operation in this dispatch (`pending_command`,
                                    // `pending_screenshot`). Finalizing joins the writer thread —
                                    // which waits a full 200 ms `recv_timeout` before it observes
                                    // `stopped` — and then reads the whole segment back and SHA-256s
                                    // it, up to DEFAULT_MAX_BYTES of it. Inline, that blocked the
                                    // loop whose FIRST biased arm is `frame_rx.recv()`, so the
                                    // capture thread parked in `frame_tx.blocking_send` (the channel
                                    // holds ~133 ms of slack) on EVERY stop — and that thread is the
                                    // only input-injection thread, so the guest's session froze and
                                    // then replayed a burst of input against a screen that had moved
                                    // on. Loop 89's review found it; `recording.rs` claims recording
                                    // "can never degrade the support session it is recording", which
                                    // was true of `offer` and false of `stop`.
                                    let video_for_stop = video.clone();
                                    let finished = tokio::task::spawn_blocking(move || {
                                        finish_recording(&video_for_stop, handle)
                                    })
                                    .await;
                                    // A panic in the blocking task must not take the session with
                                    // it: the tee is out either way and the guest is no longer being
                                    // recorded, so report the failure and carry on.
                                    let finished = match finished {
                                        Ok(r) => r,
                                        Err(e) => Err(std::io::Error::other(format!(
                                            "recording finalize task failed: {e}"
                                        ))),
                                    };
                                    match finished {
                                        Ok(side) => {
                                            if let Some(s) = guest_surface.as_ref() {
                                                s.set_recording(false);
                                            }
                                            recording_stopped_message(&side, &dir, &audit_chain)
                                        }
                                        Err(e) => {
                                            // The tee is out and the writer has exited either way,
                                            // so the guest is no longer being recorded — say so
                                            // even though the sidecar could not be written.
                                            if let Some(s) = guest_surface.as_ref() {
                                                s.set_recording(false);
                                            }
                                            ControlMessage::Error {
                                                message: format!("recording stop failed: {e}"),
                                            }
                                        }
                                    }
                                }
                            }
                            };
                            let payload = control::encode(&reply);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "recording-stopped reply send failed");
                                input_open = false;
                            }
                        }
                        Ok(ControlMessage::EndSession { uninstall, directive }) => {
                            // Configurable session-end behavior. Ack `SessionEnding` BEFORE tearing the
                            // session down (and before any self-uninstall is spawned), so the controller
                            // reliably learns whether the agent is merely disconnecting or removing
                            // itself. Setting the flag lets the CALLER (run_helper_stream) perform the
                            // self-uninstall after this session returns; here we only ack and end the
                            // session by dropping both loop flags, exactly like the guest-End path.
                            // VIEW-ONLY: a floored session may END, but it may not UNINSTALL.
                            // docs/23 finding #14.
                            //
                            // The two halves of this message are not the same act. Ending a session
                            // is the technician leaving, which anyone in the session may do and the
                            // guest can do too. Uninstalling removes the agent from the machine
                            // permanently — the most destructive thing this protocol can ask for,
                            // and irreversible without another install. It is squarely in the class
                            // gated everywhere else: reboot, shut down, log off, run a command.
                            //
                            // It also underwrites docs/23 finding #3: `perform_self_uninstall`
                            // rmdir /s /q's the directory `current_exe()` sits in, as SYSTEM, and on
                            // a stub promoted from a download that directory is the guest's
                            // Downloads folder. That path is reachable from here, so leaving this
                            // arm ungated handed a view-only session a SYSTEM-privileged recursive
                            // delete. Gating it does not fix finding #3 — the promote-copy still
                            // needs its own fix — but it removes the view-only route to it.
                            //
                            // The session still ends. Downgrading rather than refusing outright is
                            // deliberate: the controller asked to leave and to remove, and only the
                            // second is disallowed. `SessionEnding` carries the uninstall flag
                            // ACTUALLY in force, matching the `InputBlockApplied` convention, so the
                            // console reflects what happened instead of what it asked for.
                            let uninstall = if uninstall && view_only {
                                tracing::info!("uninstall refused: session is view-only; ending without removing the agent");
                                false
                            } else if uninstall {
                                // docs/65 D-C2: ONE authorization path for every removal. A bare `uninstall: true` removes
                                // nothing; only a valid signed UNINSTALL directive for this device, carried in the message
                                // (or relayed separately), does, and it runs through the directive engine (single use,
                                // recorded, reported), not through this arm.
                                crate::directive_hub::authorize_session_uninstall(crate::directive_hub::global(), directive).await
                            } else {
                                false
                            };
                            tracing::info!(uninstall, "controller requested session end");
                            if uninstall {
                                // Record the request before removing the service or its local files.
                                if let Some(event) = rmt_agent::backstage::audit::try_record_shared(
                                    &audit_chain,
                                    AuditAction::ServiceControl { service: SERVICE_NAME.into(), verb: "uninstall_requested".into() },
                                    Outcome::Ok, now_unix_ms(),
                                ) {
                                    if let Some(message) = ft_audit(event.id, &event) {
                                        let payload = file_transfer::encode(&message);
                                        let _ = transport.send_frame(Frame::new(ChannelId::FileTransfer, payload)).await;
                                    }
                                }
                                // (No `uninstall_requested` flag: the engine, not this session, performs the removal.)
                                let _ = &uninstall_requested;
                            }
                            let payload =
                                control::encode(&ControlMessage::SessionEnding { uninstall });
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::Control, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "session-ending ack send failed");
                            }
                            end_notice_sent = true;
                            input_open = false;
                            video_open = false;
                        }
                        // docs/53: an attended session asks the guest (on its own thread; the answer
                        // arrives on the admin-rights arm). Anything else cannot.
                        Ok(ControlMessage::RequestAdminRights) => match &admin_rights {
                            Some(rights) => rights.request(observer, guest_open),
                            None => {
                                let payload = control::encode(&ControlMessage::AdminRightsResult {
                                    state: control::AdminRightsState::Unavailable,
                                    reason: Some("admin rights can be requested only in an attended support session".into()),
                                });
                                if transport.send_frame(Frame::new(ChannelId::Control, payload)).await.is_err() {
                                    input_open = false;
                                }
                            }
                        },
                        // docs/61: hand this session's input control to another technician. The SENDER
                        // is always this session's own handle (never taken from the message); the target
                        // resolves through the directory and the arbiter re-validates it at begin and at
                        // commit. The hand blocks on the typist barrier, so it runs off this loop: a
                        // refusal comes back on this session's hand-off channel, and success is acked by
                        // the Owned snapshot the arbiter broadcasts to every participant.
                        Ok(ControlMessage::HandInputControl { to_session }) => {
                            let refusal = match &input_handoff {
                                None => Some(input_control_error("input hand-off is not available in this session")),
                                Some(_) if view_only => Some(input_control_error("this session is view-only, so it cannot hand input control")),
                                Some(w) => match uuid::Uuid::parse_str(&to_session)
                                    .ok()
                                    .and_then(|u| w.shared.arb.handle_of(&u.to_string()))
                                {
                                    None => Some(input_control_error("that technician is no longer in this session")),
                                    Some(target) => match hand_slot.try_acquire() {
                                        // IGNORED while this session's own hand is pending (the documented
                                        // contract: the viewer disables the action until the outcome, then
                                        // the technician may retry). No task, no job, no reply: a flood is free.
                                        None => {
                                            tracing::debug!("input hand-off already in flight; request coalesced");
                                            None
                                        }
                                        Some(permit) => match w.shared.arb.try_admit_hand() {
                                            // Machine-wide cap reached (only under session churn or a stuck
                                            // fence). `permit` drops here, freeing this session's slot.
                                            None => Some(input_control_error("input hand-offs are busy on this machine; try again shortly")),
                                            Some(hub_permit) => {
                                                tracing::info!(from = w.handle, to = target, "input hand-off requested");
                                                let shared = Arc::clone(&w.shared);
                                                let me = w.handle;
                                                let tx = handoff_tx.clone();
                                                tokio::spawn(async move {
                                                    // Both permits live INSIDE the blocking job, so they are held
                                                    // until hand_input_control returns even if this wrapper task is
                                                    // cancelled (a started spawn_blocking job runs to completion).
                                                    let outcome = tokio::task::spawn_blocking(move || {
                                                        let _held = (permit, hub_permit);
                                                        let r = shared.hand_input_control(me, target);
                                                        // docs/61 stage 3c: audit a COMMITTED hand — never one that did not
                                                        // commit — into both parties' own chains. Inside the job, so a
                                                        // cancelled wrapper task cannot lose the record.
                                                        if let Ok(crate::input_arbiter::CommitOutcome::Owned { epoch, .. }) = &r {
                                                            shared.arb.seal_handoff(me, target, *epoch);
                                                        }
                                                        r
                                                    })
                                                    .await;
                                                    let message = match outcome {
                                                        Ok(r) => hand_outcome_message(&r),
                                                        Err(_) => Some(input_control_error("the hand-off did not complete")),
                                                    };
                                                    if let Some(message) = message {
                                                        tracing::info!(%message, "input hand-off refused");
                                                        let _ = tx.send(crate::session_directory::HandoffOutbound::Control(ControlMessage::Error { message }));
                                                    }
                                                });
                                                None
                                            }
                                        },
                                    },
                                },
                            };
                            if let Some(message) = refusal {
                                let payload = control::encode(&ControlMessage::Error { message });
                                if transport.send_frame(Frame::new(ChannelId::Control, payload)).await.is_err() {
                                    input_open = false;
                                }
                            }
                        }
                        // These are agent→controller messages; the agent never consumes one itself.
                        // Ignore if a controller reflects one back (mirrors the file-transfer branch).
                        Ok(ControlMessage::AdminRightsAvailable { .. })
                        | Ok(ControlMessage::InputHandoffAvailable { .. })
                        | Ok(ControlMessage::InputControlChanged { .. })
                        | Ok(ControlMessage::AdminRightsResult { .. })
                        | Ok(ControlMessage::MonitorList { .. })
                        | Ok(ControlMessage::Error { .. })
                        | Ok(ControlMessage::GrantInstalled)
                        | Ok(ControlMessage::BackstageFeatures { .. })
                        | Ok(ControlMessage::QualityApplied { .. })
                        | Ok(ControlMessage::QualityStats { .. })
                        | Ok(ControlMessage::InputBlockApplied { .. })
                        | Ok(ControlMessage::MonitorBlankedApplied { .. })
                        | Ok(ControlMessage::ViewOnlyApplied { .. })
                        | Ok(ControlMessage::SessionPolicyInstalled { .. })
                        | Ok(ControlMessage::SessionLeaseRequired { .. })
                        | Ok(ControlMessage::RebootScheduled { .. })
                        | Ok(ControlMessage::ShutDownScheduled)
                        | Ok(ControlMessage::ToolLaunched { .. })
                        | Ok(ControlMessage::WorkstationLocked)
                        | Ok(ControlMessage::LogOffScheduled)
                        | Ok(ControlMessage::CommandResult { .. })
                        | Ok(ControlMessage::ElevationDenied { .. })
                        | Ok(ControlMessage::DirectoryListing { .. })
                        | Ok(ControlMessage::DirectoryListingRefused { .. })
                        | Ok(ControlMessage::RecordingStarted { .. })
                        | Ok(ControlMessage::RecordingStopped { .. })
                        | Ok(ControlMessage::SessionEnding { .. })
                        | Ok(ControlMessage::SessionEndedByGuest)
                        | Ok(ControlMessage::TransferDir { .. })
                        | Ok(ControlMessage::SelectMonitorAccepted { .. })
                        | Ok(ControlMessage::MonitorPinned { .. })
                        | Ok(ControlMessage::MonitorCanvas(_)) => {}
                        Err(e) => tracing::debug!(error = %e, "control decode failed; dropping frame"),
                    }
                }
                Ok(frame) => {
                    tracing::debug!(channel = ?frame.channel, "ignoring frame on unhandled channel");
                }
                // The data channel closed: the controller is GONE, so this session is over.
                //
                // Both flags are cleared (not just `input_open`) because the loop runs while
                // `video_open || input_open`, and `video_open` never becomes false on its own here:
                // it only flips when the capture thread stops or `video.send` fails, and `send` just
                // queues into an unbounded channel that stays alive with the transport. So clearing
                // `input_open` alone left the agent encoding frames into a dead peer connection
                // until the session max-run expired — and it does not re-register until this
                // returns, so the machine was unreachable for ~5 minutes after EVERY session. A
                // second session moments after the first was refused "not registered or offline".
                // Observed on the lab VM.
                Err(_) => {
                    end_reason.get_or_insert(rmt_protocol::signaling::SessionEndReason::ViewerLeft);
                    input_open = false;
                    video_open = false;
                }
            },
            // M11: 1 Hz quality telemetry, only once the controller has proved it speaks quality.
            // Borrows no transport during selection, so like the clipboard-out arm it never
            // conflicts with the `recv_frame` `&mut` borrow.
            _ = quality_tick.tick(), if quality_armed && stats.is_some() => {
                let s = stats.as_mut().expect("checked by the arm guard").sample();
                let payload = control::encode(&ControlMessage::QualityStats {
                    encoder_bitrate_bps: s.encoder_bitrate_bps,
                    measured_bitrate_bps: s.measured_bitrate_bps,
                    fraction_lost_256: s.fraction_lost_256,
                    rtt_ms: s.rtt_ms,
                    width: s.width,
                    height: s.height,
                    feedback_reports: s.feedback_reports,
                    // Derived by the transport from the two numbers it measured together, rather
                    // than recomputed here against an assumed 1 Hz tick. `frames_in_window` used to
                    // be computed and then dropped on the floor at exactly this line, which is why
                    // an operator who set 30 fps and achieved 14 was never told.
                    fps_x100: s.achieved_fps_x100(),
                    dropped_frames_total: s.dropped_frames,
                });
                // Logged as well as sent, so the achieved rate is verifiable on a machine where
                // nobody is watching a console — and, on the lab VM, cross-checkable against
                // `stream_probe`'s wholly independent `ts_delta` measurement at the receiver.
                // The agent's own report of itself is not evidence on its own; agreeing with a
                // receiver-side instrument is.
                tracing::debug!(
                    commanded_fps = quality.fps,
                    achieved_fps_x100 = s.achieved_fps_x100(),
                    window_ms = s.window_ms,
                    dropped = s.dropped_frames,
                    fresh_frames_total = capture_counts.0.load(Ordering::Relaxed),
                    capture_misses_total = capture_counts.1.load(Ordering::Relaxed),
                    "quality telemetry"
                );
                if let Err(e) = transport
                    .send_frame(Frame::new(ChannelId::Control, payload))
                    .await
                {
                    // BOTH flags, not just `input_open` — the same reason the `recv_frame` error
                    // arm below clears both, spelled out there at length. The loop runs while
                    // `video_open || input_open`, and `video_open` never becomes false on its own:
                    // `video.send` only queues. Clearing `input_open` alone would leave the agent
                    // encoding into a dead peer until the session max-run expired, during
                    // which it does not re-register and the machine is unreachable — the exact
                    // regression that arm exists to prevent, reintroduced through a new send site.
                    tracing::debug!(error = %e, "quality-stats send failed");
                    input_open = false;
                    video_open = false;
                }
            },
            // One-line command bar: the blocking `RunCommand` task finished. Guarded on
            // `pending_command.is_some()`, so the branch future is only built when a command is
            // actually in flight; the `&mut` join borrow ends (the future is dropped) before the body
            // clears the slot and touches `transport`. Sends the captured result, or an `Error` if the
            // process could not be started (`Ok(Err)`) or the blocking task panicked (`Err`).
            res = async { pending_command.as_mut().expect("guarded by is_some").await },
                if pending_command.is_some() =>
            {
                pending_command = None;
                // Read the request's identity, then clear it WITH the slot — the two are one piece
                // of state and a stale `true` would report the NEXT ordinary command's start failure
                // as an elevation refusal.
                let was_elevated = pending_command_elevated;
                pending_command_elevated = false;
                let reply = match res {
                    Ok(Ok(out)) => ControlMessage::CommandResult {
                        exit_code: out.exit_code,
                        stdout: out.stdout,
                        stderr: out.stderr,
                        truncated: out.truncated,
                        timed_out: out.timed_out,
                    },
                    // A command that could not START. WHICH channel that travels on depends on what
                    // was asked for, not on which error came back.
                    //
                    // For an `ElevatedRun`, every start failure means the same two things: nothing
                    // executed, and the elevation did not happen. That is precisely the fact
                    // `ElevationDenied` exists to carry, and reporting it as a generic `Error` tells
                    // the viewer a command FAILED — a different claim, and the one that matters
                    // least here. The reachable causes are `NotElevatable` (the interactive user has
                    // no linked elevated token at all — a standard user, or any account on a UAC-off
                    // box, refused rather than silently downgraded), `NoUser` (nobody is signed in,
                    // so there is no token to take) and `Setup`/`Spawn` (a Win32 fault building the
                    // environment or creating the process). Matching on the REQUEST rather than
                    // enumerating variants is deliberate: a new `CommandError` should not silently
                    // start reporting an elevated refusal as an ordinary command failure.
                    //
                    // Note what this does NOT fix, deliberately: the single-use grant is already
                    // burned by this point. The pre-burn `can_elevate()` gate covers the HOST axis
                    // ("am I the SYSTEM helper"), which is decidable without a syscall; the USER
                    // axis could be probed with the same two calls the run itself makes, but doing
                    // it before the claim would fetch the token twice and would still be a TOCTOU —
                    // so the grant is spent and the technician re-mints. Un-burning instead would
                    // make the ledger non-monotonic to save a re-mint of a 2-minute artifact, which
                    // is a bad trade for the one property of this design simple enough to be
                    // obviously correct. The refusal now at least tells them why.
                    Ok(Err(e)) if was_elevated => {
                        let reason = e.to_string();
                        tracing::warn!(
                            %reason,
                            "elevated command could not start — the grant is spent"
                        );
                        ControlMessage::ElevationDenied { reason }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "command could not be started");
                        ControlMessage::Error { message: format!("command failed: {e}") }
                    }
                    Err(join_err) => {
                        tracing::warn!(error = %join_err, "command task panicked");
                        ControlMessage::Error { message: "command task failed".to_string() }
                    }
                };
                if let Err(e) = transport
                    .send_frame(Frame::new(ChannelId::Control, control::encode(&reply)))
                    .await
                {
                    tracing::debug!(error = %e, "command-result reply send failed");
                }
            },
            // Screenshot: the blocking PNG encode finished. On success, PUSH the PNG over FileTransfer
            // as an `Offer`+`Chunk`s+`Done` — which the controller receives and saves like any download
            // (no explicit Request needed). On an encode error, tell the controller via `Error`.
            res = async { pending_screenshot.as_mut().expect("guarded by is_some").await },
                if pending_screenshot.is_some() =>
            {
                pending_screenshot = None;
                match res {
                    Ok(Ok(png)) => {
                        let id = uuid::Uuid::new_v4();
                        let name = crate::screenshot::screenshot_filename(now_unix_ms() as u128);
                        let size = png.len() as u64;
                        let sha256 = file_transfer::sha256_hex(&png);
                        let mut msgs: Vec<FtMessage> =
                            vec![FtMessage::Offer(Offer { id, name, size, sha256 })];
                        for chunk in file_transfer::chunk_file(id, &png) {
                            msgs.push(FtMessage::Chunk(chunk));
                        }
                        msgs.push(FtMessage::Done { id });
                        let mut send_ok = true;
                        for m in &msgs {
                            let payload = file_transfer::encode(m);
                            if let Err(e) = transport
                                .send_frame(Frame::new(ChannelId::FileTransfer, payload))
                                .await
                            {
                                tracing::debug!(error = %e, "screenshot push send failed");
                                send_ok = false;
                                break;
                            }
                        }
                        if send_ok {
                            tracing::info!(bytes = size, "screenshot: pushed PNG over file-transfer");
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(error = %e, "screenshot encode failed");
                        let payload = control::encode(&ControlMessage::Error {
                            message: format!("screenshot failed: {e}"),
                        });
                        if let Err(e) = transport
                            .send_frame(Frame::new(ChannelId::Control, payload))
                            .await
                        {
                            tracing::debug!(error = %e, "screenshot error reply send failed");
                        }
                    }
                    Err(join_err) => {
                        tracing::warn!(error = %join_err, "screenshot task panicked");
                        let payload = control::encode(&ControlMessage::Error {
                            message: "screenshot task failed".to_string(),
                        });
                        let _ = transport
                            .send_frame(Frame::new(ChannelId::Control, payload))
                            .await;
                    }
                }
            },
            _ = tokio::time::sleep(Duration::from_millis(500)) => {} // periodic stop / max-run re-check
        }
    }

    // Signal + join the capture thread so the capturer is dropped before we return. Dropping
    // `input_tx` disconnects the input channel; the capture thread discards queued events and
    // releases tracked input before exiting. This ends only THIS
    // session — the caller's `stop` is left untouched so a reconnect loop lives to serve the next
    // controller.
    let end_reason = end_reason.unwrap_or_else(|| classify_unattributed_end(
        stop.load(Ordering::Relaxed),
        start.elapsed() >= max_session,
    ));
    // FIRST, on every exit path: no more input reaches the guest. The admission fences wait out any
    // injection already past a check, queued presses are dropped where they would be injected, and
    // typing is awaited to a stop; only key/button RELEASES can still drain. Everything below (the
    // guest window saying ENDED, the end report) therefore happens after input has stopped (Codex
    // 1.3.9 round 4).
    // docs/58 §1: revoke every mutating channel before the guest window and its indicator go away,
    // and before the first await below, so nothing queued is admitted while it is pending (Codex
    // phase B review). Every upload still running is told the session ended.
    mutation_gate.revoke();
    for (flag, _) in live_uploads.values() {
        crate::upload_writer::cancel(flag, crate::upload_writer::SESSION_ENDED);
    }
    set_input_admitted(&sink, false).await;
    // docs/58 §12: queued Backstage requests now carry a dead stamp and are refused; dropping the
    // sender lets the worker exit once it has answered them. Nothing waits for it.
    drop(backstage_worker);
    // docs/53: retire a request still waiting on the guest and end a grant (the fence above already
    // revoked the helper's admission; this tells it to clean up and closes its pipe).
    if let Some(rights) = &admin_rights {
        rights.end();
    }
    session_stop.store(true, Ordering::Relaxed);
    // Tell the console WHY, unless an arm already did. AFTER the input fence (Codex end-notice r1: a
    // network await before it kept input admitted for up to 500 ms past the decision to end) and
    // before anything is torn down, so the transport is still there to carry it. Best-effort and
    // bounded: on most silent ends the peer is still connected, and when it is not this costs 500 ms.
    if !end_notice_sent {
        if let Some(message) = end_notice_message(end_detail, end_reason, max_session) {
            let payload = control::encode(&ControlMessage::Error { message });
            let _ = tokio::time::timeout(
                Duration::from_millis(500),
                transport.send_frame(Frame::new(ChannelId::Control, payload)),
            ).await;
        }
    }
    // Release the guest-input block unconditionally as the session winds down, so a guest is never
    // left frozen after the technician is gone. This runs on EVERY exit path (peer gone, guest End,
    // send failure); `InputBlocker::drop` is the final backstop if this line is ever bypassed.
    // Read the state BEFORE releasing: `set_blocked(false)` returns the (always-false) post-release
    // state, so branching on it would make the "forced release" warning dead code.
    // Finalize a recording still running at teardown (loop 89), on EVERY exit path — peer gone,
    // guest End, send failure, max-session. Without this the writer thread would be dropped with an
    // unfinalized IVF (a header claiming zero frames) and NO sidecar, so the one artifact that says
    // what a recording is and when it may be deleted would be missing exactly for the sessions that
    // ended abnormally. No `RecordingStopped` is sent: by this point the transport is usually the
    // reason we are here. The sidecar on disk is the record.
    if let Some(handle) = recorder.take() {
        match finish_recording(&video, handle) {
            Ok(side) => tracing::info!(
                segments = side.segments.len(),
                truncated = side.truncated.as_deref().unwrap_or("no"),
                "recording: finalized at session teardown"
            ),
            Err(e) => tracing::warn!(error = %e, "recording: could not finalize at teardown"),
        }
        // The window is about to say ENDED, and its ended banner discloses that a recording was
        // made (`recorded_ever` latches). This clears the LIVE claim so the two never disagree.
        if let Some(s) = guest_surface.as_ref() {
            s.set_recording(false);
        }
    }
    let was_blocked = input_blocker.is_blocked();
    input_blocker.set_blocked(false);
    if was_blocked {
        tracing::warn!("input-block: still armed at teardown; forced release (guest input restored)");
    } else {
        tracing::debug!("input-block: nothing to release at teardown");
    }
    // Remove the monitor blank unconditionally. `ScreenBlanker::drop` is the final backstop
    // if this line is ever bypassed, but calling it explicitly here mirrors the input-blocker
    // pattern and makes the intent visible to a reader.
    let was_blanked = screen_blanker.is_blanked();
    screen_blanker.set_blanked(false);
    if was_blanked {
        tracing::warn!("blank-monitor: still active at teardown; forced removal (guest screen restored)");
    } else {
        tracing::debug!("blank-monitor: nothing to remove at teardown");
    }
    // ADR-008: reap uploads that were authorized and streamed but never finalized. Without this an
    // `Offer` + `Chunk`s with no `Done` left attacker-chosen bytes in a `.part` file under the
    // transfer root with NO audit record at all — the one upload shape that produced neither the
    // denial recorded at `Offer` nor the completion recorded at `Done` — and the `.part` outlived
    // the session, so repeating it filled the volume just as quietly. Sealing them here restores
    // the invariant the ADR states: an authorized transfer always ends in a record.
    // docs/58 §1, §12: end every upload (each was cancelled at the top of teardown). The writer gets
    // up to 5 s to finish them (dispose, one record each); then the ledger CLOSES, whatever cancel
    // reason or commit an upload was in: each one still without its record is recorded here, and the
    // writer, when its system call returns, disposes and logs without ever appending again.
    drop(upload_writer);
    let wait_until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while !live_uploads.is_empty() {
        match tokio::time::timeout_at(wait_until, upload_out_rx.recv()).await {
            Ok(Some(out)) => {
                for id in &out.finished {
                    live_uploads.remove(id);
                }
            }
            Ok(None) | Err(_) => break,
        }
    }
    upload_ledger.close(|| {
        for (id, (flag, name)) in live_uploads.drain() {
            if flag.claim_record() {
                tracing::warn!(transfer = %id, "upload still busy at teardown; recorded as abandoned");
                let _ = audit_file_transfer(
                    &audit_chain,
                    dispatcher.as_mut(),
                    id,
                    Direction::Input,
                    name,
                    String::new(),
                    0,
                    Outcome::Failed {
                        error: "upload abandoned at session end: the agent was still writing or committing it".into(),
                    },
                    now_unix_ms(),
                );
            }
        }
    });
    drop(frame_rx);
    drop(input_tx);
    // Disconnect the clipboard set-channel so the worker's `recv_timeout` returns `Disconnected` and
    // it exits promptly (it also observes `stop`); then join it so its `Clipboard` is dropped here.
    drop(clip_set_tx);
    let _ = cap_thread.join();
    if let Some(t) = clip_thread {
        let _ = t.join();
    }
    // The guest window last, and in two steps. `ended()` flips its banner to "no longer shared"
    // while the window is still up; `close()` posts WM_RMT_DESTROY (the host's own teardown message,
    // distinct from the guest's [X] which now ends the session) and JOINS the UI thread, so by the
    // time this function returns there is no window on the guest's screen still claiming a session is
    // live and no thread left behind. The reconnect loop opens a fresh one on the next attempt.
    if let Some(mut s) = guest_surface.take() {
        s.ended();
        s.close();
        tracing::debug!("guest window: closed");
    }
    // docs/49: nothing of this session is still running, so its control-plane row may close.
    report_session_end(guest_end_reports.as_ref(), control_plane_session, end_reason);
    tracing::debug!(frames = sent, forwarded, ?end_reason, "serve_session: finished");
    result
}

/// Resolves once this helper has been asked to stop (service STOP/PRESHUTDOWN, or its own session
/// ending: both set helper_stop's flag). Polled, because the flag is a plain atomic; 100 ms is far
/// inside the ~10 s the stop allows sessions.
async fn wait_for_helper_stop() {
    wait_until_stopped(crate::helper_stop::requested).await
}

/// [`wait_for_helper_stop`] over an injected flag (tests must not set the process-wide one).
async fn wait_until_stopped(stopped: impl Fn() -> bool) {
    while !stopped() {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Maximum UTF-8 byte length of inbound clipboard text; larger pushes are dropped without ending the session.
const CLIPBOARD_INBOUND_MAX_BYTES: usize = 1024 * 1024;

/// docs/49: the reason for an exit no select arm attributed. The helper stopping is a service stop;
/// the session's lifetime bound is its maximum duration; anything else (a send failure, the
/// capture thread stopping, a topology change) is `Other`. A viewer leaving is attributed by the
/// arms that observe it, never assumed here.
fn classify_unattributed_end(helper_stopping: bool, lifetime_passed: bool) -> rmt_protocol::signaling::SessionEndReason {
    if helper_stopping {
        rmt_protocol::signaling::SessionEndReason::ServiceStop
    } else if lifetime_passed {
        rmt_protocol::signaling::SessionEndReason::MaxDuration
    } else {
        rmt_protocol::signaling::SessionEndReason::Other
    }
}

/// Retry the held mouse move on its own. `Ok(1)` once it is queued, `Ok(0)` while the queue is still
/// full (it stays held, epoch unchanged), `Err(())` when the capture thread is gone.
fn flush_pending_move(
    pending: &mut Option<(InputEvent, u64)>,
    mut send: impl FnMut((InputEvent, u64)) -> Result<(), std::sync::mpsc::TrySendError<(InputEvent, u64)>>,
) -> Result<u32, ()> {
    let Some(item) = pending.take() else { return Ok(0) };
    match send(item) {
        Ok(()) => Ok(1),
        Err(std::sync::mpsc::TrySendError::Full(item)) => {
            *pending = Some(item);
            Ok(0)
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(()),
    }
}

/// Preserve move-before-button ordering while retaining only the latest blocked move.
fn forward_input(
    pending: &mut Option<(InputEvent, u64)>,
    ev: InputEvent,
    epoch: u64,
    mut send: impl FnMut((InputEvent, u64)) -> Result<(), std::sync::mpsc::TrySendError<(InputEvent, u64)>>,
) -> Result<u32, ()> {
    let mut sent = 0;
    if let Some(item) = pending.take() {
        match send(item) {
            Ok(()) => sent += 1,
            Err(std::sync::mpsc::TrySendError::Full(item)) => {
                if matches!(&ev, InputEvent::MouseMove { .. }) {
                    *pending = Some((ev, epoch));
                    tracing::debug!("input queue full; replacing pending mouse move");
                    return Ok(sent);
                }
                *pending = Some(item);
                return Err(());
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return Err(()),
        }
    }
    match send((ev, epoch)) {
        Ok(()) => Ok(sent + 1),
        Err(std::sync::mpsc::TrySendError::Full((ev, epoch))) => {
            if matches!(&ev, InputEvent::MouseMove { .. }) {
                *pending = Some((ev, epoch));
                tracing::debug!("input queue full; retaining pending mouse move");
                Ok(sent)
            } else {
                Err(())
            }
        }
        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => Err(()),
    }
}

/// Give the console a specific reason for an otherwise silent session end. Delivery is
/// best-effort with a 500 ms bound at teardown because the transport may already be gone.
fn end_notice_message(
    detail: Option<&'static str>,
    reason: rmt_protocol::signaling::SessionEndReason,
    max_session: Duration,
) -> Option<String> {
    if let Some(detail) = detail {
        return Some(detail.to_string());
    }
    use rmt_protocol::signaling::SessionEndReason;
    match reason {
        SessionEndReason::MaxDuration => {
            let seconds = max_session.as_secs();
            let length = if seconds % 3600 == 0 {
                format!("{} h", seconds / 3600)
            } else {
                format!("{} min", seconds / 60)
            };
            Some(format!("session ended: this machine's maximum session length ({length}) was reached; reconnect to continue"))
        }
        SessionEndReason::ServiceStop => Some("session ended: the DeskRally agent on this machine is stopping or updating; reconnect in a minute".to_string()),
        SessionEndReason::Other => Some("session ended: the agent on this machine ended the session unexpectedly; reconnect to continue".to_string()),
        SessionEndReason::ViewerLeft
        | SessionEndReason::GuestEnded
        | SessionEndReason::LeaseLapsed
        | SessionEndReason::Idle
        | SessionEndReason::Policy => None,
    }
}

/// Queue the docs/49 end report for a signaling-vouched session: fence its id, retain the report
/// until signaling acknowledges a terminal result. A no-op without the helper's report set (every
/// non-mux path) or without a control-plane id (dev/LAN: nothing was vouched, nothing to close).
fn report_session_end(
    reports: Option<&rmt_agent_core::guest_end::GuestEndReports>,
    control_plane_session: Option<uuid::Uuid>,
    reason: rmt_protocol::signaling::SessionEndReason,
) {
    let (Some(reports), Some(id)) = (reports, control_plane_session) else { return };
    match reports.report_end(id, reason, std::time::Instant::now()) {
        rmt_agent_core::guest_end::AddResult::Queued => {
            tracing::info!(control_plane_session = %id, ?reason, "session end report queued")
        }
        rmt_agent_core::guest_end::AddResult::AlreadyPending => {}
        rmt_agent_core::guest_end::AddResult::Full => {
            tracing::warn!(control_plane_session = %id, ?reason, "session_end_unqueued: report queue full")
        }
    }
}

/// Take the recorder's tee out of the encoder loop and finalize the recording (loop 89).
///
/// **What the order buys, stated accurately** — an earlier version of this comment claimed the tee
/// had to come out first or "every clean stop would look truncated", and loop 89's mutation sweep
/// proved that false by swapping the two lines with every test still green. It is worth recording
/// why, because the reason is a deliberate property of `RecorderHandle::stop`: it snapshots
/// `queue_full` and `dropped` **as its first act**, before joining the writer, so nothing the
/// encoder does afterwards can reach the sidecar. That snapshot is what makes the reported figures
/// mean "what happened while the recording was live" rather than "what happened including
/// teardown", and it is the right meaning — frames offered after the operator pressed Stop are not
/// lost data.
///
/// So removing the tee first is not a correctness requirement; it stops the encoder thread doing
/// pointless work during the join, and it bounds which frames can still land in the file to the few
/// already queued. Keep the order, but do not defend it as more than that.
///
/// This function exists for a different reason, which IS load-bearing: the session has two stop
/// paths (the `StopRecording` message and the teardown), and finalizing in one place means there is
/// one implementation to be right rather than two to keep in step.
///
/// A failure to remove the tee is logged and NOT propagated: it means the encode pipeline has
/// already shut down, which is precisely the state in which there is nothing left to tee to, and
/// refusing to finalize the files over it would abandon a recording that is otherwise complete.
fn finish_recording(
    video: &VideoFrameSender,
    handle: crate::recording_broker::SessionRecorder,
) -> std::io::Result<crate::recording::Sidecar> {
    if let Err(e) = video.set_recording(None) {
        tracing::debug!(error = %e, "recording: the encode pipeline was already closed");
    }
    handle.stop()
}

/// Render a finished recording's sidecar as the controller-bound `RecordingStopped`.
///
/// Separated from the dispatch arm because it is the only part of the stop path with any
/// arithmetic in it, and because the figures must come from the FINISHED artifact — a count kept
/// optimistically as frames were offered would over-report exactly when it matters, on a recording
/// that was truncated.
fn recording_stopped_message(
    side: &crate::recording::Sidecar,
    dir: &std::path::Path,
    chain: &SharedAuditChain,
) -> ControlMessage {
    let frames = side.segments.iter().map(|s| s.frames).sum();
    let payload_bytes = side.segments.iter().map(|s| s.payload_bytes).sum();
    let directory = dir.display().to_string();
    // The audit-valuable half. Its DIGESTS are the point: they are what ties this line to the file
    // somebody later hands over, and they come from the finished artifact — `Segment::sha256` is
    // computed over the bytes ON DISK after finalize, not accumulated as frames went by.
    let audit = recording_audit(
        chain,
        AuditAction::RecordingStopped {
            frames,
            payload_bytes,
            truncated: side.truncated.clone(),
            dropped_frames: side.dropped_frames,
            segment_sha256: side.segments.iter().map(|s| s.sha256.clone()).collect(),
            directory: directory.clone(),
        },
        now_unix_ms(),
    );
    ControlMessage::RecordingStopped {
        segments: side.segments.len() as u32,
        frames,
        payload_bytes,
        truncated: side.truncated.clone(),
        dropped_frames_total: side.dropped_frames,
        directory,
        audit,
    }
}

/// Authorize, list, and audit one `ControlMessage::ListDirectory`, returning the reply to send
/// (docs/25 F04).
///
/// **What was here before was a straight `dir_list::list_directory(&path)`**, with a comment
/// explaining that no gate was needed because a listing "grants nothing beyond what a viewer can
/// already see on screen". That sentence was the entire defence and it was false twice over: a
/// directory listing names files that are nowhere on the screen, and `read_dir` will follow a UNC
/// path — which, from a LocalSystem service on a domain-joined machine, means authenticating to
/// somebody else's SMB server with the machine account.
///
/// The uncomfortable half of F04 is not that this arm lacked a gate. It is that the SAME operation
/// on the backstage channel (`Request::BrowseDirectory` → `panels::file::list`) has required
/// `Capability::FileBrowse` and sealed an `AuditAction::FileBrowse` since the day it was written.
/// Two directory listers, one policy, applied to one of them. This path now asks the same question
/// of the same grant and seals the same action into the same chain — deliberately WITHOUT unifying
/// the two implementations, because neither is a superset of the other and the merge would have cost
/// something real either way: this one caps entries and reports truncation, that one reports
/// symlinks and has no cap.
///
/// Still not gated on `view_only`, and now for a reason that survives inspection: view-only decides
/// what may be DRIVEN on the machine (input, reboot, lock, log off, shut down), while what may be
/// READ is decided by the capabilities in the grant — exactly as it is for the far more disclosing
/// FileTransfer download, which is likewise capability-gated and view-only-blind.
///
/// A function rather than an inline arm because the arm is unreachable by any test: it needs a live
/// transport, a capturer and a Windows desktop, so a decision made inline there is a decision nothing
/// can check. That is the same reason `SessionAccessState` exists.
fn directory_listing_reply(
    chain: &SharedAuditChain,
    dispatcher: Option<&Dispatcher>,
    path: String,
    now_ms: i64,
) -> ControlMessage {
    if let Some(reason) = file_browse_denial_reason(dispatcher) {
        tracing::warn!(?path, reason, "directory listing REFUSED: this session may not browse files");
        // The refusal is sealed BEFORE anything is read, and nothing is read at all — the ordering
        // is the guarantee, not the reply.
        let audit =
            audit_file_browse(chain, &path, Outcome::Denied { reason: reason.to_string() }, now_ms);
        return ControlMessage::DirectoryListingRefused { path, reason: reason.to_string(), audit };
    }
    match crate::dir_list::list_directory(&path) {
        Ok(listing) => {
            // Sealed HERE, on the success path, and delivered on this very message — the
            // `recording_audit` contract. A path that produces no reply able to carry the event must
            // seal nothing: the event would be a `seq` hole, and a hole wedges the rest of the
            // session's trail at ingest, permanently.
            let audit = audit_file_browse(chain, &path, Outcome::Ok, now_ms);
            ControlMessage::DirectoryListing {
                path,
                entries: listing.entries,
                truncated: listing.truncated,
                audit,
            }
        }
        // A path this agent will not REACH (UNC, device namespace, `\\?\`, a mapped network drive, a
        // link off the local disk). That is a decision this agent made about somebody, not a
        // filesystem failure, so it is recorded and gets the refusal message.
        Err(e @ crate::dir_list::ListError::Refused(_)) => {
            let reason = e.to_string();
            tracing::warn!(
                %path,
                %reason,
                "directory listing REFUSED: the path is not on this machine's local disk"
            );
            let audit =
                audit_file_browse(chain, &path, Outcome::Denied { reason: reason.clone() }, now_ms);
            ControlMessage::DirectoryListingRefused { path, reason, audit }
        }
        // The filesystem declined (missing, not a directory, access denied). Nothing is sealed:
        // `Error` carries no audit field, so an event sealed here would have no delivery vehicle —
        // and the volume of ordinary typos would make the trail worse rather than better.
        Err(e) => ControlMessage::Error { message: format!("cannot list {path}: {e}") },
    }
}

/// Why this session may not browse directories, or `None` if it may (docs/25 F04).
///
/// The two refusals are told apart in the `reason`, and that distinction goes into the audit record.
/// "You hold no grant" and "your grant does not include this" are different findings about a
/// session: the first says a peer was talking to the agent before the control plane had authorized
/// anything, the second says an authorized technician reached past their role. An investigator who
/// cannot tell those apart cannot tell an intrusion from a misconfiguration.
fn file_browse_denial_reason(dispatcher: Option<&Dispatcher>) -> Option<&'static str> {
    match dispatcher {
        None => Some("no backstage grant is installed for this session"),
        Some(disp) if !disp.allows_file_browse() => {
            Some("this session's grant does not include the file_browse capability")
        }
        Some(_) => None,
    }
}

/// Seal one `ListDirectory` outcome into the session chain and render it for the wire (docs/25 F04).
///
/// `try_record_shared`, and `None` on an unidentified chain, for the reason spelled out at
/// [`recording_audit`]: an event that could never be forwarded is not a thinner record, it is a
/// `seq` hole that makes `verifyLinkage` reject every later event in the session. Every caller
/// attaches the returned value to a reply it is about to send, so sealing and delivering are one
/// act.
///
/// It records the REQUESTED path, not a resolved one — including on a refusal, where nothing was
/// resolved because nothing was touched. What an investigator needs is what was asked for.
fn audit_file_browse(
    chain: &SharedAuditChain,
    path: &str,
    outcome: Outcome,
    now_ms: i64,
) -> Option<serde_json::Value> {
    let action = AuditAction::FileBrowse { path: path.to_string() };
    let Some(ev) = rmt_agent::backstage::audit::try_record_shared(chain, action, outcome, now_ms)
    else {
        tracing::debug!(
            %path,
            "file browse: the session chain has no identity (no verified ticket and no installed \
             grant), so nothing is sealed — an event that could not be forwarded would break the \
             chain for the rest of the session"
        );
        return None;
    };
    match serde_json::to_value(&ev) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "could not serialize the file-browse audit event");
            None
        }
    }
}

/// Seal one recording action into the session chain and render it for the wire.
///
/// Returns `None` — sealing NOTHING — when the chain has no session identity, i.e. signaling vouched
/// for no control-plane session (dev/LAN/e2e, `-insecure-no-ticket-verification`). That is not
/// squeamishness about a nil uuid: `POST /audit/ingest` refuses a batch whose `technician_id` is not
/// the authenticated forwarder, and the console builds no forwarder at all without a session id, so
/// an event sealed here could never be delivered — and an undelivered event is a `seq` HOLE that
/// wedges every later event in the session at `verifyLinkage`. Recording an unshippable event would
/// therefore not add a record, it would destroy the ones that follow it.
///
/// Serialization failure is likewise `None` and logged, for exactly the same reason.
fn recording_audit(
    chain: &SharedAuditChain,
    action: AuditAction,
    now_ms: i64,
) -> Option<serde_json::Value> {
    let Some(ev) = rmt_agent::backstage::audit::try_record_shared(chain, action, Outcome::Ok, now_ms)
    else {
        tracing::debug!(
            "recording: the session chain has no identity (no verified ticket and no installed              grant), so nothing is sealed — an event that could not be forwarded would break the              chain for the rest of the session"
        );
        return None;
    };
    match serde_json::to_value(&ev) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(error = %e, "could not serialize the recording audit event");
            None
        }
    }
}

/// The clipboard sync worker (M9), run on its own OS thread with sole ownership of the platform
/// [`Clipboard`]. The Windows clipboard is window-station-scoped (WinSta0), so this needs no
/// desktop binding and is deliberately kept off the capture thread.
///
/// It bridges the two channels `serve_session_with_ice` set up:
///  * `set_rx` — remote text to write locally (from inbound `ChannelId::Clipboard` frames);
///  * `out_tx` — local clipboard changes to forward out (framed by the async loop).
///
/// Loop: block on `set_rx.recv_timeout(POLL)` so **inbound** remote text applies immediately, while
/// a `POLL`-cadence timeout drives **local** change detection via [`Clipboard::sequence`].
///
/// ## Echo suppression (essential)
///
/// Writing the clipboard with `set_text` itself advances the OS sequence number. Without care, that
/// self-inflicted change would be detected as a "local change" on the next poll and bounced straight
/// back to the controller, which would echo it back to us — an infinite loop. So after every
/// successful `set_text` the worker records the resulting `sequence()` into `last_seen`; the local
/// change-detection only fires (and forwards) when `sequence()` differs from `last_seen`, i.e. a
/// change we did **not** cause. Startup seeds `last_seen` with the current sequence so the clipboard's
/// pre-existing contents are not spuriously pushed on connect.
/// `egress_allowed` is polled by the worker immediately before it reads the clipboard's contents,
/// and answers "may the guest's clipboard leave this machine right now?" — the session's live
/// view-only state composed with the machine's configured [`ClipboardMode`]. It is a callback rather
/// than a captured `bool` because view-only changes DURING a session and the worker outlives every
/// change; see the change-detection block for why the gate has to be here and not only at the send.
fn clipboard_worker(
    clipboard: Box<dyn Clipboard>,
    set_rx: std::sync::mpsc::Receiver<String>,
    out_tx: tokio::sync::mpsc::UnboundedSender<String>,
    stop: Arc<AtomicBool>,
    egress_allowed: impl Fn() -> bool,
    take_resync_request: impl Fn() -> bool,
) {
    use std::sync::mpsc::RecvTimeoutError;

    /// Local-clipboard change poll cadence. Inbound remote text is applied with no added latency
    /// (it wakes `recv_timeout` immediately); this only bounds how fast a LOCAL copy is noticed.
    const POLL: Duration = Duration::from_millis(300);

    // Seed with the current sequence so existing clipboard contents aren't pushed on connect.
    let mut last_seen = clipboard.sequence();

    while !stop.load(Ordering::Relaxed) {
        // Collect any remote text to apply. Block up to POLL for the first; drain the rest.
        let mut pending: Vec<String> = Vec::new();
        match set_rx.recv_timeout(POLL) {
            Ok(text) => {
                pending.push(text);
                pending.extend(set_rx.try_iter().take(7));
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break, // async side hung up → shut down
        }

        // Apply remote writes. After each successful write, record the resulting sequence as
        // `last_seen` so our own write is NOT mistaken for a local change below (echo suppression).
        for text in pending {
            match clipboard.set_text(&text) {
                Ok(()) => last_seen = clipboard.sequence(),
                Err(e) => tracing::debug!(error = %e, "clipboard set_text failed"),
            }
        }

        // Egress just re-opened: drop the baseline before looking, so whatever changed while it was
        // shut is treated as already accounted for rather than as news. Taken (and cleared) even
        // when nothing changed, so the request cannot linger and swallow a later legitimate copy.
        if take_resync_request() {
            last_seen = clipboard.sequence();
        }

        // Detect a genuine LOCAL change (a change we did not just make) and forward it.
        let seq = clipboard.sequence();
        if seq != last_seen {
            // ADVANCE `last_seen` UNCONDITIONALLY, BEFORE the egress decision. This is what makes
            // "lifting view-only shares only what the guest copies from then on" actually true.
            //
            // The gate must live HERE, where the clipboard is READ, and not only at the send site
            // in the async loop. The two run on different clocks: the async side evaluates
            // `view_only` when a message is DELIVERED, while this thread reads the clipboard up to
            // POLL later. Gating only at delivery leaves a sub-poll race — guest copies a password
            // at T with view-only in force; the technician lifts view-only at T+50ms; this thread
            // polls at T+300ms, reads the password, and the async side now sees view_only == false
            // and ships it. The secret was copied under view-only and left the machine anyway.
            //
            // Because `last_seen` advances even when egress is refused, a change that happened
            // while restricted is CONSUMED rather than deferred: it is never re-detected, so
            // lifting the restriction cannot release it afterwards.
            last_seen = seq;
            // Only touch the clipboard's CONTENTS if this session may actually send them. Reading
            // is not free of consequence: `get_text()` pulls the guest's clipboard — routinely a
            // password — into this SYSTEM process's heap. A session that may not forward it has no
            // business holding it, and a machine configured `to_guest` or `disabled` should never
            // read it at all.
            if egress_allowed() {
                if let Some(text) = clipboard.get_text() {
                    if out_tx.send(text).is_err() {
                        break; // async side gone
                    }
                }
            }
        }
    }
}

/// In-flight state for one inbound upload (controller→agent), keyed by transfer id in the
/// `uploads` map. Bytes are streamed straight to a `.part` file on disk and hashed incrementally,
/// so nothing is buffered in memory; on `Done` the size + SHA-256 are verified and the `.part` is
/// atomically renamed to its final name.
pub(crate) struct UploadState {
    /// The `.part` file, created relative to the held staging handle and held by THIS handle until
    /// commit or discard (docs/58 §12; see `upload_root`). Nothing reaches it by name.
    pub(crate) file: std::fs::File,
    /// The offered base name the verified file lands under (or the first free `name (n).ext`).
    name: String,
    /// The destination's display path, for audit text only.
    pub(crate) dest: String,
    /// The root's path, for free-space checks only.
    root_path: PathBuf,
    /// Incremental SHA-256 over the bytes written so far.
    hasher: Sha256,
    /// Bytes written so far (checked against the offer's `size` on `Done`).
    pub(crate) received: u64,
    /// Expected total size from the `Offer`.
    expected_size: u64,
    /// Expected lowercase-hex SHA-256 from the `Offer`.
    expected_sha: String,
    /// Next chunk `seq` we require (starts at 0, enforces in-order, gap-free delivery).
    next_seq: u32,
}

/// Drive the file-transfer state machine for one decoded [`FtMessage`], performing the disk I/O and
/// returning the reply messages to send back on [`ChannelId::FileTransfer`] (possibly none).
///
/// Upload (controller→agent): `Offer` opens a `.part` file (no reply); each `Chunk` is appended
/// in-order (no reply, or an `Error` that aborts the transfer on a gap/write failure); `Done`
/// verifies size + SHA-256, renames `.part`→final, and replies `Ack{ok:true}` (or `Ack{ok:false}`).
///
/// Download (controller→agent `Request`): the requested path is resolved **inside the transfer
/// root** (traversal/absolute denied; symlink escape blocked via `canonicalize`), then the file is
/// read and replied as `Offer` + `Chunk`s + `Done`. Any failure replies a single `Error`.
///
/// Messages the agent does not expect to receive (`Ack`, `Error`, `Audit`) are ignored.
///
/// ADR-008 — AUTHORIZATION + AUDIT. Every transfer is gated on the session's backstage grant and
/// recorded into that session's tamper-evident chain:
///
///   * an upload (`Offer`…`Done`) needs `Capability::FileUpload`, a download (`Request`) needs
///     `Capability::FileDownload`;
///   * with **no dispatcher** — secure mode before a signed grant is installed — every transfer is
///     refused. There is no chain to record into yet (mirroring `denied_no_grant_json`), so the
///     refusal carries no audit message;
///   * an upload is refused at its `Offer`, so an unauthorized peer never causes a disk write;
///   * the audit record is emitted where the REAL digest and byte count are known (at `Done` for an
///     upload, after the read for a download), and is appended to the reply list as an
///     `FtMessage::Audit` the controller forwards to `POST /audit/ingest`.
/// Decide whether a session is a view-only OBSERVER (observer design v2) from the access signaling
/// stated, before the first frame. `Invalid` refuses the session: it never defaults to control.
/// `force_observer` is the e2e test hook and can only tighten a session.
fn session_observer(access: BrokeredAccess, force_observer: bool) -> Result<bool, &'static str> {
    match access {
        BrokeredAccess::Invalid => Err("session refused: signaling stated an invalid session access (observer protocol)"),
        BrokeredAccess::ViewOnly => Ok(true),
        BrokeredAccess::Control | BrokeredAccess::Legacy => Ok(force_observer),
    }
}

#[cfg(test)]
mod session_observer_tests {
    use super::*;

    #[test]
    fn signaling_decides_and_the_test_hook_only_tightens() {
        assert!(session_observer(BrokeredAccess::Invalid, false).is_err(), "invalid never starts");
        assert!(session_observer(BrokeredAccess::Invalid, true).is_err(), "the hook cannot rescue invalid");
        assert_eq!(session_observer(BrokeredAccess::ViewOnly, false), Ok(true));
        assert_eq!(session_observer(BrokeredAccess::Control, false), Ok(false));
        assert_eq!(session_observer(BrokeredAccess::Legacy, false), Ok(false));
        assert_eq!(session_observer(BrokeredAccess::Control, true), Ok(true));
        assert_eq!(session_observer(BrokeredAccess::Legacy, true), Ok(true));
    }
}

/// A view-only OBSERVER may download (`Request`) but never write to the guest (observer design v2).
/// `Some(replies)` = refused, send these instead of handling; `None` = handle normally. An upload
/// `Offer` gets an explicit `Error`; a stray `Chunk`/`Done` (no authorized offer can exist) is dropped.
/// docs/58 §1: while the guest's indicator is not visible, no file reaches or leaves this machine.
/// An `Offer` or a download `Request` is answered with an error; stray chunks and `Done`s of the
/// uploads that were aborted are dropped (their state is gone, so nothing would accept them anyway).
fn indicator_lost_file_transfer_refusal(msg: &FtMessage) -> Option<Vec<FtMessage>> {
    const WHY: &str = "the guest's on-screen indicator could not be shown, so this machine is not accepting file transfers";
    match msg {
        FtMessage::Offer(offer) => Some(vec![FtMessage::Error { id: offer.id, message: WHY.to_string() }]),
        FtMessage::Request { id, .. } => Some(vec![FtMessage::Error { id: *id, message: WHY.to_string() }]),
        FtMessage::Chunk(_) | FtMessage::Done { .. } => Some(Vec::new()),
        FtMessage::Ack { .. } | FtMessage::Error { .. } | FtMessage::Audit { .. } => None,
    }
}

/// Arm a session dispatcher with this session's mutation gate and the Windows file manager
/// (docs/58).
fn equip_dispatcher(
    mut disp: Dispatcher,
    gate: &Arc<rmt_agent::backstage::gate::MutationGate>,
    uploads: &Arc<std::sync::Mutex<Option<Arc<crate::upload_root::UploadRoot>>>>,
) -> Dispatcher {
    disp.set_mutation_gate(Arc::clone(gate));
    disp.set_file_manager(Box::new(
        crate::fs_manage::WinFileManager::for_this_agent().with_upload_root(Arc::clone(uploads)),
    ));
    disp
}

/// Enforcement-posture features for `register_agent` (audit #9): always `posture_v1`, plus
/// `grant_key_pinned` only when a grant issuer key is pinned, and `session_policy_required` only when require_session_policy is on (the same condition that lets the session
/// verify signed policies and hold a session lease).
pub(crate) fn posture_features(grant_key_pinned: bool, session_policy_required: bool) -> Vec<String> {
    let mut f = vec![rmt_protocol::signaling::POSTURE_FEATURE.to_string()];
    if grant_key_pinned {
        f.push(rmt_protocol::signaling::GRANT_KEY_PINNED_FEATURE.to_string());
    }
    if session_policy_required {
        f.push(rmt_protocol::signaling::SESSION_POLICY_REQUIRED_FEATURE.to_string());
    }
    f
}

/// The Backstage features this agent advertises (docs/58 §2). `file_manage` only when the session's
/// INSTALLED grant holds `file_delete`: the console shows the controls only on that, so they rest on
/// the grant this agent verified (the console never sees a self-issued dev grant at all).
/// `file_place` (docs/58 §12) additionally needs a session whose uploads land in the agent's own
/// anchored folder, which is the only root placement works from.
pub(crate) fn backstage_features(grant_allows_file_management: bool, can_place_uploads: bool) -> Vec<String> {
    let mut f = vec!["confirm".to_string()];
    if grant_allows_file_management {
        f.push("file_manage".to_string());
        if can_place_uploads {
            f.push("file_place".to_string());
        }
    }
    f
}

fn observer_file_transfer_refusal(msg: &FtMessage) -> Option<Vec<FtMessage>> {
    match msg {
        FtMessage::Offer(offer) => Some(vec![FtMessage::Error {
            id: offer.id,
            message: "this is a view-only observer session; it cannot upload files".to_string(),
        }]),
        FtMessage::Chunk(_) | FtMessage::Done { .. } => Some(Vec::new()),
        FtMessage::Request { .. } | FtMessage::Ack { .. } | FtMessage::Error { .. } | FtMessage::Audit { .. } => None,
    }
}

#[cfg(test)]
mod observer_file_transfer_tests {
    use super::observer_file_transfer_refusal;
    use rmt_agent_core::file_transfer::{Chunk, Message as FtMessage, Offer};
    use uuid::Uuid;

    #[test]
    fn offer_gets_an_error_with_the_same_id() {
        let id = Uuid::new_v4();
        let offer = FtMessage::Offer(Offer {
            id,
            name: "probe.bin".into(),
            size: 0,
            sha256: rmt_agent_core::file_transfer::sha256_hex(b""),
        });
        let replies = observer_file_transfer_refusal(&offer).expect("offer must be refused");
        assert_eq!(replies.len(), 1);
        match &replies[0] {
            FtMessage::Error { id: reply_id, message } => {
                assert_eq!(*reply_id, id);
                assert!(message.contains("observer"));
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn chunk_and_done_are_dropped() {
        let id = Uuid::new_v4();
        for msg in [
            FtMessage::Chunk(Chunk { id, seq: 0, data: vec![1, 2, 3] }),
            FtMessage::Done { id },
        ] {
            assert_eq!(observer_file_transfer_refusal(&msg), Some(Vec::new()));
        }
    }

    #[test]
    fn download_and_non_upload_messages_are_handled_normally() {
        let id = Uuid::new_v4();
        for msg in [
            FtMessage::Request { id, path: "probe.bin".into() },
            FtMessage::Ack { id, ok: true, message: String::new() },
            FtMessage::Error { id, message: "probe".into() },
            FtMessage::Audit { id, event: serde_json::json!({}) },
        ] {
            assert_eq!(observer_file_transfer_refusal(&msg), None);
        }
    }
}

/// docs/58 §12: route one file-transfer frame. Upload frames go to the writer (never waiting: a
/// full queue cancels that upload); a download is served here as before.
#[allow(clippy::too_many_arguments)]
fn route_file_transfer(
    chain: &SharedAuditChain,
    msg: FtMessage,
    writer: &crate::upload_writer::UploadWriter,
    live: &mut HashMap<Uuid, (crate::upload_writer::Flag, String)>,
    stamp: u64,
    transfer_dir: &Path,
    dispatcher: Option<&mut Dispatcher>,
    now_ms: i64,
) -> Vec<FtMessage> {
    use crate::upload_writer::{cancel, Item, Submit, LIVE, OVERFLOW};
    match msg {
        FtMessage::Offer(offer) => {
            let id = offer.id;
            let name = offer.name.clone();
            if live.contains_key(&id) {
                // The running upload keeps its flag and its state; only this Offer is refused.
                return upload_refused(chain, dispatcher, id, name, "upload repeats an active id".into(), now_ms);
            }
            let flag = crate::upload_writer::new_flag();
            match writer.submit(Item::Offer { offer, stamp, flag: Arc::clone(&flag) }) {
                Submit::Sent => {
                    live.insert(id, (flag, name));
                    Vec::new()
                }
                Submit::Full | Submit::Closed => upload_refused(
                    chain,
                    dispatcher,
                    id,
                    name,
                    crate::upload_writer::reason(OVERFLOW).into(),
                    now_ms,
                ),
            }
        }
        FtMessage::Chunk(chunk) => {
            let id = chunk.id;
            if live.get(&id).is_some_and(|(f, _)| f.state() != LIVE) {
                return Vec::new(); // cancelled: the writer is ending it
            }
            if let Submit::Full = writer.submit(Item::Chunk(chunk)) {
                if let Some((f, _)) = live.get(&id) {
                    cancel(f, OVERFLOW);
                }
            }
            Vec::new()
        }
        FtMessage::Done { id } => {
            if live.get(&id).is_some_and(|(f, _)| f.state() != LIVE) {
                return Vec::new();
            }
            if let Submit::Full = writer.submit(Item::Done(id)) {
                if let Some((f, _)) = live.get(&id) {
                    cancel(f, OVERFLOW);
                }
            }
            Vec::new()
        }
        FtMessage::Request { id, path } => serve_download(chain, id, &path, transfer_dir, dispatcher, now_ms),
        FtMessage::Ack { .. } | FtMessage::Error { .. } | FtMessage::Audit { .. } => Vec::new(),
    }
}


/// Serialize an audit event into the `FtMessage::Audit` the controller forwards. Returns `None`
/// if the event cannot be serialized (impossible for this struct); the transfer's own reply is
/// unaffected either way, so a failure here never breaks a transfer.
fn ft_audit(id: Uuid, ev: &rmt_agent::backstage::audit::AuditEvent) -> Option<FtMessage> {
    match serde_json::to_value(ev) {
        Ok(event) => Some(FtMessage::Audit { id, event }),
        Err(e) => {
            tracing::warn!(error = %e, "could not serialize file-transfer audit event");
            None
        }
    }
}

/// Record a file-transfer audit event and return the reply message carrying it, plus whether the
/// transfer was authorized.
///
/// **With no dispatcher the transfer is still refused, and the refusal is now RECORDED** (loop 91).
/// Before the chain was lifted to session scope this branch returned `(None, false)`: a session with
/// no backstage grant produced no chain, so ADR-008's stated invariant — "an authorized transfer
/// always ends in a record", and its corollary that a refusal is a record too — held only for
/// sessions that happened to have installed a grant. An investigator reading such a session's trail
/// saw a session that did no file-transfer work at all, which is indistinguishable from one where
/// nobody tried. The chain exists for the whole session now, so the denial goes in it.
///
/// The `Denied` reason names the missing GRANT rather than a missing capability, because that is the
/// true cause and the two are worth telling apart in a trail: "you hold no grant" and "your grant
/// does not include this" are different findings about a session.
pub(crate) fn audit_file_transfer(
    chain: &SharedAuditChain,
    dispatcher: Option<&mut Dispatcher>,
    id: Uuid,
    direction: Direction,
    path: String,
    sha256: String,
    bytes: u64,
    outcome: Outcome,
    now_ms: i64,
) -> (Option<FtMessage>, bool) {
    match dispatcher {
        Some(disp) => {
            let (ev, allowed) =
                disp.record_file_transfer(direction, path, sha256, bytes, outcome, now_ms);
            (ft_audit(id, &ev), allowed)
        }
        None => {
            // `try_`, not `record_`: with no grant the chain may also be UNIDENTIFIED (a deployment
            // that verifies no session tickets vouches for neither id, and no grant has arrived to
            // supply them). Sealing there would consume a `seq` for an event nothing can forward,
            // which is worse than not recording it — see `try_record_shared`.
            match rmt_agent::backstage::audit::try_record_shared(
                chain,
                AuditAction::FileTransfer { direction, path, sha256, bytes },
                Outcome::Denied {
                    reason: "no backstage grant is installed for this session".into(),
                },
                now_ms,
            ) {
                Some(ev) => (ft_audit(id, &ev), false),
                None => (None, false),
            }
        }
    }
}

/// Begin an inbound upload: authorize, then create the transfer dir + a `.part` temp file. No reply
/// on success (the controller streams chunks next); an `Error` if the file can't be created.
///
/// ADR-008: the capability check happens FIRST, before any filesystem work, so an unauthorized peer
/// cannot create files (or even a directory) on the machine. The refusal is sealed into the audit
/// chain carrying the OFFERED name/digest/size — what was attempted — since no real bytes exist yet.
#[cfg(test)]
pub(crate) fn start_upload(
    chain: &SharedAuditChain,
    offer: Offer,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &mut crate::upload_root::LazyRoot,
    dispatcher: Option<&mut Dispatcher>,
    now_ms: i64,
) -> Vec<FtMessage> {
    start_upload_step(offer, uploads, root, dispatcher.as_deref(), now_ms).into_frames(chain, dispatcher)
}

/// An upload step's replies and, when the step ENDED the upload, its terminal record, not yet
/// appended (docs/58 §12): the upload writer appends it only if session teardown has not already
/// recorded that upload. Everything else appends it at once with [`Step::into_frames`].
#[must_use]
pub(crate) struct Step {
    pub(crate) frames: Vec<FtMessage>,
    pub(crate) record: Option<PendingRecord>,
}

/// One file-transfer audit record, described but not yet sealed into the chain.
pub(crate) struct PendingRecord {
    id: Uuid,
    direction: Direction,
    path: String,
    sha256: String,
    bytes: u64,
    pub(crate) outcome: Outcome,
    now_ms: i64,
}

impl PendingRecord {
    /// An authorized upload that ended without committing.
    pub(crate) fn upload_failed(id: Uuid, path: String, bytes: u64, reason: String, now_ms: i64) -> Self {
        Self { id, direction: Direction::Input, path, sha256: String::new(), bytes, outcome: Outcome::Failed { error: reason }, now_ms }
    }

    /// Seal it; the returned message carries it to the console.
    pub(crate) fn record(self, chain: &SharedAuditChain, dispatcher: Option<&mut Dispatcher>) -> Option<FtMessage> {
        audit_file_transfer(chain, dispatcher, self.id, self.direction, self.path, self.sha256, self.bytes, self.outcome, self.now_ms).0
    }
}

impl Step {
    fn frames(frames: Vec<FtMessage>) -> Self {
        Self { frames, record: None }
    }

    /// The replies followed by the record, sealed now.
    pub(crate) fn into_frames(self, chain: &SharedAuditChain, dispatcher: Option<&mut Dispatcher>) -> Vec<FtMessage> {
        let mut out = self.frames;
        if let Some(rec) = self.record {
            out.extend(rec.record(chain, dispatcher));
        }
        out
    }
}

/// [`start_upload`] with its record deferred. A step that returns a record refused the upload.
pub(crate) fn start_upload_step(
    offer: Offer,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &mut crate::upload_root::LazyRoot,
    dispatcher: Option<&Dispatcher>,
    now_ms: i64,
) -> Step {
    let id = offer.id;
    let name = file_transfer::safe_basename(&offer.name, id);

    let permitted = dispatcher.is_some_and(|d| d.allows_file_transfer(Direction::Input));
    if !permitted {
        // Record the denial (when there is a chain at all) and refuse before touching the disk.
        return Step {
            frames: vec![ft_ack(id, false, "file upload not permitted for this session".into())],
            record: Some(PendingRecord {
                id,
                direction: Direction::Input,
                path: name,
                sha256: offer.sha256.clone(),
                bytes: offer.size,
                outcome: Outcome::Ok, // ignored: record_file_transfer overrides it with the denial reason
                now_ms,
            }),
        };
    }
    // From here on the transfer is AUTHORIZED, so every refusal is audited as Failed and delivered on
    // this reply (ADR-008: an authorized transfer always ends in a record). The audited path is the
    // destination the bytes were headed for, as `finish_upload` and the reap record it.
    // The checks that need no disk come first, so a refused Offer creates nothing (not even the
    // transfer root, which is opened on the first upload that gets this far).
    let early_dest = name.clone();
    if name.eq_ignore_ascii_case(UPLOAD_STAGING_DIR) {
        return upload_refused_step(id, early_dest, format!("{UPLOAD_STAGING_DIR} is reserved for in-progress uploads"), now_ms);
    }
    if offer.size > 1024 * 1024 * 1024 || uploads.len() >= 4 || uploads.contains_key(&id) {
        return upload_refused_step(id, early_dest, "upload exceeds size/concurrency limit or repeats an active id".into(), now_ms);
    }
    // docs/58 §12: no held root (a SYSTEM host whose configured transfer_dir is not the agent's own
    // folder, or a root that could not be opened safely) means no uploads this session.
    let root = match root.get() {
        Ok(r) => std::sync::Arc::clone(r),
        Err(reason) => return upload_refused_step(id, early_dest, reason.to_string(), now_ms),
    };
    let dest = root.display_of(&name);
    if crate::recording::free_bytes(root.display()).is_none_or(|n| n < 100 * 1024 * 1024 + offer.size) {
        return upload_refused_step(id, dest, "insufficient free disk space for upload".into(), now_ms);
    }
    // In-progress bytes live in the held staging folder, named only by the transfer id and created
    // relative to its handle: no user-supplied text reaches a temp name, and nothing is resolved by
    // name (a planted junction cannot redirect a SYSTEM write).
    let file = match root.create_part(id) {
        Ok(f) => f,
        Err(e) => return upload_refused_step(id, dest, format!("create .part failed: {e}"), now_ms),
    };
    uploads.insert(
        id,
        UploadState {
            file,
            name,
            dest,
            root_path: root.display().to_path_buf(),
            hasher: Sha256::new(),
            received: 0,
            expected_size: offer.size,
            expected_sha: offer.sha256,
            next_seq: 0,
        },
    );
    Step::frames(Vec::new())
}

/// Append one chunk to its in-flight upload, enforcing in-order delivery. No reply on success; an
/// `Error` on an unknown id. A limit breach, seq gap or write failure ABORTS an authorized transfer:
/// the upload is dropped, its `.part` removed, and the abort is audited as Failed (with the bytes
/// that actually reached disk and no digest, as the reap records it) on this reply.
#[cfg(test)]
pub(crate) fn append_chunk(
    chain: &SharedAuditChain,
    chunk: Chunk,
    uploads: &mut HashMap<Uuid, UploadState>,
    dispatcher: Option<&mut Dispatcher>,
    now_ms: i64,
) -> Vec<FtMessage> {
    append_chunk_step(chunk, uploads, now_ms).into_frames(chain, dispatcher)
}

/// [`append_chunk`] with its record deferred. A step that returns a record aborted the upload.
pub(crate) fn append_chunk_step(chunk: Chunk, uploads: &mut HashMap<Uuid, UploadState>, now_ms: i64) -> Step {
    let id = chunk.id;
    let up = match uploads.get_mut(&id) {
        Some(u) => u,
        None => return Step::frames(vec![ft_error(id, "chunk for unknown/again transfer".into())]),
    };
    let mut partial = 0u64; // bytes of THIS chunk that reached disk before a write failed
    let failure = if chunk.data.len() > 48 * 1024
        || chunk.data.len() as u64 > up.expected_size.saturating_sub(up.received)
        || crate::recording::free_bytes(&up.root_path)
            .is_none_or(|n| n < 100 * 1024 * 1024 + chunk.data.len() as u64)
    {
        Some("upload byte or free-space limit exceeded".to_string())
    } else if chunk.seq != up.next_seq {
        Some(format!("out-of-order chunk: got seq {}, expected {}", chunk.seq, up.next_seq))
    } else {
        let (written, res) = write_counting(&mut up.file, &chunk.data);
        match res {
            Ok(()) => None,
            Err(e) => {
                partial = written;
                Some(format!("write failed: {e}"))
            }
        }
    };
    if let Some(reason) = failure {
        let dest = up.dest.clone();
        let received = up.received + partial;
        abort_upload(id, uploads);
        return Step {
            frames: vec![ft_error(id, reason.clone())],
            record: Some(PendingRecord::upload_failed(id, dest, received, reason, now_ms)),
        };
    }
    up.hasher.update(&chunk.data);
    up.received += chunk.data.len() as u64;
    up.next_seq += 1;
    Step::frames(Vec::new())
}

/// Finalize an upload on `Done`: verify size + SHA-256, rename `.part`→final on success. Returns the
/// terminal `Ack` (ok:true committed, or ok:false with the reason — the `.part` is cleaned up either
/// on failure or after a successful rename), followed by the `Audit` record (ADR-008).
///
/// The audit event is recorded HERE rather than at the `Offer` because this is where the REAL
/// figures exist: the byte count actually received and the digest actually computed over what
/// landed on disk — not the numbers the sender claimed. A verification failure is recorded as
/// `Outcome::Failed`, so the trail distinguishes "refused", "broke", and "committed".
#[cfg(test)]
pub(crate) fn finish_upload(
    chain: &SharedAuditChain,
    id: Uuid,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &crate::upload_root::UploadRoot,
    dispatcher: Option<&mut Dispatcher>,
    now_ms: i64,
) -> Vec<FtMessage> {
    finish_upload_step(id, uploads, root, now_ms).into_frames(chain, dispatcher)
}

/// [`finish_upload`] with its record deferred.
pub(crate) fn finish_upload_step(
    id: Uuid,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &crate::upload_root::UploadRoot,
    now_ms: i64,
) -> Step {
    let (ack, detail) = finish_upload_inner(id, uploads, root);
    // `None`: nothing was transferred (a Done for an unknown/never-started transfer). There is no
    // transfer to audit — the Offer that would have started one was already recorded.
    Step {
        frames: vec![ack],
        record: detail.map(|(path, sha256, bytes, outcome)| PendingRecord {
            id,
            direction: Direction::Input,
            path,
            sha256,
            bytes,
            outcome,
            now_ms,
        }),
    }
}

/// The upload-finalization state machine, split out so [`finish_upload`] can audit the real
/// outcome. Returns the terminal `Ack` plus, when a transfer genuinely concluded, the
/// `(path, sha256, bytes, outcome)` to record.
fn finish_upload_inner(
    id: Uuid,
    uploads: &mut HashMap<Uuid, UploadState>,
    root: &crate::upload_root::UploadRoot,
) -> (FtMessage, Option<(String, String, u64, Outcome)>) {
    let up = match uploads.remove(&id) {
        Some(u) => u,
        None => return (ft_ack(id, false, "Done for unknown transfer".into()), None),
    };
    let UploadState { mut file, name, dest, hasher, received, expected_size, expected_sha, .. } = up;
    // Flush to disk before hashing/renaming. The handle stays open: the commit renames THIS file.
    let _ = file.flush();
    let discard = |file: &std::fs::File| {
        let _ = crate::upload_root::UploadRoot::discard(file);
    };

    if received != expected_size {
        discard(&file);
        let msg = format!("size mismatch: got {received}, expected {expected_size}");
        return (
            ft_ack(id, false, msg.clone()),
            Some((dest, expected_sha, received, Outcome::Failed { error: msg })),
        );
    }
    let got_sha = file_transfer::hex_lower(&hasher.finalize());
    if got_sha != expected_sha {
        discard(&file);
        let msg = format!("sha256 mismatch: got {got_sha}, expected {expected_sha}");
        // Record the digest of what ACTUALLY arrived, not the one that was claimed — that is the
        // fact an investigator needs.
        return (
            ft_ack(id, false, msg.clone()),
            Some((dest, got_sha, received, Outcome::Failed { error: msg })),
        );
    }
    // Verified: commit by handle into the root, NEVER replacing an existing file (docs/58 §12): a
    // name already taken lands as `name (2).ext` and so on. The Ack names where it landed.
    match root.commit(&file, &name) {
        Ok((landed, identity)) => {
            root.record_completed(
                id,
                crate::upload_root::Completed { name: landed.clone(), sha256: got_sha.clone(), identity },
            );
            let dest = root.display_of(&landed);
            (ft_ack(id, true, landed), Some((dest, got_sha, received, Outcome::Ok)))
        }
        Err(e) => {
            discard(&file);
            let msg = format!("commit failed: {e}");
            (
                ft_ack(id, false, msg.clone()),
                Some((dest, got_sha, received, Outcome::Failed { error: msg })),
            )
        }
    }
}



/// Write all of `data` to `w`, returning how many bytes `w` accepted even when it fails partway (so a
/// failed upload's audit can state the bytes that actually reached disk, which `write_all` loses).
fn write_counting(w: &mut impl std::io::Write, data: &[u8]) -> (u64, std::io::Result<()>) {
    let mut written = 0usize;
    while written < data.len() {
        match w.write(&data[written..]) {
            Ok(0) => return (written as u64, Err(std::io::ErrorKind::WriteZero.into())),
            Ok(n) => written += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return (written as u64, Err(e)),
        }
    }
    (written as u64, Ok(()))
}

/// The folder under the transfer root that holds in-progress uploads (`<id>.part`). Reserved: an
/// upload may not be NAMED this.
const UPLOAD_STAGING_DIR: &str = ".rmt-staging";

/// Refuse an AUTHORIZED upload before any byte is accepted: an `Error` reply plus its `Failed` audit
/// record. Nothing was received, so no digest is claimed and the byte count is zero.
pub(crate) fn upload_refused(
    chain: &SharedAuditChain,
    dispatcher: Option<&mut Dispatcher>,
    id: Uuid,
    dest: String,
    reason: String,
    now_ms: i64,
) -> Vec<FtMessage> {
    upload_refused_step(id, dest, reason, now_ms).into_frames(chain, dispatcher)
}

/// [`upload_refused`] with its record deferred.
pub(crate) fn upload_refused_step(id: Uuid, dest: String, reason: String, now_ms: i64) -> Step {
    Step {
        frames: vec![ft_error(id, reason.clone())],
        record: Some(PendingRecord::upload_failed(id, dest, 0, reason, now_ms)),
    }
}

/// Drop an aborted upload and remove its partial file.
fn abort_upload(id: Uuid, uploads: &mut HashMap<Uuid, UploadState>) {
    if let Some(up) = uploads.remove(&id) {
        let _ = crate::upload_root::UploadRoot::discard(&up.file);
    }
}

/// Serve a download `Request`: resolve + read a file confined to the transfer root, reply with
/// `Offer` + `Chunk`s + `Done`. Any failure yields a single `Error`.
///
/// Path-safety policy: [`file_transfer::resolve_download_path`] rejects `..`/absolute/UNC paths
/// (deny-by-default, plain names only), then `canonicalize` on both the root and the resolved file
/// confirms the real path is still **inside** the canonical root — blocking symlink/junction escape.
fn serve_download(
    chain: &SharedAuditChain,
    id: Uuid,
    path: &str,
    transfer_dir: &Path,
    dispatcher: Option<&mut Dispatcher>,
    now_ms: i64,
) -> Vec<FtMessage> {
    // ADR-008: authorize BEFORE resolving or reading anything, so an unauthorized peer cannot use
    // the error taxonomy (path-denied vs not-found vs read-failed) as a filesystem oracle.
    let permitted = dispatcher
        .as_ref()
        .is_some_and(|d| d.allows_file_transfer(Direction::Output));
    if !permitted {
        let (audit, _) = audit_file_transfer(
            chain,
            dispatcher,
            id,
            Direction::Output,
            path.to_string(),
            String::new(), // no digest: nothing was read
            0,
            Outcome::Ok, // ignored: record_file_transfer overrides it with the denial reason
            now_ms,
        );
        let mut out = vec![ft_error(id, "file download not permitted for this session".into())];
        out.extend(audit);
        return out;
    }
    // Every post-gate failure below is AUDITED as `Outcome::Failed`, not just answered with an
    // `Error`. Recording only the successful reads would leave the trail perversely quiet about the
    // interesting behaviour: `FileDownload` is granted to every holder of `backstage_shell`
    // (control-plane `BackstageCapsFor`), so an authorized insider could probe the transfer root
    // file-by-file and hammer `..`/symlink escapes, and an investigator reading the chain afterwards
    // would see a session that did no file-transfer work at all. `record_file_transfer`'s outcome
    // parameter exists precisely so the trail separates "refused" from "broke" — this is where the
    // "broke" half comes from.
    let fail = |reason: String, dispatcher: Option<&mut Dispatcher>| -> Vec<FtMessage> {
        let (audit, _) = audit_file_transfer(
            chain,
            dispatcher,
            id,
            Direction::Output,
            path.to_string(), // the REQUESTED path — what was attempted is the fact worth keeping
            String::new(),    // nothing was read, so there is no digest
            0,
            Outcome::Failed { error: reason.clone() },
            now_ms,
        );
        let mut out = vec![ft_error(id, reason)];
        out.extend(audit);
        out
    };

    let resolved = match file_transfer::resolve_download_path(transfer_dir, path) {
        Ok(p) => p,
        Err(e) => return fail(e, dispatcher),
    };
    // Real-path confinement: the resolved file must canonicalize to somewhere under the canonical
    // transfer root (defeats a symlink/junction pointing outside).
    match (std::fs::canonicalize(transfer_dir), std::fs::canonicalize(&resolved)) {
        (Ok(root), Ok(real)) if real.starts_with(&root) => {}
        (Ok(_), Ok(_)) => {
            return fail(format!("path {path:?} escapes the transfer root"), dispatcher)
        }
        _ => return fail(format!("file not found: {path:?}"), dispatcher),
    }
    let data = (|| -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let file = std::fs::File::open(&resolved)?;
        let mut data = Vec::new();
        file.take(64 * 1024 * 1024 + 1).read_to_end(&mut data)?;
        Ok(data)
    })();
    let data = match data {
        Ok(d) if d.len() <= 64 * 1024 * 1024 => d,
        Ok(_) => return fail("download exceeds the 64 MiB buffer limit".into(), dispatcher),
        Err(e) => return fail(format!("read failed: {e}"), dispatcher),
    };
    let name = resolved
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download.bin".to_string());

    let sha256 = file_transfer::sha256_hex(&data);
    let bytes = data.len() as u64;

    let mut out: Vec<FtMessage> = Vec::new();
    out.push(FtMessage::Offer(Offer {
        id,
        name,
        size: bytes,
        sha256: sha256.clone(),
    }));
    for chunk in file_transfer::chunk_file(id, &data) {
        out.push(FtMessage::Chunk(chunk));
    }
    out.push(FtMessage::Done { id });
    // Audit the real file that left the machine: its resolved path, its digest, its size.
    let (audit, _) = audit_file_transfer(
        chain,
        dispatcher,
        id,
        Direction::Output,
        resolved.to_string_lossy().into_owned(),
        sha256,
        bytes,
        Outcome::Ok,
        now_ms,
    );
    out.extend(audit);
    out
}

/// Build an `Ack` reply.
fn ft_ack(id: Uuid, ok: bool, message: String) -> FtMessage {
    FtMessage::Ack { id, ok, message }
}

/// Build an `Error` reply.
fn ft_error(id: Uuid, message: String) -> FtMessage {
    FtMessage::Error { id, message }
}

fn parse_session_arg(args: &[String]) -> Option<u32> {
    let i = args.iter().position(|a| a == "--session")?;
    args.get(i + 1).and_then(|s| s.parse::<u32>().ok())
}

/// The per-session SYSTEM helper the installed service spawns (`--helper --session <id>`).
///
/// Three modes, decided at entry (all under one single-instance guard, stop-file, and max-run
/// safety net):
///
/// 1. **Proof** (`RMT_HELPER_PROOF=1`) — the original capture-verification loop: follow the input
///    desktop and write a capture-proof BMP per iteration. The VM capture-verification flow depends
///    on this exact behavior, so it is preserved unchanged ([`run_proof_loop`]).
/// 2. **Streaming** (a [`HelperConfig`] with a `signaling_url` is present) — the M7 product path:
///    connect to the relay and run [`serve_session_with_ice`] with a [`FollowingCapturer`] (capture
///    the followed desktop) + a [`SendInputSink`] (inject controller input on that same desktop-
///    bound thread). See [`run_helper_stream`].
/// 3. **Idle fallback** (no usable config) — log and drop into the proof loop, so a fresh install
///    with no config never hard-crashes and its capture path is still observable.
///
/// `stop_event` is the service's graceful-stop event (`--stop-event`, see [`crate::helper_stop`]).
/// When the service sets it, this helper stops the same way the stop file stops it, so its docs/49
/// end reports drain before the service would terminate it.
fn helper_worker(session: Option<u32>, stop_event: Option<String>) -> i32 {
    // Absolute pointer mapping requires PerMonitorV2 awareness before any capture/input context.
    let _ = crate::set_process_dpi_awareness();

    // Enable software SAS for services NOW, before any controller can press Ctrl+Alt+Del. The
    // helper runs as SYSTEM here, so it has the rights to set the machine policy; doing it at
    // startup (rather than lazily on the first SAS) means the policy is already in force by the
    // time SendSAS is called, sidestepping any policy-caching in Winlogon. Idempotent — a no-op on
    // every boot after the first. A failure (e.g. a non-elevated dev run) is logged, not fatal:
    // everything except Ctrl+Alt+Del still works.
    match crate::sas::ensure_software_sas_enabled() {
        Ok(true) => log_line(false, "helper: enabled software SAS for services (SoftwareSASGeneration)"),
        Ok(false) => { /* already enabled — stay quiet to keep the log terse */ }
        Err(e) => log_line(false, &format!("helper: could not enable software SAS (Ctrl+Alt+Del may not work): {e}")),
    }

    // Register the service to start under Safe Mode with Networking, so a technician's Safe-Mode
    // reboot (`RebootGuest { safe_mode: true }`) actually reconnects instead of stranding the machine.
    // Idempotent (like the SAS policy above); a failure is logged, not fatal — only Safe-Mode
    // reconnect depends on it. See `crate::reboot`.
    match crate::reboot::ensure_safeboot_service_registered() {
        Ok(true) => log_line(false, "helper: registered service to start in Safe Mode with Networking (SafeBoot\\Network)"),
        Ok(false) => { /* already registered — stay quiet */ }
        Err(e) => log_line(false, &format!("helper: could not register for Safe Mode start (Safe-Mode reboots may not reconnect): {e}")),
    }

    // Observable at startup so a VM run can confirm the boot mode from the agent's OWN log rather than
    // a host-rendered timestamp (a Safe-Mode reboot's whole point is that it reconnected).
    let boot_kind = crate::reboot::current_safe_boot_kind();
    if boot_kind.is_safe() {
        log_line(false, &format!("helper: booted in SAFE MODE ({boot_kind:?})"));
    }

    let proof = std::env::var("RMT_HELPER_PROOF").ok().as_deref() == Some("1");
    if proof {
        let _ = std::fs::create_dir_all(PROOF_DIR);
    }

    // Single-instance guard (all modes): if another helper is already running (e.g. a slow service
    // retarget left the predecessor briefly alive, or a redundant spawn), exit rather than run two
    // capture loops against the same session. Held for the process lifetime.
    let _singleton = match acquire_singleton() {
        Some(h) => h,
        None => {
            log_line(proof, "helper: another instance holds the singleton — exiting");
            return 0;
        }
    };
    log_line(proof, &format!("helper: start (session={session:?}, proof={proof})"));
    // After the singleton: a helper that is about to exit must not hold a watcher thread.
    match stop_event.as_deref() {
        Some(name) if crate::helper_stop::spawn_watcher(name) => {
            log_line(false, "helper: graceful stop armed (service stop event)");
        }
        Some(_) => log_line(false, "helper: service stop event unavailable; a service stop will terminate this helper"),
        None => {}
    }
    // This helper's own session ending (a logoff, or the one a reboot starts with) kills it before
    // the service hears anything, so it reacts itself (crate::helper_stop, VM-measured).
    crate::helper_stop::arm_session_end();

    // Mode selection: the live WebRTC **streaming** session is the product path and takes priority
    // whenever a config with a signaling URL is present. `RMT_HELPER_PROOF` must NOT suppress it —
    // it only enables the capture-proof BMP verification loop (the Phase-0 flow) when there is *no*
    // streaming config. (The SYSTEM service can inherit a stray `RMT_HELPER_PROOF` from its profile
    // and pass it to the helper, so gating streaming on it would silently disable the product.)
    let code = match crate::config::HelperConfig::load() {
        Some(mut cfg) if cfg.signaling_url.as_deref().is_some_and(|s| !s.is_empty()) => {
            run_helper_stream(cfg.signaling_url.clone().unwrap(), &mut cfg)
        }
        _ => {
            // No streaming config: run the capture loop (drops proof BMPs iff RMT_HELPER_PROOF=1,
            // otherwise a quiet, observable capture loop). Never hard-crashes a fresh install.
            log_line(false, "helper: no config with signaling_url → capture/proof loop");
            // If this build is the candidate of an in-flight update, the previous build read this
            // same config moments ago (the attempt precondition), so this is the candidate's fault.
            crate::update_helper::report_candidate_fault("installed config unreadable");
            run_proof_loop()
        }
    };
    // Every mode has stopped (the streaming loop's docs/49 drain included): release a held
    // session-end notification so Windows can finish the logoff.
    crate::helper_stop::mark_drained();
    code
}

/// The original capture-verification loop: follow the input desktop and, per iteration, capture the
/// current desktop with the working tier. Writes a capture-proof BMP per iteration when
/// `RMT_HELPER_PROOF=1` (read again here so the fallback path runs the same loop without BMPs).
///
/// Tier policy (ADR-005): **DXGI** on the `Default` desktop (fast, zero-copy capable), **GDI** on
/// the `Winlogon` secure desktop and anywhere DXGI reports unavailable (RDP returns black).
fn run_proof_loop() -> i32 {
    let proof = std::env::var("RMT_HELPER_PROOF").ok().as_deref() == Some("1");

    let mut follower = service::DesktopFollower::new();
    // Capture tiers, built on demand. A desktop switch invalidates DXGI/WGC (they bind to the
    // desktop that was current when created), so both are dropped on a switch.
    let mut capturer = CaptureLoop::new();

    let start = Instant::now();
    let mut iter: u32 = 0;
    while start.elapsed() < HELPER_MAX_RUN {
        if Path::new(STOP_FILE).exists() {
            log_line(proof, "helper: stop file — exiting");
            break;
        }
        if crate::helper_stop::requested() {
            log_line(proof, "helper: service stop requested — exiting");
            break;
        }
        iter += 1;

        // Follow the active input desktop; a change invalidates any DXGI/WGC capture context.
        match follower.poll() {
            Ok(true) => {
                capturer.invalidate(); // force DXGI/WGC rebuild against the new desktop
                log_line(proof, &format!("helper[{iter}]: switched to desktop={:?}", follower.current()));
            }
            Ok(false) => {}
            Err(e) => {
                log_line(proof, &format!("helper[{iter}]: desktop poll failed: {e}"));
                std::thread::sleep(Duration::from_millis(1000));
                continue;
            }
        }

        let desk = follower.current().unwrap_or("<none>").to_string();
        let secure = desk != "Default"; // Winlogon / Screen-saver → GDI only
        // In an RDP/RDS session DXGI Desktop Duplication returns black; WGC keeps working.
        // SAFETY: GetSystemMetrics(SM_REMOTESESSION) takes a constant index, no pointers.
        let remote = unsafe { GetSystemMetrics(SM_REMOTESESSION) } != 0;

        // The proof loop is primary-only (it captures the login/UAC screen, which renders on the
        // primary); the streaming path is where controller-selected monitors flow.
        let frame = capturer.capture(secure, remote, 0);

        match frame {
            Some((tier, f)) => {
                log_line(
                    proof,
                    &format!("helper[{iter}]: desktop={desk} remote={remote} tier={tier} {}x{} bytes={}", f.width, f.height, f.bytes.len()),
                );
                if proof {
                    let path = format!("{PROOF_DIR}\\{iter:03}_{}_{tier}.bmp", sanitize(&desk));
                    let _ = write_bmp32(&path, &f);
                }
            }
            None => log_line(proof, &format!("helper[{iter}]: desktop={desk} capture FAILED (all tiers)")),
        }

        std::thread::sleep(Duration::from_millis(1000));
    }
    log_line(proof, "helper: done");
    0
}

// ── F2 multi-tech infrastructure ──────────────────────────────────────────────────────────────────

/// A [`ScreenCapturer`] that receives pre-captured frames from a [`crate::shared_capture::SharedCapture`]
/// broadcast, bridging the async broadcast channel to the sync `capture_frame` interface.
///
/// Used in per-session tasks spawned by [`run_multi_session_stream`]: the real DXGI capturer runs
/// once in `SharedCapture` and fans frames to all concurrent sessions via this bridge.
///
/// `topology_snapshot` reads the shared topology written by the SharedCapture capture thread on
/// each keyframe, so the per-session topology guard in `serve_session_with_ice` can detect
/// display hotplug events and terminate the session cleanly.
///
/// Input injection runs on the SharedCapture capture thread (via `ChannelInputSink`) which calls
/// `SetThreadDesktop` through `FollowingCapturer`, so `SendInput` reaches Winlogon/UAC desktops.
///
/// # Selection transition contract
///
/// Each broadcast frame carries a [`crate::shared_capture::TaggedFrame::selection_gen`] stamped
/// by the capture thread the moment it detected a `selected_monitor` change.  `capture_frame`
/// verifies that every received frame's `selection_gen` matches the current
/// [`crate::shared_capture::SharedCapture::selection_generation`] AND that
/// `frame.monitor_id == selected_monitor` (closing the window before the capture thread has
/// looped to detect the change).  Stale frames return `CaptureUnavailable`; the session loop
/// retries until a matching frame arrives.
///
/// `input_ready` is set to `false` whenever a stale frame is detected (belt-and-suspenders:
/// primary invalidation happens in the `SelectMonitor` handler before `capture_frame` is called).
/// It is set back to `true` ONLY by the `FrameDisplayed` ack from the controller — NOT here on
/// matching-frame delivery.  `SessionInputSender::send` checks this flag and rejects input while
/// `false`, preventing click coordinates computed against a stale viewer frame from being applied
/// against a new monitor's geometry.  Old viewers that never send `FrameDisplayed` have input
/// permanently disabled after any `SelectMonitor` (no timeout re-enables it — removed in pass 13).
struct BroadcastCapturer {
    rx: tokio::sync::broadcast::Receiver<std::sync::Arc<crate::shared_capture::TaggedFrame>>,
    /// Frozen snapshot taken at session-accept time.  `monitors()` and the FIRST call to
    /// `topology_snapshot()` draw from this so that `serve_session_with_ice` gets monitor
    /// geometry and the topology-guard baseline from the SAME observation as
    /// `SessionInputSender::session_topology_gen`.
    initial_snapshot: std::sync::Arc<crate::shared_capture::VersionedSnapshot>,
    /// `true` after the first `topology_snapshot()` call.  Subsequent calls return the live
    /// published snapshot so the topology guard can detect runtime changes.
    initial_consumed: std::sync::atomic::AtomicBool,
    /// Live published snapshot for ongoing topology-guard checks (all calls after the first).
    live_published: std::sync::Arc<std::sync::Mutex<std::sync::Arc<crate::shared_capture::VersionedSnapshot>>>,
    rt: tokio::runtime::Handle,
    /// Coherent (monitor, generation) pair.  Read under one lock on every `capture_frame` call
    /// to validate each received frame's (monitor_id, selection_gen) pair as a unit — preventing
    /// the race where separate atomic reads of monitor and generation could see an interleaved
    /// write from a concurrent SelectMonitor handler.
    selection_state: std::sync::Arc<std::sync::Mutex<crate::shared_capture::SelectionState>>,
    /// Last monitor delivered by a successful `capture_frame` call.  Updated for observability.
    last_selection: u32,
    /// This session's frame-rate demand on the shared producer (see
    /// `SharedCapture::register_fps_demand`); `None` for capturers built without one (tests).
    fps_demand: Option<std::sync::Arc<std::sync::atomic::AtomicU32>>,
    // input_ready removed: pinned-display mode makes input unconditionally ready; BroadcastCapturer
    // no longer clears it on stale-frame rejection.  Stale frames are discarded (Err return) but
    // do not affect session input state.
}

impl BroadcastCapturer {
    fn new(
        rx: tokio::sync::broadcast::Receiver<std::sync::Arc<crate::shared_capture::TaggedFrame>>,
        initial_snapshot: std::sync::Arc<crate::shared_capture::VersionedSnapshot>,
        rt: tokio::runtime::Handle,
        live_published: std::sync::Arc<
            std::sync::Mutex<std::sync::Arc<crate::shared_capture::VersionedSnapshot>>,
        >,
        selection_state: std::sync::Arc<std::sync::Mutex<crate::shared_capture::SelectionState>>,
    ) -> Self {
        let last_selection = selection_state.lock().unwrap().monitor;
        Self {
            rx,
            initial_snapshot,
            initial_consumed: std::sync::atomic::AtomicBool::new(false),
            live_published,
            rt,
            selection_state,
            last_selection,
            fps_demand: None,
        }
    }

    /// Attach this session's demand slot, so the shared producer paces to it.
    fn with_fps_demand(mut self, slot: std::sync::Arc<std::sync::atomic::AtomicU32>) -> Self {
        self.fps_demand = Some(slot);
        self
    }
}

impl ScreenCapturer for BroadcastCapturer {
    fn monitors(&self) -> PlatformResult<Vec<MonitorInfo>> {
        // Return monitors from the frozen initial snapshot so the geometry advertised to
        // serve_session_with_ice is always coherent with initial_snapshot.generation (which
        // equals SessionInputSender::session_topology_gen).  Falls back to an empty list when
        // the snapshot has no topology (capturer does not implement the optional seam).
        match &self.initial_snapshot.topology {
            Some(t) => Ok(t.monitors.clone()),
            None => Ok(Vec::new()),
        }
    }

    fn capture_frame(&mut self, _monitor_id: u32) -> PlatformResult<CapturedFrame> {
        // block_on is safe: capture_frame is called from std::thread::spawn (a native thread),
        // never from within a Tokio worker context.
        //
        // A session that pulls slower than the shared capture produces (a low fps setting against
        // 30 fps canvas capture) is more than FRAME_BROADCAST_CAP frames behind at every pull.
        // Falling behind is not a capture failure: skip ahead (a lag only moves the receiver to the
        // oldest retained frame) and then take the NEWEST frame already buffered. Treating the lag
        // as an error backed off a whole interval and lagged again, so a 5 fps session never got a
        // new frame; taking the oldest would show a picture several frames old.
        use tokio::sync::broadcast::error::{RecvError, TryRecvError};
        let rx = &mut self.rx;
        let result = self.rt.block_on(async {
            tokio::time::timeout(Duration::from_millis(150), async {
                loop {
                    match rx.recv().await {
                        Err(RecvError::Lagged(_)) => continue,
                        other => return other,
                    }
                }
            })
            .await
        });
        let result = match result {
            Ok(Ok(mut tagged)) => {
                loop {
                    match self.rx.try_recv() {
                        Ok(newer) => tagged = newer,
                        Err(TryRecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
                Ok(Ok(tagged))
            }
            other => other,
        };
        match result {
            Ok(Ok(tagged)) => {
                // Coherent selection validation: read (monitor, generation) under one lock so we
                // never compare a frame's gen against a new-epoch monitor or vice versa.
                //
                // The frame is accepted only when BOTH fields match the current locked pair:
                // - `selection_gen`: closes the ABA race (every pin produces a distinct epoch).
                // - `monitor_id`: belt-and-suspenders for the brief window between write_selection
                //   and the capture thread reading the new selection on its next iteration.
                //
                // On mismatch the frame is discarded (Err return).  input_ready is NOT touched
                // here — pinned-display mode keeps it unconditionally true.
                let (current_sel, current_gen) = {
                    let s = self.selection_state.lock().unwrap();
                    (s.monitor, s.generation)
                };
                if tagged.selection_gen != current_gen || tagged.frame.monitor_id != current_sel {
                    return Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                        "stale frame from prior monitor selection rejected".to_string(),
                    ));
                }
                self.last_selection = current_sel;
                Ok(tagged.frame.clone())
            }
            Ok(Err(RecvError::Lagged(_))) => Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                "broadcast lagged".to_string(),
            )),
            Ok(Err(RecvError::Closed)) => {
                Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                    "shared capture stopped".to_string(),
                ))
            }
            Err(_) => Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                "frame timeout".to_string(),
            )),
        }
    }

    fn set_frame_rate_hint(&mut self, fps: u32) {
        if let Some(slot) = &self.fps_demand {
            slot.store(fps, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn capture_composite(&mut self) -> PlatformResult<CapturedFrame> {
        // The shared producer already captured the whole virtual desktop. The trait's
        // default would fetch and stitch this same full frame once per monitor.
        let frame = self.capture_frame(COMPOSITE_MONITOR_ID)?;
        let layout = self.initial_snapshot.topology.as_ref()
            .and_then(|t| crate::monitor_canvas::layout(&t.monitors));
        if !layout.is_some_and(|c| frame.monitor_id == COMPOSITE_MONITOR_ID &&
            frame.width == c.width && frame.height == c.height) {
            return Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                "composite frame geometry does not match the advertised canvas".into()));
        }
        Ok(frame)
    }

    fn topology_snapshot(&self) -> Option<rmt_agent_core::TopologySnapshot> {
        // First call: return the frozen initial snapshot topology so that serve_session_with_ice
        // gets a baseline that matches initial_snapshot.generation == session_topology_gen.
        // Subsequent calls return the live published topology so the topology guard can detect
        // runtime changes and terminate the session when the display configuration changes.
        if !self.initial_consumed.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.initial_snapshot.topology.clone()
        } else {
            self.live_published.lock().ok().and_then(|g| g.topology.clone())
        }
    }
}

/// Cloneable per-session config shared across all sessions in [`run_multi_session_stream`].
///
/// Contains everything needed to build a [`SessionOptions`] for a new brokered session: all fields
/// that are either `Copy`, `Clone`, or behind `Arc`. Fields that MUST be fresh per session (sink,
/// clipboard worker, guest window) are created inside [`run_multi_session_stream`]'s spawn closure.
struct MultiSessionOpts {
    /// Retain acknowledgements and retries across reconnects for the helper lifetime.
    guest_end_reports: Option<rmt_agent_core::guest_end::GuestEndReports>,
    /// Every live session task of the helper, across signaling reconnects: a session outlives the
    /// connection that brokered it, and a service stop must join it before draining its report.
    session_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    device: DeviceId,
    ice: Vec<IceServer>,
    identity: Option<AgentIdentity>,
    transfer_dir: PathBuf,
    clipboard_mode: ClipboardMode,
    backstage_auth: BackstageAuth,
    require_session_policy: bool,
    quality_policy: QualityPolicy,
    max_session: Duration,
    recording_dir: Option<PathBuf>,
    spent_grants: std::sync::Arc<SpentGrants>,
    spent_elevations: std::sync::Arc<SpentGrants>,
    uninstall_requested: std::sync::Arc<AtomicBool>,
    /// docs/65: the directive hub, present only when a directive key is pinned (it is what makes this agent advertise
    /// `directive_v1` and accept relayed directives). `None` ⇒ every directive is ignored and the feature is not advertised.
    directive_hub: Option<std::sync::Arc<crate::directive_hub::DirectiveHub>>,
    /// docs/64: the help-request hub (the tray's "Request help..."). Installed helper only; `None` in the lab harness.
    help_hub: Option<std::sync::Arc<crate::help_request::HelpHub>>,
    guest_banner_host: String,
    /// When `true`, all machine-action handlers (reboot, launch, command, lock, logoff) are mocked
    /// so no real OS side-effects occur. Set only by the test-harness path.
    #[cfg(feature = "test-harness")]
    mock_actions: bool,
    /// When `true` (requires feature = "secure-test"), grant verification runs real Ed25519 checks
    /// but Dispatcher::with_chain is never called. Propagated to SessionOptions per session.
    #[cfg(feature = "secure-test")]
    secure_test_harness: bool,
}

/// How often the helper re-stamps its update registration heartbeat while one signaling
/// connection lasts and is proven live. update_worker's freshness window is 8 minutes.
const UPDATE_HEARTBEAT_REFRESH: Duration = Duration::from_secs(3 * 60);

/// Multi-session streaming loop for the F2 many-tech feature.
///
/// Spawns one [`crate::shared_capture::SharedCapture`] for the helper lifetime, registers with the
/// signaling server, then loops accepting brokered sessions from a
/// [`crate::signaling_mux::SignalingMux`]. Each accepted session spawns a Tokio task that calls
/// [`serve_session_with_ice`] with a [`BroadcastCapturer`] (for video) and a
/// [`crate::shared_capture::SessionInputSender`] (for input) backed by the shared
/// [`crate::shared_capture::InputCoordinator`].
///
/// Returns `Ok(())` when the signaling connection drops or `stop` is set. Returns `Err` only on
/// registration failure. The outer reconnect loop in [`run_helper_stream`] handles retry.
async fn run_multi_session_stream(
    signaling_url: &str,
    shared: std::sync::Arc<crate::shared_capture::SharedCapture>,
    stop: std::sync::Arc<AtomicBool>,
    opts: std::sync::Arc<MultiSessionOpts>,
) -> Result<(), String> {
    let mut role = agent_role(opts.device, opts.identity.clone(), opts.require_session_policy);
    // Only the mux registration path is backed by SignalingMux + SharedCapture + BroadcastCapturer.
    // Set multi_session_capable here (not in agent_role) so that single-session callers —
    // the CLI `stream` subcommand and the attended path — do not falsely advertise it.
    if let Role::Agent { ref mut multi_session_capable, .. } = role {
        *multi_session_capable = Some(true);
    }
    // docs/65 D-C3: `directive_v1` is advertised ONLY when a directive key is pinned (a hub exists). An agent without a pin
    // refuses every directive, so it must not ask the server to relay any.
    if opts.directive_hub.is_some() {
        if let Role::Agent { ref mut features, .. } = role {
            features.push(rmt_protocol::directive::DIRECTIVE_FEATURE.to_string());
        }
    }
    // Audit #9: report the enforcement posture so the control plane can flag a machine whose
    // signed policy / lease / grants cannot be verified (no pinned issuer key).
    if let Role::Agent { ref mut features, .. } = role {
        features.extend(posture_features(
            matches!(opts.backstage_auth, BackstageAuth::SignedBy(_)),
            opts.require_session_policy,
        ));
    }
    // Updater evidence is written only on the installed path with a real enrolled identity
    // (recording_dir + identity); dev/LAN, test harness and CLI paths are excluded.
    let installed = opts.recording_dir.is_some() && opts.identity.is_some();
    let (sig, sig_rx, features) = match WebRtcTransport::register_for_mux_with_features(signaling_url, &role).await {
        Ok(registered) => registered,
        Err(e) => {
            // An explicit refusal of THIS binary is affirmative candidate evidence (design v7
            // E-cand); report_candidate_fault ignores it unless this build is the in-flight target.
            if installed && e.starts_with("register_for_mux: rejected:") {
                crate::update_helper::report_candidate_fault("signaling rejected registration");
            }
            return Err(e);
        }
    };
    let mut mux = crate::signaling_mux::SignalingMux::new_with_help(
        sig, sig_rx, Some(opts.device), opts.guest_end_reports.clone(), &features, opts.directive_hub.clone(),
        opts.help_hub.clone(),
    );

    // Registration heartbeat + attempt ack (design v5 R3, v9 R2). The ack carries the
    // compile-time AGENT_VERSION, never a value from the request.
    // Blocking file I/O off the async runtime.
    let mut registration = if installed {
        // The registration just completed on this connection; its evidence expires on the
        // connection's own absolute clock.
        let proof_expiry = mux.proof_expiry();
        tokio::task::spawn_blocking(move || crate::update_helper::on_registered(proof_expiry)).await.unwrap_or_else(|e| {
            tracing::warn!(error = %e, "update: registration heartbeat task failed");
            None
        })
    } else {
        None
    };
    // 1.3.1: re-stamp that heartbeat while this connection is PROVEN live, or the updater's
    // freshness precondition fails on a long-lived connection (1.3.0 defect). Proof is the mux's
    // pong age: the signaling client sends numbered probes every 20 s and only the server's echo,
    // written from its read loop for this connection, counts; with no echo for 60 s the client's
    // watchdog retires the connection, accept() returns None, and the next pass registers again
    // with a NEW id. A registration that could not publish at registration time publishes on the
    // first proven-live tick. The first tick is a full period away. mux.accept() is an mpsc recv,
    // which is cancel-safe across ticks.
    let mut heartbeat_refresh = tokio::time::interval_at(
        tokio::time::Instant::now() + UPDATE_HEARTBEAT_REFRESH,
        UPDATE_HEARTBEAT_REFRESH,
    );
    heartbeat_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let rt = tokio::runtime::Handle::current();
    let signaling_url_owned = signaling_url.to_owned();

    // docs/63 R2: tell the service's recording uploader while ANY session task of this helper is alive
    // (`C:\rmt-agent\session-live`, refreshed every 30 s, removed when the last one ends). Installed path only:
    // dev/LAN, test and CLI runs do not own the agent root.
    let _session_live_stamp = installed.then(|| {
        let tasks = std::sync::Arc::clone(&opts);
        crate::session_live::spawn_stamper(
            move || tasks.session_tasks.lock().map(|g| g.iter().any(|t| !t.is_finished())).unwrap_or(true),
            stop.clone(),
        )
    });

    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        // Two-branch select: accept the next session OR exit when the stop flag is set.
        // The stop-flag branch polls every 200 ms so a service shutdown during a session
        // drought (no incoming session) does not require waiting for the mux connection to
        // close before the loop exits. The poll interval is intentionally modest — this is a
        // shutdown path, not a hot loop.
        let maybe_bs = tokio::select! {
            bs = mux.accept() => bs,
            _ = heartbeat_refresh.tick(), if registration.is_some() => {
                // Absolute expiry of the connection's evidence; carried into the blocking task and
                // re-checked there under the heartbeat lock, so no pause can stretch it.
                let proof_expiry = mux.proof_expiry();
                if std::time::Instant::now() > proof_expiry {
                    tracing::info!(age_ms = mux.pong_age().as_millis() as u64, "update: signaling probe unanswered; heartbeat not refreshed");
                } else if let Some(reg) = registration.take() {
                    let kept = reg.clone();
                    // Blocking file I/O (a lock, a small read, an atomic write) off the async worker.
                    registration = Some(
                        tokio::task::spawn_blocking(move || crate::update_helper::refresh_heartbeat(reg, proof_expiry))
                            .await
                            .unwrap_or_else(|e| {
                                tracing::warn!(error = %e, "update: heartbeat refresh task failed");
                                kept
                            }),
                    );
                }
                continue;
            }
            _ = async {
                loop {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    if stop.load(Ordering::Relaxed) { return; }
                    if opts.uninstall_requested.load(Ordering::SeqCst) { return; }
                }
            } => None,
        };
        let Some(bs) = maybe_bs else { break };

        let shared_c = std::sync::Arc::clone(&shared);
        let stop_c = stop.clone();
        let opts_c = std::sync::Arc::clone(&opts);
        let rt_c = rt.clone();
        let url_c = signaling_url_owned.clone();
        // One deregister handle per session. Calling it after the session ends removes the stale
        // sender from the dispatch task's routing table — without it, entries accumulate for the
        // lifetime of the mux connection (one entry per completed session).
        let deregister = mux.deregister_handle();

        // Joined on a service stop so each end report is queued before the drain (docs/49 v4
        // shutdown ordering). Finished handles are pruned per accept.
        let mut session_tasks = opts.session_tasks.lock().unwrap();
        session_tasks.retain(|t| !t.is_finished());
        session_tasks.push(tokio::spawn(async move {
            let session_id = bs.session.clone();

            // Idle barrier: hold a FILE_SHARE_READ-only handle on the update lock file for the
            // entire session lifetime.  The updater worker's exclusive open (share_mode=0) fails
            // with OS error 32 while this guard is held.  Ok(None) for non-installed paths.
            // Fail-closed: an Err here means the lock file is absent or suspect; we deregister
            // from the mux and return before attempting transport startup.
            let installed = opts_c.recording_dir.is_some();
            let update_guard = match crate::update_guard::SessionFileGuard::open_for_installed_session(
                installed,
            ) {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        ?session_id,
                        "update_guard: session barrier unavailable; refusing session (fail-closed)"
                    );
                    deregister.deregister(&session_id);
                    report_session_end(opts_c.guest_end_reports.as_ref(), bs.control_plane_session, rmt_protocol::signaling::SessionEndReason::Other);
                    return;
                }
            };
            // Idle release (update_guard.rs, Ed 2026-10-21): after 30 minutes without technician
            // activity this session stops blocking updates, and re-arms on the next activity. The
            // poller is aborted when this task ends by ANY path (AbortOnDrop), so it can never keep
            // the guard alive past the session; that would be the leak 638a311 fixed, again.
            let activity = crate::update_guard::SessionActivity::new();
            activity.touch(); // the session starting is activity
            let barrier = std::sync::Arc::new(crate::update_guard::IdleBarrier::new(
                update_guard,
                Box::new(move || crate::update_guard::SessionFileGuard::open_for_installed_session(installed)),
                std::sync::Arc::clone(&activity),
                crate::update_guard::SESSION_IDLE_RELEASE,
            ));
            // Activity re-arms a stood-down barrier at once, before the activity is processed, rather than
            // at the next poll (Codex 1.3.7 release review: an update could take the lock in that window).
            {
                let session_id = session_id.clone();
                barrier.link(move |r| match r {
                    crate::update_guard::IdlePoll::Rearmed => tracing::info!(?session_id, "update: session active again; it blocks agent updates again"),
                    crate::update_guard::IdlePoll::RearmFailed(e) => tracing::warn!(?session_id, error = %e, "update: could not re-arm the session's update barrier (an update may be running); retrying"),
                    _ => {}
                });
            }
            let _idle_poller = AbortOnDrop(tokio::spawn({
                let barrier = std::sync::Arc::clone(&barrier);
                let session_id = session_id.clone();
                async move {
                    let mut tick = tokio::time::interval(crate::update_guard::SESSION_IDLE_POLL);
                    loop {
                        tick.tick().await;
                        match barrier.poll() {
                            crate::update_guard::IdlePoll::Released => tracing::info!(?session_id, "update: session idle 30 min; it no longer blocks agent updates"),
                            crate::update_guard::IdlePoll::Rearmed => tracing::info!(?session_id, "update: session active again; it blocks agent updates again"),
                            crate::update_guard::IdlePoll::RearmFailed(e) => tracing::warn!(?session_id, error = %e, "update: could not re-arm the session's update barrier (an update may be running); retrying"),
                            crate::update_guard::IdlePoll::Unchanged => {}
                        }
                    }
                }
            }));

            // Server-issued ICE first, then static config ICE (mirrors connect_inner ordering).
            let ice: Vec<IceServer> = bs
                .issued_ice
                .iter()
                .map(|s: &rmt_protocol::signaling::IceServerSpec| IceServer {
                    urls: s.urls.clone(),
                    username: s.username.clone(),
                    credential: s.credential.clone(),
                })
                .chain(opts_c.ice.iter().cloned())
                .collect();

            let brokered_cp_session = bs.control_plane_session;
            // A negotiation can take up to BROKERED_OPEN_TIMEOUT (60 s), but a helper stop joins its
            // sessions for only ~10 s and then the runtime is torn down, cancelling the negotiation
            // before anything reported it: the session's control-plane row stayed open (Codex 1.3.7
            // release review). So the negotiation yields to a stop, and the session reports service_stop
            // itself, inside the join budget. Abandoning the half-made connection is fine: the process
            // is exiting.
            let negotiation = WebRtcTransport::from_brokered(
                bs.session,
                bs.sig,
                bs.rx,
                bs.control_plane_session,
                bs.technician_id,
                bs.access,
                ice.clone(),
            );
            let transport = match tokio::select! {
                r = negotiation => Some(r),
                () = wait_for_helper_stop() => None,
            } {
                None => {
                    tracing::info!(?session_id, "multi-session: helper stopping during negotiation; reporting service_stop");
                    deregister.deregister(&session_id);
                    report_session_end(opts_c.guest_end_reports.as_ref(), brokered_cp_session, rmt_protocol::signaling::SessionEndReason::ServiceStop);
                    return;
                }
                Some(Ok(t)) => t,
                Some(Err(e)) => {
                    tracing::warn!(
                        error = %e,
                        ?session_id,
                        "multi-session: from_brokered failed; dropping this session"
                    );
                    // Like the barrier-refusal path above: take the session out of the mux's
                    // routing table, or its dead sender stays there for the connection's lifetime.
                    deregister.deregister(&session_id);
                    report_session_end(opts_c.guest_end_reports.as_ref(), brokered_cp_session, rmt_protocol::signaling::SessionEndReason::Other);
                    return;
                }
            };

            // Grab the published snapshot ONCE so both the input sender and the capturer share
            // the SAME (generation, topology) pair.  This closes the race where topology changes
            // between new_session_input() and BroadcastCapturer construction would give the sender
            // gen=N but the capturer initial_topology from gen=N+1, silently discarding all input.
            let snap = shared_c.session_snapshot();
            let mut input_sender = shared_c.new_session_input_from_snapshot(&snap);

            // Per-session input_ready: starts true and remains true in pinned-display mode.
            // SelectMonitor does NOT clear it; no FrameDisplayed ack cycle is used.
            // The session_slots Weak ref is retained so live_session_count stays accurate;
            // when this task exits the Arc drops and the Weak expires automatically.
            let input_ready = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            shared_c.register_session_input_ready(std::sync::Arc::downgrade(&input_ready));
            input_sender.input_ready = std::sync::Arc::clone(&input_ready);

            let broadcast_capturer = BroadcastCapturer::new(
                shared_c.subscribe(),
                std::sync::Arc::clone(&snap),
                rt_c,
                std::sync::Arc::clone(&shared_c.published_snapshot),
                std::sync::Arc::clone(&shared_c.selection_state),
            )
            .with_fps_demand(shared_c.register_fps_demand(DEFAULT_STREAM_FPS));

            let clipboard: Option<Box<dyn Clipboard>> = opts_c
                .clipboard_mode
                .any()
                .then(|| Box::new(crate::clipboard::WinClipboard::new()) as Box<dyn Clipboard>);
            // No guest window in the insecure-mechanics test profile: real Win32 UI surfaces
            // are OS side-effects. Production (run_helper_stream) always passes Some.
            #[cfg(feature = "test-harness")]
            let guest_ui: Option<Box<dyn GuestUi>> = if opts_c.mock_actions {
                None
            } else {
                Some(Box::new(crate::guest_window::WindowGuestUi::new(SessionInfo {
                    control_plane_host: opts_c.guest_banner_host.clone(),
                    reason: String::new(),
                })))
            };
            #[cfg(not(feature = "test-harness"))]
            let guest_ui: Option<Box<dyn GuestUi>> = Some(Box::new(
                crate::guest_window::WindowGuestUi::new(SessionInfo {
                    control_plane_host: opts_c.guest_banner_host.clone(),
                    reason: String::new(),
                }),
            ));

            // Route injection through the capture thread's desktop-bound channel so SendInput reaches
            // Winlogon/UAC (requires SetThreadDesktop, which FollowingCapturer calls on that thread).
            // docs/61: this session's arbiter handle, read before the sender is consumed below.
            let arb_handle = input_sender.handle();
            let session_sink = input_sender.into_channel_sink();
            let session_opts = SessionOptions {
                sink: session_sink,
                transfer_dir: opts_c.transfer_dir.clone(),
                clipboard,
                clipboard_mode: opts_c.clipboard_mode,
                backstage_auth: opts_c.backstage_auth.clone(),
                require_session_policy: opts_c.require_session_policy,
                session_lease: SessionLeaseMode::FromSessionBinding,
                session_lease_grace: DEFAULT_LEASE_GRACE,
                identity: opts_c.identity.clone(),
                quality_policy: opts_c.quality_policy,
                max_session: opts_c.max_session,
                recording_dir: opts_c.recording_dir.clone(),
                recording_via_service: false,
                guest_ui,
                spent_grants: opts_c.spent_grants.clone(),
                spent_elevations: opts_c.spent_elevations.clone(),
                // The helper-lifetime guest-end report set: a guest End in this session is queued
                // here and delivered by the mux, across reconnects, until signaling acknowledges it.
                guest_end_reports: opts_c.guest_end_reports.clone(),
                // test-harness: mock_actions covers ALL OS-side-effect sinks, including keyboard
                // input — ensures RecordingOsSink is the backend in every session spawned here.
                // Production (run_helper_stream) never sets this field; default is false.
                #[cfg(feature = "test-harness")]
                mock_input: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_input: false,
                admin_rights: None,
                force_observer: false,
                // The production helper path: always the real loopback, never a test tone.
                synthetic_tone: false,
                #[cfg(feature = "test-harness")]
                mock_reboot: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_reboot: false,
                #[cfg(feature = "test-harness")]
                mock_launch: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_launch: false,
                #[cfg(feature = "test-harness")]
                mock_command: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_command: false,
                host_runs_as_interactive_user: false,
                #[cfg(feature = "test-harness")]
                mock_lock: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_lock: false,
                #[cfg(feature = "test-harness")]
                mock_logoff: opts_c.mock_actions,
                #[cfg(not(feature = "test-harness"))]
                mock_logoff: false,
                // Secure-test: when --grant-issuer is present in multi-stream and the secure-test
                // feature is compiled in, set secure_test_harness=true so serve_session routes
                // InstallGrant through verify_grant_inert (real verification, no Dispatcher).
                #[cfg(feature = "secure-test")]
                secure_test_harness: opts_c.secure_test_harness,
                uninstall_requested: opts_c.uninstall_requested.clone(),
                pre_built_transport: Some(transport),
                // All sessions in this helper share one selected-monitor Arc so the single remap
                // boundary in inject_ev and the SharedCapture capture selection stay coherent.
                shared_selected_monitor: Some(std::sync::Arc::clone(&shared_c.selected_monitor)),
                // Session-slot registry: used for live_session_count.
                // Coherent (monitor, generation) pair: write_selection under one lock closes both
                // the ABA race and the incoherent-pair read race.
                shared_selection_state: Some(std::sync::Arc::clone(&shared_c.selection_state)),
                shared_canvas: if shared_c.read_selection().0 == COMPOSITE_MONITOR_ID {
                    snap.topology.as_ref().and_then(|t| crate::monitor_canvas::layout(&t.monitors))
                } else { None },
                activity: Some(std::sync::Arc::clone(&activity)),
                // docs/61: every session here shares one SharedCapture, so they can hand input
                // control among themselves; the directory key is the signaling id the viewers see.
                input_handoff: Some(InputHandoffWiring {
                    shared: std::sync::Arc::clone(&shared_c),
                    handle: arb_handle,
                    signaling_id: session_id.0.to_string(),
                }),
            };

            if let Err(e) = serve_session_with_ice(
                &url_c,
                opts_c.device,
                broadcast_capturer,
                DEFAULT_STREAM_FPS,
                stop_c,
                ice,
                session_opts,
            )
            .await
            {
                tracing::warn!(
                    error = %e,
                    ?session_id,
                    "multi-session: session ended with error"
                );
            } else {
                tracing::info!(?session_id, "multi-session: session ended normally");
            }

            // Remove the session from the mux dispatch routing table. Without this, the dispatch
            // task accumulates a stale dead-sender entry for every completed session.
            deregister.deregister(&session_id);
            // session_sink (inside session_opts) drops at function exit, releasing held keys via
            // ChannelInputSink → SessionInputSender::release_held → InputCoordinator::release_session.
            // [SESSION:TEARDOWN:DONE session=…] is now emitted from release_session in
            // shared_capture.rs after the coordinator lock confirms all state is removed — not here
            // (mux deregister happens before the capture thread processes the Release sentinel).
        }));
        drop(session_tasks);
    }

    tracing::info!("multi-session: mux loop exited (signaling closed or stop set)");
    // docs/49 shutdown drain. A signaling drop leaves live sessions running (they outlive the
    // connection), so this applies to a service stop only: let every session tear down and queue
    // its service_stop report, then give delivery up to SHUTDOWN_REPORT_DRAIN on this connection.
    if stop.load(Ordering::Relaxed) || opts.uninstall_requested.load(Ordering::SeqCst) {
        // Sessions brokered but never accepted (still in the mux's queue) were vouched too: report
        // them before the drain, or dropping the mux discards them unreported (Codex 1.3.7 v3).
        for bs in mux.close_accept() {
            tracing::info!(session = ?bs.session, "multi-session: brokered session never started (helper stopping); reporting service_stop");
            report_session_end(opts.guest_end_reports.as_ref(), bs.control_plane_session, rmt_protocol::signaling::SessionEndReason::ServiceStop);
        }
        if let Some(reports) = opts.guest_end_reports.as_ref() {
            let session_tasks = std::mem::take(&mut *opts.session_tasks.lock().unwrap());
            drain_session_end_reports(reports, &mut mux, session_tasks).await;
        }
    }
    Ok(())
}

/// Bound on session teardown during a service stop; sessions observe `stop` within ~500 ms.
/// `crate::service::GRACEFUL_STOP_WAIT` is sized from this and the next constant.
pub(crate) const SHUTDOWN_SESSION_JOIN: Duration = Duration::from_secs(10);
/// docs/49 §4: the report worker's drain after the last report is queued.
pub(crate) const SHUTDOWN_REPORT_DRAIN: Duration = Duration::from_secs(5);

/// Join the stopping sessions (each queues its report after its own teardown), then wait for the
/// reports this connection can deliver to be acknowledged. Losses are logged with counts: there
/// is no persistence (docs/49 §4), so an undelivered report leaves its row to the operator.
async fn drain_session_end_reports(
    reports: &rmt_agent_core::guest_end::GuestEndReports,
    mux: &mut crate::signaling_mux::SignalingMux,
    session_tasks: Vec<tokio::task::JoinHandle<()>>,
) {
    let live = session_tasks.iter().filter(|t| !t.is_finished()).count();
    let join_all = async {
        for task in session_tasks {
            let _ = task.await;
        }
    };
    if tokio::time::timeout(SHUTDOWN_SESSION_JOIN, join_all).await.is_err() {
        tracing::warn!(live, "shutdown: sessions did not finish tearing down; their reports may be missing");
    }
    reports.notify.notify_one();
    let capable = mux.session_ended_capable();
    let deadline = tokio::time::Instant::now() + SHUTDOWN_REPORT_DRAIN;
    loop {
        let sendable = reports.pending.lock().unwrap().sendable_len(capable);
        if sendable == 0 {
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let pending = reports.pending.lock().unwrap().len();
    if pending > 0 {
        tracing::warn!(pending, session_ended_capable = capable,
            "shutdown: session end reports undelivered at exit (rows stay open)");
    } else {
        tracing::info!("shutdown: every session end report was acknowledged");
    }
}

/// Streaming mode (M7): connect to the relay and run [`serve_session_with_ice`] with a
/// [`FollowingCapturer`] and a real [`SendInputSink`], so the installed SYSTEM helper streams the
/// live (input-desktop-following) screen AND injects controller input on the same desktop-bound
/// thread — reaching Winlogon/UAC.
///
/// `device_id` comes from enrollment (M3): a control-plane-managed agent redeems its token here on
/// first run and uses the **server-minted** id thereafter; an unmanaged (dev/LAN) agent still
/// generates one locally. STUN servers from the config feed WAN NAT traversal (empty ⇒
/// LAN/loopback). A `stop` file (same path the proof loop watches) or [`DEFAULT_STREAM_MAX_RUN`] ends the
/// run.
fn run_helper_stream(signaling_url: String, cfg: &mut crate::config::HelperConfig) -> i32 {
    // First-run enrollment (M3). This covers image-based deployments where the installer could not
    // reach the control plane. Attempted ONCE per start — never in a retry loop, since each attempt
    // consumes a use of the enrollment token. On failure we log and fall through: an unenrolled
    // managed agent has no device id, so it drops to the capture-proof loop below.
    //
    // Runs before the tokio runtime is built: `enroll_once` performs blocking HTTP.
    if crate::enroll::needs_enrollment(cfg) {
        match crate::enroll::enroll_once(cfg, crate::config::CONFIG_FILE, None) {
            Ok(id) => log_line(
                false,
                &format!("helper: enrolled as device {} in tenant {}", id.device_id, id.tenant_id),
            ),
            Err(e) => log_line(false, &format!("helper: enrollment failed: {e}")),
        }
    }

    // Stable per-machine identity. An agent whose identity belongs to a control plane NEVER
    // invents one.
    //
    // The reason is captured BEFORE the call, because `device_id_or_dev_fallback` returns a bare
    // `None`, and naming the signal is what turns an hour of confusion into a log grep. the operator's box
    // logged `agent identity loaded` while signaling rejected it as `device identity unknown`, and
    // nothing on either side said the two ids disagreed. A fail-closed path must say WHICH failure.
    let identity_evidence = cfg.managed_identity_evidence();
    let device_str = match cfg.device_id_or_dev_fallback() {
        Some(id) => id,
        None => {
            log_line(
                false,
                &format!(
                    "helper: no device_id, and this agent must not invent one ({}) - streaming \
                     aborted, capture loop instead. If this machine is ALREADY enrolled, \
                     restore its real device_id in {}: that needs no enrollment token and does \
                     not orphan the server-side row. Otherwise run `agent_host.exe enroll \
                     --control-plane-url <url> --token <tok>`.",
                    identity_evidence
                        .as_deref()
                        .unwrap_or("control-plane managed but not enrolled"),
                    crate::config::CONFIG_FILE,
                ),
            );
            return run_proof_loop();
        }
    };
    let device = match device_str.parse::<uuid::Uuid>() {
        Ok(u) => DeviceId(u),
        Err(e) => {
            log_line(false, &format!("helper: config device_id {device_str:?} is not a UUID ({e}); streaming aborted → capture loop"));
            return run_proof_loop();
        }
    };

    // M3 registration identity. Present only when the enrolled private key is on disk; a managed
    // agent whose key is missing/corrupt keeps streaming (so a dev-mode signaling server still
    // works) but is loudly unauthenticated, because silently dropping to a placeholder pubkey
    // against an enforcing server would look like a network fault instead of a provisioning one.
    let identity_path = cfg.identity_path_or_default();
    let agent_identity: Option<AgentIdentity> = match crate::enroll::read_identity(&identity_path) {
        Ok(Some(id)) => {
            let pubkey = id.public_hex();
            log_line(false, &format!("helper: agent identity loaded ({pubkey})"));
            Some(AgentIdentity {
                pubkey,
                tenant_id: cfg.tenant_id.clone().filter(|s| !s.is_empty()),
                signer: Arc::new(crate::enroll::IdentitySigner::new(id)),
            })
        }
        Ok(None) => {
            if cfg.is_control_plane_managed() {
                log_line(false, &format!("helper: no identity key at {identity_path} — register_agent will NOT be authenticated"));
            }
            None
        }
        Err(e) => {
            log_line(false, &format!("helper: {e} — register_agent will NOT be authenticated"));
            None
        }
    };

    // docs/65: fleet directives (reinstall / uninstall). Enabled only with a pinned dedicated directive key and a full
    // enrollment; the hub also owns the crash-resume of any operation a previous run left in flight (its pump runs on `rt`
    // below). `None` ⇒ every directive is ignored and `directive_v1` is not advertised.
    let directive_hub = crate::directive_win::build_hub(
        cfg,
        crate::enroll::read_identity(&identity_path).ok().flatten(),
        &signaling_url,
    );

    let ice: Vec<IceServer> = cfg.stun.iter().map(|u| IceServer::stun(u)).collect();
    let transfer_dir = cfg.transfer_dir_or_default();
    // M11: explicit bitrate caps bind after pixel scaling. Absent config permits the
    // 20 Mbps request maximum; initial session quality remains 3 Mbps.
    let quality_policy = QualityPolicy::from_config(cfg.quality);
    // Session length bound. A sub-minute value is treated as a mistake rather than obeyed: it would
    // make the agent look broken (sessions dying seconds after connecting) in a way that is very
    // hard to attribute to a config typo.
    let max_session = match cfg.max_session_secs {
        Some(s) if s >= 60 => Duration::from_secs(s),
        Some(s) => {
            log_line(false, &format!(
                "helper: max_session_secs={s} is below the 60s minimum; using the {}h default",
                DEFAULT_STREAM_MAX_RUN.as_secs() / 3600
            ));
            DEFAULT_STREAM_MAX_RUN
        }
        None => DEFAULT_STREAM_MAX_RUN,
    };
    log_line(false, &format!("helper: session limit {}s", max_session.as_secs()));
    log_line(
        false,
        &format!(
            "helper: quality ceiling {} kbps ({}) / {} fps, adaptive={}",
            quality_policy.max_bitrate_bps / 1000,
            if quality_policy.bitrate_cap_configured {
                "configured hard cap"
            } else if quality_policy.legacy_installer_bitrate_ignored {
                "default request maximum; config's legacy installer value 3000000 ignored"
            } else {
                "default request maximum"
            },
            quality_policy.max_fps,
            quality_policy.adaptive
        ),
    );

    // H1: pin the control-plane's grant-issuer public key if configured. Present ⇒ secure mode
    // (backstage requires a signed grant).
    //
    // Absent or malformed ⇒ DENY backstage, never dev mode. This is an INSTALLED SERVICE on someone's
    // machine, reachable by whoever the signaling server brokers to it; self-issuing a 19-capability
    // grant there because a config value was blank or had a typo is not a "convenient fallback", it
    // is the whole authorization system switched off by omission — and the shipped installer
    // defaults `-GrantIssuerPubkey` to "", so the insecure path was the one you got by not passing
    // a flag. Streaming/input/clipboard still run, so the machine stays reachable and fixable; only
    // the tool panels are gated. Failing closed here is the same house rule as the throttles.
    let backstage_auth: BackstageAuth = match cfg.grant_issuer_pubkey.as_deref() {
        Some(hex) if !hex.trim().is_empty() => match PublicIdentity::from_hex(hex.trim()) {
            Ok(pk) => {
                log_line(false, "helper: backstage secure mode — grant issuer key pinned");
                BackstageAuth::SignedBy(pk)
            }
            Err(e) => {
                log_line(false, &format!("helper: grant_issuer_pubkey is not a valid Ed25519 hex key ({e:?}); backstage is DISABLED (streaming and input are unaffected)"));
                BackstageAuth::Deny
            }
        },
        _ => {
            log_line(false, "helper: no grant_issuer_pubkey configured; backstage is DISABLED (streaming and input are unaffected)");
            BackstageAuth::Deny
        }
    };

    // The machine's clipboard ceiling. Logged next to the backstage mode because it is the same
    // kind of fact — what this machine will let a session do, decided before any session exists.
    let clipboard_mode = cfg.clipboard;

    log_line(
        false,
        &format!(
            "helper: streaming mode — device={device} → signaling {signaling_url} ({} stun, backstage {}, clipboard {})",
            ice.len(),
            match backstage_auth {
                BackstageAuth::SignedBy(_) => "secure",
                BackstageAuth::Deny => "disabled",
                BackstageAuth::InsecureSelfIssued => "dev-mode",
            },
            match clipboard_mode {
                ClipboardMode::Bidirectional => "both directions",
                ClipboardMode::ToTechnician => "to technician only",
                ClipboardMode::ToGuest => "to guest only",
                ClipboardMode::Disabled => "DISABLED",
            },
        ),
    );

    // docs/21 step 2: read, verify and REPORT the signed update manifest. Placed here, immediately
    // after the startup summary and beside the backstage-auth decision above, because it is the
    // same kind of fact — what this machine will and will not believe, decided once, before any
    // session exists. It reads one file and writes one log line; it downloads, stages and applies
    // nothing (see `log_update_status` and `rmt_agent::update`'s module docs).
    log_update_status(cfg);

    // docs/21 step 3 (guard): ensure the idle-barrier lock file exists inside the already-hardened
    // CONFIG_DIR before any session can open a shared handle against it.  An Err here means the
    // lock file is absent or suspect; per-session guard opens will then fail-closed on their own.
    if let Err(e) = crate::update_guard::ensure_session_lock_exists() {
        tracing::warn!(error = %e, "update_guard: session lock setup failed; sessions will be refused until resolved");
    }

    // Operator-driven shutdown parity with the proof loop: the stop file flips `stop`.
    let stop = Arc::new(AtomicBool::new(false));
    spawn_stop_file_watcher(stop.clone());

    // Notification-area presence icon: signals to the PC's user that a remote-access
    // agent is running and available. The icon lives for the entire helper lifetime —
    // appearing when the helper starts and disappearing when it exits. Failure to create
    // the icon (headless, no Shell, etc.) is non-fatal; the session continues unaffected.
    // Session-state updates (idle vs. active) are deferred to a future round that adds
    // service↔helper IPC; the current process lifetime already maps to "available".
    // docs/64 H3: the tray's "Request help..." menu talks to this hub; the signaling connection feeds and drains it.
    let help_hub = crate::help_request::HelpHub::new();
    let _tray = crate::tray::TrayIcon::spawn_with_help(Some(help_hub.clone()));

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            log_line(false, &format!("helper: tokio runtime build failed: {e}"));
            return 1;
        }
    };

    // docs/65: the directive pump. Its first pass is the RESUME of any operation a previous run left in flight (records are
    // read, a reinstall is probed, a removal helper is probed); after that it runs on events and a timer, and puts owed
    // acknowledgements on whichever signaling connection is attached.
    if let Some(hub) = directive_hub.clone() {
        rt.spawn(hub.run());
    }
    // docs/64: the help-request timers (resend until acknowledged, the 60 s status re-query while a request is open).
    rt.spawn(help_hub.clone().run());

    // Persistent agent: an `Agent`-role `connect()` blocks up to `CONNECT_TIMEOUT` waiting for a
    // controller, then returns (Ok when a session ends, Err on timeout/disconnect). Exiting after one
    // attempt would leave the machine unreachable until the next session-change respawn — so retry
    // until the stop file is set. Each iteration is one full remote session; a fresh
    // `FollowingCapturer` + `SendInputSink` is built per attempt (the capturer is single-use, bound
    // to its capture thread). A short pause between attempts keeps a flapping signaling server from
    // spinning the loop hot.
    // ONE ledger for the whole helper lifetime, deliberately built OUTSIDE the reconnect loop.
    // A per-session ledger would stop a grant being installed twice inside one session but would
    // forget it the moment the session ended — and a grant's TTL comfortably outlives a session, so
    // the interesting replay is precisely the one into a *later* session on the same machine.
    let spent_grants = Arc::new(SpentGrants::default());
    // …and one for ELEVATION grants, on the same reasoning and for the same lifetime. An elevation
    // grant is bound to a control-plane session id, so a cross-session replay is already refused by
    // `SignedElevationGrant::verify` — but the ledger costs nothing (it self-prunes against the
    // grants' own TTLs) and does not depend on that argument continuing to hold.
    let spent_elevations = Arc::new(SpentGrants::default());
    // The host the guest window names as the party this machine answers to. Read once, outside the
    // loop, from the same config the agent enrolled against. An unconfigured agent yields "" and
    // the presenter renders that as "an unknown server" rather than dropping the line — a banner
    // that silently omits who is connected reads as "nobody is", which is the opposite of true.
    let guest_banner_host = cfg
        .control_plane_url
        .as_deref()
        .map(crate::uri::control_plane_host)
        .unwrap_or_default();
    let mut backoff = RECONNECT_BACKOFF_MIN;
    // "Remove client": a controller can end a session AND uninstall the agent. The dispatch flips this
    // flag on `EndSession { uninstall: true }`; we read it after the mux loop returns and self-uninstall
    // instead of re-registering. One flag for the helper lifetime — once set, we uninstall and exit.
    let uninstall_flag = Arc::new(AtomicBool::new(false));

    // F2 many-tech: shared config for every brokered session spawned by this helper. Built once
    // outside the reconnect loop so the spent_grants/spent_elevations ledgers and the uninstall
    // flag survive across reconnects (same reasoning as the single-session path).
    let ms_opts = Arc::new(MultiSessionOpts {
        session_tasks: Default::default(),
        device,
        ice: ice.clone(),
        identity: agent_identity.clone(),
        transfer_dir: transfer_dir.clone(),
        clipboard_mode,
        backstage_auth: backstage_auth.clone(),
        require_session_policy: cfg.require_session_policy,
        quality_policy,
        max_session,
        // Session recording (loop 89). THE INSTALLED HELPER IS THE ONLY HOST THAT RECORDS.
        recording_dir: Some(PathBuf::from(crate::config::DEFAULT_RECORDING_DIR)),
        spent_grants: spent_grants.clone(),
        spent_elevations: spent_elevations.clone(),
        uninstall_requested: uninstall_flag.clone(),
        directive_hub: directive_hub.clone(),
        help_hub: Some(help_hub.clone()),
        guest_banner_host: guest_banner_host.clone(),
        // ONE report set for the helper's lifetime — created outside the reconnect loop below, so a
        // guest End still unacknowledged when the signaling connection drops is re-sent by the next
        // registration's mux rather than lost with the old one.
        guest_end_reports: Some(rmt_agent_core::guest_end::GuestEndShared::new()),
        // Production path: real machine actions are always enabled.
        #[cfg(feature = "test-harness")]
        mock_actions: false,
        // Production path: never in secure-test mode.
        #[cfg(feature = "secure-test")]
        secure_test_harness: false,
    });

    // Create the shared capture once for the helper lifetime.
    // A fresh FollowingCapturer per helper start (not per reconnect) is the correct scope:
    // DXGI allows only one IDXGIOutputDuplication per output; spawning a new one on every
    // reconnect would leave the old thread running and the new one failing to acquire DXGI.
    let capturer = FollowingCapturer::new().with_canvas(cfg.canvas_capture.as_deref() != Some("gdi"));
    if cfg.canvas_capture.as_deref() == Some("gdi") {
        tracing::info!("capture: config canvas_capture=gdi — the composite stream uses the GDI composite only");
    }
    let (shared_capture, _capture_thread) =
        crate::shared_capture::SharedCapture::spawn_canvas(capturer, DEFAULT_STREAM_FPS, stop.clone());
    let shared_capture = Arc::new(shared_capture);

    while !stop.load(Ordering::Relaxed) {
        let failed = match rt.block_on(run_multi_session_stream(
            &signaling_url,
            Arc::clone(&shared_capture),
            stop.clone(),
            Arc::clone(&ms_opts),
        )) {
            Ok(()) => {
                log_line(false, "helper: streaming session(s) ended; awaiting next controller");
                false
            }
            Err(e) => {
                log_line(false, &format!("helper: connect/session error: {e}; retrying"));
                true
            }
        };
        // "Remove client": a session asked us to uninstall. Do it now — spawn the detached
        // orchestrator that kills this process tree, deletes the service, and removes the binary +
        // state dirs — then break the loop so we stop re-registering. This is the LAST thing the helper
        // does; the orchestrator finishes the removal once we (and the service) have exited.
        //
        // docs/65 D-C2/D-C6: removal no longer happens here. The old path spawned a detached `cmd.exe` that killed the
        // process tree, `sc delete`d the service and `rmdir /s /q`d the directories: no product-registration removal, no
        // verification, no report. The ONE removal is the directive engine's (directive_removal::run_removal: MSI removal,
        // validated deletes, a signed final report), reached through a signed uninstall directive. `uninstall_flag` is
        // therefore never set any more; the session just ends.
        if uninstall_flag.load(Ordering::SeqCst) {
            log_line(false, "helper: unexpected legacy uninstall flag; ignoring (removal is directive-driven)");
            uninstall_flag.store(false, Ordering::SeqCst);
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        if failed {
            // A rejected registration ("registration not authorized") arrives here as a connect
            // error. Retrying tightly would hammer the signaling server AND, through its identity
            // resolver, the control plane behind it — so back off exponentially with jitter.
            let wait = jittered(backoff);
            log_line(false, &format!("helper: backing off {}s before reconnecting", wait.as_secs()));
            sleep_unless_stopped(&stop, wait);
            backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
        } else {
            // A session that actually ran proves the path is healthy; start over from the floor.
            backoff = RECONNECT_BACKOFF_MIN;
            sleep_unless_stopped(&stop, Duration::from_secs(2));
        }
    }
    log_line(false, "helper: streaming loop stopped");
    0
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Acquire the machine-global single-instance mutex for the helper.
///
/// Returns `Some(handle)` if we are the only helper (keep the handle alive for the process's
/// lifetime — dropping/closing it releases the mutex). Returns `None` if another helper already
/// holds it. Retries briefly so a service *retarget* (kill predecessor → spawn us) doesn't lose
/// the race while the predecessor's handle is still closing.
fn acquire_singleton() -> Option<HANDLE> {
    let name: Vec<u16> = HELPER_SINGLETON
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    for attempt in 0..10 {
        // SAFETY: `name` is a valid NUL-terminated wide string; default security, unowned.
        let h = unsafe { CreateMutexW(None, false, PCWSTR(name.as_ptr())) };
        match h {
            Ok(handle) => {
                // SAFETY: GetLastError is always valid to read after the call above.
                let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
                if !already {
                    return Some(handle); // fresh owner
                }
                // Another helper exists — release our handle and wait for it to exit.
                // SAFETY: `handle` is a valid mutex handle we own.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                if attempt < 9 {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            Err(_) => return None,
        }
    }
    None
}

/// Append a line to the helper's log (and stdout). No-op file write unless the log is writable.
///
/// The file half is **timestamped** and the stdout half is not, on purpose: stdout is a parsed
/// contract (the e2e tests match `INJECTED …` / `CLIPBOARD-SET …` and the streaming banners), while
/// in the file these lines sit interleaved with the tracing subscriber's timestamped ones. An
/// undated `helper: connect/session error` next to a dated `INFO` line cannot be correlated with
/// it — and correlating agent events across a guest/host timezone split is exactly what has
/// already produced one false reading in this project (docs/07 loop 5 §4).
fn log_line(proof: bool, msg: &str) {
    println!("{msg}");
    // Always persist to the helper log: a service-spawned SYSTEM helper has no console to print
    // to, so this is the only way its behavior (streaming vs proof vs idle, connect errors) is
    // observable. `proof` now only gates the capture-proof BMPs, not logging.
    let _ = proof;
    // The SAME file (and the same rotation policy) as crate::logging's tracing subscriber — one
    // observable stream, and one place that decides when the log has grown too large.
    if let Some(mut f) = crate::logging::open_log_append(crate::logging::log_path()) {
        // ONE write_all, not `writeln!`: `write_fmt` issues a separate write per format piece, so
        // the message and its newline would be two appends and the other process's line could
        // splice between them. Matches `logging::EventWriter`'s one-append-per-line guarantee.
        let _ = f.write_all(format!("{} {msg}\n", crate::logging::log_timestamp()).as_bytes());
    }
}

/// Write a [`CapturedFrame`] (packed top-down BGRA8) as a 32bpp BMP for eyeball verification.
fn write_bmp32(path: &str, frame: &CapturedFrame) -> std::io::Result<()> {
    let (w, h) = (frame.width as i32, frame.height as i32);
    let data_size = (w as usize) * (h as usize) * 4;
    let file_size = 14 + 40 + data_size;
    let mut out = Vec::with_capacity(file_size);
    // BITMAPFILEHEADER
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(file_size as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&54u32.to_le_bytes());
    // BITMAPINFOHEADER (top-down = negative height)
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&w.to_le_bytes());
    out.extend_from_slice(&(-h).to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(data_size as u32).to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    let take = data_size.min(frame.bytes.len());
    out.extend_from_slice(&frame.bytes[..take]);
    if take < data_size {
        out.resize(file_size, 0);
    }
    std::fs::write(path, &out)
}

/// Publish selection validation state before notifying the async transport owner.
/// The oneshot also retains the list when publication wins the startup race.
fn publish_monitor_list(
    published: &Mutex<Vec<MonitorDesc>>,
    ready: tokio::sync::oneshot::Sender<Vec<MonitorDesc>>,
    monitors: Vec<MonitorDesc>,
) {
    if let Ok(mut snapshot) = published.lock() {
        *snapshot = monitors.clone();
    }
    // Session teardown may already have dropped the receiver.
    let _ = ready.send(monitors);
}

/// Keep the stream on the requested display, including while it has no new frame.
/// FollowingCapturer represents both idle DXGI and temporary loss as CaptureUnavailable.
/// Falling back to id 0 here inserts an unrelated display (id 0 is the leftmost, not
/// necessarily the primary) and can make the stream alternate targets on idle frames.
fn capture_selected_frame(
    capturer: &mut dyn ScreenCapturer,
    selected: u32,
) -> Option<CapturedFrame> {
    if selected == COMPOSITE_MONITOR_ID {
        capturer.capture_composite().ok()
    } else {
        capturer.capture_frame(selected).ok()
    }
}

#[cfg(test)]
#[path = "host_ft_audit_tests.rs"]
mod file_transfer_audit_tests;

#[cfg(test)]
#[path = "host_dir_list_tests.rs"]
mod dir_list_gate_tests;

#[cfg(test)]
#[path = "host_promote_tests.rs"]
mod promote_tests;

/// Security audit 2026-10-18: under `biased;` the session-lease arm must be polled BEFORE the
/// viewer-receive arm, or a viewer that keeps the receive queue ready starves revocation, the
/// lease, and the duration/idle limits. Source order IS the priority, so the order is the test.
#[cfg(test)]
mod lease_arm_priority_tests {
    #[test]
    fn lease_arm_precedes_the_receive_arm() {
        let src = include_str!("host.rs");
        // Needles are split with concat! so the joined text never appears in this file verbatim:
        // the test cannot find ITSELF. (It did: the receive arm became `match note_activity(...)` in
        // 763de26 and this test kept passing by matching its own literal. Codex 1.3.7 review v4.)
        let lease = src
            .find(concat!("_ = lease_tick.tick(), ", "if session_lease.is_enforced() => {"))
            .expect("lease arm present");
        let receive = src
            .find(concat!("received = transport.recv_frame(), if input_open => ", "match note_activity(received, activity.as_deref()) {"))
            .expect("receive arm present");
        assert!(lease < receive, "the lease arm must come before the receive arm in the biased select");
    }
}

/// docs/49 v4 (Codex agent-slice review): a session's end is reported only after its teardown has
/// joined everything it ran. Inside `serve_session_with_ice` exactly two report sites may exist:
/// the access refusal, before any session task or thread exists, and the tail, after the capture
/// thread is joined and the guest window is closed.
#[cfg(test)]
mod session_end_report_order_tests {
    use super::{classify_unattributed_end, end_notice_message, flush_pending_move, forward_input};
    use rmt_agent_core::{InputButton, InputEvent};
    use rmt_protocol::signaling::SessionEndReason;
    use std::time::Duration;

    fn fake_input_send(
        queue: &mut Vec<(InputEvent, u64)>,
        capacity: usize,
        item: (InputEvent, u64),
    ) -> Result<(), std::sync::mpsc::TrySendError<(InputEvent, u64)>> {
        if queue.len() >= capacity {
            Err(std::sync::mpsc::TrySendError::Full(item))
        } else {
            queue.push(item);
            Ok(())
        }
    }

    #[test]
    fn full_queue_holds_a_move() {
        let mut pending = None;
        let mut queue = Vec::new();
        assert_eq!(forward_input(&mut pending, InputEvent::MouseMove { x: 10, y: 20 }, 7,
            |item| fake_input_send(&mut queue, 0, item)), Ok(0));
        assert!(queue.is_empty());
        assert!(matches!(pending, Some((InputEvent::MouseMove { x: 10, y: 20 }, 7))));
    }

    #[test]
    fn full_queue_replaces_pending_move() {
        let mut pending = Some((InputEvent::MouseMove { x: 10, y: 20 }, 7));
        let mut queue = Vec::new();
        let mut attempts = 0;
        assert_eq!(forward_input(&mut pending, InputEvent::MouseMove { x: 30, y: 40 }, 8,
            |item| {
                attempts += 1;
                fake_input_send(&mut queue, 0, item)
            }), Ok(0));
        assert_eq!(attempts, 1);
        assert!(matches!(pending, Some((InputEvent::MouseMove { x: 30, y: 40 }, 8))));
    }

    #[test]
    fn pending_move_precedes_button() {
        let mut pending = Some((InputEvent::MouseMove { x: 10, y: 20 }, 7));
        let mut queue = Vec::new();
        assert_eq!(forward_input(&mut pending, InputEvent::MouseButton { button: InputButton::Left, down: true }, 7,
            |item| fake_input_send(&mut queue, 2, item)), Ok(2));
        assert!(pending.is_none());
        assert!(matches!(&queue[..], [
            (InputEvent::MouseMove { x: 10, y: 20 }, 7),
            (InputEvent::MouseButton { button: InputButton::Left, down: true }, 7),
        ]));
    }

    #[test]
    fn full_queue_button_is_fatal() {
        let mut pending = None;
        let mut queue = Vec::new();
        assert_eq!(forward_input(&mut pending, InputEvent::MouseButton { button: InputButton::Left, down: true }, 7,
            |item| fake_input_send(&mut queue, 0, item)), Err(()));
        assert!(pending.is_none());
        assert!(queue.is_empty());
    }

    #[test]
    fn full_queue_cannot_skip_pending_move_for_button() {
        let mut pending = Some((InputEvent::MouseMove { x: 10, y: 20 }, 7));
        let mut queue = Vec::new();
        let mut attempts = 0;
        assert_eq!(forward_input(&mut pending, InputEvent::MouseButton { button: InputButton::Left, down: true }, 8,
            |item| {
                attempts += 1;
                fake_input_send(&mut queue, 0, item)
            }), Err(()));
        assert_eq!(attempts, 1);
        assert!(queue.is_empty());
    }

    #[test]
    fn disconnected_queue_is_fatal_for_moves() {
        for mut pending in [None, Some((InputEvent::MouseMove { x: 10, y: 20 }, 7))] {
            assert_eq!(forward_input(&mut pending, InputEvent::MouseMove { x: 30, y: 40 }, 8,
                |item| Err(std::sync::mpsc::TrySendError::Disconnected(item))), Err(()));
        }
    }

    /// Codex input r1 [medium]: a held move must reach the guest once the queue drains, without
    /// waiting for the technician's next input.
    #[test]
    fn a_held_move_is_sent_once_the_queue_drains_without_more_input() {
        let mut pending = Some((InputEvent::MouseMove { x: 10, y: 20 }, 7));
        let mut queue = Vec::new();
        assert_eq!(flush_pending_move(&mut pending, |item| fake_input_send(&mut queue, 0, item)), Ok(0));
        assert!(matches!(pending, Some((InputEvent::MouseMove { x: 10, y: 20 }, 7))), "still held, epoch unchanged");
        assert_eq!(flush_pending_move(&mut pending, |item| fake_input_send(&mut queue, 1, item)), Ok(1));
        assert!(pending.is_none());
        assert!(matches!(&queue[..], [(InputEvent::MouseMove { x: 10, y: 20 }, 7)]));
        assert_eq!(flush_pending_move(&mut pending, |item| fake_input_send(&mut queue, 1, item)), Ok(0), "nothing held");
        let mut held = Some((InputEvent::MouseMove { x: 1, y: 1 }, 3));
        assert_eq!(
            flush_pending_move(&mut held, |item| Err(std::sync::mpsc::TrySendError::Disconnected(item))),
            Err(()),
            "a gone capture thread ends the session"
        );
    }

    /// The loop must call the flush on every iteration, not only beside new input.
    #[test]
    fn the_session_loop_flushes_a_held_move_every_iteration() {
        let src = include_str!("host.rs");
        let head = src
            .find(concat!("&& start.elapsed() < max_", "session\n    {"))
            .expect("session loop head");
        let body = &src[head..head + 1200];
        assert!(body.contains(concat!("flush_pending_move(&mut pending_", "move")), "the flush runs at the top of the loop");
    }

    #[test]
    fn pending_move_retains_original_epoch() {
        let mut pending = None;
        let mut queue = Vec::new();
        assert_eq!(forward_input(&mut pending, InputEvent::MouseMove { x: 10, y: 20 }, 7,
            |item| fake_input_send(&mut queue, 0, item)), Ok(0));
        assert_eq!(forward_input(&mut pending, InputEvent::MouseButton { button: InputButton::Left, down: true }, 9,
            |item| fake_input_send(&mut queue, 2, item)), Ok(2));
        assert_eq!(queue[0].1, 7);
        assert_eq!(queue[1].1, 9);
    }

    #[test]
    fn a_clipboard_push_never_ends_the_session() {
        let source = include_str!("host.rs");
        let start = source
            .find(concat!("Ok(frame) if frame.channel == ChannelId::", "Clipboard =>"))
            .expect("inbound clipboard arm");
        let rest = &source[start..];
        let end = rest
            .find(concat!("Ok(frame) if frame.channel == ChannelId::", "Control =>"))
            .expect("following control arm");
        let arm = &rest[..end];
        assert!(!arm.contains("break;"), "clipboard pushes must never end the session");
        assert!(arm.contains(concat!("CLIPBOARD_INBOUND_MAX_", "BYTES")));
    }

    #[test]
    fn end_reports_are_queued_only_before_start_or_after_teardown() {
        let src = include_str!("host.rs");
        let start = src.find("pub async fn serve_session_with_ice(").expect("function present");
        let end = start + src[start..].find("\nfn classify_unattributed_end(").expect("helper follows the function");
        let body = &src[start..end];
        let sites: Vec<usize> = body.match_indices("report_session_end(").map(|(i, _)| i).collect();
        assert_eq!(sites.len(), 2, "serve_session_with_ice must report from exactly two places");
        let refusal = body.find("report_session_end(guest_end_reports.as_ref(), control_plane_session, rmt_protocol::signaling::SessionEndReason::Policy)")
            .expect("access refusal report");
        let first_thread = body.find("std::thread::spawn").expect("the session starts threads");
        assert!(refusal == sites[0] && refusal < first_thread, "the refusal report must precede every session thread");
        let joined = body.rfind("let _ = cap_thread.join();").expect("capture thread joined");
        let closed = body.rfind("s.close();").expect("guest window closed");
        assert!(sites[1] > joined && sites[1] > closed, "the session report must follow the teardown joins");
    }

    #[test]
    fn an_unattributed_exit_is_classified_without_assuming_the_viewer_left() {
        assert_eq!(classify_unattributed_end(true, true), SessionEndReason::ServiceStop);
        assert_eq!(classify_unattributed_end(true, false), SessionEndReason::ServiceStop);
        assert_eq!(classify_unattributed_end(false, true), SessionEndReason::MaxDuration);
        assert_eq!(classify_unattributed_end(false, false), SessionEndReason::Other);
    }

    /// 10-28: a laptop's monitors re-enumerating on wake ended a session six seconds in, and the
    /// console could only say "session has ended". The wording is tested below; this pins the WIRING —
    /// the topology arm names its cause, and teardown sends the notice AFTER input is fenced (no
    /// network await may keep input admitted) but before the guest window or end report.
    #[test]
    fn silent_ends_are_announced_from_teardown() {
        let src = include_str!("host.rs");
        let arm = src
            .find(concat!("topology change signaled by capture ", "thread; ending session"))
            .expect("topology arm");
        let arm_body = &src[arm..arm + 600];
        assert!(
            arm_body.contains(concat!("end_detail = Some(\"session ended: the display ", "layout")),
            "the topology arm must say the display layout changed"
        );
        let classify = src
            .find(concat!("let end_reason = end_reason.unwrap_or_else(|| classify_unattributed_", "end("))
            .expect("teardown");
        let fence = src[classify..]
            .find(concat!("set_input_admitted(&sink, ", "false).await;"))
            .expect("input fence")
            + classify;
        assert!(
            !src[classify..fence].contains(concat!("end_notice_", "message(")),
            "the notice must not be awaited before the input fence"
        );
        let report = src[fence..]
            .find(concat!("report_session_end(guest_end_reports.as_ref(), control_plane_", "session, end_reason);"))
            .expect("end report")
            + fence;
        let after_fence = &src[fence..report];
        let notice = after_fence.find(concat!("end_notice_message(end_", "detail, end_reason, max_session)"));
        assert!(notice.is_some(), "teardown must send the notice after the input fence");
        assert!(after_fence.contains(concat!("if !end_notice_", "sent {")), "teardown must skip ends already announced");
        let window = after_fence.find(concat!("s.ended();\n", "        s.close();")).expect("guest window teardown");
        assert!(notice.unwrap() < window, "the notice goes out before the guest window says ENDED");
    }

    #[test]
    fn end_notice_names_the_reason_for_every_silent_end() {
        let max_session = Duration::from_secs(14400);
        let detail = "session ended: recording could not continue";
        assert_eq!(
            end_notice_message(Some(detail), SessionEndReason::MaxDuration, max_session),
            Some(detail.to_string()),
        );
        assert_eq!(
            end_notice_message(Some(detail), SessionEndReason::Policy, max_session),
            Some(detail.to_string()),
        );
        for (reason, duration, expected) in [
            (SessionEndReason::MaxDuration, max_session,
                "session ended: this machine's maximum session length (4 h) was reached; reconnect to continue"),
            (SessionEndReason::MaxDuration, Duration::from_secs(5400),
                "session ended: this machine's maximum session length (90 min) was reached; reconnect to continue"),
            (SessionEndReason::ServiceStop, max_session,
                "session ended: the DeskRally agent on this machine is stopping or updating; reconnect in a minute"),
            (SessionEndReason::Other, max_session,
                "session ended: the agent on this machine ended the session unexpectedly; reconnect to continue"),
        ] {
            let message = end_notice_message(None, reason, duration).expect("silent end notice");
            assert_eq!(message, expected);
            assert!(message.starts_with("session ended:"));
        }
        for reason in [
            SessionEndReason::ViewerLeft,
            SessionEndReason::GuestEnded,
            SessionEndReason::LeaseLapsed,
            SessionEndReason::Idle,
            SessionEndReason::Policy,
        ] {
            assert_eq!(end_notice_message(None, reason, max_session), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dispatch hook of the idle release: technician frames touch the clock, the control
    /// channel (lease renewals) and errors do not, and the result passes through unchanged.
    #[test]
    fn note_activity_counts_technician_frames_only_and_passes_through() {
        let act = crate::update_guard::SessionActivity::new();
        std::thread::sleep(Duration::from_millis(60));
        let r = note_activity(Ok(Frame::new(ChannelId::Control, vec![1u8])), Some(&act));
        assert!(matches!(&r, Ok(f) if f.channel == ChannelId::Control));
        let r = note_activity(Err(rmt_agent_core::transport::TransportError::Closed), Some(&act));
        assert!(r.is_err());
        assert!(act.idle_for() >= Duration::from_millis(50), "control frames and errors are not activity");
        let r = note_activity(Ok(Frame::new(ChannelId::Input, vec![2u8])), Some(&act));
        assert!(matches!(&r, Ok(f) if f.channel == ChannelId::Input && f.payload[..] == [2u8]));
        assert!(act.idle_for() < Duration::from_millis(20), "input is activity");
        assert!(note_activity(Ok(Frame::new(ChannelId::Input, vec![])), None).is_ok(), "no clock: a no-op");
    }

    /// AbortOnDrop ends the idle poller with its scope, which releases the barrier (and so the
    /// update lock) it referenced. A poller outliving the session would recreate the 638a311 leak.
    #[tokio::test]
    async fn dropping_the_poller_releases_the_barrier_it_holds() {
        struct Fake(Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for Fake {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let live = Arc::new(std::sync::atomic::AtomicUsize::new(1));
        let barrier = Arc::new(crate::update_guard::IdleBarrier::new(
            Some(Fake(live.clone())),
            Box::new(|| Ok(None)),
            crate::update_guard::SessionActivity::new(),
            Duration::from_secs(3600),
        ));
        let poller = AbortOnDrop(tokio::spawn({
            let b = Arc::clone(&barrier);
            async move {
                loop {
                    let _ = b.poll();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }));
        drop(barrier); // the session scope's own reference
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(live.load(Ordering::SeqCst), 1, "the running poller keeps the guard (as designed)");
        drop(poller);
        for _ in 0..100 {
            if live.load(Ordering::SeqCst) == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(live.load(Ordering::SeqCst), 0, "aborting the poller released the guard");
    }

    /// Codex 1.3.7 release review [medium]: a brokered negotiation (up to 60 s) must yield to a helper
    /// stop, so the session reports service_stop inside the stop's ~10 s join budget instead of being
    /// cancelled unreported. Behaviour: the stop wait wins a race against a negotiation that never ends.
    #[test]
    fn a_stop_wins_the_race_against_a_negotiation_that_never_completes() {
        let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
        let stop = std::sync::Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let started = Instant::now();
        let stopped_first = rt.block_on(async move {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(150)).await;
                s2.store(true, Ordering::SeqCst);
            });
            tokio::select! {
                () = std::future::pending::<()>() => false,
                () = wait_until_stopped(|| stop.load(Ordering::SeqCst)) => true,
            }
        });
        assert!(stopped_first);
        assert!(started.elapsed() < Duration::from_secs(2), "the stop is noticed within a poll or two");
    }

    /// Wiring: the multi-session task races from_brokered against the stop, and the stop arm deregisters
    /// and reports ServiceStop (the end report is what closes the control-plane row).
    #[test]
    fn the_brokered_negotiation_is_raced_against_the_helper_stop_and_reports_service_stop() {
        let src = include_str!("host.rs");
        // Split needle (concat!): the test cannot match its own text.
        let at = src.find(concat!("let negotiation = ", "WebRtcTransport::from_brokered(")).expect("the negotiation is bound, not awaited inline");
        let region = &src[at..at + 2500];
        assert!(region.contains("() = wait_for_helper_stop() => None,"), "raced against the stop");
        let stop_arm = &region[region.find("None => {").expect("a stop arm")..];
        let stop_arm = &stop_arm[..stop_arm.find("return;").expect("the stop arm returns")];
        assert!(stop_arm.contains("deregister.deregister(&session_id);"), "the stop arm deregisters");
        assert!(stop_arm.contains("SessionEndReason::ServiceStop"), "the stop arm reports service_stop");
    }

    /// Wiring (Codex 1.3.7 v3): the stop path reports the mux's never-started sessions as service_stop
    /// BEFORE the drain that waits for reports to be acknowledged (signaling_mux's own test covers
    /// close_accept itself).
    #[test]
    fn the_shutdown_reports_queued_sessions_before_draining() {
        let src = include_str!("host.rs");
        // Split needle (concat!): the test cannot match its own text.
        let at = src.find(concat!("for bs in mux.", "close_accept() {")).expect("the shutdown takes the mux's queued sessions");
        let tail = &src[at..];
        let drain = tail.find("drain_session_end_reports(reports, &mut mux, session_tasks).await;").expect("then drains");
        assert!(tail[..drain].contains("SessionEndReason::ServiceStop"), "each queued session is reported before the drain");
    }

    #[test]
    fn sleep_unless_stopped_returns_early_on_stop_and_sleeps_otherwise() {
        // Negative control first: unset, it sleeps the full span.
        let idle = AtomicBool::new(false);
        let t = Instant::now();
        sleep_unless_stopped(&idle, Duration::from_millis(300));
        assert!(t.elapsed() >= Duration::from_millis(300), "an unset flag sleeps the whole span");

        // A stop set mid-sleep ends a long backoff within about one slice.
        let stop = Arc::new(AtomicBool::new(false));
        let setter = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(100));
                stop.store(true, Ordering::Relaxed);
            })
        };
        let t = Instant::now();
        sleep_unless_stopped(&stop, Duration::from_secs(60));
        setter.join().unwrap();
        assert!(t.elapsed() < Duration::from_secs(2), "took {:?}", t.elapsed());
    }
    use rmt_agent::backstage::grant::GrantClaims;

    #[tokio::test]
    async fn monitor_publication_recovers_an_early_empty_request() {
        let snapshot = Mutex::new(Vec::new());
        let (tx, mut rx) = tokio::sync::oneshot::channel();
        assert!(snapshot.lock().unwrap().is_empty());
        assert!(matches!(rx.try_recv(), Err(tokio::sync::oneshot::error::TryRecvError::Empty)));
        let monitors = vec![
            MonitorDesc { id: 0, width: 1920, height: 1080, primary: true },
            MonitorDesc { id: 1, width: 1920, height: 1080, primary: false },
        ];
        publish_monitor_list(&snapshot, tx, monitors);
        let announced = rx.await.unwrap();
        assert_eq!(announced.len(), 2);
        assert_eq!(snapshot.lock().unwrap().len(), 2);
        let wire = control::encode(&ControlMessage::MonitorList { monitors: announced });
        match control::decode(&wire).unwrap() {
            ControlMessage::MonitorList { monitors } => {
                assert_eq!(monitors.iter().map(|m| m.id).collect::<Vec<_>>(), vec![0, 1]);
            }
            _ => panic!("must announce the full monitor list"),
        }
    }

    #[tokio::test]
    async fn monitor_publication_survives_late_receiver_and_session_teardown() {
        let snapshot = Mutex::new(Vec::new());
        let (tx, rx) = tokio::sync::oneshot::channel();
        publish_monitor_list(&snapshot, tx, vec![
            MonitorDesc { id: 7, width: 800, height: 600, primary: true },
        ]);
        assert_eq!(rx.await.unwrap()[0].id, 7);
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(rx);
        publish_monitor_list(&snapshot, tx, vec![]);
        assert!(snapshot.lock().unwrap().is_empty());
    }

    struct IntermittentCapture {
        calls: Vec<u32>,
        unavailable: bool,
    }

    impl ScreenCapturer for IntermittentCapture {
        fn monitors(&self) -> rmt_agent_core::platform::PlatformResult<Vec<MonitorInfo>> {
            Ok(vec![])
        }

        fn capture_frame(&mut self, id: u32) -> rmt_agent_core::platform::PlatformResult<CapturedFrame> {
            self.calls.push(id);
            if self.unavailable && id != 0 {
                return Err(rmt_agent_core::platform::PlatformError::CaptureUnavailable(
                    "no new frame".into(),
                ));
            }
            Ok(CapturedFrame {
                monitor_id: id,
                width: 1,
                height: 1,
                bytes: vec![id as u8, 0, 0, 255],
                is_keyframe: true,
            })
        }

        fn capture_composite(&mut self) -> rmt_agent_core::platform::PlatformResult<CapturedFrame> {
            self.capture_frame(COMPOSITE_MONITOR_ID)
        }
    }

    #[test]
    fn selected_capture_idle_bursts_never_insert_another_display() {
        let mut cap = IntermittentCapture { calls: vec![], unavailable: false };
        let mut delivered = vec![];
        for idle in [false, true, true, false, true, false] {
            cap.unavailable = idle;
            if let Some(frame) = capture_selected_frame(&mut cap, 2) {
                delivered.push(frame.monitor_id);
            }
        }
        assert_eq!(delivered, vec![2, 2, 2]);
        assert_eq!(cap.calls, vec![2; 6]);
        cap.unavailable = false;
        assert_eq!(capture_selected_frame(&mut cap, 1).unwrap().monitor_id, 1);
    }

    #[test]
    fn selected_capture_composite_failure_never_inserts_a_single_display() {
        let mut cap = IntermittentCapture { calls: vec![], unavailable: true };
        assert!(capture_selected_frame(&mut cap, COMPOSITE_MONITOR_ID).is_none());
        assert_eq!(cap.calls, vec![COMPOSITE_MONITOR_ID]);
        cap.unavailable = false;
        assert_eq!(capture_selected_frame(&mut cap, COMPOSITE_MONITOR_ID).unwrap().monitor_id,
                   COMPOSITE_MONITOR_ID);
    }

    // -----------------------------------------------------------------------------------
    // The anti-blink cadence floor must not override the operator's chosen frame rate
    // -----------------------------------------------------------------------------------

    #[test]
    fn a_slow_frame_rate_never_slows_the_keep_alive_below_the_liveness_floor() {
        // THE regression this function shipped once. Taking the LONGER of the two let a 5 fps
        // bandwidth budget throttle the liveness guarantee down to 5 fps of delivery — which is the
        // sparse arrival the guarantee exists to prevent, so the blink came back at slow rates.
        assert_eq!(min_frame_interval(5), MIN_FRAME_INTERVAL);
        assert_eq!(min_frame_interval(10), MIN_FRAME_INTERVAL);
        assert_eq!(min_frame_interval(1), MIN_FRAME_INTERVAL);
    }

    #[test]
    fn a_fast_frame_rate_raises_the_keep_alive_cadence_to_match() {
        // The half that was missed the first time, and the one that actually bit at the DEFAULT
        // rate. An idle screen used to fall through the tier chain to a GDI blit that produced a
        // duplicate frame every iteration, so idle delivery was the COMMANDED rate and this floor
        // rarely fired. Once "nothing changed" became no-news, the floor was carrying idle delivery
        // alone — at 66 ms it halved 30 fps to 15 and the blink returned. It has to rise to meet
        // the commanded rate, not merely sit under it.
        assert_eq!(min_frame_interval(30), Duration::from_micros(33_333));
        assert_eq!(min_frame_interval(60), Duration::from_micros(16_666));
        // At the floor's own rate the two agree, so nothing changes at the boundary.
        assert_eq!(min_frame_interval(15), MIN_FRAME_INTERVAL);
    }

    #[test]
    fn the_keep_alive_is_never_slower_than_the_liveness_floor_at_any_rate() {
        // The invariant, stated once rather than implied by the two cases above: whatever the
        // operator asks for, delivery is at least ~15 fps. A future edit that reintroduces `max`
        // fails here even if someone also "fixes" the expectations above to match it.
        for fps in [1u32, 2, 5, 7, 10, 14, 15, 16, 24, 30, 60, 144] {
            assert!(
                min_frame_interval(fps) <= MIN_FRAME_INTERVAL,
                "at {fps} fps the keep-alive interval {:?} is slower than the {:?} liveness floor",
                min_frame_interval(fps),
                MIN_FRAME_INTERVAL
            );
        }
    }

    #[test]
    fn a_zero_frame_rate_does_not_divide_by_zero() {
        // `fps_now` is fed from the quality controller; 0 is not a rate it should ever apply, but a
        // panic in the session loop is a dropped session, so it is clamped rather than trusted.
        // Clamped to 1 fps, whose interval is a full second — and the floor still wins.
        assert_eq!(min_frame_interval(0), MIN_FRAME_INTERVAL);
    }

    // -----------------------------------------------------------------------------------
    // docs/21 step 2 — the ONE thing the agent does with a verified update manifest: log it
    // -----------------------------------------------------------------------------------

    /// Every [`rmt_agent::update::UpdateCheck`] outcome must render its OWN sentence, and the loud
    /// ones must be the loud ones.
    ///
    /// Both halves matter. A renderer that printed the same line for "no manifest" and "the
    /// manifest failed verification" would make the two indistinguishable in helper.log — and those
    /// are respectively the most common state in the fleet and a possible tampering event. And a
    /// renderer that marked everything loud (or nothing loud) would pass a distinctness test on its
    /// own, which is why loudness is asserted per variant rather than merely being consistent.
    #[test]
    fn every_update_check_outcome_renders_a_distinct_line() {
        use rmt_agent::update::{
            Release, UpdateAvailability, UpdateCheck, UpdateManifestError, UpdateRefusalReason,
            VersionParseError,
        };
        let release = || Release {
            version: "0.4.0".into(),
            sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            url: "https://updates.example/rmt-agent-0.4.0.exe".into(),
            min_upgradable_from: "0.2.0".into(),
        };
        let running = "0.3.0+0594362";

        // (outcome, expected loudness). Every variant of UpdateCheck, and every variant of
        // UpdateAvailability inside the one that carries it.
        let cases: Vec<(UpdateCheck, bool)> = vec![
            (UpdateCheck::NoManifest, false),
            (
                UpdateCheck::Refused(UpdateRefusalReason::NotConfigured),
                true,
            ),
            (
                UpdateCheck::Refused(UpdateRefusalReason::SameKeyAsGrantIssuer),
                true,
            ),
            (UpdateCheck::Invalid(UpdateManifestError::BadSignature), true),
            (
                UpdateCheck::Incomparable {
                    running: running.into(),
                    offered: "banana".into(),
                    reason: VersionParseError::Empty,
                },
                true,
            ),
            (
                UpdateCheck::Verified {
                    release: release(),
                    availability: UpdateAvailability::Available {
                        running: running.into(),
                        offered: "0.4.0".into(),
                    },
                },
                true,
            ),
            (
                UpdateCheck::Verified {
                    release: release(),
                    availability: UpdateAvailability::NoUpdate {
                        running: running.into(),
                        offered: "0.2.0".into(),
                    },
                },
                false,
            ),
            (
                UpdateCheck::Verified {
                    release: release(),
                    availability: UpdateAvailability::UpgradePathUnsupported {
                        running: running.into(),
                        offered: "0.4.0".into(),
                        min_upgradable_from: "0.3.5".into(),
                    },
                },
                true,
            ),
        ];

        let mut seen: Vec<String> = Vec::new();
        for (check, want_loud) in &cases {
            let (loud, msg) = describe_update_check(check, running);
            assert_eq!(loud, *want_loud, "wrong loudness for {check:?}: {msg}");
            assert!(!msg.is_empty(), "{check:?} rendered nothing");
            assert!(
                !msg.starts_with("helper:"),
                "the caller owns the prefix; {check:?} added its own: {msg}"
            );
            for prev in &seen {
                assert_ne!(prev, &msg, "two outcomes render the same line: {msg}");
            }
            seen.push(msg);
        }
        // Both loudness values actually occur, so the assertions above are not all vacuously
        // agreeing with a constant.
        assert!(cases.iter().any(|(_, l)| *l) && cases.iter().any(|(_, l)| !*l));
    }

    /// The refusal line must NAME the reason, not merely say "refused". A fail-closed control that
    /// cannot say WHICH failure closed it is the outage this repository has already had once
    /// (`fail-closed-must-say-which-failure`): a restored box 429'd every login for a day because
    /// the throttle could not report that it had failed to READ its own table.
    #[test]
    fn a_refusal_line_names_the_reason() {
        use rmt_agent::update::{UpdateCheck, UpdateRefusalReason};
        let (loud, msg) = describe_update_check(
            &UpdateCheck::Refused(UpdateRefusalReason::SameKeyAsGrantIssuer),
            "0.3.0+abc",
        );
        assert!(loud);
        assert!(msg.contains("grant_issuer_pubkey"), "{msg}");
        assert!(msg.contains("REFUSES ALL UPDATES"), "{msg}");
    }

    /// The "available" line must carry the two versions and the digest, because it is the only
    /// evidence a human has that the manifest they placed is the one the agent read.
    #[test]
    fn the_available_line_reports_both_versions_and_the_digest() {
        use rmt_agent::update::{Release, UpdateAvailability, UpdateCheck};
        let sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let (loud, msg) = describe_update_check(
            &UpdateCheck::Verified {
                release: Release {
                    version: "0.4.0".into(),
                    sha256: sha.into(),
                    url: "https://updates.example/a.exe".into(),
                    min_upgradable_from: "0.2.0".into(),
                },
                availability: UpdateAvailability::Available {
                    running: "0.3.0+0594362".into(),
                    offered: "0.4.0".into(),
                },
            },
            "0.3.0+0594362",
        );
        assert!(loud);
        assert!(msg.contains("0.3.0+0594362"), "{msg}");
        assert!(msg.contains("0.4.0"), "{msg}");
        assert!(msg.contains(sha), "{msg}");
        // And it must say, in the log, that this build does not act on it. An operator reading
        // "UPDATE AVAILABLE" on a step-2 agent would otherwise reasonably expect an install.
        assert!(msg.contains("Nothing is downloaded or installed"), "{msg}");
    }

    /// A session chain for tests that build a dispatcher. Nil ids: these tests are about grant
    /// verification, not about chain identity — `host_ft_audit_tests` owns that.
    fn test_chain() -> SharedAuditChain {
        rmt_agent::backstage::audit::new_shared_chain(
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
            uuid::Uuid::nil(),
        )
    }

    /// An [`AttendRedeem`] carrying `require_session_policy`, everything else inert.
    fn redeemed_with_floor(require_session_policy: bool) -> crate::attend::AttendRedeem {
        crate::attend::AttendRedeem {
            device_id: "dev-1".into(),
            tenant_id: "ten-1".into(),
            signaling_url: "ws://127.0.0.1:8080/ws".into(),
            attend_token: "tok".into(),
            grant_issuer_pubkey: None,
            require_session_policy,
            reason: None,
        }
    }

    fn attend_options_for(redeemed: &crate::attend::AttendRedeem) -> SessionOptions {
        attend_session_options(
            redeemed,
            Arc::new(NoopSink),
            PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
            BackstageAuth::Deny,
            None,
            None,
            false,
            false,
        )
    }

    /// LOOP 82, and the hop that had no coverage: what the control plane said at REDEEM has to reach
    /// the value the session actually enforces.
    ///
    /// This is worth a test of its own because the failure is SILENT. Deleting the field from the
    /// options left all 173 tests in this crate passing while the feature was inert in production —
    /// the attended session simply kept full control and nothing anywhere said so. Same shape as the
    /// two silent hops loop 80's review found on the viewer side.
    #[test]
    fn the_attended_policy_requirement_reaches_the_session_options() {
        assert!(
            attend_options_for(&redeemed_with_floor(true)).require_session_policy,
            "the control plane told the guest to open FLOORED and the session ignored it — a viewer              that withholds the policy frame keeps full control, which is the hole the flag exists              to close"
        );
        // The complement: a builder that hard-coded `true` would satisfy the assertion above while
        // stranding every ordinary attended session in view-only.
        assert!(
            !attend_options_for(&redeemed_with_floor(false)).require_session_policy,
            "a session opened FLOORED for a group that asked for nothing"
        );
    }

    /// docs/25 F03. The attended host is NOT leased, and this builder is the only place that decides
    /// it — so it is pinned here for the same reason loop 82 and loop 84 are pinned here.
    ///
    /// What losing it would mean concretely: an attended guest would start demanding a control-plane
    /// lease, the console would call `POST /sessions/{id}/policy`, and that route reads
    /// `session_record` — a table the attended flow never writes. Every renewal would 404, and EVERY
    /// ATTENDED SESSION IN THE PRODUCT would end at the grace deadline, roughly fifteen seconds in,
    /// for no security gain at all: attended revocation is already the three-second status poll in
    /// `spawn_attend_status_poller`, which is five times tighter than any lease and does not depend
    /// on the viewer cooperating.
    ///
    /// Both flags are asserted, because the danger is symmetric with `require_session_policy` above:
    /// a builder that hard-coded the lease mode would satisfy one half while breaking the other.
    #[test]
    fn the_attended_host_is_never_leased() {
        for floored in [true, false] {
            assert_eq!(
                attend_options_for(&redeemed_with_floor(floored)).session_lease,
                SessionLeaseMode::NotApplicable,
                "an attended session asked for a control-plane lease it can never renew: the renewal                  route knows only session_record, so every attended session would die at its grace                  deadline (floored={floored})"
            );
        }
    }

    /// LOOP 84. The attended host runs as the guest's own user, and the session options are the only
    /// place that says so.
    ///
    /// Pinned HERE, in the options builder, for the reason loop 82 paid for: this flag is read deep
    /// inside `serve_session_with_ice`, which no test can reach, so an options builder that forgot it
    /// would leave the whole fix inert with every other test still green. That is exactly how
    /// `require_session_policy` came to be missing from one of two hand-copied literals.
    ///
    /// What "inert" would mean concretely: `LaunchTool` and `RunCommand{as_user}` go back to calling
    /// `WTSQueryUserToken`, which needs `SeTcbPrivilege` that an administrator does not hold, so both
    /// fail `ERROR_PRIVILEGE_NOT_HELD` on every attended session — measured on LAB-VM before the fix.
    #[test]
    fn the_attended_host_declares_that_it_is_the_interactive_user() {
        assert!(
            attend_options_for(&redeemed_with_floor(false)).host_runs_as_interactive_user,
            "the attended session did not declare that it runs AS the guest, so its actuators will              try to fetch a token they have no privilege to fetch"
        );
    }

    /// LOOP 89. The attended host cannot record, and this is the only place that decides it.
    ///
    /// Same reason as the two above, and the same failure shape: `recording_dir` is read deep inside
    /// `serve_session_with_ice`, so a builder that started handing one out would enable recording on
    /// the attended host with every other test still green. The consequence is specific and bad —
    /// the recorder's 72-hour TTL is swept at helper start and session start, and an attended client
    /// is an ephemeral, uninstalled download that runs ONCE and is not a resident agent (it does NOT
    /// delete its own exe — that is deliberate), so on that host neither moment ever comes back after
    /// this run. A recording made there sits on a member of the public's disk with a
    /// deletion deadline nothing will ever read.
    ///
    /// The complement is deliberate too: the assertion is `is_none()` under the PRODUCTION flags AND
    /// under both lab flags, so "recording is off here" cannot be an accident of the test fixture.
    #[test]
    fn the_attended_host_is_given_nowhere_to_record() {
        let redeemed = redeemed_with_floor(false);
        for (log_input, synthetic) in [(false, false), (true, false), (false, true), (true, true)] {
            let o = attend_session_options(
                &redeemed,
                Arc::new(NoopSink),
                PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
                BackstageAuth::Deny,
                None,
                None,
                log_input,
                synthetic,
            );
            assert!(
                o.recording_dir.is_none(),
                "log_input={log_input} synthetic={synthetic}: the attended host was given a recording                  location, so a recording can be left on a guest's disk that nothing will ever sweep"
            );
        }
    }

    /// The actuating controls must be mocked under either lab flag, and `mock_input` must track
    /// `--log-input` ALONE — a synthetic capture still injects real input. Pinned because both facts
    /// used to live in two hand-copied literals, which is how the loop-82 knob came to be missing
    /// from one of them in the first place.
    #[test]
    fn the_attended_lab_flags_mock_every_actuating_control() {
        let redeemed = redeemed_with_floor(false);
        let build = |log_input, synthetic| {
            attend_session_options(
                &redeemed,
                Arc::new(NoopSink),
                PathBuf::from(crate::config::DEFAULT_TRANSFER_DIR),
                BackstageAuth::Deny,
                None,
                None,
                log_input,
                synthetic,
            )
        };
        for (log_input, synthetic) in [(true, false), (false, true), (true, true)] {
            let o = build(log_input, synthetic);
            assert!(o.mock_reboot && o.mock_launch && o.mock_command && o.mock_lock && o.mock_logoff,
                "log_input={log_input} synthetic={synthetic}: an actuating control was left REAL, so a                  gate run could reboot or lock the machine running it");
            assert_eq!(o.mock_input, log_input,
                "log_input={log_input} synthetic={synthetic}: mock_input must follow --log-input alone");
        }
        let prod = build(false, false);
        assert!(!prod.mock_input && !prod.mock_reboot && !prod.mock_lock,
            "a production attended session mocked its controls — nothing would actually happen");
    }

    /// A `rmt://` link is attacker-supplied input that arrives with a click, so the ONE thing a
    /// link launch must never be able to do is skip the consent prompt.
    ///
    /// `RMT_ATTEND_AUTO_CONSENT=1` is set here deliberately: a version of this test that merely
    /// asserted `!auto_consent` on a clean environment would pass just as happily against a
    /// `uri_command` that read the variable — it would be proving the machine's environment, not
    /// the code. (The variable is restored, and no other test in this crate reads it.)
    /// docs/48 C slice 4: a generic Support only proceeds when the server's redeem answer names the
    /// signaling URL and grant key its deployment pass pins. Exact equality, both fields.
    #[test]
    fn a_pass_binding_matches_only_the_server_the_pass_names() {
        let binding = PassBinding {
            signaling_url: "wss://remote.example.com/ws".into(),
            grant_issuer_pubkey: "ab".repeat(32),
            issued_to: "Example MSP".into(),
        };
        let redeem = |sig: &str, key: Option<String>| crate::attend::AttendRedeem {
            device_id: "d".into(),
            tenant_id: "t".into(),
            signaling_url: sig.into(),
            attend_token: "a".into(),
            grant_issuer_pubkey: key,
            require_session_policy: true,
            reason: None,
        };
        assert!(binding.matches(&redeem("wss://remote.example.com/ws", Some("ab".repeat(32)))));
        for (sig, key) in [
            ("wss://evil.example/ws", Some("ab".repeat(32))),
            ("wss://remote.example.com:8443/ws", Some("ab".repeat(32))),
            ("wss://remote.example.com/ws", Some("cd".repeat(32))),
            ("wss://remote.example.com/ws", Some("AB".repeat(32))),
            ("wss://remote.example.com/ws", None),
        ] {
            assert!(!binding.matches(&redeem(sig, key.clone())), "{sig} / {key:?} matched");
        }
    }

    #[test]
    fn a_link_launch_can_never_bypass_the_consent_prompt() {
        let previous = std::env::var("RMT_ATTEND_AUTO_CONSENT").ok();
        std::env::set_var("RMT_ATTEND_AUTO_CONSENT", "1");

        let params = attend_params_from_uri(crate::uri::AttendUri {
            code: "ABCD1234WXYZ9".to_string(),
            control_plane_url: "https://cp.example.com".to_string(),
            reason: "Acme IT".to_string(),
        });

        match previous {
            Some(v) => std::env::set_var("RMT_ATTEND_AUTO_CONSENT", v),
            None => std::env::remove_var("RMT_ATTEND_AUTO_CONSENT"),
        }

        assert!(!params.auto_consent, "a clicked link must always face the consent prompt");
        // The link carries the session's identity and nothing else — no test instrumentation, and
        // in particular no signaling override that would point the guest's media elsewhere.
        assert!(!params.synthetic);
        assert!(!params.log_input);
        assert_eq!(params.signaling_override, None);
        assert_eq!(params.code, "ABCD1234WXYZ9");
        assert_eq!(params.base, "https://cp.example.com");
        // A link must NOT be able to leave a permanent install behind, and runs the console UX with
        // the default disk root (never a per-run root it did not create).
        assert!(!params.allow_promote, "a clicked link must never promote to a permanent install");
        assert_eq!(params.ux, AttendUx::Console);
        assert_eq!(params.transfer_root, None);
    }

    /// `enroll` must NOT short-circuit as "already enrolled" when the config names a device but the
    /// identity key is missing — that half-enrolled state must re-enroll, or the agent is stranded
    /// unauthenticated forever (the trap hit installing the first real agent).
    #[test]
    fn enroll_skips_only_when_device_and_key_both_present_and_not_forced() {
        assert!(enroll_already_done(true, true, false), "fully enrolled -> skip");
        // THE BUG: a device id in config with no key on disk previously no-op'd; now it re-enrolls.
        assert!(!enroll_already_done(true, false, false), "device id but NO key -> must re-enroll");
        assert!(!enroll_already_done(true, true, true), "--force -> re-enroll even if fully enrolled");
        assert!(!enroll_already_done(false, false, false), "no device id -> enroll");
        assert!(!enroll_already_done(false, true, false), "no device id (stray key) -> enroll");
    }

    /// The `attend` command line is the ONE path allowed to promote to a permanent install, and it
    /// runs the console UX. This is the positive control paired with the link test above: if the
    /// two agreed on `allow_promote`, neither would be proving anything.
    #[test]
    fn the_attend_command_line_may_promote_and_runs_the_console_ux() {
        let args: Vec<String> = ["--control-plane-url", "https://cp.example.com", "--code", "ABCD1234WXYZ9"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let params = attend_params_from_args(&args).expect("valid attend args");
        assert!(params.allow_promote, "the attend command line is the one path that may promote");
        assert_eq!(params.ux, AttendUx::Console);
        assert_eq!(params.transfer_root, None, "console defaults its disk, never a per-run root");
        // A missing required argument returns an exit code, not params.
        assert_eq!(attend_params_from_args(&[]), Err(2));
    }

    /// Mint a signed grant blob exactly as the control plane does, so these tests exercise the real
    /// `dispatcher_from_signed_grant` entry point rather than a stand-in for it.
    fn signed_grant(
        issuer: &rmt_crypto::Identity,
        machine_id: uuid::Uuid,
        now_ms: i64,
        ttl_ms: i64,
    ) -> (String, uuid::Uuid, uuid::Uuid) {
        let technician_id = uuid::Uuid::new_v4();
        let session_id = uuid::Uuid::new_v4();
        let claims = GrantClaims {
            grant: Grant {
                technician_id,
                session_id,
                machine_id,
                capabilities: vec![Capability::SystemInfoRead],
            },
            issued_at_ms: now_ms - 1_000,
            expires_at_ms: now_ms + ttl_ms,
        };
        (
            claims.sign(issuer).to_json().expect("serialize"),
            technician_id,
            session_id,
        )
    }

    /// A signed grant is a bearer credential: the same blob presented twice used to install twice,
    /// so a grant captured from a log or a compromised console could be replayed onto the machine
    /// for the rest of its TTL. It is now single-use.
    #[test]
    fn security_grant_is_bound_to_live_session_and_technician() {
        let issuer = rmt_crypto::Identity::generate();
        let (blob, technician, session) = signed_grant(&issuer, uuid::Uuid::new_v4(), 1_700_000_000_000, 300_000);
        assert!(grant_matches_live_session(&blob, Some(session), Some(technician)).is_ok());
        assert!(grant_matches_live_session(&blob, Some(uuid::Uuid::new_v4()), Some(technician)).is_err());
        assert!(grant_matches_live_session(&blob, Some(session), Some(uuid::Uuid::new_v4())).is_err());
        assert!(grant_matches_live_session(&blob, None, Some(technician)).is_err());
    }

    #[test]
    fn a_signed_grant_installs_once_and_a_replay_is_refused() {
        let issuer = rmt_crypto::Identity::generate();
        let machine = uuid::Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        let (blob, _, _) = signed_grant(&issuer, machine, now, 5 * 60_000);
        let spent = SpentGrants::default();

        assert!(
            dispatcher_from_signed_grant(&blob, &issuer.public(), now, machine, &spent, test_chain()).is_ok(),
            "the first install of a valid grant must succeed"
        );
        let err = match dispatcher_from_signed_grant(&blob, &issuer.public(), now, machine, &spent, test_chain()) {
            Err(e) => e,
            Ok(_) => panic!("a replay of the same grant must be refused"),
        };
        assert!(
            err.contains("single use"),
            "and refused for THAT reason, not incidentally: got {err:?}"
        );
    }

    /// The ledger must not become a denial-of-service against the technician. A forged or
    /// wrong-machine blob naming a real `(technician, session)` pair must NOT burn it — which is
    /// why the claim happens strictly after verification.
    #[test]
    fn a_grant_that_fails_verification_does_not_burn_its_identity() {
        let issuer = rmt_crypto::Identity::generate();
        let attacker = rmt_crypto::Identity::generate();
        let machine = uuid::Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        let (blob, technician_id, session_id) = signed_grant(&issuer, machine, now, 5 * 60_000);
        let spent = SpentGrants::default();

        // Same claims, signed by the wrong key: rejected, and must leave no trace.
        let forged = {
            let signed = SignedGrant::from_json(&blob).expect("decode");
            signed.claims.sign(&attacker).to_json().expect("serialize")
        };
        assert!(
            dispatcher_from_signed_grant(&forged, &issuer.public(), now, machine, &spent, test_chain()).is_err(),
            "a forgery must be rejected"
        );
        // The genuine grant naming the SAME pair must still work.
        let ok = dispatcher_from_signed_grant(&blob, &issuer.public(), now, machine, &spent, test_chain());
        assert!(
            ok.is_ok(),
            "a forgery must not pre-burn the identity of the grant it impersonates: {:?}",
            ok.err()
        );
        // Sanity: the pair really is the one the forgery named.
        assert_eq!(
            SignedGrant::from_json(&forged).expect("decode").claims.grant.technician_id,
            technician_id
        );
        assert_eq!(
            SignedGrant::from_json(&forged).expect("decode").claims.grant.session_id,
            session_id
        );
    }

    /// Distinct grants are independent — the ledger must key on the grant, not merely "have I seen
    /// any grant". Without this, the first install of a session would lock out every later one.
    #[test]
    fn a_different_grant_is_unaffected_by_a_spent_one() {
        let issuer = rmt_crypto::Identity::generate();
        let machine = uuid::Uuid::new_v4();
        let now = 1_700_000_000_000i64;
        let (first, _, _) = signed_grant(&issuer, machine, now, 5 * 60_000);
        let (second, _, _) = signed_grant(&issuer, machine, now, 5 * 60_000);
        let spent = SpentGrants::default();

        assert!(dispatcher_from_signed_grant(&first, &issuer.public(), now, machine, &spent, test_chain()).is_ok());
        assert!(
            dispatcher_from_signed_grant(&second, &issuer.public(), now, machine, &spent, test_chain()).is_ok(),
            "a second, distinct grant must still install"
        );
    }

    #[test]
    fn security_fresh_grant_renews_same_session_but_old_token_stays_spent() {
        let issuer = rmt_crypto::Identity::generate();
        let machine = uuid::Uuid::new_v4();
        let now = 1_700_000_000_000;
        let (first, _, _) = signed_grant(&issuer, machine, now, 300_000);
        let mut claims = SignedGrant::from_json(&first).unwrap().claims;
        claims.issued_at_ms += 1;
        claims.expires_at_ms += 1;
        let renewal = claims.sign(&issuer).to_json().unwrap();
        let spent = SpentGrants::default();
        assert!(dispatcher_from_signed_grant(&first, &issuer.public(), now + 1, machine, &spent, test_chain()).is_ok());
        assert!(dispatcher_from_signed_grant(&renewal, &issuer.public(), now + 1, machine, &spent, test_chain()).is_ok());
        assert!(dispatcher_from_signed_grant(&first, &issuer.public(), now + 1, machine, &spent, test_chain()).is_err());
        let mut alternate = SignedGrant::from_json(&renewal).unwrap();
        alternate.sig = alternate.sig.to_uppercase();
        assert!(dispatcher_from_signed_grant(&alternate.to_json().unwrap(), &issuer.public(), now + 1, machine, &spent, test_chain()).is_err());
    }

    /// The ledger is bounded by the grants' own TTLs, with no sweeper thread: an entry is pruned
    /// once `now` passes its expiry. Asserted through `claim` directly because the shipped path
    /// cannot reach it — `verify` rejects an expired grant first, which is exactly right, and means
    /// the pruning would otherwise be untested code.
    #[test]
    fn the_ledger_prunes_entries_once_their_grants_expire() {
        let spent = SpentGrants::default();
        let key = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let expires = 1_000i64;
        assert!(spent.claim(key, expires, 0), "first claim wins");
        assert!(!spent.claim(key, expires, 999), "still spent just before expiry");
        assert!(
            spent.claim(key, expires + 1_000, 1_001),
            "after expiry the entry is gone, so the map cannot grow without bound"
        );
        assert_eq!(
            spent.seen.lock().unwrap().len(),
            1,
            "and the expired entry did not linger alongside the new one"
        );
    }

    struct NullSigner;
    impl ChallengeSigner for NullSigner {
        fn sign(&self, _preimage: &[u8]) -> [u8; 64] {
            [0u8; 64]
        }
    }

    /// The identity→Role wiring of the machine.os refresh: BOTH branches announce this machine's
    /// own `os_description()`. The premise is asserted first — on any real Windows host the
    /// description is non-empty; if it ever were empty, `os` maps to `None` on both sides and an
    /// equality against it would hold vacuously, which is exactly the hidden-skip shape this tree
    /// refuses.
    #[test]
    fn the_agent_role_announces_this_machines_os_and_floor_flag_on_both_branches() {
        let expected = crate::enroll::os_description();
        assert!(
            !expected.is_empty(),
            "premise not met: os_description() is empty on this host, so 'announced' and \
             'not announced' would be indistinguishable below"
        );

        let device = DeviceId::new();
        // Capture the logged-in user once so we can assert both branches produce the same result.
        let expected_user = query_logged_in_user();

        match agent_role(device, None, true) {
            Role::Agent { os, signer, require_session_policy, agent_version, logged_in_user, .. } => {
                assert_eq!(os.as_deref(), Some(expected.as_str()), "the dev branch announces the os");
                assert!(signer.is_none(), "no identity ⇒ no signer");
                assert!(require_session_policy, "the dev branch announces the floor flag");
                assert_eq!(
                    agent_version.as_deref(),
                    Some(rmt_agent_core::version::AGENT_VERSION),
                    "the dev branch announces the build identity"
                );
                assert_eq!(
                    logged_in_user, expected_user,
                    "the dev branch forwards the logged-in user from query_logged_in_user"
                );
            }
            _ => panic!("agent_role must build an Agent role"),
        }

        let ident = AgentIdentity {
            pubkey: "aa".repeat(32),
            tenant_id: Some("t-1".into()),
            signer: Arc::new(NullSigner),
        };
        match agent_role(device, Some(ident), true) {
            Role::Agent { os, pubkey, tenant, signer, require_session_policy, agent_version, logged_in_user, .. } => {
                assert_eq!(os.as_deref(), Some(expected.as_str()), "the enrolled branch announces the os");
                assert_eq!(
                    agent_version.as_deref(),
                    Some(rmt_agent_core::version::AGENT_VERSION),
                    "the enrolled branch announces the build identity"
                );
                assert_eq!(
                    logged_in_user, expected_user,
                    "the enrolled branch forwards the logged-in user from query_logged_in_user"
                );
                assert_eq!(pubkey, "aa".repeat(32));
                assert_eq!(tenant.as_deref(), Some("t-1"));
                assert!(signer.is_some(), "the enrolled branch keeps its signer");
                assert!(require_session_policy, "the enrolled branch announces the floor flag");
            }
            _ => panic!("agent_role must build an Agent role"),
        }

        // FALSE must be carried through just as faithfully. A role that hard-coded `true` — or that
        // dropped the argument and defaulted — would pass both assertions above while making it
        // impossible for an operator to ever turn the floor back OFF.
        match agent_role(device, None, false) {
            Role::Agent { require_session_policy, .. } => {
                assert!(!require_session_policy, "a cleared flag must stay cleared");
            }
            _ => panic!("agent_role must build an Agent role"),
        }

        // agent_role alone must NOT claim multi_session_capable. The flag is only added by
        // run_multi_session_stream (the mux registration path) AFTER calling agent_role, because:
        //
        //   - The CLI `stream` subcommand calls serve_session_with_ice directly (single session).
        //   - The attended path calls serve_session_with_ice directly (single session).
        //   - Both paths use agent_role → connect_with_ice; neither runs a SignalingMux loop.
        //
        // Advertising Some(true) from those paths would let the viewer show an "Invite technician"
        // button for a device that cannot serve the second session. The mux override in
        // run_multi_session_stream is the single source of truth for the flag.
        match agent_role(device, None, true) {
            Role::Agent { multi_session_capable, .. } => {
                assert_eq!(
                    multi_session_capable,
                    None,
                    "agent_role alone must NOT advertise multi_session_capable; \
                     only run_multi_session_stream sets it to Some(true) after calling this \
                     function: got {:?}",
                    multi_session_capable
                );
            }
            _ => panic!("agent_role must build an Agent role"),
        }
        match agent_role(device, Some(AgentIdentity {
            pubkey: "aa".repeat(32),
            tenant_id: Some("t-1".into()),
            signer: Arc::new(NullSigner),
        }), true) {
            Role::Agent { multi_session_capable, .. } => {
                assert_eq!(
                    multi_session_capable,
                    None,
                    "enrolled agent_role alone must also NOT advertise multi_session_capable: \
                     got {:?}",
                    multi_session_capable
                );
            }
            _ => panic!("agent_role must build an Agent role"),
        }
        // Simulate the run_multi_session_stream role construction: agent_role output with the
        // mux flag override applied. This is what the SYSTEM helper service actually sends to
        // the signaling server, and it must be Some(true).
        {
            let mut mux_role = agent_role(device, None, false);
            if let Role::Agent { ref mut multi_session_capable, .. } = mux_role {
                *multi_session_capable = Some(true);
            }
            match mux_role {
                Role::Agent { multi_session_capable, .. } => {
                    assert_eq!(
                        multi_session_capable,
                        Some(true),
                        "mux registration role must advertise multi_session_capable=Some(true)"
                    );
                }
                _ => panic!("mux_role must be an Agent role"),
            }
        }
    }

    /// A session that pulls slower than the shared capture produces (the 5 fps "Text" preset or
    /// 1 fps against 30 fps canvas capture) falls more than FRAME_BROADCAST_CAP frames behind
    /// between pulls. It must get the NEWEST frame, not a lag error (which backed off a whole
    /// interval and lagged again: a frozen picture) and not the oldest buffered frame.
    #[test]
    fn a_slow_session_gets_the_newest_frame_not_a_lag_error() {
        use crate::shared_capture::{SelectionState, TaggedFrame, VersionedSnapshot};
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (tx, rx) = tokio::sync::broadcast::channel::<Arc<TaggedFrame>>(crate::shared_capture::FRAME_BROADCAST_CAP);
        let snap = Arc::new(VersionedSnapshot { generation: 0, topology: None });
        let mut capturer = BroadcastCapturer::new(rx, Arc::clone(&snap), rt.handle().clone(),
            Arc::new(Mutex::new(snap)), Arc::new(Mutex::new(SelectionState { monitor: 0, generation: 0 })));
        let frame = |n: u8| Arc::new(TaggedFrame {
            frame: CapturedFrame { monitor_id: 0, width: 1, height: 1, bytes: vec![n; 4], is_keyframe: false },
            selection_gen: 0,
        });
        // Fell behind by more than the buffer (6 frames at 30 fps = one 5 fps interval).
        for n in 1..=6 { tx.send(frame(n)).unwrap(); }
        let got = capturer.capture_frame(0).expect("a lagged slow session must still get a frame");
        assert_eq!(got.bytes[0], 6, "the newest frame, not an old buffered one");
        // Behind, but within the buffer: still the newest.
        for n in 7..=9 { tx.send(frame(n)).unwrap(); }
        assert_eq!(capturer.capture_frame(0).unwrap().bytes[0], 9);
    }

    /// The session's frame-rate hint reaches the shared producer's demand slot.
    #[test]
    fn a_broadcast_capturer_passes_its_session_rate_to_the_shared_producer() {
        use crate::shared_capture::{SelectionState, VersionedSnapshot};
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (_tx, rx) = tokio::sync::broadcast::channel(4);
        let snap = Arc::new(VersionedSnapshot { generation: 0, topology: None });
        let slot = Arc::new(std::sync::atomic::AtomicU32::new(30));
        let mut c = BroadcastCapturer::new(rx, Arc::clone(&snap), rt.handle().clone(),
            Arc::new(Mutex::new(snap)), Arc::new(Mutex::new(SelectionState { monitor: 0, generation: 0 })))
            .with_fps_demand(Arc::clone(&slot));
        c.set_frame_rate_hint(5);
        assert_eq!(slot.load(std::sync::atomic::Ordering::Relaxed), 5);
    }

    /// A hidden viewer's session runs at BACKGROUND_FPS, never faster than the operator's own rate,
    /// and returns to that rate unchanged.
    #[test]
    fn a_background_session_paces_at_one_frame_a_second() {
        assert_eq!(session_fps(30, true), BACKGROUND_FPS);
        assert_eq!(session_fps(30, false), 30);
        assert_eq!(session_fps(1, true), 1);
        assert_eq!(session_fps(0, true), 1);
    }

    // ── Pass-11 / pass-10: BroadcastCapturer selection-transition contract ──────────────────────

    /// Stale frame from prior monitor selection is rejected by BroadcastCapturer.
    ///
    /// Simulates: capture thread produced a frame for monitor 0 (selection_gen=0), but by the
    /// time BroadcastCapturer drains the channel, the first SelectMonitor has pinned monitor 1
    /// (generation=1).  A subsequent matching frame must be accepted.  BroadcastCapturer does
    /// NOT touch input_ready — in pinned-display mode input stays unconditionally ready.
    #[test]
    fn broadcast_canvas_forwards_one_frame_and_rejects_layout_substitution() {
        use crate::shared_capture::{SelectionState, TaggedFrame, VersionedSnapshot};
        let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
        let (tx,rx) = tokio::sync::broadcast::channel(8);
        let mons = vec![
            MonitorInfo {id:0,left:-2,top:0,width:2,height:2,dpi_scale:1.0},
            MonitorInfo {id:1,left:0,top:-1,width:2,height:3,dpi_scale:1.0}];
        let snap = Arc::new(VersionedSnapshot {generation:0,topology:Some(rmt_agent_core::TopologySnapshot {
            monitors:mons,names:vec!["left".into(),"primary".into()]})});
        let mut capturer = BroadcastCapturer::new(rx,Arc::clone(&snap),rt.handle().clone(),
            Arc::new(Mutex::new(snap)),Arc::new(Mutex::new(SelectionState {monitor:COMPOSITE_MONITOR_ID,generation:1})));
        let frame = CapturedFrame {monitor_id:COMPOSITE_MONITOR_ID,width:4,height:3,bytes:vec![21;48],is_keyframe:true};
        tx.send(Arc::new(TaggedFrame {frame:frame.clone(),selection_gen:1})).unwrap();
        assert_eq!(capturer.capture_composite().unwrap(),frame);
        tx.send(Arc::new(TaggedFrame {frame:CapturedFrame {width:2,..frame},selection_gen:1})).unwrap();
        assert!(capturer.capture_composite().is_err());
    }

    #[test]
    fn broadcast_capturer_rejects_stale_frame_after_monitor_switch() {
        use crate::shared_capture::{SelectionState, TaggedFrame, VersionedSnapshot};

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = rt.handle().clone();

        let (frame_tx, rx) = tokio::sync::broadcast::channel::<Arc<TaggedFrame>>(8);
        let selection_state = Arc::new(Mutex::new(SelectionState { monitor: 0, generation: 0 }));
        let initial_snap = Arc::new(VersionedSnapshot { generation: 0, topology: None });
        let live_published = Arc::new(Mutex::new(Arc::clone(&initial_snap)));

        let mut capturer = BroadcastCapturer::new(
            rx,
            Arc::clone(&initial_snap),
            handle,
            Arc::clone(&live_published),
            Arc::clone(&selection_state),
        );

        // Simulate the first SelectMonitor pinning monitor 1: gen=1.
        {
            let mut s = selection_state.lock().unwrap();
            s.monitor = 1;
            s.generation = 1;
        }

        // Stale frame: produced for monitor 0 (gen=0) before the pin, arrived after.
        let stale = Arc::new(TaggedFrame {
            frame: CapturedFrame {
                monitor_id: 0,
                width: 1,
                height: 1,
                bytes: vec![10, 0, 0, 255],
                is_keyframe: false,
            },
            selection_gen: 0,
        });
        frame_tx.send(stale).unwrap();

        let r = capturer.capture_frame(0);
        assert!(r.is_err(), "stale frame (gen=0 vs pinned gen=1) must be rejected; got Ok");

        // Matching frame for the pinned selection (gen=1, monitor_id=1).
        let fresh = Arc::new(TaggedFrame {
            frame: CapturedFrame {
                monitor_id: 1,
                width: 1,
                height: 1,
                bytes: vec![20, 0, 0, 255],
                is_keyframe: false,
            },
            selection_gen: 1,
        });
        frame_tx.send(fresh).unwrap();

        let r = capturer.capture_frame(0);
        assert!(r.is_ok(), "matching frame (gen=1, monitor=1) must be accepted; got {:?}", r.err());
    }

    /// A→B→A cycle: stale first-A frame is rejected even when the selected monitor returned to A,
    /// because `selection_gen` distinguishes the two A epochs.
    ///
    /// A monitor_id-only filter would accept the stale frame (monitor_id=0 == current=0),
    /// silently applying input against an unseen frame.  The generation counter closes this gap.
    #[test]
    fn broadcast_capturer_rejects_stale_aba_frame_by_generation() {
        use crate::shared_capture::{SelectionState, TaggedFrame, VersionedSnapshot};

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let handle = rt.handle().clone();

        let (frame_tx, rx) = tokio::sync::broadcast::channel::<Arc<TaggedFrame>>(8);
        let selection_state = Arc::new(Mutex::new(SelectionState { monitor: 0, generation: 0 }));
        let initial_snap = Arc::new(VersionedSnapshot { generation: 0, topology: None });
        let live_published = Arc::new(Mutex::new(Arc::clone(&initial_snap)));

        let mut capturer = BroadcastCapturer::new(
            rx,
            Arc::clone(&initial_snap),
            handle,
            Arc::clone(&live_published),
            Arc::clone(&selection_state),
        );

        // Simulate gen=2, monitor=0 (two write_selection calls: A→B→A).
        {
            let mut s = selection_state.lock().unwrap();
            s.monitor = 0;
            s.generation = 2;
        }

        // Stale first-A frame: monitor_id=0 matches current=0, but selection_gen=0 != 2.
        let stale_a = Arc::new(TaggedFrame {
            frame: CapturedFrame {
                monitor_id: 0,
                width: 1,
                height: 1,
                bytes: vec![30, 0, 0, 255],
                is_keyframe: false,
            },
            selection_gen: 0,
        });
        frame_tx.send(stale_a).unwrap();

        let r = capturer.capture_frame(0);
        assert!(
            r.is_err(),
            "ABA stale frame (gen=0, monitor=0) must be rejected; generation counter prevents \
             the false accept that a monitor_id-only filter would make"
        );

        // Fresh A frame from the second A epoch (gen=2, monitor_id=0): must be accepted.
        let fresh_a = Arc::new(TaggedFrame {
            frame: CapturedFrame {
                monitor_id: 0,
                width: 1,
                height: 1,
                bytes: vec![40, 0, 0, 255],
                is_keyframe: false,
            },
            selection_gen: 2,
        });
        frame_tx.send(fresh_a).unwrap();

        let r = capturer.capture_frame(0);
        assert!(r.is_ok(), "fresh A frame (gen=2) must be accepted; got {:?}", r.err());
    }
}

#[cfg(test)]
mod indicator_floor_tests {
    use super::*;

    #[test]
    fn a_requested_guest_window_that_did_not_open_holds_the_session_view_only() {
        assert!(no_indicator_floor(true, false));
        assert!(!no_indicator_floor(true, true));
        assert!(!no_indicator_floor(false, false), "no window asked for (tests, mock actions): no floor");
    }

    #[test]
    fn the_floor_is_applied_before_the_access_state_is_built_and_coverage_loss_is_polled() {
        let src = include_str!("host.rs");
        let floor = src.find(concat!("let observer = observer || indicator_", "missing;")).expect("the floor feeds observer");
        let access = src.find(concat!("SessionAccessState::new_", "observer(require_session_policy)")).expect("access state");
        assert!(floor < access, "the indicator floor must be decided before the access state reads `observer`");
        assert!(src.contains(concat!("if screen_blanker.take_coverage_", "lost() {")), "the session must poll for lost privacy coverage");
    }
}

#[cfg(test)]
mod typing_cancel_wiring_tests {
    #[test]
    fn a_closed_gate_drops_presses_and_passes_releases() {
        use rmt_agent_core::platform::InputSink as _;
        #[derive(Default)]
        struct Rec(std::sync::Mutex<Vec<String>>);
        impl rmt_agent_core::platform::InputSink for Rec {
            fn inject(&self, e: rmt_agent_core::InputEvent) -> rmt_agent_core::platform::PlatformResult<()> {
                self.0.lock().unwrap().push(format!("{e:?}"));
                Ok(())
            }
        }
        let rec = std::sync::Arc::new(Rec::default());
        let g = super::GatedSink::new(rec.clone());
        g.set_admitted(false);
        let _ = g.inject(rmt_agent_core::InputEvent::Key { code: 65, down: true });
        let _ = g.inject(rmt_agent_core::InputEvent::Text("x".into()));
        let _ = g.inject(rmt_agent_core::InputEvent::Key { code: 65, down: false });
        g.set_admitted(true);
        let _ = g.inject(rmt_agent_core::InputEvent::Key { code: 66, down: true });
        let got = rec.0.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "only the release (while closed) and the press after re-admission: {got:?}");
        assert!(got[0].contains("65") && got[0].contains("false"));
        assert!(got[1].contains("66") && got[1].contains("true"));
    }

    /// The host gate's revocation waits for an injection that already passed its check.
    #[test]
    fn the_host_gate_fences_revocation_against_an_injection_in_flight() {
        use rmt_agent_core::platform::InputSink as _;
        struct Slow(std::sync::mpsc::Sender<()>, std::sync::Mutex<Option<std::time::Instant>>);
        impl rmt_agent_core::platform::InputSink for Slow {
            fn inject(&self, _e: rmt_agent_core::InputEvent) -> rmt_agent_core::platform::PlatformResult<()> {
                let _ = self.0.send(());
                std::thread::sleep(std::time::Duration::from_millis(200));
                *self.1.lock().unwrap() = Some(std::time::Instant::now()); // still inside the gate's read fence
                Ok(())
            }
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let slow = std::sync::Arc::new(Slow(tx, std::sync::Mutex::new(None)));
        let g = std::sync::Arc::new(super::GatedSink::new(slow.clone()));
        let g2 = std::sync::Arc::clone(&g);
        let injecting = std::thread::spawn(move || { let _ = g2.inject(rmt_agent_core::InputEvent::Key { code: 65, down: true }); });
        rx.recv().unwrap(); // inside the inner inject, past the check
        g.set_admitted(false);
        let revoked_at = std::time::Instant::now();
        injecting.join().unwrap();
        let injected_at = slow.1.lock().unwrap().expect("the inject finished");
        assert!(revoked_at >= injected_at, "revocation returned while a press was still being injected");
    }

    /// Codex 1.3.9 round 14: the session queue's press from before a revocation stays dead after
    /// re-admission; its RELEASE still passes; a press queued after re-admission lands.
    #[test]
    fn the_host_gate_rejects_presses_queued_before_a_revocation_even_after_readmission() {
        #[derive(Default)]
        struct Rec(std::sync::Mutex<Vec<String>>);
        impl rmt_agent_core::platform::InputSink for Rec {
            fn inject(&self, e: rmt_agent_core::InputEvent) -> rmt_agent_core::platform::PlatformResult<()> {
                self.0.lock().unwrap().push(format!("{e:?}"));
                Ok(())
            }
        }
        use rmt_agent_core::platform::InputSink as _;
        let rec = std::sync::Arc::new(Rec::default());
        let g = super::GatedSink::new(rec.clone());
        let queued = g.epoch(); // queued now...
        g.set_admitted(false); // ...then revoked...
        g.set_admitted(true); // ...and re-admitted before the capture thread drained it
        let _ = g.inject_stamped(rmt_agent_core::InputEvent::Key { code: 65, down: true }, queued);
        let _ = g.inject_stamped(rmt_agent_core::InputEvent::Key { code: 65, down: false }, queued);
        let _ = g.inject_stamped(rmt_agent_core::InputEvent::Key { code: 66, down: true }, g.epoch());
        let got = rec.0.lock().unwrap().clone();
        assert_eq!(got.len(), 2, "only the old RELEASE and the new press: {got:?}");
        assert!(got[0].contains("65") && got[0].contains("false"));
        assert!(got[1].contains("66") && got[1].contains("true"));
    }

    #[test]
    fn revocation_cancels_typing_before_taking_the_fences() {
        let src = include_str!("host.rs");
        let f = src.find(concat!("async fn set_input_", "admitted(")).expect("set_input_admitted");
        let body = &src[f..f + 1200];
        let cancel = body.find(concat!("s.cancel_typing", "(false);")).expect("an early cancel");
        let fence = body.find(concat!("s.set_admitted", "(admitted);")).expect("the fences");
        assert!(cancel < fence, "typing must be cancelled before the write fences are taken");
    }

    #[test]
    fn teardown_stops_input_before_anything_else() {
        let src = include_str!("host.rs");
        let tail = src.find(concat!("let end_reason = end_reason.unwrap_or_else(|| classify_unattributed_", "end(")).expect("teardown");
        let body = &src[tail..];
        let revoke = body.find(concat!("set_input_", "admitted(&sink, false).await;")).expect("teardown revokes input");
        let stop = body.find(concat!("session_stop.store(true, ", "Ordering::Relaxed);")).expect("teardown stop");
        assert!(revoke < stop, "input must be revoked before the session winds down");
        // docs/58 (Codex phase B review): the mutation gate is revoked before the FIRST teardown
        // await, so nothing queued is admitted while the input fence is pending.
        let gate = body.find(concat!("mutation_gate.", "revoke();")).expect("teardown revokes the gate");
        assert!(gate < revoke, "the mutation gate must be revoked before the input fence is awaited");
    }

    #[test]
    fn view_only_and_a_lost_indicator_stop_typing() {
        let src = include_str!("host.rs");
        let toggle = src.find(concat!("view_only = access_state.set_toggle(enabled) || indicator_", "lost;")).expect("SetViewOnly folds in the indicator floor");
        assert!(src[toggle..toggle + 400].contains(concat!("set_input_", "admitted(&sink, !view_only)")), "SetViewOnly must close the input gate");
        let arm = src.find(concat!("Some(GuestToHost::Indicator", "Visible(visible)) => {")).expect("the host handles indicator visibility");
        assert!(src[arm..arm + 600].contains(concat!("set_input_", "admitted(&sink, !view_only)")), "a lost indicator must close the input gate");
        let end = src.find(concat!("Some(GuestToHost::", "End) => {")).expect("the End arm");
        let body = &src[end..end + 900];
        let gate = body.find(concat!("set_input_", "admitted(&sink, false).await")).expect("End closes the input gate");
        let ended = body.find(concat!("s.end", "ed();")).expect("End shows ENDED");
        assert!(gate < ended, "input must stop BEFORE the indicator comes down");
        assert_eq!(src.matches(concat!("view_only = access_state.view_only() || indicator_", "lost;")).count(), 4,
            "every recompute (3 policy sites + the indicator arm) keeps the indicator floor");
    }
}

#[cfg(test)]
mod route_file_transfer_tests {
    use super::*;

    /// docs/58 §12 (Codex phase B review): a repeated Offer id is refused at the loop, and the running
    /// upload keeps its flag (so the loop can still cancel it) and never reaches the writer twice.
    #[test]
    fn a_repeated_offer_keeps_the_running_uploads_flag() {
        let dir = std::env::temp_dir().join(format!("rmt-route-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let chain = rmt_agent::backstage::audit::new_shared_chain(Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let gate = Arc::new(rmt_agent::backstage::gate::MutationGate::new());
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let writer = crate::upload_writer::UploadWriter::spawn(
            chain.clone(),
            Arc::new(crate::upload_writer::Ledger::default()),
            crate::upload_root::LazyRoot::new(dir.clone(), false),
            Arc::new(std::sync::Mutex::new(None)),
            Arc::clone(&gate),
            tx,
            || 1,
        );
        let mut live = HashMap::new();
        let id = Uuid::new_v4();
        let offer = |name: &str| FtMessage::Offer(Offer { id, name: name.into(), size: 3, sha256: file_transfer::sha256_hex(b"abc") });
        let first = route_file_transfer(&chain, offer("a.txt"), &writer, &mut live, gate.stamp(), &dir, None, 1);
        assert!(first.is_empty(), "the first Offer goes to the writer");
        let original = Arc::clone(&live[&id].0);
        let again = route_file_transfer(&chain, offer("b.txt"), &writer, &mut live, gate.stamp(), &dir, None, 1);
        assert!(
            again.iter().any(|f| matches!(f, FtMessage::Error { message, .. } if message.contains("repeats an active id"))),
            "{again:?}"
        );
        assert!(Arc::ptr_eq(&live[&id].0, &original), "the running upload keeps its flag");
        assert_eq!(live[&id].1, "a.txt");
    }
}

#[cfg(test)]
mod indicator_lost_file_transfer_tests {
    use super::{backstage_features, posture_features, indicator_lost_file_transfer_refusal};
    use rmt_agent_core::file_transfer::{Chunk, Message as FtMessage, Offer};
    use uuid::Uuid;

    /// docs/58 §1: with the indicator gone, no file reaches or leaves the machine, and each refusal
    /// answers the transfer it refuses (by id), so the console can say so.
    #[test]
    fn offers_and_downloads_are_refused_by_id_and_stray_frames_dropped() {
        let id = Uuid::new_v4();
        let offer = FtMessage::Offer(Offer { id, name: "a.bin".into(), size: 1, sha256: "00".repeat(32) });
        match indicator_lost_file_transfer_refusal(&offer).as_deref() {
            Some([FtMessage::Error { id: rid, message }]) => {
                assert_eq!(*rid, id);
                assert!(message.contains("indicator"));
            }
            other => panic!("offer: {other:?}"),
        }
        let download = FtMessage::Request { id, path: "a.bin".into() };
        assert!(matches!(indicator_lost_file_transfer_refusal(&download).as_deref(), Some([FtMessage::Error { .. }])));
        for stray in [FtMessage::Chunk(Chunk { id, seq: 0, data: vec![1] }), FtMessage::Done { id }] {
            assert_eq!(indicator_lost_file_transfer_refusal(&stray), Some(Vec::new()));
        }
        // Agent-bound control replies are not transfers to refuse.
        assert_eq!(indicator_lost_file_transfer_refusal(&FtMessage::Ack { id, ok: true, message: String::new() }), None);
    }

    /// Release review 1.3.17: the indicator rule must apply to EVERY session, observers included, so
    /// it is evaluated BEFORE the observer branch (an observer may download, but not while the guest
    /// cannot see that anyone is connected).
    #[test]
    fn the_indicator_rule_comes_before_the_observer_rule() {
        let src = include_str!("host.rs");
        let at = src.find(concat!("let refused = if !mutation_gate", ".is_open() {")).expect("the gate is checked first");
        let tail = &src[at..at + 400];
        let gate = tail.find(concat!("indicator_lost_file_transfer", "_refusal(&msg)")).expect("indicator refusal");
        let obs = tail.find(concat!("observer_file_transfer", "_refusal(&msg)")).expect("observer refusal");
        assert!(gate < obs);
    }

    /// Audit #9: an agent without a pinned issuer key must say so (posture_v1 without grant_key_pinned).
    #[test]
    fn posture_features_report_the_pin_honestly() {
        assert_eq!(posture_features(false, false), vec!["posture_v1".to_string()]);
        assert_eq!(posture_features(true, false), vec!["posture_v1".to_string(), "grant_key_pinned".to_string()]);
        assert_eq!(posture_features(false, true), vec!["posture_v1".to_string(), "session_policy_required".to_string()]);
        assert_eq!(
            posture_features(true, true),
            vec!["posture_v1".to_string(), "grant_key_pinned".to_string(), "session_policy_required".to_string()]
        );
    }

    /// The console offers exactly what is listed, so the list is part of the protocol; `file_manage`
    /// only with a grant that holds `file_delete`.
    #[test]
    fn file_manage_is_advertised_only_with_the_capability() {
        assert_eq!(backstage_features(true, false), vec!["confirm".to_string(), "file_manage".to_string()]);
        assert_eq!(backstage_features(false, false), vec!["confirm".to_string()]);
        assert_eq!(
            backstage_features(true, true),
            vec!["confirm".to_string(), "file_manage".to_string(), "file_place".to_string()]
        );
        assert_eq!(backstage_features(false, true), vec!["confirm".to_string()], "placement needs file_delete too");
    }
}

#[cfg(test)]
mod input_handoff_tests {
    use super::{hand_outcome_message, handoff_seal_step, HandoffSealStep};
    use rmt_agent::backstage::audit::{new_shared_chain, AuditAction};

    fn handed() -> AuditAction {
        let u = uuid::Uuid::from_u128;
        AuditAction::InputControlHanded { from_session: u(1), from_technician: u(2), to_session: u(3), to_technician: u(4), epoch: 1 }
    }

    fn next_seq(chain: &rmt_agent::backstage::audit::SharedAuditChain) -> u64 {
        // Seal a probe and read its seq: the seq the NEXT event would get before the probe.
        rmt_agent::backstage::audit::try_record_shared(chain, handed(), rmt_agent::backstage::audit::Outcome::Ok, 0)
            .expect("identified chain")
            .seq
    }

    /// Codex 3c review: once input is closed (a known-failed delivery), the arm seals NOTHING — the
    /// chain does not advance, so no event can ever land behind a hole.
    #[test]
    fn a_closed_session_never_seals_behind_a_hole() {
        let chain = new_shared_chain(uuid::Uuid::from_u128(7), uuid::Uuid::from_u128(8), uuid::Uuid::from_u128(9));
        assert!(matches!(handoff_seal_step(false, &chain, handed(), 0), HandoffSealStep::Skip));
        assert_eq!(next_seq(&chain), 0, "a skipped directive advanced the chain");
        // Open: it seals (the probe above took seq 0, so this one is seq 1) and yields a frame.
        assert!(matches!(handoff_seal_step(true, &chain, handed(), 0), HandoffSealStep::Deliver(_)));
        assert_eq!(next_seq(&chain), 2);
    }

    /// An unidentified chain (dev/LAN) seals nothing at all — no hole, no frame.
    #[test]
    fn an_unidentified_chain_seals_nothing() {
        let chain = new_shared_chain(uuid::Uuid::nil(), uuid::Uuid::nil(), uuid::Uuid::from_u128(9));
        assert!(matches!(handoff_seal_step(true, &chain, handed(), 0), HandoffSealStep::Unidentified));
    }
    use crate::input_arbiter::{CommitOutcome, HandRefusal, Member};
    use crate::shared_capture::HandError;

    /// One hand in flight per session; the slot frees when the permit drops (task end, cancel, panic).
    #[test]
    fn a_hand_slot_admits_one_at_a_time() {
        let slot = super::HandSlot::default();
        let first = slot.try_acquire().expect("an idle slot admits");
        for _ in 0..1000 {
            assert!(slot.try_acquire().is_none(), "a flood was admitted while a hand was in flight");
        }
        drop(first);
        let again = slot.try_acquire().expect("the slot frees when the permit drops");
        // A permit moved into a task that is cancelled (dropped) frees the slot too.
        let handle = std::thread::spawn(move || drop(again));
        handle.join().unwrap();
        assert!(slot.try_acquire().is_some());
    }

    /// Only a committed hand is silent (the broadcast Owned snapshot is the ack); every other outcome
    /// tells the requester why, and none of them claims success.
    #[test]
    fn only_a_committed_hand_is_silent() {
        let who = Member { handle: 2, incarnation: 1 };
        assert_eq!(hand_outcome_message(&Ok(CommitOutcome::Owned { who, epoch: 3 })), None);
        let refusals = [
            Ok(CommitOutcome::BlockedTargetGone),
            Ok(CommitOutcome::StaleTransition),
            Err(HandError::FenceAborted),
            Err(HandError::Refused(HandRefusal::NotOwner { owner: who })),
            Err(HandError::Refused(HandRefusal::Busy)),
            Err(HandError::Refused(HandRefusal::SenderNotLive)),
            Err(HandError::Refused(HandRefusal::SenderNotEligible)),
            Err(HandError::Refused(HandRefusal::TargetNotLive)),
            Err(HandError::Refused(HandRefusal::TargetNotEligible)),
            Err(HandError::Refused(HandRefusal::SelfHandMeaningless)),
        ];
        for r in refusals {
            let msg = hand_outcome_message(&r).unwrap_or_else(|| panic!("{r:?} was silent"));
            // The viewer attributes an Error to its pending hand by this prefix (docs/61 stage 3d).
            assert!(msg.starts_with("input control: "), "{msg:?} lacks the attribution prefix");
            assert!(msg.len() > "input control: ".len());
        }
        assert!(hand_outcome_message(&Err(HandError::Refused(HandRefusal::TargetNotEligible)))
            .unwrap()
            .contains("observing"));
    }
}
