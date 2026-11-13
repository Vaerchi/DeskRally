//! `stream_probe` — a standalone WebRTC **controller** for validating the streaming agent on real
//! hardware (M7 VM validation). It reaches an agent by its `DeviceId` through the signaling server,
//! counts inbound VP8 video RTP (proof the agent is capturing + encoding + streaming live), and
//! sends one input event (exercises the controller→agent input path end to end).
//!
//! Not a product surface — a deployable verification tool. Usage:
//! `stream_probe --signaling ws://127.0.0.1:8080/ws --device <uuid> [--secs 8] [--script <steps>]
//! [--ticket <path-to-session-ticket.json>]`
//! Exit 0 if enough RTP arrived, non-zero otherwise, so it scripts cleanly over PowerShell Direct.
//!
//! # `--script` — driving a real interaction
//!
//! `--script` runs a `;`-separated sequence of input steps **before** the RTP collection window,
//! which is what makes the secure-desktop end-to-end check possible: lock the machine, then drive
//! the Winlogon password field and observe whether the box actually unlocks. Injection landing on
//! the secure desktop is otherwise unobservable from the controller side — RTP proves capture, but
//! only a state change on the guest proves *input*.
//!
//! Steps run before collection (rather than concurrently) deliberately: interleaving them would mean
//! cancelling an in-flight `recv_video_rtp()` on every timer tick, and its cancel-safety is not part
//! of the `Transport` contract.
//!
//! | Step | Meaning |
//! |---|---|
//! | `wait:<ms>`     | sleep (let the UI catch up) |
//! | `key:<vk>`      | one Windows **virtual-key** down+up — e.g. `key:13` Enter, `key:32` Space |
//! | `text:<string>` | [`InputEvent::Text`] — injected as Unicode, the paste/IME path |
//! | `move:<x>,<y>`  | absolute pointer move in `0..=65535` |
//! | `click`         | left button down+up at the current position |
//! | `rclick`        | right button down+up at the current position (to test the injected-mouse filter) |
//! | `blank` / `unblank` | `SetMonitorBlanked` on/off (privacy mode), to VM-check what the technician sees |
//! | `sas`           | [`InputEvent::Sas`] — Ctrl+Alt+Del via `SendSAS` (raises the secure desktop) |
//! | `reboot`        | `RebootGuest{safe_mode:false}` — **actually reboots** a real agent (VM check) |
//! | `reboot-safe`   | `RebootGuest{safe_mode:true}` — reboots into **Safe Mode with Networking** |
//! | `tool:<key>`    | `LaunchTool{tool}` — launch a whitelisted admin tool (e.g. `tool:task_manager`) |
//!
//! `key` takes a VIRTUAL-KEY code, not a USB HID usage: `InputSink::inject` forwards
//! `InputEvent::Key` with `by_scancode = false`, so the value lands in `wVk`.
//! A `text:` step cannot contain `;`.
//!
//! # M11 — measuring quality and rate adaptation
//!
//! The quality feature is only real if a *receiver* can see it change, so this tool grew the
//! instrument rather than trusting the agent's own report of itself.
//!
//! | Flag | Meaning |
//! |---|---|
//! | `--rate-window <secs>` | bucket inbound RTP into windows and print one `PROBE RATE:` line each |
//! | `--quality-plan "<sec>:<spec>[;…]"` | send `SetQuality` at the given offsets, e.g. `"0:bps=4000000,adaptive=0;10:bps=400000;20:fps=5"` |
//! | `--inject-loss <sec>:<pct>` | from this offset, write crafted RTCP receiver reports claiming this loss |
//! | `--inject-until <sec>` | stop injecting (so recovery is observable) |
//! | `--inject-ssrc <u32>` | address the injected reports at a BOGUS ssrc — the negative control |
//! | `--report <path.csv>` | write the per-bucket time series |
//!
//! **Four independent observables, one per knob.** Bytes/sec alone cannot separate a bitrate cut
//! from a frame-rate cut from a resolution cut, so each bucket reports all of:
//! payload bytes (the bitrate ceiling), distinct RTP timestamps and their mean delta (the frame
//! rate), and the dimensions read out of the next VP8 keyframe header (the resolution). A run in
//! which only one of them moved when several should have is a *failed* run.
//!
//! **Byte accounting, precisely.** `payload_len` excludes the 12-byte RTP header, extensions, the
//! SRTP auth tag and UDP/IP, so these kbps figures run a few percent below a link-level capture.
//! That is deliberate: payload bytes are what the encoder actually controls, and they are directly
//! comparable with the agent's own `QualityStats.measured_bitrate_bps`. Packet counts are printed
//! too, so `wire_bytes ≈ bytes + pkts × 44` is available if a link-level comparison is wanted.
//!
//! **Why the crafted RTCP is not cheating.** `--inject-loss` writes a real `ReceiverReport` through
//! `pc.write_rtcp`, addressed to the agent's real media SSRC. It travels the interceptor chain,
//! DTLS/SRTP, the wire, the agent's SRTCP demux (which routes by the SSRCs a report block names),
//! and its `RTCRtpSender::read` loop — every layer production code. The only test-only thing about
//! it is who authored the packet, and that is exactly what a browser authors. `--inject-ssrc` is
//! the negative control; note in reading its result that it is satisfied by *either* the SRTP demux
//! or the agent's own per-report-block filter, which is why that filter also has a unit test.

use std::collections::BTreeMap;
use std::time::Duration;

use rmt_agent_core::control::CommandShell;
use rmt_agent_core::quality::{ColorMode, QualitySettings};
use rmt_agent_core::transport::Transport;
use rmt_agent_core::{control, file_transfer, input_codec, ControlMessage, InputButton, InputEvent};
use rmt_protocol::{ChannelId, DeviceId, Frame};
use rmt_transport_webrtc::{Role, WebRtcTransport};

fn arg(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

/// One parsed `--script` step. `Wait` is a real step rather than a property of the others because
/// the pauses matter on their own (the lock screen needs time to raise the password field).
#[derive(Debug, Clone, PartialEq)]
enum Step {
    Wait(u64),
    Key(u32),
    Text(String),
    Move(u16, u16),
    Click,
    /// Ctrl+Alt+Del. The one input that does not travel as key events — the agent routes it to
    /// `SendSAS`. Verifiable from the guest: the Windows Security / CAD screen it raises runs on
    /// the secure desktop as `LogonUI.exe` (what `guest-lock.ps1 -Action Status` detects).
    Sas,
    /// Right mouse button down+up at the current position. Exists to VM-verify the guest window's
    /// injected-mouse filter: an injected caption right-click would otherwise open the window's system
    /// menu (whose *Close* ends the session), so the agent must drop it — see `guest_window`.
    RightClick,
    /// Send a `SetInputBlocked` control message (`true` = block the guest's own keyboard/mouse,
    /// `false` = release). Rides the Control channel, not Input. Exists to VM-verify the guest-input
    /// block: with it on, an UNTAGGED `SendInput` from a separate probe process is swallowed while
    /// this controller's (tagged) injected input still works — see `input_block`.
    Block(bool),
    /// Send a `SetMonitorBlanked` control message (`true` = blank the guest's monitors). Rides the
    /// Control channel. Exists to VM-check privacy mode from the technician's side: with it on, a
    /// `screenshot` must still show the guest's desktop (the overlay is for the bystander), and the
    /// technician's clicks must still reach the desktop beneath it.
    Blank(bool),
    /// `select:<id>`: a `SelectMonitor` on the Control channel, as the console's monitor picker sends,
    /// so a test can put the session on one monitor (the DXGI tier) instead of "view all" (GDI).
    Select(u32),
    /// Send a `SetViewOnly` control message (`true` = view-only, the agent DROPS our injected input;
    /// `false` = resume control). Rides the Control channel. Exists to VM-verify view-only: with it on,
    /// a subsequent `key:` step's injection is dropped by the AGENT (never reaches a focused text box)
    /// while it works with it off — the near-mirror of `block`.
    ViewOnly(bool),
    /// Send an `InstallSessionPolicy` control message carrying the contents of a FILE (loops 79-81).
    /// Rides the Control channel.
    ///
    /// Exists to VM-verify the per-group view-only MANDATE, which is the one part of that feature only
    /// a real agent on a real desktop can prove. The blob is read and forwarded VERBATIM — the
    /// signature covers the claims and the agent re-derives the canonical preimage from exactly these
    /// bytes, so re-serializing it here would break every install in a way that looks like a crypto bug.
    ///
    /// The proof it enables: install a `view_only` policy, then send `view-control`, and observe that
    /// the guest window CAPTION still reads "… VIEW ONLY". A technician cannot lift a policy floor.
    InstallPolicy(String),
    /// Send a `RebootGuest` control message (`true` = Safe Mode with Networking, `false` = normal).
    /// Rides the Control channel. Exists to VM-verify the reboot feature end to end: a real agent
    /// **actually reboots** and re-registers on the way back. USE WITH CARE against a real machine.
    Reboot(bool),
    /// Send a `LockWorkstation` control message. Rides the Control channel. Exists to VM-verify the
    /// lock feature: a real agent locks the guest, observable as `LogonUI.exe` appearing in the guest
    /// session (`scripts/vmlab/guest-lock.ps1 -Action Status`).
    Lock,
    /// Send a `LogOffGuest` control message. Rides the Control channel. Exists to VM-verify the log-off
    /// feature: a real agent logs the guest's interactive user off, observable as the user's session
    /// disappearing (`query user` finds no session where one was Active before). USE WITH CARE — it
    /// closes the user's apps and drops the streamed session.
    LogOff,
    /// Send a `ShutDownGuest` control message. Rides the Control channel. Exists to VM-verify the
    /// shut-down feature: a real agent POWERS THE MACHINE OFF, observable as the Hyper-V VM state going
    /// to `Off`. USE WITH GREAT CARE — the agent does NOT come back on its own; the VM must be powered
    /// on again (`Start-VM`) to recover.
    ShutDown,
    /// Send a `LaunchTool` control message with the given whitelist key (e.g. `task_manager`). Rides
    /// the Control channel. Exists to VM-verify the tool launcher: a real agent spawns the tool on the
    /// interactive desktop, observable as the process appearing in the guest session.
    Tool(String),
    /// Send a `RunCommand` control message and print the returned `CommandResult`. Rides the Control
    /// channel. Exists to VM-verify the one-line command bar: a real agent RUNS the command and the
    /// captured output is the observable (e.g. `run:cmd:whoami` → `nt authority\system` for the SYSTEM
    /// helper; `run-user:cmd:whoami` → the interactive user). `as_user` picks the run context.
    Command {
        /// Which interpreter runs `command`.
        shell: CommandShell,
        /// The command line to run.
        command: String,
        /// `true` ⇒ run as the interactive user (`run-user:`), `false` ⇒ as SYSTEM (`run:`).
        as_user: bool,
    },
    /// Send an `ElevatedRun` control message carrying a signed elevation grant read from a FILE, and
    /// print the returned `CommandResult` (loop 87, docs/01 §3 "Elevate client to admin mid-session").
    /// Rides the Control channel.
    ///
    /// `elevate:<path-to-signed-elevation.json>:<cmd|ps>:<command>`.
    ///
    /// Exists to VM-verify the one thing about elevation that only a real desktop can show: WHICH
    /// TOKEN the command actually ran with. The captured output is the observable, and the A/B that
    /// proves it is the integrity level in `whoami /groups` —
    ///
    /// * `run-user:cmd:whoami /groups`      → `S-1-16-8192`  (Medium Mandatory Level)
    /// * `elevate:<g>:cmd:whoami /groups`   → `S-1-16-12288` (High Mandatory Level), same account
    ///
    /// — i.e. the same user, elevated, and NOT SYSTEM (which would say `nt authority\system`).
    ///
    /// The grant is read and forwarded VERBATIM, exactly like [`Step::InstallPolicy`]: the signature
    /// covers the claims and the agent re-derives the canonical preimage from these bytes, so
    /// re-serializing here would break every run in a way that looks like a crypto bug.
    ///
    /// A refusal is a probe FAILURE (exit 4), not a diagnostic line — this step exists to prove a
    /// command ran elevated, so "the agent declined" must not exit 0.
    ElevatedRun {
        /// Path to the signed elevation grant JSON (as returned by `POST /sessions/{id}/elevation`).
        grant_path: String,
        /// Which interpreter runs `command`.
        shell: CommandShell,
        /// The command line to run.
        command: String,
    },
    /// Send a `ListDirectory` control message and print the returned `DirectoryListing` (entry count,
    /// the `truncated` flag, and each `[D]`/`[F] name size`). Rides the Control channel. Exists to
    /// VM-verify the file browser: a real agent lists a real directory — `listdir:C:\` shows `Windows`,
    /// `Users`, … — and an empty path (`listdir:`) lists the drive roots. Read-only.
    ListDir(String),
    /// Send a `RequestScreenshot` control message, then RECEIVE the PNG the agent pushes back over the
    /// FileTransfer channel, assemble it, save it to a host file, and report its dimensions. Exists to
    /// VM-verify screenshot capture end to end: the observable is a real PNG of the guest's screen.
    Screenshot,
    /// Send a `StartRecording` (`true`) or `StopRecording` (`false`) control message and print the
    /// agent's answer (loop 89). Rides the Control channel.
    ///
    /// Exists to VM-verify session recording against a REAL DXGI capture, which is the half no
    /// automated suite can reach: the gate's agents are all `--synthetic`, so every recording they
    /// produce is of a generated pattern. The observables are the IVF file on the guest, the
    /// sidecar's digest, the DACL on the recording directory, and — the one only a human at the VM
    /// can see — the guest window's caption flipping to `RECORDING`.
    ///
    /// A recording left running is stopped by the session teardown, so `record-on` with no matching
    /// `record-off` still produces a finalized artifact. That is worth exercising deliberately, not
    /// just tolerating: it is the path a dropped session takes.
    Record(bool),
    /// Send an `EndSession` control message (`true` = "remove client" self-uninstall, `false` = plain
    /// end) and print the `SessionEnding` ack. Rides the Control channel. `end-uninstall` **actually
    /// uninstalls a real agent** — USE WITH CARE against a real machine; the observable is the service +
    /// install dirs being gone afterward.
    EndSession(bool),
    /// `background:1` / `background:0`: send `SetBackground` (the viewer's hidden/visible signal).
    /// Not acknowledged; the observable is the RTP frame rate in the collection window.
    Background(bool),
}

/// Parse a `;`-separated script. Returns `Err` naming the offending step rather than skipping it —
/// a silently-dropped step would make the probe report a clean failure to unlock that was really a
/// typo, which is exactly the false negative this tool exists to avoid.
fn parse_script(s: &str) -> Result<Vec<Step>, String> {
    let mut out = Vec::new();
    for raw in s.split(';') {
        let step = raw.trim();
        if step.is_empty() {
            continue;
        }
        // `split_once` so a `text:` payload keeps any colons it contains.
        let (kind, rest) = step.split_once(':').unwrap_or((step, ""));
        let parsed = match kind {
            "wait" => Step::Wait(
                rest.parse()
                    .map_err(|e| format!("step {step:?}: bad milliseconds: {e}"))?,
            ),
            "key" => Step::Key(
                rest.parse()
                    .map_err(|e| format!("step {step:?}: bad virtual-key code: {e}"))?,
            ),
            "text" => Step::Text(rest.to_string()),
            // The exact UTF-8 bytes, hex-encoded: `text:` is trimmed with its step, so leading or
            // trailing spaces (and any `;`) need this form.
            "texthex" => {
                let bytes = (0..rest.len())
                    .step_by(2)
                    .map(|i| rest.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
                    .collect::<Option<Vec<u8>>>()
                    .filter(|_| rest.len() % 2 == 0)
                    .ok_or_else(|| format!("step {step:?}: expected texthex:<even-length hex>"))?;
                Step::Text(String::from_utf8(bytes).map_err(|e| format!("step {step:?}: not UTF-8: {e}"))?)
            }
            "move" => {
                let (x, y) = rest
                    .split_once(',')
                    .ok_or_else(|| format!("step {step:?}: expected move:<x>,<y>"))?;
                Step::Move(
                    x.trim()
                        .parse()
                        .map_err(|e| format!("step {step:?}: bad x: {e}"))?,
                    y.trim()
                        .parse()
                        .map_err(|e| format!("step {step:?}: bad y: {e}"))?,
                )
            }
            "click" => Step::Click,
            "rclick" => Step::RightClick,
            "sas" => Step::Sas,
            "block" => Step::Block(true),
            "unblock" => Step::Block(false),
            "blank" => Step::Blank(true),
            "select" => Step::Select(rest.parse().map_err(|e| format!("step {step:?}: bad monitor id: {e}"))?),
            "unblank" => Step::Blank(false),
            "view-only" => Step::ViewOnly(true),
            "view-control" => Step::ViewOnly(false),
            "install-policy" => {
                if rest.is_empty() {
                    return Err(format!(
                        "step {step:?}: expected install-policy:<path-to-signed-policy.json>"
                    ));
                }
                Step::InstallPolicy(rest.to_string())
            }
            "reboot" => Step::Reboot(false),
            "reboot-safe" => Step::Reboot(true),
            "lock" => Step::Lock,
            "logoff" => Step::LogOff,
            "shutdown" => Step::ShutDown,
            "tool" => {
                if rest.is_empty() {
                    return Err(format!("step {step:?}: expected tool:<key> (e.g. tool:task_manager)"));
                }
                Step::Tool(rest.to_string())
            }
            "run" | "run-user" => {
                // `run:<cmd|ps>:<command>` (SYSTEM) or `run-user:...` (interactive user). `split_once`
                // so the command keeps any colons it contains (paths, `1>&2`, etc.).
                let as_user = kind == "run-user";
                let (sh, cmd) = rest.split_once(':').ok_or_else(|| {
                    format!("step {step:?}: expected {kind}:<cmd|ps>:<command>")
                })?;
                let shell = match sh.trim() {
                    "cmd" => CommandShell::Cmd,
                    "ps" | "powershell" => CommandShell::PowerShell,
                    other => {
                        return Err(format!("step {step:?}: unknown shell {other:?} (want cmd or ps)"))
                    }
                };
                if cmd.is_empty() {
                    return Err(format!("step {step:?}: empty command"));
                }
                Step::Command { shell, command: cmd.to_string(), as_user }
            }
            "elevate" => {
                // `elevate:<path>:<cmd|ps>:<command>`, split at the EARLIEST shell token anywhere in
                // `rest`.
                //
                // Earliest, not last, and across ALL THREE tokens rather than the first token that
                // happens to appear. The grant path may contain a drive colon (`C:\...`) but can
                // never contain `:cmd:`/`:ps:`/`:powershell:`, so the first such token IS the
                // separator — while the COMMAND may contain anything, including another one of
                // them. The previous form searched the tokens in order and took the last match of
                // whichever it found first, so `elevate:g.json:ps:echo :cmd: hi` silently split at
                // the `:cmd:` inside the command: the probe then ran `hi` under Cmd with a grant
                // path of `g.json:ps:echo `. A probe step that silently does something OTHER than
                // what it says is the failure class that already cost this project a VM session
                // (docs/07 loop 87: an argument split at a space ran a truncated script and read as
                // "the step did nothing").
                let mut split = None;
                for tok in [":cmd:", ":ps:", ":powershell:"] {
                    if let Some(at) = rest.find(tok) {
                        if split.is_none_or(|(best, _)| at < best) {
                            split = Some((at, tok));
                        }
                    }
                }
                let Some((at, tok)) = split else {
                    return Err(format!(
                        "step {step:?}: expected elevate:<path-to-grant.json>:<cmd|ps>:<command>"
                    ));
                };
                let grant_path = rest[..at].to_string();
                let command = rest[at + tok.len()..].to_string();
                if grant_path.is_empty() {
                    return Err(format!("step {step:?}: empty grant path"));
                }
                if command.is_empty() {
                    return Err(format!("step {step:?}: empty command"));
                }
                let shell = match tok {
                    ":cmd:" => CommandShell::Cmd,
                    _ => CommandShell::PowerShell,
                };
                Step::ElevatedRun { grant_path, shell, command }
            }
            // `split_once(':')` keeps any colons/backslashes in the path (e.g. `listdir:C:\Users`).
            "listdir" => Step::ListDir(rest.to_string()),
            "screenshot" => Step::Screenshot,
            // Distinct kinds rather than `record:<on|off>`, matching `view-only`/`view-control` and
            // `block`/`unblock`: a mistyped argument in the `record:<mode>` shape would have to be
            // rejected by hand, and a typo silently read as the WRONG direction is the exact failure
            // `parse_script` refuses to make elsewhere.
            "background" => match rest {
                "1" => Step::Background(true),
                "0" => Step::Background(false),
                _ => return Err(format!("step {step:?}: expected background:1 or background:0")),
            },
            "record-on" => Step::Record(true),
            "record-off" => Step::Record(false),
            "end" => Step::EndSession(false),
            "end-uninstall" => Step::EndSession(true),
            other => return Err(format!("step {step:?}: unknown kind {other:?}")),
        };
        out.push(parsed);
    }
    Ok(out)
}

/// One `--quality-plan` step: at `at_secs` into the collection window, send these settings.
#[derive(Debug, Clone, PartialEq)]
struct QualityStep {
    at_secs: u64,
    quality: QualitySettings,
}

/// Parse a `;`-separated quality plan, e.g. `"0:bps=4000000,adaptive=0;10:bps=400000;20:fps=5"`.
///
/// Each step starts from [`QualitySettings::DEFAULT`] and applies only the keys it names, so a
/// plan reads as "at t=10, ask for 400 kbps" rather than requiring every field every time. Keys:
/// `div`, `fps`, `color` (`full`/`gray`), `bps`, `adaptive` (`0`/`1`).
///
/// Errors name the offending step rather than skipping it — the same rule [`parse_script`] follows,
/// and for the same reason: a silently dropped step turns a typo into a clean "the feature does not
/// work", which is precisely the false negative this tool exists to avoid.
fn parse_quality_plan(s: &str) -> Result<Vec<QualityStep>, String> {
    let mut out = Vec::new();
    for raw in s.split(';') {
        let step = raw.trim();
        if step.is_empty() {
            continue;
        }
        let (at, spec) = step
            .split_once(':')
            .ok_or_else(|| format!("step {step:?}: expected <seconds>:<spec>"))?;
        let at_secs: u64 = at
            .trim()
            .parse()
            .map_err(|e| format!("step {step:?}: bad seconds: {e}"))?;
        let mut quality = QualitySettings::DEFAULT;
        for kv in spec.split(',') {
            let kv = kv.trim();
            if kv.is_empty() {
                continue;
            }
            let (k, v) = kv
                .split_once('=')
                .ok_or_else(|| format!("step {step:?}: expected key=value, got {kv:?}"))?;
            let num = |what: &str| -> Result<u32, String> {
                v.trim()
                    .parse::<u32>()
                    .map_err(|e| format!("step {step:?}: bad {what}: {e}"))
            };
            match k.trim() {
                "div" => quality.scale_div = num("div")?,
                "fps" => quality.fps = num("fps")?,
                "bps" => quality.max_bitrate_bps = num("bps")?,
                "adaptive" => quality.adaptive = num("adaptive")? != 0,
                "color" => {
                    quality.color = match v.trim() {
                        "full" | "Full" => ColorMode::Full,
                        "gray" | "Gray" | "grey" => ColorMode::Gray,
                        other => return Err(format!("step {step:?}: unknown color {other:?}")),
                    }
                }
                other => return Err(format!("step {step:?}: unknown key {other:?}")),
            }
        }
        out.push(QualityStep { at_secs, quality });
    }
    out.sort_by_key(|s| s.at_secs);
    Ok(out)
}

/// One measurement bucket: everything a receiver observed over `--rate-window` seconds.
#[derive(Debug, Default, Clone)]
struct Bucket {
    packets: u64,
    bytes: u64,
    /// Distinct RTP timestamps seen — i.e. FRAMES, not packets.
    timestamps: std::collections::BTreeSet<u32>,
    keyframes: u64,
    /// The most recent dimensions read out of a VP8 keyframe header.
    dims: Option<(u32, u32)>,
}

impl Bucket {
    /// Mean RTP timestamp delta between consecutive distinct frames, in 90 kHz ticks.
    ///
    /// This is the observable that catches a stream whose wall-clock pacing and whose RTP clock
    /// disagree — the exact defect the pre-M11 hardcoded 33 ms `Sample::duration` had, and one that
    /// no byte counter can see.
    fn mean_ts_delta(&self) -> f64 {
        let ts: Vec<u32> = self.timestamps.iter().copied().collect();
        if ts.len() < 2 {
            return 0.0;
        }
        let mut sum = 0u64;
        for w in ts.windows(2) {
            sum += w[1].wrapping_sub(w[0]) as u64;
        }
        sum as f64 / (ts.len() - 1) as f64
    }

    fn kbps(&self, window_secs: f64) -> f64 {
        (self.bytes as f64 * 8.0) / 1000.0 / window_secs
    }
}

/// Expand one step into the input events it sends. `Wait` yields none (the caller sleeps).
fn events_for(step: &Step) -> Vec<InputEvent> {
    match step {
        Step::Wait(_) => vec![],
        Step::Key(code) => vec![
            InputEvent::Key {
                code: *code,
                down: true,
            },
            InputEvent::Key {
                code: *code,
                down: false,
            },
        ],
        Step::Text(t) => vec![InputEvent::Text(t.clone())],
        Step::Move(x, y) => vec![InputEvent::MouseMove { x: *x, y: *y }],
        Step::Click => vec![
            InputEvent::MouseButton {
                button: InputButton::Left,
                down: true,
            },
            InputEvent::MouseButton {
                button: InputButton::Left,
                down: false,
            },
        ],
        Step::RightClick => vec![
            InputEvent::MouseButton {
                button: InputButton::Right,
                down: true,
            },
            InputEvent::MouseButton {
                button: InputButton::Right,
                down: false,
            },
        ],
        Step::Sas => vec![InputEvent::Sas],
        // Block, Reboot and Tool ride the Control channel, not Input — the run loop handles them directly.
        Step::Block(_) => vec![],
        Step::Blank(_) => vec![],
        Step::Select(_) => vec![],
        Step::ViewOnly(_) => vec![],
        Step::InstallPolicy(_) => vec![],
        Step::Reboot(_) => vec![],
        Step::Lock => vec![],
        Step::LogOff => vec![],
        Step::ShutDown => vec![],
        Step::Tool(_) => vec![],
        Step::Command { .. } => vec![],
        Step::ElevatedRun { .. } => vec![],
        Step::ListDir(_) => vec![],
        Step::Screenshot => vec![],
        Step::Record(_) => vec![],
        Step::EndSession(_) => vec![],
        Step::Background(_) => vec![],
    }
}

/// One line describing the audit event an ack carried, or `<none>`.
///
/// Prints the fields a VM operator actually needs in order to judge whether the trail is real: the
/// SEQ and the SESSION id. `seq` shows the event joined an existing chain instead of starting a
/// fresh one, and a nil `session_id` is the signature of a stack running without ticket
/// verification — the case where the agent deliberately seals nothing, because an event it could
/// never forward would wedge the rest of the session's chain at ingest.
fn audit_summary(ev: Option<&serde_json::Value>) -> String {
    match ev {
        None => "<none>".to_string(),
        Some(v) => format!(
            "seq={} session={} kind={} hash={}",
            v["seq"],
            v["session_id"].as_str().unwrap_or("?"),
            v["action"]["kind"].as_str().unwrap_or("?"),
            v["hash"].as_str().unwrap_or("?").chars().take(12).collect::<String>(),
        ),
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    // Install the tracing subscriber FIRST, before argument parsing and long before the transport
    // is touched.
    //
    // WHY THIS TOOL NEEDS IT AT ALL: everything below reports through `eprintln!`, but the probe
    // only ever says WHETHER the stream worked. WHY it did not is reported by
    // `rmt_transport_webrtc` through `tracing`, and with no subscriber installed every one of those
    // events was a silent no-op — so the tool used to prove the agent streams would print "too few
    // RTP packets" while the actual reason had already been produced and discarded. The verdict was
    // sound; the diagnosis was thrown away.
    //
    // BE PRECISE ABOUT WHAT THIS PROCESS CAN SEE, because it is easy to overstate (I did, and the
    // review caught it). The probe is `Role::Controller`, which CREATES the offer, so the
    // answerer-side warnings — `set_remote(offer)`, `create_answer`, the `agent_auth_challenge`
    // nonce check, and "video encoder init failed" (emitted by whichever peer SENDS video) — happen
    // in the AGENT's process and reach the agent's log, not this one. What this subscriber captures
    // is the CONTROLLER half:
    //
    //   * at the default INFO level: `set_remote(answer)` — the offerer-side SDP failure, i.e. the
    //     agent answered and we could not apply it;
    //   * with `RMT_LOG=debug`, the whole controller-side narrative that explains a silent stream:
    //     `signaling: rendezvous started` / `brokered`, `sent offer`, `pc state` transitions,
    //     `add trickled candidate`, `data channel open` / `closed`.
    //
    // The second is the reason to reach for this on a bad run: "too few RTP packets" plus an ICE
    // state that never left `checking` is a diagnosis, where the packet count alone is not.
    //
    // It logs to `%TEMP%\rmt-stream-probe.log`, NOT the agent's `C:\rmt-agent\helper.log`: this is
    // the CONTROLLER side, frequently a different machine and rarely elevated. `RMT_LOG_FILE`
    // overrides.
    //
    // cfg-gated because `rmt_agent_windows` is `#![cfg(windows)]` and compiles to an empty crate
    // root elsewhere — the same reason `bin/agent_host.rs` gates its call. Without the gate this
    // binary stops building off Windows, and no CI job would notice (the only cargo job runs on
    // windows-latest).
    #[cfg(windows)]
    rmt_agent_windows::logging::init_at(rmt_agent_windows::logging::tool_log_path("stream-probe"));
    // The pid ONLY — never argv. `--script "text:<...>"` carries whatever the caller types into the
    // guest, and the secure-desktop check types a PASSWORD through exactly that step, so logging the
    // command line would write a credential into a file that outlives the run. Same rule as
    // `host_main`, which logs the subcommand and nothing else.
    tracing::info!(pid = std::process::id(), "stream_probe start");

    let args: Vec<String> = std::env::args().collect();
    let url = arg(&args, "--signaling").unwrap_or_else(|| "ws://127.0.0.1:8080/ws".to_string());
    let device_s = match arg(&args, "--device") {
        Some(s) => s,
        None => {
            eprintln!("PROBE FAIL: --device <uuid> required");
            std::process::exit(2);
        }
    };
    let device = match device_s.parse::<uuid::Uuid>() {
        Ok(u) => DeviceId(u),
        Err(e) => {
            eprintln!("PROBE FAIL: --device {device_s:?} is not a uuid: {e}");
            std::process::exit(2);
        }
    };
    let secs: u64 = arg(&args, "--secs").and_then(|s| s.parse().ok()).unwrap_or(8);
    // `--ticket <path>`: a control-plane session ticket JSON, as `POST /sessions` (or
    // `/attended-sessions/{id}/connect`) returns it in `signaling.ticket`. Read and parsed HERE, before
    // dialling, so a bad path or bad JSON is an ARGUMENT error with a clear message rather than a
    // brokering failure 20 seconds later that reads like the agent's fault.
    let ticket: Option<rmt_protocol::signaling::SignedSessionTicket> = match arg(&args, "--ticket") {
        Some(path) => {
            let raw = match std::fs::read_to_string(&path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("PROBE FAIL: --ticket {path:?}: {e}");
                    std::process::exit(2);
                }
            };
            match serde_json::from_str(raw.trim()) {
                Ok(t) => Some(t),
                Err(e) => {
                    eprintln!("PROBE FAIL: --ticket {path:?} is not a SignedSessionTicket JSON: {e}");
                    std::process::exit(2);
                }
            }
        }
        None => None,
    };
    let rate_window: u64 = arg(&args, "--rate-window")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    let report_path = arg(&args, "--report");
    let inject_ssrc: Option<u32> = arg(&args, "--inject-ssrc").and_then(|s| s.parse().ok());
    let inject_until: Option<u64> = arg(&args, "--inject-until").and_then(|s| s.parse().ok());
    // `<sec>:<pct>`. Parsed strictly, like --script: a malformed value must be an argument error,
    // not a silent "no injection" that reports the feature as broken.
    let inject_loss: Option<(u64, u64)> = match arg(&args, "--inject-loss") {
        None if args.iter().any(|a| a == "--inject-loss") => {
            eprintln!("PROBE FAIL: --inject-loss given with no value (expected <sec>:<pct>)");
            std::process::exit(2);
        }
        None => None,
        Some(s) => match s.split_once(':') {
            Some((a, b)) => match (a.trim().parse::<u64>(), b.trim().parse::<u64>()) {
                (Ok(at), Ok(pct)) => Some((at, pct)),
                _ => {
                    eprintln!("PROBE FAIL: --inject-loss {s:?}: expected <sec>:<pct>");
                    std::process::exit(2);
                }
            },
            None => {
                eprintln!("PROBE FAIL: --inject-loss {s:?}: expected <sec>:<pct>");
                std::process::exit(2);
            }
        },
    };
    let planned = args.iter().any(|a| a == "--quality-plan");
    let plan = match arg(&args, "--quality-plan") {
        Some(s) => match parse_quality_plan(&s) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("PROBE FAIL: --quality-plan: {e}");
                std::process::exit(2);
            }
        },
        None if planned => {
            eprintln!("PROBE FAIL: --quality-plan given with no value");
            std::process::exit(2);
        }
        None => Vec::new(),
    };

    // Arguments are validated BEFORE dialling: a malformed --script must fail as an argument error,
    // not spend the connect timeout and then report "connect timed out", which reads like an agent
    // or network fault and sends the operator debugging the wrong thing entirely.
    //
    // A script REPLACES the default single mouse move: when the caller has specified an exact
    // interaction (e.g. unlocking the secure desktop) an extra uncommanded pointer move is noise
    // that can dismiss the very UI under test.
    //
    // `--script` with no value is REJECTED rather than silently falling back to the default move:
    // a typo'd invocation that quietly sends a mouse move instead of the requested keystrokes would
    // report a clean "the feature does not work" for a run that never tested the feature.
    let scripted = args.iter().any(|a| a == "--script");
    let steps = match arg(&args, "--script") {
        Some(s) => match parse_script(&s) {
            Ok(steps) => steps,
            Err(e) => {
                eprintln!("PROBE FAIL: --script: {e}");
                std::process::exit(2);
            }
        },
        None if scripted => {
            eprintln!("PROBE FAIL: --script given with no value");
            std::process::exit(2);
        }
        // Default: exercise the up path with a single absolute-centre mouse move. The agent decodes
        // this off the data channel and injects it via SendInput on its desktop-bound capture
        // thread (M7).
        None => vec![Step::Move(32768, 32768)],
    };

    // Through the subscriber as well as stderr: this line is what dates a run in the probe's own
    // log file, so a failure investigated later can be tied to the device and signaling URL it was
    // actually pointed at. Neither value is a secret (the probe carries no token).
    tracing::info!(%device, url = %url, secs, steps = steps.len(), "probe start");
    eprintln!("probe: connecting to {url}, targeting device={device}");
    // The controller role. Without `--ticket` the probe is a DEV controller, which only an insecure
    // signaling server (`-insecure-no-ticket-verification`) will broker — fine for the vmlab stack, and
    // what every probe run used until now. With `--ticket <path>` it presents a real control-plane
    // `RMTTICKETv1`, so it can drive an ENFORCING signaling server exactly as the browser viewer does.
    //
    // That mattered the moment an e2e wanted to install a session policy: the attended spec asserts its
    // signaling is ENFORCING (it greps its own log for the insecure warning), so a ticketless controller
    // is refused the broker and the guest simply times out waiting — which looks like a policy failure
    // and is not one.
    let role = match ticket {
        Some(t) => Role::controller(device, t),
        None => Role::dev_controller(device),
    };
    let mut t = match WebRtcTransport::connect(&url, role).await {
        Ok(t) => t,
        Err(e) => {
            eprintln!("PROBE FAIL: connect: {e}");
            std::process::exit(1);
        }
    };

    eprintln!(
        "probe: connected; running {} input step(s) then collecting RTP for {secs}s",
        steps.len()
    );

    // Send failures are COUNTED, not just logged. A probe that exits 0 having delivered none of its
    // keystrokes is a false green in the exact tool used to prove secure-desktop injection: RTP
    // keeps arriving regardless of whether input ever left the controller, so "enough RTP" alone
    // cannot distinguish "the agent ignored our input" from "we never sent any".
    let mut sends_attempted = 0usize;
    let mut sends_failed = 0usize;

    for step in &steps {
        if let Step::Wait(ms) = step {
            tokio::time::sleep(Duration::from_millis(*ms)).await;
            continue;
        }
        if let Step::Blank(blanked) = step {
            // Rides the Control channel. Counted like an input send so a silent failure cannot green.
            let payload = control::encode(&ControlMessage::SetMonitorBlanked { blanked: *blanked });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: SetMonitorBlanked({blanked}) send failed: {e}");
            } else {
                eprintln!("probe: sent SetMonitorBlanked({blanked})");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            continue;
        }
        if let Step::Select(id) = step {
            let payload = control::encode(&ControlMessage::SelectMonitor { id: *id });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: SelectMonitor({id}) send failed: {e}");
            } else {
                eprintln!("probe: sent SelectMonitor({id})");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            continue;
        }
        if let Step::Block(blocked) = step {
            // Rides the Control channel. Counted like an input send so a silent failure cannot green.
            let payload = control::encode(&ControlMessage::SetInputBlocked { blocked: *blocked });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: SetInputBlocked({blocked}) send failed: {e}");
            } else {
                eprintln!("probe: sent SetInputBlocked({blocked})");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            continue;
        }
        if let Step::ViewOnly(enabled) = step {
            // Rides the Control channel. Counted like an input send so a silent failure cannot green.
            let payload = control::encode(&ControlMessage::SetViewOnly { enabled: *enabled });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: SetViewOnly({enabled}) send failed: {e}");
            } else {
                eprintln!("probe: sent SetViewOnly({enabled})");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
            continue;
        }
        if let Step::InstallPolicy(path) = step {
            // Read the signed policy from disk and forward it VERBATIM (see the Step doc). A read
            // failure is counted as a failed send so a typo'd path cannot green a run that never
            // installed anything — the whole point of this step is that the policy actually arrived.
            sends_attempted += 1;
            let blob = match std::fs::read_to_string(path) {
                Ok(b) => b,
                Err(e) => {
                    sends_failed += 1;
                    eprintln!("probe: could not read session policy {path}: {e}");
                    continue;
                }
            };
            let payload = control::encode(&ControlMessage::InstallSessionPolicy {
                signed_policy: blob.trim().to_string(),
            });
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: InstallSessionPolicy send failed: {e}");
                continue;
            }
            eprintln!("probe: sent InstallSessionPolicy from {path}");
            // WAIT FOR THE AGENT'S VERDICT. Without this the step proved only that a frame LEFT the
            // probe. The agent answers `SessionPolicyInstalled` on success and `Error` when it fails
            // CLOSED (bad signature, wrong device, expired, no pinned issuer key) — and both looked
            // IDENTICAL here, so a rejected install greened the run. The loop-81 VM proof survived
            // that only because it read the agent's own observables (helper.log + the guest window
            // caption) rather than trusting this step.
            //
            // A rejection is a probe FAILURE, not a diagnostic line: this step exists to put a floor
            // in force, so "the agent refused it" must not exit 0.
            //
            // Leaving the reply unread was also a CROSS-STEP hazard: it stayed queued on the Control
            // channel, so the next reply-awaiting step (`listdir`, `run`) could dequeue this stale
            // frame while waiting for its own answer.
            let policy_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let remaining = policy_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    sends_failed += 1;
                    eprintln!("probe: no SessionPolicyInstalled within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::SessionPolicyInstalled { access, view_only, allow_recording, require_recording }) => {
                                eprintln!(
                                    "probe: SessionPolicyInstalled access={access:?} view_only={view_only} allow_recording={allow_recording} require_recording={require_recording}"
                                );
                                break;
                            }
                            Ok(ControlMessage::Error { message }) => {
                                sends_failed += 1;
                                eprintln!("probe: InstallSessionPolicy REJECTED: {message}");
                                break;
                            }
                            _ => {} // some other control frame — keep waiting for the verdict
                        }
                    }
                    Ok(Ok(_)) => {} // a frame on another channel — ignore
                    Ok(Err(e)) => {
                        sends_failed += 1;
                        eprintln!("probe: recv during install-policy wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        sends_failed += 1;
                        eprintln!("probe: no SessionPolicyInstalled within 20s");
                        break;
                    }
                }
            }
            // The verdict replaces the old fixed wait for the INSTALL, but the guest caption is
            // repainted on the window thread afterwards — still give it a moment before the next
            // step observes it.
            tokio::time::sleep(Duration::from_millis(400)).await;
            continue;
        }
        if let Step::Reboot(safe_mode) = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // reboots after this — the observable is the machine going down and re-registering.
            let payload = control::encode(&ControlMessage::RebootGuest { safe_mode: *safe_mode });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: RebootGuest(safe_mode={safe_mode}) send failed: {e}");
            } else {
                eprintln!("probe: sent RebootGuest(safe_mode={safe_mode})");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Step::Lock = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // locks the guest after this — the observable is LogonUI.exe in the guest session.
            let payload = control::encode(&ControlMessage::LockWorkstation);
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: LockWorkstation send failed: {e}");
            } else {
                eprintln!("probe: sent LockWorkstation");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Step::LogOff = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // logs the guest's user off after this — the observable is the user's session disappearing
            // (and the streamed session dropping). USE WITH CARE.
            let payload = control::encode(&ControlMessage::LogOffGuest);
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: LogOffGuest send failed: {e}");
            } else {
                eprintln!("probe: sent LogOffGuest");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Step::ShutDown = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // POWERS THE MACHINE OFF after this — the observable is the Hyper-V VM state going to Off.
            // USE WITH GREAT CARE — recover with Start-VM (the agent will not come back on its own).
            let payload = control::encode(&ControlMessage::ShutDownGuest);
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: ShutDownGuest send failed: {e}");
            } else {
                eprintln!("probe: sent ShutDownGuest");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Step::Tool(key) = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // spawns the tool on the interactive desktop — the observable is the process appearing.
            let payload = control::encode(&ControlMessage::LaunchTool { tool: key.clone() });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: LaunchTool({key}) send failed: {e}");
            } else {
                eprintln!("probe: sent LaunchTool({key})");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        if let Step::Command { shell, command, as_user } = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // RUNS the command and answers with a `CommandResult` — the captured output is the whole
            // observable (e.g. whoami → the account it ran as), so we wait for the reply and print it.
            let payload = control::encode(&ControlMessage::RunCommand {
                command: command.clone(),
                shell: *shell,
                as_user: *as_user,
            });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: RunCommand send failed: {e}");
                continue;
            }
            eprintln!("probe: sent RunCommand (shell={shell:?} as_user={as_user})");
            // Drain Control frames for a short window, printing the CommandResult (or an Error). Other
            // control frames (e.g. a QualityApplied) are ignored; video rides a media track, not these
            // data-channel frames, so this consumes nothing the RTP collection window needs.
            let cmd_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let remaining = cmd_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    eprintln!("probe: no CommandResult within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::CommandResult {
                                exit_code,
                                stdout,
                                stderr,
                                truncated,
                                timed_out,
                            }) => {
                                eprintln!(
                                    "probe: CommandResult exit={exit_code} timed_out={timed_out} truncated={truncated}"
                                );
                                eprintln!("---- stdout ----\n{stdout}\n---- stderr ----\n{stderr}\n----------------");
                                break;
                            }
                            Ok(ControlMessage::Error { message }) => {
                                eprintln!("probe: command Error: {message}");
                                break;
                            }
                            _ => {} // some other control frame — keep waiting for the result
                        }
                    }
                    Ok(Ok(_)) => {} // a frame on another channel — ignore
                    Ok(Err(e)) => {
                        eprintln!("probe: recv during command wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("probe: no CommandResult within 20s");
                        break;
                    }
                }
            }
            continue;
        }
        if let Step::ElevatedRun { grant_path, shell, command } = step {
            // Read the signed grant from disk and forward it VERBATIM (see the Step doc). A read
            // failure is a FAILED SEND, not a skip: a typo'd path must not green a run that never
            // asked for elevation at all.
            sends_attempted += 1;
            let blob = match std::fs::read_to_string(grant_path) {
                Ok(b) => b,
                Err(e) => {
                    sends_failed += 1;
                    eprintln!("probe: could not read elevation grant {grant_path}: {e}");
                    continue;
                }
            };
            let payload = control::encode(&ControlMessage::ElevatedRun {
                signed_elevation: blob.trim().to_string(),
                command: command.clone(),
                shell: *shell,
            });
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: ElevatedRun send failed: {e}");
                continue;
            }
            eprintln!("probe: sent ElevatedRun (shell={shell:?}) with the grant from {grant_path}");
            // WAIT FOR THE VERDICT, and treat a refusal as a failure. The agent answers either a
            // `CommandResult` (it verified the grant, burned it, and ran) or an `ElevationDenied`
            // (it did not) — and unlike RunCommand, those two are distinguishable on the wire
            // precisely so this step can tell them apart. Leaving the reply unread would also be a
            // CROSS-STEP hazard: it would stay queued and be dequeued by whichever later step waits.
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    sends_failed += 1;
                    eprintln!("probe: no ElevatedRun verdict within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::CommandResult {
                                exit_code,
                                stdout,
                                stderr,
                                truncated,
                                timed_out,
                            }) => {
                                eprintln!(
                                    "probe: ELEVATED CommandResult exit={exit_code} timed_out={timed_out} truncated={truncated}"
                                );
                                eprintln!("---- stdout ----\n{stdout}\n---- stderr ----\n{stderr}\n----------------");
                                break;
                            }
                            Ok(ControlMessage::ElevationDenied { reason }) => {
                                sends_failed += 1;
                                eprintln!("probe: ElevatedRun DENIED: {reason}");
                                break;
                            }
                            _ => {} // some other control frame — keep waiting for the verdict
                        }
                    }
                    Ok(Ok(_)) => {} // a frame on another channel — ignore
                    Ok(Err(e)) => {
                        sends_failed += 1;
                        eprintln!("probe: recv during elevated-run wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        sends_failed += 1;
                        eprintln!("probe: no ElevatedRun verdict within 20s");
                        break;
                    }
                }
            }
            continue;
        }
        if let Step::ListDir(path) = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // LISTS the directory and answers with a `DirectoryListing` — the entries are the whole
            // observable (e.g. listdir:C:\ → Windows, Users, …), so we wait for the reply and print it.
            let payload = control::encode(&ControlMessage::ListDirectory { path: path.clone() });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: ListDirectory send failed: {e}");
                continue;
            }
            eprintln!("probe: sent ListDirectory(path={path:?})");
            let ls_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let remaining = ls_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    eprintln!("probe: no DirectoryListing within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::DirectoryListing {
                                path: p,
                                entries,
                                truncated,
                                audit,
                            }) => {
                                eprintln!(
                                    "probe: DirectoryListing path={p:?} entries={} truncated={truncated} audit={}",
                                    entries.len(),
                                    if audit.is_some() { "sealed" } else { "none" }
                                );
                                for e in &entries {
                                    let kind = if e.is_dir { "D" } else { "F" };
                                    eprintln!("  [{kind}] {} ({} bytes)", e.name, e.size);
                                }
                                eprintln!("----------------");
                                break;
                            }
                            // docs/25 F04: the listing is capability-gated now, so the probe has to
                            // be able to SAY it was refused. Reporting a refusal as "no reply within
                            // 20s" would make a working gate look like a broken agent, which is the
                            // reading that wastes an afternoon on the VM.
                            Ok(ControlMessage::DirectoryListingRefused { path: p, reason, audit }) => {
                                eprintln!(
                                    "probe: DirectoryListing REFUSED path={p:?} reason={reason} audit={}",
                                    if audit.is_some() { "sealed" } else { "none" }
                                );
                                break;
                            }
                            Ok(ControlMessage::Error { message }) => {
                                eprintln!("probe: listdir Error: {message}");
                                break;
                            }
                            _ => {} // some other control frame — keep waiting for the listing
                        }
                    }
                    Ok(Ok(_)) => {} // a frame on another channel — ignore
                    Ok(Err(e)) => {
                        eprintln!("probe: recv during listdir wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("probe: no DirectoryListing within 20s");
                        break;
                    }
                }
            }
            continue;
        }
        if let Step::Background(hidden) = step {
            let payload = control::encode(&ControlMessage::SetBackground { background: *hidden });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: background send failed: {e}");
            } else {
                eprintln!("probe: sent SetBackground background={hidden}");
            }
            continue;
        }
        if let Step::Record(on) = step {
            // Rides the Control channel; counted so a silent send failure cannot green. The agent's
            // answer is the observable HERE, but it is not the point of the step — the artifact on
            // the guest's disk is (see `Step::Record`'s doc), and the summary printed below is what
            // tells the operator at the VM which file to go and look at.
            let payload = control::encode(&if *on {
                ControlMessage::StartRecording
            } else {
                ControlMessage::StopRecording
            });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: recording send failed: {e}");
                continue;
            }
            eprintln!("probe: sent {}", if *on { "StartRecording" } else { "StopRecording" });
            let rec_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let remaining = rec_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    eprintln!("probe: no recording reply within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::RecordingStarted { started_at_unix_ms, audit }) => {
                                // The sealed audit event is printed too, and printed as a WORD when
                                // absent rather than omitted: on the VM this probe is the only place
                                // an operator can see whether the session had a chain at all, and a
                                // missing line reads as "I did not look", not as "there was none".
                                eprintln!(
                                    "probe: RecordingStarted started_at_unix_ms={started_at_unix_ms} audit={}",
                                    audit_summary(audit.as_ref())
                                );
                                break;
                            }
                            Ok(ControlMessage::RecordingStopped {
                                segments,
                                frames,
                                payload_bytes,
                                truncated,
                                dropped_frames_total,
                                directory,
                                audit,
                            }) => {
                                // `truncated` is printed as a word rather than a Debug `Option`, and
                                // unconditionally: a reader scanning this output must not have to
                                // notice the ABSENCE of a line to learn the recording was complete.
                                eprintln!(
                                    "probe: RecordingStopped segments={segments} frames={frames} \
                                     payload_bytes={payload_bytes} truncated={} \
                                     dropped_frames={dropped_frames_total} dir={directory} audit={}",
                                    truncated.as_deref().unwrap_or("no"),
                                    audit_summary(audit.as_ref())
                                );
                                break;
                            }
                            Ok(ControlMessage::Error { message }) => {
                                eprintln!("probe: recording Error: {message}");
                                break;
                            }
                            _ => {} // some other control frame — keep waiting
                        }
                    }
                    Ok(Ok(_)) => {} // a frame on another channel — ignore
                    Ok(Err(e)) => {
                        eprintln!("probe: recv during recording wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("probe: no recording reply within 20s");
                        break;
                    }
                }
            }
            continue;
        }
        if let Step::Screenshot = step {
            // Ask for a screenshot (Control), then RECEIVE the PNG the agent pushes over FileTransfer
            // (Offer → Chunks → Done), assemble it, save it, and report its dimensions. The saved PNG
            // is the whole observable for the feature.
            let payload = control::encode(&ControlMessage::RequestScreenshot);
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: RequestScreenshot send failed: {e}");
                continue;
            }
            eprintln!("probe: sent RequestScreenshot; awaiting the pushed PNG...");
            let shot_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            // Accumulate the pushed transfer: name + ordered chunk bytes until Done.
            let mut name = String::new();
            let mut parts: Vec<u8> = Vec::new();
            let mut done = false;
            while !done {
                let remaining = shot_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    eprintln!("probe: no screenshot within 20s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::FileTransfer => {
                        match file_transfer::decode(&frame.payload) {
                            Ok(file_transfer::Message::Offer(o)) => {
                                name = o.name.clone();
                                eprintln!("probe: screenshot Offer name={} size={}", o.name, o.size);
                            }
                            Ok(file_transfer::Message::Chunk(c)) => parts.extend_from_slice(&c.data),
                            Ok(file_transfer::Message::Done { .. }) => done = true,
                            _ => {}
                        }
                    }
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        // The agent reports it could not screenshot (e.g. no frame yet) via Control Error.
                        if let Ok(ControlMessage::Error { message }) = control::decode(&frame.payload) {
                            eprintln!("probe: screenshot Error: {message}");
                            break;
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        eprintln!("probe: recv during screenshot wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("probe: no screenshot within 20s");
                        break;
                    }
                }
            }
            if done && !parts.is_empty() {
                let out_path = std::env::temp_dir().join(if name.is_empty() { "rmt-probe-screenshot.png".to_string() } else { name });
                // PNG IHDR: width at byte 16, height at byte 20 (big-endian), right after the signature.
                let dims = if parts.len() >= 24 && &parts[..8] == b"\x89PNG\r\n\x1a\n" {
                    let w = u32::from_be_bytes([parts[16], parts[17], parts[18], parts[19]]);
                    let h = u32::from_be_bytes([parts[20], parts[21], parts[22], parts[23]]);
                    format!("{w}x{h}")
                } else {
                    "not-a-PNG".to_string()
                };
                match std::fs::write(&out_path, &parts) {
                    Ok(()) => eprintln!(
                        "probe: SCREENSHOT saved {} ({} bytes, PNG {})",
                        out_path.display(),
                        parts.len(),
                        dims
                    ),
                    Err(e) => eprintln!("probe: could not write screenshot: {e}"),
                }
            }
            continue;
        }
        if let Step::EndSession(uninstall) = step {
            // Rides the Control channel; counted so a silent send failure cannot green. A real agent
            // ends the session (and, for uninstall, self-uninstalls after) — the observable is the
            // `SessionEnding` ack here plus, on the VM, the service + dirs being gone afterward.
            let payload = control::encode(&ControlMessage::EndSession { uninstall: *uninstall, directive: None });
            sends_attempted += 1;
            if let Err(e) = t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                sends_failed += 1;
                eprintln!("probe: EndSession(uninstall={uninstall}) send failed: {e}");
                continue;
            }
            eprintln!("probe: sent EndSession(uninstall={uninstall}); awaiting SessionEnding ack...");
            let end_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
            loop {
                let remaining = end_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    eprintln!("probe: no SessionEnding within 10s");
                    break;
                }
                match tokio::time::timeout(remaining, t.recv_frame()).await {
                    Ok(Ok(frame)) if frame.channel == ChannelId::Control => {
                        match control::decode(&frame.payload) {
                            Ok(ControlMessage::SessionEnding { uninstall }) => {
                                eprintln!("probe: SessionEnding ack (uninstall={uninstall})");
                                break;
                            }
                            Ok(ControlMessage::Error { message }) => {
                                eprintln!("probe: end-session Error: {message}");
                                break;
                            }
                            _ => {}
                        }
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => {
                        eprintln!("probe: recv during end-session wait failed: {e}");
                        break;
                    }
                    Err(_) => {
                        eprintln!("probe: no SessionEnding within 10s");
                        break;
                    }
                }
            }
            continue;
        }
        for ev in events_for(step) {
            sends_attempted += 1;
            if let Err(e) = t
                .send_frame(Frame::new(ChannelId::Input, input_codec::encode(&ev)))
                .await
            {
                sends_failed += 1;
                eprintln!("probe: input send failed: {e}");
            }
        }
        // A small gap between steps: SendInput events delivered back-to-back can outrun the
        // target window's message pump, which drops keystrokes into a logon field.
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
    if sends_failed > 0 {
        eprintln!("probe: {sends_failed}/{sends_attempted} input send(s) FAILED");
    }

    // --- collection ------------------------------------------------------------------------
    //
    // One loop drives measurement, the quality plan and the RTCP injector, stepping between
    // packets rather than concurrently: the quality steps land BETWEEN buckets, so a commanded
    // change never straddles a measurement boundary and smears its own step into a ramp.
    let window = Duration::from_secs(rate_window.max(1));
    let window_secs = window.as_secs_f64();
    let mut buckets: BTreeMap<u64, Bucket> = BTreeMap::new();
    let mut packets = 0usize;
    let mut bytes = 0usize;
    let mut plan_sent = 0usize;
    let mut injected = 0u64;
    let started = tokio::time::Instant::now();
    let deadline = started + Duration::from_secs(secs);
    // Injected reports go out faster than the 1 Hz the peer's own interceptor uses, so the
    // decrease path (gated to one per 300 ms + RTT) is exercised against the peer's real 0-loss
    // reports rather than alternating one-for-one with them.
    let inject_period = Duration::from_millis(250);
    let mut next_inject = started;
    let mut applied_quality: Option<QualitySettings> = None;

    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        let elapsed = now.saturating_duration_since(started).as_secs();

        // Quality plan: send any step whose time has come.
        while plan_sent < plan.len() && plan[plan_sent].at_secs <= elapsed {
            let step = &plan[plan_sent];
            plan_sent += 1;
            let payload = control::encode(&ControlMessage::SetQuality { quality: step.quality });
            match t.send_frame(Frame::new(ChannelId::Control, payload)).await {
                Ok(()) => {
                    applied_quality = Some(step.quality);
                    eprintln!(
                        "probe: t={elapsed}s SetQuality div={} fps={} color={:?} bps={} adaptive={}",
                        step.quality.scale_div,
                        step.quality.fps,
                        step.quality.color,
                        step.quality.max_bitrate_bps,
                        step.quality.adaptive
                    );
                }
                Err(e) => eprintln!("probe: SetQuality send failed: {e}"),
            }
        }

        // RTCP injection: crafted receiver reports claiming loss, addressed at the agent's real
        // media SSRC (or, with --inject-ssrc, a bogus one as the negative control).
        if let Some((from, pct)) = inject_loss {
            let within = elapsed >= from && inject_until.is_none_or(|u| elapsed < u);
            if within && now >= next_inject {
                next_inject = now + inject_period;
                let target = inject_ssrc.or_else(|| t.inbound_video_ssrc());
                match target {
                    Some(ssrc) => {
                        let fraction = ((pct.min(100) * 256) / 100).min(255) as u8;
                        match t.send_receiver_report(ssrc, fraction, (injected * 10) as u32).await {
                            Ok(()) => injected += 1,
                            Err(e) => eprintln!("probe: RTCP injection failed: {e}"),
                        }
                    }
                    None => { /* no SSRC learned yet — the first packet has not arrived */ }
                }
            }
        }

        // One packet, bounded so the plan/injector above keep ticking on a silent stream.
        let step_deadline = deadline.min(now + Duration::from_millis(100));
        match tokio::time::timeout_at(step_deadline, t.recv_video_packet()).await {
            Ok(Some(p)) => {
                packets += 1;
                bytes += p.payload_len;
                let idx = p.at.saturating_duration_since(started.into_std()).as_secs() / window.as_secs();
                let b = buckets.entry(idx).or_default();
                b.packets += 1;
                b.bytes += p.payload_len as u64;
                b.timestamps.insert(p.timestamp);
                if p.vp8.keyframe && p.vp8.frame_start {
                    b.keyframes += 1;
                }
                if let Some(d) = p.vp8.dimensions {
                    b.dims = Some(d);
                }
            }
            Ok(None) => break, // the track closed
            Err(_) => {}       // no packet this slice; loop re-checks the plan and the clock
        }
    }

    // Per-bucket time series. The FIRST bucket is printed but flagged: it starts at connect, so it
    // is short and includes the initial keyframe, and treating it as comparable to a steady-state
    // bucket is the easiest way to read a step change that is not there.
    for (idx, b) in &buckets {
        let dims = b.dims.map(|(w, h)| format!("{w}x{h}")).unwrap_or_else(|| "-".into());
        let line = format!(
            "PROBE RATE: t={} pkts={} bytes={} kbps={:.0} frames={} ts_delta={:.0} kf={} dims={}{}",
            idx * window.as_secs(),
            b.packets,
            b.bytes,
            b.kbps(window_secs),
            b.timestamps.len(),
            b.mean_ts_delta(),
            b.keyframes,
            dims,
            if *idx == 0 { "  (partial: connect + first keyframe)" } else { "" }
        );
        println!("{line}");
    }
    if let Some(path) = report_path.as_deref() {
        let mut csv = String::from("t,pkts,bytes,kbps,frames,ts_delta,keyframes,width,height\n");
        for (idx, b) in &buckets {
            let (w, h) = b.dims.unwrap_or((0, 0));
            csv.push_str(&format!(
                "{},{},{},{:.1},{},{:.1},{},{},{}\n",
                idx * window.as_secs(),
                b.packets,
                b.bytes,
                b.kbps(window_secs),
                b.timestamps.len(),
                b.mean_ts_delta(),
                b.keyframes,
                w,
                h
            ));
        }
        if let Err(e) = std::fs::write(path, csv) {
            eprintln!("probe: could not write {path}: {e}");
        } else {
            eprintln!("probe: wrote {path}");
        }
    }
    if inject_loss.is_some() {
        eprintln!(
            "probe: injected {injected} crafted RTCP receiver report(s){}",
            if inject_ssrc.is_some() { " at a BOGUS ssrc (negative control)" } else { "" }
        );
        if injected == 0 {
            // The whole point of the anti-"my stimulus never arrived" discipline: a run that
            // injected nothing must not be read as "the agent ignored the loss".
            eprintln!(
                "PROBE FAIL: --inject-loss was requested but NOTHING was injected (no video SSRC \
                 was ever learned) — this run proves nothing about adaptation"
            );
            std::process::exit(5);
        }
    }
    if let Some(q) = applied_quality {
        eprintln!(
            "probe: last commanded quality div={} fps={} bps={} adaptive={}",
            q.scale_div, q.fps, q.max_bitrate_bps, q.adaptive
        );
    }

    // Report the codec the session actually negotiated, so a VM run proves *what* streamed and not
    // merely that something did.
    let codec = match t.negotiated_video_codec().await {
        Some(c) => format!("{} (payload type {})", c.mime_type, c.payload_type),
        None => "no video track negotiated".to_string(),
    };
    println!("PROBE RESULT: {packets} RTP packets, {bytes} bytes of {codec} from device {device}");
    // The verdict also goes through the subscriber, so the log FILE collected from a VM run is
    // self-contained: without this it held the startup line and the transport's account of the
    // session but not the conclusion, leaving whoever reads it to correlate against a console
    // transcript that a scripted run may not have kept. `println!` keeps the stdout contract
    // (`PROBE RESULT: …` is matched by the VM scripts and quoted in docs/07); this is in addition
    // to it, never instead of it.
    tracing::info!(
        packets,
        bytes,
        %codec,
        %device,
        sends_attempted,
        sends_failed,
        "probe result"
    );
    if packets < 5 {
        eprintln!("PROBE FAIL: too few RTP packets ({packets}) — agent not streaming?");
        std::process::exit(3);
    }
    // Streaming alone is NOT success when input was requested: the caller asked for an interaction,
    // and an undelivered interaction must not be reported as a passing run.
    if sends_failed > 0 {
        eprintln!(
            "PROBE FAIL: streaming was fine ({packets} RTP packets) but {sends_failed}/{sends_attempted} \
             input send(s) failed — the scripted interaction did NOT happen"
        );
        std::process::exit(4);
    }
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_secure_desktop_unlock_script() {
        // The exact shape the secure-desktop e2e drives: dismiss the lock screen, type a password,
        // press Enter.
        let steps = parse_script("wait:1500;key:32;wait:1200;text:hunter2;key:13").expect("parses");
        assert_eq!(
            steps,
            vec![
                Step::Wait(1500),
                Step::Key(32),
                Step::Wait(1200),
                Step::Text("hunter2".into()),
                Step::Key(13),
            ]
        );
    }

    #[test]
    fn text_keeps_colons_and_punctuation() {
        // Passwords contain ':' and '@'. Splitting on every colon would silently truncate the
        // password to its first segment and the unlock would fail for a reason that looks like the
        // feature being broken.
        let steps = parse_script("text:P@ss:w0rd!").expect("parses");
        assert_eq!(steps, vec![Step::Text("P@ss:w0rd!".into())]);
    }

    #[test]
    fn rejects_an_unknown_or_malformed_step_instead_of_skipping_it() {
        // A dropped step would turn a typo into a "the feature does not work" result.
        assert!(parse_script("wait:1000;klick").is_err());
        assert!(parse_script("key:notanumber").is_err());
        assert!(parse_script("move:100").is_err());
    }

    #[test]
    fn empty_and_trailing_separators_are_tolerated() {
        assert_eq!(parse_script("").expect("parses"), vec![]);
        assert_eq!(
            parse_script("click;;").expect("parses"),
            vec![Step::Click]
        );
    }

    #[test]
    fn key_expands_to_a_down_then_up_pair() {
        // A key that is pressed and never released leaves the guest's keyboard state stuck.
        let evs = events_for(&Step::Key(13));
        assert_eq!(
            evs,
            vec![
                InputEvent::Key { code: 13, down: true },
                InputEvent::Key { code: 13, down: false },
            ]
        );
    }

    #[test]
    fn wait_sends_no_events() {
        assert!(events_for(&Step::Wait(500)).is_empty());
    }

    #[test]
    fn rclick_parses_and_expands_to_a_right_button_down_then_up_pair() {
        // The step the injected-mouse-filter VM check drives: a caption right-click the agent must
        // drop. It must be the RIGHT button (a left click is a different, directly-actuating path) and
        // it must release, or the guest's button state would be left stuck down.
        assert_eq!(parse_script("rclick").expect("parses"), vec![Step::RightClick]);
        assert_eq!(
            events_for(&Step::RightClick),
            vec![
                InputEvent::MouseButton { button: InputButton::Right, down: true },
                InputEvent::MouseButton { button: InputButton::Right, down: false },
            ]
        );
    }

    #[test]
    fn block_and_unblock_parse_and_carry_no_input_events() {
        // The guest-input-block VM check: `block` / `unblock` map to SetInputBlocked(true/false) and
        // ride the Control channel, so they expand to NO input events (the run loop sends them
        // directly). `on`/`off` are distinct steps, and the boolean must not be inverted.
        assert_eq!(
            parse_script("block;unblock").expect("parses"),
            vec![Step::Block(true), Step::Block(false)],
        );
        assert!(events_for(&Step::Block(true)).is_empty());
        assert!(events_for(&Step::Block(false)).is_empty());
    }

    #[test]
    fn view_only_steps_parse_with_the_right_mode_and_no_input_events() {
        // The view-only VM check: `view-only` → SetViewOnly(true), `view-control` → false. They ride
        // the Control channel, so no input events; the boolean must not be inverted — a `view-only`
        // that sent `false` would silently fail to prove the agent drops input.
        assert_eq!(
            parse_script("view-only;view-control").expect("parses"),
            vec![Step::ViewOnly(true), Step::ViewOnly(false)],
        );
        assert!(events_for(&Step::ViewOnly(true)).is_empty());
        assert!(events_for(&Step::ViewOnly(false)).is_empty());
    }

    #[test]
    fn reboot_steps_parse_with_the_right_mode_and_no_input_events() {
        // The reboot VM check: `reboot` → normal, `reboot-safe` → Safe Mode with Networking. These
        // ride the Control channel, so they carry NO input events (the run loop sends them directly).
        // The `safe_mode` boolean must not be inverted — a normal `reboot` that set Safe Mode would
        // strand the VM, and a `reboot-safe` that went normal would silently fail the whole test.
        assert_eq!(
            parse_script("reboot;reboot-safe").expect("parses"),
            vec![Step::Reboot(false), Step::Reboot(true)],
        );
        assert!(events_for(&Step::Reboot(false)).is_empty());
        assert!(events_for(&Step::Reboot(true)).is_empty());
    }

    #[test]
    fn lock_logoff_shutdown_steps_parse_and_carry_no_input_events() {
        // The power-action VM checks: `lock` → LockWorkstation, `logoff` → LogOffGuest, `shutdown` →
        // ShutDownGuest. All ride the Control channel, so they carry NO input events (the run loop sends
        // them directly). Distinct steps: a `lock` parsed as `logoff` (or a `shutdown` parsed as
        // anything milder) would put the guest in a very different state, so the mapping is pinned.
        assert_eq!(
            parse_script("lock;logoff;shutdown").expect("parses"),
            vec![Step::Lock, Step::LogOff, Step::ShutDown],
        );
        assert!(events_for(&Step::Lock).is_empty());
        assert!(events_for(&Step::LogOff).is_empty());
        assert!(events_for(&Step::ShutDown).is_empty());
    }

    #[test]
    fn tool_step_parses_its_key_and_carries_no_input_events() {
        // `tool:<key>` carries the whitelist key verbatim and rides the Control channel (no input
        // events). A `tool:` with no key is a parse error, not a silently-dropped step.
        assert_eq!(
            parse_script("tool:task_manager").expect("parses"),
            vec![Step::Tool("task_manager".to_string())],
        );
        assert!(events_for(&Step::Tool("task_manager".to_string())).is_empty());
        assert!(parse_script("tool:").is_err(), "an empty tool key must be rejected");
    }

    #[test]
    fn command_steps_parse_shell_context_and_command() {
        // The command-bar VM check: `run:<shell>:<command>` (SYSTEM) and `run-user:...` (interactive
        // user). The shell selects the interpreter, `as_user` the context, and the command keeps its
        // own colons. All ride the Control channel, so no input events.
        assert_eq!(
            parse_script("run:cmd:whoami").expect("parses"),
            vec![Step::Command { shell: CommandShell::Cmd, command: "whoami".to_string(), as_user: false }],
        );
        assert_eq!(
            parse_script("run-user:ps:Get-Date").expect("parses"),
            vec![Step::Command { shell: CommandShell::PowerShell, command: "Get-Date".to_string(), as_user: true }],
        );
        // A command keeps embedded colons (a path, a redirection) — split_once, not split.
        assert_eq!(
            parse_script(r"run:cmd:echo C:\Windows").expect("parses"),
            vec![Step::Command { shell: CommandShell::Cmd, command: r"echo C:\Windows".to_string(), as_user: false }],
        );
        assert!(events_for(&Step::Command { shell: CommandShell::Cmd, command: "x".into(), as_user: false }).is_empty());
        // A bad shell or an empty command is a parse error, not a silently-dropped step.
        assert!(parse_script("run:bash:ls").is_err(), "an unknown shell must be rejected");
        assert!(parse_script("run:cmd:").is_err(), "an empty command must be rejected");
        assert!(parse_script("run:whoami").is_err(), "a missing shell segment must be rejected");

        // The elevated form: `elevate:<path>:<cmd|ps>:<command>`. The path runs up to the EARLIEST
        // shell token, so a Windows path's own drive colon (and any colon in the command) survives —
        // the two things that would otherwise silently mangle a VM invocation.
        assert_eq!(
            parse_script(r"elevate:C:\tmp\g.json:cmd:whoami /groups").expect("parses"),
            vec![Step::ElevatedRun {
                grant_path: r"C:\tmp\g.json".into(),
                shell: CommandShell::Cmd,
                command: "whoami /groups".into(),
            }]
        );
        assert_eq!(
            parse_script("elevate:g.json:ps:Get-Date").expect("parses"),
            vec![Step::ElevatedRun {
                grant_path: "g.json".into(),
                shell: CommandShell::PowerShell,
                command: "Get-Date".into(),
            }]
        );
        // THE AMBIGUOUS CASE, which the old parser got silently wrong: a PowerShell command that
        // itself contains `:cmd:`. Searching the tokens in priority order and taking `rfind` of the
        // first one present matched the `:cmd:` INSIDE the command, yielding grant_path
        // "g.json:ps:echo " and shell Cmd — a probe step that runs something other than what it
        // says, which on the VM reads as "the feature is broken" rather than "the script is".
        assert_eq!(
            parse_script("elevate:g.json:ps:echo :cmd: hi").expect("parses"),
            vec![Step::ElevatedRun {
                grant_path: "g.json".into(),
                shell: CommandShell::PowerShell,
                command: "echo :cmd: hi".into(),
            }],
            "the separator must be the EARLIEST shell token, not the first one that appears anywhere"
        );
        // And the mirror, so the fix is not just a reordered priority list: a Cmd command carrying
        // `:ps:` must still be Cmd.
        assert_eq!(
            parse_script("elevate:g.json:cmd:echo :ps: hi").expect("parses"),
            vec![Step::ElevatedRun {
                grant_path: "g.json".into(),
                shell: CommandShell::Cmd,
                command: "echo :ps: hi".into(),
            }]
        );
        assert!(parse_script("elevate:g.json:bash:ls").is_err(), "an unknown shell must be rejected");
        assert!(parse_script("elevate:g.json:cmd:").is_err(), "an empty command must be rejected");
        assert!(parse_script("elevate::cmd:whoami").is_err(), "an empty grant path must be rejected");
        assert!(parse_script("elevate:g.json").is_err(), "a missing shell segment must be rejected");
    }

    #[test]
    fn screenshot_step_parses_and_carries_no_input_events() {
        // `screenshot` sends RequestScreenshot on the Control channel and receives the PNG over
        // FileTransfer, so it expands to NO input events (the run loop handles it directly).
        assert_eq!(parse_script("screenshot").expect("parses"), vec![Step::Screenshot]);
        assert!(events_for(&Step::Screenshot).is_empty());
    }

    #[test]
    fn record_steps_parse_with_the_right_direction_and_no_input_events() {
        // Two kinds, not one with an argument — and the DIRECTION is what the assertions are about.
        // A `record-on` parsed as `record-off` would leave the VM operator looking for a file that
        // was never started while the probe reported success, which is the class of silent wrong-way
        // bug the `view-only`/`view-control` pair is also tested for.
        assert_eq!(parse_script("record-on").expect("parses"), vec![Step::Record(true)]);
        assert_eq!(parse_script("record-off").expect("parses"), vec![Step::Record(false)]);
        assert_eq!(
            parse_script("record-on;wait:2000;record-off").expect("parses"),
            vec![Step::Record(true), Step::Wait(2000), Step::Record(false)],
        );
        // Rides the Control channel, so it expands to NO input events (the run loop sends
        // Start/StopRecording and prints the reply directly).
        assert!(events_for(&Step::Record(true)).is_empty());
        assert!(events_for(&Step::Record(false)).is_empty());
        // `record` alone is not a step: an unknown kind must be REJECTED rather than dropped, or a
        // typo becomes "the recording step did nothing".
        assert!(parse_script("record").is_err());
        assert!(parse_script("record:on").is_err());
    }

    #[test]
    fn listdir_step_parses_the_path_and_carries_no_input_events() {
        // `listdir:C:\Users` keeps the colon + backslash in the path (split_once, not split), an
        // empty path (`listdir:`) means "the drive roots", and it rides the Control channel so it
        // expands to NO input events (the run loop sends ListDirectory + prints the reply directly).
        assert_eq!(
            parse_script(r"listdir:C:\Users").expect("parses"),
            vec![Step::ListDir(r"C:\Users".to_string())],
        );
        assert_eq!(parse_script("listdir:").expect("parses"), vec![Step::ListDir(String::new())]);
        assert!(events_for(&Step::ListDir(r"C:\".to_string())).is_empty());
    }

    #[test]
    fn end_session_steps_parse_with_the_right_mode_and_no_input_events() {
        // `end` → plain end (uninstall=false), `end-uninstall` → "remove client" (uninstall=true).
        // Both ride the Control channel, so no input events; the boolean must not be inverted — an
        // `end` that uninstalled would wrongly wipe the agent.
        assert_eq!(
            parse_script("end;end-uninstall").expect("parses"),
            vec![Step::EndSession(false), Step::EndSession(true)],
        );
        assert!(events_for(&Step::EndSession(false)).is_empty());
        assert!(events_for(&Step::EndSession(true)).is_empty());
    }

    // --- M11 quality plan ---------------------------------------------------------------------

    #[test]
    fn quality_plan_parses_a_multi_phase_run() {
        // The shape a VM run actually uses: a baseline with adaptation off, then one axis per phase
        // so a byte-count change can be attributed to the lever that caused it.
        let plan = parse_quality_plan("0:bps=4000000,adaptive=0;10:bps=400000;20:fps=5;30:div=2,color=gray")
            .expect("parses");
        assert_eq!(plan.len(), 4);
        assert_eq!(plan[0].at_secs, 0);
        assert_eq!(plan[0].quality.max_bitrate_bps, 4_000_000);
        assert!(!plan[0].quality.adaptive);
        // Keys not named take the DEFAULT, not the previous step's value — each step is a complete
        // settings object on the wire, so a plan that read as a diff would silently carry state.
        assert_eq!(plan[1].quality.fps, QualitySettings::DEFAULT.fps);
        assert!(plan[1].quality.adaptive, "adaptive is not inherited from step 0");
        assert_eq!(plan[2].quality.fps, 5);
        assert_eq!(plan[3].quality.scale_div, 2);
        assert_eq!(plan[3].quality.color, ColorMode::Gray);
    }

    #[test]
    fn quality_plan_steps_are_sorted_by_time() {
        // Out-of-order steps in a hand-written plan must still fire in time order, or a "restore"
        // step would be applied before the change it is meant to undo.
        let plan = parse_quality_plan("20:fps=5;0:bps=400000;10:div=2").expect("parses");
        assert_eq!(
            plan.iter().map(|s| s.at_secs).collect::<Vec<_>>(),
            vec![0, 10, 20]
        );
    }

    #[test]
    fn quality_plan_rejects_a_malformed_spec_instead_of_skipping_it() {
        // Same rule as --script: a silently dropped step turns a typo into "the feature does not
        // work", which is the exact false negative this tool exists to avoid.
        assert!(parse_quality_plan("0:bps").is_err(), "key with no value");
        assert!(parse_quality_plan("0:nope=1").is_err(), "unknown key");
        assert!(parse_quality_plan("0:color=purple").is_err(), "unknown colour");
        assert!(parse_quality_plan("abc:bps=1").is_err(), "non-numeric time");
        assert!(parse_quality_plan("0:fps=x").is_err(), "non-numeric value");
        assert!(parse_quality_plan("bps=1").is_err(), "missing the time prefix");
        assert_eq!(parse_quality_plan("").expect("empty is legal"), vec![]);
    }

    #[test]
    fn a_bucket_reports_frames_and_the_rtp_timestamp_delta() {
        // The observable that separates a FRAME-RATE change from a bitrate change. Three distinct
        // timestamps 18000 ticks apart is 5 fps on the 90 kHz video clock; the packet count is
        // deliberately higher than the frame count, because one frame is many packets.
        let mut b = Bucket::default();
        for (ts, len) in [(1000u32, 900usize), (1000, 900), (19_000, 900), (37_000, 900)] {
            b.packets += 1;
            b.bytes += len as u64;
            b.timestamps.insert(ts);
        }
        assert_eq!(b.packets, 4, "four packets");
        assert_eq!(b.timestamps.len(), 3, "but only three frames");
        assert_eq!(b.mean_ts_delta(), 18_000.0, "= 5 fps at 90 kHz");
        assert_eq!(b.kbps(1.0), 28.8);
        // A single frame yields no delta rather than a misleading zero-based one.
        let mut one = Bucket::default();
        one.timestamps.insert(7);
        assert_eq!(one.mean_ts_delta(), 0.0);
        assert_eq!(Bucket::default().mean_ts_delta(), 0.0, "and an empty bucket never divides by zero");
    }

    #[test]
    fn sas_parses_and_expands_to_the_single_sas_event() {
        // `sas` is a bare keyword (no colon). It must NOT decompose into Ctrl/Alt/Del key events —
        // those are dropped by Windows — but into exactly one InputEvent::Sas, which the agent
        // routes to SendSAS. This is the step the VM secure-desktop-via-CAD check drives.
        let steps = parse_script("wait:500;sas").expect("parses");
        assert_eq!(steps, vec![Step::Wait(500), Step::Sas]);
        assert_eq!(events_for(&Step::Sas), vec![InputEvent::Sas]);
    }
}
