use super::*;

#[test]
fn observer_rule_allows_read_only_and_restricting_messages() {
    let messages = [
        ControlMessage::RequestMonitors,
        ControlMessage::SelectMonitor { id: 0 },
        ControlMessage::FrameDisplayed { selection_gen: 0 },
        ControlMessage::RequestQuality,
        ControlMessage::RequestScreenshot,
        ControlMessage::WatchedMonitors { monitors: Some(vec![0]) },
        ControlMessage::ListDirectory { path: String::new() },
        ControlMessage::InstallGrant { signed_grant: "{}".into() },
        ControlMessage::InstallSessionPolicy { signed_policy: "{}".into() },
        ControlMessage::SetViewOnly { enabled: false },
        ControlMessage::SetViewOnly { enabled: true },
    ];
    for msg in messages {
        assert!(matches!(observer_rule(&msg), ObserverRule::Allow), "{msg:?}");
    }
}

#[test]
fn observer_rule_preserves_view_only_gates() {
    let messages = [
        ControlMessage::SetInputBlocked { blocked: true },
        ControlMessage::SetMonitorBlanked { blanked: true },
        ControlMessage::RebootGuest { safe_mode: false },
        ControlMessage::LockWorkstation,
        ControlMessage::LogOffGuest,
        ControlMessage::ShutDownGuest,
        ControlMessage::LaunchTool { tool: "task_manager".into() },
        ControlMessage::EndSession { uninstall: false, directive: None },
        ControlMessage::EndSession { uninstall: true, directive: None },
    ];
    for msg in messages {
        assert!(matches!(observer_rule(&msg), ObserverRule::ViewOnlyGated), "{msg:?}");
    }
}

#[test]
fn observer_rule_refuses_recording_control() {
    for msg in [ControlMessage::StartRecording, ControlMessage::StopRecording] {
        assert!(matches!(observer_rule(&msg), ObserverRule::Refuse), "{msg:?}");
    }
}

#[test]
fn observer_rule_refuses_agent_to_controller_messages() {
    let messages = [
        ControlMessage::SelectMonitorAccepted { selection_gen: 0 },
        ControlMessage::MonitorPinned { monitor_id: 0 },
        ControlMessage::Error { message: "refused".into() },
        ControlMessage::GrantInstalled,
        ControlMessage::BackstageFeatures { features: vec!["confirm".into()] },
        ControlMessage::ViewOnlyApplied { enabled: true },
        ControlMessage::SessionEndedByGuest,
    ];
    for msg in messages {
        assert!(matches!(observer_rule(&msg), ObserverRule::Refuse), "{msg:?}");
    }
}

/// Round-trip a message and assert its exact canonical JSON, so the shape is pinned and the
/// TypeScript controller can be tested against the same strings.
fn round_trip(msg: ControlMessage, expect_json: &str) {
    let bytes = encode(&msg);
    assert_eq!(
        std::str::from_utf8(&bytes).unwrap(),
        expect_json,
        "canonical JSON for {msg:?}"
    );
    let back = decode(&bytes).expect("decode");
    assert_eq!(back, msg, "round-trip for {msg:?}");
}

/// A valid `Error` frame padded with trailing JSON whitespace to exactly `len` bytes.
fn padded_error_frame(len: usize) -> Vec<u8> {
    let mut bytes = encode(&ControlMessage::Error { message: "x".into() });
    assert!(bytes.len() <= len);
    bytes.resize(len, b' ');
    bytes
}

#[test]
fn decode_accepts_frame_at_exactly_the_limit() {
    let bytes = padded_error_frame(MAX_CONTROL_WIRE_LEN);
    assert_eq!(bytes.len(), MAX_CONTROL_WIRE_LEN);
    assert_eq!(
        decode(&bytes).expect("frame at the limit decodes"),
        ControlMessage::Error { message: "x".into() }
    );
}

#[test]
fn decode_refuses_valid_json_one_byte_over_the_limit() {
    let bytes = padded_error_frame(MAX_CONTROL_WIRE_LEN + 1);
    let err = decode(&bytes).expect_err("over-limit frame is refused");
    let msg = err.to_string();
    assert!(msg.contains(&(MAX_CONTROL_WIRE_LEN + 1).to_string()), "{msg}");
    assert!(msg.contains(&MAX_CONTROL_WIRE_LEN.to_string()), "{msg}");
}

/// One frame per command-carrying variant, each carrying `command`.
fn command_frames(command: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (
            "RunCommand",
            encode(&ControlMessage::RunCommand {
                command: command.into(),
                shell: CommandShell::Cmd,
                as_user: false,
                request_id: None,
            }),
        ),
        (
            "ElevatedRun",
            encode(&ControlMessage::ElevatedRun {
                signed_elevation: "{}".into(),
                command: command.into(),
                shell: CommandShell::Cmd,
            }),
        ),
    ]
}

#[test]
fn command_line_realistic_multiline_tabbed_quoted_and_empty_decode() {
    for command in ["echo \"a b\"\tc\r\nwhoami\n", ""] {
        for (name, bytes) in command_frames(command) {
            let msg = decode(&bytes).unwrap_or_else(|e| panic!("{name} {command:?}: {e}"));
            match msg {
                ControlMessage::RunCommand { command: got, .. }
                | ControlMessage::ElevatedRun { command: got, .. } => assert_eq!(got, command),
                other => panic!("unexpected {other:?}"),
            }
        }
    }
}

#[test]
fn command_line_ascii_boundary_is_exact_for_both_variants() {
    for (name, bytes) in command_frames(&"a".repeat(MAX_COMMAND_LINE_UTF16)) {
        assert!(decode(&bytes).is_ok(), "{name} at the limit decodes");
    }
    for (name, bytes) in command_frames(&"a".repeat(MAX_COMMAND_LINE_UTF16 + 1)) {
        assert!(decode(&bytes).is_err(), "{name} one over the limit is refused");
    }
}

#[test]
fn command_line_is_measured_in_utf16_units_not_chars() {
    // U+1F600 is one char but two UTF-16 units.
    for (name, bytes) in command_frames(&"\u{1F600}".repeat(16383)) {
        assert!(decode(&bytes).is_ok(), "{name}: 32766 units decodes");
    }
    let over = "\u{1F600}".repeat(16384);
    assert_eq!(over.chars().count(), 16384);
    assert_eq!(over.encode_utf16().count(), 32768);
    for (name, bytes) in command_frames(&over) {
        assert!(decode(&bytes).is_err(), "{name}: 32768 units is refused");
    }
}

#[test]
fn command_line_one_mib_is_refused_and_names_the_limit() {
    for (name, bytes) in command_frames(&"a".repeat(1024 * 1024)) {
        let msg = decode(&bytes).expect_err(name).to_string();
        assert!(msg.contains(&MAX_COMMAND_LINE_UTF16.to_string()), "{name}: {msg}");
    }
}

#[test]
fn command_line_cap_does_not_apply_to_command_result_output() {
    let bytes = encode(&ControlMessage::CommandResult {
        exit_code: 0,
        stdout: "o".repeat(MAX_COMMAND_LINE_UTF16 * 4),
        stderr: "e".repeat(MAX_COMMAND_LINE_UTF16 * 4),
        truncated: false,
        timed_out: false,
    });
    assert!(matches!(decode(&bytes), Ok(ControlMessage::CommandResult { .. })));
}

/// One frame per signed-blob variant, each carrying `blob`.
fn signed_blob_frames(blob: &str) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("InstallGrant", encode(&ControlMessage::InstallGrant { signed_grant: blob.into() })),
        (
            "InstallSessionPolicy",
            encode(&ControlMessage::InstallSessionPolicy { signed_policy: blob.into() }),
        ),
        (
            "ElevatedRun",
            encode(&ControlMessage::ElevatedRun {
                signed_elevation: blob.into(),
                command: "whoami".into(),
                shell: CommandShell::Cmd,
            }),
        ),
    ]
}

/// An opaque JSON-looking blob of exactly `len` bytes.
fn blob_of_len(len: usize) -> String {
    let prefix = r#"{"claims":{"p":""#;
    let suffix = r#""},"sig":"ab"}"#;
    assert!(len >= prefix.len() + suffix.len());
    format!("{prefix}{}{suffix}", "a".repeat(len - prefix.len() - suffix.len()))
}

#[test]
fn signed_blob_realistic_size_decodes_for_each_variant() {
    let blob = blob_of_len(2048);
    for (name, bytes) in signed_blob_frames(&blob) {
        assert!(decode(&bytes).is_ok(), "{name} with a 2 KiB blob must decode");
    }
}

#[test]
fn signed_blob_cap_is_64_kib_and_boundary_is_exact() {
    assert_eq!(MAX_SIGNED_BLOB_BYTES, 65536);
    let at = blob_of_len(MAX_SIGNED_BLOB_BYTES);
    assert_eq!(at.len(), 65536);
    for (name, bytes) in signed_blob_frames(&at) {
        assert!(decode(&bytes).is_ok(), "{name} with exactly 65536 bytes must decode");
    }
    let over = blob_of_len(MAX_SIGNED_BLOB_BYTES + 1);
    for (name, bytes) in signed_blob_frames(&over) {
        assert!(decode(&bytes).is_err(), "{name} with 65537 bytes must be refused");
    }
}

#[test]
fn signed_blob_one_mebibyte_is_refused_and_message_names_the_limit() {
    let blob = blob_of_len(1024 * 1024);
    for (name, bytes) in signed_blob_frames(&blob) {
        let msg = decode(&bytes).expect_err(name).to_string();
        assert!(msg.contains("65536"), "{name}: {msg}");
        assert!(msg.contains(&(1024 * 1024).to_string()), "{name}: {msg}");
    }
}

#[test]
fn large_error_message_still_decodes_despite_signed_blob_cap() {
    let big = "e".repeat(MAX_SIGNED_BLOB_BYTES * 4);
    let msg = ControlMessage::Error { message: big };
    assert_eq!(decode(&encode(&msg)).expect("large Error decodes"), msg);
}

fn list_frame(path: &str) -> Vec<u8> {
    encode(&ControlMessage::ListDirectory { path: path.into() })
}

#[test]
fn list_directory_accepts_ordinary_empty_unicode_unc_and_extended_paths() {
    for p in ["", r"C:\Users\Zoë", r"\\host\share", r"\\?\C:\x", r"C:\"] {
        assert_eq!(
            decode(&list_frame(p)).expect(p),
            ControlMessage::ListDirectory { path: p.into() }
        );
    }
}

#[test]
fn list_directory_refuses_control_characters() {
    for p in [
        "C:\\a\n",
        "C:\\a\r\nFORGED audit line",
        "C:\\a\u{0}b",
        "C:\\a\u{1f}",
    ] {
        let err = decode(&list_frame(p)).expect_err("control char refused");
        let msg = err.to_string();
        assert!(msg.contains("32767"), "{msg}");
        assert!(msg.contains("control characters"), "{msg}");
    }
}

/// DEL and C1 are LEGAL in Windows file names (only C0 and NUL are not), so a folder whose name
/// carries one must stay listable.
#[test]
fn list_directory_accepts_del_and_c1_which_windows_allows() {
    for p in ["C:\\a\u{7f}", "C:\\a\u{85}", "C:\\a\u{9f}b"] {
        assert_eq!(decode(&list_frame(p)).unwrap(), ControlMessage::ListDirectory { path: p.into() }, "{p:?}");
    }
}

#[test]
fn list_directory_length_limit_is_32767_ascii_chars() {
    assert!(decode(&list_frame(&"a".repeat(MAX_LIST_DIRECTORY_PATH_UTF16))).is_ok());
    assert!(decode(&list_frame(&"a".repeat(MAX_LIST_DIRECTORY_PATH_UTF16 + 1))).is_err());
}

#[test]
fn list_directory_limit_is_measured_in_utf16_units() {
    // U+1F600 is one char but two UTF-16 units.
    assert!(decode(&list_frame(&"\u{1F600}".repeat(16383))).is_ok());
    assert!(decode(&list_frame(&"\u{1F600}".repeat(16384))).is_err());
}

#[test]
fn directory_replies_with_control_characters_are_not_refused() {
    let listing = ControlMessage::DirectoryListing {
        path: "C:\\a\nb\u{0}".into(),
        entries: vec![],
        truncated: false,
        audit: None,
    };
    assert_eq!(decode(&encode(&listing)).expect("listing"), listing);
    let refused = ControlMessage::DirectoryListingRefused {
        path: "C:\\a\r\nb".into(),
        reason: "no".into(),
        audit: None,
    };
    assert_eq!(decode(&encode(&refused)).expect("refused"), refused);
}

fn launch_frame(tool: &str) -> Vec<u8> {
    encode(&ControlMessage::LaunchTool { tool: tool.into() })
}

#[test]
fn launch_tool_accepts_all_whitelisted_keys() {
    for k in ["task_manager", "registry_editor", "event_viewer", "services", "device_manager"] {
        assert_eq!(
            decode(&launch_frame(k)).expect(k),
            ControlMessage::LaunchTool { tool: k.into() }
        );
    }
}

#[test]
fn launch_tool_refuses_control_characters() {
    for k in [
        "task_manager\n",
        "task_manager\r\nFORGED log line",
        "task\u{0}manager",
        "task_manager\u{7f}",
        "task_manager\u{85}",
    ] {
        let err = decode(&launch_frame(k)).expect_err("control char refused");
        let msg = err.to_string();
        assert!(msg.contains("64 bytes"), "{msg}");
        assert!(msg.contains("control characters"), "{msg}");
    }
}

#[test]
fn launch_tool_length_limit_is_64_bytes() {
    assert!(decode(&launch_frame(&"a".repeat(MAX_LAUNCH_TOOL_KEY_BYTES))).is_ok());
    assert!(decode(&launch_frame(&"a".repeat(MAX_LAUNCH_TOOL_KEY_BYTES + 1))).is_err());
}

#[test]
fn launch_tool_refuses_a_1_mib_key() {
    assert!(decode(&launch_frame(&"a".repeat(1024 * 1024))).is_err());
}

#[test]
fn launch_tool_unknown_clean_and_empty_keys_still_decode() {
    for k in ["not_a_tool", ""] {
        assert_eq!(
            decode(&launch_frame(k)).expect(k),
            ControlMessage::LaunchTool { tool: k.into() }
        );
    }
}

#[test]
fn tool_launched_echo_with_control_characters_is_not_refused() {
    let echo = ControlMessage::ToolLaunched { tool: "a\r\nb\u{0}".into() };
    assert_eq!(decode(&encode(&echo)).expect("echo"), echo);
}

#[test]
fn decode_refuses_a_32_mib_valid_frame() {
    let bytes = padded_error_frame(32 * 1024 * 1024);
    assert!(decode(&bytes).is_err());
}

#[test]
fn decode_small_malformed_json_still_errors_via_serde() {
    let err = decode(b"{not json").expect_err("malformed");
    assert!(!err.to_string().contains("exceeds the"), "{err}");
    assert!(decode(b"").is_err());
}

#[test]
fn request_monitors_is_a_bare_tag() {
    // A unit variant carries no `c` under adjacent tagging.
    round_trip(ControlMessage::RequestMonitors, r#"{"t":"RequestMonitors"}"#);
}

#[test]
fn monitor_list_round_trips() {
    round_trip(
        ControlMessage::MonitorList {
            monitors: vec![
                MonitorDesc { id: 0, width: 1920, height: 1080, primary: true },
                MonitorDesc { id: 1, width: 1280, height: 1024, primary: false },
            ],
        },
        r#"{"t":"MonitorList","c":{"monitors":[{"id":0,"width":1920,"height":1080,"primary":true},{"id":1,"width":1280,"height":1024,"primary":false}]}}"#,
    );
}

#[test]
fn empty_monitor_list_round_trips() {
    round_trip(
        ControlMessage::MonitorList { monitors: vec![] },
        r#"{"t":"MonitorList","c":{"monitors":[]}}"#,
    );
}

#[test]
fn select_monitor_round_trips() {
    round_trip(
        ControlMessage::SelectMonitor { id: 2 },
        r#"{"t":"SelectMonitor","c":{"id":2}}"#,
    );
}

#[test]
fn select_composite_monitor_round_trips() {
    // The reserved view-all id is just a u32 on the wire (u32::MAX = 4294967295); the TS mirror
    // (control.test.ts) pins the identical string.
    round_trip(
        ControlMessage::SelectMonitor { id: crate::platform::COMPOSITE_MONITOR_ID },
        r#"{"t":"SelectMonitor","c":{"id":4294967295}}"#,
    );
}

#[test]
fn monitor_pinned_round_trips() {
    round_trip(
        ControlMessage::MonitorPinned { monitor_id: 2 },
        r#"{"t":"MonitorPinned","c":{"monitor_id":2}}"#,
    );
}

#[test]
fn error_round_trips() {
    round_trip(
        ControlMessage::Error { message: "unknown monitor id 7".into() },
        r#"{"t":"Error","c":{"message":"unknown monitor id 7"}}"#,
    );
}

#[test]
fn install_grant_round_trips() {
    // The signed grant rides as an opaque JSON string; the codec neither parses nor validates it.
    round_trip(
        ControlMessage::InstallGrant { signed_grant: r#"{"claims":{},"sig":"ab"}"#.into() },
        r#"{"t":"InstallGrant","c":{"signed_grant":"{\"claims\":{},\"sig\":\"ab\"}"}}"#,
    );
}

#[test]
fn grant_installed_is_a_bare_tag() {
    // Unit variant → no `c` under adjacent tagging (like RequestMonitors).
    round_trip(ControlMessage::GrantInstalled, r#"{"t":"GrantInstalled"}"#);
}

#[test]
fn request_backstage_features_is_a_bare_tag() {
    round_trip(ControlMessage::RequestBackstageFeatures, r#"{"t":"RequestBackstageFeatures"}"#);
    assert!(matches!(
        observer_rule(&ControlMessage::RequestBackstageFeatures),
        ObserverRule::Allow
    ));
}

#[test]
fn backstage_features_round_trips() {
    round_trip(
        ControlMessage::BackstageFeatures { features: vec!["confirm".into(), "file_manage".into()] },
        r#"{"t":"BackstageFeatures","c":{"features":["confirm","file_manage"]}}"#,
    );
}

#[test]
fn install_session_policy_round_trips() {
    // Like InstallGrant, the signed policy rides as an opaque JSON string — this crate neither
    // parses nor validates it (that is `rmt-agent`'s job, and depending on it would cycle).
    round_trip(
        ControlMessage::InstallSessionPolicy {
            signed_policy: r#"{"claims":{},"sig":"ab"}"#.into(),
        },
        r#"{"t":"InstallSessionPolicy","c":{"signed_policy":"{\"claims\":{},\"sig\":\"ab\"}"}}"#,
    );
}

/// docs/25 F03. The wire form is pinned because a viewer in another language decodes it, and an
/// agent whose announcement the console cannot read is an agent whose sessions all die at the
/// grace deadline.
#[test]
fn session_lease_required_round_trips() {
    round_trip(
        ControlMessage::SessionLeaseRequired { renew_within_ms: 15_000 },
        r#"{"t":"SessionLeaseRequired","c":{"renew_within_ms":15000}}"#,
    );
}

#[test]
fn session_policy_installed_round_trips() {
    round_trip(
        ControlMessage::SessionPolicyInstalled {
            access: "view_only".into(),
            view_only: true,
            allow_recording: true,
            require_recording: false,
        },
        r#"{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":false}}"#,
    );
    // `access` and `view_only` are independent on the wire: a `control` policy can still leave
    // the session view-only (the controller's own toggle, or a stricter earlier policy the
    // ratchet is holding). Encoding them as one field would lose that distinction.
    round_trip(
        ControlMessage::SessionPolicyInstalled {
            access: "control".into(),
            view_only: true,
            allow_recording: false,
            require_recording: false,
        },
        r#"{"t":"SessionPolicyInstalled","c":{"access":"control","view_only":true,"allow_recording":false,"require_recording":false}}"#,
    );
    // require_recording=true: the viewer must auto-start recording and the agent rejects StopRecording.
    round_trip(
        ControlMessage::SessionPolicyInstalled {
            access: "view_only".into(),
            view_only: true,
            allow_recording: true,
            require_recording: true,
        },
        r#"{"t":"SessionPolicyInstalled","c":{"access":"view_only","view_only":true,"allow_recording":true,"require_recording":true}}"#,
    );
}

/// `access` is a plain string, deliberately: a future third level must render on an older
/// controller rather than making the whole message undecodable. Pinned because switching it to
/// an enum would look like a tidy-up and would silently break forward compatibility.
///
/// An ABSENT `allow_recording` defaults to `true` (record-allowed) — backward-compatible: old
/// senders that do not know this field keep the permissive baseline.
#[test]
fn session_policy_installed_accepts_an_unfamiliar_access_level() {
    let decoded = decode(
        br#"{"t":"SessionPolicyInstalled","c":{"access":"future_level","view_only":false}}"#,
    )
    .expect("an unknown access level must still decode");
    match decoded {
        ControlMessage::SessionPolicyInstalled { access, view_only, allow_recording, require_recording } => {
            assert_eq!(access, "future_level");
            assert!(!view_only);
            assert!(allow_recording, "absent allow_recording must default to true");
            assert!(!require_recording, "absent require_recording must default to false");
        }
        other => panic!("decoded to the wrong variant: {other:?}"),
    }
}

#[test]
fn install_session_policy_requires_its_field() {
    assert!(decode(br#"{"t":"InstallSessionPolicy","c":{}}"#).is_err());
}

#[test]
fn rejects_garbage_and_unknown_variants() {
    assert!(decode(b"not json").is_err());
    assert!(decode(br#"{"t":"Nope"}"#).is_err());
}

// --- M11 quality control ---------------------------------------------------------------
//
// These six literals are the cross-language contract. `web/viewer/src/lib/control.test.ts`
// pins the SAME strings byte-for-byte; each file names the other in a comment. Reordering a
// struct field here silently changes the bytes, and only these assertions would catch it.

use crate::quality::{ColorMode, QualitySettings};

#[test]
fn request_quality_is_a_bare_tag() {
    round_trip(ControlMessage::RequestQuality, r#"{"t":"RequestQuality"}"#);
}

#[test]
fn set_quality_round_trips_at_the_defaults() {
    round_trip(
        ControlMessage::SetQuality { quality: QualitySettings::DEFAULT },
        r#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true}}}"#,
    );
}

/// The background signal's wire form is pinned; a missing flag is rejected, not defaulted.
#[test]
fn set_background_round_trips_and_requires_its_flag() {
    round_trip(ControlMessage::SetBackground { background: true }, r#"{"t":"SetBackground","c":{"background":true}}"#);
    round_trip(ControlMessage::SetBackground { background: false }, r#"{"t":"SetBackground","c":{"background":false}}"#);
    assert!(decode(br#"{"t":"SetBackground","c":{}}"#).is_err());
    assert_eq!(observer_rule(&ControlMessage::SetBackground { background: true }), ObserverRule::Allow);
}

#[test]
fn set_quality_round_trips_at_the_slow_link_end() {
    // A unit-only enum serializes as a bare string, so `color` is `"Gray"` and not an object.
    round_trip(
        ControlMessage::SetQuality {
            quality: QualitySettings {
                scale_div: 2,
                fps: 5,
                color: ColorMode::Gray,
                max_bitrate_bps: 400_000,
                adaptive: false,
            },
        },
        r#"{"t":"SetQuality","c":{"quality":{"scale_div":2,"fps":5,"color":"Gray","max_bitrate_bps":400000,"adaptive":false}}}"#,
    );
}

#[test]
fn quality_applied_round_trips() {
    round_trip(
        ControlMessage::QualityApplied {
            quality: QualitySettings {
                scale_div: 4,
                fps: 1,
                color: ColorMode::Gray,
                max_bitrate_bps: 100_000,
                adaptive: true,
            },
            encoder_bitrate_bps: 100_000,
            capped_by_policy: true,
        },
        r#"{"t":"QualityApplied","c":{"quality":{"scale_div":4,"fps":1,"color":"Gray","max_bitrate_bps":100000,"adaptive":true},"encoder_bitrate_bps":100000,"capped_by_policy":true}}"#,
    );
    round_trip(
        ControlMessage::QualityApplied {
            quality: QualitySettings::DEFAULT,
            encoder_bitrate_bps: 3_000_000,
            capped_by_policy: false,
        },
        r#"{"t":"QualityApplied","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000,"adaptive":true},"encoder_bitrate_bps":3000000,"capped_by_policy":false}}"#,
    );
}

#[test]
fn quality_stats_round_trips() {
    round_trip(
        ControlMessage::QualityStats {
            encoder_bitrate_bps: 742_000,
            measured_bitrate_bps: 731_520,
            fraction_lost_256: 13,
            rtt_ms: 24,
            width: 960,
            height: 540,
            feedback_reports: 42,
            fps_x100: 1_437,
            dropped_frames_total: 118,
        },
        // Wire key is "dropped_frames" (not "dropped_frames_total") — see field annotation.
        r#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}"#,
    );
}

/// `fps_x100` and `dropped_frames_total` are REQUIRED, like every other field on this wire.
///
/// Stated as its own test because these two are the newest and the most tempting to make
/// optional "for compatibility": a tolerant decoder would render a missing achieved frame rate
/// as `0`, i.e. as a total stall, which is a worse lie than refusing the message. The
/// absent-means-default rule is what shipped the `Option` whose `None` granted every
/// capability.
#[test]
fn the_new_telemetry_fields_are_not_optional() {
    // Wire key is "dropped_frames"; a message with the correct wire format minus fps_x100 must be rejected.
    assert!(
        decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"dropped_frames":0}}"#).is_err(),
        "a missing fps_x100 must be rejected, not read as a stalled stream"
    );
    assert!(
        decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":1,"measured_bitrate_bps":1,"fraction_lost_256":0,"rtt_ms":0,"width":8,"height":8,"feedback_reports":0,"fps_x100":0}}"#).is_err(),
        "a missing dropped_frames (wire key) must be rejected"
    );
}

/// Both deployed and current agents emit `"dropped_frames"` — the canonical wire key.
/// `"dropped_frames_total"` was the short-lived rename from the rejected commit 6a79bb3 and is
/// immediately reverted here. This test pins the revert: if a future change accidentally
/// restores the rename, a new agent would silently deliver zero to an old viewer (the old
/// viewer would read the unknown key as absent and decode the field as 0 with no error).
/// Hard-rejecting `"dropped_frames_total"` surfaces that regression as a decode failure
/// rather than as a silent zero on the operator's readout.
#[test]
fn dropped_frames_wire_key_compatibility() {
    // Old-agent / current-viewer: wire key "dropped_frames" — this is the canonical wire format.
    assert!(
        decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames":118}}"#).is_ok(),
        "QualityStats with wire key dropped_frames must be accepted"
    );
    assert!(
        decode(br#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#).is_ok(),
        "RecordingStopped with wire key dropped_frames must be accepted"
    );
    // Rejected-rename format "dropped_frames_total" must be rejected (not silently aliased).
    assert!(
        decode(br#"{"t":"QualityStats","c":{"encoder_bitrate_bps":742000,"measured_bitrate_bps":731520,"fraction_lost_256":13,"rtt_ms":24,"width":960,"height":540,"feedback_reports":42,"fps_x100":1437,"dropped_frames_total":118}}"#).is_err(),
        "QualityStats with rejected wire key dropped_frames_total must be rejected"
    );
    assert!(
        decode(br#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames_total":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#).is_err(),
        "RecordingStopped with rejected wire key dropped_frames_total must be rejected"
    );
}

#[test]
fn the_schema_owns_the_quality_constraint() {
    // The codec rejects a shape it cannot represent; it does NOT silently substitute a default.
    // A tolerant decoder here would mean an unparseable colour arrives as `Full` and the
    // operator's greyscale selection quietly does nothing.
    assert!(
        decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Sepia","max_bitrate_bps":3000000,"adaptive":true}}}"#).is_err(),
        "an unknown ColorMode must be rejected, not defaulted"
    );
    assert!(
        decode(br#"{"t":"SetQuality","c":{}}"#).is_err(),
        "a missing `quality` must be rejected — there is no partial update on this wire"
    );
    assert!(
        decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":1,"fps":30,"color":"Full","max_bitrate_bps":3000000}}}"#).is_err(),
        "a missing field must be rejected: an absent-means-default rule is what shipped the \
         Option whose None granted every capability"
    );
    // Out-of-RANGE is a different thing from out-of-SHAPE: the codec accepts it and the agent's
    // clamp is what tames it, so a hostile controller gets a working session at legal values
    // rather than a dropped frame.
    assert!(
        decode(br#"{"t":"SetQuality","c":{"quality":{"scale_div":0,"fps":0,"color":"Full","max_bitrate_bps":0,"adaptive":true}}}"#).is_ok(),
        "range is the clamp's job, not the codec's"
    );
}

// --- input block (privacy) -----------------------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn set_input_blocked_round_trips() {
    round_trip(
        ControlMessage::SetInputBlocked { blocked: true },
        r#"{"t":"SetInputBlocked","c":{"blocked":true}}"#,
    );
    round_trip(
        ControlMessage::SetInputBlocked { blocked: false },
        r#"{"t":"SetInputBlocked","c":{"blocked":false}}"#,
    );
}

#[test]
fn input_block_applied_round_trips() {
    round_trip(
        ControlMessage::InputBlockApplied { blocked: true },
        r#"{"t":"InputBlockApplied","c":{"blocked":true}}"#,
    );
    round_trip(
        ControlMessage::InputBlockApplied { blocked: false },
        r#"{"t":"InputBlockApplied","c":{"blocked":false}}"#,
    );
}

#[test]
fn input_block_requires_the_blocked_field() {
    // No partial shape on this wire (the recurring lesson): a missing `blocked` is rejected, not
    // read as some default.
    assert!(
        decode(br#"{"t":"SetInputBlocked","c":{}}"#).is_err(),
        "a missing `blocked` must be rejected"
    );
}

// --- monitor blank (privacy) ---------------------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn set_monitor_blanked_round_trips() {
    round_trip(
        ControlMessage::SetMonitorBlanked { blanked: true },
        r#"{"t":"SetMonitorBlanked","c":{"blanked":true}}"#,
    );
    round_trip(
        ControlMessage::SetMonitorBlanked { blanked: false },
        r#"{"t":"SetMonitorBlanked","c":{"blanked":false}}"#,
    );
}

#[test]
fn monitor_blanked_applied_round_trips() {
    round_trip(
        ControlMessage::MonitorBlankedApplied { blanked: true },
        r#"{"t":"MonitorBlankedApplied","c":{"blanked":true}}"#,
    );
    round_trip(
        ControlMessage::MonitorBlankedApplied { blanked: false },
        r#"{"t":"MonitorBlankedApplied","c":{"blanked":false}}"#,
    );
}

#[test]
fn monitor_blank_requires_the_blanked_field() {
    assert!(
        decode(br#"{"t":"SetMonitorBlanked","c":{}}"#).is_err(),
        "a missing `blanked` must be rejected"
    );
}

// --- view-only / presentation mode ---------------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn set_view_only_round_trips() {
    round_trip(
        ControlMessage::SetViewOnly { enabled: true },
        r#"{"t":"SetViewOnly","c":{"enabled":true}}"#,
    );
    round_trip(
        ControlMessage::SetViewOnly { enabled: false },
        r#"{"t":"SetViewOnly","c":{"enabled":false}}"#,
    );
}

#[test]
fn view_only_applied_round_trips() {
    round_trip(
        ControlMessage::ViewOnlyApplied { enabled: true },
        r#"{"t":"ViewOnlyApplied","c":{"enabled":true}}"#,
    );
    round_trip(
        ControlMessage::ViewOnlyApplied { enabled: false },
        r#"{"t":"ViewOnlyApplied","c":{"enabled":false}}"#,
    );
}

#[test]
fn set_view_only_requires_the_enabled_field() {
    assert!(
        decode(br#"{"t":"SetViewOnly","c":{}}"#).is_err(),
        "a missing `enabled` must be rejected"
    );
}

// --- reboot guest (remote support) ---------------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn reboot_guest_round_trips() {
    round_trip(
        ControlMessage::RebootGuest { safe_mode: true },
        r#"{"t":"RebootGuest","c":{"safe_mode":true}}"#,
    );
    round_trip(
        ControlMessage::RebootGuest { safe_mode: false },
        r#"{"t":"RebootGuest","c":{"safe_mode":false}}"#,
    );
}

#[test]
fn reboot_scheduled_round_trips() {
    round_trip(
        ControlMessage::RebootScheduled { safe_mode: true },
        r#"{"t":"RebootScheduled","c":{"safe_mode":true}}"#,
    );
    round_trip(
        ControlMessage::RebootScheduled { safe_mode: false },
        r#"{"t":"RebootScheduled","c":{"safe_mode":false}}"#,
    );
}

// --- lock workstation (remote support) -----------------------------------------------------
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn lock_workstation_round_trips_as_bare_tags() {
    // Both directions carry no content, so they serialize as just `{"t":…}` (like RequestScreenshot).
    round_trip(ControlMessage::LockWorkstation, r#"{"t":"LockWorkstation"}"#);
    round_trip(ControlMessage::WorkstationLocked, r#"{"t":"WorkstationLocked"}"#);
}

// --- log off the guest (remote support) ----------------------------------------------------
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn log_off_round_trips_as_bare_tags() {
    // Both directions carry no content (like lock), so they serialize as just `{"t":…}`.
    round_trip(ControlMessage::LogOffGuest, r#"{"t":"LogOffGuest"}"#);
    round_trip(ControlMessage::LogOffScheduled, r#"{"t":"LogOffScheduled"}"#);
}

// --- shut down the guest (remote support) --------------------------------------------------
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn shut_down_round_trips_as_bare_tags() {
    // Both directions carry no content (like lock/logoff), so they serialize as just `{"t":…}`.
    round_trip(ControlMessage::ShutDownGuest, r#"{"t":"ShutDownGuest"}"#);
    round_trip(ControlMessage::ShutDownScheduled, r#"{"t":"ShutDownScheduled"}"#);
}

#[test]
fn reboot_guest_requires_the_safe_mode_field() {
    // Same no-partial-shape rule as the input block: a missing `safe_mode` must be rejected, not
    // silently read as `false`. A reboot command is the last thing you want defaulting.
    assert!(
        decode(br#"{"t":"RebootGuest","c":{}}"#).is_err(),
        "a missing `safe_mode` must be rejected"
    );
}

// --- system tool launchers (remote support) ------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn launch_tool_round_trips() {
    round_trip(
        ControlMessage::LaunchTool { tool: "task_manager".into() },
        r#"{"t":"LaunchTool","c":{"tool":"task_manager"}}"#,
    );
    round_trip(
        ControlMessage::LaunchTool { tool: "registry_editor".into() },
        r#"{"t":"LaunchTool","c":{"tool":"registry_editor"}}"#,
    );
}

#[test]
fn tool_launched_round_trips() {
    round_trip(
        ControlMessage::ToolLaunched { tool: "services".into() },
        r#"{"t":"ToolLaunched","c":{"tool":"services"}}"#,
    );
}

#[test]
fn launch_tool_requires_the_tool_field() {
    // No partial shape: a missing `tool` is rejected, not read as an empty string (which the
    // agent's whitelist would reject anyway, but the codec must not invent the field).
    assert!(
        decode(br#"{"t":"LaunchTool","c":{}}"#).is_err(),
        "a missing `tool` must be rejected"
    );
}

// --- one-line command bar (remote support) -------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn run_command_round_trips() {
    // A unit-only CommandShell serializes as a BARE STRING ("Cmd"/"PowerShell"), not an object —
    // same rule as ColorMode. Field order is command, shell, as_user (declaration order).
    round_trip(
        ControlMessage::RunCommand {
            command: "whoami".into(),
            shell: CommandShell::Cmd,
            as_user: false,
            request_id: None,
        },
        r#"{"t":"RunCommand","c":{"command":"whoami","shell":"Cmd","as_user":false}}"#,
    );
    round_trip(
        ControlMessage::RunCommand {
            command: "Get-Date".into(),
            shell: CommandShell::PowerShell,
            as_user: true,
            request_id: None,
        },
        r#"{"t":"RunCommand","c":{"command":"Get-Date","shell":"PowerShell","as_user":true}}"#,
    );
}

#[test]
fn list_directory_round_trips() {
    // Field order: path (the sole field). A drive path round-trips (note the escaped backslash).
    round_trip(
        ControlMessage::ListDirectory { path: r"C:\".into() },
        r#"{"t":"ListDirectory","c":{"path":"C:\\"}}"#,
    );
    // An empty path means "list the drive roots".
    round_trip(
        ControlMessage::ListDirectory { path: String::new() },
        r#"{"t":"ListDirectory","c":{"path":""}}"#,
    );
}

#[test]
fn directory_listing_round_trips() {
    // A DirEntry serializes as {"name","is_dir","size","modified_unix"} (serde field order);
    // DirectoryListing is {"path","entries","truncated","audit"}. Directories-first ordering is a
    // property of the AGENT (dir_list.rs), not the wire, so the vector here is written in that
    // order deliberately.
    round_trip(
        ControlMessage::DirectoryListing {
            path: r"C:\".into(),
            entries: vec![
                DirEntry { name: "Windows".into(), is_dir: true, size: 0, modified_unix: 1_700_000_000 },
                DirEntry { name: "readme.txt".into(), is_dir: false, size: 42, modified_unix: 1_700_000_001 },
            ],
            truncated: false,
            audit: None,
        },
        r#"{"t":"DirectoryListing","c":{"path":"C:\\","entries":[{"name":"Windows","is_dir":true,"size":0,"modified_unix":1700000000},{"name":"readme.txt","is_dir":false,"size":42,"modified_unix":1700000001}],"truncated":false,"audit":null}}"#,
    );
    // An empty listing (an existing but empty directory) is a valid, non-error answer, and a
    // capped one sets `truncated`.
    round_trip(
        ControlMessage::DirectoryListing {
            path: String::new(),
            entries: vec![],
            truncated: true,
            audit: None,
        },
        r#"{"t":"DirectoryListing","c":{"path":"","entries":[],"truncated":true,"audit":null}}"#,
    );
}

/// docs/25 F04. A refusal is its own message because it is a different EVENT from a failure —
/// and because it has to carry an audit record, which `Error` has nowhere to put.
#[test]
fn directory_listing_refused_round_trips() {
    round_trip(
        ControlMessage::DirectoryListingRefused {
            path: r"\\attacker\share".into(),
            reason: "network (UNC) paths are not browsable".into(),
            audit: None,
        },
        r#"{"t":"DirectoryListingRefused","c":{"path":"\\\\attacker\\share","reason":"network (UNC) paths are not browsable","audit":null}}"#,
    );
}

/// The same guarantee `a_sealed_audit_event_rides_the_recording_ack_unmodified` makes for
/// recording, for the two file-browser replies: the control plane recomputes the event's
/// canonical preimage at `/audit/ingest` and treats any field-level difference as tampering, so
/// a codec that "helpfully" reshaped the event would present to an operator as the agent forging
/// its own audit trail.
#[test]
fn a_sealed_audit_event_rides_a_directory_reply_unmodified() {
    let ev = serde_json::json!({
        "seq": 3,
        "action": {"kind": "file_browse", "path": r"C:\Users"},
        "outcome": {"result": "ok"},
        "hash": "b8f1",
    });
    let listing = ControlMessage::DirectoryListing {
        path: r"C:\Users".into(),
        entries: vec![],
        truncated: false,
        audit: Some(ev.clone()),
    };
    let back = decode(&encode(&listing)).expect("round trip");
    match back {
        ControlMessage::DirectoryListing { audit: Some(got), .. } => {
            assert_eq!(got, ev, "the sealed event must survive the codec byte for byte");
        }
        other => panic!("expected a DirectoryListing carrying an audit event, got {other:?}"),
    }

    let refused = ControlMessage::DirectoryListingRefused {
        path: r"\\attacker\share".into(),
        reason: "network (UNC) paths are not browsable".into(),
        audit: Some(ev.clone()),
    };
    let back = decode(&encode(&refused)).expect("round trip");
    match back {
        ControlMessage::DirectoryListingRefused { audit: Some(got), .. } => {
            assert_eq!(got, ev, "a refusal's event must survive the codec too");
        }
        other => panic!("expected a DirectoryListingRefused carrying an audit event, got {other:?}"),
    }
}

#[test]
fn directory_messages_reject_missing_fields() {
    // Same strict-wire rule as everywhere else: no field has an absent-means-default.
    assert!(
        decode(br#"{"t":"ListDirectory","c":{}}"#).is_err(),
        "a missing `path` must be rejected"
    );
    assert!(
        decode(br#"{"t":"DirectoryListing","c":{"path":"C:\\","entries":[]}}"#).is_err(),
        "a missing `truncated` must be rejected"
    );
    assert!(
        decode(br#"{"t":"DirectoryListing","c":{"path":"C:\\","truncated":false}}"#).is_err(),
        "a missing `entries` must be rejected"
    );
    assert!(
        decode(br#"{"t":"DirectoryListing","c":{"path":"","entries":[{"name":"x","is_dir":true,"size":0}],"truncated":false}}"#).is_err(),
        "a DirEntry missing `modified_unix` must be rejected"
    );
    assert!(
        decode(br#"{"t":"DirectoryListingRefused","c":{"path":"C:\\"}}"#).is_err(),
        "a refusal missing `reason` must be rejected"
    );
    // `audit` is the one exception on these two messages, and deliberately so: an agent that
    // predates docs/25 F04 sends no `audit` key, and a reply that decoded as an error there
    // would break the file browser to protect a record that agent never sealed. An absent key is
    // `None` — the trail is thinner, but nothing false is asserted.
    assert!(
        matches!(
            decode(br#"{"t":"DirectoryListing","c":{"path":"","entries":[],"truncated":false}}"#),
            Ok(ControlMessage::DirectoryListing { audit: None, .. })
        ),
        "an absent `audit` key must decode as no event"
    );
    assert!(
        matches!(
            decode(br#"{"t":"DirectoryListingRefused","c":{"path":"","reason":"no"}}"#),
            Ok(ControlMessage::DirectoryListingRefused { audit: None, .. })
        ),
        "an absent `audit` key must decode as no event"
    );
}

#[test]
fn command_result_round_trips() {
    // A clean success: the exit code, both captured streams, and the two flags.
    round_trip(
        ControlMessage::CommandResult {
            exit_code: 0,
            stdout: "nt authority\\system\r\n".into(),
            stderr: String::new(),
            truncated: false,
            timed_out: false,
        },
        r#"{"t":"CommandResult","c":{"exit_code":0,"stdout":"nt authority\\system\r\n","stderr":"","truncated":false,"timed_out":false}}"#,
    );
    // A killed-on-timeout, truncated result: exit_code is the kill code (a real value, not null),
    // and both flags are set. A negative exit code round-trips as a signed integer.
    round_trip(
        ControlMessage::CommandResult {
            exit_code: -1,
            stdout: "partial".into(),
            stderr: "boom".into(),
            truncated: true,
            timed_out: true,
        },
        r#"{"t":"CommandResult","c":{"exit_code":-1,"stdout":"partial","stderr":"boom","truncated":true,"timed_out":true}}"#,
    );
}

#[test]
fn run_command_rejects_a_missing_field_or_unknown_shell() {
    // No partial shape on this wire: every field is required.
    assert!(
        decode(br#"{"t":"RunCommand","c":{"command":"whoami","as_user":false}}"#).is_err(),
        "a missing `shell` must be rejected"
    );
    assert!(
        decode(br#"{"t":"RunCommand","c":{"shell":"Cmd","as_user":false}}"#).is_err(),
        "a missing `command` must be rejected"
    );
    // `as_user` is a bool with no default — a missing one is rejected, not read as false. Running a
    // command as SYSTEM vs the user is exactly the kind of thing that must never silently default.
    assert!(
        decode(br#"{"t":"RunCommand","c":{"command":"whoami","shell":"Cmd"}}"#).is_err(),
        "a missing `as_user` must be rejected"
    );
    // An unknown shell is rejected, not defaulted to Cmd (which would run a PowerShell script line
    // through the wrong interpreter).
    assert!(
        decode(br#"{"t":"RunCommand","c":{"command":"x","shell":"Bash","as_user":false}}"#).is_err(),
        "an unknown CommandShell must be rejected"
    );
}

// --- elevated run (loop 87, docs/01 §3) ---------------------------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn elevated_run_round_trips() {
    // The signed elevation rides as an opaque JSON string, exactly like InstallGrant and
    // InstallSessionPolicy; this crate neither parses nor validates it.
    // Field order is declaration order: signed_elevation, command, shell.
    round_trip(
        ControlMessage::ElevatedRun {
            signed_elevation: r#"{"claims":{},"sig":"ab"}"#.into(),
            command: "whoami /groups".into(),
            shell: CommandShell::Cmd,
        },
        r#"{"t":"ElevatedRun","c":{"signed_elevation":"{\"claims\":{},\"sig\":\"ab\"}","command":"whoami /groups","shell":"Cmd"}}"#,
    );
    round_trip(
        ControlMessage::ElevatedRun {
            signed_elevation: "{}".into(),
            command: "Get-Date".into(),
            shell: CommandShell::PowerShell,
        },
        r#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"Get-Date","shell":"PowerShell"}}"#,
    );
}

#[test]
fn elevation_denied_round_trips() {
    round_trip(
        ControlMessage::ElevationDenied {
            reason: "elevation grant is for a different session".into(),
        },
        r#"{"t":"ElevationDenied","c":{"reason":"elevation grant is for a different session"}}"#,
    );
}

#[test]
fn elevated_run_rejects_a_missing_field_or_unknown_shell() {
    // No partial shape here either — and the stakes are higher than on RunCommand. A missing
    // `signed_elevation` that decoded as "" would hand the agent an unauthorized elevated run
    // request and rely entirely on the verifier to notice; a missing field must never get that
    // far.
    assert!(
        decode(br#"{"t":"ElevatedRun","c":{"command":"whoami","shell":"Cmd"}}"#).is_err(),
        "a missing `signed_elevation` must be rejected"
    );
    assert!(
        decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","shell":"Cmd"}}"#).is_err(),
        "a missing `command` must be rejected"
    );
    assert!(
        decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x"}}"#).is_err(),
        "a missing `shell` must be rejected"
    );
    assert!(
        decode(br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Bash"}}"#)
            .is_err(),
        "an unknown CommandShell must be rejected"
    );
    assert!(
        decode(br#"{"t":"ElevationDenied","c":{}}"#).is_err(),
        "a missing `reason` must be rejected"
    );
    // The full shape DOES decode, so the assertions above are not passing because the variant
    // itself is unknown to the codec.
    assert!(decode(
        br#"{"t":"ElevatedRun","c":{"signed_elevation":"{}","command":"x","shell":"Cmd"}}"#
    )
    .is_ok());
}

// --- configurable session-end behavior (remote support) -----------------------------------
//
// Cross-language contract: `web/viewer/src/lib/control.test.ts` pins the SAME strings.

#[test]
fn end_session_round_trips() {
    round_trip(
        ControlMessage::EndSession { uninstall: false, directive: None },
        r#"{"t":"EndSession","c":{"uninstall":false}}"#,
    );
    round_trip(
        ControlMessage::EndSession { uninstall: true, directive: None },
        r#"{"t":"EndSession","c":{"uninstall":true}}"#,
    );
}

#[test]
fn session_ending_round_trips() {
    round_trip(
        ControlMessage::SessionEnding { uninstall: true },
        r#"{"t":"SessionEnding","c":{"uninstall":true}}"#,
    );
    round_trip(
        ControlMessage::SessionEnding { uninstall: false },
        r#"{"t":"SessionEnding","c":{"uninstall":false}}"#,
    );
}

#[test]
fn session_ended_by_guest_is_a_bare_tag() {
    round_trip(ControlMessage::SessionEndedByGuest, r#"{"t":"SessionEndedByGuest"}"#);
}

#[test]
fn admin_rights_messages_have_pinned_shapes() {
    round_trip(ControlMessage::RequestAdminRights, r#"{"t":"RequestAdminRights"}"#);
    round_trip(
        ControlMessage::AdminRightsAvailable { available: false, reason: Some("the signed-in user is not an administrator".into()) },
        r#"{"t":"AdminRightsAvailable","c":{"available":false,"reason":"the signed-in user is not an administrator"}}"#,
    );
    round_trip(
        ControlMessage::AdminRightsResult { state: AdminRightsState::Granted, reason: None },
        r#"{"t":"AdminRightsResult","c":{"state":"granted","reason":null}}"#,
    );
    // An older or terser sender may omit the reason.
    assert_eq!(
        decode(br#"{"t":"AdminRightsResult","c":{"state":"declined"}}"#).unwrap(),
        ControlMessage::AdminRightsResult { state: AdminRightsState::Declined, reason: None }
    );
}

#[test]
fn input_handoff_messages_have_pinned_shapes() {
    round_trip(
        ControlMessage::InputHandoffAvailable { available: true },
        r#"{"t":"InputHandoffAvailable","c":{"available":true}}"#,
    );
    round_trip(
        ControlMessage::HandInputControl { to_session: "11111111-2222-3333-4444-555555555555".into() },
        r#"{"t":"HandInputControl","c":{"to_session":"11111111-2222-3333-4444-555555555555"}}"#,
    );
    round_trip(
        ControlMessage::InputControlChanged {
            owner_session: Some("11111111-2222-3333-4444-555555555555".into()),
            owner_name: Some("Jordan".into()),
            mode: InputControlMode::Owned,
        },
        r#"{"t":"InputControlChanged","c":{"owner_session":"11111111-2222-3333-4444-555555555555","owner_name":"Jordan","mode":"owned"}}"#,
    );
    round_trip(
        ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Shared },
        r#"{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"shared"}}"#,
    );
    round_trip(
        ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Blocked },
        r#"{"t":"InputControlChanged","c":{"owner_session":null,"owner_name":null,"mode":"blocked"}}"#,
    );
    // A terser sender may omit the owner fields on a Shared/Blocked snapshot.
    assert_eq!(
        decode(br#"{"t":"InputControlChanged","c":{"mode":"shared"}}"#).unwrap(),
        ControlMessage::InputControlChanged { owner_session: None, owner_name: None, mode: InputControlMode::Shared }
    );
    // A control character or an over-long target id is refused before the agent resolves it.
    assert!(decode(br#"{"t":"HandInputControl","c":{"to_session":"ok-id"}}"#).is_ok());
    assert!(decode(b"{\"t\":\"HandInputControl\",\"c\":{\"to_session\":\"bad\\u0007id\"}}").is_err());
    let long = "a".repeat(MAX_SESSION_ID_BYTES + 1);
    let frame = format!("{{\"t\":\"HandInputControl\",\"c\":{{\"to_session\":\"{long}\"}}}}");
    assert!(decode(frame.as_bytes()).is_err());
}

#[test]
fn observers_cannot_request_admin_rights() {
    assert!(matches!(observer_rule(&ControlMessage::RequestAdminRights), ObserverRule::Refuse));
}

#[test]
fn end_session_can_carry_the_signed_uninstall_directive_and_omits_it_when_absent() {
    // docs/65 D-C2: the directive rides inside EndSession; an old controller's frame (no field) still decodes, and an
    // absent directive stays off the wire (the pre-D-C2 shape is byte-identical).
    assert_eq!(
        decode(br#"{"t":"EndSession","c":{"uninstall":true}}"#).unwrap(),
        ControlMessage::EndSession { uninstall: true, directive: None }
    );
    let with = ControlMessage::EndSession { uninstall: true, directive: Some("{\"claims\":{}}".into()) };
    let wire = encode(&with);
    assert_eq!(decode(&wire).unwrap(), with);
    assert!(std::str::from_utf8(&wire).unwrap().contains("\"directive\""));
}

#[test]
fn end_session_requires_the_uninstall_field() {
    // No partial shape: a missing `uninstall` must be rejected, not read as `false`. "remove
    // client" is exactly the kind of destructive choice that must never silently default.
    assert!(
        decode(br#"{"t":"EndSession","c":{}}"#).is_err(),
        "a missing `uninstall` must be rejected"
    );
}

#[test]
fn transfer_dir_round_trips() {
    // Pins the exact wire shape so control.test.ts can assert the same literal.
    round_trip(
        ControlMessage::TransferDir { path: r"C:\rmt-agent\transfers".to_string() },
        r#"{"t":"TransferDir","c":{"path":"C:\\rmt-agent\\transfers"}}"#,
    );
}

#[test]
fn request_screenshot_is_a_bare_tag() {
    // A unit variant → no `c` under adjacent tagging (like RequestMonitors). The TS mirror
    // (control.test.ts) pins the identical string. Success comes back as a PNG on the FileTransfer
    // channel, not a Control reply, so there is no paired response variant here.
    round_trip(ControlMessage::RequestScreenshot, r#"{"t":"RequestScreenshot"}"#);
}

#[test]
fn recording_start_and_stop_are_bare_tags() {
    // Unit variants both ways (like RequestScreenshot). The TS mirror pins the same strings.
    round_trip(ControlMessage::StartRecording, r#"{"t":"StartRecording"}"#);
    round_trip(ControlMessage::StopRecording, r#"{"t":"StopRecording"}"#);
}

#[test]
fn recording_replies_round_trip() {
    round_trip(
        ControlMessage::RecordingStarted {
            started_at_unix_ms: 1_764_000_000_123,
            audit: None,
        },
        r#"{"t":"RecordingStarted","c":{"started_at_unix_ms":1764000000123,"audit":null}}"#,
    );
    round_trip(
        ControlMessage::RecordingStopped {
            segments: 2,
            frames: 913,
            payload_bytes: 4_211_337,
            truncated: None,
            dropped_frames_total: 0,
            directory: r"C:\rmt-agent\recordings".to_string(),
            audit: None,
        },
        // Wire key is "dropped_frames" (retained for deployed-agent compatibility).
        r#"{"t":"RecordingStopped","c":{"segments":2,"frames":913,"payload_bytes":4211337,"truncated":null,"dropped_frames":0,"directory":"C:\\rmt-agent\\recordings","audit":null}}"#,
    );
    round_trip(
        ControlMessage::RecordingStopped {
            segments: 1,
            frames: 12,
            payload_bytes: 900,
            truncated: Some("queue_full".to_string()),
            dropped_frames_total: 47,
            directory: String::new(),
            audit: None,
        },
        r#"{"t":"RecordingStopped","c":{"segments":1,"frames":12,"payload_bytes":900,"truncated":"queue_full","dropped_frames":47,"directory":"","audit":null}}"#,
    );
}

/// The sealed event rides on the ack, and survives the round trip byte-identically.
///
/// A round trip and not merely an encode, deliberately: the console re-posts this event VERBATIM
/// to `POST /audit/ingest`, which recomputes its canonical preimage and rejects any field-level
/// difference as tampering. A codec that reordered, re-typed or dropped one key here would
/// present to an operator as "the control plane thinks the agent forged its own audit trail" —
/// and because the chain is strictly sequential, the rejection would wedge every later event in
/// the session, not just this one.
#[test]
fn a_sealed_audit_event_rides_the_recording_ack_unmodified() {
    let ev = serde_json::json!({
        "id": "44444444-4444-4444-4444-444444444444",
        "seq": 0,
        "session_id": "11111111-1111-1111-1111-111111111111",
        "technician_id": "22222222-2222-2222-2222-222222222222",
        "machine_id": "33333333-3333-3333-3333-333333333333",
        "occurred_at_unix_ms": 1_730_000_000_000i64,
        "action": { "kind": "recording_started", "started_at_unix_ms": 1_730_000_000_000i64,
                    "directory": "D:/rec" },
        "outcome": { "result": "ok" },
        "prev_hash": "",
        "hash": "9f9ad6566756dd1bac7537dada03baf3e6b0ec799180e6be19c126163d9c63e4",
    });
    let msg = ControlMessage::RecordingStarted {
        started_at_unix_ms: 1_730_000_000_000,
        audit: Some(ev.clone()),
    };
    match decode(&encode(&msg)).expect("the ack decodes") {
        ControlMessage::RecordingStarted { audit: Some(got), .. } => {
            assert_eq!(got, ev, "the sealed event must survive the codec byte-for-byte");
        }
        other => panic!("expected RecordingStarted carrying an audit event, got {other:?}"),
    }
}

/// An ack from an agent that sealed nothing (no control-plane session was vouched for) must
/// still decode: `audit` is `#[serde(default)]`, so an ABSENT key is `None` rather than a decode
/// failure. Unlike `truncated` two tests up, absence here carries no dangerous second reading —
/// no event is no event — which is exactly why the two fields are treated differently.
#[test]
fn a_recording_ack_without_an_audit_key_decodes_as_no_event() {
    let m = decode(br#"{"t":"RecordingStarted","c":{"started_at_unix_ms":7}}"#)
        .expect("an ack with no audit key must decode");
    assert!(matches!(
        m,
        ControlMessage::RecordingStarted { started_at_unix_ms: 7, audit: None }
    ));
}
#[test]
fn a_recording_stopped_without_truncated_is_rejected_rather_than_read_as_complete() {
    // THE misreading this message exists to prevent. `truncated: null` is the "ran to
    // completion" value and is on the wire explicitly; an ABSENT key must not decode to it,
    // because the difference between the two is the difference between a complete recording and
    // one that silently stops partway — and the file looks identical either way.
    assert!(
        decode(
            // Wire key is "dropped_frames" (not "dropped_frames_total").
            br#"{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"dropped_frames":0,"directory":""}}"#
        )
        .is_err(),
        "a missing `truncated` must be rejected, not read as 'completed'"
    );
    // And the explicit null IS accepted, so the assertion above is about absence and not about
    // null — the two would be indistinguishable with only the negative case.
    assert!(decode(
        br#"{"t":"RecordingStopped","c":{"segments":1,"frames":1,"payload_bytes":1,"truncated":null,"dropped_frames":0,"directory":""}}"#
    )
    .is_ok());
    assert!(
        decode(br#"{"t":"RecordingStarted","c":{}}"#).is_err(),
        "a missing `started_at_unix_ms` must be rejected, not read as the epoch"
    );
}

#[test]
fn command_result_requires_all_fields() {
    // `exit_code` is a plain i32, so a missing one is rejected by serde rather than defaulting to 0
    // — the trap the fps_x100/dropped_frames test also guards: a tolerant decoder would render a
    // command that never ran as one that exited cleanly.
    assert!(
        decode(br#"{"t":"CommandResult","c":{"stdout":"","stderr":"","truncated":false,"timed_out":false}}"#).is_err(),
        "a missing `exit_code` must be rejected, not read as 0"
    );
    assert!(
        decode(br#"{"t":"CommandResult","c":{"exit_code":0,"stdout":"","stderr":"","timed_out":false}}"#).is_err(),
        "a missing `truncated` must be rejected"
    );
}

// docs/69: the binding messages round-trip and refuse anything but fixed-length hex.
#[test]
fn binding_messages_round_trip_and_refuse_bad_fields() {
    let nonce = "ab".repeat(32);
    let sig = "cd".repeat(64);
    for msg in [
        ControlMessage::BindStart { grant: "{\"claims\":{}}".into(), console_nonce: nonce.clone() },
        ControlMessage::BindAgentProof { agent_nonce: nonce.clone(), sig: sig.clone() },
        ControlMessage::BindConsoleProof { sig: sig.clone() },
        ControlMessage::BindResult { ok: true, reason: None },
        ControlMessage::BindResult { ok: false, reason: Some("bad_signature".into()) },
    ] {
        assert_eq!(decode(&encode(&msg)).unwrap(), msg);
    }
    for bad in [
        format!(r#"{{"t":"BindStart","c":{{"grant":"x","console_nonce":"{}"}}}}"#, "ab".repeat(31)),
        format!(r#"{{"t":"BindStart","c":{{"grant":"x","console_nonce":"{}"}}}}"#, "zz".repeat(32)),
        format!(r#"{{"t":"BindAgentProof","c":{{"agent_nonce":"{nonce}","sig":"{}"}}}}"#, "cd".repeat(63)),
        format!(r#"{{"t":"BindConsoleProof","c":{{"sig":"{}"}}}}"#, "cd".repeat(65)),
        format!(
            r#"{{"t":"BindStart","c":{{"grant":"{}","console_nonce":"{nonce}"}}}}"#,
            "g".repeat(MAX_SIGNED_BLOB_BYTES + 1)
        ),
    ] {
        assert!(decode(bad.as_bytes()).is_err(), "accepted: {}", &bad[..bad.len().min(80)]);
    }
    // A missing `reason` on BindResult decodes as None (the agent omits it on success).
    assert_eq!(
        decode(br#"{"t":"BindResult","c":{"ok":true}}"#).unwrap(),
        ControlMessage::BindResult { ok: true, reason: None }
    );
}

#[test]
fn binding_messages_observer_rules() {
    let nonce = "ab".repeat(32);
    let sig = "cd".repeat(64);
    assert_eq!(observer_rule(&ControlMessage::BindStart { grant: String::new(), console_nonce: nonce.clone() }), ObserverRule::Allow);
    assert_eq!(observer_rule(&ControlMessage::BindConsoleProof { sig: sig.clone() }), ObserverRule::Allow);
    assert_eq!(observer_rule(&ControlMessage::BindAgentProof { agent_nonce: nonce, sig }), ObserverRule::Refuse);
    assert_eq!(observer_rule(&ControlMessage::BindResult { ok: true, reason: None }), ObserverRule::Refuse);
}

#[test]
fn run_receipt_wire_keeps_legacy_dispatch_and_uses_flat_signed_claims() {
    let request = "24242424-2424-4424-8424-242424242424";
    let legacy = br#"{"t":"RunCommand","c":{"command":"echo hi","shell":"Cmd","as_user":false,"future":true}}"#;
    assert!(matches!(decode(legacy).unwrap(), ControlMessage::RunCommand { request_id: None, .. }));
    round_trip(
        ControlMessage::RunCommand {
            command: "echo hi".into(),
            shell: CommandShell::Cmd,
            as_user: false,
            request_id: Some(request.into()),
        },
        r#"{"t":"RunCommand","c":{"command":"echo hi","shell":"Cmd","as_user":false,"request_id":"24242424-2424-4424-8424-242424242424"}}"#,
    );

    let signed = serde_json::json!({
        "claims": {
            "tenant_id": request,
            "device_id": "device",
            "session_id": request,
            "request_id": request,
            "shell": "cmd",
            "run_as": "system",
            "exec_sha256": "00".repeat(32),
            "outcome": "start_failed",
            "exit_code": null,
            "truncated": false,
            "finished_at_ms": 42
        },
        "sig": "ab".repeat(64)
    });
    let receipt = ControlMessage::RunReceipt {
        receipt: serde_json::from_value(signed.clone()).unwrap(),
    };
    let encoded = encode(&receipt);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encoded).unwrap(),
        serde_json::json!({ "t": "RunReceipt", "c": signed }),
    );
    assert_eq!(decode(&encoded).unwrap(), receipt);
    assert_eq!(observer_rule(&receipt), ObserverRule::Refuse);
}
