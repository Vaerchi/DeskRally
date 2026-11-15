# DeskRally changes to webrtc-sctp

This directory is a copy of webrtc-sctp 0.17.3 from crates.io (rebased from 0.10.0 on 2026-11-14)
(MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), patched in through
`[patch.crates-io]` in the workspace Cargo.toml.

DeskRally changed it so that a failed UDP send no longer closes the SCTP
association. A transient route failure, including WSAEINVAL (10022) on Windows,
is retried within a 30-second bound.

The patch is all in src/association/mod.rs: `is_transient_send_error`, the send-failure branch and deadline
arm in `write_loop`, and `TransientSendBudget` with its tests at the end of the file. Run them with
`cargo test --manifest-path third_party/webrtc-sctp/Cargo.toml --lib deskrally`. Two upstream tests
(fuzz_artifact_test) fail standalone because the crates.io package omits fuzz/artifacts.
