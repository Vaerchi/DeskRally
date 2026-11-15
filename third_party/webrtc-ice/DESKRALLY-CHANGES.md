# DeskRally changes to webrtc-ice

This directory is a copy of webrtc-ice 0.17.3 from crates.io (rebased from 0.11.0 on 2026-11-14)
(MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE). DeskRally patches it in
through `[patch.crates-io]` in the workspace Cargo.toml.

DeskRally changed it to support TURN over TCP and TLS, so an agent on a network
that blocks UDP still has a relay.

The patch is src/relay_dialer.rs, its `pub mod` line in src/lib.rs, and one branch in
`gather_candidates_relay` (src/agent/agent_gather.rs). Diff: `git diff <pristine commit> -- third_party/webrtc-ice`.
