# DeskRally changes to webrtc-ice

This directory began as an unmodified copy of webrtc-ice 0.11.0 from crates.io
(MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE). DeskRally patches it in
through `[patch.crates-io]` in the workspace Cargo.toml.

DeskRally changed it to support TURN over TCP and TLS, so an agent on a network
that blocks UDP still has a relay.
