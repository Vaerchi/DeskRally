# DeskRally changes to webrtc-sctp

This directory is a copy of the webrtc-sctp crate from crates.io
(MIT OR Apache-2.0; see LICENSE-MIT and LICENSE-APACHE), patched in through
`[patch.crates-io]` in the workspace Cargo.toml.

DeskRally changed it so that a failed UDP send no longer closes the SCTP
association. A transient route failure, including WSAEINVAL (10022) on Windows,
is retried within a 30-second bound.
