//! `rmt-agent-core` — the platform-agnostic **brain** of the remote-management agent.
//!
//! This crate is the shared core that the per-OS layers (Windows / macOS / Linux) build on. It
//! deliberately contains **no** platform code and **no** transport implementation: instead it
//! defines the seams those layers plug into, and the pure logic that lives above them.
//!
//! Layers, bottom to top:
//!
//! * [`platform`] — traits the OS crates implement: [`platform::ScreenCapturer`],
//!   [`platform::InputSink`], [`platform::ServiceHost`]. The core drives these; it never calls a
//!   Win32/Cocoa/X11 API directly.
//! * [`transport`] — the [`transport::Transport`] trait (ADR-001 seam): WebRTC today, QUIC
//!   later. Ships an in-memory [`transport::LoopbackTransport`] for tests.
//! * [`session`] — a [`session::Session`] that owns the end-to-end [`rmt_crypto::SessionKeys`]
//!   and multiplexes [`rmt_protocol::ChannelId`] frames: seal-on-send, open-on-recv, with the
//!   channel id bound as AEAD associated data.
//! * [`reconnect`] — a deterministic exponential [`reconnect::Backoff`] for the agent→relay
//!   supervision loop.
//!
//! The crate re-exports the shared protocol/crypto types it builds on so downstream OS crates
//! depend on one surface.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod chat;
pub mod clipboard;
pub mod control;
pub mod deployment;
pub mod deployment_pass;
pub mod elevation_gate;
pub mod encode;
pub mod file_transfer;
pub mod guest_end;
pub mod guest_ui;
pub mod input_codec;
pub mod platform;
pub mod quality;
pub mod reconnect;
pub mod relay_transport;
pub mod scale;
pub mod session;
pub mod support_ui;
pub mod synth;
pub mod text;
pub mod transport;
pub mod version;

// Convenience re-exports so OS layers can `use rmt_agent_core::{ChannelId, Frame, Role, ...}`.
pub use rmt_crypto::{Handshake, Role, SessionKeys};
pub use rmt_protocol::{ChannelId, Frame, RelayToken};

pub use chat::{ChatCodecError, ChatEntry, ChatFrom, ChatMessage, Transcript};
pub use clipboard::{Clipboard, ClipboardCodecError, ClipboardMessage};
pub use control::{ControlCodecError, ControlMessage, MonitorDesc};
pub use deployment::{is_pass_mode, is_unconfigured, BUILD_MODE, CONTROL_PLANE_URL, PASS_ROOT_KEY};
pub use encode::{EncodeError, EncodedFrame, SoftwareDecoder, SoftwareEncoder};
pub use file_transfer::FileTransferError;
pub use guest_ui::{
    GuestCommand, GuestEvent, GuestLine, GuestPresenter, GuestSurface, GuestUi, SessionInfo,
    SessionPhase,
};
pub use input_codec::InputCodecError;
pub use platform::{
    composite_frames, CapturedFrame, InputButton, InputEvent, InputSink, MonitorInfo,
    ScreenCapturer, ServiceHost, TopologySnapshot, COMPOSITE_MONITOR_ID,
};
pub use quality::{ColorMode, QualitySettings};
pub use reconnect::Backoff;
pub use relay_transport::RelayTransport;
pub use scale::scale_bgra;
pub use session::{Session, SessionError};
pub use support_ui::{message as support_message, Failure as SupportFailure, SupportMessage};
pub use synth::{frame_number, monitor_number, CaptureObserver, SyntheticCapturer};
pub use text::{is_display_hostile, sanitize_display};
pub use transport::{LoopbackTransport, Transport, TransportError};
