//! Shared wire protocol — the contract every component (agent, relay, signaling, viewer)
//! builds on. Defines: stable identities, the multiplexed channel model (ADR-007), the
//! frame format, and the signaling/rendezvous message set (ADR-002).
//!
//! Keep this crate small, dependency-light, and stable — changing it ripples everywhere. It
//! is deliberately transport-agnostic: it describes *what* is exchanged, not *how* bytes move
//! (WebRTC in v1, QUIC later — see docs/02-architecture.md ADR-001).

use serde::{Deserialize, Serialize};

pub mod agent_auth;
pub mod channel;
pub mod directive;
pub mod frame;
pub mod signaling;

pub use channel::ChannelId;
pub use frame::{Frame, FrameError};

/// Wire protocol version, negotiated at connect. Agents must interoperate N-2 releases (an
/// unattended fleet can't be force-updated in lockstep — see docs/03-roadmap.md).
pub const PROTOCOL_VERSION: u16 = 1;

/// Stable, permanent identifier for an agent (a controlled machine). Decoupled from network
/// location so reconnection-after-roaming and NAT changes work. Assigned at enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub uuid::Uuid);

/// Identifies one live control session between a controller and an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub uuid::Uuid);

/// A relay-assigned token that both half-connections present so the (dumb) relay can pair
/// them without understanding the session. Issued by the authenticated signaling server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RelayToken(pub uuid::Uuid);

impl DeviceId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
impl Default for DeviceId {
    fn default() -> Self {
        Self::new()
    }
}
impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl SessionId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}
impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}
