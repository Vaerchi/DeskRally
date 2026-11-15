//! The multiplexed channel model. One session carries many logical channels, each with its
//! own reliability and priority policy (ADR-007). On QUIC these map to streams/datagrams; on
//! WebRTC to media tracks + data channels; over a TCP/WS fallback we emulate the mux.

use serde::{Deserialize, Serialize};

/// Well-known channel identities. Stable u8 tags — do not renumber (wire-compatibility).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum ChannelId {
    /// Control/handshake: capability negotiation, session lifecycle. Reliable, tiny.
    Control = 0,
    /// Mouse/keyboard events, controller -> agent. Reliable, ordered, HIGHEST priority, tiny.
    Input = 1,
    /// Screen video, agent -> controller. Partial reliability (drop stale frames), high volume.
    Video = 2,
    /// Clipboard sync, bidirectional. Reliable, small.
    Clipboard = 3,
    /// In-session chat, bidirectional. Reliable, tiny.
    Chat = 4,
    /// File transfer, bidirectional. Reliable, LOWEST priority (must yield to video+input).
    FileTransfer = 5,
    /// Backstage tool RPC (shell, panels), bidirectional. Reliable.
    Backstage = 6,
}

impl ChannelId {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Self::Control,
            1 => Self::Input,
            2 => Self::Video,
            3 => Self::Clipboard,
            4 => Self::Chat,
            5 => Self::FileTransfer,
            6 => Self::Backstage,
            _ => return None,
        })
    }

    /// Scheduling priority — higher wins when the transport must choose what to send next.
    /// Input beats video beats file transfer, so a big copy never delays a keystroke.
    pub fn priority(self) -> u8 {
        match self {
            ChannelId::Input => 250,
            ChannelId::Control => 200,
            ChannelId::Clipboard => 150,
            ChannelId::Chat => 150,
            ChannelId::Backstage => 140,
            ChannelId::Video => 100,
            ChannelId::FileTransfer => 10,
        }
    }

    /// Whether every byte must be delivered reliably. Video tolerates loss (request a keyframe
    /// instead of stalling); everything else is reliable.
    pub fn reliable(self) -> bool {
        !matches!(self, ChannelId::Video)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_ids_round_trip_through_u8() {
        for c in [
            ChannelId::Control, ChannelId::Input, ChannelId::Video, ChannelId::Clipboard,
            ChannelId::Chat, ChannelId::FileTransfer, ChannelId::Backstage,
        ] {
            assert_eq!(ChannelId::from_u8(c as u8), Some(c));
        }
        assert_eq!(ChannelId::from_u8(200), None);
    }

    #[test]
    fn input_outranks_video_outranks_files() {
        assert!(ChannelId::Input.priority() > ChannelId::Video.priority());
        assert!(ChannelId::Video.priority() > ChannelId::FileTransfer.priority());
    }

    #[test]
    fn only_video_is_lossy() {
        assert!(!ChannelId::Video.reliable());
        assert!(ChannelId::Input.reliable());
        assert!(ChannelId::FileTransfer.reliable());
    }
}
