//! DeskRally patch: TURN over TCP and TLS (docs/50).
//!
//! Upstream gathers relay candidates over UDP only; `gather_candidates_relay` logs "Unable to handle
//! URL" for `turn:…?transport=tcp` and `turns:…`. This module is the whole of the hook: the embedding
//! application registers a dialer once, and relay gathering hands it every TCP-transport TURN URL. The
//! dialer returns a packet-style [`Conn`] to the TURN server (STUN and ChannelData framed over the
//! stream), which the unchanged TURN client then uses exactly as it uses a UDP socket. The relayed
//! address the server allocates is still UDP toward the peer (RFC 8656 / RFC 8835 §3.4).
//!
//! No dialer registered: TCP and TLS URLs are skipped exactly as before.

use std::sync::{Arc, OnceLock};

use async_trait::async_trait;
use util::Conn;

use crate::url::Url;

/// Opens a stream to a TURN server and frames it as a packet [`Conn`].
#[async_trait]
pub trait RelayStreamDialer: Send + Sync {
    /// Dial `url` (scheme `turn` or `turns`, transport `tcp`). An `Err` skips this server, logged by
    /// the caller, like any other relay gathering failure.
    async fn dial(&self, url: &Url) -> Result<Arc<dyn Conn + Send + Sync>, String>;
}

static DIALER: OnceLock<Arc<dyn RelayStreamDialer>> = OnceLock::new();

/// Register the process-wide dialer. Returns false if one was already registered (the first wins).
pub fn set_relay_stream_dialer(dialer: Arc<dyn RelayStreamDialer>) -> bool {
    DIALER.set(dialer).is_ok()
}

pub(crate) fn relay_stream_dialer() -> Option<Arc<dyn RelayStreamDialer>> {
    DIALER.get().cloned()
}
