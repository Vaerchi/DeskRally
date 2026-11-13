//! Transport codecs between the agent and the technician (browser or native controller).
//!
//! This module owns the *wire formats*, kept separate from the OS-facing tool code so both can
//! be tested in isolation. The actual socket plumbing (WebSocket via the relay, or a WebRTC
//! data channel — see `docs/02-architecture.md` ADR-001) sits above these codecs and is
//! transport-agnostic: it moves opaque frames, and these types give them meaning.
//!
//!   * [`shell_ws`] — the interactive shell channel (one socket per shell).
//!   * [`backstage_api`] — the request/response backstage channel (panels + mutating ops).
//!   * [`shell_authz`] — who may open the shell demo's socket (docs/25 F16).

pub mod backstage_api;
pub mod shell_ws;

// NOT cfg(windows), though the server it guards is: there is nothing platform-specific about
// deciding whether a request is authorized, and a security guard gated to one platform is tested
// on one platform. Keeping it here also lets F16's regressions run without a ConPTY (docs/25).
pub mod shell_authz;

#[cfg(windows)]
pub mod shell_server;
