//! Mutating backstage operations — the OS-changing side of the tool panels (process kill,
//! registry write, service control). These are the bodies behind the Tier-2/3 requests in the
//! [`crate::backstage::Dispatcher`]; they are only ever reached *after* the dispatcher's
//! capability check, guard rail, and confirmation gate have passed. Nothing here re-authorizes
//! — that is the dispatcher's job — but nothing here is reachable except through it.
//!
//! Each operation returns a structured [`OpError`] on failure so the dispatcher can audit a
//! precise `Outcome::Failed`. Real implementations are Windows-only; the portable surface
//! returns [`OpError::Unsupported`] off Windows so the dispatcher compiles everywhere.

pub mod process;
pub mod registry;
pub mod service;

#[derive(Debug, thiserror::Error)]
pub enum OpError {
    #[error("operation not supported on this platform")]
    Unsupported,
    #[error("target not found: {0}")]
    NotFound(String),
    #[error("access denied (needs elevation?): {0}")]
    AccessDenied(String),
    #[error("windows API {api} failed: {source}")]
    #[cfg(windows)]
    Api { api: &'static str, source: windows::core::Error },
    #[error("{0}")]
    Other(String),
}
