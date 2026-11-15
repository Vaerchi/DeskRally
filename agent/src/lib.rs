//! rmt-agent — remote support agent library.
//!
//! Early scaffold. The headless backstage surface is the first fleshed-out area; see
//! [`backstage`] and `docs/04-backstage.md`. Platform-specific code is `cfg(windows)`-gated
//! so the crate structure and the platform-agnostic pieces (RBAC, audit) can be built and
//! unit-tested on any host, while the Win32 modules are exercised on Windows.

pub mod backstage;
pub mod elevation;
pub mod session_policy;
pub mod transport;
/// The signed agent-update manifest and its verification (docs/21 step 2). Lives here, beside
/// [`elevation`] and [`session_policy`], because it is a signed-artifact trust model rather than
/// Windows code: it must build and be tested on any host, and `crates/agent-windows` is
/// `cfg(windows)` in its entirety — a type defined there is invisible to `cargo check` on Linux.
/// **Nothing in it downloads, stages or applies anything.**
pub mod update;
