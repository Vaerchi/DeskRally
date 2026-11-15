//! The agent's **build identity**: what version of the agent is actually running on a machine.
//!
//! Before this module the fleet had no version at all. Nothing in `crates/agent-windows` or
//! `crates/agent-core` referenced `CARGO_PKG_VERSION`, and the control plane's `Machine` carried no
//! version column — so "what is actually deployed out there" was literally unanswerable. That
//! question is the prerequisite for every part of agent auto-update (docs/21 §2): a rollout that
//! cannot be observed cannot be staged, canaried, soaked, or rolled back.
//!
//! # What this is NOT
//!
//! * **Not the protocol version.** [`rmt_protocol::PROTOCOL_VERSION`] describes the wire; this
//!   describes the build. They move independently.
//! * **Not identity, and never an authorization input.** [`AGENT_VERSION`] is asserted by the agent
//!   over the network and is therefore attacker-controlled on any unauthenticated path. It is
//!   inventory for a human to read, in the same category as the OS string. It must never be parsed
//!   to decide what an agent is allowed to do, and it must never enter the agent-auth signing
//!   preimage (`rmt_protocol::agent_auth`), which is byte-pinned to the Go verifier.
//!
//! # Shape
//!
//! `<crate version>+<short git sha>`, e.g. `0.0.1+0594362`. The `+` is
//! [semver build metadata](https://semver.org/#spec-item-10): it is explicitly ignored when
//! comparing precedence, which is exactly right — two builds of `0.0.1` from different commits are
//! the same *version* and different *builds*, and that is what the fleet view needs to show.

/// The value [`AGENT_VERSION`] carries when the commit could not be determined at build time.
///
/// Kept in sync with `build.rs`'s own `PLACEHOLDER` by [`placeholder_matches_build_script`].
pub const PLACEHOLDER_SHA: &str = "unknown";

/// The short git commit this binary was built from, or [`PLACEHOLDER_SHA`].
///
/// Stamped by `build.rs`. See that file for why a dirty-tree flag was deliberately rejected.
pub const GIT_SHA: &str = env!("RMT_GIT_SHA");

/// This agent's full build identity — `<crate version>+<short git sha>`.
///
/// Reported to signaling on every `register_agent` and surfaced in the console's fleet view.
pub const AGENT_VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "+", env!("RMT_GIT_SHA"));

/// The crate version half of [`AGENT_VERSION`], without the build metadata.
pub const AGENT_SEMVER: &str = env!("CARGO_PKG_VERSION");

/// Whether this binary was built without a resolvable commit.
///
/// True means the build degraded (no git on PATH, not a checkout, a source export). The agent still
/// runs — refusing to build without git would be a far worse trade — but a fleet reporting
/// placeholder versions cannot be used to verify a rollout, so anything that *acts* on versions
/// should treat this as "unknown", never as "up to date".
#[must_use]
pub fn is_placeholder() -> bool {
    GIT_SHA == PLACEHOLDER_SHA
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build script and this module each spell the placeholder independently; a divergence
    /// would make `is_placeholder()` silently always-false, and an unstamped fleet would look
    /// perfectly healthy. build.rs cannot be imported, so the literal is asserted here and the
    /// build script names this test in a comment.
    #[test]
    fn placeholder_matches_build_script() {
        assert_eq!(
            PLACEHOLDER_SHA, "unknown",
            "build.rs writes the literal \"unknown\"; changing one without the other breaks \
             is_placeholder()"
        );
    }

    #[test]
    fn agent_version_is_semver_plus_build_metadata() {
        let (semver, sha) = AGENT_VERSION
            .split_once('+')
            .expect("AGENT_VERSION must be <semver>+<sha>");

        assert_eq!(semver, AGENT_SEMVER, "the half before + is the crate version");
        assert_eq!(sha, GIT_SHA, "the half after + is the stamped commit");

        // Establish the premise before asserting on it: a test that only checked "contains a +"
        // would pass on `+`.
        assert!(!semver.is_empty(), "crate version must not be empty");
        assert!(!sha.is_empty(), "sha half must not be empty");
        assert_eq!(
            semver.split('.').count(),
            3,
            "expected a three-part crate version, got {semver:?}"
        );
    }

    /// The one property that distinguishes a real stamp from a degraded build. This deliberately
    /// does NOT fail when the SHA is a placeholder — a source export must still pass its tests —
    /// but it does pin that a NON-placeholder value is a plausible git short hash, which is what
    /// catches a build.rs that emits something malformed.
    #[test]
    fn a_real_stamp_looks_like_a_git_short_sha() {
        if is_placeholder() {
            // Degraded build. Nothing to assert beyond the two agreeing, which the test above does.
            return;
        }
        assert!(
            (4..=40).contains(&GIT_SHA.len()),
            "git short sha out of range: {GIT_SHA:?}"
        );
        assert!(
            GIT_SHA.chars().all(|c| c.is_ascii_hexdigit()),
            "git short sha must be hex: {GIT_SHA:?}"
        );
    }

    /// AGENT_VERSION travels on the wire and into a Postgres `text` column. A stray newline or NUL
    /// would corrupt a log line or trip the control plane's control-character rejection, and the
    /// value is a compile-time constant so this can be proven rather than validated at runtime.
    #[test]
    fn agent_version_is_a_single_clean_line() {
        assert!(
            !AGENT_VERSION.chars().any(|c| c.is_control()),
            "AGENT_VERSION must contain no control characters: {AGENT_VERSION:?}"
        );
        assert!(
            AGENT_VERSION.len() <= 128,
            "AGENT_VERSION must stay well inside the server-side bound: {AGENT_VERSION:?}"
        );
    }
}
