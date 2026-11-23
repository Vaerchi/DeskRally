//! The control-plane origin this binary was **built** to talk to.
//!
//! The first-contact support client (docs/27, docs/28) ships as ONE downloadable artifact and asks
//! the customer for a session code and nothing else — no URL. So the origin cannot come from argv,
//! from a config file (there is none; the attended path persists nothing), or from the code (the
//! code format belongs to the control plane, which is a different fact). It comes from the build:
//! `build.rs` stamps `RMT_CONTROL_PLANE_URL` and this module surfaces it.
//!
//! # Why the emptiness check lives here and the URL policy does not
//!
//! This crate is portable and has no notion of the enrollment URL policy — that lives in
//! `rmt_agent_windows::enroll::validate_control_plane_url`, which is where the support client
//! validates the baked constant against the same `https`-or-loopback rule the `rmt://` URI path
//! uses. This module owns only the ONE fact a portable crate can own: whether a build was
//! configured at all. An unconfigured build must **refuse to run** with a named message
//! (`support_ui::Failure::Unconfigured`) — never fall back to a default origin, and never prompt the
//! customer for one, because a member of the public typing a URL is exactly the phishing surface the
//! typed-code design removed.

/// The control-plane origin baked at build time, or the empty string for an unconfigured build.
///
/// `env!` rather than `option_env!` because `build.rs` always emits the key (empty when the release
/// variable was unset), so it is always present at compile time; emptiness is the "unconfigured"
/// signal and is checked by [`is_unconfigured`].
pub const CONTROL_PLANE_URL: &str = env!("RMT_CONTROL_PLANE_URL");

/// The explicit build mode (docs/48 C): `"dev"` (no mode set: today's behaviour), `"baked"` (a
/// server-specific release; [`CONTROL_PLANE_URL`] is set) or `"pass"` (a GENERIC release; the
/// server comes from a signed deployment pass beside the exe, verified with [`PASS_ROOT_KEY`]).
/// `build.rs` refuses any mixed configuration, so this is one of exactly those three.
pub const BUILD_MODE: &str = env!("DESKRALLY_BUILD_MODE");

/// The deployment-pass root public key compiled into a pass-mode build (130 hex); empty otherwise.
pub const PASS_ROOT_KEY: &str = env!("DESKRALLY_PASS_ROOT_KEY");

/// Whether THIS binary is a generic, pass-mode build.
#[must_use]
pub fn is_pass_mode() -> bool {
    BUILD_MODE == "pass"
}

/// Whether a value is "unconfigured": empty or whitespace-only.
///
/// Split out from [`is_unconfigured`] so both arms are testable — the baked [`CONTROL_PLANE_URL`] is
/// a single compile-time value and a test cannot exercise it both ways.
fn is_unconfigured_value(url: &str) -> bool {
    url.trim().is_empty()
}

/// Whether THIS binary was built without a control-plane origin.
///
/// `true` ⇒ the support client must refuse to run with [`crate::support_ui::Failure::Unconfigured`].
/// It must not fall back to a default and must not prompt for a URL.
#[must_use]
pub fn is_unconfigured() -> bool {
    is_unconfigured_value(CONTROL_PLANE_URL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_whitespace_are_unconfigured() {
        assert!(is_unconfigured_value(""), "an unset build must read as unconfigured");
        assert!(is_unconfigured_value("   "), "whitespace-only must read as unconfigured");
        assert!(is_unconfigured_value("\t \r\n"), "any run of whitespace must read as unconfigured");
    }

    #[test]
    fn a_real_origin_is_configured() {
        assert!(!is_unconfigured_value("https://main.deskrally.com"));
        assert!(!is_unconfigured_value("http://127.0.0.1:8080"));
        // Leading/trailing space around a real value is configured — build.rs trims, but the
        // predicate must not itself be fooled by padding.
        assert!(!is_unconfigured_value("  https://main.deskrally.com  "));
    }

    /// The public entry point must agree with the pure predicate on whatever value THIS build baked.
    /// This is what ties the tested logic to the compile-time constant that actually ships.
    #[test]
    fn the_public_check_reads_the_baked_constant() {
        assert_eq!(is_unconfigured(), is_unconfigured_value(CONTROL_PLANE_URL));
    }
}
