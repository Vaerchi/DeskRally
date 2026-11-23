//! Native link configuration for **libopus** (the WebRTC audio track's encoder).
//!
//! Like libvpx, libopus is NOT vendored — it is a build prerequisite each machine installs once
//! (`vcpkg install opus:x64-windows-static`; see `../../.cargo/config.toml` and
//! `docs/10-deployment.md`). Unlike libvpx there is no `-sys` crate in the way: `src/audio.rs`
//! declares the five functions it uses directly, so all that is needed here is the search path and
//! the library name.
//!
//! Two things this deliberately does NOT do, both learned from the libvpx integration next door:
//!
//! * It does not vendor or build libopus. A crate that builds its own copy picks its own CRT, and
//!   the agent binaries link with `-C target-feature=+crt-static` (/MT) — mixing in a /MD build
//!   fails with LNK2038 ("mismatch detected for 'RuntimeLibrary'"), which is a link error a long
//!   way from its cause.
//! * It emits the library name `opus`, not `libopus`. On MSVC `rustc-link-lib=static=NAME` looks
//!   for `NAME.lib`, and vcpkg's static triplet produces `opus.lib`; asking for `libopus` fails
//!   with LNK1181 — the exact trap `VPX_STATIC` is left unset to avoid.
//!
//! `OPUS_LIB_DIR` overrides the search path (a different vcpkg root, a distro package, a
//! self-built libopus). Off Windows it is REQUIRED: rustc resolves a `static=` library only in
//! the directories it is given, never the linker's default search, so a distro libopus needs
//! for example `OPUS_LIB_DIR=/usr/lib/x86_64-linux-gnu` (Debian/Ubuntu `libopus-dev`).

fn main() {
    println!("cargo:rerun-if-env-changed=OPUS_LIB_DIR");
    if let Ok(dir) = std::env::var("OPUS_LIB_DIR") {
        println!("cargo:rustc-link-search=native={dir}");
    }
    println!("cargo:rustc-link-lib=static=opus");
}
