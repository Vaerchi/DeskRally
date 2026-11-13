//! Stamps the build's git commit into the binary as `RMT_GIT_SHA`.
//!
//! This is the repo's FIRST build script, so the conventions it sets matter more than the ten lines
//! it contains.
//!
//! WHY THIS CRATE. `crates/agent-windows` is `#![cfg(windows)]` in its entirety, so a constant
//! defined there is invisible to every cross-platform crate and to `cargo check` on Linux.
//! `rmt-agent-core` is portable, inherits the workspace version, and is already a dependency of
//! `rmt-agent-windows` — so the version identity is defined once, here, and read by whoever needs it.
//!
//! THREE THINGS THIS MUST NOT DO:
//!
//! 1. **It must not require git.** Nothing else in this tree assumes git is on PATH at compile
//!    time. A source export, a vendored build, or a machine without git must still compile, so
//!    every failure path degrades to [`PLACEHOLDER`] rather than panicking. `version.rs` exposes
//!    `is_placeholder()` so a test can tell a real stamp from a degraded one — otherwise a silently
//!    unstamped fleet reports a version column full of `unknown` and nobody notices.
//!
//! 2. **It must not go stale.** Cargo re-runs a build script only when a path it declared via
//!    `rerun-if-changed` changes, and declaring ANY such path REPLACES the default "re-run when a
//!    package file changes". So the git refs are declared explicitly below. Without them the SHA is
//!    baked once and then reported for every later commit — a version column that lies is worse than
//!    no version column, because a rollout would look like it landed when it had not.
//!
//! 3. **It must not report a dirty tree.** A `git status` flag was considered and DELIBERATELY
//!    REJECTED: this script does not re-run when a source file changes (see 2), so a `.dirty`
//!    suffix would be computed at some arbitrary earlier build and then reported indefinitely. A
//!    stale dirty flag is a worse lie than an absent one.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Reported when the commit cannot be determined. Must stay in sync with
/// `version::PLACEHOLDER_SHA`, which is pinned by a test in that module.
const PLACEHOLDER: &str = "unknown";

fn main() {
    // crates/agent-core → ../.. is the repo root.
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let repo_root = manifest.join("..").join("..");

    declare_git_reruns(&repo_root);

    let sha = git_short_sha(&repo_root).unwrap_or_else(|| PLACEHOLDER.to_string());
    println!("cargo:rustc-env=RMT_GIT_SHA={sha}");

    stamp_control_plane_url();
    stamp_build_mode();
}

/// Bake the explicit build MODE (docs/48 C, "Principles" 1) as `DESKRALLY_BUILD_MODE`, and in pass
/// mode the deployment-pass root key as `DESKRALLY_PASS_ROOT_KEY`.
///
/// - unset → `dev`: today's behaviour, untouched (agent, probe, CI and test builds).
/// - `baked` → the release mode for a server-specific Support: `RMT_CONTROL_PLANE_URL` is REQUIRED
///   and a pass root key is refused.
/// - `pass` → the GENERIC Support: a baked `RMT_CONTROL_PLANE_URL` is refused and a 130-hex root key
///   is REQUIRED; the server comes from a signed deployment pass at run time.
///
/// A partial or mixed configuration PANICS (fails the build): "a broken baked build can never fall
/// through to pass mode", and the reverse.
fn stamp_build_mode() {
    for var in ["DESKRALLY_BUILD_MODE", "DESKRALLY_PASS_ROOT_KEY"] {
        println!("cargo:rerun-if-env-changed={var}");
    }
    let mode = std::env::var("DESKRALLY_BUILD_MODE").unwrap_or_default();
    let url = std::env::var("RMT_CONTROL_PLANE_URL").unwrap_or_default();
    let key = std::env::var("DESKRALLY_PASS_ROOT_KEY").unwrap_or_default();
    let (mode, key) = match mode.trim() {
        "" | "dev" => {
            assert!(key.trim().is_empty(), "DESKRALLY_PASS_ROOT_KEY is set without DESKRALLY_BUILD_MODE=pass");
            ("dev", String::new())
        }
        "baked" => {
            assert!(!url.trim().is_empty(), "DESKRALLY_BUILD_MODE=baked needs RMT_CONTROL_PLANE_URL");
            assert!(key.trim().is_empty(), "DESKRALLY_BUILD_MODE=baked must not set DESKRALLY_PASS_ROOT_KEY");
            ("baked", String::new())
        }
        "pass" => {
            assert!(url.trim().is_empty(), "DESKRALLY_BUILD_MODE=pass must not bake RMT_CONTROL_PLANE_URL (the pass names the server)");
            let key = key.trim().to_string();
            assert!(
                key.len() == 130 && key.starts_with("04") && key.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "DESKRALLY_BUILD_MODE=pass needs DESKRALLY_PASS_ROOT_KEY: 130 lowercase hex, SEC1 uncompressed P-256 (rmt-pass-sign pubkey)"
            );
            ("pass", key)
        }
        other => panic!("DESKRALLY_BUILD_MODE must be baked or pass (or unset for a dev build), not {other:?}"),
    };
    println!("cargo:rustc-env=DESKRALLY_BUILD_MODE={mode}");
    println!("cargo:rustc-env=DESKRALLY_PASS_ROOT_KEY={key}");
}

/// Bake the deployment's control-plane origin into the binary as `RMT_CONTROL_PLANE_URL`.
///
/// Read by [`deployment::CONTROL_PLANE_URL`]. This is what makes ONE downloadable support artifact
/// serve exactly one deployment: the customer types only a session code, never a URL, so the origin
/// has to come from the build. The SAME three rules the git stamp above obeys apply, for the same
/// reasons:
///
/// 1. **Never require it.** An unset variable stamps the empty string, not a panic — a plain
///    `cargo build` for the installed agent, the probe, or CI must still compile. `deployment.rs`
///    exposes `is_unconfigured()` so the support client can refuse to RUN with a named message
///    rather than the build refusing to compile; a URL is a release-time input, not a source fact.
///
/// 2. **Never go stale.** `rerun-if-env-changed` re-runs this script whenever the variable changes,
///    including changing to unset — without it a URL baked once would be reported for every later
///    build, and a support client that silently talks to last week's origin is precisely the
///    "a version column that lies is worse than none" failure this file already warns about.
///
/// 3. **Never report an earlier build's value.** Follows from (2): the value emitted is always the
///    value present in THIS invocation's environment. `env!` (not `option_env!`) is correct on the
///    reader side because this script always emits the key, even when empty.
fn stamp_control_plane_url() {
    println!("cargo:rerun-if-env-changed=RMT_CONTROL_PLANE_URL");
    // Trim here so `deployment::is_unconfigured` sees "   " as unset, and so a stray newline from a
    // shell here-string cannot ride into the baked constant.
    let url = std::env::var("RMT_CONTROL_PLANE_URL").unwrap_or_default();
    println!("cargo:rustc-env=RMT_CONTROL_PLANE_URL={}", url.trim());
}

/// Ask git for the short commit. `None` on ANY failure — git missing, not a repository, a shallow
/// checkout with no commits, or a non-zero exit.
fn git_short_sha(repo_root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .current_dir(repo_root)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?.trim().to_string();
    // A blank or absurd answer is a failure, not a version.
    if sha.is_empty() || sha.len() > 40 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(sha)
}

/// Declare the files whose change means the stamp is out of date.
///
/// `.git/HEAD` covers a branch switch or a detached checkout. The branch's own ref file covers a
/// new commit on that branch — but it does not exist when refs are packed, so `packed-refs` is
/// declared too.
///
/// ONLY EXISTING PATHS ARE DECLARED, and that is load-bearing rather than tidy. Cargo treats a
/// declared path that does not exist as perpetually dirty, so declaring `packed-refs`
/// unconditionally (this repo has none) made the build script re-run on EVERY build — measured, not
/// theorised: three consecutive no-op builds each recompiled the crate. Since `rmt-agent-core` is a
/// dependency of the Windows agent and the WebRTC transport, that is a rebuild of most of the
/// workspace on every invocation of the gate.
///
/// The omission is self-healing. If `git gc` later packs the refs, the ref file this run declared
/// DISAPPEARS — which cargo sees as a change, re-runs the script, and the next run declares
/// `packed-refs` instead.
fn declare_git_reruns(repo_root: &Path) {
    let git_dir = repo_root.join(".git");

    // A worktree or submodule has `.git` as a FILE containing `gitdir: <path>`. Not the case in
    // this repo today, but a checkout under `git worktree` would silently stop re-stamping.
    let git_dir = if git_dir.is_file() {
        std::fs::read_to_string(&git_dir)
            .ok()
            .and_then(|s| s.strip_prefix("gitdir:").map(|p| PathBuf::from(p.trim())))
            .unwrap_or(git_dir)
    } else {
        git_dir
    };

    let head = git_dir.join("HEAD");
    declare_if_exists(&head);
    declare_if_exists(&git_dir.join("packed-refs"));

    // Resolve `ref: refs/heads/<branch>` from HEAD and watch that file too.
    if let Ok(contents) = std::fs::read_to_string(&head) {
        if let Some(r) = contents.strip_prefix("ref:") {
            let r = r.trim();
            if !r.is_empty() && !r.contains("..") {
                declare_if_exists(&git_dir.join(r));
            }
        }
    }
}

/// Declare a rerun trigger only when the path is really there — see [`declare_git_reruns`] for why
/// declaring an absent path is a per-build rebuild rather than a harmless no-op.
fn declare_if_exists(p: &Path) {
    if p.exists() {
        println!("cargo:rerun-if-changed={}", p.display());
    }
}
