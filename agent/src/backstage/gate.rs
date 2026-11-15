//! The mutation gate (docs/58 §1): revokes every mutating channel of a session the moment the
//! guest's on-screen indicator is lost or the session tears down.
//!
//! It is a REVOCATION GENERATION, not a boolean. Mutating work is stamped with the generation
//! current when it was admitted; [`MutationGate::revoke`] advances the generation and closes the
//! gate, so all pre-revocation work carries a dead stamp forever, and [`MutationGate::reopen`]
//! (the indicator came back) admits only NEW work. Admission is checked immediately before each
//! irreversible system call. The contract is exactly: no call is admitted after revocation; a call
//! admitted before it may still start and finish (the check-to-submit gap cannot be closed with
//! atomics, and nothing here claims otherwise).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug)]
pub struct MutationGate {
    generation: AtomicU64,
    open: AtomicBool,
}

impl Default for MutationGate {
    fn default() -> Self {
        Self { generation: AtomicU64::new(0), open: AtomicBool::new(true) }
    }
}

impl MutationGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// The stamp to give work admitted now.
    pub fn stamp(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Whether work stamped `stamp` may make its next irreversible call.
    pub fn admits(&self, stamp: u64) -> bool {
        self.open.load(Ordering::SeqCst) && self.generation.load(Ordering::SeqCst) == stamp
    }

    /// Cut off everything admitted so far, and admit nothing until [`reopen`](Self::reopen).
    /// Never blocks.
    pub fn revoke(&self) {
        self.open.store(false, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// The indicator is visible again: admit NEW work. Revoked work keeps its dead stamp.
    pub fn reopen(&self) {
        self.open.store(true, Ordering::SeqCst);
    }

    pub fn is_open(&self) -> bool {
        self.open.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoked_work_never_comes_back() {
        let g = MutationGate::new();
        let old = g.stamp();
        assert!(g.admits(old));
        g.revoke();
        assert!(!g.admits(old), "revocation cuts off admitted work");
        assert!(!g.admits(g.stamp()), "nothing new is admitted while closed");
        g.reopen();
        assert!(!g.admits(old), "reopening must not revive pre-revocation work");
        assert!(g.admits(g.stamp()), "new work is admitted after reopening");
    }

    #[test]
    fn every_revocation_is_a_new_generation() {
        let g = MutationGate::new();
        g.revoke();
        g.reopen();
        let mid = g.stamp();
        g.revoke();
        g.reopen();
        assert!(!g.admits(mid), "a second loss kills work admitted between the two");
    }
}
