//! Admission epochs and the elevated helper's lease (docs/53 §3.3).
//!
//! An attended session can forward its input to an elevated, input-only helper. The helper's
//! authority to PRESS anything expires on its own unless the session keeps renewing it, so a
//! revocation takes effect within [`LEASE_MS`] even if the helper's pipe reader is stalled.
//!
//! Two halves, both pure and platform-free (time is a caller-supplied millisecond count, in
//! production `GetTickCount64`, which every process on the machine shares):
//!
//! * [`Admission`]: the session side. Every change BUMPS the epoch; the caller holds it under one
//!   mutex, so the bump is the linearization point. A renewal's expiry is stamped from the current
//!   epoch while admitted, before any I/O, so no renewal created before a revoke can outlive it by
//!   more than [`LEASE_MS`], and none can be created after it.
//! * [`HelperGate`]: the helper side. Frames may arrive out of order (they are sent outside the
//!   session's mutex); every frame below the highest epoch seen is ignored, a revoked epoch is
//!   terminal, and a new epoch starts with no lease.
//!
//! Releases (key-up, button-up) are not gated here: the sink lets them pass a closed gate so a key
//! pressed before a revocation is still lifted (docs/53 §3.3, "What makes it ONE event").

use serde::{Deserialize, Serialize};

/// How long one renewal keeps the helper's gate open after the session stamped it.
pub const LEASE_MS: u64 = 250;
/// How often an admitted session renews.
pub const RENEW_EVERY_MS: u64 = 50;

/// One gate frame on the session → helper pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t")]
pub enum GateFrame {
    /// Open (`admitted`) or close the gate, as of `epoch`.
    SetAdmitted {
        /// Open (true) or closed (false).
        admitted: bool,
        /// The admission epoch this change created.
        epoch: u64,
    },
    /// Keep epoch `epoch` open until `valid_until` (absolute, the shared millisecond clock).
    Renew {
        /// The epoch this renewal was stamped in.
        epoch: u64,
        /// Absolute expiry on the shared millisecond clock.
        valid_until: u64,
    },
}

/// The session side of admission. Hold it under ONE mutex; see the module docs.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Admission {
    epoch: u64,
    admitted: bool,
}

impl Admission {
    /// Not admitted, epoch 0.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the current epoch is admitted.
    pub fn admitted(&self) -> bool {
        self.admitted
    }

    /// The current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Open a new epoch. The helper grants no time until the first renewal of it.
    pub fn admit(&mut self) -> GateFrame {
        self.epoch += 1;
        self.admitted = true;
        GateFrame::SetAdmitted { admitted: true, epoch: self.epoch }
    }

    /// Revoke: the linearization point. After this returns, [`Admission::renew`] yields nothing
    /// until a later [`Admission::admit`].
    pub fn revoke(&mut self) -> GateFrame {
        self.epoch += 1;
        self.admitted = false;
        GateFrame::SetAdmitted { admitted: false, epoch: self.epoch }
    }

    /// A renewal stamped NOW, while admitted. `None` when not admitted.
    pub fn renew(&self, now_ms: u64) -> Option<GateFrame> {
        self.admitted.then(|| GateFrame::Renew { epoch: self.epoch, valid_until: now_ms.saturating_add(LEASE_MS) })
    }
}

/// The helper side of admission. Hold it under the helper's state mutex.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct HelperGate {
    max_epoch: u64,
    open: bool,
    lease_until: u64,
}

impl HelperGate {
    /// Closed, no epoch seen.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one frame, in whatever order frames arrive.
    pub fn apply(&mut self, frame: GateFrame) {
        match frame {
            GateFrame::SetAdmitted { admitted: false, epoch } if epoch >= self.max_epoch => {
                self.max_epoch = epoch;
                self.open = false;
                self.lease_until = 0;
            }
            GateFrame::SetAdmitted { admitted: true, epoch } if epoch > self.max_epoch => {
                self.max_epoch = epoch;
                self.open = true;
                self.lease_until = 0;
            }
            GateFrame::Renew { epoch, valid_until } if epoch == self.max_epoch && self.open => {
                self.lease_until = self.lease_until.max(valid_until);
            }
            _ => {}
        }
    }

    /// The pipe closed or broke: the same as a revocation, and nothing can reopen it, because the
    /// helper exits after this.
    pub fn close(&mut self) {
        self.open = false;
        self.lease_until = 0;
    }

    /// Whether the current epoch is admitted (regardless of its lease).
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Whether a PRESS (anything but a release) may be injected at `now_ms`.
    pub fn may_press(&self, now_ms: u64) -> bool {
        self.open && now_ms < self.lease_until
    }

    /// The newest epoch seen. Input is bound to the epoch it arrived under; a press from an older
    /// epoch must never run under a newer admission.
    pub fn epoch(&self) -> u64 {
        self.max_epoch
    }

    /// The end of the current lease (0 before the first renewal of an epoch).
    pub fn lease_until(&self) -> u64 {
        self.lease_until
    }

    /// Admitted, had a lease, and the lease ran out with no renewal: the session side stopped
    /// renewing without a revocation reaching the helper (a stalled reader or session).
    pub fn lease_lapsed(&self, now_ms: u64) -> bool {
        self.open && self.lease_until > 0 && now_ms >= self.lease_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_renewed_admission_opens_until_its_lease_ends() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        h.apply(s.admit());
        assert!(!h.may_press(0), "a new epoch grants no time before its first renewal");
        h.apply(s.renew(1000).unwrap());
        assert!(h.may_press(1000) && h.may_press(1000 + LEASE_MS - 1));
        assert!(!h.may_press(1000 + LEASE_MS), "the lease ends on its own");
    }

    #[test]
    fn revoke_closes_at_once_and_stops_renewals() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        h.apply(s.admit());
        h.apply(s.renew(0).unwrap());
        h.apply(s.revoke());
        assert!(!h.may_press(1), "a delivered revoke closes the gate immediately");
        assert_eq!(s.renew(5), None, "no renewal can be created after the revoke");
    }

    #[test]
    fn a_late_renewal_cannot_extend_past_its_own_stamp() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        h.apply(s.admit());
        let stale = s.renew(0).unwrap();
        // Read 10 s after it was stamped: it grants nothing then.
        h.apply(stale);
        assert!(!h.may_press(10_000));
    }

    #[test]
    fn frames_of_an_older_epoch_are_ignored() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        let admit1 = s.admit();
        let renew1 = s.renew(0).unwrap();
        let revoke = s.revoke();
        let admit3 = s.admit();
        h.apply(admit3);
        // Stale frames from epochs 1 and 2 arrive after epoch 3 opened.
        h.apply(admit1);
        h.apply(renew1);
        h.apply(revoke);
        assert!(!h.may_press(1), "an old epoch's renewal grants nothing to the new epoch");
        h.apply(s.renew(1).unwrap());
        assert!(h.may_press(2), "the current epoch's own renewal does");
    }

    #[test]
    fn a_revoked_epoch_is_terminal() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        let admit = s.admit();
        let renew = s.renew(0).unwrap();
        h.apply(s.revoke());
        h.apply(admit);
        h.apply(renew);
        assert!(!h.may_press(1), "nothing below the revoke's epoch reopens the gate");
    }

    #[test]
    fn close_is_a_revocation() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        h.apply(s.admit());
        h.apply(s.renew(0).unwrap());
        h.close();
        assert!(!h.may_press(1));
    }

    /// docs/53 §6(e2c): every delivery order of the frames a session produced. After the last
    /// operation is a revoke at time `t_revoke`, no delivery order may leave the gate open at or
    /// after `t_revoke + LEASE_MS`, and once the revoke frame itself has been applied the gate is
    /// closed no matter what else arrives.
    #[test]
    fn no_delivery_order_outlives_a_revoke() {
        // A session timeline: admit, renewals, revoke, re-admit, renewal, final revoke.
        let mut s = Admission::new();
        let mut frames = vec![s.admit()];
        frames.push(s.renew(0).unwrap());
        frames.push(s.renew(50).unwrap());
        frames.push(s.revoke());
        frames.push(s.admit());
        frames.push(s.renew(100).unwrap());
        let t_revoke = 120;
        let final_revoke = s.revoke();
        frames.push(final_revoke);
        assert_eq!(s.renew(130), None);

        let mut orders = 0;
        permute(&mut frames.clone(), 0, &mut |order| {
            orders += 1;
            let mut h = HelperGate::new();
            let mut revoke_seen = false;
            for f in order {
                h.apply(*f);
                revoke_seen |= *f == final_revoke;
                if revoke_seen {
                    assert!(!h.may_press(t_revoke), "open after the final revoke was applied: {order:?}");
                }
            }
            for t in [t_revoke + LEASE_MS, t_revoke + LEASE_MS + 1, 10_000] {
                assert!(!h.may_press(t), "open at {t}, past revoke + LEASE: {order:?}");
            }
        });
        assert_eq!(orders, 5040, "all 7! orders checked");
    }

    /// A delivery order in which a revoke is LOST (never delivered, e.g. the pipe broke) still
    /// closes on its own once the last renewal's lease runs out.
    #[test]
    fn a_lost_revoke_still_expires() {
        let mut s = Admission::new();
        let mut h = HelperGate::new();
        h.apply(s.admit());
        h.apply(s.renew(0).unwrap());
        let _lost = s.revoke();
        assert!(h.may_press(LEASE_MS - 1));
        assert!(!h.may_press(LEASE_MS), "without any further frame the gate closes at the lease");
    }

    #[test]
    fn gate_frames_round_trip_as_tagged_json() {
        let f = GateFrame::Renew { epoch: 3, valid_until: 1250 };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, r#"{"t":"Renew","epoch":3,"valid_until":1250}"#);
        assert_eq!(serde_json::from_str::<GateFrame>(&json).unwrap(), f);
    }

    fn permute(items: &mut Vec<GateFrame>, k: usize, visit: &mut dyn FnMut(&[GateFrame])) {
        if k == items.len() {
            visit(items);
            return;
        }
        for i in k..items.len() {
            items.swap(k, i);
            permute(items, k + 1, visit);
            items.swap(k, i);
        }
    }
}
