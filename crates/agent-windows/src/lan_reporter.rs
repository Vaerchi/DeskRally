//! Connection-scoped full LAN snapshots, acknowledgements and retry scheduling.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmt_protocol::signaling::{ClientToServer, LanEntry};
use rmt_transport_webrtc::SignalingClient;
use tokio::time::Instant;

use crate::lan_facts::{self, InterfaceNotifications, DEBOUNCE};

const POLL: Duration = Duration::from_secs(15 * 60);
const REFRESH: Duration = Duration::from_secs(6 * 60 * 60);
const FIRST_RETRY: Duration = Duration::from_secs(30);
const MAX_RETRY: Duration = Duration::from_secs(5 * 60);

struct Pending {
    at: Instant,
    delay: Duration,
}

pub(crate) struct Reporter {
    entries: Vec<LanEntry>,
    seq: u64,
    pending: Option<Pending>,
    read_at: Instant,
    refresh_at: Instant,
    refresh_retry_at: Instant,
    changed_at: Option<Instant>,
}

impl Reporter {
    pub(crate) fn new(now: Instant) -> Self {
        Self {
            entries: Vec::new(),
            seq: 0,
            pending: None,
            read_at: now,
            refresh_at: now,
            refresh_retry_at: now,
            changed_at: None,
        }
    }

    pub(crate) fn ack(&mut self, seq: u64) {
        if seq == self.seq {
            self.pending = None;
        }
    }

    fn changed(&mut self, now: Instant) {
        self.changed_at = Some(now + DEBOUNCE);
    }

    fn read_deadline(&self) -> Instant {
        let periodic = self.read_at.min(self.refresh_at.max(self.refresh_retry_at));
        self.changed_at
            .map_or(periodic, |changed| periodic.min(changed))
    }

    fn begin_read(&mut self, now: Instant) {
        if now >= self.read_at {
            self.read_at = now + POLL;
        }
        if self.changed_at.is_some_and(|at| at <= now) {
            self.changed_at = None;
        }
    }

    fn observed(&mut self, now: Instant, snapshot: Option<Vec<LanEntry>>) {
        let Some(entries) = snapshot else {
            self.read_at = now + FIRST_RETRY;
            self.refresh_retry_at = self.read_at;
            return;
        };
        let refresh = now >= self.refresh_at;
        if refresh || self.entries != entries {
            self.seq += 1;
            self.entries = entries;
            self.pending = Some(Pending {
                at: now,
                delay: FIRST_RETRY,
            });
        }
        if refresh {
            self.refresh_at = now + REFRESH;
        }
    }

    fn due(&mut self, now: Instant) -> Option<ClientToServer> {
        let pending = self.pending.as_mut().filter(|p| now >= p.at)?;
        pending.at = now + pending.delay;
        pending.delay = (pending.delay * 2).min(MAX_RETRY);
        Some(ClientToServer::LanReport {
            seq: self.seq,
            entries: self.entries.clone(),
        })
    }
}

pub(crate) async fn run(sig: SignalingClient, reporter: Arc<Mutex<Reporter>>) {
    let subscription = InterfaceNotifications::subscribe();
    if subscription.is_none() {
        tracing::warn!("wake: interface notifications unavailable");
    }
    loop {
        let now = Instant::now();
        let read = {
            let mut state = reporter.lock().unwrap();
            let read = now >= state.read_deadline();
            if read {
                state.begin_read(now);
            }
            read
        };
        if read {
            let snapshot = tokio::task::spawn_blocking(lan_facts::snapshot)
                .await
                .ok()
                .flatten();
            reporter.lock().unwrap().observed(Instant::now(), snapshot);
        }
        let (outbound, deadline) = {
            let mut state = reporter.lock().unwrap();
            let outbound = state.due(Instant::now());
            let read = state.read_deadline();
            (
                outbound,
                state.pending.as_ref().map_or(read, |p| read.min(p.at)),
            )
        };
        if outbound.is_some_and(|msg| sig.send(msg).is_err()) {
            return;
        }
        tokio::select! {
            biased;
            _ = sig.closed() => return,
            _ = InterfaceNotifications::changed(), if subscription.is_some() => {
                reporter.lock().unwrap().changed(Instant::now());
            }
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(msg: Option<ClientToServer>) -> Option<u64> {
        msg.map(|msg| match msg {
            ClientToServer::LanReport { seq, .. } => seq,
            _ => unreachable!(),
        })
    }

    #[test]
    fn snapshots_replace_pending_retries_and_only_current_ack_stops_them() {
        let now = Instant::now();
        let mut r = Reporter::new(now);
        r.observed(now, Some(vec![]));
        assert_eq!(seq(r.due(now)), Some(1));
        assert_eq!(seq(r.due(now + Duration::from_secs(29))), None);
        assert_eq!(seq(r.due(now + FIRST_RETRY)), Some(1));
        assert_eq!(seq(r.due(now + Duration::from_secs(89))), None);
        let change = now + Duration::from_secs(90);
        r.observed(
            change,
            Some(vec![LanEntry {
                mac: "02:00:00:00:00:01".into(),
                ipv4_network: "192.168.1.0/24".into(),
                gateway_mac: None,
            }]),
        );
        r.ack(1);
        assert_eq!(seq(r.due(change)), Some(2));
        assert_eq!(seq(r.due(change + FIRST_RETRY)), Some(2));
        r.ack(2);
        assert_eq!(seq(r.due(change + POLL)), None);
    }

    #[test]
    fn trailing_debounce_periodic_poll_and_forced_refresh() {
        let now = Instant::now();
        let mut r = Reporter::new(now);
        r.begin_read(now);
        r.observed(now, Some(vec![]));
        assert_eq!(seq(r.due(now)), Some(1));
        r.ack(1);
        r.changed(now + Duration::from_secs(1));
        r.changed(now + Duration::from_secs(2));
        assert_eq!(r.read_deadline(), now + Duration::from_secs(12));
        let debounced = r.read_deadline();
        r.begin_read(debounced);
        r.observed(debounced, Some(vec![]));
        assert_eq!(r.read_deadline(), now + POLL);
        r.observed(now + POLL, Some(vec![]));
        assert_eq!(seq(r.due(now + POLL)), None);
        r.observed(now + REFRESH, Some(vec![]));
        assert_eq!(seq(r.due(now + REFRESH)), Some(2));
    }

    #[test]
    fn retry_backoff_caps_at_five_minutes() {
        let now = Instant::now();
        let mut r = Reporter::new(now);
        r.observed(now, Some(vec![]));
        let mut at = now;
        for delay in [30, 60, 120, 240, 300, 300] {
            assert_eq!(seq(r.due(at)), Some(1));
            at += Duration::from_secs(delay);
            assert_eq!(seq(r.due(at - Duration::from_millis(1))), None);
        }
        assert_eq!(seq(r.due(at)), Some(1));
    }
}
