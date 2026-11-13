//! Reconnection backoff for the agent→relay supervision loop. When the signaling/relay link
//! drops, the agent must retry — but a fleet of agents all hammering a recovering relay is a
//! self-inflicted thundering herd. This schedules exponentially growing waits between attempts.
//!
//! The schedule here is **deterministic** (no random jitter): every step is a pure function of
//! the attempt count, which makes the supervisor loop trivially unit-testable. Production may
//! later add jitter at the call site; keeping the core deterministic keeps the tests exact.

use std::time::Duration;

/// Exponential backoff with a fixed ceiling. Delays are `base * factor^n`, capped at `max`,
/// where `n` is the number of failures since the last [`reset`](Backoff::reset).
///
/// ```
/// use std::time::Duration;
/// use rmt_agent_core::reconnect::Backoff;
///
/// let mut b = Backoff::new(Duration::from_millis(100), Duration::from_secs(5), 2);
/// assert_eq!(b.next_delay(), Duration::from_millis(100)); // 100 * 2^0
/// assert_eq!(b.next_delay(), Duration::from_millis(200)); // 100 * 2^1
/// assert_eq!(b.next_delay(), Duration::from_millis(400)); // 100 * 2^2
/// b.reset();
/// assert_eq!(b.next_delay(), Duration::from_millis(100)); // back to the start
/// ```
#[derive(Debug, Clone)]
pub struct Backoff {
    base_ms: u64,
    max_ms: u64,
    factor: u32,
    attempt: u32,
}

impl Backoff {
    /// Create a backoff schedule.
    ///
    /// * `base` — the first delay (the wait before the *second* attempt).
    /// * `max` — the ceiling; delays never exceed this no matter how many failures accrue.
    /// * `factor` — the geometric growth multiplier (e.g. `2` doubles each time). A `factor` of
    ///   0 or 1 yields a constant `base` schedule.
    ///
    /// `base` is clamped to at most `max` so the schedule is always non-decreasing up to the cap.
    pub fn new(base: Duration, max: Duration, factor: u32) -> Self {
        let base_ms = base.as_millis().min(u64::MAX as u128) as u64;
        let max_ms = max.as_millis().min(u64::MAX as u128) as u64;
        Self {
            base_ms: base_ms.min(max_ms),
            max_ms,
            // 0 would collapse to a zero delay after the first attempt (0^n = 0); the doc
            // promises 0 behaves like 1, a constant `base` schedule.
            factor: factor.max(1),
            attempt: 0,
        }
    }

    /// The delay to wait before the next reconnection attempt, then advances the schedule.
    /// Saturates at `max` (and never overflows, however many times it is called).
    pub fn next_delay(&mut self) -> Duration {
        let delay = self.peek();
        // Only keep counting while it still affects the result; once we've saturated at `max`
        // there's no point growing `attempt` further (and it avoids unbounded increment).
        if delay.as_millis() < self.max_ms as u128 {
            self.attempt = self.attempt.saturating_add(1);
        }
        delay
    }

    /// The delay [`next_delay`](Backoff::next_delay) would return, without advancing.
    pub fn peek(&self) -> Duration {
        let ms = self
            .base_ms
            .checked_mul((self.factor as u64).saturating_pow(self.attempt))
            .unwrap_or(self.max_ms)
            .min(self.max_ms);
        Duration::from_millis(ms)
    }

    /// Reset to the start of the schedule — call after a successful reconnect so the *next*
    /// disconnection starts from `base` again.
    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    /// How many times [`next_delay`](Backoff::next_delay) has advanced since the last reset.
    pub fn attempt(&self) -> u32 {
        self.attempt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn doubles_until_it_hits_the_ceiling() {
        let mut b = Backoff::new(ms(100), ms(1000), 2);
        assert_eq!(b.next_delay(), ms(100)); // 2^0
        assert_eq!(b.next_delay(), ms(200)); // 2^1
        assert_eq!(b.next_delay(), ms(400)); // 2^2
        assert_eq!(b.next_delay(), ms(800)); // 2^3
        assert_eq!(b.next_delay(), ms(1000)); // 1600 capped -> 1000
        assert_eq!(b.next_delay(), ms(1000)); // stays at the cap
    }

    #[test]
    fn reset_returns_to_base() {
        let mut b = Backoff::new(ms(100), ms(5000), 2);
        b.next_delay();
        b.next_delay();
        assert!(b.attempt() > 0);
        b.reset();
        assert_eq!(b.attempt(), 0);
        assert_eq!(b.next_delay(), ms(100));
    }

    #[test]
    fn peek_does_not_advance() {
        let mut b = Backoff::new(ms(50), ms(5000), 3);
        assert_eq!(b.peek(), ms(50));
        assert_eq!(b.peek(), ms(50));
        assert_eq!(b.next_delay(), ms(50));
        assert_eq!(b.peek(), ms(150)); // now advanced once: 50 * 3^1
    }

    #[test]
    fn factor_one_is_constant() {
        let mut b = Backoff::new(ms(250), ms(5000), 1);
        assert_eq!(b.next_delay(), ms(250));
        assert_eq!(b.next_delay(), ms(250));
        assert_eq!(b.next_delay(), ms(250));
    }

    #[test]
    fn factor_zero_is_constant_base() {
        let mut b = Backoff::new(ms(250), ms(5000), 0);
        for _ in 0..8 {
            assert_eq!(b.next_delay(), ms(250));
        }
    }

    #[test]
    fn factor_zero_matches_factor_one() {
        let mut z = Backoff::new(ms(120), ms(900), 0);
        let mut o = Backoff::new(ms(120), ms(900), 1);
        for _ in 0..10 {
            assert_eq!(z.next_delay(), o.next_delay());
            assert_eq!(z.attempt(), o.attempt());
        }
    }

    #[test]
    fn factor_zero_peek_never_zero_after_advances() {
        let mut b = Backoff::new(ms(75), ms(5000), 0);
        assert_eq!(b.peek(), ms(75));
        for _ in 0..6 {
            b.next_delay();
            assert_eq!(b.peek(), ms(75));
        }
    }

    #[test]
    fn factor_zero_with_small_max_never_returns_zero() {
        let mut b = Backoff::new(ms(500), ms(40), 0);
        for _ in 0..6 {
            let d = b.next_delay();
            assert_ne!(d, Duration::ZERO);
            assert_eq!(d, ms(40));
        }
    }

    #[test]
    fn base_is_clamped_to_max() {
        let mut b = Backoff::new(ms(10_000), ms(1_000), 2);
        assert_eq!(b.next_delay(), ms(1_000));
    }

    #[test]
    fn never_overflows_under_many_calls() {
        // With a large factor this would overflow a naive `base * factor^attempt`; assert it
        // simply saturates at the ceiling instead of panicking.
        let mut b = Backoff::new(ms(1), ms(60_000), 10);
        let mut last = ms(0);
        for _ in 0..1_000 {
            last = b.next_delay();
        }
        assert_eq!(last, ms(60_000));
    }
}
