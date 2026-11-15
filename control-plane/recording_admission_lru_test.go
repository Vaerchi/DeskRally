package controlplane

import (
	"strconv"
	"testing"
	"time"
)

// Audit 2026-11-01 #18 + review repair 3.
// MUTATIONS: (a) reinstate a scan of l.buckets in allow's full-table branch -> ConstantTime fails;
// (b) evict the LRU tail even when it is live (no idle check / no overflow) -> DebtIsPreserved and
// NewSourcesShareOverflow fail.

func TestRateLimiterInsertIntoFullTableIsConstantTime(t *testing.T) {
	const keys = 100000
	l := newRateLimiter(1, 5, keys)
	now := time.Unix(1000, 0)
	for i := 0; i < keys; i++ {
		l.allow("fill-"+strconv.Itoa(i), now) // each now holds debt (4 of 5 tokens)
	}
	start := time.Now()
	for i := 0; i < 3*keys; i++ {
		l.allow("new-"+strconv.Itoa(i), now)
	}
	// The old implementation scanned all 100000 entries per insert (tens of seconds).
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("300k inserts into a saturated table took %v: not bounded work", el)
	}
	if len(l.buckets) != keys || l.lru.Len() != keys {
		t.Fatalf("table size map=%d list=%d, want %d", len(l.buckets), l.lru.Len(), keys)
	}
}

func TestRateLimiterDebtIsPreservedAndNewSourcesShareOverflow(t *testing.T) {
	l := newRateLimiter(0.001, 5, 100)
	now := time.Unix(1000, 0)
	for i := 0; i < 100; i++ {
		for j := 0; j < 5; j++ { // exhaust: each of the 100 debtors has zero tokens
			l.allow("debtor-"+strconv.Itoa(i), now)
		}
	}
	granted := 0
	for i := 0; i < 5000; i++ { // an attacker cycling far more addresses than the table holds
		if l.allow("attacker-"+strconv.Itoa(i), now) {
			granted++
		}
	}
	if granted > 5 {
		t.Fatalf("5000 fresh sources were granted %d requests; they must share ONE burst of 5", granted)
	}
	for i := 0; i < 100; i++ {
		if l.allow("debtor-"+strconv.Itoa(i), now) {
			t.Fatalf("debtor %d got a fresh budget: its debt was forgotten", i)
		}
	}
	if len(l.buckets) != 100 {
		t.Fatalf("table size %d", len(l.buckets))
	}
	if l.peek("another-new-source", now) {
		t.Fatal("peek lets a new source through while the shared overflow budget is spent")
	}
}

func TestRateLimiterEvictsIdleBucketsWhenFull(t *testing.T) {
	l := newRateLimiter(1, 2, 3)
	t0 := time.Unix(1000, 0)
	for _, k := range []string{"a", "b", "c"} {
		l.allow(k, t0)
	}
	t1 := t0.Add(time.Minute) // everything has refilled: all idle
	if !l.allow("d", t1) {
		t.Fatal("new key refused although the table holds only idle buckets")
	}
	if _, ok := l.buckets["d"]; !ok || len(l.buckets) != 3 {
		t.Fatalf("idle tail was not evicted for the new key (len=%d)", len(l.buckets))
	}
}
