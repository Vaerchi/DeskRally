package controlplane

import (
	"testing"
	"time"
)

// Codex review r1 of 218c7413: requests capture `now` before their store call, so they reach cleanupDue out of
// order. A newer request's claim must not let OLDER, delayed requests sweep again within the interval.
func TestThrottleCleanupClaimSurvivesOutOfOrderRequests(t *testing.T) {
	var th Throttle
	t0 := time.Unix(1_800_000_000, 0)
	if !th.cleanupDue(t0.Add(10 * time.Millisecond)) {
		t.Fatal("the first sweep of a process must be due")
	}
	// Older requests finishing later (reversed completion order): none of them may sweep.
	for _, older := range []time.Duration{0, 3 * time.Millisecond, 9 * time.Millisecond} {
		if th.cleanupDue(t0.Add(older)) {
			t.Fatalf("a request %v older than the claim swept again within the interval", 10*time.Millisecond-older)
		}
	}
	// Newer requests inside the interval: not due.
	if th.cleanupDue(t0.Add(29 * time.Second)) {
		t.Fatal("swept again 29 s after the claim (interval 30 s)")
	}
	// After the interval: due once, and the next request in the same instant is not.
	if !th.cleanupDue(t0.Add(41 * time.Second)) {
		t.Fatal("not due after the interval")
	}
	if th.cleanupDue(t0.Add(41*time.Second + time.Millisecond)) {
		t.Fatal("two sweeps claimed back to back")
	}
	// A real clock rollback (at least the interval) is due, so a rewound clock cannot block cleanup for ever.
	if !th.cleanupDue(t0.Add(-time.Hour)) {
		t.Fatal("a clock moved back by an hour never sweeps again")
	}
}
