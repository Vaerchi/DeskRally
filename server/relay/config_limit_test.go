package main

import "testing"

// Configuration must not undo the broker's existing tested admission bound.
func TestRelayConnectionLimitConfiguration(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{
		{"", 1024}, {" \t", 1024}, {"1", 1}, {" 64 ", 64}, {"0", 0},
	} {
		got, err := relayConnectionLimit(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("limit %q: got %d, %v; want %d", tc.raw, got, err, tc.want)
		}
	}
	for _, raw := range []string{"-1", "oops", "1.5", "999999999999999999999999999999999999"} {
		if _, err := relayConnectionLimit(raw); err == nil {
			t.Fatalf("invalid limit %q silently accepted", raw)
		}
	}
}
