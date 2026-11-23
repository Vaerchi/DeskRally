package controlplane

import "testing"

func TestRunHistoryResult(t *testing.T) {
	code := int32(-1)
	for _, tc := range []struct {
		outcome string
		exit    *int32
		want    string
	}{
		{"exited", &code, "exit -1"},
		{"timed_out", &code, "timed out"},
		{"start_failed", nil, "could not start"},
		{"", nil, "no result reported"},
	} {
		if got := runHistoryResult(tc.outcome, tc.exit); got != tc.want {
			t.Errorf("outcome %q label = %q, want %q", tc.outcome, got, tc.want)
		}
	}
}
