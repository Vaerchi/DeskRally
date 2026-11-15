package controlplane

// The docs/66 release-gate statistic (section 2c.3), the one number the hostname-theming release turns on. For each
// state, 2,000 latency samples are collected at the client, from request send to full body received. For EVERY pair
// of states the gate requires |median(A) - median(B)| < 5 ms AND |p95(A) - p95(B)| < 15 ms. Failing any pair BLOCKS
// the release. The thresholds, the sample count and the floor are never loosened to pass: a flaky environment is
// fixed, not accommodated (docs/66; release-gate plan, 2026-11-06).
//
// The unit suite's relative checks (TestResponseScheduleIsTheSameForEveryState, http_redeem_scoped_test.go) keep
// their own small-sample helpers. This file is the gate's: no tolerance parameter, strict comparisons, and a run
// with too few samples is an error, never a pass.

import (
	"fmt"
	"sort"
	"time"
)

const (
	gateMinSamples = 2000
	gateMedianMax  = 5 * time.Millisecond  // a pair FAILS at |d median| >= this
	gateP95Max     = 15 * time.Millisecond // a pair FAILS at |d p95| >= this
)

type gateSummary struct {
	N           int
	Median, P95 time.Duration
}

// gateSummarize returns the median (the mean of the two middle values for an even count) and the nearest-rank
// p95 (sorted[ceil(0.95 n) - 1]). It sorts a copy, so the caller's slice keeps its collection order.
func gateSummarize(d []time.Duration) gateSummary {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n == 0 {
		return gateSummary{}
	}
	med := s[n/2]
	if n%2 == 0 {
		med = (s[n/2-1] + s[n/2]) / 2
	}
	rank := (95*n + 99) / 100 // ceil(0.95 n) in integers
	return gateSummary{N: n, Median: med, P95: s[rank-1]}
}

type gatePairFailure struct {
	A, B           string
	DMedian, DP95  time.Duration
	MedianExceeded bool
	P95Exceeded    bool
}

func (f gatePairFailure) String() string {
	return fmt.Sprintf("%s vs %s: |d median| = %v (limit < %v, failed=%v), |d p95| = %v (limit < %v, failed=%v)",
		f.A, f.B, f.DMedian, gateMedianMax, f.MedianExceeded, f.DP95, gateP95Max, f.P95Exceeded)
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// gatePairwise checks every pair of states. It returns an error, not a pass, when there are fewer than two states
// or any state has fewer than gateMinSamples samples. States are visited in sorted order so the report is stable.
func gatePairwise(samples map[string][]time.Duration) (map[string]gateSummary, []gatePairFailure, error) {
	if len(samples) < 2 {
		return nil, nil, fmt.Errorf("release gate: %d state(s); a pairwise statistic needs at least 2", len(samples))
	}
	names := make([]string, 0, len(samples))
	for k := range samples {
		names = append(names, k)
	}
	sort.Strings(names)
	sum := make(map[string]gateSummary, len(names))
	for _, k := range names {
		if n := len(samples[k]); n < gateMinSamples {
			return nil, nil, fmt.Errorf("release gate: state %q has %d samples; the gate needs at least %d", k, n, gateMinSamples)
		}
		sum[k] = gateSummarize(samples[k])
	}
	var fails []gatePairFailure
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			a, b := sum[names[i]], sum[names[j]]
			dm, dp := absDur(a.Median-b.Median), absDur(a.P95-b.P95)
			if dm >= gateMedianMax || dp >= gateP95Max {
				fails = append(fails, gatePairFailure{A: names[i], B: names[j], DMedian: dm, DP95: dp,
					MedianExceeded: dm >= gateMedianMax, P95Exceeded: dp >= gateP95Max})
			}
		}
	}
	return sum, fails, nil
}
