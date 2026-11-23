package controlplane

// Unit tests for the release-gate statistic (releasegate_stat_test.go). These always run: the statistic must be
// right before any gate run can mean anything. Every boundary is tested on BOTH sides, so flipping a comparison
// or moving the percentile index fails a case here.

import (
	"strings"
	"testing"
	"time"
)

// gateRamp returns n samples base, base+step, ..., in a shuffled (reversed) order.
func gateRamp(n int, base, step time.Duration) []time.Duration {
	out := make([]time.Duration, n)
	for i := range out {
		out[n-1-i] = base + time.Duration(i)*step
	}
	return out
}

func gateShift(d []time.Duration, by time.Duration) []time.Duration {
	out := make([]time.Duration, len(d))
	for i, v := range d {
		out[i] = v + by
	}
	return out
}

func TestGateSummarizeDefinitions(t *testing.T) {
	// 1..2000 ms: median = mean(1000, 1001) = 1000.5 ms; nearest-rank p95 = sorted[ceil(1900)-1] = 1900 ms.
	s := gateSummarize(gateRamp(2000, time.Millisecond, time.Millisecond))
	if s.N != 2000 || s.Median != 1000500*time.Microsecond || s.P95 != 1900*time.Millisecond {
		t.Fatalf("2000-ramp: got %+v, want N=2000 median=1000.5ms p95=1900ms", s)
	}
	// Odd count: the middle value. 2001 samples: median = 1001 ms; p95 = sorted[ceil(1900.95)-1] = sorted[1900] = 1901 ms.
	s = gateSummarize(gateRamp(2001, time.Millisecond, time.Millisecond))
	if s.Median != 1001*time.Millisecond || s.P95 != 1901*time.Millisecond {
		t.Fatalf("2001-ramp: got %+v, want median=1001ms p95=1901ms", s)
	}
	// The caller's slice keeps its order.
	in := []time.Duration{3, 1, 2}
	gateSummarize(in)
	if in[0] != 3 || in[1] != 1 || in[2] != 2 {
		t.Fatalf("gateSummarize reordered its input: %v", in)
	}
}

func TestGatePairwiseMedianBoundary(t *testing.T) {
	base := gateRamp(2000, 150*time.Millisecond, 5*time.Microsecond)
	for _, c := range []struct {
		shift time.Duration
		fail  bool
	}{
		{4900 * time.Microsecond, false},
		{5 * time.Millisecond, true}, // strict: exactly the limit fails
		{5100 * time.Microsecond, true},
	} {
		_, fails, err := gatePairwise(map[string][]time.Duration{"a": base, "b": gateShift(base, c.shift)})
		if err != nil {
			t.Fatal(err)
		}
		if got := len(fails) == 1 && fails[0].MedianExceeded; got != c.fail {
			t.Fatalf("median shift %v: failed=%v (%v), want %v", c.shift, got, fails, c.fail)
		}
	}
}

// Same median, different tail: only the p95 rule can catch it.
func TestGatePairwiseP95Boundary(t *testing.T) {
	base := gateRamp(2000, 150*time.Millisecond, 5*time.Microsecond)
	tail := func(by time.Duration) []time.Duration {
		out := append([]time.Duration(nil), base...)
		// raise the slowest 6% (ranks 1881..2000 in sorted order), which moves p95 (rank 1900) and not the median
		for i, v := range out {
			if v >= 150*time.Millisecond+1880*5*time.Microsecond {
				out[i] = v + by
			}
		}
		return out
	}
	for _, c := range []struct {
		by   time.Duration
		fail bool
	}{
		{14900 * time.Microsecond, false},
		{15 * time.Millisecond, true},
		{15100 * time.Microsecond, true},
	} {
		sum, fails, err := gatePairwise(map[string][]time.Duration{"a": base, "b": tail(c.by)})
		if err != nil {
			t.Fatal(err)
		}
		if sum["a"].Median != sum["b"].Median {
			t.Fatalf("premise: the tail change moved the median (%v vs %v)", sum["a"].Median, sum["b"].Median)
		}
		got := len(fails) == 1 && fails[0].P95Exceeded && !fails[0].MedianExceeded
		if got != c.fail {
			t.Fatalf("p95 shift %v: failed=%v (%v), want %v", c.by, got, fails, c.fail)
		}
	}
}

// Every pair is checked, in both directions of the difference, and a three-state run reports exactly the bad pairs.
func TestGatePairwiseEveryPair(t *testing.T) {
	base := gateRamp(2000, 150*time.Millisecond, 5*time.Microsecond)
	_, fails, err := gatePairwise(map[string][]time.Duration{
		"published": base,
		"neutral":   gateShift(base, 2*time.Millisecond),
		"dbfail":    gateShift(base, 7*time.Millisecond), // 7 from published (fail), 5 from neutral (fail: strict)
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fails {
		got = append(got, f.A+"|"+f.B)
	}
	if strings.Join(got, ",") != "dbfail|neutral,dbfail|published" {
		t.Fatalf("failing pairs = %v, want dbfail|neutral and dbfail|published", got)
	}
	// A faster state fails just like a slower one.
	if _, fails, _ := gatePairwise(map[string][]time.Duration{"a": gateShift(base, 6*time.Millisecond), "b": base}); len(fails) != 1 {
		t.Fatalf("a slower FIRST state was not caught: %v", fails)
	}
}

func TestGatePairwiseRefusesTooFewSamplesOrStates(t *testing.T) {
	ok := gateRamp(2000, 150*time.Millisecond, time.Microsecond)
	if _, _, err := gatePairwise(map[string][]time.Duration{"a": ok, "b": ok[:1999]}); err == nil || !strings.Contains(err.Error(), "1999 samples") {
		t.Fatalf("1999 samples: err = %v, want a refusal", err)
	}
	if _, _, err := gatePairwise(map[string][]time.Duration{"a": ok}); err == nil {
		t.Fatal("one state: want a refusal, a pairwise statistic needs two")
	}
	if _, fails, err := gatePairwise(map[string][]time.Duration{"a": ok, "b": ok}); err != nil || len(fails) != 0 {
		t.Fatalf("identical states at exactly 2000 samples: fails=%v err=%v, want a clean pass", fails, err)
	}
}
