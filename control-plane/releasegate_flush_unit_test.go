package controlplane

import "testing"

func flushSamples(msPerFlush ...float64) []gateFlushSample {
	out := []gateFlushSample{{}}
	for _, v := range msPerFlush {
		p := out[len(out)-1]
		out = append(out, gateFlushSample{Flushes: p.Flushes + 1000, FlushMS: p.FlushMS + int64(v*1000)})
	}
	return out
}

// The VOID rule must fire on the step that was measured on 2026-11-13 (0.94 ms to 2.91 ms), and must NOT fire on a stable
// disk, a single slow window, a ratio of exactly 2, or too few flushes.
func TestGateFlushVoidRule(t *testing.T) {
	step := []float64{0.94, 0.94, 0.93, 0.94, 0.94, 2.91, 2.92, 2.94, 2.91, 2.9}
	if r, void, judged := gateFlushVerdict(gateFlushWindowMS(flushSamples(step...))); !judged || !void || r < 3 {
		t.Fatalf("the measured 3x step must be VOID: ratio %.2f void %v judged %v", r, void, judged)
	}
	if _, void, judged := gateFlushVerdict(gateFlushWindowMS(flushSamples(0.94, 0.95, 0.93, 0.96, 0.94, 0.95))); void || !judged {
		t.Fatal("a stable disk must not be VOID")
	}
	if _, void, _ := gateFlushVerdict(gateFlushWindowMS(flushSamples(0.94, 0.95, 4.0, 0.96, 0.94, 0.95))); void {
		t.Fatal("one slow window is noise, not a step")
	}
	if _, void, _ := gateFlushVerdict(gateFlushWindowMS(flushSamples(1, 1, 1, 2, 2, 2))); void {
		t.Fatal("a ratio of exactly 2.0 is not more than 2.0")
	}
	if _, void, _ := gateFlushVerdict(gateFlushWindowMS(flushSamples(1, 1, 1, 2.01, 2.01, 2.01))); !void {
		t.Fatal("a ratio just above 2.0 must be VOID")
	}
	if _, void, judged := gateFlushVerdict(gateFlushWindowMS(flushSamples(1, 5))); void || judged {
		t.Fatal("two windows are too few to judge")
	}
	idle := []gateFlushSample{{}, {Flushes: 5, FlushMS: 20}, {Flushes: 10, FlushMS: 90}, {Flushes: 15, FlushMS: 10}}
	if w := gateFlushWindowMS(idle); len(w) != 0 {
		t.Fatalf("windows with fewer than %d flushes carry no information: %v", gateFlushMinPerWindow, w)
	}
	if n := (gateFlushResult{Reason: "x"}).Note(); n != "flush latency not measured: x" {
		t.Fatalf("the not-measured note is part of the record: %q", n)
	}
}
