package controlplane

// The docs/66 release gate's LOAD assertions (plan step 6, merged plan items 9 and 11) as PURE functions over what a
// phase measured, so each one has a unit test that feeds it a failing measurement and requires a failure (the
// negative controls that need no database). The load tests in releasegate_load_test.go (behind the releasegate tag)
// run the real stack, hand the measurements to these functions, and add real-stack negative controls of their own.
//
// EVERY number below is fixed here, with its reasoning, BEFORE any result was looked at, and none of them moves with
// DESKRALLY_GATE_SCALE: the knob scales how much load is offered and for how long, never what counts as a failure.
// A bound that a smoke run fails is a finding to report, not a number to adjust.

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// The offered rates and durations of the plan at scale 1.
	//
	// Branding admitted ceiling: 128 in flight, each held floor 150 ms + jitter 0..10 ms (mean 155 ms), so at most
	// 128 / 0.155 = about 825 admitted requests per second. The plan offers 3,500-4,000/s ("about 5x"): 4,000.
	gateBrandingOffered = 4000.0
	gateBrandingCeiling = 825.0
	// Redeem: 64 in flight, each rejection held floor 60 ms + jitter 0..20 ms (mean 70 ms): about 914/s of rejections.
	// The plan's mix rate is 2,000/s.
	gateRedeemOffered = 2000.0
	gateRedeemCeiling = 914.0
	// The overload is "exercised" when the offered rate is at least this multiple of the ceiling; only then is the
	// assertion that the global cap was REACHED made (a smoke run at a small scale may not offer enough to reach it; its
	// record says so, and the deterministic 429 cases reach every cap at any scale).
	gateOverloadFactor = 2.0
	// 6,000 distinct client addresses (the plan says 5,000+). At the offered rate each address sends 0.67 requests per
	// second (40 per minute), inside the 120/minute rate budget, so the only 429s of the overload run are admission 429s.
	gateLoadIPPool = 6000
	// 5 minutes per soak and 60 s per load run, as the plan.
	gateSoakDuration = 5 * time.Minute
	gateLoadDuration = 60 * time.Second

	// A window's admitted throughput must be at least this fraction of the median window (plan item 11: "within 90% of
	// the median window"). Only the low side is bounded: a window ABOVE the median is not a collapse.
	gateStableFraction = 0.9
	gateMinWindows     = 3

	// Resource bounds (plan item 8). Goroutines: the connection cap is 1024 and a connection can carry a handler plus a
	// lookup goroutine plus the response timers, so 4 per connection plus 512 for everything else = 4,608.
	gateGoroutinePeakMax = 1024*4 + 512
	// Handles/descriptors: the 1024 connection cap plus 64 (pool connections, the listener, files), above the start.
	gateFDPeakOverStart = 1024 + 64
	// Heap in use: a fixed ceiling. 128 admitted exchanges hold at most a 128 KiB body each, 1024 connections hold two 4
	// KiB buffers each; the rate-budget map holds 100,000 keys at most; everything else is small. 256 MiB is far above
	// that and far below anything a leak at these rates reaches by accident.
	gateHeapInuseMax = 256 << 20
	// No-growth bounds, End - Start of a phase measured after a GC with the load stopped and the connections gone, the
	// pools already at working size (the warm-up). Goroutines: 8 (a pool health-check or timer goroutine may come and
	// go). Handles: 16 (one connection more or less in a pool, a timer). Live heap (HeapAlloc after GC): 8 MiB, which
	// is under 1 KiB per 1,000 requests of a 5-minute soak at full scale: a leak of even 8 bytes per request at 4,000
	// req/s for 300 s (9.6 MB) is caught; the in-use heap (spans, fragmentation) gets 32 MiB.
	gateGoroutineGrowthMax = 8
	gateFDGrowthMax        = 16
	gateHeapAllocGrowthMax = 8 << 20
	gateHeapInuseGrowthMax = 32 << 20
	// After the load stops, the process must be back at baseline within this long (plan item 8: "within 5 s").
	gateSettleWithin = 5 * time.Second
	// The public exchange bound (docs/66 2d.2): no admitted exchange, from the client's first byte to its last, may exceed it.
	gateExchangeMax = 2 * time.Second
)

// gateScale reads DESKRALLY_GATE_SCALE: a number in (0, 1], default 1 (the plan's full scale). It multiplies the
// offered rates and the durations of the load and soak phases, and nothing else: no threshold, bound or sample count
// reads it, and every JSON record states it.
func gateScale(t testing.TB) float64 {
	t.Helper()
	v := os.Getenv("DESKRALLY_GATE_SCALE")
	if v == "" {
		return 1
	}
	s, err := strconv.ParseFloat(v, 64)
	if err != nil || s <= 0 || s > 1 {
		t.Fatalf("release gate: DESKRALLY_GATE_SCALE=%q must be a number in (0, 1]", v)
	}
	return s
}

func gateScaledDuration(t testing.TB, d time.Duration) time.Duration {
	t.Helper()
	return time.Duration(float64(d) * gateScale(t))
}

func gateScaledRate(t testing.TB, r float64) float64 {
	t.Helper()
	return r * gateScale(t)
}

// gateWindowMS: a phase is cut into six windows of at least 1 s and at most 10 s (the plan's 10 s windows at full scale).
func gateWindowMS(d time.Duration) int64 {
	w := d.Milliseconds() / 6
	return min(max(w, 1000), 10000)
}

// evalCaps: the exact admission watermarks never exceed the caps; when the overload was exercised the global cap must
// have been REACHED (a cap that is never reached has not been tested), and likewise the per-key cap when reach is asked for.
func evalCaps(label string, p gateAdmissionPeak, capGlobal, capPerKey int, overloaded, perKeyReached bool) []string {
	var f []string
	if p.Global > capGlobal {
		f = append(f, fmt.Sprintf("%s: global in-flight peaked at %d, above the cap %d", label, p.Global, capGlobal))
	}
	if p.PerKey > capPerKey {
		f = append(f, fmt.Sprintf("%s: in-flight of one client address peaked at %d, above the per-address cap %d", label, p.PerKey, capPerKey))
	}
	if overloaded && p.Global != capGlobal {
		f = append(f, fmt.Sprintf("%s: global in-flight peaked at %d under an overload that must reach the cap %d", label, p.Global, capGlobal))
	}
	if perKeyReached && p.PerKey != capPerKey {
		f = append(f, fmt.Sprintf("%s: in-flight of one client address peaked at %d where more than the cap (%d) were offered at once; the cap is %d", label, p.PerKey, capPerKey+1, capPerKey))
	}
	return f
}

// mergeFP adds the 429 fingerprints of several results.
func mergeFP(rs ...loadResult) map[string]*loadFP {
	out := map[string]*loadFP{}
	for _, r := range rs {
		for k, f := range r.FP {
			d := out[k]
			if d == nil {
				d = &loadFP{Raw: f.Raw}
				out[k] = d
			}
			d.Count += f.Count
		}
	}
	return out
}

// evalIdentical429 requires the 429s to be ONE byte string (Date excluded) and that string to be the expected response:
// status 429, Retry-After "1", and the body the code defines.
func evalIdentical429(fps map[string]*loadFP, wantBody []byte, total429 int64) []string {
	var f []string
	var counted int64
	for _, x := range fps {
		counted += x.Count
	}
	if counted != total429 {
		f = append(f, fmt.Sprintf("429: %d fingerprinted of %d", counted, total429))
	}
	if len(fps) > 1 {
		keys := make([]string, 0, len(fps))
		for k := range fps {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f = append(f, fmt.Sprintf("429 not byte-identical: %d responses of %q", fps[k].Count, fps[k].Raw))
		}
		f = append(f, fmt.Sprintf("%d distinct 429 byte strings, want 1", len(fps)))
	}
	for _, x := range fps {
		res, err := http.ReadResponse(bufio.NewReader(strings.NewReader(x.Raw)), nil)
		if err != nil {
			f = append(f, fmt.Sprintf("429 exemplar does not parse: %v", err))
			continue
		}
		body, _ := io.ReadAll(res.Body)
		if res.StatusCode != http.StatusTooManyRequests {
			f = append(f, fmt.Sprintf("429 exemplar has status %d", res.StatusCode))
		}
		if ra := res.Header.Get("Retry-After"); ra != "1" {
			f = append(f, fmt.Sprintf("429 Retry-After is %q, want \"1\"", ra))
		}
		if len(wantBody) > 0 && !bytes.Equal(bytes.TrimSpace(body), bytes.TrimSpace(wantBody)) {
			f = append(f, fmt.Sprintf("429 body is %q, want %q", body, wantBody))
		}
	}
	return f
}

// evalContent: every body the server returned under load is one it owes. allowed[state] is the set of body hashes a 200
// of that state may carry; allowedStatus[state] the statuses it may have (429 is always allowed: its bytes are checked
// by evalIdentical429). A hash outside the set (a published state answering neutral, a corrupted logo) fails, and so
// does a state seen with a status outside its set.
func evalContent(res loadResult, allowed map[string]map[string]bool, allowedStatus map[string][]int) []string {
	var f []string
	names := make([]string, 0, len(res.States))
	for n := range res.States {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		s := res.States[n]
		ok := map[int]bool{http.StatusTooManyRequests: true}
		for _, c := range allowedStatus[n] {
			ok[c] = true
		}
		for code, cnt := range s.Status {
			if !ok[code] {
				f = append(f, fmt.Sprintf("%s: %d response(s) with status %d", n, cnt, code))
			}
		}
		for key, cnt := range s.Bodies {
			status, hash, _ := strings.Cut(key, ":")
			if status != "200" && status != "403" {
				continue
			}
			if !allowed[n][status+":"+hash] && !allowed[n][hash] {
				f = append(f, fmt.Sprintf("%s: %d response(s) with status %s carry body %s..., which this state does not owe", n, cnt, status, hash[:12]))
			}
		}
	}
	return f
}

// evalAdmittedLatency: no admitted response from the client's first byte written to its last byte read was faster than
// minNS (the floor: the client's clock starts before the server's), and none slower than the 2 s exchange bound.
func evalAdmittedLatency(res loadResult, floor time.Duration, states ...string) []string {
	var f []string
	for _, n := range states {
		s := res.States[n]
		if s == nil || s.Sampled == 0 {
			f = append(f, fmt.Sprintf("%s: no admitted sample", n))
			continue
		}
		if time.Duration(s.MinNS) < floor {
			f = append(f, fmt.Sprintf("%s: an admitted response completed after %v, before the %v floor", n, time.Duration(s.MinNS), floor))
		}
		if time.Duration(s.MaxNS) > gateExchangeMax {
			f = append(f, fmt.Sprintf("%s: an admitted response took %v, beyond the %v exchange bound", n, time.Duration(s.MaxNS), gateExchangeMax))
		}
	}
	return f
}

// evalStable: every whole window's admitted count is at least gateStableFraction of the median window.
func evalStable(windows []int64) []string {
	if len(windows) < gateMinWindows {
		return []string{fmt.Sprintf("throughput: %d whole window(s), need at least %d", len(windows), gateMinWindows)}
	}
	s := append([]int64(nil), windows...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	med := float64(s[len(s)/2])
	if len(s)%2 == 0 {
		med = float64(s[len(s)/2-1]+s[len(s)/2]) / 2
	}
	var f []string
	if med == 0 {
		return []string{"throughput: the median window admitted nothing"}
	}
	for i, w := range windows {
		if float64(w) < gateStableFraction*med {
			f = append(f, fmt.Sprintf("throughput: window %d admitted %d, under %.0f%% of the median window %.0f", i, w, gateStableFraction*100, med))
		}
	}
	return f
}

// evalResources bounds a phase's resources from its sampler summary (taken with the load stopped, after settling and a
// GC): peaks against the fixed ceilings, End-Start against the no-growth bounds. backendHeadroom is how many more
// backends the application pools may legitimately open (MaxConns minus what they held at the start).
func evalResources(m gateMetrics, backendHeadroom int64) []string {
	var f []string
	get := func(name string) (gateSeries, bool) {
		s, ok := m.Series[name]
		if !ok {
			f = append(f, fmt.Sprintf("resource %s was not measured", name))
		}
		return s, ok
	}
	if s, ok := get("goroutines"); ok {
		if s.Peak >= gateGoroutinePeakMax {
			f = append(f, fmt.Sprintf("goroutines peaked at %d, at or above %d", s.Peak, gateGoroutinePeakMax))
		}
		if s.Growth > gateGoroutineGrowthMax {
			f = append(f, fmt.Sprintf("goroutines grew by %d (%d to %d), more than %d", s.Growth, s.Start, s.End, gateGoroutineGrowthMax))
		}
	}
	if s, ok := get("open_fds"); ok && s.Peak-s.Start > gateFDPeakOverStart {
		f = append(f, fmt.Sprintf("descriptors/handles peaked %d above the start, more than %d", s.Peak-s.Start, gateFDPeakOverStart))
	}
	// Growth is judged net of the OS threads the runtime created (see gateHandlesPerOSThread).
	if s, ok := get("open_fds_net"); ok && s.Growth > gateFDGrowthMax {
		f = append(f, fmt.Sprintf("descriptors/handles (net of OS threads) grew by %d (%d to %d), more than %d", s.Growth, s.Start, s.End, gateFDGrowthMax))
	}
	if s, ok := get("heap_inuse_bytes"); ok {
		if s.Peak > gateHeapInuseMax {
			f = append(f, fmt.Sprintf("heap in use peaked at %d MiB, above %d MiB", s.Peak>>20, gateHeapInuseMax>>20))
		}
		if s.Growth > gateHeapInuseGrowthMax {
			f = append(f, fmt.Sprintf("heap in use grew by %d MiB, more than %d MiB", s.Growth>>20, gateHeapInuseGrowthMax>>20))
		}
	}
	if s, ok := get("heap_alloc_bytes"); ok && s.Growth > gateHeapAllocGrowthMax {
		f = append(f, fmt.Sprintf("live heap grew by %d KiB after GC, more than %d MiB", s.Growth>>10, gateHeapAllocGrowthMax>>20))
	}
	if s, ok := get("pg_stat_activity_backends"); ok {
		if s.Peak > s.Start+backendHeadroom+2 {
			f = append(f, fmt.Sprintf("database backends peaked at %d, more than %d above the start %d (pool headroom %d + 2)", s.Peak, backendHeadroom+2, s.Start, backendHeadroom))
		}
	}
	for name, s := range m.Series {
		if strings.HasPrefix(name, "pool/") && strings.HasSuffix(name, "/acquired_conns") && s.End != 0 {
			f = append(f, fmt.Sprintf("%s is %d after the load stopped; a connection is still held", name, s.End))
		}
	}
	for k, why := range m.NotMeasured {
		f = append(f, fmt.Sprintf("resource %s not measured: %s", k, why))
	}
	return f
}

// gateNetFDs is the descriptor/handle count net of the OS threads created (the "open_fds_net" series).
func gateNetFDs() (int, bool) {
	n, ok, _ := gateOpenFDs()
	return n - gateHandlesPerOSThread*pprof.Lookup("threadcreate").Count(), ok
}

// gateSettle waits (up to gateSettleWithin) for the process to return to baseline: goroutines and descriptors within
// their no-growth bounds of the start values. It returns when they are, or when the time is up; evalResources then
// judges the end state, so a process that does not settle fails there.
func gateSettle(startGoroutines, startFDs int) {
	deadline := time.Now().Add(gateSettleWithin)
	for time.Now().Before(deadline) {
		ng := runtime.NumGoroutine()
		fds, ok := gateNetFDs()
		if ng <= startGoroutines+gateGoroutineGrowthMax && (!ok || fds <= startFDs+gateFDGrowthMax) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Unit tests: every evaluator accepts a clean measurement and rejects each kind of failing one.
// ---------------------------------------------------------------------------------------------------------

func fpOf(raw string, n int64) map[string]*loadFP {
	return map[string]*loadFP{sha256Hex([]byte(raw)): {Count: n, Raw: raw}}
}

const goodTooMany = "HTTP/1.1 429 Too Many Requests\r\nCache-Control: no-store\r\nContent-Length: 29\r\nRetry-After: 1\r\n\r\n{\"error\":\"too many requests\"}"

func TestGateEvalCaps(t *testing.T) {
	if f := evalCaps("b", gateAdmissionPeak{Global: 128, PerKey: 4}, 128, 4, true, true); len(f) != 0 {
		t.Errorf("clean peaks failed: %v", f)
	}
	for name, c := range map[string]struct {
		p            gateAdmissionPeak
		over, reachK bool
	}{
		"global above cap":    {gateAdmissionPeak{Global: 129, PerKey: 4}, true, true},
		"per key above cap":   {gateAdmissionPeak{Global: 128, PerKey: 5}, true, true},
		"overload not hit":    {gateAdmissionPeak{Global: 100, PerKey: 4}, true, true},
		"per key not reached": {gateAdmissionPeak{Global: 128, PerKey: 3}, true, true},
	} {
		if f := evalCaps("b", c.p, 128, 4, c.over, c.reachK); len(f) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
	if f := evalCaps("b", gateAdmissionPeak{Global: 100, PerKey: 1}, 128, 4, false, false); len(f) != 0 {
		t.Errorf("an unexercised overload must not demand the cap be reached: %v", f)
	}
}

func TestGateEvalIdentical429(t *testing.T) {
	body := []byte(`{"error":"too many requests"}`)
	if f := evalIdentical429(fpOf(goodTooMany, 10), body, 10); len(f) != 0 {
		t.Errorf("clean 429s failed: %v", f)
	}
	other := strings.Replace(goodTooMany, "Retry-After: 1", "Retry-After: 2", 1)
	two := mergeFP(loadResult{FP: fpOf(goodTooMany, 9)}, loadResult{FP: fpOf(other, 1)})
	if f := evalIdentical429(two, body, 10); len(f) == 0 {
		t.Error("two different 429 byte strings were not detected")
	}
	if f := evalIdentical429(fpOf(other, 10), body, 10); len(f) == 0 {
		t.Error("a Retry-After of 2 was not detected")
	}
	diffBody := strings.Replace(goodTooMany, "too many requests", "slow down please", 1)
	if f := evalIdentical429(fpOf(diffBody, 10), body, 10); len(f) == 0 {
		t.Error("a different 429 body was not detected")
	}
	if f := evalIdentical429(fpOf(goodTooMany, 9), body, 10); len(f) == 0 {
		t.Error("a 429 that was not fingerprinted was not detected")
	}
}

func TestGateEvalContent(t *testing.T) {
	ok := map[string]map[string]bool{"pub": {"200:" + strings.Repeat("a", 64): true}}
	res := loadResult{States: map[string]*loadStateResult{"pub": {Status: map[int]int64{200: 5, 429: 2}, Bodies: map[string]int64{"200:" + strings.Repeat("a", 64): 5}}}}
	if f := evalContent(res, ok, map[string][]int{"pub": {200}}); len(f) != 0 {
		t.Errorf("clean content failed: %v", f)
	}
	res.States["pub"].Bodies["200:"+strings.Repeat("b", 64)] = 1
	if f := evalContent(res, ok, map[string][]int{"pub": {200}}); len(f) == 0 {
		t.Error("a corrupted body was not detected")
	}
	res.States["pub"].Status[500] = 1
	if f := evalContent(res, ok, map[string][]int{"pub": {200}}); len(f) < 2 {
		t.Errorf("a 500 was not detected: %v", f)
	}
}

func TestGateEvalAdmittedLatency(t *testing.T) {
	mk := func(minD, maxD time.Duration) loadResult {
		return loadResult{States: map[string]*loadStateResult{"s": {Sampled: 10, MinNS: int64(minD), MaxNS: int64(maxD)}}}
	}
	if f := evalAdmittedLatency(mk(150*time.Millisecond, 400*time.Millisecond), 150*time.Millisecond, "s"); len(f) != 0 {
		t.Errorf("clean latency failed: %v", f)
	}
	if f := evalAdmittedLatency(mk(149*time.Millisecond, 400*time.Millisecond), 150*time.Millisecond, "s"); len(f) == 0 {
		t.Error("a response before the floor was not detected")
	}
	if f := evalAdmittedLatency(mk(150*time.Millisecond, 2001*time.Millisecond), 150*time.Millisecond, "s"); len(f) == 0 {
		t.Error("a response beyond the exchange bound was not detected")
	}
	if f := evalAdmittedLatency(loadResult{States: map[string]*loadStateResult{}}, 150*time.Millisecond, "s"); len(f) == 0 {
		t.Error("a state with no admitted sample was not detected")
	}
}

func TestGateEvalStable(t *testing.T) {
	if f := evalStable([]int64{820, 830, 825, 818, 828, 822}); len(f) != 0 {
		t.Errorf("steady throughput failed: %v", f)
	}
	if f := evalStable([]int64{820, 830, 700, 818, 828, 822}); len(f) != 1 {
		t.Errorf("a window at 85%% of the median was not detected exactly once: %v", f)
	}
	if f := evalStable([]int64{820, 830, 0, 818, 828, 822}); len(f) == 0 {
		t.Error("a stalled window was not detected")
	}
	if f := evalStable([]int64{100, 100}); len(f) == 0 {
		t.Error("too few windows must fail, never pass")
	}
	// Exactly 90% passes (the bound is "at least"), just under fails.
	if f := evalStable([]int64{1000, 1000, 1000, 900}); len(f) != 0 {
		t.Errorf("exactly 90%% failed: %v", f)
	}
	if f := evalStable([]int64{1000, 1000, 1000, 899}); len(f) == 0 {
		t.Error("89.9% passed")
	}
}

func cleanMetrics() gateMetrics {
	return gateMetrics{Series: map[string]gateSeries{
		"goroutines":                 {Start: 40, End: 42, Peak: 900, Growth: 2},
		"open_fds":                   {Start: 200, End: 203, Peak: 700, Growth: 3},
		"open_fds_net":               {Start: 200, End: 203, Peak: 700, Growth: 3},
		"heap_inuse_bytes":           {Start: 20 << 20, End: 22 << 20, Peak: 60 << 20, Growth: 2 << 20},
		"heap_alloc_bytes":           {Start: 10 << 20, End: 11 << 20, Peak: 40 << 20, Growth: 1 << 20},
		"pg_stat_activity_backends":  {Start: 20, End: 20, Peak: 24, Growth: 0},
		"pool/lookup/acquired_conns": {Start: 0, End: 0, Peak: 8},
	}}
}

func TestGateEvalResources(t *testing.T) {
	if f := evalResources(cleanMetrics(), 4); len(f) != 0 {
		t.Errorf("clean resources failed: %v", f)
	}
	mutate := map[string]func(m *gateMetrics){
		"goroutine growth": func(m *gateMetrics) { s := m.Series["goroutines"]; s.Growth = 9; m.Series["goroutines"] = s },
		"goroutine peak": func(m *gateMetrics) {
			s := m.Series["goroutines"]
			s.Peak = gateGoroutinePeakMax
			m.Series["goroutines"] = s
		},
		"handle growth": func(m *gateMetrics) { s := m.Series["open_fds_net"]; s.Growth = 17; m.Series["open_fds_net"] = s },
		"handle peak": func(m *gateMetrics) {
			s := m.Series["open_fds"]
			s.Peak = s.Start + gateFDPeakOverStart + 1
			m.Series["open_fds"] = s
		},
		"heap in use peak": func(m *gateMetrics) {
			s := m.Series["heap_inuse_bytes"]
			s.Peak = gateHeapInuseMax + 1
			m.Series["heap_inuse_bytes"] = s
		},
		"heap in use growth": func(m *gateMetrics) {
			s := m.Series["heap_inuse_bytes"]
			s.Growth = gateHeapInuseGrowthMax + 1
			m.Series["heap_inuse_bytes"] = s
		},
		"live heap growth": func(m *gateMetrics) {
			s := m.Series["heap_alloc_bytes"]
			s.Growth = gateHeapAllocGrowthMax + 1
			m.Series["heap_alloc_bytes"] = s
		},
		"backends": func(m *gateMetrics) {
			s := m.Series["pg_stat_activity_backends"]
			s.Peak = s.Start + 4 + 3
			m.Series["pg_stat_activity_backends"] = s
		},
		"held connection": func(m *gateMetrics) {
			s := m.Series["pool/lookup/acquired_conns"]
			s.End = 1
			m.Series["pool/lookup/acquired_conns"] = s
		},
		"missing series": func(m *gateMetrics) { delete(m.Series, "goroutines") },
		"not measured":   func(m *gateMetrics) { m.NotMeasured = map[string]string{"pg_stat_activity": "no pool"} },
	}
	for name, mut := range mutate {
		m := cleanMetrics()
		mut(&m)
		if f := evalResources(m, 4); len(f) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
}

func TestGateScaleKnob(t *testing.T) {
	t.Setenv("DESKRALLY_GATE_SCALE", "0.25")
	if got := gateScale(t); got != 0.25 {
		t.Fatalf("scale %v", got)
	}
	if got := gateScaledRate(t, 4000); got != 1000 {
		t.Errorf("rate %v, want 1000", got)
	}
	if got := gateScaledDuration(t, 5*time.Minute); got != 75*time.Second {
		t.Errorf("duration %v, want 75s", got)
	}
	t.Setenv("DESKRALLY_GATE_SCALE", "")
	if gateScale(t) != 1 {
		t.Error("default scale is not 1")
	}
	if w := gateWindowMS(time.Minute); w != 10000 {
		t.Errorf("60 s window %d ms, want 10000", w)
	}
	if w := gateWindowMS(12 * time.Second); w != 2000 {
		t.Errorf("12 s window %d ms, want 2000", w)
	}
	if w := gateWindowMS(3 * time.Second); w != 1000 {
		t.Errorf("3 s window %d ms, want the 1000 ms minimum", w)
	}
}

// The server's own bounds on a hostile connection (listener.go): a request header block must finish within
// ReadHeaderTimeout (5 s), a request body within ReadTimeout (5 s; the public exchange wrapper cuts it at 2 s). The
// gate allows 3 s of scheduling slack on top: a connection that outlives bound + 3 s means the server holds what it
// promised to cut.
const (
	gateHostileHeaderBound = DefaultReadHeaderTimeout + 3*time.Second
	gateHostileBodyBound   = DefaultReadTimeout + 3*time.Second
	// A class is only required to have been closed at least once when the run lasts long enough for every connection
	// to reach the bound: twice the bound.
	gateHostileMinRun = 2 * DefaultReadHeaderTimeout
	// The whole mix stays below the 1024 connection cap (the plan: a hostile mix must not be the connection cap test).
	gateHostileConnCeiling = 1000
)

// evalHostile checks what the hostile client saw of the server: slow header and slow body writers are cut within
// the server's own bounds (and, on a run long enough, every one of them was cut at least once), no connection was
// refused, and the mix never reached the connection cap. Slow readers are judged by the server's resources, not by
// time: the server may have buffered the whole response and be holding nothing.
func evalHostile(h hostileResult, p hostilePlan) []string {
	var f []string
	long := time.Duration(p.DurationMS)*time.Millisecond >= gateHostileMinRun
	for _, c := range []struct {
		name  string
		cl    hostileClass
		n     int
		bound time.Duration
	}{{"slow header writers", h.SlowHeader, p.SlowHeaders, gateHostileHeaderBound}, {"slow body writers", h.SlowBody, p.SlowBodies, gateHostileBodyBound}} {
		if time.Duration(c.cl.MaxLifetimeMS)*time.Millisecond > c.bound {
			f = append(f, fmt.Sprintf("%s: a connection lived %d ms before the server closed it, beyond %v", c.name, c.cl.MaxLifetimeMS, c.bound))
		}
		if long && c.cl.ClosedByServer < int64(c.n) {
			f = append(f, fmt.Sprintf("%s: the server closed only %d of %d connections in a %d ms run", c.name, c.cl.ClosedByServer, c.n, p.DurationMS))
		}
	}
	for name, cl := range map[string]hostileClass{"slow header": h.SlowHeader, "slow body": h.SlowBody, "slow reader": h.SlowReader, "churn": h.Churn} {
		if cl.DialErrors > 0 {
			f = append(f, fmt.Sprintf("%s: %d connection(s) could not be opened", name, cl.DialErrors))
		}
		if cl.Opened == 0 && ((name == "slow header" && p.SlowHeaders > 0) || (name == "slow body" && p.SlowBodies > 0) ||
			(name == "slow reader" && p.SlowReaders > 0) || (name == "churn" && p.ChurnRate > 0)) {
			f = append(f, fmt.Sprintf("%s: no connection was ever opened; the class did not run", name))
		}
	}
	if h.PeakOpen > gateHostileConnCeiling {
		f = append(f, fmt.Sprintf("the hostile client held %d connections at once, above the %d ceiling that keeps the mix under the 1024 cap", h.PeakOpen, gateHostileConnCeiling))
	}
	return f
}

func TestGateEvalHostile(t *testing.T) {
	p := hostilePlan{DurationMS: 12000, SlowHeaders: 10, SlowBodies: 10, SlowReaders: 4, ChurnRate: 100}
	good := hostileResult{
		SlowHeader: hostileClass{Opened: 20, ClosedByServer: 10, MaxLifetimeMS: 5100},
		SlowBody:   hostileClass{Opened: 30, ClosedByServer: 28, MaxLifetimeMS: 2100},
		SlowReader: hostileClass{Opened: 4}, Churn: hostileClass{Opened: 1200}, PeakOpen: 300}
	if f := evalHostile(good, p); len(f) != 0 {
		t.Fatalf("a clean hostile run failed: %v", f)
	}
	for name, mut := range map[string]func(h *hostileResult){
		"header held":              func(h *hostileResult) { h.SlowHeader.MaxLifetimeMS = 9000 },
		"body held":                func(h *hostileResult) { h.SlowBody.MaxLifetimeMS = 9000 },
		"header never cut":         func(h *hostileResult) { h.SlowHeader.ClosedByServer = 3 },
		"dial refused":             func(h *hostileResult) { h.Churn.DialErrors = 1 },
		"class did not run":        func(h *hostileResult) { h.SlowReader.Opened = 0 },
		"above connection ceiling": func(h *hostileResult) { h.PeakOpen = 1001 },
	} {
		h := good
		mut(&h)
		if f := evalHostile(h, p); len(f) == 0 {
			t.Errorf("%s: not detected", name)
		}
	}
	// A short run does not demand a closure of every connection (it may end before the bound), but still bounds lifetimes.
	short := p
	short.DurationMS = 3000
	h := good
	h.SlowHeader.ClosedByServer = 0
	if f := evalHostile(h, short); len(f) != 0 {
		t.Errorf("a short run must not require closures: %v", f)
	}
}
