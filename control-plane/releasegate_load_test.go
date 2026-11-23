//go:build releasegate

package controlplane

// The docs/66 release gate, plan step 6: load, hostile mix and soak (merged plan items 9, 10, 11, 12).
//
// Every test here drives the REAL stack (the harness of releasegate_harness_test.go and the redeem environment of
// releasegate_redeem_timing_test.go: real handler, production pools as rmt_app, NewPublicServer + LimitListener, the
// edge marker, CP_TRUSTED_PROXIES) from a SEPARATE client process (releasegate_loadclient_test.go), with the sampler
// and the admission watermark of step 5 running, and hands what it measured to the pure assertions of
// releasegate_loadeval_test.go, whose thresholds are fixed in that file with their reasoning.
//
//	TestReleaseGateBrandingLoad       overload from 6,000 addresses; 50 addresses x 8 connections; the three 429 sources
//	TestReleaseGateHostileMix         slow headers, slow bodies, slow readers, churn, below the 1024 connection cap
//	TestReleaseGateLoadNegativeControls  the assertions above DO fail when the server is wrong (real stack)
//	TestReleaseGateRedeemLoad         the anonymous redeem mix at 2,000 req/s, class indistinguishability under load
//	TestReleaseGateBrandingSoak       5 minutes of the overload with the hostile mix running beside it
//	TestReleaseGateRedeemSoak         5 minutes of the redeem mix
//
// DESKRALLY_GATE_SCALE (default 1, a number in (0, 1]) scales the offered rates and the soak/load durations DOWN for
// development smoke runs. Thresholds and bounds never read it; each JSON record states it. The authoritative runs are
// at scale 1 on the Linux VM. A run on a developer machine is at most scale 0.2.
//
//	DESKRALLY_RELEASE_GATE=1 DESKRALLY_GATE_SCALE=0.2 go test -tags releasegate -run TestReleaseGateBrandingLoad -count=1 .

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type gateLoadRecord struct {
	Test         string  `json:"test"`
	Scale        float64 `json:"scale"`
	GOOS         string  `json:"goos"`
	NumCPU       int     `json:"num_cpu"`
	TargetRate   float64 `json:"target_rate"`
	AchievedRate float64 `json:"achieved_offered_rate"`
	Overloaded   bool    `json:"overload_exercised"`
	Sent         int64   `json:"sent"`
	Completed    int64   `json:"completed"`
	Dropped      int64   `json:"dropped_by_client"`
	Exhausted    int64   `json:"exhausted"`
	ElapsedMS    int64   `json:"elapsed_ms"`
	// Status counts "state/status".
	Status   map[string]int64             `json:"status"`
	Total429 int64                        `json:"total_429"`
	Distinct int                          `json:"distinct_429_byte_strings"`
	Windows  []int64                      `json:"admitted_per_window"`
	WindowMS int64                        `json:"window_ms"`
	Cutoffs  int64                        `json:"branding_cutoffs,omitempty"`
	Peaks    map[string]gateAdmissionPeak `json:"admission_peaks,omitempty"`
	Metrics  *gateMetrics                 `json:"metrics,omitempty"`
	Hostile  *hostileResult               `json:"hostile,omitempty"`
	// Summaries: median/p95 of the admitted samples per state (recorded for the statistic phases).
	Summaries    map[string]gateSummary `json:"summaries,omitempty"`
	MinMS        map[string]float64     `json:"min_ms,omitempty"`
	MaxMS        map[string]float64     `json:"max_ms,omitempty"`
	Notes        []string               `json:"notes,omitempty"`
	Exemplar429  string                 `json:"exemplar_429,omitempty"`
	ServerClosed map[string]int64       `json:"server_closed,omitempty"`
	Failures     []string               `json:"failures"`
}

func writeGateJSON(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("DESKRALLY_GATE_OUT")
	if dir == "" {
		dir = t.TempDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, strings.NewReplacer("/", "_", " ", "_").Replace(name)+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("release gate record: %s", p)
}

func newGateLoadRecord(t *testing.T, name string, res loadResult, target float64) gateLoadRecord {
	r := gateLoadRecord{Test: name, Scale: gateScale(t), GOOS: runtime.GOOS, NumCPU: runtime.NumCPU(), TargetRate: target,
		AchievedRate: res.offeredPerSec(), Sent: res.Sent, Completed: res.Completed, Dropped: res.Dropped, Exhausted: res.Exhausted,
		ElapsedMS: res.ElapsedMS, Status: map[string]int64{}, Total429: res.total429(), Distinct: len(res.FP),
		Windows: res.Windows, WindowMS: res.WindowMS, Failures: []string{}}
	for n, s := range res.States {
		for code, c := range s.Status {
			r.Status[fmt.Sprintf("%s/%d", n, code)] = c
		}
	}
	r.ServerClosed = res.ServerClosed
	for _, f := range res.FP {
		r.Exemplar429 = f.Raw
		break
	}
	return r
}

// ---------------------------------------------------------------------------------------------------------
// The measurement frame: warmed baseline, sampler, load, settle, idle check, summary.
// ---------------------------------------------------------------------------------------------------------

// gateWarmupMS: the warm-up before a baseline (the pools reach working size, the address table fills, the runtime has made the
// threads it will use: on Windows every thread is a handle, and the no-growth bound on handles must not read that as a leak).
const gateWarmupMS = 5000

type gateLoadSrc struct {
	shared, lookup *pgxpool.Pool
	su             *pgxpool.Pool
	admission      map[string]*admissionPool
}

// measure runs body between a baseline (one second after the previous load, after a GC) and a settled stop. The
// sampler starts after the baseline, so Start is the warmed, quiet process; the process then has gateSettleWithin to
// return to it before the End sample is taken (and judged). It returns what is not idle after the wait.
func (s gateLoadSrc) measure(body func()) (m gateMetrics, headroom int64, notIdle []string) {
	time.Sleep(time.Second)
	gateGC()
	ng := runtime.NumGoroutine()
	fds, _ := gateNetFDs()
	for _, p := range []*pgxpool.Pool{s.shared, s.lookup} {
		headroom += int64(p.Config().MaxConns) - int64(p.Stat().TotalConns())
	}
	ms := startGateSampler(gateSamplerSources{Pools: map[string]*pgxpool.Pool{"shared": s.shared, "lookup": s.lookup},
		Admission: s.admission, Super: s.su, Interval: 250 * time.Millisecond})
	body()
	gateSettle(ng, fds)
	deadline := time.Now().Add(gateSettleWithin)
	for name, p := range s.admission {
		for {
			in, _ := p.stats()
			if in == 0 {
				break
			}
			if time.Now().After(deadline) {
				notIdle = append(notIdle, fmt.Sprintf("%s admission pool still has %d in flight %v after the load stopped", name, in, gateSettleWithin))
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	return ms.stop(), headroom, notIdle
}

func logGateMetrics(t *testing.T, m gateMetrics) {
	t.Helper()
	for _, name := range m.seriesNames() {
		t.Logf("metric %-34s %+v", name, m.Series[name])
	}
	t.Logf("admission peaks %+v; not measured %v", m.Admission, m.NotMeasured)
}

// ---------------------------------------------------------------------------------------------------------
// Branding.
// ---------------------------------------------------------------------------------------------------------

func statusCount(r loadResult, state string, code int) int64 {
	if s := r.States[state]; s != nil {
		return s.Status[code]
	}
	return 0
}

func gateBrandSrc(e *gateBrandEnv, withRedeem bool) gateLoadSrc {
	s := gateLoadSrc{shared: e.shared, lookup: e.lookup, su: e.su, admission: map[string]*admissionPool{"branding": e.srv.brandingPool()}}
	if withRedeem {
		s.admission["redeem"] = e.srv.redeemPool()
	}
	return s
}

func brandingItems(e *gateBrandEnv) []loadItem {
	its := []loadItem{
		{State: "pub-json", Host: "published.gate.test", Path: e.route("json"), Weight: 3},
		{State: "pub-logo", Host: "published.gate.test", Path: e.route("logo"), Weight: 3},
	}
	for _, s := range e.states {
		switch s.Name {
		case "default", "unmapped", "pending", "unapproved", "disabled":
			its = append(its, loadItem{State: s.Name, Host: s.Host, Path: e.route("json"), Weight: 1})
		}
	}
	return its
}

// gateFetchJSON reads the published host's JSON once, idle, over a fresh connection: the content the published state owes.
func gateFetchJSON(t *testing.T, e *gateBrandEnv) []byte {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+e.addr+e.route("json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "published.gate.test"
	req.Header.Set(EdgeMarkerHeader, e.edge)
	req.Header.Set("X-Forwarded-For", "203.0.113.254") // a documentation address the 10.x load pool never uses
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || sha256Hex(b) == sha256Hex(neutralBrandingResponse.body) {
		t.Fatalf("release gate premise: the published host answers %d with the neutral or no content: %s", resp.StatusCode, b)
	}
	return b
}

func brandingAllowed(e *gateBrandEnv, pubJSON []byte) (map[string]map[string]bool, map[string][]int) {
	neutral := "200:" + sha256Hex(neutralBrandingResponse.body)
	allowed := map[string]map[string]bool{
		"pub-json": {"200:" + sha256Hex(pubJSON): true},
		"pub-logo": {"200:" + sha256Hex(e.logo): true},
	}
	statuses := map[string][]int{"pub-json": {200}, "pub-logo": {200}}
	for _, n := range []string{"default", "unmapped", "pending", "unapproved", "disabled"} {
		allowed[n] = map[string]bool{neutral: true}
		statuses[n] = []int{200}
	}
	return allowed, statuses
}

type brandingPhase struct {
	Name string
	Plan loadPlan
	// Warm: a 2 s open-loop run before the baseline (the pools reach working size, the address table fills).
	Warm        bool
	Hostile     *hostilePlan
	CheckStable bool
	// Overload: the global cap must be reached; PerKeyReached: the per-address cap must be. MaxAdmitted > 0 bounds the
	// non-429 responses (the per-address rate budget: 120 per minute per address).
	Overload      bool
	PerKeyReached bool
	MaxAdmitted   int64
	// Flush: watch the database disk's flush latency and make the run VOID if it changes more than 2x (releasegate_flush_test.go).
	Flush bool
}

// runBrandingPhase runs one phase against e and returns the result and every failed assertion. It fails the test
// itself only when the run is void (the client or a process failed), never for an assertion.
func runBrandingPhase(t *testing.T, e *gateBrandEnv, ph brandingPhase) (loadResult, []string) {
	t.Helper()
	pubJSON := gateFetchJSON(t, e)
	allowed, statuses := brandingAllowed(e, pubJSON)
	plan := ph.Plan
	plan.Addr, plan.Headers = e.addr, map[string]string{EdgeMarkerHeader: e.edge}
	if plan.Items == nil {
		plan.Items = brandingItems(e)
	}
	plan.SampleStatuses = []int{http.StatusOK}
	if ph.CheckStable {
		plan.WindowMS = gateWindowMS(time.Duration(plan.DurationMS) * time.Millisecond)
	}
	if ph.Warm {
		wp := plan
		wp.DurationMS, wp.MaxDurationMS, wp.WindowMS, wp.Total = gateWarmupMS, gateWarmupMS, 0, 0
		if wp.ConnsPerIP > 0 { // per-address connections: the warm-up must not spend the measured addresses' rate budget
			wp.IPBase += 500_000
		}
		if r := runGateLoadProcess(t, wp); r.Completed == 0 {
			t.Fatalf("release gate: the warm-up completed nothing: %v", r.Errors)
		}
	}
	cut0 := e.srv.BrandingCutoffTotal("json") + e.srv.BrandingCutoffTotal("logo")
	var res loadResult
	var hres hostileResult
	var herr error
	hp := hostilePlan{}
	var fm *gateFlushMon
	if ph.Flush {
		fm = startGateFlushMon(e.su, time.Duration(gateWindowMS(time.Duration(plan.DurationMS)*time.Millisecond))*time.Millisecond)
	}
	m, headroom, notIdle := gateBrandSrc(e, ph.Hostile != nil).measure(func() {
		var wg sync.WaitGroup
		if ph.Hostile != nil {
			hp = *ph.Hostile
			hp.Addr, hp.Headers, hp.DurationMS = e.addr, plan.Headers, plan.DurationMS
			wg.Add(1)
			go func() { defer wg.Done(); herr = runGateRoleErr("gate-hostile", hp, &hres) }()
		}
		res = runGateLoadProcess(t, plan)
		wg.Wait()
	})
	var fl *gateFlushResult
	if fm != nil {
		r := fm.result()
		fl = &r
		t.Log("flush: " + r.Note())
	}
	if herr != nil {
		t.Fatalf("release gate: the hostile client failed: %v", herr)
	}
	logGateMetrics(t, m)
	cuts := e.srv.BrandingCutoffTotal("json") + e.srv.BrandingCutoffTotal("logo") - cut0

	scale := gateScale(t)
	overloadAsked := ph.Overload || (plan.Rate > 0 && plan.Rate >= gateOverloadFactor*gateBrandingCeiling)
	var f []string
	if n := res.totalErrors(); n > 0 {
		f = append(f, fmt.Sprintf("the client saw %d error(s): %v", n, res.Errors))
	}
	if plan.Rate > 0 && res.offeredPerSec() < 0.9*plan.Rate {
		f = append(f, fmt.Sprintf("VOID: offered %.0f req/s of the %.0f asked (the client or the box could not keep the rate; %d dropped)", res.offeredPerSec(), plan.Rate, res.Dropped))
	}
	if res.Completed-res.total429() == 0 {
		f = append(f, "no request was admitted")
	}
	f = append(f, evalCaps("branding", m.Admission["branding"], DefaultBrandingAdmitGlobal, DefaultBrandingAdmitPerIP, overloadAsked, ph.PerKeyReached)...)
	if ph.Hostile != nil {
		f = append(f, evalCaps("redeem", m.Admission["redeem"], DefaultRedeemAdmitGlobal, DefaultRedeemAdmitPerIP, false, false)...)
		f = append(f, evalHostile(hres, hp)...)
	}
	f = append(f, evalIdentical429(mergeFP(res), tooManyBrandingResponse.body, res.total429())...)
	f = append(f, evalContent(res, allowed, statuses)...)
	var sampled []string
	for n, s := range res.States {
		if s.Sampled > 0 {
			sampled = append(sampled, n)
		}
	}
	f = append(f, evalAdmittedLatency(res, DefaultBrandingFloor, sampled...)...)
	if ph.CheckStable {
		f = append(f, evalStable(res.Windows)...)
	}
	if ph.MaxAdmitted > 0 {
		if adm := res.Completed - res.total429(); adm > ph.MaxAdmitted {
			f = append(f, fmt.Sprintf("%d requests admitted, above the %d the per-address rate budget allows", adm, ph.MaxAdmitted))
		}
		if res.total429() == 0 {
			f = append(f, "no 429 at all in a run that offers far more than the caps and the rate budget allow")
		}
	}
	f = append(f, evalResources(m, headroom)...)
	f = append(f, notIdle...)
	if cuts != 0 {
		f = append(f, fmt.Sprintf("%d lookup(s) were cut at the work deadline under load (BrandingCutoffTotal must stay 0)", cuts))
	}

	rec := newGateLoadRecord(t, ph.Name, res, plan.Rate)
	rec.Overloaded, rec.Cutoffs, rec.Metrics, rec.Failures = overloadAsked, cuts, &m, append([]string{}, f...)
	rec.Peaks = m.Admission
	if ph.Hostile != nil {
		rec.Hostile = &hres
	}
	if scale < 1 && !overloadAsked {
		rec.Notes = append(rec.Notes, fmt.Sprintf("scale %.2f: the offered rate is below %.0fx the admitted ceiling, so the global cap is not required to be reached by this phase (the deterministic 429 cases reach it at any scale)", scale, gateOverloadFactor))
	}
	if fl != nil {
		rec.Notes = append(rec.Notes, fl.Note())
		if fl.Void {
			rec.Failures = append(rec.Failures, "VOID: "+fl.Note())
			writeGateJSON(t, t.Name(), rec)
			t.Fatalf("release gate VOID: %s", fl.Note())
		}
	}
	writeGateJSON(t, t.Name(), rec)
	t.Logf("%s: offered %.0f/s (asked %.0f), completed %d, 429 %d (%d byte string(s)), windows %v, failures %d", ph.Name, res.offeredPerSec(), plan.Rate, res.Completed, res.total429(), len(res.FP), res.Windows, len(f))
	return res, f
}

func TestReleaseGateBrandingLoad(t *testing.T) {
	requireGateDB(t)
	// 1. The overload: about 5x the admitted ceiling from 6,000 distinct client addresses.
	t.Run("overload", func(t *testing.T) {
		e := newGateBrandEnv(t, gateEnvOpts{})
		rate := gateScaledRate(t, gateBrandingOffered)
		_, f := runBrandingPhase(t, e, brandingPhase{Name: "branding-overload", Warm: true, CheckStable: true,
			Plan: loadPlan{Conns: 300, Rate: rate, DurationMS: gateScaledDuration(t, gateLoadDuration).Milliseconds(),
				IPPool: gateLoadIPPool, IPBase: 1_000_000, Seed: 1}})
		for _, x := range f {
			t.Errorf("release gate FAIL: %s", x)
		}
	})
	// 2. 50 addresses x 8 connections, all released together: the per-address cap (4) is hit by every address, the
	// global cap (128) by the 50 x 4 = 200 that want in, and the per-address rate budget (120 a minute) is spent within
	// seconds. Every cap is therefore reached at any scale.
	t.Run("per-ip", func(t *testing.T) {
		e := newGateBrandEnv(t, gateEnvOpts{})
		d := min(max(gateScaledDuration(t, 15*time.Second), 3*time.Second), 50*time.Second)
		_, f := runBrandingPhase(t, e, brandingPhase{Name: "branding-per-ip", Warm: true, Overload: true, PerKeyReached: true, MaxAdmitted: 50 * DefaultBrandingRatePerMinute,
			Plan: loadPlan{Conns: 400, ConnsPerIP: 8, Barrier: true, ThinkMS: int64(100 / gateScale(t)), DurationMS: d.Milliseconds(), IPBase: 2_000_000, Seed: 2}})
		for _, x := range f {
			t.Errorf("release gate FAIL: %s", x)
		}
	})
	// 3. The three sources of a 429, each isolated by construction, and all three must be ONE byte string.
	t.Run("429-sources", func(t *testing.T) {
		e := newGateBrandEnv(t, gateEnvOpts{})
		pool := e.srv.brandingPool()
		hdr := map[string]string{EdgeMarkerHeader: e.edge}
		item := []loadItem{{State: "default", Host: gateDefaultHost, Path: e.route("json"), Weight: 1}}
		rec := gateLoadRecord{Test: t.Name(), Scale: gateScale(t), GOOS: runtime.GOOS, NumCPU: runtime.NumCPU(), Failures: []string{}}
		var f []string
		var all []loadResult

		// 3a. The rate budget: spend an address's 120 attempts with 8 connections, wait until nothing is in flight, then
		// send 5 requests one at a time from the same address. Nothing else can refuse them (no concurrency from that
		// address, none globally), so every one is the rate budget's 429.
		burn := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 8, ConnsPerIP: 8, Barrier: true, Total: 200, IPBase: 3_000_000})
		time.Sleep(500 * time.Millisecond)
		seq := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 1, IPPool: 1, Total: 5, IPBase: 3_000_000})
		if seq.Completed != 5 || statusCount(seq, "default", 429) != 5 {
			f = append(f, fmt.Sprintf("rate budget: %d of 5 sequential requests after the budget was spent were refused (errors %v)", statusCount(seq, "default", 429), seq.Errors))
		}
		all = append(all, burn, seq)

		// 3b. The per-address cap: 8 simultaneous requests from one fresh address (8 attempts, far inside the budget).
		pool.resetPeak()
		per := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 8, ConnsPerIP: 8, Barrier: true, Total: 8, IPBase: 3_100_000})
		g, k := pool.peak()
		if k != DefaultBrandingAdmitPerIP || per.total429() < 1 {
			f = append(f, fmt.Sprintf("per-address cap: peak per-address in flight %d (want %d), %d refused of 8", k, DefaultBrandingAdmitPerIP, per.total429()))
		}
		_ = g
		all = append(all, per)

		// 3c. The global cap: 160 simultaneous requests from 160 distinct addresses.
		pool.resetPeak()
		glob := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 160, ConnsPerIP: 1, Barrier: true, Total: 160, IPBase: 3_200_000})
		g, k = pool.peak()
		if g != DefaultBrandingAdmitGlobal || glob.total429() < 1 {
			f = append(f, fmt.Sprintf("global cap: peak in flight %d (want %d), %d refused of 160", g, DefaultBrandingAdmitGlobal, glob.total429()))
		}
		all = append(all, glob)

		merged := mergeFP(all...)
		var total int64
		for _, r := range all {
			total += r.total429()
			if n := r.totalErrors(); n > 0 {
				f = append(f, fmt.Sprintf("client errors: %v", r.Errors))
			}
		}
		f = append(f, evalIdentical429(merged, tooManyBrandingResponse.body, total)...)
		rec.Total429, rec.Distinct, rec.Failures = total, len(merged), append([]string{}, f...)
		rec.Notes = []string{fmt.Sprintf("429s: rate budget %d, per-address cap %d, global cap %d", seq.total429(), per.total429(), glob.total429())}
		writeGateJSON(t, t.Name(), rec)
		t.Logf("429 sources: rate %d, per-address %d, global %d; %d distinct byte string(s)", seq.total429(), per.total429(), glob.total429(), len(merged))
		for _, x := range f {
			t.Errorf("release gate FAIL: %s", x)
		}
	})
}

// ---------------------------------------------------------------------------------------------------------
// Hostile mix.
// ---------------------------------------------------------------------------------------------------------

// gateHostilePlan is the plan's hostile mix at full scale: 200 slow header writers, 200 slow body writers, 64 slow
// readers of the logo and connection churn at 256/s (the bottom of the plan's 256-2,000/s band: each churned request
// is a complete one the server answers to nobody, holding an admission permit for about 155 ms, so 256/s uses about 40
// of the 128 permits and leaves the rest to real traffic). That is at most 200+200+64+about 80 churn + the probes: under
// 800 connections of the 1024 cap. Only the churn RATE is scaled.
func gateHostilePlan(t testing.TB, e *gateBrandEnv) hostilePlan {
	hp := hostilePlan{Addr: e.addr, Headers: map[string]string{EdgeMarkerHeader: e.edge}, Host: gateDefaultHost,
		ReadPath: e.route("logo"), BodyPath: gateRedeemPath, SlowHeaders: 200, SlowBodies: 200, SlowReaders: 64,
		ChurnRate: gateScaledRate(t, 256), IPBase: 5_000_000}
	return hp
}

// gateWithRedeemRoute gives the branding server the redeem route, which the slow body writers need (a route that reads a body).
func gateWithRedeemRoute(s *Server, shared *pgxpool.Pool) {
	s.Attended = NewPgAttendedStore(shared)
	s.MgmtAudit = NewPgMgmtAuditStore(shared)
}

func gateHostileDuration(t testing.TB) time.Duration {
	// At least 2x the 5 s header bound, so every slow connection reaches the server's cut at least once.
	return max(gateScaledDuration(t, gateLoadDuration), gateHostileMinRun+2*time.Second)
}

func TestReleaseGateHostileMix(t *testing.T) {
	requireGateDB(t)
	e := newGateBrandEnv(t, gateEnvOpts{setup: gateWithRedeemRoute})
	hp := gateHostilePlan(t, e)
	// Light real traffic beside the hostile mix: every answer must still be the right one.
	probes := loadPlan{Conns: 8, Rate: gateScaledRate(t, 40), DurationMS: gateHostileDuration(t).Milliseconds(), IPPool: 500, IPBase: 6_000_000, Seed: 3}
	res, f := runBrandingPhase(t, e, brandingPhase{Name: "hostile-mix", Plan: probes, Hostile: &hp, Warm: true})
	t.Logf("probes beside the hostile mix: %d completed, %d refused (429)", res.Completed, res.total429())
	for _, x := range f {
		t.Errorf("release gate FAIL: %s", x)
	}
	// And the server answers normally afterwards.
	if got := gateFetchJSON(t, e); len(got) == 0 {
		t.Error("release gate FAIL: no content after the hostile mix")
	}
}

// ---------------------------------------------------------------------------------------------------------
// Negative controls on the real stack: a wrong server must FAIL the load assertions.
// ---------------------------------------------------------------------------------------------------------

type gateWrapWriter struct {
	http.ResponseWriter
	onHeader func(code int, h http.Header)
	onWrite  func(p []byte) []byte
}

func (w *gateWrapWriter) WriteHeader(code int) {
	if w.onHeader != nil {
		w.onHeader(code, w.ResponseWriter.Header())
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gateWrapWriter) Write(p []byte) (int, error) {
	if w.onWrite != nil {
		p = w.onWrite(p)
	}
	return w.ResponseWriter.Write(p)
}

func (w *gateWrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func requireFailureContaining(t *testing.T, what string, f []string, want string) {
	t.Helper()
	for _, x := range f {
		if strings.Contains(x, want) {
			t.Logf("negative control %q: detected as required: %s", what, x)
			return
		}
	}
	t.Errorf("negative control %q: NOT detected: no failure contains %q among %d: %v", what, want, len(f), f)
}

func TestReleaseGateLoadNegativeControls(t *testing.T) {
	requireGateDB(t)
	perIP := func(name string) brandingPhase {
		return brandingPhase{Name: name, Overload: true, PerKeyReached: true,
			Plan: loadPlan{Conns: 400, ConnsPerIP: 8, Barrier: true, ThinkMS: 100, DurationMS: 3000, IPBase: 7_000_000, Seed: 7}}
	}
	openLoop := func(name string) brandingPhase {
		return brandingPhase{Name: name,
			Plan: loadPlan{Conns: 200, Rate: 300, DurationMS: 3000, IPPool: 600, IPBase: 7_100_000, Seed: 8}}
	}

	// Caps far above the documented 128/4: the exact watermark must exceed them, and the gate must say so.
	t.Run("caps-too-high", func(t *testing.T) {
		e := newGateBrandEnv(t, gateEnvOpts{tuning: BrandingTuning{AdmitGlobal: 400, AdmitPerIP: 16}})
		_, f := runBrandingPhase(t, e, perIP("negative-caps-too-high"))
		requireFailureContaining(t, "global cap too high", f, "above the cap 128")
		requireFailureContaining(t, "per-address cap too high", f, "above the per-address cap 4")
	})

	// One 429 in seven carries Retry-After: 2: the 429s are no longer one byte string.
	t.Run("different-429", func(t *testing.T) {
		var n atomic.Int64
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				next.ServeHTTP(&gateWrapWriter{ResponseWriter: w, onHeader: func(code int, h http.Header) {
					if code == http.StatusTooManyRequests && n.Add(1)%7 == 0 {
						h.Set("Retry-After", "2")
					}
				}}, r)
			})
		}
		e := newGateBrandEnv(t, gateEnvOpts{wrap: wrap})
		_, f := runBrandingPhase(t, e, perIP("negative-different-429"))
		requireFailureContaining(t, "429 with another Retry-After", f, "distinct 429 byte strings")
	})

	// One 429 in seven has a different BODY (same headers, same length): only a byte comparison sees it.
	t.Run("different-429-body", func(t *testing.T) {
		var n atomic.Int64
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mutate := false // per request: this response's 429 is the odd one
				next.ServeHTTP(&gateWrapWriter{ResponseWriter: w,
					onHeader: func(code int, h http.Header) { mutate = code == http.StatusTooManyRequests && n.Add(1)%7 == 0 },
					onWrite: func(p []byte) []byte {
						if mutate {
							return []byte(strings.Replace(string(p), "too many requests", "TOO MANY REQUESTS", 1))
						}
						return p
					}}, r)
			})
		}
		e := newGateBrandEnv(t, gateEnvOpts{wrap: wrap})
		_, f := runBrandingPhase(t, e, perIP("negative-different-429-body"))
		requireFailureContaining(t, "429 with another body or header", f, "distinct 429 byte strings")
	})

	// One published logo in twenty has its first byte flipped: the content check must see it.
	t.Run("corrupt-content", func(t *testing.T) {
		var n atomic.Int64
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.Contains(r.URL.Path, "/logo") {
					next.ServeHTTP(w, r)
					return
				}
				next.ServeHTTP(&gateWrapWriter{ResponseWriter: w, onWrite: func(p []byte) []byte {
					if len(p) > 1000 && n.Add(1)%20 == 0 {
						q := append([]byte(nil), p...)
						q[0] ^= 0xff
						return q
					}
					return p
				}}, r)
			})
		}
		e := newGateBrandEnv(t, gateEnvOpts{wrap: wrap})
		_, f := runBrandingPhase(t, e, openLoop("negative-corrupt-content"))
		requireFailureContaining(t, "corrupted logo", f, "does not owe")
	})

	// Every request leaves one goroutine blocked forever: the no-growth bound must see it after the load stops.
	t.Run("goroutine-leak", func(t *testing.T) {
		block := make(chan struct{})
		t.Cleanup(func() { close(block) })
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				go func() { <-block }()
				next.ServeHTTP(w, r)
			})
		}
		e := newGateBrandEnv(t, gateEnvOpts{wrap: wrap})
		_, f := runBrandingPhase(t, e, openLoop("negative-goroutine-leak"))
		requireFailureContaining(t, "leaked goroutines", f, "goroutines grew")
	})

	// Every request is stalled 2.5 s before it reaches the handler: the 2 s exchange bound is broken, which the
	// admitted-latency assertion must see.
	t.Run("slow-exchange", func(t *testing.T) {
		wrap := func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(2500 * time.Millisecond)
				next.ServeHTTP(w, r)
			})
		}
		e := newGateBrandEnv(t, gateEnvOpts{wrap: wrap})
		ph := openLoop("negative-slow-exchange")
		ph.Plan.Rate, ph.Plan.Conns, ph.Plan.DurationMS = 40, 200, 4000
		_, f := runBrandingPhase(t, e, ph)
		requireFailureContaining(t, "exchange over 2 s", f, "exchange bound")
	})
}

// ---------------------------------------------------------------------------------------------------------
// Redeem.
// ---------------------------------------------------------------------------------------------------------

func gateRedeemSrc(e *gateRedeemEnv) gateLoadSrc {
	return gateLoadSrc{shared: e.shared, lookup: e.lookup, su: e.su, admission: map[string]*admissionPool{"redeem": e.srv.redeemPool()}}
}

// gateUseStoreThrottle puts the redeem handler on the PRODUCTION throttle (cmd/controlplane/main.go: the store-backed
// throttle on the shared pool), which the timing runs of step 4 did not need: under load every admitted rejection
// costs it a few statements, on the shared pool, inside the floor.
func gateUseStoreThrottle(t *testing.T, e *gateRedeemEnv) {
	t.Helper()
	ctx := context.Background()
	var reg *string
	if err := e.su.QueryRow(ctx, `SELECT to_regclass('throttle_counter')::text`).Scan(&reg); err != nil {
		t.Fatal(err)
	}
	if reg == nil { // the fixture schema does not carry it; production does (migration 0015)
		applyMigrationFile(t, e.su, "migrations/0015_throttle.sql")
	}
	var n int
	if err := e.shared.QueryRow(ctx, `SELECT count(*) FROM throttle_counter`).Scan(&n); err != nil {
		t.Fatalf("release gate premise: the application role cannot read the throttle table: %v", err)
	}
	e.srv.Throttle = NewStoreThrottle(DefaultThrottleConfig, NewPgThrottleStore(e.shared))
	t.Cleanup(func() {
		// Fresh addresses leave one throttle row each; remove them so a later run starts clean.
		_, _ = e.su.Exec(context.Background(), `DELETE FROM throttle_counter WHERE key LIKE 'attend-redeem:ip:10.%'`)
	})
}

func gateRedeemExpected429(t *testing.T) []byte {
	t.Helper()
	rec := httptest.NewRecorder()
	writeThrottled(rec, time.Second)
	return rec.Body.Bytes()
}

type redeemPhase struct {
	Name   string
	Rate   float64
	Dur    time.Duration
	Max    time.Duration // hard cap when MinPerState extends the run
	Stats  bool          // the statistic phase: per-class samples, floors, success
	Stable bool
	Warm   bool
	// Diag: the opt-in diagnostics wrapper (DESKRALLY_GATE_DIAG=1, releasegate_diag_test.go); nil = off.
	Diag *gateDiagMW
	// Flush: as brandingPhase.Flush.
	Flush bool
}

func runRedeemPhase(t *testing.T, e *gateRedeemEnv, ph redeemPhase) []string {
	t.Helper()
	hdr := map[string]string{EdgeMarkerHeader: e.edge}
	var items []loadItem
	var classNames []string
	for _, c := range e.classes {
		items = append(items, loadItem{State: c.Name, Host: c.Host, Path: gateRedeemPath, Method: "POST", Weight: 1,
			Bodies: []string{gateRedeemBody(c.Code, attendTestPubkey)}})
		classNames = append(classNames, c.Name)
	}
	rnd := e.class("random")
	items = append(items, loadItem{State: gateRedeemTwin, Host: rnd.Host, Path: gateRedeemPath, Method: "POST", Weight: 1,
		Bodies: []string{gateRedeemBody(rnd.Code, attendTestPubkey)}})
	classNames = append(classNames, gateRedeemTwin)
	if len(e.good) > 0 {
		var bodies []string
		for _, c := range e.good {
			bodies = append(bodies, gateRedeemBody(c, randPubkeyHex(t)))
		}
		items = append(items, loadItem{State: gateRedeemSuccess, Host: gateRedeemGoodHost, Path: gateRedeemPath, Method: "POST",
			Bodies: bodies, Consume: true, Weight: 1})
	}
	plan := loadPlan{Addr: e.addr, Headers: hdr, Items: items, Conns: 256, Rate: ph.Rate, DurationMS: ph.Dur.Milliseconds(),
		IPBase: 10_000_000, Seed: 4, SampleStatuses: []int{http.StatusForbidden, http.StatusCreated}}
	if ph.Stats {
		plan.MaxDurationMS, plan.MinPerState, plan.MinStates, plan.RecordSamples = ph.Max.Milliseconds(), gateMinSamples, classNames, true
	}
	if ph.Stable {
		plan.WindowMS = gateWindowMS(ph.Dur)
	}
	e.premise(t, classNames)
	if ph.Warm {
		wp := plan
		wp.DurationMS, wp.MaxDurationMS, wp.WindowMS, wp.MinPerState, wp.RecordSamples = gateWarmupMS, gateWarmupMS, 0, 0, false
		wp.Items = nil
		for _, it := range items {
			if !it.Consume { // the warm-up never spends a single-use code
				wp.Items = append(wp.Items, it)
			}
		}
		wp.IPBase = 20_000_000
		if r := runGateLoadProcess(t, wp); r.Completed == 0 {
			t.Fatalf("release gate: the warm-up completed nothing: %v", r.Errors)
		}
	}
	var res loadResult
	var fm *gateFlushMon
	if ph.Flush {
		fm = startGateFlushMon(e.su, time.Duration(gateWindowMS(ph.Dur))*time.Millisecond)
	}
	var diag *gateDiag
	if ph.Diag != nil {
		diag = startGateDiag(t, e.su, ph.Diag, ph.Name, time.Duration(gateWindowMS(ph.Dur))*time.Millisecond)
	}
	m, headroom, notIdle := gateRedeemSrc(e).measure(func() { res = runGateLoadProcess(t, plan) })
	var fl *gateFlushResult
	if fm != nil {
		r := fm.result()
		fl = &r
		t.Log("flush: " + r.Note())
	}
	if diag != nil {
		diag.stopAndWrite()
	}
	logGateMetrics(t, m)

	var f []string
	overload := ph.Rate >= gateOverloadFactor*gateRedeemCeiling
	if n := res.totalErrors(); n > 0 {
		f = append(f, fmt.Sprintf("the client saw %d error(s): %v", n, res.Errors))
	}
	if ph.Rate > 0 && res.offeredPerSec() < 0.9*ph.Rate {
		f = append(f, fmt.Sprintf("VOID: offered %.0f req/s of the %.0f asked (%d dropped by the client)", res.offeredPerSec(), ph.Rate, res.Dropped))
	}
	f = append(f, evalCaps("redeem", m.Admission["redeem"], DefaultRedeemAdmitGlobal, DefaultRedeemAdmitPerIP, overload, false)...)
	f = append(f, evalIdentical429(mergeFP(res), gateRedeemExpected429(t), res.total429())...)
	allowed := map[string]map[string]bool{}
	statuses := map[string][]int{}
	for _, n := range classNames {
		allowed[n] = map[string]bool{"403:" + gateRedeemRejectionBody: true}
		statuses[n] = []int{http.StatusForbidden}
	}
	statuses[gateRedeemSuccess] = []int{http.StatusCreated}
	f = append(f, evalContent(res, allowed, statuses)...)
	if ph.Stable {
		f = append(f, evalStable(res.Windows)...)
	}
	f = append(f, evalResources(m, headroom)...)
	f = append(f, notIdle...)

	rec := newGateLoadRecord(t, ph.Name, res, ph.Rate)
	rec.Overloaded, rec.Metrics, rec.Peaks = overload, &m, m.Admission
	rec.Summaries, rec.MinMS, rec.MaxMS = map[string]gateSummary{}, map[string]float64{}, map[string]float64{}
	if ph.Stats {
		rej := map[string][]time.Duration{}
		fastest := time.Hour
		for _, n := range classNames {
			s := res.States[n]
			if s == nil || s.Sampled == 0 {
				f = append(f, fmt.Sprintf("%s: no admitted rejection sampled", n))
				continue
			}
			for _, ns := range s.SamplesNS {
				rej[n] = append(rej[n], time.Duration(ns))
			}
			rec.Summaries[n] = gateSummarize(rej[n])
			rec.MinMS[n], rec.MaxMS[n] = float64(s.MinNS)/1e6, float64(s.MaxNS)/1e6
			fastest = min(fastest, time.Duration(s.MinNS))
			// 2b.4 under load: no admitted rejection is released before the floor, none outlives the 2 s exchange bound.
			if time.Duration(s.MinNS) < DefaultRedeemFloor {
				f = append(f, fmt.Sprintf("%s: an admitted rejection completed after %v, before the %v floor", n, time.Duration(s.MinNS), DefaultRedeemFloor))
			}
			if time.Duration(s.MaxNS) > gateExchangeMax {
				f = append(f, fmt.Sprintf("%s: an admitted rejection took %v, beyond the %v exchange bound", n, time.Duration(s.MaxNS), gateExchangeMax))
			}
		}
		sum, pairs, err := gatePairwise(rej)
		if err != nil {
			rec.Failures = append(f, err.Error())
			writeGateJSON(t, t.Name(), rec)
			t.Fatalf("release gate: %v", err)
		}
		_ = sum
		for _, p := range pairs {
			if (p.A == "random" && p.B == gateRedeemTwin) || (p.B == "random" && p.A == gateRedeemTwin) {
				rec.Failures = append(f, "VOID: the A/A control failed: "+p.String())
				writeGateJSON(t, t.Name(), rec)
				t.Fatalf("release gate VOID: the A/A control failed under load (%s); the environment is not stable enough to measure", p)
			}
			f = append(f, "under load, classes distinguishable: "+p.String())
		}
		if ok := res.States[gateRedeemSuccess]; ok != nil && ok.Sampled > 0 {
			s := gateSummarize(durations(ok.SamplesNS))
			rec.Summaries[gateRedeemSuccess] = s
			if s.P95 >= fastest {
				f = append(f, fmt.Sprintf("success p95 %v is not below the fastest admitted rejection %v: the floor must not apply to success", s.P95, fastest))
			}
			if ok.Status[http.StatusCreated] != ok.Sampled {
				f = append(f, fmt.Sprintf("success: %d of %d admitted answers were not 201", ok.Sampled-ok.Status[http.StatusCreated], ok.Sampled))
			}
		} else {
			f = append(f, "no successful redemption was admitted: the success class was not measured")
		}
		for n, s := range rec.Summaries {
			t.Logf("%-18s n=%d median=%v p95=%v min=%.1fms max=%.1fms", n, s.N, s.Median, s.P95, rec.MinMS[n], rec.MaxMS[n])
		}
	}
	rec.Failures = append([]string{}, f...)
	if fl != nil {
		rec.Notes = append(rec.Notes, fl.Note())
		if fl.Void {
			rec.Failures = append(rec.Failures, "VOID: "+fl.Note())
			writeGateJSON(t, t.Name(), rec)
			t.Fatalf("release gate VOID: %s", fl.Note())
		}
	}
	writeGateJSON(t, t.Name(), rec)
	t.Logf("%s: offered %.0f/s (asked %.0f), completed %d, 429 %d (%d byte string(s)), exhausted %d, windows %v, failures %d",
		ph.Name, res.offeredPerSec(), ph.Rate, res.Completed, res.total429(), len(res.FP), res.Exhausted, res.Windows, len(f))
	return f
}

func durations(ns []int64) []time.Duration {
	out := make([]time.Duration, len(ns))
	for i, n := range ns {
		out[i] = time.Duration(n)
	}
	return out
}

// gateRedeemCodes: pre-minted single-use codes for the success class of the mix (not scaled: they are consumed as
// they are drawn, and an exhausted class simply leaves the mix).
const gateRedeemCodes = 3000

func TestReleaseGateRedeemLoad(t *testing.T) {
	requireGateDB(t)
	e := newGateRedeemEnv(t, gateRedeemOpts{success: gateRedeemCodes})
	gateUseStoreThrottle(t, e)
	f := runRedeemPhase(t, e, redeemPhase{Name: "redeem-load", Rate: gateScaledRate(t, gateRedeemOffered),
		Dur: gateScaledDuration(t, gateLoadDuration), Max: 100 * time.Second, Stats: true, Stable: true, Warm: true})
	f = append(f, gateRedeem429Cases(t, e)...)
	for _, x := range f {
		t.Errorf("release gate FAIL: %s", x)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Soaks.
// ---------------------------------------------------------------------------------------------------------

// The branding soak: the overload of the load test for 5 minutes, with the hostile mix beside it for all of them.
// Asserted: the caps (exact watermark), byte-identical 429s, the right content, stable throughput, the resources and
// no growth after the load stops, and the hostile connections cut within the server's own bounds.
func TestReleaseGateBrandingSoak(t *testing.T) {
	requireGateDB(t)
	e := newGateBrandEnv(t, gateEnvOpts{setup: gateWithRedeemRoute})
	hp := gateHostilePlan(t, e)
	_, f := runBrandingPhase(t, e, brandingPhase{Name: "branding-soak", Warm: true, CheckStable: true, Flush: true, Hostile: &hp,
		Plan: loadPlan{Conns: 300, Rate: gateScaledRate(t, gateBrandingOffered), DurationMS: gateScaledDuration(t, gateSoakDuration).Milliseconds(),
			IPPool: gateLoadIPPool, IPBase: 1_000_000, Seed: 5}})
	for _, x := range f {
		t.Errorf("release gate FAIL: %s", x)
	}
}

// The redeem soak: the rejection classes (no single-use codes: 5 minutes of them would need 100,000) at 2,000 req/s
// for 5 minutes, a fresh address per request, on the production throttle.
func TestReleaseGateRedeemSoak(t *testing.T) {
	requireGateDB(t)
	opts := gateRedeemOpts{}
	var diagMW *gateDiagMW
	if gateDiagOn() {
		diagMW = newGateDiagMW()
		opts.wrap = diagMW.wrap
		gateDiagTracer = gateDiagQTracer{diagMW}
		t.Cleanup(func() { gateDiagTracer = nil })
		opts.wrapStore = func(s AttendedStore) AttendedStore { return gateDiagAttended{s, diagMW} }
	}
	e := newGateRedeemEnv(t, opts)
	if diagMW != nil && e.srv.Machines != nil {
		e.srv.Machines = gateDiagMachines{e.srv.Machines, diagMW}
	}
	gateUseStoreThrottle(t, e)
	f := runRedeemPhase(t, e, redeemPhase{Name: "redeem-soak", Rate: gateScaledRate(t, gateRedeemOffered),
		Dur: gateScaledDuration(t, gateSoakDuration), Stable: true, Warm: true, Flush: true, Diag: diagMW})
	for _, x := range f {
		t.Errorf("release gate FAIL: %s", x)
	}
}

// gateRedeem429Cases reaches the redeem caps deterministically, at any scale: 8 simultaneous requests from one address
// (per-address cap 4) and 100 simultaneous requests from 100 addresses (global cap 64). Their 429s must be the one
// byte string the handler defines.
func gateRedeem429Cases(t *testing.T, e *gateRedeemEnv) []string {
	t.Helper()
	pool := e.srv.redeemPool()
	hdr := map[string]string{EdgeMarkerHeader: e.edge}
	c := e.class("random")
	item := []loadItem{{State: "random", Host: c.Host, Path: gateRedeemPath, Method: "POST", Weight: 1, Bodies: []string{gateRedeemBody(c.Code, attendTestPubkey)}}}
	var f []string
	pool.resetPeak()
	per := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 8, ConnsPerIP: 8, Barrier: true, Total: 8, IPBase: 30_000_000})
	if _, k := pool.peak(); k != DefaultRedeemAdmitPerIP || per.total429() < 1 {
		f = append(f, fmt.Sprintf("redeem per-address cap: peak per-address in flight %d (want %d), %d refused of 8", k, DefaultRedeemAdmitPerIP, per.total429()))
	}
	pool.resetPeak()
	glob := runGateLoadProcess(t, loadPlan{Addr: e.addr, Headers: hdr, Items: item, Conns: 100, ConnsPerIP: 1, Barrier: true, Total: 100, IPBase: 31_000_000})
	if g, _ := pool.peak(); g != DefaultRedeemAdmitGlobal || glob.total429() < 1 {
		f = append(f, fmt.Sprintf("redeem global cap: peak in flight %d (want %d), %d refused of 100", g, DefaultRedeemAdmitGlobal, glob.total429()))
	}
	total := per.total429() + glob.total429()
	f = append(f, evalIdentical429(mergeFP(per, glob), gateRedeemExpected429(t), total)...)
	for _, r := range []loadResult{per, glob} {
		if r.totalErrors() > 0 {
			f = append(f, fmt.Sprintf("client errors: %v", r.Errors))
		}
	}
	writeGateJSON(t, t.Name()+"_429-sources", gateLoadRecord{Test: t.Name() + "/429-sources", Scale: gateScale(t), GOOS: runtime.GOOS, NumCPU: runtime.NumCPU(),
		Total429: total, Distinct: len(mergeFP(per, glob)), Failures: append([]string{}, f...),
		Notes: []string{fmt.Sprintf("429s: per-address cap %d of 8, global cap %d of 100", per.total429(), glob.total429())}})
	return f
}
