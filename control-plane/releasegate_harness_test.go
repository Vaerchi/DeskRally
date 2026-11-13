//go:build releasegate

package controlplane

// The docs/66 release gate's harness (plan step 2): the real Server.Handler() on production-shaped Postgres pools
// as rmt_app, served by NewPublicServer + LimitListener on a real loopback listener, behind the edge marker and
// CP_TRUSTED_PROXIES exactly as production runs it, with every branding state seeded through the real stores. The
// timing client is a separate process (releasegate_client_test.go).
//
// Behind the releasegate build tag, so the ordinary suites never compile these tests and no skip is ever printed.
// Under the tag nothing is optional: a missing database is a FAILURE (the no-skip rule).
//
//	go test -tags releasegate -run TestReleaseGate -count=1 -timeout 60m .
//
// GATE_SAMPLES raises the per-state sample count (never below gateMinSamples); GATE_SEED changes the interleaving;
// DESKRALLY_GATE_OUT names a directory for the JSON record.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	gateDefaultHost = "main.gate.test"
	gateWarmup      = 500
	gateAATwin      = "default-aa"
	gateBetweenPath = "/__gate/between"
)

type gateState struct {
	Name, Host string
	Published  bool
	// Fault: seeded as published, but its lookups are routed to a failing store (releasegate_dbfail_test.go), so the
	// response it owes is the neutral one.
	Fault bool
}

// gateEnvOpts: wrap sits between the mux and the handler (the negative control); faults are extra states seeded as
// published for the database-failure run.
type gateEnvOpts struct {
	wrap   func(http.Handler) http.Handler
	faults []gateState
}

type gateBrandEnv struct {
	addr    string
	edge    string
	srv     *Server
	states  []gateState
	logo    []byte
	logoSHA string
	lookup  *pgxpool.Pool
	su      *pgxpool.Pool // the fixture's superuser pool (fault installation only)
	// excusedCuts, when set, counts the cuts a deliberate fault caused on a route (the database-failure run's timeout
	// state): the warm-path rule is then "every cut is one of those", never "cuts are fine".
	excusedCuts func(route string) int64
}

func requireGateDB(t *testing.T) {
	t.Helper()
	if testDBURL() == "" {
		t.Fatal("release gate: TEST_DATABASE_URL is not set; the gate runs against real Postgres and never skips")
	}
}

// gateProdPools builds the shared and lookup pools exactly as cmd/controlplane/main.go does (MaxConns 16, a 1 s
// connect timeout, statement_timeout 10 s; the lookup pool from LookupPoolConfig, the very function main.go calls), as
// the application role.
func gateProdPools(t *testing.T) (shared, lookup *pgxpool.Pool) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User = "rmt_app"
	cfg.ConnConfig.Password = ""
	cfg.MaxConns = 16
	cfg.ConnConfig.ConnectTimeout = time.Second
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["statement_timeout"] = "10000"
	lcfg := LookupPoolConfig(cfg, DefaultLookupPoolConns)
	ctx := context.Background()
	if shared, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(shared.Close)
	if lookup, err = pgxpool.NewWithConfig(ctx, lcfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lookup.Close)
	for _, p := range []*pgxpool.Pool{shared, lookup} {
		if err := p.Ping(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return shared, lookup
}

// gateMaxLogo returns the largest converted logo the harness can make that the store accepts: incompressible
// noise, so the published logo route carries close to MaxLogoBytes over the wire.
func gateMaxLogo(t *testing.T) []byte {
	t.Helper()
	r := mrand.New(mrand.NewPCG(66, 2))
	for side := 220; side > 16; side -= 4 {
		img := image.NewNRGBA(image.Rect(0, 0, side, side))
		for i := range img.Pix {
			img.Pix[i] = uint8(r.UintN(256))
		}
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 255
		}
		var b bytes.Buffer
		if err := png.Encode(&b, img); err != nil {
			t.Fatal(err)
		}
		if b.Len() > LogoMaxInputBytes {
			continue
		}
		out, err := ConvertLogo(b.Bytes())
		if err == nil && len(out) <= MaxLogoBytes {
			return out
		}
	}
	t.Fatal("release gate: could not build a near-maximum logo")
	return nil
}

// newGateBrandEnv seeds one host per branding state through the real stores, then serves the real handler (see
// gateEnvOpts).
func newGateBrandEnv(t *testing.T, opts gateEnvOpts) *gateBrandEnv {
	t.Helper()
	requireGateDB(t)
	fx := newPgBrandFx(t)
	ctx := context.Background()
	e := &gateBrandEnv{logo: gateMaxLogo(t)}
	e.logoSHA = logoSHA(e.logo)

	// published: active host, approved revision with the near-maximum logo.
	pub := fx.tenant("gpub")
	asg := fx.activeHost(t, pub, "published.gate.test")
	in := brandInput("Gate Published")
	in.LogoPNG = e.logo
	rev, _, err := fx.brand.CreateRevision(ctx, pub, "owner-"+pub, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fx.approve(pub, rev, asg.ID); err != nil {
		t.Fatalf("approve published: %v", err)
	}
	// pending: assigned, never activated, with a draft.
	pend := fx.tenant("gpend")
	fx.mustAssignHost(t, pend, "pending.gate.test")
	fx.draft(t, pend, "Gate Pending")
	// unapproved: active host, draft never approved.
	unap := fx.tenant("gunap")
	fx.activeHost(t, unap, "unapproved.gate.test")
	fx.draft(t, unap, "Gate Unapproved")
	// disabled: published exactly like the first, then the tenant is suspended.
	dis := fx.tenant("gdis")
	dasg := fx.activeHost(t, dis, "disabled.gate.test")
	drev := fx.draft(t, dis, "Gate Disabled")
	if _, err := fx.approve(dis, drev, dasg.ID); err != nil {
		t.Fatalf("approve disabled: %v", err)
	}
	fx.suspend(dis, true)
	// Fault states: published exactly like "published" (without the logo), so a healthy store would brand them.
	for _, f := range opts.faults {
		ft := fx.tenant(strings.ReplaceAll(f.Name, "-", ""))
		fasg := fx.activeHost(t, ft, f.Host)
		frev := fx.draft(t, ft, "Gate "+f.Name)
		if _, err := fx.approve(ft, frev, fasg.ID); err != nil {
			t.Fatalf("approve %s: %v", f.Name, err)
		}
	}
	e.su = fx.h.pf.su

	e.states = []gateState{
		{Name: "published", Host: "published.gate.test", Published: true},
		{Name: "default", Host: gateDefaultHost},
		// The A/A control: the same host as a second state. If the two ever differ the environment, not the code, is
		// what the run measured, and the run is VOID (plan: never re-run until the environment is fixed).
		{Name: gateAATwin, Host: gateDefaultHost},
		{Name: "unmapped", Host: "unmapped.gate.test"},
		{Name: "pending", Host: "pending.gate.test"},
		{Name: "unapproved", Host: "unapproved.gate.test"},
		{Name: "disabled", Host: "disabled.gate.test"},
	}
	e.states = append(e.states, opts.faults...)
	// The premise of every state, read straight from the store: only the published host (and the fault hosts) have a row.
	for _, s := range e.states {
		if got := fx.public(t, s.Host, false); (got != nil) != (s.Published || s.Fault) {
			t.Fatalf("release gate seeding: state %s (%s) published=%v, want %v", s.Name, s.Host, got != nil, s.Published || s.Fault)
		}
	}

	shared, lookup := gateProdPools(t)
	e.lookup = lookup
	brand := NewPgBrandingRevisionStore(shared, NewPgMgmtAuditStore(shared))
	brand.LookupPool = lookup

	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	e.edge = hex.EncodeToString(secret)
	authorities := []string{}
	for _, s := range e.states {
		authorities = append(authorities, s.Host)
	}
	policy, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{gateDefaultHost}, PublicAuthorities: authorities,
		EdgeSecret: e.edge, Theming: true})
	if err != nil {
		t.Fatal(err)
	}
	// Production tuning: the zero BrandingTuning is the shipped defaults (150 ms floor, 120/min, 128/4 admission).
	e.srv = &Server{HostPolicy: policy, BrandingRevisions: brand}
	nets, err := ParseTrustedProxies("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetTrustedProxies(nets) // process globals: reset below so a later test in this binary starts clean
	t.Cleanup(func() { SetTrustedProxyNets(nil); SetTrustProxyForClientIP(false) })

	mux := http.NewServeMux() // as main.go builds it
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	// Test-only, on the test mux (never in the Server): the cold path's state between bursts. Production after an idle
	// spell keeps MinConns open and nothing else, so: close every lookup connection, then dial exactly MinConns.
	mux.HandleFunc(gateBetweenPath, func(w http.ResponseWriter, r *http.Request) {
		e.lookup.Reset()
		// Re-dialling is set-up, not measurement, so a slow backend start (the pool's 1 s connect timeout, Postgres on
		// Windows) is retried; every failure is logged. All MinConns are held at once, so each is a separate connection.
		var held []*pgxpool.Conn
		defer func() {
			for _, c := range held {
				c.Release()
			}
		}()
		want := int(e.lookup.Config().MinConns)
		var err error
		for attempt := 1; attempt <= 5 && len(held) < want; attempt++ {
			for len(held) < want {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				c, aerr := e.lookup.Acquire(ctx)
				cancel()
				if aerr != nil {
					err = aerr
					t.Logf("cold path: re-dialling the idle lookup connections (%d of %d), attempt %d: %v", len(held), want, attempt, err)
					break
				}
				held = append(held, c)
			}
		}
		if len(held) == want {
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	})
	var h http.Handler = e.srv.Handler()
	if opts.wrap != nil {
		h = opts.wrap(h)
	}
	mux.Handle("/", h)
	hs := NewPublicServer("127.0.0.1:0", mux, PublicServerConfig{})
	ln, err := net.Listen("tcp", hs.Addr)
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	go func() { _ = hs.Serve(LimitListener(ln, DefaultMaxConns)) }()
	t.Cleanup(func() { _ = hs.Close() })
	return e
}

func (e *gateBrandEnv) route(name string) string {
	if name == "logo" {
		return "/public/branding/logo?rev=" + e.logoSHA
	}
	return "/public/branding"
}

// gateXFF is a fresh synthetic client address per request (10.x.y.z), so neither the 120/min rate budget nor the
// per-IP admission cap ever answers a measured request: the only way to a 429 is a real admission fault.
func gateXFF(i int) string {
	n := i + 1
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255)
}

// gateBag is the interleaved scheduler: gateWarmup discarded requests, then n per (state, route) in one shuffled
// order, so drift over the run hits every state equally. cold: n bursts instead, each one request per (state, route)
// in its own shuffled order (the client runs each burst after the pool has been returned to its idle state).
func gateBag(e *gateBrandEnv, routes []string, n int, seed uint64, cold bool) []gateReq {
	var reqs []gateReq
	r := mrand.New(mrand.NewPCG(seed, 0x66))
	for i := 0; i < gateWarmup; i++ {
		s, rt := e.states[r.IntN(len(e.states))], routes[r.IntN(len(routes))]
		reqs = append(reqs, gateReq{State: "warmup", Host: s.Host, Path: e.route(rt)})
	}
	var one []gateReq
	for _, s := range e.states {
		for _, rt := range routes {
			one = append(one, gateReq{State: rt + "/" + s.Name, Host: s.Host, Path: e.route(rt)})
		}
	}
	var bag []gateReq
	if cold {
		for i := 0; i < n; i++ {
			burst := append([]gateReq(nil), one...)
			r.Shuffle(len(burst), func(i, j int) { burst[i], burst[j] = burst[j], burst[i] })
			bag = append(bag, burst...)
		}
	} else {
		for i := 0; i < n; i++ {
			bag = append(bag, one...)
		}
		r.Shuffle(len(bag), func(i, j int) { bag[i], bag[j] = bag[j], bag[i] })
	}
	reqs = append(reqs, bag...)
	for i := range reqs {
		reqs[i].XFF = gateXFF(i)
	}
	return reqs
}

func gateEnvInt(t *testing.T, name string, def int) int {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < def {
		t.Fatalf("release gate: %s=%q must be an integer >= %d", name, v, def)
	}
	return n
}

type gateRecord struct {
	Test      string                 `json:"test"`
	Seed      uint64                 `json:"seed"`
	Workers   int                    `json:"workers"`
	PerState  int                    `json:"per_state"`
	GOOS      string                 `json:"goos"`
	NumCPU    int                    `json:"num_cpu"`
	LogoBytes int                    `json:"logo_bytes"`
	Summaries map[string]gateSummary `json:"summaries"`
	// Lookups cut at the work deadline during the warm-up pass (the pool growing); recorded, not gated.
	WarmupCutoffs map[string]int64 `json:"warmup_cutoffs,omitempty"`
	// Lookups cut in the measured pass (gated at zero on the warm path, recorded on the cold path), and on the cold
	// path how often the published state answered neutral because its lookup was cut.
	MeasuredCutoffs      map[string]int64 `json:"measured_cutoffs,omitempty"`
	ColdNeutralPublished map[string]int   `json:"cold_neutral_published,omitempty"`
	Failures             []string         `json:"failures"`
}

func writeGateRecord(t *testing.T, rec gateRecord) {
	t.Helper()
	dir := os.Getenv("DESKRALLY_GATE_OUT")
	if dir == "" {
		dir = t.TempDir()
	}
	b, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, rec.Test+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("release gate record: %s", p)
}

// 2c.3, warm path: every branding state on both routes, at production defaults, after a warm-up. Every sample
// must be a 200 carrying exactly the content its state owes (the published body only for the published host, the
// neutral body for every other), no sample may complete before the 150 ms floor, no lookup may be cut, and every
// pair of states must pass the strict statistic.
func TestReleaseGateBrandingWarm(t *testing.T) {
	for _, f := range runGateBrandingWarm(t, newGateBrandEnv(t, gateEnvOpts{}), 16) {
		t.Errorf("release gate FAIL: %s", f)
	}
}

// 2c.3, concurrent path: the same run with 64 requests in flight (half the 128 admission cap), so the lookup pool (8)
// serves several lookups per connection while every request still waits out its floor. No lookup may be cut.
func TestReleaseGateBrandingConcurrent(t *testing.T) {
	for _, f := range runGateBrandingWarm(t, newGateBrandEnv(t, gateEnvOpts{}), 64) {
		t.Errorf("release gate FAIL: %s", f)
	}
}

// 2c.3, cold path: 2,000 bursts. Before each, the lookup pool is closed and one connection dialled, which is
// production after an idle spell (MinConns 1). Then one request per (state, route) are all in flight at once, so most
// lookups wait on a dial. The statistic must hold. Cut lookups, and the published state answering neutral because of
// them, are the designed degradation (2d.1): recorded in the JSON record, never refused.
func TestReleaseGateBrandingCold(t *testing.T) {
	for _, f := range runGateBranding(t, newGateBrandEnv(t, gateEnvOpts{}), 0, true) {
		t.Errorf("release gate FAIL: %s", f)
	}
}

// The negative control: the same run with ONE state slowed by 6 ms outside the handler (where the floor cannot absorb
// it) must fail exactly the pairs that involve that state, on both routes, and no other pair. A gate that passes this
// shift would pass a real one.
func TestReleaseGateBrandingWarmDetectsAShiftedState(t *testing.T) {
	const slow = "unmapped.gate.test"
	shift := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == slow {
				time.Sleep(6 * time.Millisecond)
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newGateBrandEnv(t, gateEnvOpts{wrap: shift})
	others := len(e.states) - 1
	fails := runGateBrandingWarm(t, e, 16)
	byRoute := map[string]int{}
	for _, f := range fails {
		if !strings.HasSuffix(f.A, "/unmapped") && !strings.HasSuffix(f.B, "/unmapped") {
			t.Errorf("negative control: a pair without the shifted state failed: %s", f)
		}
		byRoute[f.A[:strings.IndexByte(f.A, '/')]]++
	}
	// Every pair with the shifted state must fail, on both routes (it has len(states)-1 partners per route).
	for _, rt := range []string{"json", "logo"} {
		if byRoute[rt] != others {
			t.Errorf("negative control: %d failing %s pair(s), want %d (every pair with the shifted state): %v", byRoute[rt], rt, others, fails)
		}
	}
}

// runGateBrandingWarm runs the warm (or concurrent) path and returns the pairs that failed the statistic. A void run (an
// invalid sample, a cut lookup, too few samples, a failed A/A control) fails the test itself.
func runGateBrandingWarm(t *testing.T, e *gateBrandEnv, workers int) []gatePairFailure {
	t.Helper()
	return runGateBranding(t, e, workers, false)
}

// runGateBranding is the warm path (cold=false) or the cold path (cold=true: every (state, route) once per burst, all
// in flight together, with the lookup pool returned to its idle state, one open connection, before each burst). On the
// cold path a lookup may be cut while connections are dialled; the published state may then answer neutral, which is
// the designed degradation (2d.1). Those answers are counted and recorded, not refused, and the timing statistic
// applies to every sample all the same.
func runGateBranding(t *testing.T, e *gateBrandEnv, workers int, cold bool) []gatePairFailure {
	t.Helper()
	routes := []string{"json", "logo"}
	n := gateEnvInt(t, "GATE_SAMPLES", gateMinSamples)
	seed := uint64(gateEnvInt(t, "GATE_SEED", 1))
	reqs := gateBag(e, routes, n, seed, cold)
	burst := len(e.states) * len(routes)
	if cold {
		workers = burst
	}
	hdr := map[string]string{EdgeMarkerHeader: e.edge}
	// The warm-up is its own client pass, so the cutoff counters can be read at the boundary: the lookup pool grows from
	// MinConns to its size during the warm-up, and a lookup that waits on a new connection's dial may be cut there.
	// That is the cold path (plan step 3); the warm path is what follows, and there no lookup may be cut.
	res := runGateClientProcess(t, gatePlan{Addr: e.addr, Workers: workers, Headers: hdr, Requests: reqs[:gateWarmup]})
	warmupCuts, warmupExcused := map[string]int64{}, map[string]int64{}
	for _, rt := range routes {
		warmupCuts[rt] = e.srv.BrandingCutoffTotal(rt)
		if e.excusedCuts != nil {
			warmupExcused[rt] = e.excusedCuts(rt)
		}
	}
	measured := gatePlan{Addr: e.addr, Workers: workers, Headers: hdr, Requests: reqs[gateWarmup:]}
	if cold {
		measured.Batch, measured.Between = burst, gateBetweenPath
		if _, err := e.lookup.Exec(context.Background(), "SELECT 1"); err != nil { // fail fast on a broken pool
			t.Fatal(err)
		}
	}
	samp := startGatePoolSampler(e.lookup)
	res = append(res, runGateClientProcess(t, measured)...)
	poolTrace := samp.stop()

	neutral := sha256Hex(neutralBrandingResponse.body)
	wantBody := map[string]string{"logo/published": sha256Hex(e.logo)}
	published := map[string]bool{}
	for _, s := range e.states {
		for _, rt := range routes {
			published[rt+"/"+s.Name] = s.Published
		}
	}
	samples := map[string][]time.Duration{}
	coldNeutral := map[string]int{} // the published state answered neutral (a cut lookup), cold path only
	var bad []string
	for i, r := range res {
		q := reqs[i]
		if r.Err != "" || r.Status != http.StatusOK {
			bad = append(bad, fmt.Sprintf("#%d %s %s: status %d err %q", i, q.State, q.Host, r.Status, r.Err))
			continue
		}
		if q.State == "warmup" {
			continue
		}
		if cold && published[q.State] && r.Body == neutral {
			coldNeutral[q.State]++
		} else if want, pinned := wantBody[q.State]; (pinned && r.Body != want) || (!pinned && published[q.State] && r.Body == neutral) ||
			(!published[q.State] && r.Body != neutral) {
			bad = append(bad, fmt.Sprintf("#%d %s: body %s (%d bytes) is not the content this state owes", i, q.State, r.Body[:12], r.Len))
			continue
		}
		d := time.Duration(r.Nanos)
		if d < DefaultBrandingFloor {
			bad = append(bad, fmt.Sprintf("#%d %s: complete after %v, before the %v floor", i, q.State, d, DefaultBrandingFloor))
		}
		samples[q.State] = append(samples[q.State], d)
	}
	if len(bad) > 0 {
		if len(bad) > 20 {
			bad = append(bad[:20], fmt.Sprintf("... and %d more", len(bad)-20))
		}
		t.Logf("lookup pool while measuring (50 ms samples, changes only):\n%s", poolTrace)
		t.Fatalf("release gate: %d invalid sample(s); the run is void:\n  %s", len(bad), joinLines(bad))
	}
	measuredCuts := map[string]int64{}
	for _, rt := range routes {
		measuredCuts[rt] = e.srv.BrandingCutoffTotal(rt) - warmupCuts[rt]
		var excused int64
		if e.excusedCuts != nil {
			excused = e.excusedCuts(rt) - warmupExcused[rt]
			t.Logf("%s: %d cut(s), %d of them caused by a deliberate fault", rt, measuredCuts[rt], excused)
		}
		if c := measuredCuts[rt] - excused; c != 0 && !cold {
			t.Errorf("release gate: %d %s lookup(s) cut at the work deadline on the warm path", c, rt)
			t.Logf("lookup pool while measuring (50 ms samples, abnormal ticks only):\n%s", poolTrace)
		}
	}
	if cold {
		t.Logf("cold path (recorded, not gated): cut lookups %v; published state answered neutral %v", measuredCuts, coldNeutral)
	}

	rec := gateRecord{Test: t.Name(), Seed: seed, Workers: workers, PerState: n, GOOS: runtime.GOOS,
		NumCPU: runtime.NumCPU(), LogoBytes: len(e.logo), Summaries: map[string]gateSummary{}, WarmupCutoffs: warmupCuts,
		MeasuredCutoffs: measuredCuts, ColdNeutralPublished: coldNeutral}
	t.Logf("warm-up cutoffs (recorded, not gated): %v", warmupCuts)
	var all []gatePairFailure
	for _, rt := range routes {
		route := map[string][]time.Duration{}
		for k, v := range samples {
			if len(k) > len(rt) && k[:len(rt)+1] == rt+"/" {
				route[k] = v
			}
		}
		sum, fails, err := gatePairwise(route)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range fails {
			if (f.A == rt+"/default" && f.B == rt+"/"+gateAATwin) || (f.B == rt+"/default" && f.A == rt+"/"+gateAATwin) {
				writeGateRecord(t, rec)
				t.Fatalf("release gate VOID: the A/A control failed (%s); the environment is not stable enough to measure", f)
			}
		}
		names := make([]string, 0, len(sum))
		for k := range sum {
			names = append(names, k)
			rec.Summaries[k] = sum[k]
		}
		sort.Strings(names)
		for _, k := range names {
			t.Logf("%-18s n=%d median=%v p95=%v", k, sum[k].N, sum[k].Median, sum[k].P95)
		}
		for _, f := range fails {
			rec.Failures = append(rec.Failures, f.String())
		}
		all = append(all, fails...)
	}
	writeGateRecord(t, rec)
	return all
}

// gatePoolSampler records the lookup pool's state every 50 ms while a pass runs, so a void run shows WHY lookups were cut
// (connections being re-dialled, every connection busy, an acquire waiting on a dial). Diagnosis only: it decides nothing.
type gatePoolSampler struct {
	done  chan struct{}
	lines chan string
}

func startGatePoolSampler(p *pgxpool.Pool) *gatePoolSampler {
	s := &gatePoolSampler{done: make(chan struct{}), lines: make(chan string, 1)}
	go func() {
		var b strings.Builder
		start := time.Now()
		prev := p.Stat()
		max := p.Config().MaxConns
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			st := p.Stat()
			// Only the abnormal ticks: a connection missing or being dialled, an acquire cancelled, or acquirers that waited
			// 20 ms or more in total during this tick (the counters are cumulative, so the tick's share is a difference).
			wait := st.AcquireDuration() - prev.AcquireDuration()
			if st.TotalConns() < max || st.ConstructingConns() > 0 || st.CanceledAcquireCount() > prev.CanceledAcquireCount() || wait >= 20*time.Millisecond {
				fmt.Fprintf(&b, "  +%6.2fs total=%d idle=%d acquired=%d constructing=%d new_conns=%d tick: waits=%d wait=%v canceled=%d\n",
					time.Since(start).Seconds(), st.TotalConns(), st.IdleConns(), st.AcquiredConns(), st.ConstructingConns(), st.NewConnsCount(),
					st.EmptyAcquireCount()-prev.EmptyAcquireCount(), wait.Round(time.Millisecond), st.CanceledAcquireCount()-prev.CanceledAcquireCount())
			}
			prev = st
			select {
			case <-s.done:
				s.lines <- b.String()
				return
			case <-tick.C:
			}
		}
	}()
	return s
}

func (s *gatePoolSampler) stop() string { close(s.done); return <-s.lines }
