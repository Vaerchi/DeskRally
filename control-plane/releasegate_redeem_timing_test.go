//go:build releasegate

package controlplane

// The docs/66 release gate, plan step 4: REDEEM class timing and the rejection-floor bounds (docs 2a.5, 2b.4, 2b.5),
// through the real handler on production-shaped Postgres pools as rmt_app, behind NewPublicServer + LimitListener, the
// edge marker and CP_TRUSTED_PROXIES, driven by the separate-process timing client.
//
// What the doc requires, and what this file asserts at production defaults (floor 60 ms, jitter 0-20 ms, work
// deadline 250 ms, 20 ms lock wait (0081); RedeemTuning{} is the shipped tuning):
//
//   - every rejected class is indistinguishable: >= 2,000 samples per class, one interleaved shuffled bag, the strict
//     statistic of releasegate_stat_test.go (|d median| < 5 ms AND |d p95| < 15 ms, no tolerance knob) on EVERY pair.
//     The doc names the 2c.3 statistic for the redeem classes only as "the checked-in threshold"; the plan (item 7)
//     adopts the same 5/15 ms pair rule, which is what is asserted. Classes: missing, expired, spent, foreign tenant,
//     host pending, host released, tenant suspended, unknown host, and the concurrent loser that did NOT get the row
//     lock within 20 ms (a real superuser transaction holds FOR UPDATE on the code's row, so the real 55P03 fires);
//   - the floor (2b.4): no rejection completes before DefaultRedeemFloor (the client clock starts before the server's
//     admission, so a sample under the floor is a floor violation, no allowance); floor + jitter is at most 100 ms
//     (p99 <= 100 ms), no sample is later than floor + jitter + a stated scheduling slack, and the 0-20 ms jitter is
//     present (a fixed floor is itself a timing signature);
//   - success is NOT floored (2a.5, 2b.4): every success is a 201 and the success p95 is under the fastest rejection;
//   - the A/A control: the same class twice; if the twins differ the run is VOID (the environment, not the code);
//   - negative controls: an HTTP-level 20 ms shift of one class, and a lookup slower than the floor (store decorator),
//     must each fail exactly the pairs of that class; a floor-less server must fail the floor check; a lookup that is
//     slower than the cap but under the floor must NOT be visible (the floor absorbing it is the design).
//
//	go test -tags releasegate -run TestReleaseGateRedeem -count=1 -timeout 60m .

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	gateRedeemPath     = "/attended-sessions/redeem"
	gateRedeemLockHost = "lock.example.test"
	gateRedeemGoodHost = "good.example.test"
	gateRedeemTwin     = "random-aa"
	gateRedeemSuccess  = "success"
	gateRedeemLock     = "lock-timeout"
	// A sample later than floor + jitter + this is an outlier the gate refuses. It is a harness allowance for loopback
	// and scheduler noise, not a doc number (the doc's bound is floor + jitter <= 100 ms, asserted on p99).
	gateRedeemSlack = 60 * time.Millisecond
	// The doc's bound on floor + jitter (2b.4), asserted as the p99 of every rejection class.
	gateRedeemTotalMax = 100 * time.Millisecond
)

var gateRedeemRejectionBody = sha256Hex([]byte(`{"error":"invalid attended code"}` + "\n"))

type gateRedeemClass struct{ Name, Host, Code string }

type gateRedeemOpts struct {
	wrap      func(http.Handler) http.Handler   // between the mux and the handler (HTTP-level shift)
	wrapStore func(AttendedStore) AttendedStore // between the handler and the store (lookup shift)
	tuning    RedeemTuning                      // zero = the shipped defaults
	success   int                               // valid codes to pre-mint (single use)
}

type gateRedeemEnv struct {
	addr, edge     string
	srv            *Server
	attended       *PgAttendedStore
	classes        []gateRedeemClass // rejection classes, including the lock-timeout class
	good           []string          // pre-minted valid codes for the success class
	lockCode       string
	lockSID        string
	release        func()        // ends the holder's transaction (rollback), idempotent
	shared, lookup *pgxpool.Pool // the production-shaped pools, for the load gate's samplers
	su             *pgxpool.Pool // the fixture's superuser pool
}

// newGateRedeemEnv builds every rejection class through the fixtures the unit suite uses (buildRedeemClasses), adds the
// lock-timeout class and the pre-minted success codes, then serves the real handler.
func newGateRedeemEnv(t *testing.T, opts gateRedeemOpts) *gateRedeemEnv {
	t.Helper()
	requireGateDB(t)
	fx := newPgHostFx(t)
	ctx := context.Background()
	base, _ := buildRedeemClasses(t, fx.hostContractFx)
	e := &gateRedeemEnv{}
	// The two classes that buildRedeemClasses adds for the in-process unit suite (a host with a port, an IP-literal host)
	// never reach the redeem handler through the public ingress: the authority gate answers them 421 first. They are
	// not redeem classes here.
	for _, c := range base {
		if c.name == "refused-authority" || c.name == "ip-literal-host" {
			continue
		}
		e.classes = append(e.classes, gateRedeemClass{c.name, c.host, c.code})
	}
	active := func(tenant, host string) {
		a := fx.mustAssign(t, tenant, host)
		if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); err != nil {
			t.Fatal(err)
		}
	}
	// The lock-timeout class: a valid code at an active host whose row a concurrent transaction holds FOR UPDATE.
	lockTenant := fx.tenant("l")
	active(lockTenant, gateRedeemLockHost)
	e.lockCode, e.lockSID = fx.newCode(lockTenant)
	e.classes = append(e.classes, gateRedeemClass{gateRedeemLock, gateRedeemLockHost, e.lockCode})
	hold, err := fx.pf.su.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := hold.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var locked string
	if err := tx.QueryRow(ctx, `SELECT id::text FROM attended_session WHERE id = $1 FOR UPDATE`, e.lockSID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	released := false
	e.release = func() {
		if !released {
			released = true
			_ = tx.Rollback(context.Background())
			hold.Release()
		}
	}
	t.Cleanup(e.release)

	if opts.success > 0 {
		goodTenant := fx.tenant("g")
		active(goodTenant, gateRedeemGoodHost)
		for i := 0; i < opts.success; i++ {
			code, _ := fx.newCode(goodTenant)
			e.good = append(e.good, code)
		}
	}

	shared, lookup := gateProdPools(t)
	e.attended = NewPgAttendedStore(shared)
	e.attended.LookupPool = lookup // as main.go: the anonymous redeem lookup on its own pool
	e.shared, e.lookup, e.su = shared, lookup, fx.pf.su

	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	e.edge = hex.EncodeToString(secret)
	authorities := []string{gateRedeemLockHost, gateRedeemGoodHost}
	for _, c := range e.classes {
		authorities = append(authorities, c.Host)
	}
	policy, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"main.example.test"}, PublicAuthorities: authorities,
		EdgeSecret: e.edge, Theming: true})
	if err != nil {
		t.Fatal(err)
	}
	var store AttendedStore = e.attended
	if opts.wrapStore != nil {
		store = opts.wrapStore(store)
	}
	e.srv = &Server{HostPolicy: policy, Attended: store, MgmtAudit: NewPgMgmtAuditStore(shared), RedeemTuning: opts.tuning}
	nets, err := ParseTrustedProxies("127.0.0.1/32")
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetTrustedProxies(nets) // process globals: reset on cleanup
	t.Cleanup(func() { SetTrustedProxyNets(nil); SetTrustProxyForClientIP(false) })

	mux := http.NewServeMux() // as main.go builds it
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
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

func (e *gateRedeemEnv) class(name string) gateRedeemClass {
	for _, c := range e.classes {
		if c.Name == name {
			return c
		}
	}
	return gateRedeemClass{}
}

// premise proves, straight against the store with the very scope the handler would derive, that every rejection class
// really is rejected (ErrAttendedInvalid, nothing consumed) and that the lock-timeout class really waited on the row
// lock (about the 20 ms cap, not an instant "no row"). It returns each class's store latency, for the record.
func (e *gateRedeemEnv) premise(t *testing.T, names []string) map[string]time.Duration {
	t.Helper()
	ctx := context.Background()
	out := map[string]time.Duration{}
	for _, name := range names {
		if name == gateRedeemSuccess || name == gateRedeemTwin {
			continue
		}
		c := e.class(name)
		scope := e.srv.HostPolicy.ScopeFor(c.Host)
		start := time.Now()
		_, err := e.attended.RedeemScoped(ctx, c.Code, randPubkeyHex(t), "GUEST", scope)
		d := time.Since(start)
		if !errors.Is(err, ErrAttendedInvalid) {
			t.Fatalf("release gate premise: class %s is not a rejection at the store: %v", name, err)
		}
		out[name] = d
		if name == gateRedeemLock && (d < 15*time.Millisecond || d > 250*time.Millisecond) {
			t.Fatalf("release gate premise: the lock-timeout class took %v at the store; the 20 ms row-lock wait (55P03) did not happen", d)
		}
	}
	return out
}

func gateRedeemBody(code, pubkey string) string {
	return fmt.Sprintf(`{"code":%q,"pubkey":%q,"name":"GUEST"}`, code, pubkey)
}

// gateRedeemBag is the interleaved scheduler: gateWarmup discarded requests across every state, then n per state in
// one shuffled order, so drift over the run hits every state equally. Each request has a fresh synthetic client
// address (so neither the attend-redeem Fail throttle nor the per-IP admission cap ever answers) and, for success, its
// own pre-minted code and a fresh pubkey.
func gateRedeemBag(t *testing.T, e *gateRedeemEnv, names []string, n int, seed uint64) []gateReq {
	t.Helper()
	r := mrand.New(mrand.NewPCG(seed, 0x4)) // 0x4: redeem
	nextGood := 0
	mk := func(name string) gateReq {
		if name == gateRedeemSuccess {
			if nextGood >= len(e.good) {
				t.Fatalf("release gate: %d pre-minted codes are not enough", len(e.good))
			}
			code := e.good[nextGood]
			nextGood++
			return gateReq{State: name, Host: gateRedeemGoodHost, Path: gateRedeemPath, Method: "POST", Body: gateRedeemBody(code, randPubkeyHex(t))}
		}
		src := name
		if name == gateRedeemTwin {
			src = "random" // the A/A twin: the same class, a second label
		}
		c := e.class(src)
		return gateReq{State: name, Host: c.Host, Path: gateRedeemPath, Method: "POST", Body: gateRedeemBody(c.Code, attendTestPubkey)}
	}
	var reqs []gateReq
	for i := 0; i < gateWarmup; i++ {
		q := mk(names[r.IntN(len(names))])
		q.State = "warmup"
		reqs = append(reqs, q)
	}
	var bag []gateReq
	for _, name := range names {
		for i := 0; i < n; i++ {
			bag = append(bag, mk(name))
		}
	}
	r.Shuffle(len(bag), func(i, j int) { bag[i], bag[j] = bag[j], bag[i] })
	reqs = append(reqs, bag...)
	for i := range reqs {
		reqs[i].XFF = gateXFF(i)
	}
	return reqs
}

type gateRedeemResult struct {
	Pairs   []gatePairFailure
	Floor   []string // floor-bound findings
	Success []string // success-vs-rejection findings
	Sum     map[string]gateSummary
	Min     map[string]time.Duration
	Max     map[string]time.Duration
	P99     map[string]time.Duration
}

func gateRedeemSuccessCount(t *testing.T, names []string) int {
	for _, n := range names {
		if n == gateRedeemSuccess {
			return gateEnvInt(t, "GATE_SAMPLES", gateMinSamples) + gateWarmup + 16
		}
	}
	return 0
}

// runGateRedeem measures the named states (rejection classes, the twin, and optionally "success") and returns the
// statistic and the bound findings. A void run (an invalid sample, a failed premise, too few samples, a failed A/A
// control) fails the test itself.
func runGateRedeem(t *testing.T, e *gateRedeemEnv, names []string, workers int) gateRedeemResult {
	t.Helper()
	n := gateEnvInt(t, "GATE_SAMPLES", gateMinSamples)
	seed := uint64(gateEnvInt(t, "GATE_SEED", 1))
	storeLatency := e.premise(t, names)
	reqs := gateRedeemBag(t, e, names, n, seed)
	hdr := map[string]string{EdgeMarkerHeader: e.edge}
	res := runGateClientProcess(t, gatePlan{Addr: e.addr, Workers: workers, Headers: hdr, Requests: reqs})

	samples := map[string][]time.Duration{}
	var bad []string
	for i, r := range res {
		q := reqs[i]
		want := http.StatusForbidden
		if q.State == gateRedeemSuccess || (q.State == "warmup" && strings.Contains(q.Host, "good.")) {
			want = http.StatusCreated
		}
		switch {
		case r.Err != "" || r.Status != want:
			bad = append(bad, fmt.Sprintf("#%d %s %s: status %d (want %d) err %q", i, q.State, q.Host, r.Status, want, r.Err))
			continue
		case want == http.StatusForbidden && r.Body != gateRedeemRejectionBody:
			bad = append(bad, fmt.Sprintf("#%d %s: the rejection body is not the generic one (%d bytes)", i, q.State, r.Len))
			continue
		}
		if q.State != "warmup" {
			samples[q.State] = append(samples[q.State], time.Duration(r.Nanos))
		}
	}
	if len(bad) > 0 {
		if len(bad) > 20 {
			bad = append(bad[:20], fmt.Sprintf("... and %d more", len(bad)-20))
		}
		t.Fatalf("release gate: %d invalid sample(s); the run is void:\n  %s", len(bad), joinLines(bad))
	}

	out := gateRedeemResult{Min: map[string]time.Duration{}, Max: map[string]time.Duration{}, P99: map[string]time.Duration{}}
	rej := map[string][]time.Duration{}
	for k, v := range samples {
		if k != gateRedeemSuccess {
			rej[k] = v
		}
	}
	sum, pairs, err := gatePairwise(rej)
	if err != nil {
		t.Fatal(err)
	}
	out.Sum, out.Pairs = sum, pairs
	for _, f := range pairs {
		if (f.A == "random" && f.B == gateRedeemTwin) || (f.B == "random" && f.A == gateRedeemTwin) {
			t.Fatalf("release gate VOID: the A/A control failed (%s); the environment is not stable enough to measure", f)
		}
	}

	fastest := time.Hour
	keys := make([]string, 0, len(rej))
	for k := range rej {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := append([]time.Duration(nil), rej[k]...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		out.Min[k], out.Max[k], out.P99[k] = s[0], s[len(s)-1], s[(99*len(s)+99)/100-1]
		if s[0] < fastest {
			fastest = s[0]
		}
		// 2b.4: no rejection is released earlier than the floor after admission.
		if s[0] < DefaultRedeemFloor {
			under := 0
			for _, d := range s {
				if d < DefaultRedeemFloor {
					under++
				}
			}
			out.Floor = append(out.Floor, fmt.Sprintf("%s: %d of %d rejection(s) completed before the %v floor (fastest %v)", k, under, len(s), DefaultRedeemFloor, s[0]))
		}
		// 2b.4: floor + jitter is at most 100 ms.
		if out.P99[k] > gateRedeemTotalMax {
			out.Floor = append(out.Floor, fmt.Sprintf("%s: p99 %v exceeds the %v bound on floor + jitter", k, out.P99[k], gateRedeemTotalMax))
		}
		if mx := s[len(s)-1]; mx > DefaultRedeemFloor+DefaultRedeemJitter+gateRedeemSlack {
			out.Floor = append(out.Floor, fmt.Sprintf("%s: slowest rejection %v exceeds floor + jitter + %v slack", k, mx, gateRedeemSlack))
		}
		// The 0-20 ms jitter must be visible: a fixed floor is itself a timing signature.
		if spread := s[(95*len(s)+99)/100-1] - s[(5*len(s)+99)/100-1]; spread < 8*time.Millisecond {
			out.Floor = append(out.Floor, fmt.Sprintf("%s: p5-p95 spread %v; the 0-20 ms jitter is missing", k, spread))
		}
	}
	if ok := samples[gateRedeemSuccess]; len(ok) > 0 {
		s := gateSummarize(ok)
		out.Sum[gateRedeemSuccess] = s
		if s.N < gateMinSamples {
			out.Success = append(out.Success, fmt.Sprintf("only %d success samples", s.N))
		}
		if s.P95 >= fastest {
			out.Success = append(out.Success, fmt.Sprintf("success p95 %v is not below the fastest rejection %v: the floor must not apply to success", s.P95, fastest))
		}
	}
	for _, k := range keys {
		t.Logf("%-18s n=%d median=%v p95=%v p99=%v min=%v max=%v", k, out.Sum[k].N, out.Sum[k].Median, out.Sum[k].P95, out.P99[k], out.Min[k], out.Max[k])
	}
	if s, ok := out.Sum[gateRedeemSuccess]; ok {
		t.Logf("%-18s n=%d median=%v p95=%v (not floored)", gateRedeemSuccess, s.N, s.Median, s.P95)
	}

	rec := struct {
		Test         string                 `json:"test"`
		Seed         uint64                 `json:"seed"`
		Workers      int                    `json:"workers"`
		PerState     int                    `json:"per_state"`
		GOOS         string                 `json:"goos"`
		NumCPU       int                    `json:"num_cpu"`
		FloorMs      int64                  `json:"floor_ms"`
		JitterMs     int64                  `json:"jitter_ms"`
		MedianLimit  string                 `json:"median_limit"`
		P95Limit     string                 `json:"p95_limit"`
		Summaries    map[string]gateSummary `json:"summaries"`
		Min          map[string]string      `json:"min"`
		Max          map[string]string      `json:"max"`
		P99          map[string]string      `json:"p99"`
		StoreLatency map[string]string      `json:"premise_store_latency"`
		PairFailures []string               `json:"pair_failures"`
		FloorFinds   []string               `json:"floor_findings"`
		SuccessFinds []string               `json:"success_findings"`
	}{Test: t.Name(), Seed: seed, Workers: workers, PerState: n, GOOS: runtime.GOOS, NumCPU: runtime.NumCPU(),
		FloorMs: DefaultRedeemFloor.Milliseconds(), JitterMs: DefaultRedeemJitter.Milliseconds(),
		MedianLimit: "<" + gateMedianMax.String(), P95Limit: "<" + gateP95Max.String(), Summaries: out.Sum,
		Min: durStrings(out.Min), Max: durStrings(out.Max), P99: durStrings(out.P99), StoreLatency: durStrings(storeLatency),
		PairFailures: []string{}, FloorFinds: out.Floor, SuccessFinds: out.Success}
	for _, f := range out.Pairs {
		rec.PairFailures = append(rec.PairFailures, f.String())
	}
	if rec.FloorFinds == nil {
		rec.FloorFinds = []string{}
	}
	if rec.SuccessFinds == nil {
		rec.SuccessFinds = []string{}
	}
	writeGateRedeemRecord(t, rec.Test, rec)
	return out
}

func durStrings(m map[string]time.Duration) map[string]string {
	o := map[string]string{}
	for k, v := range m {
		o[k] = v.String()
	}
	return o
}

func writeGateRedeemRecord(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("DESKRALLY_GATE_OUT")
	if dir == "" {
		dir = t.TempDir()
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, name+".json")
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("release gate record: %s", p)
}

// 2a.5, 2b.4, 2b.5 at production defaults: every rejection class (including the lock-timeout class and an A/A twin),
// success, the pairwise statistic, the floor bounds. After the measurement the lock holder rolls back and the very
// code that was refused redeems (2b.5: a lock timeout is transient and consumes nothing).
func TestReleaseGateRedeemWarm(t *testing.T) {
	var names []string
	e := newGateRedeemEnv(t, gateRedeemOpts{success: gateRedeemSuccessCount(t, []string{gateRedeemSuccess})})
	for _, c := range e.classes {
		names = append(names, c.Name)
	}
	names = append(names, gateRedeemTwin, gateRedeemSuccess)
	res := runGateRedeem(t, e, names, 16)
	for _, f := range res.Pairs {
		t.Errorf("release gate FAIL: %s", f)
	}
	for _, f := range res.Floor {
		t.Errorf("release gate FAIL (floor): %s", f)
	}
	for _, f := range res.Success {
		t.Errorf("release gate FAIL (success): %s", f)
	}
	// The class was only ever refused for the lock: once the holder lets go, the same code redeems.
	e.release()
	c := e.class(gateRedeemLock)
	if _, err := e.attended.RedeemScoped(context.Background(), c.Code, randPubkeyHex(t), "GUEST", e.srv.HostPolicy.ScopeFor(c.Host)); err != nil {
		t.Errorf("release gate FAIL: the lock-timeout class's code did not redeem after the holder released (a lock timeout must consume nothing): %v", err)
	}
}

// The classes the negative controls use: four with distinct hosts, so an HTTP-level shift can single one out.
var gateRedeemControlStates = []string{"random", gateRedeemTwin, "tenant-suspended", "host-pending"}

const gateRedeemShifted = "susp.example.test" // the host of tenant-suspended

// shiftedPairs asserts that exactly the pairs involving `state` failed: the gate sees the shifted class and nothing else.
func gateRedeemExpectOnly(t *testing.T, what, state string, res gateRedeemResult, others int) {
	t.Helper()
	got := 0
	for _, f := range res.Pairs {
		if f.A != state && f.B != state {
			t.Errorf("%s: a pair without the shifted class failed: %s", what, f)
		} else {
			got++
		}
	}
	if got != others {
		t.Errorf("%s: %d failing pair(s) with the shifted class, want %d (every pair with it): %v", what, got, others, res.Pairs)
	}
}

// Negative control 1: one class delayed 20 ms outside the handler (before admission, where the floor cannot absorb it)
// must fail every pair that includes it, and no other.
func TestReleaseGateRedeemDetectsAShiftedClass(t *testing.T) {
	shift := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host == gateRedeemShifted && r.URL.Path == gateRedeemPath {
				time.Sleep(20 * time.Millisecond)
			}
			next.ServeHTTP(w, r)
		})
	}
	e := newGateRedeemEnv(t, gateRedeemOpts{wrap: shift})
	res := runGateRedeem(t, e, gateRedeemControlStates, 16)
	gateRedeemExpectOnly(t, "negative control (HTTP shift)", "tenant-suspended", res, len(gateRedeemControlStates)-1)
}

type gateSlowStore struct {
	AttendedStore
	host string
	d    time.Duration
}

func (s gateSlowStore) RedeemScoped(ctx context.Context, code, pub, name string, sc RedeemScope) (*AttendedRedeem, error) {
	if sc.Host == s.host {
		time.Sleep(s.d)
	}
	return s.AttendedStore.RedeemScoped(ctx, code, pub, name, sc)
}

// Negative control 2: a lookup for one class that outlasts the floor (a store decorator adds 100 ms, so the work, not the
// floor, sets the response time: the leak the floor exists to prevent) must fail every pair that includes the class.
func TestReleaseGateRedeemDetectsALookupSlowerThanTheFloor(t *testing.T) {
	e := newGateRedeemEnv(t, gateRedeemOpts{wrapStore: func(s AttendedStore) AttendedStore {
		return gateSlowStore{s, gateRedeemShifted, 100 * time.Millisecond}
	}})
	res := runGateRedeem(t, e, gateRedeemControlStates, 16)
	gateRedeemExpectOnly(t, "negative control (lookup over the floor)", "tenant-suspended", res, len(gateRedeemControlStates)-1)
}

// The floor is the design: a lookup that is 20 ms slower for one class but still under the 60 ms floor is invisible, so
// no pair may fail. (If this ever fails the floor stopped absorbing class-dependent work.)
func TestReleaseGateRedeemFloorAbsorbsASlowerLookup(t *testing.T) {
	e := newGateRedeemEnv(t, gateRedeemOpts{wrapStore: func(s AttendedStore) AttendedStore {
		return gateSlowStore{s, gateRedeemShifted, 20 * time.Millisecond}
	}})
	res := runGateRedeem(t, e, gateRedeemControlStates, 16)
	for _, f := range res.Pairs {
		t.Errorf("release gate FAIL: a 20 ms slower lookup under the floor is visible: %s", f)
	}
	for _, f := range res.Floor {
		t.Errorf("release gate FAIL (floor): %s", f)
	}
}

// Negative control 3: a server with the floor switched off must trip the floor check (rejections complete in a few ms).
func TestReleaseGateRedeemFloorCheckDetectsNoFloor(t *testing.T) {
	e := newGateRedeemEnv(t, gateRedeemOpts{tuning: RedeemTuning{Floor: -1}})
	res := runGateRedeem(t, e, gateRedeemControlStates, 16)
	if len(res.Floor) == 0 {
		t.Fatal("negative control: a floor-less server passed the floor bounds; the check cannot fail")
	}
	if !strings.Contains(res.Floor[0], "before the") {
		t.Errorf("negative control: unexpected first finding: %s", res.Floor[0])
	}
}
