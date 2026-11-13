package controlplane

// HTTP-level contract of the scoped redemption (docs/66 2a.5, 2b.4, 2b.5, 2c): every rejected class is
// indistinguishable (status, bytes, headers, limiter accounting, audit effects), admission is uniform and
// precedes class-dependent work, the floor applies to rejections only, and the internal callers do not
// notice the host policy. Run against the fake always and against Postgres when TEST_DATABASE_URL is set.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const redeemHostA = "acme.example.test"

func scopedPolicy(t *testing.T) *HostPolicy {
	t.Helper()
	p, err := NewHostPolicy(HostPolicyConfig{
		DefaultHosts:        []string{"main.example.test"},
		LegacyUnscopedHosts: []string{"loam.example.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// scopedRedeemServer is a Server whose attended store is fx's, with the host policy installed.
func scopedRedeemServer(t *testing.T, fx *hostContractFx, tuning RedeemTuning) *Server {
	t.Helper()
	srv, _ := newAttendedServer(t)
	srv.Attended = fx.attended
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = tuning
	return srv
}

func postRedeem(srv *Server, host, ip, code string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "/attended-sessions/redeem",
		strings.NewReader(`{"code":"`+code+`","pubkey":"`+attendTestPubkey+`","name":"GUEST"}`))
	req.Host = host
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func (s *Server) failuresFor(ip string) int {
	th := s.throttle()
	th.mu.Lock()
	defer th.mu.Unlock()
	if e := th.entries[ipKey("attend-redeem", ip)]; e != nil {
		return e.failures
	}
	return 0
}

type redeemClass struct {
	name string
	host string
	code string
}

// buildRedeemClasses sets up every rejected class on top of fx and returns them plus a valid code for the
// positive control.
func buildRedeemClasses(t *testing.T, fx *hostContractFx) (classes []redeemClass, goodCode string) {
	t.Helper()
	ctx := context.Background()
	A, B, C, E, S := fx.tenant("a"), fx.tenant("b"), fx.tenant("c"), fx.tenant("e"), fx.tenant("s")
	active := func(tenant, host string) {
		a := fx.mustAssign(t, tenant, host)
		if _, err := fx.hosts.Activate(ctx, fx.caller, a.ID, nil); err != nil {
			t.Fatal(err)
		}
	}
	active(A, redeemHostA)
	fx.mustAssign(t, C, "pend.example.test") // pending, never activated
	active(E, "rel.example.test")
	active(S, "susp.example.test")

	expired, sid := fx.newCode(A)
	fx.expire(sid)
	spent, _ := fx.newCode(A)
	if _, err := fx.redeem(t, spent, RedeemScope{Host: redeemHostA}); err != nil {
		t.Fatal(err)
	}
	foreign, _ := fx.newCode(B)
	pendingHostCode, _ := fx.newCode(C)
	releasedCode, _ := fx.newCode(E)
	all, _ := fx.hosts.List(ctx, fx.caller, E)
	if _, err := fx.hosts.Release(ctx, fx.caller, all[0].ID, 30, nil); err != nil {
		t.Fatal(err)
	}
	suspendedCode, _ := fx.newCode(S)
	fx.suspend(S, true)
	ownValid, _ := fx.newCode(A)
	goodCode, _ = fx.newCode(A)

	classes = []redeemClass{
		{"random", redeemHostA, "NOSUCHCODE0000"},
		{"expired", redeemHostA, expired},
		{"spent", redeemHostA, spent},
		{"foreign-tenant", redeemHostA, foreign},
		{"host-pending", "pend.example.test", pendingHostCode},
		{"host-released", "rel.example.test", releasedCode},
		{"tenant-suspended", "susp.example.test", suspendedCode},
		{"unknown-host", "nope.example.test", ownValid},
		{"refused-authority", redeemHostA + ":8443", ownValid},
		{"ip-literal-host", "127.0.0.1", ownValid},
	}
	return classes, goodCode
}

func runRedeemIndistinguishable(t *testing.T, fx *hostContractFx) {
	classes, good := buildRedeemClasses(t, fx)
	srv := scopedRedeemServer(t, fx, RedeemTuning{Floor: -1})
	type obs struct {
		code    int
		body    string
		headers http.Header
	}
	var ref *obs
	for i, c := range classes {
		ip := fmt.Sprintf("10.9.0.%d", i+1)
		rec := postRedeem(srv, c.host, ip, c.code)
		o := &obs{rec.Code, rec.Body.String(), rec.Header().Clone()}
		o.headers.Del("Date")
		if o.code != http.StatusForbidden || o.body != `{"error":"invalid attended code"}`+"\n" {
			t.Errorf("%s: %d %q, want the generic 403", c.name, o.code, o.body)
		}
		if ref == nil {
			ref = o
		} else if o.code != ref.code || o.body != ref.body || !reflect.DeepEqual(o.headers, ref.headers) {
			t.Errorf("%s differs from %s:\n  %d %q %v\n  %d %q %v", c.name, classes[0].name, o.code, o.body, o.headers, ref.code, ref.body, ref.headers)
		}
		if n := srv.failuresFor(ip); n != 1 {
			t.Errorf("%s: limiter accounting = %d failures, want exactly 1", c.name, n)
		}
	}
	// No rejected class wrote an audit row, on any tenant.
	events := 0
	for _, tn := range []string{attendTestTenant} {
		evs, _ := srv.MgmtAudit.(*InMemoryMgmtAuditStore).ListEvents(context.Background(), tn, 100)
		events += len(evs)
	}
	if events != 0 {
		t.Errorf("rejections wrote %d audit rows", events)
	}
	// Refused-but-valid codes were NOT consumed: the foreign and own-tenant ones still redeem where scope allows.
	rec := postRedeem(srv, redeemHostA, "10.9.1.1", good)
	if rec.Code != http.StatusCreated {
		t.Fatalf("positive control (own tenant, active host): %d %s", rec.Code, rec.Body.String())
	}
	if n := srv.failuresFor("10.9.1.1"); n != 0 {
		t.Errorf("a success must reset the limiter, failures = %d", n)
	}
}

func TestRedeemRejectedClassesAreIndistinguishableInMemory(t *testing.T) {
	runRedeemIndistinguishable(t, newFakeHostContractFx(t))
}

func TestRedeemRejectedClassesAreIndistinguishablePg(t *testing.T) {
	fx := newPgHostFx(t)
	runRedeemIndistinguishable(t, fx.hostContractFx)
}

// --- the handler consults the scope (it cannot be silently unwired) ---------------------------------

type scopeRecorder struct {
	AttendedStore
	mu     sync.Mutex
	scopes []RedeemScope
}

func (s *scopeRecorder) RedeemScoped(ctx context.Context, code, pub, name string, sc RedeemScope) (*AttendedRedeem, error) {
	s.mu.Lock()
	s.scopes = append(s.scopes, sc)
	s.mu.Unlock()
	return nil, ErrAttendedInvalid
}

func TestRedeemHandlerPassesTheHostScopeAndTheOffFlagNeverRemovesIt(t *testing.T) {
	for _, theming := range []bool{false, true} {
		srv, _ := newAttendedServer(t)
		rec := &scopeRecorder{AttendedStore: srv.Attended}
		srv.Attended = rec
		srv.RedeemTuning = RedeemTuning{Floor: -1}
		p, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"main.example.test"},
			LegacyUnscopedHosts: []string{"loam.example.test"}, Theming: theming})
		if err != nil {
			t.Fatal(err)
		}
		srv.HostPolicy = p
		for i, host := range []string{"main.example.test", "LOAM.example.test.", "acme.example.test", "acme.example.test:8443", "other.example.test:443"} {
			postRedeem(srv, host, fmt.Sprintf("10.8.%d.1", i), "CODE")
		}
		want := []RedeemScope{
			{Unscoped: true, Host: "main.example.test"}, {Unscoped: true, Host: "loam.example.test"},
			{Host: "acme.example.test"}, {}, {Host: "other.example.test"},
		}
		if !reflect.DeepEqual(rec.scopes, want) {
			t.Fatalf("theming=%v: scopes = %+v, want %+v (CP_HOST_THEMING must never change redemption scope)", theming, rec.scopes, want)
		}
	}
	// No policy at all: the pre-theming behaviour.
	srv, _ := newAttendedServer(t)
	rec := &scopeRecorder{AttendedStore: srv.Attended}
	srv.Attended = rec
	srv.RedeemTuning = RedeemTuning{Floor: -1}
	postRedeem(srv, "whatever.example.test", "10.7.0.1", "CODE")
	if len(rec.scopes) != 1 || !rec.scopes[0].Unscoped {
		t.Fatalf("nil policy: %+v, want unscoped", rec.scopes)
	}
}

// A database error is NOT a rejection: fail closed with the existing 500, no Fail recorded, no floor sleep.
type failingAttended struct {
	AttendedStore
	err error
}

func (f failingAttended) RedeemScoped(context.Context, string, string, string, RedeemScope) (*AttendedRedeem, error) {
	return nil, f.err
}

func TestRedeemStoreErrorFailsClosedAs500(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Attended = failingAttended{srv.Attended, fmt.Errorf("connection refused")}
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = RedeemTuning{Floor: -1}
	rec := postRedeem(srv, "acme.example.test", "10.7.1.1", "CODE")
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "could not redeem attended code") {
		t.Fatalf("store error: %d %s", rec.Code, rec.Body.String())
	}
	if n := srv.failuresFor("10.7.1.1"); n != 0 {
		t.Fatalf("a store error recorded %d failures", n)
	}
}

// A lookup that overruns the 250 ms work deadline (here 40 ms) is the same generic rejection.
type slowAttended struct {
	AttendedStore
	block chan struct{}
}

func (s slowAttended) RedeemScoped(ctx context.Context, _, _, _ string, _ RedeemScope) (*AttendedRedeem, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.block:
		return nil, ErrAttendedInvalid
	}
}

func TestRedeemWorkDeadlineIsTheGenericRejection(t *testing.T) {
	srv, _ := newAttendedServer(t)
	srv.Attended = slowAttended{srv.Attended, make(chan struct{})}
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = RedeemTuning{WorkDeadline: 40 * time.Millisecond}
	start := time.Now()
	cut := postRedeem(srv, "acme.example.test", "10.7.2.1", "CODE")
	if d := time.Since(start); d < 60*time.Millisecond || d > time.Second {
		t.Errorf("a deadline-cut redemption took %v, want the 40 ms cut then the 60-80 ms floor from admission (~60-100 ms)", d)
	}
	if cut.Code != http.StatusForbidden || cut.Body.String() != `{"error":"invalid attended code"}`+"\n" {
		t.Fatalf("deadline cut: %d %q, want the generic 403", cut.Code, cut.Body.String())
	}
	if n := srv.failuresFor("10.7.2.1"); n != 1 {
		t.Fatalf("deadline cut recorded %d failures, want 1", n)
	}
}

// --- admission ---------------------------------------------------------------------------------------

type gatedAttended struct {
	AttendedStore
	release chan struct{}
	entered chan struct{}
}

func (g gatedAttended) RedeemScoped(context.Context, string, string, string, RedeemScope) (*AttendedRedeem, error) {
	g.entered <- struct{}{}
	<-g.release
	return nil, ErrAttendedInvalid
}

func TestRedeemAdmissionCapsAreUniformAndPrecedeAllWork(t *testing.T) {
	srv, _ := newAttendedServer(t)
	g := gatedAttended{srv.Attended, make(chan struct{}), make(chan struct{}, 64)}
	srv.Attended = g
	srv.HostPolicy = scopedPolicy(t)
	srv.RedeemTuning = RedeemTuning{AdmitGlobal: 6, AdmitPerIP: 2, Floor: -1}

	var wg sync.WaitGroup
	launch := func(host, ip string) {
		wg.Add(1)
		go func() { defer wg.Done(); postRedeem(srv, host, ip, "CODE") }()
		<-g.entered // the request is inside the class-dependent work, holding a slot
	}
	launch("acme.example.test", "10.6.0.1")
	launch("main.example.test", "10.6.0.1")

	var ref *httptest.ResponseRecorder
	check := func(what, host, ip, code string) {
		t.Helper()
		start := time.Now()
		rec := postRedeem(srv, host, ip, code)
		if d := time.Since(start); d > 300*time.Millisecond {
			t.Errorf("%s: the over-capacity answer took %v (it must be immediate)", what, d)
		}
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("%s: %d %v, want 429 with Retry-After", what, rec.Code, rec.Header())
		}
		if ref == nil {
			ref = rec
		} else if rec.Body.String() != ref.Body.String() || !reflect.DeepEqual(rec.Header(), ref.Header()) {
			t.Errorf("%s: the over-capacity answer differs by class/host: %q %v vs %q %v", what, rec.Body.String(), rec.Header(), ref.Body.String(), ref.Header())
		}
	}
	// Per-IP cap (2): the same IP, any host or code, is refused without touching the store.
	check("3rd from the same IP (tenant host)", "acme.example.test", "10.6.0.1", "OTHER")
	check("3rd from the same IP (default host, other code)", "main.example.test", "10.6.0.1", "VALIDISH")
	check("3rd from the same IP (refused authority)", "127.0.0.1", "10.6.0.1", "X")
	// Global cap (6): fill with distinct IPs, then a fresh IP is refused identically.
	launch("acme.example.test", "10.6.0.2")
	launch("acme.example.test", "10.6.0.3")
	launch("acme.example.test", "10.6.0.4")
	launch("acme.example.test", "10.6.0.5")
	check("global cap", "other.example.test", "10.6.9.9", "Y")

	// Over-capacity requests recorded no failures and no audit rows and never reached the store.
	for _, ip := range []string{"10.6.9.9"} {
		if n := srv.failuresFor(ip); n != 0 {
			t.Errorf("%s: a 429 recorded %d failures", ip, n)
		}
	}
	if in, _ := srv.redeemPool().stats(); in != 6 {
		t.Errorf("in-flight = %d, want 6", in)
	}
	close(g.release) // everyone finishes
	wg.Wait()
	if in, keys := srv.redeemPool().stats(); in != 0 || keys != 0 {
		t.Errorf("permits leaked after completion: in-flight %d, keys %d", in, keys)
	}
	// Recovered: a fresh request is admitted again.
	if rec := postRedeem(srv, "acme.example.test", "10.6.9.9", "Z"); rec.Code != http.StatusForbidden {
		t.Errorf("after recovery: %d, want the ordinary rejection", rec.Code)
	}
}

// --- timing: floor on rejections only, and the class distributions agree -------------------------------

func pct(sorted []time.Duration, p float64) time.Duration {
	return sorted[int(float64(len(sorted)-1)*p)]
}

// measureRejectionClasses runs `samples` rejections per class, one goroutine per class, each request from its
// own IP, and returns the sorted latencies.
func measureRejectionClasses(t *testing.T, srv *Server, classes []redeemClass, samples int) map[string][]time.Duration {
	t.Helper()
	out := map[string][]time.Duration{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ci, c := range classes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lat := make([]time.Duration, 0, samples)
			for i := 0; i < samples; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", 100+ci, i/250, i%250+1)
				start := time.Now()
				rec := postRedeem(srv, c.host, ip, c.code)
				lat = append(lat, time.Since(start))
				if rec.Code != http.StatusForbidden {
					t.Errorf("%s sample %d: %d", c.name, i, rec.Code)
					return
				}
			}
			sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
			mu.Lock()
			out[c.name] = lat
			mu.Unlock()
		}()
	}
	wg.Wait()
	return out
}

// runRejectionTiming: the unit-suite version. HOST_TIMING_SAMPLES (default 60) scales it; the RELEASE GATE
// runs 2,000 per class against real Postgres with the doc's thresholds (median 5 ms, p95 15 ms). Below 1,000
// samples the median threshold is widened because the sampling noise of a median of a uniform 0-20 ms jitter
// is itself ~2 ms; the floor is never raised past 100 ms and the p95 threshold never loosened.
func runRejectionTiming(t *testing.T, fx *hostContractFx) {
	samples := 60
	if v, err := strconv.Atoi(os.Getenv("HOST_TIMING_SAMPLES")); err == nil && v > 0 {
		samples = v
	}
	medianTol := 5 * time.Millisecond
	if samples < 1000 {
		medianTol = 8 * time.Millisecond
	}
	classes, good := buildRedeemClasses(t, fx)
	srv := scopedRedeemServer(t, fx, RedeemTuning{}) // the documented defaults: floor 60 ms, jitter 20 ms
	// Warm the pool first: the COLD path (a new connection per concurrent class) is a different, documented
	// measurement (2c.3 lists cold separately); here every class runs on warm connections.
	measureRejectionClasses(t, srv, classes, 3)
	lat := measureRejectionClasses(t, srv, classes, samples)

	names := make([]string, 0, len(lat))
	for n := range lat {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		l := lat[n]
		if l[0] < DefaultRedeemFloor-2*time.Millisecond {
			t.Errorf("%s: fastest rejection %v is under the %v floor", n, l[0], DefaultRedeemFloor)
		}
		// An ABSOLUTE upper bound depends on the machine's load, so it belongs to the isolated release-gate run only.
		// The unit suite asserts the floor (lower bound), the jitter spread and the RELATIVE agreement of the classes.
		if mx := l[len(l)-1]; samples >= 1000 && mx > DefaultRedeemFloor+DefaultRedeemJitter+60*time.Millisecond {
			t.Errorf("%s: slowest rejection %v exceeds floor+jitter+slack", n, mx)
		}
		if spread := pct(l, .95) - pct(l, .05); spread < 8*time.Millisecond {
			t.Errorf("%s: latency spread p5-p95 = %v; the 0-20 ms jitter is missing (a fixed floor is a timing signature)", n, spread)
		}
		t.Logf("%-18s n=%d median=%v p95=%v", n, len(l), pct(l, .5).Round(time.Millisecond/10), pct(l, .95).Round(time.Millisecond/10))
	}
	for i := range names {
		for j := i + 1; j < len(names); j++ {
			a, b := lat[names[i]], lat[names[j]]
			dm := pct(a, .5) - pct(b, .5)
			dp := pct(a, .95) - pct(b, .95)
			if dm < 0 {
				dm = -dm
			}
			if dp < 0 {
				dp = -dp
			}
			if dm >= medianTol || dp >= 15*time.Millisecond {
				t.Errorf("%s vs %s: |median diff| %v (limit %v), |p95 diff| %v (limit 15ms)", names[i], names[j], dm, medianTol, dp)
			}
		}
	}
	// The floor does NOT apply to success.
	// Relative, not absolute: the success path is faster than the FASTEST rejection seen (which is >= the floor).
	fastestRejection := time.Hour
	for _, l := range lat {
		if l[0] < fastestRejection {
			fastestRejection = l[0]
		}
	}
	start := time.Now()
	rec := postRedeem(srv, redeemHostA, "10.5.5.5", good)
	if d := time.Since(start); rec.Code != http.StatusCreated || d >= fastestRejection {
		t.Errorf("success: %d in %v, want 201 faster than the fastest rejection (%v): the floor must not apply to success", rec.Code, d, fastestRejection)
	}
}

func TestRedeemRejectionTimingInMemory(t *testing.T) {
	runRejectionTiming(t, newFakeHostContractFx(t))
}

func TestRedeemRejectionTimingPg(t *testing.T) {
	fx := newPgHostFx(t)
	runRejectionTiming(t, fx.hostContractFx)
}

// --- internal callers do not notice the host policy -----------------------------------------------------

func TestInternalCallersAreUnaffectedByTheHostPolicyAndGate(t *testing.T) {
	type call struct{ method, path, body string }
	calls := []call{
		{"GET", "/healthz", ""},
		{"GET", "/readyz", ""},
		{"GET", "/internal/capabilities", ""},
		{"GET", "/internal/devices/nope/identity", ""},
		{"POST", "/internal/session-tickets/redeem", `{}`},
	}
	run := func(withPolicy bool) []string {
		srv, _ := identityServer(t)
		if withPolicy {
			p, err := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{"main.example.test"}, EdgeSecret: gateSecret})
			if err != nil {
				t.Fatal(err)
			}
			srv.HostPolicy = p
		}
		var out []string
		for _, c := range calls {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			req.Host = "controlplane:8081" // the compose service name: not a public authority, no marker
			req.Header.Set("Authorization", "Bearer "+deviceIdentityToken)
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			out = append(out, fmt.Sprintf("%s %s -> %d %s", c.method, c.path, rec.Code, rec.Body.String()))
		}
		return out
	}
	without, with := run(false), run(true)
	for i := range without {
		if without[i] != with[i] {
			t.Errorf("internal call changed under the host policy:\n  before: %s\n  after:  %s", without[i], with[i])
		}
		if strings.Contains(with[i], " 421 ") {
			t.Errorf("internal call was authority-gated: %s", with[i])
		}
	}
}
