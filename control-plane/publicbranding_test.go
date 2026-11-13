package controlplane

// docs/66 2a.4, 2a.6, 2b.7, 2c.3, 2c.4, 2d.1, 2e: the public branding routes. Everything here is unit scale;
// the 2,000-sample timing run and the 5,000-IP load test are release-gate runs of later stages.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	pbDefault  = "main.example.test"
	pbLegacy   = "loam.example.test"
	pbUnmapped = "nomap.example.test"
	pbPending  = "pend.example.test"
	pbUnappr   = "unappr.example.test"
	pbDisabled = "dis.example.test"
	pbDBFail   = "dbfail.example.test"
	pbBrand    = "acme.example.test"
	pbStranger = "stranger.example.test"
)

// countingBrand counts and optionally disturbs lookups.
type countingBrand struct {
	BrandingRevisionStore
	calls    atomic.Int32
	failHost string        // lookups for this host fail (a dropped connection)
	delay    time.Duration // added before the real lookup
	deaf     bool          // the delay ignores cancellation (a lookup stuck in a driver)
	gate     chan struct{} // when set, the FIRST lookup reads, signals readDone, then waits for the gate
	readDone chan struct{}
	gated    atomic.Bool
	lastLogo atomic.Bool
}

func (c *countingBrand) PublicLookup(ctx context.Context, host string, wantLogo bool) (*PublishedBranding, error) {
	c.calls.Add(1)
	c.lastLogo.Store(wantLogo)
	if host == c.failHost {
		return nil, fmt.Errorf("connection reset by peer")
	}
	if c.delay > 0 && c.deaf {
		time.Sleep(c.delay)
	} else if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	res, err := c.BrandingRevisionStore.PublicLookup(ctx, host, wantLogo)
	if c.gate != nil && c.gated.CompareAndSwap(false, true) {
		close(c.readDone)
		<-c.gate
	}
	return res, err
}

type pbEnv struct {
	hosts  *InMemoryHostnameStore
	brand  *InMemoryBrandingStore
	cb     *countingBrand
	srv    *Server
	caller PlatformCaller
	tenant string // the tenant behind pbBrand
	logo   []byte
	rev    *BrandingRevision
	susp   map[string]bool
	mu     sync.Mutex
}

func newPBEnv(t *testing.T, tuning BrandingTuning) *pbEnv {
	t.Helper()
	e := &pbEnv{hosts: &InMemoryHostnameStore{}, susp: map[string]bool{}}
	e.hosts.TenantActive = func(id string) bool { e.mu.Lock(); defer e.mu.Unlock(); return !e.susp[id] }
	e.brand = NewInMemoryBrandingStore(e.hosts)
	e.cb = &countingBrand{BrandingRevisionStore: e.brand}
	e.caller = PlatformCaller{UserID: newUUID(), TenantID: newUUID(), SessionID: newUUID(), Email: "op@test"}
	ctx := context.Background()

	mk := func(host string, activate, approve bool, name string) string {
		tenant := newUUID()
		a, err := e.hosts.Assign(ctx, e.caller, tenant, host, nil)
		if err != nil {
			t.Fatal(err)
		}
		if activate {
			if _, err := e.hosts.Activate(ctx, e.caller, a.ID, nil); err != nil {
				t.Fatal(err)
			}
		}
		in := brandInput(name)
		if host == pbBrand {
			e.logo = tinyLogo(t, 77)
			in.LogoPNG = e.logo
		}
		rev, _, err := e.brand.CreateRevision(ctx, tenant, "owner", in)
		if err != nil {
			t.Fatal(err)
		}
		if host == pbBrand {
			e.rev = rev
		}
		if approve {
			if _, err := e.brand.Approve(ctx, e.caller, tenant, BrandingApproval{RevisionID: rev.ID, Hash: rev.Hash, AssignmentID: a.ID, Generation: e.gen(tenant)}, nil); err != nil {
				t.Fatal(err)
			}
		}
		return tenant
	}
	e.tenant = mk(pbBrand, true, true, "Acme Support")
	mk(pbPending, false, true, "Pending Co")
	mk(pbUnappr, true, false, "Unapproved Co")
	dis := mk(pbDisabled, true, true, "Disabled Co")
	mk(pbDBFail, true, true, "DB Fail Co")
	e.susp[dis] = true
	e.cb.failHost = pbDBFail

	policy, err := NewHostPolicy(HostPolicyConfig{
		DefaultHosts:        []string{pbDefault},
		LegacyUnscopedHosts: []string{pbLegacy},
		PublicAuthorities:   []string{pbDefault, pbLegacy, pbUnmapped, pbPending, pbUnappr, pbDisabled, pbDBFail, pbBrand},
		Theming:             true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if tuning.RatePerMinute == 0 {
		tuning.RatePerMinute = -1
	}
	e.srv = &Server{HostPolicy: policy, BrandingRevisions: e.cb, BrandingTuning: tuning}
	return e
}

var pbIP atomic.Int32

func nextIP() string {
	n := pbIP.Add(1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255)
}

func (e *pbEnv) get(path, host string, hdr ...string) *httptest.ResponseRecorder {
	return e.getFrom(nextIP(), path, host, hdr...)
}

func (e *pbEnv) getFrom(ip, path, host string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	req.Host = host
	req.RemoteAddr = ip + ":40000"
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.srv.Handler().ServeHTTP(rec, req)
	return rec
}

// fingerprint is the whole response minus Date: status, sorted header lines, body.
func fingerprint(rec *httptest.ResponseRecorder) string {
	res := rec.Result()
	var lines []string
	for k, v := range res.Header {
		if k == "Date" {
			continue
		}
		lines = append(lines, k+": "+strings.Join(v, ","))
	}
	sort.Strings(lines)
	return fmt.Sprintf("%d\n%s\n\n%s", res.StatusCode, strings.Join(lines, "\n"), rec.Body.String())
}

const quick = -1 // BrandingTuning.Floor value: no floor (functional tests that are not about time)

func TestPublicBrandingEveryNeutralStateIsByteIdentical(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	logoPath := "/public/branding/logo?rev=" + logoSHA(e.logo)
	for _, route := range []struct{ name, path string }{{"json", "/public/branding"}, {"logo", logoPath}} {
		t.Run(route.name, func(t *testing.T) {
			// For the logo route every host (even the published one, since the rev below is wrong for all the
			// others) must also give the neutral JSON when the requested hash is not the published one.
			path := route.path
			if route.name == "logo" {
				path = "/public/branding/logo?rev=" + strings.Repeat("0", 64)
			}
			want := ""
			for _, host := range []string{pbDefault, pbLegacy, pbUnmapped, pbPending, pbUnappr, pbDisabled, pbDBFail, pbStranger, "", "bad host!", "main.example.test:8443"} {
				rec := e.get(path, host)
				fp := fingerprint(rec)
				if want == "" {
					want = fp
					if rec.Code != 200 || rec.Body.String() != string(NeutralBrandingBody()) {
						t.Fatalf("the neutral response itself is wrong: %s", fp)
					}
				}
				if fp != want {
					t.Errorf("host %q differs from the default host:\n%s\n--- vs ---\n%s", host, fp, want)
				}
			}
			for _, h := range []string{"Cache-Control: no-store", "Vary: Host", "X-Content-Type-Options: nosniff", "Referrer-Policy: no-referrer"} {
				if !strings.Contains(want, h) {
					t.Errorf("neutral response lacks %q:\n%s", h, want)
				}
			}
			for _, banned := range []string{"Etag", "Last-Modified", "Set-Cookie", "Expires"} {
				if strings.Contains(want, banned+":") {
					t.Errorf("neutral response carries %s", banned)
				}
			}
		})
	}
	// The unmapped / pending / unapproved / disabled / db-failure hosts were looked up (same work), the stranger
	// and the malformed authorities were not.
	if n := e.cb.calls.Load(); n != 2*7 {
		t.Errorf("lookups = %d, want 14 (7 configured authorities x 2 routes)", n)
	}
}

func TestPublishedBrandingDiffersOnlyInValuesAndLeaksNothingElse(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	rec := e.get("/public/branding", pbBrand)
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var got, neutral map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	_ = json.Unmarshal(NeutralBrandingBody(), &neutral)
	keys := func(m map[string]any) string {
		var k []string
		for x := range m {
			k = append(k, x)
		}
		sort.Strings(k)
		return strings.Join(k, ",")
	}
	if keys(got) != keys(neutral) || keys(got) != "accent_color,logo_rev,product_name,support_contact,support_text" {
		t.Errorf("schema differs: %s vs %s", keys(got), keys(neutral))
	}
	if got["product_name"] != "Acme Support" || got["accent_color"] != "#35654a" || got["logo_rev"] != logoSHA(e.logo) {
		t.Errorf("values: %v", got)
	}
	body := rec.Body.String()
	for _, banned := range []string{"scope", e.tenant, e.rev.ID, e.rev.Hash, "tenant", "assignment", "uuid"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(banned)) {
			t.Errorf("the public body mentions %q: %s", banned, body)
		}
	}
	for _, h := range []string{"Etag", "Last-Modified", "Set-Cookie"} {
		if rec.Header().Get(h) != "" {
			t.Errorf("published response carries %s", h)
		}
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Vary") != "Host" {
		t.Errorf("headers: %v", rec.Header())
	}
}

func TestLogoRouteServesOnlyTheRequestedApprovedRevisionHash(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	ctx := context.Background()
	good := logoSHA(e.logo)
	rec := e.get("/public/branding/logo?rev="+good, pbBrand)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "image/png" || !bytes.Equal(rec.Body.Bytes(), e.logo) {
		t.Fatalf("published logo: %d %s %d bytes", rec.Code, rec.Header().Get("Content-Type"), rec.Body.Len())
	}
	for _, h := range []string{"Cache-Control: no-store", "X-Content-Type-Options: nosniff", "Content-Security-Policy: default-src 'none'; sandbox"} {
		if !strings.Contains(fingerprint(rec), h) {
			t.Errorf("logo response lacks %q", h)
		}
	}
	neutral := fingerprint(e.get("/public/branding", pbDefault))
	for name, path := range map[string]string{
		"no rev":         "/public/branding/logo",
		"empty rev":      "/public/branding/logo?rev=",
		"wrong rev":      "/public/branding/logo?rev=" + strings.Repeat("a", 64),
		"short prefix":   "/public/branding/logo?rev=" + good[:16],
		"uppercase":      "/public/branding/logo?rev=" + strings.ToUpper(good),
		"suffix":         "/public/branding/logo?rev=" + good + "00",
		"two revs":       "/public/branding/logo?rev=" + strings.Repeat("a", 64) + "&rev=" + good,
		"other param":    "/public/branding/logo?v=" + good,
		"tenant param":   "/public/branding/logo?tenant=" + e.tenant + "&rev=" + strings.Repeat("b", 64),
		"traversal":      "/public/branding/logo?rev=../../etc/passwd",
		"current via ?":  "/public/branding/logo?rev=current",
		"other route":    "/public/branding/logo/?rev=" + good,
		"sibling suffix": "/public/branding/logo.png?rev=" + good,
	} {
		rec := e.get(path, pbBrand)
		if name == "two revs" {
			// Go's Query().Get returns the FIRST value: the wrong one, so the answer is neutral.
		}
		if name == "other route" || name == "sibling suffix" {
			if rec.Code == 200 && rec.Header().Get("Content-Type") == "image/png" {
				t.Errorf("%s: served the logo from a different path", name)
			}
			continue
		}
		if fingerprint(rec) != neutral {
			t.Errorf("%s: not the neutral response: %d %s", name, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	// An Owner edit with a NEW logo does not change what is served: the published revision's bytes only, and the
	// new draft's hash is not served until it is approved.
	in := brandInput("Acme Support Two")
	in.LogoPNG = tinyLogo(t, 200)
	draft, _, err := e.brand.CreateRevision(ctx, e.tenant, "owner", in)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint(e.get("/public/branding/logo?rev="+draft.LogoSHA256, pbBrand)) != neutral {
		t.Error("an unapproved draft's logo is served")
	}
	if rec := e.get("/public/branding/logo?rev="+good, pbBrand); !bytes.Equal(rec.Body.Bytes(), e.logo) {
		t.Error("the published logo changed under an edit")
	}
	// Once the draft is approved the OLD hash stops being served (never a stale hash's bytes).
	rv, _ := e.brand.Review(ctx, e.caller, e.tenant)
	if _, err := e.brand.Approve(ctx, e.caller, e.tenant, BrandingApproval{RevisionID: rv.Draft.ID, Hash: rv.Draft.Hash, AssignmentID: rv.Assignment.ID, Generation: rv.Generation}, nil); err != nil {
		t.Fatal(err)
	}
	if fingerprint(e.get("/public/branding/logo?rev="+good, pbBrand)) != neutral {
		t.Error("the superseded logo hash is still served")
	}
	if rec := e.get("/public/branding/logo?rev="+draft.LogoSHA256, pbBrand); rec.Header().Get("Content-Type") != "image/png" {
		t.Error("the newly approved logo is not served")
	}
}

func TestConditionalAndCachingRequestHeadersAreIgnored(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	for _, path := range []string{"/public/branding", "/public/branding/logo?rev=" + logoSHA(e.logo)} {
		plain := fingerprint(e.get(path, pbBrand))
		for _, hdr := range [][]string{
			{"If-None-Match", `*`}, {"If-None-Match", `"abc"`}, {"If-Modified-Since", "Wed, 21 Oct 2037 07:28:00 GMT"},
			{"Range", "bytes=0-5"}, {"Cache-Control", "max-age=0"}, {"If-Match", "*"},
		} {
			rec := e.get(path, pbBrand, hdr...)
			if rec.Code != 200 || fingerprint(rec) != plain {
				t.Errorf("%s with %v: %d (conditional header honoured)", path, hdr, rec.Code)
			}
		}
	}
}

func TestOnlyHostSelectsTheBrand(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	neutral := fingerprint(e.get("/public/branding", pbDefault))
	for _, c := range []struct {
		name string
		host string
		path string
		hdr  []string
	}{
		{"tenant query on the default host", pbDefault, "/public/branding?tenant=acme&host=" + pbBrand, nil},
		{"X-Forwarded-Host", pbDefault, "/public/branding", []string{"X-Forwarded-Host", pbBrand}},
		{"Forwarded", pbDefault, "/public/branding", []string{"Forwarded", "host=" + pbBrand}},
		{"X-Original-Host", pbDefault, "/public/branding", []string{"X-Original-Host", pbBrand}},
		{"Origin", pbDefault, "/public/branding", []string{"Origin", "https://" + pbBrand}},
		{"Referer", pbDefault, "/public/branding", []string{"Referer", "https://" + pbBrand + "/join"}},
		{"cookie", pbDefault, "/public/branding", []string{"Cookie", "tenant=" + e.tenant}},
	} {
		if fp := fingerprint(e.get(c.path, c.host, c.hdr...)); fp != neutral {
			t.Errorf("%s changed the answer", c.name)
		}
	}
	// And the real host is case- and dot-insensitive, port 443 only.
	for _, h := range []string{"ACME.example.test", "acme.example.test.", "acme.example.test:443"} {
		if rec := e.get("/public/branding", h); !strings.Contains(rec.Body.String(), "Acme Support") {
			t.Errorf("host %q: %s", h, rec.Body.String())
		}
	}
}

func TestThemingOffAnswersNeutralWithoutTouchingTheDatabase(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	off, _ := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{pbDefault}, PublicAuthorities: []string{pbDefault, pbBrand}, Theming: false})
	e.srv.HostPolicy = off
	neutral := fingerprint(e.get("/public/branding", pbDefault))
	if fp := fingerprint(e.get("/public/branding", pbBrand)); fp != neutral {
		t.Errorf("an approved host publishes with CP_HOST_THEMING off:\n%s", fp)
	}
	e.srv.HostPolicy = nil
	if fp := fingerprint(e.get("/public/branding", pbBrand)); fp != neutral {
		t.Error("no host policy at all must also be neutral")
	}
	e.srv.HostPolicy = off
	e.srv.BrandingRevisions = nil
	if fp := fingerprint(e.get("/public/branding", pbBrand)); fp != neutral {
		t.Error("no store must be neutral")
	}
	if e.cb.calls.Load() != 0 {
		t.Errorf("%d lookups with theming off", e.cb.calls.Load())
	}
}

func TestEveryRequestIsItsOwnFreshReadWithNoCoalescing(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: 300 * time.Millisecond, WorkDeadline: 250 * time.Millisecond})
	e.cb.gate, e.cb.readDone = make(chan struct{}), make(chan struct{})
	var first, second *httptest.ResponseRecorder
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); first = e.get("/public/branding", pbBrand) }()
	<-e.cb.readDone // request 1 has READ "published" and is parked
	if err := e.brand.Withdraw(context.Background(), e.caller, e.tenant, nil); err != nil {
		t.Fatal(err)
	}
	wg.Add(1)
	go func() { defer wg.Done(); second = e.get("/public/branding", pbBrand) }() // reads entirely after the flip
	eventually(t, time.Second, "the second read", func() bool { return e.cb.calls.Load() >= 2 })
	close(e.cb.gate) // request 1 finishes its (already read) lookup inside its own work window
	wg.Wait()
	if !strings.Contains(first.Body.String(), "Acme Support") {
		t.Errorf("request 1 read the state at ITS read time (published): %s", first.Body.String())
	}
	if second.Body.String() != string(NeutralBrandingBody()) {
		t.Errorf("request 2 must see the flipped state, not a shared in-flight result: %s", second.Body.String())
	}
	if e.cb.calls.Load() != 2 {
		t.Errorf("lookups = %d, want one per request", e.cb.calls.Load())
	}
}

func TestStateFlipsAreVisibleOnTheVeryNextRequest(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	ctx := context.Background()
	published := func() bool { return strings.Contains(e.get("/public/branding", pbBrand).Body.String(), "Acme Support") }
	if !published() {
		t.Fatal("setup")
	}
	e.mu.Lock()
	e.susp[e.tenant] = true
	e.mu.Unlock()
	if published() {
		t.Error("suspension not immediate")
	}
	e.mu.Lock()
	e.susp[e.tenant] = false
	e.mu.Unlock()
	if !published() {
		t.Error("resume not immediate")
	}
	rv, _ := e.brand.Review(ctx, e.caller, e.tenant)
	if _, err := e.hosts.Release(ctx, e.caller, rv.Assignment.ID, 30, map[string]any{"reason": "t"}); err != nil {
		t.Fatal(err)
	}
	if published() {
		t.Error("release not immediate")
	}
}

func TestStoredValuesAreRevalidatedOnTheRead(t *testing.T) {
	good := &PublishedBranding{ProductName: "Acme Support", AccentColor: "#35654a", SupportText: "hi", Contact: BrandContact{"phone", "15550100199"}}
	if r := renderPublishedBranding(good, false, ""); r == neutralBrandingResponse {
		t.Fatal("a good row rendered neutral")
	}
	bad := []*PublishedBranding{
		{ProductName: "Acme" + U(0x202e) + "Support", AccentColor: "#35654a"},
		{ProductName: "Acme Support", AccentColor: "#ffff00"},
		{ProductName: "Acme Support", AccentColor: "#35654a", SupportText: "a" + U(0x200b) + "b"},
		{ProductName: "Acme Support", AccentColor: "#35654a", Contact: BrandContact{"url", "http://x.example.com"}},
		{ProductName: " Acme Support", AccentColor: "#35654a"},
		{ProductName: "Acme Support", AccentColor: "#35654a", LogoSHA256: "xyz"},
	}
	for i, b := range bad {
		if r := renderPublishedBranding(b, false, ""); r != neutralBrandingResponse {
			t.Errorf("bad row %d published: %s", i, r.body)
		}
	}
	// A logo whose bytes do not hash to the stored hash is never served.
	png := tinyLogo(t, 5)
	row := &PublishedBranding{ProductName: "Acme Support", LogoSHA256: strings.Repeat("a", 64), LogoPNG: png}
	if r := renderPublishedBranding(row, true, row.LogoSHA256); r != neutralBrandingResponse {
		t.Error("mismatched logo bytes served")
	}
}

// ---- schedule, admission and bounds -------------------------------------------------------------------------

type firstWrite struct {
	*httptest.ResponseRecorder
	first atomic.Int64
}

func (f *firstWrite) WriteHeader(c int) {
	f.first.CompareAndSwap(0, time.Now().UnixNano())
	f.ResponseRecorder.WriteHeader(c)
}

func (f *firstWrite) Write(p []byte) (int, error) {
	f.first.CompareAndSwap(0, time.Now().UnixNano())
	return f.ResponseRecorder.Write(p)
}

// No header byte is written before 150 ms, for every outcome, on both routes.
func TestNoByteIsWrittenBeforeTheReleaseTime(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{})
	e.srv.BrandingTuning.RatePerMinute = -1
	for _, host := range []string{pbBrand, pbDefault, pbUnmapped, pbPending, pbUnappr, pbDisabled, pbDBFail, pbStranger} {
		for _, path := range []string{"/public/branding", "/public/branding/logo?rev=" + logoSHA(e.logo)} {
			req := httptest.NewRequest("GET", path, nil)
			req.Host, req.RemoteAddr = host, nextIP()+":1"
			w := &firstWrite{ResponseRecorder: httptest.NewRecorder()}
			start := time.Now()
			e.srv.Handler().ServeHTTP(w, req)
			d := time.Duration(w.first.Load() - start.UnixNano())
			if d < DefaultBrandingFloor {
				t.Errorf("%s %s: first byte at %v, before the %v floor", host, path, d, DefaultBrandingFloor)
			}
			if d > DefaultBrandingFloor+DefaultBrandingJitter+250*time.Millisecond {
				t.Errorf("%s %s: first byte at %v, far past the release time", host, path, d)
			}
		}
	}
}

func medianP95(d []time.Duration) (time.Duration, time.Duration) {
	s := append([]time.Duration(nil), d...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2], s[(len(s)*95)/100]
}

// Relative timing across the seven neutral states and the published one: every sample is at or above the floor,
// the jitter spreads the releases, and the state classes agree with each other. (The absolute 5 ms / 15 ms
// statistic over 2,000 samples is the isolated release-gate run.)
func TestResponseScheduleIsTheSameForEveryState(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{})
	states := []string{pbBrand, pbDefault, pbLegacy, pbUnmapped, pbPending, pbUnappr, pbDisabled, pbDBFail}
	const per = 30
	lat := map[string][]time.Duration{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 12)
	for _, h := range states {
		for i := 0; i < per; i++ {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				start := time.Now()
				rec := e.get("/public/branding", h)
				d := time.Since(start)
				if rec.Code != 200 {
					t.Errorf("%s: %d", h, rec.Code)
				}
				mu.Lock()
				lat[h] = append(lat[h], d)
				mu.Unlock()
			}()
		}
	}
	wg.Wait()
	var all []time.Duration
	meds := map[string]time.Duration{}
	for _, h := range states {
		m, _ := medianP95(lat[h])
		meds[h] = m
		all = append(all, lat[h]...)
		for _, d := range lat[h] {
			if d < DefaultBrandingFloor {
				t.Errorf("%s: a response after %v, below the %v floor", h, d, DefaultBrandingFloor)
				break
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	if spread := all[len(all)-1*len(all)/10] - all[0]; spread < 3*time.Millisecond {
		t.Errorf("no jitter: 90th percentile minus minimum = %v", spread)
	}
	for _, a := range states {
		for _, b := range states {
			if d := meds[a] - meds[b]; d > 25*time.Millisecond || d < -25*time.Millisecond {
				t.Errorf("median(%s)=%v vs median(%s)=%v", a, meds[a], b, meds[b])
			}
		}
	}
}

func TestAdmissionCapsAreUniformImmediateAndPrecedeAllWork(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{AdmitGlobal: 6, AdmitPerIP: 2, Floor: 500 * time.Millisecond, Jitter: 1})
	// Per-IP: 2 admitted, the rest an immediate identical 429, and no lookup was spent on a 429.
	var wg sync.WaitGroup
	type res struct {
		fp   string
		code int
		took time.Duration
	}
	out := make([]res, 12)
	for i := range out {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			host := []string{pbBrand, pbDefault, pbUnmapped}[i%3]
			rec := e.getFrom("10.9.9.9", "/public/branding", host)
			out[i] = res{fingerprint(rec), rec.Code, time.Since(start)}
		}()
	}
	wg.Wait()
	ok, rej := 0, ""
	for _, r := range out {
		if r.code == 200 {
			ok++
			continue
		}
		if r.code != 429 {
			t.Fatalf("status %d", r.code)
		}
		if rej == "" {
			rej = r.fp
		}
		if r.fp != rej {
			t.Errorf("429s differ across hosts:\n%s\n---\n%s", r.fp, rej)
		}
		if r.took > 200*time.Millisecond {
			t.Errorf("a 429 took %v: it must be immediate (no queue)", r.took)
		}
	}
	if ok != 2 {
		t.Errorf("one IP got %d admissions, want 2", ok)
	}
	if !strings.Contains(rej, "Retry-After: 1") || !strings.Contains(rej, "Cache-Control: no-store") {
		t.Errorf("429 shape: %s", rej)
	}
	if n := e.cb.calls.Load(); n > 2 {
		t.Errorf("%d lookups for 2 admitted requests: a rejected request touched the database", n)
	}
	// Global: 6 distinct IPs admitted, the 7th refused.
	e.cb.calls.Store(0)
	var wg2 sync.WaitGroup
	codes := make([]int, 9)
	for i := range codes {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			codes[i] = e.getFrom(fmt.Sprintf("10.8.8.%d", i+1), "/public/branding", pbBrand).Code
		}()
	}
	wg2.Wait()
	n200 := 0
	for _, c := range codes {
		if c == 200 {
			n200++
		}
	}
	if n200 != 6 {
		t.Errorf("%d admitted globally, want 6: %v", n200, codes)
	}
	// The permits all came back (requests asleep in the floor counted, and are gone).
	if in, keys := e.srv.brandingPool().stats(); in != 0 || keys != 0 {
		t.Errorf("permits not released: inflight=%d keys=%d", in, keys)
	}
}

func TestDefaultAdmissionIs128GlobalAnd4PerIP(t *testing.T) {
	var s Server
	p := s.brandingPool()
	if p.maxGlobal != 128 || p.maxPerKey != 4 {
		t.Errorf("caps %d/%d", p.maxGlobal, p.maxPerKey)
	}
	if DefaultBrandingFloor != 150*time.Millisecond || DefaultBrandingJitter != 10*time.Millisecond || DefaultBrandingWorkDeadline != 100*time.Millisecond {
		t.Error("schedule constants drifted from docs/66 2d.1")
	}
	if rel := brandingExchangeLimit - brandingWriteSlack; rel != 1840*time.Millisecond {
		t.Errorf("write deadline after release = %v", rel)
	}
}

func TestPerIPRateBudgetIsSeparateAndUniform(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick, RatePerMinute: 5})
	var last *httptest.ResponseRecorder
	for i := 0; i < 8; i++ {
		last = e.getFrom("10.7.7.7", "/public/branding", pbBrand)
		if want := i >= 5; (last.Code == 429) != want {
			t.Fatalf("request %d: %d", i+1, last.Code)
		}
	}
	if other := e.getFrom("10.7.7.8", "/public/branding", pbBrand); other.Code != 200 {
		t.Error("another IP is throttled by this IP's budget")
	}
	if !strings.Contains(last.Body.String(), "too many requests") || last.Header().Get("Retry-After") == "" {
		t.Errorf("rate 429: %s", last.Body.String())
	}
	// The JSON and logo routes share ONE budget.
	e2 := newPBEnv(t, BrandingTuning{Floor: quick, RatePerMinute: 3})
	for i, p := range []string{"/public/branding", "/public/branding/logo", "/public/branding", "/public/branding/logo"} {
		if code := e2.getFrom("10.6.6.6", p, pbBrand).Code; (code == 429) != (i == 3) {
			t.Errorf("request %d (%s): %d", i+1, p, code)
		}
	}
	// A request over the budget does not touch the credential throttle (no failure is recorded anywhere).
	if th := e.srv.throttle(); th != nil {
		th.mu.Lock()
		n := len(th.entries)
		th.mu.Unlock()
		if n != 0 {
			t.Errorf("the public route recorded %d throttle entries", n)
		}
	}
}

func TestRateBudgetMapIsBounded(t *testing.T) {
	b := newRateBudget(5, time.Minute, 50)
	for i := 0; i < 1000; i++ {
		b.Allow(fmt.Sprintf("k%d", i))
	}
	if n := b.size(); n > 50 {
		t.Errorf("%d keys, cap 50", n)
	}
}

func TestBodiesAndOtherMethodsAreRefused(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{AdmitGlobal: 1, AdmitPerIP: 1, Floor: 400 * time.Millisecond, Jitter: 1})
	// Hold the only permit.
	done := make(chan struct{})
	go func() { e.getFrom("10.5.5.5", "/public/branding", pbBrand); close(done) }()
	time.Sleep(100 * time.Millisecond)
	for name, mk := range map[string]func() *http.Request{
		"content-length": func() *http.Request {
			r := httptest.NewRequest("GET", "/public/branding", strings.NewReader("hello"))
			return r
		},
		"chunked": func() *http.Request {
			r := httptest.NewRequest("GET", "/public/branding", strings.NewReader("hello"))
			r.ContentLength = -1
			r.TransferEncoding = []string{"chunked"}
			return r
		},
	} {
		req := mk()
		req.Host, req.RemoteAddr = pbBrand, "10.5.5.6:1"
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, req)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "bad request") {
			t.Errorf("%s: %d %s (a body is a uniform 400, decided BEFORE admission)", name, rec.Code, rec.Body.String())
		}
	}
	<-done
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		req := httptest.NewRequest(m, "/public/branding", strings.NewReader("x"))
		req.Host, req.RemoteAddr = pbBrand, "10.5.5.7:1"
		rec := httptest.NewRecorder()
		e.srv.Handler().ServeHTTP(rec, req)
		// Not the branding handler: the mux sends other methods down the protected chain (401 in production; this
		// bare test server has no auth wiring, so the recovery middleware answers 500).
		if rec.Code == 200 || strings.Contains(rec.Body.String(), "product_name") {
			t.Errorf("%s: %d %s", m, rec.Code, rec.Body.String())
		}
	}
	if e.cb.calls.Load() != 1 {
		t.Errorf("refused requests reached the store: %d lookups", e.cb.calls.Load())
	}
}

func TestSlowRenderPathIsCutAtTheWorkDeadlineAndReleasedOnSchedule(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{})
	var slow atomic.Bool
	e.srv.brandRenderHook = func(ctx context.Context, logo bool) {
		if slow.Load() {
			time.Sleep(160 * time.Millisecond) // a render stuck beyond the 100 ms window
		}
	}
	before := e.srv.BrandingCutoffTotal("json")
	start := time.Now()
	fast := e.get("/public/branding", pbBrand)
	fastTook := time.Since(start)
	slow.Store(true)
	start = time.Now()
	cut := e.get("/public/branding", pbBrand)
	cutTook := time.Since(start)
	if !strings.Contains(fast.Body.String(), "Acme Support") {
		t.Fatal("setup")
	}
	if cut.Body.String() != string(NeutralBrandingBody()) {
		t.Errorf("a slow render must yield the neutral content: %s", cut.Body.String())
	}
	if cutTook < DefaultBrandingFloor || cutTook > fastTook+60*time.Millisecond {
		t.Errorf("cut response after %v, normal after %v: the schedule must not move", cutTook, fastTook)
	}
	if e.srv.BrandingCutoffTotal("json") != before+1 {
		t.Errorf("branding_cutoff_total{route=json} = %d, want %d", e.srv.BrandingCutoffTotal("json"), before+1)
	}
	// Permits come back when the stuck render finishes.
	eventually(t, time.Second, "permits", func() bool { in, _ := e.srv.brandingPool().stats(); return in == 0 })
}

func TestStalledStoreLookupIsCutAtTheWorkDeadline(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{})
	e.cb.delay = 400 * time.Millisecond // ignores nothing: honours ctx, but takes longer than the window
	start := time.Now()
	rec := e.get("/public/branding", pbBrand)
	took := time.Since(start)
	if rec.Body.String() != string(NeutralBrandingBody()) {
		t.Errorf("a stalled read must yield neutral: %s", rec.Body.String())
	}
	if took < DefaultBrandingFloor || took > DefaultBrandingFloor+DefaultBrandingJitter+120*time.Millisecond {
		t.Errorf("released after %v", took)
	}
	if e.srv.BrandingCutoffTotal("json") != 1 || e.srv.BrandingCutoffTotal("logo") != 0 {
		t.Errorf("cutoff counters json=%d logo=%d", e.srv.BrandingCutoffTotal("json"), e.srv.BrandingCutoffTotal("logo"))
	}
	e.get("/public/branding/logo?rev="+logoSHA(e.logo), pbBrand)
	if e.srv.BrandingCutoffTotal("logo") != 1 {
		t.Errorf("logo cutoff counter = %d", e.srv.BrandingCutoffTotal("logo"))
	}
}

// ---- real TCP: a Postgres that never answers -----------------------------------------------------------------

func TestStalledPostgresIsNeutralOnScheduleAndEverythingRecovers(t *testing.T) {
	soak := 4 * time.Second
	for _, mode := range []string{"midquery", "silent"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakePG(t, mode)
			pool := f.pool(t)
			policy, _ := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{pbDefault}, PublicAuthorities: []string{pbDefault, pbBrand}, Theming: true})
			srv := &Server{HostPolicy: policy, BrandingRevisions: NewPgBrandingRevisionStore(pool, nil),
				BrandingTuning: BrandingTuning{AdmitGlobal: 24, AdmitPerIP: 4, RatePerMinute: -1}}
			get := func(ip, host string) (*httptest.ResponseRecorder, time.Duration) {
				req := httptest.NewRequest("GET", "/public/branding", nil)
				req.Host, req.RemoteAddr = host, ip+":1"
				rec := httptest.NewRecorder()
				start := time.Now()
				srv.Handler().ServeHTTP(rec, req)
				return rec, time.Since(start)
			}
			runtime.GC()
			baseline := runtime.NumGoroutine()
			deadline := time.Now().Add(soak)
			var cutoffs int64
			wave := 0
			for time.Now().Before(deadline) {
				wave++
				var wg sync.WaitGroup
				for i := 0; i < 12; i++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						rec, d := get(fmt.Sprintf("10.60.%d.%d", wave%200, i+1), []string{pbBrand, pbDefault}[i%2])
						if rec.Code != 200 || rec.Body.String() != string(NeutralBrandingBody()) {
							t.Errorf("wave %d: %d %q, want the neutral response", wave, rec.Code, rec.Body.String())
						}
						if d < DefaultBrandingFloor || d > 700*time.Millisecond {
							t.Errorf("wave %d: released after %v, want ~150-160 ms (floor + jitter), not the database", wave, d)
						}
					}()
				}
				wg.Wait()
				rec := eventually(t, 1250*time.Millisecond, "permits, connections and goroutines", func() bool {
					in, _ := srv.brandingPool().stats()
					st := pool.Stat()
					return in == 0 && st.AcquiredConns() == 0 && st.TotalConns() <= 8 && int32(st.TotalConns()) == f.open.Load()
				})
				if rec > 1250*time.Millisecond {
					t.Errorf("recovery took %v", rec)
				}
				cutoffs = srv.BrandingCutoffTotal("json")
			}
			eventually(t, 2*time.Second, "goroutine baseline", func() bool { return runtime.NumGoroutine() <= baseline+6 })
			if cutoffs < int64(12*wave)-int64(wave) {
				t.Errorf("branding_cutoff_total = %d after %d waves of 12", cutoffs, wave)
			}

			// Permits exhausted by stalled lookups: the uniform 429, then recovery.
			srv.BrandingTuning.AdmitGlobal = 3
			srv.brandAdmitOnce = sync.Once{}
			srv.brandAdmit = nil
			var wg sync.WaitGroup
			codes := make([]int, 8)
			for i := range codes {
				wg.Add(1)
				go func() {
					defer wg.Done()
					rec, _ := get(fmt.Sprintf("10.61.0.%d", i+1), pbBrand)
					codes[i] = rec.Code
				}()
			}
			wg.Wait()
			n429 := 0
			for _, c := range codes {
				if c == 429 {
					n429++
				}
			}
			if n429 != 5 {
				t.Errorf("with 3 permits and 8 simultaneous stalled lookups, %d were 429, want 5: %v", n429, codes)
			}
			eventually(t, 1500*time.Millisecond, "permits after the stall", func() bool { in, _ := srv.brandingPool().stats(); return in == 0 })
			if rec, _ := get("10.62.0.1", pbBrand); rec.Code != 200 {
				t.Errorf("after recovery: %d", rec.Code)
			}
		})
	}
}

// A client that sends its request and never reads leaves nothing behind: the response is buffered and written in
// one go, so the handler returns and every permit is released.
func TestStalledClientHoldsNothingAfterTheHandlerReturns(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{RatePerMinute: -1})
	ts := httptest.NewUnstartedServer(e.srv.Handler())
	ts.Config = NewPublicServer("", e.srv.Handler(), PublicServerConfig{})
	ts.Start()
	defer ts.Close()
	var conns []net.Conn
	for i := 0; i < 8; i++ {
		c, err := net.Dial("tcp", ts.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		fmt.Fprintf(c, "GET /public/branding HTTP/1.1\r\nHost: %s\r\n\r\n", pbBrand)
	}
	eventually(t, 2*time.Second, "permits released although no client reads", func() bool { in, _ := e.srv.brandingPool().stats(); return in == 0 })
	for _, c := range conns {
		_ = c.Close()
	}
}

func TestAuthorityGateStillAppliesToPublicBrandingRoutes(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: quick})
	secret := strings.Repeat("s", 32)
	p, _ := NewHostPolicy(HostPolicyConfig{DefaultHosts: []string{pbDefault}, PublicAuthorities: []string{pbDefault, pbBrand}, EdgeSecret: secret, Theming: true})
	e.srv.HostPolicy = p
	marked := func(host string) *httptest.ResponseRecorder {
		return e.get("/public/branding", host, EdgeMarkerHeader, secret)
	}
	if rec := marked(pbBrand); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Acme Support") {
		t.Errorf("listed authority behind the marker: %d %s", rec.Code, rec.Body.String())
	}
	before := e.cb.calls.Load()
	if rec := marked(pbStranger); rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("an unlisted authority behind the marker: %d", rec.Code)
	}
	if e.cb.calls.Load() != before {
		t.Error("a refused authority reached the store")
	}
	if rec := e.get("/public/branding", pbBrand, EdgeMarkerHeader, "wrong"); rec.Code != http.StatusMisdirectedRequest {
		t.Errorf("a forged marker: %d", rec.Code)
	}
}

// A lookup that IGNORES cancellation keeps its admission permit after the response has gone out (docs/66 2e.1):
// the caps bound outstanding cleanup work, so a stalled database cannot accumulate unbounded goroutines.
func TestBrandingLookupThatIgnoresCancellationKeepsItsPermit(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{AdmitGlobal: 2})
	e.cb.delay, e.cb.deaf = 700*time.Millisecond, true
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			rec := e.get("/public/branding", pbBrand)
			if rec.Body.String() != string(NeutralBrandingBody()) || time.Since(start) > 400*time.Millisecond {
				t.Errorf("deaf lookup: %d after %v: %s", rec.Code, time.Since(start), rec.Body.String())
			}
		}()
	}
	wg.Wait() // both responses have been RELEASED (~150 ms); both lookups are still stuck holding the permits
	if in, _ := e.srv.brandingPool().stats(); in != 2 {
		t.Fatalf("in flight = %d after the responses, want 2 (the stuck lookups hold their permits)", in)
	}
	rec := e.get("/public/branding", pbDefault)
	if rec.Code != 429 || !strings.Contains(rec.Body.String(), "too many requests") {
		t.Errorf("permits exhausted by stuck lookups: %d %s, want the uniform 429", rec.Code, rec.Body.String())
	}
	eventually(t, 2*time.Second, "permits after the stall clears", func() bool { in, _ := e.srv.brandingPool().stats(); return in == 0 })
	if rec := e.get("/public/branding", pbBrand); rec.Code != 200 {
		t.Errorf("recovery: %d", rec.Code)
	}
}

func TestPublicLookupStatementTimeoutConstantsAgree(t *testing.T) {
	src, err := os.ReadFile("pgstore_brandrev.go")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("SET LOCAL statement_timeout = %d", PublicLookupStatementTimeout.Milliseconds())
	if !strings.Contains(string(src), "\""+want+"\"") {
		t.Errorf("the lookup's SQL does not carry %q", want)
	}
	if PublicLookupStatementTimeout != DefaultBrandingWorkDeadline {
		t.Errorf("statement timeout %v differs from the work deadline %v (docs/66 2d.1: both 100 ms)", PublicLookupStatementTimeout, DefaultBrandingWorkDeadline)
	}
}

// gen is the tenant's current review generation (the operator's review would return it).
func (e *pbEnv) gen(tenant string) int64 {
	rv, err := e.brand.Review(context.Background(), e.caller, tenant)
	if err != nil {
		panic(err)
	}
	return rv.Generation
}

// C1: IP churn must not reset a LIVE client's budget; a full map of live windows refuses unseen keys.
func TestRateBudgetNeverEvictsALiveWindow(t *testing.T) {
	now := time.Unix(1000, 0)
	b := newRateBudget(2, time.Minute, 3)
	b.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		b.Allow("victim")
	}
	if b.Allow("victim") {
		t.Fatal("setup: the victim should be over budget")
	}
	b.Allow("k2")
	b.Allow("k3")             // the map is full of LIVE windows (victim, k2, k3)
	for i := 0; i < 50; i++ { // churn of unseen keys
		if b.Allow(fmt.Sprintf("churn%d", i)) {
			t.Fatalf("unseen key churn%d admitted into a full map of live windows", i)
		}
	}
	if b.Allow("victim") {
		t.Fatal("the churn evicted the victim's live counter and handed it a fresh budget")
	}
	if n := b.size(); n != 3 {
		t.Errorf("size %d, want 3", n)
	}
	now = now.Add(2 * time.Minute) // windows expire: unseen keys are admitted again
	if !b.Allow("late") {
		t.Error("an expired map still refuses new keys")
	}
	// The per-tenant logo budget is the same type.
	e := newBrandSrv(t, RoleOwner, "00000000-0000-0000-0000-0000000000dd")
	e.srv.logoRate = newRateBudget(1, time.Minute, 2)
	e.srv.logoRateOnce.Do(func() {})
	if !e.srv.logoBudget().Allow("t1") || e.srv.logoBudget().Allow("t1") {
		t.Error("logo budget setup")
	}
	e.srv.logoBudget().Allow("t2")
	for i := 0; i < 20; i++ {
		e.srv.logoBudget().Allow(fmt.Sprintf("x%d", i))
	}
	if e.srv.logoBudget().Allow("t1") {
		t.Error("tenant churn reset another tenant's logo budget")
	}
}

type brandDeadlineRecorder struct {
	*httptest.ResponseRecorder
	mu  sync.Mutex
	dls []time.Time
}

func (d *brandDeadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	d.dls = append(d.dls, t)
	d.mu.Unlock()
	return nil
}

// C2: a late release (floor near the 2 s bound) must not push the write deadline past admission + 2 s.
func TestLateReleaseNeverExtendsTheExchangePastTwoSeconds(t *testing.T) {
	e := newPBEnv(t, BrandingTuning{Floor: 1800 * time.Millisecond, Jitter: 1})
	req := httptest.NewRequest("GET", "/public/branding", nil)
	req.Host, req.RemoteAddr = pbBrand, nextIP()+":1"
	w := &brandDeadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	start := time.Now()
	e.srv.Handler().ServeHTTP(w, req)
	if len(w.dls) == 0 {
		t.Fatal("no write deadline was set")
	}
	limit := start.Add(brandingExchangeLimit + 50*time.Millisecond)
	for i, d := range w.dls {
		if d.After(limit) {
			t.Errorf("deadline #%d is %v after the start: past the 2 s bound", i, d.Sub(start))
		}
	}
	if last := w.dls[len(w.dls)-1]; last.Before(start.Add(1500 * time.Millisecond)) {
		t.Errorf("the final deadline %v is implausibly early", last.Sub(start))
	}
}
