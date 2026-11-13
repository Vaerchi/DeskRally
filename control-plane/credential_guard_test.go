package controlplane

// Tests for credential_guard.go: the shape check, the per-source budget of failed lookups, the global cap on
// concurrent unproven lookups, and the logout path. Every claim is proved with a COUNTING store: "no store call"
// is the property, so the store is what is asserted on, not the status code alone.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingSessionStore counts the lookups that reach the session store. gate/entered, when set, hold every
// GetByTokenHash open so a test can saturate the global cap deterministically.
type countingSessionStore struct {
	SessionStore
	gets, revokes atomic.Int64
	gate          chan struct{}
	entered       chan struct{}
	// fault, when set, makes every lookup fail like a database that is down (not a credential verdict).
	fault atomic.Bool
}

func (c *countingSessionStore) GetByTokenHash(ctx context.Context, h []byte) (*Session, error) {
	c.gets.Add(1)
	if c.entered != nil {
		c.entered <- struct{}{}
	}
	if c.gate != nil {
		<-c.gate
	}
	if c.fault.Load() {
		return nil, errors.New("conn refused")
	}
	return c.SessionStore.GetByTokenHash(ctx, h)
}

func (c *countingSessionStore) Revoke(ctx context.Context, h []byte) error {
	c.revokes.Add(1)
	return c.SessionStore.Revoke(ctx, h)
}

type countingAPITokenStore struct {
	APITokenStore
	resolves atomic.Int64
	fault    atomic.Bool
}

func (c *countingAPITokenStore) Resolve(ctx context.Context, p string) (*APIToken, error) {
	c.resolves.Add(1)
	if c.fault.Load() {
		return nil, errors.New("conn refused")
	}
	return c.APITokenStore.Resolve(ctx, p)
}

type guardClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *guardClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *guardClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type guardHarness struct {
	t        *testing.T
	h        http.Handler
	store    *countingSessionStore
	apis     *countingAPITokenStore
	rawAPIs  *InMemoryAPITokenStore
	sessions *SessionManager
	guard    *CredentialGuard
	clock    *guardClock
	userID   string
	tenantID string
}

func newGuardHarness(t *testing.T, cfg CredentialGuardConfig) *guardHarness {
	t.Helper()
	clk := &guardClock{t: time.Unix(1_800_000_000, 0)}
	cfg.Now = clk.Now
	guard := NewCredentialGuard(cfg)
	users := NewInMemoryUserStore()
	store := &countingSessionStore{SessionStore: NewInMemorySessionStore()}
	sessions := NewSessionManager(store)
	rawAPIs := NewInMemoryAPITokenStore()
	apis := &countingAPITokenStore{APITokenStore: rawAPIs}
	const tenant, user = "tenant-guard", "user-guard"
	users.AddUser(&AuthUser{ID: user, TenantID: tenant, Email: "g@guard.test"},
		NewGrant(user, tenant, NewMembership(RoleOwner, AllGroups())))
	auth := &GuardedAuthenticator{
		Guard: guard,
		Next: &APITokenAuthenticator{
			Tokens: apis,
			Next:   &SessionAuthenticator{Sessions: sessions, Users: users},
		},
	}
	srv := NewServer(auth, NoopBinder{})
	srv.AuthAPI = &AuthService{Users: users, Sessions: sessions, Guard: guard, Issuer: "RMT"}
	return &guardHarness{t: t, h: srv.Handler(), store: store, apis: apis, rawAPIs: rawAPIs, sessions: sessions,
		guard: guard, clock: clk, userID: user, tenantID: tenant}
}

// session mints a valid session straight into the store (as a login on ANOTHER replica would), so the guard
// has never seen its token: this is the "unproven but valid" case.
func (g *guardHarness) session() string {
	g.t.Helper()
	tok, _, err := g.sessions.Issue(context.Background(), g.tenantID, g.userID, time.Time{})
	if err != nil {
		g.t.Fatalf("issue: %v", err)
	}
	return tok
}

func (g *guardHarness) apiToken() string {
	g.t.Helper()
	tok, _, err := g.rawAPIs.Mint(context.Background(), g.tenantID, "t", []Capability{CapManageTenant}, g.userID, nil)
	if err != nil {
		g.t.Fatalf("mint: %v", err)
	}
	return tok
}

// do sends one request to the protected chain (GET /auth/session: 204 when authenticated).
func (g *guardHarness) do(method, path, cookieTok, bearer, remote string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	r.RemoteAddr = remote + ":4000"
	if cookieTok != "" {
		r.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: cookieTok})
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	g.h.ServeHTTP(rec, r)
	return rec
}

func (g *guardHarness) get(cookieTok, bearer, remote string) *httptest.ResponseRecorder {
	return g.do("GET", "/auth/session", cookieTok, bearer, remote)
}

func (g *guardHarness) logout(bearer, remote string) *httptest.ResponseRecorder {
	return g.do("POST", "/auth/logout", "", bearer, remote)
}

// garbage returns the i-th token that has a VALID session shape but names nothing.
func garbage(i int) string {
	return base64.RawURLEncoding.EncodeToString(HashToken(fmt.Sprintf("garbage-%d", i)))
}

func (g *guardHarness) wantStatus(rec *httptest.ResponseRecorder, want int, what string) {
	g.t.Helper()
	if rec.Code != want {
		g.t.Fatalf("%s = %d (%s), want %d", what, rec.Code, strings.TrimSpace(rec.Body.String()), want)
	}
}

func (g *guardHarness) wantGets(n int64, what string) {
	g.t.Helper()
	if got := g.store.gets.Load(); got != n {
		g.t.Fatalf("%s: session store lookups = %d, want %d", what, got, n)
	}
}

// ---- shape -------------------------------------------------------------------------------------------------

func TestCredentialShape_ValidMintedTokensPass(t *testing.T) {
	// Every token the process mints must pass, many times over: a check that rejects a valid token is an outage.
	for i := 0; i < 500; i++ {
		s, err := newSessionToken()
		if err != nil {
			t.Fatal(err)
		}
		if !validSessionTokenShape(s) {
			t.Fatalf("minted session token %q rejected", s)
		}
		a, err := newAPITokenSecret()
		if err != nil {
			t.Fatal(err)
		}
		if !validAPITokenShape(a) {
			t.Fatalf("minted API token %q rejected", a)
		}
		if validSessionTokenShape(a) {
			t.Fatalf("API token %q passes the SESSION shape", a)
		}
		if validAPITokenShape(s) {
			t.Fatalf("session token %q passes the API shape", s)
		}
	}
	// Extreme alphabet members (the encoder emits both '-' and '_').
	if !validSessionTokenShape(strings.Repeat("-", 43)) || !validSessionTokenShape(strings.Repeat("_", 43)) {
		t.Fatal("'-' / '_' are in the alphabet")
	}
}

func TestCredentialShape_WrongShapesRejected(t *testing.T) {
	ok := garbage(1)
	sessionBad := []string{
		"", "x", ok[:42], ok + "A", ok[:42] + "+", ok[:42] + "/", ok[:42] + "=", ok[:42] + " ", ok[:42] + "é",
		ok[:42] + "\x00", " " + ok[:42], ok[:21] + "." + ok[22:],
		"rmt_api_" + ok, // an API token is not a session token
	}
	for _, s := range sessionBad {
		if validSessionTokenShape(s) {
			t.Errorf("session shape accepted %q", s)
		}
	}
	apiBad := []string{
		"", "rmt_api_", "rmt_api_" + ok[:42], "rmt_api_" + ok + "A", "rmt_api_" + ok[:42] + "+", "rmt_api" + ok,
		"RMT_API_" + ok, ok, "xmt_api_" + ok,
	}
	for _, s := range apiBad {
		if validAPITokenShape(s) {
			t.Errorf("API shape accepted %q", s)
		}
	}
}

func TestCredentialGuard_WrongShapeNeverReachesAStore(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{})
	ok := garbage(1)
	cookieBad := []string{"x", ok[:42], ok + "A", "rmt_api_" + ok, ok[:42] + "+", strings.Repeat("A", 4000)}
	for _, c := range cookieBad {
		g.wantStatus(g.get(c, "", "198.51.100.1"), 401, "cookie "+c[:min(len(c), 12)])
	}
	bearerBad := []string{"x", ok[:42], ok + "A", ok[:42] + "="}
	for _, b := range bearerBad {
		g.wantStatus(g.get("", b, "198.51.100.1"), 401, "bearer "+b)
	}
	apiBad := []string{"rmt_api_", "rmt_api_x", "rmt_api_" + ok[:42], "rmt_api_" + ok + "A", "rmt_api_" + ok[:42] + "="}
	for _, b := range apiBad {
		g.wantStatus(g.get("", b, "198.51.100.1"), 401, "api bearer "+b)
	}
	// A bad-shaped API header beside a perfectly VALID cookie: the authenticators read the header as the API
	// credential (headerBearerToken wins for the prefix), so it is refused — and still without a lookup.
	valid := g.session()
	g.wantStatus(g.get(valid, "rmt_api_"+ok[:42], "198.51.100.1"), 401, "valid cookie + bad api header")
	g.wantGets(0, "wrong shapes")
	if n := g.apis.resolves.Load(); n != 0 {
		t.Fatalf("API store resolves = %d, want 0", n)
	}
	// Shape rejections are free: they must not have charged the budget either.
	if n := g.guard.trackedSources(); n != 0 {
		t.Fatalf("shape rejections charged a source (%d tracked)", n)
	}
}

// ---- budget ------------------------------------------------------------------------------------------------

func TestCredentialGuard_BudgetThen429WithoutStoreCall(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 3})
	const src = "198.51.100.7"
	for i := 0; i < 3; i++ {
		g.wantStatus(g.get(garbage(i), "", src), 401, "failure within budget")
	}
	g.wantGets(3, "within budget")
	for i := 3; i < 10; i++ {
		rec := g.get(garbage(i), "", src)
		g.wantStatus(rec, 429, "over budget")
		if rec.Header().Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	g.wantGets(3, "over budget (no store call)")

	// The API-token credential kind shares the source's budget and is refused without a lookup too.
	g.wantStatus(g.get("", "rmt_api_"+garbage(50), src), 429, "api token over budget")
	if n := g.apis.resolves.Load(); n != 0 {
		t.Fatalf("API resolves = %d, want 0 (budget was spent on session lookups)", n)
	}
}

func TestCredentialGuard_APIFailuresCountAndAreMetered(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
	const src = "198.51.100.8"
	g.wantStatus(g.get("", "rmt_api_"+garbage(1), src), 401, "api 1")
	g.wantStatus(g.get("", "rmt_api_"+garbage(2), src), 401, "api 2")
	g.wantStatus(g.get("", "rmt_api_"+garbage(3), src), 429, "api 3")
	if n := g.apis.resolves.Load(); n != 2 {
		t.Fatalf("API resolves = %d, want 2", n)
	}
	// A valid API token from another source still works, and one from THIS source (unproven) is the documented
	// trade-off: refused until the window rolls.
	good := g.apiToken()
	g.wantStatus(g.get("", good, "203.0.113.9"), 204, "valid api token, other source")
	// (a token proven anywhere is known process-wide, so the unproven one must be a different token)
	unproven := g.apiToken()
	g.wantStatus(g.get("", unproven, src), 429, "valid but unproven api token from an over-budget source")
	g.wantStatus(g.get("", good, src), 204, "a token proven elsewhere is not refused here")
	g.clock.Advance(DefaultCredentialWindow + time.Second)
	g.wantStatus(g.get("", unproven, src), 204, "valid api token after the window")
}

func TestCredentialGuard_RetryAfterIsAtLeastOneSecond(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1, Window: time.Minute})
	const src = "198.51.100.12"
	g.wantStatus(g.get(garbage(1), "", src), 401, "burn")
	g.clock.Advance(time.Minute - 100*time.Millisecond)
	rec := g.get(garbage(2), "", src)
	g.wantStatus(rec, 429, "still in the window")
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q with 100 ms left, want \"1\" (never 0: a client would hammer)", got)
	}
}

func TestCredentialGuard_WindowResetAndOtherSourcesUnaffected(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2, Window: time.Minute})
	const a, b = "198.51.100.1", "198.51.100.2"
	g.wantStatus(g.get(garbage(1), "", a), 401, "a1")
	g.wantStatus(g.get(garbage(2), "", a), 401, "a2")
	rec := g.get(garbage(3), "", a)
	g.wantStatus(rec, 429, "a3")
	g.wantGets(2, "a over budget")

	// Another source has its own budget.
	g.wantStatus(g.get(garbage(4), "", b), 401, "b1")
	g.wantGets(3, "b was looked up")

	// Half a window later A is still refused; the refusal did not extend the window (it ends 60 s after the
	// FIRST failure, not after the last refused request).
	g.clock.Advance(40 * time.Second)
	g.wantStatus(g.get(garbage(5), "", a), 429, "a still over budget")
	g.clock.Advance(21 * time.Second)
	g.wantStatus(g.get(garbage(6), "", a), 401, "a after the window")
	g.wantGets(4, "a resumed")
}

func TestCredentialGuard_SourceIsTheTrustedAddressNotAHeader(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
	// An attacker rotating X-Forwarded-For / X-Real-IP while keeping its socket must stay in ONE bucket
	// (proxy trust is off here, so neither header is honoured by clientIP / resolveClientIP).
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("GET", "/auth/session", nil)
		r.RemoteAddr = "198.51.100.77:5000"
		r.Header.Set("X-Forwarded-For", fmt.Sprintf("10.0.0.%d", i))
		r.Header.Set("X-Real-IP", fmt.Sprintf("10.1.0.%d", i))
		r.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: garbage(i)})
		rec := httptest.NewRecorder()
		g.h.ServeHTTP(rec, r)
		want := 401
		if i >= 2 {
			want = 429
		}
		g.wantStatus(rec, want, fmt.Sprintf("rotating header %d", i))
	}
	g.wantGets(2, "header rotation")
}

func TestCredentialSource_IPv6CollapsesToItsSlash64(t *testing.T) {
	mk := func(remote string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		return r
	}
	a := credentialSource(mk("[2001:db8:1:2:aaaa::1]:80"))
	b := credentialSource(mk("[2001:db8:1:2:bbbb:cccc:dddd:eeee]:80"))
	c := credentialSource(mk("[2001:db8:1:3::1]:80"))
	if a != b {
		t.Fatalf("one /64 got two budgets: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("two /64s share a budget: %q", a)
	}
	if v4, mapped := credentialSource(mk("192.0.2.5:1")), credentialSource(mk("[::ffff:192.0.2.5]:1")); v4 != mapped {
		t.Fatalf("IPv4-mapped IPv6 is a different source: %q vs %q", v4, mapped)
	}
	if credentialSource(mk("not-an-address")) != "unknown" {
		t.Fatal("an unparsable source must fall into the shared 'unknown' bucket, not escape the budget")
	}
}

func TestCredentialGuard_SuccessesNeverConsumeTheBudget(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1})
	const src = "198.51.100.9"
	// Ten DIFFERENT valid sessions the guard has never seen, from a source whose whole budget is ONE failure.
	for i := 0; i < 10; i++ {
		g.wantStatus(g.get(g.session(), "", src), 204, fmt.Sprintf("valid session %d", i))
	}
	// And the budget is intact: exactly one failure is still allowed, the second is refused.
	g.wantStatus(g.get(garbage(1), "", src), 401, "the one allowed failure")
	g.wantStatus(g.get(garbage(2), "", src), 429, "the next")
}

func TestCredentialGuard_ValidSessionSurvivesAnOverBudgetSharedSource(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 3})
	const src = "198.51.100.10" // the NAT an attacker and a technician share
	tech := g.session()
	g.wantStatus(g.get(tech, "", src), 204, "technician, first request")

	for i := 0; i < 3; i++ {
		g.wantStatus(g.get(garbage(i), "", src), 401, "attacker")
	}
	g.wantStatus(g.get(garbage(99), "", src), 429, "attacker over budget")
	before := g.store.gets.Load()

	// The technician keeps working — the lookup still runs (revocation must be honoured), it is just not gated.
	g.wantStatus(g.get(tech, "", src), 204, "technician while the source is over budget")
	if g.store.gets.Load() != before+1 {
		t.Fatalf("a recently-valid token must still be LOOKED UP (lookups %d -> %d)", before, g.store.gets.Load())
	}
	// Via Authorization too.
	g.wantStatus(g.get("", tech, src), 204, "technician by bearer")

	// A token never seen by this process is NOT exempt (documented trade-off) ...
	other := g.session()
	g.wantStatus(g.get(other, "", src), 429, "unproven valid token from an over-budget source")
	// ... unless login registered it.
	g.guard.NoteValid(other)
	g.wantStatus(g.get(other, "", src), 204, "token registered by login")

	// The exemption is not a bypass: once revoked, the lookup refuses it, and it stops being exempt.
	if err := g.sessions.Revoke(context.Background(), tech); err != nil {
		t.Fatal(err)
	}
	g.wantStatus(g.get(tech, "", src), 401, "revoked token is looked up and refused")
	g.wantStatus(g.get(tech, "", src), 429, "revoked token no longer exempt")
}

func TestCredentialGuard_ValidCacheExpires(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1, ValidTTL: time.Minute, Window: time.Hour})
	const src = "198.51.100.11"
	tech := g.session()
	g.wantStatus(g.get(tech, "", src), 204, "first")
	g.wantStatus(g.get(garbage(1), "", src), 401, "burn")
	g.wantStatus(g.get(garbage(2), "", src), 429, "over")
	g.wantStatus(g.get(tech, "", src), 204, "within ttl")
	g.clock.Advance(2 * time.Minute)
	g.wantStatus(g.get(tech, "", src), 429, "after ttl the token is unproven again")
}

func TestCredentialGuard_MemoryIsBounded(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxSources: 5, ValidMax: 4, MaxFailures: 1})
	for i := 0; i < 200; i++ {
		g.wantStatus(g.get(garbage(i), "", fmt.Sprintf("198.51.%d.%d", i/250, i%250+1)), 401, "many sources")
		if n := g.guard.trackedSources(); n > 5 {
			t.Fatalf("tracked sources = %d after %d, want <= 5", n, i+1)
		}
	}
	for i := 0; i < 50; i++ {
		g.wantStatus(g.get(g.session(), "", "203.0.113.1"), 204, "many valid tokens")
	}
	g.guard.mu.Lock()
	n, ll := len(g.guard.valid), g.guard.validLL.Len()
	g.guard.mu.Unlock()
	if n > 4 || ll != n {
		t.Fatalf("recently-valid set = %d (list %d), want <= 4 and consistent", n, ll)
	}
	// The OLDEST sources are evicted first: the newest one is still enforced.
	g.wantStatus(g.get(garbage(1000), "", "192.0.2.200"), 401, "fresh source")
	g.wantStatus(g.get(garbage(1001), "", "192.0.2.200"), 429, "fresh source is tracked and enforced")
}

func TestCredentialGuard_NilGuardIsAPassThrough(t *testing.T) {
	var g *CredentialGuard
	calls := 0
	r := httptest.NewRequest("GET", "/", nil)
	if err := g.Lookup(r, "whatever-not-even-a-token", false, func() error { calls++; return nil }); err != nil || calls != 1 {
		t.Fatalf("nil guard: err=%v calls=%d", err, calls)
	}
	g.NoteValid("x")
	g.Forget("x")
}

// ---- global cap --------------------------------------------------------------------------------------------

// fire sends a request on its own goroutine and returns the channel its status arrives on.
func (g *guardHarness) fire(tok, remote string) <-chan int {
	ch := make(chan int, 1)
	go func() { ch <- g.get(tok, "", remote).Code }()
	return ch
}

func guardWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCredentialGuard_GlobalCapThen503(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 2, MaxQueue: -1, MaxFailures: 100})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)

	// Two lookups from two sources occupy both slots.
	r1 := g.fire(garbage(1), "198.51.100.1")
	r2 := g.fire(garbage(2), "198.51.100.2")
	<-g.store.entered
	<-g.store.entered

	// A third, from a THIRD source, is refused with 503 and never reaches the store.
	rec := g.get(garbage(3), "", "198.51.100.3")
	g.wantStatus(rec, 503, "beyond the global cap")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("503 without Retry-After")
	}
	g.wantGets(2, "cap")

	// A recently-valid token is NOT held out by the cap (it is not anonymous work).
	tech := g.session()
	g.guard.NoteValid(tech)
	techDone := g.fire(tech, "198.51.100.4")
	guardWaitFor(t, "the known token to reach the store", func() bool { return g.store.gets.Load() == 3 })

	close(g.store.gate)
	for i, ch := range []<-chan int{r1, r2} {
		if got := <-ch; got != 401 {
			t.Fatalf("held lookup %d = %d, want 401", i, got)
		}
	}
	if got := <-techDone; got != 204 {
		t.Fatalf("known token during saturation = %d, want 204", got)
	}
	// Slots are released: new anonymous lookups run again.
	g.wantStatus(g.get(garbage(9), "", "198.51.100.5"), 401, "after release")
}

func TestCredentialGuard_BusyRefusalRefundsTheBudget(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: -1, MaxFailures: 2})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)
	const src = "198.51.100.20"
	held := g.fire(garbage(1), src)
	<-g.store.entered
	// Three 503s from the same source: none may be charged, or this source would be locked out by load it did
	// not cause.
	for i := 0; i < 3; i++ {
		g.wantStatus(g.get(garbage(10+i), "", src), 503, "busy")
	}
	close(g.store.gate)
	<-held
	g.wantStatus(g.get(garbage(20), "", src), 401, "second failure still allowed")
	g.wantStatus(g.get(garbage(21), "", src), 429, "third refused")
}

func TestCredentialGuard_QueueWaitsThenAdmitsOrTimesOut(t *testing.T) {
	// A waiting room of one: the second request waits for the slot, the third is turned away at once.
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: 1, QueueWait: 5 * time.Second, MaxFailures: 100})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)
	a := g.fire(garbage(1), "198.51.100.1")
	<-g.store.entered
	b := g.fire(garbage(2), "198.51.100.2")
	guardWaitFor(t, "b to queue", func() bool { return g.guard.queued.Load() == 1 })
	turnedAway := time.Now()
	g.wantStatus(g.get(garbage(3), "", "198.51.100.3"), 503, "waiting room full")
	if d := time.Since(turnedAway); d > time.Second {
		t.Fatalf("a full waiting room took %v to refuse; it must turn the request away AT ONCE", d)
	}
	close(g.store.gate)
	if got := <-a; got != 401 {
		t.Fatalf("a = %d", got)
	}
	if got := <-b; got != 401 {
		t.Fatalf("queued b = %d, want it admitted and answered 401", got)
	}
	g.wantGets(2, "a and b only")

	// A waiter whose slot never frees up gives up after QueueWait with 503.
	g2 := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: 1, QueueWait: 30 * time.Millisecond, MaxFailures: 100})
	g2.store.gate = make(chan struct{})
	g2.store.entered = make(chan struct{}, 16)
	held := g2.fire(garbage(1), "198.51.100.1")
	<-g2.store.entered
	start := time.Now()
	g2.wantStatus(g2.get(garbage(2), "", "198.51.100.2"), 503, "queue wait elapsed")
	if time.Since(start) < 25*time.Millisecond {
		t.Fatalf("503 came back in %v, before the queue wait", time.Since(start))
	}
	g2.wantGets(1, "timed-out waiter never looked up")
	close(g2.store.gate)
	<-held
}

func TestDefaultCredentialLookups_SizedFromThePool(t *testing.T) {
	for pool, want := range map[int]int{0: 2, 1: 2, 4: 2, 8: 2, 16: 4, 40: 10} {
		if got := DefaultCredentialLookups(pool); got != want {
			t.Errorf("pool %d: %d, want %d", pool, got, want)
		}
	}
	if g := NewCredentialGuard(CredentialGuardConfig{MaxLookups: 7}); cap(g.slots) != 7 || g.cfg.MaxQueue != 14 {
		t.Fatalf("slots=%d queue=%d, want 7 and 14", cap(g.slots), g.cfg.MaxQueue)
	}
}

// ---- logout ------------------------------------------------------------------------------------------------

func TestCredentialGuard_LogoutWrongShapeIsUsualAnswerWithoutLookups(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1})
	for _, bad := range []string{"x", garbage(1)[:42], garbage(1) + "A", "rmt_api_" + garbage(1)} {
		rec := g.logout(bad, "198.51.100.30")
		g.wantStatus(rec, 204, "logout with a token that cannot be ours")
	}
	g.wantGets(0, "logout wrong shapes")
	if n := g.store.revokes.Load(); n != 0 {
		t.Fatalf("revokes = %d, want 0", n)
	}
}

func TestCredentialGuard_LogoutBudgetSharedWithTheProtectedChain(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
	const src = "198.51.100.31"
	g.wantStatus(g.logout(garbage(1), src), 204, "logout 1: usual answer")
	g.wantStatus(g.logout(garbage(2), src), 204, "logout 2: usual answer")
	g.wantGets(2, "two charged lookups")
	revokes := g.store.revokes.Load()

	rec := g.logout(garbage(3), src)
	g.wantStatus(rec, 429, "logout over budget")
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
	g.wantGets(2, "logout over budget: no Validate")
	if g.store.revokes.Load() != revokes {
		t.Fatal("logout over budget still called Revoke")
	}
	// The same budget gates the protected chain...
	g.wantStatus(g.get(garbage(4), "", src), 429, "protected chain shares the budget")
	// ... and another source is unaffected.
	g.wantStatus(g.logout(garbage(5), "198.51.100.32"), 204, "other source logout")
	g.wantGets(3, "other source looked up")
}

func TestCredentialGuard_LogoutOfAValidSessionStillWorksAndRevokes(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
	const src = "198.51.100.33"
	tech := g.session()
	g.wantStatus(g.get(tech, "", src), 204, "before logout")
	// Attacker exhausts the shared source.
	g.wantStatus(g.logout(garbage(1), src), 204, "a1")
	g.wantStatus(g.logout(garbage(2), src), 204, "a2")
	g.wantStatus(g.logout(garbage(3), src), 429, "a3")

	// The technician's own logout is a recently-valid token: not refused, and it really revokes.
	g.wantStatus(g.logout(tech, src), 204, "technician logout from an over-budget source")
	// A revoked token does not keep its exemption: logout itself forgets it (checked BEFORE any other request
	// could, since a failed lookup of a known token forgets it too).
	g.wantStatus(g.logout(tech, src), 429, "revoked token no longer exempt")
	g.wantStatus(g.get(tech, "", "198.51.100.34"), 401, "session is revoked")
}

func TestCredentialGuard_LogoutUnprovenValidTokenUnderBudgetRevokes(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 5})
	tech := g.session()
	g.wantStatus(g.logout(tech, "198.51.100.35"), 204, "logout")
	g.wantStatus(g.get(tech, "", "198.51.100.35"), 401, "revoked")
	// And the successful logout was not charged: the budget still has all five.
	for i := 0; i < 4; i++ {
		g.wantStatus(g.logout(garbage(i), "198.51.100.35"), 204, "budget intact")
	}
}

// ---- end to end of what a valid credential does -----------------------------------------------------------

func TestCredentialGuard_ValidSessionAndAPITokenAuthenticate(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{})
	g.wantStatus(g.get(g.session(), "", "198.51.100.40"), 204, "valid cookie session")
	g.wantStatus(g.get("", g.session(), "198.51.100.40"), 204, "valid bearer session")
	g.wantStatus(g.get("", g.apiToken(), "198.51.100.40"), 204, "valid API token")
	g.wantStatus(g.get("", "", "198.51.100.40"), 401, "no credential")
	g.wantGets(2, "valid session lookups only")
}

// A session a login on THIS replica just minted is registered with the guard, so its holder is not refused by a
// budget an attacker sharing the source ran down — the common case of the NAT trade-off.
func TestCredentialGuard_LoginRegistersTheTokenItMints(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
	users := NewInMemoryUserStore()
	hash, err := HashPassword("login-guard-correct-horse")
	if err != nil {
		t.Fatal(err)
	}
	users.AddUser(&AuthUser{ID: g.userID, TenantID: g.tenantID, Email: "l@guard.test", PasswordHash: hash},
		NewGrant(g.userID, g.tenantID, NewMembership(RoleOwner, AllGroups())))
	svc := &AuthService{Users: users, Sessions: g.sessions, Guard: g.guard, Issuer: "RMT", DisableThrottle: true}
	auth := &GuardedAuthenticator{Guard: g.guard, Next: &SessionAuthenticator{Sessions: g.sessions, Users: users}}
	srv := NewServer(auth, NoopBinder{})
	srv.AuthAPI = svc
	h := srv.Handler()

	const src = "198.51.100.50"
	r := httptest.NewRequest("POST", "/auth/login",
		strings.NewReader(`{"tenant":"`+g.tenantID+`","email":"l@guard.test","password":"login-guard-correct-horse"}`))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = src + ":1"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != 200 {
		t.Fatalf("login = %d: %s", rec.Code, rec.Body.String())
	}
	sess := sessionCookieFrom(rec)

	send := func(tok string) int {
		q := httptest.NewRequest("GET", "/auth/session", nil)
		q.RemoteAddr = src + ":1"
		q.AddCookie(&http.Cookie{Name: DefaultSessionCookie, Value: tok})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, q)
		return w.Code
	}
	for i := 0; i < 2; i++ {
		if got := send(garbage(i)); got != 401 {
			t.Fatalf("attacker %d = %d", i, got)
		}
	}
	if got := send(garbage(9)); got != 429 {
		t.Fatalf("attacker over budget = %d, want 429", got)
	}
	if got := send(sess.Value); got != 204 {
		t.Fatalf("the session login just minted, from an over-budget source = %d, want 204", got)
	}
}

func TestCredentialFailure_OnlyCredentialVerdictsCharge(t *testing.T) {
	for err, want := range map[error]bool{
		nil:                       false,
		ErrSessionNotFound:        true,
		ErrSessionExpired:         true,
		ErrSessionRevoked:         true,
		ErrSessionIdle:            true,
		ErrSessionCredentialStale: true,
		ErrInvalidCredentials:     true,
		ErrAPITokenNotFound:       true,
		ErrNoUser:                 true,
		// Infrastructure and unknown errors are NOT the presenter's fault: charging them turns a database
		// blip into a lockout of every legitimate source.
		errors.New("conn refused"):                    false,
		ErrTOTPRequired:                               false,
		fmt.Errorf("query: %w", errors.New("eof")):    false,
		fmt.Errorf("wrapped: %w", ErrNoUser):          true,
		ErrTenantSuspended:                            false, // the credential was good
		ErrUserDisabled:                               false, // the credential was good
		context.Canceled:                              false, // the caller left
		context.DeadlineExceeded:                      false,
		fmt.Errorf("wrapped: %w", ErrTenantSuspended): false,
		fmt.Errorf("wrapped: %w", ErrSessionRevoked):  true,
	} {
		if got := credentialFailure(err); got != want {
			t.Errorf("credentialFailure(%v) = %v, want %v", err, got, want)
		}
	}
}

// A lookup that fails for a reason that is not the credential's fault (tenant suspended: the token WAS good) gives its
// reservation back, so a suspended tenant's users cannot lock their own NAT out by retrying.
func TestCredentialGuard_NonCredentialFailuresAreRefunded(t *testing.T) {
	g := NewCredentialGuard(CredentialGuardConfig{MaxFailures: 1})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.70:1"
	for i := 0; i < 5; i++ {
		err := g.Lookup(r, garbage(i), false, func() error { return ErrTenantSuspended })
		if err != ErrTenantSuspended {
			t.Fatalf("lookup %d = %v, want the store's own ErrTenantSuspended (a refund, not a refusal)", i, err)
		}
	}
}

// ---- infrastructure faults are not credential failures -------------------------------------------------------

// A database that is down answers every lookup with an error that says nothing about the credential. Charging
// it would burn the budget of every legitimate source (and forget their tokens), so that once the database is
// back they are refused 429 for the rest of the window: an outage turned into a lockout that outlasts it.
func TestCredentialGuard_InfrastructureErrorsNeverChargeOrForget(t *testing.T) {
	g := NewCredentialGuard(CredentialGuardConfig{MaxFailures: 1})
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.80:1"
	down := errors.New("conn refused")

	// An UNKNOWN token: many lookups against a down database, none refused, none charged.
	for i := 0; i < 5; i++ {
		if err := g.Lookup(r, garbage(i), false, func() error { return down }); err != down {
			t.Fatalf("unknown token lookup %d = %v, want the store's own error (a refund, not a refusal)", i, err)
		}
	}
	// A KNOWN token on a source that is already out of budget: the fault neither refuses it, forgets it, nor
	// charges it.
	known := garbage(100)
	g.NoteValid(known)
	if err := g.Lookup(r, garbage(101), false, func() error { return ErrSessionNotFound }); err != ErrSessionNotFound {
		t.Fatalf("a real verdict = %v", err) // spends the one unit
	}
	if err := g.Lookup(r, garbage(102), false, func() error { return nil }); credentialRefusalOf(err) == nil {
		t.Fatalf("the source should now be over budget, got %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := g.Lookup(r, known, false, func() error { return down }); err != down {
			t.Fatalf("known token during the outage = %v, want the store's own error", err)
		}
	}
	var h [32]byte
	copy(h[:], HashToken(known))
	if !g.isValid(h) {
		t.Fatal("an outage made the guard forget a token that was good: the NAT exemption is gone")
	}
	if err := g.Lookup(r, known, false, func() error { return nil }); err != nil {
		t.Fatalf("known token once the database is back = %v, want success", err)
	}
}

// The same property end to end, through the real authenticators and both credential kinds: a database fault is
// answered with the opaque 401 the caller always got, never a 429, and it leaves the budget whole.
func TestCredentialGuard_DatabaseOutageDoesNotLockOutASource(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 3})
	const src = "198.51.100.81"
	tech := g.session()
	other := g.session()
	api := g.apiToken()
	g.wantStatus(g.get(tech, "", src), 204, "tech before the outage (now known)")

	g.store.fault.Store(true)
	g.apis.fault.Store(true)
	for i := 0; i < 10; i++ {
		for what, rec := range map[string]*httptest.ResponseRecorder{
			"known session":   g.get(tech, "", src),
			"unknown session": g.get(other, "", src),
			"api token":       g.get("", api, src),
		} {
			if rec.Code == 429 {
				t.Fatalf("%s during an outage = 429: a database fault burned the source's budget", what)
			}
		}
	}
	g.store.fault.Store(false)
	g.apis.fault.Store(false)

	g.wantStatus(g.get(tech, "", src), 204, "known session after the outage")
	g.wantStatus(g.get(other, "", src), 204, "unknown-but-valid session after the outage")
	g.wantStatus(g.get("", api, src), 204, "api token after the outage")
	// The whole budget is still there: three real failures, then the refusal.
	for i := 0; i < 3; i++ {
		g.wantStatus(g.get(garbage(i), "", src), 401, "budget intact")
	}
	g.wantStatus(g.get(garbage(9), "", src), 429, "budget spent only by real failures")
}

// APITokenAuthenticator collapses "no such token" to ErrInvalidCredentials but must pass a store FAULT through,
// or the guard downstream could not tell the two apart.
func TestAPITokenAuthenticator_PassesStoreFaultsThrough(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{})
	auth := &APITokenAuthenticator{Tokens: g.apis, Next: &SessionAuthenticator{Sessions: g.sessions, Users: NewInMemoryUserStore()}}
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+g.apiToken())
	g.apis.fault.Store(true)
	if _, err := auth.Authenticate(req); err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("a store fault came back as %v, want the fault itself", err)
	}
	g.apis.fault.Store(false)
	req.Header.Set("Authorization", "Bearer "+APITokenPrefix+garbage(1))
	if _, err := auth.Authenticate(req); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("an unknown token = %v, want ErrInvalidCredentials", err)
	}
}

// ---- first lookups of one token coalesce ----------------------------------------------------------------------

// A page load fires ~10 parallel requests with one session this process has not seen. They must cost ONE slot, or a
// restart makes the first page loads 503.
func TestCredentialGuard_ConcurrentFirstLookupsOfOneTokenCoalesce(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: 4, MaxFailures: 100, QueueWait: 5 * time.Second})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)
	tok := g.session()
	const src = "198.51.100.82"

	leader := g.fire(tok, src)
	<-g.store.entered
	var followers []<-chan int
	for i := 0; i < 4; i++ {
		followers = append(followers, g.fire(tok, src))
	}
	// Every follower holds a waiting-room seat behind the leader before the leader is released.
	guardWaitFor(t, "followers to wait behind the leader", func() bool { return g.guard.queued.Load() == 4 })
	close(g.store.gate)
	for i, ch := range append([]<-chan int{leader}, followers...) {
		if got := <-ch; got != 204 {
			t.Fatalf("request %d with one unseen valid token = %d, want 204 (a 503 means it took its own slot)", i, got)
		}
	}
	// Every request still looks the session up (a known token is authenticated work); what coalescing saves is the
	// slot and the budget unit, which is what the all-204 above proves with a cap of ONE slot and no waiting room.
	g.wantGets(5, "each request authenticates")
}

// Coalescing must not become a way to skip the budget: when the leader's token is NOT good, each waiter proceeds
// through the ordinary gates and is charged like any other unproven lookup.
func TestCredentialGuard_CoalescedWaitersOfABadTokenAreStillCharged(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: 4, MaxFailures: 3, QueueWait: 5 * time.Second})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)
	const src = "198.51.100.83"
	bad := garbage(1)
	var chans []<-chan int
	chans = append(chans, g.fire(bad, src))
	<-g.store.entered
	for i := 0; i < 3; i++ {
		chans = append(chans, g.fire(bad, src))
	}
	guardWaitFor(t, "waiters behind the leader", func() bool { return g.guard.queued.Load() == 3 })
	close(g.store.gate)
	for i, ch := range chans {
		got := <-ch
		if got != 401 && got != 429 {
			t.Fatalf("request %d = %d, want 401 or 429", i, got)
		}
	}
	// The leader and two waiters are charged (3 failures); the fourth is refused with no lookup.
	g.wantGets(3, "a bad token's waiters each look up and are charged; the budget of 3 then refuses the fourth")
}

// Followers are bounded by the waiting room: holding one plausible token's lookup open and flooding that token must
// not park an unbounded number of requests. Followers beyond the seats go through the ordinary gates at once, where
// the full cap refuses them (503) with no lookup and no wait.
func TestCredentialGuard_FollowersOfOneTokenAreBoundedByTheWaitingRoom(t *testing.T) {
	g := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: 2, MaxFailures: 100, QueueWait: 5 * time.Second})
	g.store.gate = make(chan struct{})
	g.store.entered = make(chan struct{}, 16)
	const src = "198.51.100.85"
	tok := g.session()
	leader := g.fire(tok, src)
	<-g.store.entered
	results := make(chan int, 6)
	for i := 0; i < 6; i++ {
		ch := g.fire(tok, src)
		go func() { results <- <-ch }()
	}
	deadline := time.After(2 * time.Second)
	for busy := 0; busy < 4; busy++ {
		select {
		case got := <-results:
			if got != 503 {
				t.Fatalf("an excess follower = %d before the leader finished, want 503", got)
			}
		case <-deadline:
			t.Fatalf("only %d of 4 excess followers were refused promptly; the rest are parked", busy)
		}
	}
	if q := g.guard.queued.Load(); q != 2 {
		t.Fatalf("waiting room holds %d, want exactly its 2 seats", q)
	}
	close(g.store.gate)
	if got := <-leader; got != 204 {
		t.Fatalf("leader = %d, want 204", got)
	}
	for i := 0; i < 2; i++ {
		if got := <-results; got != 204 {
			t.Fatalf("seated follower = %d, want 204", got)
		}
	}
	g.wantGets(3, "the leader and the two seated followers look up; the refused four never reach the store")
}

// Leader election is one critical section: of many simultaneous first arrivals with one token exactly one leads,
// and once it ends the next arrival leads again.
func TestCredentialGuard_FirstLookupElectsExactlyOneLeader(t *testing.T) {
	g := NewCredentialGuard(CredentialGuardConfig{})
	var hash [32]byte
	hash[0] = 7
	const n = 64
	start := make(chan struct{})
	var leaders atomic.Int64
	var ends sync.Map
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			done, leading, leader := g.beginFirstLookup(hash)
			if leader {
				leaders.Add(1)
				ends.Store(i, done)
			} else if leading == nil {
				t.Errorf("a follower got no channel to wait on")
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if got := leaders.Load(); got != 1 {
		t.Fatalf("%d leaders for one token, want exactly 1", got)
	}
	ends.Range(func(_, v any) bool { v.(func())(); return true })
	if _, _, leader := g.beginFirstLookup(hash); !leader {
		t.Fatal("after the leader ended, the next arrival did not lead")
	}
}

// The leader registry is capped in the critical section that inserts: leaders elected and held open (before any
// admission) cannot grow it past MaxLookups+MaxQueue, whatever the number of distinct tokens. A request that finds
// it full neither leads nor follows, and the registry admits again once a leader ends.
func TestCredentialGuard_LeaderRegistryIsCapped(t *testing.T) {
	g := NewCredentialGuard(CredentialGuardConfig{MaxLookups: 2, MaxQueue: 3})
	const limit = 5
	var ends []func()
	for i := 0; i < 50; i++ {
		var h [32]byte
		h[0], h[1] = byte(i), 1
		done, leading, leader := g.beginFirstLookup(h)
		switch {
		case leader:
			ends = append(ends, done)
		case leading != nil:
			t.Fatalf("token %d: a follower of a token nobody leads", i)
		}
	}
	if len(ends) != limit {
		t.Fatalf("%d leaders registered for 50 distinct tokens, want the cap %d", len(ends), limit)
	}
	g.mu.Lock()
	n := len(g.inflight)
	g.mu.Unlock()
	if n != limit {
		t.Fatalf("inflight holds %d, want %d", n, limit)
	}
	ends[0]()
	var h [32]byte
	h[0] = 200
	if _, _, leader := g.beginFirstLookup(h); !leader {
		t.Fatal("after a leader ended, a new token could not lead")
	}
}

// ---- visibility ------------------------------------------------------------------------------------------------

// A source that exhausts its budget is logged ONCE per window: an attacker, a poll loop with a revoked API token, or
// a mis-set proxy trust that put everyone behind one address would otherwise be invisible.
func TestCredentialGuard_ExhaustionIsLoggedOncePerWindow(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2, Logf: func(f string, a ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(f, a...))
		mu.Unlock()
	}})
	const src = "198.51.100.84"
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(lines) }
	for i := 0; i < 2; i++ {
		g.wantStatus(g.get(garbage(i), "", src), 401, "failure")
	}
	if count() != 0 {
		t.Fatalf("logged before the budget was exhausted: %v", lines)
	}
	for i := 0; i < 5; i++ {
		g.wantStatus(g.get(garbage(10+i), "", src), 429, "over budget")
	}
	if count() != 1 || !strings.Contains(lines[0], src) || strings.Contains(lines[0], garbage(10)) {
		t.Fatalf("want exactly one line naming the source and no token, got %q", lines)
	}
	g.clock.Advance(DefaultCredentialWindow + time.Second)
	for i := 0; i < 2; i++ {
		g.wantStatus(g.get(garbage(20+i), "", src), 401, "new window")
	}
	g.wantStatus(g.get(garbage(30), "", src), 429, "over budget again")
	if count() != 2 {
		t.Fatalf("a new window's exhaustion must be logged again, got %d lines", count())
	}
}

// ---- methods ---------------------------------------------------------------------------------------------------

// HEAD and OPTIONS are as CSRF-exempt as GET: they must be metered the same way, or they are the unmetered route.
func TestCredentialGuard_HeadAndOptionsAreGuardedToo(t *testing.T) {
	for _, method := range []string{"HEAD", "OPTIONS"} {
		g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 2})
		const src = "198.51.100.85"
		for i := 0; i < 10; i++ {
			g.do(method, "/auth/session", garbage(i), "", src)
		}
		if got := g.store.gets.Load(); got > 2 {
			t.Fatalf("%s: %d lookups for 10 garbage requests with a budget of 2", method, got)
		}
		before := g.store.gets.Load()
		g.do(method, "/auth/session", "x", "", src)
		if g.store.gets.Load() != before {
			t.Fatalf("%s: a wrong-shape token reached the store", method)
		}
	}
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1})
	g.wantStatus(g.do("HEAD", "/auth/session", garbage(1), "", "198.51.100.86"), 401, "HEAD failure")
	g.wantStatus(g.do("HEAD", "/auth/session", garbage(2), "", "198.51.100.86"), 429, "HEAD over budget")
}

// ---- every site that mints a session registers it -------------------------------------------------------------

// rotationFixture is a guarded server with one password user whose source (the httptest default) has been run out of
// budget by garbage.
func rotationFixture(t *testing.T) (http.Handler, *http.Cookie, *http.Cookie, string) {
	t.Helper()
	f := newAuthFixture(t)
	audit := NewInMemoryMgmtAuditStore()
	f.srv.MgmtAudit, f.auth.MgmtAudit = audit, audit
	f.addUser(t, "tenant-1", "u1", "dana@acme.test", pwOld, RoleOwner)
	guard := NewCredentialGuard(CredentialGuardConfig{MaxFailures: 2})
	f.srv.Auth = &GuardedAuthenticator{Guard: guard, Next: &SessionAuthenticator{Sessions: f.sessions, Users: f.users}}
	f.auth.Guard = guard
	h := f.srv.Handler()
	sess, csrfCookie, csrf := loginAndGetCSRF(t, h, "tenant-1", "dana@acme.test", pwOld)
	// An attacker sharing the source runs the budget down.
	for i := 0; i < 2; i++ {
		if rec := doJSON(t, h, "GET", "/auth/session", nil, &http.Cookie{Name: DefaultSessionCookie, Value: garbage(i)}); rec.Code != 401 {
			t.Fatalf("attacker %d = %d", i, rec.Code)
		}
	}
	if rec := doJSON(t, h, "GET", "/auth/session", nil, &http.Cookie{Name: DefaultSessionCookie, Value: garbage(9)}); rec.Code != 429 {
		t.Fatalf("attacker over budget = %d, want 429", rec.Code)
	}
	return h, sess, csrfCookie, csrf
}

// The rotated session a password change or an email change hands back is a fresh, unseen token: it must be
// registered, or its holder is refused by the very budget an attacker ran down right after they changed it.
func TestCredentialGuard_PasswordAndEmailChangeRegisterTheRotatedSession(t *testing.T) {
	for name, tc := range map[string]struct {
		path string
		body any
	}{
		"password": {"/me/password", map[string]string{"current_password": pwOld, "new_password": pwNew}},
		"email":    {"/me/email", map[string]string{"current_password": pwOld, "new_email": "dana.new@acme.test"}},
	} {
		t.Run(name, func(t *testing.T) {
			h, sess, csrfCookie, csrf := rotationFixture(t)
			rec := doJSONWith(t, h, "POST", tc.path, tc.body, csrf, sess, csrfCookie)
			if rec.Code != http.StatusOK {
				t.Fatalf("change = %d: %s", rec.Code, rec.Body.String())
			}
			rotated := sessionCookieFrom(rec)
			if rotated == nil {
				t.Fatal("no rotated session")
			}
			if got := doJSON(t, h, "GET", "/auth/session", nil, rotated); got.Code != 204 {
				t.Fatalf("the rotated session from an over-budget source = %d, want 204 (it was never registered)", got.Code)
			}
			// And the budget is still spent for everyone else.
			if got := doJSON(t, h, "GET", "/auth/session", nil, &http.Cookie{Name: DefaultSessionCookie, Value: garbage(50)}); got.Code != 429 {
				t.Fatalf("garbage after the change = %d, want 429", got.Code)
			}
		})
	}
}

// ---- logout clears the browser's cookies even when it cannot revoke ---------------------------------------------

// The console closes its gate locally on logout and ignores a failed request, so a 429/503 that left the cookie in
// place would keep a live session in the browser of a user who believes they signed out.
func TestCredentialGuard_LogoutRefusalStillClearsTheBrowsersCookies(t *testing.T) {
	cleared := func(rec *httptest.ResponseRecorder) bool {
		for _, c := range rec.Result().Cookies() {
			if c.Name == DefaultSessionCookie && c.Value == "" && (c.MaxAge < 0 || c.Expires.Before(time.Now())) {
				return true
			}
		}
		return false
	}
	g := newGuardHarness(t, CredentialGuardConfig{MaxFailures: 1})
	const src = "198.51.100.87"
	g.wantStatus(g.logout(garbage(1), src), 204, "charged")
	rec := g.logout(garbage(2), src)
	g.wantStatus(rec, 429, "over budget")
	if !cleared(rec) {
		t.Fatalf("the 429 did not clear the session cookie: %v", rec.Result().Header["Set-Cookie"])
	}

	b := newGuardHarness(t, CredentialGuardConfig{MaxLookups: 1, MaxQueue: -1, MaxFailures: 100})
	b.store.gate = make(chan struct{})
	b.store.entered = make(chan struct{}, 4)
	held := b.fire(garbage(1), "198.51.100.88")
	<-b.store.entered
	rec = b.logout(garbage(2), "198.51.100.89")
	b.wantStatus(rec, 503, "busy")
	if !cleared(rec) {
		t.Fatalf("the 503 did not clear the session cookie: %v", rec.Result().Header["Set-Cookie"])
	}
	close(b.store.gate)
	<-held
}
