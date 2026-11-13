package main

// Audit 2026-11-01 #1/#6/#7: a flood from one source must not evict or starve another source's
// pre-auth handshake; new connections are rate-limited per source; the startup posture refuses the
// coupled-variable trap.
//
// MUTATIONS (each makes a test here fail):
//   - acquireLease: pick victim = a.leases[0] regardless of source  -> TestFloodFromAcannotEvictB*
//   - acquireLease: drop the per-source count check                  -> TestPerSourcePendingCap
//   - sourceRateLimiter.allow: return true                           -> TestSourceRate*, TestHandleWSRateLimited
//   - posture.evaluate: drop the production coupling error           -> TestPostureRefuses*

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestFloodFromAcannotEvictBWhenPoolFull(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	if err := state.configure(admissionLimits{maxTotal: 1000, maxPending: 4, preAuthTimeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	// B's legitimate handshake is the OLDEST pending lease (the old FIFO policy evicted exactly it).
	b := state.acquireLease(nil, time.Now(), "198.51.100.7")
	if b == nil {
		t.Fatal("B refused on an empty pool")
	}
	defer b.Release()
	var leases []*admissionLease
	for i := 0; i < 500; i++ {
		l := state.acquireLease(nil, time.Now(), "203.0.113.9")
		if l != nil {
			leases = append(leases, l)
		}
	}
	defer func() {
		for _, l := range leases {
			l.Release()
		}
	}()
	if b.stage != leasePending {
		t.Fatal("flood from source A cancelled source B's pending handshake")
	}
	if _, _, pending := state.snapshot(); pending > 4 {
		t.Fatalf("pending=%d exceeds pool", pending)
	}
	// Pool is now full of A's leases and B's; a newcomer from a THIRD source is refused (not
	// admitted by evicting anyone).
	if c := state.acquireLease(nil, time.Now(), "192.0.2.1"); c != nil {
		c.Release()
		t.Fatal("full pool admitted a new source by evicting another source's lease")
	}
	if b.stage != leasePending {
		t.Fatal("B's lease changed stage")
	}
}

func TestPerSourcePendingCapLeavesRoomForOthers(t *testing.T) {
	t.Parallel()
	state := newAdmissionState()
	if err := state.configure(admissionLimits{maxTotal: 1000, maxPending: 8, maxPendingPerSource: 3, preAuthTimeout: time.Hour}); err != nil {
		t.Fatal(err)
	}
	var held []*admissionLease
	defer func() {
		for _, l := range held {
			l.Release()
		}
	}()
	for i := 0; i < 100; i++ {
		if l := state.acquireLease(nil, time.Now(), "203.0.113.9"); l != nil {
			held = append(held, l)
		}
	}
	if len(held) != 3 {
		t.Fatalf("source A holds %d pending leases, want exactly its per-source cap 3 (newcomers refused, none evicted)", len(held))
	}
	for _, l := range held {
		if l.stage != leasePending {
			t.Fatal("an in-progress handshake of A was cancelled by A's own newcomers")
		}
	}
	for i := 0; i < 5; i++ { // five other legitimate sources all still fit
		l := state.acquireLease(nil, time.Now(), "198.51.100."+string(rune('1'+i)))
		if l == nil {
			t.Fatalf("legitimate source %d starved by A's flood", i)
		}
		held = append(held, l)
	}
}

func TestSourceRateLimiterPerSource(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	l := newSourceRateLimiter(2, func() time.Time { return now }) // burst 12
	ok := 0
	for i := 0; i < 50; i++ {
		if l.allow("A") {
			ok++
		}
	}
	if ok != 12 {
		t.Fatalf("source A got %d of a 12-token burst", ok)
	}
	if !l.allow("B") {
		t.Fatal("source B was throttled by source A's flood")
	}
	now = now.Add(time.Second) // refill 2 tokens
	if !l.allow("A") || !l.allow("A") || l.allow("A") {
		t.Fatal("refill did not grant exactly the elapsed budget")
	}
	if !newSourceRateLimiter(0, nil).allow("A") {
		t.Fatal("rate 0 must disable the limiter")
	}
}

func TestSourceRateLimiterTableIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	l := newSourceRateLimiter(1, func() time.Time { return now })
	l.maxKeys = 50
	for i := 0; i < 5000; i++ {
		l.allow(string(rune(0x4e00 + i))) // 5000 distinct hot sources, no time passing
	}
	if len(l.buckets) > 51 {
		t.Fatalf("table grew to %d entries past its cap", len(l.buckets))
	}
	// Overflow sources share one bucket, so in aggregate they are rate limited too.
	granted := 0
	for i := 0; i < 1000; i++ {
		if l.allow(string(rune(0x6000 + i))) {
			granted++
		}
	}
	if granted > 10 {
		t.Fatalf("overflow sources were granted %d connections in aggregate", granted)
	}
}

func TestHandleWSRateLimitedPerSource(t *testing.T) {
	t.Parallel()
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 64, maxPending: 32, preAuthTimeout: 10 * time.Second,
	})
	ts.srv.SetConnectRate(1) // burst 6
	var last *http.Response
	refused := 0
	for i := 0; i < 12; i++ {
		c, resp, err := ts.dialWS()
		if err == nil {
			defer c.Close()
			continue
		}
		last = resp
		refused++
	}
	if refused == 0 || last == nil || last.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("refused=%d last=%v, want 429s once the burst is spent", refused, last)
	}
}

func TestPostureRefusesCapWithoutProxiesInProduction(t *testing.T) {
	t.Parallel()
	_, _, err := signalingPosture{production: true, maxPerIP: 64}.evaluate()
	if err == nil || !strings.Contains(err.Error(), "SIGNALING_TRUSTED_PROXIES") {
		t.Fatalf("err=%v, want refusal", err)
	}
	if _, _, err := (signalingPosture{production: false, maxPerIP: 64}).evaluate(); err != nil {
		t.Fatalf("non-production must only warn: %v", err)
	}
	if _, _, err := (signalingPosture{production: true, originEnforcing: true, maxPerIP: 64, trustedProxies: 1}).evaluate(); err != nil {
		t.Fatalf("cap with proxies must start: %v", err)
	}
}

func TestPostureListsEveryProtectionThatIsOff(t *testing.T) {
	t.Parallel()
	line, warns, err := signalingPosture{}.evaluate()
	if err != nil || len(warns) != 7 {
		t.Fatalf("err=%v warnings=%d, want 7", err, len(warns))
	}
	if !strings.Contains(line, "origin_allowlist=OFF") || !strings.Contains(line, "strict_ticket_redemption=OFF") ||
		!strings.Contains(line, "protections_off=7") {
		t.Fatalf("posture line missing items: %s", line)
	}
	_, warns, _ = signalingPosture{production: true, originEnforcing: true, trustedProxies: 1, maxPerIP: 64,
		connectRate: 10, pendingPerSource: 32, strictTickets: true, messageRate: 200}.evaluate()
	if len(warns) != 0 {
		t.Fatalf("fully configured posture still warns: %v", warns)
	}
}

func TestEnvFlagOnTreatsExplicitOffSpellingsAsOff(t *testing.T) {
	for val, want := range map[string]bool{"": false, "0": false, "false": false, "OFF": false, " no ": false, "1": true, "true": true, "yes": true} {
		t.Setenv("SIGNALING_TEST_FLAG", val)
		if got := envFlagOn("SIGNALING_TEST_FLAG"); got != want {
			t.Errorf("envFlagOn(%q)=%v want %v", val, got, want)
		}
	}
}

// Review repair 1: the per-source quota counts UNAUTHENTICATED sockets only. 200 authenticated
// agents behind one NAT must not stop a 201st handshake from that address.
// MUTATION: drop the sourceQuota.release in markAuthenticated -> the 65th agent is refused.
func TestAuthenticatedAgentsDoNotCountAgainstPendingQuota(t *testing.T) {
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 1000, maxPending: 256, preAuthTimeout: 30 * time.Second,
	})
	ts.srv.SetSourceQuota(64)
	ts.srv.SetAuthenticatedQuota(4096)
	for i := 0; i < 200; i++ {
		c, resp, err := ts.dialWS()
		if err != nil {
			t.Fatalf("agent %d refused (resp=%v): %v", i, resp, err)
		}
		defer c.Close()
		writeJSONMsg(t, c, "register_agent", RegisterAgent{
			Device: "nat-agent-" + strconv.Itoa(i), Pubkey: "ed25519:x", Tenant: "t", Nat: NatOpen,
		})
		readUntil(t, c, "registered", 5*time.Second)
	}
	c, resp, err := ts.dialWS()
	if err != nil {
		t.Fatalf("new handshake after 200 authenticated agents refused (resp=%v): %v", resp, err)
	}
	c.Close()
}

// The authenticated backstop still bounds one source.
func TestAuthenticatedBackstopStillBoundsOneSource(t *testing.T) {
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 100, maxPending: 50, preAuthTimeout: 30 * time.Second,
	})
	ts.srv.SetAuthenticatedQuota(3)
	for i := 0; i < 4; i++ {
		c, _, err := ts.dialWS()
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		writeJSONMsg(t, c, "register_agent", RegisterAgent{Device: "b-" + strconv.Itoa(i), Pubkey: "ed25519:x", Tenant: "t", Nat: NatOpen})
		if i < 3 {
			readUntil(t, c, "registered", 5*time.Second)
		} else if !waitForClose(c, 3*time.Second) {
			t.Fatal("4th authenticated socket from one source was not closed by the backstop")
		}
	}
}

// Review repair 2: 60 handshakes from one IP at once; the per-source pending cap (32) refuses
// the surplus with 503 + Retry-After and cancels NONE of the 32 admitted handshakes.
// MUTATION: make acquireLease evict the source's oldest at its cap -> admitted sockets get closed.
func TestSimultaneousOfficeHerdCancelsNoAdmittedHandshake(t *testing.T) {
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{
		maxTotal: 1000, maxPending: 256, maxPendingPerSource: 32, preAuthTimeout: 30 * time.Second,
	})
	var mu sync.Mutex
	var admitted []*websocket.Conn
	refused := 0
	var wg sync.WaitGroup
	for i := 0; i < 60; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, resp, err := ts.dialWS()
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if resp != nil && resp.StatusCode == http.StatusServiceUnavailable && resp.Header.Get("Retry-After") != "" {
					refused++
				}
				return
			}
			admitted = append(admitted, c)
		}()
	}
	wg.Wait()
	if len(admitted) != 32 || refused != 28 {
		t.Fatalf("admitted=%d refused(503+Retry-After)=%d, want 32 and 28", len(admitted), refused)
	}
	time.Sleep(300 * time.Millisecond) // any cancellation would have landed by now
	for _, c := range admitted {
		defer c.Close()
		writeJSONMsg(t, c, "heartbeat", Heartbeat{Device: "pending"})
		readUntil(t, c, "rejected", 2*time.Second) // fatals if the handshake was cancelled
	}
}

// Review repair 4: production refuses an empty Origin allowlist unless "*" was chosen explicitly.
// MUTATION: drop the origin check in posture.evaluate -> this fails.
func TestPostureProductionRefusesEmptyOriginAllowlist(t *testing.T) {
	t.Parallel()
	_, _, err := signalingPosture{production: true, trustedProxies: 1}.evaluate()
	if err == nil || !strings.Contains(err.Error(), "SIGNALING_ALLOWED_ORIGINS") {
		t.Fatalf("err=%v, want refusal of an empty allowlist in production", err)
	}
	line, warns, err := signalingPosture{production: true, originAny: true, trustedProxies: 1}.evaluate()
	if err != nil || !strings.Contains(line, "ANY(unsafe)") || len(warns) == 0 {
		t.Fatalf("explicit * must start but warn loudly: err=%v line=%s", err, line)
	}
	if _, _, err := (signalingPosture{production: true, originEnforcing: true, trustedProxies: 1}).evaluate(); err != nil {
		t.Fatalf("enforcing allowlist must start: %v", err)
	}
}

// Origin policy behaviour over the real handshake: native clients (NO Origin header) always pass,
// the derived console origin passes, a foreign page and a multi-label tenant impostor do not.
func TestOriginPolicyOverHandshake(t *testing.T) {
	ts := newTestSignaling(t, time.Minute, nil, nil, admissionLimits{maxTotal: 50, maxPending: 20, preAuthTimeout: 10 * time.Second})
	pol, err := ParseOriginPolicy("https://remote.example.com")
	if err != nil {
		t.Fatal(err)
	}
	ts.srv.SetOriginPolicy(pol.WithTenantSuffix(".example.com"))
	dial := func(origin string) (int, error) {
		h := http.Header{}
		if origin != "" {
			h.Set("Origin", origin)
		}
		c, resp, err := (&websocket.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(ts.wsURL, h)
		if c != nil {
			c.Close()
		}
		if resp != nil {
			return resp.StatusCode, err
		}
		return 0, err
	}
	for origin, wantOK := range map[string]bool{
		"":                                true, // native agent: no Origin header
		"https://remote.example.com":      true,
		"https://acme.example.com":        true, // tenant host under the SSO suffix
		"https://evil.test":               false,
		"http://remote.example.com":       false,
		"https://a.b.example.com":         false, // two labels: not a tenant host
		"https://example.com":             false,
		"https://evilexample.com":         false,
		"https://remote.example.com.evil": false,
	} {
		code, err := dial(origin)
		if wantOK && err != nil {
			t.Errorf("origin %q refused (%d): %v", origin, code, err)
		}
		if !wantOK && (err == nil || code != http.StatusForbidden) {
			t.Errorf("origin %q admitted or wrong status %d (err=%v)", origin, code, err)
		}
	}
}

func TestParseOriginPolicyStarIsExclusive(t *testing.T) {
	p, err := ParseOriginPolicy("*")
	if err != nil || !p.any || p.enforcing() {
		t.Fatalf("* must be an explicit allow-any: %+v %v", p, err)
	}
	if _, err := ParseOriginPolicy("*,https://a.example"); err == nil {
		t.Fatal("* mixed with other origins must be an error")
	}
}
