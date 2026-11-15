package controlplane

import (
	"net/http"
	"strconv"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestAPIWriteLimiterBurstThenRefuse(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(3, 1, 16, clk.now)
	for i := 0; i < 3; i++ {
		if ok, _ := l.take("t", "a"); !ok {
			t.Fatalf("write %d of the burst refused", i+1)
		}
	}
	ok, wait := l.take("t", "a")
	if ok {
		t.Fatal("write beyond the burst allowed")
	}
	if wait <= 0 || wait > time.Second {
		t.Fatalf("wait = %v, want (0, 1s] at one write per second", wait)
	}
	// A refused attempt does not dig a deeper hole: after the advertised wait, one write is allowed.
	clk.advance(wait)
	if ok, _ := l.take("t", "a"); !ok {
		t.Fatal("write after the advertised wait refused")
	}
	if ok, _ := l.take("t", "a"); ok {
		t.Fatal("second write right after the refill allowed")
	}
}

func TestAPIWriteLimiterRefillCapsAtBurst(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(2, 1, 16, clk.now)
	l.take("t", "a")
	l.take("t", "a")
	clk.advance(time.Hour) // a long idle refills to the burst, never beyond it
	for i := 0; i < 2; i++ {
		if ok, _ := l.take("t", "a"); !ok {
			t.Fatalf("write %d after a long idle refused", i+1)
		}
	}
	if ok, _ := l.take("t", "a"); ok {
		t.Fatal("idle time banked more than the burst")
	}
}

func TestAPIWriteLimiterKeysAreIndependent(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(1, 1, 16, clk.now)
	if ok, _ := l.take("t", "a"); !ok {
		t.Fatal("first write for a refused")
	}
	if ok, _ := l.take("t", "a"); ok {
		t.Fatal("a's second write allowed")
	}
	if ok, _ := l.take("t", "b"); !ok {
		t.Fatal("token b refused because token a spent its budget")
	}
	if ok, _ := l.take("other", "a"); !ok {
		t.Fatal("same token id in another tenant shares a's budget")
	}
}

func TestAPIWriteLimiterClockBackwardsMintsNothing(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(1, 1, 16, clk.now)
	l.take("t", "a")
	clk.advance(-time.Hour)
	if ok, _ := l.take("t", "a"); ok {
		t.Fatal("a clock step backwards refilled the bucket")
	}
}

// Codex review r1: evicting a spent bucket and recreating it later would hand that token a fresh burst.
// At the cap with no full bucket, a NEW key is refused and every spent bucket keeps its state.
func TestAPIWriteLimiterNeverForgetsASpentBucket(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(2, 1, 2, clk.now)
	l.take("t", "a")
	l.take("t", "a") // a is spent
	l.take("t", "b") // b is part spent; the table is at its cap
	ok, wait := l.take("t", "c")
	if ok {
		t.Fatal("a new token was admitted by forgetting a spent bucket")
	}
	if wait <= 0 || wait > 2*time.Second {
		t.Fatalf("wait = %v, want the time until b refills (1s)", wait)
	}
	if ok, _ := l.take("t", "a"); ok {
		t.Fatal("the spent token got a fresh budget while the table was full")
	}
	// Once b has refilled, it is dropped and c gets room; a is still spent until its own refill.
	clk.advance(time.Second)
	if ok, _ := l.take("t", "c"); !ok {
		t.Fatal("new token refused after a bucket refilled and freed a slot")
	}
	if _, kept := l.tenants["t"].buckets["a"]; !kept {
		t.Fatal("the spent bucket was dropped")
	}
}

func TestAPIWriteLimiterEvictionKeepsSpentBuckets(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	// Full buckets are dropped before any spent one: refill everything, spend d, then add e.
	l2 := newAPIWriteLimiter(2, 1, 2, clk.now)
	l2.take("t", "full")
	l2.take("t", "spent")
	l2.take("t", "spent")
	clk.advance(1500 * time.Millisecond) // "full" is back to the burst; "spent" has 1.5
	l2.take("t", "new")
	if _, kept := l2.tenants["t"].buckets["spent"]; !kept {
		t.Fatal("a partly spent bucket was evicted while a full one was available")
	}
	if _, kept := l2.tenants["t"].buckets["full"]; kept {
		t.Fatal("the full bucket was not dropped")
	}
}

func apiLimitServer(t *testing.T, p *Principal, l *apiWriteLimiter) http.Handler {
	t.Helper()
	srv, _ := newTestServer(p)
	srv.APIWriteLimiter = l
	return srv.Handler()
}

func tokenPrincipal(id string) *Principal {
	return &Principal{UserID: id, TenantID: "tenant-123", APIToken: true,
		Grant: NewGrant(id, "tenant-123", NewCapabilityMembership(APITokenGrantableCapabilities(), AllGroups()))}
}

const apiLimitWriteKey = "PUT /machines/{id}/properties/{key}"

func apiLimitWrite(h http.Handler) (int, string) {
	rec := publicAPIWriteRequest(h, apiLimitWriteKey,
		publicAPIBasePath+"/machines/9f1c2c3a-4b5d-4e6f-8091-a2b3c4d5e6f7/properties/site", `{"value":"HQ"}`)
	return rec.Code, rec.Header().Get("Retry-After")
}

func TestPublicAPITokenWritesAreRateLimited(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(2, 1, 16, clk.now)
	h := apiLimitServer(t, tokenPrincipal("tok-a"), l)
	for i := 0; i < 2; i++ {
		if code, _ := apiLimitWrite(h); code == http.StatusTooManyRequests {
			t.Fatalf("write %d inside the burst got 429", i+1)
		}
	}
	code, retry := apiLimitWrite(h)
	if code != http.StatusTooManyRequests {
		t.Fatalf("write beyond the burst = %d, want 429", code)
	}
	if secs, err := strconv.Atoi(retry); err != nil || secs < 1 {
		t.Fatalf("Retry-After = %q, want a positive whole number of seconds", retry)
	}

	// Reads are never charged or refused.
	rec := publicAPIWriteRequest(h, "GET /machine-groups", publicAPIBasePath+"/machine-groups", "")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("a read was refused by the write limit")
	}

	// Another token, same limiter: its own budget.
	if code, _ := apiLimitWrite(apiLimitServer(t, tokenPrincipal("tok-b"), l)); code == http.StatusTooManyRequests {
		t.Fatal("token b was throttled by token a's spending")
	}

	// After the wait, token a may write again.
	clk.advance(time.Second)
	if code, _ := apiLimitWrite(h); code == http.StatusTooManyRequests {
		t.Fatal("write after Retry-After still refused")
	}
}

func TestPublicAPISessionWritesAreNotTokenLimited(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(1, 0.001, 16, clk.now)
	person := &Principal{UserID: "u-1", TenantID: "tenant-123",
		Grant: NewGrant("u-1", "tenant-123", NewCapabilityMembership(APITokenGrantableCapabilities(), AllGroups()))}
	h := apiLimitServer(t, person, l)
	for i := 0; i < 5; i++ {
		if code, _ := apiLimitWrite(h); code == http.StatusTooManyRequests {
			t.Fatalf("a console user's write %d was refused by the API token limit", i+1)
		}
	}
	if len(l.tenants) != 0 {
		t.Fatal("a non-token principal was charged to the token limiter")
	}
}

func TestPublicAPISpecDocuments429OnWritesOnly(t *testing.T) {
	doc := buildOpenAPIDocument("./" + PublicAPIVersion)
	paths := doc["paths"].(map[string]any)
	writes := 0
	for _, rt := range publicAPIRoutes() {
		op := paths[rt.Path].(map[string]any)[map[string]string{"GET": "get", "POST": "post", "PUT": "put", "PATCH": "patch", "DELETE": "delete"}[rt.Method]].(map[string]any)
		_, has := op["responses"].(map[string]any)["429"]
		if rt.Method == http.MethodGet && has {
			t.Fatalf("%s %s documents a 429 but reads are not limited", rt.Method, rt.Path)
		}
		if rt.Method != http.MethodGet {
			writes++
			if !has {
				t.Fatalf("%s %s does not document its 429", rt.Method, rt.Path)
			}
		}
	}
	if writes != 8 {
		t.Fatalf("checked %d write routes, want 8", writes)
	}
}

// Codex review r2: one tenant filling its table must not block another tenant's new tokens.
func TestAPIWriteLimiterTenantsCannotCrowdEachOther(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(2, 1, 2, clk.now)
	l.take("noisy", "1")
	l.take("noisy", "1")
	l.take("noisy", "2")
	l.take("noisy", "2") // noisy's table is full of spent buckets
	if ok, _ := l.take("noisy", "3"); ok {
		t.Fatal("noisy's third token admitted past its own cap")
	}
	if ok, _ := l.take("quiet", "x"); !ok {
		t.Fatal("another tenant's new token was refused because noisy filled its table")
	}
}

// A refused tenant waits exactly until a slot can free up, even when buckets were added after an
// earlier scan (the cached deadline is reset on every insert, never left stale).
func TestAPIWriteLimiterWaitIsExactAfterInserts(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(4, 1, 2, clk.now)
	for i := 0; i < 4; i++ {
		l.take("t", "a") // a is spent: 4s from full
	}
	l.take("t", "b") // b is one write down: 1s from full; the table is at its cap
	ok, wait := l.take("t", "c")
	if ok || wait != time.Second {
		t.Fatalf("take c = %v, wait %v; want refused with wait 1s (until b is full)", ok, wait)
	}
	clk.advance(500 * time.Millisecond)
	if ok, wait := l.take("t", "c"); ok || wait != 500*time.Millisecond {
		t.Fatalf("take c half-way = %v, wait %v; want refused with the remaining 500ms", ok, wait)
	}
	clk.advance(500 * time.Millisecond)
	if ok, _ := l.take("t", "c"); !ok {
		t.Fatal("take c refused once b had refilled")
	}
}

// Codex review r3's scenario: the cached deadline is the real refill time, not a rounded one.
func TestAPIWriteLimiterDeadlineIsNotRounded(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	l := newAPIWriteLimiter(2, 1, 2, clk.now)
	l.take("t", "a")
	l.take("t", "b") // both one write down: full again at +1s
	clk.advance(750 * time.Millisecond)
	if ok, wait := l.take("t", "c"); ok || wait != 250*time.Millisecond {
		t.Fatalf("take c at +0.75s = %v, wait %v; want refused for exactly the remaining 250ms", ok, wait)
	}
	clk.advance(250 * time.Millisecond)
	if ok, _ := l.take("t", "c"); !ok {
		t.Fatal("take c refused at +1s although a and b had refilled")
	}
}
