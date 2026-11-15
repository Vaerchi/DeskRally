package controlplane

// Security review 2026-11-01 #17: webhook dispatch is a bounded worker pool with bounded
// per-tenant queues and a short total deadline per delivery, and never blocks the request path.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// tarpit accepts requests and answers only when released (or the client gives up).
type tarpit struct {
	ts      *httptest.Server
	release chan struct{}
	hits    atomic.Int64
}

func newTarpit(t *testing.T) *tarpit {
	tp := &tarpit{release: make(chan struct{})}
	tp.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp.hits.Add(1)
		select {
		case <-tp.release:
		case <-r.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(tp.release)
		tp.ts.Close()
	})
	return tp
}

func webhookStoreWith(t *testing.T, tenant string, urls ...string) *InMemoryWebhookStore {
	t.Helper()
	store := NewInMemoryWebhookStore()
	for i, u := range urls {
		wh := &TenantWebhook{ID: "wh-" + tenant + "-" + strconv.Itoa(i), URL: u, CreatedAt: time.Now().UTC()}
		if err := store.Create(context.Background(), tenant, wh, "secret", maxWebhooksPerTenant); err != nil {
			t.Fatal(err)
		}
	}
	return store
}

func TestWebhookDispatchIsBoundedAndNeverBlocks(t *testing.T) {
	tp := newTarpit(t)
	store := webhookStoreWith(t, "t1", tp.ts.URL)
	d := &WebhookDispatcher{Store: store, Client: tp.ts.Client(), Workers: 2, PerTenantQueue: 3,
		PerTenantInflight: 2, JobDeadline: 3 * time.Second}
	t.Cleanup(d.Stop)

	before := runtime.NumGoroutine()
	const events = 2000
	start := time.Now()
	var slowest time.Duration
	for i := 0; i < events; i++ {
		t0 := time.Now()
		d.Dispatch("t1", &MgmtAuditEvent{ID: strconv.Itoa(i), Action: "machine.alias_set", TenantID: "t1"})
		if el := time.Since(t0); el > slowest {
			slowest = el
		}
	}
	if total := time.Since(start); total > 2*time.Second || slowest > 250*time.Millisecond {
		t.Fatalf("Dispatch blocked the caller: total %v, slowest single call %v", total, slowest)
	}
	// 2 workers running + 3 queued; everything else is dropped and counted.
	if got := d.Dropped(); got < events-10 || got > events-3 {
		t.Fatalf("dropped = %d of %d, want nearly all (queue 3 + inflight 2)", got, events)
	}
	// Goroutines grew by the fixed pool plus the in-flight HTTP plumbing, never by event count.
	if grown := runtime.NumGoroutine() - before; grown > 40 {
		t.Fatalf("goroutines grew by %d for %d events", grown, events)
	}
}

func TestWebhookDeliveryHasATotalDeadline(t *testing.T) {
	tp := newTarpit(t)
	store := webhookStoreWith(t, "t1", tp.ts.URL, tp.ts.URL, tp.ts.URL, tp.ts.URL) // 4 tarpit targets
	d := &WebhookDispatcher{Store: store, Client: tp.ts.Client(), JobDeadline: 300 * time.Millisecond}
	d.retryDelay = 50 * time.Millisecond

	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), d.jobDeadline())
	defer cancel()
	if err := d.dispatchCtx(ctx, "t1", &MgmtAuditEvent{Action: "x", TenantID: "t1"}); err != nil {
		t.Fatal(err)
	}
	// 4 targets x 2 attempts with no client timeout would block until the tarpit released; the
	// shared deadline cuts the whole fan-out at ~JobDeadline.
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("fan-out took %v under a 300ms deadline", el)
	}
	if tp.hits.Load() >= 8 {
		t.Fatalf("all 8 attempts were made despite the deadline")
	}
}

// One tenant's tarpit endpoints cannot occupy every worker: another tenant's delivery still runs.
func TestWebhookTenantCannotStarveAnother(t *testing.T) {
	tp := newTarpit(t)
	var delivered atomic.Int64
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
	}))
	t.Cleanup(good.Close)

	store := NewInMemoryWebhookStore()
	for tenant, url := range map[string]string{"bad": tp.ts.URL, "good": good.URL} {
		wh := &TenantWebhook{ID: "wh-" + tenant, URL: url, CreatedAt: time.Now().UTC()}
		if err := store.Create(context.Background(), tenant, wh, "s", maxWebhooksPerTenant); err != nil {
			t.Fatal(err)
		}
	}
	d := &WebhookDispatcher{Store: store, Client: http.DefaultClient, Workers: 2, PerTenantQueue: 50,
		PerTenantInflight: 1, JobDeadline: 20 * time.Second}
	t.Cleanup(d.Stop)

	for i := 0; i < 30; i++ {
		d.Dispatch("bad", &MgmtAuditEvent{Action: "x", TenantID: "bad"})
	}
	d.Dispatch("good", &MgmtAuditEvent{Action: "x", TenantID: "good"})
	deadline := time.Now().Add(3 * time.Second)
	for delivered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if delivered.Load() != 1 {
		t.Fatalf("the healthy tenant's webhook was not delivered while another tenant's endpoint hung (workers monopolised)")
	}
	if tp.hits.Load() != 1 {
		t.Fatalf("tenant 'bad' had %d concurrent deliveries, want its in-flight cap of 1", tp.hits.Load())
	}
}

func TestWebhookDispatchStillDelivers(t *testing.T) {
	var mu sync.Mutex
	got := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got++
		mu.Unlock()
	}))
	t.Cleanup(ts.Close)
	store := webhookStoreWith(t, "t1", ts.URL)
	d := &WebhookDispatcher{Store: store, Client: ts.Client()}
	t.Cleanup(d.Stop)
	for i := 0; i < 10; i++ {
		d.Dispatch("t1", &MgmtAuditEvent{Action: "x", TenantID: "t1"})
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := got
		mu.Unlock()
		if n == 10 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("delivered %d of 10", got)
}
