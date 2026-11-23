package controlplane

// Pool-occupancy proof for streaming(): long responses must not hold tenant-pinned pooled connections
// (external review, security review 2026-11-01 #5). Needs TEST_DATABASE_URL like every pgx test here.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// streamingRig is a tenant-bound handler chain (the real tenantMiddleware + PgBinder) over a small rmt_app pool.
type streamingRig struct {
	pool *pgxpool.Pool
	srv  *httptest.Server
	tidA string
	tidB string
}

func newStreamingRig(t *testing.T, maxConns int32, routes func(mux *http.ServeMux, pool *pgxpool.Pool)) *streamingRig {
	t.Helper()
	suPool := newTestPool(t)
	applyAppRoleMigration(t, suPool)
	applyAttendedMigration(t, suPool)
	ctx := context.Background()
	var a, b string
	if err := suPool.QueryRow(ctx, "SELECT gen_random_uuid()::text, gen_random_uuid()::text").Scan(&a, &b); err != nil {
		t.Fatalf("uuids: %v", err)
	}
	seedTenantWithMachine(t, suPool, a, "stream-a")
	seedTenantWithMachine(t, suPool, b, "stream-b")
	cfg, err := pgxpool.ParseConfig(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.User, cfg.ConnConfig.Password = "rmt_app", ""
	cfg.MaxConns = maxConns
	appPool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect as rmt_app: %v", err)
	}
	mux := http.NewServeMux()
	routes(mux, appPool)
	s := &Server{Binder: NewPgBinder(appPool)}
	// The tenant is chosen by header, standing in for the authenticated principal.
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := a
		if r.Header.Get("X-Tenant") == "b" {
			tid = b
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxPrincipal, &Principal{TenantID: tid}))
		s.tenantMiddleware(mux).ServeHTTP(w, r)
	})
	srv := httptest.NewServer(h)
	t.Cleanup(func() { srv.CloseClientConnections(); srv.Close(); appPool.Close() })
	return &streamingRig{pool: appPool, srv: srv, tidA: a, tidB: b}
}

// holdHandler reads the caller's machines through the store, writes a first chunk, then blocks until release closes.
func holdHandler(pool *pgxpool.Pool, started *atomic.Int32, release <-chan struct{}, sawBound *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := principalFrom(r.Context())
		ms, err := NewPgMachineStore(pool).ListMachines(r.Context(), p.TenantID)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if boundConnFrom(r.Context()) != nil && r.URL.Path != "" {
			sawBound.Add(1)
		}
		w.WriteHeader(200)
		for _, m := range ms {
			_, _ = w.Write([]byte(m.DeviceID + "\n"))
		}
		w.(http.Flusher).Flush()
		started.Add(1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}
}

func getStatus(url, tenant string, readBody bool) (int, string, error) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("X-Tenant", tenant)
	cl := &http.Client{Timeout: 20 * time.Second}
	resp, err := cl.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if !readBody {
		return resp.StatusCode, "", nil
	}
	buf := make([]byte, 256)
	n, _ := resp.Body.Read(buf)
	// Keep draining: closing here would cancel the request and end the handler (and free its connection).
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, string(buf[:n]), nil
}

func streamEventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// Eight slow downloads on a THREE-connection pool all reach their blocked body write (so none waited for a
// pooled connection), the pool is nearly idle while they drain, an unrelated console request is served, and every
// request saw only its own tenant's rows through the released-connection fallback (RLS still applies).
func TestStreamingRoutesDoNotHoldPooledConnections(t *testing.T) {
	var started, sawBound atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	rig := newStreamingRig(t, 3, func(mux *http.ServeMux, pool *pgxpool.Pool) {
		mux.HandleFunc("GET /slow", streaming(holdHandler(pool, &started, release, &sawBound)))
		mux.HandleFunc("GET /console", func(w http.ResponseWriter, r *http.Request) {
			ms, err := NewPgMachineStore(pool).ListMachines(r.Context(), principalFrom(r.Context()).TenantID)
			if err != nil || len(ms) != 1 {
				http.Error(w, "bad", 500)
				return
			}
			w.WriteHeader(200)
		})
	})
	defer once.Do(func() { close(release) })

	const n = 8
	bodies := make(chan string, n)
	for i := 0; i < n; i++ {
		tenant := "a"
		if i%2 == 1 {
			tenant = "b"
		}
		go func() {
			code, body, err := getStatus(rig.srv.URL+"/slow", tenant, true)
			if err != nil || code != 200 {
				bodies <- "ERR"
				return
			}
			bodies <- tenant + ":" + body
		}()
	}
	streamEventually(t, "all slow downloads to reach the body write", func() bool { return started.Load() == n })
	if sawBound.Load() != 0 {
		t.Fatalf("%d streaming requests still saw a bound connection", sawBound.Load())
	}
	if got := rig.pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("pool has %d connections checked out while %d downloads drain; want 0", got, n)
	}
	if code, _, err := getStatus(rig.srv.URL+"/console", "a", false); err != nil || code != 200 {
		t.Fatalf("unrelated console request while downloads drain = %d, %v", code, err)
	}
	once.Do(func() { close(release) })
	for i := 0; i < n; i++ {
		b := <-bodies
		switch {
		case strings.HasPrefix(b, "a:"):
			if strings.TrimSpace(b[2:]) != "dev-stream-a" {
				t.Fatalf("tenant A saw %q", b)
			}
		case strings.HasPrefix(b, "b:"):
			if strings.TrimSpace(b[2:]) != "dev-stream-b" {
				t.Fatalf("tenant B saw %q", b)
			}
		default:
			t.Fatalf("download failed: %q", b)
		}
	}
}

// The control: the SAME slow handler without streaming() pins one connection each, exhausting the pool. This is
// what proves the test above can fail.
func TestNonStreamingSlowHandlerPinsConnections(t *testing.T) {
	var started, sawBound atomic.Int32
	release := make(chan struct{})
	var once sync.Once
	rig := newStreamingRig(t, 3, func(mux *http.ServeMux, pool *pgxpool.Pool) {
		mux.HandleFunc("GET /slow", holdHandler(pool, &started, release, &sawBound))
	})
	defer once.Do(func() { close(release) })
	for i := 0; i < 3; i++ {
		go func() { _, _, _ = getStatus(rig.srv.URL+"/slow", "a", true) }()
	}
	streamEventually(t, "three pinned slow handlers", func() bool { return started.Load() == 3 })
	if got := rig.pool.Stat().AcquiredConns(); got != 3 {
		t.Fatalf("control: pool has %d checked out, want all 3 pinned (sawBound=%d)", got, sawBound.Load())
	}
	once.Do(func() { close(release) })
}
