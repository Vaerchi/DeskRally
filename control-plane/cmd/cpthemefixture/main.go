// Command cpthemefixture is a TEST-ONLY control-plane HTTP server for the hostname-theming browser e2e
// (docs/66 stage 2: web/viewer/e2e/join_brand_host.spec.ts).
//
// It serves the REAL control-plane handler (Server.Handler(), so the public branding routes, the host policy,
// the edge authority gate and the 150 ms response schedule are exactly what production runs) over the REAL
// in-memory branding and hostname stores, and puts two fixture-only things around it:
//
//  1. An EDGE STAND-IN. In production Caddy sits in front of the control plane: it deletes any client copy of
//     X-DeskRally-Edge, sets the real one from the shared secret, and the control plane reads the authority
//     from the Host header. The browser in the e2e reaches the control plane through the Vite dev proxy, which
//     rewrites Host to 127.0.0.1:<port>, so the Host a guest "opened" cannot ride the connection. This binary
//     therefore takes the authority the test wants to present from the request header X-Fixture-Host (absent =
//     the default host), deletes that header, sets Host from it and sets the edge marker, exactly as the edge
//     would. A request is never mapped by a query parameter, and the production code has no such header at all
//     (control-plane/fixture_isolation_test.go asserts that no production source mentions it).
//
//  2. FIXTURE-ONLY ROUTES to publish a brand for one of the fixture's tenant hosts. They do not bypass the
//     rules: the input goes through PrepareBrandingRevision (the Owner route's own validation), a real revision
//     is created, reviewed and APPROVED through the store's compare-and-swap, so a brand that the real server
//     would refuse (a bidi override, a bad accent) is refused here too, and what is published is what the
//     public route serves.
//
// NEVER use this binary in production. It has no database, no authentication (every protected route answers
// 401), no throttle on the branding routes and a routing header that selects the host. It refuses to listen on
// anything but a loopback address.
//
// Environment variables:
//
//	CP_LISTEN   listen address, loopback only (default "127.0.0.1:8081", the port the Vite /cp proxy targets)
//
// Hosts (all under .localhost, which Chromium resolves to loopback, though the test never needs it to):
//
//	main.localhost                     the DEFAULT host: neutral, unscoped
//	tenant1.localhost .. tenant4...    ACTIVE tenant hosts, each its own tenant; a brand is published with /fixture/brand
//	pending.localhost                  a PENDING assignment: publishes nothing, so it answers neutral
//	anything else (rogue.localhost)    not a public authority: the edge gate refuses it with 421
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	cp "rmt/controlplane"
)

// FixtureHostHeader is how the test presents an authority. It exists only in this binary.
const fixtureHostHeader = "X-Fixture-Host"

const (
	defaultHost = "main.localhost"
	pendingHost = "pending.localhost"
)

var activeHosts = []string{"tenant1.localhost", "tenant2.localhost", "tenant3.localhost", "tenant4.localhost"}

// brandRequest is the body of POST /fixture/brand.
type brandRequest struct {
	Host           string          `json:"host"`
	ProductName    string          `json:"product_name"`
	AccentColor    string          `json:"accent_color"`
	SupportText    string          `json:"support_text"`
	SupportContact cp.BrandContact `json:"support_contact"`
	// Logo: "" or "none" = no logo; "wide" (160x48), "square" (64x64) or "tall" (40x120) = a generated PNG.
	Logo string `json:"logo"`
}

type fixture struct {
	hosts  *cp.InMemoryHostnameStore
	brands *cp.InMemoryBrandingStore
	op     cp.PlatformCaller

	mu       sync.Mutex
	tenantOf map[string]string // host -> tenant id
}

// logoPNG draws a deterministic logo of the named shape.
func logoPNG(kind string) ([]byte, error) {
	var w, h int
	switch kind {
	case "", "none":
		return nil, nil
	case "wide":
		w, h = 160, 48
	case "square":
		w, h = 64, 64
	case "tall":
		w, h = 40, 120
	default:
		return nil, fmt.Errorf("unknown logo %q (none, wide, square or tall)", kind)
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			c := color.NRGBA{R: 0x1d, G: 0x4e, B: 0xd8, A: 0xff}
			if (x/8+y/8)%2 == 0 {
				c = color.NRGBA{R: 0xf5, G: 0xc2, B: 0x0b, A: 0xff}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// publish creates a revision for the host's tenant and approves it, through the real store rules.
func (f *fixture) publish(ctx context.Context, req brandRequest) (map[string]any, int, error) {
	f.mu.Lock()
	tenant, ok := f.tenantOf[req.Host]
	f.mu.Unlock()
	if !ok {
		return nil, http.StatusNotFound, fmt.Errorf("%q is not one of the fixture's tenant hosts", req.Host)
	}
	logo, err := logoPNG(req.Logo)
	if err != nil {
		return nil, http.StatusBadRequest, err
	}
	prepared, ferr := cp.PrepareBrandingRevision(cp.BrandingRevisionInput{
		ProductName: req.ProductName, AccentColor: req.AccentColor, SupportText: req.SupportText,
		Contact: req.SupportContact, LogoPNG: logo,
	})
	if ferr != nil {
		return nil, http.StatusBadRequest, ferr
	}
	if _, _, err := f.brands.CreateRevision(ctx, tenant, "fixture-owner", prepared); err != nil {
		return nil, http.StatusInternalServerError, err
	}
	review, err := f.brands.Review(ctx, f.op, tenant)
	if err != nil || review.Draft == nil || review.Assignment == nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("review: %v", err)
	}
	if _, err := f.brands.Approve(ctx, f.op, tenant, cp.BrandingApproval{
		RevisionID: review.Draft.ID, Hash: review.Draft.Hash, AssignmentID: review.Assignment.ID, Generation: review.Generation,
	}, nil); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("approve: %w", err)
	}
	return map[string]any{
		"ok": true, "host": req.Host, "assignment_state": review.Assignment.State,
		"logo_rev": review.Draft.LogoSHA256, "revision_id": review.Draft.ID,
	}, http.StatusOK, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fixture) routes(srv http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /fixture/brand", func(w http.ResponseWriter, r *http.Request) {
		var req brandRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json: " + err.Error()})
			return
		}
		out, status, err := f.publish(r.Context(), req)
		if err != nil {
			writeJSON(w, status, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, status, out)
	})
	// Withdraws whatever is published for the host (the operator's real Withdraw): the very next public request is neutral.
	mux.HandleFunc("POST /fixture/withdraw", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
		f.mu.Lock()
		tenant, ok := f.tenantOf[req.Host]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown host"})
			return
		}
		if err := f.brands.Withdraw(r.Context(), f.op, tenant, nil); err != nil {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.Handle("/", srv)
	return mux
}

// edgeStandIn plays Caddy: it takes the authority the test presents from X-Fixture-Host (default host when
// absent), deletes the routing header and any client copy of the edge marker, and sets the real marker.
func edgeStandIn(secret string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.TrimSpace(r.Header.Get(fixtureHostHeader))
		r.Header.Del(fixtureHostHeader)
		if host == "" {
			host = defaultHost
		}
		r.Host = host
		r.Header.Del(cp.EdgeMarkerHeader)
		r.Header.Set(cp.EdgeMarkerHeader, secret)
		next.ServeHTTP(w, r)
	})
}

func mustLoopback(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		log.Fatalf("cpthemefixture: CP_LISTEN %q: %v", addr, err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("cpthemefixture: refusing to listen on %q: this test-only server accepts a routing header and has no authentication, so it binds loopback addresses only", addr)
	}
}

func main() {
	listen := os.Getenv("CP_LISTEN")
	if listen == "" {
		listen = "127.0.0.1:8081"
	}
	mustLoopback(listen)

	// A fresh random edge secret per process: the stand-in below is the only thing that knows it.
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		log.Fatalf("cpthemefixture: random: %v", err)
	}
	secret := hex.EncodeToString(raw)

	authorities := append([]string{defaultHost, pendingHost}, activeHosts...)
	policy, err := cp.NewHostPolicy(cp.HostPolicyConfig{
		DefaultHosts:      []string{defaultHost},
		PublicAuthorities: authorities,
		EdgeSecret:        secret,
		Theming:           true,
	})
	if err != nil {
		log.Fatalf("cpthemefixture: host policy: %v", err)
	}

	// Each fixture publication advances this clock, so the Owner's 20-revisions-an-hour budget (a real rule the
	// in-memory store enforces) never gets in the way of a test that re-publishes many times.
	var clockMu sync.Mutex
	clock := time.Now()
	hosts := &cp.InMemoryHostnameStore{Now: func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		clock = clock.Add(10 * time.Minute)
		return clock
	}}
	brands := cp.NewInMemoryBrandingStore(hosts)
	f := &fixture{hosts: hosts, brands: brands, op: cp.PlatformCaller{UserID: "fixture-operator", SessionID: "fixture-session", Email: "operator@fixture.test"},
		tenantOf: map[string]string{}}

	ctx := context.Background()
	assign := func(host string, activate bool) {
		tenant := "ffffffff-0000-4000-8000-" + fmt.Sprintf("%012d", len(f.tenantOf)+1)
		a, err := hosts.Assign(ctx, f.op, tenant, host, nil)
		if err != nil {
			log.Fatalf("cpthemefixture: assign %s: %v", host, err)
		}
		if activate {
			if _, err := hosts.Activate(ctx, f.op, a.ID, nil); err != nil {
				log.Fatalf("cpthemefixture: activate %s: %v", host, err)
			}
		}
		f.tenantOf[host] = tenant
	}
	for _, h := range activeHosts {
		assign(h, true)
	}
	assign(pendingHost, false)

	// A server with NO way to authenticate: every protected route answers 401, so the fixture exposes only the
	// public routes (and the fixture-only ones above).
	srv := cp.NewServer(&cp.SessionAuthenticator{Sessions: cp.NewSessionManager(cp.NewInMemorySessionStore()), Users: cp.NewInMemoryUserStore()}, cp.NoopBinder{})
	srv.HostPolicy = policy
	srv.Hostnames = hosts
	srv.BrandingRevisions = brands
	// The real schedule (150 ms floor plus jitter) stays; only the abuse limits are relaxed so a test that
	// reloads quickly is never answered 429 by the per-IP budget.
	srv.BrandingTuning = cp.BrandingTuning{AdmitPerIP: 32, RatePerMinute: -1}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		log.Fatalf("cpthemefixture: listen %s: %v", listen, err)
	}
	ready, _ := json.Marshal(map[string]any{
		"ready": true, "listen_addr": ln.Addr().String(), "default_host": defaultHost, "active_hosts": activeHosts,
		"pending_host": pendingHost, "host_header": fixtureHostHeader,
	})
	fmt.Printf("FIXTURE_READY %s\n", ready)
	log.Printf("cpthemefixture: listening on %s (default host %s, tenant hosts %v)", ln.Addr(), defaultHost, activeHosts)
	if err := http.Serve(ln, f.routes(edgeStandIn(secret, srv.Handler()))); err != nil {
		log.Fatalf("cpthemefixture: serve: %v", err)
	}
}
