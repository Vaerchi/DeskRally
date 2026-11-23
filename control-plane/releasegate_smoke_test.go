//go:build releasegate

package controlplane

// The docs/66 release gate's real-binary smoke stage (plan step 7; merged plan items 7 and 11).
//
// Every other gate phase runs the real handler in-process. This one builds the actual cmd/controlplane executable,
// migrates a scratch database it creates and drops, starts the binary as a child process with the production
// configuration shape (rmt_app DSN, edge marker, host theming, trusted proxy) listening on 127.0.0.1 only, waits for
// /readyz and probes it over real TCP. It covers what the in-process path cannot: cmd/controlplane/main.go's wiring
// of NewPublicServer + LimitListener, the process boundary, and cold start.
//
// HARD GATE (a failure fails the release):
//   - HTTP/2 negative (docs/66 2e.2: HTTP/1.1 only, no h2c handler; an h2 attempt is refused or downgraded, never
//     multiplexed): h2c prior knowledge, the h2c Upgrade, a Go unencrypted-HTTP/2 client and a TLS ALPN h2 hello.
//   - Slowloris closure (2d.2, 2e.2: ReadHeaderTimeout 5 s, ReadTimeout 5 s): slow header writers and slow body writers
//     are cut by the server within the bound, and ordinary requests keep succeeding while they trickle.
//   - Cold process: after each restart the first requests are correct (the neutral body, 421 for a forged authority).
//
// RECORDED ONLY: cold timings, RSS (working set / VmRSS), handle or descriptor count, and the scratch database's
// connection count, before and after load.
//
//	DESKRALLY_RELEASE_GATE=1 TEST_DATABASE_URL=... go test -tags releasegate -run TestReleaseGateRealBinarySmoke -count=1 .
//
// Missing prerequisites (database, go toolchain, a failed build or migrate) are FAILURES, never skips.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	smokeHost          = "main.smoke.test"
	smokeReadyTimeout  = 30 * time.Second
	smokeColdCycles    = 3
	smokeCutSlack      = 3 * time.Second // allowance on top of the 5 s server bounds (scheduler, 1 s trickle granularity, loaded box)
	smokeSlowConns     = 8               // per kind
	smokeProbeMaxLat   = 2 * time.Second // the doc's 2 s request deadline: a probe may never wait longer than an exchange
	smokeLoadWorkers   = 8
	smokeLoadDuration  = 4 * time.Second
	smokeLoadPause     = 100 * time.Millisecond // about 80 req/s in all
	smokeFirstReqFloor = 150 * time.Millisecond
)

type smokeSnap struct {
	Label     string `json:"label"`
	RSSBytes  uint64 `json:"rss_bytes"`
	Handles   int    `json:"handles_or_fds"`
	DBConns   int    `json:"scratch_db_connections"`
	StatError string `json:"stat_error,omitempty"`
}

type smokeCold struct {
	Cycle          int     `json:"cycle"`
	ReadyMS        float64 `json:"start_to_ready_ms"`
	FirstBrandMS   float64 `json:"first_branding_ms"`
	SecondBrandMS  float64 `json:"second_branding_ms"`
	ForgedStatus   int     `json:"forged_authority_status"`
	HealthzStatus  int     `json:"healthz_status"`
	BrandingStatus int     `json:"first_branding_status"`
	BodySHA256     string  `json:"branding_body_sha256"`
}

type smokeH2Case struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
	Pass    bool   `json:"pass"`
}

type smokeSlow struct {
	Kind        string  `json:"kind"`
	Conns       int     `json:"conns"`
	StillOpen   int     `json:"still_open_at_end"`
	MinLifeMS   float64 `json:"min_life_ms"`
	MaxLifeMS   float64 `json:"max_life_ms"`
	BoundMS     float64 `json:"bound_ms"`
	FirstAnswer string  `json:"first_response_line,omitempty"`
}

type smokeProbe struct {
	Count    int     `json:"count"`
	NonOK    int     `json:"non_200"`
	MaxMS    float64 `json:"max_ms"`
	FirstBad string  `json:"first_bad,omitempty"`
}

type smokeRecord struct {
	Test      string        `json:"test"`
	GOOS      string        `json:"goos"`
	NumCPU    int           `json:"num_cpu"`
	GoVersion string        `json:"go_version"`
	BuildMS   int64         `json:"build_ms"`
	ExeBytes  int64         `json:"exe_bytes"`
	ExeSHA256 string        `json:"exe_sha256"`
	MigrateMS int64         `json:"migrate_ms"`
	Cold      []smokeCold   `json:"cold_process"`
	HTTP2     []smokeH2Case `json:"http2_negative"`
	Slowloris []smokeSlow   `json:"slowloris"`
	Probes    smokeProbe    `json:"probes_during_slowloris"`
	Load      smokeProbe    `json:"load"`
	Process   []smokeSnap   `json:"process_stats_recorded_only"`
	Failures  []string      `json:"failures"`
}

// smokeXFF hands every request its own client address (the binary trusts 127.0.0.1 as the proxy), so the per-address
// admission and throttles never see the one loopback peer as a single abusive client.
var smokeXFFSeq atomic.Uint32

func smokeXFF() string {
	n := smokeXFFSeq.Add(1)
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&0xff, (n>>8)&0xff, n&0xff)
}

// smokeColdObs is what one cold start observed; smokeColdVerdict judges it (the hard-gate rule, separate from the
// process so a negative control can feed it a bad observation).
type smokeColdObs struct {
	Cycle     int
	Status    int
	Took      time.Duration // the first branding response
	Body      []byte        // the first branding body
	Body2     []byte        // the second (warm) branding body of the same process
	FirstBody []byte        // the first process's first body; nil on the first cycle
	Forged    int           // status for a forged authority carrying the marker
	Healthz   int
}

func smokeColdVerdict(o smokeColdObs) []string {
	var f []string
	if o.Status != 200 {
		f = append(f, fmt.Sprintf("cycle %d: first /public/branding after start = %d, want 200 (%q)", o.Cycle, o.Status, o.Body))
	}
	if o.Took < smokeFirstReqFloor {
		f = append(f, fmt.Sprintf("cycle %d: the first branding response took %s, under the %s floor (docs/66 2c.3)", o.Cycle, o.Took, smokeFirstReqFloor))
	}
	if !bytes.Equal(o.Body, o.Body2) {
		f = append(f, fmt.Sprintf("cycle %d: the cold first body differs from the warm second body: %q vs %q", o.Cycle, o.Body, o.Body2))
	}
	if o.FirstBody != nil && !bytes.Equal(o.Body, o.FirstBody) {
		f = append(f, fmt.Sprintf("cycle %d: the first body differs from the first process's: %q vs %q", o.Cycle, o.Body, o.FirstBody))
	}
	if o.Forged != http.StatusMisdirectedRequest {
		f = append(f, fmt.Sprintf("cycle %d: a forged authority with the marker got %d, want 421 (docs/66 2b.6)", o.Cycle, o.Forged))
	}
	if o.Healthz != 200 {
		f = append(f, fmt.Sprintf("cycle %d: /healthz = %d", o.Cycle, o.Healthz))
	}
	return f
}

func smokeMS(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

// ---------------------------------------------------------------------------------------------------------
// Fixture: build, scratch database, child process.
// ---------------------------------------------------------------------------------------------------------

type smokeEnv struct {
	t       *testing.T
	exe     string
	migDir  string
	adminDB string // superuser DSN of the scratch database (migrations only)
	appDSN  string // rmt_app DSN of the scratch database (the binary)
	scratch string
	edge    string
	seed    string
}

func smokeRand(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func smokeDSNs(t *testing.T, scratch string) (admin, app string) {
	t.Helper()
	u, err := url.Parse(testDBURL())
	if err != nil {
		t.Fatalf("TEST_DATABASE_URL: %v", err)
	}
	u.Path = "/" + scratch
	admin = u.String()
	u.User = url.User("rmt_app")
	return admin, u.String()
}

func newSmokeEnv(t *testing.T, rec *smokeRecord) *smokeEnv {
	t.Helper()
	requireGateDB(t)
	ctx := context.Background()
	e := &smokeEnv{t: t, edge: smokeRand(t, 32), seed: smokeRand(t, 32)}
	var err error
	if e.migDir, err = filepath.Abs("migrations"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(e.migDir); err != nil {
		t.Fatalf("migrations directory: %v", err)
	}

	// Build the real executable.
	dir := t.TempDir()
	e.exe = filepath.Join(dir, "controlplane")
	if runtime.GOOS == "windows" {
		e.exe += ".exe"
	}
	t0 := time.Now()
	bctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(bctx, "go", "build", "-o", e.exe, "./cmd/controlplane").CombinedOutput()
	if err != nil {
		t.Fatalf("go build ./cmd/controlplane: %v\n%s", err, out)
	}
	rec.BuildMS = time.Since(t0).Milliseconds()
	b, err := os.ReadFile(e.exe)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	rec.ExeBytes, rec.ExeSHA256 = int64(len(b)), hex.EncodeToString(sum[:])

	// Scratch database: created here, dropped in cleanup; nothing in rmt_test is touched.
	au, err := url.Parse(testDBURL())
	if err != nil {
		t.Fatal(err)
	}
	au.Path = "/postgres"
	admin, err := pgx.Connect(ctx, au.String())
	if err != nil {
		t.Fatalf("connect to the admin database: %v", err)
	}
	e.scratch = fmt.Sprintf("dr_smoke_%d", time.Now().UnixNano())
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+e.scratch); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create scratch database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+e.scratch+" WITH (FORCE)")
		_ = admin.Close(context.Background())
	})
	e.adminDB, e.appDSN = smokeDSNs(t, e.scratch)

	// Migrate through the real binary's own subcommand.
	t0 = time.Now()
	mctx, mcancel := context.WithTimeout(ctx, 5*time.Minute)
	defer mcancel()
	mc := exec.CommandContext(mctx, e.exe, "migrate")
	mc.Env = append(smokeBaseEnv(), "MIGRATE_DATABASE_URL="+e.adminDB, "MIGRATIONS_DIR="+e.migDir)
	if out, err = mc.CombinedOutput(); err != nil {
		t.Fatalf("controlplane migrate: %v\n%s", err, out)
	}
	rec.MigrateMS = time.Since(t0).Milliseconds()
	return e
}

// smokeBaseEnv is the whole inherited environment the child gets: nothing but what a process needs to start.
func smokeBaseEnv() []string {
	var env []string
	for _, k := range []string{"PATH", "SystemRoot", "SYSTEMROOT", "SystemDrive", "TEMP", "TMP", "TMPDIR", "HOME", "USERPROFILE"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type smokeLog struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *smokeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 1<<16 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *smokeLog) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type smokeProc struct {
	e      *smokeEnv
	cmd    *exec.Cmd
	addr   string
	log    *smokeLog
	exited chan struct{}
	ready  time.Duration
}

func smokeFreePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// start launches the binary on a fresh loopback port and waits for /readyz. The child is killed in cleanup however
// the test ends. A port taken between probing and binding is retried.
func (e *smokeEnv) start() *smokeProc {
	e.t.Helper()
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		p := &smokeProc{e: e, addr: smokeFreePort(e.t), log: &smokeLog{}, exited: make(chan struct{})}
		p.cmd = exec.Command(e.exe)
		p.cmd.Env = append(smokeBaseEnv(),
			"DATABASE_URL="+e.appDSN,
			"CP_LISTEN="+p.addr,
			"GRANT_ISSUER_SEED="+e.seed,
			"CP_HOST_THEMING=on",
			"CP_DEFAULT_HOSTS="+smokeHost,
			"CP_PUBLIC_AUTHORITIES="+smokeHost,
			"CP_EDGE_SECRET="+e.edge,
			"CP_TRUSTED_PROXIES=127.0.0.1/32",
		)
		p.cmd.Stdout, p.cmd.Stderr = p.log, p.log
		t0 := time.Now()
		if err := p.cmd.Start(); err != nil {
			e.t.Fatalf("start controlplane: %v", err)
		}
		go func() { _ = p.cmd.Wait(); close(p.exited) }()
		e.t.Cleanup(p.stop)
		lastErr = nil
		deadline := time.Now().Add(smokeReadyTimeout)
	wait:
		for time.Now().Before(deadline) {
			select {
			case <-p.exited:
				lastErr = fmt.Errorf("exited before ready:\n%s", p.log.String())
				break wait
			default:
			}
			if st, _, _, err := smokeGet(p.addr, "/readyz", "", ""); err == nil && st == 200 {
				p.ready = time.Since(t0)
				return p
			}
			time.Sleep(20 * time.Millisecond)
		}
		if lastErr == nil {
			lastErr = fmt.Errorf("not ready within %s:\n%s", smokeReadyTimeout, p.log.String())
		}
		p.stop()
		if !strings.Contains(p.log.String(), "address already in use") && !strings.Contains(p.log.String(), "Only one usage") {
			break
		}
	}
	e.t.Fatalf("controlplane: %v", lastErr)
	return nil
}

func (p *smokeProc) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
	select {
	case <-p.exited:
	case <-time.After(10 * time.Second):
	}
}

func (p *smokeProc) alive() bool {
	select {
	case <-p.exited:
		return false
	default:
		return true
	}
}

func (p *smokeProc) snap(label string) smokeSnap {
	s := smokeSnap{Label: label}
	rss, h, err := smokeProcStats(p.cmd.Process.Pid)
	if err != nil {
		s.StatError = err.Error()
	} else {
		s.RSSBytes, s.Handles = rss, h
	}
	// Connections the binary holds to the scratch database (recorded; the plan's pg_stat_activity check).
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c, cerr := pgx.Connect(ctx, p.e.adminDB); cerr == nil {
		_ = c.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = $1 AND usename = 'rmt_app'", p.e.scratch).Scan(&s.DBConns)
		_ = c.Close(ctx)
	}
	return s
}

// ---------------------------------------------------------------------------------------------------------
// Probes.
// ---------------------------------------------------------------------------------------------------------

var smokeClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{DisableKeepAlives: true},
}

// smokeGet: one GET over a fresh TCP connection. host == "" sends no edge marker and the default Host (an internal
// caller, as the compose probes are); otherwise the request comes "through the edge" with the marker.
func smokeGet(addr, path, host, edge string) (status int, body []byte, took time.Duration, err error) {
	req, err := http.NewRequest("GET", "http://"+addr+path, nil)
	if err != nil {
		return 0, nil, 0, err
	}
	if host != "" {
		req.Host = host
		req.Header.Set(EdgeMarkerHeader, edge)
		req.Header.Set("X-Forwarded-For", smokeXFF())
	}
	t0 := time.Now()
	resp, err := smokeClient.Do(req)
	if err != nil {
		return 0, nil, time.Since(t0), err
	}
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	return resp.StatusCode, body, time.Since(t0), err
}

// ---------------------------------------------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------------------------------------------

func TestReleaseGateRealBinarySmoke(t *testing.T) {
	rec := &smokeRecord{Test: "TestReleaseGateRealBinarySmoke", GOOS: runtime.GOOS, NumCPU: runtime.NumCPU(), GoVersion: runtime.Version(), Failures: []string{}}
	fail := func(format string, a ...any) {
		t.Helper()
		msg := fmt.Sprintf(format, a...)
		rec.Failures = append(rec.Failures, msg)
		t.Error(msg)
	}
	defer func() {
		dir := os.Getenv("DESKRALLY_GATE_OUT")
		if dir == "" {
			dir = t.TempDir()
		}
		b, _ := json.MarshalIndent(rec, "", "  ")
		p := filepath.Join(dir, rec.Test+".json")
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Errorf("write record: %v", err)
		}
		t.Logf("release gate record: %s", p)
	}()

	e := newSmokeEnv(t, rec)

	// Cold process: restart the binary several times; the last one is kept for the remaining probes.
	var p *smokeProc
	var firstBody string
	for cycle := 1; cycle <= smokeColdCycles; cycle++ {
		if p != nil {
			p.stop()
			if p.alive() {
				fail("cycle %d: the previous process did not exit after Kill", cycle)
			}
		}
		p = e.start()
		c := smokeCold{Cycle: cycle, ReadyMS: smokeMS(p.ready)}
		st, body, took, err := smokeGet(p.addr, "/public/branding", smokeHost, e.edge)
		if err != nil {
			fail("cycle %d: first branding request: %v", cycle, err)
			continue
		}
		c.BrandingStatus, c.FirstBrandMS = st, smokeMS(took)
		sum := sha256.Sum256(body)
		c.BodySHA256 = hex.EncodeToString(sum[:])
		obs := smokeColdObs{Cycle: cycle, Status: st, Took: took, Body: body}
		if cycle > 1 {
			obs.FirstBody = []byte(firstBody)
		}
		_, body2, took2, err := smokeGet(p.addr, "/public/branding", smokeHost, e.edge)
		if err != nil {
			fail("cycle %d: second branding request: %v", cycle, err)
		}
		obs.Body2 = body2
		c.SecondBrandMS = smokeMS(took2)
		if cycle == 1 {
			firstBody = string(body)
		}
		fst, _, _, err := smokeGet(p.addr, "/public/branding", "forged.example", e.edge)
		if err != nil {
			fail("cycle %d: forged-authority request: %v", cycle, err)
		}
		hst, _, _, err := smokeGet(p.addr, "/healthz", "", "")
		if err != nil {
			fail("cycle %d: /healthz: %v", cycle, err)
		}
		c.ForgedStatus, c.HealthzStatus = fst, hst
		obs.Forged, obs.Healthz = fst, hst
		for _, m := range smokeColdVerdict(obs) {
			fail("%s", m)
		}
		rec.Cold = append(rec.Cold, c)
	}

	rec.Process = append(rec.Process, p.snap("cold-start, after the first requests"))
	smokeHTTP2Negative(t, p, rec, fail)
	smokeLoad(t, p, rec, fail)
	smokeSlowloris(t, p, rec, fail)

	// The binary must still answer normally after everything above, and still be the same process.
	if !p.alive() {
		fail("the binary exited during the smoke:\n%s", p.log.String())
	} else if st, _, _, err := smokeGet(p.addr, "/readyz", "", ""); err != nil || st != 200 {
		fail("/readyz after the smoke: status %d err %v", st, err)
	}
	rec.Process = append(rec.Process, p.snap("after slowloris"))
	for _, s := range rec.Process {
		t.Logf("process %-40s rss=%d MiB handles=%d db_conns=%d %s", s.Label, s.RSSBytes>>20, s.Handles, s.DBConns, s.StatError)
	}
}

// ---------------------------------------------------------------------------------------------------------
// HTTP/2 negative.
// ---------------------------------------------------------------------------------------------------------

// smokeRawExchange sends raw bytes and reads whatever the server returns until it closes or the deadline passes.
func smokeRawExchange(addr string, payload []byte, wait time.Duration) (got []byte, closed bool, err error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, false, err
	}
	defer c.Close()
	if _, err = c.Write(payload); err != nil {
		return nil, true, nil
	}
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf, rerr := io.ReadAll(io.LimitReader(c, 1<<16))
	if rerr != nil {
		if ne, ok := rerr.(net.Error); ok && ne.Timeout() {
			return buf, false, nil
		}
	}
	return buf, true, nil
}

func smokeHTTP2Negative(t *testing.T, p *smokeProc, rec *smokeRecord, fail func(string, ...any)) {
	t.Helper()
	rec.HTTP2 = smokeHTTP2Check(p.addr)
	for _, c := range rec.HTTP2 {
		if !c.Pass {
			fail("HTTP/2 negative %q: %s", c.Name, c.Outcome)
		}
	}
}

// smokeHTTP2Check runs the HTTP/2 negative against any plaintext target and returns one case per attempt. It is
// target-agnostic so the negative control can point it at a server that DOES speak h2c.
func smokeHTTP2Check(addr string) []smokeH2Case {
	var cases []smokeH2Case
	add := func(name, outcome string, pass bool) {
		cases = append(cases, smokeH2Case{Name: name, Outcome: outcome, Pass: pass})
	}
	firstLine := func(b []byte) string {
		s := string(b)
		if i := strings.Index(s, "\r\n"); i >= 0 {
			s = s[:i]
		}
		if len(s) > 80 {
			s = s[:80]
		}
		return s
	}
	// An HTTP/2 answer is a SETTINGS frame (type 4) in the first nine bytes and no HTTP/1 status line.
	isH2Frame := func(b []byte) bool { return len(b) >= 9 && b[3] == 4 && !bytes.HasPrefix(b, []byte("HTTP/")) }

	// 1. h2c with prior knowledge: the client preface plus an empty SETTINGS frame.
	preface := append([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), 0, 0, 0, 4, 0, 0, 0, 0, 0)
	got, closed, err := smokeRawExchange(addr, preface, 3*time.Second)
	switch {
	case err != nil:
		add("h2c prior knowledge", "dial: "+err.Error(), false)
	case isH2Frame(got):
		add("h2c prior knowledge", "the server answered with an HTTP/2 frame (negotiated h2c)", false)
	case bytes.HasPrefix(got, []byte("HTTP/1.1 2")), bytes.HasPrefix(got, []byte("HTTP/1.0 2")):
		add("h2c prior knowledge", "served the preface as a request: "+firstLine(got), false)
	default:
		add("h2c prior knowledge", fmt.Sprintf("refused: first response %q, connection closed=%v", firstLine(got), closed), true)
	}

	// 2. h2c Upgrade on an ordinary request: must be answered as HTTP/1.1, never 101.
	up := "GET /healthz HTTP/1.1\r\nHost: " + addr + "\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
	got, _, err = smokeRawExchange(addr, []byte(up), 2*time.Second)
	low := strings.ToLower(string(got))
	switch {
	case err != nil:
		add("h2c Upgrade", "dial: "+err.Error(), false)
	case strings.Contains(firstLine(got), "101"), strings.Contains(low, "upgrade: h2c"):
		add("h2c Upgrade", "the server switched protocols: "+firstLine(got), false)
	case !strings.HasPrefix(string(got), "HTTP/1.1 200"):
		add("h2c Upgrade", "unexpected answer (want the ordinary HTTP/1.1 200): "+firstLine(got), false)
	default:
		add("h2c Upgrade", "downgraded: "+firstLine(got)+", no Upgrade header", true)
	}

	// 3. A Go client that speaks only unencrypted HTTP/2 (prior knowledge).
	tr := &http.Transport{DisableKeepAlives: true, Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	cl := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := cl.Get("http://" + addr + "/healthz")
	if err != nil {
		add("Go client, unencrypted HTTP/2 only", "refused: "+err.Error(), true)
	} else {
		_ = resp.Body.Close()
		add("Go client, unencrypted HTTP/2 only", fmt.Sprintf("got a response: %s status %d", resp.Proto, resp.StatusCode), resp.ProtoMajor != 2)
	}
	tr.CloseIdleConnections()

	// 4. A TLS hello offering ALPN h2 to the plain listener: the handshake must not complete, so nothing can be
	// negotiated (the listener is plaintext; Caddy terminates TLS in front of it).
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		add("TLS ALPN h2 hello", "dial: "+err.Error(), false)
	} else {
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		tc := tls.Client(conn, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}, ServerName: smokeHost})
		if herr := tc.Handshake(); herr != nil {
			add("TLS ALPN h2 hello", "handshake refused: "+herr.Error(), true)
		} else {
			add("TLS ALPN h2 hello", "handshake completed, ALPN="+tc.ConnectionState().NegotiatedProtocol, false)
		}
		_ = conn.Close()
	}

	// The target still serves HTTP/1.1 afterwards.
	if st, _, _, err := smokeGet(addr, "/healthz", "", ""); err != nil || st != 200 {
		add("HTTP/1.1 afterwards", fmt.Sprintf("/healthz = %d err %v", st, err), false)
	}
	return cases
}

// ---------------------------------------------------------------------------------------------------------
// Short load (recorded RSS/handles before and after).
// ---------------------------------------------------------------------------------------------------------

func smokeLoad(t *testing.T, p *smokeProc, rec *smokeRecord, fail func(string, ...any)) {
	t.Helper()
	rec.Process = append(rec.Process, p.snap("before load"))
	var mu sync.Mutex
	var wg sync.WaitGroup
	end := time.Now().Add(smokeLoadDuration)
	for w := 0; w < smokeLoadWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(end) {
				st, _, took, err := smokeGet(p.addr, "/public/branding", smokeHost, p.e.edge)
				mu.Lock()
				rec.Load.Count++
				if ms := smokeMS(took); ms > rec.Load.MaxMS {
					rec.Load.MaxMS = ms
				}
				if err != nil || st != 200 {
					rec.Load.NonOK++
					if rec.Load.FirstBad == "" {
						rec.Load.FirstBad = fmt.Sprintf("status %d err %v", st, err)
					}
				}
				mu.Unlock()
				time.Sleep(smokeLoadPause)
			}
		}()
	}
	wg.Wait()
	rec.Process = append(rec.Process, p.snap("after load"))
	// Light load at 8 connections stays far under every admission cap: any non-200 is a defect.
	if rec.Load.NonOK > 0 {
		fail("load: %d of %d requests were not 200 (first: %s)", rec.Load.NonOK, rec.Load.Count, rec.Load.FirstBad)
	}
}

// ---------------------------------------------------------------------------------------------------------
// Slowloris closure.
// ---------------------------------------------------------------------------------------------------------

type smokeSlowOne struct {
	life      time.Duration
	stillOpen bool
	answer    string
}

// smokeSlowConn opens a connection, sends the head of a request and then one byte per second, until the server
// closes it (a read error or a failed write) or wait elapses. kind is "header" or "body".
func smokeSlowConn(addr, kind, edge string, wait time.Duration) smokeSlowOne {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return smokeSlowOne{answer: "dial: " + err.Error()}
	}
	defer c.Close()
	t0 := time.Now()
	hdr := fmt.Sprintf("Host: %s\r\n%s: %s\r\nX-Forwarded-For: %s\r\n", smokeHost, EdgeMarkerHeader, edge, smokeXFF())
	if kind == "header" {
		// A request line, a valid header, then the start of another header that never ends.
		_, err = fmt.Fprintf(c, "GET /public/branding HTTP/1.1\r\n%sX-Slow: ", hdr)
	} else {
		// A complete header block declaring a 1000-byte body, then a body that trickles.
		_, err = fmt.Fprintf(c, "POST %s HTTP/1.1\r\n%sContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{", gateRedeemPath, hdr)
	}
	if err != nil {
		return smokeSlowOne{life: time.Since(t0), answer: "write: " + err.Error()}
	}
	type rd struct {
		first string
		at    time.Duration
	}
	done := make(chan rd, 1)
	go func() {
		var all []byte
		buf := make([]byte, 4096)
		for {
			n, rerr := c.Read(buf)
			all = append(all, buf[:n]...)
			if rerr != nil {
				s := string(all)
				if i := strings.Index(s, "\r\n"); i >= 0 {
					s = s[:i]
				}
				done <- rd{first: s, at: time.Since(t0)}
				return
			}
		}
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	limit := time.After(wait)
	for {
		select {
		case r := <-done:
			return smokeSlowOne{life: r.at, answer: r.first}
		case <-limit:
			return smokeSlowOne{life: time.Since(t0), stillOpen: true}
		case <-tick.C:
			if _, werr := c.Write([]byte("a")); werr != nil {
				return smokeSlowOne{life: time.Since(t0), answer: "server closed (write failed)"}
			}
		}
	}
}

func smokeSlowloris(t *testing.T, p *smokeProc, rec *smokeRecord, fail func(string, ...any)) {
	t.Helper()
	bound := max(DefaultReadHeaderTimeout, DefaultReadTimeout) // 5 s each (docs/66 2d.2, 2e.2)
	slow, probes, failures := smokeSlowlorisCheck(p.addr, p.e.edge, bound, smokeCutSlack, 4*time.Second, smokeSlowConns)
	rec.Slowloris, rec.Probes = slow, probes
	for _, f := range failures {
		fail("%s", f)
	}
}

// smokeSlowlorisCheck opens conns slow-header and conns slow-body connections against addr and judges them: each must
// be closed by the server within bound+slack, and ordinary requests must keep succeeding meanwhile. It watches for
// bound+slack+extra before reporting a connection still open. Target-agnostic, with the bound a parameter, so the
// negative control can point it at a server with no timeouts and a small bound.
func smokeSlowlorisCheck(addr, edge string, bound, slack, extra time.Duration, conns int) (slow []smokeSlow, probes smokeProbe, failures []string) {
	failf := func(format string, a ...any) { failures = append(failures, fmt.Sprintf(format, a...)) }
	wait := bound + slack + extra // long enough to see a miss: the connection is then reported still open
	kinds := []string{"header", "body"}
	results := map[string][]smokeSlowOne{}
	var wg sync.WaitGroup
	for _, kind := range kinds {
		results[kind] = make([]smokeSlowOne, conns)
		for i := range results[kind] {
			wg.Add(1)
			go func() {
				defer wg.Done()
				results[kind][i] = smokeSlowConn(addr, kind, edge, wait)
			}()
		}
	}

	// While they trickle the binary must keep serving ordinary requests.
	stop := make(chan struct{})
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		for {
			select {
			case <-stop:
				return
			default:
			}
			for _, path := range []string{"/healthz", "/public/branding"} {
				host, mark := "", ""
				if path != "/healthz" {
					host, mark = smokeHost, edge
				}
				st, _, took, err := smokeGet(addr, path, host, mark)
				probes.Count++
				if ms := smokeMS(took); ms > probes.MaxMS {
					probes.MaxMS = ms
				}
				if err != nil || st != 200 || took > smokeProbeMaxLat {
					probes.NonOK++
					if probes.FirstBad == "" {
						probes.FirstBad = fmt.Sprintf("%s: status %d, %s, err %v", path, st, took, err)
					}
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	wg.Wait()
	close(stop)
	<-probeDone

	for _, kind := range kinds {
		s := smokeSlow{Kind: kind, Conns: conns, BoundMS: smokeMS(bound + slack)}
		for i, r := range results[kind] {
			if i == 0 || smokeMS(r.life) < s.MinLifeMS {
				s.MinLifeMS = smokeMS(r.life)
			}
			if smokeMS(r.life) > s.MaxLifeMS {
				s.MaxLifeMS = smokeMS(r.life)
			}
			if r.stillOpen {
				s.StillOpen++
			}
			if s.FirstAnswer == "" {
				s.FirstAnswer = r.answer
			}
			if strings.HasPrefix(r.answer, "dial:") {
				failf("slowloris %s #%d: %s", kind, i, r.answer)
			}
		}
		slow = append(slow, s)
		if s.StillOpen > 0 {
			failf("slowloris %s: %d of %d connections were still open after %s; the server did not cut them (bound %s)", kind, s.StillOpen, s.Conns, wait, bound)
		}
		if s.MaxLifeMS > s.BoundMS {
			failf("slowloris %s: the slowest connection lived %.0f ms, past the %.0f ms bound (5 s timeout + slack)", kind, s.MaxLifeMS, s.BoundMS)
		}
	}
	if probes.Count == 0 {
		failf("slowloris: no ordinary request was made while the slow connections trickled")
	}
	if probes.NonOK > 0 {
		failf("slowloris: %d of %d ordinary requests failed while the slow connections trickled (first: %s)", probes.NonOK, probes.Count, probes.FirstBad)
	}
	return slow, probes, failures
}
