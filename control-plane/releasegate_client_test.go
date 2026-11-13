package controlplane

// The docs/66 release gate's timing client. It runs in a SEPARATE process (the test binary re-executed with argv[1]
// "gate-client", see TestMain), so the server's goroutine, heap and descriptor counts are the server's alone, and
// the client's own scheduling does not share a runtime with the code under test.
//
// It reads a plan (JSON) on stdin and writes one result per request (JSON) on stdout. Each worker owns one
// pre-dialed keep-alive connection and writes raw HTTP/1.1, so a sample is exactly first byte written to last body
// byte read on the monotonic clock, with no client pool, no redirect logic and no hidden retries. A request that
// fails is recorded as an error, never retried: the gate counts every sample it was given.
//
// Untagged on purpose: the client compiles (and its unit test runs) in every suite, so it cannot rot between
// release-gate runs. The gate tests themselves are behind the releasegate build tag.

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type gateReq struct {
	State string `json:"state"`
	Host  string `json:"host"`
	Path  string `json:"path"`
	XFF   string `json:"xff,omitempty"`
}

type gatePlan struct {
	Addr     string            `json:"addr"`
	Workers  int               `json:"workers"`
	Headers  map[string]string `json:"headers,omitempty"` // sent on every request (the edge marker)
	Requests []gateReq         `json:"requests"`
	// Batch > 0 runs the requests in consecutive batches of Batch: every request of a batch completes before
	// Between (a GET on its own connection, which must answer 200) is sent, and the next batch starts only after it.
	// The cold path uses it to return the server to a known state between bursts.
	Batch   int    `json:"batch,omitempty"`
	Between string `json:"between,omitempty"`
}

type gateResult struct {
	Idx    int    `json:"i"`
	Status int    `json:"s"`
	Nanos  int64  `json:"ns"`
	Body   string `json:"b,omitempty"` // sha256 of the body, hex
	Len    int    `json:"n"`
	Err    string `json:"e,omitempty"`
}

// runGateClient is the client process's main. Exit status 0 means every request has a result line (each of which
// may still carry an error); anything else means the run is void.
func runGateClient(in io.Reader, out io.Writer) int {
	var plan gatePlan
	if err := json.NewDecoder(in).Decode(&plan); err != nil {
		fmt.Fprintf(os.Stderr, "gate-client: plan: %v\n", err)
		return 2
	}
	if plan.Workers <= 0 {
		plan.Workers = 1
	}
	results := make([]gateResult, len(plan.Requests))
	next := make(chan int)
	var wg, inflight sync.WaitGroup
	for w := 0; w < plan.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var c *gateConn
			defer func() {
				if c != nil {
					c.close()
				}
			}()
			for i := range next {
				if c == nil {
					var err error
					if c, err = dialGate(plan.Addr); err != nil {
						results[i] = gateResult{Idx: i, Err: "dial: " + err.Error()}
						inflight.Done()
						continue
					}
				}
				r := c.do(plan.Requests[i], plan.Headers)
				r.Idx = i
				results[i] = r
				if r.Err != "" || c.closed {
					c.close()
					c = nil
				}
				inflight.Done()
			}
		}()
	}
	// Pre-dial is implicit: each worker dials before its first request, and warm-up requests (the caller
	// discards them) absorb that cost.
	for i := range plan.Requests {
		inflight.Add(1)
		next <- i
		if plan.Batch > 0 && (i+1)%plan.Batch == 0 && i+1 < len(plan.Requests) {
			inflight.Wait()
			if err := gateBetween(plan); err != nil {
				fmt.Fprintf(os.Stderr, "gate-client: between batches: %v\n", err)
				close(next)
				wg.Wait()
				return 2
			}
		}
	}
	close(next)
	wg.Wait()
	enc := json.NewEncoder(out)
	for _, r := range results {
		if err := enc.Encode(r); err != nil {
			fmt.Fprintf(os.Stderr, "gate-client: write: %v\n", err)
			return 2
		}
	}
	return 0
}

// gateBetween sends plan.Between on a fresh connection and requires a 200.
func gateBetween(plan gatePlan) error {
	c, err := dialGate(plan.Addr)
	if err != nil {
		return err
	}
	defer c.close()
	r := c.do(gateReq{Host: "between.gate.test", Path: plan.Between}, plan.Headers)
	if r.Err != "" {
		return fmt.Errorf("%s", r.Err)
	}
	if r.Status != http.StatusOK {
		return fmt.Errorf("status %d", r.Status)
	}
	return nil
}

type gateConn struct {
	c      net.Conn
	br     *bufio.Reader
	closed bool // the server said Connection: close
}

func dialGate(addr string) (*gateConn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return &gateConn{c: c, br: bufio.NewReaderSize(c, 64<<10)}, nil
}

func (g *gateConn) close() { _ = g.c.Close() }

func (g *gateConn) do(q gateReq, hdr map[string]string) gateResult {
	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\nHost: %s\r\n", q.Path, q.Host)
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, hdr[k])
	}
	if q.XFF != "" {
		fmt.Fprintf(&b, "X-Forwarded-For: %s\r\n", q.XFF)
	}
	b.WriteString("\r\n")
	raw := []byte(b.String())
	_ = g.c.SetDeadline(time.Now().Add(30 * time.Second))
	start := time.Now()
	if _, err := g.c.Write(raw); err != nil {
		return gateResult{Err: "write: " + err.Error()}
	}
	res, err := http.ReadResponse(g.br, nil)
	if err != nil {
		return gateResult{Err: "read: " + err.Error()}
	}
	body, err := io.ReadAll(res.Body)
	el := time.Since(start)
	_ = res.Body.Close()
	if err != nil {
		return gateResult{Err: "body: " + err.Error()}
	}
	g.closed = res.Close
	sum := sha256.Sum256(body)
	return gateResult{Status: res.StatusCode, Nanos: el.Nanoseconds(), Body: hex.EncodeToString(sum[:]), Len: len(body)}
}

// runGateClientProcess runs the plan in a child process and returns one result per request, in plan order.
func runGateClientProcess(t testing.TB, plan gatePlan) []gateResult {
	t.Helper()
	in, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "gate-client")
	cmd.Stdin = strings.NewReader(string(in))
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gate client: %v", err)
	}
	out := make([]gateResult, 0, len(plan.Requests))
	dec := json.NewDecoder(stdout)
	for {
		var r gateResult
		if err := dec.Decode(&r); err == io.EOF {
			break
		} else if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("gate client output: %v (stderr: %s)", err, stderr.String())
		}
		out = append(out, r)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("gate client: %v (stderr: %s)", err, stderr.String())
	}
	if len(out) != len(plan.Requests) {
		t.Fatalf("gate client returned %d results for %d requests", len(out), len(plan.Requests))
	}
	for i, r := range out {
		if r.Idx != i {
			t.Fatalf("gate client result %d has index %d", i, r.Idx)
		}
	}
	return out
}

// The client measures what the server did: a state the server delays by 40 ms must read at least 40 ms, a fast
// state must not, statuses and body hashes are the server's, every request gets a result, and a server that
// closes the connection after each response is followed by a fresh dial rather than an error.
func TestGateClientMeasuresTheServer(t *testing.T) {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Edge") != "k" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Host {
		case "slow.test":
			time.Sleep(40 * time.Millisecond)
			_, _ = io.WriteString(w, "slow")
		case "close.test":
			w.Header().Set("Connection", "close")
			_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For"))
		default:
			w.WriteHeader(http.StatusTeapot)
			_, _ = io.WriteString(w, "fast")
		}
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	plan := gatePlan{Addr: ln.Addr().String(), Workers: 3, Headers: map[string]string{"X-Edge": "k"}}
	for i := 0; i < 30; i++ {
		host := []string{"slow.test", "fast.test", "close.test"}[i%3]
		plan.Requests = append(plan.Requests, gateReq{State: host, Host: host, Path: "/x", XFF: fmt.Sprintf("10.0.0.%d", i)})
	}
	res := runGateClientProcess(t, plan)
	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	for i, r := range res {
		q := plan.Requests[i]
		if r.Err != "" {
			t.Fatalf("request %d (%s): %s", i, q.Host, r.Err)
		}
		d := time.Duration(r.Nanos)
		switch q.Host {
		case "slow.test":
			if r.Status != 200 || r.Body != hash("slow") || d < 40*time.Millisecond {
				t.Errorf("slow %d: status %d len %d took %v", i, r.Status, r.Len, d)
			}
		case "fast.test":
			if r.Status != http.StatusTeapot || r.Body != hash("fast") || d >= 40*time.Millisecond {
				t.Errorf("fast %d: status %d took %v", i, r.Status, d)
			}
		case "close.test":
			if r.Status != 200 || r.Body != hash(q.XFF) {
				t.Errorf("close %d: status %d body len %d (want the XFF echoed)", i, r.Status, r.Len)
			}
		}
	}
}

// Batches are a real barrier: every request of batch k completes before the k-th Between call, and no request of
// batch k+1 starts before it. The server records, for each request, how many Between calls it had seen when it started.
func TestGateClientBatchesAreABarrier(t *testing.T) {
	var mu sync.Mutex
	betweens := 0
	var completedAtBetween []int
	completed := 0
	seenAtStart := map[string]int{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/between" {
			mu.Lock()
			betweens++
			completedAtBetween = append(completedAtBetween, completed)
			mu.Unlock()
			return
		}
		mu.Lock()
		seenAtStart[r.Header.Get("X-Forwarded-For")] = betweens
		mu.Unlock()
		time.Sleep(5 * time.Millisecond)
		mu.Lock()
		completed++
		mu.Unlock()
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	const batch, batches = 7, 4
	plan := gatePlan{Addr: ln.Addr().String(), Workers: batch, Batch: batch, Between: "/between"}
	for i := 0; i < batch*batches; i++ {
		plan.Requests = append(plan.Requests, gateReq{Host: "x.test", Path: "/r", XFF: fmt.Sprintf("10.0.0.%d", i)})
	}
	for _, r := range runGateClientProcess(t, plan) {
		if r.Err != "" || r.Status != http.StatusOK {
			t.Fatalf("request %d: status %d err %q", r.Idx, r.Status, r.Err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if betweens != batches-1 {
		t.Fatalf("Between called %d times, want %d (between batches only)", betweens, batches-1)
	}
	for k, c := range completedAtBetween {
		if c != (k+1)*batch {
			t.Errorf("Between #%d saw %d completed requests, want %d", k+1, c, (k+1)*batch)
		}
	}
	for i := 0; i < batch*batches; i++ {
		if got, want := seenAtStart[fmt.Sprintf("10.0.0.%d", i)], i/batch; got != want {
			t.Errorf("request %d started after %d Between call(s), want %d", i, got, want)
		}
	}
}
