package controlplane

// The docs/66 release gate's LOAD clients (plan step 6), in the same separate-process style as the timing client
// (releasegate_client_test.go): the test binary re-executed with argv[1] "gate-load" or "gate-hostile", so the server
// process's goroutine, heap and descriptor counts are the server's alone.
//
//   - gate-load: an open-loop (fixed offered rate, paced) or closed-loop generator over keep-alive connections. It sends
//     a weighted mix of requests, a fresh or pooled client address per request (X-Forwarded-For, the plan's item 6), and
//     records per state the statuses, the body hashes, the latencies of the "sample" statuses, and the RAW bytes of every
//     429 (minus the Date line) so the gate can prove all 429s are one byte string. It counts the requests the server
//     completed in fixed windows, which is what the throughput-stability check reads.
//   - gate-hostile: slow header writers, slow body writers, slow readers and connection churn, each reporting how long
//     the server let its connections live.
//
// Untagged on purpose (like the timing client): it compiles in every suite and its unit tests run there.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type loadItem struct {
	State  string `json:"state"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Method string `json:"method,omitempty"`
	// Bodies: none = no body; one = sent every time; several with Consume = each used once, in order (single-use
	// codes). A consumed item whose bodies are used up is skipped (the mix continues without it).
	Bodies  []string `json:"bodies,omitempty"`
	Consume bool     `json:"consume,omitempty"`
	Weight  int      `json:"weight"`
}

type loadPlan struct {
	Addr    string            `json:"addr"`
	Headers map[string]string `json:"headers,omitempty"`
	Items   []loadItem        `json:"items"`
	Conns   int               `json:"conns"`
	// Rate is the offered requests per second (open loop); 0 is a closed loop (every connection sends as fast as it can).
	Rate float64 `json:"rate,omitempty"`
	// The run ends when DurationMS has elapsed AND every state in MinStates has MinPerState samples (a response whose
	// status is in SampleStatuses), or at MaxDurationMS, whichever is first. Total > 0 ends it after that many requests.
	DurationMS    int64 `json:"duration_ms"`
	MaxDurationMS int64 `json:"max_duration_ms,omitempty"`
	MinPerState   int   `json:"min_per_state,omitempty"`
	// MinStates names the states MinPerState applies to (empty: every state).
	MinStates      []string `json:"min_states,omitempty"`
	SampleStatuses []int    `json:"sample_statuses,omitempty"`
	Total          int      `json:"total,omitempty"`
	// Barrier: every connection is dialled before the first request is sent, then all are released together.
	Barrier bool `json:"barrier,omitempty"`
	// ThinkMS: after each response a connection waits this long before its next request (a closed loop with a bounded rate:
	// about Conns/ThinkMS requests per second when the responses are quick, as 429s are).
	ThinkMS int64 `json:"think_ms,omitempty"`
	// IPPool > 0: request i uses address IPBase+(i mod IPPool); 0 = a fresh address per request. ConnsPerIP > 0: the
	// connection k keeps ONE address, IPBase+k/ConnsPerIP (the per-IP cap case).
	IPPool     int    `json:"ip_pool,omitempty"`
	ConnsPerIP int    `json:"conns_per_ip,omitempty"`
	IPBase     int    `json:"ip_base,omitempty"`
	WindowMS   int64  `json:"window_ms,omitempty"`
	Seed       uint64 `json:"seed,omitempty"`
	// RecordSamples keeps every sample's latency (the statistic needs them; a soak does not).
	RecordSamples bool `json:"record_samples,omitempty"`
}

type loadStateResult struct {
	Status map[int]int64 `json:"status"`
	// Bodies counts "status:sha256-of-body"; a 201 is not hashed (its body is unique by design).
	Bodies    map[string]int64 `json:"bodies"`
	SamplesNS []int64          `json:"samples_ns,omitempty"`
	// Sampled counts the responses with a sample status; MinNS/MaxNS cover them.
	Sampled int64 `json:"sampled"`
	MinNS   int64 `json:"min_ns"`
	MaxNS   int64 `json:"max_ns"`
}

type loadFP struct {
	Count int64  `json:"count"`
	Raw   string `json:"raw"` // the first exemplar, Date removed
}

type loadResult struct {
	Sent      int64                       `json:"sent"`
	Completed int64                       `json:"completed"`
	ElapsedMS int64                       `json:"elapsed_ms"`
	Dropped   int64                       `json:"dropped"` // paced requests the client could not issue in time
	Exhausted int64                       `json:"exhausted"`
	States    map[string]*loadStateResult `json:"states"`
	FP        map[string]*loadFP          `json:"fp429"`
	// Windows[i] is the number of NON-429 responses completed in window i; only whole windows are reported.
	Windows  []int64          `json:"windows"`
	WindowMS int64            `json:"window_ms"`
	Errors   map[string]int64 `json:"errors"`
	// ServerClosed counts "status" of responses that told the client to close the connection (Connection: close).
	ServerClosed map[string]int64 `json:"server_closed,omitempty"`
}

func (r *loadResult) offeredPerSec() float64 {
	if r.ElapsedMS <= 0 {
		return 0
	}
	return float64(r.Sent) / (float64(r.ElapsedMS) / 1000)
}

// total429 is the number of 429 responses over every state.
func (r *loadResult) total429() int64 {
	var n int64
	for _, s := range r.States {
		n += s.Status[http.StatusTooManyRequests]
	}
	return n
}

func (r *loadResult) totalErrors() int64 {
	var n int64
	for _, c := range r.Errors {
		n += c
	}
	return n
}

// loadWorkerOut is one worker's private tallies, merged at the end (no lock on the request path).
type loadWorkerOut struct {
	states  map[string]*loadStateResult
	fp      map[string]*loadFP
	windows []int64
	errors  map[string]int64
	done    int64
	closed  map[string]int64
}

func newLoadWorkerOut() *loadWorkerOut {
	return &loadWorkerOut{states: map[string]*loadStateResult{}, fp: map[string]*loadFP{}, errors: map[string]int64{}, closed: map[string]int64{}}
}

func (o *loadWorkerOut) state(name string) *loadStateResult {
	s := o.states[name]
	if s == nil {
		s = &loadStateResult{Status: map[int]int64{}, Bodies: map[string]int64{}}
		o.states[name] = s
	}
	return s
}

var addrPort = regexp.MustCompile(`127.0.0.1:[0-9]+`)

func (o *loadWorkerOut) err(msg string) {
	msg = addrPort.ReplaceAllString(msg, "127.0.0.1:*")
	if len(msg) > 90 {
		msg = msg[:90]
	}
	o.errors[msg]++
}

// teeConn records what the connection delivers, so a response's raw bytes are available after http.ReadResponse.
type teeConn struct {
	net.Conn
	buf *bytes.Buffer
}

func (t *teeConn) Read(p []byte) (int, error) {
	n, err := t.Conn.Read(p)
	t.buf.Write(p[:n])
	return n, err
}

type loadConn struct {
	c   net.Conn
	br  *bufio.Reader
	raw *bytes.Buffer
}

func dialLoad(addr string) (*loadConn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	raw := &bytes.Buffer{}
	return &loadConn{c: c, br: bufio.NewReaderSize(&teeConn{Conn: c, buf: raw}, 64<<10), raw: raw}, nil
}

func (l *loadConn) close() { _ = l.c.Close() }

var dateLine = []byte("\r\nDate: ")

// rawWithoutDate removes the Date header line from a raw response (the only header that may differ between two
// identical responses), leaving the status line, every other header line in the server's order, and the body.
func rawWithoutDate(raw []byte) []byte {
	i := bytes.Index(raw, dateLine)
	if i < 0 {
		return raw
	}
	j := bytes.Index(raw[i+2:], []byte("\r\n"))
	if j < 0 {
		return raw
	}
	out := make([]byte, 0, len(raw))
	out = append(out, raw[:i]...)
	return append(out, raw[i+2+j:]...)
}

func buildLoadRequest(it *loadItem, body string, hdr map[string]string, xff string) []byte {
	var b strings.Builder
	method := it.Method
	if method == "" {
		method = "GET"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", method, it.Path, it.Host)
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, hdr[k])
	}
	if xff != "" {
		fmt.Fprintf(&b, "X-Forwarded-For: %s\r\n", xff)
	}
	if body != "" {
		fmt.Fprintf(&b, "Content-Type: application/json\r\nContent-Length: %d\r\n", len(body))
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

type loadRun struct {
	plan     loadPlan
	start    time.Time
	stop     chan struct{}
	stopOnce sync.Once
	sent     atomic.Int64
	dropped  atomic.Int64
	ipSeq    atomic.Int64
	next     []atomic.Int64 // per item: the next unused body (Consume)
	exhaust  atomic.Int64
	counts   []atomic.Int64 // per MinStates entry: samples so far
	minIdx   map[string]int
	sample   map[int]bool
	cum      []int
	cumTotal int
	tokens   chan struct{}
}

func (lr *loadRun) stopNow() { lr.stopOnce.Do(func() { close(lr.stop) }) }

func (lr *loadRun) stopped() bool {
	select {
	case <-lr.stop:
		return true
	default:
		return false
	}
}

func (lr *loadRun) pick(rng *mrand.Rand) (int, string, bool) {
	for try := 0; try < 8; try++ {
		x := rng.IntN(lr.cumTotal)
		k := sort.SearchInts(lr.cum, x+1)
		it := &lr.plan.Items[k]
		switch {
		case it.Consume:
			i := lr.next[k].Add(1) - 1
			if int(i) >= len(it.Bodies) {
				lr.exhaust.Add(1)
				continue
			}
			return k, it.Bodies[i], true
		case len(it.Bodies) > 0:
			return k, it.Bodies[0], true
		}
		return k, "", true
	}
	return 0, "", false
}

func (lr *loadRun) ipFor(conn int) string {
	p := lr.plan
	switch {
	case p.ConnsPerIP > 0:
		return loadAddr(p.IPBase + conn/p.ConnsPerIP)
	case p.IPPool > 0:
		return loadAddr(p.IPBase + int(lr.ipSeq.Add(1)-1)%p.IPPool)
	default:
		return loadAddr(p.IPBase + int(lr.ipSeq.Add(1)-1))
	}
}

// take reserves the right to send one more request: it waits for a pacing token (open loop), honours Total, and reports
// false once the run is over.
func (lr *loadRun) take() bool {
	if lr.plan.Rate > 0 {
		select {
		case <-lr.tokens:
		case <-lr.stop:
			return false
		}
	} else if lr.stopped() {
		return false
	}
	if lr.plan.Total > 0 {
		if n := lr.sent.Add(1); n > int64(lr.plan.Total) {
			lr.sent.Add(-1)
			lr.stopNow()
			return false
		}
		return true
	}
	lr.sent.Add(1)
	return true
}

func (lr *loadRun) worker(k int, ready *sync.WaitGroup, release <-chan struct{}, out *loadWorkerOut) {
	rng := mrand.New(mrand.NewPCG(lr.plan.Seed+1, uint64(k)+1))
	var c *loadConn
	if lr.plan.Barrier {
		// Staggered, with retries: 400 connections opened in one instant overflow a Windows listen backlog (200), which is the
		// client dying of its own burst, not the server refusing.
		time.Sleep(time.Duration(k%50) * 2 * time.Millisecond)
		var err error
		for try := 0; try < 10; try++ {
			if c, err = dialLoad(lr.plan.Addr); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			out.err("dial: " + err.Error())
		}
		ready.Done()
		<-release
	}
	defer func() {
		if c != nil {
			c.close()
		}
	}()
	win := lr.plan.WindowMS
	for lr.take() {
		ki, body, ok := lr.pick(rng)
		if !ok {
			continue
		}
		it := &lr.plan.Items[ki]
		if c == nil {
			var err error
			if c, err = dialLoad(lr.plan.Addr); err != nil {
				out.err("dial: " + err.Error())
				lr.sent.Add(-1) // nothing was sent
				select {
				case <-time.After(100 * time.Millisecond):
				case <-lr.stop:
				}
				continue
			}
		}
		st := out.state(it.State)
		raw := buildLoadRequest(it, body, lr.plan.Headers, lr.ipFor(k))
		_ = c.c.SetDeadline(time.Now().Add(30 * time.Second))
		c.raw.Reset()
		t0 := time.Now()
		if _, err := c.c.Write(raw); err != nil {
			out.err("write: " + err.Error())
			c.close()
			c = nil
			continue
		}
		res, err := http.ReadResponse(c.br, nil)
		if err != nil {
			out.err("read: " + err.Error())
			c.close()
			c = nil
			continue
		}
		rb, err := io.ReadAll(res.Body)
		el := time.Since(t0)
		_ = res.Body.Close()
		if err != nil {
			out.err("body: " + err.Error())
			c.close()
			c = nil
			continue
		}
		out.done++
		st.Status[res.StatusCode]++
		if res.StatusCode != http.StatusCreated {
			sum := sha256.Sum256(rb)
			st.Bodies[fmt.Sprintf("%d:%s", res.StatusCode, hex.EncodeToString(sum[:]))]++
		}
		if res.StatusCode == http.StatusTooManyRequests {
			nd := rawWithoutDate(c.raw.Bytes())
			sum := sha256.Sum256(nd)
			key := hex.EncodeToString(sum[:])
			f := out.fp[key]
			if f == nil {
				f = &loadFP{Raw: string(nd[:min(len(nd), 2048)])}
				out.fp[key] = f
			}
			f.Count++
		} else if win > 0 {
			wi := int(time.Since(lr.start).Milliseconds() / win)
			for len(out.windows) <= wi {
				out.windows = append(out.windows, 0)
			}
			out.windows[wi]++
		}
		if lr.sample[res.StatusCode] {
			st.Sampled++
			ns := el.Nanoseconds()
			if st.Sampled == 1 || ns < st.MinNS {
				st.MinNS = ns
			}
			st.MaxNS = max(st.MaxNS, ns)
			if lr.plan.RecordSamples {
				st.SamplesNS = append(st.SamplesNS, ns)
			}
			if mi, ok := lr.minIdx[it.State]; ok {
				lr.counts[mi].Add(1)
			}
		}
		if res.Close {
			out.closed[fmt.Sprint(res.StatusCode)]++
			c.close()
			c = nil
		}
		if lr.plan.ThinkMS > 0 {
			select {
			case <-time.After(time.Duration(lr.plan.ThinkMS) * time.Millisecond):
			case <-lr.stop:
			}
		}
	}
}

// satisfied: every state named by MinStates (or, with none named, every state) has MinPerState samples.
func (lr *loadRun) satisfied() bool {
	if lr.plan.MinPerState <= 0 {
		return true
	}
	for i := range lr.counts {
		if lr.counts[i].Load() < int64(lr.plan.MinPerState) {
			return false
		}
	}
	return true
}

func runGateLoad(in io.Reader, out io.Writer) int {
	var plan loadPlan
	if err := json.NewDecoder(in).Decode(&plan); err != nil {
		fmt.Fprintf(os.Stderr, "gate-load: plan: %v\n", err)
		return 2
	}
	if plan.Conns <= 0 || len(plan.Items) == 0 {
		fmt.Fprintln(os.Stderr, "gate-load: a plan needs connections and items")
		return 2
	}
	if plan.MaxDurationMS < plan.DurationMS {
		plan.MaxDurationMS = plan.DurationMS
	}
	lr := &loadRun{plan: plan, stop: make(chan struct{}), minIdx: map[string]int{}, sample: map[int]bool{}}
	for _, s := range plan.SampleStatuses {
		lr.sample[s] = true
	}
	lr.next = make([]atomic.Int64, len(plan.Items))
	for _, it := range plan.Items {
		lr.cumTotal += max(it.Weight, 1)
		lr.cum = append(lr.cum, lr.cumTotal)
	}
	names := plan.MinStates
	if len(names) == 0 {
		for _, it := range plan.Items {
			names = append(names, it.State)
		}
	}
	for _, n := range names {
		if _, ok := lr.minIdx[n]; !ok {
			lr.minIdx[n] = len(lr.minIdx)
		}
	}
	lr.counts = make([]atomic.Int64, len(lr.minIdx))
	if plan.Rate > 0 {
		lr.tokens = make(chan struct{}, 4096)
	}
	var ready sync.WaitGroup
	release := make(chan struct{})
	outs := make([]*loadWorkerOut, plan.Conns)
	var wg sync.WaitGroup
	if plan.Barrier {
		ready.Add(plan.Conns)
	}
	for k := 0; k < plan.Conns; k++ {
		outs[k] = newLoadWorkerOut()
		wg.Add(1)
		go func() {
			defer wg.Done()
			lr.worker(k, &ready, release, outs[k])
		}()
	}
	if plan.Barrier {
		ready.Wait()
	}
	lr.start = time.Now()
	close(release)
	if plan.Rate > 0 {
		go func() {
			issued := int64(0)
			tick := time.NewTicker(2 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-lr.stop:
					return
				case <-tick.C:
				}
				due := int64(plan.Rate*time.Since(lr.start).Seconds()) - issued
				for ; due > 0; due-- {
					issued++
					select {
					case lr.tokens <- struct{}{}:
					default:
						lr.dropped.Add(1)
					}
				}
			}
		}()
	}
	if plan.Total == 0 {
		go func() {
			for {
				time.Sleep(20 * time.Millisecond)
				el := time.Since(lr.start)
				if lr.stopped() {
					return
				}
				if el >= time.Duration(plan.MaxDurationMS)*time.Millisecond ||
					(el >= time.Duration(plan.DurationMS)*time.Millisecond && lr.satisfied()) {
					lr.stopNow()
					return
				}
			}
		}()
	}
	// A Total run (or a closed loop whose workers all quit) ends when the workers do.
	go func() {
		wg.Wait()
		lr.stopNow()
	}()
	<-lr.stop
	elapsed := time.Since(lr.start)
	wg.Wait()

	res := loadResult{States: map[string]*loadStateResult{}, FP: map[string]*loadFP{}, Errors: map[string]int64{},
		Sent: lr.sent.Load(), Dropped: lr.dropped.Load(), Exhausted: lr.exhaust.Load(), ElapsedMS: elapsed.Milliseconds(),
		WindowMS: plan.WindowMS}
	var windows []int64
	for _, o := range outs {
		res.Completed += o.done
		for name, s := range o.states {
			d := res.States[name]
			if d == nil {
				d = &loadStateResult{Status: map[int]int64{}, Bodies: map[string]int64{}}
				res.States[name] = d
			}
			for k, v := range s.Status {
				d.Status[k] += v
			}
			for k, v := range s.Bodies {
				d.Bodies[k] += v
			}
			d.SamplesNS = append(d.SamplesNS, s.SamplesNS...)
			if s.Sampled > 0 && (d.Sampled == 0 || s.MinNS < d.MinNS) {
				d.MinNS = s.MinNS
			}
			d.MaxNS = max(d.MaxNS, s.MaxNS)
			d.Sampled += s.Sampled
		}
		for k, f := range o.fp {
			d := res.FP[k]
			if d == nil {
				d = &loadFP{Raw: f.Raw}
				res.FP[k] = d
			}
			d.Count += f.Count
		}
		for k, v := range o.errors {
			res.Errors[k] += v
		}
		for k, v := range o.closed {
			if res.ServerClosed == nil {
				res.ServerClosed = map[string]int64{}
			}
			res.ServerClosed[k] += v
		}
		for i, v := range o.windows {
			for len(windows) <= i {
				windows = append(windows, 0)
			}
			windows[i] += v
		}
	}
	if plan.WindowMS > 0 {
		whole := int(elapsed.Milliseconds() / plan.WindowMS)
		for i := 0; i < whole; i++ {
			if i < len(windows) {
				res.Windows = append(res.Windows, windows[i])
			} else {
				res.Windows = append(res.Windows, 0)
			}
		}
	}
	if err := json.NewEncoder(out).Encode(res); err != nil {
		fmt.Fprintf(os.Stderr, "gate-load: write: %v\n", err)
		return 2
	}
	return 0
}

// runGateRole runs a client role in a child process: the plan goes in on stdin, the result comes back on stdout.
func runGateRoleErr(role string, plan, result any) error {
	in, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	cmd := exec.Command(os.Args[0], role)
	cmd.Stdin = bytes.NewReader(in)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %v (stderr: %s)", role, err, stderr.String())
	}
	if err := json.Unmarshal(stdout.Bytes(), result); err != nil {
		return fmt.Errorf("%s output: %v", role, err)
	}
	return nil
}

func runGateRole(t testing.TB, role string, plan, result any) {
	t.Helper()
	if err := runGateRoleErr(role, plan, result); err != nil {
		t.Fatal(err)
	}
}

func runGateLoadProcess(t testing.TB, plan loadPlan) loadResult {
	t.Helper()
	var res loadResult
	runGateRole(t, "gate-load", plan, &res)
	return res
}

// ---------------------------------------------------------------------------------------------------------
// The hostile client.
// ---------------------------------------------------------------------------------------------------------

type hostilePlan struct {
	Addr    string            `json:"addr"`
	Headers map[string]string `json:"headers,omitempty"`
	// Host / paths used by each kind. BodyPath is a POST route that reads its body (redemption); ReadPath is the
	// largest response (the logo).
	Host        string `json:"host"`
	ReadPath    string `json:"read_path"`
	BodyPath    string `json:"body_path"`
	DurationMS  int64  `json:"duration_ms"`
	SlowHeaders int    `json:"slow_headers"`
	SlowBodies  int    `json:"slow_bodies"`
	SlowReaders int    `json:"slow_readers"`
	// ChurnRate: connections per second opened, sent a full request, and reset without reading the answer.
	ChurnRate float64 `json:"churn_rate"`
	IPBase    int     `json:"ip_base"`
}

type hostileClass struct {
	Opened         int64 `json:"opened"`
	ClosedByServer int64 `json:"closed_by_server"`
	// MaxLifetimeMS is the longest a connection the SERVER closed had lived; StillOpen were open at the end.
	MaxLifetimeMS int64 `json:"max_lifetime_ms"`
	StillOpen     int64 `json:"still_open"`
	DialErrors    int64 `json:"dial_errors"`
}

type hostileResult struct {
	SlowHeader hostileClass `json:"slow_header"`
	SlowBody   hostileClass `json:"slow_body"`
	SlowReader hostileClass `json:"slow_reader"`
	Churn      hostileClass `json:"churn"`
	ElapsedMS  int64        `json:"elapsed_ms"`
	// PeakOpen is the most connections the client held at once (the plan keeps it below the 1024 cap).
	PeakOpen int64 `json:"peak_open"`
}

type hostileTally struct {
	mu    sync.Mutex
	c     hostileClass
	open  atomic.Int64
	peak  *atomic.Int64
	total *atomic.Int64
}

func (h *hostileTally) opened() {
	h.mu.Lock()
	h.c.Opened++
	h.mu.Unlock()
	n := h.total.Add(1)
	for {
		p := h.peak.Load()
		if n <= p || h.peak.CompareAndSwap(p, n) {
			break
		}
	}
	h.open.Add(1)
}

func (h *hostileTally) closed(life time.Duration, byServer bool) {
	h.total.Add(-1)
	h.open.Add(-1)
	h.mu.Lock()
	if byServer {
		h.c.ClosedByServer++
		h.c.MaxLifetimeMS = max(h.c.MaxLifetimeMS, life.Milliseconds())
	}
	h.mu.Unlock()
}

func (h *hostileTally) dialErr() {
	h.mu.Lock()
	h.c.DialErrors++
	h.mu.Unlock()
}

func hostileDial(addr string) (*net.TCPConn, error) {
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	return c.(*net.TCPConn), nil
}

func hostileHeaders(hdr map[string]string) string {
	keys := make([]string, 0, len(hdr))
	for k := range hdr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s: %s\r\n", k, hdr[k])
	}
	return b.String()
}

// hostileLoop runs one hostile connection at a time until stop: dial, hold the behaviour, redial after the server
// closes it. behave returns when the connection is finished; its result says whether the SERVER ended it.
func hostileLoop(plan hostilePlan, idx int, tally *hostileTally, stop <-chan struct{}, behave func(c *net.TCPConn, stop <-chan struct{}) (serverClosed bool)) {
	// Staggered start and jittered redial: hundreds of connections opened in one instant overflow a listen backlog (200 on
	// Windows), which would be the client dying of its own burst, not the server refusing.
	select {
	case <-stop:
		return
	case <-time.After(time.Duration(idx%250) * 4 * time.Millisecond):
	}
	for {
		select {
		case <-stop:
			return
		default:
		}
		c, err := hostileDial(plan.Addr)
		if err != nil {
			tally.dialErr()
			select {
			case <-stop:
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		tally.opened()
		t0 := time.Now()
		by := behave(c, stop)
		_ = c.SetLinger(0)
		_ = c.Close()
		tally.closed(time.Since(t0), by)
		select {
		case <-stop:
			return
		case <-time.After(20*time.Millisecond + time.Duration(mrand.IntN(400))*time.Millisecond):
		}
	}
}

// watchClose's channel closes when the peer closes the connection (or a read fails) while the caller is still writing.
func watchClose(c *net.TCPConn) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		var b [4096]byte
		for {
			if _, err := c.Read(b[:]); err != nil {
				return
			}
		}
	}()
	return ch
}

func runGateHostile(in io.Reader, out io.Writer) int {
	var plan hostilePlan
	if err := json.NewDecoder(in).Decode(&plan); err != nil {
		fmt.Fprintf(os.Stderr, "gate-hostile: plan: %v\n", err)
		return 2
	}
	var peak, total atomic.Int64
	newTally := func() *hostileTally { return &hostileTally{peak: &peak, total: &total} }
	tSH, tSB, tSR, tCH := newTally(), newTally(), newTally(), newTally()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	start := time.Now()
	hdr := hostileHeaders(plan.Headers)
	var ipSeq atomic.Int64
	ip := func() string { return loadAddr(plan.IPBase + int(ipSeq.Add(1)-1)) }

	// Slow header writers: a request line, a valid header, then one byte of the next header per second, never the end.
	for i := 0; i < plan.SlowHeaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostileLoop(plan, i, tSH, stop, func(c *net.TCPConn, stop <-chan struct{}) bool {
				_, _ = fmt.Fprintf(c, "GET /public/branding HTTP/1.1\r\nHost: %s\r\n%sX-Forwarded-For: %s\r\nX-Slow: ", plan.Host, hdr, ip())
				gone := watchClose(c)
				for {
					select {
					case <-gone:
						return true
					case <-stop:
						return false
					case <-time.After(time.Second):
						if _, err := c.Write([]byte("a")); err != nil {
							return true
						}
					}
				}
			})
		}()
	}
	// Slow body writers: a complete header block declaring a 1,000-byte body, then one byte per second.
	for i := 0; i < plan.SlowBodies; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostileLoop(plan, i+100, tSB, stop, func(c *net.TCPConn, stop <-chan struct{}) bool {
				_, _ = fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: %s\r\n%sX-Forwarded-For: %s\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{",
					plan.BodyPath, plan.Host, hdr, ip())
				gone := watchClose(c)
				for {
					select {
					case <-gone:
						return true
					case <-stop:
						return false
					case <-time.After(time.Second):
						if _, err := c.Write([]byte(" ")); err != nil {
							return true
						}
					}
				}
			})
		}()
	}
	// Slow readers: the largest response, a receive buffer of 1 KiB, and a read of 512 bytes every 100 ms.
	for i := 0; i < plan.SlowReaders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hostileLoop(plan, i+200, tSR, stop, func(c *net.TCPConn, stop <-chan struct{}) bool {
				_ = c.SetReadBuffer(1024)
				_, _ = fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\n%sX-Forwarded-For: %s\r\n\r\n", plan.ReadPath, plan.Host, hdr, ip())
				buf := make([]byte, 512)
				got := 0
				for {
					select {
					case <-stop:
						return false
					case <-time.After(100 * time.Millisecond):
					}
					_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
					n, err := c.Read(buf)
					got += n
					if err != nil {
						if ne, ok := err.(net.Error); ok && ne.Timeout() { // the server sent nothing for 10 s: it is idle, not closing us
							return false
						}
						return true
					}
					if got >= 1<<20 { // far past any response: stop reading this one
						return false
					}
				}
			})
		}()
	}
	// Churn: open, send one full request, reset without reading.
	if plan.ChurnRate > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem := make(chan struct{}, 512)
			var cw sync.WaitGroup
			defer cw.Wait()
			issued := int64(0)
			tick := time.NewTicker(5 * time.Millisecond)
			defer tick.Stop()
			t0 := time.Now()
			for {
				select {
				case <-stop:
					return
				case <-tick.C:
				}
				for due := int64(plan.ChurnRate*time.Since(t0).Seconds()) - issued; due > 0; due-- {
					issued++
					select {
					case sem <- struct{}{}:
					default:
						continue
					}
					cw.Add(1)
					go func() {
						defer cw.Done()
						defer func() { <-sem }()
						c, err := hostileDial(plan.Addr)
						if err != nil {
							tCH.dialErr()
							return
						}
						tCH.opened()
						_, _ = fmt.Fprintf(c, "GET /public/branding HTTP/1.1\r\nHost: %s\r\n%sX-Forwarded-For: %s\r\n\r\n", plan.Host, hdr, ip())
						_ = c.SetLinger(0)
						_ = c.Close()
						tCH.closed(0, false)
					}()
				}
			}
		}()
	}
	time.Sleep(time.Duration(plan.DurationMS) * time.Millisecond)
	for _, t := range []*hostileTally{tSH, tSB, tSR} {
		t.mu.Lock()
		t.c.StillOpen = t.open.Load()
		t.mu.Unlock()
	}
	close(stop)
	wg.Wait()
	res := hostileResult{SlowHeader: tSH.c, SlowBody: tSB.c, SlowReader: tSR.c, Churn: tCH.c,
		ElapsedMS: time.Since(start).Milliseconds(), PeakOpen: peak.Load()}
	if err := json.NewEncoder(out).Encode(res); err != nil {
		return 2
	}
	return 0
}

func runGateHostileProcess(t testing.TB, plan hostilePlan) hostileResult {
	t.Helper()
	var res hostileResult
	runGateRole(t, "gate-hostile", plan, &res)
	return res
}

// ---------------------------------------------------------------------------------------------------------
// Unit tests (ordinary suite, no database).
// ---------------------------------------------------------------------------------------------------------

func TestRawWithoutDateRemovesOnlyTheDateLine(t *testing.T) {
	a := "HTTP/1.1 429 Too Many Requests\r\nCache-Control: no-store\r\nDate: Mon, 02 Jan 2006 15:04:05 GMT\r\nRetry-After: 1\r\n\r\nbody"
	b := "HTTP/1.1 429 Too Many Requests\r\nCache-Control: no-store\r\nDate: Tue, 03 Jan 2006 16:05:06 GMT\r\nRetry-After: 1\r\n\r\nbody"
	if g, w := string(rawWithoutDate([]byte(a))), "HTTP/1.1 429 Too Many Requests\r\nCache-Control: no-store\r\nRetry-After: 1\r\n\r\nbody"; g != w {
		t.Fatalf("got %q want %q", g, w)
	}
	if string(rawWithoutDate([]byte(a))) != string(rawWithoutDate([]byte(b))) {
		t.Fatal("two responses that differ only in Date must be equal without it")
	}
	if c := strings.Replace(a, "Retry-After: 1", "Retry-After: 2", 1); string(rawWithoutDate([]byte(a))) == string(rawWithoutDate([]byte(c))) {
		t.Fatal("a different header must stay different")
	}
}

// The load client end to end against a stub: an open-loop run offers about the asked rate, every state is tallied, 429s
// are fingerprinted without their Date, single-use bodies are consumed once each, windows are reported, and a
// MinPerState run goes on until the named state has enough samples.
func TestGateLoadClientTalliesTheServer(t *testing.T) {
	var mu sync.Mutex
	seen := map[string]int{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "limited.test":
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"error":"x"}`)
		case "code.test":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			seen[string(b)]++
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	var bodies []string
	for i := 0; i < 40; i++ {
		bodies = append(bodies, fmt.Sprintf(`{"c":%d}`, i))
	}
	plan := loadPlan{Addr: ln.Addr().String(), Conns: 8, Rate: 400, DurationMS: 1000, MaxDurationMS: 5000, MinPerState: 50,
		MinStates: []string{"ok"}, SampleStatuses: []int{200}, WindowMS: 250, IPPool: 10, RecordSamples: true,
		Items: []loadItem{{State: "ok", Host: "ok.test", Path: "/", Weight: 6}, {State: "limited", Host: "limited.test", Path: "/", Weight: 3},
			{State: "code", Host: "code.test", Path: "/", Method: "POST", Bodies: bodies, Consume: true, Weight: 1}}}
	res := runGateLoadProcess(t, plan)
	if res.totalErrors() != 0 {
		t.Fatalf("errors: %v", res.Errors)
	}
	if rate := res.offeredPerSec(); rate < 300 || rate > 500 {
		t.Errorf("offered %.0f/s, want about 400", rate)
	}
	if res.States["ok"].Sampled < 50 || int64(len(res.States["ok"].SamplesNS)) != res.States["ok"].Sampled {
		t.Errorf("ok: sampled %d, recorded %d", res.States["ok"].Sampled, len(res.States["ok"].SamplesNS))
	}
	if len(res.FP) != 1 {
		t.Fatalf("%d distinct 429 fingerprints, want 1", len(res.FP))
	}
	for _, f := range res.FP {
		if f.Count != res.States["limited"].Status[429] || strings.Contains(f.Raw, "Date:") || !strings.Contains(f.Raw, "Retry-After: 1") {
			t.Errorf("fingerprint: count %d (want %d), raw %q", f.Count, res.States["limited"].Status[429], f.Raw)
		}
	}
	mu.Lock()
	for b, c := range seen {
		if c != 1 {
			t.Errorf("single-use body %s sent %d times", b, c)
		}
	}
	got := int64(len(seen))
	mu.Unlock()
	if c := res.States["code"].Status[201]; c != got || c == 0 {
		t.Errorf("201 count %d, distinct bodies %d", c, got)
	}
	if len(res.Windows) < 4 {
		t.Errorf("%d windows for at least 1 s of 250 ms, want at least 4 (whole windows only)", len(res.Windows))
	}
	var inWindows int64
	for _, w := range res.Windows {
		inWindows += w
	}
	if inWindows == 0 || inWindows > res.Completed-res.total429() {
		t.Errorf("windows hold %d responses, completed %d of which %d were 429", inWindows, res.Completed, res.total429())
	}
}

// A Barrier run with Total sends exactly Total requests, from the fixed address of each connection, all released together.
func TestGateLoadClientBarrierAndPerConnectionAddresses(t *testing.T) {
	var mu sync.Mutex
	ips := map[string]int{}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		ips[r.Header.Get("X-Forwarded-For")]++
		mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	plan := loadPlan{Addr: ln.Addr().String(), Conns: 12, ConnsPerIP: 4, IPBase: 100, Total: 12, Barrier: true,
		Items: []loadItem{{State: "x", Host: "x.test", Path: "/", Weight: 1}}}
	res := runGateLoadProcess(t, plan)
	if res.Sent != 12 || res.Completed != 12 || res.totalErrors() != 0 {
		t.Fatalf("sent %d completed %d errors %v", res.Sent, res.Completed, res.Errors)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ips) > 3 || len(ips) == 0 {
		t.Errorf("%d distinct addresses %v, want at most 3 (12 connections, 4 per address)", len(ips), ips)
	}
}

// The hostile client's classes see the server end them: a server with 300 ms header and read timeouts closes slow
// header and slow body writers, which are then redialled, and the result says how long each lived.
func TestGateHostileClientSeesTheServerClose(t *testing.T) {
	srv := &http.Server{ReadHeaderTimeout: 300 * time.Millisecond, ReadTimeout: 300 * time.Millisecond,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, strings.Repeat("x", 200<<10))
		})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	res := runGateHostileProcess(t, hostilePlan{Addr: ln.Addr().String(), Host: "h.test", ReadPath: "/big", BodyPath: "/body",
		DurationMS: 2500, SlowHeaders: 3, SlowBodies: 3, SlowReaders: 2, ChurnRate: 50})
	if res.SlowHeader.ClosedByServer < 3 || res.SlowHeader.MaxLifetimeMS > 1500 {
		t.Errorf("slow header: %+v", res.SlowHeader)
	}
	if res.SlowBody.ClosedByServer < 3 || res.SlowBody.MaxLifetimeMS > 1500 {
		t.Errorf("slow body: %+v", res.SlowBody)
	}
	if res.Churn.Opened < 50 || res.PeakOpen < 6 {
		t.Errorf("churn %+v, peak open %d", res.Churn, res.PeakOpen)
	}
}

// loadAddr is the synthetic client address number i (10.x.y.z), the same scheme as the harness's gateXFF.
func loadAddr(i int) string {
	n := i + 1
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255)
}
