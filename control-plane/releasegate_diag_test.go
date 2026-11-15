//go:build releasegate

package controlplane

// Opt-in per-window DIAGNOSTICS for the redeem soak (docs/66 release gate, section 2n follow-up). It never asserts
// anything and never changes a threshold: it records what moved when the soak's throughput stepped down, so the cause
// can be found rather than guessed. Off unless DESKRALLY_GATE_DIAG=1, so the authoritative run is exactly as before.
//
// Every window (the soak's own 10 s window) it records:
//   - server side (a handler wrapper): requests that arrived, answered 429, answered otherwise ("admitted"), the in-flight
//     gauge at the window's end and its maximum, and the median and p95 handler latency of the non-429 answers;
//   - Postgres, through the fixture's superuser pool, for EVERY user table: n_live_tup, n_dead_tup, seq_scan, idx_scan,
//     the write counters (n_tup_ins/upd/del), autovacuum and autoanalyze counts, and pg_total_relation_size. The JSON keeps
//     the tables whose write counters moved during the phase (an empirical answer to "which tables does the redeem path
//     write", to be read beside the code), plus the backends waiting on a wait event;
//   - the VM: /proc/stat user, system, iowait and steal as shares of the window's CPU time (Linux only).
//
// The recorder's own queries are a handful per 10 s. Alignment: the recorder starts with the measured pass and the load
// client a moment later (a process start), so a recorder window and a client window can differ by about a second.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func gateDiagOn() bool { return os.Getenv("DESKRALLY_GATE_DIAG") == "1" }

// gateDiagMW counts what the server saw. It is installed with gateRedeemOpts.wrap.
type gateDiagMW struct {
	mu            sync.Mutex
	arrived       int64
	r429          int64
	other         int64
	lat           []time.Duration // non-429 answers
	errs          []string        // the first 5xx answers: window-relative time and body (which branch of the handler answered)
	t0            time.Time
	storeErrs     []string
	storeErrCount int64
	qEvents       []string
	inflight      atomic.Int64
	maxInfl       atomic.Int64
}

func newGateDiagMW() *gateDiagMW { return &gateDiagMW{} }

type gateDiagStatusWriter struct {
	http.ResponseWriter
	status int
	body   []byte
}

func (w *gateDiagStatusWriter) WriteHeader(c int) {
	if w.status == 0 {
		w.status = c
	}
	w.ResponseWriter.WriteHeader(c)
}

func (w *gateDiagStatusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if w.status >= 500 && len(w.body) < 200 {
		w.body = append(w.body, b...)
	}
	return w.ResponseWriter.Write(b)
}

func (m *gateDiagMW) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		n := m.inflight.Add(1)
		for {
			cur := m.maxInfl.Load()
			if n <= cur || m.maxInfl.CompareAndSwap(cur, n) {
				break
			}
		}
		sw := &gateDiagStatusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		m.inflight.Add(-1)
		d := time.Since(start)
		m.mu.Lock()
		if sw.status >= 500 && len(m.errs) < 20 {
			m.errs = append(m.errs, time.Since(m.t0).Round(time.Millisecond).String()+" "+strconv.Itoa(sw.status)+" "+strings.TrimSpace(string(sw.body)))
		}
		m.arrived++
		if sw.status == http.StatusTooManyRequests {
			m.r429++
		} else {
			m.other++
			m.lat = append(m.lat, d)
		}
		m.mu.Unlock()
	})
}

// take returns the window's counters and resets them.
func (m *gateDiagMW) take() (arrived, r429, other int64, med, p95 time.Duration, inflight, maxInflight int64) {
	m.mu.Lock()
	arrived, r429, other = m.arrived, m.r429, m.other
	lat := m.lat
	m.arrived, m.r429, m.other, m.lat = 0, 0, 0, nil
	m.mu.Unlock()
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		med = lat[len(lat)/2]
		p95 = lat[min(len(lat)-1, (len(lat)*95+99)/100-1)]
	}
	inflight = m.inflight.Load()
	maxInflight = m.maxInfl.Swap(inflight)
	return
}

type gateDiagTable struct {
	Table       string `json:"table"`
	Live        int64  `json:"n_live_tup"`
	Dead        int64  `json:"n_dead_tup"`
	SeqScan     int64  `json:"seq_scan"`
	IdxScan     int64  `json:"idx_scan"`
	Ins         int64  `json:"n_tup_ins"`
	Upd         int64  `json:"n_tup_upd"`
	Del         int64  `json:"n_tup_del"`
	Autovacuum  int64  `json:"autovacuum_count"`
	Autoanalyze int64  `json:"autoanalyze_count"`
	TotalBytes  int64  `json:"total_relation_bytes"`
}

type gateDiagCPU struct {
	User, System, IOWait, Steal, Idle float64 // shares of the window's CPU time, 0..1
	Available                         bool
}

type gateDiagWindow struct {
	Index            int                      `json:"window"`
	ElapsedMS        int64                    `json:"elapsed_ms"`
	Arrived          int64                    `json:"server_arrived"`
	R429             int64                    `json:"server_429"`
	Admitted         int64                    `json:"server_admitted"`
	AdmittedMedianMS float64                  `json:"admitted_median_ms"`
	AdmittedP95MS    float64                  `json:"admitted_p95_ms"`
	InFlightEnd      int64                    `json:"in_flight_end"`
	InFlightMax      int64                    `json:"in_flight_max"`
	OfferedPerSec    float64                  `json:"server_arrival_rate_per_s"`
	WaitingBackends  int                      `json:"pg_waiting_backends"`
	ActiveBackends   int                      `json:"pg_active_backends"`
	CPU              gateDiagCPU              `json:"cpu"`
	Tables           map[string]gateDiagTable `json:"tables"`
}

type gateDiagRecord struct {
	Phase         string           `json:"phase"`
	Autovacuum    string           `json:"autovacuum_setting"`
	WindowMS      int64            `json:"window_ms"`
	Note          string           `json:"note"`
	Windows       []gateDiagWindow `json:"windows"`
	Written       []string         `json:"tables_written_during_phase"`
	Errors5xx     []string         `json:"first_5xx_answers"`
	StoreErrors   []string         `json:"store_errors_not_invalid_code"`
	StoreErrCount int64            `json:"store_error_count"`
	QueryEvents   []string         `json:"queries_ended_with_done_ctx_or_57014"`
}

type gateDiag struct {
	t     *testing.T
	su    *pgxpool.Pool
	mw    *gateDiagMW
	phase string
	every time.Duration
	stop  chan struct{}
	done  chan struct{}
	rec   gateDiagRecord
	base  map[string]gateDiagTable
	lastW map[string]gateDiagTable
}

func startGateDiag(t *testing.T, su *pgxpool.Pool, mw *gateDiagMW, phase string, every time.Duration) *gateDiag {
	t.Helper()
	d := &gateDiag{t: t, su: su, mw: mw, phase: phase, every: every, stop: make(chan struct{}), done: make(chan struct{})}
	ctx := context.Background()
	var av string
	_ = su.QueryRow(ctx, `SHOW autovacuum`).Scan(&av)
	d.rec = gateDiagRecord{Phase: phase, Autovacuum: av, WindowMS: every.Milliseconds(),
		Note: "recorder windows start with the measured pass; the load client's own windows start about a second later"}
	d.base = d.tables(ctx)
	mw.take() // discard the warm-up's counters
	mw.mu.Lock()
	mw.t0 = time.Now()
	mw.errs, mw.storeErrs, mw.storeErrCount, mw.qEvents = nil, nil, 0, nil
	mw.mu.Unlock()
	go d.loop()
	return d
}

func (d *gateDiag) tables(ctx context.Context) map[string]gateDiagTable {
	out := map[string]gateDiagTable{}
	rows, err := d.su.Query(ctx, `SELECT relname, n_live_tup, n_dead_tup, seq_scan, COALESCE(idx_scan,0), n_tup_ins, n_tup_upd, n_tup_del,
		autovacuum_count, autoanalyze_count, pg_total_relation_size(relid) FROM pg_stat_user_tables`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var x gateDiagTable
		if rows.Scan(&x.Table, &x.Live, &x.Dead, &x.SeqScan, &x.IdxScan, &x.Ins, &x.Upd, &x.Del, &x.Autovacuum, &x.Autoanalyze, &x.TotalBytes) == nil {
			out[x.Table] = x
		}
	}
	return out
}

// gateDiagReadStat reads the aggregate "cpu" line of /proc/stat.
func gateDiagReadStat() ([]float64, bool) {
	if runtime.GOOS != "linux" {
		return nil, false
	}
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 8 && f[0] == "cpu" {
			var v []float64
			for _, s := range f[1:9] { // user nice system idle iowait irq softirq steal
				n, _ := strconv.ParseFloat(s, 64)
				v = append(v, n)
			}
			return v, true
		}
	}
	return nil, false
}

func gateDiagCPUShare(a, b []float64) gateDiagCPU {
	if len(a) < 8 || len(b) < 8 {
		return gateDiagCPU{}
	}
	var tot float64
	var d [8]float64
	for i := 0; i < 8; i++ {
		d[i] = b[i] - a[i]
		tot += d[i]
	}
	if tot <= 0 {
		return gateDiagCPU{}
	}
	return gateDiagCPU{User: (d[0] + d[1]) / tot, System: (d[2] + d[5] + d[6]) / tot, Idle: d[3] / tot, IOWait: d[4] / tot, Steal: d[7] / tot, Available: true}
}

func (d *gateDiag) loop() {
	defer close(d.done)
	ctx := context.Background()
	start := time.Now()
	prevStat, _ := gateDiagReadStat()
	tick := time.NewTicker(d.every)
	defer tick.Stop()
	for i := 0; ; i++ {
		select {
		case <-d.stop:
			return
		case <-tick.C:
		}
		w := gateDiagWindow{Index: i, ElapsedMS: time.Since(start).Milliseconds()}
		var med, p95 time.Duration
		w.Arrived, w.R429, w.Admitted, med, p95, w.InFlightEnd, w.InFlightMax = d.mw.take()
		w.AdmittedMedianMS, w.AdmittedP95MS = float64(med)/1e6, float64(p95)/1e6
		w.OfferedPerSec = float64(w.Arrived) / d.every.Seconds()
		if cur, ok := gateDiagReadStat(); ok {
			w.CPU = gateDiagCPUShare(prevStat, cur)
			prevStat = cur
		}
		_ = d.su.QueryRow(ctx, `SELECT count(*) FILTER (WHERE wait_event_type IS NOT NULL AND wait_event_type <> 'Client' AND state = 'active'),
			count(*) FILTER (WHERE state = 'active') FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()`).
			Scan(&w.WaitingBackends, &w.ActiveBackends)
		w.Tables = d.tables(ctx)
		d.rec.Windows = append(d.rec.Windows, w)
	}
}

// stopAndWrite ends the recorder, keeps the tables the phase wrote to, logs a compact table and writes the JSON.
func (d *gateDiag) stopAndWrite() {
	close(d.stop)
	<-d.done
	written := map[string]bool{}
	if n := len(d.rec.Windows); n > 0 {
		last := d.rec.Windows[n-1].Tables
		for name, e := range last {
			b := d.base[name]
			if e.Ins != b.Ins || e.Upd != b.Upd || e.Del != b.Del {
				written[name] = true
			}
		}
	}
	for name := range written {
		d.rec.Written = append(d.rec.Written, name)
	}
	sort.Strings(d.rec.Written)
	d.mw.mu.Lock()
	d.rec.Errors5xx = d.mw.errs
	d.rec.StoreErrors, d.rec.StoreErrCount = d.mw.storeErrs, d.mw.storeErrCount
	d.rec.QueryEvents = d.mw.qEvents
	d.mw.mu.Unlock()
	for i := range d.rec.Windows {
		kept := map[string]gateDiagTable{}
		for name, e := range d.rec.Windows[i].Tables {
			if written[name] {
				kept[name] = e
			}
		}
		d.rec.Windows[i].Tables = kept
	}
	d.t.Logf("diag %s: autovacuum=%s, tables written during the phase: %v", d.phase, d.rec.Autovacuum, d.rec.Written)
	for _, e := range d.rec.Errors5xx {
		d.t.Logf("diag 5xx: %s", e)
	}
	for _, e := range d.rec.StoreErrors {
		d.t.Logf("diag store error: %s", e)
	}
	for _, e := range d.rec.QueryEvents {
		d.t.Logf("diag query event: %s", e)
	}
	for _, w := range d.rec.Windows {
		line := []string{"w" + strconv.Itoa(w.Index), "arr=" + strconv.FormatInt(w.Arrived, 10), "429=" + strconv.FormatInt(w.R429, 10),
			"adm=" + strconv.FormatInt(w.Admitted, 10), "med=" + strconv.FormatFloat(w.AdmittedMedianMS, 'f', 1, 64) + "ms",
			"p95=" + strconv.FormatFloat(w.AdmittedP95MS, 'f', 1, 64) + "ms", "infl=" + strconv.FormatInt(w.InFlightEnd, 10) + "/" + strconv.FormatInt(w.InFlightMax, 10),
			"wait=" + strconv.Itoa(w.WaitingBackends) + "/" + strconv.Itoa(w.ActiveBackends)}
		if w.CPU.Available {
			line = append(line, "cpu u/s/io/st="+strconv.FormatFloat(w.CPU.User*100, 'f', 0, 64)+"/"+strconv.FormatFloat(w.CPU.System*100, 'f', 0, 64)+"/"+
				strconv.FormatFloat(w.CPU.IOWait*100, 'f', 0, 64)+"/"+strconv.FormatFloat(w.CPU.Steal*100, 'f', 0, 64))
		}
		if tc, ok := w.Tables["throttle_counter"]; ok {
			line = append(line, "throttle live/dead="+strconv.FormatInt(tc.Live, 10)+"/"+strconv.FormatInt(tc.Dead, 10),
				"seq/idx="+strconv.FormatInt(tc.SeqScan, 10)+"/"+strconv.FormatInt(tc.IdxScan, 10), "bytes="+strconv.FormatInt(tc.TotalBytes, 10))
		}
		d.t.Log("diag " + strings.Join(line, " "))
	}
	if dir := os.Getenv("DESKRALLY_GATE_OUT"); dir != "" {
		if b, err := json.MarshalIndent(d.rec, "", "  "); err == nil {
			_ = os.MkdirAll(dir, 0o755)
			p := filepath.Join(dir, "TestReleaseGateRedeemSoak_diag.json")
			if os.WriteFile(p, b, 0o644) == nil {
				d.t.Logf("release gate diagnostics: %s", p)
			}
		}
	}
}

// gateDiagAttended and gateDiagMachines log every store error the redeem handler would turn into a 5xx (anything that is
// not the generic invalid-code rejection), with the context's own error: the handler answers 500 without logging the cause.
type gateDiagAttended struct {
	AttendedStore
	mw *gateDiagMW
}

func (a gateDiagAttended) RedeemScoped(ctx context.Context, code, pubkeyHex, name string, scope RedeemScope) (*AttendedRedeem, error) {
	r, err := a.AttendedStore.RedeemScoped(ctx, code, pubkeyHex, name, scope)
	if err != nil && !errors.Is(err, ErrAttendedInvalid) {
		a.mw.storeErr("AttendedStore.RedeemScoped", ctx, err)
	}
	return r, err
}

type gateDiagMachines struct {
	MachineStore
	mw *gateDiagMW
}

func (m gateDiagMachines) KeyTombstoned(ctx context.Context, pubkeyHex string) (bool, error) {
	b, err := m.MachineStore.KeyTombstoned(ctx, pubkeyHex)
	if err != nil {
		m.mw.storeErr("MachineStore.KeyTombstoned", ctx, err)
	}
	return b, err
}

// storeErr keeps the first 50 errors, with the time since the phase started, and counts them by operation.
func (m *gateDiagMW) storeErr(op string, ctx context.Context, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeErrCount++
	if len(m.storeErrs) < 50 {
		m.storeErrs = append(m.storeErrs, fmt.Sprintf("%s %s: %v (ctx err: %v)", time.Since(m.t0).Round(time.Millisecond), op, err, ctx.Err()))
	}
}

// gateDiagTracer, when set (the diagnostics run only), is installed on every pool the harness builds. It records the
// queries that ended while their own context was already done, and the queries the server answered with 57014: pgx cancels
// a query by sending a CancelRequest on another connection, which it documents as "inherently racy" (it can land on the
// NEXT query of the backend). The pairs, by backend pid and time, show whether a 57014 victim followed a near-miss.
var gateDiagTracer pgx.QueryTracer

type gateDiagQKey struct{}

type gateDiagQInfo struct {
	start time.Time
	sql   string
	pid   uint32
}

type gateDiagQTracer struct{ mw *gateDiagMW }

func (t gateDiagQTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	s := strings.Join(strings.Fields(data.SQL), " ")
	if len(s) > 70 {
		s = s[:70]
	}
	return context.WithValue(ctx, gateDiagQKey{}, &gateDiagQInfo{start: time.Now(), sql: s, pid: conn.PgConn().PID()})
}

func (t gateDiagQTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	qi, _ := ctx.Value(gateDiagQKey{}).(*gateDiagQInfo)
	if qi == nil {
		return
	}
	cancelled := data.Err != nil && strings.Contains(data.Err.Error(), "57014")
	if ctx.Err() == nil && !cancelled {
		return
	}
	t.mw.queryEvent(fmt.Sprintf("pid=%d t_end=%s dur=%s ctx_err=%v err=%v sql=%q", qi.pid, time.Since(t.mw.t0).Round(time.Millisecond), time.Since(qi.start).Round(time.Millisecond), ctx.Err(), data.Err, qi.sql))
}

func (m *gateDiagMW) queryEvent(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.qEvents) < 400 {
		m.qEvents = append(m.qEvents, s)
	}
}
