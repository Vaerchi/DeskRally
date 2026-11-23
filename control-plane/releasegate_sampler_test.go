package controlplane

// The docs/66 release gate's metrics sampler (plan step 5). Start it, run a phase, stop it, and write the summary
// into the phase's JSON record. It samples what the gate will later bound (plan items 8, 9, 11): goroutines, heap,
// pgxpool.Stat() of each pool handed to it, the test database's backends in pg_stat_activity (through a separate
// superuser pool, so the measurement never competes with the pools under test), and this process's open file
// descriptors (Linux) or handles (Windows).
//
// A sampler cannot see every transient, so it is NOT the evidence for the in-flight caps: that is the admission
// pool's own peak watermark (redeem_admission.go), read exactly at stop. The sampler's peaks are the evidence for the
// coarser resources, where a 50 ms tick is fine.
//
// Untagged on purpose: it has a fast unit test (releasegate_sampler_unit_test.go) in the ordinary suite. The file
// descriptor counters live in releasegate_fds_*_test.go.

import (
	"context"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// gateSamplerSources names what to measure; every field is optional.
type gateSamplerSources struct {
	// Pools: application pools by label ("shared", "lookup"), measured through Stat().
	Pools map[string]*pgxpool.Pool
	// Admission: admission pools by label ("branding", "redeem"); their peak watermark is reset at start, read at stop.
	Admission map[string]*admissionPool
	// Super: a superuser pool for pg_stat_activity. Nil means that series is reported as not measured.
	Super *pgxpool.Pool
	// Interval defaults to 50 ms.
	Interval time.Duration
}

// gateSeries summarises one sampled quantity. Growth = End - Start: the figure the soak (plan item 11) bounds.
type gateSeries struct {
	Start   int64 `json:"start"`
	End     int64 `json:"end"`
	Peak    int64 `json:"peak"`
	Growth  int64 `json:"growth"`
	Samples int   `json:"samples"`
}

// gateAdmissionPeak is the exact high-water mark of an admission pool over the phase.
type gateAdmissionPeak struct {
	Global int `json:"global"`
	PerKey int `json:"per_key"`
}

// gateMetrics is what a phase's JSON record embeds.
type gateMetrics struct {
	DurationMS int64                        `json:"duration_ms"`
	Samples    int                          `json:"samples"`
	Series     map[string]gateSeries        `json:"series"`
	Admission  map[string]gateAdmissionPeak `json:"admission_peaks,omitempty"`
	// NotMeasured names every series that could not be measured, with the reason: never silently absent.
	NotMeasured map[string]string `json:"not_measured,omitempty"`
}

type gateSampler struct {
	src   gateSamplerSources
	start time.Time

	mu       sync.Mutex
	series   map[string]*gateSeries
	notMeas  map[string]string
	samples  int
	done     chan struct{}
	finished chan struct{}
	stopOnce sync.Once
	result   gateMetrics
}

// startGateSampler takes the first sample synchronously (after a GC, so the heap start is the retained heap, not
// garbage) and then samples every Interval until stop.
func startGateSampler(src gateSamplerSources) *gateSampler {
	if src.Interval <= 0 {
		src.Interval = 50 * time.Millisecond
	}
	s := &gateSampler{src: src, series: map[string]*gateSeries{}, notMeas: map[string]string{},
		done: make(chan struct{}), finished: make(chan struct{})}
	for _, p := range src.Admission {
		p.resetPeak()
	}
	gateGC()
	s.start = time.Now()
	s.sample()
	go func() {
		defer close(s.finished)
		tick := time.NewTicker(src.Interval)
		defer tick.Stop()
		for {
			select {
			case <-s.done:
				return
			case <-tick.C:
				s.sample()
			}
		}
	}()
	return s
}

func (s *gateSampler) record(name string, v int64) {
	sr := s.series[name]
	if sr == nil {
		sr = &gateSeries{Start: v, Peak: v}
		s.series[name] = sr
	}
	sr.End = v
	sr.Peak = max(sr.Peak, v)
	sr.Samples++
}

func (s *gateSampler) sample() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.samples++
	s.record("goroutines", int64(runtime.NumGoroutine()))
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	s.record("heap_inuse_bytes", int64(ms.HeapInuse))
	s.record("heap_alloc_bytes", int64(ms.HeapAlloc))
	// OS threads created so far (the runtime never ends one): on Windows each is a handle, so this explains a handle plateau
	// that is not a leak. Recorded, never gated.
	s.record("os_threads_created", int64(pprof.Lookup("threadcreate").Count()))
	if n, ok, why := gateOpenFDs(); ok {
		s.record("open_fds", int64(n))
		s.record("open_fds_net", int64(n)-gateHandlesPerOSThread*int64(pprof.Lookup("threadcreate").Count()))
	} else {
		s.notMeas["open_fds"] = why
	}
	for name, p := range s.src.Pools {
		st := p.Stat()
		s.record("pool/"+name+"/total_conns", int64(st.TotalConns()))
		s.record("pool/"+name+"/acquired_conns", int64(st.AcquiredConns()))
	}
	if s.src.Super == nil {
		s.notMeas["pg_stat_activity"] = "no superuser pool supplied"
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var n int64
	if err := s.src.Super.QueryRow(ctx, "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()").Scan(&n); err != nil {
		s.notMeas["pg_stat_activity"] = "query failed: " + err.Error()
		return
	}
	s.record("pg_stat_activity_backends", n)
}

// stop ends sampling, takes a final sample after a GC (so heap End is retained memory), reads the admission peaks,
// and returns the summary. It is safe to call twice; the second call returns the first result.
func (s *gateSampler) stop() gateMetrics {
	s.stopOnce.Do(func() {
		close(s.done)
		<-s.finished
		gateGC()
		s.sample()
		s.mu.Lock()
		defer s.mu.Unlock()
		m := gateMetrics{DurationMS: time.Since(s.start).Milliseconds(), Samples: s.samples,
			Series: map[string]gateSeries{}}
		for name, sr := range s.series {
			c := *sr
			c.Growth = c.End - c.Start
			m.Series[name] = c
		}
		if len(s.notMeas) > 0 {
			m.NotMeasured = map[string]string{}
			for k, v := range s.notMeas {
				m.NotMeasured[k] = v
			}
		}
		if len(s.src.Admission) > 0 {
			m.Admission = map[string]gateAdmissionPeak{}
			for name, p := range s.src.Admission {
				g, k := p.peak()
				m.Admission[name] = gateAdmissionPeak{Global: g, PerKey: k}
			}
		}
		s.result = m
	})
	return s.result
}

// seriesNames lists a summary's series in order (stable log output).
func (m gateMetrics) seriesNames() []string {
	names := make([]string, 0, len(m.Series))
	for k := range m.Series {
		names = append(names, k)
	}
	sort.Strings(names)
	return names
}

// gateGC collects twice. A sync.Pool is emptied only by two collections (the first moves its contents to a victim
// cache, the second drops them), and net/http keeps its 4 KiB connection buffers in pools: after a burst of
// connections one GC would leave megabytes of pooled buffers counted as live heap, which is retention the runtime
// releases by itself and not a leak. Two collections measure what the code itself holds.
func gateGC() {
	runtime.GC()
	runtime.GC()
}
