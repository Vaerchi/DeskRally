package controlplane

// The soak VOID rule for the disk under the database (docs/66 section 2o, the coordinator's decision of 2026-11-13).
//
// A soak whose throughput follows the commit rate of the disk (the redeem rejection path does synchronous writes) is a
// measurement of that disk when the disk itself changes speed mid-run: on 2026-11-13 the VM's virtual disk went from 0.94
// ms to 2.91 ms per cache flush five minutes into a soak and the soak stepped with it. Such a run is VOID, not passed and
// not failed (the precedent is the A/A control's "release gate VOID"): the environment, not the code, moved.
//
// Per window the monitor reads the block device's cumulative flush count and flush time from /proc/diskstats (the whole
// disk under the PostgreSQL data directory) and derives the mean time per flush in that window. A window with fewer than
// gateFlushMinPerWindow flushes carries no information (the database was not flushing) and is left out; fewer than
// gateFlushMinWindows usable windows means "not enough flushes to judge" and never voids. The window values are smoothed
// with a running median of three (one slow window is noise, a step is not) and the run is VOID when the largest smoothed
// value is more than gateFlushVoidRatio times the smallest. Where /proc/diskstats is unavailable (Windows, a database on
// another machine) the record says "flush latency not measured" and nothing is voided. The ratio is fixed here and does
// not move with DESKRALLY_GATE_SCALE; it judges the environment, not a threshold of the product.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	gateFlushVoidRatio    = 2.0
	gateFlushMinPerWindow = 20
	gateFlushMinWindows   = 3
)

// gateFlushSample is one cumulative reading of a block device.
type gateFlushSample struct {
	Flushes int64
	FlushMS int64
}

// gateFlushWindowMS turns consecutive cumulative samples into mean milliseconds per flush per usable window.
func gateFlushWindowMS(samples []gateFlushSample) []float64 {
	var out []float64
	for i := 1; i < len(samples); i++ {
		n := samples[i].Flushes - samples[i-1].Flushes
		if n < gateFlushMinPerWindow {
			continue
		}
		out = append(out, float64(samples[i].FlushMS-samples[i-1].FlushMS)/float64(n))
	}
	return out
}

// gateFlushVerdict returns the ratio of the largest to the smallest smoothed window value, whether the run is VOID, and
// whether there was enough to judge at all.
func gateFlushVerdict(windows []float64) (ratio float64, void, judged bool) {
	if len(windows) < gateFlushMinWindows {
		return 0, false, false
	}
	sm := make([]float64, 0, len(windows))
	for i := range windows {
		lo, hi := max(0, i-1), min(len(windows)-1, i+1)
		w := append([]float64{}, windows[lo:hi+1]...)
		sort.Float64s(w)
		sm = append(sm, w[len(w)/2])
	}
	mn, mx := sm[0], sm[0]
	for _, v := range sm {
		mn, mx = min(mn, v), max(mx, v)
	}
	if mn <= 0 {
		return 0, false, false
	}
	ratio = mx / mn
	return ratio, ratio > gateFlushVoidRatio, true
}

type gateFlushResult struct {
	Measured bool
	Reason   string // why not measured
	Device   string
	Windows  []float64 // mean ms per flush per usable window
	Ratio    float64
	Judged   bool
	Void     bool
}

// Note is the sentence the JSON record and the log carry.
func (r gateFlushResult) Note() string {
	switch {
	case !r.Measured:
		return "flush latency not measured: " + r.Reason
	case !r.Judged:
		return fmt.Sprintf("flush latency of %s: too few flushes to judge (%d usable windows, need %d of at least %d flushes)", r.Device, len(r.Windows), gateFlushMinWindows, gateFlushMinPerWindow)
	case r.Void:
		return fmt.Sprintf("flush latency of %s changed %.2fx within the run (more than %.1fx; per-window ms per flush %s): the disk moved, not the code", r.Device, r.Ratio, gateFlushVoidRatio, fmtFlushWindows(r.Windows))
	}
	return fmt.Sprintf("flush latency of %s stable: %.2fx between the largest and smallest smoothed window (limit %.1fx; per-window ms per flush %s)", r.Device, r.Ratio, gateFlushVoidRatio, fmtFlushWindows(r.Windows))
}

func fmtFlushWindows(w []float64) string {
	s := make([]string, len(w))
	for i, v := range w {
		s[i] = strconv.FormatFloat(v, 'f', 2, 64)
	}
	return strings.Join(s, " ")
}

// gateFlushMon samples the device once per window of the phase.
type gateFlushMon struct {
	dev     string
	reason  string
	every   time.Duration
	stop    chan struct{}
	done    chan struct{}
	samples []gateFlushSample
}

// gateReadFlush reads one device's cumulative flush count and flush milliseconds from /proc/diskstats.
func gateReadFlush(dev string) (gateFlushSample, error) {
	b, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return gateFlushSample{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[2] != dev {
			continue
		}
		if len(f) < 20 {
			return gateFlushSample{}, fmt.Errorf("/proc/diskstats has no flush columns for %s (kernel older than 5.5)", dev)
		}
		n, e1 := strconv.ParseInt(f[18], 10, 64)
		ms, e2 := strconv.ParseInt(f[19], 10, 64)
		if e1 != nil || e2 != nil {
			return gateFlushSample{}, fmt.Errorf("unreadable flush columns for %s", dev)
		}
		return gateFlushSample{Flushes: n, FlushMS: ms}, nil
	}
	return gateFlushSample{}, fmt.Errorf("%s not in /proc/diskstats", dev)
}

// startGateFlushMon finds the disk under the database's data directory (through the fixture's superuser pool) and starts
// sampling it every window. It never fails: a monitor that cannot measure says why.
func startGateFlushMon(su *pgxpool.Pool, every time.Duration) *gateFlushMon {
	m := &gateFlushMon{every: every, stop: make(chan struct{}), done: make(chan struct{})}
	var dataDir string
	if su == nil {
		m.reason = "no database pool"
	} else if err := su.QueryRow(context.Background(), `SHOW data_directory`).Scan(&dataDir); err != nil {
		m.reason = "the data directory is not readable through the database: " + err.Error()
	} else if dev, err := gateBlockDeviceOf(dataDir); err != nil {
		m.reason = err.Error()
	} else if s, err := gateReadFlush(dev); err != nil {
		m.reason = err.Error()
	} else {
		m.dev = dev
		m.samples = append(m.samples, s)
	}
	if m.reason != "" {
		close(m.done)
		return m
	}
	go func() {
		defer close(m.done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-m.stop:
				if s, err := gateReadFlush(m.dev); err == nil {
					m.samples = append(m.samples, s)
				}
				return
			case <-tick.C:
				if s, err := gateReadFlush(m.dev); err == nil {
					m.samples = append(m.samples, s)
				}
			}
		}
	}()
	return m
}

// result stops the monitor and returns what it saw.
func (m *gateFlushMon) result() gateFlushResult {
	if m.reason != "" {
		return gateFlushResult{Reason: m.reason}
	}
	close(m.stop)
	<-m.done
	w := gateFlushWindowMS(m.samples)
	ratio, void, judged := gateFlushVerdict(w)
	return gateFlushResult{Measured: true, Device: m.dev, Windows: w, Ratio: ratio, Judged: judged, Void: void}
}
