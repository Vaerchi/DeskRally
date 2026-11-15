package controlplane

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestGateSamplerSummarisesAPhase(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable") // never dials
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	adm := newAdmissionPool(64, 4)
	s := startGateSampler(gateSamplerSources{Pools: map[string]*pgxpool.Pool{"lookup": pool},
		Admission: map[string]*admissionPool{"branding": adm}, Interval: 5 * time.Millisecond})

	// A burst the sampler cannot see (acquired and released at once), plus goroutines that live long enough to be sampled.
	var rel []func()
	for i := 0; i < 12; i++ {
		r, _ := adm.Acquire(fmt.Sprintf("k%d", i%3))
		rel = append(rel, r)
	}
	for _, r := range rel {
		r()
	}
	stopGo := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() { <-stopGo }()
	}
	time.Sleep(60 * time.Millisecond)
	close(stopGo)
	time.Sleep(20 * time.Millisecond)
	m := s.stop()
	if again := s.stop(); again.Samples != m.Samples {
		t.Fatal("second stop changed the result")
	}

	if g := m.Series["goroutines"]; g.Peak < g.Start+20 || g.Samples < 3 {
		t.Fatalf("goroutines %+v: want a peak at least 20 above the start", g)
	}
	if g := m.Series["goroutines"]; g.Growth != g.End-g.Start {
		t.Fatalf("goroutine growth %d != end-start", g.Growth)
	}
	for _, name := range []string{"heap_inuse_bytes", "heap_alloc_bytes", "pool/lookup/total_conns", "pool/lookup/acquired_conns"} {
		if _, ok := m.Series[name]; !ok {
			t.Errorf("series %s missing: %v", name, m.seriesNames())
		}
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		if f, ok := m.Series["open_fds"]; !ok || f.Start <= 0 {
			t.Errorf("open_fds = %+v (present %v), want a positive count", f, ok)
		}
	} else if m.NotMeasured["open_fds"] == "" {
		t.Error("open_fds not measured but no reason given")
	}
	if m.NotMeasured["pg_stat_activity"] == "" {
		t.Error("no superuser pool: pg_stat_activity must be reported as not measured")
	}
	if a := m.Admission["branding"]; a.Global != 12 || a.PerKey != 4 {
		t.Fatalf("admission peak %+v, want global 12, per key 4 (the burst between two ticks)", a)
	}
	if _, err := json.Marshal(m); err != nil {
		t.Fatal(err)
	}
}

func TestGateOpenFDsSeesAnOpenFile(t *testing.T) {
	before, ok, why := gateOpenFDs()
	if !ok {
		if why == "" {
			t.Fatal("open descriptors not measured and no reason given")
		}
		return // a platform without a counter says so; the sampler records the reason (never a skip)
	}
	var fs []*os.File
	for i := 0; i < 10; i++ {
		f, err := os.Open(os.Args[0])
		if err != nil {
			t.Fatal(err)
		}
		fs = append(fs, f)
	}
	after, _, _ := gateOpenFDs()
	for _, f := range fs {
		f.Close()
	}
	if after < before+10 {
		t.Fatalf("handles %d -> %d after opening 10 files", before, after)
	}
}
