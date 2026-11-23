package controlplane

import (
	"fmt"
	"sync"
	"testing"
)

// The peak watermark records what no sampler can: a burst that is acquired and released in microseconds.

func TestAdmissionPeakSeesAShortBurstASamplerWouldMiss(t *testing.T) {
	p := newAdmissionPool(64, 4)
	var rel []func()
	for i := 0; i < 40; i++ {
		r, ok := p.Acquire(fmt.Sprintf("k%d", i%10)) // 4 per key at most
		if !ok {
			t.Fatalf("acquire %d refused", i)
		}
		rel = append(rel, r)
	}
	for _, r := range rel {
		r()
	}
	if in, keys := p.stats(); in != 0 || keys != 0 {
		t.Fatalf("pool not drained: %d in flight, %d keys", in, keys)
	}
	if g, k := p.peak(); g != 40 || k != 4 {
		t.Fatalf("peak = (%d, %d), want (40, 4)", g, k)
	}
}

func TestAdmissionPeakNeverExceedsTheCaps(t *testing.T) {
	p := newAdmissionPool(5, 2)
	var rel []func()
	for i := 0; i < 20; i++ {
		if r, ok := p.Acquire(fmt.Sprintf("k%d", i%3)); ok {
			rel = append(rel, r)
		}
	}
	if g, k := p.peak(); g != 5 || k != 2 {
		t.Fatalf("peak = (%d, %d), want (5, 2): refused requests must not count", g, k)
	}
	for _, r := range rel {
		r()
	}
}

func TestAdmissionPeakIgnoresRefusalsAndDoubleRelease(t *testing.T) {
	p := newAdmissionPool(2, 1)
	r1, _ := p.Acquire("a")
	if _, ok := p.Acquire("a"); ok {
		t.Fatal("per-key cap not enforced")
	}
	r1()
	r1()
	if g, k := p.peak(); g != 1 || k != 1 {
		t.Fatalf("peak = (%d, %d), want (1, 1)", g, k)
	}
}

func TestAdmissionPeakReset(t *testing.T) {
	p := newAdmissionPool(10, 3)
	var rel []func()
	for i := 0; i < 6; i++ {
		r, _ := p.Acquire(fmt.Sprintf("k%d", i%2))
		rel = append(rel, r)
	}
	for _, r := range rel[:4] { // k0 and k1 hold 3 each; releasing 4 leaves k0:1, k1:1
		r()
	}
	in, _ := p.stats()
	p.resetPeak()
	if g, k := p.peak(); g != in || k != 1 {
		t.Fatalf("after reset with %d in flight: peak = (%d, %d), want (%d, 1)", in, g, k, in)
	}
	for _, r := range rel[4:] {
		r()
	}
	p.resetPeak()
	if g, k := p.peak(); g != 0 || k != 0 {
		t.Fatalf("after drain and reset: peak = (%d, %d), want (0, 0)", g, k)
	}
	r, _ := p.Acquire("z")
	r()
	if g, k := p.peak(); g != 1 || k != 1 {
		t.Fatalf("after reset and one request: peak = (%d, %d), want (1, 1)", g, k)
	}
}

// Under -race: many goroutines each hold a slot for a barrier-bounded moment; the true maximum is known exactly
// because every holder reaches the barrier before any releases.
func TestAdmissionPeakIsTheTrueMaximumUnderConcurrency(t *testing.T) {
	const keys, perKey, rounds = 8, 4, 50
	p := newAdmissionPool(keys*perKey, perKey)
	for round := 0; round < rounds; round++ {
		p.resetPeak()
		var held, done sync.WaitGroup
		held.Add(keys * perKey)
		done.Add(keys * perKey)
		gate := make(chan struct{})
		for k := 0; k < keys; k++ {
			for j := 0; j < perKey; j++ {
				go func(key string) {
					defer done.Done()
					r, ok := p.Acquire(key)
					held.Done()
					if !ok {
						t.Error("refused under the cap")
						return
					}
					<-gate
					r()
				}(fmt.Sprintf("k%d", k))
			}
		}
		held.Wait()
		close(gate)
		done.Wait()
		if g, k := p.peak(); g != keys*perKey || k != perKey {
			t.Fatalf("round %d: peak = (%d, %d), want (%d, %d)", round, g, k, keys*perKey, perKey)
		}
	}
	// Unsynchronised churn beyond the caps: the peak is exactly the cap, never above, and the pool drains.
	q := newAdmissionPool(6, 3)
	var wg sync.WaitGroup
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if r, ok := q.Acquire(fmt.Sprintf("k%d", (g+i)%4)); ok {
					r()
				}
			}
		}(g)
	}
	wg.Wait()
	if g, k := q.peak(); g > 6 || k > 3 || g < 1 || k < 1 {
		t.Fatalf("churn peak = (%d, %d), want within (1..6, 1..3)", g, k)
	}
	if in, keys := q.stats(); in != 0 || keys != 0 {
		t.Fatalf("pool not drained: %d, %d", in, keys)
	}
}
