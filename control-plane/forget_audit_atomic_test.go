package controlplane

// Review (Codex, MEDIUM) of the fake's all-or-nothing audit append: another writer can append a same-tenant event
// BETWEEN the batch's appends; a later failure then deleted the earlier event while the concurrent event kept its
// hash as predecessor, breaking the chain. The in-memory store now appends a batch atomically (appendBatch), so no
// writer can land inside it and a failure commits nothing.

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRecordAllNeverBreaksTheChainUnderAConcurrentWriter(t *testing.T) {
	ctx := context.Background()
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mem := NewInMemoryMgmtAuditStore()
	audit := &failAuditStore{MgmtAuditStore: mem, yield: true}
	audit.failOnly("batch.fail")
	dirs := NewInMemoryDirectiveStore(NewInMemoryMachineStore(), audit)

	var stop atomic.Bool
	var wg sync.WaitGroup
	var concurrent atomic.Int64
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 3000 && !stop.Load(); n++ {
				if err := audit.RecordEvent(ctx, tenant, &MgmtAuditEvent{Action: "other.writer", TargetKind: "x", TargetID: "x"}); err != nil {
					t.Errorf("concurrent writer: %v", err)
					return
				}
				concurrent.Add(1)
			}
		}()
	}
	ev := func(a string) *MgmtAuditEvent { return &MgmtAuditEvent{Action: a, TargetKind: "x", TargetID: "x"} }
	var failed, ok int
	for i := 0; i < 1500; i++ {
		if i%2 == 0 {
			// the SECOND append fails: nothing of the batch may survive
			if err := dirs.recordAll(ctx, tenant, []*MgmtAuditEvent{ev("batch.first"), ev("batch.fail")}); err == nil {
				t.Fatal("a failing batch reported success")
			}
			failed++
		} else {
			if err := dirs.recordAll(ctx, tenant, []*MgmtAuditEvent{ev("batch.a"), ev("batch.b")}); err != nil {
				t.Fatalf("a good batch failed: %v", err)
			}
			ok++
		}
	}
	stop.Store(true)
	wg.Wait()

	res, err := VerifyMgmtAuditChain(ctx, mem, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Completed {
		t.Fatalf("the tenant's audit chain broke under a concurrent writer: %+v", res)
	}
	evs, _ := mem.ListEventsAsc(ctx, tenant, -1, 100000)
	var firsts, adjacent int
	for i, e := range evs {
		if e.Action == "batch.first" || e.Action == "batch.fail" {
			firsts++
		}
		if e.Action == "batch.a" && i+1 < len(evs) && evs[i+1].Action == "batch.b" {
			adjacent++
		}
	}
	if firsts != 0 {
		t.Fatalf("%d events of failed batches survived", firsts)
	}
	if adjacent != ok {
		t.Fatalf("only %d of %d good batches are contiguous: a writer landed inside a batch", adjacent, ok)
	}
	if concurrent.Load() == 0 {
		t.Fatal("the concurrent writer never ran, the test proved nothing")
	}
	t.Logf("%d failed + %d good batches, %d concurrent events, chain of %d verified", failed, ok, concurrent.Load(), res.CheckedEvents)
}

// The help-request fake stages its audit rows and appends them together at commit, so the same interleaving
// cannot break the chain there either (a failing transition discards nothing another writer chained onto).
func TestHelpFakeAuditBatchNeverBreaksTheChainUnderAConcurrentWriter(t *testing.T) {
	ctx := context.Background()
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mem := NewInMemoryMgmtAuditStore()
	audit := &failAuditStore{MgmtAuditStore: mem, yield: true}
	hs := NewInMemoryHelpRequestStore(NewInMemoryMachineStore(), nil, audit)
	audit.failOnly("batch.fail")

	var stop atomic.Bool
	var wg sync.WaitGroup
	var concurrent atomic.Int64
	wg.Add(1)
	go func() {
		defer wg.Done()
		for n := 0; n < 3000 && !stop.Load(); n++ {
			if err := audit.RecordEvent(ctx, tenant, &MgmtAuditEvent{Action: "other.writer", TargetKind: "x", TargetID: "x"}); err != nil {
				t.Errorf("concurrent writer: %v", err)
				return
			}
			concurrent.Add(1)
		}
	}()
	for i := 0; i < 1000; i++ {
		done := hs.begin()
		var err error
		for _, a := range []string{"batch.first", "batch.fail"} {
			if rerr := hs.record(ctx, tenant, &HelpResult{}, &MgmtAuditEvent{Action: a, TargetKind: "x", TargetID: "x"}); rerr != nil {
				err = rerr
			}
		}
		done(&err)
		if err == nil {
			t.Fatal("a failing transition reported success")
		}
	}
	stop.Store(true)
	wg.Wait()
	res, err := VerifyMgmtAuditChain(ctx, mem, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || !res.Completed {
		t.Fatalf("the help fake broke the tenant's audit chain under a concurrent writer: %+v", res)
	}
	if concurrent.Load() == 0 {
		t.Fatal("the concurrent writer never ran")
	}
}

// Verifier gap: the wrappers fail a batch BEFORE the real store is reached, so the store's own staged-failure path
// had no test. Invalid-JSON metadata makes stampMgmtChainFields fail on a LATER event of the batch, inside
// appendBatch: nothing of the batch may be committed, the tail must not move, and the caller's events stay untouched.
func TestAppendBatchStagedFailureCommitsNothing(t *testing.T) {
	ctx := context.Background()
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mem := NewInMemoryMgmtAuditStore()
	ev := func(a string) *MgmtAuditEvent { return &MgmtAuditEvent{Action: a, TargetKind: "x", TargetID: "x"} }
	if err := mem.RecordEvent(ctx, tenant, ev("seed")); err != nil {
		t.Fatal(err)
	}
	bad := ev("bad")
	bad.Metadata = []byte("{not json")
	first, second := ev("first"), ev("second")
	if err := mem.appendBatch(ctx, tenant, []*MgmtAuditEvent{first, second, bad}); err == nil {
		t.Fatal("a batch with an unhashable event reported success")
	}
	if first.Seq != nil || first.Hash != "" || second.Seq != nil {
		t.Fatalf("a failed batch wrote back into the caller's events: %+v %+v", first, second)
	}
	evs, _ := mem.ListEventsAsc(ctx, tenant, -1, 100)
	if len(evs) != 1 || evs[0].Action != "seed" {
		t.Fatalf("a failed batch left %d events (want only the seed)", len(evs))
	}
	// the tail did not move: the next batch chains straight onto the seed
	if err := mem.appendBatch(ctx, tenant, []*MgmtAuditEvent{ev("a"), ev("b")}); err != nil {
		t.Fatal(err)
	}
	res, err := VerifyMgmtAuditChain(ctx, mem, tenant)
	if err != nil || !res.OK || !res.Completed || res.CheckedEvents != 3 {
		t.Fatalf("chain after a failed then a good batch: %+v err=%v", res, err)
	}
}

// The store's own atomicity and contiguity under concurrent same-tenant writers, with failures raised INSIDE
// appendBatch (the unhashable last event), not by a wrapper.
func TestAppendBatchIsContiguousUnderConcurrentWritersWithInnerFailures(t *testing.T) {
	ctx := context.Background()
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mem := NewInMemoryMgmtAuditStore()
	var stop atomic.Bool
	var wg sync.WaitGroup
	var concurrent atomic.Int64
	for w := 0; w < 3; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 5000 && !stop.Load(); n++ {
				if err := mem.RecordEvent(ctx, tenant, &MgmtAuditEvent{Action: "other.writer", TargetKind: "x", TargetID: "x"}); err != nil {
					t.Errorf("concurrent writer: %v", err)
					return
				}
				concurrent.Add(1)
				runtime.Gosched()
			}
		}()
	}
	ev := func(a string) *MgmtAuditEvent { return &MgmtAuditEvent{Action: a, TargetKind: "x", TargetID: "x"} }
	var ok int
	for i := 0; i < 1000; i++ {
		if i%2 == 0 {
			bad := ev("batch.bad")
			bad.Metadata = []byte("{not json")
			if err := mem.appendBatch(ctx, tenant, []*MgmtAuditEvent{ev("batch.first"), ev("batch.mid"), bad}); err == nil {
				t.Fatal("a failing batch reported success")
			}
		} else {
			if err := mem.appendBatch(ctx, tenant, []*MgmtAuditEvent{ev("batch.a"), ev("batch.b"), ev("batch.c")}); err != nil {
				t.Fatal(err)
			}
			ok++
		}
	}
	stop.Store(true)
	wg.Wait()
	res, err := VerifyMgmtAuditChain(ctx, mem, tenant)
	if err != nil || !res.OK || !res.Completed {
		t.Fatalf("chain broke: %+v err=%v", res, err)
	}
	evs, _ := mem.ListEventsAsc(ctx, tenant, -1, 100000)
	var adjacent int
	for i, e := range evs {
		if e.Action == "batch.first" || e.Action == "batch.mid" || e.Action == "batch.bad" {
			t.Fatalf("an event of a failed batch survived: %s", e.Action)
		}
		if e.Action == "batch.a" && i+2 < len(evs) && evs[i+1].Action == "batch.b" && evs[i+2].Action == "batch.c" {
			adjacent++
		}
	}
	if adjacent != ok {
		t.Fatalf("only %d of %d good batches are contiguous: a writer landed inside a batch", adjacent, ok)
	}
	if concurrent.Load() == 0 {
		t.Fatal("the concurrent writers never ran")
	}
}

// Through the help fake, with transitions that SUCCEED (their batch reaches the real store) interleaved with
// failing ones: good batches must be contiguous and failed ones absent.
func TestHelpFakeGoodAndFailingTransitionsStayContiguousUnderAConcurrentWriter(t *testing.T) {
	ctx := context.Background()
	const tenant = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	mem := NewInMemoryMgmtAuditStore()
	audit := &failAuditStore{MgmtAuditStore: mem, yield: true}
	hs := NewInMemoryHelpRequestStore(NewInMemoryMachineStore(), nil, audit)
	audit.failOnly("batch.fail")
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 2; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for n := 0; n < 4000 && !stop.Load(); n++ {
				if err := audit.RecordEvent(ctx, tenant, &MgmtAuditEvent{Action: "other.writer", TargetKind: "x", TargetID: "x"}); err != nil {
					t.Errorf("concurrent writer: %v", err)
					return
				}
			}
		}()
	}
	run := func(actions ...string) error {
		done := hs.begin()
		var err error
		for _, a := range actions {
			if rerr := hs.record(ctx, tenant, &HelpResult{}, &MgmtAuditEvent{Action: a, TargetKind: "x", TargetID: "x"}); rerr != nil {
				err = rerr
			}
		}
		done(&err)
		return err
	}
	var ok int
	for i := 0; i < 800; i++ {
		if i%2 == 0 {
			if run("batch.first", "batch.fail") == nil {
				t.Fatal("a failing transition reported success")
			}
		} else {
			if err := run("batch.a", "batch.b", "batch.c"); err != nil {
				t.Fatal(err)
			}
			ok++
		}
	}
	stop.Store(true)
	wg.Wait()
	res, err := VerifyMgmtAuditChain(ctx, mem, tenant)
	if err != nil || !res.OK || !res.Completed {
		t.Fatalf("chain broke: %+v err=%v", res, err)
	}
	evs, _ := mem.ListEventsAsc(ctx, tenant, -1, 100000)
	var adjacent int
	for i, e := range evs {
		if e.Action == "batch.first" || e.Action == "batch.fail" {
			t.Fatalf("an event of a failed transition survived: %s", e.Action)
		}
		if e.Action == "batch.a" && i+2 < len(evs) && evs[i+1].Action == "batch.b" && evs[i+2].Action == "batch.c" {
			adjacent++
		}
	}
	if adjacent != ok {
		t.Fatalf("only %d of %d good transitions are contiguous", adjacent, ok)
	}
}
