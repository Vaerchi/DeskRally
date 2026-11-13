package controlplane

// Deterministic regression tests for bufferTenantBody admission-control fairness.
//
// WHAT IS TESTED
//
// TestBodyAdmissionTenantFairness
//   Eight in-progress tenant-A reads (goroutines blocked inside io.ReadAll, signaled by
//   channels) hold all eight per-tenant slots.  While those reads are in progress:
//     - A ninth tenant-A request is denied 503 and its body's Read is never called
//       (the negative control: over-limit tenant cannot consume new body IO).
//     - A tenant-B request is admitted normally (cross-tenant isolation).
//   After all eight goroutines are unblocked and call release():
//     - The global slot count returns to its pre-test value (no leak).
//     - The tenant-A counter is zero / key absent (no leak).
//     - Tenant A is re-admitted immediately.
//
// TestBodyAdmissionErrorReleasesSlot
//   A body whose Read returns a plain error yields 400; an oversize body yields 413.
//   Both exit paths call release() internally, so neither strands a global slot or
//   a tenant counter.  Admission for the same tenant works again after each failure.
//
// TestBodyAdmissionGlobalCapacity
//   Fills every remaining global slot synchronously (holding release funcs), verifies
//   that any additional request from any tenant gets 503, then releases all slots and
//   verifies recovery.  Uses four tenant groups of ≤8 each to stay under the per-tenant
//   limit while exhausting the global cap of 32.
//
// WHAT IS NOT TESTED
//
//   - The HTTP handler chain above bufferTenantBody (auth, CSRF, RLS middleware, router).
//     Those are tested in bodylimit_test.go and security_remediation_test.go.
//   - Any network connection or database.  All I/O is in-process.
//   - t.Parallel: not used because tenantBodySlots and tenantBodyCounts are package-level
//     state shared across the whole test binary.
//   - Concurrent races toward the global cap: the goroutine-based fairness test covers
//     concurrent in-progress reads; the capacity test covers sequential fill accounting.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// blockingBody is a ReadCloser whose first Read signals entered (buffered 1), then blocks
// on unblock.  After unblock it returns (0, io.EOF) so io.ReadAll completes with no bytes.
// The goroutine holds its global slot and tenant counter for exactly as long as it blocks.
type blockingBody struct {
	entered  chan<- struct{}
	unblock  <-chan struct{}
	signaled bool
}

func (b *blockingBody) Read(p []byte) (int, error) {
	if !b.signaled {
		b.signaled = true
		b.entered <- struct{}{} // non-blocking: channel is always buffered(1)
		<-b.unblock
	}
	return 0, io.EOF
}
func (b *blockingBody) Close() error { return nil }

// alwaysErrBody returns the wrapped error on the first Read, simulating a transport fault.
type alwaysErrBody struct{ err error }

func (e *alwaysErrBody) Read(p []byte) (int, error) { return 0, e.err }
func (e *alwaysErrBody) Close() error               { return nil }

// Records unexpected I/O without blocking the test when an admission guard regresses.
type fairnessObservedBody struct{ read bool }

func (b *fairnessObservedBody) Read(p []byte) (int, error) { b.read = true; return 0, io.EOF }
func (b *fairnessObservedBody) Close() error               { return nil }

// fairnessReq builds an in-process request whose context carries a Principal for tenantID.
// It is the minimal harness for calling bufferTenantBody without the router or middleware.
func fairnessReq(tenantID string, body io.ReadCloser) (*httptest.ResponseRecorder, *http.Request) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/sessions", nil)
	req.Body = body
	p := &Principal{TenantID: tenantID, UserID: "u-fair-" + tenantID}
	ctx := context.WithValue(req.Context(), ctxPrincipal, p)
	return rec, req.WithContext(ctx)
}

// TestBodyAdmissionTenantFairness is the primary concurrency test for the slot-fairness
// invariants.  See the file-level comment for a full description of what each phase proves.
func TestBodyAdmissionTenantFairness(t *testing.T) {
	const tenantA = "fa000000-0000-0000-0000-000000000001"
	const tenantB = "fa000000-0000-0000-0000-000000000002"

	slotsBefore := len(tenantBodySlots)

	// ── Phase 1: 8 goroutines for tenant A, each blocking inside io.ReadAll ──────────────

	const nA = 8
	type worker struct {
		entered chan struct{}
		unblock chan struct{}
		done    chan error // buffered(1); non-nil = unexpected failure
	}
	ws := make([]worker, nA)
	for i := range ws {
		ws[i] = worker{
			entered: make(chan struct{}, 1),
			unblock: make(chan struct{}),
			done:    make(chan error, 1),
		}
	}

	// unblockAll is a helper to drain any already-closed channels and close the rest,
	// used in the early-exit paths so goroutines can always terminate.
	unblockAll := func() {
		for _, w := range ws {
			select {
			case <-w.unblock: // already closed, drain
			default:
				close(w.unblock)
			}
		}
	}

	t.Cleanup(func() {
		unblockAll()
		for i, w := range ws {
			select {
			case err := <-w.done:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("worker %d did not stop during cleanup", i)
			}
		}
	})

	for idx, w := range ws {
		idx, w := idx, w
		go func() {
			defer close(w.done)
			rec, req := fairnessReq(tenantA, &blockingBody{entered: w.entered, unblock: w.unblock})
			release, ok := bufferTenantBody(rec, req)
			if !ok {
				// Do not call t.Fatal from a goroutine; report via channel instead.
				w.done <- fmt.Errorf("worker %d: bufferTenantBody denied unexpectedly (code %d)", idx, rec.Code)
				return
			}
			release()
			w.done <- nil
		}()
	}

	// Wait for every goroutine to reach its first Read call; the slot is held from this point.
	for i, w := range ws {
		select {
		case <-w.entered:
		case <-time.After(5 * time.Second):
			// Unblock remaining goroutines so they can exit before aborting.
			for _, w2 := range ws {
				select {
				case <-w2.unblock:
				default:
					close(w2.unblock)
				}
			}
			t.Fatalf("worker %d did not enter Read within 5 s", i)
		}
	}

	// ── Phase 2: 9th tenant-A request denied 503; body NOT read ──────────────────────────

	// Unexpected admission must fail an assertion, not deadlock in a deliberately blocked Read.
	ninthBody := &fairnessObservedBody{}
	rec9, req9 := fairnessReq(tenantA, ninthBody)
	release9, ok9 := bufferTenantBody(rec9, req9)
	if ok9 {
		release9()
		unblockAll()
		t.Fatal("9th tenant-A request was admitted; want 503 (per-tenant limit)")
	}
	if rec9.Code != http.StatusServiceUnavailable {
		t.Errorf("9th tenant-A: code=%d, want 503", rec9.Code)
	}
	// Negative control: the over-limit tenant must not consume any body IO.
	if ninthBody.read {
		t.Error("9th tenant-A body was read despite per-tenant denial")
	}

	// ── Phase 3: tenant B admitted while tenant A is saturated ───────────────────────────

	recB, reqB := fairnessReq(tenantB, io.NopCloser(strings.NewReader(`{}`)))
	releaseB, okB := bufferTenantBody(recB, reqB)
	if !okB {
		unblockAll()
		t.Fatalf("tenant-B denied while tenant-A is saturated: code=%d", recB.Code)
	}
	releaseB()

	// ── Phase 4: unblock all 8 workers and collect results ───────────────────────────────

	unblockAll()

	for i, w := range ws {
		select {
		case err := <-w.done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("worker %d did not complete within 5 s after unblock", i)
		}
	}

	// ── Phase 5: verify no leaked global slots or tenant counters ─────────────────────────

	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak: before=%d after=%d", slotsBefore, got)
	}
	tenantBodyCounts.Lock()
	countA, existsA := tenantBodyCounts.counts[tenantA]
	tenantBodyCounts.Unlock()
	if countA != 0 || existsA {
		t.Errorf("tenant-A count leak: %d, want 0", countA)
	}

	// ── Phase 6: re-admission works after full release ────────────────────────────────────

	recA2, reqA2 := fairnessReq(tenantA, io.NopCloser(strings.NewReader(`{}`)))
	releaseA2, okA2 := bufferTenantBody(recA2, reqA2)
	if !okA2 {
		t.Fatalf("tenant-A denied after full release: code=%d", recA2.Code)
	}
	releaseA2()

	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak after re-admission: before=%d after=%d", slotsBefore, got)
	}
}

// TestBodyAdmissionErrorReleasesSlot proves that both internal failure paths inside
// bufferTenantBody release the global slot and decrement the tenant counter:
//   - A body whose Read returns a plain error  → 400, slot and count freed.
//   - An oversize body                         → 413, slot and count freed.
//
// In both cases admission must succeed again for the same tenant immediately after failure.
//
// What this does NOT prove: the response bodies are already asserted in
// TestOverLimitBodyIsRejectedWithoutBuffering (bodylimit_test.go).
func TestBodyAdmissionErrorReleasesSlot(t *testing.T) {
	const tenantErr = "fe000000-0000-0000-0000-000000000001"
	const tenantBig = "fe000000-0000-0000-0000-000000000002"

	slotsBefore := len(tenantBodySlots)

	// Sub-case 1: plain read error → 400.
	recErr, reqErr := fairnessReq(tenantErr, &alwaysErrBody{err: errors.New("simulated transport fault")})
	releaseErr, okErr := bufferTenantBody(recErr, reqErr)
	if okErr {
		releaseErr()
		t.Fatal("bufferTenantBody returned ok=true on a read error; want false")
	}
	if recErr.Code != http.StatusBadRequest {
		t.Errorf("read error: code=%d, want 400", recErr.Code)
	}

	// Sub-case 2: body exceeds maxSmallJSONBodyBytes on /sessions path → 413.
	bigBody := io.NopCloser(strings.NewReader(strings.Repeat("x", maxSmallJSONBodyBytes+2)))
	recBig, reqBig := fairnessReq(tenantBig, bigBody)
	releaseBig, okBig := bufferTenantBody(recBig, reqBig)
	if okBig {
		releaseBig()
		t.Fatal("bufferTenantBody returned ok=true on an oversize body; want false")
	}
	if recBig.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: code=%d, want 413", recBig.Code)
	}

	// Both global slots must be back.
	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak after errors: before=%d after=%d", slotsBefore, got)
	}

	// Both tenant counters must be zero (key may be absent, which is also correct).
	tenantBodyCounts.Lock()
	cErr, existsErr := tenantBodyCounts.counts[tenantErr]
	cBig, existsBig := tenantBodyCounts.counts[tenantBig]
	tenantBodyCounts.Unlock()
	if cErr != 0 || cBig != 0 || existsErr || existsBig {
		t.Errorf("tenant count leak after errors: err=%d big=%d (want 0, 0)", cErr, cBig)
	}

	// Admission works again for both tenants.
	for _, tid := range []string{tenantErr, tenantBig} {
		rec, req := fairnessReq(tid, io.NopCloser(strings.NewReader(`{}`)))
		release, ok := bufferTenantBody(rec, req)
		if !ok {
			t.Errorf("tenant %s denied after error recovery: code=%d", tid, rec.Code)
			continue
		}
		release()
	}

	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak after recovery: before=%d after=%d", slotsBefore, got)
	}
}

// TestBodyAdmissionGlobalCapacity fills every remaining global slot (synchronously, by
// holding the returned release funcs without calling them), then verifies 503 for any
// additional tenant, and verifies full recovery after release.
//
// Uses four tenant groups of ≤8 to stay under the per-tenant limit while reaching the
// global cap of 32.
//
// What this does NOT prove: concurrent races toward the global cap.
// TestBodyAdmissionTenantFairness covers concurrent in-progress reads.
func TestBodyAdmissionGlobalCapacity(t *testing.T) {
	const globalCap = 32
	const tenantGC = "fc000000-0000-0000-0000-000000000099"

	slotsBefore := len(tenantBodySlots)
	toFill := globalCap - slotsBefore
	if slotsBefore != 0 {
		t.Fatalf("global slots leaked before test start: %d", slotsBefore)
	}

	releases := make([]func(), 0, toFill)
	// Always release on exit so stranded slots do not affect later tests.
	defer func() {
		for _, r := range releases {
			r()
		}
	}()

	// Fill toFill slots; spread across four tenant groups of ≤8 to avoid per-tenant limit.
	for i := 0; i < toFill; i++ {
		tid := fmt.Sprintf("fc-group%d", i/8)
		rec, req := fairnessReq(tid, io.NopCloser(strings.NewReader(`{}`)))
		release, ok := bufferTenantBody(rec, req)
		if !ok {
			t.Fatalf("unexpected denial filling slot %d of %d: code=%d", i+1, toFill, rec.Code)
		}
		releases = append(releases, release)
	}

	// Global capacity exhausted: any tenant must get 503.
	fullBody := &fairnessObservedBody{}
	recFull, reqFull := fairnessReq(tenantGC, fullBody)
	releaseFull, okFull := bufferTenantBody(recFull, reqFull)
	if okFull {
		releaseFull()
		t.Fatal("request admitted when global capacity was exhausted; want 503")
	}
	if recFull.Code != http.StatusServiceUnavailable {
		t.Errorf("global exhausted: code=%d, want 503", recFull.Code)
	}

	if fullBody.read {
		t.Error("globally denied request performed body I/O")
	}

	// Release all held slots explicitly (defer will skip them via the slice truncation below).
	for _, r := range releases {
		r()
	}
	releases = releases[:0] // prevent double-release in defer

	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak after release: before=%d after=%d", slotsBefore, got)
	}

	// Admission works again after recovery.
	recRec, reqRec := fairnessReq(tenantGC, io.NopCloser(strings.NewReader(`{}`)))
	releaseRec, okRec := bufferTenantBody(recRec, reqRec)
	if !okRec {
		t.Fatalf("admission denied after global capacity recovery: code=%d", recRec.Code)
	}
	releaseRec()

	if got := len(tenantBodySlots); got != slotsBefore {
		t.Errorf("global slot leak after recovery: before=%d after=%d", slotsBefore, got)
	}
}
