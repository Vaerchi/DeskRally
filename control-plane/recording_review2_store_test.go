package controlplane

// Codex implementation review r2, parts A/B at the store layer. Run against BOTH backends (fake here,
// pg in the TestRecordingReview2StorePg wrapper), so fake and pg agree on: the per-recording lock (A1),
// the persisted shortened retention (B2) and the playback dimension ceiling (B3). B1's arithmetic is
// store-independent.

import (
	"context"
	"testing"
	"time"
)

func runRecordingReview2StoreSuite(t *testing.T, mk func(t *testing.T) *recEnv) {
	ctx := context.Background()

	t.Run("LockRecording is exclusive per recording, honours ctx and releases", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		a, _ := e.create(t, e.tenantA, e.machineA)
		b, _ := e.create(t, e.tenantA, e.machineA)
		unlockA, err := e.store.LockRecording(ctx, e.tenantA, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		defer unlockA() // idempotent; a failed assertion must not leave a pooled connection held
		// Another recording is independent.
		unlockB, err := e.store.LockRecording(ctx, e.tenantA, b.ID)
		if err != nil {
			t.Fatalf("lock of a DIFFERENT recording was blocked: %v", err)
		}
		unlockB()
		// The same recording is not available while held, and the wait ends with the context.
		wctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
		start := time.Now()
		if u, err := e.store.LockRecording(wctx, e.tenantA, a.ID); err == nil {
			u()
			cancel()
			t.Fatal("a second holder got the lock while it was held")
		}
		cancel()
		if time.Since(start) < 200*time.Millisecond {
			t.Fatal("the second lock attempt returned before its deadline")
		}
		// A waiter gets the lock the moment it is released.
		got := make(chan func(), 1)
		go func() {
			u, err := e.store.LockRecording(ctx, e.tenantA, a.ID)
			if err != nil {
				t.Error(err)
				got <- func() {}
				return
			}
			got <- u
		}()
		select {
		case <-got:
			t.Fatal("waiter acquired before release")
		case <-time.After(150 * time.Millisecond):
		}
		unlockA()
		unlockA() // idempotent
		select {
		case u := <-got:
			u()
		case <-time.After(5 * time.Second):
			t.Fatal("waiter never acquired after release")
		}
		// And it can be taken again afterwards (nothing leaked).
		u, err := e.store.LockRecording(ctx, e.tenantA, a.ID)
		if err != nil {
			t.Fatalf("re-lock after release: %v", err)
		}
		u()
	})

	t.Run("a shortened retention is persisted and survives lengthening or switching storage off", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		up, _ := e.create(t, e.tenantA, e.machineA) // still uploading: has no schedule
		r := e.complete(t, e.tenantA, e.machineA)
		stored30 := *r.ExpiresAt
		if want := r.EvidenceCompleteAt.Add(30 * 24 * time.Hour); !stored30.Equal(want) {
			t.Fatalf("expires_at %v, want %v", stored30, want)
		}
		// No change while the policy is not shorter.
		if exp, changed, err := e.store.ApplyRetention(ctx, e.tenantA, r.ID); err != nil || changed || !exp.Equal(stored30) {
			t.Fatalf("apply with an equal policy: %v %v %v", exp, changed, err)
		}
		// Shorten to 5 days: persisted.
		e.enable(t, e.tenantA, 5, 1<<30, 20<<30)
		want5 := r.EvidenceCompleteAt.Add(5 * 24 * time.Hour)
		exp, changed, err := e.store.ApplyRetention(ctx, e.tenantA, r.ID)
		if err != nil || !changed || !exp.Equal(want5) {
			t.Fatalf("apply after shortening: %v %v %v, want %v", exp, changed, err, want5)
		}
		cur, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if !cur.ExpiresAt.Equal(want5) {
			t.Fatalf("stored expires_at %v, want the shortened %v", cur.ExpiresAt, want5)
		}
		// Lengthen to 90: the durable deadline does NOT come back.
		e.enable(t, e.tenantA, 90, 1<<30, 20<<30)
		if exp, changed, err := e.store.ApplyRetention(ctx, e.tenantA, r.ID); err != nil || changed || !exp.Equal(want5) {
			t.Fatalf("apply after lengthening: %v %v %v, want %v unchanged", exp, changed, err, want5)
		}
		// Storage off (0): same.
		e.enable(t, e.tenantA, 0, 1<<30, 20<<30)
		if exp, changed, err := e.store.ApplyRetention(ctx, e.tenantA, r.ID); err != nil || changed || !exp.Equal(want5) {
			t.Fatalf("apply with storage off: %v %v %v", exp, changed, err)
		}
		if cur, _ := e.store.GetRecording(ctx, e.tenantA, r.ID); !cur.ExpiresAt.Equal(want5) {
			t.Fatalf("expires_at drifted back to %v", cur.ExpiresAt)
		}
		// The cross-tenant sweep list and the list API report the durable value.
		rows, err := e.store.SweepList(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, sr := range rows {
			if sr.ID == r.ID && !sr.ExpiresAt.Equal(want5) {
				t.Fatalf("sweep list expires_at %v", sr.ExpiresAt)
			}
		}
		// Only completed recordings have a schedule to move; another tenant cannot touch it.
		wantErr(t, "an uploading recording", func() error { _, _, err := e.store.ApplyRetention(ctx, e.tenantA, up.ID); return err }(), ErrRecordingState)
		wantErr(t, "cross-tenant", func() error { _, _, err := e.store.ApplyRetention(ctx, e.tenantB, r.ID); return err }(), ErrRecordingNotFound)
	})

	t.Run("playback dimensions above the muxer ceiling are refused identically", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		for name, mut := range map[string]func(*PlaybackSegment){
			"width 8193":  func(p *PlaybackSegment) { p.Width = 8193 },
			"height 8193": func(p *PlaybackSegment) { p.Height = 8193 },
			"width 9000":  func(p *PlaybackSegment) { p.Width = 9000 },
		} {
			r := e.complete(t, e.tenantA, e.machineA)
			segs := playbackSegs(2)
			mut(&segs[1])
			wantErr(t, name, e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: segs}), ErrRecordingState)
			if cur, _ := e.store.GetRecording(ctx, e.tenantA, r.ID); cur.State != RecEvidenceComplete || cur.Segments[1].Playback != nil {
				t.Fatalf("%s: a refused outcome changed the row: %+v", name, cur)
			}
		}
		r := e.complete(t, e.tenantA, e.machineA)
		segs := playbackSegs(2)
		segs[0].Width, segs[0].Height = 8192, 8192
		if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: segs}); err != nil {
			t.Fatalf("8192 x 8192 is the ceiling and must be accepted: %v", err)
		}
	})
}

func TestRecordingReview2StoreFake(t *testing.T) {
	runRecordingReview2StoreSuite(t, func(t *testing.T) *recEnv {
		return &recEnv{
			store:   NewInMemoryRecordingStore(),
			tenantA: newUUIDLike(0xa), tenantB: newUUIDLike(0xb),
			machineA: newUUIDLike(0xc), machineB: newUUIDLike(0xd),
			session: func(string, string) string { return freshID() },
		}
	})
}

func TestRecordingReview2StorePg(t *testing.T) {
	runRecordingReview2StoreSuite(t, func(t *testing.T) *recEnv {
		h := newPgRecHarness(t)
		return &recEnv{store: h.store, tenantA: h.tenantA, tenantB: h.tenantB, machineA: h.machineA, machineB: h.machineB,
			session: h.sessionOf}
	})
}

// ---- B1: the reservation covers the largest playback copy the muxer may write ------------------

func TestRecordingReservationCoversTheMuxersMaximumOutput(t *testing.T) {
	for _, n := range []int64{1, 100, 4096, EnvFrameSize, 10*RecChunkSize + 7, RecHardMaxBytes} {
		maxPlain := n*muxOutNum/muxOutDen + muxOutSlack // PlanWebM refuses anything above this
		need := recDiskBound(n) + recDiskBound(maxPlain)
		if got := RecordingReservation([]int64{n}); got < need {
			t.Errorf("segment of %d bytes: reservation %d is below the evidence copy plus the largest permitted playback copy (%d)", n, got, need)
		}
	}
}
