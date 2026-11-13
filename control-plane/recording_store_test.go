package controlplane

// Behaviour of the RecordingStore, run against BOTH backends: TestRecordingStoreFake here, and
// TestRecordingStorePg in recording_pgstore_test.go (it needs TEST_DATABASE_URL and skips without it).
// Fake and pg must agree, so they run the SAME scenarios.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// recEnv is what a scenario needs from a backend. The pg env seeds real tenant / machine / session
// rows (composite FKs); the fake needs none, so its ids are just uuids.
type recEnv struct {
	store    RecordingStore
	tenantA  string
	tenantB  string
	machineA string // a machine of tenantA
	machineB string // a machine of tenantB
	session  func(tenant, machine string) string
}

var recFree = RecordingCreateLimits{FreeBytes: 1 << 40, FreeKnown: true, FloorBytes: 1 << 20}

var uploadCounter atomic.Int64

func newUUIDLike(n int64) string {
	const hexd = "0123456789abcdef"
	b := []byte("00000000-0000-4000-8000-000000000000")
	for i := len(b) - 1; n > 0 && i >= 24; i-- {
		if b[i] == '-' {
			continue
		}
		b[i] = hexd[n&15]
		n >>= 4
	}
	return string(b)
}

func freshID() string { return newUUIDLike(uploadCounter.Add(1) + 1000) }

func (e *recEnv) newRec(tenant, machine string, lens ...int64) NewRecording {
	if len(lens) == 0 {
		lens = []int64{3 * RecChunkSize, 100}
	}
	var fp [32]byte
	fp[0] = 9
	return NewRecording{ID: freshID(), SessionID: e.session(tenant, machine), MachineID: machine, UploadID: freshID(),
		EnrollmentFP: fp, Generation: 1, SegmentLens: lens,
		Key: EnvelopeKey{KeyID: 1, Wrapped: make([]byte, stdWrappedDEKLen)}}
}

func (e *recEnv) enable(t *testing.T, tenant string, days int, max, quota int64) {
	t.Helper()
	if err := e.store.SetPolicy(context.Background(), tenant, RecordingPolicy{RetentionDays: days, MaxRecordingBytes: max, QuotaBytes: quota}); err != nil {
		t.Fatal(err)
	}
}

func (e *recEnv) create(t *testing.T, tenant, machine string, lens ...int64) (*RecordingRow, NewRecording) {
	t.Helper()
	in := e.newRec(tenant, machine, lens...)
	r, created, err := e.store.CreateRecording(context.Background(), tenant, in, recFree)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	return r, in
}

// commitAll fully commits every segment.
func (e *recEnv) commitAll(t *testing.T, tenant string, r *RecordingRow) {
	t.Helper()
	for _, sg := range r.Segments {
		err := e.store.UpdateSegment(context.Background(), tenant, r.ID, sg.Index, func(_ *RecordingRow, cur RecordingSegment) (int64, error) {
			return cur.DeclaredLen, nil
		})
		if err != nil {
			t.Fatalf("commit segment %d: %v", sg.Index, err)
		}
	}
}

func digestsFor(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%064x", i+1)
	}
	return out
}

func completion(r *RecordingRow) EvidenceCompletion {
	return EvidenceCompletion{Digests: digestsFor(len(r.Segments)), Provenance: ProvNoStopEvent}
}

func wantErr(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: err = %v, want %v", what, got, want)
	}
}

func runRecordingStoreSuite(t *testing.T, mk func(t *testing.T) *recEnv) {
	ctx := context.Background()

	t.Run("policy defaults to OFF and is tenant scoped", func(t *testing.T) {
		e := mk(t)
		p, err := e.store.GetPolicy(ctx, e.tenantA)
		if err != nil || p.Enabled() || p.RetentionDays != 0 {
			t.Fatalf("default policy = %+v, %v; storage must be OFF", p, err)
		}
		e.enable(t, e.tenantA, 30, 1<<30, 5<<30)
		if p, _ := e.store.GetPolicy(ctx, e.tenantA); p.RetentionDays != 30 || p.QuotaBytes != 5<<30 {
			t.Fatalf("policy A = %+v", p)
		}
		if p, _ := e.store.GetPolicy(ctx, e.tenantB); p.Enabled() {
			t.Fatalf("tenant B inherited A's policy: %+v", p)
		}
		for _, bad := range []RecordingPolicy{
			{RetentionDays: 366, MaxRecordingBytes: 1, QuotaBytes: 1},
			{RetentionDays: -1, MaxRecordingBytes: 1, QuotaBytes: 1},
			{RetentionDays: 30, MaxRecordingBytes: 0, QuotaBytes: 1},
			{RetentionDays: 30, MaxRecordingBytes: RecHardMaxBytes + 1, QuotaBytes: 1},
			{RetentionDays: 30, MaxRecordingBytes: 1, QuotaBytes: -1},
		} {
			if err := e.store.SetPolicy(ctx, e.tenantA, bad); err == nil {
				t.Errorf("policy %+v accepted", bad)
			}
		}
		if p, _ := e.store.GetPolicy(ctx, e.tenantA); p.RetentionDays != 30 {
			t.Fatalf("a refused policy changed the stored one: %+v", p)
		}
	})

	t.Run("create refused while storage is off, accepted when on, idempotent, immutable", func(t *testing.T) {
		e := mk(t)
		in := e.newRec(e.tenantA, e.machineA)
		_, _, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree)
		wantErr(t, "storage off", err, ErrRecordingStorageOff)

		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		r, created, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree)
		if err != nil || !created || r.State != RecUploading || len(r.Segments) != 2 || r.RetentionDays != 30 {
			t.Fatalf("create: %+v created=%v err=%v", r, created, err)
		}
		if want := RecordingReservation(in.SegmentLens); r.ReservedBytes != want || want <= r.DeclaredBytes*2 {
			t.Fatalf("reservation %d, want %d (must exceed twice the declared %d)", r.ReservedBytes, want, r.DeclaredBytes)
		}
		// Replay: same row, created=false, same upload id (the server's choice is kept).
		in2 := in
		in2.UploadID = freshID()
		in2.Key = EnvelopeKey{KeyID: 2, Wrapped: make([]byte, stdWrappedDEKLen)}
		r2, created, err := e.store.CreateRecording(ctx, e.tenantA, in2, recFree)
		if err != nil || created || r2.UploadID != in.UploadID || r2.KeyID != 1 {
			t.Fatalf("replay: created=%v upload=%s key=%d err=%v", created, r2.UploadID, r2.KeyID, err)
		}
		// Any change to the immutable metadata conflicts.
		for name, mut := range map[string]func(*NewRecording){
			"segment length": func(n *NewRecording) { n.SegmentLens = []int64{3 * RecChunkSize, 101} },
			"segment count":  func(n *NewRecording) { n.SegmentLens = []int64{3 * RecChunkSize} },
			"generation":     func(n *NewRecording) { n.Generation = 2 },
			"session":        func(n *NewRecording) { n.SessionID = freshID() },
			"enrollment fp":  func(n *NewRecording) { n.EnrollmentFP[0] ^= 1 },
		} {
			c := in
			mut(&c)
			_, _, err := e.store.CreateRecording(ctx, e.tenantA, c, recFree)
			if !errors.Is(err, ErrRecordingConflict) {
				t.Errorf("%s change: err = %v, want conflict", name, err)
			}
		}
		// Idempotent replay is still allowed after storage is turned off for the tenant.
		e.enable(t, e.tenantA, 0, 1<<30, 20<<30)
		if _, created, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree); err != nil || created {
			t.Fatalf("replay after storage off: created=%v err=%v", created, err)
		}
		// ... but a NEW recording is refused.
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA), recFree)
		wantErr(t, "new create after storage off", err, ErrRecordingStorageOff)
	})

	t.Run("per-recording cap and tenant quota are enforced from reservations", func(t *testing.T) {
		e := mk(t)
		one := RecordingReservation([]int64{4 * RecChunkSize})
		e.enable(t, e.tenantA, 30, 4*RecChunkSize, one*2+one/2)
		_, _, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 4*RecChunkSize+1), recFree)
		wantErr(t, "over the per-recording cap", err, ErrRecordingTooLarge)

		r1, _ := e.create(t, e.tenantA, e.machineA, 4*RecChunkSize)
		r2, _ := e.create(t, e.tenantA, e.machineA, 4*RecChunkSize)
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 4*RecChunkSize), recFree)
		wantErr(t, "third recording over quota", err, ErrRecordingQuota)
		// Another tenant's usage does not count against A, and A's does not count against B.
		e.enable(t, e.tenantB, 30, 4*RecChunkSize, one+1)
		e.create(t, e.tenantB, e.machineB, 4*RecChunkSize)
		// Abandoning releases the reservation: the third now fits.
		if err := e.store.AbandonRecording(ctx, e.tenantA, r1.ID); err != nil {
			t.Fatal(err)
		}
		if _, created, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 4*RecChunkSize), recFree); err != nil || !created {
			t.Fatalf("create after abandon: %v %v", created, err)
		}
		// Refusing releases too (r2 -> refused frees its share for another).
		if err := e.store.RefuseRecording(ctx, e.tenantA, r2.ID); err != nil {
			t.Fatal(err)
		}
		if _, created, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 4*RecChunkSize), recFree); err != nil || !created {
			t.Fatalf("create after refuse: %v %v", created, err)
		}
	})

	t.Run("disk floor is measured against reservations and fails closed", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 100<<30)
		res := RecordingReservation([]int64{2 * RecChunkSize})
		floor := uint64(10 << 20)
		lim := func(free uint64) RecordingCreateLimits {
			return RecordingCreateLimits{FreeBytes: free, FreeKnown: true, FloorBytes: floor}
		}
		_, _, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 2*RecChunkSize), lim(uint64(res)+floor-1))
		wantErr(t, "one byte under reservation+floor", err, ErrRecordingServerFull)
		in := e.newRec(e.tenantA, e.machineA, 2*RecChunkSize)
		if _, created, err := e.store.CreateRecording(ctx, e.tenantA, in, lim(uint64(res)+floor)); err != nil || !created {
			t.Fatalf("exactly reservation+floor free: %v %v", created, err)
		}
		// A live upload's UNWRITTEN reservation counts against the floor for the next create...
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 2*RecChunkSize), lim(uint64(res)+floor))
		wantErr(t, "second create with the first still unwritten", err, ErrRecordingServerFull)
		// ...but bytes that are WRITTEN stop counting (free space already reflects them): once the first
		// upload's evidence is committed only its not-yet-written playback share is still promised.
		r, _ := e.store.GetRecording(ctx, e.tenantA, in.ID)
		e.commitAll(t, e.tenantA, r)
		need := uint64(res-2*RecChunkSize) + uint64(res) + floor
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 2*RecChunkSize), lim(need-1))
		wantErr(t, "one byte under the remaining promise", err, ErrRecordingServerFull)
		if _, created, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 2*RecChunkSize), lim(need)); err != nil || !created {
			t.Fatalf("exactly enough once the first upload's bytes are written: %v %v", created, err)
		}
		// Unmeasurable volume: refuse.
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 2*RecChunkSize),
			RecordingCreateLimits{FreeBytes: 1 << 40, FreeKnown: false, FloorBytes: floor})
		wantErr(t, "unknown free space", err, ErrRecordingServerFull)
	})

	t.Run("segment commits are monotonic and serialised", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		r, _ := e.create(t, e.tenantA, e.machineA, 3*RecChunkSize)
		step := func(from, to int64) error {
			return e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(_ *RecordingRow, cur RecordingSegment) (int64, error) {
				if cur.CommittedOffset != from {
					return 0, ErrRecordingConflict
				}
				return to, nil
			})
		}
		if err := step(0, RecChunkSize); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "stale offset seen by the callback", step(0, RecChunkSize), ErrRecordingConflict)
		if err := e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(_ *RecordingRow, cur RecordingSegment) (int64, error) {
			return cur.CommittedOffset, nil // a no-change commit (an exact re-send)
		}); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "regress", e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 5, nil }), ErrRecordingOffset)
		wantErr(t, "beyond declared", e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 3*RecChunkSize + 1, nil }), ErrRecordingOffset)
		boom := errors.New("disk write failed")
		wantErr(t, "callback error", e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 2 * RecChunkSize, boom }), boom)
		got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.Segments[0].CommittedOffset != RecChunkSize {
			t.Fatalf("a failed commit moved the offset to %d", got.Segments[0].CommittedOffset)
		}
		wantErr(t, "no such segment", e.store.UpdateSegment(ctx, e.tenantA, r.ID, 7, func(*RecordingRow, RecordingSegment) (int64, error) { return 0, nil }), ErrRecordingNotFound)
		wantErr(t, "no such recording", e.store.UpdateSegment(ctx, e.tenantA, freshID(), 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 0, nil }), ErrRecordingNotFound)

		// Concurrent commits at the same offset: exactly one wins.
		r2, _ := e.create(t, e.tenantA, e.machineA, 3*RecChunkSize)
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := e.store.UpdateSegment(ctx, e.tenantA, r2.ID, 0, func(_ *RecordingRow, cur RecordingSegment) (int64, error) {
					if cur.CommittedOffset != 0 {
						return 0, ErrRecordingConflict
					}
					time.Sleep(5 * time.Millisecond) // hold the lock so the others queue behind it
					return RecChunkSize, nil
				})
				if err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("%d concurrent commits at offset 0 succeeded, want exactly 1", wins.Load())
		}
	})

	t.Run("evidence completion needs every byte, anchors retention at server time, is single-shot", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		r, in := e.create(t, e.tenantA, e.machineA)
		_, err := e.store.CompleteEvidence(ctx, e.tenantA, r.ID, completion(r))
		wantErr(t, "complete with nothing committed", err, ErrRecordingState)
		e.commitAll(t, e.tenantA, r)
		bad := completion(r)
		bad.Digests = bad.Digests[:1]
		_, err = e.store.CompleteEvidence(ctx, e.tenantA, r.ID, bad)
		wantErr(t, "wrong digest count", err, ErrRecordingState)

		before := time.Now().Add(-2 * time.Second)
		trunc := "size_limit"
		var dropped, frames int64 = 3, 913
		var seq int64 = 5
		c := completion(r)
		c.Provenance, c.MatchedAuditSeq, c.Truncated, c.DroppedFrames, c.Frames = ProvMatchesAudit, &seq, &trunc, &dropped, &frames
		done, err := e.store.CompleteEvidence(ctx, e.tenantA, r.ID, c)
		if err != nil {
			t.Fatal(err)
		}
		after := time.Now().Add(2 * time.Second)
		if done.State != RecEvidenceComplete || done.Provenance != ProvMatchesAudit || *done.MatchedAuditSeq != 5 ||
			*done.Truncated != "size_limit" || *done.DroppedFrames != 3 || *done.Frames != 913 {
			t.Fatalf("completed row = %+v", done)
		}
		if done.EvidenceCompleteAt == nil || done.EvidenceCompleteAt.Before(before) || done.EvidenceCompleteAt.After(after) {
			t.Fatalf("evidence_complete_at %v is not server 'now'", done.EvidenceCompleteAt)
		}
		if want := done.EvidenceCompleteAt.Add(30 * 24 * time.Hour); !done.ExpiresAt.Equal(want) {
			t.Fatalf("expires_at %v, want evidence_complete_at + 30d = %v", done.ExpiresAt, want)
		}
		for i, sg := range done.Segments {
			if sg.SHA256 != digestsFor(2)[i] {
				t.Fatalf("segment %d digest not stored", i)
			}
		}
		_, err = e.store.CompleteEvidence(ctx, e.tenantA, r.ID, c)
		wantErr(t, "second completion", err, ErrRecordingState)
		wantErr(t, "commit after completion", e.store.UpdateSegment(ctx, e.tenantA, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 0, nil }), ErrRecordingState)
		// A completed recording's identical create is "already complete" (409), a different one conflicts.
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, in, recFree)
		wantErr(t, "create of a completed recording", err, ErrRecordingAlreadyComplete)
		c2 := in
		c2.Generation = 5
		_, _, err = e.store.CreateRecording(ctx, e.tenantA, c2, recFree)
		wantErr(t, "conflicting create of a completed recording", err, ErrRecordingConflict)

		// Retention is anchored at completion and shortened — never lengthened — by a later policy.
		r3, _ := e.create(t, e.tenantA, e.machineA, 100)
		e.commitAll(t, e.tenantA, r3)
		e.enable(t, e.tenantA, 7, 1<<30, 20<<30) // shortened before finish
		d3, err := e.store.CompleteEvidence(ctx, e.tenantA, r3.ID, completion(r3))
		if err != nil {
			t.Fatal(err)
		}
		if want := d3.EvidenceCompleteAt.Add(7 * 24 * time.Hour); !d3.ExpiresAt.Equal(want) {
			t.Fatalf("shortened policy: expires %v want %v", d3.ExpiresAt, want)
		}
		r4, _ := e.create(t, e.tenantA, e.machineA, 100) // snapshot 7 days
		e.commitAll(t, e.tenantA, r4)
		e.enable(t, e.tenantA, 365, 1<<30, 20<<30) // lengthened before finish: must NOT extend
		d4, _ := e.store.CompleteEvidence(ctx, e.tenantA, r4.ID, completion(r4))
		if want := d4.EvidenceCompleteAt.Add(7 * 24 * time.Hour); !d4.ExpiresAt.Equal(want) {
			t.Fatalf("lengthened policy extended retention: expires %v want %v", d4.ExpiresAt, want)
		}
		r5, _ := e.create(t, e.tenantA, e.machineA, 100) // snapshot 365
		e.commitAll(t, e.tenantA, r5)
		e.enable(t, e.tenantA, 0, 1<<30, 20<<30) // turned OFF before finish: keeps its snapshot schedule
		d5, _ := e.store.CompleteEvidence(ctx, e.tenantA, r5.ID, completion(r5))
		if want := d5.EvidenceCompleteAt.Add(365 * 24 * time.Hour); !d5.ExpiresAt.Equal(want) {
			t.Fatalf("storage turned off: expires %v want %v", d5.ExpiresAt, want)
		}
	})

	t.Run("terminal states are tombstones: a recording id is never resurrected", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		mkTomb := func(finish func(r *RecordingRow)) NewRecording {
			r, in := e.create(t, e.tenantA, e.machineA, 100)
			finish(r)
			return in
		}
		cases := map[string]NewRecording{
			"abandoned": mkTomb(func(r *RecordingRow) { _ = e.store.AbandonRecording(ctx, e.tenantA, r.ID) }),
			"refused":   mkTomb(func(r *RecordingRow) { _ = e.store.RefuseRecording(ctx, e.tenantA, r.ID) }),
			"expired": mkTomb(func(r *RecordingRow) {
				e.commitAll(t, e.tenantA, r)
				if _, err := e.store.CompleteEvidence(ctx, e.tenantA, r.ID, completion(r)); err != nil {
					t.Fatal(err)
				}
				if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
					t.Fatal(err)
				}
			}),
			"deleted": mkTomb(func(r *RecordingRow) {
				e.commitAll(t, e.tenantA, r)
				e.store.CompleteEvidence(ctx, e.tenantA, r.ID, completion(r))
				e.store.MarkExpired(ctx, e.tenantA, r.ID)
				if err := e.store.MarkDeleted(ctx, e.tenantA, r.ID); err != nil {
					t.Fatal(err)
				}
			}),
		}
		for name, in := range cases {
			_, _, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree)
			if !errors.Is(err, ErrRecordingTombstoned) {
				t.Errorf("%s: create err = %v, want tombstoned (410)", name, err)
			}
			// ...even with different metadata, and even after storage is turned off.
			c := in
			c.Generation = 99
			if _, _, err := e.store.CreateRecording(ctx, e.tenantA, c, recFree); !errors.Is(err, ErrRecordingTombstoned) {
				t.Errorf("%s: changed create err = %v, want tombstoned", name, err)
			}
			if _, err := e.store.GetRecording(ctx, e.tenantA, in.ID); err != nil {
				t.Errorf("%s: the tombstone row is gone: %v", name, err)
			}
			wantErr(t, name+" commit", e.store.UpdateSegment(ctx, e.tenantA, in.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 0, nil }), ErrRecordingState)
			wantErr(t, name+" abandon", e.store.AbandonRecording(ctx, e.tenantA, in.ID), ErrRecordingState)
		}
	})

	t.Run("retention steps are ordered and idempotent", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		r, _ := e.create(t, e.tenantA, e.machineA, 100)
		wantErr(t, "expire an uploading recording", e.store.MarkExpired(ctx, e.tenantA, r.ID), ErrRecordingState)
		e.commitAll(t, e.tenantA, r)
		if _, err := e.store.CompleteEvidence(ctx, e.tenantA, r.ID, completion(r)); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "delete before expire", e.store.MarkDeleted(ctx, e.tenantA, r.ID), ErrRecordingState)
		if err := e.store.SetPlaybackState(ctx, e.tenantA, r.ID, RecPlaybackFailed); err != nil {
			t.Fatal(err)
		}
		if err := e.store.SetPlaybackState(ctx, e.tenantA, r.ID, RecPlaybackReady); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "invalid playback state", e.store.SetPlaybackState(ctx, e.tenantA, r.ID, RecDeleted), ErrRecordingState)
		for i := 0; i < 2; i++ { // idempotent
			if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
				t.Fatalf("MarkExpired #%d: %v", i, err)
			}
		}
		got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.State != RecExpired || got.ExpiredAt == nil {
			t.Fatalf("after expiry: %+v", got)
		}
		for i := 0; i < 2; i++ {
			if err := e.store.MarkDeleted(ctx, e.tenantA, r.ID); err != nil {
				t.Fatalf("MarkDeleted #%d: %v", i, err)
			}
		}
		if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
			t.Fatalf("MarkExpired on a deleted row must be a no-op: %v", err)
		}
		got, _ = e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.State != RecDeleted || got.DeletedAt == nil {
			t.Fatalf("after deletion: %+v", got)
		}
		// A deleted recording no longer holds quota.
		wantErr(t, "unknown recording", e.store.MarkExpired(ctx, e.tenantA, freshID()), ErrRecordingNotFound)
	})

	t.Run("finish failures reset the segment and refuse after the third", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		r, in := e.create(t, e.tenantA, e.machineA)
		e.commitAll(t, e.tenantA, r)
		for i := 1; i <= RecMaxFinishFailures; i++ {
			st, err := e.store.RecordFinishFailure(ctx, e.tenantA, r.ID, []int{1})
			if err != nil {
				t.Fatalf("failure %d: %v", i, err)
			}
			want := RecUploading
			if i == RecMaxFinishFailures {
				want = RecRefused
			}
			if st != want {
				t.Fatalf("failure %d: state %s, want %s", i, st, want)
			}
			got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
			if i < RecMaxFinishFailures {
				if got.Segments[1].CommittedOffset != 0 || got.Segments[0].CommittedOffset != got.Segments[0].DeclaredLen {
					t.Fatalf("failure %d did not reset exactly segment 1: %+v", i, got.Segments)
				}
				// the agent re-sends segment 1
				e.commitAll(t, e.tenantA, got)
			}
		}
		_, _, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree)
		wantErr(t, "create after refusal", err, ErrRecordingTombstoned)
		_, err = e.store.RecordFinishFailure(ctx, e.tenantA, r.ID, nil)
		wantErr(t, "failure on a refused recording", err, ErrRecordingState)
	})

	t.Run("recordings are tenant scoped", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		e.enable(t, e.tenantB, 30, 1<<30, 20<<30)
		r, _ := e.create(t, e.tenantA, e.machineA, 100)
		if _, err := e.store.GetRecording(ctx, e.tenantB, r.ID); !errors.Is(err, ErrRecordingNotFound) {
			t.Fatalf("tenant B read tenant A's recording: %v", err)
		}
		wantErr(t, "B commits A's segment", e.store.UpdateSegment(ctx, e.tenantB, r.ID, 0, func(*RecordingRow, RecordingSegment) (int64, error) { return 1, nil }), ErrRecordingNotFound)
		wantErr(t, "B abandons A's recording", e.store.AbandonRecording(ctx, e.tenantB, r.ID), ErrRecordingNotFound)
		got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.State != RecUploading || got.Segments[0].CommittedOffset != 0 {
			t.Fatalf("tenant B changed tenant A's recording: %+v", got)
		}
		wantErr(t, "malformed id", func() error { _, err := e.store.GetRecording(ctx, e.tenantA, "not-a-uuid"); return err }(), ErrRecordingNotFound)
	})

	t.Run("sweep list is cross-tenant, non-terminal only, and carries current retention", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		e.enable(t, e.tenantB, 90, 1<<30, 20<<30)
		ra, _ := e.create(t, e.tenantA, e.machineA, 100)
		rb, _ := e.create(t, e.tenantB, e.machineB, 100)
		gone, _ := e.create(t, e.tenantA, e.machineA, 100)
		e.store.AbandonRecording(ctx, e.tenantA, gone.ID)
		rows, err := e.store.SweepList(ctx)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]RecordingSweepRow{}
		for _, r := range rows {
			seen[r.ID] = r
		}
		if len(seen) < 2 || seen[ra.ID].TenantID != e.tenantA || seen[rb.ID].TenantID != e.tenantB {
			t.Fatalf("sweep list missing live rows: %+v", rows)
		}
		if _, ok := seen[gone.ID]; ok {
			t.Fatal("a terminal (abandoned) row is in the sweep list")
		}
		if seen[ra.ID].PolicyRetentionDays != 30 || seen[rb.ID].PolicyRetentionDays != 90 || seen[ra.ID].UploadID != ra.UploadID {
			t.Fatalf("sweep rows = %+v", seen)
		}
	})
}

func TestRecordingStoreFake(t *testing.T) {
	runRecordingStoreSuite(t, func(t *testing.T) *recEnv {
		return &recEnv{
			store:   NewInMemoryRecordingStore(),
			tenantA: newUUIDLike(0xa), tenantB: newUUIDLike(0xb),
			machineA: newUUIDLike(0xc), machineB: newUUIDLike(0xd),
			session: func(string, string) string { return freshID() },
		}
	})
}

// ---- pure rules --------------------------------------------------------------------------------

func TestClassifySweepAndEffectiveExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	day := 24 * time.Hour
	ec, exp := now.Add(-10*day), now.Add(20*day)
	row := func(state string, pol int) RecordingSweepRow {
		return RecordingSweepRow{State: state, CreatedAt: now.Add(-time.Hour), EvidenceCompleteAt: &ec, ExpiresAt: &exp, PolicyRetentionDays: pol}
	}
	cases := []struct {
		name string
		r    RecordingSweepRow
		want SweepAction
	}{
		{"fresh upload", RecordingSweepRow{State: RecUploading, CreatedAt: now.Add(-time.Hour)}, SweepNone},
		{"upload at the lifetime bound", RecordingSweepRow{State: RecUploading, CreatedAt: now.Add(-RecMaxUploadLifetime)}, SweepAbandon},
		{"upload just under the bound", RecordingSweepRow{State: RecUploading, CreatedAt: now.Add(-RecMaxUploadLifetime + time.Second)}, SweepNone},
		{"within its own schedule", row(RecPlaybackReady, 0), SweepNone},
		{"policy off keeps the stored schedule", row(RecEvidenceComplete, 0), SweepNone},
		{"longer policy never extends", row(RecEvidenceComplete, 365), SweepNone},
		{"policy shortened below the age: expires on the next sweep", row(RecEvidenceComplete, 5), SweepExpire},
		{"policy shortened but not yet reached", row(RecPlaybackFailed, 15), SweepNone},
		{"policy exactly at the age", row(RecPlaybackReady, 10), SweepExpire},
		{"already expired: deletion owed", row(RecExpired, 0), SweepDeleteNow},
		{"stored schedule reached", func() RecordingSweepRow {
			r := row(RecPlaybackReady, 0)
			e := now.Add(-time.Second)
			r.ExpiresAt = &e
			return r
		}(), SweepExpire},
	}
	for _, c := range cases {
		if got := ClassifySweep(c.r, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestRecordingReservationCoversBothCopies(t *testing.T) {
	n := int64(10 * RecChunkSize)
	r := RecordingReservation([]int64{n})
	// evidence copy + 1.1x playback copy + per-frame tags + two headers.
	min := n + n*11/10
	if r < min+2*(n/EnvFrameSize)*envTagSize {
		t.Fatalf("reservation %d does not cover both copies and the AEAD overhead (min %d)", r, min)
	}
	if RecordingReservation([]int64{n, n}) != 2*r {
		t.Fatal("reservation is not additive over segments")
	}
}

func TestDecodeRecordingPolicyPutIsFailClosed(t *testing.T) {
	ok := `{"retention_days":30,"max_recording_bytes":1073741824,"quota_bytes":1000}`
	p, err := DecodeRecordingPolicyPut([]byte(ok))
	if err != nil || p.RetentionDays != 30 {
		t.Fatalf("good body: %+v %v", p, err)
	}
	if p, err := DecodeRecordingPolicyPut([]byte(`{"retention_days":0,"max_recording_bytes":10,"quota_bytes":0}`)); err != nil || p.Enabled() {
		t.Fatalf("explicit off: %+v %v", p, err)
	}
	for name, body := range map[string]string{
		"stale client without retention_days": `{"max_recording_bytes":1073741824,"quota_bytes":1000}`,
		"retention only":                      `{"retention_days":30}`,
		"null retention":                      `{"retention_days":null,"max_recording_bytes":10,"quota_bytes":1}`,
		"missing quota":                       `{"retention_days":30,"max_recording_bytes":10}`,
		"an old-style field":                  `{"retention":30,"max_recording_bytes":10,"quota_bytes":1}`,
		"unknown extra field":                 `{"retention_days":30,"max_recording_bytes":10,"quota_bytes":1,"enabled":true}`,
		"empty object":                        `{}`,
		"not json":                            `retention_days=30`,
		"trailing data":                       ok + `{}`,
		"string number":                       `{"retention_days":"30","max_recording_bytes":10,"quota_bytes":1}`,
		"fractional":                          `{"retention_days":30.5,"max_recording_bytes":10,"quota_bytes":1}`,
		"out of range":                        `{"retention_days":400,"max_recording_bytes":10,"quota_bytes":1}`,
		"negative cap":                        `{"retention_days":30,"max_recording_bytes":-1,"quota_bytes":1}`,
	} {
		if p, err := DecodeRecordingPolicyPut([]byte(body)); err == nil {
			t.Errorf("%s accepted as %+v", name, p)
		}
	}
}
