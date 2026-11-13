package controlplane

// The 'lost' state at the store layer (migration 0077, docs/63 C11): ONE suite, run against the in-memory
// fake and against Postgres (recording_lost_pgstore_test.go), so the two cannot drift.

import (
	"context"
	"errors"
	"testing"
	"time"
)

func runRecordingLostStoreSuite(t *testing.T, mk func(t *testing.T) *recEnv) {
	ctx := context.Background()
	setup := func(t *testing.T) *recEnv {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		e.enable(t, e.tenantB, 30, 1<<30, 20<<30)
		return e
	}
	ready := func(t *testing.T, e *recEnv) *RecordingRow {
		r := e.complete(t, e.tenantA, e.machineA, 100, 200)
		if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}); err != nil {
			t.Fatal(err)
		}
		return r
	}

	t.Run("each blob-promising state can become lost, remembering where from", func(t *testing.T) {
		e := setup(t)
		ec := e.complete(t, e.tenantA, e.machineA, 100)
		pr := ready(t, e)
		pf := e.complete(t, e.tenantA, e.machineA, 100)
		if err := e.store.RecordPlayback(ctx, e.tenantA, pf.ID, PlaybackResult{OK: false, Reason: MuxInvalid}); err != nil {
			t.Fatal(err)
		}
		for id, want := range map[string]string{ec.ID: RecEvidenceComplete, pr.ID: RecPlaybackReady, pf.ID: RecPlaybackFailed} {
			from, err := e.store.MarkLost(ctx, e.tenantA, id)
			if err != nil || from != want {
				t.Fatalf("MarkLost(%s) = %q, %v; want %q", want, from, err, want)
			}
			got, _ := e.store.GetRecording(ctx, e.tenantA, id)
			if got.State != RecLost || got.LostFrom != want || got.LostAt == nil {
				t.Fatalf("row after loss: state=%s from=%q at=%v", got.State, got.LostFrom, got.LostAt)
			}
			// Evidence facts survive untouched: a lost row is still an honest tombstone of what existed.
			if got.Provenance == "" || got.EvidenceCompleteAt == nil || got.ExpiresAt == nil {
				t.Fatalf("a lost row dropped its evidence metadata: %+v", got)
			}
			// Idempotent: a second call leaves it alone and reports the original origin.
			if from2, err := e.store.MarkLost(ctx, e.tenantA, id); err != nil || from2 != want {
				t.Fatalf("second MarkLost = %q, %v", from2, err)
			}
		}
	})

	t.Run("states that promise no blob refuse", func(t *testing.T) {
		e := setup(t)
		up, _ := e.create(t, e.tenantA, e.machineA, 100)
		_, err := e.store.MarkLost(ctx, e.tenantA, up.ID)
		wantErr(t, "uploading -> lost", err, ErrRecordingState)
		ex := e.complete(t, e.tenantA, e.machineA, 100)
		if err := e.store.MarkExpired(ctx, e.tenantA, ex.ID); err != nil {
			t.Fatal(err)
		}
		_, err = e.store.MarkLost(ctx, e.tenantA, ex.ID)
		wantErr(t, "expired -> lost", err, ErrRecordingState)
		_, err = e.store.MarkLost(ctx, e.tenantA, "00000000-0000-0000-0000-000000000000")
		wantErr(t, "unknown id", err, ErrRecordingNotFound)
		_, err = e.store.MarkLost(ctx, e.tenantB, ex.ID)
		wantErr(t, "another tenant", err, ErrRecordingNotFound)
	})

	t.Run("a lost row is never playable, never re-muxed, and shows in the list as lost", func(t *testing.T) {
		e := setup(t)
		r := ready(t, e)
		if _, err := e.store.MarkLost(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "playback publish on a lost row", e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}), ErrRecordingState)
		wantErr(t, "failed publish on a lost row", e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: false, Reason: MuxIO}), ErrRecordingState)
		wantErr(t, "SetPlaybackState", e.store.SetPlaybackState(ctx, e.tenantA, r.ID, RecPlaybackReady), ErrRecordingState)
		items, err := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, it := range items {
			if it.ID == r.ID {
				found = it.State == RecLost
			}
		}
		if !found {
			t.Fatalf("the list does not show the lost row as lost: %+v", items)
		}
		// The session-history link still names it (the console shows it as Lost).
		m, err := e.store.RecordingIDsBySession(ctx, e.tenantA, []string{r.SessionID})
		if err != nil || m[r.SessionID] != r.ID {
			t.Fatalf("RecordingIDsBySession = %v, %v", m, err)
		}
		// Not offered to the muxer: the sweep's pending list holds evidence_complete rows only.
		rows, _ := e.store.SweepList(ctx)
		for _, sr := range rows {
			if sr.ID == r.ID && sr.State != RecLost {
				t.Fatalf("sweep row state = %s", sr.State)
			}
		}
	})

	t.Run("restore goes back to a blob-promising state, only from lost", func(t *testing.T) {
		e := setup(t)
		r := ready(t, e)
		wantErr(t, "restore of a row that is not lost", e.store.RestoreLost(ctx, e.tenantA, r.ID, RecPlaybackReady), ErrRecordingState)
		if _, err := e.store.MarkLost(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "restore to expired", e.store.RestoreLost(ctx, e.tenantA, r.ID, RecExpired), ErrRecordingState)
		wantErr(t, "restore to uploading", e.store.RestoreLost(ctx, e.tenantA, r.ID, RecUploading), ErrRecordingState)
		wantErr(t, "another tenant", e.store.RestoreLost(ctx, e.tenantB, r.ID, RecEvidenceComplete), ErrRecordingNotFound)
		lostRow, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if err := e.store.RestoreLost(ctx, e.tenantA, r.ID, RecPlaybackReady); err != nil {
			t.Fatal(err)
		}
		got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.State != RecPlaybackReady {
			t.Fatalf("state after restore = %s", got.State)
		}
		// The loss history survives the restore (state is the truth; lost_from / lost_at say it was once lost).
		if got.LostFrom != RecPlaybackReady || got.LostAt == nil || lostRow.LostAt == nil || !got.LostAt.Equal(*lostRow.LostAt) {
			t.Fatalf("restore dropped or rewrote the loss history: before %v %v, after %q %v", lostRow.LostFrom, lostRow.LostAt, got.LostFrom, got.LostAt)
		}
		// And it can be lost again (a second restore drill).
		if from, err := e.store.MarkLost(ctx, e.tenantA, r.ID); err != nil || from != RecPlaybackReady {
			t.Fatalf("lost again: %q %v", from, err)
		}
	})

	t.Run("retention: a lost row expires and is deleted like any other, and is classified by the sweeper", func(t *testing.T) {
		e := setup(t)
		r := e.complete(t, e.tenantA, e.machineA, 100)
		if _, err := e.store.MarkLost(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		rows, _ := e.store.SweepList(ctx)
		var sr RecordingSweepRow
		for _, x := range rows {
			if x.ID == r.ID {
				sr = x
			}
		}
		if sr.State != RecLost {
			t.Fatalf("a lost row is missing from the sweep list: %+v", rows)
		}
		if ClassifySweep(sr, time.Now()) != SweepNone {
			t.Fatal("a lost row inside its window must not be swept")
		}
		if ClassifySweep(sr, sr.ExpiresAt.Add(time.Second)) != SweepExpire {
			t.Fatal("a lost row past its deadline must be expired by the sweeper")
		}
		if _, _, err := e.store.ApplyRetention(ctx, e.tenantA, r.ID); err != nil && !errors.Is(err, ErrRecordingState) {
			t.Fatal(err)
		}
		lostRow, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
			t.Fatalf("lost -> expired: %v", err)
		}
		if ex, _ := e.store.GetRecording(ctx, e.tenantA, r.ID); ex.LostFrom != RecEvidenceComplete || ex.LostAt == nil || lostRow.LostAt == nil || !ex.LostAt.Equal(*lostRow.LostAt) {
			t.Fatalf("expiry dropped or rewrote the loss history: %q %v", ex.LostFrom, ex.LostAt)
		}
		wantErr(t, "restore after expiry", e.store.RestoreLost(ctx, e.tenantA, r.ID, RecEvidenceComplete), ErrRecordingState)
		if err := e.store.MarkDeleted(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		got, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if got.State != RecDeleted {
			t.Fatalf("state = %s", got.State)
		}
	})

	t.Run("a lost row keeps its quota reservation until retention frees it", func(t *testing.T) {
		e := mk(t)
		res := RecordingReservation([]int64{100})
		e.enable(t, e.tenantA, 30, 1<<30, res+res/2) // room for one, not two
		r := e.complete(t, e.tenantA, e.machineA, 100)
		if _, err := e.store.MarkLost(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		_, _, err := e.store.CreateRecording(ctx, e.tenantA, e.newRec(e.tenantA, e.machineA, 100), recFree)
		wantErr(t, "create while a lost row holds the quota", err, ErrRecordingQuota)
	})
}

func TestRecordingLostStoreFake(t *testing.T) {
	runRecordingLostStoreSuite(t, func(t *testing.T) *recEnv {
		return &recEnv{
			store:   NewInMemoryRecordingStore(),
			tenantA: newUUIDLike(0xa), tenantB: newUUIDLike(0xb),
			machineA: newUUIDLike(0xc), machineB: newUUIDLike(0xd),
			session: func(string, string) string { return freshID() },
		}
	})
}
