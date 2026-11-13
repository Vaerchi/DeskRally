package controlplane

// Store behaviour added in R1b (docs/63 C7, D6): the muxer's outcome (RecordPlayback) and the list. Like
// the R1a suite these run against BOTH backends: TestRecordingPlaybackStoreFake here and
// TestRecordingPlaybackStorePg in recording_pgstore_test.go (needs TEST_DATABASE_URL).

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"
)

func (e *recEnv) complete(t *testing.T, tenant, machine string, lens ...int64) *RecordingRow {
	t.Helper()
	r, _ := e.create(t, tenant, machine, lens...)
	e.commitAll(t, tenant, r)
	done, err := e.store.CompleteEvidence(context.Background(), tenant, r.ID, completion(r))
	if err != nil {
		t.Fatalf("complete evidence: %v", err)
	}
	return done
}

func playbackSegs(n int) []PlaybackSegment {
	out := make([]PlaybackSegment, n)
	for i := range out {
		out[i] = PlaybackSegment{Index: i, WebMLen: 1000 + int64(i), Width: 640 + i, Height: 480, StartMs: int64(i) * 5000, DurationMs: 4000, Frames: 120}
	}
	return out
}

// evidenceFieldsEqual compares everything R1a established at evidence_complete: a playback outcome must
// never move any of it.
func evidenceFieldsEqual(a, b *RecordingRow) bool {
	if a.Provenance != b.Provenance || !a.EvidenceCompleteAt.Equal(*b.EvidenceCompleteAt) || !a.ExpiresAt.Equal(*b.ExpiresAt) ||
		len(a.Segments) != len(b.Segments) {
		return false
	}
	for i := range a.Segments {
		if a.Segments[i].SHA256 != b.Segments[i].SHA256 || a.Segments[i].CommittedOffset != b.Segments[i].CommittedOffset ||
			a.Segments[i].DeclaredLen != b.Segments[i].DeclaredLen {
			return false
		}
	}
	return true
}

func runRecordingPlaybackStoreSuite(t *testing.T, mk func(t *testing.T) *recEnv) {
	ctx := context.Background()

	t.Run("playback outcome: ready, failed, retry, and what is refused", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
		up, _ := e.create(t, e.tenantA, e.machineA)
		wantErr(t, "an uploading recording has no playback outcome",
			e.store.RecordPlayback(ctx, e.tenantA, up.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}), ErrRecordingState)

		r := e.complete(t, e.tenantA, e.machineA)
		before, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if before.State != RecEvidenceComplete || before.Segments[0].Playback != nil || before.PlaybackError != "" {
			t.Fatalf("fresh completed row: %+v", before)
		}

		// Malformed outcomes are refused and change nothing.
		for name, res := range map[string]PlaybackResult{
			"wrong segment count":  {OK: true, Segments: playbackSegs(1)},
			"no segments":          {OK: true},
			"index out of order":   {OK: true, Segments: []PlaybackSegment{playbackSegs(2)[1], playbackSegs(2)[0]}},
			"zero width":           {OK: true, Segments: []PlaybackSegment{{Index: 0, WebMLen: 5, Width: 0, Height: 1, Frames: 1}, playbackSegs(2)[1]}},
			"zero length":          {OK: true, Segments: []PlaybackSegment{{Index: 0, WebMLen: 0, Width: 1, Height: 1, Frames: 1}, playbackSegs(2)[1]}},
			"free-text reason":     {OK: false, Reason: "bad frame at /srv/x <script>"},
			"empty failure reason": {OK: false},
		} {
			if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, res); !errors.Is(err, ErrRecordingState) {
				t.Errorf("%s: err = %v, want ErrRecordingState", name, err)
			}
		}
		if cur, _ := e.store.GetRecording(ctx, e.tenantA, r.ID); cur.State != RecEvidenceComplete || cur.Segments[1].Playback != nil {
			t.Fatalf("a refused outcome changed the row: %+v", cur)
		}
		// Another tenant cannot record an outcome on it.
		wantErr(t, "cross-tenant outcome",
			e.store.RecordPlayback(ctx, e.tenantB, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}), ErrRecordingNotFound)

		// ready: every segment's metadata lands, the error stays empty.
		if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}); err != nil {
			t.Fatal(err)
		}
		ready, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if ready.State != RecPlaybackReady || ready.PlaybackError != "" {
			t.Fatalf("ready row: %+v", ready)
		}
		for i, sg := range ready.Segments {
			want := playbackSegs(2)[i]
			if sg.Playback == nil || *sg.Playback != want {
				t.Errorf("segment %d playback = %+v, want %+v", i, sg.Playback, want)
			}
		}
		// EVIDENCE IS UNTOUCHED by every playback outcome: digests, completion time, expiry, provenance.
		if !evidenceFieldsEqual(before, ready) {
			t.Error("a playback outcome changed the evidence fields")
		}
		// Two racing jobs cannot both win: ready -> ready is refused.
		wantErr(t, "ready twice", e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}), ErrRecordingState)

		// ready -> failed (a later check found the copy unusable), with a CLOSED reason.
		if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: false, Reason: MuxTimeBudget}); err != nil {
			t.Fatal(err)
		}
		failed, _ := e.store.GetRecording(ctx, e.tenantA, r.ID)
		if failed.State != RecPlaybackFailed || failed.PlaybackError != MuxTimeBudget || !evidenceFieldsEqual(before, failed) {
			t.Fatalf("failed row: %+v", failed)
		}
		// failed -> ready is the retry: the reason is cleared.
		if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}); err != nil {
			t.Fatal(err)
		}
		if cur, _ := e.store.GetRecording(ctx, e.tenantA, r.ID); cur.State != RecPlaybackReady || cur.PlaybackError != "" {
			t.Fatalf("after retry: %+v", cur)
		}
		// An expired recording has no playback outcome.
		if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
			t.Fatal(err)
		}
		wantErr(t, "expired recording", e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: false, Reason: MuxIO}), ErrRecordingState)
	})

	t.Run("list: completed recordings only, newest first, filters, paging, tenant isolation", func(t *testing.T) {
		e := mk(t)
		e.enable(t, e.tenantA, 30, 1<<30, 50<<30)
		e.enable(t, e.tenantB, 30, 1<<30, 50<<30)
		// Five completed in A (states vary), plus rows that must NOT be listed.
		var want []string
		for i := 0; i < 5; i++ {
			r := e.complete(t, e.tenantA, e.machineA, 200+int64(i), 100)
			switch i {
			case 1:
				if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: true, Segments: playbackSegs(2)}); err != nil {
					t.Fatal(err)
				}
			case 2:
				if err := e.store.RecordPlayback(ctx, e.tenantA, r.ID, PlaybackResult{OK: false, Reason: MuxInvalid}); err != nil {
					t.Fatal(err)
				}
			case 3:
				if err := e.store.MarkExpired(ctx, e.tenantA, r.ID); err != nil {
					t.Fatal(err)
				}
			}
			want = append(want, r.ID)
		}
		e.create(t, e.tenantA, e.machineA) // uploading: never listed
		ab, _ := e.create(t, e.tenantA, e.machineA)
		if err := e.store.AbandonRecording(ctx, e.tenantA, ab.ID); err != nil { // abandoned: never listed
			t.Fatal(err)
		}
		rb := e.complete(t, e.tenantB, e.machineB)

		all, err := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(all) != 5 {
			t.Fatalf("listed %d recordings, want the 5 completed ones: %+v", len(all), all)
		}
		got := map[string]RecordingListItem{}
		for _, it := range all {
			got[it.ID] = it
			if it.ID == rb.ID {
				t.Fatal("tenant B's recording is in tenant A's list")
			}
		}
		for _, id := range want {
			if _, ok := got[id]; !ok {
				t.Errorf("completed recording %s missing from the list", id)
			}
		}
		if !sort.SliceIsSorted(all, func(i, j int) bool {
			if !all[i].EvidenceCompleteAt.Equal(all[j].EvidenceCompleteAt) {
				return all[i].EvidenceCompleteAt.After(all[j].EvidenceCompleteAt)
			}
			return all[i].ID > all[j].ID
		}) {
			t.Fatalf("list is not newest-first: %+v", all)
		}
		states := map[string]int{}
		for _, it := range all {
			states[it.State]++
			if it.Provenance != ProvNoStopEvent || it.SegmentCount != 2 || it.DeclaredBytes <= 0 || it.MachineID != e.machineA {
				t.Errorf("item fields: %+v", it)
			}
			if it.State == RecPlaybackFailed && it.PlaybackError != MuxInvalid {
				t.Errorf("failed item carries reason %q", it.PlaybackError)
			}
		}
		if states[RecPlaybackReady] != 1 || states[RecPlaybackFailed] != 1 || states[RecExpired] != 1 || states[RecEvidenceComplete] != 2 {
			t.Errorf("states = %v", states)
		}

		// Paging by cursor visits every row exactly once, in the same order as one big page.
		var paged []string
		var cur *RecordingCursor
		for pages := 0; pages < 10; pages++ {
			page, err := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{Limit: 2, After: cur})
			if err != nil {
				t.Fatal(err)
			}
			if len(page) == 0 {
				break
			}
			for _, it := range page {
				paged = append(paged, it.ID)
			}
			last := page[len(page)-1]
			cur = &RecordingCursor{At: last.EvidenceCompleteAt, ID: last.ID}
		}
		if len(paged) != len(all) {
			t.Fatalf("paging yielded %d rows, want %d", len(paged), len(all))
		}
		for i := range all {
			if paged[i] != all[i].ID {
				t.Fatalf("paged order differs at %d", i)
			}
		}

		// Filters.
		bySession, _ := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{SessionID: all[0].SessionID, Limit: 100})
		if len(bySession) != 1 || bySession[0].ID != all[0].ID {
			t.Errorf("session filter: %+v", bySession)
		}
		if none, _ := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{MachineID: e.machineB, Limit: 100}); len(none) != 0 {
			t.Errorf("another tenant's machine id listed rows: %+v", none)
		}
		if inB, _ := e.store.ListRecordings(ctx, e.tenantB, RecordingListFilter{Limit: 100}); len(inB) != 1 || inB[0].ID != rb.ID {
			t.Errorf("tenant B list: %+v", inB)
		}
		// A malformed id names no row.
		if bad, err := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{SessionID: "not-a-uuid", Limit: 10}); err != nil || len(bad) != 0 {
			t.Errorf("malformed session id: %+v %v", bad, err)
		}
		if got, _ := e.store.ListRecordings(ctx, e.tenantA, RecordingListFilter{Limit: 1}); len(got) != 1 {
			t.Errorf("limit 1 returned %d", len(got))
		}
	})
}

// The session list names a session's recording through this lookup (no authorization of its own: the HTTP
// layer gates it). Fake and pg must agree: the NEWEST completed recording per session, never an unfinished
// one, never another tenant's, and malformed ids name nothing.
func runRecordingIDsBySessionSuite(t *testing.T, mk func(t *testing.T) *recEnv) {
	ctx := context.Background()
	e := mk(t)
	e.enable(t, e.tenantA, 30, 1<<30, 20<<30)
	e.enable(t, e.tenantB, 30, 1<<30, 20<<30)

	first := e.complete(t, e.tenantA, e.machineA)
	time.Sleep(20 * time.Millisecond)
	in := e.newRec(e.tenantA, e.machineA)
	in.SessionID = first.SessionID // a second recording of the SAME session
	second, created, err := e.store.CreateRecording(ctx, e.tenantA, in, recFree)
	if err != nil || !created {
		t.Fatalf("create second: %v %v", created, err)
	}
	// While the second is still uploading, the session names the FIRST (only completed ones count).
	got, err := e.store.RecordingIDsBySession(ctx, e.tenantA, []string{first.SessionID})
	if err != nil || got[first.SessionID] != first.ID || len(got) != 1 {
		t.Fatalf("uploading second must not be named: %v %v", got, err)
	}
	e.commitAll(t, e.tenantA, second)
	if _, err := e.store.CompleteEvidence(ctx, e.tenantA, second.ID, completion(second)); err != nil {
		t.Fatal(err)
	}
	got, _ = e.store.RecordingIDsBySession(ctx, e.tenantA, []string{first.SessionID})
	if got[first.SessionID] != second.ID {
		t.Fatalf("newest completed recording = %q, want %q", got[first.SessionID], second.ID)
	}

	other := e.complete(t, e.tenantA, e.machineA) // a different session
	e.create(t, e.tenantA, e.machineA)            // an uploading one in yet another session
	got, _ = e.store.RecordingIDsBySession(ctx, e.tenantA, []string{first.SessionID, other.SessionID, "not-a-uuid", freshID()})
	if len(got) != 2 || got[other.SessionID] != other.ID {
		t.Fatalf("batch lookup = %v", got)
	}
	// Another tenant, malformed ids and an empty list name nothing.
	if got, err := e.store.RecordingIDsBySession(ctx, e.tenantB, []string{first.SessionID}); err != nil || len(got) != 0 {
		t.Fatalf("cross-tenant lookup = %v %v", got, err)
	}
	if got, err := e.store.RecordingIDsBySession(ctx, e.tenantA, nil); err != nil || len(got) != 0 {
		t.Fatalf("empty lookup = %v %v", got, err)
	}
	if got, err := e.store.RecordingIDsBySession(ctx, e.tenantA, []string{"not-a-uuid"}); err != nil || len(got) != 0 {
		t.Fatalf("malformed lookup = %v %v", got, err)
	}
}

func TestRecordingIDsBySessionFake(t *testing.T) {
	runRecordingIDsBySessionSuite(t, func(t *testing.T) *recEnv {
		return &recEnv{
			store:   NewInMemoryRecordingStore(),
			tenantA: newUUIDLike(0xa), tenantB: newUUIDLike(0xb),
			machineA: newUUIDLike(0xc), machineB: newUUIDLike(0xd),
			session: func(string, string) string { return freshID() },
		}
	})
}

func TestRecordingPlaybackStoreFake(t *testing.T) {
	runRecordingPlaybackStoreSuite(t, func(t *testing.T) *recEnv {
		return &recEnv{
			store:   NewInMemoryRecordingStore(),
			tenantA: newUUIDLike(0xa), tenantB: newUUIDLike(0xb),
			machineA: newUUIDLike(0xc), machineB: newUUIDLike(0xd),
			session: func(string, string) string { return freshID() },
		}
	})
}
