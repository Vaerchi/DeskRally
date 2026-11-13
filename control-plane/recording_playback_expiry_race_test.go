package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// sweepingStore plays the retention sweeper against a running mux job: on the Nth GetRecording it
// expires + deletes the row and unlinks the recording directory (mark, unlink, mark), either BEFORE the
// call answers (the job then sees a closed row) or AFTER it answers (the job saw an open row and the
// sweeper strikes before its publish).
type sweepingStore struct {
	*InMemoryRecordingStore
	files *RecordingStorage
	calls atomic.Int32
	on    int32
	after bool
}

func (s *sweepingStore) GetRecording(ctx context.Context, tenantID, id string) (*RecordingRow, error) {
	n := s.calls.Add(1)
	if n == s.on && !s.after {
		s.sweep(ctx, tenantID, id)
	}
	row, err := s.InMemoryRecordingStore.GetRecording(ctx, tenantID, id)
	if n == s.on && s.after {
		s.sweep(ctx, tenantID, id)
	}
	return row, err
}

func (s *sweepingStore) sweep(ctx context.Context, tenantID, id string) {
	_ = s.InMemoryRecordingStore.MarkExpired(ctx, tenantID, id)
	_, _ = s.files.RemoveRecording(tenantID, id)
	_ = s.InMemoryRecordingStore.MarkDeleted(ctx, tenantID, id)
}

func TestMuxJobThatLosesItsRowLeavesNoDirectoryBehind(t *testing.T) {
	// GetRecording call 1 is MuxRecording's own read; 2 is the pre-publish check of segment 0, 3 of segment 1.
	for _, tc := range []struct {
		name  string
		on    int32
		after bool
	}{
		{"expired between segments (the check sees it)", 3, false},
		{"expired after the check, before the publish (the post-check cleans up)", 3, true},
		{"expired after segment 0 was published (segment 1 then fails)", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ss *sweepingStore
			h := newRecH(t, recHOpts{wireUp: func(h *recH) {
				ss = &sweepingStore{InMemoryRecordingStore: h.store, files: h.files}
				h.srv.Recording.Store = ss
			}})
			a, b := framesA(), framesB(10*90000)
			u := ivfUpload(buildIVF(320, 200, 90000, 1, a, uint32(len(a))), buildIVF(640, 360, 90000, 1, b, uint32(len(b))))
			h.completeUpload(u)
			ss.on, ss.after = tc.on, tc.after
			ss.calls.Store(0)
			// The job may report an error (the evidence it was reading is gone) or not; what matters is the volume.
			_ = h.srv.MuxRecording(context.Background(), h.tenant, u.id)
			if st := h.row(u).State; st != RecDeleted {
				t.Fatalf("state %s, want deleted", st)
			}
			if _, err := os.Stat(filepath.Join(h.dir, h.tenant, u.id)); !os.IsNotExist(err) {
				t.Fatalf("a recording directory remains after the row was expired and deleted: %v", err)
			}
			if ents := incomingEntries(t, h.dir); len(ents) != 0 {
				t.Fatalf("temp directories left behind: %v", ents)
			}
		})
	}
}
