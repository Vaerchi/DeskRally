package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// failCompleteStore fails CompleteEvidence with a non-state error (a database outage mid-finish).
type failCompleteStore struct {
	RecordingStore
	fail bool
}

func (f *failCompleteStore) CompleteEvidence(ctx context.Context, tenantID, id string, c EvidenceCompletion) (*RecordingRow, error) {
	if f.fail {
		return nil, errors.New("simulated database outage")
	}
	return f.RecordingStore.CompleteEvidence(ctx, tenantID, id, c)
}

// Every finish field is validated BEFORE the digest pass and any Promote: a bad one is a 400, the row is
// untouched, no failure is charged and no file left the incoming area.
func TestRecordingFinishValidatesEveryFieldBeforeAnyWork(t *testing.T) {
	cases := map[string]map[string]any{
		"frames above int64":       {"frames": uint64(1) << 63},
		"frames above C7":          {"frames": uint64(64*500_000 + 1)},
		"payload above int64":      {"payload_bytes": uint64(1) << 63},
		"payload above declared":   {"payload_bytes": uint64(101)},
		"dropped above int64":      {"dropped_frames": uint64(1) << 63},
		"dropped above sane":       {"dropped_frames": uint64(1)<<40 + 1},
		"truncated with NUL":       {"truncated": "size\u0000limit"},
		"truncated with control":   {"truncated": "size\nlimit"},
		"truncated with uppercase": {"truncated": "SIZE_LIMIT"},
	}
	for name, over := range cases {
		t.Run(name, func(t *testing.T) {
			h := newRecH(t, recHOpts{})
			u := newRecUpload(100)
			h.mustCreate(u)
			h.putAll(u)
			body := map[string]any{"recording_id": u.id, "generation": 1, "digests": u.digest, "truncated": nil, "dropped_frames": 0}
			for k, v := range over {
				body[k] = v
			}
			raw, _ := json.Marshal(body)
			st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: raw})
			if st != 400 {
				t.Fatalf("%d %v, want 400", st, m)
			}
			r := h.row(u)
			if r.State != RecUploading || r.FinishFailures != 0 {
				t.Fatalf("row touched: %s failures=%d", r.State, r.FinishFailures)
			}
			if h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
				t.Fatal("a segment was promoted before the fields were validated")
			}
		})
	}
	t.Run("a legitimate size_limit finish still completes", func(t *testing.T) {
		h := newRecH(t, recHOpts{})
		u := newRecUpload(100)
		h.mustCreate(u)
		h.putAll(u)
		st, m, _ := h.do(call{op: UploadOpFinish, rec: u.id, body: h.finishBody(u, u.digest, "size_limit", 3)})
		if st != 200 {
			t.Fatalf("%d %v", st, m)
		}
	})
}

// If the database step fails after Promote, the files are moved back so the 'uploading' row does not keep
// promoted files; the retried finish then succeeds.
func TestRecordingFinishUndoesPromotionWhenCompleteEvidenceFails(t *testing.T) {
	var fs *failCompleteStore
	h := newRecH(t, recHOpts{wireUp: func(h *recH) {
		fs = &failCompleteStore{RecordingStore: h.store, fail: true}
		h.srv.Recording.Store = fs
	}})
	u := newRecUpload(100)
	h.mustCreate(u)
	h.putAll(u)
	if st, m := h.finish(u); st != 500 {
		t.Fatalf("%d %v, want 500", st, m)
	}
	if r := h.row(u); r.State != RecUploading {
		t.Fatalf("state %s", r.State)
	}
	if h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
		t.Fatal("the promotion was not undone: an uploading row keeps files in the final directory")
	}
	if _, err := os.Stat(filepath.Join(h.dir, ".incoming", h.row(u).UploadID)); err != nil {
		t.Fatalf("the incoming directory is gone: %v", err)
	}
	fs.fail = false
	if st, m := h.finish(u); st != 200 {
		t.Fatalf("retry: %d %v", st, m)
	}
	if h.row(u).State != RecEvidenceComplete || !h.files.FinalExists(h.tenant, u.id, 0, RepIVF) {
		t.Fatal("the retry did not complete")
	}
}
