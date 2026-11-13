//go:build rustinterop

package controlplane

// Rust agent <-> real Go upload handler (docs/63 R2). The shared golden vectors prove the PREIMAGE is
// the same on both sides; they cannot prove the Rust uploader's actual requests (headers, canonical
// path, chunking, finish body, resume) are accepted by the real verifier. This test starts the real
// handler (recH, the same harness the upload tests use), writes a finished recording in the agent's
// on-disk format, runs the Rust uploader (`go_driven_upload` in
// crates/agent-windows/tests/recording_upload_wire.rs) against it, then checks the SERVER side: row
// state, per-segment digests, and the decrypted bytes on the volume.
//
// It is behind a build tag because it needs a Rust toolchain and a built agent crate (minutes on a cold
// target dir), which the Go-only CI jobs do not have. Run it from the repo root with:
//
//	go test -tags rustinterop -run TestRustAgent -count=1 ./control-plane/
//
// On Windows run the cargo part from PowerShell-launched go (the test shells out to cargo itself).

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

type rustSidecarSegment struct {
	File         string `json:"file"`
	Width        uint32 `json:"width"`
	Height       uint32 `json:"height"`
	Frames       uint64 `json:"frames"`
	PayloadBytes uint64 `json:"payload_bytes"`
	SHA256       string `json:"sha256"`
}

type rustSidecar struct {
	Kind          string               `json:"kind"`
	DeviceID      string               `json:"device_id"`
	SessionID     string               `json:"session_id"`
	StartedAt     int64                `json:"started_at_unix_ms"`
	EndedAt       int64                `json:"ended_at_unix_ms"`
	DeleteAfter   int64                `json:"delete_after_unix_ms"`
	Segments      []rustSidecarSegment `json:"segments"`
	Truncated     *string              `json:"truncated"`
	DroppedFrames uint64               `json:"dropped_frames"`
	Disclaimer    string               `json:"disclaimer"`
}

// writeAgentRecording lays out `rec-<ms>.json` + `rec-<ms>-NNNN.ivf` the way recording.rs does and
// returns the plaintext of each segment.
func writeAgentRecording(t *testing.T, dir, device, session string, ms int64, sizes []int, truncated *string) [][]byte {
	t.Helper()
	stem := fmt.Sprintf("rec-%d", ms)
	var segs []rustSidecarSegment
	var plain [][]byte
	for i, n := range sizes {
		data := make([]byte, n)
		for j := range data {
			data[j] = byte((j*31 + i*7 + int(ms)) % 251)
		}
		name := fmt.Sprintf("%s-%04d.ivf", stem, i)
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(data)
		segs = append(segs, rustSidecarSegment{File: name, Width: 640, Height: 480, Frames: uint64(10 + i), PayloadBytes: uint64(n / 2), SHA256: hex.EncodeToString(sum[:])})
		plain = append(plain, data)
	}
	now := time.Now().UnixMilli()
	side := rustSidecar{Kind: "rmt.session-recording.v1", DeviceID: device, SessionID: session, StartedAt: ms,
		EndedAt: now - 1000, DeleteAfter: now + 72*3600*1000, Segments: segs, Truncated: truncated, DroppedFrames: 3, Disclaimer: "interop"}
	b, _ := json.Marshal(side)
	if err := os.WriteFile(filepath.Join(dir, stem+".json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return plain
}

var recIDLine = regexp.MustCompile(`RECORDING_ID=([0-9a-f-]{36}) STATUS=(\w+)`)

func runRustUploader(t *testing.T, h *recH, dir, stateDir, expect string) []string {
	return runRustUploaderMode(t, h, dir, stateDir, expect, "")
}

func runRustUploaderMode(t *testing.T, h *recH, dir, stateDir, expect, mode string) []string {
	t.Helper()
	cmd := exec.Command("cargo", "test", "-j", "4", "-p", "rmt-agent-windows", "--test", "recording_upload_wire",
		"--", "--ignored", "--exact", "go_driven_upload", "--nocapture", "--test-threads=1")
	cmd.Dir = ".." // repo root: control-plane/..
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = 42 // newRecH's device key
	}
	cmd.Env = append(os.Environ(),
		"RMT_E2E_BASE="+h.ts.URL,
		"RMT_E2E_AUDIENCE="+h.audience,
		"RMT_E2E_TENANT="+h.tenant,
		"RMT_E2E_DEVICE="+h.device,
		"RMT_E2E_SEED_HEX="+hex.EncodeToString(seed),
		"RMT_E2E_DIR="+dir,
		"RMT_E2E_STATE_DIR="+stateDir,
		"RMT_E2E_EXPECT="+expect,
		"RMT_E2E_MODE="+mode,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("rust uploader failed: %v\n%s", err, out)
	}
	var ids []string
	for _, m := range recIDLine.FindAllStringSubmatch(string(out), -1) {
		ids = append(ids, m[1])
	}
	return ids
}

func TestRustAgentUploadsToTheRealHandler(t *testing.T) {
	h := newRecH(t, recHOpts{})
	dir, stateDir := t.TempDir(), t.TempDir()
	trunc := "size_limit"
	plain := writeAgentRecording(t, dir, h.device, h.session, 1790000000000, []int{2*RecChunkSize + 777, 1000, 1}, &trunc)

	ids := runRustUploader(t, h, dir, stateDir, "complete")
	if len(ids) != 1 {
		t.Fatalf("want one recording id, got %v", ids)
	}
	ctx := context.Background()
	row, err := h.store.GetRecording(ctx, h.tenant, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	if row.State != RecEvidenceComplete && row.State != RecPlaybackReady && row.State != RecPlaybackFailed {
		t.Fatalf("state %q", row.State)
	}
	if len(row.Segments) != len(plain) {
		t.Fatalf("segments %d", len(row.Segments))
	}
	for i, p := range plain {
		sum := sha256.Sum256(p)
		if row.Segments[i].SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("segment %d digest %s", i, row.Segments[i].SHA256)
		}
		if row.Segments[i].DeclaredLen != int64(len(p)) {
			t.Fatalf("segment %d length %d", i, row.Segments[i].DeclaredLen)
		}
		// The bytes on the VOLUME decrypt to exactly what the agent had on disk.
		d, err := h.srv.recSegmentDigest(ctx, row, i)
		if err != nil || d != hex.EncodeToString(sum[:]) {
			t.Fatalf("segment %d stored digest %q err %v", i, d, err)
		}
	}
	if row.Truncated == nil || *row.Truncated != trunc || row.DroppedFrames == nil || *row.DroppedFrames != 3 {
		t.Fatalf("attested metadata: truncated=%v dropped=%v", row.Truncated, row.DroppedFrames)
	}
	if left, _ := os.ReadDir(dir); len(left) != 0 {
		t.Fatalf("the agent must delete its local copy after the acknowledgement; left %d entries", len(left))
	}
}

func TestRustAgentStorageOffEndsTheRecordingAndKeepsTheLocalCopy(t *testing.T) {
	h := newRecH(t, recHOpts{noPolicy: true}) // no tenant policy: retention 0 = storage off
	dir, stateDir := t.TempDir(), t.TempDir()
	writeAgentRecording(t, dir, h.device, h.session, 1790000001000, []int{500}, nil)
	ids := runRustUploader(t, h, dir, stateDir, "not_stored")
	if len(ids) != 1 {
		t.Fatalf("ids %v", ids)
	}
	if _, err := h.store.GetRecording(context.Background(), h.tenant, ids[0]); err == nil {
		t.Fatal("a storage-off tenant must not have a recording row")
	}
	if left, _ := os.ReadDir(dir); len(left) != 2 {
		t.Fatalf("local copy must stay: %d entries", len(left))
	}
	_ = strings.TrimSpace
}

// A restart mid-upload: the first uploader stops after one acknowledged chunk, a second one starts from the
// persisted queue state and must resync with a REAL signed HEAD (bodyless, explicit Content-Length: 0)
// against the strict handler, then finish. The Rust side asserts the HEAD happened; this side asserts the
// server row.
func TestRustAgentRestartResumesWithARealHEAD(t *testing.T) {
	h := newRecH(t, recHOpts{})
	dir, stateDir := t.TempDir(), t.TempDir()
	plain := writeAgentRecording(t, dir, h.device, h.session, 1790000002000, []int{3*RecChunkSize + 10}, nil)
	ids := runRustUploaderMode(t, h, dir, stateDir, "complete", "restart")
	if len(ids) != 1 {
		t.Fatalf("ids %v", ids)
	}
	row, err := h.store.GetRecording(context.Background(), h.tenant, ids[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain[0])
	if row.Segments[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", row.Segments[0].SHA256)
	}
}
