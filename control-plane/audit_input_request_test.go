package controlplane

// Cross-language vectors for the docs/73 2.2.5 audit kinds input_control_requested and
// input_control_request_closed. The shared file is written by the Rust agent test
// (agent/src/backstage/audit.rs :: audit_golden_input_request_vectors_v1) and read by both sides. A kind
// with no arm here would make ingest report a ContentTamperError and wedge the session's sequential chain,
// so every vector's preimage and hash must match byte for byte, and every "invalid" entry must be refused.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const inputRequestVectorsPath = "../crates/protocol/testdata/input-request-audit-vectors.json"

type inputRequestVectorFile struct {
	Vectors []struct {
		Name        string          `json:"name"`
		EventID     string          `json:"event_id"`
		Seq         uint64          `json:"seq"`
		OccurredMs  int64           `json:"occurred_ms"`
		PrevHash    string          `json:"prev_hash"`
		Action      json.RawMessage `json:"action"`
		PreimageHex string          `json:"preimage_hex"`
		Hash        string          `json:"hash"`
	} `json:"vectors"`
	Invalid []struct {
		Name   string          `json:"name"`
		Action json.RawMessage `json:"action"`
	} `json:"invalid"`
}

func loadInputRequestVectors(t *testing.T) inputRequestVectorFile {
	t.Helper()
	raw, err := os.ReadFile(inputRequestVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v", inputRequestVectorsPath, err)
	}
	var f inputRequestVectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return f
}

func TestAuditGoldenInputRequestVectors(t *testing.T) {
	f := loadInputRequestVectors(t)
	if len(f.Vectors) != 14 {
		t.Fatalf("expected 14 vectors, got %d", len(f.Vectors))
	}
	for _, v := range f.Vectors {
		e := goldenAuditEvent(v.EventID, v.Seq, v.OccurredMs, v.Action, json.RawMessage(`{"result":"ok"}`), v.PrevHash)
		assertGolden(t, v.Name, e, v.PreimageHex, v.Hash)
	}
}

// Every refusal is a refusal of the ACTION: nothing may be canonicalized, so the chain cannot be
// made to hash something other than what the agent sealed.
func TestAuditInputRequestInvalidVectorsAreRefused(t *testing.T) {
	f := loadInputRequestVectors(t)
	if len(f.Invalid) == 0 {
		t.Fatal("the shared file has no invalid section")
	}
	for _, v := range f.Invalid {
		w := &canonicalWriter{}
		if err := encodeAuditAction(w, v.Action); err == nil {
			t.Errorf("%s: was canonicalized", v.Name)
		}
	}
}

// A missing key, an empty/unknown outcome and a wrong-type value are reported as DIFFERENT refusals.
func TestAuditInputRequestRefusalsAreDistinct(t *testing.T) {
	const ids = `"request_id":"00000000-0000-0000-0000-000000000000","requester_session":"00000000-0000-0000-0000-000000000000",` +
		`"requester_technician":"00000000-0000-0000-0000-000000000000","holder_session":"00000000-0000-0000-0000-000000000000",` +
		`"holder_technician":"00000000-0000-0000-0000-000000000000"`
	closed := func(extra string) string {
		return `{"kind":"input_control_request_closed",` + ids + extra + `}`
	}
	cases := []struct{ name, action, want string }{
		{"missing epoch", closed(`,"outcome":"granted"`), "epoch is required"},
		{"missing outcome", closed(`,"epoch":1`), "outcome is required"},
		{"empty outcome", closed(`,"epoch":1,"outcome":""`), "unknown outcome"},
		{"unknown outcome", closed(`,"epoch":1,"outcome":"bogus"`), "unknown outcome"},
		{"number outcome", closed(`,"epoch":1,"outcome":7`), "cannot unmarshal"},
		{"string epoch", closed(`,"epoch":"1","outcome":"granted"`), "cannot unmarshal"},
	}
	for _, c := range cases {
		err := encodeAuditAction(&canonicalWriter{}, json.RawMessage(c.action))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want it to contain %q", c.name, err, c.want)
		}
	}
}
