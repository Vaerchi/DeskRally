package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Every reviewed edit must name the file exactly as it is on disk now, so the allowance cannot outlive the file.
func TestReviewedCommentOnlyEditsMatchDisk(t *testing.T) {
	for name, e := range reviewedCommentOnlyEdits {
		b, err := os.ReadFile(filepath.Join("migrations", name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != e.to {
			t.Errorf("%s is %s on disk, but the reviewed edit allows only %s: a further edit needs its own review", name, got, e.to)
		}
	}
}

func TestIsReviewedCommentOnlyEditIsExact(t *testing.T) {
	e := reviewedCommentOnlyEdits["0080_oidc_remember.sql"]
	cases := []struct {
		name, recorded, onDisk string
		want                   bool
	}{
		{"0080_oidc_remember.sql", e.from, e.to, true},
		{"0080_oidc_remember.sql", e.from, "0000", false},         // a different edit
		{"0080_oidc_remember.sql", "0000", e.to, false},           // recorded from some other version
		{"0083_tenant_session_binding.sql", e.from, e.to, false},  // another file's hashes
		{"0001_init.sql", e.from, e.to, false},                    // not listed
	}
	for _, c := range cases {
		if got := isReviewedCommentOnlyEdit(c.name, c.recorded, c.onDisk); got != c.want {
			t.Errorf("isReviewedCommentOnlyEdit(%s, %s, %s) = %v, want %v", c.name, c.recorded, c.onDisk, got, c.want)
		}
	}
}
