package controlplane

// CodeQL go/incorrect-integer-conversion (public repo scan, 2026-11-14): values converted to unsigned or narrower
// types are range-checked first, so a bad row or an absurd setting is refused or capped instead of wrapping.

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRecEnvMetaRefusesOutOfRangeValues(t *testing.T) {
	row := &RecordingRow{TenantID: "11111111-1111-1111-1111-111111111111", ID: "22222222-2222-2222-2222-222222222222", Generation: 1}
	if _, err := recEnvMeta(row, 3, 1024, RepIVF); err != nil {
		t.Fatalf("an in-range segment was refused: %v", err)
	}
	for name, c := range map[string]struct {
		idx      int
		declared int64
		gen      int64
	}{
		"negative index":      {-1, 1024, 1},
		"negative length":     {0, -1, 1},
		"negative generation": {0, 1024, -1},
	} {
		r := *row
		r.Generation = c.gen
		if _, err := recEnvMeta(&r, c.idx, c.declared, RepIVF); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLookupPoolConfigCapsAnAbsurdConnectionCount(t *testing.T) {
	shared, err := pgxpool.ParseConfig("postgres://rmt_app@db.example:5432/rmt?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	c := LookupPoolConfig(shared, 1<<40)
	if c.MaxConns != MaxLookupPoolConns || c.MinConns != MaxLookupPoolConns {
		t.Fatalf("MaxConns=%d MinConns=%d, want both capped at %d", c.MaxConns, c.MinConns, MaxLookupPoolConns)
	}
}
