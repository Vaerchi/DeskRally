package controlplane

import (
	"context"
	"errors"
	"testing"
)

// TestInMemoryMachinePropertyStore exercises the KV contract the fake shares with the pg store:
// upsert, ordered listing, idempotent-not-found delete, and (tenant, machine) keying. Cross-tenant
// WRITE isolation (the composite FK) is a pg-only property proven in machineproperty_pgstore_test.go.
func TestInMemoryMachinePropertyStore(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachinePropertyStore()
	const (
		tenantA = "tenant-a"
		tenantB = "tenant-b"
		machine = "m-1"
	)

	// Unknown machine lists empty, not an error (parity with the pg SELECT, which never consults the FK).
	if got, err := s.ListProperties(ctx, tenantA, machine); err != nil || len(got) != 0 {
		t.Fatalf("list of empty machine = %+v, %v; want [] , nil", got, err)
	}

	// Set two keys, then a third write that UPDATES the first key in place.
	if err := s.SetProperty(ctx, tenantA, machine, "site", "HQ"); err != nil {
		t.Fatalf("set site: %v", err)
	}
	if err := s.SetProperty(ctx, tenantA, machine, "rack", "R7"); err != nil {
		t.Fatalf("set rack: %v", err)
	}
	if err := s.SetProperty(ctx, tenantA, machine, "site", "DR"); err != nil {
		t.Fatalf("upsert site: %v", err)
	}

	// List is ordered by key and reflects the upsert (site=DR, not HQ).
	got, err := s.ListProperties(ctx, tenantA, machine)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []MachineProperty{{Key: "rack", Value: "R7"}, {Key: "site", Value: "DR"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("list = %+v, want %+v (ordered by key, upsert must update in place)", got, want)
	}

	// A different tenant with the SAME machine id has its own, independent bag.
	if got, _ := s.ListProperties(ctx, tenantB, machine); len(got) != 0 {
		t.Fatalf("tenant B sees %d of tenant A's properties, want 0", len(got))
	}
	if err := s.SetProperty(ctx, tenantB, machine, "site", "Branch"); err != nil {
		t.Fatalf("set B/site: %v", err)
	}
	if got, _ := s.ListProperties(ctx, tenantA, machine); len(got) != 2 || got[1].Value != "DR" {
		t.Fatalf("tenant A's bag changed after a tenant-B write: %+v", got)
	}

	// Delete an existing key: success, and it disappears from the listing.
	if err := s.DeleteProperty(ctx, tenantA, machine, "site"); err != nil {
		t.Fatalf("delete site: %v", err)
	}
	if got, _ := s.ListProperties(ctx, tenantA, machine); len(got) != 1 || got[0].Key != "rack" {
		t.Fatalf("after delete, list = %+v, want [rack=R7]", got)
	}

	// Deleting a now-absent key is ErrMachinePropertyNotFound (a 404), not a silent success.
	if err := s.DeleteProperty(ctx, tenantA, machine, "site"); !errors.Is(err, ErrMachinePropertyNotFound) {
		t.Fatalf("re-delete of a gone key = %v, want ErrMachinePropertyNotFound", err)
	}
	// Deleting a key on a machine with no properties at all is likewise not-found.
	if err := s.DeleteProperty(ctx, tenantA, "m-never", "site"); !errors.Is(err, ErrMachinePropertyNotFound) {
		t.Fatalf("delete on empty machine = %v, want ErrMachinePropertyNotFound", err)
	}
}

// TestInMemoryMachineIDsWithProperty pins the fake's fleet-search behaviour to the pg store's
// (TestPgMachineIDsWithPropertyIsolation): key-only matches any value, key+value is exact, a machine
// lacking the key is excluded, and another tenant's machine with the same key/value is never returned.
func TestInMemoryMachineIDsWithProperty(t *testing.T) {
	ctx := context.Background()
	s := NewInMemoryMachinePropertyStore()
	const tenantA, tenantB = "tenant-a", "tenant-b"

	_ = s.SetProperty(ctx, tenantA, "a1", "site", "HQ")
	_ = s.SetProperty(ctx, tenantA, "a2", "site", "DR")
	_ = s.SetProperty(ctx, tenantA, "a3", "rack", "R7") // no site
	_ = s.SetProperty(ctx, tenantB, "b1", "site", "HQ") // same key+value, other tenant

	ids := func(tid, key, val string) map[string]struct{} {
		got, err := s.MachineIDsWithProperty(ctx, tid, key, val)
		if err != nil {
			t.Fatalf("ids(%s,%s,%s): %v", tid, key, val, err)
		}
		return got
	}
	has := func(m map[string]struct{}, id string) bool { _, ok := m[id]; return ok }

	// key-only (any value): a1 + a2, not a3, and NEVER b1 (other tenant).
	any := ids(tenantA, "site", "")
	if len(any) != 2 || !has(any, "a1") || !has(any, "a2") {
		t.Fatalf("A site=* = %v, want {a1,a2}", any)
	}
	if has(any, "b1") {
		t.Fatal("tenant A search leaked tenant B's machine")
	}
	// key+value exact: only a1.
	if hq := ids(tenantA, "site", "HQ"); len(hq) != 1 || !has(hq, "a1") {
		t.Fatalf("A site=HQ = %v, want {a1}", hq)
	}
	// tenant B, same key+value: only b1, never a1.
	if bhq := ids(tenantB, "site", "HQ"); len(bhq) != 1 || !has(bhq, "b1") || has(bhq, "a1") {
		t.Fatalf("B site=HQ = %v, want {b1} only", bhq)
	}
	// no match / unknown key: empty.
	if len(ids(tenantA, "site", "NOWHERE")) != 0 || len(ids(tenantA, "nope", "")) != 0 {
		t.Fatal("no-match searches must be empty")
	}
}
